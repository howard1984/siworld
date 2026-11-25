//! Experimental eight-leaf relation. It exports the existing internal-statement
//! digest but has a distinct verifier key. No node or pinned key uses it.

use super::*;

pub const FAN_IN: usize = 8;

pub struct EightLeafAggregation {
    child: Child,
    backend: Backend,
    circuit: Circuit<Challenge>,
    children: Vec<VRes>,
    prepared: PreparedCircuitProver<Cfg>,
}

impl EightLeafAggregation {
    pub fn new(
        prover: Arc<SlotProver>,
        sample: Input<'_>,
        out_cfg: &Cfg,
        params: &ProveNextLayerParams,
    ) -> Result<Self, String> {
        if !matches!(sample, Input::Uni(_, _, _)) {
            return Err("eight-leaf relation requires leaf proofs".into());
        }
        let child = Child::Uni(prover);
        let backend = backend();
        let mut builder = CircuitBuilder::new();
        child.prepare(&backend, &mut builder)?;
        let mut children = Vec::with_capacity(FAN_IN);
        let mut statements = Vec::with_capacity(FAN_IN);
        for _ in 0..FAN_IN {
            let (result, statement) = child.build(&backend, sample, &mut builder)?;
            children.push(result);
            statements.push(statement);
        }
        let root = builder.alloc_private_inputs(DIGEST, "common anchor root");
        bind_base(&mut builder, &root)?;
        let root_lanes = lanes(&mut builder, &root);
        let one = builder.define_const(Challenge::ONE);
        for statement in &mut statements {
            let count_error = builder.sub(statement[ACC_COUNT], one);
            builder.assert_zero(count_error);
            let entry = lanes(&mut builder, &statement[ACC_ENTRY..]);
            anchor_path(&mut builder, entry, root_lanes)?;
            statement.truncate(ACC_ENTRY);
            statement.extend_from_slice(&root);
        }
        let mut full = statements[0].clone();
        for statement in &statements[1..] {
            let mut merged: Vec<_> = (ACC_SET..ACC_FEE)
                .map(|k| builder.add(full[k], statement[k]))
                .collect();
            let mut carry = ExprId::ZERO;
            for k in ACC_FEE..ACC_COUNT {
                let sum = builder.add(full[k], statement[k]);
                let sum = builder.add(sum, carry);
                let (low, high) = split_low(&mut builder, sum, LIMB_BITS)?;
                merged.push(low);
                carry = high;
            }
            builder.assert_zero(carry);
            let count = builder.add(full[ACC_COUNT], statement[ACC_COUNT]);
            builder
                .decompose_to_bits::<F>(count, COUNT_BITS)
                .map_err(err)?;
            merged.push(count);
            merged.extend_from_slice(&root);
            full = merged;
        }
        let exports: Vec<_> = sponge(&mut builder, TAG_ACC_NODE, &full)?
            .into_iter()
            .map(StatementExport::Base)
            .collect();
        let schema = builder.set_statement_exports::<F>(&exports).map_err(err)?;
        let circuit = builder.build().map_err(err)?;
        let mut preprocessors =
            <Backend as PcsRecursionBackend<Cfg, BatchOnly, 8>>::non_primitive_preprocessors(
                &backend,
            );
        let mut air_builders =
            <Backend as PcsRecursionBackend<Cfg, BatchOnly, 8>>::non_primitive_air_builders(
                &backend,
            );
        let mut provers =
            <Backend as PcsRecursionBackend<Cfg, BatchOnly, 8>>::non_primitive_provers(&backend, 8);
        preprocessors.push(Box::new(StatementPreprocessor::new(schema.clone())));
        air_builders.push(Box::new(StatementAirBuilder::<8>::new(schema.clone())));
        provers.push(Box::new(StatementProver::<8>::new(schema)));
        let mut prover = BatchStarkProver::new(out_cfg.clone())
            .with_table_packing(params.table_packing.clone())
            .with_alu_variant(match params.constraint_profile {
                ConstraintProfile::Standard => AirVariant::Baseline,
                ConstraintProfile::RecursionOptimized => AirVariant::Optimized,
            });
        for table in provers {
            prover.register_table_prover(table);
        }
        let prepared = prover
            .prepare_circuit::<Challenge, 8>(
                &circuit,
                &preprocessors,
                &air_builders,
                params.constraint_profile,
            )
            .map_err(err)?;
        Ok(Self {
            child,
            backend,
            circuit,
            children,
            prepared,
        })
    }

    pub fn prove(&self, inputs: &[Input<'_>]) -> Result<BatchStarkProof<Cfg>, String> {
        if inputs.len() != FAN_IN
            || inputs.iter().any(|input| {
                !matches!(input, Input::Uni(_, statement, path)
                if statement.len() == NUM_ACC_PUBLIC && path.len() == ANCHOR_DEPTH)
            })
        {
            return Err("eight-leaf relation requires exactly eight complete leaves".into());
        }
        let previous: Vec<_> = inputs
            .iter()
            .map(|&input| self.child.prev(input))
            .collect::<Result<_, _>>()?;
        let mut public = Vec::new();
        let mut private = Vec::new();
        for (child, prev) in self.children.iter().zip(&previous) {
            public.extend(self.child.pack_public(child, prev)?);
            private.extend(self.child.pack_private(child, prev)?);
        }
        let Input::Uni(_, statement, path) = inputs[0] else {
            unreachable!()
        };
        let full = anchor_leaf(statement, path);
        private.extend(full[ACC_ROOT..].iter().copied().map(Challenge::from));
        for input in inputs {
            let Input::Uni(_, _, path) = input else {
                unreachable!()
            };
            let position: u32 = path
                .iter()
                .enumerate()
                .map(|(k, (_, right))| u32::from(*right) << k)
                .sum();
            private.push(Challenge::from(F::from_u32(position)));
            for (sibling, _) in *path {
                private.extend(sibling.iter().copied().map(Challenge::from));
            }
        }
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&public).map_err(err)?;
        runner.set_private_inputs(&private).map_err(err)?;
        for ((child, prev), &input) in self.children.iter().zip(&previous).zip(inputs) {
            self.child
                .set_private(&self.backend, child, prev, input, &mut runner)?;
        }
        let traces = {
            #[cfg(feature = "phase-profile")]
            let _phase = crate::profile::Span::new("recursive_witness");
            runner.run().map_err(err)?
        };
        #[cfg(feature = "phase-profile")]
        let _phase = crate::profile::Span::new("recursive_stark");
        let (proof, _) = self.prepared.prove_with_legacy_data(&traces).map_err(err)?;
        Ok(proof)
    }

    pub fn verifier(&self) -> CircuitVerifier<Cfg> {
        self.prepared.verifier()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FriParams;
    use crate::common::{
        FEE_BASE, MINER_SHARE, Rng, acc_witnesses, sample_empty_slot, sample_priority_slot,
        sample_slot, with_unlock_heights,
    };

    #[test]
    fn d8_w24_eight_input_smoke_binds_statement() {
        let fri = FriParams {
            batch_pow_bits: 4,
            query_pow_bits: 4,
            ..FriParams::fast()
        };
        eprintln!("D8_TEST_PHASE leaf_setup");
        let prover = Arc::new(SlotProver::new_acc(fri));
        let (witnesses, _) = acc_witnesses(vec![sample_slot(100, false)], 1000, FEE_BASE, 21);
        eprintln!("D8_TEST_PHASE leaf_proof");
        let (proof, statement) = prover.prove_acc(&witnesses[0]);
        eprintln!("D8_TEST_PHASE leaf_verification");
        prover.verify(&proof, &statement).unwrap();
        let input = Input::Uni(&proof, &statement, &witnesses[0].anchor_path);
        let params = ProveNextLayerParams {
            table_packing: TablePacking::new(4, 4).with_min_trace_height(128),
            ..Default::default()
        };
        eprintln!("D8_TEST_PHASE merge_setup");
        let batch = EightLeafAggregation::new(prover, input, &fri.config(), &params).unwrap();
        eprintln!("D8_TEST_PHASE merge_proof");
        let result = batch.prove(&[input; FAN_IN]).unwrap();
        let full = anchor_leaf(&statement, &witnesses[0].anchor_path);
        let expected = (1..FAN_IN).fold(full.clone(), |a, _| compose_acc(&a, &full));
        let public = node_digest(&expected);
        eprintln!("D8_TEST_PHASE merge_verification");
        batch.verifier().verify(&result, &public).unwrap();
        eprintln!("D8_TEST_PHASE public_digest_rejection");
        for i in [0, DIGEST - 1] {
            let mut changed = public.clone();
            changed[i] += F::ONE;
            assert!(batch.verifier().verify(&result, &changed).is_err());
        }
        eprintln!("D8_TEST_PHASE last_child_rejection");
        let mut wrong = statement.clone();
        wrong[ACC_SET + SET_LEN - 1] += F::ONE;
        let mut inputs = [input; FAN_IN];
        inputs[FAN_IN - 1] = Input::Uni(&proof, &wrong, &witnesses[0].anchor_path);
        assert!(
            batch.prove(&inputs).is_err(),
            "last child statement is bound"
        );
    }
    use p3_circuit_prover::TablePacking;
    use p3_recursion::artifact::{ArtifactLimits, PortableArtifactExport};

    #[test]
    fn sixteen_leaves_form_two_eight_input_proofs_and_one_root() {
        compare_topologies(FriParams::fast(), FriParams::fast());
    }

    #[test]
    fn distinct_leaf_parameters_are_pinned_by_the_recursive_relation() {
        let recursive = FriParams::fast();
        let leaf = FriParams {
            log_blowup: 4,
            ..recursive
        };
        compare_topologies(leaf, recursive);
    }

    fn compare_topologies(leaf_fri: FriParams, fri: FriParams) {
        // Insecure parameters exercise the relation only, never hardware acceptance.
        let params = ProveNextLayerParams {
            table_packing: TablePacking::new(4, 4).with_min_trace_height(64),
            ..ProveNextLayerParams::default()
        };
        let prover = Arc::new(SlotProver::new_acc(leaf_fri));
        let slots = (0..16)
            .map(|i| match i % 3 {
                0 => sample_empty_slot(100 + i),
                1 => sample_slot(100 + i, false),
                _ => sample_priority_slot(100 + i),
            })
            .collect();
        let (witnesses, _) = acc_witnesses(slots, 1000, FEE_BASE, 21);
        let leaves: Vec<_> = witnesses.iter().map(|w| prover.prove_acc(w)).collect();
        let inputs: Vec<_> = (0..16)
            .map(|i| Input::Uni(&leaves[i].0, &leaves[i].1, &witnesses[i].anchor_path))
            .collect();
        let full: Vec<_> = (0..16)
            .map(|i| anchor_leaf(&leaves[i].1, &witnesses[i].anchor_path))
            .collect();
        let fold = |rows: &[Vec<F>]| {
            rows[1..]
                .iter()
                .fold(rows[0].clone(), |acc, row| compose_acc(&acc, row))
        };
        let left = fold(&full[..8]);
        let right = fold(&full[8..]);
        let batch =
            EightLeafAggregation::new(prover.clone(), inputs[0], &fri.config(), &params).unwrap();
        assert!(batch.prove(&inputs[..7]).is_err());
        if leaf_fri.log_blowup != fri.log_blowup {
            let wrong_prover = SlotProver::new_acc(fri);
            let wrong_leaf = wrong_prover.prove_acc(&witnesses[0]);
            wrong_prover.verify(&wrong_leaf.0, &wrong_leaf.1).unwrap();
            let mut wrong_inputs = inputs[..8].to_vec();
            wrong_inputs[0] = Input::Uni(&wrong_leaf.0, &wrong_leaf.1, &witnesses[0].anchor_path);
            assert!(batch.prove(&wrong_inputs).is_err());
        }
        let pleft = batch.prove(&inputs[..8]).unwrap();
        let pright = batch.prove(&inputs[8..]).unwrap();
        let verifier = batch.verifier();
        verifier.verify(&pleft, &node_digest(&left)).unwrap();
        verifier.verify(&pright, &node_digest(&right)).unwrap();

        let note = MinerNote {
            height: 1234,
            share: MINER_SHARE,
            owner: Rng::new(9).digest(),
            rseed: Rng::new(10).digest(),
        };
        let root = AccAggregation::new(
            Child::Batch(verifier.clone()),
            Input::Batch(&pleft, &left),
            &fri.config(),
            &params,
            true,
        )
        .unwrap();
        let proof = root
            .prove(
                Input::Batch(&pleft, &left),
                Input::Batch(&pright, &right),
                Some(&note),
            )
            .unwrap();
        let statement = root_statement(&left, &right, &note);
        root.verifier().verify(&proof, &statement).unwrap();
        assert_eq!(statement[ROOT_COUNT], F::from_u32(16));

        // Prove the same leaves with the existing balanced binary topology.
        // Equal public values do not imply compatible pinned verifiers.
        let mut child = Child::Uni(prover.clone());
        let mut binary_proofs = Vec::new();
        let mut binary_statements = full.clone();
        let (binary_proof, binary_statement, binary_verifier) = loop {
            let count = binary_statements.len() / 2;
            let is_root = count == 1;
            let input = |i: usize| {
                if binary_proofs.is_empty() {
                    inputs[i]
                } else {
                    Input::Batch(&binary_proofs[i], &binary_statements[i])
                }
            };
            let layer =
                AccAggregation::new(child, input(0), &fri.config(), &params, is_root).unwrap();
            let next: Vec<_> = (0..count)
                .map(|i| {
                    layer
                        .prove(input(2 * i), input(2 * i + 1), is_root.then_some(&note))
                        .unwrap()
                })
                .collect();
            if is_root {
                break (
                    next.into_iter().next().unwrap(),
                    root_statement(&binary_statements[0], &binary_statements[1], &note),
                    layer.verifier(),
                );
            }
            binary_statements = binary_statements
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| compose_acc(&pair[0], &pair[1]))
                .collect();
            binary_proofs = next;
            child = Child::Batch(layer.verifier());
        };
        assert_eq!(statement, binary_statement);
        binary_verifier.verify(&binary_proof, &statement).unwrap();
        let limits = ArtifactLimits::default();
        assert_ne!(
            root.verifier().encode_verifier_artifact(limits).unwrap(),
            binary_verifier.encode_verifier_artifact(limits).unwrap(),
            "topology changes the pinned root verifier artifact"
        );
        assert!(binary_verifier.verify(&proof, &statement).is_err());
        assert!(root.verifier().verify(&binary_proof, &statement).is_err());

        for k in 0..statement.len() {
            let mut changed = statement.clone();
            changed[k] += F::ONE;
            assert!(
                root.verifier().verify(&proof, &changed).is_err(),
                "root field {k}"
            );
        }
        // A binary parent cannot accept a child with a spliced full statement.
        let mut changed = left.clone();
        changed[ACC_FEE] += F::ONE;
        assert!(
            root.prove(
                Input::Batch(&pleft, &changed),
                Input::Batch(&pright, &right),
                Some(&note)
            )
            .is_err()
        );
        let mut spliced = inputs[..8].to_vec();
        spliced[0] = Input::Uni(&leaves[0].0, &leaves[1].1, &witnesses[1].anchor_path);
        assert!(batch.prove(&spliced).is_err());
        let mut path = witnesses[0].anchor_path.clone();
        path[0].0[0] += F::ONE;
        spliced[0] = Input::Uni(&leaves[0].0, &leaves[0].1, &path);
        assert!(batch.prove(&spliced).is_err());
        // Multiplicity is bound by the statement; native slot/nullifier checks
        // remain necessary, as with the binary relation.
        let mut repeated = inputs[..8].to_vec();
        repeated[1] = repeated[0];
        let repeated_proof = batch.prove(&repeated).unwrap();
        assert!(
            verifier
                .verify(&repeated_proof, &node_digest(&left))
                .is_err()
        );
        // Eight individually valid 2^61 fees overflow u64 only at the final
        // addition. The checked carry chain must reject that eighth child.
        let mut expensive = sample_slot(999, true);
        expensive.inputs[0].value = 1 << 62;
        expensive.outputs[0].value = 0;
        expensive.outputs[1].value = 1 << 61;
        expensive.fee = 1 << 61;
        let expensive = with_unlock_heights(expensive, [0, 0]);
        let (high_witnesses, high_root) = acc_witnesses(vec![expensive], 1000, 1 << 61, 31);
        high_witnesses[0].check(&Hasher::new(), &high_root).unwrap();
        let high_leaf = prover.prove_acc(&high_witnesses[0]);
        prover.verify(&high_leaf.0, &high_leaf.1).unwrap();
        let high_input = Input::Uni(&high_leaf.0, &high_leaf.1, &high_witnesses[0].anchor_path);
        assert!(batch.prove(&[high_input; FAN_IN]).is_err());
        let binary =
            AccAggregation::new(Child::Uni(prover), inputs[0], &fri.config(), &params, false)
                .unwrap();
        let binary_proof = binary.prove(inputs[0], inputs[1], None).unwrap();
        assert!(verifier.verify(&binary_proof, &node_digest(&left)).is_err());
    }
}
