use super::super::backend::PublicPreprocessing;
use super::*;
use p3_air::BaseAir;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{BatchMultiOpening, CommitPhaseMultiStep, FriProof};
use p3_merkle_tree::PrunedMerklePaths;
use p3_symmetric::MerkleCap;
use p3_uni_stark::{Commitments, OpenedValues, PreprocessedOpenedValues};

fn shape<A: Air<SymbolicAirBuilder<F>>>(
    air: &A,
    degree_bits: usize,
    profile: Profile,
    relation: Relation,
) -> NativeProofShape {
    // A synthetic key authenticates no network. It supplies only the public
    // dimensions needed to test exact encoding and structural bounds.
    let key = PreprocessedVerifierKey {
        width: air.preprocessed_width(),
        degree_bits,
        commitment: MerkleCap::new(vec![[F::ZERO; 12]; 2]),
    };
    let public = PublicPreprocessing::new(profile);
    let limit = if relation == Relation::Issuance {
        524_288
    } else {
        super::super::MAX_PROOF_BYTES
    };
    NativeProofShape::from_trusted(
        air,
        &key,
        public.config(),
        profile,
        relation,
        ProtocolBinding {
            genesis: [1; 32],
            rules: [2; 32],
            air: [3; 32],
        },
        limit,
    )
    .unwrap()
}

/// A zero-filled structural container, never a cryptographically valid proof.
fn container(schema: &ProofShape, maximum_paths: bool) -> Proof<Config> {
    let cap = |n| MerkleCap::new(vec![[F::ZERO; 12]; n]);
    let salts = |n| vec![vec![vec![F::ZERO; SALTS]; n]; schema.num_queries];
    let paths = |n| PrunedMerklePaths {
        sibling_hashes: vec![[F::ZERO; 12]; if maximum_paths { n } else { 0 }],
    };
    let zero = Challenge::ZERO;
    Proof {
        commitments: Commitments {
            trace: cap(schema.input_cap_roots),
            quotient_chunks: cap(schema.input_cap_roots),
            random: Some(cap(schema.input_cap_roots)),
        },
        opened_values: OpenedValues {
            trace_local: vec![zero; schema.main_width],
            trace_next: schema.main_next.then(|| vec![zero; schema.main_width]),
            preprocessed: Some(PreprocessedOpenedValues {
                local: vec![zero; schema.preprocessed_width],
                next: schema
                    .preprocessed_next
                    .then(|| vec![zero; schema.preprocessed_width]),
            }),
            quotient_chunks: vec![vec![zero; EXTENSION_DEGREE]; schema.quotient_chunks],
            random: Some(vec![zero; EXTENSION_DEGREE]),
        },
        opening_proof: (
            schema
                .rounds
                .iter()
                .map(|r| vec![vec![vec![zero; r.random_values]; r.points]; r.matrices])
                .collect(),
            FriProof {
                batch_pow_witness: F::ZERO,
                commit_phase_commits: schema.folds.iter().map(|f| cap(f.cap_roots)).collect(),
                commit_pow_witnesses: vec![F::ZERO; schema.folds.len()],
                input_openings: schema
                    .rounds
                    .iter()
                    .map(|r| BatchMultiOpening {
                        opened_values: vec![
                            vec![vec![F::ZERO; r.width]; r.matrices];
                            schema.num_queries
                        ],
                        opening_proof: (salts(r.matrices), paths(schema.input_path_hashes)),
                    })
                    .collect(),
                commit_phase_openings: schema
                    .folds
                    .iter()
                    .map(|f| CommitPhaseMultiStep {
                        sibling_values: vec![vec![zero; f.siblings]; schema.num_queries],
                        opening_proof: (salts(1), paths(f.path_hashes)),
                    })
                    .collect(),
                final_poly: vec![zero; schema.final_poly_len],
                query_pow_witness: F::ZERO,
            },
        ),
        degree_bits: schema.degree_bits,
        ood_pow_witness: F::ZERO,
    }
}

fn without_salts(proof: Proof<Config>) -> Proof<native::Cfg> {
    let (random_values, fri) = proof.opening_proof;
    Proof {
        commitments: proof.commitments,
        opened_values: proof.opened_values,
        opening_proof: (
            random_values,
            FriProof {
                batch_pow_witness: fri.batch_pow_witness,
                commit_phase_commits: fri.commit_phase_commits,
                commit_pow_witnesses: fri.commit_pow_witnesses,
                input_openings: fri
                    .input_openings
                    .into_iter()
                    .map(|opening| BatchMultiOpening {
                        opened_values: opening.opened_values,
                        opening_proof: opening.opening_proof.1,
                    })
                    .collect(),
                commit_phase_openings: fri
                    .commit_phase_openings
                    .into_iter()
                    .map(|opening| CommitPhaseMultiStep {
                        sibling_values: opening.sibling_values,
                        opening_proof: opening.opening_proof.1,
                    })
                    .collect(),
                final_poly: fri.final_poly,
                query_pow_witness: fri.query_pow_witness,
            },
        ),
        degree_bits: proof.degree_bits,
        ood_pow_witness: proof.ood_pow_witness,
    }
}

#[test]
fn native_relation_structural_maxima_match_typed_postcard_sizes_and_fit() {
    use native::{
        issuance_air::IssuanceAir, multi_asset_transaction::TransactionAir,
        settlement::SettlementAir,
    };
    let transaction =
        TransactionAir::new().with_min_height(Profile::transaction().minimum_height());
    let settlement =
        SettlementAir::new(576).with_min_height(Profile::settlement().minimum_height());
    let issuance = IssuanceAir::new(3).with_min_height(Profile::issuance().minimum_height());
    let shapes = [
        shape(
            &transaction,
            transaction.degree_bits() + 1,
            Profile::transaction(),
            Relation::Transaction,
        ),
        shape(
            &settlement,
            settlement.degree_bits() + 1,
            Profile::settlement(),
            Relation::Settlement,
        ),
        shape(
            &issuance,
            issuance.degree_bits() + 1,
            Profile::issuance(),
            Relation::Issuance,
        ),
    ];
    for shape in shapes {
        let bound = shape.maximum_frame_bytes().unwrap();
        for maximum in [false, true] {
            let proof = container(&shape.schema, maximum);
            let frame = shape.encode(&proof).unwrap();
            assert_eq!(
                frame.len(),
                postcard::experimental::serialized_size(&proof).unwrap() + FRAME_BYTES
            );
            assert!(frame.len() <= bound);
            assert!(shape.decode(&frame).is_ok());
            if maximum {
                assert_eq!(frame.len(), bound);
            }
        }
        println!(
            "native V2 {:?} complete structural frame bound: {}",
            shape.identity.relation, bound
        );
        let unsalted = without_salts(container(&shape.schema, true));
        let retained_body = postcard::experimental::serialized_size(&unsalted).unwrap();
        println!(
            "same geometry unsalted body: {}; added salt encoding: {}; new frame overhead: {}",
            retained_body,
            bound - FRAME_BYTES - retained_body,
            FRAME_BYTES
        );
        assert!(bound <= shape.frame_limit);
    }
}

#[test]
fn salt_lengths_are_checked_before_typed_decoding() {
    let air = native::multi_asset_transaction::TransactionAir::new()
        .with_min_height(Profile::transaction().minimum_height());
    let shape = shape(
        &air,
        air.degree_bits() + 1,
        Profile::transaction(),
        Relation::Transaction,
    );
    for fri in [false, true] {
        for length in [0, SALTS - 1, SALTS + 1] {
            let mut proof = container(&shape.schema, false);
            if fri {
                proof.opening_proof.1.commit_phase_openings[0]
                    .opening_proof
                    .0[0][0]
                    .resize(length, F::ZERO);
            } else {
                proof.opening_proof.1.input_openings[0].opening_proof.0[0][0]
                    .resize(length, F::ZERO);
            }
            let body = postcard::to_allocvec(&proof).unwrap();
            let frame = super::super::encode(shape.identity, &body, shape.frame_limit).unwrap();
            assert!(matches!(
                shape.decode(&frame),
                Err(DecodeError::Body(ProofDecodeError::Shape("salt_elements")))
            ));
        }
    }
}

#[test]
fn frame_identity_binds_protocol_backend_air_key_and_codec_shape() {
    let air = native::multi_asset_transaction::TransactionAir::new()
        .with_min_height(Profile::transaction().minimum_height());
    let profile = Profile::transaction();
    let shape = shape(&air, air.degree_bits() + 1, profile, Relation::Transaction);
    let key = PreprocessedVerifierKey {
        width: air.preprocessed_width(),
        degree_bits: shape.schema.degree_bits,
        commitment: MerkleCap::new(vec![[F::ZERO; 12]; 2]),
    };
    let binding = ProtocolBinding {
        genesis: [1; 32],
        rules: [2; 32],
        air: [3; 32],
    };
    let bind =
        |relation, binding, profile, key: &PreprocessedVerifierKey<Config>, schema: &ProofShape| {
            bind_identity(relation, binding, profile, key, schema).unwrap()
        };
    let expected = bind(Relation::Transaction, binding, profile, &key, &shape.schema);
    assert_eq!(expected, shape.identity);
    for changed in [
        ProtocolBinding {
            genesis: [4; 32],
            ..binding
        },
        ProtocolBinding {
            rules: [4; 32],
            ..binding
        },
        ProtocolBinding {
            air: [4; 32],
            ..binding
        },
    ] {
        assert_ne!(
            expected,
            bind(Relation::Transaction, changed, profile, &key, &shape.schema)
        );
    }
    assert_ne!(
        expected,
        bind(Relation::Settlement, binding, profile, &key, &shape.schema)
    );
    assert_ne!(
        expected,
        bind(
            Relation::Transaction,
            binding,
            Profile::settlement(),
            &key,
            &shape.schema
        )
    );
    let mut changed_key = key.clone();
    changed_key.width += 1;
    assert_ne!(
        expected,
        bind(
            Relation::Transaction,
            binding,
            profile,
            &changed_key,
            &shape.schema
        )
    );
    changed_key = key.clone();
    changed_key.degree_bits += 1;
    assert_ne!(
        expected,
        bind(
            Relation::Transaction,
            binding,
            profile,
            &changed_key,
            &shape.schema
        )
    );
    changed_key = key.clone();
    changed_key.commitment = MerkleCap::new(vec![[F::ONE; 12]; 2]);
    assert_ne!(
        expected,
        bind(
            Relation::Transaction,
            binding,
            profile,
            &changed_key,
            &shape.schema
        )
    );
    let mut changed_schema = shape.schema.clone();
    changed_schema.body_limit -= 1;
    assert_ne!(
        expected,
        bind(
            Relation::Transaction,
            binding,
            profile,
            &key,
            &changed_schema
        )
    );
}

#[test]
fn pruned_frontier_bound_matches_every_small_binary_tree_query_set() {
    for height in 0..=4 {
        let leaves = 1usize << height;
        for cap in 0..=height {
            let mut exact_by_count = vec![0usize; leaves + 1];
            for subset in 0u64..(1u64 << leaves) {
                let mut nodes = subset;
                let mut width = leaves;
                let mut hashes = 0usize;
                for _ in 0..height - cap {
                    let mut parents = 0u64;
                    for index in 0..width {
                        if nodes & (1u64 << index) != 0 {
                            hashes += usize::from(nodes & (1u64 << (index ^ 1)) == 0);
                            parents |= 1u64 << (index / 2);
                        }
                    }
                    nodes = parents;
                    width /= 2;
                }
                let count = subset.count_ones() as usize;
                exact_by_count[count] = exact_by_count[count].max(hashes);
            }
            let mut maximum = 0;
            for (queries, exact) in exact_by_count.into_iter().enumerate() {
                maximum = maximum.max(exact);
                assert_eq!(
                    maximum_pruned_hashes(height, cap, queries).unwrap(),
                    maximum
                );
            }
        }
    }
}
