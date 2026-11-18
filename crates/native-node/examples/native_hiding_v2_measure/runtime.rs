//! Manual sealed-genesis facade measurements; no network or mining entry point.
use super::*;
use native::codec::{ProofContext, PublicTransaction, encode_digest};
use native::encryption::{ChangeCiphertext, PaymentCiphertext};
use siworld_native_node::{
    eng2::genesis::{FeeMode, Genesis},
    eng2_governance::GovernanceState,
    issuance::IssuanceRecord,
    proofs::{NativeProver, NativeVerifier},
    state::Config as ChainConfig,
    wallet::WalletKeys,
};

fn genesis(network: [u8; 32], work_bits: u8) -> Result<Genesis> {
    let config = ChainConfig::development(network, work_bits)?;
    let address = |seed| {
        WalletKeys::from_seed(network, zeroize::Zeroizing::new([seed; 32]), 0)
            .map(|keys| keys.address())
    };
    let key = |seed| {
        *libcrux_ml_dsa::ml_dsa_65::generate_key_pair([seed; 32])
            .verification_key
            .as_ref()
    };
    let governance = GovernanceState::new(
        network,
        key(1),
        key(2),
        [3, 4, 5].map(key),
        address(30)?,
        vec![address(31)?, address(32)?],
    )?;
    Genesis::seal(config, governance, FeeMode::LegacyMiner)
}
fn public_transaction(witness: &AccWitness) -> PublicTransaction {
    let public = witness.slot.public_inputs(&Hasher::new());
    let change = ChangeCiphertext {
        nonce: [0; 12],
        body: [0; 208],
        tag: [0; 16],
        view_tag: 0,
    };
    PublicTransaction {
        nf: public.nf,
        cm: public.cm_out,
        payment: PaymentCiphertext {
            kem_ciphertext: [0; 1088],
            body: [0; 208],
            tag: [0; 16],
            view_tag: 0,
        },
        change: [change.clone(), change],
    }
}
fn transaction_context(network: [u8; 32]) -> ProofContext {
    ProofContext::for_snapshot(network, SNAPSHOT_HEIGHT, [0x29; 32])
}
fn issuance_record(context: &Value, frame: &[u8]) -> Result<IssuanceRecord> {
    let (signed, ciphertexts, _) = issuance_statement(context)?;
    Ok(IssuanceRecord {
        signed,
        ciphertexts,
        proof: frame.to_vec(),
        fee_commitment: encode_digest(&digest(&context["fee_commitment"])?),
        fee_rho: encode_digest(&digest(&context["fee_rho"])?),
    })
}
fn settlement_parts(context: &Value) -> Result<(Vec<Digest>, RewardPlan, [Digest; 5])> {
    let fees = array(&context["fees"], SETTLEMENT_CAPACITY)?
        .iter()
        .map(digest)
        .collect::<Result<Vec<_>>>()?;
    let allocations = array(&context["allocations"], 5)?
        .iter()
        .map(|entry| {
            Ok(RewardAllocation {
                amount: number(&entry["amount"])?,
                unlock_height: number(&entry["unlock_height"])?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if number(&context["mode"])? != RewardMode::Holder as u64 {
        return Err("runtime measurement requires retained Holder settlement".into());
    }
    Ok((
        fees,
        RewardPlan {
            block_height: number(&context["height"])?,
            mode: RewardMode::Holder,
            allocations,
        },
        digests(&context["reward_commitments"])?,
    ))
}
fn verify_frame(
    verifier: &NativeVerifier,
    family: Family,
    context: &Value,
    frame: &[u8],
) -> Result<()> {
    match family {
        Family::Transaction => {
            let public = PublicTransaction::decode(&unhex(
                string(&context["public_transaction"])?,
                native::codec::PUBLIC_TRANSACTION_BYTES,
            )?)
            .map_err(|_| "invalid runtime public transaction")?;
            let proof_context = ProofContext::for_snapshot(
                bytes(&context["network"])?,
                number(&context["snapshot_height"])?,
                bytes(&context["snapshot_id"])?,
            );
            verifier.verify_transaction(
                &public,
                &proof_context,
                &digest(&context["fee_commitment"])?,
                &digest(&context["recent_roots_root"])?,
                frame,
            )
        }
        Family::Settlement => {
            let (fees, plan, rewards) = settlement_parts(context)?;
            verifier.verify_settlement(
                &fees,
                &plan,
                bytes(&context["network"])?,
                bytes(&context["list_digest"])?,
                &rewards,
                frame,
            )
        }
        Family::Issuance => verifier.verify_issuance(&issuance_record(context, frame)?),
    }
}
pub(super) fn measure_pair(family: Family, output: &Path) -> Result<()> {
    fs::create_dir(output).map_err(|_| "use a new runtime pair directory")?;
    let selected = genesis([9; 32], 0)?;
    // Construct the private witness and all public bytes exactly once.
    let mut fixture = Fixture::new(family);
    if let Fixture::Settlement(witness) = &mut fixture {
        witness.network = selected.config().network;
    }
    let context = match &fixture {
        Fixture::Transaction(witness) => {
            let public = public_transaction(witness);
            let bound = transaction_context(selected.config().network);
            let fee = witness.slot.public_inputs(&Hasher::new()).fee_commit;
            json!({"network":hex(&selected.config().network),
                "public_transaction":hex(&public.encode()),"snapshot_height":SNAPSHOT_HEIGHT,
                "snapshot_id":hex(&bound.snapshot().ok_or("missing fixture snapshot")?.1),
                "fee_commitment":public_digest(&fee),
                "recent_roots_root":public_digest(&witness.anchors_root(&Hasher::new()))})
        }
        Fixture::Settlement(witness) => settlement_context(witness),
        Fixture::Issuance(signed, witness, policy) => {
            let mut context = issuance_context(signed, &witness.ciphertexts, *policy)?;
            context["fee_commitment"] = json!(public_digest(&[F::ZERO; 12]));
            context["fee_rho"] = json!(public_digest(&[F::ZERO; 12]));
            context
        }
    };
    let mut times = BTreeMap::new();
    let prover = phase(family, "runtime_public_setup", &mut times, || {
        NativeProver::for_genesis(&selected)
    })?;
    for attempt in ["first", "second"] {
        let directory = output.join(attempt);
        fs::create_dir(&directory).map_err(|_| "cannot create runtime attempt directory")?;
        let frame = phase(family, attempt, &mut times, || match &fixture {
            Fixture::Transaction(witness) => prover.transaction(
                witness,
                &public_transaction(witness),
                &transaction_context(selected.config().network),
            ),
            Fixture::Settlement(witness) => prover.settlement(witness),
            Fixture::Issuance(_, witness, _) => prover.issuance(witness),
        })?;
        let manifest = json!({"schema":2,"relation":family.name(),
            "genesis_bytes":hex(&selected.encode()?),"profile":hex(&selected.encode()?[9..41]),
            "binding":{"genesis":hex(&selected.id()),"rules":hex(&selected.rules_commitment())},
            "public_context":context,"proof_bytes":frame.len(),"proof_sha256":hex(&sha(&frame)),
            "frame_limit":family.limit(),"source_commit":option_env!("SIWORLD_SOURCE_COMMIT")});
        write_new(&directory.join("proof.frame"), &frame)?;
        write_new(
            &directory.join("public-manifest.json"),
            &serde_json::to_vec_pretty(&manifest)
                .map_err(|_| "runtime manifest encoding failed")?,
        )?;
    }
    drop(prover);
    drop(fixture);
    let (_, hashes) = pair_manifests(output)?;
    let report = json!({"status":"runtime_facade_pair_generated","relation":family.name(),
        "public_manifest_sha256":hashes,"phase_wall_microseconds":times,
        "fresh_process_verification":false,"same_witness_and_public_context":true,
        "zero_knowledge_qualified":false,"network_activation":false});
    write_new(
        &output.join("pair.json"),
        &serde_json::to_vec_pretty(&report).map_err(|_| "runtime report encoding failed")?,
    )?;
    println!("{report}");
    Ok(())
}
pub(super) fn verify_pair(input: &Path, first: &str, second: &str) -> Result<()> {
    let (manifests, hashes) = pair_manifests(input)?;
    if hashes != [first, second] {
        return Err("trusted runtime manifest hashes mismatch".into());
    }
    let mut all_times = Vec::new();
    for (name, manifest) in ["first", "second"].into_iter().zip(manifests) {
        if number(&manifest["schema"])? != 2 {
            return Err("unsupported runtime measurement schema".into());
        }
        let family = Family::parse(string(&manifest["relation"])?)?;
        let selected = Genesis::decode(&unhex(string(&manifest["genesis_bytes"])?, 262_144)?)?;
        if bytes::<32>(&manifest["binding"]["genesis"])? != selected.id()
            || bytes::<32>(&manifest["binding"]["rules"])? != selected.rules_commitment()
            || bytes::<32>(&manifest["profile"])? != selected.encode()?[9..41]
            || number(&manifest["frame_limit"])? != family.limit() as u64
        {
            return Err("runtime genesis/profile binding differs".into());
        }
        let frame = read_bounded(&input.join(name).join("proof.frame"), family.limit())?;
        if bytes::<32>(&manifest["proof_sha256"])? != sha(&frame)
            || number(&manifest["proof_bytes"])? != frame.len() as u64
        {
            return Err("runtime frame binding differs".into());
        }
        let context = &manifest["public_context"];
        let mut times = BTreeMap::new();
        let verifier = phase(family, "runtime_public_setup_rebuilt", &mut times, || {
            NativeVerifier::for_genesis(&selected)
        })?;
        phase(family, "runtime_verify", &mut times, || {
            verify_frame(&verifier, family, context, &frame)
        })?;
        let reject = |result: Result<()>| {
            if result.is_err() {
                Ok(())
            } else {
                Err("runtime negative case accepted".into())
            }
        };
        phase(family, "reject_changed_public", &mut times, || {
            let mut changed = context.clone();
            match family {
                Family::Transaction => {
                    changed["fee_commitment"][0] = json!(
                        (number(&changed["fee_commitment"][0])? + 1) % u64::from(F::ORDER_U32)
                    )
                }
                Family::Settlement => {
                    let mut hash = bytes::<32>(&changed["list_digest"])?;
                    hash[0] ^= 1;
                    changed["list_digest"] = json!(hex(&hash));
                }
                Family::Issuance => changed["supply"] = json!(number(&changed["supply"])? + 1),
            }
            reject(verify_frame(&verifier, family, &changed, &frame))
        })?;
        for (case, network, bits) in [
            ("reject_wrong_genesis_rules", [9; 32], 1),
            ("reject_wrong_network", [8; 32], 0),
        ] {
            phase(family, case, &mut times, || {
                let other = genesis(network, bits)?;
                let wrong = NativeVerifier::for_genesis(&other)?;
                reject(verify_frame(&wrong, family, context, &frame))
            })?;
        }
        phase(
            family,
            "reject_reframed_wrong_genesis_rules",
            &mut times,
            || {
                let other = genesis([9; 32], 1)?;
                let wrong = NativeVerifier::for_genesis(&other)?;
                let identity = wrong.proof_identity(family.relation())?;
                let reframed = siworld_native_node::proof_codec::v2::encode(
                    identity,
                    &frame[siworld_native_node::proof_codec::v2::FRAME_BYTES..],
                    family.limit(),
                )
                .map_err(|_| "target-domain reframing failed")?;
                siworld_native_node::proof_codec::v2::parse(&reframed, identity, family.limit())
                    .map_err(|_| "target-domain outer frame rejected before cryptography")?;
                let expected = match family {
                    Family::Transaction => "native transaction proof verification failed",
                    Family::Settlement => "native settlement proof verification failed",
                    Family::Issuance => "native issuance proof verification failed",
                };
                match verify_frame(&wrong, family, context, &reframed) {
                    Err(error) if error == expected => Ok(()),
                    _ => Err(
                        "correct target-domain header did not reach cryptographic rejection".into(),
                    ),
                }
            },
        )?;
        phase(family, "reject_malformed_frames", &mut times, || {
            let mut changed = frame.clone();
            changed[12] ^= 1;
            reject(verify_frame(&verifier, family, context, &changed))?;
            reject(verify_frame(
                &verifier,
                family,
                context,
                &frame[..frame.len() - 1],
            ))?;
            let mut changed = frame.clone();
            changed.push(0);
            reject(verify_frame(&verifier, family, context, &changed))
        })?;
        all_times.push(times);
    }
    println!(
        "{}",
        json!({"status":"runtime_facade_public_pair_verified",
        "public_manifest_sha256":hashes,"public_preprocessing_rebuilt":true,
        "phase_wall_microseconds":all_times,"witness_generation":false,
        "negative_checks_per_frame":["changed_public","wrong_genesis_rules","reframed_wrong_genesis_rules","wrong_network","wrong_identity","truncated","trailing"],
        "zero_knowledge_qualified":false,"network_activation":false})
    );
    Ok(())
}
