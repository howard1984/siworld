//! Explicit native-fixture checks for unchanged-head prevalidation and replay.

use super::*;
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf, time::Duration};

struct NativePreviewFixture {
    store: Store,
    verifier: NativeVerifier,
    records: Vec<(Header, Body)>,
    genesis_bytes: Vec<u8>,
    destination: PathBuf,
    limits: Limits,
}
impl NativePreviewFixture {
    fn existing_three_blocks() -> Self {
        assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
        let source = PathBuf::from(
            std::env::var_os("SIWORLD_REORG_NATIVE_SOURCE").expect("explicit source required"),
        );
        let destination = PathBuf::from(
            std::env::var_os("SIWORLD_REORG_NATIVE_DESTINATION")
                .expect("fresh disposable destination required"),
        );
        assert!(source.is_absolute() && destination.is_absolute() && !destination.exists());
        assert!(source.join("disposable-fixture").is_file());
        assert!(!destination.starts_with(&source));
        let genesis_bytes = fs::read(source.join("genesis.bin")).unwrap();
        let genesis = || Genesis::decode(&genesis_bytes).unwrap();
        assert!(genesis().config().fixture);
        assert_eq!(genesis().config().genesis_target, [0xff; 32]);
        assert_eq!(genesis().config().pow_iterations, 0);
        let limits = Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        };
        let engine = Engine::new(genesis(), limits).unwrap();
        let records = {
            let database = redb::ReadOnlyDatabase::open(source.join("chain.redb")).unwrap();
            let transaction = database.begin_read().unwrap();
            let table = transaction.open_table(BLOCKS).unwrap();
            (1..=3)
                .map(|height| {
                    let row = table
                        .get(height)
                        .unwrap()
                        .expect("three native blocks required");
                    assert!(
                        row.value().len() <= HEADER_BYTES + engine.body_policy().max_body_bytes
                    );
                    decode(&engine, row.value()).unwrap()
                })
                .collect::<Vec<_>>()
        };
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&destination)
            .unwrap();
        fs::write(destination.join("genesis.bin"), &genesis_bytes).unwrap();
        fs::set_permissions(
            destination.join("genesis.bin"),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        let identity =
            crate::identity::NativeIdentity::initialize(&destination, genesis().peer_binding())
                .unwrap();
        let mut store = Store::create(&destination.join("chain.redb"), genesis(), limits).unwrap();
        store.enable_authenticated_restart(identity).unwrap();
        let verifier = NativeVerifier::new().unwrap();
        for (header, body) in &records {
            store.append(header, body, &verifier).unwrap();
        }
        Self {
            store,
            verifier,
            records,
            genesis_bytes,
            destination,
            limits,
        }
    }
}

fn ids(records: &[(Header, Body)]) -> Vec<Hash> {
    records
        .iter()
        .map(|(header, _)| header.id().unwrap())
        .collect()
}
fn budget() -> ReplacementBudget {
    ReplacementBudget {
        max_blocks: 64,
        max_body_bytes: 256 * 1024 * 1024,
        max_elapsed: Duration::from_secs(60),
    }
}
fn unchanged(store: &Store, original_tip: Hash, original_points: &[RollbackPoint]) {
    assert_eq!(store.engine().state().height(), 3);
    assert_eq!(store.engine().state().tip(), original_tip);
    assert_eq!(store.rollback_points().unwrap(), original_points);
    store.ensure_exportable().unwrap();
    let transaction = store.database.begin_write().unwrap();
    let restored = restoration::verify(
        &transaction,
        store.engine().genesis(),
        store.engine().limits(),
        &store.restart.as_ref().unwrap().identity,
        *original_points
            .iter()
            .find(|point| point.height == 3)
            .unwrap(),
        store.imported_prefix,
        store.import_seed,
    )
    .unwrap();
    transaction.abort().unwrap();
    let binding = super::super::state_components::Binding {
        genesis: store.engine().genesis().id(),
        rules_commitment: store.engine().genesis().rules_commitment(),
        parent: store.compact(3).unwrap().0.parent,
    };
    assert_eq!(
        restored
            .engine
            .state()
            .canonical_components(binding, store.engine().limits())
            .unwrap(),
        store
            .engine()
            .state()
            .canonical_components(binding, store.engine().limits())
            .unwrap(),
    );
}

#[test]
#[ignore = "requires explicit disposable complete native fixture and fresh destination"]
fn real_native_prevalidation_preserves_original_and_binds_replay() {
    let NativePreviewFixture {
        mut store,
        verifier,
        records,
        genesis_bytes,
        destination,
        limits,
    } = NativePreviewFixture::existing_three_blocks();
    let ancestor = records[0].0.id().unwrap();
    let original_tip = store.engine().state().tip();
    let original_points = store.rollback_points().unwrap();
    let replacement = &records[1..];
    let expected_ids = ids(replacement);
    let mut native_prevalidated = 0;

    for restricted in [
        ReplacementBudget {
            max_blocks: 1,
            ..budget()
        },
        ReplacementBudget {
            max_body_bytes: 1,
            ..budget()
        },
        ReplacementBudget {
            max_elapsed: Duration::ZERO,
            ..budget()
        },
        ReplacementBudget {
            max_elapsed: Duration::from_nanos(1),
            ..budget()
        },
    ] {
        let failure = store
            .prevalidate_replacement(1, ancestor, &expected_ids, restricted, &verifier, |index| {
                Ok(replacement[index].clone())
            })
            .err()
            .unwrap();
        assert!(matches!(failure, ReplacementFailure::Deferred(_)));
        unchanged(&store, original_tip, &original_points);
    }
    let unavailable = store
        .prevalidate_replacement(1, ancestor, &expected_ids, budget(), &verifier, |_| {
            Err("fixture material unavailable".into())
        })
        .err()
        .unwrap();
    assert_eq!(
        unavailable,
        ReplacementFailure::Deferred("fixture material unavailable".into())
    );
    unchanged(&store, original_tip, &original_points);

    // The last block is deterministically invalid only after its complete
    // native proofs and preceding replacement block have been verified.
    let mut invalid = replacement.to_vec();
    invalid[1].0.execution_commitment[0] ^= 1;
    let rejected = store
        .prevalidate_replacement(1, ancestor, &ids(&invalid), budget(), &verifier, |index| {
            Ok(invalid[index].clone())
        })
        .err()
        .unwrap();
    assert_eq!(
        rejected,
        ReplacementFailure::Rejected {
            index: 1,
            reason: "native execution commitment differs from complete checked state".into(),
        }
    );
    unchanged(&store, original_tip, &original_points);

    let prepared = store
        .prevalidate_replacement(1, ancestor, &expected_ids, budget(), &verifier, |index| {
            Ok(replacement[index].clone())
        })
        .unwrap();
    native_prevalidated += prepared.len();
    assert_eq!(prepared.ancestor(), (1, ancestor));
    assert_eq!(prepared.tip(), original_tip);
    assert_eq!(
        prepared.cumulative_work(),
        store.engine().state().chain().cumulative_work
    );
    unchanged(&store, original_tip, &original_points);
    let proof_changed = store
        .begin_prevalidated_replacement(prepared, |index| {
            let (header, mut body) = replacement[index].clone();
            if index == 1 {
                let last = body.settlement_proof.len() - 1;
                body.settlement_proof[last] ^= 1;
            }
            Ok((header, body))
        })
        .err()
        .unwrap();
    assert_eq!(
        proof_changed,
        ReplacementFailure::Deferred("prevalidated replacement material changed".into(),)
    );
    unchanged(&store, original_tip, &original_points);

    let prepared = store
        .prevalidate_replacement(1, ancestor, &expected_ids, budget(), &verifier, |index| {
            Ok(replacement[index].clone())
        })
        .unwrap();
    native_prevalidated += prepared.len();
    // Returning to the exact same height and hash must not revive a capability
    // issued before restoration: the in-process canonical generation changed.
    store.restore_ancestor(1, ancestor).unwrap();
    for (header, body) in replacement {
        store.append(header, body, &verifier).unwrap();
    }
    assert_eq!(store.engine().state().tip(), original_tip);
    let generation_changed = store
        .begin_prevalidated_replacement(prepared, |_| {
            panic!("a stale generation must be rejected before loading material")
        })
        .err()
        .unwrap();
    assert_eq!(
        generation_changed,
        ReplacementFailure::Deferred("prevalidated canonical generation changed".into(),)
    );
    let current_points = store.rollback_points().unwrap();
    unchanged(&store, original_tip, &current_points);

    let prepared = store
        .prevalidate_replacement(1, ancestor, &expected_ids, budget(), &verifier, |index| {
            Ok(replacement[index].clone())
        })
        .unwrap();
    native_prevalidated += prepared.len();
    drop(store);
    let path = destination.join("chain.redb");
    let mut store =
        Store::resume_existing(&path, Genesis::decode(&genesis_bytes).unwrap(), limits).unwrap();
    let instance_changed = store
        .begin_prevalidated_replacement(prepared, |_| {
            panic!("a capability cannot cross store instances or process reopen")
        })
        .err()
        .unwrap();
    assert_eq!(
        instance_changed,
        ReplacementFailure::Deferred("prevalidated canonical generation changed".into(),)
    );
    unchanged(&store, original_tip, &current_points);

    // Change only the final nonce at minimum difficulty, with zero PoW rounds.
    // This creates a distinct valid terminal header without proving or mining.
    let mut candidate = replacement.to_vec();
    candidate[1].0.nonce = candidate[1].0.nonce.checked_add(1).unwrap();
    let final_tip = candidate[1].0.id().unwrap();
    assert_ne!(final_tip, original_tip);
    let prepared = store
        .prevalidate_replacement(
            1,
            ancestor,
            &ids(&candidate),
            budget(),
            &verifier,
            |index| Ok(candidate[index].clone()),
        )
        .unwrap();
    native_prevalidated += prepared.len();
    unchanged(&store, original_tip, &current_points);
    let mut replay = store
        .begin_prevalidated_replacement(prepared, |index| Ok(candidate[index].clone()))
        .unwrap();
    assert_eq!(store.engine().state().height(), 1);
    assert_eq!(replay.next_index(), 0);
    assert!(!replay.is_complete());
    let out_of_order = store
        .append_prevalidated(&mut replay, &candidate[1].0, &candidate[1].1, &verifier)
        .err()
        .unwrap();
    assert!(matches!(out_of_order, ReplacementFailure::Deferred(_)));
    assert_eq!(store.engine().state().height(), 1);
    assert_eq!(replay.next_index(), 0);
    for (index, (header, body)) in candidate.iter().enumerate() {
        store
            .append_prevalidated(&mut replay, header, body, &verifier)
            .unwrap();
        assert_eq!(replay.next_index(), index + 1);
    }
    assert!(replay.is_complete());
    assert_eq!(replay.tip(), final_tip);
    assert_eq!(store.engine().state().tip(), final_tip);
    let binding = super::super::state_components::Binding {
        genesis: store.engine().genesis().id(),
        rules_commitment: store.engine().genesis().rules_commitment(),
        parent: candidate[1].0.parent,
    };
    let final_components = store
        .engine()
        .state()
        .canonical_components(binding, limits)
        .unwrap();
    assert_eq!(
        store
            .engine()
            .state()
            .execution_commitment(binding, limits)
            .unwrap(),
        candidate[1].0.execution_commitment,
    );
    drop(store);
    let resumed =
        Store::resume_existing(&path, Genesis::decode(&genesis_bytes).unwrap(), limits).unwrap();
    assert_eq!(resumed.engine().state().tip(), final_tip);
    assert_eq!(
        resumed
            .engine()
            .state()
            .canonical_components(binding, limits)
            .unwrap(),
        final_components,
    );
    let result = serde_json::json!({
        "scope":"existing-native-three-block-prevalidation-and-bound-replay",
        "native_successfully_prevalidated_blocks":native_prevalidated,
        "native_verified_canonical_appends":7,
        "late_execution_root_rejected_before_restore":true,
        "preview_keeps_canonical_head_and_savepoints":true,
        "local_budgets_defer":true,
        "missing_material_defers":true,
        "proof_mutation_rejected_before_restore":true,
        "aba_generation_rejected":true,
        "reopened_instance_rejected":true,
        "bound_replay_and_authenticated_reopen":true,
        "old_chain_depth":2,
        "replacement_blocks":2,
        "replacement_longer_than_24_executed":false,
        "deadline_is_hard_verifier_termination":false,
        "source_modified":false,
        "proof_generation":false,
        "mining":false,
        "g2":false,
    });
    fs::write(
        destination.join("result.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!("{result}");
}
