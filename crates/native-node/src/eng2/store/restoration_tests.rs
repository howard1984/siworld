//! Owner-operated reconstruction using existing complete native block bytes.

use super::*;
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf, time::Instant};

#[test]
#[ignore = "requires explicit disposable complete native fixture and fresh destination"]
fn real_native_ancestor_restore_append_and_original_replay() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_REORG_NATIVE_SOURCE").expect("explicit native source required"),
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
    let policy = Engine::new(
        genesis(),
        Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        },
    )
    .unwrap()
    .body_policy();
    // ReadOnlyDatabase never changes the retained source fixture.
    let records = {
        let database = redb::ReadOnlyDatabase::open(source.join("chain.redb")).unwrap();
        let transaction = database.begin_read().unwrap();
        let table = transaction.open_table(BLOCKS).unwrap();
        (1..=3)
            .map(|height| {
                let row = table
                    .get(height)
                    .unwrap()
                    .expect("three complete native blocks required");
                assert!(row.value().len() <= HEADER_BYTES + policy.max_body_bytes);
                row.value().to_vec()
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
    let path = destination.join("chain.redb");
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    let identity =
        crate::identity::NativeIdentity::initialize(&destination, genesis().peer_binding())
            .unwrap();
    let mut store = Store::create(&path, genesis(), limits).unwrap();
    store.enable_authenticated_restart(identity).unwrap();
    let verifier = NativeVerifier::new().unwrap();
    let mut verified_blocks = 0;
    for record in &records {
        let (header, body) = decode(store.engine(), record).unwrap();
        store.append(&header, &body, &verifier).unwrap();
        verified_blocks += 1;
    }
    let original_tip = store.engine().state().tip();
    let (last, _) = decode(store.engine(), &records[2]).unwrap();
    let binding = super::super::state_components::Binding {
        genesis: genesis().id(),
        rules_commitment: genesis().rules_commitment(),
        parent: last.parent,
    };
    let original_components = store
        .engine()
        .state()
        .canonical_components(binding, limits)
        .unwrap();
    let original_root = store
        .engine()
        .state()
        .execution_commitment(binding, limits)
        .unwrap();
    let first_point = *store
        .rollback_points()
        .unwrap()
        .iter()
        .find(|p| p.height == 1)
        .unwrap();
    let timer = Instant::now();
    store.restore_ancestor(1, first_point.block_id).unwrap();
    let first_restore_ms = timer.elapsed().as_millis();
    assert_eq!(store.engine().state().height(), 1);
    let second_point = *store
        .rollback_points()
        .unwrap()
        .iter()
        .find(|p| p.height == 1)
        .unwrap();
    assert_ne!(first_point.savepoint, second_point.savepoint);
    let (second, second_body) = decode(store.engine(), &records[1]).unwrap();
    store.append(&second, &second_body, &verifier).unwrap();
    verified_blocks += 1;
    let (third, third_body) = decode(store.engine(), &records[2]).unwrap();
    let mut invalid = third.clone();
    invalid.execution_commitment[0] ^= 1;
    assert_eq!(
        store
            .append(&invalid, &third_body, &verifier)
            .err()
            .unwrap(),
        "native execution commitment differs from complete checked state"
    );
    assert_eq!(store.engine().state().height(), 2);
    store.restore_ancestor(1, first_point.block_id).unwrap();
    let third_point = *store
        .rollback_points()
        .unwrap()
        .iter()
        .find(|p| p.height == 1)
        .unwrap();
    assert_ne!(second_point.savepoint, third_point.savepoint);
    for record in records.iter().skip(1) {
        let (header, body) = decode(store.engine(), record).unwrap();
        store.append(&header, &body, &verifier).unwrap();
        verified_blocks += 1;
    }
    assert_eq!(store.engine().state().tip(), original_tip);
    assert_eq!(
        store
            .engine()
            .state()
            .canonical_components(binding, limits)
            .unwrap(),
        original_components
    );
    assert_eq!(
        store
            .engine()
            .state()
            .execution_commitment(binding, limits)
            .unwrap(),
        original_root
    );
    drop(store);
    let resumed = Store::resume_existing(&path, genesis(), limits).unwrap();
    assert_eq!(resumed.engine().state().tip(), original_tip);
    assert_eq!(
        resumed
            .engine()
            .state()
            .execution_commitment(binding, limits)
            .unwrap(),
        original_root
    );
    assert_eq!(resumed.rollback_points().unwrap().len(), 4);
    let result = serde_json::json!({"scope":"existing-native-three-block-restore-append-replay","native_verified_appends":verified_blocks,"first_restore_ms":first_restore_ms.to_string(),"repeated_ancestor_recapture":true,"invalid_execution_root_rejected":true,"original_complete_components_restored":true,"authenticated_reopen":true,"source_modified":false,"proof_generation":false,"g2":false});
    fs::write(
        destination.join("result.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!("{}", result);
}
