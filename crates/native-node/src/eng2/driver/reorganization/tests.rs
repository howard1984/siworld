//! Owner-only checks reuse a disposable old-profile native fixture read-only.
use super::*;
use crate::eng2::{
    genesis::Genesis,
    header::HEADER_BYTES,
    selection::HeaderRules,
    state_components::{Binding, Limits},
};
use std::{
    cell::Cell,
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
};

struct Fixture {
    driver: Driver,
    records: Vec<(Header, Body)>,
    directory: PathBuf,
    genesis: Vec<u8>,
    rules: HeaderRules,
}
fn load(directory: &Path, source: &Path) -> Fixture {
    load_at(directory, source, 3)
}
fn load_at(directory: &Path, source: &Path, count: usize) -> Fixture {
    assert!((3..=24).contains(&count));
    use redb::ReadableDatabase;
    fs::DirBuilder::new().mode(0o700).create(directory).unwrap();
    let genesis_path = std::env::var_os("SIWORLD_REORG_NATIVE_GENESIS")
        .map(PathBuf::from)
        .unwrap_or_else(|| source.join("genesis.bin"));
    assert!(genesis_path.is_absolute());
    let genesis = fs::read(genesis_path).unwrap();
    let parsed = Genesis::decode(&genesis).unwrap();
    assert!(parsed.config().fixture && parsed.config().pow_iterations == 0);
    assert_eq!(parsed.config().genesis_target, [255; 32]);
    let config = parsed.config();
    let rules = HeaderRules {
        network: config.network,
        genesis: parsed.id(),
        genesis_timestamp: config.genesis_timestamp,
        genesis_target: config.genesis_target,
        target_interval: config.target_interval,
        pow_iterations: config.pow_iterations,
        max_headers: 1000,
    };
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    let policy = Engine::new(Genesis::decode(&genesis).unwrap(), limits)
        .unwrap()
        .body_policy();
    let records = {
        let database = redb::ReadOnlyDatabase::open(source.join("chain.redb")).unwrap();
        let transaction = database.begin_read().unwrap();
        let table = transaction
            .open_table(redb::TableDefinition::<u64, &[u8]>::new(
                "eng2-canonical-blocks-v1",
            ))
            .unwrap();
        (1..=count as u64)
            .map(|height| {
                let row = table.get(height).unwrap().unwrap();
                assert!(row.value().len() <= HEADER_BYTES + policy.max_body_bytes);
                let header = Header::decode(&row.value()[..HEADER_BYTES], &rules.network).unwrap();
                let body =
                    Body::decode(&row.value()[HEADER_BYTES..], rules.network, height, policy)
                        .unwrap();
                (header, body)
            })
            .collect::<Vec<_>>()
    };
    fs::write(directory.join("genesis.bin"), &genesis).unwrap();
    fs::set_permissions(
        directory.join("genesis.bin"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let identity =
        crate::identity::NativeIdentity::initialize(directory, parsed.peer_binding()).unwrap();
    let mut store = Store::create(&directory.join("chain.redb"), parsed, limits).unwrap();
    store.enable_authenticated_restart(identity).unwrap();
    let mut driver = Driver::new(
        store,
        NativeVerifier::new().unwrap(),
        ImportLimits {
            chain: limits,
            max_snapshot_bytes: 256 * 1024 * 1024,
        },
    )
    .unwrap();
    let archive = BranchStore::create(
        &directory.join("branches.redb"),
        rules.clone(),
        branch_limits(),
    )
    .unwrap();
    driver.enable_reorganization(archive).unwrap();
    for (header, body) in &records[..count - 1] {
        driver
            .accept(header, body)
            .unwrap_or_else(|error| panic!("native fixture height {}: {error}", header.height));
    }
    Fixture {
        driver,
        records,
        directory: directory.to_path_buf(),
        genesis,
        rules,
    }
}
fn branch_limits() -> crate::eng2::branches::Limits {
    crate::eng2::branches::Limits {
        maximum_headers: 2000,
        maximum_body_bytes: 2 * 1024 * 1024 * 1024,
    }
}
fn competitor(fixture: &mut Fixture, invalid: bool) -> Hash {
    let mut headers = fixture
        .records
        .iter()
        .map(|(header, _)| header.clone())
        .collect::<Vec<_>>();
    headers[2].nonce = headers[2].nonce.checked_add(1).unwrap();
    if invalid {
        headers[2].execution_commitment[0] ^= 1;
    }
    let candidate = headers[2].clone();
    let verified = VerifiedHeaders::verify(fixture.rules.clone(), headers).unwrap();
    fixture.driver.retain_competing_headers(&verified).unwrap();
    fixture
        .driver
        .retain_competing_body(&candidate, &fixture.records[2].1)
        .unwrap();
    fixture
        .driver
        .accept(&fixture.records[2].0, &fixture.records[2].1)
        .unwrap();
    candidate.id().unwrap()
}
fn check_fingerprint(driver: &Driver, header: &Header) {
    let binding = Binding {
        genesis: driver.engine().genesis().id(),
        rules_commitment: driver.engine().genesis().rules_commitment(),
        parent: header.parent,
    };
    assert_eq!(
        driver
            .engine()
            .state()
            .execution_commitment(binding, driver.engine().limits())
            .unwrap(),
        header.execution_commitment
    );
    driver.store().ensure_exportable().unwrap();
}
#[test]
#[ignore = "owner-only complete native fixture and fresh disposable destination"]
fn real_native_driver_switch_pause_invalid_and_restart() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_REORG_NATIVE_SOURCE").expect("native source required"),
    );
    let destination = PathBuf::from(
        std::env::var_os("SIWORLD_REORG_NATIVE_DESTINATION").expect("fresh destination required"),
    );
    assert!(
        source.is_absolute()
            && destination.is_absolute()
            && source.join("disposable-fixture").is_file()
    );
    assert!(!destination.exists() && !destination.starts_with(&source));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&destination)
        .unwrap();
    let started = Instant::now();
    let mut fixture = load(&destination.join("success"), &source);
    let candidate = competitor(&mut fixture, false);
    let barrier = Cell::new(0);
    fixture
        .driver
        .reorganization_tick(|_| {
            barrier.set(barrier.get() + 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(barrier.get(), 1);
    assert_eq!(fixture.driver.head().unwrap().height, 2);
    assert!(!fixture.driver.activities_allowed());
    assert_eq!(fixture.driver.template_generation(), 1);
    assert!(fixture.driver.prepare_padding().is_err());
    assert!(
        fixture
            .driver
            .accept(&fixture.records[2].0, &fixture.records[2].1)
            .is_err()
    );
    fixture
        .driver
        .reorganization_tick(|_| panic!("barrier repeated during append"))
        .unwrap();
    assert_eq!(fixture.driver.head().unwrap().id, candidate);
    assert!(fixture.driver.activities_allowed());
    let event = fixture.driver.last_reorganization().unwrap();
    assert_eq!(event.depth, 1);
    assert_eq!(event.ancestor_height, 2);
    check_fingerprint(&fixture.driver, &fixture.driver.header(3).unwrap());
    let mut independent = Engine::new(
        Genesis::decode(&fixture.genesis).unwrap(),
        fixture.driver.engine().limits(),
    )
    .unwrap();
    let verifier = NativeVerifier::new().unwrap();
    for (header, body) in &fixture.records[..2] {
        independent.apply(header, body, &verifier).unwrap();
    }
    let changed = fixture.driver.header(3).unwrap();
    independent
        .apply(&changed, &fixture.records[2].1, &verifier)
        .unwrap();
    let binding = Binding {
        genesis: independent.genesis().id(),
        rules_commitment: independent.genesis().rules_commitment(),
        parent: changed.parent,
    };
    assert_eq!(
        fixture
            .driver
            .engine()
            .state()
            .canonical_components(binding, independent.limits())
            .unwrap(),
        independent
            .state()
            .canonical_components(binding, independent.limits())
            .unwrap()
    );
    let mut invalid = load(&destination.join("invalid"), &source);
    let rejected = competitor(&mut invalid, true);
    let old = invalid.driver.head().unwrap();
    invalid
        .driver
        .reorganization_tick(|_| panic!("invalid candidate reached restore"))
        .unwrap();
    assert_eq!(invalid.driver.head().unwrap(), old);
    assert!(invalid.driver.activities_allowed());
    assert_eq!(invalid.driver.template_generation(), 0);
    assert_eq!(
        invalid
            .driver
            .reorganization
            .as_ref()
            .unwrap()
            .branches
            .entry(rejected)
            .unwrap()
            .unwrap()
            .status,
        crate::eng2::branches::Status::Invalid
    );
    check_fingerprint(&invalid.driver, &invalid.records[2].0);
    let mut blocked = load(&destination.join("barrier"), &source);
    competitor(&mut blocked, false);
    let old = blocked.driver.head().unwrap();
    assert!(
        blocked
            .driver
            .reorganization_tick(|_| Err("injected cursor withdrawal failure".into()))
            .is_err()
    );
    assert_eq!(blocked.driver.head().unwrap(), old);
    assert!(!blocked.driver.activities_allowed());
    assert_eq!(
        blocked.driver.reorganization_alarm(),
        Some("reorganization_output_barrier_failed")
    );
    let mut restart = load(&destination.join("restart"), &source);
    let candidate = competitor(&mut restart, false);
    restart.driver.reorganization_tick(|_| Ok(())).unwrap();
    assert_eq!(restart.driver.head().unwrap().height, 2);
    let limits = restart.driver.engine().limits();
    let imports = ImportLimits {
        chain: limits,
        max_snapshot_bytes: 256 * 1024 * 1024,
    };
    drop(restart.driver);
    let store = Store::resume_existing(
        &restart.directory.join("chain.redb"),
        Genesis::decode(&restart.genesis).unwrap(),
        limits,
    )
    .unwrap();
    let mut resumed = Driver::new(store, NativeVerifier::new().unwrap(), imports).unwrap();
    resumed
        .enable_reorganization(
            BranchStore::open(
                &restart.directory.join("branches.redb"),
                restart.rules,
                branch_limits(),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(!resumed.activities_allowed());
    assert_eq!(resumed.reorganization_status(), "resuming_best_branch");
    assert!(resumed.prepare_padding().is_err());
    resumed.reorganization_tick(|_| Ok(())).unwrap();
    resumed.reorganization_tick(|_| Ok(())).unwrap();
    assert!(resumed.activities_allowed());
    assert_eq!(resumed.head().unwrap().id, candidate);
    check_fingerprint(&resumed, &resumed.header(3).unwrap());
    let mut exhausted = load(&destination.join("budget"), &source);
    competitor(&mut exhausted, false);
    let old = exhausted.driver.head().unwrap();
    exhausted.driver.reorganization.as_mut().unwrap().memory = crate::p2p::Budget::new(1);
    assert!(
        exhausted
            .driver
            .reorganization_tick(|_| panic!("unreserved replay reached restore"))
            .is_err()
    );
    assert_eq!(exhausted.driver.head().unwrap(), old);
    assert_eq!(
        exhausted.driver.reorganization_alarm(),
        Some("reorganization_shared_byte_budget_deferred")
    );
    assert!(!exhausted.driver.activities_allowed());
    // A header-only retained descendant must not deadlock ordinary restart sync.
    let headers_only = load(&destination.join("headers-only"), &source);
    let Fixture {
        mut driver,
        records,
        directory,
        genesis,
        rules,
    } = headers_only;
    let mut headers = records
        .iter()
        .map(|(header, _)| header.clone())
        .collect::<Vec<_>>();
    headers[2].nonce = headers[2].nonce.checked_add(1).unwrap();
    let candidate = headers[2].clone();
    driver
        .retain_competing_headers(&VerifiedHeaders::verify(rules.clone(), headers).unwrap())
        .unwrap();
    assert!(
        driver
            .branch_block_size(candidate.id().unwrap())
            .unwrap()
            .is_none()
    );
    let limits = driver.engine().limits();
    drop(driver);
    let store = Store::resume_existing(
        &directory.join("chain.redb"),
        Genesis::decode(&genesis).unwrap(),
        limits,
    )
    .unwrap();
    let mut resumed = Driver::new(
        store,
        NativeVerifier::new().unwrap(),
        ImportLimits {
            chain: limits,
            max_snapshot_bytes: 256 * 1024 * 1024,
        },
    )
    .unwrap();
    resumed
        .enable_reorganization(
            BranchStore::open(&directory.join("branches.redb"), rules, branch_limits()).unwrap(),
        )
        .unwrap();
    assert!(!resumed.activities_allowed());
    resumed
        .reorganization_tick(|_| panic!("missing body reached restore"))
        .unwrap();
    assert!(!resumed.activities_allowed());
    resumed.accept(&candidate, &records[2].1).unwrap();
    resumed
        .reorganization_tick(|_| panic!("forward sync needs no restore"))
        .unwrap();
    assert!(resumed.activities_allowed());
    assert_eq!(resumed.head().unwrap().id, candidate.id().unwrap());
    check_fingerprint(&resumed, &candidate);
    let receipt = serde_json::json!({"result":"passed","elapsed_seconds":started.elapsed().as_secs_f64(),"fixture_profile":"old_native_h1_h3","reorganization_depth":1,"fork":"terminal_nonce_only_equal_work_first_seen","native_proof_generation":false,"success_state_components":11,"invalid_candidate_preserves_original":true,"barrier_failure_stops":true,"restart_pending_gate":true,"header_only_restart_forward_sync":true,"shared_byte_budget_preflight":true,"new_v2":false,"g2":false});
    fs::write(
        destination.join("result.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    eprintln!("{}", receipt);
}

#[test]
#[ignore = "requires explicit read-only native source through height24 and fresh private destination"]
fn real_native_checkpoint_archives_follow_restore_append_and_restart() {
    use redb::ReadableDatabase;
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source = PathBuf::from(std::env::var_os("SIWORLD_REORG_NATIVE_SOURCE").unwrap());
    let destination = PathBuf::from(std::env::var_os("SIWORLD_REORG_NATIVE_DESTINATION").unwrap());
    assert!(source.is_absolute() && destination.is_absolute() && !destination.exists());
    assert!(!destination.starts_with(&source) && !source.starts_with(&destination));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&destination)
        .unwrap();
    let started = Instant::now();
    let fixture = load_at(&destination.join("ancestor"), &source, 13);
    let Fixture {
        mut driver,
        records: _,
        directory,
        genesis,
        rules,
    } = fixture;
    assert_eq!(driver.head().unwrap().height, 12);
    let id = driver.header(12).unwrap().id().unwrap();
    assert_eq!(
        driver
            .store
            .checkpoint_anchor(12, driver.imports)
            .unwrap()
            .tip(),
        id
    );
    driver.store.restore_ancestor(12, id).unwrap();
    // The height12 savepoint predates the separate checkpoint archive write,
    // and there is no earlier positive anchor for migration to reuse.
    assert!(driver.store.checkpoint_anchor(12, driver.imports).is_err());
    let limits = driver.engine().limits();
    let imports = driver.imports;
    drop(driver);
    let store = Store::resume_existing(
        &directory.join("chain.redb"),
        Genesis::decode(&genesis).unwrap(),
        limits,
    )
    .unwrap();
    let mut resumed = Driver::new(store, NativeVerifier::new().unwrap(), imports).unwrap();
    resumed
        .enable_reorganization(
            BranchStore::open(&directory.join("branches.redb"), rules, branch_limits()).unwrap(),
        )
        .unwrap();
    assert_eq!(
        resumed.store.checkpoint_anchor(12, imports).unwrap().tip(),
        id
    );
    // The same hook executes immediately after the ancestor restore barrier.
    resumed.store.restore_ancestor(12, id).unwrap();
    assert!(resumed.store.checkpoint_anchor(12, imports).is_err());
    resumed.archive_reorganization_boundary().unwrap();
    assert_eq!(
        resumed.store.checkpoint_anchor(12, imports).unwrap().tip(),
        id
    );
    drop(resumed);

    let mut fixture = load_at(&destination.join("replacement"), &source, 24);
    let mut headers = fixture
        .records
        .iter()
        .map(|(header, _)| header.clone())
        .collect::<Vec<_>>();
    headers[23].nonce = headers[23].nonce.checked_add(1).unwrap();
    let replacement = headers[23].clone();
    fixture
        .driver
        .retain_competing_headers(&VerifiedHeaders::verify(fixture.rules.clone(), headers).unwrap())
        .unwrap();
    fixture
        .driver
        .retain_competing_body(&replacement, &fixture.records[23].1)
        .unwrap();
    fixture
        .driver
        .accept(&fixture.records[23].0, &fixture.records[23].1)
        .unwrap();
    fixture
        .driver
        .reorganization_tick(|height| {
            assert_eq!(height, 23);
            Ok(())
        })
        .unwrap();
    assert_eq!(fixture.driver.head().unwrap().height, 23);
    fixture
        .driver
        .reorganization_tick(|_| panic!("barrier repeated"))
        .unwrap();
    assert_eq!(fixture.driver.head().unwrap().id, replacement.id().unwrap());
    check_fingerprint(&fixture.driver, &replacement);
    let database_path = fixture.directory.join("chain.redb");
    drop(fixture.driver);
    let database = redb::ReadOnlyDatabase::open(database_path).unwrap();
    let transaction = database.begin_read().unwrap();
    // Inspect before checkpoint_anchor can perform lazy migration.
    let archives = transaction
        .open_table(redb::TableDefinition::<u64, &[u8]>::new(
            "eng2-committed-anchor-states-v1",
        ))
        .unwrap();
    assert!(archives.get(24).unwrap().is_some());
    let result = serde_json::json!({"result":"passed","elapsed_seconds":started.elapsed().as_secs_f64(),"fixture_profile":"old_native_h1_h24","restored_first_anchor_missing_before_repair":true,"authenticated_restart_recreates_current_boundary":true,"post_restore_recreates_current_boundary":true,"replacement_append_archives_height24":true,"replacement_depth":1,"native_proof_generation":false,"actual_certificate_cross_fork":false,"new_v2":false,"g2":false});
    fs::write(
        destination.join("result.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    eprintln!("{result}");
}
