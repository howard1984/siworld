//! Explicit long native replay from retained public fixture bytes only.

use super::*;
use std::{
    fs::{self, OpenOptions},
    os::unix::{fs::DirBuilderExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn limits() -> Limits {
    Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    }
}
struct Source {
    database: redb::ReadOnlyDatabase,
    genesis: Vec<u8>,
    network: Hash,
    policy: super::super::body::Policy,
}
impl Source {
    fn open(path: &Path) -> Self {
        assert!(path.is_absolute());
        let database = redb::ReadOnlyDatabase::open(path).unwrap();
        let transaction = database.begin_read().unwrap();
        let meta = transaction.open_table(META).unwrap();
        let genesis = meta.get("genesis").unwrap().unwrap().value().to_vec();
        let decoded = Genesis::decode(&genesis).unwrap();
        assert!(decoded.config().fixture);
        assert_eq!(decoded.config().genesis_target, [0xff; 32]);
        assert_eq!(decoded.config().pow_iterations, 0);
        let engine = Engine::new(decoded, limits()).unwrap();
        let network = engine.state().network();
        let policy = engine.body_policy();
        drop(meta);
        drop(transaction);
        let source = Self {
            database,
            genesis,
            network,
            policy,
        };
        for height in 1..=30 {
            assert_eq!(source.header(height).height, height);
        }
        source
    }
    fn genesis(&self) -> Genesis {
        Genesis::decode(&self.genesis).unwrap()
    }
    fn header(&self, height: u64) -> Header {
        let transaction = self.database.begin_read().unwrap();
        let blocks = transaction.open_table(BLOCKS).unwrap();
        let row = blocks
            .get(height)
            .unwrap()
            .expect("thirty complete native blocks required");
        assert!(row.value().len() <= HEADER_BYTES + self.policy.max_body_bytes);
        Header::decode(&row.value()[..HEADER_BYTES], &self.network).unwrap()
    }
    fn block(&self, height: u64) -> (Header, Body) {
        let transaction = self.database.begin_read().unwrap();
        let blocks = transaction.open_table(BLOCKS).unwrap();
        let row = blocks
            .get(height)
            .unwrap()
            .expect("complete native body required");
        assert!(row.value().len() <= HEADER_BYTES + self.policy.max_body_bytes);
        let header = Header::decode(&row.value()[..HEADER_BYTES], &self.network).unwrap();
        let body = Body::decode(
            &row.value()[HEADER_BYTES..],
            self.network,
            height,
            self.policy,
        )
        .unwrap();
        assert_eq!(
            body.commitment(self.policy).unwrap(),
            header.body_commitment
        );
        (header, body)
    }
    fn replacement_ids(&self, invalid_last: bool) -> Vec<Hash> {
        (3..=30)
            .map(|height| {
                let mut header = self.header(height);
                if invalid_last && height == 30 {
                    header.execution_commitment[0] ^= 1;
                }
                header.id().unwrap()
            })
            .collect()
    }
    fn replacement(&self, index: usize, invalid_last: bool) -> Result<(Header, Body), String> {
        let (mut header, body) = self.block(index as u64 + 3);
        if invalid_last && index == 27 {
            header.execution_commitment[0] ^= 1;
        }
        Ok((header, body))
    }
}
fn budget() -> ReplacementBudget {
    ReplacementBudget {
        max_blocks: 28,
        max_body_bytes: 4 * 1024 * 1024 * 1024,
        max_elapsed: Duration::from_secs(900),
    }
}
fn components(store: &Store, header: &Header) -> [Vec<u8>; 11] {
    store.ensure_exportable().unwrap();
    assert_eq!(store.engine().state().height(), header.height);
    assert_eq!(store.engine().state().tip(), header.id().unwrap());
    let binding = super::super::state_components::Binding {
        genesis: store.engine().genesis().id(),
        rules_commitment: store.engine().genesis().rules_commitment(),
        parent: header.parent,
    };
    assert_eq!(
        store
            .engine()
            .state()
            .execution_commitment(binding, limits())
            .unwrap(),
        header.execution_commitment,
    );
    store
        .engine()
        .state()
        .canonical_components(binding, limits())
        .unwrap()
}
struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "child entry for explicit long native replacement crash fixture"]
fn native_long_replacement_worker() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    assert_eq!(
        std::env::var("SIWORLD_REORG_CRASH_CHILD").as_deref(),
        Ok("1")
    );
    let source = Source::open(Path::new(
        &std::env::var_os("SIWORLD_REORG_NATIVE_LONG_SOURCE").unwrap(),
    ));
    let root = PathBuf::from(std::env::var_os("SIWORLD_REORG_NATIVE_DESTINATION").unwrap());
    assert!(root.is_absolute() && root.join("disposable-fixture").is_file());
    let mut store =
        Store::resume_existing(&root.join("chain.redb"), source.genesis(), limits()).unwrap();
    assert_eq!(store.engine().state().height(), 3);
    let old_tip = store.engine().state().tip();
    let old_points = store.rollback_points().unwrap();
    let verifier = NativeVerifier::new().unwrap();
    let prepared = store
        .prevalidate_replacement(
            2,
            source.header(2).id().unwrap(),
            &source.replacement_ids(false),
            budget(),
            &verifier,
            |index| source.replacement(index, false),
        )
        .unwrap();
    assert_eq!(prepared.len(), 28);
    assert_eq!(prepared.tip(), source.header(30).id().unwrap());
    assert_eq!(store.engine().state().tip(), old_tip);
    assert_eq!(store.rollback_points().unwrap(), old_points);
    let mut replay = store
        .begin_prevalidated_replacement(prepared, |index| source.replacement(index, false))
        .unwrap();
    assert_eq!(store.engine().state().height(), 2);
    let (mut wrong, body) = source.block(3);
    wrong.nonce = wrong.nonce.checked_add(1).unwrap();
    assert!(matches!(
        store.append_prevalidated(&mut replay, &wrong, &body, &verifier),
        Err(ReplacementFailure::Deferred(_)),
    ));
    assert_eq!(store.engine().state().height(), 2);
    assert_eq!(replay.next_index(), 0);
    drop(body);
    fs::write(root.join("long-preview-qualified.json"), br#"{"complete_native_prevalidated_blocks":28,"fixed_material_mismatch_rejected_without_append":true}"#).unwrap();
    for index in 0..28 {
        let (header, body) = source.replacement(index, false).unwrap();
        store
            .append_prevalidated(&mut replay, &header, &body, &verifier)
            .unwrap();
    }
    panic!("long native crash boundary was not reached");
}

#[test]
#[ignore = "requires explicit thirty-block read-only native source and fresh private destination"]
fn real_native_long_replacement_rejects_late_invalid_and_resumes_pruned_ancestor() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source_path = PathBuf::from(
        std::env::var_os("SIWORLD_REORG_NATIVE_LONG_SOURCE")
            .expect("explicit thirty-block source required"),
    );
    let root = PathBuf::from(
        std::env::var_os("SIWORLD_REORG_NATIVE_DESTINATION")
            .expect("fresh disposable destination required"),
    );
    assert!(source_path.is_absolute() && root.is_absolute() && !root.exists());
    assert!(!source_path.starts_with(&root) && !root.starts_with(&source_path));
    let metadata_before = fs::metadata(&source_path).unwrap();
    let source = Source::open(&source_path);
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    fs::write(root.join("genesis.bin"), &source.genesis).unwrap();
    fs::write(
        root.join("disposable-fixture"),
        b"native-long-replacement\n",
    )
    .unwrap();
    let identity =
        crate::identity::NativeIdentity::initialize(&root, source.genesis().peer_binding())
            .unwrap();
    let path = root.join("chain.redb");
    let mut store = Store::create(&path, source.genesis(), limits()).unwrap();
    store.enable_authenticated_restart(identity).unwrap();
    let verifier = NativeVerifier::new().unwrap();
    let started = Instant::now();
    let mut old_tip = source.header(3);
    old_tip.nonce = old_tip.nonce.checked_add(1).unwrap();
    for height in 1..=3 {
        let (header, body) = source.block(height);
        store
            .append(
                if height == 3 { &old_tip } else { &header },
                &body,
                &verifier,
            )
            .unwrap();
    }
    let old_components = components(&store, &old_tip);
    let old_points = store.rollback_points().unwrap();
    let late_invalid = store
        .prevalidate_replacement(
            2,
            source.header(2).id().unwrap(),
            &source.replacement_ids(true),
            budget(),
            &verifier,
            |index| source.replacement(index, true),
        )
        .err()
        .unwrap();
    assert_eq!(
        late_invalid,
        ReplacementFailure::Rejected {
            index: 27,
            reason: "native execution commitment differs from complete checked state".into(),
        }
    );
    assert_eq!(components(&store, &old_tip), old_components);
    assert_eq!(store.rollback_points().unwrap(), old_points);
    drop(store);
    let marker = root.join("parked");
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("worker.log"))
        .unwrap();
    let mut worker = KillOnDrop(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "eng2::store::long_replacement_tests::native_long_replacement_worker",
                "--nocapture",
            ])
            .env("SIWORLD_REORG_CRASH_CHILD", "1")
            .env("SIWORLD_REORG_CRASH_POINT", "append_after_capture")
            .env("SIWORLD_REORG_CRASH_HEIGHT", "27")
            .env("SIWORLD_REORG_CRASH_MARKER", &marker)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let wait = Instant::now();
    while !marker.exists() {
        if let Some(status) = worker.0.try_wait().unwrap() {
            panic!(
                "long worker exited before crash boundary: {status}; {}",
                fs::read_to_string(root.join("worker.log")).unwrap()
            );
        }
        assert!(
            wait.elapsed() < Duration::from_secs(300),
            "long native child deadline"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        fs::read_to_string(&marker).unwrap(),
        "append_after_capture:27\n"
    );
    worker.0.kill().unwrap();
    assert_eq!(worker.0.wait().unwrap().signal(), Some(9));
    let mut resumed = Store::resume_existing(&path, source.genesis(), limits()).unwrap();
    let resumed_components = components(&resumed, &source.header(27));
    let points = resumed.rollback_points().unwrap();
    assert_eq!(points.len(), 25);
    assert_eq!(points.first().unwrap().height, 3);
    assert_eq!(points.last().unwrap().height, 27);
    assert!(!points.iter().any(|point| point.height == 2));
    assert!(
        resumed
            .restore_ancestor(2, source.header(2).id().unwrap())
            .is_err()
    );
    assert_eq!(components(&resumed, &source.header(27)), resumed_components);
    for height in 28..=30 {
        let (header, body) = source.block(height);
        resumed.append(&header, &body, &verifier).unwrap();
    }
    let final_components = components(&resumed, &source.header(30));
    drop(resumed);
    let reopened = Store::resume_existing(&path, source.genesis(), limits()).unwrap();
    assert_eq!(components(&reopened, &source.header(30)), final_components);
    let metadata_after = fs::metadata(&source_path).unwrap();
    assert_eq!(metadata_before.len(), metadata_after.len());
    assert_eq!(
        metadata_before.modified().unwrap(),
        metadata_after.modified().unwrap()
    );
    let child: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("long-preview-qualified.json")).unwrap())
            .unwrap();
    assert_eq!(child["complete_native_prevalidated_blocks"], 28);
    assert_eq!(
        child["fixed_material_mismatch_rejected_without_append"],
        true
    );
    let result = serde_json::json!({
        "scope":"existing-native-28-block-replacement-late-invalid-and-pruned-ancestor-crash",
        "old_rollback_depth":1,"replacement_blocks":28,
        "late_invalid_index":27,"late_invalid_rejected_before_restore":true,
        "old_full_components_and_savepoints_unchanged_on_rejection":true,
        "complete_native_prevalidation_before_restore":true,
        "fixed_material_mismatch_rejected_without_append":true,
        "native_canonical_appends":31,"source_native_blocks":30,
        "signal":9,"crash_height":27,"replacement_blocks_committed_before_kill":25,
        "retained_states_at_reopen":25,"original_ancestor_pruned":true,
        "authenticated_reopen_and_complete_root_at_prefix":true,
        "ordinary_native_appends_after_crash":3,"second_authenticated_reopen_at_30":true,
        "elapsed_seconds":started.elapsed().as_secs_f64(),
        "source_opened_readonly":true,"source_size_and_mtime_unchanged":true,
        "proof_generation":false,"mining":false,"network":false,
        "old_profile_only":true,"g2":false,"all_rollback_depths":false,
        "driver_or_branch_store_crash_integrated":false,
    });
    fs::write(
        root.join("result.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!("{result}");
}

#[test]
#[ignore = "explicit read-only native source and fresh fork probe destination required"]
fn real_native_existing_body_fork_probe() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source_path = PathBuf::from(std::env::var_os("SIWORLD_REORG_NATIVE_LONG_SOURCE").unwrap());
    let root = PathBuf::from(std::env::var_os("SIWORLD_REORG_NATIVE_DESTINATION").unwrap());
    assert!(source_path.is_absolute() && root.is_absolute() && !root.exists());
    assert!(!source_path.starts_with(&root) && !root.starts_with(&source_path));
    let metadata_before = fs::metadata(&source_path).unwrap();
    let source = Source::open(&source_path);
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    fs::write(root.join("genesis.bin"), &source.genesis).unwrap();
    let verifier = NativeVerifier::new().unwrap();
    let mut engine = Engine::new(source.genesis(), limits()).unwrap();
    let started = Instant::now();
    for height in 1..=2 {
        let (header, body) = source.block(height);
        engine.apply(&header, &body, &verifier).unwrap();
    }
    let (mut third, body) = source.block(3);
    third.nonce = third.nonce.checked_add(1).unwrap();
    engine.apply(&third, &body, &verifier).unwrap();
    let mut headers = vec![third];
    let mut failure = None;
    for height in 4..=30 {
        let (original, body) = source.block(height);
        let next = engine.prepare_header(&body, original.timestamp, &verifier);
        let next = match next {
            Ok(next) => next,
            Err(reason) => {
                failure = Some(
                    serde_json::json!({"height":height,"stage":"prepare_header","reason":reason}),
                );
                break;
            }
        };
        assert_ne!(next.parent, original.parent);
        assert_eq!(next.body_commitment, original.body_commitment);
        assert_eq!(next.target, [0xff; 32]);
        if let Err(reason) = engine.apply(&next, &body, &verifier) {
            failure = Some(serde_json::json!({"height":height,"stage":"apply","reason":reason}));
            break;
        }
        headers.push(next);
        if height == 4 {
            fs::write(
                root.join("h4-qualified.json"),
                br#"{"complete_native_prepare_and_apply_at_h4":true,"proof_generation":false}"#,
            )
            .unwrap();
        }
    }
    let complete = failure.is_none() && headers.len() == 28;
    let mut encoded = Vec::new();
    for header in &headers {
        encoded.extend_from_slice(&header.encode().unwrap());
    }
    fs::write(root.join("alt-headers.bin"), &encoded).unwrap();
    let metadata_after = fs::metadata(&source_path).unwrap();
    assert_eq!(metadata_before.len(), metadata_after.len());
    assert_eq!(
        metadata_before.modified().unwrap(),
        metadata_after.modified().unwrap()
    );
    let result = serde_json::json!({
        "scope":"existing-body-full-native-fork-feasibility",
        "complete":complete,"common_ancestor_height":2,
        "native_applied_height":engine.state().height(),"alternate_headers":headers.len(),
        "h4_complete_native_validated":headers.len()>=2,
        "first_failure":failure,"frozen_header_blake3":crate::local::hex(blake3::hash(&encoded).as_bytes()),
        "elapsed_seconds":started.elapsed().as_secs_f64(),
        "proof_generation":false,"pow_search":false,"network":false,
        "old_profile_only":true,"g2":false,
        "source_opened_readonly":true,"source_size_and_mtime_unchanged":true,
    });
    fs::write(
        root.join("result.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!("{result}");
}
