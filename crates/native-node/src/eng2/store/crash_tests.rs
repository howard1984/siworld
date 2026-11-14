//! Owner-local SIGKILL checks at complete native Store commit boundaries.

use super::*;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{fs::DirBuilderExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

// Full-frame cases first construct A through normal append. Keep those append
// hooks disarmed until every competing frame has been retained for the switch.
static FULL_FRAME_ARMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(super) fn arm_full_frame() {
    if std::env::var("SIWORLD_REORG_CRASH_FULL_FRAME").as_deref() == Ok("1") {
        assert_eq!(
            std::env::var("SIWORLD_REORG_CRASH_CHILD").as_deref(),
            Ok("1")
        );
        assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
        FULL_FRAME_ARMED.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// This rendezvous exists only in an explicitly selected local test build.
/// The parent kills a parked worker; normal process shutdown never runs.
pub(super) fn boundary(point: &str, height: u64) {
    if std::env::var("SIWORLD_REORG_CRASH_FULL_FRAME").as_deref() == Ok("1")
        && !FULL_FRAME_ARMED.load(std::sync::atomic::Ordering::Acquire)
    {
        return;
    }

    if std::env::var("SIWORLD_REORG_CRASH_CHILD").as_deref() != Ok("1")
        || std::env::var("SIWORLD_REORG_CRASH_POINT").as_deref() != Ok(point)
        || std::env::var("SIWORLD_REORG_CRASH_HEIGHT").ok().as_deref()
            != Some(height.to_string().as_str())
    {
        return;
    }
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let marker = PathBuf::from(std::env::var_os("SIWORLD_REORG_CRASH_MARKER").unwrap());
    assert!(marker.is_absolute() && marker.parent().unwrap().is_dir());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
        .unwrap();
    writeln!(file, "{point}:{height}").unwrap();
    file.sync_all().unwrap();
    loop {
        std::thread::park();
    }
}

fn limits() -> Limits {
    Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    }
}
fn private_directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}
fn resume(root: &Path, path: &Path) -> Result<Store, String> {
    let genesis = Genesis::decode(&fs::read(root.join("genesis.bin")).unwrap()).unwrap();
    let identity =
        crate::identity::NativeIdentity::load(&root.join("original"), &genesis.peer_binding())
            .unwrap();
    Store::resume_qualification_copy(path, genesis, limits(), identity)
}
fn records(root: &Path, engine: &Engine) -> Vec<(Header, Body)> {
    (1..=3)
        .map(|height| {
            decode(
                engine,
                &fs::read(root.join(format!("block-{height}.bin"))).unwrap(),
            )
            .unwrap()
        })
        .collect()
}
fn candidate(original: &[(Header, Body)]) -> Vec<(Header, Body)> {
    let mut candidate = original[1..].to_vec();
    candidate[1].0.nonce = candidate[1].0.nonce.checked_add(1).unwrap();
    candidate
}
fn binding(engine: &Engine, header: &Header) -> super::super::state_components::Binding {
    super::super::state_components::Binding {
        genesis: engine.genesis().id(),
        rules_commitment: engine.genesis().rules_commitment(),
        parent: header.parent,
    }
}
fn complete_components(engine: &Engine, header: &Header) -> [Vec<u8>; 11] {
    assert_eq!(engine.state().height(), header.height);
    assert_eq!(engine.state().tip(), header.id().unwrap());
    assert_eq!(
        engine
            .state()
            .execution_commitment(binding(engine, header), limits())
            .unwrap(),
        header.execution_commitment,
    );
    engine
        .state()
        .canonical_components(binding(engine, header), limits())
        .unwrap()
}

#[test]
#[ignore = "child process entry for explicit owner-local native crash fixture"]
fn native_crash_worker() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    assert_eq!(
        std::env::var("SIWORLD_REORG_CRASH_CHILD").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("SIWORLD_REORG_CRASH_ROOT").unwrap());
    let path = PathBuf::from(std::env::var_os("SIWORLD_REORG_CRASH_DATABASE").unwrap());
    assert!(root.is_absolute() && path.starts_with(&root));
    assert!(root.join("disposable-fixture").is_file());
    let mut store = resume(&root, &path).unwrap();
    let original = records(&root, store.engine());
    let replacement = candidate(&original);
    let verifier = NativeVerifier::new().unwrap();
    let prepared = store
        .prevalidate_replacement(
            1,
            original[0].0.id().unwrap(),
            &replacement
                .iter()
                .map(|(header, _)| header.id().unwrap())
                .collect::<Vec<_>>(),
            ReplacementBudget {
                max_blocks: 2,
                max_body_bytes: 256 * 1024 * 1024,
                max_elapsed: Duration::from_secs(60),
            },
            &verifier,
            |index| Ok(replacement[index].clone()),
        )
        .unwrap();
    let mut replay = store
        .begin_prevalidated_replacement(prepared, |index| Ok(replacement[index].clone()))
        .unwrap();
    for (header, body) in replacement {
        store
            .append_prevalidated(&mut replay, &header, &body, &verifier)
            .unwrap();
    }
    panic!("selected crash boundary was not reached");
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires explicit read-only native fixture and fresh private destination"]
fn real_native_restore_and_append_sigkill_reopen_complete_prefix() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_REORG_NATIVE_SOURCE").expect("explicit native source required"),
    );
    let root = PathBuf::from(
        std::env::var_os("SIWORLD_REORG_NATIVE_DESTINATION")
            .expect("fresh disposable destination required"),
    );
    assert!(source.is_absolute() && root.is_absolute() && !root.exists());
    assert!(source.join("disposable-fixture").is_file() && !root.starts_with(&source));
    let genesis_bytes = fs::read(source.join("genesis.bin")).unwrap();
    let genesis = || Genesis::decode(&genesis_bytes).unwrap();
    assert!(genesis().config().fixture);
    assert_eq!(genesis().config().genesis_target, [0xff; 32]);
    assert_eq!(genesis().config().pow_iterations, 0);
    let policy = Engine::new(genesis(), limits()).unwrap().body_policy();
    let raw = {
        // The retained source is opened strictly read-only and never repaired.
        let database = redb::ReadOnlyDatabase::open(source.join("chain.redb")).unwrap();
        let transaction = database.begin_read().unwrap();
        let table = transaction.open_table(BLOCKS).unwrap();
        (1..=3)
            .map(|height| {
                let value = table
                    .get(height)
                    .unwrap()
                    .expect("three full native blocks required");
                assert!(value.value().len() <= HEADER_BYTES + policy.max_body_bytes);
                value.value().to_vec()
            })
            .collect::<Vec<_>>()
    };
    private_directory(&root);
    fs::write(
        root.join("disposable-fixture"),
        b"native-store-crash-fixture\n",
    )
    .unwrap();
    fs::write(root.join("genesis.bin"), &genesis_bytes).unwrap();
    let original_directory = root.join("original");
    private_directory(&original_directory);
    let identity =
        crate::identity::NativeIdentity::initialize(&original_directory, genesis().peer_binding())
            .unwrap();
    let original_path = original_directory.join("chain.redb");
    let mut store = Store::create(&original_path, genesis(), limits()).unwrap();
    store.enable_authenticated_restart(identity).unwrap();
    let verifier = NativeVerifier::new().unwrap();
    let mut expected_original = Vec::new();
    let mut original = Vec::new();
    for (index, bytes) in raw.iter().enumerate() {
        fs::write(root.join(format!("block-{}.bin", index + 1)), bytes).unwrap();
        let (header, body) = decode(store.engine(), bytes).unwrap();
        store.append(&header, &body, &verifier).unwrap();
        expected_original.push(complete_components(store.engine(), &header));
        original.push((header, body));
    }
    drop(store);
    let replacement = candidate(&original);
    let mut expected_engine = Engine::new(genesis(), limits()).unwrap();
    expected_engine
        .apply(&original[0].0, &original[0].1, &verifier)
        .unwrap();
    expected_engine
        .apply(&replacement[0].0, &replacement[0].1, &verifier)
        .unwrap();
    expected_engine
        .apply(&replacement[1].0, &replacement[1].1, &verifier)
        .unwrap();
    let expected_candidate = complete_components(&expected_engine, &replacement[1].0);
    // Restore, memory publication and recapture are distinct durability edges.
    // Append boundaries also include the terminal replacement block.
    let cases = [
        ("restore_before_commit", 1, 3, false),
        ("restore_after_commit", 1, 1, false),
        ("restore_after_publish", 1, 1, false),
        ("restore_after_capture", 1, 1, false),
        ("append_before_commit", 2, 1, false),
        ("append_after_commit", 2, 2, false),
        ("append_after_publish", 2, 2, false),
        ("append_after_capture", 2, 2, false),
        ("append_before_commit", 3, 2, false),
        ("append_after_commit", 3, 3, true),
    ];
    let mut results = Vec::new();
    let mut failed = 0usize;
    let started = Instant::now();
    for (point, height, expected_height, final_candidate) in cases {
        let case = root.join(format!("{point}-{height}"));
        private_directory(&case);
        let path = case.join("chain.redb");
        fs::copy(&original_path, &path).unwrap();
        let marker = case.join("parked");
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(case.join("worker.log"))
            .unwrap();
        let mut worker = KillOnDrop(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "eng2::store::crash_tests::native_crash_worker",
                    "--nocapture",
                ])
                .env("SIWORLD_REORG_CRASH_CHILD", "1")
                .env("SIWORLD_REORG_CRASH_ROOT", &root)
                .env("SIWORLD_REORG_CRASH_DATABASE", &path)
                .env("SIWORLD_REORG_CRASH_POINT", point)
                .env("SIWORLD_REORG_CRASH_HEIGHT", height.to_string())
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
                    "worker exited before {point}:{height}: {status}; {}",
                    fs::read_to_string(case.join("worker.log")).unwrap()
                );
            }
            assert!(
                wait.elapsed() < Duration::from_secs(60),
                "crash rendezvous deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            fs::read_to_string(&marker).unwrap(),
            format!("{point}:{height}\n")
        );
        worker.0.kill().unwrap();
        let status = worker.0.wait().unwrap();
        assert_eq!(
            status.signal(),
            Some(9),
            "worker must terminate with SIGKILL"
        );
        let mut resumed = match resume(&root, &path) {
            Ok(store) => store,
            Err(error) => {
                let mut builder = Database::builder();
                builder.set_repair_callback(|session| session.abort());
                let detail = builder.open(&path).err().map(|error| format!("{error:?}"));
                results.push(serde_json::json!({
                    "boundary":point,"height":height,"signal":9,
                    "expected_height":expected_height,"authenticated_reopen":false,
                    "error":error,"redb_strict_open_error":detail,
                    "failed_database_preserved":true,
                }));
                failed += 1;
                println!("native crash case failed authenticated reopen: {point}:{height}");
                continue;
            }
        };
        let expected_header = if final_candidate {
            &replacement[1].0
        } else {
            &original[expected_height as usize - 1].0
        };
        let complete = complete_components(resumed.engine(), expected_header);
        assert_eq!(
            complete,
            if final_candidate {
                expected_candidate.clone()
            } else {
                expected_original[expected_height as usize - 1].clone()
            }
        );
        assert!(resumed.rollback_points().unwrap().iter().any(|point| {
            point.height == expected_height && point.block_id == expected_header.id().unwrap()
        }));
        // No switch log is needed: the reopened committed prefix can complete
        // through ordinary full append from retained immutable native bytes.
        if point == "restore_before_commit" {
            resumed
                .restore_ancestor(1, original[0].0.id().unwrap())
                .unwrap();
        }
        for (header, body) in &replacement {
            if header.height > resumed.engine().state().height() {
                resumed.append(header, body, &verifier).unwrap();
            }
        }
        assert_eq!(
            complete_components(resumed.engine(), &replacement[1].0),
            expected_candidate
        );
        drop(resumed);
        let reopened = resume(&root, &path).unwrap();
        assert_eq!(
            complete_components(reopened.engine(), &replacement[1].0),
            expected_candidate
        );
        drop(reopened);
        fs::remove_file(&path).unwrap();
        results.push(serde_json::json!({
            "boundary":point,"height":height,"signal":9,
            "resumed_height":expected_height,"exact_prefix_components_and_root":true,
            "current_savepoint_recaptured":true,"ordinary_append_to_fixed_tip":true,
            "second_authenticated_reopen":true,
        }));
        println!("native crash case passed: {point}:{height}");
    }
    let result = serde_json::json!({
        "scope":"existing-native-three-block-restore-and-append-sigkill",
        "cases":results,"failed_cases":failed,"elapsed_seconds":started.elapsed().as_secs_f64(),
        "source_modified":false,"old_profile_only":true,"proof_generation":false,
        "mining":false,"network":false,"forced_process_kill":true,
        "hard_power_loss_simulated":false,"repair_policy_weakened":false,
        "complete_1_through_24_depths":false,"g2":false,
    });
    fs::write(
        root.join("result.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!("{result}");
    assert_eq!(
        failed, 0,
        "all crash boundaries must support authenticated reopen"
    );
}

#[test]
#[ignore = "diagnostic only: permits allocator repair on a copied disposable failed fixture"]
fn diagnostic_allocator_repair_copy_preserves_authenticated_ancestor() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let root = PathBuf::from(
        std::env::var_os("SIWORLD_REORG_CRASH_ROOT").expect("explicit failed fixture required"),
    );
    let destination = PathBuf::from(
        std::env::var_os("SIWORLD_REORG_NATIVE_DESTINATION")
            .expect("fresh disposable diagnostic destination required"),
    );
    assert!(root.is_absolute() && destination.is_absolute() && !destination.exists());
    assert!(root.join("disposable-fixture").is_file() && !destination.starts_with(&root));
    private_directory(&destination);
    let path = destination.join("chain.redb");
    fs::copy(root.join("restore_after_commit-1/chain.redb"), &path).unwrap();
    let progress = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let events = progress.clone();
    let mut builder = Database::builder();
    // Diagnostic copy only. Production Store still aborts every repair request.
    builder.set_repair_callback(move |session| {
        events.lock().unwrap().push(session.progress());
    });
    let started = Instant::now();
    let database = builder.open(&path).unwrap();
    drop(database);
    let repair_elapsed = started.elapsed();
    let resumed = resume(&root, &path).unwrap();
    let original = records(&root, resumed.engine());
    let genesis = Genesis::decode(&fs::read(root.join("genesis.bin")).unwrap()).unwrap();
    let mut expected = Engine::new(genesis, limits()).unwrap();
    expected
        .apply(
            &original[0].0,
            &original[0].1,
            &NativeVerifier::new().unwrap(),
        )
        .unwrap();
    assert_eq!(
        complete_components(resumed.engine(), &original[0].0),
        complete_components(&expected, &original[0].0),
    );
    let result = serde_json::json!({
        "scope":"diagnostic-copy-allocator-rebuild-authenticated-ancestor",
        "repair_callback_progress":*progress.lock().unwrap(),
        "repair_elapsed_seconds":repair_elapsed.as_secs_f64(),
        "authenticated_resume_height":1,
        "complete_components_match_independent_native_execution":true,
        "production_repair_policy_changed":false,
        "failed_source_modified":false,"g2":false,
    });
    fs::write(
        destination.join("result.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!("{result}");
}
