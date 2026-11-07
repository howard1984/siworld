use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "siworld-native-service-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn lifetime_lease_is_exclusive_and_released_on_drop() {
    let directory = Directory::new();
    let first = Lease::acquire(&directory.0).unwrap();
    assert!(Lease::acquire(&directory.0).is_err());
    drop(first);
    assert!(Lease::acquire(&directory.0).is_ok());
}
#[cfg(unix)]
#[test]
fn lease_refuses_symlinks_without_changing_evidence() {
    use std::os::unix::fs::symlink;
    let directory = Directory::new();
    let target = directory.0.join("evidence");
    std::fs::write(&target, b"preserved").unwrap();
    symlink(&target, directory.0.join(LEASE_FILE)).unwrap();
    assert!(Lease::acquire(&directory.0).is_err());
    assert_eq!(std::fs::read(target).unwrap(), b"preserved");
}
#[test]
fn wall_clock_changes_cannot_manufacture_monotonic_completion() {
    let mut clock = ClockGuard::new(1_000_000);
    clock.observe(1_005_000, 5000).unwrap();
    assert!(clock.observe(999_000, 6000).is_err());
    assert!(clock.observe(100_000_000, 6000).is_err());
    assert!(!observation_complete(86_399_999));
    assert!(observation_complete(86_400_000));
}
#[test]
fn resume_uses_new_run_identity_and_does_not_trust_saved_elapsed() {
    let first = RunIdentity::new([3; 32], "a".repeat(64), "b".repeat(64), 100).unwrap();
    let resumed = RunIdentity::new([3; 32], "a".repeat(64), "b".repeat(64), 200).unwrap();
    assert_ne!(first.run_id, resumed.run_id);
    let status = Status::new(&resumed);
    assert_eq!(status.observation_elapsed_ms(Instant::now()), 0);
    assert!(
        !status.to_json(&resumed, Instant::now(), 0).unwrap()["observation_complete"]
            .as_bool()
            .unwrap()
    );
}
#[test]
fn atomic_export_failure_preserves_destination_and_cleans_temporary() {
    let directory = Directory::new();
    let destination = directory.0.join("status.json");
    std::fs::create_dir(&destination).unwrap();
    assert!(atomic_json(&destination, &serde_json::json!({"ready":true})).is_err());
    assert!(destination.is_dir());
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
}
#[test]
fn status_exposes_work_progress_without_private_positions() {
    let identity = RunIdentity::new([4; 32], "a".repeat(64), "b".repeat(64), 100).unwrap();
    let status = Status::new(&identity);
    let value = status.to_json(&identity, Instant::now(), 7).unwrap();
    for key in [
        "phase",
        "pow_attempts",
        "progress_sequence",
        "last_progress_elapsed_ms",
        "state_fingerprint",
        "sequence",
    ] {
        assert!(value.get(key).is_some());
    }
    for key in [
        "pool_count",
        "padding_count",
        "real_count",
        "nullifier",
        "fee",
        "peer",
        "address",
    ] {
        assert!(value.get(key).is_none());
    }
}
#[test]
fn private_metrics_expose_public_head_time_and_scoped_template_duration_only() {
    let identity = RunIdentity::new([6; 32], "a".repeat(64), "b".repeat(64), 100).unwrap();
    let mut status = Status::new(&identity);
    status.block_timestamp = 1_800_000_000;
    status.template_generation_ms = Some(5500);
    let value = status.to_json(&identity, Instant::now(), 1).unwrap();
    assert_eq!(
        value["chain_metrics"],
        json!({"last_block_timestamp": 1_800_000_000u64})
    );
    assert_eq!(
        value["production_metrics"],
        json!({"last_template_generation_ms": 5500,
        "scope": "block-assembly-including-settlement-proof-excluding-pow"})
    );
    assert!(!value.to_string().contains("transaction_count"));
    assert!(!value.to_string().contains("fee_tier"));
}

#[test]
fn immutable_receipts_and_run_bound_stop_requests() {
    let directory = Directory::new();
    let identity = RunIdentity::new([5; 32], "a".repeat(64), "b".repeat(64), 100).unwrap();
    write_run_receipt(&directory.0, &identity).unwrap();
    assert!(write_run_receipt(&directory.0, &identity).is_err());
    assert!(!stop_requested(&directory.0, &identity.run_id).unwrap());
    write_stop_request(&directory.0, &identity.run_id).unwrap();
    assert!(stop_requested(&directory.0, &identity.run_id).unwrap());
    let other = RunIdentity::new([5; 32], "a".repeat(64), "b".repeat(64), 200).unwrap();
    assert!(!stop_requested(&directory.0, &other.run_id).unwrap());
}

fn active_status(directory: &Path, run_id: &str) {
    atomic_json(
        &directory.join(STATUS_FILE),
        &json!({"run_id": run_id, "phase": "networking"}),
    )
    .unwrap();
}

#[test]
fn expected_run_stop_rejects_malformed_or_replaced_runs_without_mutation() {
    let directory = Directory::new();
    let expected = "a".repeat(64);
    let replacement = "b".repeat(64);
    active_status(&directory.0, &replacement);
    let before = fs::read(directory.0.join(STATUS_FILE)).unwrap();
    for invalid in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        format!("../{}", "a".repeat(64)),
        expected,
    ] {
        assert!(request_stop_expected(&directory.0, &invalid).is_err());
        assert_eq!(fs::read(directory.0.join(STATUS_FILE)).unwrap(), before);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
        assert!(!stop_requested(&directory.0, &replacement).unwrap());
    }
    request_stop_expected(&directory.0, &replacement).unwrap();
    assert!(stop_requested(&directory.0, &replacement).unwrap());
    request_stop_expected(&directory.0, &replacement).unwrap();
}

#[test]
fn explicitly_requested_stop_file_cannot_stop_a_later_replacement_run() {
    let directory = Directory::new();
    let expected = "a".repeat(64);
    let replacement = "b".repeat(64);
    active_status(&directory.0, &expected);
    request_stop_expected(&directory.0, &expected).unwrap();
    active_status(&directory.0, &replacement);
    assert!(stop_requested(&directory.0, &expected).unwrap());
    assert!(!stop_requested(&directory.0, &replacement).unwrap());
    assert!(request_stop_expected(&directory.0, &expected).is_err());
    assert!(!stop_requested(&directory.0, &replacement).unwrap());
    request_stop(&directory.0).unwrap();
    assert!(stop_requested(&directory.0, &replacement).unwrap());
}

#[test]
fn expected_run_stop_requires_an_active_export() {
    let directory = Directory::new();
    let run_id = "a".repeat(64);
    assert!(request_stop_expected(&directory.0, &run_id).is_err());
    for status in [
        json!({"run_id": run_id, "phase": "stopped"}),
        json!({"run_id": run_id, "phase": "error"}),
        json!({"run_id": run_id}),
        json!({"phase": "networking"}),
    ] {
        atomic_json(&directory.0.join(STATUS_FILE), &status).unwrap();
        assert!(request_stop_expected(&directory.0, &run_id).is_err());
        assert!(!stop_requested(&directory.0, &run_id).unwrap());
    }
}

#[test]
fn offline_check_reports_only_replayed_state_and_integer_receipt_count() {
    let parent = Directory::new();
    let directory = parent.0.join("network");
    let config = local::initialize(&directory, 0).unwrap();
    let store = Store::open(
        directory.join("chain.redb"),
        config,
        &crate::fixtures::TestVerifier,
    )
    .unwrap();
    let state = store.state().clone();
    drop(store);
    // An exported status is not independent verification evidence.
    atomic_json(
        &directory.join(STATUS_FILE),
        &json!({"height": 999, "proof_replay_checked": true}),
    )
    .unwrap();
    let mut summary = check_offline(&directory).unwrap();
    let storage = summary
        .as_object_mut()
        .unwrap()
        .remove("storage_metrics")
        .unwrap();
    assert_eq!(storage["policy_active"], false);
    assert!(storage["role"].is_null());
    assert!(storage["database_allocated_bytes"].is_u64());
    assert_eq!(
        summary,
        json!({
            "schema": 1,
            "height": 0,
            "tip": local::hex(&state.tip),
            "state_fingerprint": local::hex(&state.fingerprint()),
            "proof_replay_checked": true,
            "proof_tail_replay_checked": true,
            "local_checkpoint_verified": false,
            "local_reward_receipts_checked": 0,
            "validation_scope": "indexed-local-rewards",
        })
    );
    assert!(summary["local_reward_receipts_checked"].is_u64());
    for field in ["tip", "state_fingerprint"] {
        assert!(hash_text(summary[field].as_str().unwrap()));
    }
    let lease = Lease::acquire(&directory).unwrap();
    assert!(check_offline(&directory).is_err());
    drop(lease);
}

#[test]
fn offline_check_preserves_the_strict_legacy_receipt_scope() {
    let parent = Directory::new();
    let directory = parent.0.join("network");
    let config = local::initialize(&directory, 0).unwrap();
    let store = Store::open(
        directory.join("chain.redb"),
        config,
        &crate::fixtures::TestVerifier,
    )
    .unwrap();
    drop(store);
    let database = redb::Database::open(directory.join("chain.redb")).unwrap();
    let transaction = database.begin_write().unwrap();
    let rewards: redb::TableDefinition<&[u8], &[u8]> =
        redb::TableDefinition::new("local-production-receipts-v1");
    let metadata: redb::TableDefinition<&str, &[u8]> =
        redb::TableDefinition::new("native-store-meta-v2");
    transaction.delete_table(rewards).unwrap();
    transaction
        .open_table(metadata)
        .unwrap()
        .remove("local-production-receipts")
        .unwrap();
    transaction.commit().unwrap();
    drop(database);
    let summary = check_offline(&directory).unwrap();
    assert_eq!(summary["validation_scope"], "strict-legacy-rewards");
    assert_eq!(summary["local_reward_receipts_checked"], 0);
    assert_eq!(summary["proof_replay_checked"], true);
}

#[test]
fn offline_check_rejects_non_native_proofs_even_when_saved_state_is_consistent() {
    let parent = Directory::new();
    let directory = parent.0.join("network");
    let config = local::initialize(&directory, 0).unwrap();
    let mut store = Store::open(
        directory.join("chain.redb"),
        config,
        &crate::fixtures::TestVerifier,
    )
    .unwrap();
    let block = crate::fixtures::candidate(store.state(), 410_000);
    store
        .append(&block, &crate::fixtures::TestVerifier)
        .unwrap();
    assert_eq!(store.state().height, 1);
    assert_eq!(store.verify_local_rewards().unwrap(), 0);
    drop(store);
    assert!(check_offline(&directory).is_err());
    assert!(directory.join("chain.redb").exists());
}

#[test]
fn calibration_uses_integer_hash_rate_and_rejects_empty_measurements() {
    assert!(calibration_target(0, 1).is_err());
    assert!(calibration_target(8, 0).is_err());
    let slow = calibration_target(8, 250_000_000).unwrap();
    let fast = calibration_target(16, 250_000_000).unwrap();
    assert!(slow > fast);
    assert_ne!(fast, [0; 32]);
}
#[test]
fn service_worker_settings_reject_implicit_or_oversubscribed_hiding() {
    assert!(check_workers(None, None).is_err());
    assert!(check_workers(Some("4"), Some("2")).is_ok());
    assert!(check_workers(Some("8"), Some("2")).is_err());
    assert!(check_workers(Some("4"), Some("4")).is_err());
}

#[test]
fn stopping_freezes_observation_before_offline_replay() {
    let identity = RunIdentity::new([6; 32], "a".repeat(64), "b".repeat(64), 100).unwrap();
    let mut status = Status::new(&identity);
    let start = Instant::now();
    status.observation_started = Some(start);
    status.observation_stopped = Some(start + Duration::from_secs(1));
    assert_eq!(
        status.observation_elapsed_ms(start + Duration::from_secs(86_400)),
        1000
    );
    assert!(
        !status
            .to_json(&identity, start + Duration::from_secs(86_400), 1)
            .unwrap()["observation_complete"]
            .as_bool()
            .unwrap()
    );
}
#[test]
#[ignore = "bounded actual resident-service lifecycle with native proofs; not 24-hour acceptance"]
fn actual_continuous_service_exports_stops_and_replays() {
    check_workers(
        std::env::var("RAYON_NUM_THREADS").ok().as_deref(),
        std::env::var("SIWORLD_COMPOSITION_HIDING_WORKERS")
            .ok()
            .as_deref(),
    )
    .unwrap();
    let directory = Directory::new();
    let network = directory.0.join("network");
    let timestamp = wall_ms().unwrap() / 1000;
    let rules = crate::state::Config::asert_development([68; 32], timestamp, [0xff; 32], 1)
        .unwrap()
        .with_fund_wallets(
            siworld_core::v1_economics::FundAllocation::new_bps(vec![5000, 5000], 1).unwrap(),
            crate::state::Config::development([121; 32], 0)
                .unwrap()
                .fund_verifying_keys,
        )
        .unwrap();
    let config = local::initialize_config(&network, rules).unwrap();
    let keys =
        crate::wallet::WalletKeys::from_seed(config.network, zeroize::Zeroizing::new([42; 32]), 0)
            .unwrap();
    crate::mining::save(
        &network,
        config.network,
        &crate::producer::MiningSettings {
            mode: crate::state::RewardMode::Voyager,
            recipient: keys.address(),
        },
    )
    .unwrap();
    let verifier = NativeVerifier::new().unwrap();
    let store = Store::open(network.join("chain.redb"), config.clone(), &verifier).unwrap();
    drop(store);
    let service_directory = network.clone();
    let worker = std::thread::spawn(move || run(&service_directory));
    let observed = (|| {
        let deadline = Instant::now() + Duration::from_secs(600);
        loop {
            if worker.is_finished() {
                return Err("resident service exited before a verified block".to_owned());
            }
            if let Ok(status) = exported_status(&network) {
                if status["phase"] == "error" {
                    return Err("resident service exported an error".to_owned());
                }
                if status["height"].as_u64().unwrap_or(0) >= 1 && status["state_available"] == true
                {
                    if status["pow_attempts"].as_u64().unwrap_or(0) == 0 {
                        return Err("no actual work was exported".to_owned());
                    }
                    if status["observation_complete"] != false
                        || status["observation_target_ms"] != OBSERVATION_TARGET_MS
                    {
                        return Err("bounded test manufactured observation acceptance".to_owned());
                    }
                    return Ok(status);
                }
            }
            if Instant::now() >= deadline {
                return Err("bounded service lifecycle exceeded its deadline".to_owned());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })();
    if let Ok(status) = exported_status(&network) {
        write_stop_request(&network, status["run_id"].as_str().unwrap()).unwrap();
    }
    let finished = worker.join().expect("resident service panicked");
    let observed = observed.unwrap();
    finished.unwrap();
    let final_status = exported_status(&network).unwrap();
    assert_eq!(final_status["run_id"], observed["run_id"]);
    assert_eq!(final_status["phase"], "stopped");
    assert_eq!(final_status["observation_complete"], false);
    assert_eq!(final_status["state_available"], true);
    let run_id = final_status["run_id"].as_str().unwrap();
    assert_eq!(
        read_json(&network.join("service-runs").join(run_id).join("final.json")).unwrap(),
        final_status
    );
    let _lease = Lease::acquire(&network).unwrap();
    let replayed = Store::open_existing(network.join("chain.redb"), config, &verifier).unwrap();
    assert_eq!(
        replayed.verify_local_rewards().unwrap(),
        replayed.state().height
    );
    assert_eq!(final_status["tip"], local::hex(&replayed.state().tip));
    assert_eq!(
        final_status["state_fingerprint"],
        local::hex(&replayed.state().fingerprint())
    );
    for height in 1..=replayed.state().height {
        let block = replayed.block(height).unwrap();
        let id = block.id().unwrap();
        producer::validate_reward_secret(&block, &local::read_reward(&network, &id).unwrap())
            .unwrap();
    }
    let height = replayed.state().height;
    let reward_id = replayed.block(height).unwrap().id().unwrap();
    drop(replayed);
    drop(_lease);
    let checked = check_offline(&network).unwrap();
    assert_eq!(checked["height"], height);
    assert_eq!(checked["tip"], final_status["tip"]);
    assert_eq!(
        checked["state_fingerprint"],
        final_status["state_fingerprint"]
    );
    assert_eq!(checked["proof_replay_checked"], true);
    assert_eq!(checked["local_reward_receipts_checked"], height);
    assert_eq!(checked["validation_scope"], "indexed-local-rewards");
    let receipt = network.join(format!("reward-{}.secret", local::hex(&reward_id)));
    let retained = network.join("retained-reward-evidence.secret");
    std::fs::rename(&receipt, &retained).unwrap();
    assert!(check_offline(&network).is_err());
    assert!(retained.is_file());
    assert!(!receipt.exists());
}

#[cfg(unix)]
#[test]
fn cleanup_never_removes_a_replacement_at_an_owned_temporary_name() {
    let directory = Directory::new();
    let temporary = directory.0.join("owned.tmp");
    let original = new_file(&temporary).unwrap();
    let identity = original.metadata().unwrap();
    std::fs::remove_file(&temporary).unwrap();
    std::fs::write(&temporary, b"replacement evidence").unwrap();
    remove_owned_temporary(&temporary, &identity);
    assert_eq!(std::fs::read(&temporary).unwrap(), b"replacement evidence");
}

#[cfg(all(feature = "native-p2p", unix))]
#[test]
fn recovery_transport_is_specimen_scoped_and_preserves_storage_seals() {
    use crate::{identity::NativeIdentity, p2p::Binding, state::Config};
    use std::os::unix::fs::{PermissionsExt, symlink};
    let specimen = Directory::new();
    let outside = Directory::new();
    let transport = specimen.0.join("transport-identity");
    fs::create_dir(&transport).unwrap();
    fs::set_permissions(&transport, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        recovery_identity_directory(&specimen.0, None).unwrap(),
        specimen.0
    );
    assert_eq!(
        recovery_identity_directory(&specimen.0, Some(transport.as_os_str())).unwrap(),
        transport.canonicalize().unwrap()
    );
    assert!(recovery_identity_directory(&specimen.0, Some(specimen.0.as_os_str())).is_err());
    assert!(recovery_identity_directory(&specimen.0, Some(outside.0.as_os_str())).is_err());
    let alias = specimen.0.join("transport-alias");
    symlink(&transport, &alias).unwrap();
    assert!(recovery_identity_directory(&specimen.0, Some(alias.as_os_str())).is_err());
    let binding = Binding::new(&Config::development([231; 32], 0).unwrap());
    let storage = NativeIdentity::initialize(&specimen.0.canonicalize().unwrap(), binding).unwrap();
    let storage_public = storage.descriptor().unwrap();
    let seal = storage.seal_local_storage([29; 32]).unwrap();
    let temporary =
        NativeIdentity::initialize(&transport.canonicalize().unwrap(), binding).unwrap();
    assert_ne!(
        storage_public.fingerprint(),
        temporary.descriptor().unwrap().fingerprint()
    );
    storage_public
        .verify_local_storage([29; 32], &seal)
        .unwrap();
    assert!(
        temporary
            .descriptor()
            .unwrap()
            .verify_local_storage([29; 32], &seal)
            .is_err()
    );
    let reopened = NativeIdentity::load(&specimen.0.canonicalize().unwrap(), &binding).unwrap();
    assert_eq!(
        reopened.descriptor().unwrap().fingerprint(),
        storage_public.fingerprint()
    );
    reopened
        .descriptor()
        .unwrap()
        .verify_local_storage([29; 32], &seal)
        .unwrap();
}

#[cfg(feature = "native-p2p")]
#[test]
fn recovery_transport_rejects_mining_listeners_and_miner_cli_before_start() {
    assert!(check_recovery_transport(true, false, false, false).is_ok());
    for (mining, listening, private_view) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
        (true, true, true),
    ] {
        assert!(check_recovery_transport(true, mining, listening, private_view).is_err());
        assert!(check_recovery_transport(false, mining, listening, private_view).is_ok());
    }
}
