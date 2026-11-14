//! Offline integration against explicitly provided disposable native fixtures.
//! These tests never mine, create a network connection, or generate a key.
use super::*;
use crate::eng2::{genesis::Genesis, resident::peers::NetworkStatus};
use crate::proofs::NativeVerifier;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

fn fixture_root() -> PathBuf {
    let root = PathBuf::from(
        std::env::var_os("SIWORLD_CHECKPOINT_RUNTIME_FIXTURE")
            .expect("explicit disposable native fixture directory required"),
    );
    assert!(root.is_absolute() && root.file_name().unwrap() == "checkpoint-runtime-fixture");
    assert!(root.join("disposable-fixture").is_file());
    root
}
fn fixture_limits() -> ImportLimits {
    ImportLimits {
        chain: crate::eng2::state_components::Limits {
            max_leaves: 100_000,
            max_nullifiers: 100_000,
            max_component_bytes: 32 * 1024 * 1024,
        },
        max_snapshot_bytes: 64 * 1024 * 1024,
    }
}
fn source(root: &Path) -> Store {
    let genesis = Genesis::decode(&std::fs::read(root.join("genesis.bin")).unwrap()).unwrap();
    // The supplied fixture has minimum-difficulty headers and actual native
    // proofs. Fixture audit is offline and never repairs or rewrites history.
    assert!(genesis.config().fixture);
    assert_eq!(genesis.config().work_bits, 0);
    assert_eq!(genesis.config().pow_iterations, 0);
    let store = Store::audit_existing(
        &root.join("chain.redb"),
        genesis,
        fixture_limits().chain,
        &NativeVerifier::new().unwrap(),
    )
    .unwrap();
    assert!((37..=48).contains(&store.engine().state().height()));
    store
}
fn journals(root: &Path, prefix: &str) -> Vec<Vec<u8>> {
    let mut names: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(prefix))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect()
}
fn wait_prepared(host: &mut Host, owner: &Mutex<Store>, network: &NetworkStatus, now: &mut u64) {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        *now += 1;
        let store = owner.lock().unwrap();
        host.tick_resident(
            &store,
            *now,
            &[],
            network,
            &crate::eng2::checkpoint_observer::Observer::default(),
        )
        .unwrap();
        if host.preparation.as_ref().unwrap().completed.is_some() || host.pending.is_some() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "bounded archive preparation deadline exceeded"
        );
        drop(store);
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn resident_ticks_progress_during_delayed_full_component_validation_and_reject_unmatched_result() {
    let dir = super::super::tests::Directory::new();
    let owner = Mutex::new(dir.store());
    let root = dir.private("component-worker-export");
    let mut host = Host::open(
        &root,
        &owner.lock().unwrap(),
        crate::eng2::snapshot::tests::limits(),
        None,
    )
    .unwrap();
    let budget = crate::p2p::Budget::new(64 * 1024 * 1024);
    host.enable_async_preparation(&budget).unwrap();
    let work = archive_work::ArchiveWork::component_fixture_for_test(&budget);
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let preparation = host.preparation.as_mut().unwrap();
    preparation
        .worker
        .start_with_test_hook(work, move |_| {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        })
        .unwrap();
    // This proposal is only a bounded context fixture. It is never admitted as
    // a block or candidate; the actual Store remains canonical genesis.
    let candidate = super::super::tests::synthetic_candidate();
    preparation.request = Some(Proposal {
        statement: candidate.statement,
        witness: candidate.witness,
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let network = NetworkStatus::new([[1; 32]]);
    let observer = crate::eng2::checkpoint_observer::Observer::default();
    for now in 100_000..100_003 {
        let store = owner
            .try_lock()
            .expect("keyless preparation must not retain owner");
        let tick = host
            .tick_resident(&store, now, &[], &network, &observer)
            .unwrap();
        assert_eq!(tick.status.height, 0);
        assert_eq!(public_projection(&store, now, None).unwrap()["height"], 0);
        assert!(tick.vote.is_none());
        assert!(tick.proposal.is_none());
    }
    release_tx.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut now = 100_003;
    while host.preparation.as_ref().unwrap().worker.is_busy() {
        now += 1;
        let store = owner.lock().unwrap();
        assert!(
            host.tick_resident(&store, now, &[], &network, &observer)
                .unwrap()
                .vote
                .is_none()
        );
        assert!(Instant::now() < deadline);
        drop(store);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(host.pending.is_none());
    assert!(host.preparation.as_ref().unwrap().completed.is_none());
    assert!(journals(&root, "candidate-").is_empty());
    assert!(journals(&root, "vote-").is_empty());
    host.stop_preparation().unwrap();
    assert_eq!(budget.available().unwrap(), 64 * 1024 * 1024);
}

#[test]
#[ignore = "requires disposable minimum-difficulty native blocks 1..37 and existing synthetic checkpoint signer records"]
fn delayed_native_preparation_allows_append_but_requires_a_new_fresh_round_before_journaling_and_signing()
 {
    let fixture = fixture_root();
    let accepted = source(&fixture);
    let dir = super::super::tests::Directory::new();
    let genesis = Genesis::decode(&accepted.engine().genesis().encode().unwrap()).unwrap();
    let mut store =
        Store::create(&dir.0.join("chain.redb"), genesis, fixture_limits().chain).unwrap();
    let verifier = NativeVerifier::new().unwrap();
    for height in 1..=36 {
        let (header, body) = accepted.block(height).unwrap();
        store.append(&header, &body, &verifier).unwrap();
        if height == 12 {
            store.archive_checkpoint_anchor(fixture_limits()).unwrap();
        }
    }
    let root = dir.private("checkpoint-export");
    let mut host = Host::open(
        &root,
        &store,
        fixture_limits(),
        Some(&fixture.join("checkpoint-signer-0.synthetic.bin")),
    )
    .unwrap();
    assert_eq!(host.signer.as_ref().unwrap().slot, 0);
    let budget = crate::p2p::Budget::new(512 * 1024 * 1024);
    host.enable_async_preparation(&budget).unwrap();
    let network = Arc::new(NetworkStatus::new([[1; 32]]));
    let _connection = network.connected([1; 32]).unwrap();
    network
        .round([1; 32], 0, Some((36, store.engine().state().tip())))
        .unwrap();
    let (statement, witness) = PreparedCheckpoint::current_proposal(&store, fixture_limits())
        .unwrap()
        .unwrap();
    assert_eq!(statement.checkpoint_height, 12);
    assert_eq!(statement.authorization_height, 36);
    let expected_snapshot = store
        .checkpoint_anchor(12, fixture_limits())
        .unwrap()
        .canonical_components(
            Binding {
                genesis: store.engine().genesis().id(),
                rules_commitment: store.engine().genesis().rules_commitment(),
                parent: store.header(12).unwrap().parent,
            },
            fixture_limits().chain,
        )
        .unwrap();
    let expected_snapshot =
        crate::eng2::snapshot::encode_components(&expected_snapshot, fixture_limits()).unwrap();
    let work = store
        .capture_checkpoint_archive(12, fixture_limits(), &budget)
        .unwrap();
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let preparation = host.preparation.as_mut().unwrap();
    preparation
        .worker
        .start_with_test_hook(work, move |_| {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(180)).unwrap();
        })
        .unwrap();
    preparation.request = Some(Proposal {
        statement: statement.clone(),
        witness: witness.clone(),
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let owner = Mutex::new(store);
    let mut now = 100_000;
    // Exercise the real owner projection while full validation is delayed.
    for _ in 0..3 {
        now += 1;
        let store = owner
            .try_lock()
            .expect("checkpoint worker must not hold canonical owner");
        assert_eq!(public_projection(&store, now, None).unwrap()["height"], 36);
        assert!(
            host.tick_resident(
                &store,
                now,
                &[],
                &network,
                &crate::eng2::checkpoint_observer::Observer::default()
            )
            .unwrap()
            .vote
            .is_none()
        );
    }
    assert!(journals(&root, "candidate-").is_empty());
    assert!(journals(&root, "vote-").is_empty());
    // This is an actual native append, not a modified old header or asserted
    // head. The archived anchor and its authorization prefix remain unchanged.
    let (header, body) = accepted.block(37).unwrap();
    owner
        .lock()
        .unwrap()
        .append(&header, &body, &verifier)
        .unwrap();
    network
        .round([1; 32], 0, Some((37, header.id().unwrap())))
        .unwrap();
    network.expire_checkpoint_round_for_test([1; 32]);
    release_tx.send(()).unwrap();
    wait_prepared(&mut host, &owner, &network, &mut now);
    assert!(host.pending.is_none());
    assert!(host.preparation.as_ref().unwrap().completed.is_some());
    assert!(journals(&root, "candidate-").is_empty());
    assert!(journals(&root, "vote-").is_empty());
    network
        .round([1; 32], 0, Some((36, statement.authorization_block)))
        .unwrap();
    now += 1;
    {
        let store = owner.lock().unwrap();
        assert!(
            host.tick_resident(
                &store,
                now,
                &[],
                &network,
                &crate::eng2::checkpoint_observer::Observer::default()
            )
            .unwrap()
            .vote
            .is_none()
        );
    }
    assert!(journals(&root, "candidate-").is_empty());
    network.begin_round([1; 32]).unwrap();
    now += 1;
    {
        let store = owner.lock().unwrap();
        assert!(
            host.tick_resident(
                &store,
                now,
                &[],
                &network,
                &crate::eng2::checkpoint_observer::Observer::default()
            )
            .unwrap()
            .vote
            .is_none()
        );
    }
    assert!(journals(&root, "vote-").is_empty());
    network
        .round([1; 32], 0, Some((37, header.id().unwrap())))
        .unwrap();
    now += 1;
    let store = owner.lock().unwrap();
    let tick = host
        .tick_resident(
            &store,
            now,
            &[],
            &network,
            &crate::eng2::checkpoint_observer::Observer::default(),
        )
        .unwrap();
    assert!(tick.vote.is_some());
    let pending = host.pending.as_ref().unwrap();
    assert_eq!(pending.statement(), &statement);
    assert_eq!(pending.witness(), &witness);
    assert_eq!(pending.snapshot_bytes(), expected_snapshot);
    assert_eq!(pending.statement.authorization_height, 36);
    assert_eq!(store.engine().state().height(), 37);
    assert_eq!(journals(&root, "candidate-").len(), 1);
    let first_vote = journals(&root, "vote-");
    assert_eq!(first_vote.len(), 1);
    let vote = tick.vote.unwrap();
    let duplicate = Incoming::Certified {
        certificate: Box::new(Certificate {
            statement: statement.clone(),
            votes: [vote.clone(), vote],
        }),
        witness: witness.clone(),
    };
    now += 1;
    assert!(
        host.tick_resident(
            &store,
            now,
            &[duplicate],
            &network,
            &crate::eng2::checkpoint_observer::Observer::default()
        )
        .is_err()
    );
    assert!(host.pending.is_some());
    assert_eq!(journals(&root, "vote-"), first_vote);
    now += 1;
    host.tick_resident(
        &store,
        now,
        &[],
        &network,
        &crate::eng2::checkpoint_observer::Observer::default(),
    )
    .unwrap();
    assert_eq!(journals(&root, "vote-"), first_vote);
    drop(store);
    host.stop_preparation().unwrap();
}

#[test]
#[ignore = "requires disposable native canonical, anchor-fork, authorization-fork and activated-epoch fixture stores"]
fn complete_native_archive_reuse_rejects_actual_anchor_authorization_and_epoch_changes() {
    let fixture = fixture_root();
    let accepted = source(&fixture);
    let budget = crate::p2p::Budget::new(512 * 1024 * 1024);
    let mut worker = archive_work::ArchiveWorker::default();
    worker
        .start(
            accepted
                .capture_checkpoint_archive(12, fixture_limits(), &budget)
                .unwrap(),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(180);
    let validated = loop {
        if let Some(validated) = worker.try_complete().unwrap() {
            break validated;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    };
    validated.check_current(&accepted).unwrap();
    for variant in ["anchor-fork", "authorization-fork", "activated-epoch"] {
        let changed = source(&fixture.join(variant));
        assert_eq!(
            changed.engine().genesis().id(),
            accepted.engine().genesis().id()
        );
        assert_eq!(
            changed.engine().state().height(),
            accepted.engine().state().height()
        );
        match variant {
            "anchor-fork" => assert_ne!(changed.header(12).unwrap(), accepted.header(12).unwrap()),
            "authorization-fork" => {
                assert_eq!(changed.header(12).unwrap(), accepted.header(12).unwrap());
                assert_ne!(
                    changed.header(accepted.engine().state().height()).unwrap(),
                    accepted.header(accepted.engine().state().height()).unwrap()
                );
            }
            _ => assert_ne!(
                changed
                    .engine()
                    .state()
                    .governance()
                    .active_roster()
                    .digest(changed.engine().state().network()),
                accepted
                    .engine()
                    .state()
                    .governance()
                    .active_roster()
                    .digest(accepted.engine().state().network())
            ),
        }
        assert!(validated.check_current(&changed).is_err());
    }
}

#[test]
fn retained_barrier_cancels_inflight_archive_without_waiting_or_rearming_unchanged_head() {
    let dir = super::super::tests::Directory::new();
    let owner = Mutex::new(dir.store());
    let root = dir.private("retained-worker-export");
    let mut host = Host::open_retained(
        &root,
        &owner.lock().unwrap(),
        crate::eng2::snapshot::tests::limits(),
        None,
        |_, _| Ok(None),
    )
    .unwrap();
    let maximum = 64 * 1024 * 1024;
    let budget = crate::p2p::Budget::new(maximum);
    host.enable_async_preparation(&budget).unwrap();
    let work = archive_work::ArchiveWork::component_fixture_for_test(&budget);
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let preparation = host.preparation.as_mut().unwrap();
    preparation
        .worker
        .start_with_test_hook(work, move |_| {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        })
        .unwrap();
    // Only a bounded context fixture; it never becomes an accepted block.
    let candidate = super::super::tests::synthetic_candidate();
    let retired_height = candidate.statement.checkpoint_height;
    preparation.request = Some(Proposal {
        statement: candidate.statement,
        witness: candidate.witness,
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let guard = owner.lock().unwrap();
    let original_tip = guard.engine().state().tip();
    // The worker still waits for release. Joining under this lock would fail
    // its bounded rendezvous instead of returning from the output barrier.
    host.pause_reorganization_exports_at(0).unwrap();
    let preparation = host.preparation.as_ref().unwrap();
    assert!(preparation.worker.is_busy());
    assert!(preparation.request.is_some());
    assert_ne!(preparation.request_generation, preparation.generation);
    assert!(host.anchor_retired(retired_height));
    release_tx.send(()).unwrap();
    drop(guard);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let store = owner.lock().unwrap();
        host.advance_preparation(&store, None).unwrap();
        assert_eq!(store.engine().state().tip(), original_tip);
        let preparation = host.preparation.as_ref().unwrap();
        if !preparation.worker.is_busy() {
            assert!(preparation.request.is_none());
            assert!(preparation.completed.is_none());
            assert_eq!(preparation.request_generation, preparation.generation);
            break;
        }
        assert!(Instant::now() < deadline);
        drop(store);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(host.pending.is_none());
    assert!(host.latest_checkpoint().is_none());
    assert!(journals(&root, "candidate-").is_empty());
    assert!(journals(&root, "vote-").is_empty());
    assert!(!root.join("checkpoint-eng2.json").exists());
    host.stop_preparation().unwrap();
    assert_eq!(budget.available().unwrap(), maximum);
}

#[test]
fn retained_barrier_drops_completed_candidate_and_rejects_same_anchor_after_failed_restore() {
    let dir = super::super::tests::Directory::new();
    let store = dir.store();
    let root = dir.private("completed-retained-export");
    let mut host = Host::open_retained(
        &root,
        &store,
        crate::eng2::snapshot::tests::limits(),
        None,
        |_, _| Ok(None),
    )
    .unwrap();
    let budget = crate::p2p::Budget::new(64 * 1024 * 1024);
    host.enable_async_preparation(&budget).unwrap();
    // This existing signature-format fixture supplies only the buffered
    // candidate context. No block or snapshot is admitted to the Store.
    let candidate = super::super::tests::synthetic_candidate();
    let proposal = Proposal {
        statement: candidate.statement.clone(),
        witness: candidate.witness.clone(),
    };
    host.preparation.as_mut().unwrap().completed = Some(candidate);
    let original_tip = store.engine().state().tip();
    host.pause_reorganization_exports_at(0).unwrap();
    assert_eq!(store.engine().state().tip(), original_tip);
    assert!(host.preparation.as_ref().unwrap().completed.is_none());
    assert!(host.anchor_retired(proposal.statement.checkpoint_height));
    assert_eq!(
        host.schedule_peer_preparation(&store, &proposal, true)
            .unwrap_err(),
        "checkpoint preparation anchor is retired",
    );
    host.advance_preparation(&store, None).unwrap();
    assert!(host.pending.is_none());
    assert!(host.latest_checkpoint().is_none());
    assert!(journals(&root, "candidate-").is_empty());
    assert!(journals(&root, "vote-").is_empty());
    assert!(!root.join("checkpoint-eng2.json").exists());
    host.stop_preparation().unwrap();
    assert_eq!(budget.available().unwrap(), 64 * 1024 * 1024);
}

#[test]
#[ignore = "requires disposable minimum-difficulty native blocks 1..37 and existing synthetic signer records 0 and 1"]
fn retained_native_restore_reuses_live_budget_and_rejects_every_same_head_material_mutation() {
    use std::fs::{self, FileTimes};
    fn restore(host: &mut Host, store: &Store) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            if host.reconcile_retained_async(store, || Ok(None))? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("retained native fixture deadline exceeded".into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    let fixture = fixture_root();
    let store = source(&fixture);
    assert!((37..48).contains(&store.engine().state().height()));
    let dir = super::super::tests::Directory::new();
    let root = dir.private("retained-native");
    let mut export = PublicExport::open(&root, &store, fixture_limits()).unwrap();
    let prepared = PreparedCheckpoint::prepare_from_archive(&store, fixture_limits())
        .unwrap()
        .unwrap();
    let mut votes = Vec::new();
    for slot in 0..=1 {
        let signer = ExistingSigner::load(
            &fixture.join(format!("checkpoint-signer-{slot}.synthetic.bin")),
            &store,
        )
        .unwrap();
        votes.push(
            export
                .sign_vote(
                    &store,
                    &prepared,
                    slot,
                    &signer.key,
                    [slot; 32],
                    fixture_limits(),
                )
                .unwrap(),
        );
    }
    let initial_local_source = (prepared.statement.clone(), votes[0].clone());
    let certificate = prepared
        .certify(&store, votes.try_into().unwrap(), 100_000)
        .unwrap();
    assert!(
        export
            .publish_checkpoint(&store, &certificate, fixture_limits())
            .unwrap()
    );
    drop((certificate, export));
    let budget = crate::p2p::Budget::new(640 * 1024 * 1024);
    let mut host = Host::open_resident(&root, &store, fixture_limits(), None, &budget).unwrap();
    restore(&mut host, &store).unwrap();
    let pointer = host.latest.as_ref().unwrap().prepared.snapshot.as_ptr();
    let native = host
        .latest
        .as_ref()
        .unwrap()
        .prepared
        ._native_identity
        .clone()
        .unwrap();
    let available = budget.available().unwrap();
    restore(&mut host, &store).unwrap();
    let latest = host.latest.as_ref().unwrap();
    assert_eq!(latest.prepared.snapshot.as_ptr(), pointer);
    assert!(native.same_live_validation(latest.prepared._native_identity.as_ref().unwrap()));
    assert_eq!(budget.available().unwrap(), available);
    let head = (
        store.engine().state().height(),
        store.engine().state().tip(),
    );
    let mut artifacts: Vec<_> = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy();
            name == "checkpoint-eng2.json"
                || name.starts_with("candidate-")
                || name.starts_with("vote-")
                || name.starts_with("checkpoint-publication-")
                || name.ends_with(".snapshot-eng2.bin")
                || name.ends_with(".witness-eng2.bin")
                || name.ends_with(".certificate-eng2.bin")
        })
        .collect();
    artifacts.sort();
    assert!(artifacts.len() >= 8);
    for path in artifacts {
        let original = fs::read(&path).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let mut corrupt = original.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(&path, corrupt).unwrap();
        fs::File::open(&path)
            .unwrap()
            .set_times(FileTimes::new().set_modified(metadata.modified().unwrap()))
            .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().modified().unwrap(),
            metadata.modified().unwrap()
        );
        assert!(restore(&mut host, &store).is_err());
        assert!(host.latest_checkpoint().is_none());
        assert_eq!(
            head,
            (
                store.engine().state().height(),
                store.engine().state().tip()
            )
        );
        fs::write(&path, original).unwrap();
        restore(&mut host, &store).unwrap();
        assert_eq!(
            host.latest.as_ref().unwrap().prepared.snapshot.as_ptr(),
            pointer
        );
        assert_eq!(budget.available().unwrap(), available);
    }
    let cursor_path = root.join("checkpoint-eng2.json");
    let original_cursor = fs::read(&cursor_path).unwrap();
    let height = host
        .latest
        .as_ref()
        .unwrap()
        .certificate
        .statement
        .checkpoint_height;
    let record_path = root.join(format!("checkpoint-publication-{height:020}.json"));
    let original_record = fs::read(&record_path).unwrap();
    let mut changed_time: Value = serde_json::from_slice(&original_cursor).unwrap();
    changed_time["published_unix_seconds"] = serde_json::json!(100_001);
    let changed_time = serde_json::to_vec(&changed_time).unwrap();
    fs::write(&cursor_path, &changed_time).unwrap();
    fs::write(&record_path, &changed_time).unwrap();
    assert!(restore(&mut host, &store).is_err());
    fs::write(cursor_path, original_cursor).unwrap();
    fs::write(record_path, original_record).unwrap();
    restore(&mut host, &store).unwrap();
    let statement = &host.latest.as_ref().unwrap().certificate.statement;
    let third = root.join(format!(
        "vote-{:020}-{:020}-2.eng2.bin",
        statement.roster_sequence, statement.checkpoint_height
    ));
    assert!(!third.exists());
    let invalid = [
        statement.encode().unwrap().as_slice(),
        &[2],
        &[0; super::super::super::certificate::SIGNATURE_BYTES],
    ]
    .concat();
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&third)
        .unwrap()
        .write_all(&invalid)
        .unwrap();
    assert!(restore(&mut host, &store).is_err());
    fs::remove_file(third).unwrap();
    restore(&mut host, &store).unwrap();
    // Known local provenance survives a missing live pending and a failed
    // restoration. A same-statement eligible candidate cannot reenter cold
    // after its successful local durable vote disappears.
    host.journaled_vote = Some(initial_local_source.clone());
    host.pending = None;
    let eligible_vote = root.join(format!(
        "vote-{:020}-{:020}-0.eng2.bin",
        initial_local_source.0.roster_sequence, initial_local_source.0.checkpoint_height
    ));
    let held_eligible_vote = root.join("held-eligible-local-vote");
    fs::rename(&eligible_vote, &held_eligible_vote).unwrap();
    assert!(restore(&mut host, &store).is_err());
    assert!(host.pending.is_none());
    assert_eq!(host.journaled_vote, Some(initial_local_source));
    assert!(restore(&mut host, &store).is_err());
    fs::rename(&held_eligible_vote, &eligible_vote).unwrap();
    restore(&mut host, &store).unwrap();
    // A confirmed peer checkpoint need not be a local cadence multiple.
    // Keep the existing protocol rule and inspect its own exact journal names.
    let mut noncadence_statement = host.latest.as_ref().unwrap().certificate.statement.clone();
    noncadence_statement.checkpoint_height = 13;
    noncadence_statement.checkpoint_block = store.header(13).unwrap().id().unwrap();
    let noncadence_witness = host.latest.as_ref().unwrap().prepared.witness.clone();
    let archive = store
        .capture_checkpoint_archive(13, fixture_limits(), &budget)
        .unwrap()
        .validate(&std::sync::atomic::AtomicBool::new(false))
        .unwrap();
    let prepared = PreparedCheckpoint::from_validated_archive(
        &store,
        archive,
        noncadence_statement,
        noncadence_witness,
        fixture_limits(),
    )
    .unwrap();
    let mut export = PublicExport::open(&root, &store, fixture_limits()).unwrap();
    let signer =
        ExistingSigner::load(&fixture.join("checkpoint-signer-0.synthetic.bin"), &store).unwrap();
    let vote = export
        .sign_vote(&store, &prepared, 0, &signer.key, [3; 32], fixture_limits())
        .unwrap();
    let own_candidate = root.join(format!(
        "candidate-{:020}-{:020}.eng2.bin",
        prepared.statement.roster_sequence, prepared.statement.checkpoint_height
    ));
    let new_local_source = (prepared.statement.clone(), vote.clone());
    host.pending = Some(prepared);
    host.votes[0] = Some(vote.clone());
    drop(export);
    restore(&mut host, &store).unwrap();
    restore(&mut host, &store).unwrap();
    assert_eq!(
        host.pending.as_ref().unwrap().statement.checkpoint_height,
        13
    );
    assert_eq!(host.votes[0], Some(vote));
    let local_vote = root.join(format!(
        "vote-{:020}-{:020}-0.eng2.bin",
        host.pending.as_ref().unwrap().statement.roster_sequence,
        13
    ));
    let held_vote = root.join("held-known-local-vote");
    // A remote received vote has no matching local durable-source tag. Its
    // valid signature suffices without a journal; older provenance is retained.
    fs::rename(&local_vote, &held_vote).unwrap();
    restore(&mut host, &store).unwrap();
    assert!(host.votes[0].is_some());
    assert!(!local_vote.exists());
    assert!(host.journaled_vote.is_some());
    fs::rename(&held_vote, &local_vote).unwrap();
    // Model the new source tag installed only after the same successful local
    // durable operation in Host's production signing path. It replaces only
    // the older successful local source, never clears it on failure or reorg.
    host.journaled_vote = Some(new_local_source);
    fs::rename(&local_vote, &held_vote).unwrap();
    assert!(restore(&mut host, &store).is_err());
    assert!(host.journaled_vote.is_some());
    fs::rename(&held_vote, &local_vote).unwrap();
    restore(&mut host, &store).unwrap();
    let held_candidate = root.join("held-noncadence-candidate");
    fs::rename(&own_candidate, &held_candidate).unwrap();
    assert!(restore(&mut host, &store).is_err());
    assert!(host.latest_checkpoint().is_none());
    fs::rename(&held_candidate, &own_candidate).unwrap();
    restore(&mut host, &store).unwrap();
    let held_cursor = root.join("held-live-checkpoint-cursor");
    fs::rename(root.join("checkpoint-eng2.json"), &held_cursor).unwrap();
    assert!(restore(&mut host, &store).is_err());
    fs::rename(&held_cursor, root.join("checkpoint-eng2.json")).unwrap();
    restore(&mut host, &store).unwrap();
    assert_eq!(host.latest.as_ref().unwrap().published, 100_000);
    host.stop_preparation().unwrap();
    drop(host);
    assert_eq!(budget.available().unwrap(), 640 * 1024 * 1024);
}

#[test]
fn resident_pause_drains_obsolete_completed_worker_without_an_activity_enabled_tick() {
    for polled in [false, true] {
        let dir = super::super::tests::Directory::new();
        let owner = Mutex::new(dir.store());
        let root = dir.private("pause-completed-worker");
        let mut host = Host::open(
            &root,
            &owner.lock().unwrap(),
            crate::eng2::snapshot::tests::limits(),
            None,
        )
        .unwrap();
        let maximum = 64 * 1024 * 1024;
        let budget = crate::p2p::Budget::new(maximum);
        host.enable_async_preparation(&budget).unwrap();
        let work = archive_work::ArchiveWork::component_fixture_for_test(&budget);
        host.preparation
            .as_mut()
            .unwrap()
            .worker
            .start(work)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !host
            .preparation
            .as_ref()
            .unwrap()
            .worker
            .has_finished_result_for_test()
        {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        if polled {
            // Archive results remain buffered when the retained-result accessor
            // polls them. Pause must discard both result representations.
            assert!(
                host.preparation
                    .as_mut()
                    .unwrap()
                    .worker
                    .try_complete_retained()
                    .unwrap()
                    .is_none()
            );
        }
        assert!(budget.reserve(maximum).is_err());
        let store = owner.lock().unwrap();
        let tip = store.engine().state().tip();
        host.pause_reorganization_exports().unwrap();
        let preparation = host.preparation.as_ref().unwrap();
        assert!(!preparation.worker.is_busy());
        assert!(preparation.request.is_none() && preparation.completed.is_none());
        assert!(!preparation.retained_request);
        assert_eq!(store.engine().state().tip(), tip);
        let replay = budget.reserve(maximum).unwrap();
        drop(replay);
        // No reconcile, signing tick, native execution or ownership bypass.
        assert!(host.pending.is_none() && host.latest_checkpoint().is_none());
        drop(store);
        host.stop_preparation().unwrap();
    }
}
