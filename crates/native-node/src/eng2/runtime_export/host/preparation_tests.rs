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
