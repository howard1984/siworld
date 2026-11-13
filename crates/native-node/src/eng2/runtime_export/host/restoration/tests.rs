use super::*;
use crate::eng2::{runtime_export::tests::Directory, snapshot::tests::limits};
use std::{
    sync::{Mutex, mpsc},
    time::{Duration, Instant},
};

fn empty_result(host: &Host, store: &Store) -> ValidatedRetained {
    ValidatedRetained {
        revision: store.checkpoint_revision().unwrap(),
        generation: host.preparation.as_ref().unwrap().generation,
        material_generation: host.export.material_generation(),
        retired_through: host.retired_through,
        authenticated_retired_through: None,
        material: [0; 32],
        cursor: None,
        latest: Restored::Absent,
        pending: Restored::Absent,
    }
}

#[test]
fn delayed_cold_restoration_releases_owner_and_keeps_exports_unavailable() {
    let directory = Directory::new();
    let owner = Mutex::new(directory.store());
    let root = directory.private("cold-retained");
    let budget = crate::p2p::Budget::new(64 * 1024 * 1024);
    let mut host =
        Host::open_resident(&root, &owner.lock().unwrap(), limits(), None, &budget).unwrap();
    host.export
        .publish_wallet_head(&owner.lock().unwrap(), 10)
        .unwrap();
    host.wallet_requested = true;
    let wallet_cursor = std::fs::read(root.join("wallet-head.json")).unwrap();
    let material_generation = host.export.material_generation();
    let file_count = std::fs::read_dir(&root).unwrap().count();
    let work = {
        let store = owner.lock().unwrap();
        RetainedWork::capture(
            &store,
            None,
            &host.export,
            limits(),
            &budget,
            0,
            None,
            None,
            None,
        )
        .unwrap()
    };
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let preparation = host.preparation.as_mut().unwrap();
    preparation
        .worker
        .start_retained_with_test_hook(work, move |_| {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        })
        .unwrap();
    preparation.retained_request = true;
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    for now in 1..=3 {
        let store = owner
            .try_lock()
            .expect("retained reader must not retain the canonical owner");
        assert!(!host.reconcile_retained_async(&store, || Ok(None)).unwrap());
        assert_eq!(public_projection(&store, now, None).unwrap()["height"], 0);
        assert!(host.latest_checkpoint().is_none());
        assert!(host.tick(&store, now, &[]).is_err());
        assert!(host.tick_wallet_export(&store, now, &budget).is_err());
        assert_eq!(
            std::fs::read(root.join("wallet-head.json")).unwrap(),
            wallet_cursor
        );
        assert_eq!(host.export.material_generation(), material_generation);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), file_count);
    }
    release_tx.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if host
            .reconcile_retained_async(&owner.lock().unwrap(), || Ok(None))
            .unwrap()
        {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(host.retained_ready);
    assert_eq!(budget.available().unwrap(), 64 * 1024 * 1024);
    host.stop_preparation().unwrap();
}

#[test]
fn late_restore_result_cannot_cross_same_head_barrier_or_reopened_store() {
    let directory = Directory::new();
    let store = directory.store();
    let root = directory.private("restore-generations");
    let budget = crate::p2p::Budget::new(64 * 1024 * 1024);
    let mut host = Host::open_resident(&root, &store, limits(), None, &budget).unwrap();
    let late = empty_result(&host, &store);
    let before = (
        store.engine().state().height(),
        store.engine().state().tip(),
    );
    host.export.publish_wallet_head(&store, 10).unwrap();
    assert!(root.join("wallet-head.json").is_file());
    host.pause_reorganization_exports_at(0).unwrap();
    assert!(!root.join("wallet-head.json").exists());
    // The barrier survives even when a subsequent restoration never commits.
    assert_eq!(
        before,
        (
            store.engine().state().height(),
            store.engine().state().tip()
        )
    );
    assert!(host.install_retained(&store, late).is_err());
    assert!(!host.retained_ready);
    let mut wrong_material = empty_result(&host, &store);
    wrong_material.material_generation += 1;
    assert!(host.install_retained(&store, wrong_material).is_err());
    let other_directory = Directory::new();
    let other = other_directory.store();
    let same_head_other_instance = empty_result(&host, &store);
    assert!(
        host.install_retained(&other, same_head_other_instance)
            .is_err()
    );
    let before_retirement = empty_result(&host, &store);
    host.retire_anchor(12).unwrap();
    assert!(host.install_retained(&store, before_retirement).is_err());
    assert_eq!(host.retired_through, Some(12));
    assert!(host.latest.is_none() && host.pending.is_none());
}

#[test]
fn initial_and_failed_authentication_withdraw_mutable_wallet_head() {
    use std::{fs, io::Write, os::unix::fs::OpenOptionsExt};
    let directory = Directory::new();
    let store = directory.store();
    let root = directory.private("failed-retained");
    let export = PublicExport::open_unrestored(&root, &store).unwrap();
    export.publish_wallet_head(&store, 10).unwrap();
    assert!(root.join("wallet-head.json").is_file());
    drop(export);
    let budget = crate::p2p::Budget::new(64 * 1024 * 1024);
    let mut host = Host::open_resident(&root, &store, limits(), None, &budget).unwrap();
    assert!(!root.join("wallet-head.json").exists());
    host.export.publish_wallet_head(&store, 11).unwrap();
    let before = host.preparation.as_ref().unwrap().generation;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("checkpoint-eng2.json"))
        .unwrap()
        .write_all(b"invalid")
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if host.reconcile_retained_async(&store, || Ok(None)).is_err() {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(!root.join("wallet-head.json").exists());
    assert!(host.preparation.as_ref().unwrap().generation > before);
    assert!(!host.retained_ready);
    assert!(host.latest_checkpoint().is_none());
    host.stop_preparation().unwrap();
    assert_eq!(budget.available().unwrap(), 64 * 1024 * 1024);
}

#[test]
fn warm_pending_reuse_preserves_collected_votes_and_original_snapshot_guard() {
    use crate::eng2::runtime_export::retained_work::LiveArchive;
    use std::sync::atomic::AtomicBool;
    let directory = Directory::new();
    let store = directory.store();
    let root = directory.private("warm-vote-transfer");
    let mut host = Host::open(&root, &store, limits(), None).unwrap();
    let budget = crate::p2p::Budget::new(128 * 1024 * 1024);
    let validated = archive_work::ArchiveWork::component_fixture_for_test(&budget)
        .validate(&AtomicBool::new(false))
        .unwrap();
    let identity = validated.identity();
    let (snapshot, guard) = validated
        .into_snapshot(std::mem::size_of::<CertifiedCheckpoint>())
        .unwrap();
    // This isolates an already-authenticated object's transfer and vote set.
    // It never admits this format fixture as an executed Store checkpoint.
    let mut prepared = crate::eng2::runtime_export::tests::synthetic_candidate();
    prepared.statement.checkpoint_height = 13;
    prepared.statement.authorization_height = 37;
    prepared.snapshot = snapshot;
    prepared._snapshot_reservation = Some(guard);
    prepared._native_identity = Some(identity);
    host.pending = Some(prepared);
    host.votes[0] = Some(Vote {
        slot: 0,
        signature: std::array::from_fn(|_| 5),
    });
    host.votes[2] = Some(Vote {
        slot: 2,
        signature: std::array::from_fn(|_| 7),
    });
    let original_votes = host.votes.clone();
    let pointer = host.pending.as_ref().unwrap().snapshot.as_ptr();
    let available = budget.available().unwrap();
    for _ in 0..2 {
        let live = LiveArchive::capture(host.pending.as_ref().unwrap()).unwrap();
        host.install_current_retained_pending(PreparedResult::Reuse(Box::new(live)), 37, None)
            .unwrap();
        assert_eq!(host.votes, original_votes);
        assert_eq!(host.pending.as_ref().unwrap().snapshot.as_ptr(), pointer);
        assert_eq!(budget.available().unwrap(), available);
    }
    drop(host);
    assert_eq!(budget.available().unwrap(), 128 * 1024 * 1024);
}
