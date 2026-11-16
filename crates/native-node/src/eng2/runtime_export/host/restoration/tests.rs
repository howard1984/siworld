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
    assert!(root.join("wallet-head.json").is_file());
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
fn initial_and_failed_authentication_preserve_history_without_restoring_authority() {
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
    assert!(root.join("wallet-head.json").is_file());
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
    assert!(root.join("wallet-head.json").is_file());
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

#[test]
fn authenticated_retirement_discards_old_pending_without_granting_new_authority() {
    let directory = Directory::new();
    let store = directory.store();
    let root = directory.private("installed-retirement");
    let budget = crate::p2p::Budget::new(64 * 1024 * 1024);
    let mut host = Host::open_resident(&root, &store, limits(), None, &budget).unwrap();
    // Isolate installation of a worker-authenticated result. This format-only
    // candidate is never presented as a natively executed checkpoint.
    let mut old = crate::eng2::runtime_export::tests::synthetic_candidate();
    old.statement.checkpoint_height = 12;
    old.statement.authorization_height = 36;
    host.pending = Some(old);
    host.votes[0] = Some(Vote {
        slot: 0,
        signature: [5; crate::eng2::certificate::SIGNATURE_BYTES],
    });
    let mut result = empty_result(&host, &store);
    result.pending = Restored::Retired(12);
    result.authenticated_retired_through = Some(12);
    host.install_retained(&store, result).unwrap();
    assert!(host.pending.is_none());
    assert!(host.votes.iter().all(Option::is_none));
    assert!(host.anchor_retired(12));
    assert!(!host.anchor_retired(24));
    assert!(host.latest_checkpoint().is_none());
    assert!(host.signer.is_none());
    assert!(host.tick(&store, 10, &[]).is_err());
    host.stop_preparation().unwrap();
    assert_eq!(budget.available().unwrap(), 64 * 1024 * 1024);
}

#[test]
fn captured_revision_freshness_rejects_another_store_instance() {
    let first = Directory::new();
    let store = first.store();
    let second = Directory::new();
    let other = second.store();
    let revision = store.checkpoint_revision().unwrap();
    assert!(revision.is_current_revision(&store).unwrap());
    assert!(revision.is_current_revision(&other).is_err());
}

#[test]
fn obsolete_retained_success_stays_pending_and_authentication_errors_remain_hard() {
    use std::{
        fs,
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    let mut directory = Directory::new();
    directory.0 = directory.0.canonicalize().unwrap();
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = directory.store();
    let identity = crate::identity::NativeIdentity::initialize(
        &directory.0,
        store.engine().genesis().peer_binding(),
    )
    .unwrap();
    store.enable_authenticated_restart(identity).unwrap();
    let revision = store.checkpoint_revision().unwrap();
    let original_head = (
        store.engine().state().height(),
        store.engine().state().tip(),
    );
    let root = directory.private("obsolete-retained-result");
    let budget = crate::p2p::Budget::new(64 * 1024 * 1024);
    let mut host = Host::open_resident(&root, &store, limits(), None, &budget).unwrap();
    let work = RetainedWork::capture(
        &store,
        None,
        &host.export,
        limits(),
        &budget,
        host.preparation.as_ref().unwrap().generation,
        None,
        None,
        None,
    )
    .unwrap();
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
    // A real authenticated same-head restoration advances the canonical
    // revision without proof generation or an externally supplied block corpus.
    store
        .restore_ancestor(original_head.0, original_head.1)
        .unwrap();
    assert_eq!(
        original_head,
        (
            store.engine().state().height(),
            store.engine().state().tip()
        )
    );
    assert!(!revision.is_current_revision(&store).unwrap());
    release_tx.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(!host.reconcile_retained_async(&store, || Ok(None)).unwrap());
        assert!(!host.retained_ready);
        assert!(host.latest_checkpoint().is_none());
        assert_eq!(
            host.tick(&store, 1, &[]).err().as_deref(),
            Some("checkpoint retained restoration unavailable")
        );
        if !host.preparation.as_ref().unwrap().retained_request {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    // An obsolete successful result must not suppress a subsequent genuine
    // artifact authentication failure or reopen any publication authority.
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("checkpoint-eng2.json"))
        .unwrap()
        .write_all(b"invalid")
        .unwrap();
    loop {
        match host.reconcile_retained_async(&store, || Ok(None)) {
            Err(_) => break,
            Ok(ready) => assert!(!ready),
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(!host.retained_ready && host.latest_checkpoint().is_none());
    assert_eq!(
        host.tick(&store, 2, &[]).err().as_deref(),
        Some("checkpoint retained restoration unavailable")
    );
    let other_directory = Directory::new();
    assert!(
        revision
            .is_current_revision(&other_directory.store())
            .is_err()
    );
    host.stop_preparation().unwrap();
    assert_eq!(budget.available().unwrap(), 64 * 1024 * 1024);
}
