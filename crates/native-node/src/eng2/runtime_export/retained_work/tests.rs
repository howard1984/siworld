//! Component proof and live-budget tests; these grant no canonical authority.
use super::*;

#[test]
fn native_reuse_requires_complete_input_bytes_and_the_original_live_guard() {
    let budget = crate::p2p::Budget::new(128 * 1024 * 1024);
    let work = ArchiveWork::component_fixture_for_test(&budget);
    let validated = work.validate(&AtomicBool::new(false)).unwrap();
    let native = validated.identity();
    let mut prepared = super::super::tests::synthetic_candidate();
    let (snapshot, guard) = validated
        .into_snapshot(std::mem::size_of::<CertifiedCheckpoint>())
        .unwrap();
    prepared.snapshot = snapshot;
    prepared._snapshot_reservation = Some(guard);
    prepared._native_identity = Some(native.clone());
    let live = LiveArchive::capture(&prepared).unwrap();
    let before = budget.available().unwrap();
    assert!(live.matches(&prepared));
    assert_eq!(budget.available().unwrap(), before);
    let captured = ArchiveWork::component_fixture_for_test(&budget);
    assert!(native.matches(&captured, &prepared.snapshot).unwrap());
    drop(captured);
    let captured = ArchiveWork::component_fixture_with_changed_archive_for_test(&budget);
    assert!(!native.matches(&captured, &prepared.snapshot).unwrap());
    drop(captured);
    let captured = ArchiveWork::component_fixture_for_test(&budget);
    let mut changed_snapshot = prepared.snapshot.clone();
    changed_snapshot[10] ^= 1;
    assert!(!native.matches(&captured, &changed_snapshot).unwrap());
    drop(changed_snapshot);
    let independently_validated = captured.validate(&AtomicBool::new(false)).unwrap();
    assert!(!native.same_live_validation(&independently_validated.identity()));
    drop(independently_validated);
    let guard = prepared._snapshot_reservation.take().unwrap();
    assert!(LiveArchive::capture(&prepared).is_none());
    assert!(!live.matches(&prepared));
    assert_eq!(budget.available().unwrap(), before);
    prepared._snapshot_reservation = Some(guard);
    assert!(live.matches(&prepared));
    {
        use std::{fs, io::Write, os::unix::fs::OpenOptionsExt};
        let directory = crate::eng2::runtime_export::tests::Directory::new();
        let store = directory.store();
        let root = directory.private("required-live-material");
        let export = PublicExport::open_unrestored(&root, &store).unwrap();
        let original_statement = prepared.statement.clone();
        // Required captured records must be visited even when their own height
        // and epoch differ from current eligible selection. These format
        // fixtures intentionally cannot authenticate against canonical genesis.
        for height in [12, 13] {
            prepared.statement.checkpoint_height = height;
            prepared.statement.authorization_height = height + 24;
            prepared.statement.roster_sequence += 1;
            let work = RetainedWork::capture(
                &store,
                None,
                &export,
                crate::eng2::snapshot::tests::limits(),
                &budget,
                0,
                None,
                None,
                Some(&prepared),
            )
            .unwrap();
            let error = work.validate(&AtomicBool::new(false)).err().unwrap();
            assert_eq!(error, "checkpoint live candidate material missing");
            let name = format!(
                "candidate-{:020}-{height:020}.eng2.bin",
                prepared.statement.roster_sequence
            );
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.join(&name))
                .unwrap()
                .write_all(b"malformed")
                .unwrap();
            let work = RetainedWork::capture(
                &store,
                None,
                &export,
                crate::eng2::snapshot::tests::limits(),
                &budget,
                0,
                None,
                None,
                Some(&prepared),
            )
            .unwrap();
            assert!(work.validate(&AtomicBool::new(false)).is_err());
            fs::remove_file(root.join(name)).unwrap();
        }
        prepared.statement = original_statement;
        let certificate = Certificate {
            statement: prepared.statement.clone(),
            votes: [
                Vote {
                    slot: 0,
                    signature: std::array::from_fn(|_| 0),
                },
                Vote {
                    slot: 1,
                    signature: std::array::from_fn(|_| 0),
                },
            ],
        };
        let latest = CertifiedCheckpoint {
            prepared,
            certificate,
            published: 100_000,
        };
        let work = RetainedWork::capture(
            &store,
            None,
            &export,
            crate::eng2::snapshot::tests::limits(),
            &budget,
            0,
            None,
            Some(&latest),
            None,
        )
        .unwrap();
        let error = work.validate(&AtomicBool::new(false)).err().unwrap();
        assert_eq!(error, "checkpoint live publication cursor missing");
        drop(latest);
    }
    drop((live, native));
    assert_eq!(budget.available().unwrap(), 128 * 1024 * 1024);
}

#[test]
fn pinned_reader_types_move_without_transferring_a_store_or_signer() {
    fn requires_send<T: Send>() {}
    requires_send::<crate::eng2::store::CheckpointArchiveRead>();
    requires_send::<crate::eng2::store::CheckpointRestoreRead>();
    requires_send::<crate::eng2::branches::CheckpointHeaders>();
    requires_send::<RetainedWork>();
    requires_send::<ValidatedRetained>();
}
