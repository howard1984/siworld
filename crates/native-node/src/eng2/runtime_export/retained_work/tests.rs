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

#[cfg(feature = "eng2-rehearsal")]
#[test]
#[ignore = "requires an existing owner-local public native Store fixture"]
fn retained_budget_diagnostic_existing_live_identity_requires_duplicate_workspace() {
    use super::super::budget_diagnostic::Operation;
    let source = std::path::PathBuf::from(std::env::var_os("SIWORLD_ENG2_NATIVE_FIXTURE").unwrap());
    assert!(source.is_absolute());
    const MAXIMUM: usize = 1024 * 1024 * 1024;
    let budget = crate::p2p::Budget::new(MAXIMUM);
    let limits = crate::eng2::snapshot::ImportLimits {
        chain: crate::eng2::state_components::Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        },
        max_snapshot_bytes: 512 * 1024 * 1024,
    };
    let (read, height, archive_bytes) =
        crate::eng2::store::CheckpointRestoreRead::existing_public_fixture_for_test(
            &source, limits, &budget,
        );
    let validated = ArchiveWork::from_restore_read(&read, height, limits, &budget)
        .unwrap()
        .validate(&AtomicBool::new(false))
        .unwrap();
    let native = validated.identity();
    let (snapshot, live_guard) = validated
        .into_snapshot(std::mem::size_of::<CertifiedCheckpoint>())
        .unwrap();
    let charge = archive_bytes * 16 + 8 * 1024 * 1024;
    let available = budget.available().unwrap();
    assert!(available > charge);
    let pressure = budget.reserve(available - charge + 1).unwrap();
    let used = MAXIMUM - budget.available().unwrap();
    // This is the unchanged eager read invoked before NativeArchiveIdentity::matches.
    // The original fully validated snapshot and its guard are still alive.
    let failure = ArchiveWork::from_restore_read(&read, height, limits, &budget)
        .err()
        .unwrap();
    assert_eq!(failure, "checkpoint archive preparation budget unavailable");
    let observed = failure.budget.unwrap();
    assert_eq!(observed.operation, Operation::ArchivePreparation);
    assert_eq!(observed.requested, Some(charge));
    assert_eq!(
        observed.usage().unwrap(),
        crate::p2p::ByteUsage {
            maximum: MAXIMUM,
            used
        }
    );
    // The same real pinned Store and prior complete native validation can
    // match without the duplicate 16x workspace while pressure remains held.
    let before_match = budget.available().unwrap();
    assert!(
        native
            .matches_restore_read(&read, height, limits, &snapshot)
            .unwrap()
    );
    assert_eq!(budget.available().unwrap(), before_match);
    let mut changed_snapshot = snapshot.clone();
    changed_snapshot[10] ^= 1;
    assert!(
        !native
            .matches_restore_read(&read, height, limits, &changed_snapshot)
            .unwrap()
    );
    drop(changed_snapshot);
    let mut changed_limits = limits;
    changed_limits.chain.max_leaves += 1;
    assert!(
        !native
            .matches_restore_read(&read, height, changed_limits, &snapshot)
            .unwrap()
    );
    drop(pressure);
    let duplicate = ArchiveWork::from_restore_read(&read, height, limits, &budget).unwrap();
    assert!(native.matches(&duplicate, &snapshot).unwrap());
    let mut changed = snapshot.clone();
    changed[10] ^= 1;
    assert!(!native.matches(&duplicate, &changed).unwrap());
    drop((duplicate, changed, native, snapshot, live_guard, read));
    assert_eq!(budget.available().unwrap(), MAXIMUM);
    println!(
        "{}",
        serde_json::json!({"result":"LOCAL_REAL_ARCHIVE_LIVE_IDENTITY_DUPLICATE_WORKSPACE_REPRODUCED","checkpoint_height":height,"base_archive_bytes":archive_bytes,"suffix_body_bytes":0,"requested":charge,"used":used,"maximum":MAXIMUM,"native_validation_performed":true,"same_identity_matches_after_pressure_released":true,"same_identity_matches_while_pressure_held":true,"snapshot_and_limits_changes_rejected":true,"changed_snapshot_rejected":true,"production_cause_established":false,"proof_generation":false,"database_writes":0})
    );
}
