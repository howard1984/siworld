use super::super::tests::{Directory, synthetic_candidate};
use super::*;
use crate::eng2::{
    genesis::{FeeMode, Genesis},
    snapshot::tests::{bootstrap, limits},
};
use std::os::unix::fs::symlink;

#[test]
fn actual_genesis_files_reopen_bound_context_and_preserve_export_on_failure() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let mut export = PublicExport::open(&root, &store, limits()).unwrap();
    assert!(
        export
            .prepare_checkpoint(&store, limits())
            .unwrap()
            .is_none()
    );
    assert!(export.pruning_paused(123).unwrap());
    assert!(!export.publication_due(123, 0).unwrap());
    export.publish_current(&store, 123, None).unwrap();
    let bytes = fs::read(root.join("explorer.json")).unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed, public_projection(&store, 123, None).unwrap());
    assert_eq!(export.cached_head, Some((0, store.engine().genesis().id())));
    assert!(export.blocks.is_empty());
    assert_eq!(
        fs::metadata(root.join("explorer.json")).unwrap().mode() & 0o777,
        0o600
    );
    assert!(export.publish_current(&store, 1u64 << 53, None).is_err());
    assert_eq!(fs::read(root.join("explorer.json")).unwrap(), bytes);
    assert!(!fs::read_dir(&root).unwrap().any(|entry| {
        entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|e| e == "tmp")
    }));
    export.publish_current(&store, 124, None).unwrap();
    drop(export);
    let reopened = PublicExport::open(&root, &store, limits()).unwrap();
    assert!(reopened.restore_latest(&store, limits()).unwrap().is_none());
    let initial = bootstrap();
    let foreign = Genesis::seal(
        crate::state::Config::development(initial.network(), 1).unwrap(),
        initial.governance().clone(),
        FeeMode::LegacyMiner,
    )
    .unwrap();
    let other = Store::create(&dir.0.join("other.redb"), foreign, limits().chain).unwrap();
    assert!(reopened.check_store(&other).is_err());
    assert!(PublicExport::open(&root, &other, limits()).is_err());
}
#[test]
fn opened_directory_descriptor_confines_writes_after_path_replacement() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let mut export = PublicExport::open(&root, &store, limits()).unwrap();
    let moved = dir.0.join("original");
    fs::rename(&root, &moved).unwrap();
    dir.private("export");
    export.publish_current(&store, 123, None).unwrap();
    assert!(moved.join("explorer.json").exists());
    assert!(!root.join("explorer.json").exists());
}
#[test]
fn filesystem_rejects_symlinks_hardlinks_permissions_and_oversized_artifacts() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let link = dir.0.join("linked-root");
    symlink(&root, &link).unwrap();
    assert!(PublicExport::open(&link, &store, limits()).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(export.read_optional("eng2-context.bin", 96).is_err());
    assert!(PublicExport::open(&root, &store, limits()).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    export.write_once("immutable.bin", b"first").unwrap();
    export.write_once("immutable.bin", b"first").unwrap();
    assert!(export.write_once("immutable.bin", b"other").is_err());
    assert_eq!(export.read("immutable.bin", 5).unwrap(), b"first");
    assert!(export.read("immutable.bin", 4).is_err());
    fs::set_permissions(
        root.join("immutable.bin"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(export.read("immutable.bin", 5).is_err());
    fs::set_permissions(
        root.join("immutable.bin"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::hard_link(root.join("immutable.bin"), dir.0.join("outside-copy.bin")).unwrap();
    assert!(export.read("immutable.bin", 5).is_err());
    symlink(dir.0.join("outside-copy.bin"), root.join("explorer.json")).unwrap();
    assert!(export.replace("explorer.json", b"replacement").is_err());
    assert_eq!(fs::read(dir.0.join("outside-copy.bin")).unwrap(), b"first");
}
#[test]
fn malformed_cursor_cannot_supply_arbitrary_paths_or_advance_pruning_clock() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    export.replace("checkpoint-eng2.json", b"{}").unwrap();
    assert!(export.restore_latest(&store, limits()).is_err());
    assert!(PublicExport::open(&root, &store, limits()).is_err());
    assert!(export.pruning_paused(999999).unwrap());
    for name in [
        "../secret.certificate-eng2.bin",
        "aa.certificate-eng2.bin",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.certificate-eng2.bin",
    ] {
        assert!(artifact_name(&json!({"file":name}), "file", ".certificate-eng2.bin").is_err());
    }
    let name = format!("{}.certificate-eng2.bin", "ab".repeat(32));
    assert_eq!(
        artifact_name(&json!({"file":name}), "file", ".certificate-eng2.bin").unwrap(),
        name
    );
}
#[test]
fn block_cadence_duplicates_and_staleness_do_not_mutate_the_clock() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let mut export = PublicExport::open(&root, &store, limits()).unwrap();
    let published = 100_000;
    export.latest = Some((72, [7; 32], published));
    assert!(!export.publication_due(published, 107).unwrap());
    assert!(export.publication_due(published, 108).unwrap());
    assert!(
        !export
            .publication_due(published + PUBLICATION_INTERVAL_SECONDS, 107)
            .unwrap()
    );
    assert!(export.publication_due(published - 1, 168).is_err());
    assert!(!export.pruning_paused(published + STALE_SECONDS).unwrap());
    assert!(
        export
            .pruning_paused(published + STALE_SECONDS + 1)
            .unwrap()
    );
    assert!(export.pruning_paused(published - 1).is_err());
    assert!(
        !export
            .accept_publication(72, [7; 32], published + STALE_SECONDS + 100)
            .unwrap()
    );
    assert_eq!(export.latest, Some((72, [7; 32], published)));
    assert!(
        export
            .accept_publication(72, [8; 32], published + STALE_SECONDS + 100)
            .is_err()
    );
    assert!(
        export
            .accept_publication(84, [8; 32], published + 1)
            .unwrap()
    );
    assert!(
        export
            .accept_publication(84, [8; 32], published - 1)
            .is_err()
    );
    assert!(
        export
            .accept_publication(144, [8; 32], published + PUBLICATION_INTERVAL_SECONDS)
            .unwrap()
    );
    assert!(
        export
            .accept_publication(0, [8; 32], published + PUBLICATION_INTERVAL_SECONDS)
            .is_err()
    );
    export.latest = Some((144, [8; 32], published + PUBLICATION_INTERVAL_SECONDS));
    assert!(
        !export
            .pruning_paused(published + PUBLICATION_INTERVAL_SECONDS + 1)
            .unwrap()
    );
}
#[test]
fn synthetic_candidate_codec_and_vote_journal_are_exact_but_cannot_admit_a_checkpoint() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let mut export = PublicExport::open(&root, &store, limits()).unwrap();
    let candidate = synthetic_candidate();
    let bytes = encode_candidate(&candidate, limits()).unwrap();
    assert!(decode_candidate(&store, &bytes, limits()).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_candidate(&store, &trailing, limits()).is_err());
    let mut tiny = limits();
    tiny.max_snapshot_bytes = 1;
    assert!(encode_candidate(&candidate, tiny).is_err());
    let name = candidate_name(candidate.statement.roster_sequence, 72);
    export.write_once(&name, &bytes).unwrap();
    let mut changed = bytes.clone();
    changed[40] ^= 1;
    assert!(export.write_once(&name, &changed).is_err());
    assert_eq!(export.read(&name, bytes.len()).unwrap(), bytes);
    let message = candidate.statement.encode().unwrap();
    let key = ml_dsa_65::generate_key_pair([3; 32]).signing_key;
    let signature = ml_dsa_65::sign(&key, &message, Statement::signing_context(), [4; 32]).unwrap();
    let journal = [message.as_slice(), &[0], signature.as_ref()].concat();
    let vote = decode_vote(&message, 0, &journal).unwrap();
    candidate.verify_vote(&vote).unwrap();
    assert!(decode_vote(&message, 1, &journal).is_err());
    let mut wrong = message;
    wrong[50] ^= 1;
    assert!(decode_vote(&wrong, 0, &journal).is_err());
    assert!(
        export
            .sign_vote(&store, &candidate, 0, &key, [5; 32], limits())
            .is_err()
    );
    assert!(
        !root
            .join("vote-00000000000000000000-00000000000000000072-0.eng2.bin")
            .exists()
    );
}

#[test]
fn concurrent_immutable_publications_install_one_complete_record_without_clobbering() {
    use std::sync::{Arc, Barrier};
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let first = PublicExport::open(&root, &store, limits()).unwrap();
    let second = PublicExport::open(&root, &store, limits()).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let other = barrier.clone();
    let left = std::thread::spawn(move || {
        barrier.wait();
        first.write_once("raced.bin", b"first complete record")
    });
    let right = std::thread::spawn(move || {
        other.wait();
        second.write_once("raced.bin", b"second complete record")
    });
    let left = left.join().unwrap();
    let right = right.join().unwrap();
    assert_ne!(left.is_ok(), right.is_ok());
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let actual = export.read("raced.bin", 64).unwrap();
    assert!(actual == b"first complete record" || actual == b"second complete record");
    assert!(!fs::read_dir(&root).unwrap().any(|entry| {
        entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|extension| extension == "tmp")
    }));
}

#[test]
fn withdrawal_preserves_original_publication_time_and_immutable_dependencies() {
    // Synthetic signed export records test file behavior, not native execution.
    let directory = Directory::new();
    let store = directory.store();
    let root = directory.private("withdrawal");
    let mut export = PublicExport::open(&root, &store, limits()).unwrap();
    let prepared = synthetic_candidate();
    let message = prepared.statement.encode().unwrap();
    let vote = |slot: u8, seed: u8| Vote {
        slot,
        signature: *ml_dsa_65::sign(
            &ml_dsa_65::generate_key_pair([seed; 32]).signing_key,
            &message,
            Statement::signing_context(),
            [42; 32],
        )
        .unwrap()
        .as_ref(),
    };
    let certificate = Certificate {
        statement: prepared.statement.clone(),
        votes: [vote(0, 3), vote(1, 4)],
    };
    certificate
        .check_signatures(prepared.roster.keys())
        .unwrap();
    let mut checkpoint = CertifiedCheckpoint {
        prepared,
        certificate,
        published: 100_000,
    };
    let cursor = export.publication_cursor(&checkpoint).unwrap();
    let value: Value = serde_json::from_slice(&cursor).unwrap();
    let certificate = checkpoint.certificate.encode().unwrap();
    let witness = checkpoint
        .witness()
        .encode(limits().chain.max_component_bytes)
        .unwrap();
    for (key, bytes) in [
        ("certificate_file", certificate.as_slice()),
        ("witness_file", witness.as_slice()),
        ("snapshot_file", checkpoint.snapshot_bytes()),
    ] {
        export
            .write_once(value[key].as_str().unwrap(), bytes)
            .unwrap();
    }
    let journal_name = format!(
        "vote-{:020}-{:020}-0.eng2.bin",
        checkpoint.certificate.statement.roster_sequence,
        checkpoint.certificate.statement.checkpoint_height
    );
    let journal = [
        message.as_slice(),
        &[0],
        checkpoint.certificate.votes[0].signature.as_slice(),
    ]
    .concat();
    export.write_once(&journal_name, &journal).unwrap();
    export.replace("checkpoint-eng2.json", &cursor).unwrap();
    export.remember_publication(&checkpoint).unwrap();
    export.withdraw_checkpoint(&checkpoint).unwrap();
    assert!(!root.join("checkpoint-eng2.json").exists());
    assert_eq!(export.latest_height(), None);
    let record = publication_name(checkpoint.certificate.statement.checkpoint_height);
    assert_eq!(export.read(&record, 8192).unwrap(), cursor);
    assert_eq!(export.read(&journal_name, journal.len()).unwrap(), journal);
    assert_eq!(
        export
            .retained_votes(&checkpoint.certificate.statement)
            .unwrap()
            .len(),
        1
    );
    for key in ["certificate_file", "witness_file", "snapshot_file"] {
        assert!(root.join(value[key].as_str().unwrap()).is_file());
    }
    // Repeating a barrier keeps the exact original record. A later attempt to
    // relabel the same anchor with a newer publication time is rejected.
    export.withdraw_checkpoint(&checkpoint).unwrap();
    checkpoint.published += 100;
    assert!(export.withdraw_checkpoint(&checkpoint).is_err());
    assert_eq!(export.read(&record, 8192).unwrap(), cursor);
    let mut corrupted = journal.clone();
    corrupted[0] ^= 1;
    fs::write(root.join(&journal_name), &corrupted).unwrap();
    assert!(
        export
            .retained_votes(&checkpoint.certificate.statement)
            .is_err()
    );
}

#[test]
fn retained_reader_inspects_all_actual_material_with_unchanged_length_and_mtime() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("retained-material");
    let export = PublicExport::open_unrestored(&root, &store).unwrap();
    let candidate = synthetic_candidate();
    let witness = candidate
        .witness
        .encode(limits().chain.max_component_bytes)
        .unwrap();
    let encoded = encode_candidate(&candidate, limits()).unwrap();
    let rows = [
        ("checkpoint-eng2.json", b"cursor-record".to_vec()),
        (
            "candidate-00000000000000000000-00000000000000000012.eng2.bin",
            encoded,
        ),
        (
            "checkpoint-publication-00000000000000000012.json",
            b"withdrawn-record".to_vec(),
        ),
        ("material.certificate-eng2.bin", vec![8; 64]),
        ("material.witness-eng2.bin", witness),
        ("material.snapshot-eng2.bin", vec![7; 4096]),
        (
            "vote-00000000000000000000-00000000000000000012-0.eng2.bin",
            vec![0; 64],
        ),
        (
            "vote-00000000000000000000-00000000000000000012-1.eng2.bin",
            vec![1; 64],
        ),
        (
            "vote-00000000000000000000-00000000000000000012-2.eng2.bin",
            vec![2; 64],
        ),
    ];
    let budget = crate::p2p::Budget::new(64 * 1024 * 1024);
    for (name, bytes) in rows {
        export.write_once(name, &bytes).unwrap();
        let path = root.join(name);
        let metadata = fs::metadata(&path).unwrap();
        let reader = export.retained_reader(&budget).unwrap();
        assert_eq!(
            reader.read_optional(name, bytes.len()).unwrap(),
            Some(bytes.clone())
        );
        let original = reader.material_identity();
        drop(reader);
        let mut changed = bytes;
        *changed.last_mut().unwrap() ^= 1;
        fs::write(&path, &changed).unwrap();
        fs::File::open(&path)
            .unwrap()
            .set_times(
                fs::FileTimes::new()
                    .set_accessed(metadata.accessed().unwrap())
                    .set_modified(metadata.modified().unwrap()),
            )
            .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().modified().unwrap(),
            metadata.modified().unwrap()
        );
        let reader = export.retained_reader(&budget).unwrap();
        assert_eq!(
            reader.read_optional(name, changed.len()).unwrap(),
            Some(changed)
        );
        assert_ne!(reader.material_identity(), original);
        drop(reader);
        assert_eq!(budget.available().unwrap(), 64 * 1024 * 1024);
    }
    let reader = export.retained_reader(&budget).unwrap();
    reader.read_optional("absent-vote", 64).unwrap();
    let absent = reader.material_identity();
    drop(reader);
    export.write_once("absent-vote", &[0; 64]).unwrap();
    let reader = export.retained_reader(&budget).unwrap();
    reader.read_optional("absent-vote", 64).unwrap();
    assert_ne!(reader.material_identity(), absent);
}

#[test]
fn retained_reader_reserves_before_large_read_and_releases_every_guard() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("retained-budget");
    let export = PublicExport::open_unrestored(&root, &store).unwrap();
    export
        .write_once("bounded.snapshot-eng2.bin", &[4; 8192])
        .unwrap();
    let budget = crate::p2p::Budget::new(64 * 1024 + 8192);
    let reader = export.retained_reader(&budget).unwrap();
    assert_eq!(budget.available().unwrap(), 8192);
    assert!(
        reader
            .read_optional("bounded.snapshot-eng2.bin", 8192)
            .is_err()
    );
    assert_eq!(budget.available().unwrap(), 8192);
    drop(reader);
    assert_eq!(budget.available().unwrap(), 64 * 1024 + 8192);
    let budget = crate::p2p::Budget::new(64 * 1024 + 16384);
    let reader = export.retained_reader(&budget).unwrap();
    let bytes = reader
        .read_optional("bounded.snapshot-eng2.bin", 8192)
        .unwrap()
        .unwrap();
    assert_eq!(budget.available().unwrap(), 0);
    drop(bytes);
    drop(reader);
    assert_eq!(budget.available().unwrap(), 64 * 1024 + 16384);
}

#[test]
fn material_generation_rejects_same_head_own_writes_and_exhaustion() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("material-generation");
    let export = PublicExport::open_unrestored(&root, &store).unwrap();
    let original = export.material_generation();
    export.write_once("vote-0.eng2.bin", &[7; 64]).unwrap();
    assert!(export.material_generation() > original);
    let unchanged = export.material_generation();
    export.write_once("vote-0.eng2.bin", &[7; 64]).unwrap();
    export.write_status(b"{}").unwrap();
    assert_eq!(export.material_generation(), unchanged);
    export.material_generation.set(u64::MAX);
    assert!(export.write_once("vote-1.eng2.bin", &[8; 64]).is_err());
    assert!(!root.join("vote-1.eng2.bin").exists());
}

#[test]
fn segmented_candidate_preserves_the_existing_format_and_snapshot_bound() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("segmented-candidate");
    let export = PublicExport::open_unrestored(&root, &store).unwrap();
    let mut candidate = synthetic_candidate();
    candidate.snapshot = (0..(2 * IMMUTABLE_COMPARE_BYTES + 17))
        .map(|n| (n % 251) as u8)
        .collect();
    let expected = encode_candidate(&candidate, limits()).unwrap();
    let name = candidate_name(candidate.statement.roster_sequence, 72);
    export.write_candidate(&name, &candidate, limits()).unwrap();
    assert_eq!(fs::read(root.join(&name)).unwrap(), expected);
    export.write_candidate(&name, &candidate, limits()).unwrap();
    let mut tiny = limits();
    tiny.max_snapshot_bytes = candidate.snapshot.len() - 1;
    assert!(
        export
            .write_candidate("refused.eng2.bin", &candidate, tiny)
            .is_err()
    );
    assert!(!root.join("refused.eng2.bin").exists());
}

#[test]
fn immutable_segment_comparison_reads_tail_bytes_and_preserves_conflicting_files() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("segmented-comparison");
    let export = PublicExport::open_unrestored(&root, &store).unwrap();
    let bytes = (0..(2 * IMMUTABLE_COMPARE_BYTES + 37))
        .map(|n| (n % 251) as u8)
        .collect::<Vec<_>>();
    let parts = [&bytes[..1], &[][..], &bytes[1..65539], &bytes[65539..]];
    export.write_once_parts("segmented.bin", &parts).unwrap();
    export.write_once("segmented.bin", &bytes).unwrap();
    export.write_once_parts("segmented.bin", &parts).unwrap();
    let path = root.join("segmented.bin");
    let metadata = fs::metadata(&path).unwrap();
    let mut changed = bytes.clone();
    *changed.last_mut().unwrap() ^= 1;
    fs::write(&path, &changed).unwrap();
    fs::File::open(&path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(metadata.modified().unwrap()))
        .unwrap();
    assert!(export.write_once_parts("segmented.bin", &parts).is_err());
    assert_eq!(fs::read(&path).unwrap(), changed);
    assert!(
        export
            .write_once_parts("segmented.bin", &[&bytes[..7]])
            .is_err()
    );
    fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
    assert!(export.write_once_parts("segmented.bin", &parts).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes[..bytes.len() - 1]);
    assert!(!fs::read_dir(&root).unwrap().any(|entry| {
        entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|ext| ext == "tmp")
    }));
}

#[test]
fn immutable_install_collision_authenticates_existing_segments_without_replacing_them() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("segmented-install-collision");
    let export = PublicExport::open_unrestored(&root, &store).unwrap();
    let bytes = vec![19u8; IMMUTABLE_COMPARE_BYTES + 7];
    let parts = [&bytes[..3], &bytes[3..]];
    export.write_once_parts("occupied.bin", &parts).unwrap();
    export.write_once_parts("incoming.tmp", &parts).unwrap();
    export
        .install_immutable_parts("incoming.tmp", "occupied.bin", &parts, bytes.len())
        .unwrap();
    let mut changed = bytes.clone();
    *changed.last_mut().unwrap() ^= 1;
    fs::write(root.join("occupied.bin"), &changed).unwrap();
    assert!(
        export
            .install_immutable_parts("incoming.tmp", "occupied.bin", &parts, bytes.len())
            .is_err()
    );
    assert_eq!(fs::read(root.join("occupied.bin")).unwrap(), changed);
    assert_eq!(fs::read(root.join("incoming.tmp")).unwrap(), bytes);
}
