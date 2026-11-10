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
fn publication_intervals_duplicates_and_staleness_do_not_mutate_the_clock() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let mut export = PublicExport::open(&root, &store, limits()).unwrap();
    let published = 100_000;
    export.latest = Some((72, [7; 32], published));
    assert!(
        !export
            .publication_due(published + PUBLICATION_INTERVAL_SECONDS - 1, 168)
            .unwrap()
    );
    assert!(
        export
            .publication_due(published + PUBLICATION_INTERVAL_SECONDS, 168)
            .unwrap()
    );
    assert!(
        !export
            .publication_due(published + PUBLICATION_INTERVAL_SECONDS, 167)
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
            .accept_publication(144, [8; 32], published + PUBLICATION_INTERVAL_SECONDS - 1)
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
