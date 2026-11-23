use sivault_core::{Error, crypto, standard::Safe};
use std::fs;

#[test]
fn offline_roundtrip_normalized_password_and_nested_files() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("safe");
    let source = temp.path().join("document.txt");
    let data: Vec<_> = (0..131_089).map(|i| (i % 251) as u8).collect();
    fs::write(&source, &data).unwrap();
    let mut safe = Safe::create(&root, "caf\u{e9}").unwrap();
    let directory = safe.create_directory("Documents", None).unwrap();
    let entry = safe.import_file(&source, Some(&directory.id)).unwrap();
    assert_eq!(safe.entries().len(), 2);
    assert!(Safe::open(&root, "caf\u{e9}", false).is_err());
    drop(safe);
    assert!(matches!(
        Safe::open(&root, "wrong", false),
        Err(Error::Authentication)
    ));
    let mut safe = Safe::open(&root, "cafe\u{301}", true).unwrap();
    assert!(matches!(
        safe.import_file(&source, None),
        Err(Error::ReadOnly)
    ));
    let destination = temp.path().join("export.txt");
    safe.export_file(&entry.id, &destination).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), data);
    assert!(safe.export_file(&entry.id, &source).is_err());
    assert_eq!(fs::read(&source).unwrap(), data);
}

#[test]
fn corrupt_piece_does_not_create_export_and_truncation_fails_open() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("safe");
    let source = temp.path().join("source");
    fs::write(&source, vec![7; 131_072]).unwrap();
    let mut safe = Safe::create(&root, "password").unwrap();
    let entry = safe.import_file(&source, None).unwrap();
    let piece = fs::read_dir(&root)
        .unwrap()
        .map(|x| x.unwrap().path())
        .find(|p| p.file_name().unwrap().to_str().unwrap().starts_with("p-"))
        .unwrap();
    let original = fs::read(&piece).unwrap();
    let mut changed = original.clone();
    changed[20] ^= 1;
    fs::write(&piece, &changed).unwrap();
    let destination = temp.path().join("export");
    assert!(safe.export_file(&entry.id, &destination).is_err());
    assert!(!destination.exists());
    drop(safe);
    fs::write(&piece, &original[..original.len() - 1]).unwrap();
    assert!(Safe::open(&root, "password", false).is_err());
}

#[test]
fn published_damaged_newest_record_never_silently_rolls_back() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("safe");
    drop(Safe::create(&root, "password").unwrap());
    fs::write(root.join("g-0000000000000002"), b"torn").unwrap();
    assert!(matches!(
        Safe::open(&root, "password", false),
        Err(Error::InvalidFormat)
    ));
}

#[test]
fn empty_files_remove_and_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("safe");
    let input = temp.path().join("empty");
    fs::write(&input, []).unwrap();
    let mut safe = Safe::create(&root, "password").unwrap();
    let directory = safe.create_directory("folder", None).unwrap();
    let entry = safe.import_file(&input, Some(&directory.id)).unwrap();
    let destination = temp.path().join("out");
    safe.export_file(&entry.id, &destination).unwrap();
    assert_eq!(fs::metadata(destination).unwrap().len(), 0);
    safe.remove(&directory.id).unwrap();
    drop(safe);
    assert!(
        Safe::open(&root, "password", false)
            .unwrap()
            .entries()
            .is_empty()
    );
}

#[test]
fn stream_rejects_reorder_wrong_final_and_context() {
    let key = [1; 32];
    let prefix = [2; 19];
    let ad = b"bound to immutable file context";
    let first = crypto::encrypt_chunk(&key, &prefix, 0, false, ad, b"first").unwrap();
    let last = crypto::encrypt_chunk(&key, &prefix, 1, true, ad, b"last").unwrap();
    assert!(crypto::decrypt_chunk(&key, &prefix, 0, false, ad, &last).is_err());
    assert!(crypto::decrypt_chunk(&key, &prefix, 1, true, ad, &first).is_err());
    assert!(crypto::decrypt_chunk(&key, &prefix, 1, false, ad, &last).is_err());
    assert!(crypto::decrypt_chunk(&key, &prefix, 1, true, b"other", &last).is_err());
}

#[test]
fn password_profile_preserves_case_maps_spaces_and_rejects_controls() {
    assert_eq!(
        &**crypto::password_bytes("cafe\u{301}").unwrap(),
        "caf\u{e9}"
    );
    assert_eq!(&**crypto::password_bytes("a\u{a0}b").unwrap(), "a b");
    assert_ne!(
        *crypto::password_bytes("Password").unwrap(),
        *crypto::password_bytes("password").unwrap()
    );
    assert!(crypto::password_bytes("bad\npassword").is_err());
    assert!(crypto::password_bytes("").is_err());
}

#[cfg(unix)]
#[test]
fn symlink_source_and_safe_are_rejected() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("safe");
    let mut safe = Safe::create(&root, "password").unwrap();
    let source = temp.path().join("source");
    fs::write(&source, b"secret").unwrap();
    let link = temp.path().join("link");
    symlink(&source, &link).unwrap();
    assert!(safe.import_file(&link, None).is_err());
    drop(safe);
    let alias = temp.path().join("alias");
    symlink(&root, &alias).unwrap();
    assert!(Safe::open(alias, "password", false).is_err());
}
