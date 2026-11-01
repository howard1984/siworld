use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const PASSWORD: &str = "synthetic-test-password-one";
const BACKUP_PASSWORD: &str = "synthetic-test-password-two";

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "siworld-fund-keytool-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn generated_keys_restart_and_local_signatures_match_public_submission() {
    let temp = Sandbox::new();
    let first = generate(&temp.path("first"), PASSWORD).unwrap();
    let second = generate(&temp.path("second"), PASSWORD).unwrap();
    assert_ne!(first.fingerprint, second.fingerprint);
    assert_eq!(public(&temp.path("first"), PASSWORD).unwrap(), first);
    assert_eq!(verify(&temp.path("first"), PASSWORD).unwrap(), first);
    assert_eq!(
        check_public(&temp.path("first/public.json")).unwrap(),
        first
    );
    assert_eq!(first.public_key_hex.len(), 1952 * 2);
    assert_eq!(first.fingerprint.len(), 64);
}

#[test]
fn incorrect_password_and_authenticated_record_mutations_fail_closed() {
    let temp = Sandbox::new();
    let directory = temp.path("key");
    generate(&directory, PASSWORD).unwrap();
    assert!(public(&directory, "incorrect-password").is_err());
    let original = fs::read(directory.join("seed.vault")).unwrap();
    for offset in [0, 8, 10, 26, 50, 82, original.len() - 1] {
        let mut changed = original.clone();
        changed[offset] ^= 1;
        fs::write(directory.join("seed.vault"), &changed).unwrap();
        assert!(public(&directory, PASSWORD).is_err(), "offset {offset}");
    }
    fs::write(directory.join("seed.vault"), &original).unwrap();
    assert!(verify(&directory, PASSWORD).is_ok());
}

#[test]
fn backup_reencrypts_same_identity_and_authenticates_recovery() {
    let temp = Sandbox::new();
    let source = temp.path("key");
    let destination = temp.path("backup");
    let expected = generate(&source, PASSWORD).unwrap();
    assert_eq!(
        backup(&source, PASSWORD, &destination, BACKUP_PASSWORD).unwrap(),
        expected
    );
    assert_eq!(verify(&destination, BACKUP_PASSWORD).unwrap(), expected);
    let a = fs::read(source.join("seed.vault")).unwrap();
    let b = fs::read(destination.join("seed.vault")).unwrap();
    assert_ne!(&a[10..26], &b[10..26]);
    assert_ne!(&a[26..50], &b[26..50]);
    assert!(public(&destination, PASSWORD).is_err());
    assert!(backup(&source, PASSWORD, &destination, BACKUP_PASSWORD).is_err());
    assert_eq!(fs::read(destination.join("seed.vault")).unwrap(), b);
}

#[test]
fn creation_never_overwrites_and_live_custody_is_exclusive() {
    let temp = Sandbox::new();
    let directory = temp.path("key");
    generate(&directory, PASSWORD).unwrap();
    let before = fs::read(directory.join("seed.vault")).unwrap();
    assert!(generate(&directory, PASSWORD).is_err());
    assert_eq!(fs::read(directory.join("seed.vault")).unwrap(), before);
    let _held = storage::Directory::open(&directory).unwrap();
    assert!(public(&directory, PASSWORD).is_err());
}

#[test]
fn record_publication_never_replaces_existing_files_or_dangling_symlinks() {
    let temp = Sandbox::new();
    let path = temp.path("custody");
    let directory = storage::Directory::create(&path).unwrap();
    directory
        .write_once("public.json", b"first record")
        .unwrap();
    assert!(directory.write_once("public.json", b"replacement").is_err());
    assert_eq!(fs::read(path.join("public.json")).unwrap(), b"first record");
    symlink(temp.path("absent"), path.join("seed.vault")).unwrap();
    assert!(directory.write_once("seed.vault", b"replacement").is_err());
    assert!(
        fs::symlink_metadata(path.join("seed.vault"))
            .unwrap()
            .is_symlink()
    );
    assert!(!temp.path("absent").exists());
}

#[test]
fn public_records_are_bounded_exact_canonical_and_bound_to_fingerprint() {
    let expected = PublicKey::from_raw(&[17; PUBLIC_BYTES]);
    let canonical = expected.canonical_bytes().unwrap();
    assert_eq!(PublicKey::decode(&canonical).unwrap(), expected);
    let mut changed = canonical.clone();
    changed.insert(0, b' ');
    assert!(PublicKey::decode(&changed).is_err());
    for extra in [
        ",\"version\":1}\n",
        ",\"private_seed\":\"not permitted\"}\n",
    ] {
        let mut changed = canonical[..canonical.len() - 2].to_vec();
        changed.extend_from_slice(extra.as_bytes());
        assert!(PublicKey::decode(&changed).is_err());
    }
    for changed in [
        canonical[..canonical.len() - 1].to_vec(),
        vec![b' '; MAX_PUBLIC_BYTES + 1],
        b"{\"version\":1,\"version\":1}\n".to_vec(),
    ] {
        assert!(PublicKey::decode(&changed).is_err());
    }
    for mutate in 0..5 {
        let mut invalid = expected.clone();
        match mutate {
            0 => invalid.version = 2,
            1 => invalid.algorithm = "ML-DSA-44".into(),
            2 => invalid.public_key_hex = "ff".into(),
            3 => invalid.fingerprint = "00".repeat(32),
            _ => invalid.public_key_hex.replace_range(..2, "GG"),
        }
        let mut encoded = serde_json::to_vec(&invalid).unwrap();
        encoded.push(b'\n');
        assert!(PublicKey::decode(&encoded).is_err());
    }
    assert!(
        PublicKey::decode(
            &PublicKey::from_raw(&[0; PUBLIC_BYTES])
                .canonical_bytes()
                .unwrap()
        )
        .is_err()
    );
}

#[test]
fn paths_permissions_symlinks_and_hardlinks_are_rejected() {
    let temp = Sandbox::new();
    let directory = temp.path("key");
    generate(&directory, PASSWORD).unwrap();
    symlink(&directory, temp.path("alias")).unwrap();
    assert!(public(&temp.path("alias"), PASSWORD).is_err());
    assert!(generate(&temp.path("alias/new"), PASSWORD).is_err());
    for mode in [0o755, 0o770] {
        fs::set_permissions(&directory, fs::Permissions::from_mode(mode)).unwrap();
        assert!(public(&directory, PASSWORD).is_err());
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["seed.vault", "public.json", ".fund-key.lock"] {
        let path = directory.join(name);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(public(&directory, PASSWORD).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, temp.path("hardlink")).unwrap();
        assert!(public(&directory, PASSWORD).is_err());
        fs::remove_file(temp.path("hardlink")).unwrap();
    }
    let vault = directory.join("seed.vault");
    fs::rename(&vault, temp.path("moved-vault")).unwrap();
    symlink(temp.path("moved-vault"), &vault).unwrap();
    assert!(public(&directory, PASSWORD).is_err());
    assert!(check_public(Path::new("../public.json")).is_err());
}

#[test]
fn fifos_are_rejected_without_waiting_for_a_writer() {
    use std::sync::mpsc;
    use std::time::Duration;

    let temp = Sandbox::new();
    let directory = temp.path("key");
    generate(&directory, PASSWORD).unwrap();
    for name in ["seed.vault", "public.json", ".fund-key.lock"] {
        let path = directory.join(name);
        let retained = directory.join("retained-record");
        fs::rename(&path, &retained).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .args(["-m", "600"])
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let (send, receive) = mpsc::channel();
        let candidate = directory.clone();
        let operation = std::thread::spawn(move || {
            let _ = send.send(public(&candidate, PASSWORD));
        });
        assert!(
            receive
                .recv_timeout(Duration::from_secs(5))
                .expect("custody FIFO must fail before a blocking read")
                .is_err(),
            "record {name}"
        );
        operation.join().unwrap();
        if name == "public.json" {
            let (send, receive) = mpsc::channel();
            let candidate = path.clone();
            let operation = std::thread::spawn(move || {
                let _ = send.send(check_public(&candidate));
            });
            assert!(
                receive
                    .recv_timeout(Duration::from_secs(5))
                    .expect("public FIFO must fail before a blocking read")
                    .is_err()
            );
            operation.join().unwrap();
        }
        fs::remove_file(&path).unwrap();
        fs::rename(&retained, &path).unwrap();
    }
    assert!(verify(&directory, PASSWORD).is_ok());
}

#[test]
fn incomplete_directories_are_preserved_and_never_reinitialized() {
    let temp = Sandbox::new();
    let empty = temp.path("empty");
    drop(storage::Directory::create(&empty).unwrap());
    assert!(public(&empty, PASSWORD).is_err());
    assert!(generate(&empty, PASSWORD).is_err());
    assert_eq!(fs::read_dir(&empty).unwrap().count(), 1);

    let public_only = temp.path("public-only");
    let owner = storage::Directory::create(&public_only).unwrap();
    let submission = PublicKey::from_raw(&[17; PUBLIC_BYTES])
        .canonical_bytes()
        .unwrap();
    owner.write_once("public.json", &submission).unwrap();
    drop(owner);
    assert!(public(&public_only, PASSWORD).is_err());
    assert!(generate(&public_only, PASSWORD).is_err());
    assert_eq!(
        fs::read(public_only.join("public.json")).unwrap(),
        submission
    );
    assert!(!public_only.join("seed.vault").exists());

    let secret_only = temp.path("secret-only");
    generate(&secret_only, PASSWORD).unwrap();
    let vault = fs::read(secret_only.join("seed.vault")).unwrap();
    fs::remove_file(secret_only.join("public.json")).unwrap();
    assert!(public(&secret_only, PASSWORD).is_err());
    assert!(generate(&secret_only, PASSWORD).is_err());
    assert_eq!(fs::read(secret_only.join("seed.vault")).unwrap(), vault);
    assert!(!secret_only.join("public.json").exists());

    let no_lock = temp.path("missing-lock");
    generate(&no_lock, PASSWORD).unwrap();
    let vault = fs::read(no_lock.join("seed.vault")).unwrap();
    let submission = fs::read(no_lock.join("public.json")).unwrap();
    fs::remove_file(no_lock.join(".fund-key.lock")).unwrap();
    assert!(public(&no_lock, PASSWORD).is_err());
    assert!(generate(&no_lock, PASSWORD).is_err());
    assert!(!no_lock.join(".fund-key.lock").exists());
    assert_eq!(fs::read(no_lock.join("seed.vault")).unwrap(), vault);
    assert_eq!(fs::read(no_lock.join("public.json")).unwrap(), submission);
}
