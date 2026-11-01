use super::*;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
struct Directory(PathBuf);
#[cfg(unix)]
impl Directory {
    fn new() -> Self {
        let root = fs::canonicalize(std::env::temp_dir()).unwrap();
        let mut token = [0; 16];
        getrandom::fill(&mut token).unwrap();
        let path = root.join(format!("siworld-identity-{}", crate::local::hex(&token)));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).unwrap();
        Self(path)
    }
}
#[cfg(unix)]
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn binding() -> Binding {
    Binding {
        network: [1; 32],
        genesis: [2; 32],
        verifier: [3; 32],
    }
}
fn identity(seed: u8) -> NativeIdentity {
    NativeIdentity::from_seeds(binding(), &[seed; 32], &[seed + 1; 32])
}

#[test]
fn descriptor_is_fixed_canonical_dual_signed_and_context_bound() {
    let descriptor = identity(8).descriptor().unwrap();
    let encoded = descriptor.encode();
    assert_eq!(encoded.len(), DESCRIPTOR_BYTES);
    assert_eq!(DESCRIPTOR_BYTES, 5459);
    assert_eq!(
        Descriptor::decode(&encoded, &binding()).unwrap(),
        descriptor
    );
    for offset in [0, 4, 6, 38, 70, 102, 134, BODY_BYTES, BODY_BYTES + 64] {
        let mut bad = encoded;
        bad[offset] ^= 1;
        assert!(
            Descriptor::decode(&bad, &binding()).is_err(),
            "offset {offset}"
        );
    }
    for end in [0, 4, BODY_BYTES, DESCRIPTOR_BYTES - 1] {
        assert!(Descriptor::decode(&encoded[..end], &binding()).is_err());
    }
    let mut longer = encoded.to_vec();
    longer.push(0);
    assert!(Descriptor::decode(&longer, &binding()).is_err());
    for selected in 0..3 {
        let mut expected = binding();
        match selected {
            0 => expected.network[0] ^= 1,
            1 => expected.genesis[0] ^= 1,
            _ => expected.verifier[0] ^= 1,
        }
        assert!(Descriptor::decode(&encoded, &expected).is_err());
    }
}

#[test]
fn pin_is_stable_across_signature_randomness_and_rejects_substituted_keys() {
    let key = identity(16);
    let first = key.descriptor().unwrap();
    let second = key.descriptor().unwrap();
    assert_eq!(first.fingerprint(), second.fingerprint());
    assert_ne!(first.ml_dsa_signature, second.ml_dsa_signature);
    let pin = PeerPin::from_trusted_descriptor(&first, &binding()).unwrap();
    pin.verify(&second).unwrap();
    assert!(pin.verify(&identity(32).descriptor().unwrap()).is_err());
    let mut missing_ed = second.clone();
    missing_ed.ed25519_signature.fill(0);
    assert!(pin.verify(&missing_ed).is_err());
    let mut missing_ml = second.clone();
    missing_ml.ml_dsa_signature.fill(0);
    assert!(pin.verify(&missing_ml).is_err());
    let mut zero_key = first.clone();
    zero_key.ed25519_public.fill(0);
    assert!(zero_key.verify(&binding()).is_err());
    let mut zero_key = first;
    zero_key.ml_dsa_public.fill(0);
    assert!(zero_key.verify(&binding()).is_err());
}

#[test]
fn debug_contains_no_secret_or_key_material() {
    let key = identity(48);
    assert_eq!(format!("{key:?}"), "NativeIdentity(REDACTED)");
    fn zeroizes<T: zeroize::ZeroizeOnDrop>() {}
    zeroizes::<NativeIdentity>();
}

#[test]
fn empty_context_identifiers_are_rejected() {
    let encoded = identity(52).descriptor().unwrap().encode();
    for selected in 0..3 {
        let mut expected = binding();
        match selected {
            0 => expected.network = [0; 32],
            1 => expected.genesis = [0; 32],
            _ => expected.verifier = [0; 32],
        }
        assert!(Descriptor::decode(&encoded, &expected).is_err());
    }
}

#[cfg(unix)]
#[test]
fn explicit_initialization_is_write_once_and_restart_stable() {
    let directory = Directory::new();
    assert_eq!(
        NativeIdentity::load(&directory.0, &binding()).err(),
        Some(Error::Storage)
    );
    assert!(!directory.0.join(IDENTITY_FILE).exists());
    let first = NativeIdentity::initialize(&directory.0, binding()).unwrap();
    let before = fs::read(directory.0.join(IDENTITY_FILE)).unwrap();
    assert_eq!(before.len(), SECRET_BYTES);
    let loaded = NativeIdentity::load(&directory.0, &binding()).unwrap();
    assert_eq!(
        first.descriptor().unwrap().fingerprint(),
        loaded.descriptor().unwrap().fingerprint()
    );
    assert!(NativeIdentity::initialize(&directory.0, binding()).is_err());
    assert_eq!(fs::read(directory.0.join(IDENTITY_FILE)).unwrap(), before);
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn concurrent_initializers_leave_exactly_one_identity_without_temporary_files() {
    use std::sync::{Arc, Barrier};
    let directory = Directory::new();
    let barrier = Arc::new(Barrier::new(4));
    let threads = (0..4)
        .map(|_| {
            let path = directory.0.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                NativeIdentity::initialize(&path, binding())
                    .map(|key| key.descriptor().unwrap().fingerprint())
            })
        })
        .collect::<Vec<_>>();
    let winners = threads
        .into_iter()
        .filter_map(|thread| thread.join().unwrap().ok())
        .collect::<Vec<_>>();
    assert_eq!(winners.len(), 1);
    assert_eq!(
        NativeIdentity::load(&directory.0, &binding())
            .unwrap()
            .descriptor()
            .unwrap()
            .fingerprint(),
        winners[0]
    );
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn every_corrupted_record_and_wrong_binding_fail_without_regeneration() {
    let directory = Directory::new();
    NativeIdentity::initialize(&directory.0, binding()).unwrap();
    let path = directory.0.join(IDENTITY_FILE);
    let original = fs::read(&path).unwrap();
    for offset in 0..SECRET_BYTES {
        let mut corrupt = original.clone();
        corrupt[offset] ^= 1;
        fs::write(&path, &corrupt).unwrap();
        assert!(
            NativeIdentity::load(&directory.0, &binding()).is_err(),
            "offset {offset}"
        );
        assert_eq!(fs::read(&path).unwrap(), corrupt);
    }
    fs::write(&path, &original).unwrap();
    let mut other = binding();
    other.genesis[1] ^= 1;
    assert!(NativeIdentity::load(&directory.0, &other).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    for size in [0, 1, SECRET_BYTES - 1, SECRET_BYTES + 1, 65_536] {
        fs::write(&path, vec![0; size]).unwrap();
        assert!(NativeIdentity::load(&directory.0, &binding()).is_err());
    }
}

#[cfg(unix)]
#[test]
fn public_pin_persistence_is_explicit_immutable_and_binding_checked() {
    let directory = Directory::new();
    let descriptor = identity(64).descriptor().unwrap();
    let pin = PeerPin::from_trusted_descriptor(&descriptor, &binding()).unwrap();
    pin.persist(&directory.0).unwrap();
    assert!(pin.persist(&directory.0).is_err());
    let loaded = PeerPin::load(&directory.0, pin.fingerprint(), &binding()).unwrap();
    loaded.verify(&descriptor).unwrap();
    assert!(PeerPin::load(&directory.0, [0; 32], &binding()).is_err());
    let mut other = binding();
    other.verifier[0] ^= 1;
    assert!(PeerPin::load(&directory.0, pin.fingerprint(), &other).is_err());
    let path = directory.0.join(pin_filename(&pin.fingerprint()));
    let mut corrupt = fs::read(&path).unwrap();
    corrupt[10] ^= 1;
    fs::write(&path, corrupt).unwrap();
    assert!(PeerPin::load(&directory.0, pin.fingerprint(), &binding()).is_err());
}

#[cfg(unix)]
#[test]
fn symlinks_hardlinks_permissions_and_nonregular_records_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = Directory::new();
    NativeIdentity::initialize(&directory.0, binding()).unwrap();
    let path = directory.0.join(IDENTITY_FILE);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(NativeIdentity::load(&directory.0, &binding()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let linked = directory.0.join("linked");
    fs::hard_link(&path, &linked).unwrap();
    assert!(NativeIdentity::load(&directory.0, &binding()).is_err());
    fs::remove_file(&linked).unwrap();
    fs::rename(&path, &linked).unwrap();
    symlink(&linked, &path).unwrap();
    assert!(NativeIdentity::load(&directory.0, &binding()).is_err());
    assert!(NativeIdentity::initialize(&directory.0, binding()).is_err());
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(NativeIdentity::load(&directory.0, &binding()).is_err());
    fs::remove_dir(&path).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert!(NativeIdentity::load(&directory.0, &binding()).is_err());
    fs::remove_file(&path).unwrap();
    fs::rename(&linked, &path).unwrap();
    let alias_parent = Directory::new();
    let alias = alias_parent.0.join("alias");
    symlink(&directory.0, &alias).unwrap();
    assert!(NativeIdentity::load(&alias, &binding()).is_err());
    assert!(NativeIdentity::initialize(&alias, binding()).is_err());
    let nested = directory.0.join("nested");
    fs::create_dir(&nested).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(NativeIdentity::initialize(&alias.join("nested"), binding()).is_err());
    assert!(NativeIdentity::load(&nested.join("..").join("."), &binding()).is_err());
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(NativeIdentity::load(&directory.0, &binding()).is_err());
}
