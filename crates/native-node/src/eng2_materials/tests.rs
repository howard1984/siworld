use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "siworld-eng2-material-tests-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn prepared(dir: &Directory, name: &str, purpose: Purpose, index: u8, seed: u8) -> Value {
    prepare_seed(
        &dir.path(name),
        [1; 32],
        purpose,
        index,
        Zeroizing::new([seed; 32]),
    )
    .unwrap()
}
fn sealed(dir: &Directory) -> (std::path::PathBuf, [u8; 32], [u8; 32]) {
    let state = crate::eng2::snapshot::tests::bootstrap();
    let config = crate::state::Config::asert_development([1; 32], 1, [0xff; 32], 1)
        .unwrap()
        .with_fund_wallets(
            state.chain.config.fund_allocation.clone().unwrap(),
            state.chain.config.fund_verifying_keys.clone(),
        )
        .unwrap();
    let genesis = Genesis::seal(
        config,
        state.governance.clone(),
        crate::eng2::genesis::FeeMode::LegacyMiner,
    )
    .unwrap();
    let bytes = genesis.encode().unwrap();
    let path = dir.path("genesis.bin");
    fs::write(&path, &bytes).unwrap();
    (path, genesis.id(), Sha256::digest(&bytes).into())
}
#[test]
fn prepare_writes_exact_protected_context_and_hash_only_receipt() {
    let dir = Directory::new();
    let r = prepared(&dir, "key", Purpose::Checkpoint, 0, 3);
    let root = dir.path("key");
    let private = fs::read(root.join("pending.secret")).unwrap();
    assert_eq!(private.len(), PENDING_BYTES);
    assert_eq!(&private[..8], MAGIC);
    assert_eq!(private[40], 0);
    assert_eq!(private[41], 0);
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    for name in ["pending.secret", "public.json"] {
        assert_eq!(
            fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }
    let p: Value = serde_json::from_slice(&fs::read(root.join("public.json")).unwrap()).unwrap();
    assert_eq!(p["purpose"], "checkpoint");
    assert_eq!(p["public_key_hex"].as_str().unwrap().len(), 3904);
    let text = serde_json::to_string(&r).unwrap();
    assert!(!text.contains("public_key_hex"));
    assert!(!text.contains("address_hex"));
    assert!(!text.contains("seed"));
    assert!(!text.contains(root.to_str().unwrap()));
}
#[test]
fn all_purposes_export_public_material_without_changing_fund_allocation() {
    let dir = Directory::new();
    for (i, purpose) in [
        Purpose::Founder,
        Purpose::Revocation,
        Purpose::FundClaim,
        Purpose::FeeWallet,
        Purpose::FundWallet,
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("purpose-{i}");
        let receipt = prepared(&dir, &name, purpose, 0, i as u8 + 10);
        let p: Value =
            serde_json::from_slice(&fs::read(dir.path(&name).join("public.json")).unwrap())
                .unwrap();
        assert_eq!(p["purpose"], purpose.name());
        assert_eq!(p.get("address_hex").is_some(), purpose.wallet());
        assert_eq!(
            receipt["public_identity_sha256"].as_str().unwrap().len(),
            64
        );
        assert!(p.get("allocation").is_none());
        assert!(p.get("basis_points").is_none());
    }
}
#[test]
fn checkpoint_binding_matches_the_existing_runtime_layout_and_preserves_pending() {
    let dir = Directory::new();
    prepared(&dir, "key", Purpose::Checkpoint, 0, 3);
    let (genesis, id, digest) = sealed(&dir);
    let before = fs::read(dir.path("key/pending.secret")).unwrap();
    let receipt = bind_checkpoint(&dir.path("key"), &genesis, id, digest).unwrap();
    let bound = fs::read(dir.path("key/checkpoint-bound.secret")).unwrap();
    assert_eq!(bound.len(), 169);
    assert_eq!(&bound[..8], b"SW2KEY01");
    assert_eq!(&bound[8..40], &[1; 32]);
    assert_eq!(&bound[40..72], &id);
    assert_eq!(bound[104], 0);
    assert_eq!(
        bound[137..],
        blake3::derive_key(BOUND_CONTEXT, &bound[..137])
    );
    assert_eq!(fs::read(dir.path("key/pending.secret")).unwrap(), before);
    assert_eq!(receipt["pending_preserved"], true);
}
#[test]
fn wrong_roster_slot_key_network_or_role_cannot_bind() {
    let dir = Directory::new();
    let (genesis, id, digest) = sealed(&dir);
    for (name, role, index, seed) in [
        ("slot", Purpose::Checkpoint, 1, 3),
        ("key", Purpose::Checkpoint, 0, 8),
        ("role", Purpose::Founder, 0, 3),
    ] {
        prepared(&dir, name, role, index, seed);
        assert!(bind_checkpoint(&dir.path(name), &genesis, id, digest).is_err());
        assert!(!dir.path(name).join("checkpoint-bound.secret").exists());
    }
    prepare_seed(
        &dir.path("network"),
        [2; 32],
        Purpose::Checkpoint,
        0,
        Zeroizing::new([3; 32]),
    )
    .unwrap();
    assert!(bind_checkpoint(&dir.path("network"), &genesis, id, digest).is_err());
}
#[test]
fn independent_genesis_pins_and_public_file_shape_are_mandatory() {
    let dir = Directory::new();
    prepared(&dir, "key", Purpose::Checkpoint, 0, 3);
    let (genesis, id, digest) = sealed(&dir);
    assert!(bind_checkpoint(&dir.path("key"), &genesis, [9; 32], digest).is_err());
    assert!(bind_checkpoint(&dir.path("key"), &genesis, id, [9; 32]).is_err());
    assert!(bind_checkpoint(&dir.path("key"), &genesis, [0; 32], digest).is_err());
    symlink(&genesis, dir.path("genesis-link")).unwrap();
    assert!(bind_checkpoint(&dir.path("key"), &dir.path("genesis-link"), id, digest).is_err());
    fs::hard_link(&genesis, dir.path("genesis-hard")).unwrap();
    assert!(bind_checkpoint(&dir.path("key"), &genesis, id, digest).is_err());
}
#[test]
fn repeated_prepare_and_bind_never_overwrite() {
    let dir = Directory::new();
    prepared(&dir, "key", Purpose::Checkpoint, 0, 3);
    let original = fs::read(dir.path("key/pending.secret")).unwrap();
    assert!(
        prepare_seed(
            &dir.path("key"),
            [1; 32],
            Purpose::Checkpoint,
            0,
            Zeroizing::new([8; 32])
        )
        .is_err()
    );
    assert_eq!(fs::read(dir.path("key/pending.secret")).unwrap(), original);
    let (genesis, id, digest) = sealed(&dir);
    bind_checkpoint(&dir.path("key"), &genesis, id, digest).unwrap();
    let bound = fs::read(dir.path("key/checkpoint-bound.secret")).unwrap();
    assert!(bind_checkpoint(&dir.path("key"), &genesis, id, digest).is_err());
    assert_eq!(
        fs::read(dir.path("key/checkpoint-bound.secret")).unwrap(),
        bound
    );
}
#[test]
fn malformed_pending_or_public_record_is_rejected_before_publication() {
    let dir = Directory::new();
    let (genesis, id, digest) = sealed(&dir);
    for (i, offset) in [0, 8, 40, 41, 42, 74].into_iter().enumerate() {
        let name = format!("corrupt-{i}");
        prepared(&dir, &name, Purpose::Checkpoint, 0, 3);
        let path = dir.path(&name).join("pending.secret");
        let mut bytes = fs::read(&path).unwrap();
        bytes[offset] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert!(bind_checkpoint(&dir.path(&name), &genesis, id, digest).is_err());
        assert!(!dir.path(&name).join("checkpoint-bound.secret").exists());
    }
    prepared(&dir, "public", Purpose::Checkpoint, 0, 3);
    let path = dir.path("public/public.json");
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 1;
    fs::write(&path, &bytes).unwrap();
    assert!(bind_checkpoint(&dir.path("public"), &genesis, id, digest).is_err());
}
#[test]
fn symlink_hardlink_and_permissive_private_records_are_rejected() {
    let dir = Directory::new();
    let (genesis, id, digest) = sealed(&dir);
    prepared(&dir, "key", Purpose::Checkpoint, 0, 3);
    let key = dir.path("key/pending.secret");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(bind_checkpoint(&dir.path("key"), &genesis, id, digest).is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let hard = dir.path("alias");
    fs::hard_link(&key, &hard).unwrap();
    assert!(bind_checkpoint(&dir.path("key"), &genesis, id, digest).is_err());
    fs::remove_file(hard).unwrap();
    fs::rename(&key, dir.path("saved")).unwrap();
    symlink(dir.path("saved"), &key).unwrap();
    assert!(bind_checkpoint(&dir.path("key"), &genesis, id, digest).is_err());
    fs::set_permissions(dir.path("key"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(storage::Directory::open(&dir.path("key")).is_err());
}
#[test]
fn repository_and_symlink_ancestors_are_rejected() {
    let dir = Directory::new();
    fs::create_dir(dir.path("repo")).unwrap();
    fs::write(dir.path("repo/.git"), b"gitdir: irrelevant").unwrap();
    assert!(
        prepare_seed(
            &dir.path("repo/key"),
            [1; 32],
            Purpose::Checkpoint,
            0,
            Zeroizing::new([3; 32])
        )
        .is_err()
    );
    assert!(!dir.path("repo/key").exists());
    symlink(&dir.0, dir.path("link")).unwrap();
    assert!(
        prepare_seed(
            &dir.path("link/key"),
            [1; 32],
            Purpose::Checkpoint,
            0,
            Zeroizing::new([3; 32])
        )
        .is_err()
    );
    assert!(!dir.path("key").exists());
}
#[test]
fn invalid_context_and_indices_create_no_custody() {
    let dir = Directory::new();
    for (purpose, index) in [
        (Purpose::Checkpoint, 3),
        (Purpose::Founder, 1),
        (Purpose::Revocation, 1),
        (Purpose::FundClaim, 32),
        (Purpose::FeeWallet, 1),
        (Purpose::FundWallet, 32),
    ] {
        assert!(prepare(&dir.path("invalid"), [1; 32], purpose, index).is_err());
    }
    assert!(prepare(&dir.path("zero"), [0; 32], Purpose::Checkpoint, 0).is_err());
    assert!(!dir.path("invalid").exists());
    assert!(!dir.path("zero").exists());
}

#[test]
fn entropy_failure_stops_before_directory_creation() {
    let dir = Directory::new();
    let result = prepare_with_entropy(
        &dir.path("entropy"),
        [1; 32],
        Purpose::Checkpoint,
        0,
        |_| Err("test entropy unavailable".into()),
    );
    assert!(result.is_err());
    assert!(!dir.path("entropy").exists());
}

#[test]
fn fixture_genesis_is_refused_before_binding() {
    let dir = Directory::new();
    prepared(&dir, "key", Purpose::Checkpoint, 0, 3);
    let state = crate::eng2::snapshot::tests::bootstrap();
    let genesis = Genesis::seal(
        state.chain.config.clone(),
        state.governance.clone(),
        crate::eng2::genesis::FeeMode::LegacyMiner,
    )
    .unwrap();
    let bytes = genesis.encode().unwrap();
    let path = dir.path("fixture-genesis.bin");
    fs::write(&path, &bytes).unwrap();
    assert!(
        bind_checkpoint(
            &dir.path("key"),
            &path,
            genesis.id(),
            Sha256::digest(&bytes).into()
        )
        .is_err()
    );
    assert!(!dir.path("key/checkpoint-bound.secret").exists());
}
