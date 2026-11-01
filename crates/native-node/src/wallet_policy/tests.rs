use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn network_defaults_never_enable_engineering_or_testnet_delay() {
    for network in [WalletNetwork::Engineering, WalletNetwork::Testnet] {
        let policy = WalletPrivacyPolicy::for_network(network);
        assert!(!policy.background_delay);
        assert!(!policy.enhanced_privacy);
    }
    assert!(WalletPrivacyPolicy::for_network(WalletNetwork::Mainnet).background_delay);
    assert!(!WalletPrivacyPolicy::for_network(WalletNetwork::Mainnet).enhanced_privacy);
    assert_eq!(
        WalletPrivacyPolicy::default().network_class,
        WalletNetwork::Engineering
    );
    assert_eq!(crate::wallet::AUTO_DELAY_MIN_SECONDS, 0);
    assert_eq!(crate::wallet::AUTO_DELAY_MAX_SECONDS, 21_600);
}

#[cfg(unix)]
struct Temporary(PathBuf);
#[cfg(unix)]
impl Temporary {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "wallet-policy-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
#[cfg(unix)]
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
#[test]
fn absent_policy_defaults_off_and_updates_preserve_network_binding() {
    let directory = Temporary::new();
    let network = [91; 32];
    assert_eq!(
        load(&directory.0, network).unwrap(),
        WalletPrivacyPolicy::default()
    );
    let mut policy = WalletPrivacyPolicy::for_network(WalletNetwork::Mainnet);
    policy.enhanced_privacy = true;
    save(&directory.0, network, policy).unwrap();
    assert_eq!(load(&directory.0, network).unwrap(), policy);
    policy.enhanced_privacy = false;
    policy.save(&directory.0, network).unwrap();
    assert_eq!(
        WalletPrivacyPolicy::load(&directory.0, network).unwrap(),
        policy
    );
    assert!(load(&directory.0, [92; 32]).is_err());
    assert!(save(&directory.0, [92; 32], policy).is_err());
}

#[cfg(unix)]
#[test]
fn policy_storage_rejects_symlinks_hardlinks_and_insecure_modes() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = Temporary::new();
    let other = Temporary::new();
    let network = [93; 32];
    save(&other.0, network, WalletPrivacyPolicy::default()).unwrap();
    let path = directory.0.join(FILE_NAME);
    symlink(other.0.join(FILE_NAME), &path).unwrap();
    assert!(load(&directory.0, network).is_err());
    assert!(save(&directory.0, network, WalletPrivacyPolicy::default()).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::hard_link(other.0.join(FILE_NAME), &path).unwrap();
    assert!(load(&directory.0, network).is_err());
    assert!(save(&directory.0, network, WalletPrivacyPolicy::default()).is_err());
    std::fs::remove_file(&path).unwrap();
    save(&directory.0, network, WalletPrivacyPolicy::default()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load(&directory.0, network).is_err());
}

#[cfg(unix)]
#[test]
fn policy_storage_rejects_ambiguous_unknown_or_wrong_typed_configuration() {
    use std::os::unix::fs::PermissionsExt;
    let directory = Temporary::new();
    let network = [94; 32];
    for raw in [
        b"{\"schema\":1,\"schema\":1}\n".as_slice(),
        b"{\"schema\":true}\n".as_slice(),
        b"{\"unknown\":false}\n".as_slice(),
    ] {
        let path = directory.0.join(FILE_NAME);
        std::fs::write(&path, raw).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&directory.0, network).is_err());
        assert!(save(&directory.0, network, WalletPrivacyPolicy::default()).is_err());
    }
    assert!(load(&directory.0, [0; 32]).is_err());
}
