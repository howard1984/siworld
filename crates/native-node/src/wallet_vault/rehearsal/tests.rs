use super::*;
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
const PASSWORD: &str = "synthetic isolated vault password";
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "siworld-isolated-actor-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn parameters(campaign: u8, network: u8) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"version":1,"campaign_id":crate::local::hex(&[campaign;32]),
        "network":crate::local::hex(&[network;32]),"prior_network":crate::local::hex(&[1;32]),
        "genesis_parameters_sha256":crate::local::hex(&[3;32])}),
    )
    .unwrap()
}
fn binding(campaign: u8) -> RehearsalBinding {
    let bytes = parameters(campaign, 2);
    RehearsalBinding::decode(&bytes, Sha256::digest(&bytes).into()).unwrap()
}
#[test]
fn public_binding_rejects_changed_pin_same_network_and_unknown_fields() {
    let bytes = parameters(4, 2);
    assert!(RehearsalBinding::decode(&bytes, [9; 32]).is_err());
    let bytes = parameters(4, 1);
    assert!(RehearsalBinding::decode(&bytes, Sha256::digest(&bytes).into()).is_err());
    let mut value: Value = serde_json::from_slice(&parameters(4, 2)).unwrap();
    value["unreviewed"] = json!(true);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(RehearsalBinding::decode(&bytes, Sha256::digest(&bytes).into()).is_err());
}
#[test]
fn independent_actor_vaults_reopen_same_format_and_refuse_replacement_or_wrong_role() {
    let root = Directory::new();
    let parameters = binding(4);
    let first = root.0.join("payer");
    let second = root.0.join("recipient");
    let payer =
        WalletVault::create_isolated_rehearsal(&first, PASSWORD, &parameters, ActorRole::Payer)
            .unwrap();
    let payer_address = canonical_address(&payer.wallet().unwrap().address());
    let receipt =
        WalletVault::isolated_rehearsal_receipt(&payer, &parameters, ActorRole::Payer).unwrap();
    assert_eq!(receipt["recovery_backup_verified"], false);
    assert_eq!(receipt["encrypted_vault_format"], "SWNVLT01");
    assert_eq!(
        &fs::read(first.join("seed.vault")).unwrap()[..8],
        b"SWNVLT01"
    );
    drop(payer);
    let ciphertext = fs::read(first.join("seed.vault")).unwrap();
    assert!(
        WalletVault::create_isolated_rehearsal(&first, PASSWORD, &parameters, ActorRole::Payer)
            .is_err()
    );
    assert_eq!(fs::read(first.join("seed.vault")).unwrap(), ciphertext);
    assert!(
        WalletVault::open_isolated_rehearsal(&first, PASSWORD, &parameters, ActorRole::Recipient)
            .is_err()
    );
    assert!(
        WalletVault::open_isolated_rehearsal(&first, PASSWORD, &binding(5), ActorRole::Payer)
            .is_err()
    );
    let recipient = WalletVault::create_isolated_rehearsal(
        &second,
        PASSWORD,
        &parameters,
        ActorRole::Recipient,
    )
    .unwrap();
    assert_ne!(
        payer_address,
        canonical_address(&recipient.wallet().unwrap().address())
    );
    drop(recipient);
    let reopened =
        WalletVault::open_isolated_rehearsal(&first, PASSWORD, &parameters, ActorRole::Payer)
            .unwrap();
    assert_eq!(
        canonical_address(&reopened.wallet().unwrap().address()),
        payer_address
    );
}
