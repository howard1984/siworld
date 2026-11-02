#![cfg(feature = "native-parity")]
use reference_native::{wallet::WalletKeys, wallet_vault::WalletVault};
use siworld_native_wallet_core::{identity::Identity, vault::Material};
use std::os::unix::fs::PermissionsExt;

#[test]
fn native_identity_matches_multiple_networks_accounts_and_entropy() {
    let mut vectors = Vec::new();
    for network in [[1; 32], [9; 32]] {
        for account in [0, 42, u32::MAX] {
            for entropy in [[0; 32], [7; 32]] {
                let native = WalletKeys::from_seed(network, entropy.into(), account).unwrap();
                let portable = Identity::derive(&entropy.into(), network, account).unwrap();
                let native_address = native.address();
                assert_eq!(
                    &portable.address()[..48],
                    &reference_math::codec::encode_digest(&native_address.owner())
                );
                assert_eq!(
                    &portable.address()[48..],
                    native_address.encapsulation_key()
                );
                let material = Material {
                    network,
                    account,
                    entropy: entropy.into(),
                };
                vectors.push(serde_json::json!({"network":siworld_native_wallet_core::hex(&network),"account":account,"words":material.words().as_str(),"address_hex":siworld_native_wallet_core::hex(portable.address())}));
            }
        }
    }
    if let Ok(path) = std::env::var("WALLET_PARITY_OUTPUT") {
        std::fs::write(path, serde_json::to_vec(&vectors).unwrap()).unwrap();
    }
}

#[test]
fn native_and_portable_vaults_authenticate_each_other() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("siworld-wallet-parity-{}", std::process::id()));
    assert!(!root.exists());
    let material = Material {
        network: [3; 32],
        account: 42,
        entropy: [0; 32].into(),
    };
    let native = WalletVault::restore(
        &root,
        material.network,
        material.account,
        material.words(),
        "synthetic-native-password",
    )
    .unwrap();
    drop(native);
    let native_bytes = std::fs::read(root.join("seed.vault")).unwrap();
    if let Ok(path) = std::env::var("WALLET_PARITY_VAULT") {
        std::fs::write(path,serde_json::to_vec(&serde_json::json!({"network":siworld_native_wallet_core::hex(&material.network),"account":material.account,"vault_hex":siworld_native_wallet_core::hex(&native_bytes),"address_hex":siworld_native_wallet_core::hex(Identity::derive(&material.entropy,material.network,material.account).unwrap().address())})).unwrap()).unwrap();
    }
    let portable =
        Material::open(&native_bytes, "synthetic-native-password", material.network).unwrap();
    assert_eq!(portable.account, material.account);
    assert_eq!(portable.entropy.as_ref(), material.entropy.as_ref());
    let portable_bytes = material.seal("synthetic-browser-password").unwrap();
    std::fs::write(root.join("seed.vault"), portable_bytes).unwrap();
    std::fs::set_permissions(
        root.join("seed.vault"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let native = WalletVault::open(&root, material.network, "synthetic-browser-password").unwrap();
    assert_eq!(native.account(), material.account);
    assert_eq!(
        native.keys().unwrap().address().encapsulation_key(),
        &Identity::derive(&material.entropy, material.network, material.account)
            .unwrap()
            .address()[48..]
    );
    drop(native);
    std::fs::remove_dir_all(root).unwrap();
}
