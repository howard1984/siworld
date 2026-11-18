mod common;
use siworld_native_wallet_engine::{compact::CompactBlock, light::LightWallet};
use zeroize::Zeroizing;

#[test]
fn private_cache_reopens_receipts_paths_and_extends_without_compact_replay() {
    let (config, block) = common::fixture();
    let mut light = LightWallet::new(config.clone(), Zeroizing::new([42; 32]), 0).unwrap();
    light
        .append(&CompactBlock::decode(&CompactBlock::export(&block).unwrap()).unwrap())
        .unwrap();
    let cached = light.local_cache().unwrap();
    assert!(cached.len() < 100000);
    let mut reopened =
        LightWallet::open_local(config.clone(), Zeroizing::new([42; 32]), 0, &cached).unwrap();
    assert_eq!(
        light.balance_json().unwrap(),
        reopened.balance_json().unwrap()
    );
    assert_eq!(light.state.fingerprint(), reopened.state.fingerprint());
    assert_eq!(
        reopened.wallet.receipts()[0].commitment,
        light.wallet.receipts()[0].commitment
    );
    let address = reopened.wallet.address();
    assert!(reopened.prepare(&address, 1000000, true, &[]).is_ok());
    reopened.clear_prepared();
    let mut second = block;
    second.height = 2;
    second.parent = light.state.tip;
    second.timestamp = 601;
    second.rewards[0].commitment = common::digest(800001);
    second.rewards[0].ciphertext = [0; 1313];
    let compact = CompactBlock::decode(&CompactBlock::export(&second).unwrap()).unwrap();
    light.append(&compact).unwrap();
    reopened.append(&compact).unwrap();
    assert_eq!(light.state.fingerprint(), reopened.state.fingerprint());
    assert_eq!(
        light.local_cache().unwrap().as_slice(),
        reopened.local_cache().unwrap().as_slice()
    );
    assert!(reopened.prepare(&address, 1000000, false, &[]).is_ok());
    assert!(LightWallet::open_local(config, Zeroizing::new([42; 32]), 1, &cached).is_err());
}

#[test]
fn malformed_private_cache_never_replaces_an_accepted_wallet() {
    let (config, block) = common::fixture();
    let mut light = LightWallet::new(config.clone(), Zeroizing::new([42; 32]), 0).unwrap();
    light
        .append(&CompactBlock::decode(&CompactBlock::export(&block).unwrap()).unwrap())
        .unwrap();
    let saved = light.local_cache().unwrap();
    for offset in [0, 8, saved.len() - 1] {
        let mut bad = saved.to_vec();
        bad[offset] ^= 1;
        assert!(
            LightWallet::open_local(config.clone(), Zeroizing::new([42; 32]), 0, &bad).is_err()
        );
    }
    assert!(
        LightWallet::open_local(
            config.clone(),
            Zeroizing::new([42; 32]),
            0,
            &saved[..saved.len() - 1]
        )
        .is_err()
    );
    let mut extra = saved.to_vec();
    extra.push(0);
    assert!(LightWallet::open_local(config, Zeroizing::new([42; 32]), 0, &extra).is_err());
    assert_eq!(light.local_cache().unwrap().as_slice(), saved.as_slice());
    // A valid outer checksum must not bypass the private path invariant.
    let mut wrong_path = saved.to_vec();
    let end = wrong_path.len() - 32;
    wrong_path[end - 1] ^= 1;
    let checksum = *blake3::hash(&wrong_path[..end]).as_bytes();
    wrong_path[end..].copy_from_slice(&checksum);
    assert!(
        LightWallet::open_local(
            light.state.config.clone(),
            Zeroizing::new([42; 32]),
            0,
            &wrong_path
        )
        .is_err()
    );
}

#[test]
fn local_cache_preserves_spent_receipts_and_unspent_change_paths() {
    let (config, mut block) = common::fixture();
    let mut light = LightWallet::new(config.clone(), Zeroizing::new([42; 32]), 0).unwrap();
    light
        .append(&CompactBlock::decode(&CompactBlock::export(&block).unwrap()).unwrap())
        .unwrap();
    let old = light.wallet.receipts()[0].commitment;
    let prepared: serde_json::Value = serde_json::from_str(
        &light
            .prepare(&light.wallet.address(), 1000000, false, &[])
            .unwrap(),
    )
    .unwrap();
    light.clear_prepared();
    let public = prepared["public"].as_str().unwrap();
    // Synthetic light-client data only; this does not assert proof validity.
    block.height = 2;
    block.parent = light.state.tip;
    block.timestamp = 601;
    block.transactions[0].record.body = public
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    block.transactions[0].record.snapshot = light.state.tip_snapshot().selector;
    block
        .transactions
        .sort_by_key(|t| t.record.statement_id(&config.network));
    block.rewards[0].commitment = common::digest(800002);
    block.rewards[0].ciphertext = [0; 1313];
    light
        .append(&CompactBlock::decode(&CompactBlock::export(&block).unwrap()).unwrap())
        .unwrap();
    assert!(
        light
            .wallet
            .receipts()
            .iter()
            .find(|r| r.commitment == old)
            .unwrap()
            .spent
    );
    let saved = light.local_cache().unwrap();
    let mut reopened =
        LightWallet::open_local(config, Zeroizing::new([42; 32]), 0, &saved).unwrap();
    assert_eq!(reopened.state.fingerprint(), light.state.fingerprint());
    assert_eq!(
        reopened.balance_json().unwrap(),
        light.balance_json().unwrap()
    );
    assert!(
        reopened
            .prepare(&reopened.wallet.address(), 1000000, true, &[])
            .is_ok()
    );
}

#[test]
fn cached_asset_registry_preserves_order_and_rejects_invalid_bounds() {
    use native::issuance::{
        AssetMetadata, ISSUER_KEY_BYTES, IssuanceDeclaration, SignedIssuance, derive_asset_id,
    };
    use siworld_native_wallet_engine::issuance::{AssetRegistry, IssuanceRecord};
    let (config, _) = common::fixture();
    let mut registry = AssetRegistry::default();
    for sequence in [2, 1] {
        let key = [7; ISSUER_KEY_BYTES];
        let declaration = IssuanceDeclaration {
            network: config.network,
            version: 1,
            issuer_key: key,
            sequence,
            asset_id: derive_asset_id(&config.network, &key, sequence),
            public_supply: 100,
            metadata: AssetMetadata {
                name: "Synthetic asset".into(),
                decimals: 2,
            },
            issuance_fee_atoms: 5000000000,
            note_commitments: vec![],
            note_ciphertext_digests: vec![],
        };
        let record = IssuanceRecord {
            signed: SignedIssuance {
                declaration,
                signature: None,
            },
            ciphertexts: vec![],
            proof: vec![],
            fee_commitment: common::digest(9000 + sequence as u32),
            fee_rho: common::digest(9100 + sequence as u32),
        };
        registry.apply(&record, sequence).unwrap();
    }
    let mut bytes = Vec::new();
    registry.visit_encoding(&mut |part| bytes.extend_from_slice(part));
    assert_eq!(
        AssetRegistry::from_local_encoding(&bytes, 2).unwrap(),
        registry
    );
    assert!(AssetRegistry::from_local_encoding(&bytes, 1).is_err());
    assert!(AssetRegistry::from_local_encoding(&bytes[..bytes.len() - 1], 2).is_err());
    bytes[0] = 255;
    assert!(AssetRegistry::from_local_encoding(&bytes, 2).is_err());
}
