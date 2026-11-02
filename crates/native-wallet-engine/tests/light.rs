mod common;
use siworld_native_wallet_engine::{
    compact::CompactBlock,
    light::LightWallet,
    ranges::{DOMAIN, RangeProof},
    state::State,
    wallet::Wallet,
};
use zeroize::Zeroizing;
#[test]
fn light_balance_lists_each_holder_unlock_and_matures_at_accepted_height() {
    use native::{
        codec::encode_digest,
        encryption::{EncryptionContext, encrypt_payment},
        multi_asset::{F, Hasher, Note, SIP_ASSET_ID},
    };
    use p3_field::PrimeCharacteristicRing;
    use siworld_native_wallet_engine::wire::RewardRecord;
    let (config, mut block) = common::fixture();
    let wallet = Wallet::from_seed(config.network, Zeroizing::new([42; 32]), 0).unwrap();
    let heights = [24, 105216, 210408, 315600, 420792];
    block.rewards = heights
        .iter()
        .enumerate()
        .map(|(i, &height)| {
            let note = Note {
                owner: wallet.address().owner(),
                value: 100,
                unlock_height: height,
                rho: [F::from_u32(300000 + i as u32); 12],
                rseed: [F::from_u32(400000 + i as u32); 12],
                asset_id: SIP_ASSET_ID,
            };
            let p = encrypt_payment(
                &wallet.address(),
                &note,
                &EncryptionContext::new(config.network),
            )
            .unwrap();
            let mut ciphertext = [0; 1313];
            ciphertext[..1088].copy_from_slice(&p.kem_ciphertext);
            ciphertext[1088..1296].copy_from_slice(&p.body);
            ciphertext[1296..1312].copy_from_slice(&p.tag);
            ciphertext[1312] = p.view_tag;
            RewardRecord {
                commitment: encode_digest(&Hasher::new().note_cm(&note)),
                ciphertext,
            }
        })
        .collect();
    let compact = CompactBlock::decode(&CompactBlock::export(&block).unwrap()).unwrap();
    let mut light = LightWallet::new(config, Zeroizing::new([42; 32]), 0).unwrap();
    light.append(&compact).unwrap();
    let balance: serde_json::Value = serde_json::from_str(&light.balance_json().unwrap()).unwrap();
    let tranches = balance["locked_tranches"].as_array().unwrap();
    assert_eq!(tranches.len(), 5);
    assert_eq!(
        tranches
            .iter()
            .map(|r| r["unlock_height"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        heights
    );
    assert!(
        tranches
            .iter()
            .all(|r| r["estimated_timestamp"].as_u64().is_some() && r["amount_atoms"] == "100")
    );
    // Display logic uses accepted height, including during fast ASERT catch-up.
    light.state.height = 24;
    light
        .wallet
        .scan_light_data(&light.state, &[], &[], true)
        .unwrap();
    let balance: serde_json::Value = serde_json::from_str(&light.balance_json().unwrap()).unwrap();
    assert_eq!(balance["locked_tranches"].as_array().unwrap().len(), 4);
    assert_eq!(balance["rows"][0]["available_atoms"], "100");
    assert_eq!(balance["rows"][0]["locked_atoms"], "400");
}
#[test]
fn compact_authenticates_all_positions_and_never_retains_historical_proofs() {
    let (_, b) = common::fixture();
    let bytes = CompactBlock::export(&b).unwrap();
    let c = CompactBlock::decode(&bytes).unwrap();
    assert_eq!(b.id().unwrap(), c.id);
    assert_eq!(c.block.transactions.len(), 64);
    assert!(c.block.transactions.iter().all(|t| t.proof.is_empty()));
    assert!(c.block.settlement_proof.is_empty());
    for offset in [0, 16, 64, 200, bytes.len() - 1] {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        assert!(CompactBlock::decode(&corrupt).is_err());
    }
    assert!(CompactBlock::decode(&bytes[..bytes.len() - 1]).is_err());
    // A valid authentication proof for the header alone cannot hide required outputs.
    let mut raw = b.encode().unwrap();
    raw.drain(145..153);
    let proof = RangeProof::create(&raw, &[(0, 150)]).unwrap();
    let mut hidden = b"SWLC0001".to_vec();
    hidden.extend(b.nonce.to_le_bytes());
    hidden.extend(b.pow_seed().unwrap());
    hidden.extend(proof);
    assert!(
        CompactBlock::decode(&hidden)
            .unwrap_err_string()
            .contains("concealed")
    );
    let full = RangeProof::create(&raw, &[(0, raw.len())]).unwrap();
    let mut excess = b"SWLC0001".to_vec();
    excess.extend(b.nonce.to_le_bytes());
    excess.extend(b.pow_seed().unwrap());
    excess.extend(full);
    assert!(
        CompactBlock::decode(&excess)
            .unwrap_err_string()
            .contains("extra historical")
    );
    let seed = *blake3::Hasher::new_derive_key(DOMAIN)
        .update(&raw)
        .finalize()
        .as_bytes();
    assert_eq!(seed, b.pow_seed().unwrap());
}
trait ErrorString {
    fn unwrap_err_string(self) -> String;
}
impl<T> ErrorString for Result<T, String> {
    fn unwrap_err_string(self) -> String {
        match self {
            Ok(_) => panic!("Unexpected acceptance"),
            Err(e) => e,
        }
    }
}
#[test]
fn light_scans_owned_rewards_and_rejects_a_failed_append_atomically() {
    let (config, b) = common::fixture();
    let mut l = LightWallet::new(config.clone(), Zeroizing::new([42; 32]), 0).unwrap();
    let c = CompactBlock::decode(&CompactBlock::export(&b).unwrap()).unwrap();
    l.append(&c).unwrap();
    assert_eq!(l.wallet.receipts().len(), 1);
    assert_eq!(l.wallet.receipts()[0].note().value, 100000000000);
    let old = l.balance_json().unwrap();
    assert!(l.append(&c).is_err());
    assert_eq!(l.balance_json().unwrap(), old);
    let mut wrong = b.clone();
    wrong.height = 2;
    wrong.parent = c.id;
    wrong.timestamp = 601;
    let d = CompactBlock::decode(&CompactBlock::export(&wrong).unwrap()).unwrap();
    assert!(l.append(&d).is_err());
    assert_eq!(l.balance_json().unwrap(), old);
    let mut w = Wallet::from_seed(config.network, Zeroizing::new([42; 32]), 0).unwrap();
    w.scan_light_data(&l.state, &[b.clone()], &[c.id], false)
        .unwrap();
    let mut invalid = b;
    invalid.rewards[0].commitment = [255; 48];
    assert!(
        w.scan_light_data(&l.state, &[invalid], &[c.id], true)
            .is_err()
    );
    assert_eq!(w.receipts().len(), 1);
    let genesis = State::new(config).unwrap();
    assert!(genesis.cumulative_work < l.state.cumulative_work);
}
#[test]
fn rejects_work_target_parent_timestamp_and_network_substitution() {
    let (config, b) = common::fixture();
    for variant in 0..4 {
        let mut bad = b.clone();
        match variant {
            0 => bad.target = [1; 32],
            1 => bad.parent = [2; 32],
            2 => bad.timestamp = 0,
            _ => bad.network = [9; 32],
        };
        let Ok(encoded) = CompactBlock::export(&bad) else {
            continue;
        };
        let c = CompactBlock::decode(&encoded).unwrap();
        let mut l = LightWallet::new(config.clone(), Zeroizing::new([42; 32]), 0).unwrap();
        assert!(l.append(&c).is_err());
        assert_eq!(l.state.height, 0);
        assert!(l.wallet.receipts().is_empty());
    }
}

#[test]
fn compact_owned_paths_prepare_both_fee_tiers_and_enforce_reservations() {
    let (config, b) = common::fixture();
    let mut light = LightWallet::new(config, Zeroizing::new([42; 32]), 0).unwrap();
    light
        .append(&CompactBlock::decode(&CompactBlock::export(&b).unwrap()).unwrap())
        .unwrap();
    assert!(light.state.leaves.is_empty());
    let recipient = light.wallet.address();
    let ordinary: serde_json::Value =
        serde_json::from_str(&light.prepare(&recipient, 1000000, false, &[]).unwrap()).unwrap();
    assert_eq!(ordinary["amount_atoms"], "1000000");
    assert_eq!(ordinary["input_atoms"], "100000000000");
    assert!(light.prepare(&recipient, 1000000, false, &[]).is_err());
    light.clear_prepared();
    let priority: serde_json::Value =
        serde_json::from_str(&light.prepare(&recipient, 1000000, true, &[]).unwrap()).unwrap();
    assert_eq!(
        priority["fee_atoms"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap(),
        ordinary["fee_atoms"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            * 4
    );
    light.clear_prepared();
    let reserved = light.wallet.receipts()[0].commitment;
    assert!(
        light
            .prepare(&recipient, 1000000, false, &[reserved])
            .is_err()
    );
}

#[test]
fn compact_issuance_preserves_authenticated_public_fields_and_omits_proof() {
    use native::codec::decode_digest;
    use native::issuance::{
        AssetMetadata, ISSUER_KEY_BYTES, ISSUER_SIGNATURE_BYTES, IssuanceDeclaration,
        SignedIssuance, derive_asset_id,
    };
    use siworld_native_wallet_engine::issuance::IssuanceRecord;
    for name in [String::new(), "Synthetic asset".into(), "x".repeat(255)] {
        let (config, mut block) = common::fixture();
        let key = [7; ISSUER_KEY_BYTES];
        let declaration = IssuanceDeclaration {
            network: config.network,
            version: 1,
            issuer_key: key,
            sequence: 1,
            asset_id: derive_asset_id(&config.network, &key, 1),
            public_supply: 100,
            metadata: AssetMetadata { name, decimals: 2 },
            issuance_fee_atoms: 5000000000,
            note_commitments: (0..3)
                .map(|i| decode_digest(&common::digest(8000 + i)).unwrap())
                .collect(),
            note_ciphertext_digests: vec![[9; 32]; 3],
        };
        block.issuances.push(IssuanceRecord {
            signed: SignedIssuance {
                declaration: declaration.clone(),
                signature: Some([0; ISSUER_SIGNATURE_BYTES]),
            },
            ciphertexts: vec![vec![3; 1313]; 3],
            proof: vec![4; 524288],
            fee_commitment: common::digest(9000),
            fee_rho: common::digest(9001),
        });
        let encoded = CompactBlock::export(&block).unwrap();
        let decoded = CompactBlock::decode(&encoded).unwrap();
        assert_eq!(decoded.block.issuances[0].signed.declaration, declaration);
        assert_eq!(
            decoded.block.issuances[0].ciphertexts,
            block.issuances[0].ciphertexts
        );
        assert!(decoded.block.issuances[0].proof.is_empty());
    }
}
