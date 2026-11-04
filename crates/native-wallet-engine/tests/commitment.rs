mod common;
use native::codec::{PublicTransaction, encode_digest};
use siworld_native_wallet_engine::{commitment::CommitmentBlock, compact::CompactBlock};
#[test]
fn historical_projection_binds_all_outputs_in_native_order_without_ciphertext_fields() {
    for slots in [64, 576] {
        let (_, block) = common::fixture_slots(slots);
        let compact = CompactBlock::export(&block).unwrap();
        let projected = CommitmentBlock::project(&compact).unwrap();
        let decoded = CommitmentBlock::decode(&projected).unwrap();
        assert_eq!(CommitmentBlock::project(&projected).unwrap(), projected);
        let expected = block
            .transactions
            .iter()
            .flat_map(|t| {
                PublicTransaction::decode(&t.record.body)
                    .unwrap()
                    .cm
                    .map(|cm| encode_digest(&cm))
            })
            .chain(block.rewards.iter().map(|r| r.commitment))
            .collect::<Vec<_>>();
        assert_eq!(decoded.outputs, expected);
        assert_eq!(decoded.id, block.id().unwrap());
        assert_eq!(decoded.network, block.network);
        assert_eq!(decoded.timestamp, block.timestamp);
        assert!(projected.len() < compact.len());
        assert!(decoded.authentication_ciphertext_bytes > 0);
        assert!(decoded.authentication_ciphertext_bytes < slots * (2027 - 240) + 5 * 1313);
        for offset in [0, 16, 64, 512, projected.len() - 1] {
            let mut corrupt = projected.clone();
            corrupt[offset] ^= 1;
            assert!(CommitmentBlock::decode(&corrupt).is_err());
        }
        assert!(CommitmentBlock::decode(&compact).is_err());
        assert!(CompactBlock::decode(&projected).is_err());
    }
}
#[test]
fn extra_disclosure_and_missing_commitments_are_rejected() {
    use siworld_native_wallet_engine::ranges::{DOMAIN, RangeProof};
    let (_, block) = common::fixture();
    let mut raw = block.encode().unwrap();
    raw.drain(145..153);
    for ranges in [vec![(0, 150)], vec![(0, raw.len())]] {
        let seed = *blake3::Hasher::new_derive_key(DOMAIN)
            .update(&raw)
            .finalize()
            .as_bytes();
        let mut bytes = b"SWLT0001".to_vec();
        bytes.extend(block.nonce.to_le_bytes());
        bytes.extend(seed);
        bytes.extend(RangeProof::create(&raw, &ranges).unwrap());
        assert!(CommitmentBlock::decode(&bytes).is_err());
    }
}

#[test]
fn historical_tree_rejects_invalid_header_context_without_advancing_cache() {
    use siworld_native_wallet_engine::history::CommitmentHistory;
    let (config, block) = common::fixture();
    let bytes = CommitmentBlock::project(&CompactBlock::export(&block).unwrap()).unwrap();
    for variant in 0..4 {
        let mut bad = CommitmentBlock::decode(&bytes).unwrap();
        match variant {
            0 => bad.target = [1; 32],
            1 => bad.parent = [2; 32],
            2 => bad.timestamp = 0,
            _ => bad.network = [9; 32],
        }
        let mut history = CommitmentHistory::new(config.clone()).unwrap();
        let accepted = history.cache().unwrap();
        assert!(history.append(&bad).is_err());
        assert_eq!(history.cache().unwrap(), accepted);
    }
}

#[test]
fn historical_projection_places_issuance_and_fund_outputs_in_native_tree_order() {
    use native::codec::decode_digest;
    use native::issuance::{
        AssetMetadata, ISSUER_KEY_BYTES, ISSUER_SIGNATURE_BYTES, IssuanceDeclaration,
        SignedIssuance, derive_asset_id,
    };
    use siworld_native_wallet_engine::{fund_spend::FundSpend, issuance::IssuanceRecord};
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
                declaration,
                signature: Some([0; ISSUER_SIGNATURE_BYTES]),
            },
            ciphertexts: vec![vec![3; 1313]; 3],
            proof: vec![4; 524288],
            fee_commitment: common::digest(9000),
            fee_rho: common::digest(9001),
        });
        block.fund_spends.push(FundSpend {
            account: 0,
            counter: 1,
            amount: 10,
            owner: common::digest(6000),
            rho: common::digest(6001),
            rseed: common::digest(6002),
            commitment: common::digest(6003),
            ciphertext: [5; 1313],
            verifying_key: [0; 1952],
            signature: [0; 3309],
        });
        // Synthetic codec records only; no signature or consensus-validity claim.
        let compact = CompactBlock::export(&block).unwrap();
        let tree = CommitmentBlock::decode(&CommitmentBlock::project(&compact).unwrap()).unwrap();
        let expected = block
            .transactions
            .iter()
            .flat_map(|t| {
                PublicTransaction::decode(&t.record.body)
                    .unwrap()
                    .cm
                    .map(|v| encode_digest(&v))
            })
            .chain(block.issuances.iter().flat_map(|v| {
                v.signed
                    .declaration
                    .note_commitments
                    .iter()
                    .map(encode_digest)
            }))
            .chain(block.rewards.iter().map(|v| v.commitment))
            .chain(block.fund_spends.iter().map(|v| v.commitment))
            .collect::<Vec<_>>();
        assert_eq!(tree.outputs, expected);
    }
}

#[test]
fn local_tree_cache_reuses_frontier_and_skips_all_historical_decryption() {
    use siworld_native_wallet_engine::{history::CommitmentHistory, light::LightWallet};
    use zeroize::Zeroizing;
    let (config, first) = common::fixture();
    let projected = CommitmentBlock::project(&CompactBlock::export(&first).unwrap()).unwrap();
    let mut history = CommitmentHistory::new(config.clone()).unwrap();
    history
        .append(&CommitmentBlock::decode(&projected).unwrap())
        .unwrap();
    let saved = history.cache().unwrap();
    let mut restored = CommitmentHistory::open_local(config.clone(), &saved).unwrap();
    assert_eq!(restored.cache().unwrap(), saved);
    let mut born = LightWallet::new(config.clone(), Zeroizing::new([42; 32]), 0).unwrap();
    born.adopt_history(&restored).unwrap();
    assert!(
        born.wallet.receipts().is_empty(),
        "older owned reward must not be trial-decrypted"
    );
    assert!(born.adopt_history(&restored).is_err());
    let mut second = first.clone();
    second.height = 2;
    second.parent = restored.state.tip;
    second.timestamp = 601;
    second.rewards[0].commitment = common::digest(800001);
    second.rewards[0].ciphertext = [0; 1313];
    let compact = CompactBlock::decode(&CompactBlock::export(&second).unwrap()).unwrap();
    born.append(&compact).unwrap();
    restored
        .append(
            &CommitmentBlock::decode(
                &CommitmentBlock::project(&CompactBlock::export(&second).unwrap()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(born.state.tree.root(), restored.state.tree.root());
    assert_eq!(born.state.tree.count, restored.state.tree.count);
    assert_eq!(born.state.tip, restored.state.tip);
    let prior = restored.cache().unwrap();
    assert!(
        restored
            .append(&CommitmentBlock::decode(&projected).unwrap())
            .is_err()
    );
    assert_eq!(
        restored.cache().unwrap(),
        prior,
        "failed header append is atomic"
    );
    let mut wrong: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    wrong["root"] = serde_json::json!("00".repeat(48));
    assert!(
        CommitmentHistory::open_local(config.clone(), &serde_json::to_vec(&wrong).unwrap())
            .is_err()
    );
    let mut other = config;
    other.network = [9; 32];
    assert!(CommitmentHistory::open_local(other, &saved).is_err());
}
