//! Synthetic public records for local browser transport/scan measurements only.
use native::{
    codec::encode_digest,
    encryption::{EncryptionContext, encrypt_payment},
    multi_asset::{F, Hasher, Note, SIP_ASSET_ID},
};
use p3_field::PrimeCharacteristicRing;
use siworld_native_wallet_engine::{
    commitment::CommitmentBlock,
    compact::CompactBlock,
    state::{Config, State},
    wallet::Wallet,
    wire::*,
};
use std::path::Path;
use zeroize::Zeroizing;
fn digest(v: u32) -> [u8; 48] {
    let mut a = [F::ZERO; 12];
    a[0] = F::from_u32(v);
    encode_digest(&a)
}
fn main() {
    let output = std::env::args().nth(1).expect("Output directory");
    let out = Path::new(&output);
    std::fs::create_dir_all(out).unwrap();
    let config = Config::development([3; 32], 0).unwrap();
    let state = State::new(config.clone()).unwrap();
    let wallet = Wallet::from_seed(config.network, Zeroizing::new([42; 32]), 0).unwrap();
    let note = Note {
        owner: wallet.address().owner(),
        value: 100_000_000_000,
        unlock_height: 0,
        rho: [F::from_u32(900001); 12],
        rseed: [F::from_u32(900002); 12],
        asset_id: SIP_ASSET_ID,
    };
    let cm = Hasher::new().note_cm(&note);
    let payment = encrypt_payment(
        &wallet.address(),
        &note,
        &EncryptionContext::new(config.network),
    )
    .unwrap();
    let mut ciphertext = [0; REWARD_CIPHERTEXT_BYTES];
    ciphertext[..1088].copy_from_slice(&payment.kem_ciphertext);
    ciphertext[1088..1296].copy_from_slice(&payment.body);
    ciphertext[1296..1312].copy_from_slice(&payment.tag);
    ciphertext[1312] = payment.view_tag;
    let mut rows = Vec::new();
    for slots in [64, 576] {
        let mut txs = Vec::new();
        for i in 0..slots {
            let mut body = [0; PUBLIC_BYTES];
            for j in 0..5 {
                body[j * 48..(j + 1) * 48].copy_from_slice(&digest(10 + i as u32 * 5 + j as u32));
            }
            txs.push(Transaction {
                record: PublicRecord::new(
                    state.tip_snapshot().selector,
                    body,
                    digest(100000 + i as u32),
                )
                .unwrap(),
                proof: vec![7; 588832],
            });
        }
        txs.sort_by_key(|t| t.record.statement_id(&config.network));
        let rewards = (0..5)
            .map(|i| {
                if i == 0 {
                    RewardRecord {
                        commitment: encode_digest(&cm),
                        ciphertext,
                    }
                } else {
                    RewardRecord {
                        commitment: digest(200000 + i),
                        ciphertext: [0; REWARD_CIPHERTEXT_BYTES],
                    }
                }
            })
            .collect();
        let block = Block {
            network: config.network,
            height: 1,
            parent: state.tip,
            timestamp: 301,
            target: config.genesis_target,
            nonce: 0,
            transactions: txs,
            reward_mode: RewardMode::Holder,
            rewards,
            fund_spends: vec![],
            issuances: vec![],
            settlement_proof: vec![9; 520203],
        };
        let compact = CompactBlock::export(&block).unwrap();
        let decoded = CompactBlock::decode(&compact).unwrap();
        assert_eq!(decoded.id, block.id().unwrap());
        assert!(
            decoded
                .block
                .transactions
                .iter()
                .all(|t| t.proof.is_empty())
        );
        std::fs::write(out.join(format!("block-{slots}.bin")), &compact).unwrap();
        std::fs::write(
            out.join(format!("commitments-{slots}.bin")),
            CommitmentBlock::project(&compact).unwrap(),
        )
        .unwrap();
        // Header-valid synthetic extension for birthday scanning; proofs are fixtures.
        let mut next = block.clone();
        next.height = 2;
        next.parent = decoded.id;
        next.timestamp = 601;
        let next_note = Note {
            rho: [F::from_u32(900003); 12],
            rseed: [F::from_u32(900004); 12],
            ..note.clone()
        };
        let payment = encrypt_payment(
            &wallet.address(),
            &next_note,
            &EncryptionContext::new(config.network),
        )
        .unwrap();
        let mut next_ciphertext = [0; REWARD_CIPHERTEXT_BYTES];
        next_ciphertext[..1088].copy_from_slice(&payment.kem_ciphertext);
        next_ciphertext[1088..1296].copy_from_slice(&payment.body);
        next_ciphertext[1296..1312].copy_from_slice(&payment.tag);
        next_ciphertext[1312] = payment.view_tag;
        next.rewards[0] = RewardRecord {
            commitment: encode_digest(&Hasher::new().note_cm(&next_note)),
            ciphertext: next_ciphertext,
        };
        for (i, reward) in next.rewards.iter_mut().enumerate().skip(1) {
            reward.commitment = digest(300000 + i as u32);
        }
        let next_compact = CompactBlock::export(&next).unwrap();
        let next_id = CompactBlock::decode(&next_compact).unwrap().id;
        std::fs::write(out.join(format!("next-{slots}.bin")), next_compact).unwrap();
        rows.push(serde_json::json!({"slots":slots,"compact_bytes":compact.len(),"full_block_bytes":block.encoded_len().unwrap(),"block_id":siworld_native_wallet_engine::local::hex(&decoded.id),"next_block_id":siworld_native_wallet_engine::local::hex(&next_id)}));
    }
    let metadata = serde_json::json!({"scope":"synthetic-codec-and-local-browser-fixture-not-live-chain-or-consensus-qualification","words":bip39::Mnemonic::from_entropy(&[42;32]).unwrap().to_string(),"network":siworld_native_wallet_engine::local::hex(&config.network),"rules_hex":siworld_native_wallet_engine::local::hex(&config.encode_rules()),"genesis":siworld_native_wallet_engine::local::hex(&config.genesis_id()),"rows":rows});
    std::fs::write(
        out.join("fixture.json"),
        serde_json::to_vec_pretty(&metadata).unwrap(),
    )
    .unwrap();
    println!("Synthetic compact fixtures written.");
}
