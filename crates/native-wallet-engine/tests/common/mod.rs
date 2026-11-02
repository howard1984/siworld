use native::{
    codec::encode_digest,
    encryption::{EncryptionContext, encrypt_payment},
    multi_asset::{F, Hasher, Note, SIP_ASSET_ID},
};
use p3_field::PrimeCharacteristicRing;
use siworld_native_wallet_engine::{
    state::{Config, State},
    wallet::Wallet,
    wire::*,
};
use zeroize::Zeroizing;
pub fn digest(v: u32) -> [u8; 48] {
    let mut a = [F::ZERO; 12];
    a[0] = F::from_u32(v);
    encode_digest(&a)
}
pub fn fixture() -> (Config, Block) {
    fixture_slots(64)
}
pub fn fixture_slots(slots: usize) -> (Config, Block) {
    let c = Config::development([3; 32], 0).unwrap();
    let s = State::new(c.clone()).unwrap();
    let w = Wallet::from_seed(c.network, Zeroizing::new([42; 32]), 0).unwrap();
    let note = Note {
        owner: w.address().owner(),
        value: 100000000000,
        unlock_height: 0,
        rho: [F::from_u32(900001); 12],
        rseed: [F::from_u32(900002); 12],
        asset_id: SIP_ASSET_ID,
    };
    let p = encrypt_payment(&w.address(), &note, &EncryptionContext::new(c.network)).unwrap();
    let mut ciphertext = [0; REWARD_CIPHERTEXT_BYTES];
    ciphertext[..1088].copy_from_slice(&p.kem_ciphertext);
    ciphertext[1088..1296].copy_from_slice(&p.body);
    ciphertext[1296..1312].copy_from_slice(&p.tag);
    ciphertext[1312] = p.view_tag;
    let mut transactions = Vec::new();
    for i in 0..slots {
        let mut body = [0; PUBLIC_BYTES];
        for j in 0..5 {
            body[j * 48..(j + 1) * 48].copy_from_slice(&digest((10 + i * 5 + j) as u32));
        }
        transactions.push(Transaction {
            record: PublicRecord::new(s.tip_snapshot().selector, body, digest((100000 + i) as u32))
                .unwrap(),
            proof: vec![7; 4097],
        });
    }
    transactions.sort_by_key(|t| t.record.statement_id(&c.network));
    let rewards = (0..5)
        .map(|i| {
            if i == 0 {
                RewardRecord {
                    commitment: encode_digest(&Hasher::new().note_cm(&note)),
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
    (
        c.clone(),
        Block {
            network: c.network,
            height: 1,
            parent: s.tip,
            timestamp: 301,
            target: c.genesis_target,
            nonce: 0,
            transactions,
            reward_mode: RewardMode::Holder,
            rewards,
            fund_spends: vec![],
            issuances: vec![],
            settlement_proof: vec![9; 4097],
        },
    )
}
