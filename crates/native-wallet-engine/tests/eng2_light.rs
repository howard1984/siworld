//! Synthetic framing/work fixtures; no transaction or settlement proof is made.
mod common;
use native::codec::encode_digest;
use siworld_core::pow;
pub use siworld_native_wallet_engine::wire;
use siworld_native_wallet_engine::{
    eng2_history::{BODY_DOMAIN, Context, Header, MAX_BODY_BYTES},
    eng2_light::{Eng2LightState, native_profile},
    state::Config,
    wire::*,
};
use zeroize::Zeroizing;
#[allow(dead_code)]
#[path = "../src/ranges.rs"]
mod fixture_ranges;
use fixture_ranges::RangeProof;
fn genesis(config: &Config) -> (Vec<u8>, Hash) {
    let profile = native_profile();
    let governance = b"SWG2GOV2";
    let mut rules = blake3::Hasher::new_derive_key("siworld eng2 internal immutable rules v1");
    rules.update(&[0]);
    rules.update(&config.encode_rules());
    rules.update(&profile);
    rules.update(&(governance.len() as u64).to_le_bytes());
    rules.update(governance);
    rules.update(b"native-header:2;execution-components:2;fund:direct24-month8766x48;governance:4032-roster24;issuance-fee:public-governed-destination-v1");
    let id = blake3::derive_key(
        "siworld eng2 internal genesis v1",
        rules.finalize().as_bytes(),
    );
    let mut bytes = b"SWE2GEN1".to_vec();
    bytes.push(0);
    bytes.extend(profile);
    bytes.extend(config.encode_rules());
    bytes.extend_from_slice(&(governance.len() as u32).to_le_bytes());
    bytes.extend_from_slice(governance);
    (bytes, id)
}
fn fixture() -> (Config, Vec<u8>, Hash, Block) {
    let (_, block) = common::fixture();
    let config = Config::development(block.network, 4).unwrap();
    let (genesis, id) = genesis(&config);
    (config, genesis, id, block)
}
fn qualified_block(
    config: &Config,
    context: &Context,
    mut block: Block,
    height: u64,
    parent: Hash,
    parent_timestamp: u64,
) -> (Header, Vec<u8>) {
    block.height = height;
    block.parent = parent;
    block.timestamp = config.genesis_timestamp + height * config.target_interval;
    for tx in &mut block.transactions {
        tx.record.snapshot = Snapshot {
            height: height - 1,
            block_id: parent,
        };
    }
    block
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&config.network));
    let mut raw = vec![0; 8];
    let mut ranges = vec![(0, 8)];
    let mut prefix = b"SW2B\x01\x00".to_vec();
    prefix.extend(config.network);
    prefix.extend(height.to_le_bytes());
    prefix.extend(context.profile());
    prefix.extend((block.transactions.len() as u16).to_le_bytes());
    prefix.extend([1, 5, 0, 0, 0]);
    fn disclosed(raw: &mut Vec<u8>, ranges: &mut Vec<(usize, usize)>, bytes: &[u8]) {
        ranges.push((raw.len(), bytes.len()));
        raw.extend_from_slice(bytes);
    }
    disclosed(&mut raw, &mut ranges, &prefix);
    for reward in &block.rewards {
        let mut bytes = reward.commitment.to_vec();
        bytes.extend(reward.ciphertext);
        disclosed(&mut raw, &mut ranges, &bytes);
    }
    disclosed(&mut raw, &mut ranges, &[0; REWARD_RECORD_BYTES]);
    for tx in &block.transactions {
        let envelope = tx.encode_envelope(&config.network).unwrap();
        disclosed(
            &mut raw,
            &mut ranges,
            &(envelope.len() as u32).to_le_bytes(),
        );
        disclosed(&mut raw, &mut ranges, &envelope[..TX_PREFIX_BYTES]);
        raw.extend_from_slice(&envelope[TX_PREFIX_BYTES..]);
    }
    disclosed(
        &mut raw,
        &mut ranges,
        &(block.settlement_proof.len() as u32).to_le_bytes(),
    );
    raw.extend(&block.settlement_proof);
    let length = raw.len() - 8;
    raw[..8].copy_from_slice(&(length as u64).to_le_bytes());
    let mut header = Header {
        network: config.network,
        height,
        parent,
        timestamp: block.timestamp,
        target: pow::asert_target(
            &config.genesis_target,
            config.genesis_timestamp,
            config.target_interval,
            height - 1,
            parent_timestamp,
        ),
        execution_commitment: [9; 32],
        body_commitment: blake3::derive_key(BODY_DOMAIN, &raw),
        nonce: 0,
    };
    header.nonce = (0..4096)
        .find(|nonce| {
            pow::meets_target(
                &pow::pow_hash(&header.pow_seed().unwrap(), *nonce, config.pow_iterations),
                &header.target,
            )
        })
        .expect("bounded minimum-difficulty synthetic work");
    let mut bytes = b"SWE2WLT1".to_vec();
    for value in [
        config.network,
        context.genesis(),
        context.rules(),
        context.profile(),
    ] {
        bytes.extend(value);
    }
    bytes.push(0);
    bytes.extend(header.encode().unwrap());
    bytes.extend(RangeProof::create_bound(&raw, &ranges, BODY_DOMAIN, MAX_BODY_BYTES + 8).unwrap());
    (header, bytes)
}
#[test]
fn receives_scans_all_history_and_reopens_only_same_context_private_cache() {
    let (config, genesis, id, block) = fixture();
    let context = Context::from_genesis(&genesis, id).unwrap();
    let (header, receipt) = qualified_block(
        &config,
        &context,
        block.clone(),
        1,
        id,
        config.genesis_timestamp,
    );
    let mut wallet = Eng2LightState::new(&genesis, id, Zeroizing::new([42; 32]), 0).unwrap();
    wallet.append(&header.encode().unwrap(), &receipt).unwrap();
    wallet.check_head(1, header.id().unwrap(), None).unwrap();
    let balance: serde_json::Value = serde_json::from_str(&wallet.balance_json().unwrap()).unwrap();
    assert_eq!(balance["rows"][0]["available_atoms"], "100000000000");
    assert_eq!(balance["send_supported"], false);
    assert_eq!(balance["full_node_consensus_verified"], false);
    assert_eq!(wallet.wallet().receipts().len(), 1);
    let cached = wallet.local_cache().unwrap();
    let reopened =
        Eng2LightState::open_local(&genesis, id, Zeroizing::new([42; 32]), 0, &cached).unwrap();
    assert_eq!(
        wallet.balance_json().unwrap(),
        reopened.balance_json().unwrap()
    );
    assert_eq!(wallet.history_json(), reopened.history_json());
    assert_eq!(wallet.root(), reopened.root());
    assert_eq!(
        cached.as_slice(),
        reopened.local_cache().unwrap().as_slice()
    );
    assert!(
        Eng2LightState::open_local(&genesis, id, Zeroizing::new([42; 32]), 1, &cached).is_err()
    );
    let mut next = block;
    next.rewards[0].commitment = common::digest(800001);
    next.rewards[0].ciphertext = [0; REWARD_CIPHERTEXT_BYTES];
    let (second, receipt) = qualified_block(
        &config,
        &context,
        next,
        2,
        header.id().unwrap(),
        header.timestamp,
    );
    let mut extended = reopened.fork(Zeroizing::new([42; 32]), 0).unwrap();
    extended
        .append(&second.encode().unwrap(), &receipt)
        .unwrap();
    extended
        .check_head(2, second.id().unwrap(), Some(&reopened))
        .unwrap();
    assert!(extended.cumulative_work() > reopened.cumulative_work());
    assert_eq!(reopened.height(), 1);
    assert_eq!(extended.height(), 2);
    let mut missing = Eng2LightState::new(&genesis, id, Zeroizing::new([42; 32]), 0).unwrap();
    assert!(missing.append(&second.encode().unwrap(), &receipt).is_err());
    assert_eq!(missing.height(), 0);
}
#[test]
fn malformed_headers_receipts_and_stale_candidate_do_not_change_accepted_state() {
    let (config, genesis, id, block) = fixture();
    let context = Context::from_genesis(&genesis, id).unwrap();
    let (header, receipt) =
        qualified_block(&config, &context, block, 1, id, config.genesis_timestamp);
    let mut wallet = Eng2LightState::new(&genesis, id, Zeroizing::new([42; 32]), 0).unwrap();
    let original = wallet.local_cache().unwrap();
    for mutation in 0..6 {
        let mut bad = header.clone();
        match mutation {
            0 => bad.network[0] ^= 1,
            1 => bad.parent[0] ^= 1,
            2 => bad.height = 2,
            3 => bad.timestamp = config.genesis_timestamp,
            4 => bad.target[0] ^= 1,
            _ => bad.body_commitment[0] ^= 1,
        }
        assert!(wallet.append(&bad.encode().unwrap(), &receipt).is_err());
        assert_eq!(
            wallet.local_cache().unwrap().as_slice(),
            original.as_slice()
        );
    }
    let mut bad = header.clone();
    bad.nonce = (0..4096)
        .find(|nonce| {
            !pow::meets_target(
                &pow::pow_hash(&bad.pow_seed().unwrap(), *nonce, config.pow_iterations),
                &bad.target,
            )
        })
        .expect("bounded rejected synthetic work");
    assert!(
        wallet
            .append(&bad.encode().unwrap(), &receipt)
            .unwrap_err()
            .contains("work")
    );
    for offset in [8, 40, 104, receipt.len() - 1] {
        let mut bad = receipt.clone();
        bad[offset] ^= 1;
        assert!(wallet.append(&header.encode().unwrap(), &bad).is_err());
    }
    wallet.append(&header.encode().unwrap(), &receipt).unwrap();
    assert!(wallet.check_head(1, [0; 32], None).is_err());
    let same = wallet.fork(Zeroizing::new([42; 32]), 0).unwrap();
    same.check_head(1, header.id().unwrap(), Some(&wallet))
        .unwrap();
    let fresh = Eng2LightState::new(&genesis, id, Zeroizing::new([42; 32]), 0).unwrap();
    assert!(fresh.check_head(0, id, Some(&wallet)).is_err());
    let (_, _, _, mut alternate_body) = fixture();
    alternate_body.rewards[4].commitment = common::digest(900003);
    let (alternate_header, alternate_receipt) = qualified_block(
        &config,
        &context,
        alternate_body,
        1,
        id,
        config.genesis_timestamp,
    );
    let mut alternate = Eng2LightState::new(&genesis, id, Zeroizing::new([42; 32]), 0).unwrap();
    alternate
        .append(&alternate_header.encode().unwrap(), &alternate_receipt)
        .unwrap();
    assert_eq!(alternate.cumulative_work(), wallet.cumulative_work());
    assert_ne!(alternate.tip(), wallet.tip());
    assert!(
        alternate
            .check_head(1, alternate.tip(), Some(&wallet))
            .is_err()
    );
    let cache = wallet.local_cache().unwrap();
    for offset in [0, 8, 40, 72, 104, 136, 137, cache.len() - 1] {
        let mut bad = cache.to_vec();
        bad[offset] ^= 1;
        if offset < cache.len() - 32 {
            let end = bad.len() - 32;
            let sum = *blake3::hash(&bad[..end]).as_bytes();
            bad[end..].copy_from_slice(&sum);
        }
        assert!(
            Eng2LightState::open_local(&genesis, id, Zeroizing::new([42; 32]), 0, &bad).is_err()
        );
    }
    assert_eq!(wallet.local_cache().unwrap().as_slice(), cache.as_slice());
}
#[test]
fn legacy_genesis_compact_and_other_profile_are_rejected() {
    let (config, genesis, id, block) = fixture();
    assert!(
        Eng2LightState::new(
            &config.encode_rules(),
            config.genesis_id(),
            Zeroizing::new([42; 32]),
            0
        )
        .is_err()
    );
    let mut foreign = genesis.clone();
    foreign[9] ^= 1;
    assert!(Eng2LightState::new(&foreign, id, Zeroizing::new([42; 32]), 0).is_err());
    let mut fee = genesis.clone();
    fee[8] = 1;
    assert!(Eng2LightState::new(&fee, id, Zeroizing::new([42; 32]), 0).is_err());
    let context = Context::from_genesis(&genesis, id).unwrap();
    let (header, _) = qualified_block(
        &config,
        &context,
        block.clone(),
        1,
        id,
        config.genesis_timestamp,
    );
    let compact = siworld_native_wallet_engine::compact::CompactBlock::export(&block).unwrap();
    let mut wallet = Eng2LightState::new(&genesis, id, Zeroizing::new([42; 32]), 0).unwrap();
    assert!(wallet.append(&header.encode().unwrap(), &compact).is_err());
    assert_eq!(wallet.height(), 0);
    assert_eq!(
        wallet.root(),
        encode_digest(&siworld_native_wallet_engine::state::CommitmentTree::new().root())
    );
}
