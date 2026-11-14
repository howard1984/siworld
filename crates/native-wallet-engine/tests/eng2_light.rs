//! Synthetic framing/work fixtures; no transaction or settlement proof is made.
mod common;
use native::codec::encode_digest;
use siworld_core::pow;
use siworld_native_wallet_engine::local::hex;
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
    // Sixty-four three-output transaction slots and five reward records.
    assert_eq!(wallet.output_count(), 197);
    assert_eq!(wallet.asset_count(), 0);
    assert_eq!(wallet.tip_snapshot().selector.height, 1);
    assert_eq!(wallet.tip_snapshot().selector.block_id, wallet.tip());
    assert_eq!(wallet.tip_snapshot().commitment_root, wallet.root());
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
fn existing_custody_wallet_scans_authenticated_receipt_and_refuses_reused_or_wrong_network_views() {
    use siworld_native_wallet_engine::wallet::Wallet;
    let (config, genesis, id, block) = fixture();
    let context = Context::from_genesis(&genesis, id).unwrap();
    let (header, receipt) =
        qualified_block(&config, &context, block, 1, id, config.genesis_timestamp);
    let existing = Wallet::from_seed(config.network, Zeroizing::new([42; 32]), 0).unwrap();
    let address = existing.address();
    let mut light = Eng2LightState::from_existing_wallet(&genesis, id, existing).unwrap();
    assert_eq!(light.wallet().address(), address);
    light.append(&header.encode().unwrap(), &receipt).unwrap();
    light.check_head(1, header.id().unwrap(), None).unwrap();
    assert!(light.check_head(2, header.id().unwrap(), None).is_err());
    let balance: serde_json::Value = serde_json::from_str(&light.balance_json().unwrap()).unwrap();
    assert_eq!(balance["rows"][0]["available_atoms"], "100000000000");
    assert_eq!(light.wallet().receipts().len(), 1);
    assert_eq!(light.asset_registry().len(), 0);
    // A populated independent view cannot be silently relabeled as a fresh scan.
    let mut reused = Wallet::from_seed(config.network, Zeroizing::new([42; 32]), 0).unwrap();
    let state = siworld_native_wallet_engine::state::State::new(config.clone()).unwrap();
    reused.scan_light_data(&state, &[], &[], false).unwrap();
    assert!(Eng2LightState::from_existing_wallet(&genesis, id, reused).is_err());
    let wrong = Wallet::from_seed([99; 32], Zeroizing::new([42; 32]), 0).unwrap();
    assert!(Eng2LightState::from_existing_wallet(&genesis, id, wrong).is_err());
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

#[test]
fn payments_bind_the_verified_eng2_anchor_network_and_input_reservations() {
    let (config, genesis, id, block) = fixture();
    let context = Context::from_genesis(&genesis, id).unwrap();
    let (header, receipt) =
        qualified_block(&config, &context, block, 1, id, config.genesis_timestamp);
    let mut wallet = Eng2LightState::new(&genesis, id, Zeroizing::new([42; 32]), 0).unwrap();
    wallet.append(&header.encode().unwrap(), &receipt).unwrap();
    let recipient = wallet.wallet().address();
    let anchor = wallet.tip_snapshot().selector;
    let before = wallet.local_cache().unwrap();
    assert!(
        wallet
            .prepare_sip([8; 32], anchor, &recipient, 1_000_000, false, &[])
            .is_err()
    );
    assert!(
        wallet
            .prepare_sip(
                config.network,
                Snapshot {
                    height: 1,
                    block_id: id
                },
                &recipient,
                1_000_000,
                false,
                &[]
            )
            .is_err()
    );
    let reserved = [wallet.wallet().receipts()[0].commitment];
    assert!(
        wallet
            .prepare_sip(
                config.network,
                anchor,
                &recipient,
                1_000_000,
                false,
                &reserved
            )
            .is_err()
    );
    assert_eq!(wallet.local_cache().unwrap().as_slice(), before.as_slice());
    let prepared: serde_json::Value = serde_json::from_str(
        &wallet
            .prepare_sip(config.network, anchor, &recipient, 1_000_000, false, &[])
            .unwrap(),
    )
    .unwrap();
    assert_eq!(prepared["network"], hex(&config.network));
    assert_eq!(prepared["genesis"], hex(&id));
    assert_eq!(prepared["anchor_height"], 1);
    assert_eq!(prepared["anchor_tip"], hex(&header.id().unwrap()));
    assert_eq!(prepared["commitment_root"], hex(&wallet.root()));
    assert_eq!(
        prepared["fee_atoms"],
        siworld_native_wallet_engine::state::base_fee(1).to_string()
    );
    assert_eq!(prepared["inputs"][0], hex(&reserved[0]));
    assert_eq!(
        prepared["expires_at_height"],
        1 + siworld_native_wallet_engine::state::SNAPSHOT_WINDOW
    );
    assert!(
        wallet
            .prepare_sip(config.network, anchor, &recipient, 1_000_000, false, &[])
            .is_err()
    );
    wallet.clear_eng2_prepared();
    assert!(wallet.prove_sip().is_err());
    assert_eq!(wallet.local_cache().unwrap().as_slice(), before.as_slice());
}

#[test]
fn offline_payment_proves_and_verifies_the_frozen_native_eng2_binding() {
    let (config, genesis, id, block) = fixture();
    let context = Context::from_genesis(&genesis, id).unwrap();
    let (header, receipt) =
        qualified_block(&config, &context, block, 1, id, config.genesis_timestamp);
    let mut wallet = Eng2LightState::new(&genesis, id, Zeroizing::new([42; 32]), 0).unwrap();
    wallet.append(&header.encode().unwrap(), &receipt).unwrap();
    let recipient = wallet.wallet().address();
    let before = wallet.local_cache().unwrap();
    let prepared: serde_json::Value = serde_json::from_str(
        &wallet
            .prepare_sip(
                config.network,
                wallet.tip_snapshot().selector,
                &recipient,
                1_000_000,
                false,
                &[],
            )
            .unwrap(),
    )
    .unwrap();
    let packet = wallet.prove_sip().unwrap();
    let checked: serde_json::Value = serde_json::from_str(
        &wallet
            .check_payment_packet(config.network, &packet)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(checked["statement_id"], prepared["statement_id"]);
    assert_eq!(checked["anchor_height"], 1);
    assert_eq!(checked["anchor_tip"], hex(&header.id().unwrap()));
    assert_eq!(checked["proof_verified"], true);
    assert_eq!(checked["send_supported"], false);
    assert!(wallet.check_payment_packet([8; 32], &packet).is_err());
    let mut corrupt = packet.clone();
    corrupt[TX_PREFIX_BYTES + 20] ^= 1;
    assert!(
        wallet
            .check_payment_packet(config.network, &corrupt)
            .is_err()
    );
    let mut wrong_anchor = packet.clone();
    wrong_anchor[4 + 2 + 27 + 32 + 8] ^= 1;
    assert!(
        wallet
            .check_payment_packet(config.network, &wrong_anchor)
            .is_err()
    );
    assert_eq!(wallet.local_cache().unwrap().as_slice(), before.as_slice());
}

#[test]
fn payment_anchor_lifetime_rejects_the_exact_expiry_and_future_boundaries() {
    use siworld_native_wallet_engine::{eng2_light::PaymentAnchor, state::SNAPSHOT_WINDOW};
    let anchor = PaymentAnchor {
        network: [3; 32],
        snapshot: Snapshot {
            height: 9,
            block_id: [4; 32],
        },
    };
    assert!(anchor.check_lifetime([3; 32], 9).is_ok());
    assert!(
        anchor
            .check_lifetime([3; 32], 9 + SNAPSHOT_WINDOW as u64 - 1)
            .is_ok()
    );
    assert!(
        anchor
            .check_lifetime([3; 32], 9 + SNAPSHOT_WINDOW as u64)
            .is_err()
    );
    assert!(anchor.check_lifetime([3; 32], 8).is_err());
    assert!(anchor.check_lifetime([8; 32], 9).is_err());
    assert!(anchor.check_lifetime([3; 32], u64::MAX).is_err());
}

#[test]
fn payment_inclusion_requires_a_committed_header_and_body_authenticated_statement() {
    let (config, genesis, id, block) = fixture();
    let statement = block.transactions[0].record.clone();
    let context = Context::from_genesis(&genesis, id).unwrap();
    let (header, receipt) =
        qualified_block(&config, &context, block, 1, id, config.genesis_timestamp);
    let mut wallet = Eng2LightState::new(&genesis, id, Zeroizing::new([42; 32]), 0).unwrap();
    assert!(wallet.payment_receipt(1, &receipt, [0; 32]).is_err());
    wallet.append(&header.encode().unwrap(), &receipt).unwrap();
    let mut statement = statement;
    statement.snapshot = Snapshot {
        height: 0,
        block_id: id,
    };
    let transaction = statement.statement_id(&config.network);
    let included: serde_json::Value =
        serde_json::from_str(&wallet.payment_receipt(1, &receipt, transaction).unwrap()).unwrap();
    assert_eq!(included["statement_id"], hex(&transaction));
    assert_eq!(included["block_id"], hex(&wallet.tip()));
    assert_eq!(included["receipt_authenticated"], true);
    assert_eq!(included["full_node_consensus_verified"], false);
    assert!(wallet.payment_inclusion_valid(1, wallet.tip()));
    assert!(!wallet.payment_inclusion_valid(1, id));
    assert!(!wallet.payment_inclusion_valid(2, wallet.tip()));
    assert!(wallet.payment_receipt(1, &receipt, [8; 32]).is_err());
    let mut corrupt = receipt;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(wallet.payment_receipt(1, &corrupt, transaction).is_err());
}

#[test]
fn isolated_cached_prefix_replays_a_branch_without_mutating_the_accepted_wallet() {
    let (config, genesis, id, block) = fixture();
    let context = Context::from_genesis(&genesis, id).unwrap();
    let mut empty = block.clone();
    empty.rewards[0].commitment = common::digest(810001);
    empty.rewards[0].ciphertext = [0; REWARD_CIPHERTEXT_BYTES];
    let (first, first_receipt) = qualified_block(
        &config,
        &context,
        empty.clone(),
        1,
        id,
        config.genesis_timestamp,
    );
    let mut accepted = Eng2LightState::new(&genesis, id, Zeroizing::new([42; 32]), 0).unwrap();
    accepted
        .append(&first.encode().unwrap(), &first_receipt)
        .unwrap();
    let checkpoint = accepted.tip_snapshot().selector;
    let cached = accepted.local_cache().unwrap();
    let (original, original_receipt) = qualified_block(
        &config,
        &context,
        block,
        2,
        first.id().unwrap(),
        first.timestamp,
    );
    accepted
        .append(&original.encode().unwrap(), &original_receipt)
        .unwrap();
    let before = accepted.local_cache().unwrap();
    let balance: serde_json::Value =
        serde_json::from_str(&accepted.balance_json().unwrap()).unwrap();
    assert_eq!(balance["rows"][0]["available_atoms"], "100000000000");
    for wrong in [
        Snapshot {
            height: 0,
            block_id: id,
        },
        Snapshot {
            height: 1,
            block_id: [8; 32],
        },
        Snapshot {
            height: 3,
            block_id: original.id().unwrap(),
        },
    ] {
        assert!(
            accepted
                .fork_local_cache(&genesis, id, Zeroizing::new([42; 32]), 0, &cached, wrong)
                .is_err()
        );
    }
    assert!(
        accepted
            .fork_local_cache(
                &genesis,
                id,
                Zeroizing::new([42; 32]),
                1,
                &cached,
                checkpoint
            )
            .is_err()
    );
    assert!(
        accepted
            .fork_local_cache(
                &genesis,
                id,
                Zeroizing::new([43; 32]),
                0,
                &cached,
                checkpoint
            )
            .is_err()
    );
    let mut foreign_config = config.clone();
    foreign_config.target_interval += 1;
    let (foreign_genesis, foreign_id) = self::genesis(&foreign_config);
    assert!(
        accepted
            .fork_local_cache(
                &foreign_genesis,
                foreign_id,
                Zeroizing::new([42; 32]),
                0,
                &cached,
                checkpoint
            )
            .is_err()
    );
    let mut corrupted = cached.to_vec();
    corrupted[0] ^= 1;
    assert!(
        accepted
            .fork_local_cache(
                &genesis,
                id,
                Zeroizing::new([42; 32]),
                0,
                &corrupted,
                checkpoint
            )
            .is_err()
    );
    let mut candidate = accepted
        .fork_local_cache(
            &genesis,
            id,
            Zeroizing::new([42; 32]),
            0,
            &cached,
            checkpoint,
        )
        .unwrap();
    assert_eq!(candidate.height(), 1);
    assert_eq!(candidate.wallet().receipts().len(), 0);
    assert!(
        candidate
            .check_head(1, candidate.tip(), Some(&accepted))
            .is_err()
    );
    empty.rewards[4].commitment = common::digest(820004);
    let (alternate, alternate_receipt) = qualified_block(
        &config,
        &context,
        empty.clone(),
        2,
        first.id().unwrap(),
        first.timestamp,
    );
    let mut bad = alternate_receipt.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(
        candidate
            .append(&alternate.encode().unwrap(), &bad)
            .is_err()
    );
    assert_eq!(
        candidate.local_cache().unwrap().as_slice(),
        cached.as_slice()
    );
    candidate
        .append(&alternate.encode().unwrap(), &alternate_receipt)
        .unwrap();
    assert_eq!(candidate.cumulative_work(), accepted.cumulative_work());
    assert!(
        candidate
            .check_head(2, candidate.tip(), Some(&accepted))
            .is_err()
    );
    let (third, third_receipt) = qualified_block(
        &config,
        &context,
        empty,
        3,
        alternate.id().unwrap(),
        alternate.timestamp,
    );
    candidate
        .append(&third.encode().unwrap(), &third_receipt)
        .unwrap();
    candidate
        .check_head(3, third.id().unwrap(), Some(&accepted))
        .unwrap();
    assert!(candidate.cumulative_work() > accepted.cumulative_work());
    assert_ne!(candidate.root(), accepted.root());
    assert!(candidate.wallet().receipts().is_empty());
    // Dropping/reopening this synthetic candidate models private cache lifetime;
    // it does not model a real browser's five-minute automatic lock timer.
    let saved_candidate = candidate.local_cache().unwrap();
    drop(candidate);
    let reopened =
        Eng2LightState::open_local(&genesis, id, Zeroizing::new([42; 32]), 0, &saved_candidate)
            .unwrap();
    reopened
        .check_head(3, third.id().unwrap(), Some(&accepted))
        .unwrap();
    assert!(reopened.wallet().receipts().is_empty());
    assert_eq!(
        accepted.local_cache().unwrap().as_slice(),
        before.as_slice()
    );
    assert_eq!(accepted.wallet().receipts().len(), 1);
}

#[test]
fn cached_candidate_bounds_include_24_blocks_plus_seven_prefix_replay_blocks() {
    let (config, genesis, id, mut block) = fixture();
    block.rewards[0].commitment = common::digest(830001);
    block.rewards[0].ciphertext = [0; REWARD_CIPHERTEXT_BYTES];
    let context = Context::from_genesis(&genesis, id).unwrap();
    let mut accepted = Eng2LightState::new(&genesis, id, Zeroizing::new([42; 32]), 0).unwrap();
    let genesis_cache = accepted.local_cache().unwrap();
    let mut first_cache = None;
    let mut first_tip = id;
    let mut parent = id;
    let mut timestamp = config.genesis_timestamp;
    for height in 1..=32 {
        let (header, receipt) =
            qualified_block(&config, &context, block.clone(), height, parent, timestamp);
        accepted
            .append(&header.encode().unwrap(), &receipt)
            .unwrap();
        parent = header.id().unwrap();
        timestamp = header.timestamp;
        if height == 1 {
            first_cache = Some(accepted.local_cache().unwrap());
            first_tip = parent;
        }
        if height == 31 {
            assert!(
                accepted
                    .fork_local_cache(
                        &genesis,
                        id,
                        Zeroizing::new([42; 32]),
                        0,
                        &genesis_cache,
                        Snapshot {
                            height: 0,
                            block_id: id
                        }
                    )
                    .is_ok()
            );
        }
    }
    let before = accepted.local_cache().unwrap();
    assert!(
        accepted
            .fork_local_cache(
                &genesis,
                id,
                Zeroizing::new([42; 32]),
                0,
                &genesis_cache,
                Snapshot {
                    height: 0,
                    block_id: id
                }
            )
            .is_err()
    );
    let prefix = accepted
        .fork_local_cache(
            &genesis,
            id,
            Zeroizing::new([42; 32]),
            0,
            first_cache.as_ref().unwrap(),
            Snapshot {
                height: 1,
                block_id: first_tip,
            },
        )
        .unwrap();
    assert_eq!(prefix.height(), 1);
    assert_eq!(
        accepted.local_cache().unwrap().as_slice(),
        before.as_slice()
    );
}
