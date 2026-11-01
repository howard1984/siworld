use super::*;
use crate::wire::{PUBLIC_BYTES, PublicRecord, REWARD_CIPHERTEXT_BYTES, RewardRecord, Transaction};
use native::codec::encode_digest;
use p3_field::PrimeCharacteristicRing;

struct TestVerifier;
impl BlockVerifier for TestVerifier {
    fn transaction(
        &self,
        _: &PublicTransaction,
        _: &ProofContext,
        _: &Digest,
        _: &Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        if proof == [1] {
            Ok(())
        } else {
            Err("test transaction rejection".into())
        }
    }
    fn settlement(
        &self,
        _: &[Digest],
        _: &native::settlement::RewardPlan,
        _: Hash,
        _: Hash,
        _: &[Digest],
        proof: &[u8],
    ) -> Result<(), String> {
        if proof == [1] {
            Ok(())
        } else {
            Err("test settlement rejection".into())
        }
    }
}
fn felt(value: u32) -> DigestBytes {
    let mut d = [F::ZERO; 12];
    d[0] = F::from_u32(value);
    encode_digest(&d)
}
fn candidate(state: &State, seed: u32) -> Block {
    let snapshot = state.tip_snapshot().selector;
    let mut transactions = Vec::new();
    for i in 0..64u32 {
        let mut body = [0u8; PUBLIC_BYTES];
        for j in 0..5u32 {
            body[j as usize * 48..(j as usize + 1) * 48].copy_from_slice(&felt(seed + i * 5 + j));
        }
        transactions.push(Transaction {
            record: PublicRecord::new(snapshot, body, felt(seed + 10000 + i)).unwrap(),
            proof: vec![1],
        });
    }
    transactions.sort_by_key(|tx| tx.record.statement_id(&state.config.network));
    let mut block = Block {
        network: state.config.network,
        height: state.height + 1,
        parent: state.tip,
        timestamp: state.timestamp() + state.config.target_interval,
        target: state.next_target(),
        nonce: 0,
        transactions,
        reward_mode: crate::state::RewardMode::Voyager,
        rewards: vec![RewardRecord {
            commitment: felt(seed + 20000),
            ciphertext: [0; REWARD_CIPHERTEXT_BYTES],
        }],
        fund_spends: Vec::new(),
        issuances: Vec::new(),
        settlement_proof: vec![1],
    };
    let seed = block.pow_seed().unwrap();
    while !siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(&seed, block.nonce, state.config.pow_iterations),
        &block.target,
    ) {
        block.nonce += 1;
    }
    block
}
#[test]
fn producer_and_validator_apply_the_same_transition() {
    let initial = State::new(Config::development([1; 32], 0).unwrap()).unwrap();
    let block = candidate(&initial, 1);
    let mut producer = initial.clone();
    let mut validator = initial;
    producer.apply(&block, &TestVerifier).unwrap();
    validator.apply(&block, &TestVerifier).unwrap();
    assert_eq!(producer.fingerprint(), validator.fingerprint());
    assert_eq!(producer.height, 1);
    assert_eq!(producer.spent.len(), 128);
    assert_eq!(producer.tree.count, 193);
    assert_eq!(
        producer.economics.totals().issued,
        u128::from(siworld_core::v1_economics::INITIAL_REWARD)
    );
}
#[test]
fn every_public_mutation_failure_is_atomic() {
    let initial = State::new(Config::development([2; 32], 0).unwrap()).unwrap();
    let base = candidate(&initial, 2);
    for kind in 0..8 {
        let mut block = base.clone();
        match kind {
            0 => block.parent[0] ^= 1,
            1 => block.network[0] ^= 1,
            2 => block.height += 1,
            3 => block.transactions.swap(0, 1),
            4 => block.transactions[63].proof = vec![0],
            5 => block.settlement_proof = vec![0],
            6 => block.transactions[0].record.snapshot.block_id[0] ^= 1,
            _ => {
                block.transactions[1].record.body[..48]
                    .copy_from_slice(&base.transactions[0].record.body[..48]);
                block
                    .transactions
                    .sort_by_key(|tx| tx.record.statement_id(&block.network));
            }
        }
        let mut state = initial.clone();
        let before = state.fingerprint();
        assert!(state.apply(&block, &TestVerifier).is_err(), "case {kind}");
        assert_eq!(state.fingerprint(), before);
    }
}
#[test]
fn rejects_second_input_reuse_across_blocks() {
    let mut state = State::new(Config::development([3; 32], 0).unwrap()).unwrap();
    let first = candidate(&state, 3);
    state.apply(&first, &TestVerifier).unwrap();
    let mut next = candidate(&state, 100000);
    next.transactions[63].record.body[48..96]
        .copy_from_slice(&first.transactions[0].record.body[48..96]);
    next.transactions
        .sort_by_key(|tx| tx.record.statement_id(&next.network));
    let before = state.fingerprint();
    assert!(state.apply(&next, &TestVerifier).is_err());
    assert_eq!(state.fingerprint(), before);
}
#[test]
fn rejects_reused_output_and_reward_commitments() {
    let mut state = State::new(Config::development([4; 32], 0).unwrap()).unwrap();
    let first = candidate(&state, 4);
    state.apply(&first, &TestVerifier).unwrap();
    for reward in [false, true] {
        let mut next = candidate(&state, 200000);
        if reward {
            next.rewards[0].commitment = first.rewards[0].commitment;
        } else {
            next.transactions[63].record.body[96..144]
                .copy_from_slice(&first.transactions[0].record.body[96..144]);
            next.transactions
                .sort_by_key(|tx| tx.record.statement_id(&next.network));
        }
        let before = state.fingerprint();
        assert!(state.apply(&next, &TestVerifier).is_err());
        assert_eq!(state.fingerprint(), before);
    }
}
#[test]
fn snapshot_window_accepts_4096th_rejects_4097th_and_removed_identity() {
    let mut state = State::new(Config::development([5; 32], 0).unwrap()).unwrap();
    let root = state.tip_snapshot().recent_root;
    state.snapshots.clear();
    state.height = 4096;
    for height in 1..=4096 {
        state.snapshots.push_back(CanonicalSnapshot {
            selector: Snapshot {
                height,
                block_id: blake3::hash(&height.to_le_bytes()).into(),
            },
            commitment_root: root,
            recent_root: root,
        });
    }
    let oldest = state.snapshots[0].selector;
    assert!(state.snapshot(oldest).is_ok());
    assert!(
        state
            .snapshot(Snapshot {
                height: 0,
                block_id: [0; 32]
            })
            .is_err()
    );
    let mut orphan = oldest;
    orphan.block_id[0] ^= 1;
    assert!(state.snapshot(orphan).is_err());
    state.snapshots.pop_front();
    assert!(state.snapshot(oldest).is_err());
}
#[test]
fn settlement_tail_is_multi_asset_context_bound_and_canonical() {
    let a = tail_slots([1; 32], 1, 64).unwrap();
    let b = tail_slots([1; 32], 1, 80).unwrap();
    assert_eq!(a.len(), 512);
    assert_ne!(a[0].commitment, b[0].commitment);
    let c = tail_slots([1; 32], 2, 64).unwrap();
    assert_ne!(a[0].commitment, c[0].commitment);
    let mut seen = BTreeSet::new();
    for row in a {
        assert_eq!(row.opening.fee, 0);
        assert!(seen.insert(encode_digest(&row.commitment)));
        assert_eq!(
            Hasher::new().fee_commit(0, &row.opening.blind),
            row.commitment
        );
    }
    assert!(tail_slots([1; 32], 1, 63).is_err());
    assert!(tail_slots([1; 32], 1, 577).is_err());
}
#[test]
fn incremental_tree_matches_native_merkle_paths() {
    let hasher = Hasher::new();
    let mut tree = CommitmentTree::new();
    let mut leaves = Vec::new();
    for i in 1..=9u32 {
        let leaf = decode_digest(&felt(i)).unwrap();
        leaves.push(leaf);
        tree.append(leaf).unwrap();
        for (index, value) in leaves.iter().enumerate() {
            assert_eq!(
                hasher.merkle_root(value, &tree.path(&leaves, index).unwrap()),
                tree.root()
            );
        }
    }
}

#[test]
fn asert_configuration_is_genesis_bound_and_fixture_mode_is_explicit() {
    let config = Config::asert_development([6; 32], 1_700_000_000, [0x7f; 32], 100).unwrap();
    assert_eq!(config.target_interval, 300);
    assert!(!config.fixture);
    let id = config.genesis_id();
    for change in 0..5 {
        let mut changed = config.clone();
        match change {
            0 => changed.genesis_timestamp += 1,
            1 => changed.genesis_target[31] ^= 1,
            2 => changed.pow_iterations += 1,
            3 => changed.target_interval += 1,
            _ => changed.fixture = true,
        }
        assert_ne!(changed.genesis_id(), id);
    }
    assert!(Config::asert_development([6; 32], 0, [0x7f; 32], 100).is_err());
    assert!(Config::asert_development([6; 32], 1, [0; 32], 100).is_err());
    assert!(Config::asert_development([6; 32], 1, [0x7f; 32], 0).is_err());
    assert!(Config::asert_development([6; 32], 1, [0x7f; 32], 1_000_001).is_err());
    assert!(Config::development([6; 32], 0).unwrap().fixture);
}
#[test]
fn timestamp_window_and_cumulative_work_survive_shared_transitions() {
    let mut state = State::new(Config::development([8; 32], 0).unwrap()).unwrap();
    let initial = state.config.genesis_timestamp;
    let mut expected_work = siworld_core::pow::Work::zero();
    for height in 1..=12u32 {
        let block = candidate(&state, 400000 + height * 100000);
        expected_work += siworld_core::pow::block_work(&block.target);
        state.apply(&block, &TestVerifier).unwrap();
    }
    assert_eq!(state.timestamps.len(), 11);
    assert_eq!(state.timestamp(), initial + 12 * 300);
    assert_eq!(state.median_time_past(), initial + 7 * 300);
    assert_eq!(state.cumulative_work, expected_work);
    let before = state.fingerprint();
    state.timestamps[0] += 1;
    assert_ne!(state.fingerprint(), before);
    state.timestamps[0] -= 1;
    state.cumulative_work += siworld_core::pow::Work::one();
    assert_ne!(state.fingerprint(), before);
}
#[test]
fn asert_header_failures_precede_proof_checks_and_are_atomic() {
    struct NoProofCalls;
    impl BlockVerifier for NoProofCalls {
        fn transaction(
            &self,
            _: &PublicTransaction,
            _: &ProofContext,
            _: &Digest,
            _: &Digest,
            _: &[u8],
        ) -> Result<(), String> {
            panic!("header failure reached transaction verifier")
        }
        fn settlement(
            &self,
            _: &[Digest],
            _: &native::settlement::RewardPlan,
            _: Hash,
            _: Hash,
            _: &[Digest],
            _: &[u8],
        ) -> Result<(), String> {
            panic!("header failure reached settlement verifier")
        }
    }
    let state = State::new(Config::development([7; 32], 1).unwrap()).unwrap();
    let valid = candidate(&state, 300000);
    for kind in 0..3 {
        let mut invalid = valid.clone();
        match kind {
            0 => invalid.timestamp = state.median_time_past(),
            1 => invalid.target[31] ^= 1,
            _ => {
                let seed = invalid.pow_seed().unwrap();
                while siworld_core::pow::meets_target(
                    &siworld_core::pow::pow_hash(&seed, invalid.nonce, state.config.pow_iterations),
                    &invalid.target,
                ) {
                    invalid.nonce += 1;
                }
            }
        }
        let mut next = state.clone();
        let before = next.fingerprint();
        assert!(next.apply(&invalid, &NoProofCalls).is_err());
        assert_eq!(next.fingerprint(), before);
    }
}

#[test]
fn early_parent_changes_the_next_asert_target_and_old_target_is_rejected() {
    let mut state = State::new(Config::development([10; 32], 0).unwrap()).unwrap();
    let mut early = candidate(&state, 2000000);
    early.timestamp = state.timestamp() + 1;
    let seed = early.pow_seed().unwrap();
    while !siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(&seed, early.nonce, state.config.pow_iterations),
        &early.target,
    ) {
        early.nonce += 1;
    }
    state.apply(&early, &TestVerifier).unwrap();
    assert!(state.next_target() < state.config.genesis_target);
    let mut stale = candidate(&state, 2100000);
    stale.target = state.config.genesis_target;
    let before = state.fingerprint();
    assert!(
        state
            .apply(&stale, &TestVerifier)
            .unwrap_err()
            .contains("ASERT")
    );
    assert_eq!(state.fingerprint(), before);
}

#[test]
fn future_time_is_local_admission_only_not_a_replay_clock_rule() {
    let mut state = State::new(Config::development([11; 32], 0).unwrap()).unwrap();
    let mut block = candidate(&state, 2200000);
    block.timestamp = u64::MAX;
    assert!(siworld_core::pow::beyond_future_limit(
        block.timestamp,
        1_700_000_000
    ));
    let seed = block.pow_seed().unwrap();
    while !siworld_core::pow::meets_target(
        &siworld_core::pow::pow_hash(&seed, block.nonce, state.config.pow_iterations),
        &block.target,
    ) {
        block.nonce += 1;
    }
    state.apply(&block, &TestVerifier).unwrap();
    assert_eq!(state.timestamp(), u64::MAX);
}

#[test]
fn configuration_codec_rejects_noncanonical_modes_and_rule_changes() {
    let config = Config::asert_development([12; 32], 1_700_000_000, [0xff; 32], 64).unwrap();
    let encoded = config.encode_rules();
    assert_eq!(Config::decode_rules(&encoded).unwrap(), config);
    for index in [32, 33, 74] {
        let mut invalid = encoded;
        invalid[index] = 2;
        assert!(Config::decode_rules(&invalid).is_err());
    }
    assert!(Config::decode_rules(&encoded[..89]).is_err());
}

#[test]
fn economic_timings_are_genesis_bound_and_engineering_only() {
    let production = Config::development([21; 32], 0).unwrap();
    let compressed = production
        .clone()
        .with_economics(
            siworld_core::v1_economics::EconomicsParams::engineering([60, 120, 180, 240], 3)
                .unwrap(),
        )
        .unwrap();
    assert_ne!(production.genesis_id(), compressed.genesis_id());
    assert_eq!(
        Config::decode_rules(&compressed.encode_rules()).unwrap(),
        compressed
    );
    assert_eq!(compressed.encode_rules().len(), CONFIG_RULE_BYTES);
    let service = Config::asert_development([21; 32], 1, [0xff; 32], 1).unwrap();
    assert!(service.with_economics(compressed.economics).is_err());
}

fn holder_candidate(state: &State, seed: u32) -> Block {
    let mut block = candidate(state, seed);
    block.reward_mode = RewardMode::Holder;
    block.rewards = (0..5)
        .map(|index| RewardRecord {
            commitment: felt(seed + 20_000 + index),
            ciphertext: [index as u8; REWARD_CIPHERTEXT_BYTES],
        })
        .collect();
    block
}

#[test]
fn mode_reward_count_pool_burn_and_trusted_plan_are_bound() {
    let initial = State::new(Config::development([22; 32], 0).unwrap()).unwrap();
    let voyager = candidate(&initial, 1_000);
    let holder = holder_candidate(&initial, 2_000);
    let mut v = initial.clone();
    v.apply(&voyager, &TestVerifier).unwrap();
    let mut h = initial.clone();
    h.apply(&holder, &TestVerifier).unwrap();
    assert_eq!(v.economics.totals().holder_pool, 692_483_000);
    assert_eq!(v.economics.totals().burned, 147_661_816);
    assert_eq!(h.economics.totals().holder_pool, 101_835_735);
    assert_eq!(h.economics.totals().burned, 0);
    assert_eq!(h.tree.count, v.tree.count + 4);
    assert_eq!(
        initial
            .reward_plan(RewardMode::Holder)
            .unwrap()
            .allocations
            .len(),
        5
    );
    for mut malformed in [voyager.clone(), holder.clone()] {
        malformed.reward_mode = if malformed.reward_mode == RewardMode::Voyager {
            RewardMode::Holder
        } else {
            RewardMode::Voyager
        };
        let mut state = initial.clone();
        let before = state.fingerprint();
        assert!(state.apply(&malformed, &TestVerifier).is_err());
        assert_eq!(state.fingerprint(), before);
    }
    let mut duplicate = holder;
    duplicate.rewards[4] = duplicate.rewards[0].clone();
    let mut state = initial;
    let before = state.fingerprint();
    assert!(state.apply(&duplicate, &TestVerifier).is_err());
    assert_eq!(state.fingerprint(), before);
}

#[test]
fn failed_settlement_never_advances_any_economic_state() {
    let mut state = State::new(Config::development([23; 32], 0).unwrap()).unwrap();
    let mut holder = holder_candidate(&state, 30_000);
    holder.settlement_proof = vec![0];
    let before = state.fingerprint();
    let economics = state.economics.clone();
    assert!(state.apply(&holder, &TestVerifier).is_err());
    assert_eq!(state.fingerprint(), before);
    assert_eq!(state.economics, economics);
}

#[test]
fn fund_policy_is_explicit_genesis_bound_and_unconfigured_service_fails_closed() {
    use siworld_core::v1_economics::FundAllocation;
    let service = Config::asert_development([24; 32], 1, [0xff; 32], 1).unwrap();
    assert_eq!(service.fund_allocation, None);
    let mut state = State::new(service.clone()).unwrap();
    let before = state.fingerprint();
    assert!(state.reward_plan(RewardMode::Holder).is_err());
    assert!(
        state
            .apply(&candidate(&state, 4_000), &TestVerifier)
            .is_err()
    );
    assert_eq!(state.fingerprint(), before);
    let configured = service
        .clone()
        .with_fund_wallets(
            FundAllocation::new_bps(vec![3000, 7000], 1).unwrap(),
            Config::development([121; 32], 0)
                .unwrap()
                .fund_verifying_keys,
        )
        .unwrap();
    assert_ne!(service.genesis_id(), configured.genesis_id());
    assert_eq!(
        Config::decode_rules(&configured.encode_rules()).unwrap(),
        configured
    );
    assert_eq!(configured.fund_verifying_keys.len(), 2);
    assert!(
        State::new(configured)
            .unwrap()
            .reward_plan(RewardMode::Holder)
            .is_ok()
    );
    assert!(
        service
            .with_fund_wallets(
                FundAllocation::new_bps(vec![2000, 3000, 5000], 2).unwrap(),
                Vec::new()
            )
            .is_err()
    );
}

#[test]
fn immutable_fund_genesis_binds_thirty_two_full_keys_shares_and_team_index() {
    use siworld_core::v1_economics::FundAllocation;
    let base = Config::asert_development([124; 32], 1, [0xff; 32], 1).unwrap();
    let keys: Vec<_> = (0..32u8)
        .map(|index| {
            *libcrux_ml_dsa::ml_dsa_65::generate_key_pair([120 + index; 32])
                .verification_key
                .as_ref()
        })
        .collect();
    let mut shares = vec![300; 32];
    shares[31] = 700;
    let configured = base
        .clone()
        .with_fund_wallets(
            FundAllocation::new_bps(shares.clone(), 31).unwrap(),
            keys.clone(),
        )
        .unwrap();
    assert_eq!(
        Config::decode_rules(&configured.encode_rules()).unwrap(),
        configured
    );
    assert_eq!(configured.fund_verifying_keys.len(), 32);
    assert_eq!(configured.fund_verifying_keys[31], keys[31]);
    let changed_team = base
        .clone()
        .with_fund_wallets(
            FundAllocation::new_bps(shares.clone(), 0).unwrap(),
            keys.clone(),
        )
        .unwrap();
    assert_ne!(configured.genesis_id(), changed_team.genesis_id());
    let mut alternate_keys = keys.clone();
    alternate_keys.swap(0, 1);
    let changed_key = base
        .clone()
        .with_fund_wallets(
            FundAllocation::new_bps(shares.clone(), 31).unwrap(),
            alternate_keys,
        )
        .unwrap();
    assert_ne!(configured.genesis_id(), changed_key.genesis_id());
    let mut duplicate = keys.clone();
    duplicate[31] = duplicate[0];
    assert!(
        base.clone()
            .with_fund_wallets(
                FundAllocation::new_bps(shares.clone(), 31).unwrap(),
                duplicate,
            )
            .is_err()
    );
    let mut zero = keys.clone();
    zero[0] = [0; crate::fund_spend::VERIFYING_KEY_BYTES];
    assert!(
        base.clone()
            .with_fund_wallets(FundAllocation::new_bps(shares.clone(), 31).unwrap(), zero,)
            .is_err()
    );
    assert!(
        base.with_fund_wallets(
            FundAllocation::new_bps(shares, 31).unwrap(),
            keys[..31].to_vec(),
        )
        .is_err()
    );
    let mut noncanonical = configured.encode_rules();
    noncanonical[146] = 33;
    assert!(Config::decode_rules(&noncanonical).is_err());
    assert!(Config::decode_rules(&[0; 279]).is_err());
}

#[test]
fn eight_distinct_fund_wallets_claim_together_and_ninth_claim_is_rejected_atomically() {
    use siworld_core::v1_economics::{FundAccount, FundAllocation};
    let network = [125; 32];
    let keys = (0..32u8)
        .map(|account| signed_fund_spend(network, account, 1, 0, 20_000_000).verifying_key)
        .collect();
    let mut shares = vec![300; 32];
    shares[31] = 700;
    let config = Config::development(network, 0)
        .unwrap()
        .with_fund_wallets(FundAllocation::new_bps(shares, 31).unwrap(), keys)
        .unwrap();
    let mut state = State::new(config).unwrap();
    for height in 1..=24u32 {
        let block = candidate(&state, height * 100_000);
        state.apply(&block, &TestVerifier).unwrap();
    }
    let mut claim = candidate(&state, 3_000_000);
    claim.fund_spends = [0, 1, 2, 3, 4, 5, 6, 31]
        .into_iter()
        .map(|account| {
            signed_fund_spend(network, account, 1, 0, 21_000_000 + u32::from(account) * 10)
        })
        .collect();
    let mut ninth = claim.clone();
    ninth
        .fund_spends
        .insert(7, signed_fund_spend(network, 7, 1, 0, 22_000_000));
    let before = state.fingerprint();
    assert!(state.apply(&ninth, &TestVerifier).is_err());
    assert_eq!(state.fingerprint(), before);
    state.apply(&claim, &TestVerifier).unwrap();
    for index in [0, 1, 2, 3, 4, 5, 6, 31] {
        assert_eq!(
            state
                .economics
                .fund(FundAccount::new(index).unwrap())
                .unwrap()
                .spent,
            1
        );
    }
    assert_eq!(
        state
            .economics
            .fund(FundAccount::new(7).unwrap())
            .unwrap()
            .spent,
        0
    );
}

fn signed_fund_spend(
    network: Hash,
    account: u8,
    amount: u64,
    counter: u64,
    seed: u32,
) -> crate::fund_spend::FundSpend {
    use libcrux_ml_dsa::ml_dsa_65;
    use native::codec::decode_digest;
    use native::multi_asset::{Note, SIP_ASSET_ID};
    let pair = ml_dsa_65::generate_key_pair([83 + account; 32]);
    let mut spend = crate::fund_spend::FundSpend {
        account,
        counter,
        amount,
        owner: felt(seed),
        rho: encode_digest(&crate::fund_spend::canonical_rho(network, account, counter)),
        rseed: felt(seed + 2),
        commitment: [0; 48],
        ciphertext: [account + 3; 1313],
        verifying_key: *pair.verification_key.as_ref(),
        signature: [0; crate::fund_spend::SIGNATURE_BYTES],
    };
    let note = Note {
        asset_id: SIP_ASSET_ID,
        owner: decode_digest(&spend.owner).unwrap(),
        value: amount,
        unlock_height: 0,
        rho: decode_digest(&spend.rho).unwrap(),
        rseed: decode_digest(&spend.rseed).unwrap(),
    };
    spend.commitment = encode_digest(&Hasher::new().note_cm(&note));
    spend.signature = *ml_dsa_65::sign(
        &pair.signing_key,
        &spend.message(network),
        b"siworld v0",
        [84 + account; 32],
    )
    .unwrap()
    .as_ref();
    spend
}

#[test]
fn signed_fund_payouts_mature_independently_are_atomic_and_replay_without_orphans() {
    use siworld_core::v1_economics::FundAllocation;
    let network = [25; 32];
    let mut config = Config::development(network, 0)
        .unwrap()
        .with_fund_wallets(
            FundAllocation::new_bps(vec![3000, 7000], 1).unwrap(),
            Config::development([121; 32], 0)
                .unwrap()
                .fund_verifying_keys,
        )
        .unwrap();
    for account in 0..2 {
        let spend = signed_fund_spend(network, account as u8, 1, 0, 8_000_000);
        config.fund_verifying_keys[account] = spend.verifying_key;
    }
    let mut state = State::new(config).unwrap();
    for height in 1..=23 {
        let block = candidate(&state, height * 100_000);
        state.apply(&block, &TestVerifier).unwrap();
    }
    let mut early = candidate(&state, 2_400_000);
    early
        .fund_spends
        .push(signed_fund_spend(network, 0, 1, 0, 8_100_000));
    let before = state.fingerprint();
    assert!(state.apply(&early, &TestVerifier).is_err());
    assert_eq!(state.fingerprint(), before);
    early.fund_spends.clear();
    state.apply(&early, &TestVerifier).unwrap();
    let parent = state.clone();
    let first_available = (siworld_core::v1_economics::INITIAL_REWARD * 3 / 100) / 2;
    let mut payout = candidate(&state, 2_500_000);
    payout
        .fund_spends
        .push(signed_fund_spend(network, 0, first_available, 0, 8_200_000));
    let mut wrong_rho = payout.clone();
    wrong_rho.fund_spends[0].rho = felt(8_300_000);
    let before = state.fingerprint();
    assert!(
        state
            .apply(&wrong_rho, &TestVerifier)
            .unwrap_err()
            .contains("nonce")
    );
    assert_eq!(state.fingerprint(), before);
    for case in 0..4 {
        let mut invalid = payout.clone();
        invalid.fund_spends[0] = match case {
            0 => {
                let mut invalid = invalid.fund_spends[0].clone();
                invalid.signature[0] ^= 1;
                invalid
            }
            1 => signed_fund_spend(network, 0, first_available, 1, 8_200_000),
            2 => signed_fund_spend(network, 0, first_available + 1, 0, 8_200_000),
            _ => signed_fund_spend(
                network,
                1,
                (siworld_core::v1_economics::INITIAL_REWARD * 7 / 100) / 2 + 1,
                0,
                8_200_000,
            ),
        };
        let before = state.fingerprint();
        assert!(state.apply(&invalid, &TestVerifier).is_err(), "case {case}");
        assert_eq!(state.fingerprint(), before);
    }
    state.apply(&payout, &TestVerifier).unwrap();
    assert_eq!(
        state.economics.fund(FundAccount::FIRST).unwrap().spent,
        u128::from(first_available)
    );
    assert_eq!(state.economics.fund(FundAccount::SECOND).unwrap().spent, 0);
    assert!(
        state
            .commitments
            .contains(&payout.fund_spends[0].commitment)
    );
    let mut replacement = parent.clone();
    let without_payout = candidate(&replacement, 2_600_000);
    replacement.apply(&without_payout, &TestVerifier).unwrap();
    assert_eq!(
        replacement
            .economics
            .fund(FundAccount::FIRST)
            .unwrap()
            .spent,
        0
    );
    assert_eq!(
        replacement
            .economics
            .fund(FundAccount::FIRST)
            .unwrap()
            .spend_count,
        0
    );
    assert!(
        !replacement
            .commitments
            .contains(&payout.fund_spends[0].commitment)
    );
    assert_eq!(
        replacement.economics.totals().issued,
        state.economics.totals().issued
    );
    let mut replay = parent;
    replay.apply(&without_payout, &TestVerifier).unwrap();
    assert_eq!(replay.fingerprint(), replacement.fingerprint());
}
