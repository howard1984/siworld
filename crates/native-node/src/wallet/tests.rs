use super::*;
use crate::audit::tests::{TestVerifier, candidate, felt};
use crate::wire::REWARD_CIPHERTEXT_BYTES;
use native::encryption::{encrypt_change_at, encrypt_payment_with_opening};

fn wallet(network: Hash, seed: u8) -> Wallet {
    Wallet::from_seed(network, Zeroizing::new([seed; 32]), 0).unwrap()
}
fn note(owner: Digest, value: u64, asset_id: AssetId, tag: u32) -> Note {
    Note {
        asset_id,
        owner,
        value,
        unlock_height: 0,
        rho: [F::from_u32(tag); 12],
        rseed: [F::from_u32(tag + 1); 12],
    }
}
fn encrypted_record(
    state: &State,
    target: &Wallet,
    asset: AssetId,
    amount: u64,
    tag: u32,
) -> (PublicRecord, [Note; 3], PaymentEncryptionOpening) {
    let h = Hasher::new();
    let notes = [
        note(target.keys.address().owner(), amount, asset, tag),
        note(
            target.keys.address().owner(),
            20_000,
            SIP_ASSET_ID,
            tag + 10,
        ),
        note(target.keys.address().owner(), 0, SIP_ASSET_ID, tag + 20),
    ];
    let ec = EncryptionContext::new(state.config.network);
    let (payment, opening) =
        encrypt_payment_with_opening(&target.keys.address(), &notes[0], &ec).unwrap();
    let public = PublicTransaction {
        nf: [
            decode_digest(&felt(tag + 100)).unwrap(),
            decode_digest(&felt(tag + 101)).unwrap(),
        ],
        cm: notes.each_ref().map(|n| h.note_cm(n)),
        payment,
        change: [
            encrypt_change_at(&target.keys.change, &notes[1], &ec, 1).unwrap(),
            encrypt_change_at(&target.keys.change, &notes[2], &ec, 2).unwrap(),
        ],
    };
    let fee = h.fee_commit(0, &[F::from_u32(tag + 200); 8]);
    (
        PublicRecord::new(
            state.tip_snapshot().selector,
            public.encode(),
            encode_digest(&fee),
        )
        .unwrap(),
        notes,
        opening,
    )
}
fn insert_record(block: &mut Block, record: PublicRecord) {
    block.transactions[0].record = record;
    block
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&block.network));
}

#[test]
fn supplied_seed_recovery_is_network_and_account_separated() {
    let first = WalletKeys::from_seed([1; 32], Zeroizing::new([2; 32]), 0).unwrap();
    let restored = WalletKeys::from_seed([1; 32], Zeroizing::new([2; 32]), 0).unwrap();
    assert_eq!(first.address(), restored.address());
    assert_eq!(*first.nullifier_key, *restored.nullifier_key);
    let other_network = WalletKeys::from_seed([3; 32], Zeroizing::new([2; 32]), 0).unwrap();
    let other_account = WalletKeys::from_seed([1; 32], Zeroizing::new([2; 32]), 1).unwrap();
    assert_ne!(first.address(), other_network.address());
    assert_ne!(first.address(), other_account.address());
    assert_ne!(*first.nullifier_key, *other_network.nullifier_key);
    assert_ne!(*first.nullifier_key, *other_account.nullifier_key);
    assert!(WalletKeys::from_seed([0; 32], Zeroizing::new([2; 32]), 0).is_err());
}

#[test]
fn authenticated_rescan_recovers_all_three_outputs_without_a_sidecar() {
    let network = [4; 32];
    let config = Config::development(network, 0).unwrap();
    let state = State::new(config.clone()).unwrap();
    let original = wallet(network, 5);
    let asset = AssetId([7; 32]);
    let (record, notes, _) = encrypted_record(&state, &original, asset, 123_456, 500);
    let mut block = candidate(&state, 100_000);
    insert_record(&mut block, record);
    let mut restored = wallet(network, 5);
    restored
        .reconcile(config.clone(), &[block.clone()], &TestVerifier)
        .unwrap();
    assert_eq!(restored.receipts().len(), 3);
    assert_eq!(restored.balances(1).unwrap()[&asset], 123_456);
    assert_eq!(restored.balances(1).unwrap()[&SIP_ASSET_ID], 20_000);
    for expected in &notes {
        assert!(
            restored
                .receipts()
                .iter()
                .any(|receipt| same_note(receipt.note(), expected))
        );
    }
    let mut wrong_seed = wallet(network, 6);
    wrong_seed
        .reconcile(config, &[block], &TestVerifier)
        .unwrap();
    assert!(wrong_seed.receipts().is_empty());
}

fn reward_block(
    state: &State,
    target: &Wallet,
    mode: crate::state::RewardMode,
    seed: u32,
) -> Block {
    let h = Hasher::new();
    let plan = state.reward_plan(mode).unwrap();
    let mut block = candidate(state, seed);
    block.reward_mode = mode;
    block.rewards = plan
        .allocations
        .iter()
        .enumerate()
        .map(|(index, allocation)| {
            let reward_note = Note {
                asset_id: SIP_ASSET_ID,
                owner: target.address().owner(),
                value: allocation.amount,
                unlock_height: allocation.unlock_height,
                rho: h.reward_rho(plan.block_height, index),
                rseed: [F::from_u32(seed + index as u32); 12],
            };
            let (ciphertext, _) = encrypt_payment_with_opening(
                &target.address(),
                &reward_note,
                &EncryptionContext::new(state.config.network),
            )
            .unwrap();
            crate::wire::RewardRecord {
                commitment: encode_digest(&h.note_cm(&reward_note)),
                ciphertext: encode_payment(&ciphertext),
            }
        })
        .collect();
    block
}

#[test]
fn first_voyager_reward_uses_the_reward_receipt_namespace() {
    let network = [18; 32];
    let config = Config::development(network, 0).unwrap();
    let state = State::new(config.clone()).unwrap();
    let original = wallet(network, 19);
    let block = reward_block(
        &state,
        &original,
        crate::state::RewardMode::Voyager,
        120_000,
    );
    let expected = block.rewards[0].commitment;
    let mut restored = wallet(network, 19);
    restored.reconcile(config, &[block], &TestVerifier).unwrap();
    assert_eq!(restored.receipts().len(), 1);
    assert!(
        restored
            .receipts()
            .iter()
            .all(|receipt| receipt.output_index != 0)
    );
    let reward = restored
        .receipts()
        .iter()
        .find(|receipt| receipt.height == 1 && receipt.output_index == 3)
        .expect("the first miner reward uses the first reward receipt position");
    assert_eq!(reward.commitment, expected);
    assert_eq!(reward.note().unlock_height, 25);
}

#[test]
fn reward_scanning_recovers_five_holder_batches_and_unique_nullifiers_from_seed() {
    let network = [8; 32];
    let config = Config::development(network, 0).unwrap();
    let mut state = State::new(config.clone()).unwrap();
    let original = wallet(network, 9);
    let plan = state.reward_plan(crate::state::RewardMode::Holder).unwrap();
    let block = reward_block(&state, &original, crate::state::RewardMode::Holder, 100_000);
    assert_eq!(block.rewards.len(), 5);
    for reward in &block.rewards {
        assert_eq!(reward.ciphertext.len(), REWARD_CIPHERTEXT_BYTES);
    }
    state.apply(&block, &TestVerifier).unwrap();
    let mut restored = wallet(network, 9);
    restored.reconcile(config, &[block], &TestVerifier).unwrap();
    assert_eq!(restored.receipts().len(), 5);
    let nullifiers = restored
        .receipts()
        .iter()
        .map(|r| r.nullifier)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(nullifiers.len(), 5);
    let details = restored.balance_details(&state).unwrap();
    assert!(details.available.is_empty());
    assert_eq!(
        details.locked[&SIP_ASSET_ID],
        plan.allocations
            .iter()
            .map(|a| u128::from(a.amount))
            .sum::<u128>()
    );
    assert_eq!(
        details.next_unlock_height,
        Some(plan.allocations[0].unlock_height)
    );
    assert_eq!(details.tranches.len(), 5);
    for (index, allocation) in plan.allocations.iter().enumerate() {
        let receipt = &restored.receipts()[index];
        assert_eq!(receipt.note.unlock_height, allocation.unlock_height);
        assert_eq!(receipt.note.value, allocation.amount);
        assert_eq!(receipt.output_index, 3 + index as u8);
        assert_eq!(
            details.tranches[index].unlock_height,
            allocation.unlock_height
        );
        assert_eq!(
            details.tranches[index].estimated_timestamp,
            state.timestamp().checked_add(
                (allocation.unlock_height - state.height) * state.config.target_interval
            )
        );
        let before = restored
            .balances(allocation.unlock_height - 1)
            .unwrap()
            .get(&SIP_ASSET_ID)
            .copied()
            .unwrap_or(0);
        let after = restored.balances(allocation.unlock_height).unwrap()[&SIP_ASSET_ID];
        assert_eq!(after - before, u128::from(allocation.amount));
        assert_eq!(
            restored
                .automatic_ready_timestamp(&receipt.commitment)
                .unwrap(),
            None
        );
    }
    assert!(
        restored
            .prepare_transfer(
                &state,
                [Some(restored.receipts()[0].commitment), None],
                &restored.address(),
                SIP_ASSET_ID,
                100_000,
                FeeTier::Standard,
                state.timestamp(),
            )
            .is_err()
    );
}

#[test]
fn voyager_reward_recovers_as_one_maturing_note() {
    let network = [43; 32];
    let config = Config::development(network, 0).unwrap();
    let state = State::new(config.clone()).unwrap();
    let mut target = wallet(network, 44);
    let block = reward_block(&state, &target, crate::state::RewardMode::Voyager, 100_000);
    target.reconcile(config, &[block], &TestVerifier).unwrap();
    assert_eq!(target.receipts().len(), 1);
    assert_eq!(target.receipts()[0].note.unlock_height, 25);
    assert!(target.balances(24).unwrap().is_empty());
    assert!(target.balances(25).unwrap()[&SIP_ASSET_ID] > 0);
}

#[test]
fn locked_input_spending_waits_for_private_delay_and_rebuilds_after_reorg() {
    use siworld_core::v1_economics::EconomicsParams;
    let network = [55; 32];
    let config = Config::development(network, 0)
        .unwrap()
        .with_economics(EconomicsParams::engineering([60, 120, 180, 240], 4).unwrap())
        .unwrap();
    let mut state = State::new(config.clone()).unwrap();
    let mut sender = wallet(network, 56);
    let receiver = wallet(network, 57);
    let mut blocks = Vec::new();
    for height in 1..=60u32 {
        let block = if height == 1 {
            reward_block(&state, &sender, crate::state::RewardMode::Holder, 100_000)
        } else {
            candidate(&state, 100_000 + height * 20_000)
        };
        state.apply(&block, &TestVerifier).unwrap();
        blocks.push(block);
    }
    sender
        .reconcile(config.clone(), &blocks, &TestVerifier)
        .unwrap();
    let commitment = sender
        .receipts()
        .iter()
        .find(|receipt| receipt.note.unlock_height == 61)
        .unwrap()
        .commitment;
    assert_eq!(sender.automatic_ready_timestamp(&commitment).unwrap(), None);
    for selected in [[Some(commitment), None], [None, Some(commitment)]] {
        assert_eq!(
            sender
                .prepare_transfer(
                    &state,
                    selected,
                    &receiver.address(),
                    SIP_ASSET_ID,
                    100_000,
                    FeeTier::Standard,
                    u64::MAX,
                )
                .err()
                .as_deref(),
            Some("wallet input is spent, zero-valued, or immature")
        );
    }

    let parent = state.clone();
    let mature = candidate(&state, 2_000_000);
    let maturity_timestamp = mature.timestamp;
    state.apply(&mature, &TestVerifier).unwrap();
    blocks.push(mature);
    sender
        .reconcile(config.clone(), &blocks, &TestVerifier)
        .unwrap();
    let ready = sender
        .automatic_ready_timestamp(&commitment)
        .unwrap()
        .unwrap();
    assert!(
        (maturity_timestamp + AUTO_DELAY_MIN_SECONDS..=maturity_timestamp + AUTO_DELAY_MAX_SECONDS)
            .contains(&ready)
    );
    for selected in [[Some(commitment), None], [None, Some(commitment)]] {
        for now in [maturity_timestamp, ready - 1] {
            assert_eq!(
                sender
                    .prepare_transfer(
                        &state,
                        selected,
                        &receiver.address(),
                        SIP_ASSET_ID,
                        100_000,
                        FeeTier::Standard,
                        now,
                    )
                    .err()
                    .as_deref(),
                Some("wallet locked input privacy delay has not elapsed")
            );
        }
        let prepared = sender
            .prepare_transfer(
                &state,
                selected,
                &receiver.address(),
                SIP_ASSET_ID,
                100_000,
                FeeTier::Standard,
                ready,
            )
            .unwrap_or_else(|error| panic!("ready locked-input transfer failed: {error}"));
        let input = selected.iter().position(Option::is_some).unwrap();
        assert_eq!(prepared.witness().slot.inputs[input].unlock_height, 61);
        assert!(!prepared.witness().slot.inputs[input].dummy);
    }

    let mut restored = wallet(network, 56);
    restored
        .reconcile(config.clone(), &blocks, &TestVerifier)
        .unwrap();
    assert_eq!(
        restored.automatic_ready_timestamp(&commitment).unwrap(),
        Some(ready)
    );
    restored
        .receipts
        .iter_mut()
        .find(|r| r.commitment == commitment)
        .unwrap()
        .eligible_timestamp = None;
    assert_eq!(
        restored
            .prepare_transfer(
                &state,
                [Some(commitment), None],
                &receiver.address(),
                SIP_ASSET_ID,
                100_000,
                FeeTier::Standard,
                u64::MAX,
            )
            .err()
            .as_deref(),
        Some("wallet locked input has no canonical eligibility timestamp")
    );

    let mut replacement = candidate(&parent, 2_100_000);
    replacement.timestamp += 60;
    let mut replacement_state = parent.clone();
    replacement_state
        .apply(&replacement, &TestVerifier)
        .unwrap();
    blocks.pop();
    blocks.push(replacement);
    restored
        .reconcile(config.clone(), &blocks, &TestVerifier)
        .unwrap();
    let replacement_ready = restored
        .automatic_ready_timestamp(&commitment)
        .unwrap()
        .unwrap();
    assert_eq!(replacement_ready, ready + 60);
    assert_eq!(
        restored
            .prepare_transfer(
                &replacement_state,
                [Some(commitment), None],
                &receiver.address(),
                SIP_ASSET_ID,
                100_000,
                FeeTier::Standard,
                replacement_ready - 1,
            )
            .err()
            .as_deref(),
        Some("wallet locked input privacy delay has not elapsed")
    );
    let prepared = restored
        .prepare_transfer(
            &replacement_state,
            [Some(commitment), None],
            &receiver.address(),
            SIP_ASSET_ID,
            100_000,
            FeeTier::Standard,
            replacement_ready,
        )
        .unwrap_or_else(|error| panic!("replayed ready transfer failed: {error}"));
    assert_eq!(prepared.witness().slot.inputs[0].unlock_height, 61);
    assert!(!prepared.witness().slot.inputs[0].dummy);

    blocks.pop();
    restored.reconcile(config, &blocks, &TestVerifier).unwrap();
    assert_eq!(
        restored.automatic_ready_timestamp(&commitment).unwrap(),
        None
    );
    assert_eq!(
        restored
            .prepare_transfer(
                &parent,
                [Some(commitment), None],
                &receiver.address(),
                SIP_ASSET_ID,
                100_000,
                FeeTier::Standard,
                u64::MAX,
            )
            .err()
            .as_deref(),
        Some("wallet input is spent, zero-valued, or immature")
    );
}

#[test]
fn automatic_consolidation_is_delayed_seed_recoverable_and_sip_only() {
    let network = [45; 32];
    let config = Config::development(network, 0).unwrap();
    let mut state = State::new(config.clone()).unwrap();
    let mut sender = wallet(network, 46);
    let (record, _, _) = encrypted_record(&state, &sender, SIP_ASSET_ID, 5_000_000, 5000);
    let mut block = candidate(&state, 100_000);
    insert_record(&mut block, record);
    state.apply(&block, &TestVerifier).unwrap();
    sender
        .reconcile(config.clone(), &[block.clone()], &TestVerifier)
        .unwrap();
    let owned = sender
        .receipts()
        .iter()
        .filter(|r| r.note.value > 0)
        .collect::<Vec<_>>();
    assert_eq!(owned.len(), 2);
    let ready = owned
        .iter()
        .map(|r| {
            sender
                .automatic_ready_timestamp(&r.commitment)
                .unwrap()
                .unwrap()
        })
        .collect::<Vec<_>>();
    for at in &ready {
        assert!(
            (block.timestamp + AUTO_DELAY_MIN_SECONDS..=block.timestamp + AUTO_DELAY_MAX_SECONDS)
                .contains(at)
        );
    }
    let mut recovered = wallet(network, 46);
    recovered
        .reconcile(config, &[block.clone()], &TestVerifier)
        .unwrap();
    for (receipt, at) in owned.iter().zip(&ready) {
        assert_eq!(
            recovered
                .automatic_ready_timestamp(&receipt.commitment)
                .unwrap(),
            Some(*at)
        );
    }
    let first_ready = *ready.iter().min().unwrap();
    assert!(
        sender
            .prepare_small_sip_consolidation(&state, 5_000_000, FeeTier::Standard, first_ready - 1)
            .unwrap()
            .is_none()
    );
    let all_ready = *ready.iter().max().unwrap();
    let consolidation = sender
        .prepare_small_sip_consolidation(&state, 5_000_000, FeeTier::Standard, all_ready)
        .unwrap()
        .unwrap();
    let expected = 5_020_000 - base_fee(state.height);
    assert_eq!(consolidation.witness().slot.outputs[0].value, expected);
    assert_eq!(
        consolidation.witness().slot.outputs[0].asset_id,
        SIP_ASSET_ID
    );
    assert_eq!(
        consolidation.witness().slot.outputs[0].owner,
        sender.address().owner()
    );
    assert!(consolidation.witness().slot.inputs.iter().all(|i| !i.dummy));
    assert!(
        sender
            .prepare_small_sip_consolidation(&state, 19_999, FeeTier::Standard, all_ready)
            .unwrap()
            .is_none()
    );
    assert!(
        sender
            .prepare_small_sip_consolidation(&state, 0, FeeTier::Standard, all_ready)
            .is_err()
    );
    let mut stale = state.clone();
    stale.height += 1;
    assert!(
        sender
            .prepare_small_sip_consolidation(&stale, 5_000_000, FeeTier::Standard, all_ready)
            .is_err()
    );
    // Ordinary notes have no unlock cohort and can be spent immediately.
    // Select the funded payment rather than relying on receipt discovery order.
    let funded = owned
        .iter()
        .find(|receipt| receipt.note.value == 5_000_000)
        .unwrap();
    let minimum = native::multi_asset::MIN_PACKAGE_DEPOSIT;
    let below_minimum = sender.prepare_transfer(
        &state,
        [Some(funded.commitment), None],
        &sender.address(),
        SIP_ASSET_ID,
        minimum - 1,
        FeeTier::Standard,
        state.timestamp(),
    );
    assert_eq!(
        below_minimum.err().as_deref(),
        Some("below minimum deposit")
    );
    let manual = sender
        .prepare_transfer(
            &state,
            [Some(funded.commitment), None],
            &sender.address(),
            SIP_ASSET_ID,
            minimum,
            FeeTier::Standard,
            state.timestamp(),
        )
        .unwrap_or_else(|error| panic!("mature manual transfer preparation failed: {error}"));
    assert_eq!(manual.witness().slot.outputs[0].value, minimum);
}

#[test]
fn automatic_consolidation_rejects_immature_or_token_only_candidates() {
    let network = [47; 32];
    let config = Config::development(network, 0).unwrap();
    let mut state = State::new(config.clone()).unwrap();
    let mut target = wallet(network, 48);
    let block = reward_block(&state, &target, crate::state::RewardMode::Holder, 100_000);
    state.apply(&block, &TestVerifier).unwrap();
    target.reconcile(config, &[block], &TestVerifier).unwrap();
    assert!(
        target
            .prepare_small_sip_consolidation(&state, u64::MAX, FeeTier::Standard, u64::MAX)
            .unwrap()
            .is_none()
    );
    for receipt in &mut target.receipts {
        receipt.note.asset_id = AssetId([49; 32]);
        receipt.note.unlock_height = 0;
        receipt.eligible_timestamp = Some(1);
    }
    assert!(
        target
            .prepare_small_sip_consolidation(&state, u64::MAX, FeeTier::Standard, u64::MAX)
            .unwrap()
            .is_none()
    );
}

#[test]
fn reorg_rescan_removes_orphans_and_reverses_orphan_spends_atomically() {
    let network = [10; 32];
    let config = Config::development(network, 0).unwrap();
    let mut state = State::new(config.clone()).unwrap();
    let mut target = wallet(network, 11);
    let (record, _, _) = encrypted_record(&state, &target, SIP_ASSET_ID, 4_000_000, 800);
    let mut first = candidate(&state, 100_000);
    insert_record(&mut first, record);
    state.apply(&first, &TestVerifier).unwrap();
    target
        .reconcile(config.clone(), &[first.clone()], &TestVerifier)
        .unwrap();
    let nullifier = target.receipts()[0].nullifier;
    let mut orphan = candidate(&state, 200_000);
    orphan.transactions[0].record.body[..48].copy_from_slice(&nullifier);
    orphan
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&network));
    target
        .reconcile(config.clone(), &[first.clone(), orphan], &TestVerifier)
        .unwrap();
    assert!(target.receipts()[0].spent);
    let replacement = candidate(&state, 300_000);
    target
        .reconcile(
            config.clone(),
            &[first.clone(), replacement.clone()],
            &TestVerifier,
        )
        .unwrap();
    assert!(!target.receipts()[0].spent);
    let saved_tip = target.head();
    let mut invalid = replacement;
    invalid.settlement_proof = vec![0];
    assert!(
        target
            .reconcile(config.clone(), &[first, invalid], &TestVerifier)
            .is_err()
    );
    assert_eq!(target.head(), saved_tip);
    target.reconcile(config, &[], &TestVerifier).unwrap();
    assert!(target.receipts().is_empty());
}

#[test]
fn prebroadcast_check_rejects_every_ciphertext_commitment_and_context_change() {
    let network = [12; 32];
    let state = State::new(Config::development(network, 0).unwrap()).unwrap();
    let sender = wallet(network, 13);
    let (record, notes, opening) = encrypted_record(&state, &sender, SIP_ASSET_ID, 50_000, 900);
    let public = PublicTransaction::decode(&record.body).unwrap();
    sender
        .keys
        .check_before_broadcast(&public, &notes, &sender.keys.address(), &opening)
        .unwrap();
    for kind in 0..6 {
        let mut changed = public.clone();
        match kind {
            0 => changed.payment.body[0] ^= 1,
            1 => changed.payment.kem_ciphertext[0] ^= 1,
            2 => changed.change[0].tag[0] ^= 1,
            3 => changed.change[1].body[0] ^= 1,
            4 => changed.cm[2][0] += F::ONE,
            _ => changed.change.swap(0, 1),
        }
        assert!(
            sender
                .keys
                .check_before_broadcast(&changed, &notes, &sender.keys.address(), &opening)
                .is_err()
        );
    }
    let wrong_network = wallet([14; 32], 13);
    assert!(
        wrong_network
            .keys
            .check_before_broadcast(&public, &notes, &sender.keys.address(), &opening)
            .is_err()
    );
    let wrong_opening = PaymentEncryptionOpening::from_encapsulation_coins([0; 32]);
    assert!(
        sender
            .keys
            .check_before_broadcast(&public, &notes, &sender.keys.address(), &wrong_opening)
            .is_err()
    );
}

#[test]
fn transfer_witness_balances_sip_fees_and_token_change_with_two_or_one_inputs() {
    let network = [15; 32];
    let config = Config::development(network, 0).unwrap();
    let mut state = State::new(config.clone()).unwrap();
    let mut sender = wallet(network, 16);
    let receiver = wallet(network, 17);
    let asset = AssetId([18; 32]);
    let (token_record, token_notes, _) = encrypted_record(&state, &sender, asset, 500_000, 1000);
    let token_id = token_record.statement_id(&network);
    let token_commitment = encode_digest(&Hasher::new().note_cm(&token_notes[0]));
    let mut block = candidate(&state, 100_000);
    // A second owned SIP payment funds either canonical-snapshot fee tier.
    let sip_funding = base_fee(block.height) * 4 + 100_000;
    let (sip_record, sip_notes, _) =
        encrypted_record(&state, &sender, SIP_ASSET_ID, sip_funding, 2000);
    let sip_id = sip_record.statement_id(&network);
    let sip_commitment = encode_digest(&Hasher::new().note_cm(&sip_notes[0]));
    // Populate both positions before sorting: the first record's random
    // ciphertext can otherwise move it into the second replacement position.
    block.transactions[0].record = token_record;
    block.transactions[1].record = sip_record;
    block
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&network));
    for (id, commitment) in [(token_id, token_commitment), (sip_id, sip_commitment)] {
        let inserted = block
            .transactions
            .iter()
            .filter(|transaction| transaction.record.statement_id(&network) == id)
            .collect::<Vec<_>>();
        assert_eq!(inserted.len(), 1);
        let public = PublicTransaction::decode(&inserted[0].record.body).unwrap();
        assert_eq!(encode_digest(&public.cm[0]), commitment);
    }
    state.apply(&block, &TestVerifier).unwrap();
    sender.reconcile(config, &[block], &TestVerifier).unwrap();
    let token = sender
        .receipts()
        .iter()
        .find(|r| r.note.asset_id == asset && r.note.value > 0)
        .unwrap()
        .commitment;
    assert_eq!(token, token_commitment);
    let sip = sender
        .receipts()
        .iter()
        .find(|r| r.note.asset_id == SIP_ASSET_ID && r.note.value == sip_funding)
        .unwrap()
        .commitment;
    assert_eq!(sip, sip_commitment);
    for tier in [FeeTier::Standard, FeeTier::Priority] {
        let prepared = sender
            .prepare_transfer(
                &state,
                [Some(token), Some(sip)],
                &receiver.keys.address(),
                asset,
                100_000,
                tier,
                state.timestamp(),
            )
            .unwrap();
        let witness = prepared.witness();
        witness
            .check_at_snapshot(
                &Hasher::new(),
                &decode_digest(&state.tip_snapshot().recent_root).unwrap(),
                state.tip_snapshot().selector.height,
            )
            .unwrap();
        assert_eq!(witness.slot.outputs[0].asset_id, asset);
        assert_eq!(witness.slot.outputs[0].value, 100_000);
        assert_eq!(
            witness.slot.fee,
            base_fee(state.height) * if tier == FeeTier::Priority { 4 } else { 1 }
        );
        prepared
            .sidecar()
            .check_opening(prepared.record(), &network)
            .unwrap();
    }
    let one_input = sender
        .prepare_transfer(
            &state,
            [Some(sip), None],
            &receiver.keys.address(),
            SIP_ASSET_ID,
            100_000,
            FeeTier::Standard,
            state.timestamp(),
        )
        .unwrap();
    assert!(one_input.witness().slot.inputs[1].dummy);
    assert!(
        sender
            .prepare_transfer(
                &state,
                [Some(token), None],
                &receiver.keys.address(),
                asset,
                100_000,
                FeeTier::Standard,
                state.timestamp(),
            )
            .is_err()
    );
    assert!(
        sender
            .prepare_transfer(
                &state,
                [Some(sip), Some(sip)],
                &receiver.keys.address(),
                SIP_ASSET_ID,
                100_000,
                FeeTier::Standard,
                state.timestamp(),
            )
            .is_err()
    );
    assert!(
        sender
            .prepare_transfer(
                &state,
                [None, None],
                &receiver.keys.address(),
                SIP_ASSET_ID,
                100_000,
                FeeTier::Standard,
                state.timestamp(),
            )
            .is_err()
    );
    assert!(
        sender
            .prepare_transfer(
                &state,
                [Some(sip), None],
                &receiver.keys.address(),
                SIP_ASSET_ID,
                sip_funding + 1,
                FeeTier::Standard,
                state.timestamp(),
            )
            .is_err()
    );
}

/// The funding history below is a synthetic fixture checked by TestVerifier.
/// Only the transfer uses actual frozen native proving/verification. This does
/// not establish genesis funding, live mining or a fully native wallet chain.
#[test]
#[ignore = "explicit frozen native wallet proof and encrypted receiver check"]
fn actual_native_wallet_proof_passes_admission_and_recipient_authentication() {
    use crate::admission::{Mempool, PeerId};
    use crate::proofs::{NativeProver, NativeVerifier};
    let network = [19; 32];
    let config = Config::development(network, 0).unwrap();
    let mut state = State::new(config.clone()).unwrap();
    let mut sender = wallet(network, 20);
    let receiver = wallet(network, 21);
    let mut funding = candidate(&state, 100_000);
    let sip_funding = base_fee(funding.height) * 4 + 100_000;
    let (record, _, _) = encrypted_record(&state, &sender, SIP_ASSET_ID, sip_funding, 3000);
    insert_record(&mut funding, record);
    state.apply(&funding, &TestVerifier).unwrap();
    sender.reconcile(config, &[funding], &TestVerifier).unwrap();
    let commitment = sender
        .receipts()
        .iter()
        .find(|receipt| receipt.note.value == sip_funding)
        .unwrap()
        .commitment;
    let prover = NativeProver::new().unwrap();
    let verifier = NativeVerifier::new().unwrap();
    for tier in [FeeTier::Standard, FeeTier::Priority] {
        let prepared = sender
            .prepare_transfer(
                &state,
                [Some(commitment), None],
                &receiver.address(),
                SIP_ASSET_ID,
                100_000,
                tier,
                state.timestamp(),
            )
            .unwrap();
        let expected =
            prepared
                .witness()
                .slot
                .output_note(&Hasher::new(), &prepared.public().nf, 0);
        let payment = prepared.prove(&prover).unwrap();
        let envelope = payment.transaction.encode_envelope(&network).unwrap();
        let sidecar = payment.sidecar.encode().unwrap();
        let mut pool = Mempool::new(network);
        let accepted = pool
            .submit_encoded(
                &state,
                PeerId([22; 32]),
                &envelope,
                Some(&sidecar),
                &verifier,
            )
            .unwrap();
        assert_eq!(accepted, payment.transaction.record.statement_id(&network));
        let public = PublicTransaction::decode(&payment.transaction.record.body).unwrap();
        let received = receiver
            .keys
            .recipient
            .decrypt_payment(
                &public.cm[0],
                &public.payment,
                &EncryptionContext::new(network),
            )
            .unwrap();
        assert!(same_note(&received, &expected));
        let receipt = payment
            .payment_opening()
            .verify_payment(
                &receiver.address(),
                &public.cm[0],
                &public.payment,
                &EncryptionContext::new(network),
            )
            .unwrap();
        assert!(same_note(&receipt, &expected));
        assert_eq!(pool.len(), 1);
    }
}

#[test]
fn permanent_fund_ciphertext_recovers_after_seed_restore_without_private_sidecars() {
    use crate::fund_spend::{FundSpend, SIGNATURE_BYTES, canonical_rho};
    use libcrux_ml_dsa::ml_dsa_65;
    let network = [50; 32];
    let mut config = Config::development(network, 0).unwrap();
    let pair = ml_dsa_65::generate_key_pair([51; 32]);
    config.fund_verifying_keys[0] = *pair.verification_key.as_ref();
    let mut state = State::new(config.clone()).unwrap();
    let original = wallet(network, 52);
    let mut blocks = Vec::new();
    for height in 1..=24u32 {
        let block = candidate(&state, 100_000 + height * 20_000);
        state.apply(&block, &TestVerifier).unwrap();
        blocks.push(block);
    }
    let mut block = candidate(&state, 1_000_000);
    let expected = Note {
        asset_id: SIP_ASSET_ID,
        owner: original.address().owner(),
        value: 12_345,
        unlock_height: 0,
        rho: canonical_rho(network, 0, 0),
        rseed: [F::from_u32(54); 12],
    };
    let commitment = Hasher::new().note_cm(&expected);
    let (ciphertext, _) = encrypt_payment_with_opening(
        &original.address(),
        &expected,
        &EncryptionContext::new(network),
    )
    .unwrap();
    let mut spend = FundSpend {
        account: 0,
        counter: 0,
        amount: expected.value,
        owner: encode_digest(&expected.owner),
        rho: encode_digest(&expected.rho),
        rseed: encode_digest(&expected.rseed),
        commitment: encode_digest(&commitment),
        ciphertext: encode_payment(&ciphertext),
        verifying_key: *pair.verification_key.as_ref(),
        signature: [0; SIGNATURE_BYTES],
    };
    spend.signature = *ml_dsa_65::sign(
        &pair.signing_key,
        &spend.message(network),
        b"siworld v0",
        [53; 32],
    )
    .unwrap()
    .as_ref();
    block.fund_spends.push(spend);
    state.apply(&block, &TestVerifier).unwrap();
    blocks.push(block);
    let mut restored = wallet(network, 52);
    restored.reconcile(config, &blocks, &TestVerifier).unwrap();
    assert_eq!(restored.receipts().len(), 1);
    assert!(same_note(restored.receipts()[0].note(), &expected));
    assert_eq!(restored.receipts()[0].output_index, 8);
    assert_eq!(
        restored.balance_details(&state).unwrap().available[&SIP_ASSET_ID],
        12_345
    );
}

fn issuance_request(
    recipient: &Wallet,
    key: [u8; native::issuance::ISSUER_KEY_BYTES],
) -> issuance::IssuanceRequest {
    issuance::IssuanceRequest {
        issuer_key: key,
        sequence: 1,
        public_supply: 900,
        metadata: native::issuance::AssetMetadata {
            name: "Synthetic asset".into(),
            decimals: 2,
        },
        outputs: [300, 200, 400].map(|amount| issuance::InitialOutput {
            recipient: recipient.address(),
            amount,
        }),
    }
}
fn configured_issuance_funding() -> (
    Config,
    State,
    Wallet,
    Wallet,
    Wallet,
    Vec<Block>,
    DigestBytes,
) {
    let network = [91; 32];
    let mut config = Config::development(network, 0).unwrap();
    let mut sender = wallet(network, 92);
    let recipient = wallet(network, 93);
    let fund = wallet(network, 94);
    config.issuance = Some(crate::issuance::IssuanceConfig {
        fee_owner: encode_digest(&fund.address().owner()),
        max_metadata_bytes: 256,
        max_per_block: 1,
    });
    let mut state = State::new(config.clone()).unwrap();
    let mut funding = candidate(&state, 2_000_000);
    // Cover the issuance payment and the largest ordinary fee tier selected
    // by the canonical funding snapshot, with nonzero change left over.
    let amount = crate::issuance::TESTNET_ISSUANCE_FEE_ATOMS
        .checked_add(base_fee(funding.height).checked_mul(4).unwrap())
        .and_then(|value| value.checked_add(1_000_000))
        .unwrap();
    let (record, _, _) = encrypted_record(&state, &sender, SIP_ASSET_ID, amount, 3_000_000);
    insert_record(&mut funding, record);
    state.apply(&funding, &TestVerifier).unwrap();
    sender
        .reconcile(config.clone(), &[funding.clone()], &TestVerifier)
        .unwrap();
    let selected = sender
        .receipts()
        .iter()
        .find(|r| r.note.value == amount)
        .unwrap()
        .commitment;
    (
        config,
        state,
        sender,
        recipient,
        fund,
        vec![funding],
        selected,
    )
}
#[test]
fn issuance_fee_uses_air_derived_rho_and_declaration_bound_randomness() {
    use libcrux_ml_dsa::ml_dsa_65;
    let (config, state, sender, recipient, fund, _, selected) = configured_issuance_funding();
    let pair = ml_dsa_65::generate_key_pair([95; 32]);
    let key = *pair.verification_key.as_ref();
    let issuance = sender
        .prepare_issuance(&config, issuance_request(&recipient, key))
        .unwrap();
    let fee = sender
        .prepare_issuance_fee(
            &state,
            [Some(selected), None],
            &fund.address(),
            issuance.declaration(),
            FeeTier::Standard,
            state.timestamp(),
        )
        .unwrap();
    let note =
        fee.transfer()
            .witness()
            .slot
            .output_note(&Hasher::new(), &fee.transfer().public().nf, 0);
    assert_eq!(encode_digest(&note.rho), fee.receipt().rho);
    assert_eq!(
        note.rseed,
        crate::issuance::fee_rseed(issuance.declaration().binding())
    );
    assert_eq!(note.value, crate::issuance::TESTNET_ISSUANCE_FEE_ATOMS);
    assert_eq!(note.asset_id, SIP_ASSET_ID);
    assert_eq!(note.unlock_height, 0);
    let receipt = crate::issuance::IssuanceRecord {
        signed: native::issuance::SignedIssuance {
            declaration: issuance.declaration().clone(),
            signature: Some(
                *ml_dsa_65::sign(
                    &pair.signing_key,
                    &issuance.signature_message(),
                    issuance::ISSUER_SIGNATURE_CONTEXT,
                    [96; 32],
                )
                .unwrap()
                .as_ref(),
            ),
        },
        ciphertexts: vec![vec![0; crate::issuance::CIPHERTEXT_BYTES]; 3],
        proof: vec![1],
        fee_commitment: fee.receipt().commitment,
        fee_rho: fee.receipt().rho,
    };
    assert!(same_note(
        &note,
        &receipt.fee_note(config.issuance.as_ref().unwrap()).unwrap()
    ));
    assert!(
        sender
            .prepare_issuance_fee(
                &state,
                [Some(selected), None],
                &recipient.address(),
                issuance.declaration(),
                FeeTier::Standard,
                state.timestamp()
            )
            .is_err()
    );
}

/// Only the funding prefix is synthetic. Every position, settlement and issuance
/// in the next block uses the native frozen prover and independent verifier.
/// This does not establish genesis funding, live P2P or persistent wallet storage.
#[test]
#[ignore = "explicit complete native issuance block, durable replay and seed rescan"]
fn actual_native_issuance_block_recovers_registry_and_seed_wallet_after_restart() {
    use crate::pool::Padding;
    use crate::proofs::{NativeProver, NativeVerifier};
    use crate::state::BlockVerifier;
    use crate::store::Store;
    use libcrux_ml_dsa::ml_dsa_65;
    use native::confidential_fees::FeeOpening;
    use native::issuance_air::IssuanceProver;
    let (config, state, sender, recipient, fund, mut blocks, selected) =
        configured_issuance_funding();
    let pair = ml_dsa_65::generate_key_pair([95; 32]);
    let prepared = sender
        .prepare_issuance(
            &config,
            issuance_request(&recipient, *pair.verification_key.as_ref()),
        )
        .unwrap();
    let fee = sender
        .prepare_issuance_fee(
            &state,
            [Some(selected), None],
            &fund.address(),
            prepared.declaration(),
            FeeTier::Standard,
            state.timestamp(),
        )
        .unwrap();
    let receipt = fee.receipt().clone();
    let signature = *ml_dsa_65::sign(
        &pair.signing_key,
        &prepared.signature_message(),
        issuance::ISSUER_SIGNATURE_CONTEXT,
        [96; 32],
    )
    .unwrap()
    .as_ref();
    let issuance_prover =
        IssuanceProver::new(crate::issuance::INITIAL_NOTES, crate::issuance::params());
    let record = prepared
        .attach_signature(signature)
        .unwrap()
        .prove(&issuance_prover, &receipt, &config)
        .unwrap()
        .record;
    let asset_id = record.signed.declaration.asset_id;
    let prover = NativeProver::new().unwrap();
    let verifier = NativeVerifier::new().unwrap();
    let fee_opening = FeeOpening {
        fee: fee.transfer().sidecar().fee,
        blind: fee.transfer().sidecar().blind.map(F::from_u32),
        priority: false,
        dummy: false,
    };
    let fee_payment = fee.into_transfer().prove(&prover).unwrap();
    let mut positions = vec![Padding {
        transaction: fee_payment.transaction,
        opening: fee_opening,
    }];
    for _ in 1..64 {
        positions.push(crate::producer::prepare_padding(&state, &prover).unwrap());
    }
    let settings = crate::producer::MiningSettings {
        mode: crate::state::RewardMode::Voyager,
        recipient: sender.address(),
    };
    let mut block = crate::producer::assemble(
        &state,
        &prover,
        positions,
        state.timestamp() + 300,
        &settings,
    )
    .unwrap()
    .block;
    block.issuances.push(record);
    let mut accepted = state.clone();
    accepted.apply(&block, &verifier).unwrap();
    let expected = accepted.fingerprint();
    struct PrefixVerifier(NativeVerifier);
    impl BlockVerifier for PrefixVerifier {
        fn transaction(
            &self,
            p: &PublicTransaction,
            c: &ProofContext,
            f: &Digest,
            r: &Digest,
            proof: &[u8],
        ) -> Result<(), String> {
            if proof == [1] {
                TestVerifier.transaction(p, c, f, r, proof)
            } else {
                self.0.transaction(p, c, f, r, proof)
            }
        }
        fn settlement(
            &self,
            f: &[Digest],
            p: &native::settlement::RewardPlan,
            n: Hash,
            l: Hash,
            r: &[Digest],
            proof: &[u8],
        ) -> Result<(), String> {
            if proof == [1] {
                TestVerifier.settlement(f, p, n, l, r, proof)
            } else {
                self.0.settlement(f, p, n, l, r, proof)
            }
        }
        fn issuance(&self, r: &crate::issuance::IssuanceRecord) -> Result<(), String> {
            self.0.issuance(r)
        }
    }
    let verifier = PrefixVerifier(verifier);
    let path = std::env::temp_dir().join(format!(
        "siworld-native-issuance-replay-{}",
        std::process::id()
    ));
    std::fs::create_dir(&path).unwrap();
    let db = path.join("chain.redb");
    let mut store = Store::open(&db, config.clone(), &verifier).unwrap();
    store.append(&blocks[0], &verifier).unwrap();
    store.append(&block, &verifier).unwrap();
    assert_eq!(store.state().fingerprint(), expected);
    drop(store);
    let reopened = Store::open_existing(&db, config.clone(), &verifier).unwrap();
    assert_eq!(reopened.state().fingerprint(), expected);
    assert_eq!(
        reopened
            .state()
            .assets
            .get(&asset_id.0)
            .unwrap()
            .public_supply,
        900
    );
    blocks.push(block);
    let mut restored = wallet(config.network, 93);
    let report = restored
        .reconcile(config.clone(), &blocks, &verifier)
        .unwrap();
    assert_eq!(report.issued_assets.len(), 1);
    // The eight reserved fund-claim positions occupy indices 8 through 15.
    // A restored issuance must not reuse any of those local category indices.
    assert_eq!(
        restored
            .receipts()
            .iter()
            .map(|receipt| receipt.output_index)
            .collect::<Vec<_>>(),
        vec![16, 17, 18]
    );
    assert_eq!(
        restored.balances(reopened.state().height).unwrap()[&asset_id],
        900
    );
    drop(reopened);
    std::fs::remove_dir_all(path).unwrap();
}
