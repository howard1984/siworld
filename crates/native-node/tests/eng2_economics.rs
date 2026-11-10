use siworld_core::v1_economics::{FundAllocation, RewardMode};
use siworld_native_node::eng2_economics::EconomicState;

fn funds() -> FundAllocation {
    FundAllocation::new_bps(vec![6000, 4000], 1).unwrap()
}

#[test]
fn fee_schedule_uses_the_confirmed_flooring_order_at_every_epoch() {
    use siworld_native_node::eng2_economics::{fee_base, fee_priority};
    for height in [
        1,
        4032,
        4033,
        8065,
        siworld_core::v1_economics::tail_entry_height(),
        u64::MAX,
    ] {
        let previous = siworld_core::v1_economics::fee_base(height).unwrap();
        assert_eq!(fee_base(height).unwrap(), previous / 10);
        assert_eq!(fee_priority(height).unwrap(), 4 * (previous / 10));
    }
    assert!(fee_base(0).is_err());
}

#[test]
fn every_mode_preserves_public_subsidy_conservation_without_fee_income() {
    let mut state = EconomicState::new([71; 32]).unwrap();
    for height in 1..=64 {
        let mode = if height % 2 == 0 {
            RewardMode::Holder
        } else {
            RewardMode::Voyager
        };
        let before = state.clone();
        let (next, allocation) = state.prepare(height, mode, &funds()).unwrap();
        assert_eq!(state, before);
        assert_eq!(
            next.issued(),
            next.miner_credited() + next.fund_credited() + next.pool() + next.burned()
        );
        assert_eq!(
            allocation.miner_subsidy_credit(),
            next.miner_credited() - state.miner_credited()
        );
        state = next;
    }
}

#[test]
fn failure_never_mutates_parent_and_height_is_consecutive() {
    let state = EconomicState::new([71; 32]).unwrap();
    let before = state.clone();
    assert!(state.prepare(2, RewardMode::Holder, &funds()).is_err());
    assert_eq!(state, before);
}

#[test]
fn maturity_unlocks_at_height_plus_twenty_four() {
    let mut state = EconomicState::new([71; 32]).unwrap();
    let (first, allocation) = state.prepare(1, RewardMode::Voyager, &funds()).unwrap();
    let matured = u128::from(allocation.reward_notes[0].amount);
    state = first;
    for height in 2..=24 {
        state = state
            .prepare(height, RewardMode::Voyager, &funds())
            .unwrap()
            .0;
    }
    assert_eq!(state.locked_total(), state.miner_credited());
    state = state.prepare(25, RewardMode::Voyager, &funds()).unwrap().0;
    assert_eq!(state.locked_total(), state.miner_credited() - matured);
}

#[test]
fn canonical_components_roundtrip_with_all_state_fields_bound() {
    let state = EconomicState::new([71; 32])
        .unwrap()
        .prepare(1, RewardMode::Holder, &funds())
        .unwrap()
        .0;
    let bytes = state.component_bytes().unwrap();
    assert_eq!(
        EconomicState::from_components([71; 32], 1, [&bytes[0], &bytes[1], &bytes[2]]).unwrap(),
        state
    );
    assert!(
        EconomicState::from_components([72; 32], 1, [&bytes[0], &bytes[1], &bytes[2]]).is_err()
    );
    assert!(
        EconomicState::from_components([71; 32], 2, [&bytes[0], &bytes[1], &bytes[2]]).is_err()
    );
    let mut trailing = bytes[1].clone();
    trailing.push(0);
    assert!(
        EconomicState::from_components([71; 32], 1, [&bytes[0], &trailing, &bytes[2]]).is_err()
    );
}

#[test]
fn corrupted_supply_or_locked_sum_is_rejected_at_import() {
    let state = EconomicState::new([71; 32])
        .unwrap()
        .prepare(1, RewardMode::Holder, &funds())
        .unwrap()
        .0;
    let bytes = state.component_bytes().unwrap();
    for component in 0..3 {
        let mut changed = bytes.clone();
        changed[component][46] ^= 1;
        assert!(
            EconomicState::from_components([71; 32], 1, [&changed[0], &changed[1], &changed[2]])
                .is_err()
        );
    }
}

#[test]
fn malformed_schedule_order_count_and_duplicate_unlocks_are_rejected() {
    let state = EconomicState::new([71; 32])
        .unwrap()
        .prepare(1, RewardMode::Holder, &funds())
        .unwrap()
        .0;
    let bytes = state.component_bytes().unwrap();
    let mut changed = bytes.clone();
    changed[2][62..66].fill(255);
    assert!(
        EconomicState::from_components([71; 32], 1, [&changed[0], &changed[1], &changed[2]])
            .is_err()
    );
    let mut changed = bytes.clone();
    let first_unlock = changed[2][66..74].to_vec();
    changed[2][90..98].copy_from_slice(&first_unlock);
    assert!(
        EconomicState::from_components([71; 32], 1, [&changed[0], &changed[1], &changed[2]])
            .is_err()
    );
}
