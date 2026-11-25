use super::*;

fn fixture() -> FundLedger {
    FundLedger::new([7; 32], FundAllocation::new_bps(vec![10000], 0).unwrap()).unwrap()
}
// A synthetic state after zero-subsidy intervening blocks, with one credit at 1.
// Expected release is independently derived from the specified monthly rule.
fn single_credit_before(height: u64, credit: u64) -> FundLedger {
    let mut ledger = fixture();
    ledger.advance(1, credit * 10).unwrap();
    ledger.height = height;
    let balance = &mut ledger.balances[0];
    balance.direct_unlocked = if height >= 25 {
        u128::from(credit / 2)
    } else {
        0
    };
    balance.vesting_unlocked = u128::from(credit - credit / 2)
        * u128::from(((height - 1) / MONTH_BLOCKS).min(MONTHS))
        / u128::from(MONTHS);
    ledger
}
#[test]
fn direct_half_unlocks_at_credit_plus_24_and_not_before() {
    let mut ledger = fixture();
    ledger.advance(1, 1010).unwrap();
    for height in 2..=24 {
        ledger.advance(height, 0).unwrap();
    }
    assert_eq!(ledger.balance(0).unwrap().available().unwrap(), 0);
    ledger.advance(25, 0).unwrap();
    let b = ledger.balance(0).unwrap();
    assert_eq!(b.entitlement, 101);
    assert_eq!(b.direct_unlocked, 50);
    assert_eq!(b.vesting_unlocked, 0);
    assert!(ledger.spend(0, 51, 0).is_err());
    ledger.spend(0, 50, 0).unwrap();
}
#[test]
fn monthly_release_starts_at_original_credit_plus_8766_and_finishes_exactly_at_48() {
    for month in 1..=MONTHS {
        let effective = 1 + month * MONTH_BLOCKS;
        let mut ledger = single_credit_before(effective - 1, 101);
        let before = ledger.balance(0).unwrap();
        assert_eq!(before.vesting_unlocked, 51 * u128::from(month - 1) / 48);
        ledger.advance(effective, 0).unwrap();
        let after = ledger.balance(0).unwrap();
        assert_eq!(after.vesting_unlocked, 51 * u128::from(month) / 48);
        assert_eq!(after.direct_unlocked, 50);
        if month == MONTHS {
            assert_eq!(after.available().unwrap(), 101);
            assert!(ledger.cohorts.is_empty());
        }
    }
}
#[test]
fn per_member_allocation_rounding_and_team_remainder_are_conserved() {
    let allocation = FundAllocation::new_bps(vec![3333, 6667], 1).unwrap();
    let mut ledger = FundLedger::new([7; 32], allocation).unwrap();
    ledger.advance(1, 1010).unwrap();
    assert_eq!(ledger.balance(0).unwrap().entitlement, 33);
    assert_eq!(ledger.balance(1).unwrap().entitlement, 68);
    assert_eq!(ledger.total_entitlement(), 101);
    for height in 2..=25 {
        ledger.advance(height, 0).unwrap();
    }
    assert_eq!(ledger.balance(0).unwrap().direct_unlocked, 16);
    assert_eq!(ledger.balance(1).unwrap().direct_unlocked, 34);
    assert!(ledger.spend(0, 17, 0).is_err());
    ledger.spend(1, 34, 0).unwrap();
    assert_eq!(ledger.balance(0).unwrap().spent, 0);
    assert_eq!(ledger.balance(1).unwrap().spent, 34);
}
#[test]
fn consecutive_credit_cohorts_compress_and_zero_credit_gaps_do_not_merge() {
    let mut ledger = fixture();
    for height in 1..=100 {
        ledger.advance(height, 1000).unwrap();
    }
    assert_eq!(ledger.cohorts.len(), 1);
    assert_eq!((ledger.cohorts[0].start, ledger.cohorts[0].end), (1, 100));
    ledger.advance(101, 0).unwrap();
    ledger.advance(102, 1000).unwrap();
    assert_eq!(ledger.cohorts.len(), 2);
    assert_eq!(ledger.balance(0).unwrap().entitlement, 10100);
}
#[test]
fn claims_require_exact_independent_counters_and_are_atomic() {
    let mut ledger = single_credit_before(24, 101);
    ledger.advance(25, 0).unwrap();
    for claims in [
        vec![(0, 0, 0)],
        vec![(1, 1, 0)],
        vec![(0, 1, 1)],
        vec![(0, 1, 0), (0, 51, 1)],
    ] {
        let before = ledger.clone();
        assert!(ledger.spend_many(&claims).is_err());
        assert_eq!(ledger, before);
    }
    ledger.spend_many(&[(0, 20, 0), (0, 30, 1)]).unwrap();
    assert_eq!(ledger.balance(0).unwrap().spend_count, 2);
    assert_eq!(ledger.balance(0).unwrap().available().unwrap(), 0);
    assert!(ledger.spend(0, 1, 1).is_err());
}
#[test]
fn component_round_trip_preserves_schedule_balances_and_counters() {
    let mut ledger = single_credit_before(8766, 101);
    ledger.advance(8767, 0).unwrap();
    ledger.spend(0, 17, 0).unwrap();
    let bytes = ledger.canonical_component_bytes().unwrap();
    let restored = FundLedger::decode_component(&bytes, [7; 32], &ledger.allocation).unwrap();
    assert_eq!(ledger, restored);
    assert!(FundLedger::decode_component(&bytes, [8; 32], &ledger.allocation).is_err());
    let wrong = FundAllocation::new_bps(vec![5000, 5000], 0).unwrap();
    assert!(FundLedger::decode_component(&bytes, [7; 32], &wrong).is_err());
    assert!(
        FundLedger::decode_component(&bytes[..bytes.len() - 1], [7; 32], &ledger.allocation)
            .is_err()
    );
    assert!(
        FundLedger::decode_component(
            &[bytes.as_slice(), &[0]].concat(),
            [7; 32],
            &ledger.allocation
        )
        .is_err()
    );
}
#[test]
fn nonconsecutive_heights_and_overflows_preserve_the_complete_ledger() {
    let mut ledger = fixture();
    let before = ledger.clone();
    assert!(ledger.advance(2, 1000).is_err());
    assert_eq!(ledger, before);
    ledger.height = u64::MAX;
    let before = ledger.clone();
    assert!(ledger.advance(0, 1000).is_err());
    assert_eq!(ledger, before);
    let mut ledger = single_credit_before(24, 101);
    ledger.advance(25, 0).unwrap();
    ledger.balances[0].spend_count = u64::MAX;
    let before = ledger.clone();
    assert!(ledger.spend(0, 1, u64::MAX).is_err());
    assert_eq!(ledger, before);
}
#[test]
fn malformed_component_state_is_rejected_before_encoding() {
    for change in 0..7 {
        let mut ledger = single_credit_before(24, 101);
        match change {
            0 => ledger.network = [0; 32],
            1 => ledger.balances[0].spent = 1,
            2 => ledger.balances[0].direct_unlocked = 200,
            3 => ledger.total_entitlement = 102,
            4 => ledger.cohorts[0].start = 0,
            5 => ledger.cohorts[0].end = 25,
            _ => ledger.cohorts[0].credits = vec![0],
        }
        assert!(
            ledger.canonical_component_bytes().is_err(),
            "change {change}"
        );
    }
}

#[test]
fn component_rejects_swapping_direct_and_monthly_release_counters() {
    let mut ledger = single_credit_before(8766, 101);
    ledger.advance(8767, 0).unwrap();
    ledger.balances[0].direct_unlocked -= 1;
    ledger.balances[0].vesting_unlocked += 1;
    assert!(ledger.canonical_component_bytes().is_err());
}

#[test]
fn completed_prefix_of_a_compressed_cohort_retires_without_losing_lifetime_totals() {
    let mut ledger = fixture();
    for height in 1..=100 {
        ledger.advance(height, 1000).unwrap();
    }
    ledger.height = VESTING_BLOCKS;
    ledger.balances[0].direct_unlocked = 5000;
    ledger.balances[0].vesting_unlocked = (1..=100)
        .map(|credit_height| {
            50 * u128::from(((VESTING_BLOCKS - credit_height) / MONTH_BLOCKS).min(MONTHS)) / 48
        })
        .sum();
    assert_eq!(ledger.balances[0].vesting_unlocked, 4800);
    ledger.advance(VESTING_BLOCKS + 1, 0).unwrap();
    assert_eq!(ledger.cohorts[0].start, 2);
    assert_eq!(ledger.cohorts[0].end, 100);
    assert_eq!(ledger.balances[0].vesting_unlocked, 4802);
    assert_eq!(ledger.total_entitlement(), 10000);
    let bytes = ledger.canonical_component_bytes().unwrap();
    assert_eq!(
        FundLedger::decode_component(&bytes, [7; 32], &ledger.allocation).unwrap(),
        ledger
    );
}
