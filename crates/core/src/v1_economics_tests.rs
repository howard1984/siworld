use super::*;

fn allocation() -> FundAllocation {
    FundAllocation::new_bps(vec![5_000, 5_000], 1).unwrap()
}
fn configured_ledger(params: EconomicsParams) -> Result<EconomicsLedger> {
    EconomicsLedger::new(params)?.with_fund_allocation(allocation())
}

#[test]
fn exact_initial_mode_allocations_and_note_unlocks() {
    let params = EconomicsParams::production();
    let voyager = allocate_reward(
        &params,
        &allocation(),
        1,
        RewardMode::Voyager,
        INITIAL_REWARD,
        0,
    )
    .unwrap();
    assert_eq!(voyager.fund_credit, [169_726_225, 169_726_226]);
    assert_eq!(voyager.miner_base, 2_953_236_329);
    assert_eq!(voyager.protocol_pool_credit, 101_835_735);
    assert_eq!(voyager.mode_pool_credit, 590_647_265);
    assert_eq!(voyager.burn, 147_661_816);
    assert_eq!(voyager.pool_payout, 0);
    assert_eq!(voyager.pool_after, 692_483_000);
    assert_eq!(
        voyager.reward_notes,
        vec![RewardNote {
            index: 0,
            amount: 2_214_927_248,
            unlock_height: 25
        }]
    );
    let holder = allocate_reward(
        &params,
        &allocation(),
        1,
        RewardMode::Holder,
        INITIAL_REWARD,
        0,
    )
    .unwrap();
    assert_eq!(holder.fund_credit, [169_726_225, 169_726_226]);
    assert_eq!(holder.pool_payout, 0);
    assert_eq!(holder.pool_after, 101_835_735);
    assert_eq!(holder.mode_pool_credit, 0);
    assert_eq!(holder.burn, 0);
    assert_eq!(
        holder
            .reward_notes
            .iter()
            .map(|n| n.amount)
            .collect::<Vec<_>>(),
        vec![
            1_771_941_801,
            295_323_632,
            295_323_632,
            295_323_632,
            295_323_632
        ]
    );
    assert_eq!(
        holder
            .reward_notes
            .iter()
            .map(|n| n.unlock_height)
            .collect::<Vec<_>>(),
        vec![25, 52_561, 105_121, 157_681, 210_241]
    );
    assert_eq!(
        holder
            .reward_notes
            .iter()
            .map(|n| n.index)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );
}

#[test]
fn rounding_residuals_are_conserved_at_every_split() {
    for subsidy in [0, 1, 19, 20, 99, 101, INITIAL_REWARD, u64::MAX] {
        for mode in [RewardMode::Voyager, RewardMode::Holder] {
            let a = allocate_reward(
                &EconomicsParams::production(),
                &allocation(),
                1,
                mode,
                subsidy,
                4_031,
            )
            .unwrap();
            let credited: u128 = a.reward_notes.iter().map(|n| u128::from(n.amount)).sum();
            assert_eq!(
                u128::from(subsidy) + 4_031,
                credited
                    + a.pool_after
                    + u128::from(a.burn)
                    + a.fund_credit.iter().map(|x| u128::from(*x)).sum::<u128>()
            );
            assert_eq!(
                a.fund_credit,
                [subsidy / 10 / 2, subsidy / 10 - subsidy / 10 / 2]
            );
            assert_eq!(
                a.protocol_pool_credit,
                (u128::from(subsidy) * 3 / 100) as u64
            );
            if mode == RewardMode::Holder {
                assert!(a.reward_notes[1..]
                    .iter()
                    .all(|n| n.amount == a.miner_base / 10));
            }
        }
    }
}

#[test]
fn pool_empty_claim_credit_order_and_remainder() {
    let params = EconomicsParams::production();
    let empty = allocate_reward(&params, &allocation(), 1, RewardMode::Holder, 0, 0).unwrap();
    assert_eq!((empty.pool_payout, empty.pool_after), (0, 0));
    let remainder =
        allocate_reward(&params, &allocation(), 1, RewardMode::Holder, 0, 4_033).unwrap();
    assert_eq!((remainder.pool_payout, remainder.pool_after), (1, 4_032));
    let claim_first =
        allocate_reward(&params, &allocation(), 1, RewardMode::Holder, 134_400, 0).unwrap();
    assert_eq!(claim_first.protocol_pool_credit, 4_032);
    assert_eq!(
        (claim_first.pool_payout, claim_first.pool_after),
        (0, 4_032)
    );
    let sub_divisor = allocate_reward(
        &params,
        &allocation(),
        1,
        RewardMode::Holder,
        134_400,
        4_031,
    )
    .unwrap();
    assert_eq!(
        (sub_divisor.pool_payout, sub_divisor.pool_after),
        (0, 8_063)
    );
    let funded = allocate_reward(
        &params,
        &allocation(),
        1,
        RewardMode::Holder,
        134_400,
        4_033,
    )
    .unwrap();
    assert_eq!((funded.pool_payout, funded.pool_after), (1, 8_064));
    for allocation in [&empty, &remainder, &claim_first, &sub_divisor, &funded] {
        allocation.check_conservation().unwrap();
    }
    let voyager =
        allocate_reward(&params, &allocation(), 1, RewardMode::Voyager, 0, 4_033).unwrap();
    assert_eq!((voyager.pool_payout, voyager.pool_after), (0, 4_033));
}

#[test]
fn reward_notes_that_claim_this_blocks_pool_credit_are_rejected() {
    let correct = allocate_reward(
        &EconomicsParams::production(),
        &allocation(),
        1,
        RewardMode::Holder,
        INITIAL_REWARD,
        0,
    )
    .unwrap();
    let mut credit_before_claim = correct.reward_notes.clone();
    credit_before_claim[0].amount += correct.protocol_pool_credit / POOL_PAYOUT_DIVISOR as u64;
    assert_eq!(
        correct.verify_reward_notes(&credit_before_claim),
        Err(EconomicsError::RewardMismatch)
    );
    correct.verify_reward_notes(&correct.reward_notes).unwrap();
}

#[test]
fn issuance_epoch_and_tail_boundaries() {
    assert_eq!(subsidy(0), Err(EconomicsError::InvalidHeight));
    assert_eq!(epoch_of(1).unwrap(), 0);
    assert_eq!(epoch_of(4_032).unwrap(), 0);
    assert_eq!(epoch_of(4_033).unwrap(), 1);
    assert_eq!(subsidy(1).unwrap(), 3_394_524_515);
    assert_eq!(subsidy(4_032).unwrap(), 3_394_524_515);
    assert_eq!(subsidy(4_033).unwrap(), 3_373_372_441);
    assert_eq!(tail_entry_epoch(), 564);
    assert_eq!(tail_entry_height(), 2_274_049);
    assert!(subsidy(tail_entry_height() - 1).unwrap() > TAIL_REWARD);
    assert_eq!(subsidy(tail_entry_height()).unwrap(), 100_000_000);
    assert_eq!(subsidy(u64::MAX).unwrap(), TAIL_REWARD);
    assert_eq!(TAIL_REWARD_60_SECONDS * 5, TAIL_REWARD);
}

#[test]
fn projections_match_independent_epoch_vectors() {
    for (years, atoms) in [
        (1, 330_301_640_337_408u128),
        (4, 1_051_940_734_229_376),
        (10, 1_765_966_769_721_792),
        (20, 2_112_093_162_237_312),
        (40, 2_324_882_623_548_096),
    ] {
        let p = project_years(years).unwrap();
        assert_eq!(p.height, years * 105_120);
        assert_eq!(p.issued, atoms);
        assert_eq!(p.last_subsidy, subsidy(p.height).unwrap());
    }
    assert_eq!(project_blocks(0).unwrap().issued, 0);
    assert_eq!(
        project_blocks(4_032).unwrap().issued,
        u128::from(INITIAL_REWARD) * 4_032
    );
    let a = project_blocks(tail_entry_height() - 1).unwrap();
    let b = project_blocks(tail_entry_height()).unwrap();
    assert_eq!(b.issued - a.issued, u128::from(TAIL_REWARD));
}

#[test]
fn engineering_timings_are_explicit_immutable_and_checked() {
    let production = EconomicsParams::production();
    let test = EconomicsParams::engineering([60, 120, 180, 240], 4).unwrap();
    assert_ne!(production.canonical_bytes(), test.canonical_bytes());
    assert_eq!(
        production.holder_unlock_offsets,
        [52_560, 105_120, 157_680, 210_240]
    );
    assert_eq!(production.fund_vesting_days, 1_461);
    assert_eq!(test.maturity, 24);
    for (offsets, days) in [
        ([24, 120, 180, 240], 4),
        ([60, 60, 180, 240], 4),
        ([60, 120, 180, 240], 0),
        ([60, 120, 180, 240], 1_462),
    ] {
        assert!(EconomicsParams::engineering(offsets, days).is_err());
    }
    assert_eq!(RewardMode::from_byte(0).unwrap(), RewardMode::Voyager);
    assert_eq!(RewardMode::from_byte(1).unwrap(), RewardMode::Holder);
    assert!(RewardMode::from_byte(2).is_err());
}

#[test]
fn locked_subsidy_unlocks_at_the_exact_scheduled_height() {
    let params = EconomicsParams::engineering([60, 120, 180, 240], 4).unwrap();
    let mut ledger = configured_ledger(params).unwrap();
    let first = ledger.advance(1, RewardMode::Holder).unwrap();
    let immediate = u128::from(first.reward_notes[0].amount);
    assert_eq!(ledger.locked_schedule()[&25], immediate);
    for height in 2..=24 {
        ledger.advance(height, RewardMode::Voyager).unwrap();
    }
    assert_eq!(ledger.locked_schedule()[&25], immediate);
    let before = ledger.totals().locked_subsidy;
    let next = ledger.advance(25, RewardMode::Voyager).unwrap();
    assert!(!ledger.locked_schedule().contains_key(&25));
    assert_eq!(
        ledger.totals().locked_subsidy,
        before - immediate + u128::from(next.reward_notes[0].amount)
    );
    for height in 26..=241 {
        ledger.advance(height, RewardMode::Voyager).unwrap();
    }
    assert!(!ledger.locked_schedule().contains_key(&241));
    assert_eq!(
        ledger.locked_schedule().values().copied().sum::<u128>(),
        ledger.totals().locked_subsidy
    );
    ledger.assert_supply_invariant().unwrap();
}

#[test]
fn fund_maturity_daily_floor_last_day_and_independent_spending() {
    let params = EconomicsParams::engineering([60, 120, 180, 240], 4).unwrap();
    let mut ledger = configured_ledger(params.clone()).unwrap();
    let direct = (INITIAL_REWARD / 20) / 2;
    let vested = INITIAL_REWARD / 20 - direct;
    for height in 1..=24 {
        ledger.advance(height, RewardMode::Voyager).unwrap();
    }
    assert_eq!(ledger.fund(FundAccount::FIRST).unwrap().direct_unlocked, 0);
    ledger.advance(25, RewardMode::Voyager).unwrap();
    assert_eq!(
        ledger.fund(FundAccount::FIRST).unwrap().direct_unlocked,
        u128::from(direct)
    );
    ledger
        .spend_fund(FundAccount::FIRST, u128::from(direct), 0)
        .unwrap();
    assert_eq!(
        ledger.fund(FundAccount::FIRST).unwrap().spent,
        u128::from(direct)
    );
    assert_eq!(ledger.fund(FundAccount::SECOND).unwrap().spent, 0);
    assert_eq!(ledger.fund(FundAccount::FIRST).unwrap().spend_count, 1);
    for height in 26..=288 {
        ledger.advance(height, RewardMode::Voyager).unwrap();
    }
    assert_eq!(ledger.fund(FundAccount::FIRST).unwrap().vesting_unlocked, 0);
    ledger.advance(289, RewardMode::Voyager).unwrap();
    assert_eq!(
        ledger.fund(FundAccount::FIRST).unwrap().vesting_unlocked,
        u128::from(vested / 4)
    );
    for height in 290..=1_153 {
        ledger.advance(height, RewardMode::Voyager).unwrap();
        let expected: u128 = (1..=height)
            .map(|credit_height| {
                let age_days = ((height - credit_height) / 288).min(4);
                u128::from(vested) * u128::from(age_days) / 4
            })
            .sum();
        assert_eq!(
            ledger.fund(FundAccount::FIRST).unwrap().vesting_unlocked,
            expected
        );
    }
    assert_eq!(u128::from(vested), u128::from(vested) * 4 / 4);
    ledger.assert_supply_invariant().unwrap();
}

#[test]
fn fund_release_cohorts_match_slow_per_credit_oracle_across_epochs() {
    let params = EconomicsParams::engineering([60, 120, 180, 240], 3).unwrap();
    let mut ledger = EconomicsLedger::new(params)
        .unwrap()
        .with_fund_allocation(FundAllocation::new_bps(vec![3_000, 7_000], 1).unwrap())
        .unwrap();
    for height in 1..=5_200 {
        ledger.advance(height, RewardMode::Holder).unwrap();
        if height.is_multiple_of(37) || [4_032, 4_033, 4_896, 4_897, 5_200].contains(&height) {
            for (account, numerator) in [(FundAccount::FIRST, 3), (FundAccount::SECOND, 7)] {
                let mut direct = 0u128;
                let mut vested = 0u128;
                for h in 1..=height {
                    let total = subsidy(h).unwrap() / 10;
                    let first = total * 3_000 / 10_000;
                    let share = if numerator == 3 { first } else { total - first };
                    if height - h >= 24 {
                        direct += u128::from(share / 2);
                    }
                    vested +=
                        u128::from(share - share / 2) * u128::from(((height - h) / 288).min(3)) / 3;
                }
                let balance = ledger.fund(account).unwrap();
                assert_eq!(
                    (balance.direct_unlocked, balance.vesting_unlocked),
                    (direct, vested),
                    "height {height}, wallet {account:?}"
                );
            }
        }
    }
}

#[test]
fn invalid_heights_spends_and_arithmetic_fail_atomically() {
    let mut ledger = configured_ledger(EconomicsParams::production()).unwrap();
    for height in 1..=25 {
        ledger.advance(height, RewardMode::Holder).unwrap();
    }
    let before = ledger.clone();
    assert_eq!(
        ledger.advance(27, RewardMode::Holder),
        Err(EconomicsError::NonConsecutiveHeight)
    );
    assert_eq!(ledger, before);
    for (amount, counter, expected) in [
        (1, 1, EconomicsError::FundCounter),
        (0, 0, EconomicsError::InvalidAmount),
        (u128::MAX, 0, EconomicsError::FundOverdraft),
    ] {
        assert_eq!(
            ledger.spend_fund(FundAccount::FIRST, amount, counter),
            Err(expected)
        );
        assert_eq!(ledger, before);
    }
    let mut overflow = ledger.clone();
    overflow.totals.issued = u128::MAX;
    let before_overflow = overflow.clone();
    assert!(overflow.advance(26, RewardMode::Holder).is_err());
    assert_eq!(overflow, before_overflow);
    assert!(allocate_reward(
        &EconomicsParams::production(),
        &allocation(),
        u64::MAX,
        RewardMode::Holder,
        INITIAL_REWARD,
        0
    )
    .is_err());
    assert!(allocate_reward(
        &EconomicsParams::production(),
        &allocation(),
        1,
        RewardMode::Voyager,
        INITIAL_REWARD,
        u128::MAX
    )
    .is_err());
}

#[test]
fn replacement_replay_restores_pool_burn_fund_and_unlock_schedules() {
    let params = EconomicsParams::engineering([60, 120, 180, 240], 3).unwrap();
    let mut common = configured_ledger(params.clone()).unwrap();
    for h in 1..=300 {
        common.advance(h, RewardMode::Holder).unwrap();
    }
    let mut orphan = common.clone();
    for h in 301..=325 {
        orphan.advance(h, RewardMode::Voyager).unwrap();
    }
    let mut replacement = common;
    for h in 301..=325 {
        replacement.advance(h, RewardMode::Holder).unwrap();
    }
    let mut replay = configured_ledger(params).unwrap();
    for h in 1..=325 {
        replay.advance(h, RewardMode::Holder).unwrap();
    }
    assert_eq!(replacement, replay);
    assert_ne!(orphan.totals().holder_pool, replay.totals().holder_pool);
    assert_ne!(orphan.totals().burned, replay.totals().burned);
    assert_eq!(
        orphan.fund(FundAccount::FIRST).unwrap(),
        replay.fund(FundAccount::FIRST).unwrap()
    );
    assert_ne!(orphan.locked_schedule(), replay.locked_schedule());
}

#[test]
#[ignore = "Long deterministic production-schedule simulation; run explicitly in remote CI"]
fn seeded_twenty_year_modes_preserve_supply_and_curve() {
    // Synthetic public fixture: twenty-three independent equal shares and a team
    // remainder account. It does not select any deployed wallet allocation.
    let mut bps = vec![400u16; 23];
    bps.push(800);
    let mut ledger = EconomicsLedger::new(EconomicsParams::production())
        .unwrap()
        .with_fund_allocation(FundAllocation::new_bps(bps.clone(), 23).unwrap())
        .unwrap();
    let mut seed = 0x6730_fab9_a521_80d3u64;
    let height = 20 * BLOCKS_PER_YEAR;
    let mut reference = vec![FundBalance::default(); bps.len()];
    let mut reference_subsidy = INITIAL_REWARD;
    let mut reference_pool = 0u128;
    let mut reference_burn = 0u128;
    let mut reference_miner_credit = 0u128;
    for h in 1..=height {
        if h > 1 && (h - 1).is_multiple_of(EPOCH_BLOCKS) {
            reference_subsidy = ((u128::from(reference_subsidy)
                * u128::from(crate::params::DECAY_Q32))
                >> 32) as u64;
            reference_subsidy = reference_subsidy.max(TAIL_REWARD);
        }
        // Independent slow oracle for the final per-wallet totals: each block's
        // credit is split and aged independently, without cohort helpers.
        let fund_total = reference_subsidy / 10;
        let mut credits: Vec<u64> = bps
            .iter()
            .map(|share| (u128::from(fund_total) * u128::from(*share) / 10_000) as u64)
            .collect();
        let residue = fund_total - credits.iter().sum::<u64>();
        credits[23] += residue;
        for (account, credit) in reference.iter_mut().zip(credits) {
            account.entitlement += u128::from(credit);
            if height - h >= COINBASE_MATURITY {
                account.direct_unlocked += u128::from(credit / 2);
            }
            let days = ((height - h) / BLOCKS_PER_DAY).min(FUND_VESTING_DAYS);
            account.vesting_unlocked +=
                u128::from(credit - credit / 2) * u128::from(days) / u128::from(FUND_VESTING_DAYS);
        }
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let mode = if seed & 1 == 0 {
            RewardMode::Voyager
        } else {
            RewardMode::Holder
        };
        // Independent atom arithmetic claims only the pre-block balance.
        // Same-block protocol and Voyager credits enter after the claim.
        let protocol_credit = u128::from(reference_subsidy) * 3 / 100;
        let miner_base = u128::from(reference_subsidy - fund_total) - protocol_credit;
        let claim = if mode == RewardMode::Holder {
            reference_pool / 4_032
        } else {
            0
        };
        let burn = if mode == RewardMode::Voyager {
            miner_base * 5 / 100
        } else {
            0
        };
        let mode_credit = if mode == RewardMode::Voyager {
            miner_base * 20 / 100
        } else {
            0
        };
        reference_pool = reference_pool - claim + protocol_credit + mode_credit;
        reference_burn += burn;
        reference_miner_credit += miner_base + claim - burn - mode_credit;
        let actual = ledger.advance(h, mode).unwrap();
        assert_eq!(u128::from(actual.pool_payout), claim);
        assert_eq!(actual.pool_after, reference_pool);
        assert_eq!(ledger.totals().holder_pool, reference_pool);
        assert_eq!(ledger.totals().burned, reference_burn);
        assert_eq!(
            ledger.totals().miner_subsidy_credited,
            reference_miner_credit
        );
        ledger.assert_supply_invariant().unwrap();
        if h.is_multiple_of(50_000) {
            let account = FundAccount::new((seed as usize) % bps.len()).unwrap();
            let balance = ledger.fund(account).unwrap();
            let amount = balance.available().unwrap() / 2;
            if amount > 0 {
                ledger
                    .spend_fund(account, amount, balance.spend_count)
                    .unwrap();
            }
        }
    }
    assert_eq!(ledger.totals().issued, 2_112_093_162_237_312);
    assert_eq!(
        ledger.totals().issued,
        project_blocks(height).unwrap().issued
    );
    assert_eq!(
        ledger.locked_schedule().values().copied().sum::<u128>(),
        ledger.totals().locked_subsidy
    );
    for (actual, expected) in ledger.funds().iter().zip(&reference) {
        assert_eq!(
            (
                actual.entitlement,
                actual.direct_unlocked,
                actual.vesting_unlocked
            ),
            (
                expected.entitlement,
                expected.direct_unlocked,
                expected.vesting_unlocked
            )
        );
    }
    let entitlement: u128 = ledger.funds().iter().map(|fund| fund.entitlement).sum();
    let unlocked: u128 = ledger
        .funds()
        .iter()
        .map(|fund| fund.unlocked().unwrap())
        .sum();
    let spent: u128 = ledger.funds().iter().map(|fund| fund.spent).sum();
    let wallet_records: Vec<_> = ledger.funds().iter().enumerate().map(|(index, fund)| {
        format!("{{\"index\":{index},\"basis_points\":{},\"entitlement\":{},\"direct_unlocked\":{},\"vesting_unlocked\":{},\"spent\":{},\"available\":{},\"spend_count\":{}}}",
            bps[index], fund.entitlement, fund.direct_unlocked, fund.vesting_unlocked,
            fund.spent, fund.available().unwrap(), fund.spend_count)
    }).collect();
    let wallets_json = wallet_records.join(",");
    println!(
        "V1_ECONOMICS_SIMULATION={{\"economics_rule_version\":{ECONOMICS_RULE_VERSION},\"holder_claim_before_injection\":1,\"height\":{height},\"issued\":{},\"miner_subsidy_credited\":{},\"holder_pool\":{},\"burned\":{},\"locked_subsidy\":{},\"synthetic_wallet_basis_points\":{:?},\"team_remainder_index\":23,\"wallet_count\":24,\"fund_entitlement\":{entitlement},\"fund_unlocked\":{unlocked},\"fund_spent\":{spent},\"fund_wallets\":[{wallets_json}]}}",
        ledger.totals().issued,
        ledger.totals().miner_subsidy_credited,
        ledger.totals().holder_pool,
        ledger.totals().burned,
        ledger.totals().locked_subsidy,
        bps,
    );
}

#[test]
fn canonical_state_encoding_covers_counters_and_future_schedules() {
    let mut ledger = configured_ledger(EconomicsParams::production()).unwrap();
    ledger.advance(1, RewardMode::Holder).unwrap();
    let encode = |state: &EconomicsLedger| {
        let mut bytes = Vec::new();
        state.visit_encoding(&mut |part| bytes.extend_from_slice(part));
        bytes
    };
    let original = encode(&ledger);
    assert_eq!(original[..2], ECONOMICS_RULE_VERSION.to_le_bytes());
    assert_eq!(original, encode(&ledger.clone()));
    let mut changed = ledger.clone();
    changed.current_subsidy += 1;
    assert_ne!(original, encode(&changed));
    let mut changed = ledger.clone();
    changed.fund_allocation.as_mut().unwrap().team_index = 0;
    assert_ne!(original, encode(&changed));
    let mut changed = ledger.clone();
    changed.fund_cohorts[0].credit[0] += 1;
    assert_ne!(original, encode(&changed));
    let mut changed = ledger.clone();
    changed.locked_schedule.insert(123, 1);
    assert_ne!(original, encode(&changed));
    let mut changed = ledger;
    changed.funds[0].spent += 1;
    assert_ne!(original, encode(&changed));
}

#[test]
fn unconfigured_fund_policy_prevents_issuance_and_mutation() {
    let mut ledger = EconomicsLedger::new(EconomicsParams::production()).unwrap();
    let before = ledger.clone();
    assert_eq!(
        ledger.advance(1, RewardMode::Voyager),
        Err(EconomicsError::UnconfiguredFund)
    );
    assert_eq!(ledger, before);
    for (shares, team) in [
        (Vec::new(), 0),
        (vec![10_000, 0], 0),
        (vec![5_000, 4_999], 1),
        (vec![5_000, 5_001], 1),
        (vec![10_000], 1),
        (vec![1; 33], 0),
    ] {
        assert!(FundAllocation::new_bps(shares, team).is_err());
    }
    ledger = ledger
        .with_fund_allocation(FundAllocation::new_bps(vec![3_000, 7_000], 1).unwrap())
        .unwrap();
    ledger.advance(1, RewardMode::Voyager).unwrap();
    assert!(ledger.with_fund_allocation(allocation()).is_err());
}

#[test]
fn explicit_wallet_weights_have_independent_entitlements_unlocks_and_budgets() {
    let weights = FundAllocation::new_bps(vec![3_000, 7_000], 1).unwrap();
    let allocation = allocate_reward(
        &EconomicsParams::production(),
        &weights,
        1,
        RewardMode::Holder,
        INITIAL_REWARD,
        0,
    )
    .unwrap();
    assert_eq!(allocation.fund_credit, vec![101_835_735, 237_616_716]);
    let mut ledger = EconomicsLedger::new(EconomicsParams::production())
        .unwrap()
        .with_fund_allocation(weights)
        .unwrap();
    for height in 1..=25 {
        ledger.advance(height, RewardMode::Holder).unwrap();
    }
    let first = ledger
        .fund(FundAccount::FIRST)
        .unwrap()
        .available()
        .unwrap();
    let second = ledger
        .fund(FundAccount::SECOND)
        .unwrap()
        .available()
        .unwrap();
    assert_eq!(first, 101_835_735 / 2);
    assert_eq!(second, 237_616_716 / 2);
    ledger.spend_fund(FundAccount::FIRST, first, 0).unwrap();
    let before = ledger.clone();
    assert_eq!(
        ledger.spend_fund(FundAccount::FIRST, second, 1),
        Err(EconomicsError::FundOverdraft)
    );
    assert_eq!(ledger, before);
    ledger.spend_fund(FundAccount::SECOND, second, 0).unwrap();
    assert_eq!(
        ledger
            .fund(FundAccount::FIRST)
            .unwrap()
            .available()
            .unwrap(),
        0
    );
    assert_eq!(
        ledger
            .fund(FundAccount::SECOND)
            .unwrap()
            .available()
            .unwrap(),
        0
    );
    ledger.assert_supply_invariant().unwrap();
}

#[test]
fn generic_fund_builder_has_no_implicit_wallet_count_or_ratio() {
    let weights = FundAllocation::new_bps(vec![2_000, 3_000, 5_000], 2).unwrap();
    assert_eq!(weights.basis_points(), &[2_000, 3_000, 5_000]);
    assert_eq!(weights.team_index(), 2);
    let allocation = allocate_reward(
        &EconomicsParams::production(),
        &weights,
        1,
        RewardMode::Voyager,
        100_000,
        0,
    )
    .unwrap();
    assert_eq!(allocation.fund_credit, vec![2_000, 3_000, 5_000]);
    allocation.check_conservation().unwrap();
}

#[test]
fn basis_points_are_exact_bounded_and_team_receives_only_split_residual() {
    assert!(FundAccount::new(MAX_FUND_WALLETS).is_err());
    let mut shares = vec![300u16; 31];
    shares.push(700);
    let allocation = FundAllocation::new_bps(shares.clone(), 19).unwrap();
    assert_eq!(allocation.basis_points(), shares);
    assert_eq!(allocation.team_index(), 19);
    for subsidy in [0, 9, 10, 109, INITIAL_REWARD, u64::MAX] {
        let total = subsidy / 10;
        let credits = allocation.credits(subsidy);
        assert_eq!(credits.len(), 32);
        assert_eq!(
            credits.iter().map(|v| u128::from(*v)).sum::<u128>(),
            u128::from(total)
        );
        let floors: Vec<_> = shares
            .iter()
            .map(|bps| (u128::from(total) * u128::from(*bps) / 10_000) as u64)
            .collect();
        let residual = total - floors.iter().sum::<u64>();
        for index in 0..32 {
            assert_eq!(
                credits[index],
                floors[index] + if index == 19 { residual } else { 0 }
            );
        }
    }
    let mut ledger = EconomicsLedger::new(EconomicsParams::production())
        .unwrap()
        .with_fund_allocation(allocation)
        .unwrap();
    for height in 1..=25 {
        ledger.advance(height, RewardMode::Holder).unwrap();
    }
    assert_eq!(ledger.funds().len(), 32);
    assert_eq!(ledger.fund_allocation().unwrap().team_index(), 19);
    assert!(ledger
        .clone()
        .with_fund_allocation(FundAllocation::new_bps(vec![10_000], 0).unwrap())
        .is_err());
    let one = EconomicsLedger::new(EconomicsParams::production())
        .unwrap()
        .with_fund_allocation(FundAllocation::new_bps(vec![10_000], 0).unwrap())
        .unwrap();
    assert_eq!(
        one.fund(FundAccount::SECOND),
        Err(EconomicsError::InvalidFundAccount)
    );
    let before = ledger.clone();
    assert_eq!(
        ledger.spend_fund(FundAccount::new(31).unwrap(), u128::MAX, 0),
        Err(EconomicsError::FundOverdraft)
    );
    assert_eq!(ledger, before);
}

#[test]
fn many_wallet_claims_are_independent_and_batch_failure_is_atomic() {
    let mut shares = vec![450u16; 20];
    shares.push(1_000);
    let allocation = FundAllocation::new_bps(shares, 20).unwrap();
    let mut ledger = EconomicsLedger::new(EconomicsParams::production())
        .unwrap()
        .with_fund_allocation(allocation)
        .unwrap();
    for height in 1..=25 {
        ledger.advance(height, RewardMode::Voyager).unwrap();
    }
    let a = FundAccount::new(0).unwrap();
    let b = FundAccount::new(20).unwrap();
    let av = ledger.fund(a).unwrap().available().unwrap();
    let bv = ledger.fund(b).unwrap().available().unwrap();
    let before = ledger.clone();
    assert_eq!(
        ledger.spend_funds(&[(a, av, 0), (b, bv + 1, 0)]),
        Err(EconomicsError::FundOverdraft)
    );
    assert_eq!(ledger, before);
    ledger.spend_funds(&[(a, av, 0), (b, bv, 0)]).unwrap();
    assert_eq!(ledger.fund(a).unwrap().spent, av);
    assert_eq!(ledger.fund(b).unwrap().spent, bv);
    for index in 1..20 {
        assert_eq!(
            ledger.fund(FundAccount::new(index).unwrap()).unwrap().spent,
            0
        );
    }
    ledger.assert_supply_invariant().unwrap();
}

#[test]
fn twenty_one_wallet_reorg_restores_each_wallet_credits_spends_and_schedule() {
    let params = EconomicsParams::engineering([60, 120, 180, 240], 3).unwrap();
    let mut shares = vec![450u16; 20];
    shares.push(1_000);
    let configured = || {
        EconomicsLedger::new(params.clone())
            .unwrap()
            .with_fund_allocation(FundAllocation::new_bps(shares.clone(), 20).unwrap())
            .unwrap()
    };
    let mut common = configured();
    for height in 1..=288 {
        common.advance(height, RewardMode::Holder).unwrap();
    }
    let mut orphan = common.clone();
    for height in 289..=312 {
        orphan.advance(height, RewardMode::Voyager).unwrap();
    }
    for index in 0..21 {
        let account = FundAccount::new(index).unwrap();
        let value = orphan.fund(account).unwrap().available().unwrap();
        orphan.spend_fund(account, value, 0).unwrap();
    }
    let mut replacement = common;
    for height in 289..=312 {
        replacement.advance(height, RewardMode::Holder).unwrap();
    }
    let mut replay = configured();
    for height in 1..=312 {
        replay.advance(height, RewardMode::Holder).unwrap();
    }
    assert_eq!(replacement, replay);
    assert_ne!(orphan.totals().holder_pool, replay.totals().holder_pool);
    assert_ne!(orphan.totals().burned, replay.totals().burned);
    for index in 0..21 {
        let account = FundAccount::new(index).unwrap();
        assert_eq!(replacement.fund(account), replay.fund(account));
        assert_eq!(replacement.fund(account).unwrap().spent, 0);
        assert!(orphan.fund(account).unwrap().spent > 0);
    }
}

#[test]
fn fund_resource_accounting_charges_owned_vector_capacities() {
    let mut shares = Vec::with_capacity(10_000);
    shares.extend([5_000, 5_000]);
    let allocation = FundAllocation::new_bps(shares, 1).unwrap();
    assert!(allocation.owned_bytes().unwrap() >= 20_000);
    let mut ledger = EconomicsLedger::new(EconomicsParams::production())
        .unwrap()
        .with_fund_allocation(allocation)
        .unwrap();
    ledger.advance(1, RewardMode::Holder).unwrap();
    let mut previous = ledger.logical_memory_bytes().unwrap();
    ledger.funds.reserve_exact(1_000);
    assert!(ledger.logical_memory_bytes().unwrap() > previous);
    previous = ledger.logical_memory_bytes().unwrap();
    ledger.fund_cohorts[0].credit.reserve_exact(1_000);
    assert!(ledger.logical_memory_bytes().unwrap() > previous);
}
