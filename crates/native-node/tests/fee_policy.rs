use native::{
    confidential_fees::{FeeOpening, SettlementSlot},
    multi_asset::{F, FEE_BLIND_LEN, Hasher, Note, SIP_ASSET_ID},
    settlement::{RewardAllocation, RewardMode, RewardPlan},
};
use p3_field::PrimeCharacteristicRing;
use siworld_native_node::eng2_settlement::{FeeSchedule, PrivateSettlement, SettlementPolicy};

fn sample(mode: RewardMode, fees: &[u64]) -> (SettlementPolicy, PrivateSettlement) {
    let h = Hasher::new();
    let owner = [F::from_u32(12); 12];
    let plan = RewardPlan {
        block_height: 100,
        mode,
        allocations: (0..mode.note_count())
            .map(|i| RewardAllocation {
                amount: 50 + i as u64,
                unlock_height: 124 + i as u64,
            })
            .collect(),
    };
    let slots = fees
        .iter()
        .enumerate()
        .map(|(i, fee)| {
            SettlementSlot::from_opening(
                &h,
                FeeOpening {
                    fee: *fee,
                    blind: [F::from_usize(i + 1); FEE_BLIND_LEN],
                    dummy: *fee == 0,
                    priority: *fee == 40,
                },
            )
        })
        .collect();
    let rewards = plan
        .allocations
        .iter()
        .enumerate()
        .map(|(i, a)| Note {
            asset_id: SIP_ASSET_ID,
            owner: [F::from_u32(20); 12],
            value: a.amount,
            unlock_height: a.unlock_height,
            rho: h.reward_rho(100, i),
            rseed: [F::from_usize(i + 1); 12],
        })
        .collect();
    let fee_note = Note {
        asset_id: SIP_ASSET_ID,
        owner,
        value: fees.iter().sum(),
        unlock_height: 0,
        rho: [F::from_u32(41); 12],
        rseed: [F::from_u32(42); 12],
    };
    (
        SettlementPolicy {
            plan,
            fee_owner: owner,
            fees: FeeSchedule::from_previous_standard(100).unwrap(),
            max_slots: 16,
        },
        PrivateSettlement {
            rewards,
            fee_note,
            slots,
        },
    )
}

#[test]
fn floor_standard_before_priority_multiplication() {
    for old in [0, 1, 9, 10, 19, 99, 101, u64::MAX] {
        let fees = FeeSchedule::from_previous_standard(old).unwrap();
        assert_eq!(fees.standard(), old / 10);
        assert_eq!(fees.priority(), 4 * (old / 10));
    }
}

#[test]
fn both_modes_pay_exact_subsidy_and_private_destination() {
    for mode in [RewardMode::Holder, RewardMode::Voyager] {
        let (policy, witness) = sample(mode, &[10, 0, 40, 10]);
        witness.validate(&policy).unwrap();
    }
}

#[test]
fn fees_cannot_be_redirected_or_added_to_miner() {
    let (policy, mut witness) = sample(RewardMode::Voyager, &[10, 40]);
    witness.fee_note.owner[0] += F::ONE;
    assert!(witness.validate(&policy).is_err());
    let (policy, mut witness) = sample(RewardMode::Holder, &[10, 40]);
    witness.rewards[0].value += 50;
    witness.fee_note.value = 0;
    assert!(witness.validate(&policy).is_err());
}

#[test]
fn fee_output_remains_present_and_unlocked_at_zero_sum() {
    let (policy, mut witness) = sample(RewardMode::Voyager, &[0, 0]);
    witness.validate(&policy).unwrap();
    witness.fee_note.unlock_height = 1;
    assert!(witness.validate(&policy).is_err());
}

#[test]
fn tier_padding_and_commitment_substitutions_are_rejected() {
    let h = Hasher::new();
    for opening in [
        FeeOpening {
            fee: 10,
            blind: [F::ONE; FEE_BLIND_LEN],
            dummy: true,
            priority: false,
        },
        FeeOpening {
            fee: 11,
            blind: [F::ONE; FEE_BLIND_LEN],
            dummy: false,
            priority: false,
        },
        FeeOpening {
            fee: 40,
            blind: [F::ONE; FEE_BLIND_LEN],
            dummy: false,
            priority: false,
        },
    ] {
        let (policy, mut witness) = sample(RewardMode::Voyager, &[10]);
        witness.slots[0] = SettlementSlot::from_opening(&h, opening);
        witness.fee_note.value = witness.slots[0].opening.fee;
        assert!(witness.validate(&policy).is_err());
    }
    let (policy, mut witness) = sample(RewardMode::Voyager, &[10]);
    witness.slots[0].commitment[0] += F::ONE;
    assert!(witness.validate(&policy).is_err());
}

#[test]
fn duplicate_commitments_and_unbounded_capacity_are_rejected() {
    let (policy, mut witness) = sample(RewardMode::Voyager, &[10, 10]);
    witness.slots[1] = witness.slots[0].clone();
    assert!(witness.validate(&policy).is_err());
    let (mut policy, witness) = sample(RewardMode::Voyager, &[10]);
    policy.max_slots = 0;
    assert!(witness.validate(&policy).is_err());
}

#[test]
fn reward_schedule_and_asset_cannot_be_substituted() {
    let (policy, mut witness) = sample(RewardMode::Holder, &[10]);
    witness.rewards[1].unlock_height -= 1;
    assert!(witness.validate(&policy).is_err());
    let (policy, mut witness) = sample(RewardMode::Voyager, &[10]);
    witness.fee_note.asset_id.0[0] ^= 1;
    assert!(witness.validate(&policy).is_err());
}

#[test]
fn fee_sum_overflow_is_rejected() {
    let (mut policy, mut witness) = sample(RewardMode::Voyager, &[0, 0]);
    policy.fees = FeeSchedule::from_previous_standard(u64::MAX).unwrap();
    for (i, slot) in witness.slots.iter_mut().enumerate() {
        *slot = SettlementSlot::from_opening(
            &Hasher::new(),
            FeeOpening {
                fee: policy.fees.priority(),
                blind: [F::from_usize(i + 1); FEE_BLIND_LEN],
                dummy: false,
                priority: true,
            },
        );
    }
    // Three maximum priority fees exceed u64; append a separately blinded slot.
    witness.slots.push(SettlementSlot::from_opening(
        &Hasher::new(),
        FeeOpening {
            fee: policy.fees.priority(),
            blind: [F::from_u32(3); FEE_BLIND_LEN],
            dummy: false,
            priority: true,
        },
    ));
    assert!(witness.validate(&policy).is_err());
}
