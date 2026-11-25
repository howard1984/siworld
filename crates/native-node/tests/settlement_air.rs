use native::{
    FriParams,
    confidential_fees::{FeeOpening, SettlementSlot},
    multi_asset::{F, FEE_BLIND_LEN, Hasher, Note, SIP_ASSET_ID},
    settlement::{RewardAllocation, RewardMode, RewardPlan},
};
use p3_field::PrimeCharacteristicRing;
use siworld_native_node::{
    eng2_settlement::{FeeSchedule, PrivateSettlement, SettlementPolicy},
    eng2_settlement_air::{
        SettlementProverV2, SettlementWitnessV2, fee_commitment_offset, fee_owner_offset,
        profile_offset, public_len, validate_settlement_public_v2,
    },
};

fn fixture(mode: RewardMode, padding_only: bool) -> SettlementWitnessV2 {
    let h = Hasher::new();
    let owner = [F::from_u32(71); 12];
    let fees = FeeSchedule::from_previous_standard(100).unwrap();
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
    let slot_fees = if padding_only {
        [0, 0, 0, 0]
    } else {
        [10, 0, 40, 10]
    };
    let slots = slot_fees
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
            owner: [F::from_u32(80); 12],
            value: a.amount,
            unlock_height: a.unlock_height,
            rho: h.reward_rho(plan.block_height, i),
            rseed: [F::from_usize(i + 10); 12],
        })
        .collect();
    SettlementWitnessV2 {
        policy: SettlementPolicy {
            plan,
            fee_owner: owner,
            fees,
            max_slots: 4,
        },
        network: [9; 32],
        transaction_list_digest: [11; 32],
        fee_destination_digest: [12; 32],
        settlement: PrivateSettlement {
            rewards,
            fee_note: Note {
                asset_id: SIP_ASSET_ID,
                owner,
                value: slot_fees.iter().sum(),
                unlock_height: 0,
                rho: [F::from_u32(91); 12],
                rseed: [F::from_u32(92); 12],
            },
            slots,
        },
    }
}

#[test]
fn actual_v2_proofs_bind_all_public_fields_in_both_reward_modes() {
    let prover = SettlementProverV2::new(4, FriParams::fast());
    for mode in [RewardMode::Voyager, RewardMode::Holder] {
        let witness = fixture(mode, false);
        let (proof, public) = prover.prove(&witness).unwrap();
        assert_eq!(public.len(), public_len(4));
        prover.verify(&proof, &public).unwrap();
        for i in 0..public.len() {
            let mut changed = public.clone();
            changed[i] += F::ONE;
            assert!(prover.verify(&proof, &changed).is_err(), "public field {i}");
        }
    }
}

#[test]
fn zero_fee_output_is_still_proven_and_profile_is_versioned() {
    let prover = SettlementProverV2::new(4, FriParams::fast());
    let witness = fixture(RewardMode::Voyager, true);
    let (proof, public) = prover.prove(&witness).unwrap();
    prover.verify(&proof, &public).unwrap();
    assert!(
        public[fee_commitment_offset(4)..]
            .iter()
            .any(|x| *x != F::ZERO)
    );
    let mut missing = public.clone();
    missing[fee_commitment_offset(4)..].fill(F::ZERO);
    assert!(validate_settlement_public_v2(4, &missing).is_err());
    let mut old = public.clone();
    old[profile_offset(4)] = F::ONE;
    assert!(prover.verify(&proof, &old).is_err());
    let mut redirected = public;
    redirected[fee_owner_offset(4)] += F::ONE;
    assert!(prover.verify(&proof, &redirected).is_err());
}

#[test]
fn prover_rejects_fee_theft_bad_tiers_and_capacity_before_proving() {
    let prover = SettlementProverV2::new(4, FriParams::fast());
    let mut witness = fixture(RewardMode::Holder, false);
    witness.settlement.rewards[0].value += 60;
    witness.settlement.fee_note.value = 0;
    assert!(prover.prove(&witness).is_err());
    let mut witness = fixture(RewardMode::Holder, false);
    witness.settlement.slots[0].opening.priority = true;
    assert!(prover.prove(&witness).is_err());
    let mut witness = fixture(RewardMode::Holder, false);
    witness.settlement.slots.pop();
    assert!(prover.prove(&witness).is_err());
}

#[test]
fn full_576_slot_shape_proves_with_the_same_fixed_output_count() {
    let mut witness = fixture(RewardMode::Holder, false);
    let h = Hasher::new();
    for i in 4..576 {
        witness.settlement.slots.push(SettlementSlot::from_opening(
            &h,
            FeeOpening {
                fee: 0,
                blind: [F::from_usize(i + 1); FEE_BLIND_LEN],
                dummy: true,
                priority: false,
            },
        ));
    }
    witness.policy.max_slots = 576;
    let prover = SettlementProverV2::new(576, FriParams::fast());
    let (proof, public) = prover.prove(&witness).unwrap();
    assert_eq!(public.len(), public_len(576));
    assert_eq!(prover.air.capacity, 576);
    assert_eq!(prover.air.height, 1024);
    prover.verify(&proof, &public).unwrap();
}
