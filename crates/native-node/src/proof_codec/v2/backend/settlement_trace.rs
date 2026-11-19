//! Trace construction for the unchanged retained settlement AIR.
use ::native::air::{LinearLayers, P2, p2_constants};
use ::native::multi_asset::{self as common, F, Hasher, LIMB_BITS, LIMBS, WIDTH};
use ::native::settlement::{FixedSettlementWitness, SettlementAir};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
const REWARD_ROWS: usize = 6;
const FEE: usize = P2;
const BLIND: usize = FEE + LIMBS;
const SUM: usize = BLIND + common::FEE_BLIND_LEN;
const SUM_CARRY: usize = SUM + LIMBS;
const REWARD_CARRY: usize = SUM_CARRY + LIMBS - 1;
const RANGE_BITS: usize = REWARD_CARRY + LIMBS - 1;
const IMMEDIATE_AMOUNT: usize = RANGE_BITS + LIMBS * LIMB_BITS;
const IMMEDIATE_BITS: usize = IMMEDIATE_AMOUNT + LIMBS;
const NOTE_AMOUNT: usize = IMMEDIATE_BITS + LIMBS * LIMB_BITS;
const NOTE_BITS: usize = NOTE_AMOUNT + LIMBS;
const OWNER: usize = NOTE_BITS + LIMBS * LIMB_BITS;
const RSEED: usize = OWNER + common::DIGEST;
const RHO: usize = RSEED + common::DIGEST;
const UNLOCK: usize = RHO + common::DIGEST;
const UNLOCK_BITS: usize = UNLOCK + LIMBS;
const ASSET: usize = UNLOCK_BITS + LIMBS * LIMB_BITS;
const MAIN_WIDTH: usize = ASSET + 16;
fn put_bits(rows: &mut [F], offset: usize, start: usize, bits: usize, value: u64) {
    let limbs = common::limbs(value);
    rows[offset + start..offset + start + LIMBS].copy_from_slice(&limbs);
    for k in 0..LIMBS {
        for bit in 0..LIMB_BITS {
            rows[offset + bits + k * LIMB_BITS + bit] =
                F::from_u32((limbs[k].as_canonical_u32() >> bit) & 1);
        }
    }
}
pub(super) fn generate(
    air: &SettlementAir,
    w: &FixedSettlementWitness,
) -> (RowMajorMatrix<F>, Vec<F>) {
    let h = Hasher::new();
    let mut inputs = vec![[F::ZERO; WIDTH]; air.height];
    let mut rows = F::zero_vec(air.height * MAIN_WIDTH);
    let mut sum = 0u64;
    for (r, input) in inputs.iter_mut().enumerate().take(air.capacity) {
        let off = r * MAIN_WIDTH;
        let slot = &w.slots[r];
        *input = Hasher::first_input(
            common::TAG_FEE,
            1,
            &common::fee_block(slot.opening.fee, &slot.opening.blind),
        );
        put_bits(&mut rows, off, FEE, RANGE_BITS, slot.opening.fee);
        rows[off + BLIND..off + BLIND + common::FEE_BLIND_LEN].copy_from_slice(&slot.opening.blind);
        sum = sum.checked_add(slot.opening.fee).expect("fee sum overflow");
        let limbs = common::limbs(sum);
        rows[off + SUM..off + SUM + LIMBS].copy_from_slice(&limbs);
        if r + 1 < air.capacity {
            let next = common::limbs(w.slots[r + 1].opening.fee);
            let mut carry = 0u64;
            for k in 0..LIMBS - 1 {
                carry = (u64::from(limbs[k].as_canonical_u32())
                    + u64::from(next[k].as_canonical_u32())
                    + carry)
                    >> LIMB_BITS;
                rows[off + SUM_CARRY + k] = F::from_u64(carry);
            }
        }
    }
    for r in 0..air.height {
        put_bits(
            &mut rows,
            r * MAIN_WIDTH,
            IMMEDIATE_AMOUNT,
            IMMEDIATE_BITS,
            w.rewards[0].amount,
        );
    }
    let final_off = (air.capacity - 1) * MAIN_WIDTH;
    let total = common::limbs(sum);
    let base = common::limbs(w.plan.allocations[0].amount);
    let mut carry = 0u64;
    for k in 0..LIMBS - 1 {
        carry = (u64::from(total[k].as_canonical_u32())
            + u64::from(base[k].as_canonical_u32())
            + carry)
            >> LIMB_BITS;
        rows[final_off + REWARD_CARRY + k] = F::from_u64(carry);
    }
    for i in 0..w.rewards.len() {
        let note = w.reward_note(i);
        let row = air.capacity + i * REWARD_ROWS;
        let mut block = common::padded_block(&common::limbs(w.plan.block_height));
        block[LIMBS] = F::from_usize(i);
        inputs[row] = Hasher::first_input(common::TAG_MINER_RHO, 1, &block);
        let (note_inputs, _) = h.sponge_trace(common::TAG_NOTE, &note.blocks());
        inputs[row + 1..row + 6].copy_from_slice(&note_inputs);
        for r in row..row + REWARD_ROWS {
            let off = r * MAIN_WIDTH;
            put_bits(&mut rows, off, NOTE_AMOUNT, NOTE_BITS, note.value);
            put_bits(&mut rows, off, UNLOCK, UNLOCK_BITS, note.unlock_height);
            rows[off + OWNER..off + OWNER + common::DIGEST].copy_from_slice(&note.owner);
            rows[off + RSEED..off + RSEED + common::DIGEST].copy_from_slice(&note.rseed);
            rows[off + RHO..off + RHO + common::DIGEST].copy_from_slice(&note.rho);
            rows[off + ASSET..off + ASSET + 16].copy_from_slice(&note.asset_id.limbs());
        }
    }
    let p2 = p3_poseidon2_air::generate_trace_rows::<F, LinearLayers, WIDTH, 3, 0, 4, 23>(
        inputs,
        &p2_constants(),
        0,
    );
    for r in 0..air.height {
        rows[r * MAIN_WIDTH..r * MAIN_WIDTH + P2].copy_from_slice(&p2.values[r * P2..(r + 1) * P2]);
    }
    (RowMajorMatrix::new(rows, MAIN_WIDTH), w.public_inputs())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn moved_trace_satisfies_both_retained_reward_modes_and_binds_context() {
        use ::native::settlement::{RewardMode, context_offset, sample_fixed_settlement_witness};
        for mode in [RewardMode::Voyager, RewardMode::Holder] {
            let witness = sample_fixed_settlement_witness(4, mode);
            let air = SettlementAir::new(4).with_min_height(128);
            let (trace, mut public) = generate(&air, &witness);
            assert!(
                p3_air::check_all_constraints(&air, &trace, &public, Some(1))
                    .failures
                    .is_empty()
            );
            public[context_offset(4)] += F::ONE;
            assert!(
                !p3_air::check_all_constraints(&air, &trace, &public, Some(1))
                    .failures
                    .is_empty()
            );
        }
    }
}
