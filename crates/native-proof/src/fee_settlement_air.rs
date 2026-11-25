//! Fixed-capacity confidential-fee settlement AIR and native prover.
//!
//! This is an evaluation implementation. It proves one fee-opening row per
//! fixed slot and binds the private limb-wise sum to a miner note commitment.
//! Block context is authenticated through the public Fiat--Shamir transcript.
//! It does not
//! activate Scheme B on the node or consensus path.

use crate::air::{LinearLayers, P2, p2_constants};
use crate::common::{self, F, Hasher, LIMB_BITS, LIMBS, RATE, WIDTH};
use crate::fee_settlement::{SettlementError, SettlementSlot};
use crate::{Cfg, FriParams};
use p3_air::check_all_constraints;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::Poseidon2Air;
use p3_uni_stark::SubAirBuilder;
use p3_uni_stark::{
    PreprocessedProverData, PreprocessedVerifierKey, Proof, prove_with_preprocessed,
    setup_preprocessed, verify_with_preprocessed,
};

pub type FeeP2Air = Poseidon2Air<F, LinearLayers, WIDTH, 3, 0, 4, 23>;
const P2_OUT: usize = P2 - WIDTH;
const FEE: usize = P2;
const BLIND: usize = FEE + LIMBS;
const SUM: usize = BLIND + common::FEE_BLIND_LEN;
// Carry columns start after the complete limb group.  Keeping the starts
// disjoint is essential: the final limb is a value, not a carry witness.
const SUM_CARRY: usize = SUM + LIMBS;
const REWARD_CARRY: usize = SUM_CARRY + (LIMBS - 1);
const RANGE_BITS: usize = REWARD_CARRY + (LIMBS - 1);
const MINER_AMOUNT: usize = RANGE_BITS + LIMBS * LIMB_BITS;
const MINER_RANGE: usize = MINER_AMOUNT + LIMBS;
const MINER_OWNER: usize = MINER_RANGE + LIMBS * LIMB_BITS;
const MINER_RSEED: usize = MINER_OWNER + common::DIGEST;
const MINER_RHO: usize = MINER_RSEED + common::DIGEST;
const MINER_UNLOCK: usize = MINER_RHO + common::DIGEST;
const UNLOCK_RANGE: usize = MINER_UNLOCK + LIMBS;
const UNLOCK_CARRY: usize = UNLOCK_RANGE + LIMBS * LIMB_BITS;
const MAIN_WIDTH: usize = UNLOCK_CARRY + LIMBS - 1;

const PRE_ACTIVE: usize = 0;
const PRE_FIRST: usize = 1;
const PRE_LAST: usize = 2;
const PRE_MINER: usize = 3;
const MINER_ROWS: usize = 8;
const PRE_SLOTS: usize = PRE_MINER + MINER_ROWS;

pub const fn public_len(capacity: usize) -> usize {
    capacity * common::DIGEST + 2 * LIMBS + 16 + 16 + common::DIGEST
}

/// Validate public encodings before cryptographic work. The caller must also
/// reconstruct every value from the trusted candidate block, including the
/// ordered transaction/fee list, reward, height and network. This helper does
/// not make a peer-supplied context trustworthy.
pub fn validate_settlement_public(capacity: usize, public: &[F]) -> Result<(), String> {
    if public.len() != public_len(capacity) {
        return Err("invalid settlement public-input length".into());
    }
    let numeric = capacity * common::DIGEST;
    let commitment = numeric + 2 * LIMBS + 32;
    if public[numeric..commitment]
        .iter()
        .any(|x| x.as_canonical_u32() >= (1u32 << LIMB_BITS))
    {
        return Err("noncanonical settlement numeric or context limb".into());
    }
    let height = public[numeric + LIMBS..numeric + 2 * LIMBS]
        .iter()
        .enumerate()
        .fold(0u64, |out, (i, value)| {
            out | ((value.as_canonical_u32() as u64) << (i * LIMB_BITS))
        });
    if height.checked_add(common::COINBASE_MATURITY).is_none() {
        return Err("miner unlock height overflows".into());
    }
    for (i, left) in public[..numeric]
        .as_chunks::<{ common::DIGEST }>()
        .0
        .iter()
        .enumerate()
    {
        if public[..i * common::DIGEST]
            .as_chunks::<{ common::DIGEST }>()
            .0
            .iter()
            .any(|right| left == right)
        {
            return Err("duplicate settlement commitment".into());
        }
    }
    Ok(())
}

fn byte_limbs(bytes: &[u8; 32]) -> [F; 16] {
    core::array::from_fn(|i| {
        F::from_u32(u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]) as u32)
    })
}

/// Witness for a fixed-capacity block. `slots.len()` is the capacity and must
/// include dummy openings for every unused position.
#[derive(Clone, Debug)]
pub struct FixedSettlementWitness {
    pub issuance_reward: u64,
    /// Private reward-note amount. It is never placed in public inputs.
    pub miner_amount: u64,
    pub block_height: u64,
    pub network: [u8; 32],
    pub transaction_list_digest: [u8; 32],
    pub miner_owner: common::Digest,
    pub miner_rseed: common::Digest,
    pub slots: Vec<SettlementSlot>,
}

impl FixedSettlementWitness {
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn public_inputs(&self) -> Vec<F> {
        let mut out = Vec::with_capacity(public_len(self.capacity()));
        for slot in &self.slots {
            out.extend_from_slice(&slot.commitment);
        }
        out.extend_from_slice(&common::limbs(self.issuance_reward));
        out.extend_from_slice(&common::limbs(self.block_height));
        out.extend_from_slice(&byte_limbs(&self.network));
        out.extend_from_slice(&byte_limbs(&self.transaction_list_digest));
        out.extend_from_slice(&Hasher::new().miner_note_cm(
            self.miner_amount,
            self.block_height,
            &self.miner_owner,
            &self.miner_rseed,
        ));
        out
    }

    /// Check the native opening relation before invoking the AIR prover.
    pub fn check(&self, hasher: &Hasher) -> Result<(), SettlementError> {
        self.block_height
            .checked_add(common::COINBASE_MATURITY)
            .ok_or(SettlementError::MinerUnlockOverflow)?;
        if self.slots.is_empty() {
            return Err(SettlementError::EmptySettlement);
        }
        let mut sum = 0u64;
        for (i, slot) in self.slots.iter().enumerate() {
            if self.slots[..i]
                .iter()
                .any(|other| other.commitment == slot.commitment)
            {
                return Err(SettlementError::DuplicateCommitment { index: i });
            }
            if hasher.fee_commit(slot.opening.fee, &slot.opening.blind) != slot.commitment {
                return Err(SettlementError::CommitmentMismatch { index: i });
            }
            sum = sum
                .checked_add(slot.opening.fee)
                .ok_or(SettlementError::FeeSumOverflow)?;
        }
        let expected = self
            .issuance_reward
            .checked_add(sum)
            .ok_or(SettlementError::RewardOverflow)?;
        if expected != self.miner_amount {
            return Err(SettlementError::MinerAmountMismatch {
                expected,
                actual: self.miner_amount,
            });
        }
        Ok(())
    }
}

pub struct SettlementAir {
    pub capacity: usize,
    pub height: usize,
    p2: FeeP2Air,
}

impl SettlementAir {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        let height = (capacity + MINER_ROWS).next_power_of_two();
        Self {
            capacity,
            height,
            p2: FeeP2Air::new(p2_constants()),
        }
    }

    pub fn degree_bits(&self) -> usize {
        self.height.trailing_zeros() as usize
    }
    pub fn main_width(&self) -> usize {
        MAIN_WIDTH
    }
    pub fn preprocessed_width(&self) -> usize {
        PRE_SLOTS + self.capacity
    }

    /// Extract the concrete per-row constraint count for this fixed capacity.
    /// The checker is used only by the evaluation harness; proving and
    /// verification do not execute it.
    pub fn constraint_count(&self, witness: &FixedSettlementWitness) -> usize {
        let (trace, public) = generate_trace(self, witness);
        check_all_constraints(self, &trace, &public, Some(1)).total_constraints_per_row
    }
    pub fn with_min_height(mut self, min_height: usize) -> Self {
        assert!(min_height.is_power_of_two());
        if min_height > self.height {
            self.height = min_height;
        }
        self
    }
    fn slot_selector(&self, i: usize) -> usize {
        PRE_SLOTS + i
    }
}

impl BaseAir<F> for SettlementAir {
    fn width(&self) -> usize {
        MAIN_WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        self.preprocessed_width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let width = self.preprocessed_width();
        let mut values = F::zero_vec(self.height * width);
        for r in 0..self.height {
            let row = &mut values[r * width..(r + 1) * width];
            if r < self.capacity {
                row[PRE_ACTIVE] = F::ONE;
                row[self.slot_selector(r)] = F::ONE;
            }
            if r == 0 {
                row[PRE_FIRST] = F::ONE;
            }
            if r + 1 == self.capacity {
                row[PRE_LAST] = F::ONE;
            }
            if (self.capacity..self.capacity + MINER_ROWS).contains(&r) {
                row[PRE_MINER + r - self.capacity] = F::ONE;
            }
        }
        Some(RowMajorMatrix::new(values, width))
    }
    fn num_public_values(&self) -> usize {
        public_len(self.capacity)
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for SettlementAir {
    fn eval(&self, b: &mut AB) {
        let mut sub = SubAirBuilder::<AB, FeeP2Air, AB::Var>::new(b, 0..P2);
        self.p2.eval(&mut sub);

        let main = b.main();
        let pre = b.preprocessed().clone();
        let pis: Vec<AB::PublicVar> = b.public_values().to_vec();
        let l = main.current_slice();
        let n = main.next_slice();
        let pl = pre.current_slice();
        let x = |v: AB::Var| -> AB::Expr { v.into() };
        let active = x(pl[PRE_ACTIVE]);
        let first = x(pl[PRE_FIRST]);
        let last = x(pl[PRE_LAST]);

        // One rate block contains four fee limbs and eight independent blinding elements.
        for e in 0..RATE {
            let expected = if e < LIMBS {
                x(l[FEE + e])
            } else if e < LIMBS + common::FEE_BLIND_LEN {
                x(l[BLIND + e - LIMBS])
            } else {
                AB::Expr::ZERO
            };
            b.assert_zero((x(l[e]) - expected) * active.clone());
        }
        b.assert_zero((x(l[RATE]) - F::from_u32(common::TAG_FEE)) * active.clone());
        b.assert_zero((x(l[RATE + 1]) - F::ONE) * active.clone());
        for e in RATE + 2..WIDTH {
            b.assert_zero(x(l[e]) * active.clone());
        }

        // Bind each permutation digest to the corresponding public commitment.
        for i in 0..self.capacity {
            let selector = x(pl[self.slot_selector(i)]);
            for e in 0..common::DIGEST {
                b.assert_zero(
                    (x(l[P2_OUT + e]) - pis[i * common::DIGEST + e].into()) * selector.clone(),
                );
            }
        }

        let base_offset = self.capacity * common::DIGEST;
        for k in 0..LIMBS {
            for q in 0..LIMB_BITS {
                b.assert_bool(l[RANGE_BITS + k * LIMB_BITS + q]);
            }
            let mut limb = AB::Expr::ZERO;
            for q in 0..LIMB_BITS {
                limb += x(l[RANGE_BITS + k * LIMB_BITS + q]) * F::from_u32(1 << q);
            }
            b.assert_eq(limb, l[FEE + k]);
        }

        // Running sum. A current row stores the sum after its own fee.
        // The transition is constrained only while both rows are real slots.
        for k in 0..LIMBS {
            if k + 1 < LIMBS {
                b.assert_bool(l[SUM_CARRY + k]);
            }
            let carry = if k + 1 < LIMBS {
                x(l[SUM_CARRY + k])
            } else {
                AB::Expr::ZERO
            };
            let prior = if k == 0 {
                AB::Expr::ZERO
            } else {
                x(l[SUM_CARRY + k - 1])
            };
            b.assert_zero(
                (x(l[SUM + k]) + x(n[FEE + k]) + prior
                    - x(n[SUM + k])
                    - carry * F::from_u32(1 << LIMB_BITS))
                    * (active.clone() - last.clone()),
            );
        }
        for k in 0..LIMBS {
            b.assert_zero((x(l[SUM + k]) - x(l[FEE + k])) * first.clone());
        }

        // On the last real row, sum + issuance = miner amount, with checked carries.
        let issuance = base_offset;
        for k in 0..LIMBS {
            if k + 1 < LIMBS {
                b.assert_bool(l[REWARD_CARRY + k]);
            }
            let prior = if k == 0 {
                AB::Expr::ZERO
            } else {
                x(l[REWARD_CARRY + k - 1])
            };
            let carry = if k + 1 < LIMBS {
                x(l[REWARD_CARRY + k])
            } else {
                AB::Expr::ZERO
            };
            b.assert_zero(
                (x(l[SUM + k]) + pis[issuance + k].into() + prior
                    - x(l[MINER_AMOUNT + k])
                    - carry * F::from_u32(1 << LIMB_BITS))
                    * last.clone(),
            );
        }

        // The payout opening remains private and is copied through the entire
        // trace. Numeric limbs are range-checked independently of fee limbs.
        for column in MINER_AMOUNT..UNLOCK_RANGE {
            b.when_transition().assert_eq(l[column], n[column]);
        }
        for (start, bits) in [(MINER_AMOUNT, MINER_RANGE), (MINER_UNLOCK, UNLOCK_RANGE)] {
            for k in 0..LIMBS {
                let mut value = AB::Expr::ZERO;
                for q in 0..LIMB_BITS {
                    b.assert_bool(l[bits + k * LIMB_BITS + q]);
                    value += x(l[bits + k * LIMB_BITS + q]) * F::from_u32(1 << q);
                }
                b.assert_eq(value, l[start + k]);
            }
        }
        let height = base_offset + LIMBS;
        let maturity = common::limbs(common::COINBASE_MATURITY);
        for k in 0..LIMBS {
            let previous = if k == 0 {
                AB::Expr::ZERO
            } else {
                x(l[UNLOCK_CARRY + k - 1])
            };
            let carry = if k + 1 == LIMBS {
                AB::Expr::ZERO
            } else {
                b.assert_bool(l[UNLOCK_CARRY + k]);
                x(l[UNLOCK_CARRY + k])
            };
            b.assert_zero(
                pis[height + k].into() + maturity[k] + previous
                    - x(l[MINER_UNLOCK + k])
                    - carry * F::from_u32(1 << LIMB_BITS),
            );
        }

        // First tail row: rho = H_miner_rho(height).
        let rho_selector = x(pl[PRE_MINER]);
        for e in 0..RATE {
            let value = if e < LIMBS {
                pis[height + e].into()
            } else {
                AB::Expr::ZERO
            };
            b.assert_zero((x(l[e]) - value) * rho_selector.clone());
        }
        for e in RATE..WIDTH {
            let value = if e == RATE {
                F::from_u32(common::TAG_MINER_RHO)
            } else if e == RATE + 1 {
                F::ONE
            } else {
                F::ZERO
            };
            b.assert_zero((x(l[e]) - value) * rho_selector.clone());
        }
        for e in 0..common::DIGEST {
            b.assert_zero((x(l[P2_OUT + e]) - x(l[MINER_RHO + e])) * rho_selector.clone());
        }

        // Next four rows: the ordinary note commitment, with the amount and
        // rseed hidden. The capacity of each later overwrite block is the
        // preceding permutation output, exactly as Hasher::note_cm specifies.
        for stage in 0..4 {
            let selector = x(pl[PRE_MINER + 1 + stage]);
            for e in 0..RATE {
                let value = match stage {
                    0 => x(l[MINER_OWNER + e]),
                    1 if e < LIMBS => x(l[MINER_AMOUNT + e]),
                    1 if e < 2 * LIMBS => x(l[MINER_UNLOCK + e - LIMBS]),
                    1 => AB::Expr::ZERO,
                    2 => x(l[MINER_RHO + e]),
                    _ => x(l[MINER_RSEED + e]),
                };
                b.assert_zero((x(l[e]) - value) * selector.clone());
            }
            if stage == 0 {
                for e in RATE..WIDTH {
                    let value = if e == RATE {
                        F::from_u32(common::TAG_NOTE)
                    } else if e == RATE + 1 {
                        F::from_u32(4)
                    } else {
                        F::ZERO
                    };
                    b.assert_zero((x(l[e]) - value) * selector.clone());
                }
            }
            if stage < 3 {
                for e in RATE..WIDTH {
                    b.when_transition()
                        .assert_zero((x(n[e]) - x(l[P2_OUT + e])) * selector.clone());
                }
            }
        }
        let miner_commitment = base_offset + 2 * LIMBS + 32;
        for e in 0..common::DIGEST {
            b.assert_zero(
                (x(l[P2_OUT + e]) - pis[miner_commitment + e].into()) * x(pl[PRE_MINER + 4]),
            );
        }
        for stage in 5..MINER_ROWS {
            let selector = x(pl[PRE_MINER + stage]);
            for e in 0..WIDTH {
                b.assert_zero(x(l[e]) * selector.clone());
            }
        }
    }
}

pub struct SettlementProver {
    pub cfg: Cfg,
    pub air: SettlementAir,
    pub pdata: PreprocessedProverData<Cfg>,
    pub vk: PreprocessedVerifierKey<Cfg>,
}

impl SettlementProver {
    pub fn new(capacity: usize, params: FriParams) -> Self {
        let cfg = params.config();
        let air = SettlementAir::new(capacity).with_min_height(params.hiding_min_height());
        let (pdata, vk) = setup_preprocessed(&cfg, &air, air.degree_bits())
            .expect("preprocessed commitment")
            .expect("preprocessed AIR");
        Self {
            cfg,
            air,
            pdata,
            vk,
        }
    }

    pub fn prove(&self, witness: &FixedSettlementWitness) -> (Proof<Cfg>, Vec<F>) {
        assert_eq!(witness.capacity(), self.air.capacity);
        witness
            .check(&Hasher::new())
            .expect("invalid settlement witness");
        let (trace, pis) = generate_trace(&self.air, witness);
        let proof = prove_with_preprocessed(&self.cfg, &self.air, trace, &pis, Some(&self.pdata))
            .expect("settlement proof generation");
        (proof, pis)
    }

    pub fn verify(&self, proof: &Proof<Cfg>, pis: &[F]) -> Result<(), String> {
        validate_settlement_public(self.air.capacity, pis)?;
        verify_with_preprocessed(&self.cfg, &self.air, proof, pis, Some(&self.vk))
            .map_err(|e| format!("{e:?}"))
    }
}

fn generate_trace(
    air: &SettlementAir,
    witness: &FixedSettlementWitness,
) -> (RowMajorMatrix<F>, Vec<F>) {
    let mut inputs = vec![[F::ZERO; WIDTH]; air.height];
    let mut rows = vec![F::ZERO; air.height * MAIN_WIDTH];
    let mut sum = 0u64;
    let mut cumulative = [0u32; LIMBS];
    for r in 0..air.capacity {
        let slot = &witness.slots[r];
        let off = r * MAIN_WIDTH;
        let fee = common::limbs(slot.opening.fee);
        let block = common::fee_block(slot.opening.fee, &slot.opening.blind);
        let mut input = [F::ZERO; WIDTH];
        input[..RATE].copy_from_slice(&block);
        input[RATE] = F::from_u32(common::TAG_FEE);
        input[RATE + 1] = F::ONE;
        inputs[r] = input;
        for k in 0..LIMBS {
            rows[off + FEE + k] = fee[k];
            rows[off + RANGE_BITS + k * LIMB_BITS..off + RANGE_BITS + (k + 1) * LIMB_BITS]
                .copy_from_slice(&std::array::from_fn::<F, LIMB_BITS, _>(|q| {
                    F::from_u32((fee[k].as_canonical_u32() >> q) & 1)
                }));
        }
        rows[off + BLIND..off + BLIND + common::FEE_BLIND_LEN].copy_from_slice(&slot.opening.blind);

        sum = sum.checked_add(slot.opening.fee).expect("sum overflow");
        let sum_limbs = common::limbs(sum);
        for k in 0..LIMBS {
            rows[off + SUM + k] = sum_limbs[k];
        }
        // The carry in row r adds row r+1's fee to the cumulative sum.
        if r + 1 < air.capacity {
            let next_fee = common::limbs(witness.slots[r + 1].opening.fee);
            let mut sc = 0u64;
            for k in 0..LIMBS - 1 {
                sc = (sum_limbs[k].as_canonical_u32() as u64
                    + next_fee[k].as_canonical_u32() as u64
                    + sc)
                    >> LIMB_BITS;
                rows[off + SUM_CARRY + k] = F::from_u64(sc);
            }
        }
        cumulative = sum_limbs.map(|x| x.as_canonical_u32());
    }
    let hasher = Hasher::new();
    let unlock_height = witness
        .block_height
        .checked_add(common::COINBASE_MATURITY)
        .expect("miner unlock height overflow");
    let amount = common::limbs(witness.miner_amount);
    let height = common::limbs(witness.block_height);
    let unlock = common::limbs(unlock_height);
    let (rho_inputs, rho) =
        hasher.sponge_trace(common::TAG_MINER_RHO, &[common::padded_block(&height)]);
    inputs[air.capacity] = rho_inputs[0];
    let note = common::Note {
        owner: witness.miner_owner,
        value: witness.miner_amount,
        unlock_height,
        rho,
        rseed: witness.miner_rseed,
    };
    let (note_inputs, _) = hasher.sponge_trace(common::TAG_NOTE, &note.blocks());
    inputs[air.capacity + 1..air.capacity + 5].copy_from_slice(&note_inputs);
    let maturity = common::limbs(common::COINBASE_MATURITY);
    for r in 0..air.height {
        let off = r * MAIN_WIDTH;
        rows[off + MINER_AMOUNT..off + MINER_AMOUNT + LIMBS].copy_from_slice(&amount);
        rows[off + MINER_OWNER..off + MINER_OWNER + common::DIGEST]
            .copy_from_slice(&witness.miner_owner);
        rows[off + MINER_RSEED..off + MINER_RSEED + common::DIGEST]
            .copy_from_slice(&witness.miner_rseed);
        rows[off + MINER_RHO..off + MINER_RHO + common::DIGEST].copy_from_slice(&rho);
        rows[off + MINER_UNLOCK..off + MINER_UNLOCK + LIMBS].copy_from_slice(&unlock);
        for (limbs, bits) in [(&amount, MINER_RANGE), (&unlock, UNLOCK_RANGE)] {
            for k in 0..LIMBS {
                for q in 0..LIMB_BITS {
                    rows[off + bits + k * LIMB_BITS + q] =
                        F::from_u32((limbs[k].as_canonical_u32() >> q) & 1);
                }
            }
        }
        let mut carry = 0u64;
        for k in 0..LIMBS - 1 {
            carry = (height[k].as_canonical_u32() as u64
                + maturity[k].as_canonical_u32() as u64
                + carry)
                >> LIMB_BITS;
            rows[off + UNLOCK_CARRY + k] = F::from_u64(carry);
        }
    }
    let final_off = (air.capacity - 1) * MAIN_WIDTH;
    let issuance = common::limbs(witness.issuance_reward);
    let mut rc = 0u64;
    for k in 0..LIMBS - 1 {
        rc = (cumulative[k] as u64 + issuance[k].as_canonical_u32() as u64 + rc) >> LIMB_BITS;
        rows[final_off + REWARD_CARRY + k] = F::from_u64(rc);
    }

    let p2 = p3_poseidon2_air::generate_trace_rows::<F, LinearLayers, WIDTH, 3, 0, 4, 23>(
        inputs,
        &p2_constants(),
        0,
    );
    for r in 0..air.height {
        rows[r * MAIN_WIDTH..r * MAIN_WIDTH + P2].copy_from_slice(&p2.values[r * P2..(r + 1) * P2]);
    }
    (
        RowMajorMatrix::new(rows, MAIN_WIDTH),
        witness.public_inputs(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{F, FEE_BASE, Hasher};
    use crate::fee_settlement::FeeOpening;
    use p3_air::check_all_constraints;
    use p3_field::PrimeCharacteristicRing;

    fn blind(seed: u32) -> [F; common::FEE_BLIND_LEN] {
        core::array::from_fn(|i| F::from_u32(seed + i as u32))
    }

    fn witness(capacity: usize) -> FixedSettlementWitness {
        let hasher = Hasher::new();
        let mut slots = Vec::with_capacity(capacity);
        slots.push(SettlementSlot::from_opening(
            &hasher,
            FeeOpening::standard(blind(1)),
        ));
        for i in 1..capacity {
            slots.push(SettlementSlot::from_opening(
                &hasher,
                FeeOpening::dummy(blind(100 + i as u32)),
            ));
        }
        FixedSettlementWitness {
            issuance_reward: 100,
            miner_amount: 100 + FEE_BASE,
            block_height: 1000,
            network: [9; 32],
            transaction_list_digest: [11; 32],
            miner_owner: core::array::from_fn(|i| F::from_u32(800 + i as u32)),
            miner_rseed: core::array::from_fn(|i| F::from_u32(900 + i as u32)),
            slots,
        }
    }

    #[test]
    fn fixed_capacity_trace_satisfies_air() {
        let w = witness(4);
        let air = SettlementAir::new(w.capacity());
        let (trace, pis) = generate_trace(&air, &w);
        let failures = check_all_constraints(&air, &trace, &pis, None).failures;
        assert!(failures.is_empty(), "settlement AIR failures: {failures:?}");
    }

    #[test]
    fn fixed_capacity_proof_round_trip() {
        let w = witness(4);
        let prover = SettlementProver::new(4, FriParams::fast());
        let (proof, pis) = prover.prove(&w);
        prover
            .verify(&proof, &pis)
            .expect("settlement proof verifies");
    }

    #[test]
    fn public_statement_has_one_commitment_per_slot() {
        let w = witness(8);
        assert_eq!(w.public_inputs().len(), public_len(8));
        assert_eq!(w.public_inputs().len(), 8 * crate::common::DIGEST + 52);
    }

    #[test]
    fn native_settlement_proof_verifies_and_binds_reward_statement() {
        let w = witness(4);
        let prover = SettlementProver::new(w.capacity(), crate::FriParams::fast());
        let (proof, public) = prover.prove(&w);
        prover
            .verify(&proof, &public)
            .expect("valid settlement proof");
        let mut changed = public.clone();
        let last = changed.len() - 1;
        changed[last] += F::ONE;
        assert!(prover.verify(&proof, &changed).is_err());
    }

    #[test]
    fn miner_amount_is_private_and_only_changes_public_note_commitment() {
        let w = witness(4);
        let mut changed = w.clone();
        changed.miner_amount += 1;
        let public = w.public_inputs();
        let altered = changed.public_inputs();
        let note = public.len() - common::DIGEST;
        assert_eq!(public[..note], altered[..note]);
        assert_ne!(public[note..], altered[note..]);
        assert_eq!(
            public[note..],
            Hasher::new().miner_note_cm(
                w.miner_amount,
                w.block_height,
                &w.miner_owner,
                &w.miner_rseed
            )
        );
    }

    #[test]
    fn invalid_private_reward_amount_fails_air_constraints() {
        let mut w = witness(4);
        w.miner_amount += 1;
        let air = SettlementAir::new(w.capacity());
        let (trace, public) = generate_trace(&air, &w);
        assert!(
            !check_all_constraints(&air, &trace, &public, None)
                .failures
                .is_empty()
        );
    }

    #[test]
    fn native_proof_binds_all_public_fee_reward_and_context_fields() {
        let w = witness(4);
        let prover = SettlementProver::new(w.capacity(), crate::FriParams::fast());
        let (proof, public) = prover.prove(&w);
        for i in 0..public.len() {
            let mut changed = public.clone();
            changed[i] += F::ONE;
            assert!(prover.verify(&proof, &changed).is_err(), "public field {i}");
        }
    }

    #[test]
    fn public_range_and_maturity_overflow_are_rejected() {
        let w = witness(4);
        let mut public = w.public_inputs();
        public[w.capacity() * common::DIGEST] = F::from_u32(1 << LIMB_BITS);
        assert!(validate_settlement_public(w.capacity(), &public).is_err());
        let mut public = w.public_inputs();
        let height = w.capacity() * common::DIGEST + LIMBS;
        public[height..height + LIMBS].copy_from_slice(&common::limbs(u64::MAX));
        assert!(validate_settlement_public(w.capacity(), &public).is_err());
    }

    #[test]
    fn settlement_accepts_openings_from_different_anchor_fee_schedules() {
        let mut w = witness(4);
        let opening = FeeOpening::for_base_fee(FEE_BASE + 17, false, false, blind(52));
        w.slots[1] = SettlementSlot::from_opening(&Hasher::new(), opening);
        w.miner_amount += FEE_BASE + 17;
        w.check(&Hasher::new())
            .expect("transaction proofs establish each anchored fee tier");
        let air = SettlementAir::new(w.capacity());
        let (trace, public) = generate_trace(&air, &w);
        assert!(
            check_all_constraints(&air, &trace, &public, None)
                .failures
                .is_empty()
        );
    }

    #[test]
    fn symbolic_constraint_degree_is_extracted_from_the_complete_relation() {
        use p3_air::symbolic::{AirLayout, get_max_constraint_degree};
        let air = SettlementAir::new(576);
        let mut layout = AirLayout::from_air(&air);
        layout.preprocessed_width = air.preprocessed_width();
        assert_eq!(
            get_max_constraint_degree::<F, _>(&air, layout, air.height),
            3
        );
    }
}
