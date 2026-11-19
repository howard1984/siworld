//! Inactive fee-local V1-compatible relation for already proved historical fees.
//!
//! The verifier must reconstruct this statement from authenticated block state,
//! including the complete canonical destination-address digest and its owner.
//! The always-present fee note receives the private sum; reward notes receive
//! exactly the subsidy/Holder allocations. Neither the sum nor padding flags
//! occur in public inputs. Ciphertext correctness is not proved by this AIR.
use super::policy::{MAX_SETTLEMENT_SLOTS, SettlementPolicy};
use ::native::air::{LinearLayers, P2, p2_constants};
use ::native::multi_asset::{
    self as common, F, Hasher, LIMB_BITS, LIMBS, RATE, SIP_ASSET_ID, WIDTH,
};
use ::native::settlement::{FeeP2Air, MAX_REWARD_NOTES};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SubAirBuilder;

/// This relation revision is distinct from the global-feature fee-local V4 relation.
pub const FEE_LOCAL_SETTLEMENT_REVISION: u32 = 4;
pub const LEGACY_FEE_BLIND_FIELDS: usize = 8;
pub const LEGACY_FEE_TAG: u32 = 136;

/// An exact historical V1 opening, independent of native privacy feature flags.
pub struct LegacyFeeOpening {
    pub fee: u64,
    pub blind: [F; LEGACY_FEE_BLIND_FIELDS],
}
pub struct LegacySettlementSlot {
    pub commitment: common::Digest,
    pub opening: LegacyFeeOpening,
}
pub struct LegacyPrivateSettlement {
    pub rewards: Vec<common::Note>,
    pub fee_note: common::Note,
    pub slots: Vec<LegacySettlementSlot>,
}
fn legacy_fee_block(fee: u64, blind: &[F; LEGACY_FEE_BLIND_FIELDS]) -> common::Block {
    let mut block = [F::ZERO; RATE];
    block[..4].copy_from_slice(&common::limbs(fee));
    block[4..].copy_from_slice(blind);
    block
}
pub fn legacy_fee_commit(
    hasher: &Hasher,
    fee: u64,
    blind: &[F; LEGACY_FEE_BLIND_FIELDS],
) -> common::Digest {
    hasher.sponge(LEGACY_FEE_TAG, &[legacy_fee_block(fee, blind)])
}
// Fail at compile time if a future shared field/permutation layout changes.
const _: () =
    assert!(LIMBS == 4 && LIMB_BITS == 16 && RATE == 12 && WIDTH == 24 && common::DIGEST == 12);
const OUTPUT_SLOTS: usize = MAX_REWARD_NOTES + 1;
pub(crate) const NOTE_ROWS: usize = 6;

/// Private openings only; individual fee validity comes from the exact native
/// transaction proofs. Legacy sidecar tier/dummy labels have no authority here.
pub struct FeeLocalSumWitness {
    pub policy: SettlementPolicy,
    pub network: [u8; 32],
    pub transaction_list_digest: [u8; 32],
    pub fee_destination_digest: [u8; 32],
    pub settlement: LegacyPrivateSettlement,
}
impl FeeLocalSumWitness {
    pub fn public_inputs(&self) -> Result<Vec<F>, String> {
        let h = Hasher::new();
        fee_local_settlement_public_v4(
            &self.policy,
            self.network,
            self.transaction_list_digest,
            self.fee_destination_digest,
            &self
                .settlement
                .slots
                .iter()
                .map(|s| s.commitment)
                .collect::<Vec<_>>(),
            &self
                .settlement
                .rewards
                .iter()
                .map(|n| h.note_cm(n))
                .collect::<Vec<_>>(),
            h.note_cm(&self.settlement.fee_note),
        )
    }
    pub fn validate(&self) -> Result<(), String> {
        validate_openings(&self.settlement, &self.policy)
    }
}

pub const fn profile_offset(capacity: usize) -> usize {
    capacity * common::DIGEST
}
pub const fn fee_owner_offset(capacity: usize) -> usize {
    profile_offset(capacity) + 1
}
pub const fn fee_destination_offset(capacity: usize) -> usize {
    fee_owner_offset(capacity) + common::DIGEST
}
pub const fn fee_schedule_offset(capacity: usize) -> usize {
    fee_destination_offset(capacity) + 16
}
pub const fn context_offset(capacity: usize) -> usize {
    fee_schedule_offset(capacity) + 2 * LIMBS
}
pub const fn reward_mode_offset(capacity: usize) -> usize {
    context_offset(capacity) + LIMBS
}
pub const fn reward_allocations_offset(capacity: usize) -> usize {
    reward_mode_offset(capacity) + 2 + 32
}
pub const fn reward_commitments_offset(capacity: usize) -> usize {
    reward_allocations_offset(capacity) + MAX_REWARD_NOTES * 2 * LIMBS
}
pub const fn fee_commitment_offset(capacity: usize) -> usize {
    reward_commitments_offset(capacity) + MAX_REWARD_NOTES * common::DIGEST
}
pub const fn public_len(capacity: usize) -> usize {
    fee_commitment_offset(capacity) + common::DIGEST
}

fn byte_limbs(bytes: &[u8; 32]) -> [F; 16] {
    core::array::from_fn(|i| {
        F::from_u32(u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]) as u32)
    })
}

/// Reconstruct from trusted state and the ordered block commitments. A peer's
/// serialized public statement is not a source for policy or destination data.
pub fn fee_local_settlement_public_v4(
    policy: &SettlementPolicy,
    network: [u8; 32],
    list_hash: [u8; 32],
    fee_destination_digest: [u8; 32],
    fees: &[common::Digest],
    rewards: &[common::Digest],
    fee_note: common::Digest,
) -> Result<Vec<F>, String> {
    policy.plan.validate()?;
    if !(1..=MAX_SETTLEMENT_SLOTS).contains(&policy.max_slots)
        || fees.is_empty()
        || fees.len() > policy.max_slots
        || rewards.len() != policy.plan.mode.note_count()
    {
        return Err("invalid fee-local V4 settlement capacity or reward count".into());
    }
    let mut out = Vec::with_capacity(public_len(fees.len()));
    for commitment in fees {
        out.extend_from_slice(commitment);
    }
    out.push(F::from_u32(FEE_LOCAL_SETTLEMENT_REVISION));
    out.extend_from_slice(&policy.fee_owner);
    out.extend_from_slice(&byte_limbs(&fee_destination_digest));
    out.extend_from_slice(&common::limbs(policy.fees.standard()));
    out.extend_from_slice(&common::limbs(policy.fees.priority()));
    out.extend_from_slice(&common::limbs(policy.plan.block_height));
    out.push(F::from_u32(policy.plan.mode as u32));
    out.push(F::from_usize(policy.plan.mode.note_count()));
    out.extend_from_slice(&byte_limbs(&network));
    out.extend_from_slice(&byte_limbs(&list_hash));
    for i in 0..MAX_REWARD_NOTES {
        if let Some(a) = policy.plan.allocations.get(i) {
            out.extend_from_slice(&common::limbs(a.amount));
            out.extend_from_slice(&common::limbs(a.unlock_height));
        } else {
            out.extend_from_slice(&[F::ZERO; 2 * LIMBS]);
        }
    }
    for i in 0..MAX_REWARD_NOTES {
        out.extend_from_slice(rewards.get(i).unwrap_or(&[F::ZERO; common::DIGEST]));
    }
    out.extend_from_slice(&fee_note);
    validate_fee_local_settlement_public_v4(fees.len(), &out)?;
    Ok(out)
}

pub fn validate_fee_local_settlement_public_v4(
    capacity: usize,
    public: &[F],
) -> Result<(), String> {
    if !(1..=MAX_SETTLEMENT_SLOTS).contains(&capacity) || public.len() != public_len(capacity) {
        return Err("invalid fee-local V4 settlement public-input length".into());
    }
    if public[profile_offset(capacity)] != F::from_u32(FEE_LOCAL_SETTLEMENT_REVISION) {
        return Err("invalid fee-local V4 settlement profile".into());
    }
    if public[fee_destination_offset(capacity)..reward_commitments_offset(capacity)]
        .iter()
        .any(|x| x.as_canonical_u32() >= (1 << LIMB_BITS))
    {
        return Err("noncanonical fee-local V4 settlement numeric or context limb".into());
    }
    let integer = |offset: usize| {
        (0..LIMBS).fold(0u64, |a, k| {
            a | ((public[offset + k].as_canonical_u32() as u64) << (k * LIMB_BITS))
        })
    };
    if integer(fee_schedule_offset(capacity)).checked_mul(4)
        != Some(integer(fee_schedule_offset(capacity) + LIMBS))
    {
        return Err("invalid fee-local V4 fee schedule".into());
    }
    let mode = public[reward_mode_offset(capacity)].as_canonical_u32();
    let count = match mode {
        0 => 1,
        1 => 5,
        _ => return Err("invalid fee-local V4 reward mode".into()),
    };
    if public[reward_mode_offset(capacity) + 1].as_canonical_u32() as usize != count {
        return Err("fee-local V4 reward count differs from mode".into());
    }
    let height = integer(context_offset(capacity));
    let mut outputs = Vec::with_capacity(OUTPUT_SLOTS);
    for i in 0..MAX_REWARD_NOTES {
        let allocation = reward_allocations_offset(capacity) + i * 2 * LIMBS;
        let cm = reward_commitments_offset(capacity) + i * common::DIGEST;
        if i < count {
            if integer(allocation + LIMBS) < height {
                return Err("fee-local V4 reward unlock precedes block".into());
            }
            outputs.push(&public[cm..cm + common::DIGEST]);
        } else if public[allocation..allocation + 2 * LIMBS]
            .iter()
            .chain(&public[cm..cm + common::DIGEST])
            .any(|x| *x != F::ZERO)
        {
            return Err("noncanonical inactive fee-local V4 reward slot".into());
        }
    }
    outputs.push(&public[fee_commitment_offset(capacity)..]);
    for (i, cm) in outputs.iter().enumerate() {
        if cm.iter().all(|x| *x == F::ZERO) || outputs[..i].contains(cm) {
            return Err("zero or duplicate fee-local V4 output commitment".into());
        }
    }
    for i in 0..capacity {
        let cm = &public[i * common::DIGEST..(i + 1) * common::DIGEST];
        if (0..i).any(|j| &public[j * common::DIGEST..(j + 1) * common::DIGEST] == cm) {
            return Err("duplicate fee-local V4 fee commitment".into());
        }
    }
    Ok(())
}

const P2_OUT: usize = P2 - WIDTH;
const FEE: usize = P2;
const FEE_BITS: usize = FEE + LIMBS;
const BLIND: usize = FEE_BITS + LIMBS * LIMB_BITS;
const SUM: usize = BLIND + LEGACY_FEE_BLIND_FIELDS;
const SUM_BITS: usize = SUM + LIMBS;
const SUM_CARRY: usize = SUM_BITS + LIMBS * LIMB_BITS;
const TOTAL: usize = SUM_CARRY + LIMBS - 1;
const TOTAL_BITS: usize = TOTAL + LIMBS;
const DUMMY: usize = TOTAL_BITS + LIMBS * LIMB_BITS;
const PRIORITY: usize = DUMMY + 1;
const NONZERO_INV: usize = PRIORITY + 1;
pub(crate) const NOTE_AMOUNT: usize = NONZERO_INV + 1;
const NOTE_BITS: usize = NOTE_AMOUNT + LIMBS;
pub(crate) const OWNER: usize = NOTE_BITS + LIMBS * LIMB_BITS;
pub(crate) const RSEED: usize = OWNER + common::DIGEST;
pub(crate) const RHO: usize = RSEED + common::DIGEST;
const UNLOCK: usize = RHO + common::DIGEST;
const UNLOCK_BITS: usize = UNLOCK + LIMBS;
const ASSET: usize = UNLOCK_BITS + LIMBS * LIMB_BITS;
pub(crate) const MAIN_WIDTH: usize = ASSET + 16;
const PRE_ACTIVE: usize = 0;
const PRE_FIRST: usize = 1;
const PRE_LAST: usize = 2;
pub(crate) const PRE_NOTES: usize = 3;
const PRE_SLOTS: usize = PRE_NOTES + OUTPUT_SLOTS * NOTE_ROWS;

pub struct FeeLocalSumAir {
    pub capacity: usize,
    pub height: usize,
    p2: FeeP2Air,
}
impl FeeLocalSumAir {
    pub fn new(capacity: usize) -> Self {
        assert!((1..=MAX_SETTLEMENT_SLOTS).contains(&capacity));
        Self {
            capacity,
            height: (capacity + OUTPUT_SLOTS * NOTE_ROWS).next_power_of_two(),
            p2: FeeP2Air::new(p2_constants()),
        }
    }
    pub fn with_min_height(mut self, height: usize) -> Self {
        assert!(height.is_power_of_two());
        self.height = self.height.max(height);
        self
    }
    fn note_selector(&self, index: usize, stage: usize) -> usize {
        PRE_NOTES + index * NOTE_ROWS + stage
    }
    fn slot_selector(&self, index: usize) -> usize {
        PRE_SLOTS + index
    }
}
impl BaseAir<F> for FeeLocalSumAir {
    fn width(&self) -> usize {
        MAIN_WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        PRE_SLOTS + self.capacity
    }
    fn num_public_values(&self) -> usize {
        public_len(self.capacity)
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let width = self.preprocessed_width();
        let mut values = F::zero_vec(self.height * width);
        for r in 0..self.capacity {
            values[r * width + PRE_ACTIVE] = F::ONE;
            values[r * width + self.slot_selector(r)] = F::ONE;
        }
        values[PRE_FIRST] = F::ONE;
        values[(self.capacity - 1) * width + PRE_LAST] = F::ONE;
        for i in 0..OUTPUT_SLOTS {
            for stage in 0..NOTE_ROWS {
                values[(self.capacity + i * NOTE_ROWS + stage) * width
                    + self.note_selector(i, stage)] = F::ONE;
            }
        }
        Some(RowMajorMatrix::new(values, width))
    }
}
impl<AB: AirBuilder<F = F>> Air<AB> for FeeLocalSumAir {
    fn eval(&self, b: &mut AB) {
        self.eval_at(b, 0, 0, 0);
    }
}
impl FeeLocalSumAir {
    pub(crate) fn eval_at<AB: AirBuilder<F = F>>(
        &self,
        b: &mut AB,
        main_offset: usize,
        pre_offset: usize,
        public_offset: usize,
    ) {
        let mut sub = SubAirBuilder::<AB, FeeP2Air, AB::Var>::new(b, main_offset..main_offset + P2);
        self.p2.eval(&mut sub);
        let main = b.main();
        let pre = b.preprocessed().clone();
        let l = &main.current_slice()[main_offset..];
        let n = &main.next_slice()[main_offset..];
        let pl = &pre.current_slice()[pre_offset..];
        let pis = b.public_values()[public_offset..].to_vec();
        let x = |v: AB::Var| -> AB::Expr { v.into() };
        let active = x(pl[PRE_ACTIVE]);
        let first = x(pl[PRE_FIRST]);
        let last = x(pl[PRE_LAST]);
        b.assert_eq(
            pis[profile_offset(self.capacity)],
            F::from_u32(FEE_LOCAL_SETTLEMENT_REVISION),
        );
        // The commitment encoding remains four u16 limbs and eight blind fields.
        // The nine PCS salt fields belong to the independent recipe, not this hash.
        for e in 0..RATE {
            let expected = if e < LIMBS {
                x(l[FEE + e])
            } else {
                x(l[BLIND + e - LIMBS])
            };
            b.assert_zero((x(l[e]) - expected) * active.clone());
        }
        b.assert_zero((x(l[RATE]) - F::from_u32(LEGACY_FEE_TAG)) * active.clone());
        b.assert_zero((x(l[RATE + 1]) - F::ONE) * active.clone());
        for &value in &l[RATE + 2..WIDTH] {
            b.assert_zero(x(value) * active.clone());
        }
        for i in 0..self.capacity {
            for e in 0..common::DIGEST {
                b.assert_zero(
                    (x(l[P2_OUT + e]) - pis[i * common::DIGEST + e].into())
                        * x(pl[self.slot_selector(i)]),
                );
            }
        }
        for (start, bits) in [
            (FEE, FEE_BITS),
            (SUM, SUM_BITS),
            (TOTAL, TOTAL_BITS),
            (NOTE_AMOUNT, NOTE_BITS),
            (UNLOCK, UNLOCK_BITS),
        ] {
            for k in 0..LIMBS {
                let mut limb = AB::Expr::ZERO;
                for bit in 0..LIMB_BITS {
                    b.assert_bool(l[bits + k * LIMB_BITS + bit]);
                    limb += x(l[bits + k * LIMB_BITS + bit]) * F::from_u32(1 << bit);
                }
                b.assert_eq(limb, l[start + k]);
            }
        }
        b.assert_bool(l[DUMMY]);
        // Fees were authenticated under their private transaction anchors.
        // Settlement opens and sums those exact commitments without repricing.
        b.assert_zero(x(l[PRIORITY]) * active.clone());
        let mut fee_nonzero = AB::Expr::ZERO;
        for k in 0..LIMBS {
            fee_nonzero += x(l[FEE + k]);
        }
        b.assert_zero(fee_nonzero.clone() * x(l[DUMMY]) * active.clone());
        b.assert_zero(
            (fee_nonzero * x(l[NONZERO_INV]) - (AB::Expr::ONE - x(l[DUMMY]))) * active.clone(),
        );
        for k in 0..LIMBS {
            let carry = if k + 1 < LIMBS {
                b.assert_bool(l[SUM_CARRY + k]);
                x(l[SUM_CARRY + k])
            } else {
                AB::Expr::ZERO
            };
            let previous = if k == 0 {
                AB::Expr::ZERO
            } else {
                x(l[SUM_CARRY + k - 1])
            };
            b.assert_zero(
                (x(l[SUM + k]) + x(n[FEE + k]) + previous
                    - x(n[SUM + k])
                    - carry * F::from_u32(1 << LIMB_BITS))
                    * (active.clone() - last.clone()),
            );
            b.assert_zero((x(l[SUM + k]) - x(l[FEE + k])) * first.clone());
            b.assert_zero((x(l[TOTAL + k]) - x(l[SUM + k])) * last.clone());
            b.when_transition().assert_eq(l[TOTAL + k], n[TOTAL + k]);
        }
        let mode: AB::Expr = pis[reward_mode_offset(self.capacity)].into();
        b.assert_bool(mode.clone());
        b.assert_eq(
            pis[reward_mode_offset(self.capacity) + 1],
            AB::Expr::ONE + mode.clone() * F::from_u32(4),
        );
        for e in 0..16 {
            b.assert_zero(l[ASSET + e]);
        }
        for i in 0..OUTPUT_SLOTS {
            let is_fee = i == MAX_REWARD_NOTES;
            let enabled = if i == 0 || is_fee {
                AB::Expr::ONE
            } else {
                mode.clone()
            };
            let inactive = AB::Expr::ONE - enabled.clone();
            let allocation = reward_allocations_offset(self.capacity) + i * 2 * LIMBS;
            let cm = if is_fee {
                fee_commitment_offset(self.capacity)
            } else {
                reward_commitments_offset(self.capacity) + i * common::DIGEST
            };
            if !is_fee {
                for e in 0..2 * LIMBS {
                    b.assert_zero(pis[allocation + e].into() * inactive.clone());
                }
                for e in 0..common::DIGEST {
                    b.assert_zero(pis[cm + e].into() * inactive.clone());
                }
            }
            for stage in 0..NOTE_ROWS {
                let selector = x(pl[self.note_selector(i, stage)]);
                let selected = selector.clone() * enabled.clone();
                for k in 0..LIMBS {
                    let amount = if is_fee {
                        x(l[TOTAL + k])
                    } else {
                        pis[allocation + k].into()
                    };
                    let unlock = if is_fee {
                        AB::Expr::ZERO
                    } else {
                        pis[allocation + LIMBS + k].into()
                    };
                    b.assert_zero((x(l[NOTE_AMOUNT + k]) - amount) * selected.clone());
                    b.assert_zero((x(l[UNLOCK + k]) - unlock) * selected.clone());
                }
                if is_fee {
                    for e in 0..common::DIGEST {
                        b.assert_zero(
                            (x(l[OWNER + e]) - pis[fee_owner_offset(self.capacity) + e].into())
                                * selected.clone(),
                        );
                    }
                }
                if stage + 1 < NOTE_ROWS {
                    for col in NOTE_AMOUNT..MAIN_WIDTH {
                        b.when_transition()
                            .assert_zero((x(n[col]) - x(l[col])) * selector.clone());
                    }
                }
                for &value in &l[NOTE_AMOUNT..MAIN_WIDTH] {
                    b.assert_zero(x(value) * selector.clone() * inactive.clone());
                }
                if is_fee && stage == 0 {
                    for &value in &l[..WIDTH] {
                        b.assert_zero(x(value) * selected.clone());
                    }
                    continue;
                }
                for e in 0..RATE {
                    let value = match stage {
                        0 if e < LIMBS => pis[context_offset(self.capacity) + e].into(),
                        0 if e == LIMBS => AB::Expr::from_usize(i),
                        0 => AB::Expr::ZERO,
                        1 => x(l[OWNER + e]),
                        2 if e < LIMBS => x(l[NOTE_AMOUNT + e]),
                        2 if e < 2 * LIMBS => x(l[UNLOCK + e - LIMBS]),
                        2 => x(l[ASSET + e - 2 * LIMBS]),
                        3 => x(l[ASSET + e + 4]),
                        4 => x(l[RHO + e]),
                        _ => x(l[RSEED + e]),
                    };
                    b.assert_zero((x(l[e]) - value) * selected.clone());
                }
                if stage <= 1 {
                    for (e, &actual) in l.iter().enumerate().take(WIDTH).skip(RATE) {
                        let value = if e == RATE {
                            F::from_u32(if stage == 0 {
                                common::TAG_MINER_RHO
                            } else {
                                common::TAG_NOTE
                            })
                        } else if e == RATE + 1 {
                            F::from_u32(if stage == 0 { 1 } else { 5 })
                        } else {
                            F::ZERO
                        };
                        b.assert_zero((x(actual) - value) * selected.clone());
                    }
                }
                if (1..5).contains(&stage) {
                    for e in RATE..WIDTH {
                        b.when_transition()
                            .assert_zero((x(n[e]) - x(l[P2_OUT + e])) * selected.clone());
                    }
                }
                if stage == 0 {
                    for e in 0..common::DIGEST {
                        b.assert_zero((x(l[P2_OUT + e]) - x(l[RHO + e])) * selected.clone());
                    }
                }
                if stage == 5 {
                    for e in 0..common::DIGEST {
                        b.assert_zero((x(l[P2_OUT + e]) - pis[cm + e].into()) * selected.clone());
                    }
                }
                for &value in &l[..WIDTH] {
                    b.assert_zero(x(value) * selector.clone() * inactive.clone());
                }
            }
        }
    }
}

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
pub fn generate_trace(
    air: &FeeLocalSumAir,
    w: &FeeLocalSumWitness,
) -> Result<RowMajorMatrix<F>, String> {
    if air.capacity != w.settlement.slots.len() {
        return Err("fee-local trace capacity differs from witness".into());
    }
    let h = Hasher::new();
    let mut inputs = vec![[F::ZERO; WIDTH]; air.height];
    let mut rows = F::zero_vec(air.height * MAIN_WIDTH);
    let mut sum = 0u64;
    for (r, input) in inputs.iter_mut().enumerate().take(air.capacity) {
        let off = r * MAIN_WIDTH;
        let slot = &w.settlement.slots[r];
        *input = Hasher::first_input(
            LEGACY_FEE_TAG,
            1,
            &legacy_fee_block(slot.opening.fee, &slot.opening.blind),
        );
        put_bits(&mut rows, off, FEE, FEE_BITS, slot.opening.fee);
        rows[off + BLIND..off + BLIND + LEGACY_FEE_BLIND_FIELDS]
            .copy_from_slice(&slot.opening.blind);
        sum = sum
            .checked_add(slot.opening.fee)
            .ok_or("fee-local V4 fee sum overflow")?;
        put_bits(&mut rows, off, SUM, SUM_BITS, sum);
        rows[off + DUMMY] = F::from_bool(slot.opening.fee == 0);
        rows[off + PRIORITY] = F::ZERO;
        let nonzero = common::limbs(slot.opening.fee).into_iter().sum::<F>();
        rows[off + NONZERO_INV] = if nonzero == F::ZERO {
            F::ZERO
        } else {
            nonzero.inverse()
        };
        if r + 1 < air.capacity {
            let current = common::limbs(sum);
            let next = common::limbs(w.settlement.slots[r + 1].opening.fee);
            let mut carry = 0u64;
            for k in 0..LIMBS - 1 {
                carry = (u64::from(current[k].as_canonical_u32())
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
            TOTAL,
            TOTAL_BITS,
            w.settlement.fee_note.value,
        );
    }
    for i in 0..OUTPUT_SLOTS {
        let is_fee = i == MAX_REWARD_NOTES;
        let Some(note) = (if is_fee {
            Some(&w.settlement.fee_note)
        } else {
            w.settlement.rewards.get(i)
        }) else {
            continue;
        };
        let row = air.capacity + i * NOTE_ROWS;
        if !is_fee {
            let mut block = common::padded_block(&common::limbs(w.policy.plan.block_height));
            block[LIMBS] = F::from_usize(i);
            inputs[row] = Hasher::first_input(common::TAG_MINER_RHO, 1, &block);
        }
        let (note_inputs, _) = h.sponge_trace(common::TAG_NOTE, &note.blocks());
        inputs[row + 1..row + NOTE_ROWS].copy_from_slice(&note_inputs);
        for r in row..row + NOTE_ROWS {
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
    Ok(RowMajorMatrix::new(rows, MAIN_WIDTH))
}

fn validate_openings(
    settlement: &LegacyPrivateSettlement,
    policy: &SettlementPolicy,
) -> Result<(), String> {
    policy.plan.validate()?;
    if !(1..=MAX_SETTLEMENT_SLOTS).contains(&policy.max_slots)
        || settlement.slots.is_empty()
        || settlement.slots.len() > policy.max_slots
        || settlement.rewards.len() != policy.plan.mode.note_count()
    {
        return Err("invalid settlement capacity or reward count".into());
    }
    let hasher = Hasher::new();
    let mut total = 0u64;
    for (index, slot) in settlement.slots.iter().enumerate() {
        let opening = &slot.opening;
        if legacy_fee_commit(&hasher, opening.fee, &opening.blind) != slot.commitment
            || settlement.slots[..index]
                .iter()
                .any(|old| old.commitment == slot.commitment)
        {
            return Err("invalid or duplicate fee commitment".into());
        }
        total = total
            .checked_add(opening.fee)
            .ok_or("private fee sum overflow")?;
    }
    if settlement.fee_note.asset_id != SIP_ASSET_ID
        || settlement.fee_note.owner != policy.fee_owner
        || settlement.fee_note.value != total
        || settlement.fee_note.unlock_height != 0
    {
        return Err("invalid private fee destination output".into());
    }
    for (index, (note, allocation)) in settlement
        .rewards
        .iter()
        .zip(&policy.plan.allocations)
        .enumerate()
    {
        if note.asset_id != SIP_ASSET_ID
            || note.value != allocation.amount
            || note.unlock_height != allocation.unlock_height
            || note.rho != hasher.reward_rho(policy.plan.block_height, index)
        {
            return Err("invalid subsidy-only reward witness".into());
        }
    }
    let fee_commitment = hasher.note_cm(&settlement.fee_note);
    let mut reward_commitments = Vec::with_capacity(settlement.rewards.len());
    for note in &settlement.rewards {
        let commitment = hasher.note_cm(note);
        if commitment == fee_commitment || reward_commitments.contains(&commitment) {
            return Err("duplicate settlement output".into());
        }
        reward_commitments.push(commitment);
    }
    Ok(())
}
