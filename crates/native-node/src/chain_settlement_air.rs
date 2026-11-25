//! Version-two private fee settlement relation, separate from the V1 profile.
//!
//! The verifier must reconstruct this statement from authenticated block state,
//! including the complete canonical destination-address digest and its owner.
//! The always-present fee note receives the private sum; reward notes receive
//! exactly the subsidy/Holder allocations. Neither the sum nor padding flags
//! occur in public inputs. Ciphertext correctness is not proved by this AIR.
#![allow(clippy::needless_range_loop)]

use crate::eng2_settlement::{MAX_SETTLEMENT_SLOTS, PrivateSettlement, SettlementPolicy};

use native::air::{LinearLayers, P2, p2_constants};
use native::multi_asset::{self as common, F, Hasher, LIMB_BITS, LIMBS, RATE, WIDTH};
use native::settlement::{FeeP2Air, MAX_REWARD_NOTES};
use native::{Cfg, FriParams};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{
    PreprocessedProverData, PreprocessedVerifierKey, Proof, SubAirBuilder, prove_with_preprocessed,
    setup_preprocessed, verify_with_preprocessed,
};

pub const SETTLEMENT_PROFILE_V2: u32 = 2;
const OUTPUT_SLOTS: usize = MAX_REWARD_NOTES + 1;
const NOTE_ROWS: usize = 6;

/// Private prover input. Never serialize note openings into public artifacts.
pub struct SettlementWitnessV2 {
    pub policy: SettlementPolicy,
    pub network: [u8; 32],
    pub transaction_list_digest: [u8; 32],
    /// Hash of the authenticated complete canonical destination address.
    /// In particular, this must include the encryption public key.
    pub fee_destination_digest: [u8; 32],
    pub settlement: PrivateSettlement,
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
pub fn settlement_public_v2(
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
        return Err("invalid V2 settlement capacity or reward count".into());
    }
    let mut out = Vec::with_capacity(public_len(fees.len()));
    for commitment in fees {
        out.extend_from_slice(commitment);
    }
    out.push(F::from_u32(SETTLEMENT_PROFILE_V2));
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
    validate_settlement_public_v2(fees.len(), &out)?;
    Ok(out)
}

pub fn validate_settlement_public_v2(capacity: usize, public: &[F]) -> Result<(), String> {
    if !(1..=MAX_SETTLEMENT_SLOTS).contains(&capacity) || public.len() != public_len(capacity) {
        return Err("invalid V2 settlement public-input length".into());
    }
    if public[profile_offset(capacity)] != F::from_u32(SETTLEMENT_PROFILE_V2) {
        return Err("invalid V2 settlement profile".into());
    }
    if public[fee_destination_offset(capacity)..reward_commitments_offset(capacity)]
        .iter()
        .any(|x| x.as_canonical_u32() >= (1 << LIMB_BITS))
    {
        return Err("noncanonical V2 settlement numeric or context limb".into());
    }
    let integer = |offset: usize| {
        (0..LIMBS).fold(0u64, |a, k| {
            a | ((public[offset + k].as_canonical_u32() as u64) << (k * LIMB_BITS))
        })
    };
    if integer(fee_schedule_offset(capacity)).checked_mul(4)
        != Some(integer(fee_schedule_offset(capacity) + LIMBS))
    {
        return Err("invalid V2 fee schedule".into());
    }
    let mode = public[reward_mode_offset(capacity)].as_canonical_u32();
    let count = match mode {
        0 => 1,
        1 => 5,
        _ => return Err("invalid V2 reward mode".into()),
    };
    if public[reward_mode_offset(capacity) + 1].as_canonical_u32() as usize != count {
        return Err("V2 reward count differs from mode".into());
    }
    let height = integer(context_offset(capacity));
    let mut outputs = Vec::with_capacity(OUTPUT_SLOTS);
    for i in 0..MAX_REWARD_NOTES {
        let allocation = reward_allocations_offset(capacity) + i * 2 * LIMBS;
        let cm = reward_commitments_offset(capacity) + i * common::DIGEST;
        if i < count {
            if integer(allocation + LIMBS) < height {
                return Err("V2 reward unlock precedes block".into());
            }
            outputs.push(&public[cm..cm + common::DIGEST]);
        } else if public[allocation..allocation + 2 * LIMBS]
            .iter()
            .chain(&public[cm..cm + common::DIGEST])
            .any(|x| *x != F::ZERO)
        {
            return Err("noncanonical inactive V2 reward slot".into());
        }
    }
    outputs.push(&public[fee_commitment_offset(capacity)..]);
    for (i, cm) in outputs.iter().enumerate() {
        if cm.iter().all(|x| *x == F::ZERO) || outputs[..i].contains(cm) {
            return Err("zero or duplicate V2 output commitment".into());
        }
    }
    for i in 0..capacity {
        let cm = &public[i * common::DIGEST..(i + 1) * common::DIGEST];
        if (0..i).any(|j| &public[j * common::DIGEST..(j + 1) * common::DIGEST] == cm) {
            return Err("duplicate V2 fee commitment".into());
        }
    }
    Ok(())
}

impl SettlementWitnessV2 {
    pub fn public_inputs(&self) -> Result<Vec<F>, String> {
        let h = Hasher::new();
        settlement_public_v2(
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
}

const P2_OUT: usize = P2 - WIDTH;
const FEE: usize = P2;
const FEE_BITS: usize = FEE + LIMBS;
const BLIND: usize = FEE_BITS + LIMBS * LIMB_BITS;
const SUM: usize = BLIND + common::FEE_BLIND_LEN;
const SUM_BITS: usize = SUM + LIMBS;
const SUM_CARRY: usize = SUM_BITS + LIMBS * LIMB_BITS;
const TOTAL: usize = SUM_CARRY + LIMBS - 1;
const TOTAL_BITS: usize = TOTAL + LIMBS;
const DUMMY: usize = TOTAL_BITS + LIMBS * LIMB_BITS;
const PRIORITY: usize = DUMMY + 1;
const NONZERO_INV: usize = PRIORITY + 1;
const NOTE_AMOUNT: usize = NONZERO_INV + 1;
const NOTE_BITS: usize = NOTE_AMOUNT + LIMBS;
const OWNER: usize = NOTE_BITS + LIMBS * LIMB_BITS;
const RSEED: usize = OWNER + common::DIGEST;
const RHO: usize = RSEED + common::DIGEST;
const UNLOCK: usize = RHO + common::DIGEST;
const UNLOCK_BITS: usize = UNLOCK + LIMBS;
const ASSET: usize = UNLOCK_BITS + LIMBS * LIMB_BITS;
const MAIN_WIDTH: usize = ASSET + 16;
const PRE_ACTIVE: usize = 0;
const PRE_FIRST: usize = 1;
const PRE_LAST: usize = 2;
const PRE_NOTES: usize = 3;
const PRE_SLOTS: usize = PRE_NOTES + OUTPUT_SLOTS * NOTE_ROWS;

pub struct SettlementAirV2 {
    pub capacity: usize,
    pub height: usize,
    p2: FeeP2Air,
}
impl SettlementAirV2 {
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
    pub fn degree_bits(&self) -> usize {
        self.height.trailing_zeros() as usize
    }
    fn note_selector(&self, index: usize, stage: usize) -> usize {
        PRE_NOTES + index * NOTE_ROWS + stage
    }
    fn slot_selector(&self, index: usize) -> usize {
        PRE_SLOTS + index
    }
}
impl BaseAir<F> for SettlementAirV2 {
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
impl<AB: AirBuilder<F = F>> Air<AB> for SettlementAirV2 {
    fn eval(&self, b: &mut AB) {
        let mut sub = SubAirBuilder::<AB, FeeP2Air, AB::Var>::new(b, 0..P2);
        self.p2.eval(&mut sub);
        let main = b.main();
        let pre = b.preprocessed().clone();
        let l = main.current_slice();
        let n = main.next_slice();
        let pl = pre.current_slice();
        let pis = b.public_values().to_vec();
        let x = |v: AB::Var| -> AB::Expr { v.into() };
        let active = x(pl[PRE_ACTIVE]);
        let first = x(pl[PRE_FIRST]);
        let last = x(pl[PRE_LAST]);
        b.assert_eq(
            pis[profile_offset(self.capacity)],
            F::from_u32(SETTLEMENT_PROFILE_V2),
        );
        for e in 0..RATE {
            let expected = if e < LIMBS {
                x(l[FEE + e])
            } else {
                x(l[BLIND + e - LIMBS])
            };
            b.assert_zero((x(l[e]) - expected) * active.clone());
        }
        b.assert_zero((x(l[RATE]) - F::from_u32(common::TAG_FEE)) * active.clone());
        b.assert_zero((x(l[RATE + 1]) - F::ONE) * active.clone());
        for e in RATE + 2..WIDTH {
            b.assert_zero(x(l[e]) * active.clone());
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
        b.assert_bool(l[PRIORITY]);
        b.assert_zero(x(l[DUMMY]) * x(l[PRIORITY]) * active.clone());
        let mut fee_nonzero = AB::Expr::ZERO;
        for k in 0..LIMBS {
            fee_nonzero += x(l[FEE + k]);
            let standard: AB::Expr = pis[fee_schedule_offset(self.capacity) + k].into();
            let priority: AB::Expr = pis[fee_schedule_offset(self.capacity) + LIMBS + k].into();
            b.assert_zero(
                (x(l[FEE + k])
                    - (AB::Expr::ONE - x(l[DUMMY]))
                        * (standard.clone() + x(l[PRIORITY]) * (priority - standard)))
                    * active.clone(),
            );
        }
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
                for col in NOTE_AMOUNT..MAIN_WIDTH {
                    b.assert_zero(x(l[col]) * selector.clone() * inactive.clone());
                }
                if is_fee && stage == 0 {
                    for e in 0..WIDTH {
                        b.assert_zero(x(l[e]) * selected.clone());
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
                    for e in RATE..WIDTH {
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
                        b.assert_zero((x(l[e]) - value) * selected.clone());
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
                for e in 0..WIDTH {
                    b.assert_zero(x(l[e]) * selector.clone() * inactive.clone());
                }
            }
        }
    }
}

pub struct SettlementProverV2 {
    pub cfg: Cfg,
    pub air: SettlementAirV2,
    pub pdata: PreprocessedProverData<Cfg>,
    pub vk: PreprocessedVerifierKey<Cfg>,
}
impl SettlementProverV2 {
    pub fn new(capacity: usize, params: FriParams) -> Self {
        let cfg = params.config();
        let air = SettlementAirV2::new(capacity).with_min_height(params.hiding_min_height());
        let (pdata, vk) = setup_preprocessed(&cfg, &air, air.degree_bits())
            .expect("V2 settlement preprocessing")
            .expect("preprocessed V2 AIR");
        Self {
            cfg,
            air,
            pdata,
            vk,
        }
    }
    pub fn prove(&self, w: &SettlementWitnessV2) -> Result<(Proof<Cfg>, Vec<F>), String> {
        if w.settlement.slots.len() != self.air.capacity {
            return Err("V2 prover capacity mismatch".into());
        }
        w.settlement.validate(&w.policy)?;
        let public = w.public_inputs()?;
        let trace = generate_trace(&self.air, w)?;
        let proof =
            prove_with_preprocessed(&self.cfg, &self.air, trace, &public, Some(&self.pdata))
                .map_err(|e| format!("{e:?}"))?;
        Ok((proof, public))
    }
    /// The caller supplies a locally reconstructed statement, never a peer's
    /// policy, fee address, reward plan, network identity or transaction list.
    pub fn verify(&self, proof: &Proof<Cfg>, public: &[F]) -> Result<(), String> {
        validate_settlement_public_v2(self.air.capacity, public)?;
        verify_with_preprocessed(&self.cfg, &self.air, proof, public, Some(&self.vk))
            .map_err(|e| format!("{e:?}"))
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
fn generate_trace(
    air: &SettlementAirV2,
    w: &SettlementWitnessV2,
) -> Result<RowMajorMatrix<F>, String> {
    let h = Hasher::new();
    let mut inputs = vec![[F::ZERO; WIDTH]; air.height];
    let mut rows = F::zero_vec(air.height * MAIN_WIDTH);
    let mut sum = 0u64;
    for r in 0..air.capacity {
        let off = r * MAIN_WIDTH;
        let slot = &w.settlement.slots[r];
        inputs[r] = Hasher::first_input(
            common::TAG_FEE,
            1,
            &common::fee_block(slot.opening.fee, &slot.opening.blind),
        );
        put_bits(&mut rows, off, FEE, FEE_BITS, slot.opening.fee);
        rows[off + BLIND..off + BLIND + common::FEE_BLIND_LEN].copy_from_slice(&slot.opening.blind);
        sum = sum
            .checked_add(slot.opening.fee)
            .ok_or("V2 fee sum overflow")?;
        put_bits(&mut rows, off, SUM, SUM_BITS, sum);
        rows[off + DUMMY] = F::from_bool(slot.opening.dummy);
        rows[off + PRIORITY] = F::from_bool(slot.opening.priority);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eng2_settlement::FeeSchedule;
    use native::settlement::{RewardMode, sample_fixed_settlement_witness};
    use p3_air::check_all_constraints;

    fn fixture(mode: RewardMode) -> SettlementWitnessV2 {
        let old = sample_fixed_settlement_witness(4, mode);
        let h = Hasher::new();
        let rewards = (0..old.rewards.len())
            .map(|i| {
                let mut note = old.reward_note(i);
                note.value = old.plan.allocations[i].amount;
                note
            })
            .collect();
        let owner = [F::from_u32(73); common::DIGEST];
        let fee_note = common::Note {
            asset_id: common::SIP_ASSET_ID,
            owner,
            value: 1000,
            unlock_height: 0,
            rho: [F::from_u32(91); common::DIGEST],
            rseed: [F::from_u32(92); common::DIGEST],
        };
        let w = SettlementWitnessV2 {
            policy: SettlementPolicy {
                plan: old.plan,
                fee_owner: owner,
                fees: FeeSchedule::from_previous_standard(10_000).unwrap(),
                max_slots: 4,
            },
            network: old.network,
            transaction_list_digest: old.transaction_list_digest,
            fee_destination_digest: [12; 32],
            settlement: PrivateSettlement {
                rewards,
                fee_note,
                slots: old.slots,
            },
        };
        w.settlement.validate(&w.policy).unwrap();
        assert_ne!(h.note_cm(&w.settlement.fee_note), [F::ZERO; common::DIGEST]);
        w
    }
    fn air_accepts(w: &SettlementWitnessV2) -> bool {
        let air = SettlementAirV2::new(4);
        let trace = generate_trace(&air, w).unwrap();
        let public = w.public_inputs().unwrap();
        check_all_constraints(&air, &trace, &public, Some(1))
            .failures
            .is_empty()
    }
    fn rehash_slot(w: &mut SettlementWitnessV2, index: usize) {
        let slot = &mut w.settlement.slots[index];
        slot.commitment = Hasher::new().fee_commit(slot.opening.fee, &slot.opening.blind);
    }

    #[test]
    fn air_rejects_rehashed_fee_theft_owner_asset_and_unlock_substitution() {
        for mode in [RewardMode::Voyager, RewardMode::Holder] {
            assert!(air_accepts(&fixture(mode)));
            for mutation in 0..7 {
                let mut w = fixture(mode);
                match mutation {
                    0 => {
                        w.settlement.rewards[0].value += 1000;
                        w.settlement.fee_note.value = 0;
                    }
                    1 => w.settlement.fee_note.owner[0] += F::ONE,
                    2 => w.settlement.fee_note.asset_id.0[0] = 1,
                    3 => w.settlement.fee_note.unlock_height = 1,
                    4 => w.settlement.rewards[0].rho[0] += F::ONE,
                    5 => w.settlement.rewards[0].asset_id.0[0] = 1,
                    _ => w.settlement.rewards[0].unlock_height += 1,
                }
                assert!(!air_accepts(&w), "mutation {mutation}, mode {mode:?}");
            }
        }
    }

    #[test]
    fn private_tiers_and_padding_are_constraints_not_only_host_checks() {
        for mutation in 0..5 {
            let mut w = fixture(RewardMode::Holder);
            match mutation {
                0 => w.settlement.slots[0].opening.priority = true,
                1 => w.settlement.slots[0].opening.dummy = true,
                2 => {
                    w.settlement.slots[0].opening.fee = 999;
                    w.settlement.fee_note.value = 999;
                }
                3 => w.settlement.slots[1].opening.priority = true,
                _ => {
                    w.settlement.slots[0].opening.fee = 0;
                    w.settlement.fee_note.value = 0;
                }
            }
            rehash_slot(&mut w, 0);
            rehash_slot(&mut w, 1);
            assert!(!air_accepts(&w), "tier mutation {mutation}");
        }
    }

    #[test]
    fn trace_mutations_cannot_change_private_sums_ranges_or_note_chain() {
        let w = fixture(RewardMode::Holder);
        let air = SettlementAirV2::new(4);
        let trace = generate_trace(&air, &w).unwrap();
        let public = w.public_inputs().unwrap();
        for (row, column) in [
            (0, SUM_CARRY),
            (0, SUM),
            (1, SUM_BITS),
            (3, TOTAL),
            (4, NOTE_AMOUNT),
            (4, RHO),
            (4 + MAX_REWARD_NOTES * NOTE_ROWS, OWNER),
            (4 + MAX_REWARD_NOTES * NOTE_ROWS + 2, NOTE_BITS),
            (4 + MAX_REWARD_NOTES * NOTE_ROWS + 3, RATE),
        ] {
            let mut changed = trace.clone();
            changed.values[row * MAIN_WIDTH + column] += F::ONE;
            assert!(
                !check_all_constraints(&air, &changed, &public, Some(1))
                    .failures
                    .is_empty(),
                "row {row}, column {column}"
            );
        }
    }

    #[test]
    fn limb_carries_are_checked_without_public_fee_sum() {
        let mut w = fixture(RewardMode::Holder);
        w.policy.fees = FeeSchedule::from_previous_standard(655_350).unwrap();
        for i in 0..4 {
            let slot = &mut w.settlement.slots[i];
            slot.opening.fee = w.policy.fees.standard();
            slot.opening.dummy = false;
            slot.opening.priority = false;
            rehash_slot(&mut w, i);
        }
        w.settlement.fee_note.value = 4 * w.policy.fees.standard();
        assert!(air_accepts(&w));
        let before = w.public_inputs().unwrap();
        w.settlement.fee_note.value -= 1;
        let after = w.public_inputs().unwrap();
        assert_eq!(
            &before[..fee_commitment_offset(4)],
            &after[..fee_commitment_offset(4)]
        );
        assert!(!air_accepts(&w));
    }
}
