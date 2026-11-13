//! Native D8/W24 proof of fixed-supply asset issuance; no recursive verifier.
//!
//! The public statement binds the asset identifier, declared supply, complete
//! signed declaration digest and ordered initial note commitments. Signature,
//! asset-ID derivation, policy and SIP fee checks remain native validation steps.

use crate::air::{LinearLayers, P2, P2Air, p2_constants};
use crate::common::{DIGEST, F, LIMB_BITS, LIMBS, RATE, WIDTH};
use crate::issuance::{
    IssuanceError, IssuancePolicy, IssuanceWitness, SignedIssuance, VerifiedIssuance,
};
use crate::{Cfg, FriParams};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{
    PreprocessedProverData, PreprocessedVerifierKey, Proof, SubAirBuilder, prove_with_preprocessed,
    setup_preprocessed, verify_with_preprocessed,
};

const P2_OUT: usize = P2 - WIDTH;
const OWNER: usize = P2;
const VALUE: usize = OWNER + DIGEST;
const UNLOCK: usize = VALUE + LIMBS;
const ASSET: usize = UNLOCK + LIMBS;
const RHO: usize = ASSET + 16;
const RSEED: usize = RHO + DIGEST;
const BEFORE: usize = RSEED + DIGEST;
const AFTER: usize = BEFORE + LIMBS;
const CARRY: usize = AFTER + LIMBS;
const BITS: usize = CARRY + LIMBS - 1;
const RANGE_LANES: usize = 7;
const CONTEXT: usize = BITS + RANGE_LANES * LIMB_BITS;
pub const MAIN_WIDTH: usize = CONTEXT + 16;
const PRE_STAGE: usize = 0;
const PRE_FIRST: usize = 5;
const PRE_LAST: usize = 6;
const PRE_NOTE: usize = 7;
pub const PUBLIC_ASSET: usize = 0;
pub const PUBLIC_SUPPLY: usize = 16;
pub const PUBLIC_BINDING: usize = 20;
pub const PUBLIC_COMMITMENTS: usize = 36;

pub const fn public_len(note_count: usize) -> usize {
    PUBLIC_COMMITMENTS + note_count * DIGEST
}
fn range_column(index: usize) -> Option<usize> {
    match index {
        0..24 => Some(VALUE + index),
        24..28 => Some(BEFORE + index - 24),
        28..32 => Some(AFTER + index - 28),
        _ => None,
    }
}

pub struct IssuanceAir {
    pub note_count: usize,
    pub height: usize,
    p2: P2Air,
}

impl IssuanceAir {
    pub fn new(note_count: usize) -> Self {
        assert!(note_count > 0);
        let height = note_count
            .checked_mul(5)
            .and_then(|n| n.checked_add(1))
            .expect("issuance dimensions overflow")
            .next_power_of_two();
        Self {
            note_count,
            height,
            p2: P2Air::new(p2_constants()),
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
    pub fn main_width(&self) -> usize {
        MAIN_WIDTH
    }
    pub fn preprocessed_width(&self) -> usize {
        PRE_NOTE + self.note_count
    }
    pub fn constraint_count(&self, witness: &IssuanceWitness) -> usize {
        let (trace, public) = generate_trace(self, witness);
        p3_air::check_all_constraints(self, &trace, &public, Some(1)).total_constraints_per_row
    }
}

impl BaseAir<F> for IssuanceAir {
    fn width(&self) -> usize {
        MAIN_WIDTH
    }
    fn num_public_values(&self) -> usize {
        public_len(self.note_count)
    }
    fn preprocessed_width(&self) -> usize {
        self.preprocessed_width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let width = self.preprocessed_width();
        let mut data = F::zero_vec(width * self.height);
        for i in 0..self.note_count {
            for stage in 0..5 {
                data[(i * 5 + stage) * width + PRE_STAGE + stage] = F::ONE;
            }
            data[(i * 5 + 4) * width + PRE_NOTE + i] = F::ONE;
        }
        data[PRE_FIRST] = F::ONE;
        data[(self.note_count * 5 - 1) * width + PRE_LAST] = F::ONE;
        Some(RowMajorMatrix::new(data, width))
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for IssuanceAir {
    fn eval(&self, b: &mut AB) {
        let mut sub = SubAirBuilder::<AB, P2Air, AB::Var>::new(b, 0..P2);
        self.p2.eval(&mut sub);
        let main = b.main();
        let pre = b.preprocessed().clone();
        let l = main.current_slice();
        let n = main.next_slice();
        let p = pre.current_slice();
        let pis: Vec<AB::PublicVar> = b.public_values().to_vec();
        let x = |v: AB::Var| -> AB::Expr { v.into() };
        let stages: Vec<AB::Expr> = (0..5).map(|k| x(p[PRE_STAGE + k])).collect();
        let active = stages.iter().cloned().sum::<AB::Expr>();
        let continuing = stages[..4].iter().cloned().sum::<AB::Expr>();
        let first = x(p[PRE_FIRST]);
        let last = x(p[PRE_LAST]);
        // All note fields and both running sums stay fixed during one sponge.
        for col in OWNER..CARRY {
            b.when_transition()
                .assert_zero((x(n[col]) - x(l[col])) * continuing.clone());
        }
        for e in 0..16 {
            b.assert_zero((x(l[ASSET + e]) - pis[PUBLIC_ASSET + e].into()) * active.clone());
            // Bind otherwise native-only declaration fields to the proof transcript.
            b.assert_eq(l[CONTEXT + e], pis[PUBLIC_BINDING + e]);
        }
        // Asset issuance creates ordinary unlocked notes only.
        for k in 0..LIMBS {
            b.assert_zero(x(l[UNLOCK + k]) * active.clone());
        }
        // Seven independent 16-bit range checks per row cover value, unlock,
        // all 16 asset limbs, and all before/after accumulator limbs.
        for lane in 0..RANGE_LANES {
            let mut limb = AB::Expr::ZERO;
            for bit in 0..LIMB_BITS {
                b.assert_bool(l[BITS + lane * LIMB_BITS + bit]);
                limb += x(l[BITS + lane * LIMB_BITS + bit]) * F::from_u32(1 << bit);
            }
            let mut target = AB::Expr::ZERO;
            for stage in 0..5 {
                if let Some(col) = range_column(stage * RANGE_LANES + lane) {
                    target += x(l[col]) * stages[stage].clone();
                }
            }
            b.assert_eq(limb, target);
        }
        for stage in 0..5 {
            for e in 0..RATE {
                let value = match stage {
                    0 => x(l[OWNER + e]),
                    1 if e < 4 => x(l[VALUE + e]),
                    1 if e < 8 => x(l[UNLOCK + e - 4]),
                    1 => x(l[ASSET + e - 8]),
                    2 => x(l[ASSET + e + 4]),
                    3 => x(l[RHO + e]),
                    _ => x(l[RSEED + e]),
                };
                b.assert_zero((x(l[e]) - value) * stages[stage].clone());
            }
            if stage == 0 {
                for e in RATE..WIDTH {
                    let expected = if e == RATE {
                        F::from_u32(130)
                    } else if e == RATE + 1 {
                        F::from_u32(5)
                    } else {
                        F::ZERO
                    };
                    b.assert_zero((x(l[e]) - expected) * stages[0].clone());
                }
            }
        }
        for e in RATE..WIDTH {
            b.when_transition()
                .assert_zero((x(n[e]) - x(l[P2_OUT + e])) * continuing.clone());
        }
        // Exact 64-bit sum, with no terminal carry: field wrap cannot mint supply.
        for k in 0..LIMBS {
            let prior = if k == 0 {
                AB::Expr::ZERO
            } else {
                x(l[CARRY + k - 1])
            };
            let carry = if k + 1 == LIMBS {
                AB::Expr::ZERO
            } else {
                b.assert_bool(l[CARRY + k]);
                x(l[CARRY + k])
            };
            b.assert_zero(
                (x(l[BEFORE + k]) + x(l[VALUE + k]) + prior
                    - x(l[AFTER + k])
                    - carry * F::from_u32(1 << LIMB_BITS))
                    * active.clone(),
            );
            b.assert_zero(x(l[BEFORE + k]) * first.clone());
            b.when_transition().assert_zero(
                (x(n[BEFORE + k]) - x(l[AFTER + k])) * (stages[4].clone() - last.clone()),
            );
            b.assert_zero((x(l[AFTER + k]) - pis[PUBLIC_SUPPLY + k].into()) * last.clone());
        }
        for i in 0..self.note_count {
            for e in 0..DIGEST {
                b.assert_zero(
                    (x(l[P2_OUT + e]) - pis[PUBLIC_COMMITMENTS + i * DIGEST + e].into())
                        * x(p[PRE_NOTE + i]),
                );
            }
        }
    }
}

pub struct IssuanceProver {
    pub cfg: Cfg,
    pub air: IssuanceAir,
    pub pdata: PreprocessedProverData<Cfg>,
    pub vk: PreprocessedVerifierKey<Cfg>,
}
impl IssuanceProver {
    pub fn new(note_count: usize, params: FriParams) -> Self {
        let cfg = params.config();
        let air = IssuanceAir::new(note_count).with_min_height(params.hiding_min_height());
        let (pdata, vk) = setup_preprocessed(&cfg, &air, air.degree_bits())
            .expect("issuance setup")
            .expect("preprocessed AIR");
        Self {
            cfg,
            air,
            pdata,
            vk,
        }
    }
    pub fn prove(&self, witness: &IssuanceWitness) -> Result<(Proof<Cfg>, Vec<F>), IssuanceError> {
        witness.check()?;
        if witness.notes.len() != self.air.note_count {
            return Err(IssuanceError::NoteCountMismatch);
        }
        let (trace, public) = generate_trace(&self.air, witness);
        let proof =
            prove_with_preprocessed(&self.cfg, &self.air, trace, &public, Some(&self.pdata))
                .map_err(|_| IssuanceError::InvalidProof)?;
        Ok((proof, public))
    }
    /// The fee callback must verify an already validated SIP payment bound to
    /// this declaration digest; it must never merely check a claimed amount.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_signed(
        &self,
        signed: &SignedIssuance,
        proof: &Proof<Cfg>,
        network: &[u8; 32],
        version: u32,
        policy: IssuancePolicy,
        ciphertexts: &[Vec<u8>],
        verify_sip_fee: impl FnOnce(&[u8; 32], u64) -> bool,
    ) -> Result<VerifiedIssuance, IssuanceError> {
        signed.declaration.validate(network, version, policy)?;
        signed.verify_signature()?;
        signed
            .declaration
            .validate_ciphertexts(ciphertexts, policy.max_ciphertext_bytes_per_note)?;
        if signed.declaration.note_commitments.len() != self.air.note_count {
            return Err(IssuanceError::NoteCountMismatch);
        }
        self.verify(proof, &signed.declaration.public_inputs())?;
        if !verify_sip_fee(&signed.declaration.binding(), policy.required_fee_atoms) {
            return Err(IssuanceError::UnpaidIssuanceFee);
        }
        Ok(VerifiedIssuance(signed.declaration.clone()))
    }
    pub fn verify(&self, proof: &Proof<Cfg>, public: &[F]) -> Result<(), IssuanceError> {
        if public.len() != public_len(self.air.note_count) {
            return Err(IssuanceError::NoteCountMismatch);
        }
        if public[..PUBLIC_COMMITMENTS]
            .iter()
            .any(|v| v.as_canonical_u32() > 0xffff)
        {
            return Err(IssuanceError::InvalidProof);
        }
        verify_with_preprocessed(&self.cfg, &self.air, proof, public, Some(&self.vk))
            .map_err(|_| IssuanceError::InvalidProof)
    }
}

fn generate_trace(air: &IssuanceAir, witness: &IssuanceWitness) -> (RowMajorMatrix<F>, Vec<F>) {
    let mut inputs = vec![[F::ZERO; WIDTH]; air.height];
    let mut data = F::zero_vec(air.height * MAIN_WIDTH);
    let mut sum = 0u64;
    for (i, note) in witness.notes.iter().enumerate() {
        let blocks = note.blocks();
        let (trace, _) = crate::common::Hasher::new().sponge_trace(130, &blocks);
        inputs[i * 5..i * 5 + 5].copy_from_slice(&trace);
        let before = crate::common::limbs(sum);
        sum = sum.checked_add(note.value).expect("checked witness sum");
        let after = crate::common::limbs(sum);
        let value = crate::common::limbs(note.value);
        let mut registers = vec![F::ZERO; MAIN_WIDTH - P2];
        for (col, values) in [
            (OWNER, note.owner.as_slice()),
            (VALUE, value.as_slice()),
            (UNLOCK, crate::common::limbs(note.unlock_height).as_slice()),
            (
                ASSET,
                crate::issuance::byte_limbs(&note.asset_id.0).as_slice(),
            ),
            (RHO, note.rho.as_slice()),
            (RSEED, note.rseed.as_slice()),
            (BEFORE, before.as_slice()),
            (AFTER, after.as_slice()),
        ] {
            registers[col - P2..col - P2 + values.len()].copy_from_slice(values);
        }
        let mut carry = 0u64;
        for k in 0..LIMBS - 1 {
            carry =
                (before[k].as_canonical_u32() as u64 + value[k].as_canonical_u32() as u64 + carry)
                    >> 16;
            registers[CARRY - P2 + k] = F::from_u64(carry);
        }
        for stage in 0..5 {
            let offset = (i * 5 + stage) * MAIN_WIDTH;
            data[offset + P2..offset + MAIN_WIDTH].copy_from_slice(&registers);
            for lane in 0..RANGE_LANES {
                if let Some(col) = range_column(stage * RANGE_LANES + lane) {
                    let value = data[offset + col].as_canonical_u32();
                    for bit in 0..LIMB_BITS {
                        data[offset + BITS + lane * LIMB_BITS + bit] =
                            F::from_u32((value >> bit) & 1);
                    }
                }
            }
        }
    }
    let binding = crate::issuance::byte_limbs(&witness.declaration.binding());
    for row in 0..air.height {
        data[row * MAIN_WIDTH + CONTEXT..row * MAIN_WIDTH + CONTEXT + 16].copy_from_slice(&binding);
    }
    let p2 = p3_poseidon2_air::generate_trace_rows::<F, LinearLayers, WIDTH, 3, 0, 4, 23>(
        inputs,
        &p2_constants(),
        0,
    );
    for row in 0..air.height {
        data[row * MAIN_WIDTH..row * MAIN_WIDTH + P2]
            .copy_from_slice(&p2.values[row * P2..(row + 1) * P2]);
    }
    (
        RowMajorMatrix::new(data, MAIN_WIDTH),
        witness.declaration.public_inputs(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuance::{IssuanceRegistry, tests::fixture};
    use crate::multi_asset::Hasher;
    use p3_air::check_all_constraints;
    #[test]
    fn issuance_rejects_locked_initial_notes_in_air() {
        let (_, mut w, _) = fixture(3);
        w.notes[0].unlock_height = 1;
        w.declaration.note_commitments[0] = Hasher::new().note_cm(&w.notes[0]);
        let air = IssuanceAir::new(3);
        let (trace, public) = generate_trace(&air, &w);
        assert!(
            !check_all_constraints(&air, &trace, &public, Some(1))
                .failures
                .is_empty()
        );
    }

    #[test]
    fn hidden_supply_trace_rejects_public_tampering() {
        let (_, w, _) = fixture(3);
        let air = IssuanceAir::new(3);
        let (trace, public) = generate_trace(&air, &w);
        assert!(
            check_all_constraints(&air, &trace, &public, None)
                .failures
                .is_empty()
        );
        for index in [
            PUBLIC_ASSET,
            PUBLIC_SUPPLY,
            PUBLIC_BINDING,
            PUBLIC_COMMITMENTS,
            public.len() - 1,
        ] {
            let mut bad = public.clone();
            bad[index] += F::ONE;
            assert!(
                !check_all_constraints(&air, &trace, &bad, None)
                    .failures
                    .is_empty(),
                "field {index}"
            );
        }
    }
    #[test]
    fn native_issuance_round_trip_requires_signature_supply_and_sip_fee() {
        let (signed, witness, policy) = fixture(2);
        let prover = IssuanceProver::new(2, FriParams::fast());
        let (proof, public) = prover.prove(&witness).unwrap();
        prover.verify(&proof, &public).unwrap();
        assert!(matches!(
            prover.verify_signed(
                &signed,
                &proof,
                &signed.declaration.network,
                1,
                policy,
                &witness.ciphertexts,
                |_, _| false
            ),
            Err(IssuanceError::UnpaidIssuanceFee)
        ));
        let verified = prover
            .verify_signed(
                &signed,
                &proof,
                &signed.declaration.network,
                1,
                policy,
                &witness.ciphertexts,
                |binding, fee| *binding == signed.declaration.binding() && fee == 123,
            )
            .unwrap();
        let mut registry = IssuanceRegistry::default();
        registry.apply_verified(verified).unwrap();
        let mut bad = public.clone();
        bad[PUBLIC_SUPPLY] += F::ONE;
        assert!(prover.verify(&proof, &bad).is_err());
    }
    #[test]
    fn air_itself_rejects_oversupply_and_asset_substitution() {
        let (_, mut witness, _) = fixture(2);
        let air = IssuanceAir::new(2);
        witness.notes[0].value += 1;
        witness.declaration.note_commitments[0] = Hasher::new().note_cm(&witness.notes[0]);
        let (trace, public) = generate_trace(&air, &witness);
        assert!(
            !check_all_constraints(&air, &trace, &public, None)
                .failures
                .is_empty()
        );
        witness.declaration.public_supply += 1;
        witness.notes[0].asset_id.0[0] ^= 1;
        witness.declaration.note_commitments[0] = Hasher::new().note_cm(&witness.notes[0]);
        let (trace, public) = generate_trace(&air, &witness);
        assert!(
            !check_all_constraints(&air, &trace, &public, None)
                .failures
                .is_empty()
        );
    }

    #[test]
    fn issuer_cannot_prove_hidden_overissuance_or_wrong_asset() {
        let (_, mut w, _) = fixture(2);
        let prover = IssuanceProver::new(2, FriParams::fast());
        w.notes[0].value += 1;
        w.declaration.note_commitments[0] = Hasher::new().note_cm(&w.notes[0]);
        assert!(matches!(
            prover.prove(&w),
            Err(IssuanceError::SupplyMismatch)
        ));
        w.notes[0].asset_id.0[0] ^= 1;
        assert!(matches!(
            prover.prove(&w),
            Err(IssuanceError::NoteAssetMismatch)
        ));
    }
}
