//! Plonky3 implementation of the slot-relation subset: single-slot uni-STARK proofs plus
//! recursive binary aggregation.
//!
//! A library-selection experiment only; not on the consensus path.

// AIR code indexes several column slices with one row or element index.
#![allow(clippy::needless_range_loop)]

pub mod agg;
pub mod air;
pub mod codec;
pub mod common;
pub mod encryption;
pub mod envelope;
pub mod fee_settlement;
pub mod fee_settlement_air;
#[cfg(feature = "security-report")]
pub mod native_security;
pub mod native_verifier;
pub mod padding_pool;
#[cfg(feature = "phase-profile")]
pub mod profile;
pub mod proof_codec;
#[cfg(feature = "security-report")]
pub mod security;
pub mod snapshots;
pub mod trace;
pub mod transaction;

use crate::common::{AccWitness, Digest, F, SlotWitness};
use p3_recursion::VerifierLimits;
use p3_recursion::builtin_config::{
    ExperimentalKoalaBearD8Poseidon2W24RandomCodewordConfig, FriConfigV1, SuiteIdV1,
    experimental_koala_bear_d8_poseidon2_w24_random_codeword,
};
use p3_uni_stark::{
    PreprocessedProverData, PreprocessedVerifierKey, Proof, prove_with_preprocessed,
    setup_preprocessed, verify_with_preprocessed,
};
use rand::rngs::StdRng;

pub use air::SlotAir;

/// Configuration shared by every layer: KoalaBear, degree-8 extension, Poseidon2 Merkle trees,
/// and hiding FRI with random codewords (zero knowledge).
pub type Cfg = ExperimentalKoalaBearD8Poseidon2W24RandomCodewordConfig<StdRng>;

/// Experimental D8 parameters require actual instance-shape security reports.
/// `fast()` is for debugging only.
#[derive(Clone, Copy, Debug)]
pub struct FriParams {
    pub log_blowup: u32,
    pub num_queries: u32,
    pub query_pow_bits: u32,
    pub commit_pow_bits: u32,
    pub batch_pow_bits: u32,
    pub max_log_arity: u32,
}

impl FriParams {
    /// Recursive planning profile only; the checkpoint supplies explicit screened values.
    pub const fn candidate() -> Self {
        Self {
            log_blowup: 2,
            num_queries: 208,
            query_pow_bits: 16,
            commit_pow_bits: 16,
            batch_pow_bits: 16,
            max_log_arity: 1,
        }
    }

    pub const fn fast() -> Self {
        Self {
            log_blowup: 2,
            num_queries: 2,
            query_pow_bits: 0,
            commit_pow_bits: 0,
            batch_pow_bits: 0,
            max_log_arity: 1,
        }
    }

    /// Engineering-frozen native V1 profile selected by the 80-bit scan.
    /// The legacy method name is retained for benchmark compatibility.
    /// This freeze does not assert cryptographic approval or network activation.
    pub const fn transaction_candidate() -> Self {
        Self {
            log_blowup: 8,
            num_queries: 36,
            query_pow_bits: 20,
            commit_pow_bits: 0,
            batch_pow_bits: 20,
            max_log_arity: 1,
        }
    }

    /// Smallest trace height hiding FRI accepts: 2·(D·opening points + queries) mask rows,
    /// with D = 8 and two opening points (ζ and ζ·g), rounded up to a power of two.
    pub fn hiding_min_height(&self) -> usize {
        (2 * (8 * 2 + self.num_queries as usize)).next_power_of_two()
    }

    /// Historical query/grinding score only; use instance-specific security reports.
    pub fn conjectured_bits(&self) -> u32 {
        self.log_blowup * self.num_queries + self.query_pow_bits
    }

    pub fn descriptor(&self) -> FriConfigV1 {
        let suite = SuiteIdV1::ExperimentalKoalaBearD8Poseidon2W24RandomCodewordFri;
        FriConfigV1::new(
            suite,
            self.log_blowup,
            0,
            self.max_log_arity,
            self.num_queries,
            self.commit_pow_bits,
            self.query_pow_bits,
            1,
            2,
            8,
            suite.spec().salt_elements as u32,
        )
        .with_batch_pow_bits(self.batch_pow_bits)
    }

    /// Hiding-FRI randomness: the PCS holds a ChaCha12 generator seeded from the operating
    /// system's CSPRNG when the configuration is built, and derives a fresh generator from it for
    /// every commitment and opening. Nothing is seeded deterministically.
    pub fn config(&self) -> Cfg {
        experimental_koala_bear_d8_poseidon2_w24_random_codeword(
            &self.descriptor(),
            &VerifierLimits::default(),
            rand::make_rng::<StdRng>(),
        )
        .expect("valid FRI parameters")
    }
}

/// Single-slot prover: holds the AIR and the preprocessed commitment.
pub struct SlotProver {
    pub cfg: Cfg,
    pub air: SlotAir,
    pub pdata: PreprocessedProverData<Cfg>,
    pub vk: PreprocessedVerifierKey<Cfg>,
}

impl SlotProver {
    pub fn new(params: FriParams) -> Self {
        Self::with_air(params, SlotAir::new())
    }

    /// Chain mode (fixed-width statement, for state-transition aggregation).
    pub fn new_chain(params: FriParams) -> Self {
        Self::with_air(params, SlotAir::new_chain())
    }

    /// Accumulator mode (order-independent set sum plus fee limbs, for the custom aggregation in
    /// `agg`).
    pub fn new_acc(params: FriParams) -> Self {
        Self::with_air(params, SlotAir::new_acc())
    }

    fn with_air(params: FriParams, air: SlotAir) -> Self {
        let cfg = params.config();
        let air = air.with_min_height(params.hiding_min_height());
        let (pdata, vk) = setup_preprocessed(&cfg, &air, air.degree_bits())
            .expect("preprocessed commitment")
            .expect("AIR has preprocessed columns");
        Self {
            cfg,
            air,
            pdata,
            vk,
        }
    }

    /// Returns (proof, public inputs).
    pub fn prove(&self, w: &SlotWitness) -> (Proof<Cfg>, Vec<F>) {
        let (trace, pis) = trace::generate(&self.air, w);
        let proof = prove_with_preprocessed(&self.cfg, &self.air, trace, &pis, Some(&self.pdata))
            .expect("proof generation");
        (proof, pis)
    }

    /// Chain mode: returns (proof, [s_in, s_out, 1]).
    pub fn prove_chain(&self, w: &SlotWitness, s_in: &Digest) -> (Proof<Cfg>, Vec<F>) {
        let (trace, pis) = trace::generate_chain(&self.air, w, s_in);
        let proof = prove_with_preprocessed(&self.cfg, &self.air, trace, &pis, Some(&self.pdata))
            .expect("proof generation");
        (proof, pis)
    }

    /// Accumulator mode: returns (proof, [E, fee limbs, 1, 𝒜 root]).
    pub fn prove_acc(&self, w: &AccWitness) -> (Proof<Cfg>, Vec<F>) {
        let (trace, pis) = trace::generate_acc(&self.air, w);
        let proof = prove_with_preprocessed(&self.cfg, &self.air, trace, &pis, Some(&self.pdata))
            .expect("proof generation");
        (proof, pis)
    }

    pub fn verify(&self, proof: &Proof<Cfg>, pis: &[F]) -> Result<(), String> {
        verify_with_preprocessed(&self.cfg, &self.air, proof, pis, Some(&self.vk))
            .map_err(|e| format!("{e:?}"))
    }
}

/// Serialized proof size in bytes (postcard).
pub fn proof_size(proof: &Proof<Cfg>) -> usize {
    postcard::to_allocvec(proof).expect("serialize").len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        FEE_BASE, Hasher, LIMB_BITS, LIMBS, MIN_PACKAGE_DEPOSIT, Rng, WIDTH, acc_witnesses,
        sample_empty_slot, sample_slot, with_unlock_heights,
    };
    use air::*;
    use p3_air::check_all_constraints;
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use p3_matrix::Matrix;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_poseidon2_air::generate_trace_rows;
    use std::collections::BTreeSet;

    fn violations(w: &SlotWitness) -> usize {
        let air = SlotAir::new();
        let (trace, pis) = trace::generate(&air, w);
        check_all_constraints(&air, &trace, &pis, None)
            .failures
            .len()
    }

    #[test]
    fn poseidon2_air_layout_matches_native_permutation() {
        let h = Hasher::new();
        let mut rng = Rng::new(7);
        let inputs: Vec<[F; WIDTH]> = (0..4)
            .map(|_| core::array::from_fn(|_| rng.felt()))
            .collect();
        let t = generate_trace_rows::<F, LinearLayers, WIDTH, 3, 0, 4, 23>(
            inputs.clone(),
            &p2_constants(),
            0,
        );
        for (r, inp) in inputs.iter().enumerate() {
            let row = &t.values[r * P2..(r + 1) * P2];
            assert_eq!(&row[..WIDTH], inp);
            assert_eq!(&row[OUT..P2], &h.permute(*inp));
        }
    }

    #[test]
    fn valid_slots_satisfy_constraints() {
        let h = Hasher::new();
        for (seed, dummy) in [(1, false), (2, true), (3, false)] {
            let w = sample_slot(seed, dummy);
            w.check(&h).expect("sample is valid");
            assert_eq!(violations(&w), 0, "seed {seed} dummy {dummy}");
        }
    }

    #[test]
    fn tampered_witnesses_violate_constraints() {
        let base = sample_slot(1, false);
        let mut cases: Vec<(&str, SlotWitness)> = Vec::new();

        let mut w = base.clone();
        w.outputs[0].value += 1;
        cases.push(("value not conserved", w));

        let mut w = base.clone();
        w.anchor[0] += F::from_u32(1);
        cases.push(("anchor mismatch", w));

        let mut w = base.clone();
        w.inputs[0].path[17].0[3] += F::from_u32(1);
        cases.push(("Merkle path tampered", w));

        let mut w = base.clone();
        w.fee += 1;
        cases.push(("fee not in a tier", w));

        let mut w = base.clone();
        w.inputs[1].dummy = true;
        cases.push(("non-zero value marked as dummy input", w));

        // Output value overflowing 64 bits: o₀ = 2^64 − 1 with o₁ absorbing the difference must be
        // rejected by the range check or by conservation.
        let mut w = base.clone();
        w.outputs[0].value = u64::MAX;
        cases.push(("output value overflow", w));

        for (name, w) in cases {
            assert!(violations(&w) > 0, "{name} should violate constraints");
        }
    }

    fn chain_violations(w: &SlotWitness, tamper: impl Fn(&mut Vec<F>)) -> usize {
        let air = SlotAir::new_chain();
        let s_in = Rng::new(9).digest();
        let (trace, mut stmt) = trace::generate_chain(&air, w, &s_in);
        tamper(&mut stmt);
        check_all_constraints(&air, &trace, &stmt, None)
            .failures
            .len()
    }

    #[test]
    fn chain_mode_binds_statement() {
        let h = Hasher::new();
        let w = sample_slot(1, false);
        assert_eq!(chain_violations(&w, |_| {}), 0);
        let w2 = sample_slot(2, true);
        assert_eq!(chain_violations(&w2, |_| {}), 0, "dummy input");
        // s_out must equal the native chain hash.
        let s_in = Rng::new(9).digest();
        let (_, stmt) = trace::generate_chain(&SlotAir::new_chain(), &w, &s_in);
        assert_eq!(
            &stmt[STMT_OUT..STMT_COUNT],
            &w.check(&h).unwrap().chain_step(&h, &s_in)
        );
        assert!(
            chain_violations(&w, |s| s[STMT_OUT + 2] += F::ONE) > 0,
            "tampered s_out"
        );
        assert!(
            chain_violations(&w, |s| s[STMT_IN] += F::ONE) > 0,
            "tampered s_in"
        );
        assert!(
            chain_violations(&w, |s| s[STMT_COUNT] = F::TWO) > 0,
            "count ≠ 1"
        );
        let mut bad = w.clone();
        bad.outputs[0].value += 1;
        assert!(
            chain_violations(&bad, |_| {}) > 0,
            "conservation must still be checked in chain mode"
        );
        let mut bad = w.clone();
        bad.inputs[0].path[3].0[0] += F::ONE;
        assert!(
            chain_violations(&bad, |_| {}) > 0,
            "anchor must still be checked in chain mode"
        );
    }

    /// Constraint failures of the trace of `w` checked against `stmt` (tampered by `tamper`).
    fn acc_failures(w: &AccWitness, stmt: &[F], tamper: impl Fn(&mut Vec<F>)) -> usize {
        let air = SlotAir::new_acc();
        let (trace, _) = trace::generate_acc(&air, w);
        let mut stmt = stmt.to_vec();
        tamper(&mut stmt);
        check_all_constraints(&air, &trace, &stmt, None)
            .failures
            .len()
    }

    /// Failures against the statement the witness itself implies.
    fn acc_violations(w: &AccWitness, tamper: impl Fn(&mut Vec<F>)) -> usize {
        let (_, stmt) = trace::generate_acc(&SlotAir::new_acc(), w);
        acc_failures(w, &stmt, tamper)
    }

    fn acc_block(base_fee: u64) -> (Vec<AccWitness>, crate::common::Digest) {
        use crate::common::{sample_priority_slot, with_base_fee};
        let slots = [
            sample_slot(1, false),
            sample_priority_slot(2),
            sample_empty_slot(3),
            sample_slot(4, true),
        ]
        .map(|w| with_base_fee(w, base_fee));
        acc_witnesses(slots.to_vec(), 4094, base_fee, 9)
    }

    #[test]
    fn acc_mode_binds_statement() {
        use crate::common::{DCT_LEN, FEE_BASE, SET_LEN, limbs, pack_dct};
        let h = Hasher::new();
        let air = SlotAir::new_acc();
        assert_eq!(
            air.height, 128,
            "without the 𝒜 path the leaf fits in 128 rows"
        );
        let (ws, root) = acc_block(FEE_BASE);
        let fees = [FEE_BASE, 4 * FEE_BASE, 0, FEE_BASE];
        for (w, fee) in ws.iter().zip(fees) {
            assert_eq!(acc_violations(w, |_| {}), 0, "fee {fee}");
            let (_, stmt) = trace::generate_acc(&air, w);
            assert_eq!(stmt.len(), NUM_ACC_PUBLIC);
            let leaf = w.check(&h, &root).unwrap();
            assert_eq!(&stmt[ACC_SET..ACC_FEE], &leaf.set);
            assert_eq!(&stmt[ACC_FEE..ACC_COUNT], &limbs(fee));
            assert_eq!(stmt[ACC_COUNT], F::ONE);
            assert_eq!(&stmt[ACC_ENTRY..NUM_ACC_PUBLIC], &w.anchor_entry(&h));
            assert_eq!(leaf.anchors_root, root);
        }
        // Any base fee the accumulator entry carries works.
        let (alt, _) = acc_block(500_001);
        for w in &alt {
            assert_eq!(acc_violations(w, |_| {}), 0, "base fee 500001");
        }

        let w = &ws[0];
        let (_, stmt) = trace::generate_acc(&air, w);
        for e in [0, 7, 8, SET_LEN - 1] {
            assert!(
                acc_violations(w, |s| s[ACC_SET + e] += F::ONE) > 0,
                "tampered set element {e}"
            );
        }
        for k in 0..4 {
            assert!(
                acc_violations(w, |s| s[ACC_FEE + k] += F::ONE) > 0,
                "tampered fee limb {k}"
            );
        }
        for e in [0, 7] {
            assert!(
                acc_violations(w, |s| s[ACC_ENTRY + e] += F::ONE) > 0,
                "tampered 𝒜 entry {e}"
            );
        }
        assert!(
            acc_violations(&ws[2], |s| s[ACC_FEE] = F::ONE) > 0,
            "empty slot claiming a fee"
        );
        assert!(
            acc_violations(w, |s| s[ACC_COUNT] = F::TWO) > 0,
            "count ≠ 1"
        );

        // E binds every d_ct limb.
        for k in [0, DCT_LEN - 1] {
            let mut bad = w.clone();
            bad.d_ct[2 * k] ^= 1;
            assert_ne!(pack_dct(&bad.d_ct), pack_dct(&w.d_ct));
            assert!(acc_failures(&bad, &stmt, |_| {}) > 0, "d_ct limb {k}");
        }
        // The entry binds the anchor root, its height and the base fee. Membership in 𝒜 is the
        // level-1 node's job (agg.rs), so the leaf ignores the path.
        let mut bad = w.clone();
        bad.anchor_height += 1;
        assert!(acc_failures(&bad, &stmt, |_| {}) > 0, "anchor height");
        let mut bad = w.clone();
        bad.anchor_path[5].0[0] += F::ONE;
        bad.anchor_path[0].1 ^= true;
        assert_eq!(
            acc_failures(&bad, &stmt, |_| {}),
            0,
            "the leaf does not read the path"
        );
        // A base fee the entry does not carry, with the fee following it.
        let mut bad = w.clone();
        bad.slot = crate::common::with_base_fee(bad.slot, 1);
        bad.base_fee = 1;
        assert!(
            acc_failures(&bad, &stmt, |s| s[ACC_FEE..ACC_COUNT]
                .copy_from_slice(&limbs(1)))
                > 0,
            "wrong base fee"
        );
        // Fees off the tier set {0, base, 4·base}.
        for fee in [2 * FEE_BASE, FEE_BASE - 1, FEE_BASE + 1, 0] {
            let mut bad = w.clone();
            bad.slot.outputs[1].value = bad.slot.outputs[1].value + bad.slot.fee - fee;
            bad.slot.fee = fee;
            assert!(acc_violations(&bad, |_| {}) > 0, "fee {fee}");
        }
        let mut bad = ws[1].clone();
        bad.slot.outputs[1].value += 3 * FEE_BASE;
        bad.slot.fee = FEE_BASE;
        assert!(
            acc_violations(&bad, |_| {}) > 0,
            "priority slot paying base"
        );

        let mut bad = w.clone();
        bad.slot.outputs[0].value += 1;
        assert!(
            acc_violations(&bad, |_| {}) > 0,
            "conservation must still be checked in accumulator mode"
        );
        let mut bad = w.clone();
        bad.slot.inputs[0].path[3].0[0] += F::ONE;
        assert!(
            acc_violations(&bad, |_| {}) > 0,
            "input membership must still be checked in accumulator mode"
        );
    }

    #[test]
    fn d8_ciphertext_limbs_and_padding_are_constrained() {
        let (witnesses, _) = acc_block(FEE_BASE);
        let air = SlotAir::new_acc();
        let witness = &witnesses[0];
        for k in 0..crate::common::DCT_LEN {
            let column = ACC_REG + ACC_DCT + k;
            assert!(
                air.range.contains(&column),
                "ciphertext limb {k} has a range-check row"
            );
            let (trace, public) =
                trace::generate_edited(&air, &witness.slot, Some(witness), &|registers| {
                    registers[column - REG] = F::from_u32(1 << LIMB_BITS);
                });
            assert!(failing_rows(&air, &trace, &public).contains(&range_row(&air, column)));
        }
        for k in crate::common::DCT_LEN
            ..crate::common::DCT_LEN.div_ceil(crate::common::RATE) * crate::common::RATE
        {
            let column = ACC_REG + ACC_DCT + k;
            let (trace, public) =
                trace::generate_edited(&air, &witness.slot, Some(witness), &|registers| {
                    registers[column - REG] = F::ONE;
                });
            assert!(
                !failing_rows(&air, &trace, &public).is_empty(),
                "padding {k}"
            );
        }
    }

    /// Sets register `col` to `v` in every row and refreshes its range-check row, as a prover
    /// choosing that witness would.
    fn set_reg(air: &SlotAir, trace: &mut RowMajorMatrix<F>, col: usize, v: F) {
        let w = trace.width;
        for r in 0..trace.height() {
            trace.values[r * w + col] = v;
        }
        if let Some(r) = air.range.iter().position(|&c| c == col) {
            let rv = v.as_canonical_u32();
            trace.values[r * w + RV] = v;
            for k in 0..LIMB_BITS {
                trace.values[r * w + RBITS + k] = F::from_u32((rv >> k) & 1);
            }
        }
    }

    fn failing_rows(air: &SlotAir, trace: &RowMajorMatrix<F>, pis: &[F]) -> BTreeSet<usize> {
        check_all_constraints(air, trace, pis, None)
            .failures
            .iter()
            .map(|f| f.row)
            .collect()
    }

    /// The row that range-checks register `col`.
    fn range_row(air: &SlotAir, col: usize) -> usize {
        air.range
            .iter()
            .position(|&c| c == col)
            .unwrap_or_else(|| panic!("column {col} is not range-checked"))
    }

    /// The single-slot accumulator witness anchored at `height`, with its 𝒜 root.
    fn acc_at(w: SlotWitness, height: u64) -> (AccWitness, crate::common::Digest) {
        let (mut ws, root) = acc_witnesses(vec![w], height, FEE_BASE, 3);
        (ws.remove(0), root)
    }

    #[test]
    fn unlock_height_at_most_anchor_height() {
        let h = Hasher::new();
        // sample_slot unlocks its inputs at 100 and 120; equality is allowed.
        for (height, ok) in [(120, true), (119, false), (100, false), (1 << 20, true)] {
            let (a, root) = acc_at(sample_slot(1, false), height);
            assert_eq!(a.check(&h, &root).is_ok(), ok, "native, height {height}");
            assert_eq!(acc_violations(&a, |_| {}) == 0, ok, "height {height}");
        }
        for (unlock, ok) in [
            ([500, 500], true),
            ([501, 0], false),
            ([0, 501], false),
            ([500 + (1 << 16), 0], false),
            ([u64::MAX, 0], false),
        ] {
            let (a, root) = acc_at(with_unlock_heights(sample_slot(1, false), unlock), 500);
            assert_eq!(a.check(&h, &root).is_ok(), ok, "native, {unlock:?}");
            assert_eq!(acc_violations(&a, |_| {}) == 0, ok, "{unlock:?}");
        }
        // A dummy input's unlock height is not checked.
        let (a, _) = acc_at(
            with_unlock_heights(sample_slot(1, true), [500, u64::MAX]),
            500,
        );
        assert_eq!(acc_violations(&a, |_| {}), 0, "dummy input");

        // unlock = height + 1 with δ = −1 (p − 1) and no carries satisfies every limb equation;
        // only the range check of δ rejects it.
        let (a, _) = acc_at(with_unlock_heights(sample_slot(1, false), [501, 0]), 500);
        let air = SlotAir::new_acc();
        let (mut trace, stmt) = trace::generate_acc(&air, &a);
        let d = acc_ud(0);
        set_reg(&air, &mut trace, d, F::NEG_ONE);
        for col in d + 1..d + UD_W {
            set_reg(&air, &mut trace, col, F::ZERO);
        }
        assert_eq!(
            failing_rows(&air, &trace, &stmt),
            BTreeSet::from([range_row(&air, d)])
        );
    }

    /// Output 0 set to `o0`, output 1 absorbing the difference.
    fn with_output0(mut w: SlotWitness, o0: u64) -> SlotWitness {
        w.outputs[1].value = w.outputs[1].value + w.outputs[0].value - o0;
        w.outputs[0].value = o0;
        w
    }

    #[test]
    fn outputs_are_zero_or_at_least_the_minimum_deposit() {
        let h = Hasher::new();
        for (o0, ok) in [
            (1, false),
            (MIN_PACKAGE_DEPOSIT - 1, false),
            (MIN_PACKAGE_DEPOSIT, true),
            (0, true),
        ] {
            let w = with_output0(sample_slot(1, false), o0);
            assert_eq!(w.check(&h).is_ok(), ok, "native {o0}");
            assert_eq!(violations(&w) == 0, ok, "plain {o0}");
            assert_eq!(chain_violations(&w, |_| {}) == 0, ok, "chain {o0}");
            let (a, _) = acc_at(w, 4094);
            assert_eq!(acc_violations(&a, |_| {}) == 0, ok, "accumulator {o0}");
        }
        let mut w = sample_slot(1, false);
        w.outputs[0].value += w.outputs[1].value - (MIN_PACKAGE_DEPOSIT - 1);
        w.outputs[1].value = MIN_PACKAGE_DEPOSIT - 1;
        assert!(violations(&w) > 0, "output 1");

        let w = with_output0(sample_slot(1, false), MIN_PACKAGE_DEPOSIT - 1);
        let air = SlotAir::new();
        // Claiming the value is zero.
        let (mut trace, pis) = trace::generate(&air, &w);
        set_reg(&air, &mut trace, output(0) + OUT_Z, F::ONE);
        assert!(!failing_rows(&air, &trace, &pis).is_empty(), "z = 1");
        // δ = −1 (p − 1) and no carries satisfies every limb equation; only the range check of
        // δ rejects it.
        let (mut trace, pis) = trace::generate(&air, &w);
        let d = output(0) + OUT_MD;
        for col in d..output(0) + OUT_W {
            set_reg(&air, &mut trace, col, F::ZERO);
        }
        set_reg(&air, &mut trace, d, F::NEG_ONE);
        assert_eq!(
            failing_rows(&air, &trace, &pis),
            BTreeSet::from([range_row(&air, d)])
        );
    }

    #[test]
    fn nullifiers_must_differ() {
        let h = Hasher::new();
        // Input 1 repeats input 0's nk and ρ as a dummy, so nf₁ = nf₀.
        let mut w = sample_slot(1, false);
        w.outputs[1].value -= w.inputs[1].value;
        w.inputs[1].nk = w.inputs[0].nk;
        w.inputs[1].rho = w.inputs[0].rho;
        w.inputs[1].dummy = true;
        w.inputs[1].value = 0;
        assert_eq!(w.check(&h), Err("duplicate nullifier"));
        assert!(violations(&w) > 0, "plain");
        assert!(chain_violations(&w, |_| {}) > 0, "chain");
        let (a, _) = acc_at(w, 4094);
        assert!(acc_violations(&a, |_| {}) > 0, "accumulator");
    }

    /// Every u64 limb the prover hashes is range-checked (00-decisions). Respelling a u64 as
    /// (l₀ + 2¹⁶, l₁ − 1, …) keeps the integer; with every hash recomputed, only the range check
    /// rejects it.
    #[test]
    fn hashed_limbs_are_range_checked() {
        let respell = |col: usize| {
            move |regs: &mut [F]| {
                regs[col - REG] += F::from_u32(1 << LIMB_BITS);
                regs[col + 1 - REG] -= F::ONE;
            }
        };
        let check = |air: &SlotAir, w: &SlotWitness, a: Option<&AccWitness>, col: usize| {
            let (trace, pis) = trace::generate_edited(air, w, a, &|_| {});
            assert!(failing_rows(air, &trace, &pis).is_empty(), "unedited {col}");
            let (trace, pis) = trace::generate_edited(air, w, a, &respell(col));
            assert_eq!(
                failing_rows(air, &trace, &pis),
                BTreeSet::from([range_row(air, col)]),
                "column {col}"
            );
        };
        // Input 0 unlocks at 2¹⁶ + 100 (limbs 100, 1), input 1 is a dummy; output 0 unlocks at
        // 2¹⁶ + 7. The anchor height 2·2¹⁶ + 300 has limbs (300, 2).
        let spend = with_unlock_heights(sample_slot(1, true), [(1 << 16) + 100, 0]);
        let mut spend_out = spend.clone();
        spend_out.outputs[0].unlock_height = (1 << 16) + 7;
        let height = 2 * (1 << 16) + 300;

        let air = SlotAir::new();
        check(&air, &spend, None, input(0) + IN_VU);
        check(&air, &spend, None, input(0) + IN_VU + LIMBS);
        check(&air, &spend_out, None, output(0) + OUT_VU + LIMBS);

        let air = SlotAir::new_acc();
        let (a, _) = acc_at(spend, height);
        check(&air, &a.slot, Some(&a), input(0) + IN_VU + LIMBS);
        let (a, _) = acc_at(spend_out, height);
        check(&air, &a.slot, Some(&a), output(0) + OUT_VU + LIMBS);
        // The 𝒜 entry's anchor height and base fee, on an empty slot where neither feeds another
        // check.
        let (a, _) = acc_at(sample_empty_slot(3), height);
        check(&air, &a.slot, Some(&a), ACC_REG + ACC_HB);
        check(&air, &a.slot, Some(&a), ACC_REG + ACC_BF);
    }

    #[test]
    fn prove_and_verify_fast_params() {
        let p = SlotProver::new(FriParams::fast());
        let w = sample_slot(5, false);
        let (proof, pis) = p.prove(&w);
        p.verify(&proof, &pis).expect("valid proof should verify");
        let mut bad = pis.clone();
        bad[0] += F::from_u32(1);
        assert!(
            p.verify(&proof, &bad).is_err(),
            "tampered public inputs should fail"
        );
    }

    #[test]
    fn leaf_height_covers_hiding_budget() {
        use crate::common::FEE_BASE;
        // Hiding FRI needs 2·(D·opening points + queries) mask rows (`hiding_budget` in p3-fri),
        // so 42 queries fit the 128-row leaf and 92 queries need 256 rows.
        assert_eq!(FriParams::candidate().hiding_min_height(), 512);
        let q92 = FriParams {
            num_queries: 92,
            ..FriParams::candidate()
        };
        assert_eq!(q92.hiding_min_height(), 256);
        assert_eq!(SlotAir::new_acc().with_min_height(64).height, 128);
        let air = SlotAir::new_acc().with_min_height(256);
        assert_eq!(air.height, 256);
        let (ws, _) = acc_block(FEE_BASE);
        for w in &ws {
            let (trace, stmt) = trace::generate_acc(&air, w);
            assert_eq!(p3_matrix::Matrix::height(&trace), 256);
            assert_eq!(stmt, trace::generate_acc(&SlotAir::new_acc(), w).1);
            assert!(
                check_all_constraints(&air, &trace, &stmt, None)
                    .failures
                    .is_empty()
            );
        }
        let p = SlotProver::new_acc(q92);
        assert_eq!(p.air.height, 256);
        let (proof, pis) = p.prove_acc(&ws[1]);
        p.verify(&proof, &pis)
            .expect("92 queries prove on the padded leaf");
    }
}
