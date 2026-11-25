//! Native D8/W24 transaction proof with a private recent-root membership path.
//!
//! The existing accumulator leaf relation is embedded as a sub-AIR. Its anchor
//! entry is private in this proof; a second Poseidon2 trace proves that entry's
//! depth-12 membership and binds its position to the private anchor height.
//! Public values are `[E, fee commitment, 1, recent_roots_root]`. A verifier must
//! recompute E from the canonical public transaction encoding before verifying.
//! This module does not change the retained network's codec or proof system.

use crate::air::{
    ACC_ENTRY_CONF, ACC_HB, ACC_REG, LinearLayers, NUM_ACC_CONF_PUBLIC, OUT, P2, P2Air, SlotAir,
    p2_constants,
};
use crate::common::{
    ANCHOR_DEPTH, AccWitness, DCT_BYTES, DIGEST, Digest, F, Hasher, LIMB_BITS, PublicInputs, WIDTH,
    digest_of, pack_dct,
};
use crate::{Cfg, FriParams, trace};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::generate_trace_rows;
use p3_uni_stark::{
    PreprocessedProverData, PreprocessedVerifierKey, Proof, SubAirBuilder, prove_with_preprocessed,
    setup_preprocessed, verify_with_preprocessed,
};
use std::ops::Range;

/// The public statement retains the accumulator's layout but replaces its
/// per-transaction anchor entry with the shared recent-root tree root.
pub const NUM_TRANSACTION_PUBLIC: usize = NUM_ACC_CONF_PUBLIC;
pub const TRANSACTION_ROOT: usize = ACC_ENTRY_CONF;

/// Recompute the proof statement from canonical decoded transaction fields.
/// The caller supplies the current accepted recent-root tree root, never a
/// root copied from an untrusted proof. Ciphertext/nonces/tags must all enter
/// `ciphertext_digest` through the canonical codec's domain-separated hash.
pub fn statement_for(
    nullifiers: &[Digest; 2],
    commitments: &[Digest; 2],
    ciphertext_digest: &[u8; DCT_BYTES],
    fee_commit: &Digest,
    recent_roots_root: &Digest,
) -> Vec<F> {
    let inputs = PublicInputs {
        nf: *nullifiers,
        cm_out: *commitments,
        anchor: [F::ZERO; DIGEST],
        fee_commit: *fee_commit,
    };
    let mut statement = inputs
        .set_element(&Hasher::new(), &pack_dct(ciphertext_digest))
        .to_vec();
    statement.extend_from_slice(fee_commit);
    statement.push(F::ONE);
    statement.extend_from_slice(recent_roots_root);
    statement
}

/// Main columns after the embedded leaf: its now-private statement, a second
/// Poseidon2 permutation, the current path direction and the low height bits.
const HEIGHT_BITS: usize = LIMB_BITS;

pub struct TransactionAir {
    pub slot: SlotAir,
    path_p2: P2Air,
}

impl Default for TransactionAir {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionAir {
    pub fn new() -> Self {
        Self {
            slot: SlotAir::new_acc_confidential(),
            path_p2: P2Air::new(p2_constants()),
        }
    }

    pub fn with_min_height(mut self, height: usize) -> Self {
        self.slot = self.slot.with_min_height(height);
        self
    }

    pub fn degree_bits(&self) -> usize {
        self.slot.degree_bits()
    }

    fn statement(&self) -> usize {
        self.slot.main_width()
    }

    fn path(&self) -> usize {
        self.statement() + NUM_ACC_CONF_PUBLIC
    }

    fn bit(&self) -> usize {
        self.path() + P2
    }

    fn height_bits(&self) -> usize {
        self.bit() + 1
    }

    fn selector(&self) -> usize {
        self.slot.preprocessed_width()
    }

    /// Generate a trace without accepting or repairing an invalid witness.
    /// Constraint checking or proof verification remains the validity decision.
    pub fn generate(&self, w: &AccWitness) -> (RowMajorMatrix<F>, Vec<F>) {
        assert_eq!(w.anchor_path.len(), ANCHOR_DEPTH, "anchor path length");
        let (leaf, private_statement) = trace::generate_acc_confidential(&self.slot, w);
        let mut public = private_statement.clone();
        public[TRANSACTION_ROOT..].copy_from_slice(&w.anchors_root(&Hasher::new()));
        let h = Hasher::new();
        let mut current = w.anchor_entry(&h);
        let mut path_inputs = Vec::with_capacity(self.slot.height);
        let mut directions = vec![F::ZERO; self.slot.height];
        for (level, (sibling, right)) in w.anchor_path.iter().enumerate() {
            let input = if *right {
                Hasher::compress_input(sibling, &current)
            } else {
                Hasher::compress_input(&current, sibling)
            };
            path_inputs.push(input);
            directions[level] = F::from_bool(*right);
            current = digest_of(&h.permute(input));
        }
        path_inputs.resize(self.slot.height, [F::ZERO; WIDTH]);
        let path = generate_trace_rows::<F, LinearLayers, WIDTH, 3, 0, 4, 23>(
            path_inputs,
            &p2_constants(),
            0,
        );
        let bits: Vec<F> = (0..HEIGHT_BITS)
            .map(|i| F::from_u32(((w.anchor_height >> i) & 1) as u32))
            .collect();
        let mut values = Vec::with_capacity(self.slot.height * self.width());
        for (row, direction) in directions.into_iter().enumerate() {
            values.extend_from_slice(leaf.row_slice(row).unwrap().as_ref());
            values.extend_from_slice(&private_statement);
            values.extend_from_slice(path.row_slice(row).unwrap().as_ref());
            values.push(direction);
            values.extend_from_slice(&bits);
        }
        (RowMajorMatrix::new(values, self.width()), public)
    }
}

impl BaseAir<F> for TransactionAir {
    fn width(&self) -> usize {
        self.height_bits() + HEIGHT_BITS
    }

    fn preprocessed_width(&self) -> usize {
        self.selector() + ANCHOR_DEPTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let leaf = self.slot.preprocessed_trace().expect("leaf selectors");
        let mut values = Vec::with_capacity(self.slot.height * self.preprocessed_width());
        for row in 0..self.slot.height {
            values.extend_from_slice(leaf.row_slice(row).unwrap().as_ref());
            values.extend((0..ANCHOR_DEPTH).map(|level| F::from_bool(row == level)));
        }
        Some(RowMajorMatrix::new(values, self.preprocessed_width()))
    }

    fn num_public_values(&self) -> usize {
        NUM_TRANSACTION_PUBLIC
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

/// A window view used to embed the leaf with private statement values.
#[derive(Clone)]
struct Columns<W> {
    inner: W,
    range: Range<usize>,
}

impl<W: WindowAccess<T>, T> WindowAccess<T> for Columns<W> {
    fn current_slice(&self) -> &[T] {
        &self.inner.current_slice()[self.range.clone()]
    }
    fn next_slice(&self) -> &[T] {
        &self.inner.next_slice()[self.range.clone()]
    }
}

/// The embedded leaf consumes its original public statement from private,
/// row-constant trace registers. Outer constraints bind all non-anchor values
/// to the actual public statement and replace the anchor entry by membership.
struct PrivateStatementBuilder<'a, AB: AirBuilder> {
    inner: &'a mut AB,
    main: Columns<AB::MainWindow>,
    pre: Columns<AB::PreprocessedWindow>,
    statement: Vec<AB::Var>,
}

impl<AB: AirBuilder> AirBuilder for PrivateStatementBuilder<'_, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type MainWindow = Columns<AB::MainWindow>;
    type PreprocessedWindow = Columns<AB::PreprocessedWindow>;
    type PublicVar = AB::Var;
    type PeriodicVar = AB::PeriodicVar;
    fn main(&self) -> Self::MainWindow {
        self.main.clone()
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.pre
    }
    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }
    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }
    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, value: I) {
        self.inner.assert_zero(value);
    }
    fn public_values(&self) -> &[Self::PublicVar] {
        &self.statement
    }
    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.inner.periodic_values()
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for TransactionAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let private_statement =
            main.current_slice()[self.statement()..self.statement() + NUM_ACC_CONF_PUBLIC].to_vec();
        let pre = builder.preprocessed().clone();
        let mut leaf_builder = PrivateStatementBuilder {
            main: Columns {
                inner: main.clone(),
                range: 0..self.slot.main_width(),
            },
            pre: Columns {
                inner: pre.clone(),
                range: 0..self.slot.preprocessed_width(),
            },
            statement: private_statement,
            inner: builder,
        };
        self.slot.eval(&mut leaf_builder);
        {
            let mut path_builder =
                SubAirBuilder::<AB, P2Air, AB::Var>::new(builder, self.path()..self.path() + P2);
            self.path_p2.eval(&mut path_builder);
        }
        let public = builder.public_values().to_vec();
        let local = main.current_slice();
        let next = main.next_slice();
        let selectors = pre.current_slice();
        let next_selectors = pre.next_slice();
        let x = |v: AB::Var| -> AB::Expr { v.into() };
        for col in self.statement()..self.path() {
            builder.when_transition().assert_eq(next[col], local[col]);
        }
        for i in 0..TRANSACTION_ROOT {
            builder.assert_eq(local[self.statement() + i], public[i]);
        }
        let mut height_low = AB::Expr::ZERO;
        for bit in 0..HEIGHT_BITS {
            let col = self.height_bits() + bit;
            builder.assert_bool(local[col]);
            builder.when_transition().assert_eq(next[col], local[col]);
            height_low += x(local[col]) * F::from_u32(1 << bit);
        }
        builder.assert_eq(height_low, local[ACC_REG + ACC_HB]);
        builder.assert_bool(local[self.bit()]);
        for level in 0..ANCHOR_DEPTH {
            let selector = selectors[self.selector() + level];
            builder.assert_zero(
                (x(local[self.bit()]) - x(local[self.height_bits() + level])) * x(selector),
            );
        }
        for element in 0..DIGEST {
            let current = (x(local[self.path() + DIGEST + element])
                - x(local[self.path() + element]))
                * x(local[self.bit()])
                + x(local[self.path() + element]);
            builder.assert_zero(
                (current - x(local[self.statement() + ACC_ENTRY_CONF + element]))
                    * x(selectors[self.selector()]),
            );
            let following = (x(next[self.path() + DIGEST + element])
                - x(next[self.path() + element]))
                * x(next[self.bit()])
                + x(next[self.path() + element]);
            for level in 1..ANCHOR_DEPTH {
                builder.assert_zero(
                    (following.clone() - x(local[self.path() + OUT + element]))
                        * x(next_selectors[self.selector() + level]),
                );
            }
            builder.assert_zero(
                (x(local[self.path() + OUT + element]) - public[TRANSACTION_ROOT + element].into())
                    * x(selectors[self.selector() + ANCHOR_DEPTH - 1]),
            );
        }
    }
}

/// Prepared native transaction prover. No recursive verifier or aggregation
/// circuit is constructed or executed by this interface.
pub struct TransactionProver {
    pub cfg: Cfg,
    pub air: TransactionAir,
    pub pdata: PreprocessedProverData<Cfg>,
    pub vk: PreprocessedVerifierKey<Cfg>,
}

impl TransactionProver {
    pub fn new(params: FriParams) -> Self {
        let cfg = params.config();
        let air = TransactionAir::new().with_min_height(params.hiding_min_height());
        let (pdata, vk) = setup_preprocessed(&cfg, &air, air.degree_bits())
            .expect("transaction preprocessing")
            .expect("transaction has preprocessed columns");
        Self {
            cfg,
            air,
            pdata,
            vk,
        }
    }
    pub fn prove(&self, witness: &AccWitness) -> (Proof<Cfg>, Vec<F>) {
        let (trace, public) = self.air.generate(witness);
        let proof =
            prove_with_preprocessed(&self.cfg, &self.air, trace, &public, Some(&self.pdata))
                .expect("transaction proof generation");
        (proof, public)
    }
    pub fn verify(&self, proof: &Proof<Cfg>, public: &[F]) -> Result<(), String> {
        verify_with_preprocessed(&self.cfg, &self.air, proof, public, Some(&self.vk))
            .map_err(|e| format!("{e:?}"))
    }
    /// Verify against decoded public fields and an accepted anchor-tree root.
    /// This API does not trust a statement supplied alongside the proof.
    pub fn verify_fields(
        &self,
        proof: &Proof<Cfg>,
        nullifiers: &[Digest; 2],
        commitments: &[Digest; 2],
        ciphertext_digest: &[u8; DCT_BYTES],
        fee_commit: &Digest,
        recent_roots_root: &Digest,
    ) -> Result<(), String> {
        self.verify(
            proof,
            &statement_for(
                nullifiers,
                commitments,
                ciphertext_digest,
                fee_commit,
                recent_roots_root,
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::{ACC_COUNT_CONF, ACC_FEE_COMMIT, CHAIN_REG, pub_cm, pub_nf};
    use crate::common::{
        FEE_BASE, acc_witnesses, sample_empty_slot, sample_priority_slot, sample_slot,
    };
    use p3_air::check_all_constraints;

    fn witness() -> AccWitness {
        let slot = sample_slot(0x7710, false);
        acc_witnesses(vec![slot], 12_289, FEE_BASE, 0x7711)
            .0
            .remove(0)
    }
    fn failures(air: &TransactionAir, witness: &AccWitness) -> usize {
        let (trace, public) = air.generate(witness);
        check_all_constraints(air, &trace, &public, None)
            .failures
            .len()
    }
    #[test]
    fn valid_transaction_checks_private_anchor_path_in_same_air() {
        let air = TransactionAir::new();
        let w = witness();
        let (trace, public) = air.generate(&w);
        assert_eq!(public.len(), NUM_TRANSACTION_PUBLIC);
        assert_eq!(&public[TRANSACTION_ROOT..], &w.anchors_root(&Hasher::new()));
        assert_ne!(&public[TRANSACTION_ROOT..], &w.anchor_entry(&Hasher::new()));
        let fields = w.slot.public_inputs(&Hasher::new());
        assert_eq!(
            public,
            statement_for(
                &fields.nf,
                &fields.cm_out,
                &w.d_ct,
                &fields.fee_commit,
                &w.anchors_root(&Hasher::new())
            )
        );
        assert!(
            check_all_constraints(&air, &trace, &public, None)
                .failures
                .is_empty()
        );
    }
    #[test]
    fn standard_priority_and_dummy_share_one_air_across_ring_wrap() {
        let air = TransactionAir::new();
        let slots = vec![
            sample_slot(70, false),
            sample_priority_slot(71),
            sample_empty_slot(72),
        ];
        let (witnesses, root) = acc_witnesses(slots, 4095, FEE_BASE, 73);
        for witness in witnesses {
            let (trace, public) = air.generate(&witness);
            assert_eq!(&public[TRANSACTION_ROOT..], &root);
            assert!(
                check_all_constraints(&air, &trace, &public, None)
                    .failures
                    .is_empty()
            );
            assert_eq!(air.width(), trace.width());
            assert_eq!(
                air.preprocessed_width(),
                air.preprocessed_trace().unwrap().width()
            );
        }
    }
    #[test]
    fn rejects_anchor_path_position_and_fee_tampering() {
        let air = TransactionAir::new();
        let w = witness();
        let (trace, public) = air.generate(&w);
        for element in 0..NUM_TRANSACTION_PUBLIC {
            let mut changed = public.clone();
            changed[element] += F::ONE;
            assert!(
                !check_all_constraints(&air, &trace, &changed, None)
                    .failures
                    .is_empty(),
                "public element {element}"
            );
        }
        let mut wrong_sibling = w.clone();
        wrong_sibling.anchor_path[7].0[0] += F::ONE;
        let (changed_trace, _) = air.generate(&wrong_sibling);
        assert!(
            !check_all_constraints(&air, &changed_trace, &public, None)
                .failures
                .is_empty()
        );
        let mut wrong_anchor = w.clone();
        wrong_anchor.slot.anchor[0] += F::ONE;
        assert!(failures(&air, &wrong_anchor) > 0);
        let mut wrong_position = w.clone();
        wrong_position.anchor_path[0].1 ^= true;
        assert!(failures(&air, &wrong_position) > 0);
        let mut wrong_height = w.clone();
        wrong_height.anchor_height += 1;
        assert!(failures(&air, &wrong_height) > 0);
        let mut wrong_fee = w;
        wrong_fee.slot.fee += 1;
        assert!(failures(&air, &wrong_fee) > 0);
    }
    #[test]
    fn rejects_duplicate_nullifiers_even_with_rebound_public_values() {
        let air = TransactionAir::new();
        let mut w = witness();
        // Spend exactly the same valid note twice, with the same valid
        // membership path, and rebalance the outputs. This leaves the
        // nullifier-inequality relation as the only failing clause.
        w.slot.inputs[1] = w.slot.inputs[0].clone();
        let total = 2 * w.slot.inputs[0].value;
        w.slot.outputs[0].value = total - w.slot.fee - w.slot.outputs[1].value;
        assert_eq!(failures(&air, &w), air.slot.height);
    }
    #[test]
    fn rejects_register_mutation_and_private_anchor_entry_substitution() {
        let air = TransactionAir::new();
        let w = witness();
        for column in [
            CHAIN_REG + pub_nf(0),
            CHAIN_REG + pub_nf(1),
            CHAIN_REG + pub_cm(0),
            CHAIN_REG + pub_cm(1),
            air.statement() + ACC_ENTRY_CONF,
            air.statement() + ACC_FEE_COMMIT,
            air.statement() + ACC_COUNT_CONF,
        ] {
            let (mut trace, public) = air.generate(&w);
            let width = trace.width;
            for row in trace.values.chunks_exact_mut(width) {
                row[column] += F::ONE;
            }
            assert!(
                !check_all_constraints(&air, &trace, &public, None)
                    .failures
                    .is_empty(),
                "register {column}"
            );
        }
    }
    #[test]
    fn rejects_malicious_trace_at_selector_boundaries_and_height_bits() {
        let air = TransactionAir::new();
        let w = witness();
        let attacks = [
            (0, air.statement() + ACC_ENTRY_CONF),
            (1, air.statement() + ACC_ENTRY_CONF),
            (ANCHOR_DEPTH - 1, air.path() + OUT),
            (ANCHOR_DEPTH, air.path()),
            (air.slot.height - 1, air.statement()),
            (0, air.height_bits()),
            (ANCHOR_DEPTH - 1, air.bit()),
        ];
        for (row, column) in attacks {
            let (mut trace, public) = air.generate(&w);
            let index = row * trace.width + column;
            trace.values[index] += F::ONE;
            assert!(
                !check_all_constraints(&air, &trace, &public, None)
                    .failures
                    .is_empty(),
                "trace row {row} column {column}"
            );
        }
        // A row-constant but inconsistent height decomposition also fails.
        let (mut trace, public) = air.generate(&w);
        let width = trace.width;
        for row in trace.values.chunks_exact_mut(width) {
            row[air.height_bits() + 15] = F::ONE;
        }
        assert!(
            !check_all_constraints(&air, &trace, &public, None)
                .failures
                .is_empty()
        );
    }
    #[test]
    fn real_native_stark_rejects_batch_and_query_grinding_nonce_tampering() {
        let params = FriParams {
            query_pow_bits: 16,
            batch_pow_bits: 16,
            commit_pow_bits: 0,
            ..FriParams::fast()
        };
        let prover = TransactionProver::new(params);
        let (mut proof, public) = prover.prove(&witness());
        prover
            .verify(&proof, &public)
            .expect("valid native proof with batch and query grinding");

        // A different nonce might satisfy the work predicate by chance. It
        // must still be absorbed into the transcript: the existing opening
        // coefficients and authenticated query rows cannot be reused with it.
        // Test both nonce fields independently without changing any other
        // proof or statement field, and never search only for rejected values.
        let batch_nonce = proof.opening_proof.1.batch_pow_witness;
        let query_nonce = proof.opening_proof.1.query_pow_witness;
        for delta in [F::ONE, F::from_u32(2), F::from_u32(17)] {
            proof.opening_proof.1.batch_pow_witness = batch_nonce + delta;
            assert!(
                prover.verify(&proof, &public).is_err(),
                "changed opening-batch grinding nonce"
            );
            proof.opening_proof.1.batch_pow_witness = batch_nonce;
            proof.opening_proof.1.query_pow_witness = query_nonce + delta;
            assert!(
                prover.verify(&proof, &public).is_err(),
                "changed query grinding nonce"
            );
            proof.opening_proof.1.query_pow_witness = query_nonce;
        }
        prover
            .verify(&proof, &public)
            .expect("original nonces remain valid after rejection checks");
    }
    #[test]
    fn real_d8_stark_verification_rejects_changed_statement() {
        let prover = TransactionProver::new(FriParams::fast());
        let w = witness();
        let (proof, public) = prover.prove(&w);
        prover
            .verify(&proof, &public)
            .expect("valid transaction proof");
        let fields = w.slot.public_inputs(&Hasher::new());
        let root = w.anchors_root(&Hasher::new());
        prover
            .verify_fields(
                &proof,
                &fields.nf,
                &fields.cm_out,
                &w.d_ct,
                &fields.fee_commit,
                &root,
            )
            .expect("canonical field binding");
        for field in 0..4 {
            for element in 0..DIGEST {
                let mut nf = fields.nf;
                let mut cm = fields.cm_out;
                if field < 2 {
                    nf[field][element] += F::ONE;
                } else {
                    cm[field - 2][element] += F::ONE;
                }
                assert!(
                    prover
                        .verify_fields(&proof, &nf, &cm, &w.d_ct, &fields.fee_commit, &root)
                        .is_err(),
                    "public field {field} element {element}"
                );
            }
        }
        for byte in 0..DCT_BYTES {
            let mut changed = w.d_ct;
            changed[byte] ^= 1;
            assert!(
                prover
                    .verify_fields(
                        &proof,
                        &fields.nf,
                        &fields.cm_out,
                        &changed,
                        &fields.fee_commit,
                        &root
                    )
                    .is_err(),
                "ciphertext digest byte {byte}"
            );
        }
        for index in [
            0,
            ACC_FEE_COMMIT,
            ACC_COUNT_CONF,
            TRANSACTION_ROOT,
            NUM_TRANSACTION_PUBLIC - 1,
        ] {
            let mut wrong = public.clone();
            wrong[index] += F::ONE;
            assert!(prover.verify(&proof, &wrong).is_err(), "public {index}");
        }
    }
}
