//! Owner-only raw-trace checks against the unchanged CompleteFee AIR sources.
//! These checks do not construct a PCS, setup, proof, verifier key or node.
#![cfg(test)]

#[path = "../src/proof_codec/v2/complete_fee/arx_closed.rs"]
pub mod arx_closed;
#[path = "../src/proof_codec/v2/complete_fee/fee_local_complete.rs"]
pub mod fee_local_complete;
#[path = "../src/proof_codec/v2/complete_fee/fee_local_sum.rs"]
pub mod fee_local_sum;
#[path = "../src/proof_codec/v2/complete_fee/fixed_public.rs"]
pub mod fixed_public;
#[path = "../src/proof_codec/v2/complete_fee/fixed_window.rs"]
pub mod fixed_window;
#[path = "../src/proof_codec/v2/complete_fee/kem_arx_closed.rs"]
pub mod kem_arx_closed;
#[path = "../src/proof_codec/v2/complete_fee/kem_closed.rs"]
pub mod kem_closed;
#[path = "../src/proof_codec/v2/complete_fee/kem_reference.rs"]
pub mod kem_reference;
#[path = "../src/proof_codec/v2/complete_fee/ntt_closed.rs"]
pub mod ntt_closed;
#[path = "../src/proof_codec/v2/complete_fee/payment_closed.rs"]
pub mod payment_closed;
#[path = "../src/proof_codec/v2/complete_fee/policy.rs"]
pub mod policy;
#[path = "../src/proof_codec/v2/complete_fee/poly1305_closed.rs"]
pub mod poly1305_closed;
#[path = "../src/proof_codec/v2/complete_fee/prefix.rs"]
pub mod prefix;

use native::{
    encryption::{EncryptionContext, PaymentAddress},
    multi_asset::{F, Hasher, LIMB_BITS, LIMBS, Note, SIP_ASSET_ID, limbs},
    settlement::{MAX_REWARD_NOTES, RewardAllocation, RewardMode, RewardPlan},
};
use p3_air::{Air, AirBuilder, BaseAir, ExtensionBuilder, PermutationAirBuilder, RowWindow};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use siworld_native_node::proof_codec::v2::{backend::E, complete_fee};
use std::collections::BTreeMap;

const HEIGHT: usize = 1024;
const CAPACITY: usize = 576;
const MAX_FAILURE_EXAMPLES: usize = 16;
// Pin the original routing surface independently of balanced tuple contents.
const ORIGINAL_NAMED_BUSES: [&str; 13] = [
    "arx-key",
    "arx-original",
    "arx-private-message",
    "arx-state",
    "kem-error",
    "kem-forward-output",
    "kem-inverse-stage",
    "kem-message-word",
    "kem-scaled",
    "mlkem-ntt-stage",
    "mlkem-prf-word",
    "settlement-fee-limb",
    "settlement-note-field",
];

// Use the actual production facade, not a second destination-hash recipe.
fn fee_destination_digest(address: &PaymentAddress) -> [u8; 32] {
    complete_fee::fee_destination_digest(address)
}

fn owner_gate() {
    assert!(std::env::var_os("CI").is_none(), "owner-only, refuse CI");
    assert!(
        std::env::var_os("GITHUB_ACTIONS").is_none(),
        "refuse Actions"
    );
    assert_eq!(
        std::env::var("SIWORLD_COMPLETE_FEE_RAW_EVAL").as_deref(),
        Ok("original-air-malicious-twins"),
        "explicit owner gate required"
    );
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Channel {
    Named(String),
    // One local call defines one separate multiset across all trace rows.
    Local(usize),
}

#[derive(Default, Debug)]
struct Bus {
    tuples: BTreeMap<Vec<u32>, i64>,
    arity: Option<usize>,
    height_weight: u64,
    absolute_multiplicity: u64,
    provided_terms: u64,
    messages: u64,
}

#[derive(Default, Debug)]
struct Evaluation {
    rows: usize,
    ordinary_assertions: u64,
    extension_assertions: u64,
    ordinary_failures: u64,
    extension_failures: u64,
    // No witness values or raw bus payloads are written to external artifacts.
    failure_examples: Vec<(usize, usize, bool)>,
    count_failures: u64,
    exclusive_failures: u64,
    shape_failures: u64,
    buses: BTreeMap<Channel, Bus>,
    first_row_schema: Option<Vec<String>>,
    assertions_per_row: Option<usize>,
    global_calls_per_row: Option<usize>,
    local_calls_per_row: Option<usize>,
    exclusive_calls_per_row: Option<usize>,
}

impl Evaluation {
    fn assertion(&mut self, row: usize, index: usize, extension: bool, valid: bool) {
        if extension {
            self.extension_assertions += 1;
            self.extension_failures += u64::from(!valid);
        } else {
            self.ordinary_assertions += 1;
            self.ordinary_failures += u64::from(!valid);
        }
        if !valid && self.failure_examples.len() < MAX_FAILURE_EXAMPLES {
            self.failure_examples.push((row, index, extension));
        }
    }

    fn add(
        &mut self,
        channel: Channel,
        fields: Vec<F>,
        count: Count<F>,
        flag: F,
        add_weight: bool,
    ) {
        let (value, weight) = count.into_parts();
        let raw = i64::from(value.as_canonical_u32());
        let modulus = i64::from(F::ORDER_U32);
        let signed = if raw > modulus / 2 {
            raw - modulus
        } else {
            raw
        };
        // A nonzero declared bound must hold for every row, including inactive
        // exclusive branches. Weight zero denotes a provided multiplicity.
        if weight > 0 && signed.unsigned_abs() > u64::from(weight) {
            self.count_failures += 1;
        }
        let bus = self.buses.entry(channel).or_default();
        if let Some(arity) = bus.arity {
            self.shape_failures += u64::from(arity != fields.len());
        } else {
            bus.arity = Some(fields.len());
        }
        if add_weight {
            bus.height_weight = bus.height_weight.checked_add(u64::from(weight)).unwrap();
        }
        bus.provided_terms += u64::from(weight == 0);
        bus.messages += 1;
        // Exclusivity/boolean failures are counted separately, never converted
        // into fractional integer counts or silently accepted field residues.
        if flag != F::ZERO && flag != F::ONE {
            return;
        }
        if flag == F::ZERO || signed == 0 {
            return;
        }
        bus.absolute_multiplicity = bus
            .absolute_multiplicity
            .checked_add(signed.unsigned_abs())
            .unwrap();
        let key = fields.into_iter().map(|x| x.as_canonical_u32()).collect();
        let total = bus.tuples.entry(key).or_default();
        *total = total.checked_add(signed).unwrap();
    }

    fn imbalanced(&self, channel: &Channel) -> usize {
        self.buses.get(channel).map_or(0, |bus| {
            bus.tuples.values().filter(|count| **count != 0).count()
        })
    }

    fn bus_failures(&self) -> usize {
        self.buses
            .keys()
            .map(|channel| self.imbalanced(channel))
            .sum()
    }

    fn bounds_hold(&self) -> bool {
        self.count_failures == 0
            && self.exclusive_failures == 0
            && self.buses.values().all(|bus| {
                // This is integer accounting, never mod-p cancellation. The
                // extra absolute bound also makes provided terms unambiguous.
                bus.height_weight < u64::from(F::ORDER_U32)
                    && bus.absolute_multiplicity < u64::from(F::ORDER_U32)
            })
    }

    fn has_original_bus_set(&self) -> bool {
        self.buses.len() == ORIGINAL_NAMED_BUSES.len()
            && ORIGINAL_NAMED_BUSES.iter().all(|name| {
                self.buses
                    .get(&Channel::Named((*name).into()))
                    .is_some_and(|bus| bus.messages > 0)
            })
    }

    fn accepted(&self) -> bool {
        self.rows == HEIGHT
            && self.has_original_bus_set()
            && self.ordinary_assertions > 0
            && self.ordinary_failures == 0
            && self.extension_failures == 0
            && self.shape_failures == 0
            && self.bounds_hold()
            && self.bus_failures() == 0
    }
}

struct Evaluator<'a> {
    row: usize,
    main: RowWindow<'a, F>,
    pre: RowWindow<'a, F>,
    public: &'a [F],
    report: &'a mut Evaluation,
    assertion_index: usize,
    global_calls: usize,
    local_calls: usize,
    exclusive_calls: usize,
    schema: Vec<String>,
}

impl<'a> AirBuilder for Evaluator<'a> {
    type F = F;
    type Expr = F;
    type Var = F;
    type MainWindow = RowWindow<'a, F>;
    type PreprocessedWindow = RowWindow<'a, F>;
    type PublicVar = F;
    type PeriodicVar = F;
    fn main(&self) -> Self::MainWindow {
        self.main
    }
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.pre
    }
    fn is_first_row(&self) -> F {
        F::from_bool(self.row == 0)
    }
    fn is_last_row(&self) -> F {
        F::from_bool(self.row + 1 == HEIGHT)
    }
    fn is_transition(&self) -> F {
        F::from_bool(self.row + 1 < HEIGHT)
    }
    fn assert_zero<I: Into<F>>(&mut self, x: I) {
        self.report
            .assertion(self.row, self.assertion_index, false, x.into() == F::ZERO);
        self.assertion_index += 1;
    }
    fn public_values(&self) -> &[F] {
        self.public
    }
    fn periodic_values(&self) -> &[F] {
        &[]
    }
}

impl ExtensionBuilder for Evaluator<'_> {
    type EF = E;
    type ExprEF = E;
    type VarEF = E;
    fn assert_zero_ext<I: Into<E>>(&mut self, x: I) {
        self.report
            .assertion(self.row, self.assertion_index, true, x.into() == E::ZERO);
        self.assertion_index += 1;
    }
}

impl<'a> PermutationAirBuilder for Evaluator<'a> {
    type MP = RowWindow<'a, E>;
    type RandomVar = E;
    type PermutationVar = E;
    fn permutation(&self) -> Self::MP {
        panic!("raw original AIR unexpectedly requested auxiliary permutation witness")
    }
    fn permutation_randomness(&self) -> &[E] {
        panic!("raw original AIR unexpectedly requested permutation challenges")
    }
    fn permutation_values(&self) -> &[E] {
        panic!("raw original AIR unexpectedly requested permutation terminal")
    }
}

impl InteractionBuilder for Evaluator<'_> {
    fn push_interaction<T: Into<F>>(
        &mut self,
        name: &str,
        fields: impl IntoIterator<Item = T>,
        count: impl Into<Count<F>>,
    ) {
        let fields: Vec<F> = fields.into_iter().map(Into::into).collect();
        let count = count.into();
        self.schema
            .push(format!("global:{name}:{}:{}", fields.len(), count.weight()));
        self.global_calls += 1;
        self.report
            .add(Channel::Named(name.into()), fields, count, F::ONE, true);
    }

    fn push_local_interaction(&mut self, tuples: impl IntoIterator<Item = (Vec<F>, Count<F>)>) {
        let channel = Channel::Local(self.local_calls);
        let tuples: Vec<_> = tuples.into_iter().collect();
        self.schema
            .push(format!("local:{}:{}", self.local_calls, tuples.len()));
        self.local_calls += 1;
        assert!(
            !tuples.is_empty(),
            "empty local interaction is not qualified"
        );
        for (fields, count) in tuples {
            self.schema
                .push(format!("local-tuple:{}:{}", fields.len(), count.weight()));
            self.report
                .add(channel.clone(), fields, count, F::ONE, true);
        }
    }

    fn push_exclusive_interaction(
        &mut self,
        name: &str,
        branches: impl IntoIterator<Item = (F, Count<F>, Vec<F>)>,
    ) {
        let channel = Channel::Named(name.into());
        let branches: Vec<_> = branches.into_iter().collect();
        self.schema
            .push(format!("exclusive:{name}:{}", branches.len()));
        self.exclusive_calls += 1;
        assert!(
            !branches.is_empty(),
            "empty exclusive interaction is not qualified"
        );
        let active = branches
            .iter()
            .filter(|(flag, _, _)| *flag == F::ONE)
            .count();
        if active > 1
            || branches
                .iter()
                .any(|(flag, _, _)| *flag != F::ZERO && *flag != F::ONE)
        {
            self.report.exclusive_failures += 1;
        }
        let max_weight = branches
            .iter()
            .map(|(_, count, _)| count.weight())
            .max()
            .unwrap();
        self.report
            .buses
            .entry(channel.clone())
            .or_default()
            .height_weight += u64::from(max_weight);
        for (flag, count, fields) in branches {
            self.schema.push(format!(
                "exclusive-branch:{}:{}",
                fields.len(),
                count.weight()
            ));
            self.report.add(channel.clone(), fields, count, flag, false);
        }
    }
    fn num_global_interactions(&self) -> usize {
        self.global_calls
    }
    fn num_local_interactions(&self) -> usize {
        self.local_calls
    }
    fn num_exclusive_interactions(&self) -> usize {
        self.exclusive_calls
    }
}

fn evaluate(
    air: &fixed_public::FixedPublicAir,
    trace: &RowMajorMatrix<F>,
    public: &[F],
) -> Evaluation {
    assert_eq!(air.original_for_test().width(), fixed_public::BASE_MAIN);
    assert_eq!(
        trace.width,
        fixed_public::BASE_MAIN + fixed_public::EXTRA_MAIN
    );
    assert_eq!(trace.values.len(), HEIGHT * trace.width);
    assert_eq!(public.len(), air.num_public_values());
    assert_eq!(air.num_periodic_columns(), 0);
    assert!(
        air.public_boundary_io().is_empty(),
        "new boundary IO needs explicit evaluator support"
    );
    let pre = air.preprocessed_trace().unwrap();
    assert_eq!(pre.width, fixed_public::PRE_WIDTH);
    assert_eq!(pre.values.len(), HEIGHT * pre.width);
    let mut report = Evaluation::default();
    for row in 0..HEIGHT {
        let next = (row + 1) % HEIGHT;
        let mut b = Evaluator {
            row,
            main: RowWindow::from_two_rows(
                &trace.values[row * trace.width..(row + 1) * trace.width],
                &trace.values[next * trace.width..(next + 1) * trace.width],
            ),
            pre: RowWindow::from_two_rows(
                &pre.values[row * pre.width..(row + 1) * pre.width],
                &pre.values[next * pre.width..(next + 1) * pre.width],
            ),
            public,
            report: &mut report,
            assertion_index: 0,
            global_calls: 0,
            local_calls: 0,
            exclusive_calls: 0,
            schema: Vec::new(),
        };
        // This is the full unmodified evaluator, including the original mapped
        // preprocessing, fixed window, KEM/KDF/AEAD/settlement and every bus.
        air.eval(&mut b);
        let shape = (
            b.assertion_index,
            b.global_calls,
            b.local_calls,
            b.exclusive_calls,
        );
        let schema = std::mem::take(&mut b.schema);
        if let Some(expected) = &b.report.first_row_schema {
            b.report.shape_failures += u64::from(*expected != schema);
            b.report.shape_failures += u64::from(b.report.assertions_per_row != Some(shape.0));
        } else {
            b.report.first_row_schema = Some(schema);
            b.report.assertions_per_row = Some(shape.0);
            b.report.global_calls_per_row = Some(shape.1);
            b.report.local_calls_per_row = Some(shape.2);
            b.report.exclusive_calls_per_row = Some(shape.3);
        }
        b.report.rows += 1;
    }
    report
}

fn fixture() -> (fee_local_sum::FeeLocalSumWitness, PaymentAddress) {
    use fee_local_sum::{LegacyFeeOpening, LegacyPrivateSettlement, LegacySettlementSlot};
    let h = Hasher::new();
    let pair = libcrux_ml_kem::mlkem768::portable::generate_key_pair([3; 64]);
    let owner = [F::from_u8(7); 12];
    let address = PaymentAddress::new(owner, *pair.public_key().as_slice()).unwrap();
    let slots: Vec<_> = (0..CAPACITY)
        .map(|i| {
            let fee = [0, 10, 40][i % 3];
            let blind = [F::from_usize(i + 1); 8];
            LegacySettlementSlot {
                commitment: fee_local_sum::legacy_fee_commit(&h, fee, &blind),
                opening: LegacyFeeOpening { fee, blind },
            }
        })
        .collect();
    let total = slots.iter().map(|s| s.opening.fee).sum();
    let note = |value, unlock_height, owner, rho, rseed| Note {
        value,
        unlock_height,
        owner,
        rho,
        rseed,
        asset_id: SIP_ASSET_ID,
    };
    let witness = fee_local_sum::FeeLocalSumWitness {
        policy: policy::SettlementPolicy {
            plan: RewardPlan {
                block_height: 17,
                mode: RewardMode::Voyager,
                allocations: vec![RewardAllocation {
                    amount: 41,
                    unlock_height: 17,
                }],
            },
            fee_owner: owner,
            fees: policy::FeeSchedule::from_previous_standard(100).unwrap(),
            max_slots: CAPACITY,
        },
        network: [31; 32],
        transaction_list_digest: [47; 32],
        fee_destination_digest: fee_destination_digest(&address),
        settlement: LegacyPrivateSettlement {
            rewards: vec![note(
                41,
                17,
                [F::from_u8(9); 12],
                h.reward_rho(17, 0),
                [F::from_u8(83); 12],
            )],
            fee_note: note(total, 0, owner, [F::from_u8(87); 12], [F::from_u8(89); 12]),
            slots,
        },
    };
    witness.validate().unwrap();
    (witness, address)
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Baseline,
    RawWordPlusModulus,
    EncryptedAmountPlusOne,
    CoherentNotePlusOne,
}

fn candidate(case: Case) -> (fixed_public::FixedPublicAir, RowMajorMatrix<F>, Vec<F>) {
    let (mut w, address) = fixture();
    let true_total = w.settlement.fee_note.value;
    if matches!(case, Case::CoherentNotePlusOne) {
        w.settlement.fee_note.value += 1;
        assert!(
            w.validate().is_err(),
            "invalid witness must not pass host validation"
        );
    }
    let mut plain = payment_closed::note_bytes(&w.settlement.fee_note);
    if matches!(case, Case::RawWordPlusModulus) {
        let x = u32::from_le_bytes(plain[16..20].try_into().unwrap());
        let noncanonical = x.checked_add(F::ORDER_U32).unwrap();
        plain[16..20].copy_from_slice(&noncanonical.to_le_bytes());
    }
    if matches!(case, Case::EncryptedAmountPlusOne) {
        plain[..8].copy_from_slice(&(true_total + 1).to_le_bytes());
    }
    let commitment = Hasher::new().note_cm(&w.settlement.fee_note);
    // Real coherent KEM/KDF/AEAD and Poly1305 trace for the modified plaintext,
    // including independent host encrypt/decrypt checks in the original helper.
    let (payment, ptrace) = payment_closed::generate_with_plaintext(
        &address,
        [5; 32],
        plain,
        &EncryptionContext::new(w.network),
        commitment,
    );
    let settlement = fee_local_sum::FeeLocalSumAir::new(CAPACITY).with_min_height(512);
    let mut strace = fee_local_sum::generate_trace(&settlement, &w).unwrap();
    if matches!(case, Case::CoherentNotePlusOne) {
        // Preserve the actual sum, all running-sum transitions and canonical
        // bits. Only the coherent note is wrong; host validation is not oracle.
        const TOTAL: usize = fee_local_sum::NOTE_AMOUNT - 3 - LIMBS * LIMB_BITS - LIMBS;
        const TOTAL_BITS: usize = TOTAL + LIMBS;
        for row in strace.values.chunks_exact_mut(strace.width) {
            row[TOTAL..TOTAL + LIMBS].copy_from_slice(&limbs(true_total));
            for (k, value) in limbs(true_total).into_iter().enumerate() {
                for bit in 0..LIMB_BITS {
                    row[TOTAL_BITS + k * LIMB_BITS + bit] =
                        F::from_bool(value.as_canonical_u32() >> bit & 1 != 0);
                }
            }
        }
    }
    let mut base_public = prefix::public_hash(payment.kem.0.public_key_hash());
    base_public.push(F::from_u8(payment.view_tag));
    base_public.extend(w.public_inputs().unwrap());
    base_public.extend(
        fee_local_complete::canonical_address(&address)
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| F::from_u16(u16::from_le_bytes(*b))),
    );
    let original = fee_local_complete::FeeLocalCompleteAir {
        payment,
        settlement,
    };
    let trusted = fixed_public::TrustedStatementBinding(
        fixed_public::canonical_statement_binding(&original, &base_public).unwrap(),
    );
    let public = fixed_public::public_inputs(&original, &base_public, trusted).unwrap();
    let width = fixed_public::BASE_MAIN;
    let bridge = payment_closed::WIDTH + fee_local_sum::MAIN_WIDTH;
    assert_eq!(bridge + 33, width);
    assert_eq!(strace.values.len() / strace.width, HEIGHT);
    let mut values = F::zero_vec(HEIGHT * width);
    for row in 0..HEIGHT {
        if row < 512 {
            values[row * width..row * width + payment_closed::WIDTH]
                .copy_from_slice(&ptrace.values[row * ptrace.width..(row + 1) * ptrace.width]);
        }
        values[row * width + payment_closed::WIDTH..row * width + bridge]
            .copy_from_slice(&strace.values[row * strace.width..(row + 1) * strace.width]);
    }
    // Original fill_bridge is private. Construct exactly its documented witness
    // geometry, then let the original constraints reject invalid complements.
    for row in 36..60 {
        let off = row * width + bridge;
        let word = u32::from_le_bytes(plain[(row - 32) * 4..(row - 31) * 4].try_into().unwrap());
        let complement = (F::ORDER_U32 - 1).saturating_sub(word);
        for bit in 0..32 {
            values[off + bit] = F::from_bool(complement >> bit & 1 != 0);
        }
        values[off + 32] = F::from_bool(((word & 65535) + (complement & 65535)) >> 16 != 0);
    }
    let air = fixed_public::FixedPublicAir::new(original).unwrap();
    let trace = fixed_public::extend_trace(RowMajorMatrix::new(values, width), &public).unwrap();
    (air, trace, public)
}

// Small controls qualify evaluator routing only, never substitute for the
// subsequent unchanged FixedPublicAir execution on the complete 1024 rows.
fn evaluator_contract_checks() {
    fn builder(report: &mut Evaluation) -> Evaluator<'_> {
        Evaluator {
            row: 0,
            main: RowWindow::from_two_rows(&[], &[]),
            pre: RowWindow::from_two_rows(&[], &[]),
            public: &[],
            report,
            assertion_index: 0,
            global_calls: 0,
            local_calls: 0,
            exclusive_calls: 0,
            schema: Vec::new(),
        }
    }
    let mut r = Evaluation::default();
    {
        let mut b = builder(&mut r);
        b.assert_zero(F::ZERO);
        b.assert_zero(F::ONE);
        b.assert_zero_ext(E::ZERO);
        b.assert_zero_ext(E::ONE);
    }
    assert_eq!((r.ordinary_assertions, r.extension_assertions), (2, 2));
    assert_eq!((r.ordinary_failures, r.extension_failures), (1, 1));
    let mut r = Evaluation::default();
    {
        let mut b = builder(&mut r);
        b.push_interaction("shared", [F::ONE], Count::bounded(-F::ONE, 1));
        b.push_exclusive_interaction(
            "shared",
            [
                (F::ONE, Count::bounded(F::ONE, 1), vec![F::ONE]),
                (F::ZERO, Count::bounded(-F::ONE, 1), vec![F::TWO]),
            ],
        );
    }
    assert!(r.bounds_hold());
    assert_eq!(r.bus_failures(), 0);
    assert_eq!(r.buses[&Channel::Named("shared".into())].height_weight, 2);
    let mut r = Evaluation::default();
    {
        let mut b = builder(&mut r);
        b.push_local_interaction([
            (vec![F::ONE], Count::bounded(F::ONE, 1)),
            (vec![F::ONE], Count::provided(-F::ONE)),
        ]);
    }
    assert!(r.bounds_hold());
    assert_eq!(r.bus_failures(), 0);
    assert_eq!(r.buses[&Channel::Local(0)].provided_terms, 1);
    let mut r = Evaluation::default();
    {
        let mut b = builder(&mut r);
        b.push_local_interaction([(vec![F::ONE], Count::bounded(F::ONE, 1))]);
        b.push_local_interaction([(vec![F::ONE], Count::bounded(-F::ONE, 1))]);
    }
    assert_eq!(
        r.bus_failures(),
        2,
        "local call IDs must never cross-cancel"
    );
    let mut r = Evaluation::default();
    {
        let mut b = builder(&mut r);
        b.push_interaction("bad-count", [F::ONE], Count::bounded(F::TWO, 1));
        b.push_exclusive_interaction(
            "bad-flags",
            [
                (F::ONE, Count::bounded(F::ONE, 1), vec![F::ONE]),
                (F::ONE, Count::bounded(-F::ONE, 1), vec![F::ONE]),
            ],
        );
        b.push_exclusive_interaction(
            "nonboolean",
            [(F::TWO, Count::bounded(F::ONE, 1), vec![F::ONE])],
        );
    }
    assert_eq!(r.count_failures, 1);
    assert_eq!(r.exclusive_failures, 2);
    assert!(!r.bounds_hold());
    r.buses
        .entry(Channel::Named("height-wrap".into()))
        .or_default()
        .height_weight = u64::from(F::ORDER_U32);
    assert!(!r.bounds_hold(), "query height bound must be strict");

    let mut r = Evaluation::default();
    assert!(!r.has_original_bus_set(), "empty routing must fail closed");
    {
        let mut b = builder(&mut r);
        for name in ORIGINAL_NAMED_BUSES {
            b.push_interaction(name, [F::ONE], Count::bounded(F::ZERO, 1));
        }
    }
    assert!(r.has_original_bus_set());
    let original = Channel::Named("settlement-fee-limb".into());
    let removed = r.buses.remove(&original).unwrap();
    assert!(
        !r.has_original_bus_set(),
        "balanced omission must fail closed"
    );
    r.buses.insert(Channel::Local(0), removed);
    assert!(r.bus_failures() == 0 && !r.has_original_bus_set());
    let removed = r.buses.remove(&Channel::Local(0)).unwrap();
    r.buses.insert(Channel::Named("renamed".into()), removed);
    assert!(r.bus_failures() == 0 && !r.has_original_bus_set());
    let removed = r.buses.remove(&Channel::Named("renamed".into())).unwrap();
    r.buses.insert(original.clone(), removed);
    assert!(r.has_original_bus_set());
    r.buses.get_mut(&original).unwrap().messages = 0;
    assert!(!r.has_original_bus_set(), "unvisited bus must fail closed");
}

#[test]
#[ignore = "owner-only raw CompleteFee AIR evaluation; explicit resource grant required"]
fn complete_fee_original_air_rejects_malicious_twins() {
    owner_gate();
    evaluator_contract_checks();
    for case in [
        Case::Baseline,
        Case::RawWordPlusModulus,
        Case::EncryptedAmountPlusOne,
        Case::CoherentNotePlusOne,
    ] {
        let (air, trace, public) = candidate(case);
        let report = evaluate(&air, &trace, &public);
        assert_eq!(report.rows, HEIGHT);
        assert!(report.bounds_hold());
        assert_eq!(report.shape_failures, 0);
        assert!(report.has_original_bus_set());
        match case {
            Case::Baseline => assert!(report.accepted()),
            Case::RawWordPlusModulus => {
                assert!(!report.accepted());
                // The final 32 assertions constrain reserved plaintext rows.
                // Immediately before them are the two exact u16 canonical
                // equations, after the 33 complement/carry boolean checks.
                let canonical_low = report.assertions_per_row.unwrap() - 34;
                assert_eq!(report.ordinary_failures, 1);
                assert_eq!(report.extension_failures, 0);
                assert_eq!(report.failure_examples, vec![(36, canonical_low, false)]);
                assert_eq!(report.bus_failures(), 0, "x+p aliases on a field bus");
            }
            Case::EncryptedAmountPlusOne => {
                assert!(!report.accepted());
                assert_eq!(report.ordinary_failures, 0);
                assert_eq!(report.extension_failures, 0);
                let bridge = Channel::Named("settlement-fee-limb".into());
                assert_eq!(report.imbalanced(&bridge), 2);
                assert_eq!(report.bus_failures(), 2);
            }
            Case::CoherentNotePlusOne => {
                assert!(!report.accepted());
                assert_eq!(report.bus_failures(), 0);
                // Original NOTE_AMOUNT == TOTAL, at each of the six fee-note
                // selectors. The actual running total remains the true sum.
                assert_eq!(report.ordinary_failures, 6);
                assert!(report.failure_examples.iter().all(|(row, _, ext)| {
                    (CAPACITY + MAX_REWARD_NOTES * 6..CAPACITY + (MAX_REWARD_NOTES + 1) * 6)
                        .contains(row)
                        && !*ext
                }));
            }
        }
        println!(
            "case={case:?} rows={} ordinary={} extension={} ordinary_failed={} extension_failed={} buses={} bus_imbalances={} globals_per_row={} locals_per_row={} exclusive_per_row={}",
            report.rows,
            report.ordinary_assertions,
            report.extension_assertions,
            report.ordinary_failures,
            report.extension_failures,
            report.buses.len(),
            report.bus_failures(),
            report.global_calls_per_row.unwrap(),
            report.local_calls_per_row.unwrap(),
            report.exclusive_calls_per_row.unwrap()
        );
    }
}
