//! Custom binary aggregation for accumulator-mode leaves (`SlotAir::new_acc`).
//!
//! Full statement of a leaf or internal node, all base-field elements (docs/protocol.md):
//!   [ΣE (SET_LEN), fee limbs (LIMBS × 16 bits), count, 𝒜 entry or root (DIGEST)]
//! A leaf ends with its 𝒜 entry. A level-1 node checks each leaf's entry by a depth-12 Merkle
//! path into an 𝒜 root it takes as private input (the paths are public chain data the
//! aggregator supplies), so a leaf proof stays usable while its anchor is in the window; every
//! node statement ends with that 𝒜 root. A parent proves both children, checks that they use
//! the same 𝒜 root, and computes the field sum of E (order-independent: the slots form a
//! multiset, so subtrees merge as soon as their slots exist), the fee total as u64 limbs with
//! carries, and the count sum.
//!
//! A leaf publishes its full statement. An internal node publishes only
//! D = sponge(TAG_ACC_NODE, full statement) (DIGEST elements): its parent takes the full statement
//! as a private input, binds every element to the base field, recomputes D in the circuit and
//! checks it against the child's public digest. The long statement would otherwise cost the
//! recursive verifier enough rows to double two of its tables.
//!
//! The root replaces the fee limbs with the commitment of the block's miner package, an ordinary
//! note carrying the fee total plus the public miner share of the block reward:
//! cm_miner = note_cm(owner, total + share, height + COINBASE_MATURITY,
//! ρ = sponge(TAG_MINER_RHO, height), rseed), with owner and rseed private. The root statement
//! never shows the fee total or any per-slot fee:
//!   [ΣE (SET_LEN), 𝒜 root (DIGEST), height, cm_miner (DIGEST), share limbs (LIMBS), count]
//!
//! The library's trusted aggregation owner does not expose the child statement targets
//! (`CheckedVerifierResult.inner` and the `TrustedChildStatementLayout` constructors are
//! crate-private), so this module repeats its construction and locates the targets by
//! allocation order; `child_targets` checks the order against the packed public inputs.

use p3_circuit::ops::{Poseidon2Config, Poseidon2PermCall};
use p3_circuit::{Circuit, CircuitBuilder, ExprId, StatementExport};
use p3_circuit_prover::batch_stark_prover::TableProver;
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    AirVariant, BatchStarkProof, BatchStarkProver, CircuitVerifier, ConstraintProfile,
    PreparedCircuitProver, StatementAirBuilder, StatementPreprocessor, StatementProver,
};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::{
    BatchOnly, FriRecursionBackend, FriRecursionBackendForExt, PcsRecursionBackend,
    ProveNextLayerParams, RecursionInput, TrustedPcsRecursionBackend, VerifierCircuitResult,
};
use std::sync::Arc;

use crate::common::{
    ANCHOR_DEPTH, Block, COINBASE_MATURITY, DIGEST, Digest, F, HEIGHT_BITS, Hasher, LIMB_BITS,
    LIMBS, RATE, SET_LEN, TAG_ACC_NODE, TAG_MINER_RHO, TAG_NOTE, limbs,
};
use p3_uni_stark::{Proof, StarkGenericConfig};

use crate::air::{ACC_COUNT, ACC_ENTRY, ACC_FEE, ACC_ROOT, ACC_SET, NUM_ACC_PUBLIC};
use crate::{Cfg, SlotAir, SlotProver};

#[cfg(feature = "experimental-fanin")]
pub mod fanin;

type Challenge = <Cfg as StarkGenericConfig>::Challenge;
pub type Backend = FriRecursionBackendForExt<8, 24, 12, Poseidon2Config>;
type VRes = <Backend as PcsRecursionBackend<Cfg, BatchOnly, 8>>::VerifierResult;

/// Root statement offsets.
pub const ROOT_SET: usize = 0;
pub const ROOT_ANCHORS: usize = SET_LEN;
pub const ROOT_HEIGHT: usize = ROOT_ANCHORS + DIGEST;
pub const ROOT_CM_MINER: usize = ROOT_HEIGHT + 1;
pub const ROOT_SHARE: usize = ROOT_CM_MINER + DIGEST;
pub const ROOT_COUNT: usize = ROOT_SHARE + LIMBS;
pub const NUM_ROOT_PUBLIC: usize = ROOT_COUNT + 1;
/// Public statement length of an internal node.
pub const NUM_NODE_PUBLIC: usize = DIGEST;

/// The count is range-checked to 8 bits (≤ 255 slots), like the chained layout.
const COUNT_BITS: usize = 8;

pub fn backend() -> Backend {
    FriRecursionBackend::<24, 12, _>::new(Poseidon2Config::KOALA_BEAR_D1_W24)
        .for_extension_degree::<8>()
}

fn err(e: impl core::fmt::Debug) -> String {
    format!("{e:?}")
}

/// Fee total encoded in a statement's limbs.
pub fn fee_of(stmt: &[F]) -> u64 {
    use p3_field::PrimeField32;
    stmt[ACC_FEE..ACC_COUNT]
        .iter()
        .enumerate()
        .map(|(k, l)| u64::from(l.as_canonical_u32()) << (LIMB_BITS * k))
        .sum()
}

/// Public statement of an internal node: the digest of its full statement (zero-padded blocks).
pub fn node_digest(stmt: &[F]) -> Vec<F> {
    assert_eq!(stmt.len(), NUM_ACC_PUBLIC);
    let blocks: Vec<Block> = stmt
        .chunks(RATE)
        .map(|c| {
            let mut b = [F::ZERO; RATE];
            b[..c.len()].copy_from_slice(c);
            b
        })
        .collect();
    Hasher::new().sponge(TAG_ACC_NODE, &blocks).to_vec()
}

/// Native view of a leaf statement as level 1 sees it: the 𝒜 entry replaced by the 𝒜 root its
/// path leads to.
pub fn anchor_leaf(stmt: &[F], path: &[(Digest, bool)]) -> Vec<F> {
    assert_eq!(stmt.len(), NUM_ACC_PUBLIC);
    assert_eq!(path.len(), ANCHOR_DEPTH);
    let entry: Digest = stmt[ACC_ENTRY..].try_into().expect("digest");
    let mut v = stmt[..ACC_ENTRY].to_vec();
    v.extend_from_slice(&Hasher::new().merkle_root(&entry, path));
    v
}

/// Native full statement of an internal node over two node statements, or over two leaves
/// passed through `anchor_leaf`. Both children must use the same 𝒜 root.
pub fn compose_acc(l: &[F], r: &[F]) -> Vec<F> {
    assert_eq!(l.len(), NUM_ACC_PUBLIC);
    assert_eq!(r.len(), NUM_ACC_PUBLIC);
    assert_eq!(
        l[ACC_ROOT..],
        r[ACC_ROOT..],
        "children use different 𝒜 roots"
    );
    let mut v: Vec<F> = (ACC_SET..ACC_FEE).map(|e| l[e] + r[e]).collect();
    let fee = fee_of(l)
        .checked_add(fee_of(r))
        .expect("fee total overflows u64");
    v.extend_from_slice(&limbs(fee));
    v.push(l[ACC_COUNT] + r[ACC_COUNT]);
    v.extend_from_slice(&l[ACC_ROOT..]);
    v
}

/// The root's miner package data: the block height and the miner share (both public), and the
/// package's owner and rseed (private).
#[derive(Clone, Copy, Debug)]
pub struct MinerNote {
    pub height: u64,
    pub share: u64,
    pub owner: Digest,
    pub rseed: Digest,
}

/// Native root statement: the fee total appears only inside the miner package commitment.
pub fn root_statement(l: &[F], r: &[F], note: &MinerNote) -> Vec<F> {
    let n = compose_acc(l, r);
    let value = fee_of(&n)
        .checked_add(note.share)
        .expect("miner package value overflows u64");
    let mut v = n[ACC_SET..ACC_FEE].to_vec();
    v.extend_from_slice(&n[ACC_ROOT..]);
    v.push(F::from_u64(note.height));
    v.extend_from_slice(&Hasher::new().miner_note_cm(value, note.height, &note.owner, &note.rseed));
    v.extend_from_slice(&limbs(note.share));
    v.push(n[ACC_COUNT]);
    v
}

/// The child relation of one aggregation layer. Owned, so a prepared layer
/// can live as long as the prover that holds it.
pub enum Child {
    /// Accumulator-mode leaf proofs.
    Uni(Arc<SlotProver>),
    /// Proofs of the previous aggregation layer.
    Batch(CircuitVerifier<Cfg>),
}

/// One child proof with its full statement; a leaf also carries its entry's 𝒜 path.
#[derive(Clone, Copy)]
pub enum Input<'p> {
    Uni(&'p Proof<Cfg>, &'p [F], &'p [(Digest, bool)]),
    Batch(&'p BatchStarkProof<Cfg>, &'p [F]),
}

impl Input<'_> {
    fn full(&self) -> &[F] {
        match self {
            Input::Uni(_, s, _) | Input::Batch(_, s) => s,
        }
    }

    /// The statement the child proof actually exposes.
    fn public(&self) -> Vec<F> {
        match self {
            Input::Uni(_, s, _) => s.to_vec(),
            Input::Batch(_, s) => node_digest(s),
        }
    }
}

enum Prev<'a> {
    Uni(RecursionInput<'a, Cfg, SlotAir>),
    Batch(RecursionInput<'a, Cfg, BatchOnly>),
}

impl Child {
    fn prev<'p>(&'p self, input: Input<'p>) -> Result<Prev<'p>, String> {
        match (self, input) {
            (Child::Uni(p), Input::Uni(proof, pis, _)) => Ok(Prev::Uni(RecursionInput::UniStark {
                proof,
                air: &p.air,
                public_inputs: pis.to_vec(),
                preprocessed_commit: Some(p.vk.commitment.clone()),
            })),
            (Child::Batch(v), Input::Batch(proof, _)) => {
                let stmt = input.public();
                v.verify(proof, &stmt).map_err(err)?;
                Ok(Prev::Batch(RecursionInput::BatchStark {
                    proof,
                    common_data: v.common_data(),
                    table_public_inputs: v.table_public_values(&stmt).map_err(err)?,
                }))
            }
            _ => Err("child kind mismatch".into()),
        }
    }

    fn uni_cfg(&self) -> &Cfg {
        match self {
            Child::Uni(p) => &p.cfg,
            Child::Batch(_) => unreachable!(),
        }
    }

    /// Prepare the circuit tables this child's verifier needs.
    fn prepare(&self, b: &Backend, builder: &mut CircuitBuilder<Challenge>) -> Result<(), String> {
        match self {
            Child::Uni(p) => <Backend as PcsRecursionBackend<Cfg, SlotAir, 8>>::prepare_circuit(
                b, &p.cfg, builder,
            ),
            Child::Batch(v) => {
                <Backend as PcsRecursionBackend<Cfg, BatchOnly, 8>>::prepare_circuit(
                    b,
                    v.config(),
                    builder,
                )
            }
        }
        .map_err(err)
    }

    /// Build the in-circuit verifier for `sample`, pin the child's preprocessed commitment, and
    /// return the targets of the child statement.
    fn build(
        &self,
        b: &Backend,
        sample: Input<'_>,
        builder: &mut CircuitBuilder<Challenge>,
    ) -> Result<(VRes, Vec<ExprId>), String> {
        let prev = self.prev(sample)?;
        let stmt = sample.public();
        let base = builder.construction_usage().map_err(err)?.expression_nodes as u32;
        let p0 = builder.public_input_count();
        let (res, offset, len) = match (self, &prev, sample) {
            (Child::Uni(p), Prev::Uni(prev), _) => {
                let res =
                    <Backend as PcsRecursionBackend<Cfg, SlotAir, 8>>::build_verifier_circuit(
                        b, prev, &p.cfg, builder,
                    )
                    .map_err(err)?;
                <Backend as TrustedPcsRecursionBackend<Cfg, SlotAir, 8>>::constrain_trusted_preprocessing(
                    b,
                    builder,
                    &res,
                    Some(&p.vk.commitment),
                )
                .map_err(err)?;
                (res, 0, p.air.num_public())
            }
            (Child::Batch(v), Prev::Batch(_), Input::Batch(proof, _)) => {
                let res = <Backend as TrustedPcsRecursionBackend<Cfg, BatchOnly, 8>>::build_trusted_batch_verifier_circuit(
                    b, v, proof, &stmt, builder,
                )
                .map_err(err)?;
                <Backend as TrustedPcsRecursionBackend<Cfg, BatchOnly, 8>>::constrain_trusted_preprocessing(
                    b,
                    builder,
                    &res,
                    v.common_data().preprocessed.as_ref().map(|g| &g.commitment),
                )
                .map_err(err)?;
                let counts: Vec<usize> = v
                    .table_public_values(&stmt)
                    .map_err(err)?
                    .iter()
                    .map(Vec::len)
                    .collect();
                let k = v
                    .statement_layout()
                    .table_instance()
                    .ok_or("child has no statement table")?;
                (res, counts[..k].iter().sum(), stmt.len())
            }
            _ => unreachable!(),
        };
        // The verifier input builders allocate the AIR public values first and consecutively,
        // one expression node per value; check that against the packed public inputs.
        let packed = self.pack_public(&res, &prev)?;
        if builder.public_input_count() - p0 != packed.len()
            || packed[offset..offset + len]
                .iter()
                .zip(&stmt)
                .any(|(&x, &y)| x != Challenge::from(y))
        {
            return Err("child public-input layout differs from the expected order".into());
        }
        let targets = (0..len)
            .map(|j| ExprId(base + (offset + j) as u32))
            .collect();
        Ok((res, targets))
    }

    fn pack_public(&self, res: &VRes, prev: &Prev<'_>) -> Result<Vec<Challenge>, String> {
        match prev {
            Prev::Uni(p) => res.pack_public_inputs(p),
            Prev::Batch(p) => res.pack_public_inputs(p),
        }
        .map_err(err)
    }

    fn pack_private(&self, res: &VRes, prev: &Prev<'_>) -> Result<Vec<Challenge>, String> {
        match prev {
            Prev::Uni(p) => res.pack_private_inputs(p),
            Prev::Batch(p) => res.pack_private_inputs(p),
        }
        .map_err(err)
    }

    fn set_private(
        &self,
        b: &Backend,
        res: &VRes,
        prev: &Prev<'_>,
        input: Input<'_>,
        runner: &mut p3_circuit::CircuitRunner<'_, Challenge>,
    ) -> Result<(), String> {
        match (self, prev, input) {
            (Child::Uni(_), Prev::Uni(prev), _) => {
                <Backend as PcsRecursionBackend<Cfg, SlotAir, 8>>::set_private_data_for_result(
                    b,
                    self.uni_cfg(),
                    runner,
                    res,
                    prev,
                )
                .map_err(err)
            }
            (Child::Batch(v), Prev::Batch(_), Input::Batch(proof, _)) => {
                <Backend as TrustedPcsRecursionBackend<Cfg, BatchOnly, 8>>::set_private_data_for_trusted_batch(
                    b,
                    v,
                    proof,
                    &input.public(),
                    runner,
                    VerifierCircuitResult::<Cfg, BatchOnly>::op_ids(res),
                )
                .map_err(err)
            }
            _ => Err("child kind mismatch".into()),
        }
    }
}

/// A prepared aggregation layer over two children of the same relation.
pub struct AccAggregation {
    child: Child,
    backend: Backend,
    circuit: Circuit<Challenge>,
    left: VRes,
    right: VRes,
    root: bool,
    prepared: PreparedCircuitProver<Cfg>,
}

/// Field element of `bits` low bits of `x`, plus the remaining high bits (as one target).
/// `x` must be a base-field element below 2^(bits + 1).
fn split_low(
    builder: &mut CircuitBuilder<Challenge>,
    x: ExprId,
    bits: usize,
) -> Result<(ExprId, ExprId), String> {
    let b = builder.decompose_to_bits::<F>(x, bits + 1).map_err(err)?;
    let hi = b[bits];
    let scale = builder.define_const(Challenge::from(F::from_u32(1 << bits)));
    let hi_scaled = builder.mul(hi, scale);
    Ok((builder.sub(x, hi_scaled), hi))
}

/// Scalar W24 permutation calls lifted into the D8 circuit field.
/// Every input is bound to the base field by the permutation witness bus.
fn padded_targets(xs: &[ExprId]) -> [ExprId; RATE] {
    assert!(xs.len() <= RATE);
    let mut out = [ExprId::ZERO; RATE];
    out[..xs.len()].copy_from_slice(xs);
    out
}

fn sponge(
    builder: &mut CircuitBuilder<Challenge>,
    tag: u32,
    xs: &[ExprId],
) -> Result<[ExprId; DIGEST], String> {
    let blocks: Vec<_> = xs.chunks(RATE).map(padded_targets).collect();
    sponge_lanes(builder, tag, &blocks)
}

fn sponge_lanes(
    builder: &mut CircuitBuilder<Challenge>,
    tag: u32,
    blocks: &[[ExprId; RATE]],
) -> Result<[ExprId; DIGEST], String> {
    let tag = builder.define_const(Challenge::from(F::from_u32(tag)));
    let len = builder.define_const(Challenge::from(F::from_usize(blocks.len())));
    let zero = builder.define_const(Challenge::ZERO);
    let mut result = None;
    for (i, block) in blocks.iter().enumerate() {
        let first = i == 0;
        let last = i + 1 == blocks.len();
        let mut inputs: Vec<_> = block.iter().copied().map(Some).collect();
        inputs.extend((0..RATE).map(|k| {
            if first {
                Some(match k {
                    0 => tag,
                    1 => len,
                    _ => zero,
                })
            } else {
                None
            }
        }));
        let out = builder
            .add_poseidon2_perm(&Poseidon2PermCall {
                config: Poseidon2Config::KOALA_BEAR_D1_W24,
                new_start: first,
                merkle_path: false,
                mmcs_bit: None,
                mmcs_bit2: None,
                inputs,
                out_ctl: vec![last; DIGEST],
                return_all_outputs: false,
                absorb_len: 0,
            })
            .map_err(err)?
            .1;
        if last {
            result = Some(core::array::from_fn(|k| {
                out[k].expect("scalar digest output")
            }));
        }
    }
    result.ok_or("empty sponge input".into())
}

fn bind_base(builder: &mut CircuitBuilder<Challenge>, xs: &[ExprId]) -> Result<(), String> {
    for chunk in xs.chunks(8) {
        let mut padded = chunk.to_vec();
        padded.resize(8, ExprId::ZERO);
        builder
            .recompose_base_coeffs_to_ext_with_coeff_lookups::<F>(&padded)
            .map_err(err)?;
    }
    Ok(())
}

/// 16-bit limbs of a value given by its little-endian bits (at most 32 bits).
fn limbs_of_bits(builder: &mut CircuitBuilder<Challenge>, bits: &[ExprId]) -> Vec<ExprId> {
    bits.chunks(LIMB_BITS)
        .map(|c| {
            let mut acc = ExprId::ZERO;
            for (k, &b) in c.iter().enumerate() {
                let w = builder.define_const(Challenge::from(F::from_u32(1 << k)));
                let t = builder.mul(b, w);
                acc = builder.add(acc, t);
            }
            acc
        })
        .collect()
}

/// The root's miner package: height and share limbs (exported), and its commitment.
struct MinerTargets {
    height: ExprId,
    share: Vec<ExprId>,
    cm: [ExprId; DIGEST],
}

/// In-circuit `Hasher::miner_note_cm(total + share, height, owner, rseed)`, with the fee total
/// given as 16-bit limbs. Allocates height, the share limbs, owner and rseed as private inputs,
/// in that order; the root exports height and share.
fn miner_note_cm(
    builder: &mut CircuitBuilder<Challenge>,
    fee: &[ExprId],
) -> Result<MinerTargets, String> {
    let height = builder.alloc_private_input("miner package height");
    let share = builder.alloc_private_inputs(LIMBS, "miner share limbs");
    let owner = builder.alloc_private_inputs(DIGEST, "miner package owner");
    let rseed = builder.alloc_private_inputs(DIGEST, "miner package rseed");
    bind_base(builder, &[height])?;
    bind_base(builder, &share)?;
    bind_base(builder, &owner)?;
    bind_base(builder, &rseed)?;
    // value = fee + share, limbwise with carries. Fee limbs are < 2^16 (the root's own carry
    // chain) and share limbs are range-checked here, so each sum is < 2^17 + 1 and the 17-bit
    // decomposition is sound; the final carry is 0, so the value fits in u64.
    let mut carry = ExprId::ZERO;
    let mut value = Vec::with_capacity(LIMBS);
    for (&f, &s) in fee.iter().zip(&share) {
        builder.decompose_to_bits::<F>(s, LIMB_BITS).map_err(err)?;
        let t = builder.add(f, s);
        let t = builder.add(t, carry);
        let (lo, hi) = split_low(builder, t, LIMB_BITS)?;
        value.push(lo);
        carry = hi;
    }
    builder.assert_zero(carry);
    // Both heights below 2^HEIGHT_BITS, so each is two limbs (the upper two are zero).
    let hb = builder
        .decompose_to_bits::<F>(height, HEIGHT_BITS)
        .map_err(err)?;
    let delay = builder.define_const(Challenge::from(F::from_u64(COINBASE_MATURITY)));
    let unlock = builder.add(height, delay);
    let ub = builder
        .decompose_to_bits::<F>(unlock, HEIGHT_BITS)
        .map_err(err)?;
    let hl = limbs_of_bits(builder, &hb);
    let ul = limbs_of_bits(builder, &ub);
    let rho = sponge(builder, TAG_MINER_RHO, &hl)?;
    let blocks = [
        lanes(builder, &owner),
        {
            let mut numeric = value.clone();
            numeric.extend_from_slice(&ul);
            padded_targets(&numeric)
        },
        rho,
        lanes(builder, &rseed),
    ];
    let cm = sponge_lanes(builder, TAG_NOTE, &blocks)?;
    Ok(MinerTargets { height, share, cm })
}

fn lanes(_builder: &mut CircuitBuilder<Challenge>, d: &[ExprId]) -> [ExprId; DIGEST] {
    d.try_into().expect("exact scalar digest length")
}

fn anchor_path(
    builder: &mut CircuitBuilder<Challenge>,
    entry: [ExprId; DIGEST],
    root: [ExprId; DIGEST],
) -> Result<(), String> {
    let pos = builder.alloc_private_input("anchor position");
    let bits = builder
        .decompose_to_bits::<F>(pos, ANCHOR_DEPTH)
        .map_err(err)?;
    let sibs = builder.alloc_private_inputs(DIGEST * ANCHOR_DEPTH, "anchor siblings");
    bind_base(builder, &sibs)?;
    let mut cur = entry;
    for (bit, sib) in bits.iter().zip(sibs.chunks(DIGEST)) {
        let mut left = [ExprId::ZERO; DIGEST];
        let mut right = [ExprId::ZERO; DIGEST];
        for k in 0..DIGEST {
            let d = builder.sub(sib[k], cur[k]);
            let t = builder.mul(*bit, d);
            left[k] = builder.add(cur[k], t);
            let sum = builder.add(sib[k], cur[k]);
            right[k] = builder.sub(sum, left[k]);
        }
        let inputs = left.into_iter().chain(right).map(Some).collect();
        let out = builder
            .add_poseidon2_perm(&Poseidon2PermCall {
                config: Poseidon2Config::KOALA_BEAR_D1_W24,
                new_start: true,
                merkle_path: false,
                mmcs_bit: None,
                mmcs_bit2: None,
                inputs,
                out_ctl: vec![true; DIGEST],
                return_all_outputs: false,
                absorb_len: 0,
            })
            .map_err(err)?
            .1;
        cur = core::array::from_fn(|k| out[k].expect("scalar digest output"));
    }
    for k in 0..DIGEST {
        let d = builder.sub(cur[k], root[k]);
        builder.assert_zero(d);
    }
    Ok(())
}

/// Full statement targets of a child. A leaf exposes them directly; an internal node exposes a
/// digest, so the full statement is allocated as private base-field inputs and hashed.
fn full_statement(
    builder: &mut CircuitBuilder<Challenge>,
    child: &Child,
    public: Vec<ExprId>,
) -> Result<Vec<ExprId>, String> {
    if let Child::Uni(_) = child {
        return Ok(public);
    }
    let full = builder.alloc_private_inputs(NUM_ACC_PUBLIC, "child statement");
    bind_base(builder, &full)?;
    let d = sponge(builder, TAG_ACC_NODE, &full)?;
    for (computed, supplied) in d.iter().zip(&public) {
        let diff = builder.sub(*computed, *supplied);
        builder.assert_zero(diff);
    }
    Ok(full)
}

impl AccAggregation {
    /// `sample` fixes the child proof shape; any later child with the same shape may be proven.
    /// `root` outputs the 𝒜 root, height, miner package commitment and miner share instead of
    /// the fee limbs.
    pub fn new(
        child: Child,
        sample: Input<'_>,
        out_cfg: &Cfg,
        params: &ProveNextLayerParams,
        root: bool,
    ) -> Result<Self, String> {
        let backend = backend();
        let mut builder = CircuitBuilder::new();
        child.prepare(&backend, &mut builder)?;
        let (left, lt) = child.build(&backend, sample, &mut builder)?;
        let (right, rt) = child.build(&backend, sample, &mut builder)?;
        let mut lt = full_statement(&mut builder, &child, lt)?;
        let mut rt = full_statement(&mut builder, &child, rt)?;
        if let Child::Uni(_) = child {
            // Level 1: both leaves' 𝒜 entries lie in one 𝒜 root, which replaces the entries.
            let root = builder.alloc_private_inputs(DIGEST, "𝒜 root");
            bind_base(&mut builder, &root)?;
            let root_lanes = lanes(&mut builder, &root);
            for t in [&mut lt, &mut rt] {
                let entry = lanes(&mut builder, &t[ACC_ENTRY..]);
                anchor_path(&mut builder, entry, root_lanes)?;
                t.truncate(ACC_ENTRY);
                t.extend_from_slice(&root);
            }
        }

        // Both children prove against the same 𝒜 root.
        for e in ACC_ROOT..NUM_ACC_PUBLIC {
            let d = builder.sub(lt[e], rt[e]);
            builder.assert_zero(d);
        }
        let anchors = &lt[ACC_ROOT..];
        // Set accumulator: elementwise sum.
        let set: Vec<ExprId> = (ACC_SET..ACC_FEE)
            .map(|e| builder.add(lt[e], rt[e]))
            .collect();
        // Fee: limbwise sum with carries; every limb stays below 2^16 and the final carry is 0,
        // so the total fits in u64. Child limbs are < 2^16 by induction (the leaf AIR
        // range-checks its fee limbs), so each sum is < 2^17 + 1 and the 17-bit decomposition
        // is sound.
        let mut carry = ExprId::ZERO;
        let mut fee = Vec::with_capacity(LIMBS);
        for k in ACC_FEE..ACC_COUNT {
            let s = builder.add(lt[k], rt[k]);
            let s = builder.add(s, carry);
            let (lo, hi) = split_low(&mut builder, s, LIMB_BITS)?;
            fee.push(lo);
            carry = hi;
        }
        builder.assert_zero(carry);
        let count = builder.add(lt[ACC_COUNT], rt[ACC_COUNT]);
        builder
            .decompose_to_bits::<F>(count, COUNT_BITS)
            .map_err(err)?;

        let mut exports: Vec<StatementExport> = Vec::new();
        if root {
            // [ΣE, 𝒜 root, height, cm_miner, share limbs, count].
            let m = miner_note_cm(&mut builder, &fee)?;
            exports.extend(set.iter().map(|&e| StatementExport::Base(e)));
            exports.extend(anchors.iter().map(|&e| StatementExport::Base(e)));
            exports.push(StatementExport::Base(m.height));
            exports.extend(m.cm.map(StatementExport::Base));
            exports.extend(m.share.iter().map(|&e| StatementExport::Base(e)));
            exports.push(StatementExport::Base(count));
        } else {
            let mut full = set.clone();
            full.extend(&fee);
            full.push(count);
            full.extend(anchors);
            for o in sponge(&mut builder, TAG_ACC_NODE, &full)? {
                exports.push(StatementExport::Base(o));
            }
        }
        let schema = builder.set_statement_exports::<F>(&exports).map_err(err)?;
        let circuit = builder.build().map_err(err)?;

        let mut preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> =
            <Backend as PcsRecursionBackend<Cfg, BatchOnly, 8>>::non_primitive_preprocessors(
                &backend,
            );
        let mut air_builders: Vec<Box<dyn NpoAirBuilder<Cfg, 8>>> =
            <Backend as PcsRecursionBackend<Cfg, BatchOnly, 8>>::non_primitive_air_builders(
                &backend,
            );
        let mut provers: Vec<Box<dyn TableProver<Cfg>>> =
            <Backend as PcsRecursionBackend<Cfg, BatchOnly, 8>>::non_primitive_provers(&backend, 8);
        preprocessors.push(Box::new(StatementPreprocessor::new(schema.clone())));
        air_builders.push(Box::new(StatementAirBuilder::<8>::new(schema.clone())));
        provers.push(Box::new(StatementProver::<8>::new(schema)));
        let mut prover = BatchStarkProver::new(out_cfg.clone())
            .with_table_packing(params.table_packing.clone())
            .with_alu_variant(match params.constraint_profile {
                ConstraintProfile::Standard => AirVariant::Baseline,
                ConstraintProfile::RecursionOptimized => AirVariant::Optimized,
            });
        for p in provers {
            prover.register_table_prover(p);
        }
        let prepared = prover
            .prepare_circuit::<Challenge, 8>(
                &circuit,
                &preprocessors,
                &air_builders,
                params.constraint_profile,
            )
            .map_err(err)?;
        Ok(Self {
            child,
            backend,
            circuit,
            left,
            right,
            root,
            prepared,
        })
    }

    /// Prove one node. `note` is required at the root and ignored elsewhere.
    pub fn prove(
        &self,
        left: Input<'_>,
        right: Input<'_>,
        note: Option<&MinerNote>,
    ) -> Result<BatchStarkProof<Cfg>, String> {
        self.prove_with(left, right, note, [left.full(), right.full()], None)
    }

    /// `full` is the private full statement of each child, and `anchors` the 𝒜 root a level-1
    /// node checks both leaves against (by default the root of the left leaf's path). Only tests
    /// pass values other than the defaults.
    fn prove_with(
        &self,
        left: Input<'_>,
        right: Input<'_>,
        note: Option<&MinerNote>,
        full: [&[F]; 2],
        anchors: Option<&Digest>,
    ) -> Result<BatchStarkProof<Cfg>, String> {
        let lp = self.child.prev(left)?;
        let rp = self.child.prev(right)?;
        let mut public = self.child.pack_public(&self.left, &lp)?;
        public.extend(self.child.pack_public(&self.right, &rp)?);
        let mut private = self.child.pack_private(&self.left, &lp)?;
        private.extend(self.child.pack_private(&self.right, &rp)?);
        if let Child::Batch(_) = self.child {
            for x in full {
                private.extend(x.iter().map(|&e| Challenge::from(e)));
            }
        }
        if let (Input::Uni(_, ls, lpath), Input::Uni(_, _, rpath)) = (left, right) {
            if lpath.len() != ANCHOR_DEPTH || rpath.len() != ANCHOR_DEPTH {
                return Err("𝒜 path length".into());
            }
            let root = match anchors {
                Some(r) => *r,
                None => anchor_leaf(ls, lpath)[ACC_ROOT..]
                    .try_into()
                    .expect("digest"),
            };
            private.extend(root.iter().map(|&e| Challenge::from(e)));
            for path in [lpath, rpath] {
                let pos: u32 = path
                    .iter()
                    .enumerate()
                    .map(|(k, (_, is_right))| u32::from(*is_right) << k)
                    .sum();
                private.push(Challenge::from(F::from_u32(pos)));
                for (sib, _) in path {
                    private.extend(sib.iter().copied().map(Challenge::from));
                }
            }
        }
        if self.root {
            let n = note.ok_or("root needs the miner package data")?;
            private.push(Challenge::from(F::from_u64(n.height)));
            private.extend(limbs(n.share).map(Challenge::from));
            private.extend(n.owner.iter().chain(&n.rseed).map(|&e| Challenge::from(e)));
        }
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&public).map_err(err)?;
        runner.set_private_inputs(&private).map_err(err)?;
        self.child
            .set_private(&self.backend, &self.left, &lp, left, &mut runner)?;
        self.child
            .set_private(&self.backend, &self.right, &rp, right, &mut runner)?;
        let traces = {
            #[cfg(feature = "phase-profile")]
            let _phase = crate::profile::Span::new("recursive_witness");
            runner.run().map_err(err)?
        };
        #[cfg(feature = "phase-profile")]
        let _phase = crate::profile::Span::new("recursive_stark");
        let (proof, _) = self.prepared.prove_with_legacy_data(&traces).map_err(err)?;
        Ok(proof)
    }

    pub fn verifier(&self) -> CircuitVerifier<Cfg> {
        self.prepared.verifier()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FriParams;
    use crate::air::ACC_ENTRY;
    use crate::common::{
        ANCHOR_DEPTH, FEE_BASE, FEE_PRIORITY, MINER_SHARE, RecentRoots, Rng, acc_witnesses,
        sample_empty_slot, sample_priority_slot, sample_slot,
    };
    use p3_circuit_prover::TablePacking;

    fn params(p: FriParams) -> ProveNextLayerParams {
        let min_height = (4 * (8 + p.num_queries as usize)).next_power_of_two();
        ProveNextLayerParams {
            table_packing: TablePacking::new(4, 4).with_min_trace_height(min_height),
            ..ProveNextLayerParams::default()
        }
    }

    fn bump(s: &[F], i: usize) -> Vec<F> {
        let mut v = s.to_vec();
        v[i] += F::ONE;
        v
    }

    /// Four leaves (standard, priority, empty, dummy-input) → two internal nodes → root.
    #[test]
    fn accumulates_fees_and_commits_at_root() {
        let p = FriParams::fast();
        let lp = params(p);
        let prover = Arc::new(SlotProver::new_acc(p));
        let slots = vec![
            sample_slot(11, false),
            sample_priority_slot(12),
            sample_empty_slot(13),
            sample_slot(14, true),
        ];
        let (ws, anchors) = acc_witnesses(slots, 1000, FEE_BASE, 5);
        let leaves: Vec<_> = ws.iter().map(|w| prover.prove_acc(w)).collect();
        let inp = |i: usize| Input::Uni(&leaves[i].0, &leaves[i].1, &ws[i].anchor_path);
        let al = |i: usize| anchor_leaf(&leaves[i].1, &ws[i].anchor_path);

        let l1 = AccAggregation::new(Child::Uni(prover.clone()), inp(0), &p.config(), &lp, false)
            .expect("level 1 setup");
        let v1 = l1.verifier();
        let n01 = l1.prove(inp(0), inp(1), None).expect("node 01");
        let s01 = compose_acc(&al(0), &al(1));
        assert_eq!(fee_of(&s01), FEE_BASE + FEE_PRIORITY);
        assert_eq!(&s01[ACC_ROOT..], &anchors);
        let d01 = node_digest(&s01);
        assert_eq!(d01.len(), NUM_NODE_PUBLIC);
        v1.verify(&n01, &d01).expect("node 01 verifies");
        for i in [0, NUM_NODE_PUBLIC - 1] {
            assert!(
                v1.verify(&n01, &bump(&d01, i)).is_err(),
                "tampered digest {i}"
            );
        }
        // The digest binds every field of the full statement.
        for (name, i) in [
            ("set accumulator", ACC_SET),
            ("set accumulator tail", ACC_FEE - 1),
            ("fee limb 0", ACC_FEE),
            ("fee limb 1", ACC_FEE + 1),
            ("count", ACC_COUNT),
            ("𝒜 root", ACC_ROOT),
            ("𝒜 root tail", NUM_ACC_PUBLIC - 1),
        ] {
            let d = node_digest(&bump(&s01, i));
            assert!(v1.verify(&n01, &d).is_err(), "tampered {name}");
        }
        // A leaf statement that does not match its proof cannot be aggregated.
        assert!(
            l1.prove(
                Input::Uni(&leaves[0].0, &leaves[1].1, &ws[1].anchor_path),
                inp(1),
                None
            )
            .is_err(),
            "leaf proof with another leaf's statement"
        );
        // A leaf anchored in another 𝒜 cannot be merged.
        let (other_ws, other_anchors) =
            acc_witnesses(vec![sample_slot(15, false)], 2000, FEE_BASE, 6);
        assert_ne!(other_anchors, anchors);
        let other_leaf = prover.prove_acc(&other_ws[0]);
        assert!(
            l1.prove(
                inp(0),
                Input::Uni(&other_leaf.0, &other_leaf.1, &other_ws[0].anchor_path),
                None
            )
            .is_err(),
            "children with different 𝒜 roots"
        );
        // Order independence: swapping the children proves the same statement.
        let n10 = l1.prove(inp(1), inp(0), None).expect("node 10");
        v1.verify(&n10, &d01)
            .expect("swapped children give the same statement");
        // The circuit does not exclude one leaf under two positions: ΣE counts it twice and the
        // count is 2. Multiplicity stays bounded by the fixed tree shape, and the native rules
        // (distinct nullifiers, ΣE recomputed from the block's slots) reject such a root
        // (docs/cryptography.md).
        let n00 = l1.prove(inp(0), inp(0), None).expect("node 00");
        let s00 = compose_acc(&al(0), &al(0));
        assert_eq!(s00[ACC_COUNT], F::TWO);
        assert_eq!(fee_of(&s00), 2 * FEE_BASE);
        v1.verify(&n00, &node_digest(&s00))
            .expect("a repeated leaf is a valid node");

        let n23 = l1.prove(inp(2), inp(3), None).expect("node 23");
        let s23 = compose_acc(&al(2), &al(3));
        assert_eq!(fee_of(&s23), FEE_BASE);
        v1.verify(&n23, &node_digest(&s23))
            .expect("node 23 verifies");

        // Root over two internal nodes.
        let note = MinerNote {
            height: 1234,
            share: MINER_SHARE,
            owner: Rng::new(7).digest(),
            rseed: Rng::new(8).digest(),
        };
        let root = AccAggregation::new(
            Child::Batch(v1.clone()),
            Input::Batch(&n01, &s01),
            &p.config(),
            &lp,
            true,
        )
        .expect("root setup");
        let vr = root.verifier();
        let pr = root
            .prove(
                Input::Batch(&n01, &s01),
                Input::Batch(&n23, &s23),
                Some(&note),
            )
            .expect("root proof");
        let sr = root_statement(&s01, &s23, &note);
        assert_eq!(sr.len(), NUM_ROOT_PUBLIC);
        let h = Hasher::new();
        let mut set = [F::ZERO; SET_LEN];
        for w in &ws {
            for (s, e) in set.iter_mut().zip(w.set_element(&h)) {
                *s += e;
            }
        }
        assert_eq!(&sr[ROOT_SET..ROOT_ANCHORS], &set);
        assert_eq!(&sr[ROOT_ANCHORS..ROOT_HEIGHT], &anchors);
        assert_eq!(sr[ROOT_HEIGHT], F::from_u64(note.height));
        assert_eq!(
            &sr[ROOT_CM_MINER..ROOT_SHARE],
            &h.miner_note_cm(
                2 * FEE_BASE + FEE_PRIORITY + MINER_SHARE,
                note.height,
                &note.owner,
                &note.rseed
            )
        );
        assert_eq!(&sr[ROOT_SHARE..ROOT_COUNT], &limbs(MINER_SHARE));
        assert_eq!(sr[ROOT_COUNT], F::from_u32(4));
        vr.verify(&pr, &sr).expect("root verifies");
        for (name, i) in [
            ("set accumulator", ROOT_SET),
            ("𝒜 root", ROOT_ANCHORS),
            ("height", ROOT_HEIGHT),
            ("cm_miner", ROOT_CM_MINER),
            ("cm_miner tail", ROOT_SHARE - 1),
            ("share", ROOT_SHARE),
            ("share tail", ROOT_COUNT - 1),
            ("count", ROOT_COUNT),
        ] {
            assert!(vr.verify(&pr, &bump(&sr, i)).is_err(), "tampered {name}");
        }
        for (name, other) in [
            (
                "height",
                MinerNote {
                    height: 1235,
                    ..note
                },
            ),
            (
                "share",
                MinerNote {
                    share: MINER_SHARE + 1,
                    ..note
                },
            ),
            (
                "owner",
                MinerNote {
                    owner: note.rseed,
                    ..note
                },
            ),
            (
                "rseed",
                MinerNote {
                    rseed: note.owner,
                    ..note
                },
            ),
        ] {
            assert!(
                vr.verify(&pr, &root_statement(&s01, &s23, &other)).is_err(),
                "a miner package with another {name} must fail"
            );
        }
        let mut other = s01.clone();
        other[ACC_FEE] += F::ONE;
        let wrong_fee = root_statement(&other, &s23, &note);
        assert!(
            vr.verify(&pr, &wrong_fee).is_err(),
            "a commitment to a different fee total must fail"
        );
        // Heights whose unlock height reaches 2^HEIGHT_BITS are out of range.
        let tall = MinerNote {
            height: (1 << HEIGHT_BITS) - COINBASE_MATURITY,
            ..note
        };
        assert!(
            root.prove(
                Input::Batch(&n01, &s01),
                Input::Batch(&n23, &s23),
                Some(&tall)
            )
            .is_err(),
            "unlock height out of range"
        );
        // Fee total plus share must fit in u64.
        let rich = MinerNote {
            share: u64::MAX,
            ..note
        };
        assert!(
            root.prove(
                Input::Batch(&n01, &s01),
                Input::Batch(&n23, &s23),
                Some(&rich)
            )
            .is_err(),
            "miner package value overflows u64"
        );
        // A full child statement that does not hash to the child's digest cannot be aggregated.
        assert!(
            root.prove(
                Input::Batch(&n01, &other),
                Input::Batch(&n23, &s23),
                Some(&note)
            )
            .is_err(),
            "tampered child fee"
        );
        // The same, with the real child proofs and digests: only the private full statement
        // differs, so the in-circuit digest check must reject it.
        assert!(
            root.prove_with(
                Input::Batch(&n01, &s01),
                Input::Batch(&n23, &s23),
                Some(&note),
                [&other, &s23],
                None,
            )
            .is_err(),
            "private child statement that does not hash to the child's digest"
        );
    }

    /// The level-1 node, not the leaf, proves each leaf's 𝒜 entry is in the 𝒜 root it outputs,
    /// so a leaf proof stays usable while its anchor is in the window.
    #[test]
    fn level_one_checks_anchor_membership() {
        let p = FriParams::fast();
        let prover = Arc::new(SlotProver::new_acc(p));
        let h = Hasher::new();
        let slots = vec![sample_slot(21, false), sample_priority_slot(22)];
        let (ws, root1) = acc_witnesses(slots, 300, FEE_BASE, 3);
        let leaves: Vec<_> = ws.iter().map(|w| prover.prove_acc(w)).collect();
        for (w, (_, stmt)) in ws.iter().zip(&leaves) {
            assert_eq!(
                &stmt[ACC_ENTRY..],
                &w.anchor_entry(&h),
                "the leaf exposes its entry"
            );
        }
        assert_ne!(leaves[0].1[ACC_ENTRY..], leaves[1].1[ACC_ENTRY..]);

        // 𝒜 a few dozen blocks later: same entries, more blocks, another root.
        let mut ring = RecentRoots::new();
        for w in &ws {
            ring.insert(&h, w.anchor_height, &w.slot.anchor, w.base_fee);
        }
        let mut rng = Rng::new(4);
        for height in 302..340 {
            ring.insert(&h, height, &rng.digest(), FEE_BASE);
        }
        let tree2 = ring.tree(&h);
        let root2 = tree2.root();
        assert_ne!(root1, root2);
        let paths2: Vec<_> = ws.iter().map(|w| tree2.path(w.anchor_height)).collect();

        let l1 = AccAggregation::new(
            Child::Uni(prover.clone()),
            Input::Uni(&leaves[0].0, &leaves[0].1, &ws[0].anchor_path),
            &p.config(),
            &params(p),
            false,
        )
        .expect("level 1 setup");
        let v1 = l1.verifier();
        let node = |paths: [&[(Digest, bool)]; 2], anchors: Option<&Digest>| {
            l1.prove_with(
                Input::Uni(&leaves[0].0, &leaves[0].1, paths[0]),
                Input::Uni(&leaves[1].0, &leaves[1].1, paths[1]),
                None,
                [&leaves[0].1, &leaves[1].1],
                anchors,
            )
        };
        let stmt = |paths: [&[(Digest, bool)]; 2]| {
            compose_acc(
                &anchor_leaf(&leaves[0].1, paths[0]),
                &anchor_leaf(&leaves[1].1, paths[1]),
            )
        };

        let p1 = [&ws[0].anchor_path[..], &ws[1].anchor_path[..]];
        let s1 = stmt(p1);
        assert_eq!(&s1[ACC_ROOT..], &root1);
        v1.verify(
            &node(p1, None).expect("node under 𝒜 at the anchor block"),
            &node_digest(&s1),
        )
        .expect("node verifies");

        // The same leaf proofs, merged under the later 𝒜.
        let p2 = [&paths2[0][..], &paths2[1][..]];
        let s2 = stmt(p2);
        assert_eq!(&s2[ACC_ROOT..], &root2);
        let n2 = node(p2, None).expect("node under a later 𝒜");
        v1.verify(&n2, &node_digest(&s2))
            .expect("leaf proofs outlive later blocks");
        assert!(
            v1.verify(&n2, &node_digest(&s1)).is_err(),
            "the node binds its 𝒜 root"
        );

        // Children under different 𝒜 roots.
        assert!(
            node([p1[0], p2[1]], None).is_err(),
            "children under different 𝒜 roots"
        );
        // Each child's path is checked, not only the one the claimed root came from.
        assert!(
            node([p1[0], p2[1]], Some(&root2)).is_err(),
            "left path into another root"
        );
        assert!(
            node(p2, Some(&root1)).is_err(),
            "both paths into another root"
        );
        // A wrong sibling or direction bit on either side.
        for side in 0..2 {
            for level in [0, 5, ANCHOR_DEPTH - 1] {
                let mut bad = paths2[side].clone();
                bad[level].0[3] += F::ONE;
                let mut ps = p2;
                ps[side] = &bad;
                assert!(node(ps, Some(&root2)).is_err(), "sibling {side}/{level}");
                let mut bad = paths2[side].clone();
                bad[level].1 ^= true;
                ps[side] = &bad;
                assert!(node(ps, Some(&root2)).is_err(), "direction {side}/{level}");
            }
        }
        // A short path is refused.
        assert!(node([&paths2[0][1..], p2[1]], None).is_err(), "short path");
        // An entry that is not in 𝒜: another anchor at a height 𝒜 holds.
        let (stray, _) = acc_witnesses(vec![sample_slot(23, false)], 301, FEE_BASE, 5);
        assert_ne!(stray[0].slot.anchor, ws[1].slot.anchor);
        let stray_leaf = prover.prove_acc(&stray[0]);
        assert!(
            l1.prove(
                Input::Uni(&leaves[0].0, &leaves[0].1, p2[0]),
                Input::Uni(&stray_leaf.0, &stray_leaf.1, p2[1]),
                None
            )
            .is_err(),
            "entry not in 𝒜"
        );
    }
}
