//! Single-slot AIR: one Poseidon2 permutation per row (KoalaBear, width 24, S-box x³).
//!
//! - The permutation columns reuse `p3-poseidon2-air` directly.
//! - Register columns (nk, ρ, rseed, owner, value limbs, ...) are constant across rows.
//! - The role of each row (first block / continuation / Merkle / padding, which register
//!   it absorbs, where its output is bound) comes from preprocessed selector columns; the
//!   schedule is fixed and independent of the witness.
//! - Every u64 the slot hashes (values, unlock heights, and in accumulator mode the anchor
//!   height and base fee) is four 16-bit limbs, each range-checked on its own row, as are the
//!   difference limbs of the comparisons below. Conservation is compared limb by limb with
//!   carries.
//! - nf₀ ≠ nf₁, and each output value is 0 or at least MIN_PACKAGE_DEPOSIT.
//!
//! Row schedule (107 rows, padded to 128):
//! - input i (47 rows): owner = H(nk) 1 row, cm 4 rows, Merkle 40 rows, nf 2 rows;
//! - output j (6 rows): ρⱼ 2 rows, cmⱼ 4 rows;
//! - fee commitment 1 row.
//!
//! The trace height is the schedule length rounded up to a power of two.
//!
//! Chain mode (`SlotAir::new_chain`, for fixed-width aggregation): the 72 public values
//! above become register columns (witness), leaving only [s_in(16), s_out(16), count(1)] as
//! public inputs. Seven extra rows compute
//! s_out = H(TAG_CHAIN; s_in, nf₀, nf₁, cm₀, cm₁, anchor, fee_commit), and count = 1 is
//! constrained.
//!
//! Accumulator mode (`SlotAir::new_acc`, for order-independent aggregation, docs/00-decisions):
//! the slot public values also become registers; the public inputs are
//! [E(72), fee limbs(4), count(1), anchor entry(12)]. The fee commitment row is dropped (the fee is
//! in the clear), and 12 rows are added (118 rows, padded to 128):
//! - 𝒜 entry, 2 rows: entry = sponge(TAG_ANCHOR; anchor, [h limbs ‖ base_fee limbs]); the
//!   level-1 merge node proves its membership in 𝒜 (agg.rs), so the leaf has no 𝒜 path;
//! - E, 10 rows: sponge(TAG_SET; nf₀, nf₁, cm₀, cm₁, d_ct) with six squeezes, where d_ct is
//!   16 register limbs;
//! - fee tier: fee = (1 − all_dummy)·(1 + 3t)·base_fee, limb by limb with carries in [0, 3],
//!   so fee ∈ {0, base_fee, 4·base_fee} with base_fee taken from the 𝒜 entry; count = 1;
//! - each real input's unlock height is at most the 𝒜 entry's anchor height.

use crate::common::{
    self as c, DCT_LEN, DIGEST, F, FEE_BASE, FEE_PRIORITY, LIMB_BITS, LIMBS, MIN_PACKAGE_DEPOSIT,
    NUM_PUBLIC, RATE, SET_ABSORB, SET_LEN, TAG_ANCHOR, TAG_CHAIN, TAG_FEE, TAG_NF, TAG_NOTE,
    TAG_OWNER, TAG_RHO, TAG_SET, TREE_DEPTH, WIDTH,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KOALABEAR_POSEIDON2_RC_24_EXTERNAL_FINAL,
    KOALABEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL, KOALABEAR_POSEIDON2_RC_24_INTERNAL,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants, num_cols};
use p3_uni_stark::SubAirBuilder;

pub type LinearLayers = GenericPoseidon2LinearLayersKoalaBear;
pub type P2Air = Poseidon2Air<F, LinearLayers, WIDTH, 3, 0, 4, 23>;
pub type P2Constants = RoundConstants<F, WIDTH, 4, 23>;

pub fn p2_constants() -> P2Constants {
    RoundConstants::new(
        KOALABEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL,
        KOALABEAR_POSEIDON2_RC_24_INTERNAL,
        KOALABEAR_POSEIDON2_RC_24_EXTERNAL_FINAL,
    )
}

// ---- Main trace column layout ----
/// Permutation columns: 24 inputs + 8 full rounds × 24 + 23 partial rounds × 1.
pub const P2: usize = num_cols::<WIDTH, 3, 0, 4, 23>();
/// Permutation output = the post state of the last full round (the last 24 permutation columns).
pub const OUT: usize = P2 - WIDTH;
/// Merkle rows: whether the current node is a right child.
pub const BIT: usize = P2;
/// The limb range-checked on this row and its 16 bits.
pub const RV: usize = BIT + 1;
pub const RBITS: usize = RV + 1;
pub const REG: usize = RBITS + LIMB_BITS;

pub const IN_NK: usize = 0;
pub const IN_RHO: usize = DIGEST;
pub const IN_RSEED: usize = 2 * DIGEST;
pub const IN_OWNER: usize = 3 * DIGEST;
/// Four value limbs + four unlock limbs + four zero elements: second note block.
pub const IN_VU: usize = 4 * DIGEST;
pub const IN_D: usize = IN_VU + RATE;
pub const IN_W: usize = IN_D + 1;

pub const OUT_OWNER: usize = 0;
pub const OUT_VU: usize = DIGEST;
pub const OUT_RSEED: usize = OUT_VU + RATE;
pub const OUT_RHO: usize = OUT_RSEED + DIGEST;
/// Zero flag z: the value is 0 (z = 1) or value = MIN_PACKAGE_DEPOSIT + δ (z = 0), with four δ
/// limbs and three 1-bit carries.
pub const OUT_Z: usize = OUT_RHO + DIGEST;
pub const OUT_MD: usize = OUT_Z + 1;
pub const OUT_MC: usize = OUT_MD + LIMBS;
pub const OUT_W: usize = OUT_MC + LIMBS - 1;

/// Four fee limbs + four blind elements + four zero elements: fee block.
pub const FEE_VB: usize = 0;
pub const FEE_T: usize = RATE;
pub const FEE_AD: usize = RATE + 1;
/// Three carries of 3 bits each, c = b₀ + 2b₁ + 4b₂ − 3 ∈ [−3, 4].
pub const FEE_CARRY: usize = RATE + 2;
pub const FEE_W: usize = RATE + 11;

pub const fn input(i: usize) -> usize {
    REG + i * IN_W
}
pub const fn output(j: usize) -> usize {
    REG + 2 * IN_W + j * OUT_W
}
pub const FEE: usize = REG + 2 * IN_W + 2 * OUT_W;
/// nf₀ ≠ nf₁: sixteen coefficients r with Σ rₑ·(nf₀ₑ − nf₁ₑ) = 1, unsatisfiable when the nullifiers
/// are equal.
pub const NEQ: usize = FEE + FEE_W;
pub const MAIN_WIDTH: usize = NEQ + DIGEST;

// ---- Public input layout ----
pub const fn pub_nf(i: usize) -> usize {
    i * DIGEST
}
pub const fn pub_cm(j: usize) -> usize {
    2 * DIGEST + j * DIGEST
}
pub const PUB_ANCHOR: usize = 4 * DIGEST;
pub const PUB_FEE: usize = 5 * DIGEST;

/// Chain mode: first register column holding the slot public values (after the regular registers).
pub const CHAIN_REG: usize = MAIN_WIDTH;
/// Chain-mode public inputs: s_in, s_out, count.
pub const STMT_IN: usize = 0;
pub const STMT_OUT: usize = DIGEST;
pub const STMT_COUNT: usize = 2 * DIGEST;
pub const NUM_CHAIN_PUBLIC: usize = 2 * DIGEST + 1;
/// Accumulator-mode public inputs: E, fee limbs, count, then the 𝒜 entry in a leaf statement or
/// the 𝒜 root in a node statement.
pub const ACC_SET: usize = 0;
pub const ACC_FEE: usize = SET_LEN;
pub const ACC_COUNT: usize = SET_LEN + LIMBS;
pub const ACC_ENTRY: usize = ACC_COUNT + 1;
pub const ACC_ROOT: usize = ACC_ENTRY;
pub const NUM_ACC_PUBLIC: usize = ACC_ROOT + DIGEST;
/// Confidential-fee accumulator statement: E, fee commitment, count, root.
pub const ACC_FEE_COMMIT: usize = SET_LEN;
pub const ACC_COUNT_CONF: usize = ACC_FEE_COMMIT + DIGEST;
pub const ACC_ENTRY_CONF: usize = ACC_COUNT_CONF + 1;
pub const ACC_ROOT_CONF: usize = ACC_ENTRY_CONF;
pub const NUM_ACC_CONF_PUBLIC: usize = ACC_ROOT_CONF + DIGEST;
/// Accumulator mode: registers after the slot public values.
pub const ACC_REG: usize = CHAIN_REG + NUM_PUBLIC;
/// Anchor height limbs ‖ base_fee limbs ‖ four zeros: second block of the 𝒜 entry.
pub const ACC_HB: usize = 0;
pub const ACC_BF: usize = ACC_HB + LIMBS;
pub const ACC_DCT: usize = ACC_HB + RATE;
/// Three tier carries of 2 bits each, c ∈ [0, 3].
pub const ACC_TC: usize = ACC_DCT + DCT_LEN.div_ceil(RATE) * RATE;
/// unlock_height ≤ anchor height for each real input: anchor height = unlock + δ with four δ
/// limbs and three 1-bit carries per input.
pub const ACC_UD: usize = ACC_TC + 2 * (LIMBS - 1);
pub const UD_W: usize = 2 * LIMBS - 1;
pub const ACC_W: usize = ACC_UD + 2 * UD_W;

pub const fn acc_ud(i: usize) -> usize {
    ACC_REG + ACC_UD + i * UD_W
}

/// Source of an 16-element vector: register columns, slot public values (held in registers in
/// chain and accumulator modes), the aggregation statement, or zeros (squeeze rows).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Src {
    Reg(usize),
    Pub(usize),
    Stmt(usize),
    Zero,
}

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Pad,
    /// The first block of a sponge absorbing `len` blocks.
    First {
        tag: u32,
        len: usize,
        absorb: Src,
    },
    Cont {
        absorb: Src,
    },
    Merkle {
        input: usize,
        level: usize,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct RowSpec {
    pub kind: Kind,
    /// The value the first 16 elements of this row's permutation output must equal.
    pub out: Option<Src>,
    /// This row is the Merkle root of input i (must equal anchor unless the input is a dummy).
    pub root: Option<usize>,
}

fn row(kind: Kind) -> RowSpec {
    RowSpec {
        kind,
        out: None,
        root: None,
    }
}

pub fn schedule(chain: bool, acc: bool, confidential_fee: bool) -> Vec<RowSpec> {
    let mut rows = Vec::new();
    for i in 0..2 {
        let b = input(i);
        rows.push(RowSpec {
            out: Some(Src::Reg(b + IN_OWNER)),
            ..row(Kind::First {
                tag: TAG_OWNER,
                len: 1,
                absorb: Src::Reg(b + IN_NK),
            })
        });
        rows.push(row(Kind::First {
            tag: TAG_NOTE,
            len: 4,
            absorb: Src::Reg(b + IN_OWNER),
        }));
        for off in [IN_VU, IN_RHO, IN_RSEED] {
            rows.push(row(Kind::Cont {
                absorb: Src::Reg(b + off),
            }));
        }
        for level in 0..TREE_DEPTH {
            rows.push(RowSpec {
                root: (level == TREE_DEPTH - 1).then_some(i),
                ..row(Kind::Merkle { input: i, level })
            });
        }
        rows.push(row(Kind::First {
            tag: TAG_NF,
            len: 2,
            absorb: Src::Reg(b + IN_NK),
        }));
        rows.push(RowSpec {
            out: Some(Src::Pub(pub_nf(i))),
            ..row(Kind::Cont {
                absorb: Src::Reg(b + IN_RHO),
            })
        });
    }
    for j in 0..2 {
        let b = output(j);
        rows.push(row(Kind::First {
            tag: TAG_RHO + j as u32,
            len: 2,
            absorb: Src::Pub(pub_nf(0)),
        }));
        rows.push(RowSpec {
            out: Some(Src::Reg(b + OUT_RHO)),
            ..row(Kind::Cont {
                absorb: Src::Pub(pub_nf(1)),
            })
        });
        rows.push(row(Kind::First {
            tag: TAG_NOTE,
            len: 4,
            absorb: Src::Reg(b + OUT_OWNER),
        }));
        for off in [OUT_VU, OUT_RHO] {
            rows.push(row(Kind::Cont {
                absorb: Src::Reg(b + off),
            }));
        }
        rows.push(RowSpec {
            out: Some(Src::Pub(pub_cm(j))),
            ..row(Kind::Cont {
                absorb: Src::Reg(b + OUT_RSEED),
            })
        });
    }
    if !acc || confidential_fee {
        rows.push(RowSpec {
            out: Some(Src::Pub(PUB_FEE)),
            ..row(Kind::First {
                tag: TAG_FEE,
                len: 1,
                absorb: Src::Reg(FEE + FEE_VB),
            })
        });
    }
    if chain {
        rows.push(row(Kind::First {
            tag: TAG_CHAIN,
            len: 1 + NUM_PUBLIC / DIGEST,
            absorb: Src::Stmt(STMT_IN),
        }));
        for k in 0..NUM_PUBLIC / DIGEST {
            rows.push(RowSpec {
                out: (k + 1 == NUM_PUBLIC / DIGEST).then_some(Src::Stmt(STMT_OUT)),
                ..row(Kind::Cont {
                    absorb: Src::Pub(k * DIGEST),
                })
            });
        }
    }
    if acc {
        rows.push(row(Kind::First {
            tag: TAG_ANCHOR,
            len: 2,
            absorb: Src::Pub(PUB_ANCHOR),
        }));
        rows.push(RowSpec {
            out: Some(Src::Stmt(if confidential_fee {
                ACC_ENTRY_CONF
            } else {
                ACC_ENTRY
            })),
            ..row(Kind::Cont {
                absorb: Src::Reg(ACC_REG + ACC_HB),
            })
        });
        rows.push(row(Kind::First {
            tag: TAG_SET,
            len: SET_ABSORB,
            absorb: Src::Pub(pub_nf(0)),
        }));
        let absorbs = [
            Src::Pub(pub_nf(1)),
            Src::Pub(pub_cm(0)),
            Src::Pub(pub_cm(1)),
            Src::Reg(ACC_REG + ACC_DCT),
            Src::Reg(ACC_REG + ACC_DCT + RATE),
        ];
        for (k, absorb) in absorbs.into_iter().enumerate() {
            rows.push(RowSpec {
                out: (k + 1 == absorbs.len()).then_some(Src::Stmt(ACC_SET)),
                ..row(Kind::Cont { absorb })
            });
        }
        for k in 1..SET_LEN / DIGEST {
            rows.push(RowSpec {
                out: Some(Src::Stmt(ACC_SET + k * DIGEST)),
                ..row(Kind::Cont { absorb: Src::Zero })
            });
        }
    }
    let height = rows.len().next_power_of_two();
    rows.resize(height, row(Kind::Pad));
    rows
}

// ---- Preprocessed column layout ----
const PRE_TAG: usize = 0;
const PRE_FIRST: usize = 1;
const PRE_CONT: usize = 2;
const PRE_MERKLE: usize = 3;
const PRE_ROOT: usize = 4; // 2 columns
const PRE_LEN: usize = 6;
const PRE_ABSORB: usize = 7;

pub struct SlotAir {
    p2: P2Air,
    pub chain: bool,
    pub acc: bool,
    /// Accumulator mode with a private fee and a public fee commitment.
    pub confidential_fee: bool,
    /// Trace height (a power of two).
    pub height: usize,
    pub rows: Vec<RowSpec>,
    /// Deduplicated absorb sources; the k-th maps to preprocessed column PRE_ABSORB + k.
    pub absorb: Vec<Src>,
    pub outs: Vec<Src>,
    /// Register columns of the limbs to range-check; the k-th is checked on row k.
    pub range: Vec<usize>,
}

impl Default for SlotAir {
    fn default() -> Self {
        Self::new()
    }
}

impl SlotAir {
    pub fn new() -> Self {
        Self::build(false, false, false)
    }

    pub fn new_chain() -> Self {
        Self::build(true, false, false)
    }

    pub fn new_acc() -> Self {
        Self::build(false, true, false)
    }

    pub fn new_acc_confidential() -> Self {
        Self::build(false, true, true)
    }

    fn build(chain: bool, acc: bool, confidential_fee: bool) -> Self {
        let rows = schedule(chain, acc, confidential_fee);
        let mut absorb = Vec::new();
        let mut outs = Vec::new();
        for r in &rows {
            if let Kind::First { absorb: s, .. } | Kind::Cont { absorb: s } = r.kind
                && !absorb.contains(&s)
            {
                absorb.push(s);
            }
            if let Some(s) = r.out
                && !outs.contains(&s)
            {
                outs.push(s);
            }
        }
        let mut range = Vec::new();
        for i in 0..2 {
            range.extend((0..LIMBS).map(|k| input(i) + IN_VU + k));
        }
        for j in 0..2 {
            range.extend((0..LIMBS).map(|k| output(j) + OUT_VU + k));
        }
        range.extend((0..LIMBS).map(|k| FEE + FEE_VB + k));
        for i in 0..2 {
            range.extend((0..LIMBS).map(|k| input(i) + IN_VU + LIMBS + k));
        }
        for j in 0..2 {
            range.extend((0..LIMBS).map(|k| output(j) + OUT_VU + LIMBS + k));
        }
        for j in 0..2 {
            range.extend((0..LIMBS).map(|k| output(j) + OUT_MD + k));
        }
        if acc {
            range.extend((0..2 * LIMBS).map(|k| ACC_REG + ACC_HB + k));
            range.extend((0..DCT_LEN).map(|k| ACC_REG + ACC_DCT + k));
            for i in 0..2 {
                range.extend((0..LIMBS).map(|k| acc_ud(i) + k));
            }
        }
        let height = rows.len();
        assert!(range.len() <= height);
        Self {
            p2: P2Air::new(p2_constants()),
            chain,
            acc,
            confidential_fee,
            height,
            rows,
            absorb,
            outs,
            range,
        }
    }

    /// Pads the schedule with idle rows to at least `height` rows (a power of two). Hiding FRI
    /// needs more rows than the leaf uses when the query count is high (`FriParams::hiding_min_height`).
    pub fn with_min_height(mut self, height: usize) -> Self {
        assert!(height.is_power_of_two());
        if height > self.height {
            self.rows.resize(height, row(Kind::Pad));
            self.height = height;
        }
        self
    }

    /// Whether the slot public values are held in registers (chain and accumulator modes).
    pub fn pub_in_regs(&self) -> bool {
        self.chain || self.acc
    }

    pub fn degree_bits(&self) -> usize {
        self.height.trailing_zeros() as usize
    }

    pub fn main_width(&self) -> usize {
        MAIN_WIDTH
            + if self.pub_in_regs() { NUM_PUBLIC } else { 0 }
            + if self.acc { ACC_W } else { 0 }
    }

    pub fn num_public(&self) -> usize {
        if self.chain {
            NUM_CHAIN_PUBLIC
        } else if self.acc {
            if self.confidential_fee {
                NUM_ACC_CONF_PUBLIC
            } else {
                NUM_ACC_PUBLIC
            }
        } else {
            NUM_PUBLIC
        }
    }

    fn pre_out(&self) -> usize {
        PRE_ABSORB + self.absorb.len()
    }

    fn pre_range(&self) -> usize {
        self.pre_out() + self.outs.len()
    }

    fn pre_width(&self) -> usize {
        self.pre_range() + self.range.len()
    }
}

impl BaseAir<F> for SlotAir {
    fn width(&self) -> usize {
        self.main_width()
    }

    fn preprocessed_width(&self) -> usize {
        self.pre_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let w = self.pre_width();
        let mut m = F::zero_vec(self.height * w);
        for (r, spec) in self.rows.iter().enumerate() {
            let row = &mut m[r * w..(r + 1) * w];
            match spec.kind {
                Kind::Pad => {}
                Kind::First { tag, len, absorb } => {
                    row[PRE_TAG] = F::from_u32(tag);
                    row[PRE_LEN] = F::from_usize(len);
                    row[PRE_FIRST] = F::ONE;
                    row[PRE_ABSORB + self.absorb.iter().position(|s| *s == absorb).unwrap()] =
                        F::ONE;
                }
                Kind::Cont { absorb } => {
                    row[PRE_CONT] = F::ONE;
                    row[PRE_ABSORB + self.absorb.iter().position(|s| *s == absorb).unwrap()] =
                        F::ONE;
                }
                Kind::Merkle { .. } => row[PRE_MERKLE] = F::ONE,
            }
            if let Some(s) = spec.out {
                row[self.pre_out() + self.outs.iter().position(|o| *o == s).unwrap()] = F::ONE;
            }
            if let Some(i) = spec.root {
                row[PRE_ROOT + i] = F::ONE;
            }
            if r < self.range.len() {
                row[self.pre_range() + r] = F::ONE;
            }
        }
        Some(RowMajorMatrix::new(m, w))
    }

    fn num_public_values(&self) -> usize {
        self.num_public()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder<F = F>> Air<AB> for SlotAir {
    fn eval(&self, b: &mut AB) {
        {
            let mut sub = SubAirBuilder::<AB, P2Air, AB::Var>::new(b, 0..P2);
            self.p2.eval(&mut sub);
        }

        let main = b.main();
        let pre = b.preprocessed().clone();
        let pis: Vec<AB::PublicVar> = b.public_values().to_vec();
        let l = main.current_slice();
        let n = main.next_slice();
        let pl = pre.current_slice();
        let pn = pre.next_slice();
        let x = |v: AB::Var| -> AB::Expr { v.into() };
        let src = |s: Src, e: usize| -> AB::Expr {
            match s {
                Src::Reg(o) => l[o + e].into(),
                Src::Pub(o) if self.pub_in_regs() => l[CHAIN_REG + o + e].into(),
                Src::Pub(o) | Src::Stmt(o) => pis[o + e].into(),
                Src::Zero => AB::Expr::ZERO,
            }
        };
        let one = AB::Expr::ONE;

        // Registers are constant across rows.
        for col in REG..self.main_width() {
            b.when_transition().assert_eq(n[col], l[col]);
        }

        if self.acc {
            for k in DCT_LEN..DCT_LEN.div_ceil(RATE) * RATE {
                b.assert_zero(l[ACC_REG + ACC_DCT + k]);
            }
        }

        // W24 numeric blocks have eight data elements and four canonical zero elements.
        // Constrain padding even when an adversary recomputes all affected commitments.
        for k in 2 * LIMBS..RATE {
            for i in 0..2 {
                b.assert_zero(l[input(i) + IN_VU + k]);
                b.assert_zero(l[output(i) + OUT_VU + k]);
            }
            if self.acc {
                b.assert_zero(l[ACC_REG + ACC_HB + k]);
            }
        }

        // First block: capacity = [tag, len, 0, …, 0].
        b.assert_zero((x(l[RATE]) - x(pl[PRE_TAG])) * x(pl[PRE_FIRST]));
        b.assert_zero((x(l[RATE + 1]) - x(pl[PRE_LEN])) * x(pl[PRE_FIRST]));
        for e in RATE + 2..WIDTH {
            b.assert_zero(x(l[e]) * x(pl[PRE_FIRST]));
        }
        // Absorb: rate = the selected 16-element source.
        for (k, s) in self.absorb.iter().enumerate() {
            let sel = pl[PRE_ABSORB + k];
            for e in 0..RATE {
                b.assert_zero((x(l[e]) - src(*s, e)) * x(sel));
            }
        }
        // Continuation: next row's capacity = this row's output capacity.
        for e in RATE..WIDTH {
            b.assert_zero((x(n[e]) - x(l[OUT + e])) * x(pn[PRE_CONT]));
        }
        // Merkle: next row's current node (left/right half chosen by BIT) = first 16 outputs of this row.
        for e in 0..DIGEST {
            let cur = (x(n[DIGEST + e]) - x(n[e])) * x(n[BIT]) + x(n[e]);
            b.assert_zero((cur - x(l[OUT + e])) * x(pn[PRE_MERKLE]));
        }
        b.assert_bool(l[BIT]);
        // Merkle root: must equal anchor for real inputs.
        for i in 0..2 {
            let real = one.clone() - x(l[input(i) + IN_D]);
            for e in 0..DIGEST {
                b.assert_zero(
                    (x(l[OUT + e]) - src(Src::Pub(PUB_ANCHOR), e))
                        * real.clone()
                        * x(pl[PRE_ROOT + i]),
                );
            }
        }
        // Output bindings.
        let pre_out = self.pre_out();
        for (k, s) in self.outs.iter().enumerate() {
            for e in 0..DIGEST {
                b.assert_zero((x(l[OUT + e]) - src(*s, e)) * x(pl[pre_out + k]));
            }
        }

        // Chain mode: each leaf counts as one slot.
        if self.chain {
            b.when_first_row()
                .assert_eq(pis[STMT_COUNT].into(), one.clone());
        }
        // Accumulator mode: either expose fee limbs (legacy aggregation) or only
        // the fee commitment (native transaction route); count = 1.
        if self.acc {
            if self.confidential_fee {
                b.when_first_row()
                    .assert_eq(pis[ACC_COUNT_CONF].into(), one.clone());
            } else {
                for k in 0..LIMBS {
                    b.assert_eq(pis[ACC_FEE + k].into(), x(l[FEE + FEE_VB + k]));
                }
                b.when_first_row()
                    .assert_eq(pis[ACC_COUNT].into(), one.clone());
            }
        }

        // Range check: RV = Σ bit·2^k; each row binds one limb to RV.
        let mut acc = AB::Expr::ZERO;
        for k in 0..LIMB_BITS {
            b.assert_bool(l[RBITS + k]);
            acc += x(l[RBITS + k]) * F::from_u32(1 << k);
        }
        b.assert_eq(acc, l[RV]);
        let pre_range = self.pre_range();
        for (k, &col) in self.range.iter().enumerate() {
            b.assert_zero((x(l[RV]) - x(l[col])) * x(pl[pre_range + k]));
        }

        // Dummy inputs: value is 0.
        for i in 0..2 {
            let d = l[input(i) + IN_D];
            b.assert_bool(d);
            for k in 0..LIMBS {
                b.assert_zero(x(d) * x(l[input(i) + IN_VU + k]));
            }
        }
        // Fee tier: 0 when all inputs are dummies, otherwise (1−t)·standard + t·priority.
        let ad = l[FEE + FEE_AD];
        let t = l[FEE + FEE_T];
        b.assert_eq(ad, x(l[input(0) + IN_D]) * x(l[input(1) + IN_D]));
        b.assert_bool(t);
        if self.acc {
            // fee = (1 − ad)·(1 + 3t)·base_fee limb by limb, carries c_k ∈ [0, 3], top carry 0.
            // Both sides of each limb equation stay below 2^19, so it holds over the integers;
            // the fee limbs are range-checked and base_fee is bound by the 𝒜 entry hash.
            let mult = (one.clone() - x(ad)) * (one.clone() + x(t) * F::from_u32(3));
            let mut carry_prev = AB::Expr::ZERO;
            for k in 0..LIMBS {
                let carry = if k + 1 < LIMBS {
                    let cb = ACC_REG + ACC_TC + 2 * k;
                    b.assert_bool(l[cb]);
                    b.assert_bool(l[cb + 1]);
                    x(l[cb]) + x(l[cb + 1]) * F::TWO
                } else {
                    AB::Expr::ZERO
                };
                b.assert_zero(
                    mult.clone() * x(l[ACC_REG + ACC_BF + k]) + carry_prev
                        - x(l[FEE + FEE_VB + k])
                        - carry.clone() * F::from_u32(1 << LIMB_BITS),
                );
                carry_prev = carry;
            }
        } else {
            let base = c::limbs_u32(FEE_BASE);
            let prio = c::limbs_u32(FEE_PRIORITY);
            for k in 0..LIMBS {
                let tier = AB::Expr::from(F::from_u32(base[k]))
                    + x(t) * (F::from_u32(prio[k]) - F::from_u32(base[k]));
                b.assert_zero(x(l[FEE + FEE_VB + k]) - (one.clone() - x(ad)) * tier);
            }
        }
        // nf₀ ≠ nf₁: Σ rₑ·(nf₀ₑ − nf₁ₑ) = 1.
        let mut dot = AB::Expr::ZERO;
        for e in 0..DIGEST {
            dot += x(l[NEQ + e]) * (src(Src::Pub(pub_nf(0)), e) - src(Src::Pub(pub_nf(1)), e));
        }
        b.assert_eq(dot, one.clone());
        // Each output value v is 0 (z = 1) or v = MIN_PACKAGE_DEPOSIT + δ (z = 0), limb by limb
        // with 1-bit carries and a top carry of 0. Every term is below 2^18, so each limb equation
        // holds over the integers; v and δ are range-checked, so v ≥ MIN_PACKAGE_DEPOSIT.
        let min = c::limbs_u32(MIN_PACKAGE_DEPOSIT);
        for j in 0..2 {
            let o = output(j);
            let z = l[o + OUT_Z];
            b.assert_bool(z);
            let mut carry_prev = AB::Expr::ZERO;
            for k in 0..LIMBS {
                let v = x(l[o + OUT_VU + k]);
                b.assert_zero(x(z) * v.clone());
                let carry = if k + 1 < LIMBS {
                    b.assert_bool(l[o + OUT_MC + k]);
                    x(l[o + OUT_MC + k])
                } else {
                    AB::Expr::ZERO
                };
                b.assert_zero(
                    (one.clone() - x(z))
                        * (x(l[o + OUT_MD + k]) + F::from_u32(min[k]) + carry_prev
                            - v
                            - carry.clone() * F::from_u32(1 << LIMB_BITS)),
                );
                carry_prev = carry;
            }
        }
        // Accumulator mode: a real input's unlock height u is at most the anchor height h:
        // h = u + δ limb by limb with 1-bit carries and a top carry of 0; δ is range-checked.
        if self.acc {
            for i in 0..2 {
                let real = one.clone() - x(l[input(i) + IN_D]);
                let d = acc_ud(i);
                let mut carry_prev = AB::Expr::ZERO;
                for k in 0..LIMBS {
                    let carry = if k + 1 < LIMBS {
                        b.assert_bool(l[d + LIMBS + k]);
                        x(l[d + LIMBS + k])
                    } else {
                        AB::Expr::ZERO
                    };
                    b.assert_zero(
                        real.clone()
                            * (x(l[input(i) + IN_VU + LIMBS + k]) + x(l[d + k]) + carry_prev
                                - x(l[ACC_REG + ACC_HB + k])
                                - carry.clone() * F::from_u32(1 << LIMB_BITS)),
                    );
                    carry_prev = carry;
                }
            }
        }
        // Value conservation: v₀ + v₁ = o₀ + o₁ + fee, limb by limb with carries; the top carry is 0.
        let mut carry_prev = AB::Expr::ZERO;
        for k in 0..LIMBS {
            let carry = if k + 1 < LIMBS {
                let cb = FEE + FEE_CARRY + 3 * k;
                for q in 0..3 {
                    b.assert_bool(l[cb + q]);
                }
                x(l[cb]) + x(l[cb + 1]) * F::TWO + x(l[cb + 2]) * F::from_u32(4) - F::from_u32(3)
            } else {
                AB::Expr::ZERO
            };
            let lhs = x(l[input(0) + IN_VU + k]) + x(l[input(1) + IN_VU + k]) + carry_prev;
            let rhs = x(l[output(0) + OUT_VU + k])
                + x(l[output(1) + OUT_VU + k])
                + x(l[FEE + FEE_VB + k]);
            b.assert_zero(lhs - rhs - carry.clone() * F::from_u32(1 << LIMB_BITS));
            carry_prev = carry;
        }
    }
}
