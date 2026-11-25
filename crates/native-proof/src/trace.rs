//! Main trace generation from a slot witness. Permutation inputs are computed row by row
//! according to the row roles from `schedule()`, the same schedule the AIR uses.

use crate::common::{
    AccWitness, DIGEST, Digest, F, Hasher, LIMB_BITS, LIMBS, MIN_PACKAGE_DEPOSIT, RATE,
    SlotWitness, WIDTH, anchor_block, digest_of, fee_block, limbs, limbs_u32, pack_dct,
};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::generate_trace_rows;

use crate::air::*;

/// Returns (main trace, public inputs). The witness is not checked: an invalid witness
/// yields a trace that violates the constraints.
pub fn generate(air: &SlotAir, w: &SlotWitness) -> (RowMajorMatrix<F>, Vec<F>) {
    assert!(!air.pub_in_regs());
    build(air, w, None, Vec::new(), None)
}

/// Chain mode: returns (main trace, [s_in, s_out, 1]), where s_out = H(s_in, slot public values).
pub fn generate_chain(
    air: &SlotAir,
    w: &SlotWitness,
    s_in: &Digest,
) -> (RowMajorMatrix<F>, Vec<F>) {
    assert!(air.chain);
    let h = Hasher::new();
    let s_out = w.public_inputs(&h).chain_step(&h, s_in);
    let mut stmt = s_in.to_vec();
    stmt.extend_from_slice(&s_out);
    stmt.push(F::ONE);
    build(air, w, None, stmt, None)
}

/// Accumulator mode: returns (main trace, [E, fee limbs, 1, 𝒜 entry]). The entry's 𝒜 path is
/// not part of the leaf; the level-1 merge node checks it.
pub fn generate_acc(air: &SlotAir, w: &AccWitness) -> (RowMajorMatrix<F>, Vec<F>) {
    assert!(air.acc);
    build(air, &w.slot, Some(w), acc_stmt(w), None)
}

/// Native transaction mode: the fee limbs remain private and only the
/// randomized fee commitment is public in the statement.
pub fn generate_acc_confidential(air: &SlotAir, w: &AccWitness) -> (RowMajorMatrix<F>, Vec<F>) {
    assert!(air.acc && air.confidential_fee);
    build(air, &w.slot, Some(w), acc_stmt_confidential(w), None)
}

fn acc_stmt(w: &AccWitness) -> Vec<F> {
    let h = Hasher::new();
    let mut stmt = w.set_element(&h).to_vec();
    stmt.extend_from_slice(&limbs(w.slot.fee));
    stmt.push(F::ONE);
    stmt.extend_from_slice(&w.anchor_entry(&h));
    stmt
}

fn acc_stmt_confidential(w: &AccWitness) -> Vec<F> {
    let h = Hasher::new();
    let mut stmt = w.set_element(&h).to_vec();
    stmt.extend_from_slice(&w.slot.public_inputs(&h).fee_commit);
    stmt.push(F::ONE);
    stmt.extend_from_slice(&w.anchor_entry(&h));
    stmt
}

/// An edit of the register columns, indexed from REG.
type Edit<'a> = &'a dyn Fn(&mut [F]);

/// Test hook (plain or accumulator mode): `edit` changes the register columns (indexed from
/// REG) once they are filled. Carries and δ limbs are derived from the edited registers, and
/// every hashed output (owner, ρ, nf, cm, fee commitment, E, 𝒜 entry, and the anchor as the root
/// of the first real input) is rebound to what the edited trace computes. The trace then
/// satisfies every constraint the edit does not itself break.
#[cfg(test)]
pub(crate) fn generate_edited(
    air: &SlotAir,
    w: &SlotWitness,
    acc: Option<&AccWitness>,
    edit: Edit,
) -> (RowMajorMatrix<F>, Vec<F>) {
    assert!(!air.chain && air.acc == acc.is_some());
    build(air, w, acc, acc.map_or(Vec::new(), acc_stmt), Some(edit))
}

fn put(regs: &mut [F], col: usize, vals: &[F]) {
    regs[col - REG..col - REG + vals.len()].copy_from_slice(vals);
}

/// The four limbs at `col` as integers (canonical representatives).
fn limbs_at(regs: &[F], col: usize) -> [i64; LIMBS] {
    core::array::from_fn(|k| i64::from(regs[col - REG + k].as_canonical_u32()))
}

/// Σ limbₖ·2^(16k) mod 2^64.
fn from_limbs(l: [i64; LIMBS]) -> u64 {
    l.iter().rev().fold(0u64, |a, &x| {
        a.wrapping_shl(LIMB_BITS as u32).wrapping_add(x as u64)
    })
}

fn bits(x: u32, n: usize) -> Vec<F> {
    (0..n).map(|q| F::from_u32((x >> q) & 1)).collect()
}

/// a + δ = b limb by limb: writes δ = b − a (wrapping) and the three carries
/// cₖ = (aₖ + δₖ + cₖ₋₁ − bₖ) / 2¹⁶ as single bits. When a > b the wrap leaves a top carry the
/// constraints reject.
fn put_difference(regs: &mut [F], col: usize, a: [i64; LIMBS], b: [i64; LIMBS]) {
    let d = limbs_u32(from_limbs(b).wrapping_sub(from_limbs(a)));
    let mut carry = 0i64;
    for k in 0..LIMBS {
        put(regs, col + k, &[F::from_u32(d[k])]);
        if k + 1 < LIMBS {
            carry = (a[k] + i64::from(d[k]) + carry - b[k]) >> LIMB_BITS;
            put(regs, col + LIMBS + k, &[F::from_bool(carry != 0)]);
        }
    }
}

fn get(s: Src, regs: &[F], pub_vec: &[F], stmt: &[F]) -> [F; RATE] {
    let (v, o) = match s {
        Src::Reg(o) => (regs, o - REG),
        Src::Pub(o) => (pub_vec, o),
        Src::Stmt(o) => (stmt, o),
        Src::Zero => return [F::ZERO; RATE],
    };
    core::array::from_fn(|e| v[o + e])
}

fn build(
    air: &SlotAir,
    w: &SlotWitness,
    acc: Option<&AccWitness>,
    mut stmt: Vec<F>,
    edit: Option<Edit>,
) -> (RowMajorMatrix<F>, Vec<F>) {
    let height = air.height;
    let h = Hasher::new();
    let pis = w.public_inputs(&h);
    let mut pub_vec = pis.to_vec();
    let width = air.main_width();

    let mut regs = vec![F::ZERO; width - REG];
    for (i, inp) in w.inputs.iter().enumerate() {
        let b = input(i);
        put(&mut regs, b + IN_NK, &inp.nk);
        put(&mut regs, b + IN_RHO, &inp.rho);
        put(&mut regs, b + IN_RSEED, &inp.rseed);
        put(&mut regs, b + IN_OWNER, &h.owner(&inp.nk));
        put(&mut regs, b + IN_VU, &limbs(inp.value));
        put(&mut regs, b + IN_VU + LIMBS, &limbs(inp.unlock_height));
        put(&mut regs, b + IN_D, &[F::from_bool(inp.dummy)]);
    }
    for (j, out) in w.outputs.iter().enumerate() {
        let b = output(j);
        put(&mut regs, b + OUT_OWNER, &out.owner);
        put(&mut regs, b + OUT_VU, &limbs(out.value));
        put(&mut regs, b + OUT_VU + LIMBS, &limbs(out.unlock_height));
        put(&mut regs, b + OUT_RSEED, &out.rseed);
        put(
            &mut regs,
            b + OUT_RHO,
            &h.output_rho(&pis.nf[0], &pis.nf[1], j),
        );
    }
    put(&mut regs, FEE + FEE_VB, &fee_block(w.fee, &w.fee_blind));
    put(&mut regs, FEE + FEE_T, &[F::from_bool(w.fee_is_priority)]);
    let ad = w.inputs[0].dummy && w.inputs[1].dummy;
    put(&mut regs, FEE + FEE_AD, &[F::from_bool(ad)]);
    if let Some(a) = acc {
        put(
            &mut regs,
            ACC_REG + ACC_HB,
            &anchor_block(a.anchor_height, a.base_fee),
        );
        put(&mut regs, ACC_REG + ACC_DCT, &pack_dct(&a.d_ct));
    }
    if let Some(edit) = edit {
        edit(&mut regs);
    }

    // Everything below is derived from the registers.
    let fl = limbs_at(&regs, FEE + FEE_VB);
    if acc.is_some() {
        // Tier carry: c_k = (mult·bf_k + c_{k−1} − fee_k) / 2¹⁶, stored as 2 bits.
        let mult = if regs[FEE + FEE_AD - REG] == F::ONE {
            0
        } else if regs[FEE + FEE_T - REG] == F::ONE {
            4
        } else {
            1
        };
        let bf = limbs_at(&regs, ACC_REG + ACC_BF);
        let mut carry = 0i64;
        for k in 0..LIMBS - 1 {
            carry = (mult * bf[k] + carry - fl[k]) >> LIMB_BITS;
            put(
                &mut regs,
                ACC_REG + ACC_TC + 2 * k,
                &bits(carry.clamp(0, 3) as u32, 2),
            );
        }
        // Real inputs: anchor height = unlock + δ.
        let hl = limbs_at(&regs, ACC_REG + ACC_HB);
        for i in 0..2 {
            if regs[input(i) + IN_D - REG] == F::ZERO {
                let u = limbs_at(&regs, input(i) + IN_VU + LIMBS);
                put_difference(&mut regs, acc_ud(i), u, hl);
            }
        }
    }
    // Nonzero outputs: value = MIN_PACKAGE_DEPOSIT + δ.
    let min = limbs_u32(MIN_PACKAGE_DEPOSIT).map(i64::from);
    for j in 0..2 {
        let v = limbs_at(&regs, output(j) + OUT_VU);
        let zero = v.iter().all(|&x| x == 0);
        put(&mut regs, output(j) + OUT_Z, &[F::from_bool(zero)]);
        if !zero {
            put_difference(&mut regs, output(j) + OUT_MD, min, v);
        }
    }
    // Carry: c_k = ⌊(v₀ₖ + v₁ₖ + c_{k−1} − o₀ₖ − o₁ₖ − feeₖ) / 2¹⁶⌋, stored as the 3 bits of c + 3.
    let (v0, v1) = (
        limbs_at(&regs, input(0) + IN_VU),
        limbs_at(&regs, input(1) + IN_VU),
    );
    let (o0, o1) = (
        limbs_at(&regs, output(0) + OUT_VU),
        limbs_at(&regs, output(1) + OUT_VU),
    );
    let mut carry = 0i64;
    for k in 0..LIMBS - 1 {
        carry = (v0[k] + v1[k] + carry - o0[k] - o1[k] - fl[k]) >> LIMB_BITS;
        put(
            &mut regs,
            FEE + FEE_CARRY + 3 * k,
            &bits((carry + 3).clamp(0, 7) as u32, 3),
        );
    }

    let rebind = edit.is_some();
    let first_real = w.inputs.iter().position(|i| !i.dummy);
    let mut perm_inputs = Vec::with_capacity(height);
    let mut merkle_bits = vec![F::ZERO; height];
    let mut prev_out = [F::ZERO; WIDTH];
    for (r, spec) in air.rows.iter().enumerate() {
        let inp = match spec.kind {
            Kind::Pad => [F::ZERO; WIDTH],
            Kind::First { tag, len, absorb } => {
                Hasher::first_input(tag, len, &get(absorb, &regs, &pub_vec, &stmt))
            }
            Kind::Cont { absorb } => {
                let mut s = prev_out;
                s[..RATE].copy_from_slice(&get(absorb, &regs, &pub_vec, &stmt));
                s
            }
            Kind::Merkle { input, level } => {
                let (sib, is_right) = w.inputs[input].path[level];
                let cur = digest_of(&prev_out);
                merkle_bits[r] = F::from_bool(is_right);
                if is_right {
                    Hasher::compress_input(&sib, &cur)
                } else {
                    Hasher::compress_input(&cur, &sib)
                }
            }
        };
        prev_out = h.permute(inp);
        perm_inputs.push(inp);
        if rebind {
            let d = digest_of(&prev_out);
            match spec.out {
                Some(Src::Reg(o)) => put(&mut regs, o, &d),
                Some(Src::Pub(o)) => pub_vec[o..o + DIGEST].copy_from_slice(&d),
                Some(Src::Stmt(o)) => stmt[o..o + DIGEST].copy_from_slice(&d),
                Some(Src::Zero) | None => {}
            }
            if spec.root.is_some() && spec.root == first_real {
                pub_vec[PUB_ANCHOR..PUB_ANCHOR + DIGEST].copy_from_slice(&d);
            }
        }
    }
    debug_assert_eq!(DIGEST, RATE);
    if air.pub_in_regs() {
        put(&mut regs, CHAIN_REG, &pub_vec);
    }
    // nf₀ ≠ nf₁: the inverse of the first differing element; no solution when they are equal.
    let (nf0, nf1) = (&pub_vec[pub_nf(0)..], &pub_vec[pub_nf(1)..]);
    if let Some(e) = (0..DIGEST).find(|&e| nf0[e] != nf1[e]) {
        put(&mut regs, NEQ + e, &[(nf0[e] - nf1[e]).inverse()]);
    }

    let p2 =
        generate_trace_rows::<F, LinearLayers, WIDTH, 3, 0, 4, 23>(perm_inputs, &p2_constants(), 0);
    let mut values = Vec::with_capacity(height * width);
    for r in 0..height {
        values.extend_from_slice(&p2.values[r * P2..(r + 1) * P2]);
        values.push(merkle_bits[r]);
        let rv = air
            .range
            .get(r)
            .map_or(0, |&col| regs[col - REG].as_canonical_u32());
        values.push(F::from_u32(rv));
        values.extend((0..LIMB_BITS).map(|k| F::from_u32((rv >> k) & 1)));
        values.extend_from_slice(&regs);
    }
    let pis = if air.pub_in_regs() { stmt } else { pub_vec };
    (RowMajorMatrix::new(values, width), pis)
}
