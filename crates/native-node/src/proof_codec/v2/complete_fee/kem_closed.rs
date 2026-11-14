//! Private synthetic ML-KEM encapsulation relation, not the payment AEAD.
//! All witness buses stay inside one AIR; the public lookup terminal is zero.
use super::{
    kem_reference,
    ntt_closed::{
        self, HEIGHT, LANE_WIDTH, NttClosedAir, RESIDUE_WIDTH, eval_residue, write_residue,
    },
    prefix::{self, COEFF, SHA_WIDTH},
};
use ::native::multi_asset::F;
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

const Q: u32 = 3329;
const PRODUCT_BOUND: u32 = 19968;
const COINS_OFFSET: usize = ntt_closed::WIDTH;
const PRODUCT_OFFSET: usize = COINS_OFFSET + 16;
const PRODUCT_WIDTH: usize = 6 + 2 * RESIDUE_WIDTH + 2 * 31;
const INVERSE_OFFSET: usize = PRODUCT_OFFSET + PRODUCT_WIDTH;
const INVERSE_LANES: usize = 7;
const SCALE_OFFSET: usize = INVERSE_OFFSET + INVERSE_LANES * LANE_WIDTH;
const SCALE_WIDTH: usize = 3 * RESIDUE_WIDTH;
const COMPRESS_OFFSET: usize = SCALE_OFFSET + 2 * SCALE_WIDTH;
const COMPRESS_WIDTH: usize = 2 + 2 * RESIDUE_WIDTH + 2 + 1 + 16;
pub(crate) const WIDTH: usize = COMPRESS_OFFSET + 2 * COMPRESS_WIDTH;
const PRODUCT_PRE: usize = ntt_closed::PRE_WIDTH;
const INVERSE_PRE: usize = PRODUCT_PRE + 11;
const SCALE_PRE: usize = INVERSE_PRE + INVERSE_LANES * 6;
const COMPRESS_PRE: usize = SCALE_PRE + 4;
pub(crate) const PRE_WIDTH: usize = COMPRESS_PRE + 2 * 21;

#[derive(Clone)]
pub struct KemClosedAir {
    pub public_key: [u8; 1184],
    pub ciphertext: [u8; 1088],
}

#[derive(Clone, Copy)]
struct InverseEvent {
    poly: usize,
    stage: usize,
    left: usize,
    right: usize,
    zeta: u16,
}

fn pow17(exponent: usize) -> u16 {
    (0..exponent).fold(1u32, |a, _| a * 17 % Q) as u16
}
fn inverse_schedule() -> Vec<InverseEvent> {
    let mut events = Vec::with_capacity(3584);
    for poly in 0..4 {
        let mut k = 127;
        for stage in 0..7 {
            let len = 2 << stage;
            for start in (0..256).step_by(len * 2) {
                let zeta = pow17((k as u8).reverse_bits() as usize >> 1);
                k -= 1;
                for left in start..start + len {
                    events.push(InverseEvent {
                        poly,
                        stage,
                        left,
                        right: left + len,
                        zeta,
                    });
                }
            }
        }
    }
    assert_eq!(events.len(), 3584);
    events
}
fn compressed_value(ciphertext: &[u8; 1088], poly: usize, index: usize) -> u16 {
    let (offset, bits) = if poly < 3 { (poly * 320, 10) } else { (960, 4) };
    (0..bits).fold(0, |value, bit| {
        value
            | ((((ciphertext[offset + (index * bits + bit) / 8] >> ((index * bits + bit) % 8)) & 1)
                as u16)
                << bit)
    })
}
impl KemClosedAir {
    pub fn public_key_hash(&self) -> [u8; 32] {
        let mut hash = [0; 32];
        libcrux_sha3::portable::sha256(&mut hash, &self.public_key);
        hash
    }
}
impl BaseAir<F> for KemClosedAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        16
    }
    fn preprocessed_width(&self) -> usize {
        PRE_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let base = NttClosedAir.preprocessed_trace().unwrap();
        let (matrix, public_t) = kem_reference::public_polynomials(&self.public_key);
        let mut values = F::zero_vec(HEIGHT * PRE_WIDTH);
        for row in 0..HEIGHT {
            values[row * PRE_WIDTH..row * PRE_WIDTH + ntt_closed::PRE_WIDTH].copy_from_slice(
                &base.values[row * ntt_closed::PRE_WIDTH..(row + 1) * ntt_closed::PRE_WIDTH],
            );
            let poly = row / 128;
            let pair = row % 128;
            let gamma = pow17(2 * ((pair as u8).reverse_bits() as usize >> 1) + 1) as u32;
            let offset = row * PRE_WIDTH + PRODUCT_PRE;
            values[offset] = F::from_usize(poly);
            values[offset + 1] = F::from_usize(pair * 2);
            for j in 0..3 {
                let public = if poly < 3 {
                    &matrix[poly][j]
                } else {
                    &public_t[j]
                };
                values[offset + 2 + j * 3] = F::from_u16(public[pair * 2]);
                values[offset + 3 + j * 3] = F::from_u16(public[pair * 2 + 1]);
                values[offset + 4 + j * 3] = F::from_u32(gamma * public[pair * 2 + 1] as u32 % Q);
            }
            for lane in 0..2 {
                let index = row * 2 + lane;
                let poly = index / 256;
                let coefficient = index % 256;
                let offset = row * PRE_WIDTH + SCALE_PRE + lane * 2;
                values[offset] = F::from_usize(poly);
                values[offset + 1] = F::from_usize(coefficient);
                let offset = row * PRE_WIDTH + COMPRESS_PRE + lane * 21;
                values[offset] = F::from_usize(poly);
                values[offset + 1] = F::from_usize(coefficient);
                values[offset + 2] =
                    F::from_u16(compressed_value(&self.ciphertext, poly, coefficient));
                values[offset + 3] = F::from_bool(poly == 3);
                values[offset + 4] = F::from_usize(coefficient / 16);
                if poly == 3 {
                    values[offset + 5 + coefficient % 16] = F::ONE;
                }
            }
        }
        for (index, event) in inverse_schedule().into_iter().enumerate() {
            let offset =
                index / INVERSE_LANES * PRE_WIDTH + INVERSE_PRE + index % INVERSE_LANES * 6;
            for (column, value) in [
                1,
                event.poly,
                event.stage,
                event.left,
                event.right,
                event.zeta as usize,
            ]
            .into_iter()
            .enumerate()
            {
                values[offset + column] = F::from_usize(value);
            }
        }
        Some(RowMajorMatrix::new(values, PRE_WIDTH))
    }
}

fn eval_bounded_product_quotient<AB: AirBuilder<F = F>>(builder: &mut AB, columns: &[AB::Var]) {
    let mut value = AB::Expr::ZERO;
    let mut complement = AB::Expr::ZERO;
    for bit in 0..15 {
        builder.assert_bool(columns[1 + bit]);
        builder.assert_bool(columns[16 + bit]);
        value += AB::Expr::from(columns[1 + bit]) * F::from_u32(1 << bit);
        complement += AB::Expr::from(columns[16 + bit]) * F::from_u32(1 << bit);
    }
    builder.assert_eq(value, columns[0]);
    builder.assert_eq(
        AB::Expr::from(columns[0]) + complement,
        F::from_u32(PRODUCT_BOUND),
    );
}

impl<AB> Air<AB> for KemClosedAir
where
    AB: AirBuilder<F = F> + PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        NttClosedAir.eval(builder);
        let main = builder.main();
        let pre = builder.preprocessed().clone();
        let local = main.current_slice();
        let next = main.next_slice();
        let p = pre.current_slice();
        let x = |value: AB::Var| -> AB::Expr { value.into() };
        let k: &KeccakCols<AB::Var> = local[..NUM_KECCAK_COLS].borrow();
        for word in 0..16 {
            builder
                .when_transition()
                .assert_eq(local[COINS_OFFSET + word], next[COINS_OFFSET + word]);
            builder
                .assert_zero((x(local[COINS_OFFSET + word]) - x(prefix::input(k, word))) * x(p[0]));
            builder.push_interaction(
                "kem-message-word",
                [AB::Expr::from_usize(word), x(local[COINS_OFFSET + word])],
                Count::bounded(-x(p[0]) * F::from_u32(16), 16),
            );
        }
        // The old forward-NTT sink remains constrained, then supplies one
        // copy to each of the four public-key polynomial products.
        for lane in 0..2 {
            let fixed = &p[ntt_closed::SINK_PRE + lane * 3..];
            builder.push_interaction(
                "kem-forward-output",
                [
                    x(fixed[1]),
                    x(fixed[2]),
                    x(local[ntt_closed::SINK_OFFSET + lane]),
                ],
                Count::bounded(-x(fixed[0]) * F::from_u32(4), 4),
            );
        }
        // Every e1/e2 coefficient comes from the same constrained PRF/CBD.
        for coefficient in 0..4 {
            builder.push_interaction(
                "kem-error",
                [
                    x(p[17]) - F::from_u32(3),
                    x(p[18]) * F::from_u32(4) + F::from_usize(coefficient),
                    x(local[SHA_WIDTH + COEFF + coefficient]),
                ],
                Count::bounded(x(p[19]) - x(p[16]), 1),
            );
        }
        let product = &local[PRODUCT_OFFSET..];
        let fixed = &p[PRODUCT_PRE..];
        for j in 0..3 {
            for side in 0..2 {
                builder.push_interaction(
                    "kem-forward-output",
                    [
                        AB::Expr::from_usize(j),
                        x(fixed[1]) + F::from_usize(side),
                        x(product[j * 2 + side]),
                    ],
                    Count::bounded(AB::Expr::ONE, 1),
                );
            }
        }
        for side in 0..2 {
            eval_residue(builder, &product[6 + side * RESIDUE_WIDTH..]);
            eval_bounded_product_quotient(builder, &product[6 + 2 * RESIDUE_WIDTH + side * 31..]);
            let mut sum = AB::Expr::ZERO;
            for j in 0..3 {
                let y0 = x(product[j * 2]);
                let y1 = x(product[j * 2 + 1]);
                sum += if side == 0 {
                    x(fixed[2 + j * 3]) * y0 + x(fixed[4 + j * 3]) * y1
                } else {
                    x(fixed[3 + j * 3]) * y0 + x(fixed[2 + j * 3]) * y1
                };
            }
            builder.assert_eq(
                sum,
                x(product[6 + side * RESIDUE_WIDTH])
                    + x(product[6 + 2 * RESIDUE_WIDTH + side * 31]) * F::from_u32(Q),
            );
            builder.push_interaction(
                "kem-inverse-stage",
                [
                    x(fixed[0]),
                    AB::Expr::ZERO,
                    x(fixed[1]) + F::from_usize(side),
                    x(product[6 + side * RESIDUE_WIDTH]),
                ],
                Count::bounded(-AB::Expr::ONE, 1),
            );
        }
        for lane in 0..INVERSE_LANES {
            let columns = &local[INVERSE_OFFSET + lane * LANE_WIDTH..];
            let fixed = &p[INVERSE_PRE + lane * 6..];
            for residue in 0..6 {
                eval_residue(builder, &columns[residue * RESIDUE_WIDTH..]);
            }
            let [a, b, d, u, v, quotient] = core::array::from_fn(|i| x(columns[i * RESIDUE_WIDTH]));
            let carry = x(columns[6 * RESIDUE_WIDTH]);
            let borrow = x(columns[6 * RESIDUE_WIDTH + 1]);
            builder.assert_bool(columns[6 * RESIDUE_WIDTH]);
            builder.assert_bool(columns[6 * RESIDUE_WIDTH + 1]);
            builder.assert_eq(a.clone() + b.clone(), u.clone() + carry * F::from_u32(Q));
            builder.assert_eq(b.clone() - a.clone() + borrow * F::from_u32(Q), d.clone());
            builder.assert_eq(x(fixed[5]) * d, v.clone() + quotient * F::from_u32(Q));
            for (index, value) in [(fixed[3], a), (fixed[4], b)] {
                builder.push_interaction(
                    "kem-inverse-stage",
                    [x(fixed[1]), x(fixed[2]), x(index), value],
                    Count::bounded(x(fixed[0]), 1),
                );
            }
            for (index, value) in [(fixed[3], u), (fixed[4], v)] {
                builder.push_interaction(
                    "kem-inverse-stage",
                    [x(fixed[1]), x(fixed[2]) + AB::Expr::ONE, x(index), value],
                    Count::bounded(-x(fixed[0]), 1),
                );
            }
        }
        for lane in 0..2 {
            let columns = &local[SCALE_OFFSET + lane * SCALE_WIDTH..];
            let fixed = &p[SCALE_PRE + lane * 2..];
            for residue in 0..3 {
                eval_residue(builder, &columns[residue * RESIDUE_WIDTH..]);
            }
            builder.assert_eq(
                x(columns[0]) * F::from_u32(3303),
                x(columns[RESIDUE_WIDTH]) + x(columns[2 * RESIDUE_WIDTH]) * F::from_u32(Q),
            );
            builder.push_interaction(
                "kem-inverse-stage",
                [
                    x(fixed[0]),
                    AB::Expr::from_u32(7),
                    x(fixed[1]),
                    x(columns[0]),
                ],
                Count::bounded(AB::Expr::ONE, 1),
            );
            builder.push_interaction(
                "kem-scaled",
                [x(fixed[0]), x(fixed[1]), x(columns[RESIDUE_WIDTH])],
                Count::bounded(-AB::Expr::ONE, 1),
            );
        }
        for lane in 0..2 {
            let columns = &local[COMPRESS_OFFSET + lane * COMPRESS_WIDTH..];
            let fixed = &p[COMPRESS_PRE + lane * 21..];
            eval_residue(builder, &columns[2..]);
            eval_residue(builder, &columns[2 + RESIDUE_WIDTH..]);
            let carry_offset = 2 + 2 * RESIDUE_WIDTH;
            builder.assert_bool(columns[carry_offset]);
            builder.assert_bool(columns[carry_offset + 1]);
            builder.assert_zero(x(columns[carry_offset]) * x(columns[carry_offset + 1]));
            let carry = x(columns[carry_offset]) + x(columns[carry_offset + 1]) * F::from_u32(2);
            builder.assert_bool(columns[carry_offset + 2]);
            let wrap = x(columns[carry_offset + 2]);
            let mut word = AB::Expr::ZERO;
            let mut bit = AB::Expr::ZERO;
            for i in 0..16 {
                builder.assert_bool(columns[carry_offset + 3 + i]);
                word += x(columns[carry_offset + 3 + i]) * F::from_u32(1 << i);
                bit += x(columns[carry_offset + 3 + i]) * x(fixed[5 + i]);
            }
            builder.assert_eq(
                x(columns[0]) + x(columns[1]) + bit * F::from_u32(1665),
                x(columns[2]) + carry * F::from_u32(Q),
            );
            let scale = AB::Expr::from_u32(1024) - x(fixed[3]) * F::from_u32(1008);
            builder.assert_eq(
                x(columns[2]) * scale.clone() + F::from_u32(1664),
                (x(fixed[2]) + wrap * scale) * F::from_u32(Q) + x(columns[2 + RESIDUE_WIDTH]),
            );
            builder.push_interaction(
                "kem-scaled",
                [x(fixed[0]), x(fixed[1]), x(columns[0])],
                Count::bounded(AB::Expr::ONE, 1),
            );
            builder.push_interaction(
                "kem-error",
                [x(fixed[0]), x(fixed[1]), x(columns[1])],
                Count::bounded(AB::Expr::ONE, 1),
            );
            builder.push_interaction(
                "kem-message-word",
                [x(fixed[4]), word],
                Count::bounded(x(fixed[3]), 1),
            );
        }
    }
}

fn write_product_quotient(columns: &mut [F], value: u32) {
    assert!(value <= PRODUCT_BOUND);
    columns[0] = F::from_u32(value);
    for bit in 0..15 {
        columns[1 + bit] = F::from_bool(value >> bit & 1 != 0);
        columns[16 + bit] = F::from_bool((PRODUCT_BOUND - value) >> bit & 1 != 0);
    }
}

pub fn generate(public_key: &[u8; 1184], coins: [u8; 32]) -> (KemClosedAir, RowMajorMatrix<F>) {
    let (ciphertext, _) = kem_reference::encapsulate_reference(public_key, coins);
    let air = KemClosedAir {
        public_key: *public_key,
        ciphertext,
    };
    let (base, cbd) = ntt_closed::generate(coins, air.public_key_hash());
    let (matrix, public_t) = kem_reference::public_polynomials(public_key);
    let forward: [[u16; 256]; 3] = core::array::from_fn(|poly| {
        core::array::from_fn(|i| ntt_closed::output_coefficient(&base, poly, i))
    });
    let mut products = [[0u16; 256]; 4];
    let mut values = F::zero_vec(HEIGHT * WIDTH);
    for row in 0..HEIGHT {
        values[row * WIDTH..row * WIDTH + ntt_closed::WIDTH]
            .copy_from_slice(&base.values[row * ntt_closed::WIDTH..(row + 1) * ntt_closed::WIDTH]);
        for word in 0..16 {
            values[row * WIDTH + COINS_OFFSET + word] =
                F::from_u16(u16::from_le_bytes([coins[word * 2], coins[word * 2 + 1]]));
        }
        let poly = row / 128;
        let pair = row % 128;
        let gamma = pow17(2 * ((pair as u8).reverse_bits() as usize >> 1) + 1) as u32;
        let offset = row * WIDTH + PRODUCT_OFFSET;
        let mut sums = [0u32; 2];
        for j in 0..3 {
            let y0 = forward[j][pair * 2];
            let y1 = forward[j][pair * 2 + 1];
            values[offset + j * 2] = F::from_u16(y0);
            values[offset + j * 2 + 1] = F::from_u16(y1);
            let public = if poly < 3 {
                &matrix[poly][j]
            } else {
                &public_t[j]
            };
            let a0 = public[pair * 2] as u32;
            let a1 = public[pair * 2 + 1] as u32;
            sums[0] += a0 * y0 as u32 + (gamma * a1 % Q) * y1 as u32;
            sums[1] += a1 * y0 as u32 + a0 * y1 as u32;
        }
        for side in 0..2 {
            products[poly][pair * 2 + side] = (sums[side] % Q) as u16;
            write_residue(
                &mut values[offset + 6 + side * RESIDUE_WIDTH..],
                products[poly][pair * 2 + side],
            );
            write_product_quotient(
                &mut values[offset + 6 + 2 * RESIDUE_WIDTH + side * 31..],
                sums[side] / Q,
            );
        }
    }
    for (index, event) in inverse_schedule().into_iter().enumerate() {
        let a = products[event.poly][event.left];
        let b = products[event.poly][event.right];
        let d = (b as i32 - a as i32).rem_euclid(Q as i32) as u16;
        let product = event.zeta as u32 * d as u32;
        let u = ((a as u32 + b as u32) % Q) as u16;
        let v = (product % Q) as u16;
        let offset =
            index / INVERSE_LANES * WIDTH + INVERSE_OFFSET + index % INVERSE_LANES * LANE_WIDTH;
        for (residue, value) in [a, b, d, u, v, (product / Q) as u16]
            .into_iter()
            .enumerate()
        {
            write_residue(&mut values[offset + residue * RESIDUE_WIDTH..], value);
        }
        values[offset + 6 * RESIDUE_WIDTH] = F::from_bool(a as u32 + b as u32 >= Q);
        values[offset + 6 * RESIDUE_WIDTH + 1] = F::from_bool(b < a);
        products[event.poly][event.left] = u;
        products[event.poly][event.right] = v;
    }
    for index in 0..1024 {
        let poly = index / 256;
        let coefficient = index % 256;
        let row = index / 2;
        let lane = index % 2;
        let input = products[poly][coefficient];
        let product = input as u32 * 3303;
        let scaled = (product % Q) as u16;
        let offset = row * WIDTH + SCALE_OFFSET + lane * SCALE_WIDTH;
        for (residue, value) in [input, scaled, (product / Q) as u16]
            .into_iter()
            .enumerate()
        {
            write_residue(&mut values[offset + residue * RESIDUE_WIDTH..], value);
        }
        let error = cbd[poly + 3][coefficient];
        let bit = if poly == 3 {
            (coins[coefficient / 8] >> (coefficient % 8)) & 1
        } else {
            0
        };
        let sum = scaled as u32 + error as u32 + bit as u32 * 1665;
        let total = sum % Q;
        let carry = sum / Q;
        let bits = if poly < 3 { 10 } else { 4 };
        let numerator = (total << bits) + 1664;
        let quotient = numerator / Q;
        let remainder = numerator % Q;
        let offset = row * WIDTH + COMPRESS_OFFSET + lane * COMPRESS_WIDTH;
        values[offset] = F::from_u16(scaled);
        values[offset + 1] = F::from_u16(error);
        write_residue(&mut values[offset + 2..], total as u16);
        write_residue(&mut values[offset + 2 + RESIDUE_WIDTH..], remainder as u16);
        let carry_offset = offset + 2 + 2 * RESIDUE_WIDTH;
        values[carry_offset] = F::from_bool(carry & 1 != 0);
        values[carry_offset + 1] = F::from_bool(carry & 2 != 0);
        values[carry_offset + 2] = F::from_bool(quotient >= 1 << bits);
        if poly == 3 {
            let word =
                u16::from_le_bytes([coins[coefficient / 16 * 2], coins[coefficient / 16 * 2 + 1]]);
            for bit in 0..16 {
                values[carry_offset + 3 + bit] = F::from_bool(word >> bit & 1 != 0);
            }
        }
    }
    (air, RowMajorMatrix::new(values, WIDTH))
}
