//! Exact radix-2^10 Poly1305 with canonical 130-bit values and bounded carries.
//! Synthetic local relation only; this is not a screened proof profile.
use ::native::multi_asset::F;
use num_bigint::BigUint;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

const HEIGHT: usize = 512;
const CANON_WIDTH: usize = 13 + 130 + 130 + 13;
const A: usize = 13;
const OUT: usize = A + CANON_WIDTH;
pub(crate) const R: usize = OUT + CANON_WIDTH;
pub(crate) const S: usize = R + 130;
const QUOTIENT: usize = S + 128;
const ADD_CARRY: usize = QUOTIENT + 1;
const MULT_CARRY: usize = ADD_CARRY + 24;
const TAG_CARRY: usize = MULT_CARRY + 13 * 18;
pub(crate) const WIDTH: usize = TAG_CARRY + 8;
pub(crate) const PRE_WIDTH: usize = 24;

#[derive(Clone)]
pub struct Poly1305Air {
    pub aad: [u8; 117],
    pub body: [u8; 208],
    pub tag: [u8; 16],
}
fn modulus() -> BigUint {
    (BigUint::from(1u8) << 130usize) - BigUint::from(5u8)
}
fn digits(value: &BigUint) -> [u16; 13] {
    core::array::from_fn(|i| {
        ((value >> (i * 10)) & BigUint::from(1023u16))
            .to_u32_digits()
            .first()
            .copied()
            .unwrap_or(0) as u16
    })
}
fn messages(aad: &[u8; 117], body: &[u8; 208]) -> [BigUint; 22] {
    let mut bytes = [0u8; 352];
    bytes[..117].copy_from_slice(aad);
    bytes[128..336].copy_from_slice(body);
    bytes[336..344].copy_from_slice(&117u64.to_le_bytes());
    bytes[344..].copy_from_slice(&208u64.to_le_bytes());
    core::array::from_fn(|i| {
        BigUint::from_bytes_le(&bytes[i * 16..(i + 1) * 16]) + (BigUint::from(1u8) << 128usize)
    })
}
impl BaseAir<F> for Poly1305Air {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        0
    }
    fn preprocessed_width(&self) -> usize {
        PRE_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut values = F::zero_vec(HEIGHT * PRE_WIDTH);
        for (row, message) in messages(&self.aad, &self.body).iter().enumerate() {
            let off = row * PRE_WIDTH;
            values[off] = F::ONE;
            values[off + 1] = F::from_bool(row == 0);
            values[off + 2] = F::from_bool(row == 21);
            for (i, value) in digits(message).into_iter().enumerate() {
                values[off + 3 + i] = F::from_u16(value);
            }
            if row == 21 {
                for i in 0..8 {
                    values[off + 16 + i] =
                        F::from_u16(u16::from_le_bytes([self.tag[i * 2], self.tag[i * 2 + 1]]));
                }
            }
        }
        Some(RowMajorMatrix::new(values, PRE_WIDTH))
    }
}
fn limb<AB: AirBuilder<F = F>>(bits: &[AB::Var], width: usize) -> AB::Expr {
    (0..width)
        .map(|i| AB::Expr::from(bits[i]) * F::from_u32(1 << i))
        .sum()
}
fn eval_canonical<AB: AirBuilder<F = F>>(b: &mut AB, c: &[AB::Var]) {
    let x = |v: AB::Var| -> AB::Expr { v.into() };
    for value in &c[13..13 + 260] {
        b.assert_bool(*value);
    }
    for i in 0..13 {
        b.assert_eq(c[i], limb::<AB>(&c[13 + i * 10..], 10));
        b.assert_bool(c[273 + i]);
        let previous = if i == 0 {
            AB::Expr::ZERO
        } else {
            x(c[273 + i - 1])
        };
        let expected = AB::Expr::from_u32(if i == 0 { 1018 } else { 1023 });
        b.assert_eq(
            x(c[i]) + limb::<AB>(&c[143 + i * 10..], 10) + previous,
            expected + x(c[273 + i]) * F::from_u32(1024),
        );
    }
    b.assert_zero(c[285]);
}
pub(crate) fn clamped_bit(bit: usize) -> bool {
    bit >= 128
        || [28..32, 60..64, 92..96, 124..128, 32..34, 64..66, 96..98]
            .iter()
            .any(|range| range.contains(&bit))
}
pub(crate) fn eval_at<AB: AirBuilder<F = F>>(b: &mut AB, main_offset: usize, pre_offset: usize) {
    let main = b.main();
    let pre = b.preprocessed().clone();
    let l = &main.current_slice()[main_offset..];
    let n = &main.next_slice()[main_offset..];
    let p = &pre.current_slice()[pre_offset..];
    let x = |v: AB::Var| -> AB::Expr { v.into() };
    eval_canonical(b, &l[A..]);
    eval_canonical(b, &l[OUT..]);
    for bit in 0..130 {
        b.assert_bool(l[R + bit]);
        if clamped_bit(bit) {
            b.assert_zero(l[R + bit]);
        }
        b.when_transition().assert_eq(l[R + bit], n[R + bit]);
    }
    for bit in 0..128 {
        b.assert_bool(l[S + bit]);
        b.when_transition().assert_eq(l[S + bit], n[S + bit]);
    }
    b.assert_bool(l[QUOTIENT]);
    for i in 0..13 {
        b.assert_zero(x(l[i]) * x(p[1]));
        b.when_transition()
            .assert_zero((x(n[i]) - x(l[OUT + i])) * (x(p[0]) - x(p[2])));
        let previous = if i == 0 {
            AB::Expr::ZERO
        } else {
            x(l[ADD_CARRY + (i - 1) * 2]) - x(l[ADD_CARRY + (i - 1) * 2 + 1])
        };
        let next = if i == 12 {
            AB::Expr::ZERO
        } else {
            b.assert_bool(l[ADD_CARRY + i * 2]);
            b.assert_bool(l[ADD_CARRY + i * 2 + 1]);
            b.assert_zero(x(l[ADD_CARRY + i * 2]) * x(l[ADD_CARRY + i * 2 + 1]));
            x(l[ADD_CARRY + i * 2]) - x(l[ADD_CARRY + i * 2 + 1])
        };
        b.assert_eq(
            x(l[i]) + x(p[3 + i]) + previous,
            x(l[A + i])
                + x(l[QUOTIENT]) * F::from_u32(if i == 0 { 1019 } else { 1023 })
                + next * F::from_u32(1024),
        );
        let carry = &l[MULT_CARRY + i * 18..];
        for bit in 0..17 {
            b.assert_bool(carry[1 + bit]);
        }
        b.assert_eq(carry[0], limb::<AB>(&carry[1..], 17));
        let previous = if i == 0 {
            x(l[MULT_CARRY + 12 * 18]) * F::from_u32(5)
        } else {
            x(l[MULT_CARRY + (i - 1) * 18])
        };
        let mut product = AB::Expr::ZERO;
        for j in 0..13 {
            let k = (i + 13 - j) % 13;
            let factor = if j + k == i { 1 } else { 5 };
            product += x(l[A + j]) * limb::<AB>(&l[R + k * 10..], 10) * F::from_u32(factor);
        }
        b.assert_eq(
            product + previous,
            x(l[OUT + i]) + x(carry[0]) * F::from_u32(1024),
        );
    }
    for i in 0..8 {
        b.assert_bool(l[TAG_CARRY + i]);
        let previous = if i == 0 {
            AB::Expr::ZERO
        } else {
            x(l[TAG_CARRY + i - 1])
        };
        b.assert_zero(
            (limb::<AB>(&l[OUT + 13 + i * 16..], 16) + limb::<AB>(&l[S + i * 16..], 16) + previous
                - x(p[16 + i])
                - x(l[TAG_CARRY + i]) * F::from_u32(65536))
                * x(p[2]),
        );
    }
}
impl<AB: AirBuilder<F = F>> Air<AB> for Poly1305Air {
    fn eval(&self, b: &mut AB) {
        eval_at(b, 0, 0);
    }
}

fn write_canonical(c: &mut [F], value: &BigUint) {
    let complement = modulus() - BigUint::from(1u8) - value;
    let a = digits(value);
    let comp = digits(&complement);
    let mut carry = 0u16;
    for i in 0..13 {
        c[i] = F::from_u16(a[i]);
        for bit in 0..10 {
            c[13 + i * 10 + bit] = F::from_bool(a[i] >> bit & 1 != 0);
            c[143 + i * 10 + bit] = F::from_bool(comp[i] >> bit & 1 != 0);
        }
        let total = a[i] + comp[i] + carry;
        carry = total >> 10;
        c[273 + i] = F::from_u16(carry);
    }
    assert_eq!(carry, 0);
}
fn write_carry(c: &mut [F], value: u32) {
    assert!(value < 1 << 17);
    c[0] = F::from_u32(value);
    for bit in 0..17 {
        c[1 + bit] = F::from_bool(value >> bit & 1 != 0);
    }
}
pub fn generate(
    key: [u8; 32],
    aad: [u8; 117],
    body: [u8; 208],
) -> (Poly1305Air, RowMajorMatrix<F>) {
    let p = modulus();
    let mut rbytes: [u8; 16] = key[..16].try_into().unwrap();
    for bit in 0..128 {
        if clamped_bit(bit) {
            rbytes[bit / 8] &= !(1 << (bit % 8));
        }
    }
    let r = BigUint::from_bytes_le(&rbytes);
    let rdigits = digits(&r);
    let s = BigUint::from_bytes_le(&key[16..]);
    let messages = messages(&aad, &body);
    let mut h = BigUint::from(0u8);
    let mut values = F::zero_vec(HEIGHT * WIDTH);
    for (row, message) in messages
        .iter()
        .map(Some)
        .chain(core::iter::repeat_n(None, HEIGHT - messages.len()))
        .enumerate()
    {
        let off = row * WIDTH;
        for bit in 0..130 {
            values[off + R + bit] =
                F::from_bool(bit < 128 && rbytes[bit / 8] >> (bit % 8) & 1 != 0);
        }
        for bit in 0..128 {
            values[off + S + bit] = F::from_bool(key[16 + bit / 8] >> (bit % 8) & 1 != 0);
        }
        let Some(message) = message else {
            write_canonical(&mut values[off + A..], &BigUint::from(0u8));
            write_canonical(&mut values[off + OUT..], &BigUint::from(0u8));
            continue;
        };
        let sum = &h + message;
        let q = &sum / &p;
        let a = &sum % &p;
        let out = (&a * &r) % &p;
        let hd = digits(&h);
        let md = digits(message);
        let ad = digits(&a);
        let od = digits(&out);
        for i in 0..13 {
            values[off + i] = F::from_u16(hd[i]);
        }
        write_canonical(&mut values[off + A..], &a);
        write_canonical(&mut values[off + OUT..], &out);
        let q = q.to_u32_digits().first().copied().unwrap_or(0);
        assert!(q <= 1);
        values[off + QUOTIENT] = F::from_u32(q);
        let mut carry = 0i32;
        for i in 0..13 {
            let delta = hd[i] as i32 + md[i] as i32 + carry
                - ad[i] as i32
                - q as i32 * if i == 0 { 1019 } else { 1023 };
            assert_eq!(delta % 1024, 0);
            carry = delta / 1024;
            assert!((-1..=1).contains(&carry));
            if i < 12 {
                values[off + ADD_CARRY + i * 2] = F::from_bool(carry == 1);
                values[off + ADD_CARRY + i * 2 + 1] = F::from_bool(carry == -1);
            }
        }
        assert_eq!(carry, 0);
        let coefficients: [u32; 13] = core::array::from_fn(|i| {
            (0..13)
                .map(|j| {
                    let k = (i + 13 - j) % 13;
                    ad[j] as u32 * rdigits[k] as u32 * if j + k == i { 1 } else { 5 }
                })
                .sum()
        });
        let folded = coefficients
            .iter()
            .enumerate()
            .fold(BigUint::from(0u8), |acc, (i, c)| {
                acc + (BigUint::from(*c) << (i * 10))
            });
        let quotient = ((&folded - &out) / &p)
            .to_u32_digits()
            .first()
            .copied()
            .unwrap_or(0);
        let mut carry = quotient * 5;
        for i in 0..13 {
            let numerator = coefficients[i] + carry - od[i] as u32;
            assert_eq!(numerator % 1024, 0);
            carry = numerator / 1024;
            write_carry(&mut values[off + MULT_CARRY + i * 18..], carry);
        }
        assert_eq!(carry, quotient);
        h = out;
    }
    let tag_value = (&h + &s) & ((BigUint::from(1u8) << 128usize) - BigUint::from(1u8));
    let mut tagbytes = tag_value.to_bytes_le();
    tagbytes.resize(16, 0);
    let tag: [u8; 16] = tagbytes.try_into().unwrap();
    let mut carry = 0u32;
    let mut hbytes = h.to_bytes_le();
    hbytes.resize(17, 0);
    for i in 0..8 {
        let a = u16::from_le_bytes([hbytes[i * 2], hbytes[i * 2 + 1]]) as u32;
        let b = u16::from_le_bytes([key[16 + i * 2], key[17 + i * 2]]) as u32;
        carry = (a + b + carry) >> 16;
        values[21 * WIDTH + TAG_CARRY + i] = F::from_u32(carry);
    }
    (
        Poly1305Air { aad, body, tag },
        RowMajorMatrix::new(values, WIDTH),
    )
}
