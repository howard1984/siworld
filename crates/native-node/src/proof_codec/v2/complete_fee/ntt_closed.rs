//! Synthetic forward-NTT proof prefix with one closed AIR lookup terminal.
//! This does not implement or prove the complete encryption relation.
use super::prefix::{self, CBD_WIDTH, COEFF, PrefixAir, SHA_WIDTH};
use ::native::multi_asset::F;
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

const Q: u32 = 3329;
pub(crate) const HEIGHT: usize = 512;
const LANES: usize = 6;
pub(crate) const RESIDUE_WIDTH: usize = 25;
pub(crate) const LANE_WIDTH: usize = 6 * RESIDUE_WIDTH + 2;
const NTT_OFFSET: usize = SHA_WIDTH + CBD_WIDTH;
pub(crate) const SINK_OFFSET: usize = NTT_OFFSET + LANES * LANE_WIDTH;
pub(crate) const WIDTH: usize = SINK_OFFSET + 2;
const INITIAL_PRE: usize = 19;
const NTT_PRE: usize = 20;
const PRE_LANE_WIDTH: usize = 6;
pub(crate) const SINK_PRE: usize = NTT_PRE + LANES * PRE_LANE_WIDTH;
pub(crate) const PRE_WIDTH: usize = SINK_PRE + 6;

#[derive(Clone, Copy)]
pub struct NttClosedAir;

#[derive(Clone, Copy)]
struct Event {
    poly: usize,
    stage: usize,
    left: usize,
    right: usize,
    zeta: u16,
}

fn schedule() -> Vec<Event> {
    let mut events = Vec::with_capacity(2688);
    for poly in 0..3 {
        let mut k = 1;
        for stage in 0..7 {
            let len = 128 >> stage;
            for start in (0..256).step_by(len * 2) {
                let exponent = (k as u8).reverse_bits() as usize >> 1;
                let zeta = (0..exponent).fold(1u32, |a, _| a * 17 % Q) as u16;
                k += 1;
                for left in start..start + len {
                    events.push(Event {
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
    assert_eq!(events.len(), 2688);
    events
}

impl BaseAir<F> for NttClosedAir {
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
        let prefix = PrefixAir::Closed.preprocessed_trace().unwrap();
        let mut values = F::zero_vec(HEIGHT * PRE_WIDTH);
        for row in 0..HEIGHT {
            values[row * PRE_WIDTH..row * PRE_WIDTH + 19]
                .copy_from_slice(&prefix.values[row * 19..(row + 1) * 19]);
            values[row * PRE_WIDTH + INITIAL_PRE] = F::from_bool(row < 192);
        }
        for (index, event) in schedule().into_iter().enumerate() {
            let offset = index / LANES * PRE_WIDTH + NTT_PRE + index % LANES * PRE_LANE_WIDTH;
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
        for index in 0..768 {
            let offset = index / 2 * PRE_WIDTH + SINK_PRE + index % 2 * 3;
            values[offset] = F::ONE;
            values[offset + 1] = F::from_usize(index / 256);
            values[offset + 2] = F::from_usize(index % 256);
        }
        Some(RowMajorMatrix::new(values, PRE_WIDTH))
    }
}

pub(crate) fn eval_residue<AB: AirBuilder<F = F>>(builder: &mut AB, columns: &[AB::Var]) {
    let mut value = AB::Expr::ZERO;
    let mut complement = AB::Expr::ZERO;
    for bit in 0..12 {
        builder.assert_bool(columns[1 + bit]);
        builder.assert_bool(columns[13 + bit]);
        value += AB::Expr::from(columns[1 + bit]) * F::from_u32(1 << bit);
        complement += AB::Expr::from(columns[13 + bit]) * F::from_u32(1 << bit);
    }
    builder.assert_eq(value, columns[0]);
    builder.assert_eq(AB::Expr::from(columns[0]) + complement, F::from_u32(Q - 1));
}

impl<AB> Air<AB> for NttClosedAir
where
    AB: AirBuilder<F = F> + PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        PrefixAir::Closed.eval(builder);
        let main = builder.main();
        let pre = builder.preprocessed().clone();
        let local = main.current_slice();
        let p = pre.current_slice();
        let x = |value: AB::Var| -> AB::Expr { value.into() };
        // Initial coefficients are taken from the already constrained CBD
        // sampling result, never supplied by a disconnected witness table.
        for coefficient in 0..4 {
            builder.push_interaction(
                "mlkem-ntt-stage",
                [
                    x(p[17]),
                    AB::Expr::ZERO,
                    x(p[18]) * F::from_u32(4) + F::from_usize(coefficient),
                    x(local[SHA_WIDTH + COEFF + coefficient]),
                ],
                Count::bounded(-x(p[INITIAL_PRE]), 1),
            );
        }
        for lane in 0..LANES {
            let columns =
                &local[NTT_OFFSET + lane * LANE_WIDTH..NTT_OFFSET + (lane + 1) * LANE_WIDTH];
            let fixed = &p[NTT_PRE + lane * PRE_LANE_WIDTH..];
            for residue in columns[..6 * RESIDUE_WIDTH].as_chunks::<RESIDUE_WIDTH>().0 {
                eval_residue(builder, residue);
            }
            let a = x(columns[0]);
            let b = x(columns[RESIDUE_WIDTH]);
            let t = x(columns[2 * RESIDUE_WIDTH]);
            let u = x(columns[3 * RESIDUE_WIDTH]);
            let v = x(columns[4 * RESIDUE_WIDTH]);
            let quotient = x(columns[5 * RESIDUE_WIDTH]);
            let carry = x(columns[6 * RESIDUE_WIDTH]);
            let borrow = x(columns[6 * RESIDUE_WIDTH + 1]);
            builder.assert_bool(columns[6 * RESIDUE_WIDTH]);
            builder.assert_bool(columns[6 * RESIDUE_WIDTH + 1]);
            builder.assert_eq(
                x(fixed[5]) * b.clone(),
                t.clone() + quotient * F::from_u32(Q),
            );
            builder.assert_eq(a.clone() + t.clone(), u.clone() + carry * F::from_u32(Q));
            builder.assert_eq(a.clone() - t + borrow * F::from_u32(Q), v.clone());
            for (index, value) in [(fixed[3], a), (fixed[4], b)] {
                builder.push_interaction(
                    "mlkem-ntt-stage",
                    [x(fixed[1]), x(fixed[2]), x(index), value],
                    Count::bounded(x(fixed[0]), 1),
                );
            }
            for (index, value) in [(fixed[3], u), (fixed[4], v)] {
                builder.push_interaction(
                    "mlkem-ntt-stage",
                    [x(fixed[1]), x(fixed[2]) + AB::Expr::ONE, x(index), value],
                    Count::bounded(-x(fixed[0]), 1),
                );
            }
        }
        for lane in 0..2 {
            let fixed = &p[SINK_PRE + lane * 3..];
            builder.push_interaction(
                "mlkem-ntt-stage",
                [
                    x(fixed[1]),
                    AB::Expr::from_u32(7),
                    x(fixed[2]),
                    x(local[SINK_OFFSET + lane]),
                ],
                Count::bounded(x(fixed[0]), 1),
            );
        }
    }
}

pub(crate) fn write_residue(columns: &mut [F], value: u16) {
    assert!((value as u32) < Q);
    columns[0] = F::from_u16(value);
    for bit in 0..12 {
        columns[1 + bit] = F::from_bool(value >> bit & 1 != 0);
        columns[13 + bit] = F::from_bool((Q as u16 - 1 - value) >> bit & 1 != 0);
    }
}

pub fn generate(coins: [u8; 32], hash: [u8; 32]) -> (RowMajorMatrix<F>, [[u16; 256]; 7]) {
    let (prefix, cbd) = prefix::generate_closed(coins, hash);
    let mut values = F::zero_vec(HEIGHT * WIDTH);
    for row in 0..HEIGHT {
        values[row * WIDTH..row * WIDTH + NTT_OFFSET]
            .copy_from_slice(&prefix.values[row * NTT_OFFSET..(row + 1) * NTT_OFFSET]);
        for lane in 0..LANES {
            for residue in 0..6 {
                let offset = row * WIDTH + NTT_OFFSET + lane * LANE_WIDTH + residue * RESIDUE_WIDTH;
                write_residue(&mut values[offset..offset + RESIDUE_WIDTH], 0);
            }
        }
    }
    let mut coefficients = [cbd[0], cbd[1], cbd[2]];
    for (index, event) in schedule().into_iter().enumerate() {
        let a = coefficients[event.poly][event.left];
        let b = coefficients[event.poly][event.right];
        let product = event.zeta as u32 * b as u32;
        let t = (product % Q) as u16;
        let quotient = (product / Q) as u16;
        let u = ((a as u32 + t as u32) % Q) as u16;
        let v = ((a as i32 - t as i32).rem_euclid(Q as i32)) as u16;
        let offset = index / LANES * WIDTH + NTT_OFFSET + index % LANES * LANE_WIDTH;
        for (residue, value) in [a, b, t, u, v, quotient].into_iter().enumerate() {
            write_residue(
                &mut values
                    [offset + residue * RESIDUE_WIDTH..offset + (residue + 1) * RESIDUE_WIDTH],
                value,
            );
        }
        values[offset + 6 * RESIDUE_WIDTH] = F::from_bool(a as u32 + t as u32 >= Q);
        values[offset + 6 * RESIDUE_WIDTH + 1] = F::from_bool(a < t);
        coefficients[event.poly][event.left] = u;
        coefficients[event.poly][event.right] = v;
    }
    for index in 0..768 {
        values[index / 2 * WIDTH + SINK_OFFSET + index % 2] =
            F::from_u16(coefficients[index / 256][index % 256]);
    }
    (RowMajorMatrix::new(values, WIDTH), cbd)
}

pub fn output_coefficient(trace: &RowMajorMatrix<F>, poly: usize, index: usize) -> u16 {
    let index = poly * 256 + index;
    trace.values[index / 2 * WIDTH + SINK_OFFSET + index % 2].as_canonical_u32() as u16
}
