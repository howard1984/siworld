//! Private two-table prefix prototype only. It does not prove encryption.
use ::native::multi_asset::F;
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SubAirBuilder;

const SEED: usize = NUM_KECCAK_COLS;
pub(crate) const SHA_WIDTH: usize = SEED + 16;
const SHA_HEIGHT: usize = 256;
const WORD: usize = 0;
const BITS: usize = 1;
pub(crate) const COEFF: usize = BITS + 16;
const NEG: usize = COEFF + 4;
const COEFF_BITS: usize = NEG + 4;
const COMPLEMENT: usize = COEFF_BITS + 48;
const COMPLEMENT_BITS: usize = COMPLEMENT + 4;
pub(crate) const CBD_WIDTH: usize = COMPLEMENT_BITS + 48;
const CBD_HEIGHT: usize = 512;

#[derive(Clone)]
pub enum PrefixAir {
    Keccak,
    Cbd,
    Closed,
}
impl BaseAir<F> for PrefixAir {
    fn width(&self) -> usize {
        match self {
            Self::Keccak => SHA_WIDTH,
            Self::Cbd => CBD_WIDTH,
            Self::Closed => SHA_WIDTH + CBD_WIDTH,
        }
    }
    fn num_public_values(&self) -> usize {
        match self {
            Self::Keccak => 16,
            Self::Cbd => 0,
            Self::Closed => 16,
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Keccak => 16,
            Self::Cbd => 3,
            Self::Closed => 19,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Keccak => {
                let mut values = F::zero_vec(SHA_HEIGHT * 16);
                for job in 0..8 {
                    values[job * 24 * 16 + job] = F::ONE;
                    values[(job * 24 + 23) * 16 + 8 + job] = F::ONE;
                }
                Some(RowMajorMatrix::new(values, 16))
            }
            Self::Cbd => {
                let mut values = F::zero_vec(CBD_HEIGHT * 3);
                for r in 0..448 {
                    values[r * 3] = F::ONE;
                    values[r * 3 + 1] = F::from_usize(r / 64);
                    values[r * 3 + 2] = F::from_usize(r % 64);
                }
                Some(RowMajorMatrix::new(values, 3))
            }
            Self::Closed => {
                let sha = Self::Keccak.preprocessed_trace().unwrap();
                let cbd = Self::Cbd.preprocessed_trace().unwrap();
                let mut values = F::zero_vec(CBD_HEIGHT * 19);
                for r in 0..CBD_HEIGHT {
                    if r < SHA_HEIGHT {
                        values[r * 19..r * 19 + 16]
                            .copy_from_slice(&sha.values[r * 16..(r + 1) * 16]);
                    }
                    values[r * 19 + 16..(r + 1) * 19]
                        .copy_from_slice(&cbd.values[r * 3..(r + 1) * 3]);
                }
                Some(RowMajorMatrix::new(values, 19))
            }
        }
    }
}
pub(crate) fn input<T: Copy>(k: &KeccakCols<T>, word: usize) -> T {
    k.preimage[word / 20][(word / 4) % 5][word % 4]
}
pub(crate) fn output<T: Copy>(k: &KeccakCols<T>, word: usize) -> T {
    k.a_prime_prime_prime(word / 20, (word / 4) % 5, word % 4)
}
impl<AB> Air<AB> for PrefixAir
where
    AB: AirBuilder<F = F> + PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, b: &mut AB) {
        match self {
            Self::Keccak => eval_keccak(b),
            Self::Cbd => eval_cbd(b, 0, 0),
            Self::Closed => {
                eval_keccak(b);
                eval_cbd(b, SHA_WIDTH, 16);
            }
        }
    }
}
fn eval_keccak<AB>(b: &mut AB)
where
    AB: AirBuilder<F = F> + PermutationAirBuilder + InteractionBuilder,
{
    let mut sub = SubAirBuilder::<AB, KeccakAir, AB::Var>::new(b, 0..NUM_KECCAK_COLS);
    KeccakAir {}.eval(&mut sub);
    let main = b.main();
    let pre = b.preprocessed().clone();
    let l = main.current_slice();
    let n = main.next_slice();
    let p = pre.current_slice();
    let k: &KeccakCols<AB::Var> = l[..NUM_KECCAK_COLS].borrow();
    let x = |v: AB::Var| -> AB::Expr { v.into() };
    let public = b.public_values().to_vec();
    for e in 0..16 {
        b.when_transition().assert_eq(l[SEED + e], n[SEED + e]);
        b.assert_zero((x(output(k, 16 + e)) - x(l[SEED + e])) * x(p[8]));
    }
    for (job, &selector) in p[..8].iter().enumerate() {
        let selected = x(selector);
        for word in 0..100 {
            if job == 0 && word < 16 {
                continue;
            }
            let expected = if job == 0 {
                match word {
                    16..32 => public[word - 16].into(),
                    32 => AB::Expr::from_u32(0x0006),
                    35 => AB::Expr::from_u32(0x8000),
                    _ => AB::Expr::ZERO,
                }
            } else {
                match word {
                    0..16 => x(l[SEED + word]),
                    16 => AB::Expr::from_usize((job - 1) | (0x1f << 8)),
                    67 => AB::Expr::from_u32(0x8000),
                    _ => AB::Expr::ZERO,
                }
            };
            b.assert_zero((x(input(k, word)) - expected) * selected.clone());
        }
    }
    let active = (1..8).map(|job| x(p[8 + job])).sum::<AB::Expr>();
    let job = (1..8)
        .map(|job| x(p[8 + job]) * F::from_usize(job - 1))
        .sum::<AB::Expr>();
    for word in 0..64 {
        b.push_interaction(
            "mlkem-prf-word",
            [job.clone(), AB::Expr::from_usize(word), x(output(k, word))],
            Count::bounded(-active.clone(), 1),
        );
    }
}
fn eval_cbd<AB>(b: &mut AB, main_offset: usize, pre_offset: usize)
where
    AB: AirBuilder<F = F> + PermutationAirBuilder + InteractionBuilder,
{
    let main = b.main();
    let pre = b.preprocessed().clone();
    let l = &main.current_slice()[main_offset..];
    let p = &pre.current_slice()[pre_offset..];
    let x = |v: AB::Var| -> AB::Expr { v.into() };
    let active = x(p[0]);
    let mut word = AB::Expr::ZERO;
    for bit in 0..16 {
        b.assert_bool(l[BITS + bit]);
        word += x(l[BITS + bit]) * F::from_u32(1 << bit);
    }
    b.assert_eq(word, l[WORD]);
    for c in 0..4 {
        let mut value = AB::Expr::ZERO;
        let mut complement = AB::Expr::ZERO;
        for bit in 0..12 {
            b.assert_bool(l[COEFF_BITS + c * 12 + bit]);
            b.assert_bool(l[COMPLEMENT_BITS + c * 12 + bit]);
            value += x(l[COEFF_BITS + c * 12 + bit]) * F::from_u32(1 << bit);
            complement += x(l[COMPLEMENT_BITS + c * 12 + bit]) * F::from_u32(1 << bit);
        }
        b.assert_eq(value, l[COEFF + c]);
        b.assert_eq(complement, l[COMPLEMENT + c]);
        b.assert_bool(l[NEG + c]);
        let delta = x(l[BITS + c * 4]) + x(l[BITS + c * 4 + 1])
            - x(l[BITS + c * 4 + 2])
            - x(l[BITS + c * 4 + 3]);
        b.assert_eq(l[COEFF + c], delta + x(l[NEG + c]) * F::from_u32(3329));
        b.assert_eq(x(l[COEFF + c]) + x(l[COMPLEMENT + c]), F::from_u32(3328));
    }
    b.push_interaction(
        "mlkem-prf-word",
        [x(p[1]), x(p[2]), x(l[WORD])],
        Count::bounded(active, 1),
    );
}

pub fn public_hash(hash: [u8; 32]) -> Vec<F> {
    hash.as_chunks::<2>()
        .0
        .iter()
        .map(|b| F::from_u32(u16::from_le_bytes(*b) as u32))
        .collect()
}
fn padded(input: &[u8], rate: usize, suffix: u8) -> [u64; 25] {
    assert!(input.len() < rate);
    let mut bytes = [0u8; 200];
    bytes[..input.len()].copy_from_slice(input);
    bytes[input.len()] ^= suffix;
    bytes[rate - 1] ^= 0x80;
    core::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()))
}
fn generate_internal(
    coins: [u8; 32],
    hash: [u8; 32],
    closed: bool,
) -> (RowMajorMatrix<F>, RowMajorMatrix<F>, [[u16; 256]; 7]) {
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&coins);
    g_input[32..].copy_from_slice(&hash);
    let mut g = [0u8; 64];
    libcrux_sha3::portable::sha512(&mut g, &g_input);
    let mut states = vec![padded(&g_input, 72, 0x06)];
    let mut prf = [[0u8; 128]; 7];
    for (i, prf_output) in prf.iter_mut().enumerate() {
        let mut input = [0u8; 33];
        input[..32].copy_from_slice(&g[32..]);
        input[32] = i as u8;
        libcrux_sha3::portable::shake256(prf_output, &input);
        states.push(padded(&input, 136, 0x1f));
    }
    if closed {
        states.resize(16, [0; 25]);
    }
    let keccak = p3_keccak_air::generate_trace_rows::<F>(states, 0);
    let sha_height = keccak.values.len() / NUM_KECCAK_COLS;
    let seed = g[32..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| F::from_u32(u16::from_le_bytes(*b) as u32))
        .collect::<Vec<_>>();
    let mut sha = F::zero_vec(sha_height * SHA_WIDTH);
    for r in 0..sha_height {
        sha[r * SHA_WIDTH..r * SHA_WIDTH + NUM_KECCAK_COLS]
            .copy_from_slice(&keccak.values[r * NUM_KECCAK_COLS..(r + 1) * NUM_KECCAK_COLS]);
        sha[r * SHA_WIDTH + SEED..(r + 1) * SHA_WIDTH].copy_from_slice(&seed);
    }
    let mut cbd = F::zero_vec(CBD_HEIGHT * CBD_WIDTH);
    let mut expected = [[0u16; 256]; 7];
    for r in 0..CBD_HEIGHT {
        let word = if r < 448 {
            u16::from_le_bytes([prf[r / 64][(r % 64) * 2], prf[r / 64][(r % 64) * 2 + 1]])
        } else {
            0
        };
        let off = r * CBD_WIDTH;
        cbd[off + WORD] = F::from_u32(word as u32);
        for bit in 0..16 {
            cbd[off + BITS + bit] = F::from_u32(((word >> bit) & 1) as u32);
        }
        for c in 0..4 {
            let bits = (word >> (c * 4)) & 15;
            let delta = (bits & 1) as i32 + ((bits >> 1) & 1) as i32
                - ((bits >> 2) & 1) as i32
                - ((bits >> 3) & 1) as i32;
            let value = delta.rem_euclid(3329) as u16;
            if r < 448 {
                expected[r / 64][(r % 64) * 4 + c] = value;
            }
            cbd[off + COEFF + c] = F::from_u32(value as u32);
            cbd[off + NEG + c] = F::from_bool(delta < 0);
            cbd[off + COMPLEMENT + c] = F::from_u32(3328 - value as u32);
            for bit in 0..12 {
                cbd[off + COEFF_BITS + c * 12 + bit] = F::from_u32(((value >> bit) & 1) as u32);
                cbd[off + COMPLEMENT_BITS + c * 12 + bit] =
                    F::from_u32((((3328 - value) >> bit) & 1) as u32);
            }
        }
    }
    (
        RowMajorMatrix::new(sha, SHA_WIDTH),
        RowMajorMatrix::new(cbd, CBD_WIDTH),
        expected,
    )
}
/// Keep every send and receive inside one committed AIR. Its sole public
/// rational terminal is required to be zero by the stock batch verifier.
/// This only removes cross-AIR terminal leakage for the measured prefix.
pub fn generate_closed(coins: [u8; 32], hash: [u8; 32]) -> (RowMajorMatrix<F>, [[u16; 256]; 7]) {
    let (sha, cbd, expected) = generate_internal(coins, hash, true);
    let width = SHA_WIDTH + CBD_WIDTH;
    let mut values = F::zero_vec(CBD_HEIGHT * width);
    for r in 0..CBD_HEIGHT {
        values[r * width..r * width + SHA_WIDTH]
            .copy_from_slice(&sha.values[r * SHA_WIDTH..(r + 1) * SHA_WIDTH]);
        values[r * width + SHA_WIDTH..(r + 1) * width]
            .copy_from_slice(&cbd.values[r * CBD_WIDTH..(r + 1) * CBD_WIDTH]);
    }
    (RowMajorMatrix::new(values, width), expected)
}
