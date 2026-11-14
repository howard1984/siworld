//! Synthetic narrow BLAKE3 derive-key and ChaCha20 relation, without Poly1305.
//! Private buses are internal to one AIR. This is not a screened profile.
use ::native::multi_asset::F;
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

const HEIGHT: usize = 512;
const G_WIDTH: usize = 14 * 32 + 12;
pub(crate) const SECRET_OFFSET: usize = G_WIDTH;
const INITIAL_OFFSET: usize = SECRET_OFFSET + 16;
pub(crate) const POST_OFFSET: usize = INITIAL_OFFSET + 32;
const POST_WIDTH: usize = 3 * 32 + 2;
pub(crate) const WIDTH: usize = POST_OFFSET + POST_WIDTH;
const INITIAL_PRE: usize = 15;
const POST_PRE: usize = INITIAL_PRE + 8;
pub(crate) const PRE_WIDTH: usize = POST_PRE + 9;
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
const POSITIONS: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];
const MESSAGE_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[derive(Clone, Copy)]
pub struct ArxClosedAir;
#[derive(Clone, Copy)]
struct Event {
    job: usize,
    positions: [usize; 4],
    versions: [usize; 4],
    x: usize,
    y: usize,
}

fn schedule() -> Vec<Event> {
    let mut events = Vec::with_capacity(HEIGHT);
    for job in 0..7 {
        let mut versions = [0; 16];
        let mut message: [usize; 16] = core::array::from_fn(|i| i);
        let rounds = if job < 2 { 7 } else { 10 };
        for _ in 0..rounds {
            for (g, positions) in POSITIONS.into_iter().enumerate() {
                events.push(Event {
                    job,
                    positions,
                    versions: positions.map(|i| versions[i]),
                    x: if job < 2 { message[g * 2] } else { 16 },
                    y: if job < 2 { message[g * 2 + 1] } else { 16 },
                });
                for position in positions {
                    versions[position] += 1;
                }
            }
            message = MESSAGE_PERMUTATION.map(|i| message[i]);
        }
    }
    assert_eq!(events.len(), HEIGHT);
    events
}

fn g_words([a, b, c, d]: [u32; 4], x: u32, y: u32, chacha: bool) -> [u32; 14] {
    let rotate = |value: u32, amount| {
        if chacha {
            value.rotate_left(amount)
        } else {
            value.rotate_right(amount)
        }
    };
    let a1 = a.wrapping_add(b).wrapping_add(x);
    let d1 = rotate(d ^ a1, 16);
    let c1 = c.wrapping_add(d1);
    let b1 = rotate(b ^ c1, 12);
    let a2 = a1.wrapping_add(b1).wrapping_add(y);
    let d2 = rotate(d1 ^ a2, 8);
    let c2 = c1.wrapping_add(d2);
    let b2 = rotate(b1 ^ c2, 7);
    [a, b, c, d, x, y, a1, d1, c1, b1, a2, d2, c2, b2]
}

fn blake3_compress(cv: [u32; 8], message: [u32; 16], len: u32, flags: u32) -> [u32; 8] {
    let mut state = [0; 16];
    state[..8].copy_from_slice(&cv);
    state[8..12].copy_from_slice(&IV[..4]);
    state[14] = len;
    state[15] = flags;
    let mut message = message;
    for _ in 0..7 {
        for (g, positions) in POSITIONS.into_iter().enumerate() {
            let words = g_words(
                positions.map(|i| state[i]),
                message[g * 2],
                message[g * 2 + 1],
                false,
            );
            for (position, word) in positions
                .into_iter()
                .zip([words[10], words[13], words[12], words[11]])
            {
                state[position] = word;
            }
        }
        message = MESSAGE_PERMUTATION.map(|i| message[i]);
    }
    core::array::from_fn(|i| state[i] ^ state[i + 8])
}
fn context_key(context: &str) -> [u32; 8] {
    assert!(context.len() < 64);
    let mut bytes = [0; 64];
    bytes[..context.len()].copy_from_slice(context.as_bytes());
    let message =
        core::array::from_fn(|i| u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()));
    blake3_compress(IV, message, context.len() as u32, 43)
}
fn public_initial(job: usize, word: usize) -> u32 {
    if job < 2 {
        let context = if job == 0 {
            "siworld multi-asset payment-key-v1"
        } else {
            "siworld multi-asset payment-view-v1"
        };
        match word {
            0..8 => context_key(context)[word],
            8..12 => IV[word - 8],
            12 | 13 => 0,
            14 => 32,
            15 => 75,
            _ => unreachable!(),
        }
    } else {
        match word {
            0..4 => SIGMA[word],
            4..12 => 0,
            12 => (job - 2) as u32,
            13..16 => 0,
            _ => unreachable!(),
        }
    }
}

impl BaseAir<F> for ArxClosedAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        PRE_WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut values = F::zero_vec(HEIGHT * PRE_WIDTH);
        for (row, event) in schedule().into_iter().enumerate() {
            let off = row * PRE_WIDTH;
            for (column, value) in [
                event.job,
                usize::from(event.job >= 2),
                event.x,
                event.y,
                usize::from(event.x < 8),
                usize::from(event.y < 8),
            ]
            .into_iter()
            .enumerate()
            {
                values[off + column] = F::from_usize(value);
            }
            for i in 0..4 {
                values[off + 6 + i] = F::from_usize(event.positions[i]);
                values[off + 10 + i] = F::from_usize(event.versions[i]);
            }
            values[off + 14] = F::from_bool(row == 0);
            if row < 112 {
                let job = row / 16;
                let word = row % 16;
                let expected = public_initial(job, word);
                let off = off + INITIAL_PRE;
                for (column, value) in [
                    1,
                    job,
                    word,
                    expected as usize & 65535,
                    (expected >> 16) as usize,
                    usize::from(job >= 2 && (4..12).contains(&word)),
                    usize::from(job >= 2),
                    word.wrapping_sub(4),
                ]
                .into_iter()
                .enumerate()
                {
                    values[off + column] = F::from_usize(value);
                }
            }
            if row < 96 {
                let (job, word) = if row < 16 {
                    (row / 8, row % 8)
                } else {
                    (2 + (row - 16) / 16, (row - 16) % 16)
                };
                let version = if job < 2 { 14 } else { 20 };
                let off = off + POST_PRE;
                for (column, value) in [
                    1,
                    job,
                    word,
                    version,
                    version,
                    usize::from(job >= 2),
                    usize::from(job == 0),
                    usize::from(job == 1 && word == 0),
                    usize::from(job < 2),
                ]
                .into_iter()
                .enumerate()
                {
                    values[off + column] = F::from_usize(value);
                }
            }
        }
        Some(RowMajorMatrix::new(values, PRE_WIDTH))
    }
}

fn limb<AB: AirBuilder<F = F>>(bits: &[AB::Var], high: bool) -> AB::Expr {
    let offset = usize::from(high) * 16;
    (0..16)
        .map(|i| AB::Expr::from(bits[offset + i]) * F::from_u32(1 << i))
        .sum()
}
fn eval_add<AB: AirBuilder<F = F>>(
    builder: &mut AB,
    columns: &[AB::Var],
    inputs: &[usize],
    output: usize,
    carry_offset: usize,
    three: bool,
) {
    let x = |value: AB::Var| -> AB::Expr { value.into() };
    let (low, high) = if three {
        for i in 0..4 {
            builder.assert_bool(columns[carry_offset + i]);
        }
        builder.assert_zero(x(columns[carry_offset]) * x(columns[carry_offset + 1]));
        builder.assert_zero(x(columns[carry_offset + 2]) * x(columns[carry_offset + 3]));
        (
            x(columns[carry_offset]) + x(columns[carry_offset + 1]) * F::from_u32(2),
            x(columns[carry_offset + 2]) + x(columns[carry_offset + 3]) * F::from_u32(2),
        )
    } else {
        builder.assert_bool(columns[carry_offset]);
        builder.assert_bool(columns[carry_offset + 1]);
        (x(columns[carry_offset]), x(columns[carry_offset + 1]))
    };
    let low_sum = inputs
        .iter()
        .map(|i| limb::<AB>(&columns[i * 32..], false))
        .sum::<AB::Expr>();
    let high_sum = inputs
        .iter()
        .map(|i| limb::<AB>(&columns[i * 32..], true))
        .sum::<AB::Expr>();
    builder.assert_eq(
        low_sum,
        limb::<AB>(&columns[output * 32..], false) + low.clone() * F::from_u32(65536),
    );
    builder.assert_eq(
        high_sum + low,
        limb::<AB>(&columns[output * 32..], true) + high * F::from_u32(65536),
    );
}
fn xor<AB: AirBuilder<F = F>>(a: AB::Var, b: AB::Var) -> AB::Expr {
    let a = AB::Expr::from(a);
    let b = AB::Expr::from(b);
    a.clone() + b.clone() - a * b * F::from_u32(2)
}

impl<AB> Air<AB> for ArxClosedAir
where
    AB: AirBuilder<F = F> + PermutationAirBuilder + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        eval_at(builder, 0, 0, 0);
    }
}
pub(crate) fn eval_at<AB>(
    builder: &mut AB,
    main_offset: usize,
    pre_offset: usize,
    tag_offset: usize,
) where
    AB: AirBuilder<F = F> + PermutationAirBuilder + InteractionBuilder,
{
    let main = builder.main();
    let pre = builder.preprocessed().clone();
    let local = &main.current_slice()[main_offset..];
    let next = &main.next_slice()[main_offset..];
    let p = &pre.current_slice()[pre_offset..];
    let x = |value: AB::Var| -> AB::Expr { value.into() };
    for value in &local[..14 * 32] {
        builder.assert_bool(*value);
    }
    eval_add(builder, local, &[0, 1, 4], 6, 448, true);
    eval_add(builder, local, &[2, 7], 8, 452, false);
    eval_add(builder, local, &[6, 9, 5], 10, 454, true);
    eval_add(builder, local, &[8, 11], 12, 458, false);
    for (a, b, out, rotation) in [(3, 6, 7, 16), (1, 8, 9, 12), (7, 10, 11, 8), (9, 12, 13, 7)] {
        for bit in 0..32 {
            let right = (bit + rotation) % 32;
            let left = (bit + 32 - rotation) % 32;
            let expected = xor::<AB>(local[a * 32 + right], local[b * 32 + right])
                * (AB::Expr::ONE - x(p[1]))
                + xor::<AB>(local[a * 32 + left], local[b * 32 + left]) * x(p[1]);
            builder.assert_eq(local[out * 32 + bit], expected);
        }
    }
    for (slot, word_selector, active_selector) in [(4, 2, 4), (5, 3, 5)] {
        for bit in 0..32 {
            builder
                .assert_zero(x(local[slot * 32 + bit]) * (AB::Expr::ONE - x(p[active_selector])));
        }
        builder.push_interaction(
            "arx-private-message",
            [
                x(p[word_selector]),
                limb::<AB>(&local[slot * 32..], false),
                limb::<AB>(&local[slot * 32..], true),
            ],
            Count::bounded(x(p[active_selector]), 1),
        );
    }
    for word in 0..8 {
        for side in 0..2 {
            builder.when_transition().assert_eq(
                local[SECRET_OFFSET + word * 2 + side],
                next[SECRET_OFFSET + word * 2 + side],
            );
        }
        builder.push_interaction(
            "arx-private-message",
            [
                AB::Expr::from_usize(word),
                x(local[SECRET_OFFSET + word * 2]),
                x(local[SECRET_OFFSET + word * 2 + 1]),
            ],
            Count::bounded(-x(p[14]) * F::from_u32(14), 14),
        );
    }
    for slot in 0..4 {
        builder.push_interaction(
            "arx-state",
            [
                x(p[0]),
                x(p[6 + slot]),
                x(p[10 + slot]),
                limb::<AB>(&local[slot * 32..], false),
                limb::<AB>(&local[slot * 32..], true),
            ],
            Count::bounded(AB::Expr::ONE, 1),
        );
        let output = [10, 13, 12, 11][slot];
        builder.push_interaction(
            "arx-state",
            [
                x(p[0]),
                x(p[6 + slot]),
                x(p[10 + slot]) + AB::Expr::ONE,
                limb::<AB>(&local[output * 32..], false),
                limb::<AB>(&local[output * 32..], true),
            ],
            Count::bounded(-AB::Expr::ONE, 1),
        );
    }
    let initial = &local[INITIAL_OFFSET..];
    let fixed = &p[INITIAL_PRE..];
    for &bit in &initial[..32] {
        builder.assert_bool(bit);
    }
    let low = limb::<AB>(initial, false);
    let high = limb::<AB>(initial, true);
    builder.assert_zero((low.clone() - x(fixed[3])) * (x(fixed[0]) - x(fixed[5])));
    builder.assert_zero((high.clone() - x(fixed[4])) * (x(fixed[0]) - x(fixed[5])));
    builder.push_interaction(
        "arx-state",
        [
            x(fixed[1]),
            x(fixed[2]),
            AB::Expr::ZERO,
            low.clone(),
            high.clone(),
        ],
        Count::bounded(-x(fixed[0]), 1),
    );
    builder.push_interaction(
        "arx-key",
        [x(fixed[7]), low.clone(), high.clone()],
        Count::bounded(x(fixed[5]), 1),
    );
    builder.push_interaction(
        "arx-original",
        [x(fixed[1]), x(fixed[2]), low, high],
        Count::bounded(-x(fixed[6]), 1),
    );
    let post = &local[POST_OFFSET..];
    let fixed = &p[POST_PRE..];
    for &bit in &post[..96] {
        builder.assert_bool(bit);
    }
    for bit in 0..32 {
        builder
            .assert_zero((x(post[64 + bit]) - xor::<AB>(post[bit], post[32 + bit])) * x(fixed[8]));
    }
    builder.assert_bool(post[96]);
    builder.assert_bool(post[97]);
    builder.assert_zero(
        (limb::<AB>(post, false) + limb::<AB>(&post[32..], false)
            - limb::<AB>(&post[64..], false)
            - x(post[96]) * F::from_u32(65536))
            * x(fixed[5]),
    );
    builder.assert_zero(
        (limb::<AB>(post, true) + limb::<AB>(&post[32..], true) + x(post[96])
            - limb::<AB>(&post[64..], true)
            - x(post[97]) * F::from_u32(65536))
            * x(fixed[5]),
    );
    builder.push_interaction(
        "arx-state",
        [
            x(fixed[1]),
            x(fixed[2]),
            x(fixed[3]),
            limb::<AB>(post, false),
            limb::<AB>(post, true),
        ],
        Count::bounded(x(fixed[0]), 1),
    );
    builder.push_interaction(
        "arx-state",
        [
            x(fixed[1]),
            x(fixed[2]) + F::from_u32(8),
            x(fixed[4]),
            limb::<AB>(&post[32..], false),
            limb::<AB>(&post[32..], true),
        ],
        Count::bounded(x(fixed[8]), 1),
    );
    builder.push_interaction(
        "arx-original",
        [
            x(fixed[1]),
            x(fixed[2]),
            limb::<AB>(&post[32..], false),
            limb::<AB>(&post[32..], true),
        ],
        Count::bounded(x(fixed[5]), 1),
    );
    builder.push_interaction(
        "arx-key",
        [
            x(fixed[2]),
            limb::<AB>(&post[64..], false),
            limb::<AB>(&post[64..], true),
        ],
        Count::bounded(-x(fixed[6]) * F::from_u32(5), 5),
    );
    let tag = (0..8)
        .map(|i| x(post[64 + i]) * F::from_u32(1 << i))
        .sum::<AB::Expr>();
    let public_tag = builder.public_values()[tag_offset];
    builder.assert_zero((tag - public_tag.into()) * x(fixed[7]));
}

fn write_word(columns: &mut [F], value: u32) {
    for (bit, column) in columns[..32].iter_mut().enumerate() {
        *column = F::from_bool(value >> bit & 1 != 0);
    }
}
fn read_word(columns: &[F]) -> u32 {
    (0..32).fold(0, |a, i| a | (columns[i].as_canonical_u32() << i))
}
fn write_carries(columns: &mut [F], inputs: &[u32], three: bool) {
    let low = inputs.iter().map(|v| (v & 65535) as u64).sum::<u64>() >> 16;
    let high = (inputs.iter().map(|v| (v >> 16) as u64).sum::<u64>() + low) >> 16;
    if three {
        columns[0] = F::from_bool(low & 1 != 0);
        columns[1] = F::from_bool(low & 2 != 0);
        columns[2] = F::from_bool(high & 1 != 0);
        columns[3] = F::from_bool(high & 2 != 0);
    } else {
        columns[0] = F::from_bool(low != 0);
        columns[1] = F::from_bool(high != 0);
    }
}
pub fn generate(secret: [u8; 32]) -> (RowMajorMatrix<F>, u8) {
    let secret_words: [u32; 8] =
        core::array::from_fn(|i| u32::from_le_bytes(secret[i * 4..i * 4 + 4].try_into().unwrap()));
    let mut message = [0; 16];
    message[..8].copy_from_slice(&secret_words);
    let key = blake3_compress(
        context_key("siworld multi-asset payment-key-v1"),
        message,
        32,
        75,
    );
    let tag = blake3_compress(
        context_key("siworld multi-asset payment-view-v1"),
        message,
        32,
        75,
    )[0] as u8;
    let initial: [[u32; 16]; 7] = core::array::from_fn(|job| {
        core::array::from_fn(|word| {
            if job >= 2 && (4..12).contains(&word) {
                key[word - 4]
            } else {
                public_initial(job, word)
            }
        })
    });
    let mut state = initial;
    let mut values = F::zero_vec(HEIGHT * WIDTH);
    for (row, event) in schedule().into_iter().enumerate() {
        let x = if event.x < 8 {
            secret_words[event.x]
        } else {
            0
        };
        let y = if event.y < 8 {
            secret_words[event.y]
        } else {
            0
        };
        let words = g_words(
            event.positions.map(|i| state[event.job][i]),
            x,
            y,
            event.job >= 2,
        );
        let off = row * WIDTH;
        for (i, word) in words.into_iter().enumerate() {
            write_word(&mut values[off + i * 32..], word);
        }
        for (inputs, carry, three) in [
            (vec![words[0], words[1], words[4]], 448, true),
            (vec![words[2], words[7]], 452, false),
            (vec![words[6], words[9], words[5]], 454, true),
            (vec![words[8], words[11]], 458, false),
        ] {
            write_carries(&mut values[off + carry..], &inputs, three);
        }
        for (position, word) in event
            .positions
            .into_iter()
            .zip([words[10], words[13], words[12], words[11]])
        {
            state[event.job][position] = word;
        }
        for word in 0..8 {
            values[off + SECRET_OFFSET + word * 2] = F::from_u32(secret_words[word] & 65535);
            values[off + SECRET_OFFSET + word * 2 + 1] = F::from_u32(secret_words[word] >> 16);
        }
        if row < 112 {
            write_word(
                &mut values[off + INITIAL_OFFSET..],
                initial[row / 16][row % 16],
            );
        }
    }
    for row in 0..96 {
        let (job, word) = if row < 16 {
            (row / 8, row % 8)
        } else {
            (2 + (row - 16) / 16, (row - 16) % 16)
        };
        let left = state[job][word];
        let right = if job < 2 {
            state[job][word + 8]
        } else {
            initial[job][word]
        };
        let output = if job < 2 {
            left ^ right
        } else {
            left.wrapping_add(right)
        };
        let off = row * WIDTH + POST_OFFSET;
        write_word(&mut values[off..], left);
        write_word(&mut values[off + 32..], right);
        write_word(&mut values[off + 64..], output);
        if job >= 2 {
            write_carries(&mut values[off + 96..], &[left, right], false);
        }
    }
    (RowMajorMatrix::new(values, WIDTH), tag)
}
pub fn private_key_bytes(trace: &RowMajorMatrix<F>) -> [u8; 32] {
    let mut key = [0; 32];
    for i in 0..8 {
        key[i * 4..i * 4 + 4].copy_from_slice(
            &read_word(&trace.values[i * WIDTH + POST_OFFSET + 64..]).to_le_bytes(),
        );
    }
    key
}
pub fn private_stream_bytes(trace: &RowMajorMatrix<F>) -> [u8; 320] {
    let mut stream = [0; 320];
    for i in 0..80 {
        stream[i * 4..i * 4 + 4].copy_from_slice(
            &read_word(&trace.values[(16 + i) * WIDTH + POST_OFFSET + 64..]).to_le_bytes(),
        );
    }
    stream
}
