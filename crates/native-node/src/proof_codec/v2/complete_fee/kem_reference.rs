//! Independent canonical FIPS 203 host witness reference. Not a proof gadget.
pub const Q: u32 = 3329;
pub type Poly = [u16; 256];
fn modq(value: i64) -> u16 {
    value.rem_euclid(Q as i64) as u16
}
fn pow17(mut exponent: usize) -> u16 {
    let mut base = 17u32;
    let mut product = 1u32;
    while exponent != 0 {
        if exponent & 1 != 0 {
            product = product * base % Q;
        }
        base = base * base % Q;
        exponent >>= 1;
    }
    product as u16
}
fn bitrev7(value: usize) -> usize {
    (value as u8).reverse_bits() as usize >> 1
}
pub fn ntt(mut coefficients: Poly) -> Poly {
    let mut k = 1;
    for layer in 0..7 {
        let len = 128 >> layer;
        for start in (0..256).step_by(len * 2) {
            let zeta = pow17(bitrev7(k)) as i64;
            k += 1;
            for j in start..start + len {
                let t = zeta * coefficients[j + len] as i64;
                let a = coefficients[j] as i64;
                coefficients[j] = modq(a + t);
                coefficients[j + len] = modq(a - t);
            }
        }
    }
    coefficients
}
pub fn inverse_ntt(mut coefficients: Poly) -> Poly {
    let mut k = 127;
    for layer in 0..7 {
        let len = 2 << layer;
        for start in (0..256).step_by(len * 2) {
            let zeta = pow17(bitrev7(k)) as i64;
            k -= 1;
            for j in start..start + len {
                let a = coefficients[j] as i64;
                let b = coefficients[j + len] as i64;
                coefficients[j] = modq(a + b);
                coefficients[j + len] = modq(zeta * (b - a));
            }
        }
    }
    coefficients.map(|coefficient| modq(coefficient as i64 * 3303))
}
fn multiply_ntt(a: &Poly, b: &Poly) -> Poly {
    let mut result = [0; 256];
    for i in 0..128 {
        let gamma = pow17(2 * bitrev7(i) + 1) as i64;
        let [a0, a1] = [a[2 * i] as i64, a[2 * i + 1] as i64];
        let [b0, b1] = [b[2 * i] as i64, b[2 * i + 1] as i64];
        result[2 * i] = modq(a0 * b0 + gamma * a1 * b1);
        result[2 * i + 1] = modq(a0 * b1 + a1 * b0);
    }
    result
}
fn add(a: Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| modq(a[i] as i64 + b[i] as i64))
}
fn decode12(bytes: &[u8]) -> Poly {
    assert_eq!(bytes.len(), 384);
    let mut result = [0; 256];
    for i in 0..128 {
        result[i * 2] = bytes[i * 3] as u16 | ((bytes[i * 3 + 1] as u16 & 15) << 8);
        result[i * 2 + 1] = (bytes[i * 3 + 1] as u16 >> 4) | ((bytes[i * 3 + 2] as u16) << 4);
    }
    assert!(result.iter().all(|coefficient| *coefficient < Q as u16));
    result
}
fn sample_matrix(rho: &[u8], i: usize, j: usize) -> Poly {
    let mut seed = [0; 34];
    seed[..32].copy_from_slice(rho);
    seed[32] = j as u8;
    seed[33] = i as u8;
    // Public rejection expansion has no invented fixed worst-case cutoff.
    let mut bytes = vec![0; 168 * 3];
    loop {
        libcrux_sha3::portable::shake128(&mut bytes, &seed);
        let mut result = [0; 256];
        let mut count = 0;
        for group in bytes.as_chunks::<3>().0 {
            let d1 = group[0] as u16 + 256 * (group[1] as u16 & 15);
            let d2 = (group[1] as u16 >> 4) + 16 * group[2] as u16;
            for value in [d1, d2] {
                if value < Q as u16 {
                    result[count] = value;
                    count += 1;
                    if count == 256 {
                        return result;
                    }
                }
            }
        }
        bytes.resize(bytes.len() + 168, 0);
    }
}
fn sample_cbd(seed: &[u8], counter: u8) -> Poly {
    let mut input = [0; 33];
    input[..32].copy_from_slice(seed);
    input[32] = counter;
    let mut bytes = [0; 128];
    libcrux_sha3::portable::shake256(&mut bytes, &input);
    core::array::from_fn(|index| {
        let nibble = (bytes[index / 2] >> ((index % 2) * 4)) & 15;
        modq(
            (nibble & 1) as i64 + ((nibble >> 1) & 1) as i64
                - ((nibble >> 2) & 1) as i64
                - ((nibble >> 3) & 1) as i64,
        )
    })
}
fn compress_encode(poly: Poly, bits: usize, output: &mut [u8]) {
    assert_eq!(output.len(), 256 * bits / 8);
    output.fill(0);
    for (index, value) in poly.iter().enumerate() {
        let compressed = (((*value as u32) << bits) + Q / 2) / Q % (1 << bits);
        for bit in 0..bits {
            output[(index * bits + bit) / 8] |=
                (((compressed >> bit) & 1) as u8) << ((index * bits + bit) % 8);
        }
    }
}
pub fn encapsulate_reference(public_key: &[u8; 1184], coins: [u8; 32]) -> ([u8; 1088], [u8; 32]) {
    let public_t: [Poly; 3] =
        core::array::from_fn(|i| decode12(&public_key[i * 384..(i + 1) * 384]));
    let mut hash = [0; 32];
    libcrux_sha3::portable::sha256(&mut hash, public_key);
    let mut g_input = [0; 64];
    g_input[..32].copy_from_slice(&coins);
    g_input[32..].copy_from_slice(&hash);
    let mut g = [0; 64];
    libcrux_sha3::portable::sha512(&mut g, &g_input);
    let yhat: [Poly; 3] = core::array::from_fn(|i| ntt(sample_cbd(&g[32..], i as u8)));
    let e1: [Poly; 3] = core::array::from_fn(|i| sample_cbd(&g[32..], i as u8 + 3));
    let e2 = sample_cbd(&g[32..], 6);
    let mut ciphertext = [0; 1088];
    for i in 0..3 {
        let mut u = [0; 256];
        for (j, y) in yhat.iter().enumerate() {
            u = add(
                u,
                &multiply_ntt(&sample_matrix(&public_key[1152..], j, i), y),
            );
        }
        let u = add(inverse_ntt(u), &e1[i]);
        compress_encode(u, 10, &mut ciphertext[i * 320..(i + 1) * 320]);
    }
    let mut vhat = [0; 256];
    for i in 0..3 {
        vhat = add(vhat, &multiply_ntt(&public_t[i], &yhat[i]));
    }
    let message = core::array::from_fn(|i| {
        if coins[i / 8] >> (i % 8) & 1 != 0 {
            1665
        } else {
            0
        }
    });
    let v = add(add(inverse_ntt(vhat), &e2), &message);
    compress_encode(v, 4, &mut ciphertext[960..]);
    (ciphertext, g[..32].try_into().unwrap())
}
pub fn public_polynomials(public_key: &[u8; 1184]) -> ([[Poly; 3]; 3], [Poly; 3]) {
    let matrix = core::array::from_fn(|i| {
        core::array::from_fn(|j| sample_matrix(&public_key[1152..], j, i))
    });
    let t = core::array::from_fn(|i| decode12(&public_key[i * 384..(i + 1) * 384]));
    (matrix, t)
}
#[cfg(test)]
mod tests {
    use super::*;
    use libcrux_ml_kem::mlkem768::portable;
    #[test]
    fn canonical_ntt_and_inverse_are_inverses_on_bounded_vectors() {
        for tag in [0, 1, 17, 200, 3328] {
            let input = core::array::from_fn(|i| ((i * 99 + tag) % 3329) as u16);
            assert_eq!(inverse_ntt(ntt(input)), input);
        }
    }
    #[test]
    fn fips203_reference_matches_library_encapsulation_for_distinct_inputs() {
        for case in 0..4u8 {
            let seed = core::array::from_fn(|i| (i as u8).wrapping_mul(19).wrapping_add(case));
            let pair = portable::generate_key_pair(seed);
            let coins = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(case + 91));
            let (library_ciphertext, library_secret) =
                portable::encapsulate(pair.public_key(), coins);
            let (ciphertext, secret) = encapsulate_reference(pair.public_key().as_slice(), coins);
            assert_eq!(ciphertext.as_slice(), library_ciphertext.as_ref());
            assert_eq!(secret.as_slice(), library_secret.as_ref());
            assert_eq!(
                portable::decapsulate(pair.private_key(), &library_ciphertext).as_ref(),
                secret.as_slice()
            );
        }
        println!(
            "fips203_host_reference_library_differential_cases=4; all_1088_ciphertext_bytes_equal=true; proof_gadget=false"
        );
    }
}
