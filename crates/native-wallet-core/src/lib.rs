//! Client-side custody and address interfaces. No consensus or proof generation.
// Reuse the frozen native field/hash implementation without its prover graph.
pub mod address;
pub mod content_vault;
pub mod identity;
#[allow(dead_code)]
#[path = "../../bench-multi-asset/src/multi_asset.rs"]
mod native_hash;
pub mod vault;

pub fn network(text: &str) -> Result<[u8; 32], String> {
    let network = hex_array(text)?;
    if network == [0; 32] {
        return Err("A nonzero native network ID is required.".into());
    }
    Ok(network)
}
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                DIGITS[(b >> 4) as usize] as char,
                DIGITS[(b & 15) as usize] as char,
            ]
        })
        .collect()
}
pub fn hex_array<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Canonical lowercase hexadecimal is required.".into());
    }
    let mut out = [0; N];
    for (i, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        out[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(out)
}
