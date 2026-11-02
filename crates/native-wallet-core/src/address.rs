//! Proposed V1 user-interface encoding; native recipient bytes are unchanged.
//! A short address is a commitment, not a compressed ML-KEM public key. Resolving
//! one requires an independently obtained full address; substitutions are rejected.
use crate::{hex, hex_array, network};
use libcrux_ml_kem::mlkem768::{self, MlKem768PublicKey};
use serde::{Deserialize, Serialize};

const FULL: &str = "sivf1";
const SHORT: &str = "sivs1";
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const CHECK: usize = 8;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub version: u8,
    pub network: String,
    pub account: u32,
    pub address_hex: String,
}
impl Descriptor {
    pub fn new(network: [u8; 32], account: u32, address: &[u8; 1232]) -> Self {
        Self {
            version: 1,
            network: hex(&network),
            account,
            address_hex: hex(address),
        }
    }
    pub fn validate(&self, expected: [u8; 32]) -> Result<[u8; 1232], String> {
        if self.version != 1 || network(&self.network)? != expected {
            return Err("Recipient network or version differs.".into());
        }
        let address = hex_array(&self.address_hex)?;
        validate(&address)?;
        Ok(address)
    }
}
pub fn validate(address: &[u8; 1232]) -> Result<(), String> {
    for word in address[..48].as_chunks::<4>().0 {
        if u32::from_le_bytes(*word) >= 2_130_706_433 {
            return Err("Noncanonical V1 owner field.".into());
        }
    }
    let bytes: [u8; 1184] = address[48..].try_into().expect("key width");
    if !mlkem768::validate_public_key(&MlKem768PublicKey::from(&bytes)) {
        return Err("Invalid V1 receiving key.".into());
    }
    Ok(())
}
fn commitment(network: &[u8; 32], address: &[u8; 1232]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("siworld native recipient directory v1");
    h.update(network);
    h.update(address);
    *h.finalize().as_bytes()
}
pub fn full(network: [u8; 32], address: &[u8; 1232]) -> Result<String, String> {
    validate(address)?;
    let mut payload = vec![1];
    payload.extend(network);
    payload.extend(address);
    Ok(encode(FULL, &payload, &network))
}
pub fn short(network: [u8; 32], address: &[u8; 1232]) -> Result<String, String> {
    validate(address)?;
    let mut payload = vec![1];
    payload.extend(commitment(&network, address));
    Ok(encode(SHORT, &payload, &network))
}
/// Check the network-bound spelling before performing a directory lookup.
pub fn validate_short(text: &str, network: [u8; 32]) -> Result<(), String> {
    let payload = decode(SHORT, text, &network, 33)?;
    if !text.starts_with(SHORT) || payload[0] != 1 {
        return Err("Unsupported short receiving address.".into());
    }
    Ok(())
}
/// Resolve either form. `resolved` comes from a bounded local contact record or
/// future directory response and is always authenticated against the commitment.
pub fn resolve(
    text: &str,
    expected: [u8; 32],
    resolved: Option<&str>,
) -> Result<[u8; 1232], String> {
    if text.starts_with(FULL) {
        let payload = decode(FULL, text, &expected, 1265)?;
        if payload[0] != 1 || payload[1..33] != expected {
            return Err("Recipient network or version differs.".into());
        }
        let address = payload[33..].try_into().expect("address width");
        validate(&address)?;
        return Ok(address);
    }
    if text.starts_with(SHORT) {
        validate_short(text, expected)?;
        let payload = decode(SHORT, text, &expected, 33)?;
        let full = resolved
            .ok_or("Short address unresolved. Import its full address contact record first.")?;
        if !full.starts_with(FULL) {
            return Err("A full V1 address is required to resolve this contact.".into());
        }
        let address = resolve(full, expected, None)?;
        if payload[1..] != commitment(&expected, &address) {
            return Err("Short address commitment mismatch.".into());
        }
        return Ok(address);
    }
    Err("Use a native V1 full or short address. Legacy website addresses are incompatible.".into())
}
fn checksum(prefix: &str, payload: &[u8], network: &[u8; 32]) -> [u8; CHECK] {
    let mut h = blake3::Hasher::new_derive_key("siworld native recipient text checksum v1");
    h.update(prefix.as_bytes());
    h.update(network);
    h.update(payload);
    h.finalize().as_bytes()[..CHECK]
        .try_into()
        .expect("checksum width")
}
fn encode(prefix: &str, payload: &[u8], network: &[u8; 32]) -> String {
    let mut bytes = payload.to_vec();
    bytes.extend(checksum(prefix, payload, network));
    let mut out = prefix.to_string();
    let mut acc = 0u32;
    let mut bits = 0;
    for b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}
fn decode(prefix: &str, text: &str, network: &[u8; 32], length: usize) -> Result<Vec<u8>, String> {
    if text.len() != prefix.len() + ((length + CHECK) * 8).div_ceil(5) {
        return Err("Invalid receiving address length.".into());
    }
    let mut out = Vec::with_capacity(length + CHECK);
    let mut acc = 0u32;
    let mut bits = 0;
    for b in text.as_bytes()[prefix.len()..].iter() {
        let v = ALPHABET
            .iter()
            .position(|a| a == b)
            .ok_or("Invalid receiving address alphabet.")?;
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 255) as u8);
        }
    }
    if out.len() != length + CHECK
        || (acc & ((1u32 << bits) - 1)) != 0
        || out[length..] != checksum(prefix, &out[..length], network)
    {
        return Err("Receiving address checksum or network mismatch.".into());
    }
    out.truncate(length);
    Ok(out)
}
