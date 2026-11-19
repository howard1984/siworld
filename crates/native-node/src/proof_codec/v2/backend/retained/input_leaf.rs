//! Canonical independent input-leaf hash. FRI and internal compression retain P.
use ::native::common::F;
use libcrux_sha3::portable::incremental::{Shake256Xof, Xof};
use p3_field::{PackedValue, PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::CryptographicHasher;

pub(super) const SUITE: &[u8] = b"shake256/canonical-u32le/count-u64le/map64x31/12/v1";
const TAG: &[u8; 26] = b"SIWORLD-NATIVE-INPUT-LEAF\0";
const HEADER_BYTES: usize = 68;
const XOF_BYTES: usize = 256;
const DIGEST_ELEMENTS: usize = 12;

#[derive(Clone, Copy)]
pub struct InputLeafHash {
    profile: [u8; 32],
}
impl InputLeafHash {
    pub(super) const fn new(profile: [u8; 32]) -> Self {
        Self { profile }
    }
    fn header(&self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0; HEADER_BYTES];
        bytes[..26].copy_from_slice(TAG);
        bytes[26..28].copy_from_slice(&1u16.to_le_bytes());
        bytes[28] = 1; // Input-MMCS role; no peer-selected role or suite.
        bytes[29..33].copy_from_slice(&F::ORDER_U32.to_le_bytes());
        bytes[33] = super::SALT_ELEMENTS as u8;
        bytes[34] = DIGEST_ELEMENTS as u8;
        bytes[35] = 1; // Finite 64-word, upper-31-bit rejection map.
        bytes[36..].copy_from_slice(&self.profile);
        bytes
    }
}

// Under uniform XOF words, a rejected upper-31-bit candidate has probability
// below 2^-7. Fewer than twelve accepts among sixty-four words therefore has
// probability at most 2^64*(2^-7)^53 < 2^-307. This finite map always returns;
// its zero suffix is an explicit suite rule, not an entropy retry or fallback.
fn map_prefix(prefix: &[u8; XOF_BYTES]) -> [F; DIGEST_ELEMENTS] {
    let mut digest = [F::ZERO; DIGEST_ELEMENTS];
    let mut filled = 0;
    for word in prefix.as_chunks::<4>().0 {
        let candidate = u32::from_le_bytes(*word) >> 1;
        if candidate < F::ORDER_U32 {
            digest[filled] = F::from_u32(candidate);
            filled += 1;
            if filled == DIGEST_ELEMENTS {
                break;
            }
        }
    }
    digest
}

// The scalar field also implements PackedValue with WIDTH=1. One generic
// implementation gives identical canonical bytes on native packed and WASM
// scalar paths, without overlapping scalar/packed trait implementations.
impl<P: PackedValue<Value = F>> CryptographicHasher<P, [P; DIGEST_ELEMENTS]> for InputLeafHash {
    fn hash_iter<I>(&self, input: I) -> [P; DIGEST_ELEMENTS]
    where
        I: IntoIterator<Item = P>,
    {
        let header = self.header();
        let mut states: Vec<_> = (0..P::WIDTH)
            .map(|_| {
                let mut state = Shake256Xof::new();
                state.absorb(&header);
                state
            })
            .collect();
        let mut count = 0u64;
        for packed in input {
            for (state, value) in states.iter_mut().zip(packed.as_slice()) {
                state.absorb(&value.as_canonical_u32().to_le_bytes());
            }
            // Trusted matrix widths and preflighted proof dimensions bound this
            // count far below u64::MAX; never encode a wrapped length.
            count = count
                .checked_add(1)
                .expect("input leaf field-count overflow");
        }
        let digests: Vec<_> = states
            .iter_mut()
            .map(|state| {
                state.absorb_final(&count.to_le_bytes());
                let mut prefix = [0; XOF_BYTES];
                state.squeeze(&mut prefix);
                map_prefix(&prefix)
            })
            .collect();
        core::array::from_fn(|element| P::from_fn(|lane| digests[lane][element]))
    }
}

#[cfg(test)]
#[path = "input_leaf/tests.rs"]
mod tests;
