//! Native owner command identity, independent of wallet spending and folder possession.
use libcrux_ml_dsa::ml_dsa_65::{
    self, MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey, portable,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result, crypto};

const CONTROL_SALT: &[u8; 16] = b"sivault/owner/v1";
const CONTROL_SEED: &[u8] = b"sivault/owner-control/ML-DSA-65/v1";
const COMMAND_CONTEXT: &[u8] = b"sivault/owner-command/v1";

pub struct OwnerIdentity {
    seed: crypto::Secret,
    public: MLDSA65VerificationKey,
}

/// Owner-level recovery positions, independent of a particular safe.
/// Positions are one-based and ordered as drawn. This type defines no storage
/// or wire representation and never owns the selected secret words.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RecoveryPositions([u8; 3]);

impl RecoveryPositions {
    pub fn generate() -> Result<Self> {
        Self::sample(|| crypto::random::<1>().map(|bytes| bytes[0]))
    }

    pub fn from_positions(positions: [u8; 3]) -> Result<Self> {
        for (i, position) in positions.iter().enumerate() {
            if !(1..=24).contains(position) || positions[..i].contains(position) {
                return Err(Error::InvalidFormat);
            }
        }
        Ok(Self(positions))
    }

    pub fn positions(self) -> [u8; 3] {
        self.0
    }

    /// Select from the canonical output of the existing owner-phrase codec.
    /// The caller must validate the phrase and keep its backing buffer secret.
    pub fn select(self, canonical_phrase: &str) -> Result<[&str; 3]> {
        let mut result = [""; 3];
        let mut count = 0;
        for (i, word) in canonical_phrase.split(' ').enumerate() {
            if i >= 24 || word.is_empty() {
                return Err(Error::InvalidFormat);
            }
            for (target, position) in result.iter_mut().zip(self.0) {
                if usize::from(position) == i + 1 {
                    *target = word;
                }
            }
            count += 1;
        }
        if count != 24 {
            return Err(Error::InvalidFormat);
        }
        Ok(result)
    }

    fn sample(mut byte: impl FnMut() -> Result<u8>) -> Result<Self> {
        let mut positions = [0; 3];
        for i in 0..positions.len() {
            loop {
                let value = byte()?;
                // 240 is the largest multiple of 24 representable below 256.
                if value < 240 {
                    let position = value % 24 + 1;
                    if !positions[..i].contains(&position) {
                        positions[i] = position;
                        break;
                    }
                }
            }
        }
        Ok(Self(positions))
    }
}

impl OwnerIdentity {
    /// The input is the original 256-bit entropy of a validated 24-word phrase.
    pub fn derive(entropy: &crypto::Secret) -> Self {
        let seed = crypto::derive(entropy, CONTROL_SALT, CONTROL_SEED);
        let (_, public) = expand(&seed);
        Self { seed, public }
    }

    pub fn verification_key(&self) -> &MLDSA65VerificationKey {
        &self.public
    }

    pub fn identifier(&self) -> [u8; 32] {
        key_id(&self.public)
    }

    /// Sign an already encoded and scoped owner command, never renderer input.
    pub fn sign_command(&self, transcript: &[u8]) -> Result<MLDSA65Signature> {
        let (private, _) = expand(&self.seed);
        let mut signature = [0; MLDSA65Signature::len()];
        portable::sign_mut(
            &private,
            transcript,
            COMMAND_CONTEXT,
            crypto::random()?,
            &mut signature,
        )
        .map_err(|_| Error::Authentication)?;
        Ok(MLDSA65Signature::new(signature))
    }
}

pub fn key_id(public: &MLDSA65VerificationKey) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"sivault/owner-key-id/ML-DSA-65/v1");
    hash.update(public.as_slice());
    hash.finalize().into()
}

pub fn verify_command(
    public: &MLDSA65VerificationKey,
    transcript: &[u8],
    signature: &MLDSA65Signature,
) -> Result<()> {
    ml_dsa_65::verify(public, transcript, COMMAND_CONTEXT, signature)
        .map_err(|_| Error::Authentication)
}

fn expand(
    seed: &crypto::Secret,
) -> (
    Zeroizing<[u8; MLDSA65SigningKey::len()]>,
    MLDSA65VerificationKey,
) {
    let mut private = Zeroizing::new([0; MLDSA65SigningKey::len()]);
    let mut public = [0; MLDSA65VerificationKey::len()];
    portable::generate_key_pair_mut(**seed, &mut private, &mut public);
    (private, MLDSA65VerificationKey::new(public))
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[test]
    fn recovery_positions_reject_bias_and_duplicates_and_keep_draw_order() {
        let mut draws = [255, 23, 47, 240, 0, 24, 10].into_iter();
        let positions = RecoveryPositions::sample(|| draws.next().ok_or(Error::Random)).unwrap();
        assert_eq!(positions.positions(), [24, 1, 11]);
        assert!(RecoveryPositions::from_positions([1, 1, 24]).is_err());
        assert!(RecoveryPositions::from_positions([1, 25, 24]).is_err());
        assert!(RecoveryPositions::from_positions([0, 1, 24]).is_err());
    }

    #[test]
    fn recovery_selection_uses_exactly_the_existing_phrase_positions() {
        let positions = RecoveryPositions::from_positions([24, 1, 11]).unwrap();
        let phrase = (1..=24)
            .map(|index| format!("fixture{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            positions.select(&phrase).unwrap(),
            ["fixture24", "fixture1", "fixture11"]
        );
        assert!(positions.select(&phrase[9..]).is_err());
        assert!(positions.select(&format!("{phrase} fixture25")).is_err());
    }
}
