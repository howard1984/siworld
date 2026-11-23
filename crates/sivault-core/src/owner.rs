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
