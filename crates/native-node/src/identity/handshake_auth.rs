//! Candidate, transport-bound dual signatures for a future reviewed provider.
//!
//! This internal API does not perform a handshake, establish nonce freshness,
//! verify a key exchange or create an authenticated-channel capability. Its
//! separate candidate domain is not the frozen TLS or Noise wire profile.
use super::*;
use crate::p2p::ConnectionRole;

pub(crate) const SIGNATURE_BYTES: usize = 64 + 3309;
const DOMAIN: &[u8] = b"siworld native channel authentication candidate v1\0";
const CONTEXT: &[u8] = b"siworld native channel candidate v1";

/// The provider must derive both hashes from its completed key exchange and
/// exact ordered transcript, and supply independently pinned endpoint keys.
/// Nonzero, distinct nonces are structural checks, not evidence of freshness.
#[derive(Clone)]
pub(crate) struct Transcript {
    binding: Binding,
    sender: ConnectionRole,
    endpoints: [Hash; 2],
    nonces: [Hash; 2],
    transport_hash: Hash,
    prefix_hash: Hash,
}
impl Transcript {
    pub(crate) fn new(
        binding: Binding,
        sender: ConnectionRole,
        endpoints: [Hash; 2],
        nonces: [Hash; 2],
        transport_hash: Hash,
        prefix_hash: Hash,
    ) -> Result<Self, Error> {
        let value = Self {
            binding,
            sender,
            endpoints,
            nonces,
            transport_hash,
            prefix_hash,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), Error> {
        check_binding(&self.binding)?;
        if self.endpoints.contains(&[0; 32])
            || self.endpoints[0] == self.endpoints[1]
            || self.nonces.contains(&[0; 32])
            || self.nonces[0] == self.nonces[1]
            || self.transport_hash == [0; 32]
            || self.prefix_hash == [0; 32]
        {
            return Err(Error::InvalidRecord);
        }
        Ok(())
    }
    fn sender_fingerprint(&self) -> Hash {
        self.endpoints[match self.sender {
            ConnectionRole::Initiator => 0,
            ConnectionRole::Responder => 1,
        }]
    }
    fn message(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(DOMAIN.len() + 96 + 1 + 32 * 6);
        result.extend_from_slice(DOMAIN);
        result.extend_from_slice(&self.binding.network);
        result.extend_from_slice(&self.binding.genesis);
        result.extend_from_slice(&self.binding.verifier);
        result.push(match self.sender {
            ConnectionRole::Initiator => 1,
            ConnectionRole::Responder => 2,
        });
        for field in self
            .endpoints
            .iter()
            .chain(self.nonces.iter())
            .chain([&self.transport_hash, &self.prefix_hash])
        {
            result.extend_from_slice(field);
        }
        result
    }
}

pub(crate) struct Signatures {
    ed25519: [u8; 64],
    ml_dsa: [u8; 3309],
}
impl Signatures {
    pub(crate) fn encode(&self) -> [u8; SIGNATURE_BYTES] {
        let mut result = [0; SIGNATURE_BYTES];
        result[..64].copy_from_slice(&self.ed25519);
        result[64..].copy_from_slice(&self.ml_dsa);
        result
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SIGNATURE_BYTES {
            return Err(Error::InvalidRecord);
        }
        Ok(Self {
            ed25519: bytes[..64].try_into().map_err(|_| Error::InvalidRecord)?,
            ml_dsa: bytes[64..].try_into().map_err(|_| Error::InvalidRecord)?,
        })
    }
}

fn fingerprint(identity: &NativeIdentity) -> Hash {
    // Possession signatures do not enter the public fingerprint.
    Descriptor {
        binding: identity.binding,
        ed25519_public: identity.ed25519.verifying_key().to_bytes(),
        ml_dsa_public: identity.ml_dsa_public,
        ed25519_signature: [0; 64],
        ml_dsa_signature: [0; 3309],
    }
    .fingerprint()
}
impl NativeIdentity {
    pub(crate) fn sign_channel_transcript(
        &self,
        transcript: &Transcript,
    ) -> Result<Signatures, Error> {
        transcript.validate()?;
        if self.binding != transcript.binding
            || fingerprint(self) != transcript.sender_fingerprint()
        {
            return Err(Error::ContextMismatch);
        }
        let message = transcript.message();
        let mut randomness = Zeroizing::new([0; 32]);
        getrandom::fill(randomness.as_mut()).map_err(|_| Error::Entropy)?;
        Ok(Signatures {
            ed25519: self.ed25519.sign(&message).to_bytes(),
            ml_dsa: *ml_dsa_65::sign(&self.ml_dsa, &message, CONTEXT, *randomness)
                .map_err(|_| Error::Signature)?
                .as_ref(),
        })
    }
}
impl Descriptor {
    pub(crate) fn verify_channel_transcript(
        &self,
        transcript: &Transcript,
        signatures: &Signatures,
    ) -> Result<(), Error> {
        transcript.validate()?;
        self.verify(&transcript.binding)?;
        if self.fingerprint() != transcript.sender_fingerprint() {
            return Err(Error::UnexpectedPeer);
        }
        let message = transcript.message();
        VerifyingKey::from_bytes(&self.ed25519_public)
            .map_err(|_| Error::Signature)?
            .verify_strict(&message, &EdSignature::from_bytes(&signatures.ed25519))
            .map_err(|_| Error::Signature)?;
        ml_dsa_65::verify(
            &MLDSA65VerificationKey::new(self.ml_dsa_public),
            &message,
            CONTEXT,
            &MLDSA65Signature::new(signatures.ml_dsa),
        )
        .map_err(|_| Error::Signature)
    }
}

#[cfg(test)]
mod tests;
