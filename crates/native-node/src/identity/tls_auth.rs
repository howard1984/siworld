//! Typed signatures for the six-frame TLS-exporter authentication profile.

use super::*;
use crate::p2p::ConnectionRole;

pub(crate) const TLS_SIGNATURE_BYTES: usize = 64 + 3309;
const DOMAIN: &[u8] = b"siworld native hybrid authentication v1\0";
const CONTEXT: &[u8] = b"siworld native hybrid v1";

/// The ordered transcript digest is computed by the TLS authentication runner.
/// The context and endpoints are checked locally before either key signs.
#[derive(Clone)]
pub(crate) struct TlsAuthentication {
    binding: Binding,
    sender: ConnectionRole,
    endpoints: [Hash; 2],
    prefix_hash: Hash,
}
impl TlsAuthentication {
    pub(crate) fn new(
        binding: Binding,
        sender: ConnectionRole,
        endpoints: [Hash; 2],
        prefix_hash: Hash,
    ) -> Result<Self, Error> {
        let result = Self {
            binding,
            sender,
            endpoints,
            prefix_hash,
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<(), Error> {
        check_binding(&self.binding)?;
        if self.endpoints.contains(&[0; 32]) || self.endpoints[0] == self.endpoints[1] {
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

    fn message(&self) -> [u8; DOMAIN.len() + 1 + 32] {
        let mut bytes = [0; DOMAIN.len() + 1 + 32];
        bytes[..DOMAIN.len()].copy_from_slice(DOMAIN);
        bytes[DOMAIN.len()] = match self.sender {
            ConnectionRole::Initiator => 1,
            ConnectionRole::Responder => 2,
        };
        bytes[DOMAIN.len() + 1..].copy_from_slice(&self.prefix_hash);
        bytes
    }
}

pub(crate) struct TlsSignatures {
    ed25519: [u8; 64],
    ml_dsa: [u8; 3309],
}
impl TlsSignatures {
    pub(crate) fn encode(&self) -> [u8; TLS_SIGNATURE_BYTES] {
        let mut bytes = [0; TLS_SIGNATURE_BYTES];
        bytes[..64].copy_from_slice(&self.ed25519);
        bytes[64..].copy_from_slice(&self.ml_dsa);
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != TLS_SIGNATURE_BYTES {
            return Err(Error::InvalidRecord);
        }
        Ok(Self {
            ed25519: bytes[..64].try_into().map_err(|_| Error::InvalidRecord)?,
            ml_dsa: bytes[64..].try_into().map_err(|_| Error::InvalidRecord)?,
        })
    }
}

fn fingerprint(identity: &NativeIdentity) -> Hash {
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
    pub(crate) fn sign_tls_authentication(
        &self,
        transcript: &TlsAuthentication,
    ) -> Result<TlsSignatures, Error> {
        let mut randomness = Zeroizing::new([0; 32]);
        getrandom::fill(randomness.as_mut()).map_err(|_| Error::Entropy)?;
        self.sign_tls_authentication_with_randomness(transcript, randomness)
    }

    fn sign_tls_authentication_with_randomness(
        &self,
        transcript: &TlsAuthentication,
        randomness: Zeroizing<[u8; 32]>,
    ) -> Result<TlsSignatures, Error> {
        transcript.validate()?;
        if self.binding != transcript.binding
            || fingerprint(self) != transcript.sender_fingerprint()
        {
            return Err(Error::ContextMismatch);
        }
        let message = transcript.message();
        Ok(TlsSignatures {
            ed25519: self.ed25519.sign(&message).to_bytes(),
            ml_dsa: *ml_dsa_65::sign(&self.ml_dsa, &message, CONTEXT, *randomness)
                .map_err(|_| Error::Signature)?
                .as_ref(),
        })
    }
}

impl Descriptor {
    pub(crate) fn verify_tls_authentication(
        &self,
        transcript: &TlsAuthentication,
        signatures: &TlsSignatures,
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
pub(crate) fn fixture_identity(binding: Binding, tag: u8) -> NativeIdentity {
    NativeIdentity::from_seeds(binding, &[tag; 32], &[tag.wrapping_add(1); 32])
}

#[cfg(test)]
pub(crate) fn fixture_sign(
    identity: &NativeIdentity,
    message: &TlsAuthentication,
) -> Result<TlsSignatures, Error> {
    identity.sign_tls_authentication_with_randomness(message, Zeroizing::new([0; 32]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Binding {
        Binding {
            network: [1; 32],
            genesis: [2; 32],
            verifier: [3; 32],
        }
    }

    fn message(first: &NativeIdentity, second: &NativeIdentity) -> TlsAuthentication {
        TlsAuthentication::new(
            binding(),
            ConnectionRole::Initiator,
            [
                first.descriptor().unwrap().fingerprint(),
                second.descriptor().unwrap().fingerprint(),
            ],
            [8; 32],
        )
        .unwrap()
    }

    #[test]
    fn tls_requires_both_signatures_and_exact_encoding() {
        let first = fixture_identity(binding(), 4);
        let second = fixture_identity(binding(), 6);
        let message = message(&first, &second);
        let descriptor = first.descriptor().unwrap();
        let bytes = first.sign_tls_authentication(&message).unwrap().encode();
        assert_eq!(bytes.len(), 3373);
        descriptor
            .verify_tls_authentication(&message, &TlsSignatures::decode(&bytes).unwrap())
            .unwrap();
        for missing in [0..64, 64..TLS_SIGNATURE_BYTES] {
            let mut changed = bytes;
            changed[missing].fill(0);
            assert!(
                descriptor
                    .verify_tls_authentication(&message, &TlsSignatures::decode(&changed).unwrap())
                    .is_err()
            );
        }
        assert!(TlsSignatures::decode(&bytes[..TLS_SIGNATURE_BYTES - 1]).is_err());
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(TlsSignatures::decode(&extra).is_err());
    }

    #[test]
    fn tls_signatures_reject_role_context_prefix_and_identity_replay() {
        let first = fixture_identity(binding(), 4);
        let second = fixture_identity(binding(), 6);
        let original = message(&first, &second);
        let signature = first.sign_tls_authentication(&original).unwrap();
        let descriptor = first.descriptor().unwrap();
        for field in 0..7 {
            let mut changed = original.clone();
            match field {
                0 => changed.binding.network[0] ^= 1,
                1 => changed.binding.genesis[0] ^= 1,
                2 => changed.binding.verifier[0] ^= 1,
                3 => changed.sender = ConnectionRole::Responder,
                4 => changed.endpoints[0][0] ^= 1,
                5 => {
                    changed.endpoints[1][0] ^= 1;
                    // The authentication runner hashes both endpoints into
                    // the prefix before constructing this typed message.
                    changed.prefix_hash[0] ^= 1;
                }
                _ => changed.prefix_hash[0] ^= 1,
            }
            assert!(
                descriptor
                    .verify_tls_authentication(&changed, &signature)
                    .is_err()
            );
        }
        assert!(second.sign_tls_authentication(&original).is_err());
        let possession = descriptor.encode();
        assert!(
            descriptor
                .verify_tls_authentication(
                    &original,
                    &TlsSignatures::decode(&possession[possession.len() - TLS_SIGNATURE_BYTES..])
                        .unwrap()
                )
                .is_err()
        );
        let candidate = super::super::handshake_auth::Transcript::new(
            binding(),
            ConnectionRole::Initiator,
            original.endpoints,
            [[9; 32], [10; 32]],
            [11; 32],
            original.prefix_hash,
        )
        .unwrap();
        let candidate = first.sign_channel_transcript(&candidate).unwrap().encode();
        assert!(
            descriptor
                .verify_tls_authentication(&original, &TlsSignatures::decode(&candidate).unwrap())
                .is_err()
        );
    }

    #[test]
    fn tls_rejects_invalid_or_reflected_endpoint_contexts() {
        let first = fixture_identity(binding(), 4);
        let second = fixture_identity(binding(), 6);
        let original = message(&first, &second);
        for field in 0..4 {
            let mut changed = original.clone();
            match field {
                0 => changed.binding.network = [0; 32],
                1 => changed.endpoints[0] = [0; 32],
                2 => changed.endpoints[1] = changed.endpoints[0],
                _ => changed.endpoints[0][0] ^= 1,
            }
            assert!(first.sign_tls_authentication(&changed).is_err());
        }
    }
}
