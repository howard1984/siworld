//! Domain-separated seals for locally verified storage checkpoints.
//! A local seal is not a remote checkpoint-authority quorum.
use super::*;
const DOMAIN: &[u8] = b"siworld locally verified storage checkpoint v1\0";
const CONTEXT: &[u8] = b"siworld local storage v1";
pub(crate) const SEAL_BYTES: usize = 64 + 3309;

fn message(binding: &Binding, digest: Hash) -> Vec<u8> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&binding.network);
    bytes.extend_from_slice(&binding.genesis);
    bytes.extend_from_slice(&binding.verifier);
    bytes.extend_from_slice(&digest);
    bytes
}
impl NativeIdentity {
    pub(crate) fn seal_local_storage(&self, digest: Hash) -> Result<[u8; SEAL_BYTES], Error> {
        let message = message(&self.binding, digest);
        let mut result = [0; SEAL_BYTES];
        result[..64].copy_from_slice(&self.ed25519.sign(&message).to_bytes());
        let mut randomness = Zeroizing::new([0; 32]);
        getrandom::fill(randomness.as_mut()).map_err(|_| Error::Entropy)?;
        result[64..].copy_from_slice(
            ml_dsa_65::sign(&self.ml_dsa, &message, CONTEXT, *randomness)
                .map_err(|_| Error::Signature)?
                .as_ref(),
        );
        Ok(result)
    }
}
impl Descriptor {
    pub(crate) fn verify_local_storage(&self, digest: Hash, seal: &[u8]) -> Result<(), Error> {
        if seal.len() != SEAL_BYTES {
            return Err(Error::InvalidRecord);
        }
        let message = message(&self.binding, digest);
        VerifyingKey::from_bytes(&self.ed25519_public)
            .map_err(|_| Error::Signature)?
            .verify_strict(
                &message,
                &EdSignature::from_bytes(&seal[..64].try_into().map_err(|_| Error::InvalidRecord)?),
            )
            .map_err(|_| Error::Signature)?;
        ml_dsa_65::verify(
            &MLDSA65VerificationKey::new(self.ml_dsa_public),
            &message,
            CONTEXT,
            &MLDSA65Signature::new(seal[64..].try_into().map_err(|_| Error::InvalidRecord)?),
        )
        .map_err(|_| Error::Signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_storage_seals_require_both_signatures_and_the_exact_content() {
        let binding = Binding::new(&crate::state::Config::development([17; 32], 0).unwrap());
        let identity = NativeIdentity::from_seeds(binding, &[1; 32], &[2; 32]);
        let descriptor = identity.descriptor().unwrap();
        let seal = identity.seal_local_storage([3; 32]).unwrap();
        descriptor.verify_local_storage([3; 32], &seal).unwrap();
        assert!(descriptor.verify_local_storage([4; 32], &seal).is_err());
        for offset in [0, 64] {
            let mut bad = seal;
            bad[offset] ^= 1;
            assert!(descriptor.verify_local_storage([3; 32], &bad).is_err());
        }
    }
}
