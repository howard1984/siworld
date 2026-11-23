//! Credential primitives for a scoped releaser record. The caller must verify
//! possession and commit the attempt charge before evaluating a client proof.

use crate::{
    Error, Result,
    crypto::{self, Secret},
};
use hkdf::Hkdf;
use libcrux_ml_dsa::ml_dsa_65::{
    self, MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type Word = [u8; 32];

/// Portable folder possession key, separate from the verifier's folder input.
pub struct FolderIdentity {
    signing: MLDSA65SigningKey,
    public: MLDSA65VerificationKey,
}

impl FolderIdentity {
    pub fn derive(folder_secret: &Secret, safe_id: &[u8; 16]) -> Self {
        let seed = crypto::derive(
            folder_secret,
            safe_id,
            b"sivault/folder-possession/ML-DSA-65/v1",
        );
        let keys = ml_dsa_65::generate_key_pair(*seed);
        Self {
            signing: keys.signing_key,
            public: keys.verification_key,
        }
    }

    pub fn signing_key(&self) -> &MLDSA65SigningKey {
        &self.signing
    }

    pub fn verification_key(&self) -> &MLDSA65VerificationKey {
        &self.public
    }
}

impl Drop for FolderIdentity {
    fn drop(&mut self) {
        self.signing.as_mut_slice().zeroize();
    }
}

/// An authenticated channel transcript digest.
///
/// ```compile_fail,E0423
/// use sivault_core::controlled_credential::ChannelBinding;
/// let _ = ChannelBinding([0; 32]);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelBinding(Word);

impl ChannelBinding {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn authenticated(digest: Word) -> Self {
        Self(digest)
    }

    pub fn as_bytes(&self) -> &Word {
        &self.0
    }
}

pub struct RecordContext {
    pub suite: u16,
    pub version: u16,
    pub deployment: Word,
    pub safe: Word,
    pub generation: u64,
    pub slot: Word,
    pub ledger: Word,
    pub operation: u8,
    pub record: Word,
    pub argon_salt: Word,
}

pub struct AttemptContext {
    pub request: Word,
    pub client_nonce: Word,
    pub server_nonce: Word,
    pub challenge: Word,
    pub reply_key_digest: Word,
    pub init_digest: Word,
    pub challenge_digest: Word,
    pub incarnation: Word,
    pub deadline: u64,
    pub channel_binding: ChannelBinding,
}

fn frame(label: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut bytes = b"SIVault/S4/1".to_vec();
    for field in std::iter::once(label).chain(fields.iter().copied()) {
        bytes.extend(
            u32::try_from(field.len())
                .expect("fixed field width")
                .to_be_bytes(),
        );
        bytes.extend(field);
    }
    bytes
}

impl RecordContext {
    pub fn encode(&self) -> Vec<u8> {
        frame(
            b"record",
            &[
                &self.suite.to_be_bytes(),
                &self.version.to_be_bytes(),
                &self.deployment,
                &self.safe,
                &self.generation.to_be_bytes(),
                &self.slot,
                &self.ledger,
                &[self.operation],
                &self.record,
                &self.argon_salt,
            ],
        )
    }
}

impl AttemptContext {
    pub fn encode(&self, record: &RecordContext) -> Vec<u8> {
        frame(
            b"auth",
            &[
                &record.encode(),
                &self.request,
                &self.client_nonce,
                &self.server_nonce,
                &self.challenge,
                &self.reply_key_digest,
                &self.init_digest,
                &self.challenge_digest,
                &self.incarnation,
                &self.deadline.to_be_bytes(),
                self.channel_binding.as_bytes(),
            ],
        )
    }
}

pub struct ClientCredential {
    stretched: Secret,
    client_key: Secret,
    server_key: Secret,
}

pub struct ReleaserVerifier {
    pub stored_key: Word,
    pub server_key: Secret,
}

impl Drop for ReleaserVerifier {
    fn drop(&mut self) {
        self.stored_key.zeroize();
    }
}

fn derive(salt: &[u8; 32], input: &[u8; 32], label: &[u8], record: &RecordContext) -> Secret {
    let mut bytes = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(salt), input)
        .expand(&frame(label, &[&record.encode()]), bytes.as_mut())
        .expect("fixed HKDF output");
    bytes
}

impl ClientCredential {
    pub fn new(password: &str, folder_secret: &Secret, record: &RecordContext) -> Result<Self> {
        Ok(Self::with_stretched(
            crypto::stretch_with_salt(password, &record.argon_salt)?,
            folder_secret,
            record,
        ))
    }

    fn with_stretched(stretched: Secret, folder_secret: &Secret, record: &RecordContext) -> Self {
        let root = derive(folder_secret, &stretched, b"scram-root", record);
        Self {
            stretched,
            client_key: Zeroizing::new(crypto::mac(&root, b"Client Key")),
            server_key: Zeroizing::new(crypto::mac(&root, b"Server Key")),
        }
    }

    pub fn enrollment_verifier(&self) -> ReleaserVerifier {
        ReleaserVerifier {
            stored_key: Sha256::digest(self.client_key.as_ref()).into(),
            server_key: self.server_key.clone(),
        }
    }

    pub fn proof(&self, transcript: &[u8]) -> Word {
        let mut proof = crypto::mac(&Sha256::digest(self.client_key.as_ref()).into(), transcript);
        for (byte, key) in proof.iter_mut().zip(self.client_key.iter()) {
            *byte ^= key;
        }
        proof
    }

    pub fn wrap(&self, record: &RecordContext, share: &Secret, key: &Secret) -> Result<Envelope> {
        let nonce = crypto::random()?;
        let wrap_key = derive(share, &self.stretched, b"wrap-key", record);
        let ciphertext = crypto::seal(
            &wrap_key,
            &nonce,
            &frame(b"wrap-aad", &[&record.encode()]),
            key.as_ref(),
        )?;
        Ok(Envelope {
            nonce,
            ciphertext: ciphertext.try_into().map_err(|_| Error::InvalidFormat)?,
        })
    }

    pub fn verify_and_unwrap(
        self,
        record: &RecordContext,
        transcript: &[u8],
        server_mac: &Word,
        share: &Secret,
        envelope: &Envelope,
    ) -> Result<Secret> {
        crypto::verify_mac(&self.server_key, transcript, server_mac)?;
        let wrap_key = derive(share, &self.stretched, b"wrap-key", record);
        let plaintext = crypto::unseal(
            &wrap_key,
            &envelope.nonce,
            &frame(b"wrap-aad", &[&record.encode()]),
            &envelope.ciphertext,
        )?;
        let mut key = Zeroizing::new([0; 32]);
        if plaintext.len() != key.len() {
            return Err(Error::Authentication);
        }
        key.copy_from_slice(&plaintext);
        Ok(key)
    }
}

pub struct Envelope {
    pub nonce: [u8; 24],
    pub ciphertext: [u8; 48],
}

impl ReleaserVerifier {
    /// Evaluate only after consuming the live attempt and committing its charge.
    pub fn evaluate_charged_proof(&self, transcript: &[u8], proof: &Word) -> Result<Word> {
        let mut candidate = Zeroizing::new(crypto::mac(&self.stored_key, transcript));
        for (byte, proof_byte) in candidate.iter_mut().zip(proof) {
            *byte ^= proof_byte;
        }
        let digest: Word = Sha256::digest(candidate.as_ref()).into();
        if !bool::from(self.stored_key.ct_eq(&digest)) {
            return Err(Error::Authentication);
        }
        Ok(crypto::mac(&self.server_key, transcript))
    }
}

pub fn sign_possession(key: &MLDSA65SigningKey, transcript: &[u8]) -> Result<MLDSA65Signature> {
    ml_dsa_65::sign(
        key,
        &frame(b"possession", &[transcript]),
        b"",
        crypto::random()?,
    )
    .map_err(|_| Error::Authentication)
}

pub fn verify_possession(
    key: &MLDSA65VerificationKey,
    transcript: &[u8],
    signature: &MLDSA65Signature,
) -> Result<()> {
    ml_dsa_65::verify(key, &frame(b"possession", &[transcript]), b"", signature)
        .map_err(|_| Error::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contexts() -> (RecordContext, AttemptContext) {
        (
            RecordContext {
                suite: 1,
                version: 1,
                deployment: [1; 32],
                safe: [2; 32],
                generation: 3,
                slot: [4; 32],
                ledger: [5; 32],
                operation: 1,
                record: [6; 32],
                argon_salt: [7; 32],
            },
            AttemptContext {
                request: [8; 32],
                client_nonce: [9; 32],
                server_nonce: [10; 32],
                challenge: [11; 32],
                reply_key_digest: [12; 32],
                init_digest: [13; 32],
                challenge_digest: [14; 32],
                incarnation: [15; 32],
                deadline: 80,
                channel_binding: ChannelBinding([16; 32]),
            },
        )
    }

    #[test]
    fn fixed_transcript_and_wrong_scope() {
        let (record, mut attempt) = contexts();
        let bytes = attempt.encode(&record);
        let client = ClientCredential::with_stretched(
            Zeroizing::new([0x21; 32]),
            &Zeroizing::new([0x22; 32]),
            &record,
        );
        let verifier = client.enrollment_verifier();
        let proof = client.proof(&bytes);
        let reply = verifier.evaluate_charged_proof(&bytes, &proof).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(record.encode())),
            "404fb1468218f1bfb601b1f514bf2912d2d4c82bfecaddb2f887f9e6c7027766"
        );
        let wrap_key = derive(&[0x23; 32], &client.stretched, b"wrap-key", &record);
        assert_eq!(
            format!("{:x}", sha2::digest::Output::<Sha256>::from(*wrap_key)),
            "91c0b7324df9eb02b3ec08d32574424a6b1f8eaf09def62036977c8ee35780ff"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            "d46d346df946ca9a3916a588cdf20678664d45c48e0c88d6ea7502019a685e4e"
        );
        assert_eq!(
            format!("{:x}", sha2::digest::Output::<Sha256>::from(proof)),
            "3f72c476068e16947ec7039b3c7b82d4e04a7ccfb53919b5245d30b64f0bdefd"
        );
        assert_eq!(
            format!("{:x}", sha2::digest::Output::<Sha256>::from(reply)),
            "f4c2e08b680a90f630a61993b68fcd36f052f00b910833ad4c645eb7579833f7"
        );
        attempt.channel_binding.0[0] ^= 1;
        assert!(
            verifier
                .evaluate_charged_proof(&attempt.encode(&record), &proof)
                .is_err()
        );
        let keys = ml_dsa_65::generate_key_pair([0x24; 32]);
        let signature = sign_possession(&keys.signing_key, &bytes).unwrap();
        verify_possession(&keys.verification_key, &bytes, &signature).unwrap();
        assert!(
            verify_possession(&keys.verification_key, &attempt.encode(&record), &signature)
                .is_err()
        );
    }

    #[test]
    fn password_derivation_normalizes_and_rejects_wrong_proof() {
        let (record, attempt) = contexts();
        let folder_secret = Zeroizing::new([0x22; 32]);
        let enrolled = ClientCredential::new("caf\u{e9}", &folder_secret, &record).unwrap();
        let verifier = enrolled.enrollment_verifier();
        let transcript = attempt.encode(&record);
        let equivalent = ClientCredential::new("cafe\u{301}", &folder_secret, &record).unwrap();
        let wrong = ClientCredential::new("cafe", &folder_secret, &record).unwrap();
        assert!(
            verifier
                .evaluate_charged_proof(&transcript, &equivalent.proof(&transcript))
                .is_ok()
        );
        assert!(
            verifier
                .evaluate_charged_proof(&transcript, &wrong.proof(&transcript))
                .is_err()
        );
    }

    #[test]
    fn result_requires_server_mac_and_matching_share() {
        let (record, attempt) = contexts();
        let make_client = || {
            ClientCredential::with_stretched(
                Zeroizing::new([0x21; 32]),
                &Zeroizing::new([0x22; 32]),
                &record,
            )
        };
        let bytes = attempt.encode(&record);
        let share = Zeroizing::new([0x23; 32]);
        let content = Zeroizing::new([0x24; 32]);
        let client = make_client();
        let envelope = client.wrap(&record, &share, &content).unwrap();
        let reply = client
            .enrollment_verifier()
            .evaluate_charged_proof(&bytes, &client.proof(&bytes))
            .unwrap();
        assert!(
            make_client()
                .verify_and_unwrap(&record, &bytes, &[0; 32], &share, &envelope)
                .is_err()
        );
        assert!(
            make_client()
                .verify_and_unwrap(
                    &record,
                    &bytes,
                    &reply,
                    &Zeroizing::new([0x25; 32]),
                    &envelope,
                )
                .is_err()
        );
        assert_eq!(
            *client
                .verify_and_unwrap(&record, &bytes, &reply, &share, &envelope)
                .unwrap(),
            *content
        );
    }
}
