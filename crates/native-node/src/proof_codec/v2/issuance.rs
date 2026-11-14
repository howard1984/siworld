//! Verification-only adapter for an inactive, locally pinned V2 issuance.
//!
//! Proof validity does not establish issuer authorization, the active fee
//! policy, fee-output membership or uniqueness, or a block/state capability.
//! The enclosing transition must independently validate those properties.
use super::backend::{Config, IssuanceVerifier, Profile};
use super::native::{DecodeError, NativeProofShape};
use super::{FrameError, Identity, MAX_ISSUANCE_PROOF_BYTES, ProtocolBinding, Relation};
use crate::issuance::{CIPHERTEXT_BYTES, INITIAL_NOTES, IssuanceRecord};
use crate::proof_codec::ProofDecodeError;
use ::native::issuance::IssuanceError;
use p3_uni_stark::PreprocessedVerifierKey;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
    LocalBinding,
    TrustedShape(ProofDecodeError),
    IdentityMismatch,
    Network,
    RecordShape,
    Ciphertext(IssuanceError),
    Frame(FrameError),
    Body(ProofDecodeError),
    InvalidProof,
}

/// Fixed three-note proof verification; never creates or retains a prover.
pub struct FixedIssuanceVerifier {
    network: [u8; 32],
    verifier: IssuanceVerifier,
    shape: NativeProofShape,
}

impl FixedIssuanceVerifier {
    /// Authenticate every input independently from the received record. The
    /// expected identity pins the complete derived key/profile/AIR binding;
    /// nonzero identifiers alone are not registry authentication.
    pub fn from_trusted(
        network: [u8; 32],
        profile: Profile,
        binding: ProtocolBinding,
        key: PreprocessedVerifierKey<Config>,
        expected: Identity,
    ) -> Result<Self, VerificationError> {
        if network == [0; 32]
            || binding.genesis == [0; 32]
            || binding.rules == [0; 32]
            || binding.air == [0; 32]
            || expected.relation != Relation::Issuance
            || expected.profile == [0; 32]
        {
            return Err(VerificationError::LocalBinding);
        }
        let verifier = IssuanceVerifier::from_trusted_key(INITIAL_NOTES, profile, key);
        let shape = NativeProofShape::from_trusted(
            &verifier.air,
            verifier.verification_key(),
            verifier.public_config(),
            profile,
            Relation::Issuance,
            binding,
            MAX_ISSUANCE_PROOF_BYTES,
        )
        .map_err(VerificationError::TrustedShape)?;
        if shape.identity() != expected {
            return Err(VerificationError::IdentityMismatch);
        }
        Ok(Self {
            network,
            verifier,
            shape,
        })
    }

    /// Rebuild the statement from the complete bounded declaration, including
    /// its metadata, ciphertext digests and ordered note commitments. This is
    /// proof verification only, even though the record carries a signature.
    pub fn verify_record(&self, record: &IssuanceRecord) -> Result<(), VerificationError> {
        if record.signed.declaration.network != self.network {
            return Err(VerificationError::Network);
        }
        record
            .validate_shape()
            .map_err(|_| VerificationError::RecordShape)?;
        record
            .signed
            .declaration
            .validate_ciphertexts(&record.ciphertexts, CIPHERTEXT_BYTES)
            .map_err(VerificationError::Ciphertext)?;
        let proof = self
            .shape
            .decode(&record.proof)
            .map_err(|error| match error {
                DecodeError::Frame(error) => VerificationError::Frame(error),
                DecodeError::Body(error) => VerificationError::Body(error),
            })?;
        self.verifier
            .verify(&proof, &record.signed.declaration.public_inputs())
            .map_err(|_| VerificationError::InvalidProof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::native::FriParams;
    use ::native::issuance::{AssetMetadata, IssuanceDeclaration, SignedIssuance};
    use ::native::issuance_air::IssuanceAir;
    use ::native::multi_asset::{AssetId, F};
    use p3_field::PrimeCharacteristicRing;
    use p3_symmetric::MerkleCap;

    const NETWORK: [u8; 32] = [7; 32];
    const BINDING: ProtocolBinding = ProtocolBinding {
        genesis: [1; 32],
        rules: [2; 32],
        air: [3; 32],
    };

    fn profile() -> Profile {
        // Structural fixtures only, not a registered security profile.
        Profile::new(FriParams {
            log_blowup: 1,
            num_queries: 1,
            query_pow_bits: 0,
            commit_pow_bits: 0,
            batch_pow_bits: 0,
            max_log_arity: 1,
        })
        .unwrap()
    }

    fn configuration() -> (PreprocessedVerifierKey<Config>, Identity) {
        let air = IssuanceAir::new(INITIAL_NOTES).with_min_height(profile().minimum_height());
        // Synthetic public roots support rejection tests, not a valid proof.
        let key = PreprocessedVerifierKey {
            width: air.preprocessed_width(),
            degree_bits: air.degree_bits() + 1,
            commitment: MerkleCap::new(vec![[F::ZERO; 12]; 2]),
        };
        let verifier = IssuanceVerifier::from_trusted_key(INITIAL_NOTES, profile(), key.clone());
        let identity = NativeProofShape::from_trusted(
            &verifier.air,
            &key,
            verifier.public_config(),
            profile(),
            Relation::Issuance,
            BINDING,
            MAX_ISSUANCE_PROOF_BYTES,
        )
        .unwrap()
        .identity();
        (key, identity)
    }

    fn verifier() -> FixedIssuanceVerifier {
        let (key, identity) = configuration();
        FixedIssuanceVerifier::from_trusted(NETWORK, profile(), BINDING, key, identity).unwrap()
    }

    fn record(proof: Vec<u8>) -> IssuanceRecord {
        let ciphertexts = vec![vec![0; CIPHERTEXT_BYTES]; INITIAL_NOTES];
        let ciphertext_digest = *blake3::hash(&ciphertexts[0]).as_bytes();
        IssuanceRecord {
            signed: SignedIssuance {
                declaration: IssuanceDeclaration {
                    network: NETWORK,
                    version: 1,
                    issuer_key: [0; ::native::issuance::ISSUER_KEY_BYTES],
                    sequence: 0,
                    asset_id: AssetId([0; 32]),
                    public_supply: 1,
                    metadata: AssetMetadata {
                        name: String::new(),
                        decimals: 0,
                    },
                    issuance_fee_atoms: 0,
                    note_commitments: (1..=INITIAL_NOTES)
                        .map(|i| [F::from_u32(i as u32); 12])
                        .collect(),
                    note_ciphertext_digests: vec![ciphertext_digest; INITIAL_NOTES],
                },
                // Shape-only public bytes; no valid signature is claimed.
                signature: Some([0; ::native::issuance::ISSUER_SIGNATURE_BYTES]),
            },
            ciphertexts,
            proof,
            fee_commitment: [0; 48],
            fee_rho: [0; 48],
        }
    }

    #[test]
    fn rejects_missing_local_bindings_and_nonissuance_identity() {
        let (key, identity) = configuration();
        for binding in [
            ProtocolBinding {
                genesis: [0; 32],
                ..BINDING
            },
            ProtocolBinding {
                rules: [0; 32],
                ..BINDING
            },
            ProtocolBinding {
                air: [0; 32],
                ..BINDING
            },
        ] {
            assert!(matches!(
                FixedIssuanceVerifier::from_trusted(
                    NETWORK,
                    profile(),
                    binding,
                    key.clone(),
                    identity
                ),
                Err(VerificationError::LocalBinding)
            ));
        }
        for (network, expected) in [
            ([0; 32], identity),
            (
                NETWORK,
                Identity {
                    relation: Relation::Transaction,
                    ..identity
                },
            ),
            (
                NETWORK,
                Identity {
                    profile: [0; 32],
                    ..identity
                },
            ),
        ] {
            assert!(matches!(
                FixedIssuanceVerifier::from_trusted(
                    network,
                    profile(),
                    BINDING,
                    key.clone(),
                    expected
                ),
                Err(VerificationError::LocalBinding)
            ));
        }
    }

    #[test]
    fn independently_pinned_identity_rejects_changed_key_profile_and_air() {
        let (key, identity) = configuration();
        let mut different_key = key.clone();
        different_key.commitment = MerkleCap::new(vec![[F::ONE; 12]; 2]);
        let different_profile = Profile::new(FriParams {
            num_queries: 2,
            ..profile().params()
        })
        .unwrap();
        for (selected_profile, selected_binding, selected_key) in [
            (profile(), BINDING, different_key),
            (different_profile, BINDING, key.clone()),
            (
                profile(),
                ProtocolBinding {
                    air: [4; 32],
                    ..BINDING
                },
                key.clone(),
            ),
        ] {
            assert!(matches!(
                FixedIssuanceVerifier::from_trusted(
                    NETWORK,
                    selected_profile,
                    selected_binding,
                    selected_key,
                    identity
                ),
                Err(VerificationError::IdentityMismatch)
            ));
        }
        let mut invalid_key = key;
        invalid_key.width = 0;
        assert!(matches!(
            FixedIssuanceVerifier::from_trusted(NETWORK, profile(), BINDING, invalid_key, identity),
            Err(VerificationError::TrustedShape(
                ProofDecodeError::InvalidTrustedShape
            ))
        ));
    }

    #[test]
    fn rejects_network_shape_and_ciphertext_binding_before_frame_decoding() {
        let verifier = verifier();
        let mut changed = record(vec![0]);
        changed.signed.declaration.network = [8; 32];
        assert_eq!(
            verifier.verify_record(&changed),
            Err(VerificationError::Network)
        );
        let mut changed = record(Vec::new());
        assert_eq!(
            verifier.verify_record(&changed),
            Err(VerificationError::RecordShape)
        );
        changed.proof = vec![0];
        changed.ciphertexts[0].pop();
        assert_eq!(
            verifier.verify_record(&changed),
            Err(VerificationError::RecordShape)
        );
        let mut changed = record(vec![0]);
        changed.signed.declaration.note_commitments.pop();
        assert_eq!(
            verifier.verify_record(&changed),
            Err(VerificationError::RecordShape)
        );
        let mut changed = record(vec![0]);
        changed.signed.declaration.version = 2;
        assert_eq!(
            verifier.verify_record(&changed),
            Err(VerificationError::RecordShape)
        );
        let mut changed = record(vec![0]);
        changed.signed.signature = None;
        assert_eq!(
            verifier.verify_record(&changed),
            Err(VerificationError::RecordShape)
        );
        let mut changed = record(vec![0]);
        changed.signed.declaration.metadata.name =
            "x".repeat(crate::issuance::METADATA_CODEC_LIMIT);
        assert_eq!(
            verifier.verify_record(&changed),
            Err(VerificationError::RecordShape)
        );
        let mut changed = record(vec![0]);
        changed.ciphertexts[0][0] ^= 1;
        assert_eq!(
            verifier.verify_record(&changed),
            Err(VerificationError::Ciphertext(
                IssuanceError::CiphertextBindingMismatch
            ))
        );
    }

    #[test]
    fn rejects_frame_identity_cap_trailing_bytes_and_malformed_body() {
        let verifier = verifier();
        let identity = verifier.shape.identity();
        for wrong in [
            Identity {
                profile: [42; 32],
                ..identity
            },
            Identity {
                relation: Relation::Transaction,
                ..identity
            },
        ] {
            let frame = super::super::encode(wrong, &[0], MAX_ISSUANCE_PROOF_BYTES).unwrap();
            assert_eq!(
                verifier.verify_record(&record(frame)),
                Err(VerificationError::Frame(FrameError::Identity))
            );
        }
        assert_eq!(
            verifier.verify_record(&record(vec![0; MAX_ISSUANCE_PROOF_BYTES + 1])),
            Err(VerificationError::RecordShape)
        );
        let frame = super::super::encode(identity, &[0], MAX_ISSUANCE_PROOF_BYTES).unwrap();
        assert!(matches!(
            verifier.verify_record(&record(frame.clone())),
            Err(VerificationError::Body(_))
        ));
        let mut trailing = frame;
        trailing.push(0);
        assert_eq!(
            verifier.verify_record(&record(trailing)),
            Err(VerificationError::Frame(FrameError::Size))
        );
    }

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExistingFixture {
        network: [u8; 32],
        genesis: [u8; 32],
        rules: [u8; 32],
        air: [u8; 32],
        expected_identity: [u8; 32],
        fri_parameters: [u32; 6],
        key_width: usize,
        key_degree_bits: usize,
        key_commitment: Vec<u8>,
        issuance_record: Vec<u8>,
    }

    #[test]
    #[ignore = "requires a pinned existing V2 issuance proof with its complete original declaration, ciphertexts, key and profile"]
    fn existing_valid_proof_rejects_declaration_ciphertext_and_proof_mutations() {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        const FIXTURE_LIMIT: usize = 4 * 1024 * 1024;
        let path = std::env::var_os("SIWORLD_V2_ISSUANCE_FIXTURE")
            .expect("an independently reviewed existing fixture path is required");
        let pin = std::env::var("SIWORLD_V2_ISSUANCE_FIXTURE_SHA256")
            .expect("the independently pinned fixture SHA-256 is required");
        assert_eq!(pin.len(), 64);
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .unwrap()
            .take(FIXTURE_LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(!bytes.is_empty() && bytes.len() <= FIXTURE_LIMIT);
        let expected: Vec<_> = pin
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(actual.as_slice(), expected.as_slice());
        let fixture: ExistingFixture = serde_json::from_slice(&bytes).unwrap();
        assert!(fixture.key_commitment.len() <= 4096);
        assert!(!fixture.issuance_record.is_empty());
        assert!(fixture.issuance_record.len() <= crate::issuance::MAX_RECORD_BYTES);
        let (commitment, tail) = postcard::take_from_bytes(&fixture.key_commitment).unwrap();
        assert!(tail.is_empty());
        assert_eq!(
            postcard::to_allocvec(&commitment).unwrap(),
            fixture.key_commitment
        );
        let [
            log_blowup,
            num_queries,
            query_pow_bits,
            commit_pow_bits,
            batch_pow_bits,
            max_log_arity,
        ] = fixture.fri_parameters;
        let profile = Profile::new(FriParams {
            log_blowup,
            num_queries,
            query_pow_bits,
            commit_pow_bits,
            batch_pow_bits,
            max_log_arity,
        })
        .unwrap();
        let verifier = FixedIssuanceVerifier::from_trusted(
            fixture.network,
            profile,
            ProtocolBinding {
                genesis: fixture.genesis,
                rules: fixture.rules,
                air: fixture.air,
            },
            PreprocessedVerifierKey {
                width: fixture.key_width,
                degree_bits: fixture.key_degree_bits,
                commitment,
            },
            Identity {
                relation: Relation::Issuance,
                profile: fixture.expected_identity,
            },
        )
        .unwrap();
        // Fee-opening envelope fields are not authenticated by this proof.
        // Their provenance and payment validity remain separate obligations.
        let original = IssuanceRecord::decode(&fixture.issuance_record).unwrap();
        assert_eq!(original.encode().unwrap(), fixture.issuance_record);
        // Every mutation assertion depends on genuine verification success.
        assert_eq!(verifier.verify_record(&original), Ok(()));
        assert_eq!(original.signed.verify_signature(), Ok(()));
        // The proof-only adapter must not be mistaken for issuer authorization
        // or payment validation. These envelope fields are outside its proof.
        assert_eq!(original.fee_commitment, [0; 48]);
        assert_eq!(original.fee_rho, [0; 48]);
        let mut unauthorized = original.clone();
        unauthorized.signed.signature.as_mut().unwrap()[0] ^= 1;
        assert!(unauthorized.signed.verify_signature().is_err());
        assert_eq!(verifier.verify_record(&unauthorized), Ok(()));
        let mut different_opening = original.clone();
        different_opening.fee_commitment[0] = 1;
        different_opening.fee_rho[0] = 1;
        assert_eq!(verifier.verify_record(&different_opening), Ok(()));
        let mut mutations = Vec::new();
        let mut changed = original.clone();
        changed.signed.declaration.public_supply = changed
            .signed
            .declaration
            .public_supply
            .checked_add(1)
            .unwrap();
        mutations.push(changed);
        let mut changed = original.clone();
        changed.signed.declaration.metadata.decimals ^= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.signed.declaration.issuer_key[0] ^= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.signed.declaration.issuance_fee_atoms ^= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.signed.declaration.note_commitments[0][0] += F::ONE;
        mutations.push(changed);
        for changed in mutations {
            assert_eq!(
                verifier.verify_record(&changed),
                Err(VerificationError::InvalidProof)
            );
        }
        let mut changed = original.clone();
        changed.ciphertexts[0][0] ^= 1;
        assert_eq!(
            verifier.verify_record(&changed),
            Err(VerificationError::Ciphertext(
                IssuanceError::CiphertextBindingMismatch
            ))
        );
        changed.signed.declaration.note_ciphertext_digests[0] =
            *blake3::hash(&changed.ciphertexts[0]).as_bytes();
        assert_eq!(
            verifier.verify_record(&changed),
            Err(VerificationError::InvalidProof)
        );
        let mut changed = original;
        let middle =
            super::super::FRAME_BYTES + (changed.proof.len() - super::super::FRAME_BYTES) / 2;
        changed.proof[middle] ^= 1;
        assert!(verifier.verify_record(&changed).is_err());
    }
}
