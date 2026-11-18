//! Verification-only adapter for an inactive, locally pinned V2 transaction.
//!
//! The caller authenticates the local configuration and selects a canonical
//! historical snapshot before constructing the prepared input. Proof validity
//! grants no block, Engine, issuance, settlement or state-commit capability.
#[cfg(all(test, unix))]
#[path = "transaction/fixture_tests.rs"]
mod fixture_tests;

use super::backend::{Config, Profile, TransactionVerifier};
use super::native::{DecodeError, NativeProofShape};
use super::{FrameError, Identity, MAX_TRANSACTION_PROOF_BYTES, ProtocolBinding, Relation};
use crate::proof_codec::ProofDecodeError;
use crate::state::TransactionProof;
use ::native::codec::{CodecError, FORMAT_VERSION, PublicTransaction};
use p3_uni_stark::PreprocessedVerifierKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    LocalBinding,
    TrustedShape(ProofDecodeError),
    IdentityMismatch,
    Network,
    Context,
    Public(CodecError),
    Frame(FrameError),
    Body(ProofDecodeError),
    InvalidProof,
}

/// Immutable verification configuration; it neither generates nor holds a prover.
pub struct FixedTransactionVerifier {
    network: [u8; 32],
    verifier: TransactionVerifier,
    shape: NativeProofShape,
}

impl FixedTransactionVerifier {
    /// All inputs, including the expected composite identity, must come from
    /// independently authenticated local configuration. Nonzero identifiers
    /// are only a structural check; they do not authenticate a registry.
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
            || expected.relation != Relation::Transaction
            || expected.profile == [0; 32]
        {
            return Err(VerificationError::LocalBinding);
        }
        let verifier = TransactionVerifier::from_trusted_key(profile, key);
        let shape = NativeProofShape::from_trusted(
            &verifier.air,
            verifier.verification_key(),
            verifier.public_config(),
            profile,
            Relation::Transaction,
            binding,
            MAX_TRANSACTION_PROOF_BYTES,
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

    /// Verify the exact prepared transaction with an independently rebuilt
    /// statement. TransactionProof has no public field constructor: the chain
    /// preparation code checks snapshot membership and selects its stored root.
    /// This method checks binding presence, not canonical snapshot membership.
    pub fn verify_prepared(&self, input: &TransactionProof<'_>) -> Result<(), VerificationError> {
        if input.context.network != self.network {
            return Err(VerificationError::Network);
        }
        if input.context.version() != FORMAT_VERSION || input.context.snapshot().is_none() {
            return Err(VerificationError::Context);
        }
        PublicTransaction::decode(&input.public.encode()).map_err(VerificationError::Public)?;
        let proof = self
            .shape
            .decode(input.proof)
            .map_err(|error| match error {
                DecodeError::Frame(error) => VerificationError::Frame(error),
                DecodeError::Body(error) => VerificationError::Body(error),
            })?;
        let public = input
            .public
            .statement(&input.context, &input.fee, &input.root);
        self.verifier
            .verify(&proof, &public)
            .map_err(|_| VerificationError::InvalidProof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::native::FriParams;
    use ::native::codec::{ProofContext, decode_digest};
    use ::native::multi_asset::F;
    use p3_air::BaseAir;
    use p3_field::PrimeCharacteristicRing;
    use p3_symmetric::MerkleCap;

    const NETWORK: [u8; 32] = [7; 32];
    const BINDING: ProtocolBinding = ProtocolBinding {
        genesis: [1; 32],
        rules: [2; 32],
        air: [3; 32],
    };

    fn profile() -> Profile {
        // Small structural fixture only, not a registered security profile.
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
        let air = ::native::multi_asset_transaction::TransactionAir::new()
            .with_min_height(profile().minimum_height());
        // Synthetic public roots exercise configuration and rejection only.
        // No proof made with this key is asserted cryptographically valid.
        let key = PreprocessedVerifierKey {
            width: air.preprocessed_width(),
            degree_bits: air.degree_bits() + 1,
            commitment: MerkleCap::new(vec![[F::ZERO; 12]; 2]),
        };
        let verifier = TransactionVerifier::from_trusted_key(profile(), key.clone());
        let identity = NativeProofShape::from_trusted(
            &verifier.air,
            &key,
            verifier.public_config(),
            profile(),
            Relation::Transaction,
            BINDING,
            MAX_TRANSACTION_PROOF_BYTES,
        )
        .unwrap()
        .identity();
        (key, identity)
    }

    fn verifier() -> FixedTransactionVerifier {
        let (key, identity) = configuration();
        FixedTransactionVerifier::from_trusted(NETWORK, profile(), BINDING, key, identity).unwrap()
    }

    fn input(proof: &[u8]) -> TransactionProof<'_> {
        let mut bytes = [0; ::native::codec::PUBLIC_TRANSACTION_BYTES];
        bytes[48] = 1;
        TransactionProof {
            public: PublicTransaction::decode(&bytes).unwrap(),
            context: ProofContext::for_snapshot(NETWORK, 600, [8; 32]),
            fee: [F::ZERO; 12],
            root: [F::ZERO; 12],
            proof,
        }
    }

    #[test]
    fn rejects_missing_local_bindings_and_nontransaction_identity() {
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
                FixedTransactionVerifier::from_trusted(
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
                    relation: Relation::Issuance,
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
                FixedTransactionVerifier::from_trusted(
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
    fn independently_pinned_identity_rejects_different_key_profile_and_binding() {
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
                FixedTransactionVerifier::from_trusted(
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
            FixedTransactionVerifier::from_trusted(
                NETWORK,
                profile(),
                BINDING,
                invalid_key,
                identity
            ),
            Err(VerificationError::TrustedShape(
                ProofDecodeError::InvalidTrustedShape
            ))
        ));
    }

    #[test]
    fn rejects_context_and_duplicate_nullifiers_before_frame_decoding() {
        let verifier = verifier();
        let mut prepared = input(&[]);
        prepared.context.network = [9; 32];
        assert_eq!(
            verifier.verify_prepared(&prepared),
            Err(VerificationError::Network)
        );
        prepared.context = ProofContext::new(NETWORK);
        assert_eq!(
            verifier.verify_prepared(&prepared),
            Err(VerificationError::Context)
        );
        prepared.context = ProofContext::for_snapshot(NETWORK, 600, [8; 32]);
        prepared.public.nf[1] = prepared.public.nf[0];
        assert_eq!(
            verifier.verify_prepared(&prepared),
            Err(VerificationError::Public(CodecError::DuplicateNullifier))
        );
    }

    #[test]
    fn rejects_frame_identity_size_and_malformed_body() {
        let verifier = verifier();
        let identity = verifier.shape.identity();
        let wrong = Identity {
            profile: [42; 32],
            ..identity
        };
        let frame = super::super::encode(wrong, &[0], MAX_TRANSACTION_PROOF_BYTES).unwrap();
        assert_eq!(
            verifier.verify_prepared(&input(&frame)),
            Err(VerificationError::Frame(FrameError::Identity))
        );
        let excessive = vec![0; MAX_TRANSACTION_PROOF_BYTES + 1];
        assert_eq!(
            verifier.verify_prepared(&input(&excessive)),
            Err(VerificationError::Frame(FrameError::Size))
        );
        let frame = super::super::encode(identity, &[0], MAX_TRANSACTION_PROOF_BYTES).unwrap();
        assert!(matches!(
            verifier.verify_prepared(&input(&frame)),
            Err(VerificationError::Body(_))
        ));
        let mut trailing = frame;
        trailing.push(0);
        assert_eq!(
            verifier.verify_prepared(&input(&trailing)),
            Err(VerificationError::Frame(FrameError::Size))
        );
    }

    // An external, independently reviewed artifact is deliberately required.
    // The ordinary rejection tests above establish no proof-validity result.
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
        public_transaction: Vec<u8>,
        fee_commitment: Vec<u8>,
        recent_roots_root: Vec<u8>,
        snapshot_height: u64,
        snapshot_block_id: [u8; 32],
        proof_frame: Vec<u8>,
    }

    #[test]
    #[ignore = "requires a pinned existing valid V2 frame with its original encoded transaction, snapshot and key"]
    fn existing_valid_proof_rejects_exact_statement_and_proof_mutations() {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        const FIXTURE_LIMIT: usize = 4 * 1024 * 1024;
        let path = std::env::var_os("SIWORLD_V2_TRANSACTION_FIXTURE")
            .expect("an independently reviewed existing fixture path is required");
        let pin = std::env::var("SIWORLD_V2_TRANSACTION_FIXTURE_SHA256")
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
        assert!(!fixture.proof_frame.is_empty());
        assert!(fixture.proof_frame.len() <= MAX_TRANSACTION_PROOF_BYTES);
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
        let verifier = FixedTransactionVerifier::from_trusted(
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
                relation: Relation::Transaction,
                profile: fixture.expected_identity,
            },
        )
        .unwrap();
        let mut prepared = TransactionProof {
            public: PublicTransaction::decode(&fixture.public_transaction).unwrap(),
            context: ProofContext::for_snapshot(
                fixture.network,
                fixture.snapshot_height,
                fixture.snapshot_block_id,
            ),
            fee: decode_digest(fixture.fee_commitment.as_slice().try_into().unwrap()).unwrap(),
            root: decode_digest(fixture.recent_roots_root.as_slice().try_into().unwrap()).unwrap(),
            proof: &fixture.proof_frame,
        };
        // Every negative below is conditional on this exact, genuine success.
        assert_eq!(verifier.verify_prepared(&prepared), Ok(()));
        prepared.public.payment.body[0] ^= 1;
        assert_eq!(
            verifier.verify_prepared(&prepared),
            Err(VerificationError::InvalidProof)
        );
        prepared.public.payment.body[0] ^= 1;
        prepared.fee[0] += F::ONE;
        assert_eq!(
            verifier.verify_prepared(&prepared),
            Err(VerificationError::InvalidProof)
        );
        prepared.fee[0] -= F::ONE;
        prepared.root[0] += F::ONE;
        assert_eq!(
            verifier.verify_prepared(&prepared),
            Err(VerificationError::InvalidProof)
        );
        prepared.root[0] -= F::ONE;
        prepared.context = prepared.context.bind_snapshot(
            fixture.snapshot_height.checked_add(1).unwrap(),
            fixture.snapshot_block_id,
        );
        assert_eq!(
            verifier.verify_prepared(&prepared),
            Err(VerificationError::InvalidProof)
        );
        let mut different_id = fixture.snapshot_block_id;
        different_id[0] ^= 1;
        prepared.context = prepared
            .context
            .bind_snapshot(fixture.snapshot_height, different_id);
        assert_eq!(
            verifier.verify_prepared(&prepared),
            Err(VerificationError::InvalidProof)
        );
        prepared.context = prepared
            .context
            .bind_snapshot(fixture.snapshot_height, fixture.snapshot_block_id);
        let mut changed_proof = fixture.proof_frame.clone();
        let middle =
            super::super::FRAME_BYTES + (changed_proof.len() - super::super::FRAME_BYTES) / 2;
        changed_proof[middle] ^= 1;
        prepared.proof = &changed_proof;
        assert!(verifier.verify_prepared(&prepared).is_err());
    }
}
