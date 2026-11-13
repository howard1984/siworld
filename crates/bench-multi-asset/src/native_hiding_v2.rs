//! Candidate-only native relations using the explicit dual-hiding V2 backend.
//!
//! Public preprocessing is prepared once and reused. Every proof creates one
//! fresh OS-seeded attempt; no private PCS or witness is cached across attempts.
//! The retained configuration and network adapters remain unchanged.
use crate::issuance::{
    IssuanceError, IssuancePolicy, IssuanceWitness, SignedIssuance, VerifiedIssuance,
};
use crate::issuance_air::{IssuanceAir, PUBLIC_COMMITMENTS, public_len};
use crate::multi_asset::{AccWitness, DCT_BYTES, Digest, F, Hasher};
use crate::multi_asset_transaction::{TransactionAir, statement_for};
use crate::settlement::{FixedSettlementWitness, SettlementAir, validate_settlement_public};
pub use native_base::native_hiding_v2::{
    Config, PrivateAttempt, Profile, PublicPreprocessing, RANDOM_CODEWORDS, SALT_ELEMENTS,
};
use p3_field::PrimeField32;
use p3_uni_stark::{
    PreprocessedProverData, PreprocessedVerifierKey, Proof, QuotientAir, prove_with_preprocessed,
    setup_preprocessed, verify_with_preprocessed,
};

struct Setup {
    public: PublicPreprocessing,
    pdata: PreprocessedProverData<Config>,
    vk: PreprocessedVerifierKey<Config>,
}
impl Setup {
    fn new<A: QuotientAir<Config>>(
        profile: Profile,
        air: &A,
        degree: usize,
    ) -> Result<Self, String> {
        let public = PublicPreprocessing::new(profile);
        let (pdata, vk) = setup_preprocessed(public.config(), air, degree)
            .map_err(|_| "native hiding V2 public preprocessing failed")?
            .ok_or("native hiding V2 relation has no public preprocessing")?;
        Ok(Self { public, pdata, vk })
    }
}

macro_rules! relation {
    ($prover:ident,$verifier:ident,$air:ty) => {
        pub struct $prover {
            pub air: $air,
            setup: Setup,
        }
        /// Verification-only relation. The caller must authenticate the exact
        /// key and bind its AIR/parameters to the enclosing profile identity.
        pub struct $verifier {
            pub air: $air,
            public: PublicPreprocessing,
            vk: PreprocessedVerifierKey<Config>,
        }
        impl $prover {
            pub fn verification_key(&self) -> &PreprocessedVerifierKey<Config> {
                &self.setup.vk
            }
            pub fn public_config(&self) -> &Config {
                self.setup.public.config()
            }
            pub fn profile(&self) -> Profile {
                self.setup.public.profile()
            }
            fn verify_raw(&self, proof: &Proof<Config>, public: &[F]) -> Result<(), String> {
                verify_with_preprocessed(
                    self.public_config(),
                    &self.air,
                    proof,
                    public,
                    Some(&self.setup.vk),
                )
                .map_err(|_| "native hiding V2 proof verification failed".into())
            }
        }
        impl $verifier {
            pub fn verification_key(&self) -> &PreprocessedVerifierKey<Config> {
                &self.vk
            }
            pub fn public_config(&self) -> &Config {
                self.public.config()
            }
            pub fn profile(&self) -> Profile {
                self.public.profile()
            }
            fn verify_raw(&self, proof: &Proof<Config>, public: &[F]) -> Result<(), String> {
                verify_with_preprocessed(
                    self.public_config(),
                    &self.air,
                    proof,
                    public,
                    Some(&self.vk),
                )
                .map_err(|_| "native hiding V2 proof verification failed".into())
            }
        }
    };
}
relation!(TransactionProver, TransactionVerifier, TransactionAir);
relation!(SettlementProver, SettlementVerifier, SettlementAir);
relation!(IssuanceProver, IssuanceVerifier, IssuanceAir);

impl TransactionProver {
    pub fn new(profile: Profile) -> Result<Self, String> {
        let air = TransactionAir::new().with_min_height(profile.minimum_height());
        let setup = Setup::new(profile, &air, air.degree_bits())?;
        Ok(Self { air, setup })
    }
    pub fn verifier(&self) -> TransactionVerifier {
        TransactionVerifier::from_trusted_key(self.profile(), self.setup.vk.clone())
    }
    pub fn prove_at_snapshot(
        &self,
        witness: &AccWitness,
        height: u64,
    ) -> Result<(Proof<Config>, Vec<F>), String> {
        let (trace, public) = self.air.generate_at_snapshot(witness, height);
        let attempt = PrivateAttempt::from_os(self.profile())
            .map_err(|_| "native hiding V2 OS entropy unavailable")?;
        let proof = attempt
            .run(|cfg| {
                prove_with_preprocessed(cfg, &self.air, trace, &public, Some(&self.setup.pdata))
            })
            .map_err(|_| "native hiding V2 private attempt unavailable")?
            .map_err(|_| "native hiding V2 transaction proving failed")?;
        Ok((proof, public))
    }
    pub fn verify(&self, proof: &Proof<Config>, public: &[F]) -> Result<(), String> {
        self.verify_raw(proof, public)
    }
}
impl TransactionVerifier {
    pub fn from_trusted_key(profile: Profile, vk: PreprocessedVerifierKey<Config>) -> Self {
        Self {
            air: TransactionAir::new().with_min_height(profile.minimum_height()),
            public: PublicPreprocessing::new(profile),
            vk,
        }
    }
    pub fn verify(&self, proof: &Proof<Config>, public: &[F]) -> Result<(), String> {
        self.verify_raw(proof, public)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn verify_fields(
        &self,
        proof: &Proof<Config>,
        nullifiers: &[Digest; 2],
        commitments: &[Digest; 3],
        ciphertext_digest: &[u8; DCT_BYTES],
        fee: &Digest,
        roots: &Digest,
        height: u64,
    ) -> Result<(), String> {
        self.verify(
            proof,
            &statement_for(
                nullifiers,
                commitments,
                ciphertext_digest,
                fee,
                roots,
                height,
            ),
        )
    }
}
impl SettlementProver {
    pub fn new(capacity: usize, profile: Profile) -> Result<Self, String> {
        let air = SettlementAir::new(capacity).with_min_height(profile.minimum_height());
        let setup = Setup::new(profile, &air, air.degree_bits())?;
        Ok(Self { air, setup })
    }
    pub fn verifier(&self) -> SettlementVerifier {
        SettlementVerifier::from_trusted_key(
            self.air.capacity,
            self.profile(),
            self.setup.vk.clone(),
        )
    }
    pub fn prove(
        &self,
        witness: &FixedSettlementWitness,
    ) -> Result<(Proof<Config>, Vec<F>), String> {
        if witness.capacity() != self.air.capacity {
            return Err("native hiding V2 settlement capacity mismatch".into());
        }
        witness
            .check(&Hasher::new())
            .map_err(|_| "native hiding V2 settlement witness rejected")?;
        let (trace, public) = crate::settlement::generate_trace(&self.air, witness);
        let attempt = PrivateAttempt::from_os(self.profile())
            .map_err(|_| "native hiding V2 OS entropy unavailable")?;
        let proof = attempt
            .run(|cfg| {
                prove_with_preprocessed(cfg, &self.air, trace, &public, Some(&self.setup.pdata))
            })
            .map_err(|_| "native hiding V2 private attempt unavailable")?
            .map_err(|_| "native hiding V2 settlement proving failed")?;
        Ok((proof, public))
    }
    pub fn verify(&self, proof: &Proof<Config>, public: &[F]) -> Result<(), String> {
        validate_settlement_public(self.air.capacity, public)?;
        self.verify_raw(proof, public)
    }
}
impl SettlementVerifier {
    pub fn from_trusted_key(
        capacity: usize,
        profile: Profile,
        vk: PreprocessedVerifierKey<Config>,
    ) -> Self {
        Self {
            air: SettlementAir::new(capacity).with_min_height(profile.minimum_height()),
            public: PublicPreprocessing::new(profile),
            vk,
        }
    }
    pub fn verify(&self, proof: &Proof<Config>, public: &[F]) -> Result<(), String> {
        validate_settlement_public(self.air.capacity, public)?;
        self.verify_raw(proof, public)
    }
}
fn validate_issuance(air: &IssuanceAir, public: &[F]) -> Result<(), IssuanceError> {
    if public.len() != public_len(air.note_count) {
        return Err(IssuanceError::NoteCountMismatch);
    }
    if public[..PUBLIC_COMMITMENTS]
        .iter()
        .any(|v| v.as_canonical_u32() > 0xffff)
    {
        return Err(IssuanceError::InvalidProof);
    }
    Ok(())
}
impl IssuanceProver {
    pub fn new(note_count: usize, profile: Profile) -> Result<Self, String> {
        let air = IssuanceAir::new(note_count).with_min_height(profile.minimum_height());
        let setup = Setup::new(profile, &air, air.degree_bits())?;
        Ok(Self { air, setup })
    }
    pub fn verifier(&self) -> IssuanceVerifier {
        IssuanceVerifier::from_trusted_key(
            self.air.note_count,
            self.profile(),
            self.setup.vk.clone(),
        )
    }
    pub fn prove(
        &self,
        witness: &IssuanceWitness,
    ) -> Result<(Proof<Config>, Vec<F>), IssuanceError> {
        let (trace, public) = self.air.generate(witness)?;
        let attempt =
            PrivateAttempt::from_os(self.profile()).map_err(|_| IssuanceError::InvalidProof)?;
        let proof = attempt
            .run(|cfg| {
                prove_with_preprocessed(cfg, &self.air, trace, &public, Some(&self.setup.pdata))
            })
            .map_err(|_| IssuanceError::InvalidProof)?
            .map_err(|_| IssuanceError::InvalidProof)?;
        Ok((proof, public))
    }
    pub fn verify(&self, proof: &Proof<Config>, public: &[F]) -> Result<(), IssuanceError> {
        validate_issuance(&self.air, public)?;
        self.verify_raw(proof, public)
            .map_err(|_| IssuanceError::InvalidProof)
    }
}
impl IssuanceVerifier {
    pub fn from_trusted_key(
        note_count: usize,
        profile: Profile,
        vk: PreprocessedVerifierKey<Config>,
    ) -> Self {
        Self {
            air: IssuanceAir::new(note_count).with_min_height(profile.minimum_height()),
            public: PublicPreprocessing::new(profile),
            vk,
        }
    }
    pub fn verify(&self, proof: &Proof<Config>, public: &[F]) -> Result<(), IssuanceError> {
        validate_issuance(&self.air, public)?;
        self.verify_raw(proof, public)
            .map_err(|_| IssuanceError::InvalidProof)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn verify_signed(
        &self,
        signed: &SignedIssuance,
        proof: &Proof<Config>,
        network: &[u8; 32],
        version: u32,
        policy: IssuancePolicy,
        ciphertexts: &[Vec<u8>],
        verify_fee: impl FnOnce(&[u8; 32], u64) -> bool,
    ) -> Result<VerifiedIssuance, IssuanceError> {
        signed.declaration.validate(network, version, policy)?;
        signed.verify_signature()?;
        signed
            .declaration
            .validate_ciphertexts(ciphertexts, policy.max_ciphertext_bytes_per_note)?;
        if signed.declaration.note_commitments.len() != self.air.note_count {
            return Err(IssuanceError::NoteCountMismatch);
        }
        self.verify(proof, &signed.declaration.public_inputs())?;
        if !verify_fee(&signed.declaration.binding(), policy.required_fee_atoms) {
            return Err(IssuanceError::UnpaidIssuanceFee);
        }
        Ok(VerifiedIssuance(signed.declaration.clone()))
    }
}
