//! Native verification from authenticated public preprocessing commitments.
//!
//! Loading this module's verifier never creates traces, preprocessing prover
//! data or a proof. Artifact authentication is supplied by a trusted caller;
//! an untrusted envelope cannot select its own key or parameter profile.

use crate::common::F;
use crate::fee_settlement_air::{SettlementAir, SettlementProver, validate_settlement_public};
use crate::proof_codec::ProofShape;
use crate::transaction::{TransactionAir, TransactionProver};
use crate::{Cfg, FriParams};
use p3_air::BaseAir;
use p3_uni_stark::{PreprocessedVerifierKey, Proof, verify_with_preprocessed};
use sha2::{Digest as _, Sha256};

const HEADER: usize = 43;
const MAX_COMMITMENT_BYTES: usize = 4096;
const TRANSACTION: u8 = 1;
const SETTLEMENT: u8 = 2;

/// Canonical public verifier data for the fixed native candidate profile.
/// The SHA-256 of these complete bytes must be pinned outside untrusted input.
pub struct VerifierArtifact {
    bytes: Vec<u8>,
}

impl VerifierArtifact {
    pub fn transaction(prover: &TransactionProver) -> Result<Self, String> {
        let params = FriParams::transaction_candidate();
        let expected = TransactionAir::new().with_min_height(params.hiding_min_height());
        if *prover.cfg.descriptor() != params.descriptor()
            || prover.air.width() != expected.width()
            || prover.air.preprocessed_width() != expected.preprocessed_width()
            || prover.air.num_public_values() != expected.num_public_values()
            || prover.air.degree_bits() != expected.degree_bits()
            || prover.vk.width != expected.preprocessed_width()
            || prover.vk.degree_bits != expected.degree_bits() + 1
        {
            return Err("transaction prover does not match fixed verifier profile".into());
        }
        ProofShape::from_trusted(&prover.air, &prover.vk, &prover.cfg)
            .map_err(|e| e.to_string())?;
        Self::from_key(TRANSACTION, &prover.vk)
    }
    pub fn settlement(prover: &SettlementProver) -> Result<Self, String> {
        if prover.air.capacity != 576 {
            return Err("settlement verifier artifact requires capacity 576".into());
        }
        let params = FriParams::transaction_candidate();
        let expected = SettlementAir::new(576).with_min_height(params.hiding_min_height());
        if *prover.cfg.descriptor() != params.descriptor()
            || prover.air.width() != expected.width()
            || prover.air.preprocessed_width() != expected.preprocessed_width()
            || prover.air.num_public_values() != expected.num_public_values()
            || prover.air.degree_bits() != expected.degree_bits()
            || prover.vk.width != expected.preprocessed_width()
            || prover.vk.degree_bits != expected.degree_bits() + 1
        {
            return Err("settlement prover does not match fixed verifier profile".into());
        }
        ProofShape::from_trusted(&prover.air, &prover.vk, &prover.cfg)
            .map_err(|e| e.to_string())?;
        Self::from_key(SETTLEMENT, &prover.vk)
    }
    fn from_key(kind: u8, vk: &PreprocessedVerifierKey<Cfg>) -> Result<Self, String> {
        let commitment = postcard::to_allocvec(&vk.commitment).map_err(|e| e.to_string())?;
        if commitment.len() > MAX_COMMITMENT_BYTES {
            return Err("oversized public verifier commitment".into());
        }
        let mut bytes = Vec::with_capacity(HEADER + commitment.len());
        bytes.extend_from_slice(b"SWVK");
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.push(kind);
        for value in profile() {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for value in [vk.width, vk.degree_bits, commitment.len()] {
            bytes.extend_from_slice(
                &u32::try_from(value)
                    .map_err(|_| "key dimension overflow")?
                    .to_le_bytes(),
            );
        }
        bytes.extend_from_slice(&commitment);
        Ok(Self { bytes })
    }
    pub fn encode(&self) -> Vec<u8> {
        self.bytes.clone()
    }
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }
}

fn profile() -> [u32; 6] {
    let p = FriParams::transaction_candidate();
    [
        p.log_blowup,
        p.num_queries,
        p.query_pow_bits,
        p.commit_pow_bits,
        p.batch_pow_bits,
        p.max_log_arity,
    ]
}

fn load_key(
    bytes: &[u8],
    expected: [u8; 32],
    kind: u8,
) -> Result<PreprocessedVerifierKey<Cfg>, String> {
    if bytes.len() < HEADER
        || bytes.len() > HEADER + MAX_COMMITMENT_BYTES
        || <[u8; 32]>::from(Sha256::digest(bytes)) != expected
    {
        return Err("public verifier artifact authentication failed".into());
    }
    if &bytes[..4] != b"SWVK" || bytes[4..6] != 1u16.to_le_bytes() || bytes[6] != kind {
        return Err("public verifier artifact type mismatch".into());
    }
    let word = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    if profile()
        .iter()
        .enumerate()
        .any(|(i, value)| word(7 + i * 4) != *value)
    {
        return Err("public verifier artifact profile mismatch".into());
    }
    let width = word(31) as usize;
    let degree_bits = word(35) as usize;
    let length = word(39) as usize;
    if length != bytes.len() - HEADER {
        return Err("public verifier commitment length mismatch".into());
    }
    let commitment =
        postcard::from_bytes(&bytes[HEADER..]).map_err(|_| "invalid verifier commitment")?;
    let key = PreprocessedVerifierKey {
        width,
        degree_bits,
        commitment,
    };
    if VerifierArtifact::from_key(kind, &key)?.bytes != bytes {
        return Err("noncanonical verifier commitment".into());
    }
    Ok(key)
}

/// Prepared transaction verifier, containing public verifier data only.
pub struct TransactionVerifier {
    cfg: Cfg,
    air: TransactionAir,
    vk: PreprocessedVerifierKey<Cfg>,
    pub shape: ProofShape,
}
impl TransactionVerifier {
    pub fn load(bytes: &[u8], expected_sha256: [u8; 32]) -> Result<Self, String> {
        let params = FriParams::transaction_candidate();
        let cfg = params.config();
        let air = TransactionAir::new().with_min_height(params.hiding_min_height());
        let vk = load_key(bytes, expected_sha256, TRANSACTION)?;
        if vk.width != air.preprocessed_width() || vk.degree_bits != air.degree_bits() + 1 {
            return Err("transaction verifier key shape mismatch".into());
        }
        let shape = ProofShape::from_trusted(&air, &vk, &cfg).map_err(|e| e.to_string())?;
        Ok(Self {
            cfg,
            air,
            vk,
            shape,
        })
    }
    pub fn verify(&self, proof: &Proof<Cfg>, public: &[F]) -> Result<(), String> {
        if public.len() != self.air.num_public_values() {
            return Err("transaction statement length mismatch".into());
        }
        verify_with_preprocessed(&self.cfg, &self.air, proof, public, Some(&self.vk))
            .map_err(|_| "native transaction verification failed".into())
    }
    pub fn verify_bytes(&self, bytes: &[u8], public: &[F]) -> Result<(), String> {
        let proof = self.shape.decode(bytes).map_err(|e| e.to_string())?;
        self.verify(&proof, public)
    }
}

/// Prepared 576-slot settlement verifier with no preprocessing prover data.
pub struct SettlementVerifier {
    cfg: Cfg,
    air: SettlementAir,
    vk: PreprocessedVerifierKey<Cfg>,
    pub shape: ProofShape,
}
impl SettlementVerifier {
    pub fn load(bytes: &[u8], expected_sha256: [u8; 32]) -> Result<Self, String> {
        let params = FriParams::transaction_candidate();
        let cfg = params.config();
        let air = SettlementAir::new(576).with_min_height(params.hiding_min_height());
        let vk = load_key(bytes, expected_sha256, SETTLEMENT)?;
        if vk.width != air.preprocessed_width() || vk.degree_bits != air.degree_bits() + 1 {
            return Err("settlement verifier key shape mismatch".into());
        }
        let shape = ProofShape::from_trusted(&air, &vk, &cfg).map_err(|e| e.to_string())?;
        Ok(Self {
            cfg,
            air,
            vk,
            shape,
        })
    }
    pub fn verify(&self, proof: &Proof<Cfg>, public: &[F]) -> Result<(), String> {
        validate_settlement_public(576, public)?;
        verify_with_preprocessed(&self.cfg, &self.air, proof, public, Some(&self.vk))
            .map_err(|_| "native settlement verification failed".into())
    }
    pub fn verify_bytes(&self, bytes: &[u8], public: &[F]) -> Result<(), String> {
        let proof = self.shape.decode(bytes).map_err(|e| e.to_string())?;
        self.verify(&proof, public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_merkle_tree::MerkleCap;

    fn artifact(kind: u8) -> VerifierArtifact {
        let params = FriParams::transaction_candidate();
        let air = TransactionAir::new().with_min_height(params.hiding_min_height());
        VerifierArtifact::from_key(
            kind,
            &PreprocessedVerifierKey {
                width: air.preprocessed_width(),
                degree_bits: air.degree_bits() + 1,
                commitment: MerkleCap::new(vec![[F::ZERO; 12]; 2]),
            },
        )
        .unwrap()
    }
    #[test]
    fn trusted_key_reconstruction_does_not_require_prover_setup() {
        let artifact = artifact(TRANSACTION);
        assert!(TransactionVerifier::load(&artifact.encode(), artifact.sha256()).is_ok());
    }
    #[test]
    fn artifact_export_rejects_non_frozen_prover_profiles() {
        let transaction = TransactionProver::new(FriParams::fast());
        assert!(VerifierArtifact::transaction(&transaction).is_err());
        let settlement = SettlementProver::new(576, FriParams::fast());
        assert!(VerifierArtifact::settlement(&settlement).is_err());
    }
    #[test]
    fn artifact_export_rejects_changed_air_and_key_dimensions() {
        let params = FriParams::transaction_candidate();
        let mut transaction = TransactionProver::new(FriParams::fast());
        transaction.cfg = params.config();
        transaction.vk.width += 1;
        assert!(VerifierArtifact::transaction(&transaction).is_err());
        transaction.vk.width -= 1;
        let height = 1 << (transaction.air.degree_bits() + 1);
        transaction.air = TransactionAir::new().with_min_height(height);
        assert!(VerifierArtifact::transaction(&transaction).is_err());
        let mut settlement = SettlementProver::new(576, FriParams::fast());
        settlement.cfg = params.config();
        settlement.vk.degree_bits += 1;
        assert!(VerifierArtifact::settlement(&settlement).is_err());
        settlement.vk.degree_bits -= 1;
        settlement.air.height *= 2;
        assert!(VerifierArtifact::settlement(&settlement).is_err());
    }
    #[test]
    fn untrusted_hash_type_profile_shape_and_trailing_data_are_rejected() {
        let artifact = artifact(TRANSACTION);
        assert!(TransactionVerifier::load(&artifact.encode(), [0; 32]).is_err());
        assert!(SettlementVerifier::load(&artifact.encode(), artifact.sha256()).is_err());
        for offset in [0, 4, 6, 7, 31, 35, 39] {
            let mut bytes = artifact.encode();
            bytes[offset] ^= 1;
            let hash = Sha256::digest(&bytes).into();
            assert!(
                TransactionVerifier::load(&bytes, hash).is_err(),
                "offset {offset}"
            );
        }
        let mut bytes = artifact.encode();
        bytes.push(0);
        let hash = Sha256::digest(&bytes).into();
        assert!(TransactionVerifier::load(&bytes, hash).is_err());
    }
}
