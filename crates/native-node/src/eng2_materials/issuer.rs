//! Local temporary issuer custody for an explicitly bound isolated rehearsal.
//! SW2MAT01 is owner-only plaintext material, not an encrypted authority vault.
use super::*;
use crate::wallet::issuance::ISSUER_SIGNATURE_CONTEXT;
use crate::wallet_vault::rehearsal::{RehearsalBinding, new_private_path};
use native::issuance::{
    AssetMetadata, ISSUER_KEY_BYTES, ISSUER_SIGNATURE_BYTES, IssuanceDeclaration, IssuancePolicy,
    SignedIssuance,
};
use native::multi_asset::{AssetId, SIP_ASSET_ID};

/// Create a distinct OS-random issuer using the unchanged protected seed frame.
/// A partial failure is retained; callers must not overwrite or retry implicitly.
pub fn prepare_isolated_issuer(directory: &Path, binding: &RehearsalBinding) -> Result<Value> {
    new_private_path(directory)?;
    let mut result =
        prepare_with_entropy(directory, binding.network(), Purpose::Issuer, 0, |seed| {
            getrandom::fill(seed).map_err(|_| "OS randomness unavailable".into())
        })?;
    let custody = storage::Directory::open(directory)?;
    custody.write_once("rehearsal.json", binding.bytes())?;
    if *custody.read("rehearsal.json", binding.bytes().len())? != binding.bytes() {
        return Err("isolated issuer public binding readback differs".into());
    }
    result["initialization"] = binding.receipt();
    result["temporary_isolated_issuer"] = json!(true);
    result["encrypted"] = json!(false);
    Ok(result)
}
/// Public economics independently selected in the pinned business plan.
pub struct IssuerExpectation {
    pub sequence: u64,
    pub asset_id: AssetId,
    pub public_supply: u64,
    pub metadata: AssetMetadata,
    pub issuance_fee_atoms: u64,
}
/// Owns one protected isolated signer session. No secret accessor is provided.
/// Exactly one signing attempt is permitted, including an ordinary failure.
pub struct IssuerSigner {
    seed: Zeroizing<[u8; 32]>,
    network: [u8; 32],
    authority: [u8; ISSUER_KEY_BYTES],
    used: bool,
    _custody: storage::Directory,
}
struct Key(ml_dsa_65::MLDSA65SigningKey);
impl Drop for Key {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}
impl IssuerSigner {
    /// The expected public key must come from the independent campaign pin.
    pub fn open(
        directory: &Path,
        binding: &RehearsalBinding,
        expected_authority: [u8; ISSUER_KEY_BYTES],
    ) -> Result<Self> {
        if expected_authority == [0; ISSUER_KEY_BYTES] {
            return Err("isolated issuer requires an independent public key".into());
        }
        let custody = storage::Directory::open(directory)?;
        if *custody.read("rehearsal.json", binding.bytes().len())? != binding.bytes() {
            return Err("isolated issuer belongs to different initialization parameters".into());
        }
        let pending = custody.read("pending.secret", PENDING_BYTES)?;
        if &pending[..8] != MAGIC
            || pending[8..40] != binding.network()
            || pending[40] != Purpose::Issuer as u8
            || pending[41] != 0
            || pending[74..] != blake3::derive_key(PENDING_CONTEXT, &pending[..74])
        {
            return Err("isolated issuer protected context differs".into());
        }
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(&pending[42..74])
                .map_err(|_| "isolated issuer seed width differs")?,
        );
        let (public, fingerprint) =
            public_parameters(binding.network(), Purpose::Issuer, 0, Zeroizing::new(*seed))?;
        if *custody.read("public.json", public.len())? != public
            || fingerprint != sha(&expected_authority)
        {
            return Err("isolated issuer public key differs from independent pin".into());
        }
        Ok(Self {
            seed,
            network: binding.network(),
            authority: expected_authority,
            used: false,
            _custody: custody,
        })
    }
    /// Validate typed public economics, sign fixed-context canonical bytes, and
    /// independently verify the actual ML-DSA signature before returning it.
    pub fn sign(
        &mut self,
        declaration: &IssuanceDeclaration,
        expectation: &IssuerExpectation,
        policy: IssuancePolicy,
    ) -> Result<[u8; ISSUER_SIGNATURE_BYTES]> {
        if self.used {
            return Err("isolated issuer signing attempt already consumed".into());
        }
        self.used = true;
        if declaration.note_commitments.len() != crate::issuance::INITIAL_NOTES
            || declaration.note_ciphertext_digests.len() != crate::issuance::INITIAL_NOTES
            || declaration.metadata.name.len() >= crate::issuance::METADATA_CODEC_LIMIT
        {
            return Err("isolated issuer native declaration size rejected".into());
        }
        declaration
            .validate(&self.network, 1, policy)
            .map_err(|_| "isolated issuer declaration policy rejected")?;
        if declaration.issuer_key != self.authority
            || expectation.asset_id == SIP_ASSET_ID
            || declaration.sequence != expectation.sequence
            || declaration.asset_id != expectation.asset_id
            || declaration.public_supply != expectation.public_supply
            || declaration.metadata != expectation.metadata
            || declaration.issuance_fee_atoms != expectation.issuance_fee_atoms
            || declaration.note_commitments.len() != crate::issuance::INITIAL_NOTES
        {
            return Err("isolated issuer declaration differs from independent expectations".into());
        }
        let message = declaration.canonical_bytes();
        let pair = ml_dsa_65::generate_key_pair(*self.seed);
        let key = Key(pair.signing_key);
        if *pair.verification_key.as_ref() != self.authority {
            return Err("isolated issuer live key differs".into());
        }
        let mut randomness = Zeroizing::new([0; 32]);
        getrandom::fill(randomness.as_mut())
            .map_err(|_| "isolated issuer signing entropy unavailable")?;
        let signature = *ml_dsa_65::sign(&key.0, &message, ISSUER_SIGNATURE_CONTEXT, *randomness)
            .map_err(|_| "isolated issuer signing failed")?
            .as_ref();
        SignedIssuance {
            declaration: declaration.clone(),
            signature: Some(signature),
        }
        .verify_signature()
        .map_err(|_| "isolated issuer signature verification failed")?;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests;
