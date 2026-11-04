//! Fixed three-note native issuance and declaration-bound SIP fee receipts.
//!
//! A fee receipt opens an ordinary transaction output paid to the immutable
//! dedicated fund owner. Its randomness binds the issuance declaration, and its
//! commitment must exist in canonical history or be created by a proof-verified
//! transaction in the same block. Issuer signatures or claimed fee amounts alone never authorize minting.
use crate::proof_codec::ProofShape;
use crate::state::Config;
use crate::wire::{DigestBytes, Hash};
use native::codec::{decode_digest, encode_digest};
use native::issuance::{
    AssetMetadata, ISSUER_KEY_BYTES, ISSUER_SIGNATURE_BYTES, IssuanceDeclaration, IssuancePolicy,
    SignedIssuance,
};
use native::issuance_air::IssuanceAir;
use native::multi_asset::{AssetId, Digest, F, Hasher, Note, SIP_ASSET_ID};
use native::{Cfg, FriParams};
use p3_air::{
    BaseAir,
    symbolic::{AirLayout, get_max_constraint_degree},
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::MerkleCap;
use p3_uni_stark::{PreprocessedVerifierKey, verify_with_preprocessed};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const INITIAL_NOTES: usize = 3;
pub const CIPHERTEXT_BYTES: usize = 1313;
pub const MAX_PROOF_BYTES: usize = 524_288;
pub const TESTNET_ISSUANCE_FEE_ATOMS: u64 = 5_000_000_000;
/// Implementation codec bounds. Activated limits must be explicit in Config.
pub const METADATA_CODEC_LIMIT: usize = 256;
pub const RECORDS_CODEC_LIMIT: usize = 4;
pub const MAX_RECORD_BYTES: usize = 4
    + 2
    + 32
    + ISSUER_KEY_BYTES
    + 8
    + 32
    + 8
    + 2
    + METADATA_CODEC_LIMIT
    + 1
    + 8
    + INITIAL_NOTES * (48 + 32 + CIPHERTEXT_BYTES)
    + ISSUER_SIGNATURE_BYTES
    + 48
    + 48
    + 4
    + MAX_PROOF_BYTES;
const KEY_HEADER: usize = 47;
const KEY_COMMITMENT: usize = 97;
const KEY_SHA256: &str = "c6c94e3d6f6261f82e504c44b5a92de65083f6b31e3ed9c668ccedaa404ef885";
const KEY_HEX: &str = "53574d50010003030000000800000024000000140000000000000014000000010000000a00000008000000610000000261ec79522617de34b7ba6a39a92ba9765a717406262e740c4dc39a305d0573309909190c63a68f39f5b194374d753a1fc1a0da3b3392ab7203f5eb64a2ec02011a863138a457744cabe5865378b4c47ceeb6f23948bade4d2d0a0379c59a167c";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceConfig {
    pub fee_owner: DigestBytes,
    /// Includes the precision byte, matching the issuance relation policy.
    pub max_metadata_bytes: u16,
    pub max_per_block: u8,
}
impl IssuanceConfig {
    pub fn validate(&self) -> Result<(), String> {
        let _ = decode_digest(&self.fee_owner).map_err(|_| "invalid issuance fund owner")?;
        if self.fee_owner == [0; 48]
            || self.max_metadata_bytes == 0
            || usize::from(self.max_metadata_bytes) > METADATA_CODEC_LIMIT
            || self.max_per_block == 0
            || usize::from(self.max_per_block) > RECORDS_CODEC_LIMIT
        {
            return Err("invalid explicit engineering issuance configuration".into());
        }
        Ok(())
    }
    pub(crate) fn policy(&self) -> IssuancePolicy {
        IssuancePolicy {
            max_notes: INITIAL_NOTES,
            max_metadata_bytes: usize::from(self.max_metadata_bytes),
            max_ciphertext_bytes_per_note: CIPHERTEXT_BYTES,
            required_fee_atoms: TESTNET_ISSUANCE_FEE_ATOMS,
        }
    }
}

#[derive(Clone)]
pub struct IssuanceRecord {
    pub signed: SignedIssuance,
    pub ciphertexts: Vec<Vec<u8>>,
    pub proof: Vec<u8>,
    pub fee_commitment: DigestBytes,
    pub fee_rho: DigestBytes,
}
impl core::fmt::Debug for IssuanceRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IssuanceRecord")
            .field("declaration", &self.signed.declaration.binding())
            .field("proof_bytes", &self.proof.len())
            .finish_non_exhaustive()
    }
}
impl PartialEq for IssuanceRecord {
    fn eq(&self, other: &Self) -> bool {
        self.signed.declaration == other.signed.declaration
            && self.signed.signature == other.signed.signature
            && self.ciphertexts == other.ciphertexts
            && self.proof == other.proof
            && self.fee_commitment == other.fee_commitment
            && self.fee_rho == other.fee_rho
    }
}
impl Eq for IssuanceRecord {}

pub fn fee_rseed(binding: Hash) -> Digest {
    let mut reader =
        blake3::Hasher::new_derive_key("siworld native issuance fee note randomness v1");
    reader.update(&binding);
    let mut reader = reader.finalize_xof();
    let mut out = [F::ZERO; 12];
    for value in &mut out {
        loop {
            let mut bytes = [0; 4];
            reader.fill(&mut bytes);
            let raw = u32::from_le_bytes(bytes);
            if raw < F::ORDER_U32 {
                *value = F::from_u32(raw);
                break;
            }
        }
    }
    out
}
impl IssuanceRecord {
    pub fn fee_note(&self, config: &IssuanceConfig) -> Result<Note, String> {
        Ok(Note {
            asset_id: SIP_ASSET_ID,
            owner: decode_digest(&config.fee_owner).map_err(|_| "invalid issuance fee owner")?,
            value: TESTNET_ISSUANCE_FEE_ATOMS,
            unlock_height: 0,
            rho: decode_digest(&self.fee_rho).map_err(|_| "noncanonical issuance fee rho")?,
            rseed: fee_rseed(self.signed.declaration.binding()),
        })
    }
    pub fn validate_shape(&self) -> Result<(), String> {
        let d = &self.signed.declaration;
        if d.version != 1
            || d.note_commitments.len() != INITIAL_NOTES
            || d.note_ciphertext_digests.len() != INITIAL_NOTES
            || self.ciphertexts.len() != INITIAL_NOTES
            || self.ciphertexts.iter().any(|c| c.len() != CIPHERTEXT_BYTES)
            || d.metadata.name.len() + 1 > METADATA_CODEC_LIMIT
            || self.proof.is_empty()
            || self.proof.len() > MAX_PROOF_BYTES
            || self.signed.signature.is_none()
        {
            return Err("issuance record codec bounds".into());
        }
        let _ = decode_digest(&self.fee_commitment)
            .map_err(|_| "noncanonical issuance fee commitment")?;
        let _ = decode_digest(&self.fee_rho).map_err(|_| "noncanonical issuance fee rho")?;
        Ok(())
    }
    pub fn validate(&self, config: &Config) -> Result<(), String> {
        self.validate_shape()?;
        let policy = config
            .issuance
            .as_ref()
            .ok_or("issuance destination and policy are not configured")?;
        policy.validate()?;
        self.signed
            .declaration
            .validate(&config.network, 1, policy.policy())
            .map_err(|e| format!("invalid issuance declaration: {e:?}"))?;
        self.signed
            .verify_signature()
            .map_err(|e| format!("invalid issuance signature: {e:?}"))?;
        self.signed
            .declaration
            .validate_ciphertexts(&self.ciphertexts, CIPHERTEXT_BYTES)
            .map_err(|e| format!("invalid issuance ciphertext binding: {e:?}"))?;
        if encode_digest(&Hasher::new().note_cm(&self.fee_note(policy)?)) != self.fee_commitment {
            return Err(
                "issuance fee output does not match declaration and fund destination".into(),
            );
        }
        Ok(())
    }
    pub fn encoded_len(&self) -> Result<usize, String> {
        self.validate_shape()?;
        Ok(MAX_RECORD_BYTES - METADATA_CODEC_LIMIT - MAX_PROOF_BYTES
            + self.signed.declaration.metadata.name.len()
            + self.proof.len())
    }
    pub(crate) fn owned_bytes(&self) -> Option<usize> {
        self.proof
            .capacity()
            .checked_add(self.signed.declaration.metadata.name.capacity())?
            .checked_add(
                self.signed
                    .declaration
                    .note_commitments
                    .capacity()
                    .checked_mul(48)?,
            )?
            .checked_add(
                self.signed
                    .declaration
                    .note_ciphertext_digests
                    .capacity()
                    .checked_mul(32)?,
            )?
            .checked_add(
                self.ciphertexts
                    .capacity()
                    .checked_mul(std::mem::size_of::<Vec<u8>>())?,
            )?
            .checked_add(
                self.ciphertexts
                    .iter()
                    .try_fold(0usize, |n, c| n.checked_add(c.capacity()))?,
            )
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate_shape()?;
        let d = &self.signed.declaration;
        let mut out = Vec::new();
        out.extend_from_slice(b"SWIS");
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&d.network);
        out.extend_from_slice(&d.issuer_key);
        out.extend_from_slice(&d.sequence.to_le_bytes());
        out.extend_from_slice(&d.asset_id.0);
        out.extend_from_slice(&d.public_supply.to_le_bytes());
        out.extend_from_slice(&(d.metadata.name.len() as u16).to_le_bytes());
        out.extend_from_slice(d.metadata.name.as_bytes());
        out.push(d.metadata.decimals);
        out.extend_from_slice(&d.issuance_fee_atoms.to_le_bytes());
        for i in 0..INITIAL_NOTES {
            out.extend_from_slice(&encode_digest(&d.note_commitments[i]));
            out.extend_from_slice(&d.note_ciphertext_digests[i]);
            out.extend_from_slice(&self.ciphertexts[i]);
        }
        out.extend_from_slice(self.signed.signature.as_ref().expect("checked signature"));
        out.extend_from_slice(&self.fee_commitment);
        out.extend_from_slice(&self.fee_rho);
        out.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.proof);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err("issuance byte limit".into());
        }
        let mut r = Reader { bytes, position: 0 };
        if r.take(4)? != b"SWIS" || u16::from_le_bytes(r.array()?) != 1 {
            return Err("issuance codec version".into());
        }
        let network = r.array()?;
        let issuer_key = r.array()?;
        let sequence = u64::from_le_bytes(r.array()?);
        let asset_id = AssetId(r.array()?);
        let public_supply = u64::from_le_bytes(r.array()?);
        let name_len = usize::from(u16::from_le_bytes(r.array()?));
        if name_len + 1 > METADATA_CODEC_LIMIT {
            return Err("issuance metadata byte limit".into());
        }
        let name = std::str::from_utf8(r.take(name_len)?)
            .map_err(|_| "issuance metadata UTF-8")?
            .to_owned();
        let decimals = r.take(1)?[0];
        let issuance_fee_atoms = u64::from_le_bytes(r.array()?);
        let mut note_commitments = Vec::with_capacity(INITIAL_NOTES);
        let mut note_ciphertext_digests = Vec::with_capacity(INITIAL_NOTES);
        let mut ciphertexts = Vec::with_capacity(INITIAL_NOTES);
        for _ in 0..INITIAL_NOTES {
            note_commitments
                .push(decode_digest(&r.array()?).map_err(|_| "issuance commitment encoding")?);
            note_ciphertext_digests.push(r.array()?);
            ciphertexts.push(r.take(CIPHERTEXT_BYTES)?.to_vec());
        }
        let signature = Some(r.array()?);
        let fee_commitment = r.array()?;
        let fee_rho = r.array()?;
        let proof_len = u32::from_le_bytes(r.array()?) as usize;
        if proof_len == 0 || proof_len > MAX_PROOF_BYTES || proof_len != bytes.len() - r.position {
            return Err("issuance proof byte limit".into());
        }
        let proof = r.take(proof_len)?.to_vec();
        let record = Self {
            signed: SignedIssuance {
                declaration: IssuanceDeclaration {
                    network,
                    version: 1,
                    issuer_key,
                    sequence,
                    asset_id,
                    public_supply,
                    metadata: AssetMetadata { name, decimals },
                    issuance_fee_atoms,
                    note_commitments,
                    note_ciphertext_digests,
                },
                signature,
            },
            ciphertexts,
            proof,
            fee_commitment,
            fee_rho,
        };
        record.validate_shape()?;
        Ok(record)
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(n)
            .ok_or("issuance length overflow")?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or("truncated issuance")?;
        self.position = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        Ok(self.take(N)?.try_into().expect("fixed issuance field"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicAsset {
    pub height: u64,
    pub public_supply: u64,
    pub declaration: Hash,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetRegistry {
    assets: BTreeMap<Hash, PublicAsset>,
    sequences: BTreeSet<([u8; ISSUER_KEY_BYTES], u64)>,
    fees: BTreeSet<DigestBytes>,
}
impl AssetRegistry {
    pub fn len(&self) -> usize {
        self.assets.len()
    }
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&Hash, &PublicAsset)> {
        self.assets.iter()
    }
    pub fn get(&self, id: &Hash) -> Option<&PublicAsset> {
        self.assets.get(id)
    }
    pub fn check_available(&self, record: &IssuanceRecord) -> Result<(), String> {
        let d = &record.signed.declaration;
        if self.assets.contains_key(&d.asset_id.0)
            || self.sequences.contains(&(d.issuer_key, d.sequence))
            || self.fees.contains(&record.fee_commitment)
        {
            return Err("issuance asset, sequence or fee output reused".into());
        }
        Ok(())
    }
    pub fn apply(&mut self, record: &IssuanceRecord, height: u64) -> Result<(), String> {
        self.check_available(record)?;
        let d = &record.signed.declaration;
        let sequence = (d.issuer_key, d.sequence);
        self.assets.insert(
            d.asset_id.0,
            PublicAsset {
                height,
                public_supply: d.public_supply,
                declaration: d.binding(),
            },
        );
        self.sequences.insert(sequence);
        self.fees.insert(record.fee_commitment);
        Ok(())
    }
    pub(crate) fn logical_memory_bytes(&self) -> Option<usize> {
        // Logical conservative charge for sparse BTree nodes. This includes
        // doubled payload plus room for a full root node in every collection;
        // whole-process RSS still requires an independent process guard.
        let asset = 32 + std::mem::size_of::<PublicAsset>();
        let sequence = ISSUER_KEY_BYTES + 8;
        let fee = 48;
        self.assets
            .len()
            .checked_mul(2 * asset + 128)?
            .checked_add(self.sequences.len().checked_mul(2 * sequence + 128)?)?
            .checked_add(self.fees.len().checked_mul(2 * fee + 128)?)?
            .checked_add(if self.is_empty() {
                0
            } else {
                11 * (asset + sequence + fee) + 4096
            })
    }
    pub fn visit_encoding(&self, visit: &mut impl FnMut(&[u8])) {
        visit(&(self.assets.len() as u64).to_le_bytes());
        for (id, a) in &self.assets {
            visit(id);
            visit(&a.height.to_le_bytes());
            visit(&a.public_supply.to_le_bytes());
            visit(&a.declaration);
        }
        for (key, seq) in &self.sequences {
            visit(key);
            visit(&seq.to_le_bytes());
        }
        for fee in &self.fees {
            visit(fee);
        }
    }
    /// Decode an already authenticated local wallet cache, never a peer checkpoint.
    pub fn from_local_encoding(bytes: &[u8], height: u64) -> Result<Self, String> {
        let mut reader = Reader { bytes, position: 0 };
        let count = usize::try_from(u64::from_le_bytes(reader.array()?))
            .map_err(|_| "Local asset cache count exceeds capacity.")?;
        if count > 10000 || bytes.len() != 8 + count * (80 + ISSUER_KEY_BYTES + 8 + 48) {
            return Err("Local asset cache size differs.".into());
        }
        let mut result = Self::default();
        for _ in 0..count {
            let id = reader.array()?;
            let asset = PublicAsset {
                height: u64::from_le_bytes(reader.array()?),
                public_supply: u64::from_le_bytes(reader.array()?),
                declaration: reader.array()?,
            };
            if asset.height == 0
                || asset.height > height
                || result.assets.insert(id, asset).is_some()
            {
                return Err("Local asset cache entry differs.".into());
            }
        }
        for _ in 0..count {
            let key = reader.array()?;
            let sequence = u64::from_le_bytes(reader.array()?);
            if !result.sequences.insert((key, sequence)) {
                return Err("Local issuer sequence reused.".into());
            }
        }
        for _ in 0..count {
            let fee = reader.array()?;
            let _ = decode_digest(&fee).map_err(|_| "Invalid cached issuance field.")?;
            if !result.fees.insert(fee) {
                return Err("Local issuance fee reused.".into());
            }
        }
        let mut canonical = Vec::with_capacity(bytes.len());
        result.visit_encoding(&mut |part| canonical.extend_from_slice(part));
        if canonical != bytes {
            return Err("Local asset cache is not canonical.".into());
        }
        Ok(result)
    }
}

pub(crate) fn params() -> FriParams {
    FriParams {
        log_blowup: 8,
        num_queries: 36,
        query_pow_bits: 20,
        commit_pow_bits: 0,
        batch_pow_bits: 20,
        max_log_arity: 1,
    }
}
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("issuance key hex".into());
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            let digit = |x: u8| match x {
                b'0'..=b'9' => Ok(x - b'0'),
                b'a'..=b'f' => Ok(x - b'a' + 10),
                _ => Err("issuance key hex"),
            };
            Ok((digit(p[0])? << 4) | digit(p[1])?)
        })
        .collect()
}
pub(crate) fn profile_id() -> Hash {
    let air = IssuanceAir::new(INITIAL_NOTES).with_min_height(params().hiding_min_height());
    let mut hash = blake3::Hasher::new_derive_key("siworld native issuance proof profile v1");
    hash.update(b"fixed-three-note-issuance-1");
    hash.update(&unhex(KEY_HEX).expect("fixed issuance key hex"));
    for dimension in [
        air.width() as u64,
        air.preprocessed_width() as u64,
        air.num_public_values() as u64,
        (1u64 << air.degree_bits()),
        get_max_constraint_degree::<F, _>(&air, AirLayout::from_air(&air), 1 << air.degree_bits())
            as u64,
    ] {
        hash.update(&dimension.to_le_bytes());
    }
    *hash.finalize().as_bytes()
}
/// Verification-only adapter. It never sets up a prover from peer-supplied data.
pub struct IssuanceVerifier {
    cfg: Cfg,
    air: IssuanceAir,
    vk: PreprocessedVerifierKey<Cfg>,
    shape: ProofShape,
}
impl IssuanceVerifier {
    pub fn new() -> Result<Self, String> {
        let bytes = unhex(KEY_HEX)?;
        if bytes.len() != KEY_HEADER + KEY_COMMITMENT
            || Sha256::digest(&bytes).as_slice() != unhex(KEY_SHA256)?
        {
            return Err("issuance trusted key authentication".into());
        }
        let word = |o| u32::from_le_bytes(bytes[o..o + 4].try_into().expect("fixed key word"));
        let p = params();
        if &bytes[..7] != b"SWMP\x01\x00\x03"
            || word(7) != INITIAL_NOTES as u32
            || word(43) != KEY_COMMITMENT as u32
            || bytes[KEY_HEADER] != 2
            || [
                p.log_blowup,
                p.num_queries,
                p.query_pow_bits,
                p.commit_pow_bits,
                p.batch_pow_bits,
                p.max_log_arity,
            ]
            .iter()
            .enumerate()
            .any(|(i, v)| word(11 + 4 * i) != *v)
        {
            return Err("issuance trusted profile mismatch".into());
        }
        let mut roots = vec![[F::ZERO; 12]; 2];
        for (field, encoded) in roots
            .iter_mut()
            .flatten()
            .zip(bytes[KEY_HEADER + 1..].as_chunks::<4>().0)
        {
            let value = u32::from_le_bytes(*encoded);
            if value >= F::ORDER_U32 {
                return Err("issuance key field encoding".into());
            }
            *field = postcard::from_bytes(encoded).map_err(|_| "issuance key field decoding")?;
        }
        let vk = PreprocessedVerifierKey {
            width: word(35) as usize,
            degree_bits: word(39) as usize,
            commitment: MerkleCap::new(roots),
        };
        let cfg = p.config();
        let air = IssuanceAir::new(INITIAL_NOTES).with_min_height(p.hiding_min_height());
        if vk.width != air.preprocessed_width() || vk.degree_bits != air.degree_bits() + 1 {
            return Err("issuance trusted AIR dimensions".into());
        }
        let shape = ProofShape::from_trusted(&air, &vk, &cfg, MAX_PROOF_BYTES)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            cfg,
            air,
            vk,
            shape,
        })
    }
    pub fn verify(&self, record: &IssuanceRecord) -> Result<(), String> {
        record.validate_shape()?;
        let proof = self
            .shape
            .decode(&record.proof)
            .map_err(|e| e.to_string())?;
        verify_with_preprocessed(
            &self.cfg,
            &self.air,
            &proof,
            &record.signed.declaration.public_inputs(),
            Some(&self.vk),
        )
        .map_err(|_| "native issuance proof verification failed".into())
    }
}
#[cfg(test)]
mod tests;
