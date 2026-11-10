//! Public, signed development-fund transfers with per-account spend counters.
//! The opening is public because fund disbursement amounts are public audit data.
use crate::wire::{DigestBytes, Hash};
use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65Signature, MLDSA65VerificationKey};
use native::codec::{decode_digest, encode_digest};
use native::multi_asset::{Digest, F, Hasher, Note, SIP_ASSET_ID};
use p3_field::{PrimeCharacteristicRing, PrimeField32};

pub const VERIFYING_KEY_BYTES: usize = 1952;
pub const SIGNATURE_BYTES: usize = 3309;
pub const ENCODED_BYTES: usize = 6783;
const SIGNED_BYTES: usize = ENCODED_BYTES - SIGNATURE_BYTES;
const CONTEXT: &[u8] = b"siworld v0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundSpend {
    pub account: u8,
    pub counter: u64,
    pub amount: u64,
    pub owner: DigestBytes,
    pub rho: DigestBytes,
    pub rseed: DigestBytes,
    pub commitment: DigestBytes,
    pub ciphertext: [u8; 1313],
    pub verifying_key: [u8; VERIFYING_KEY_BYTES],
    pub signature: [u8; SIGNATURE_BYTES],
}

/// Deterministic nonce per authorized wallet and monotonically consumed counter.
/// Rejection sampling avoids modulo bias in canonical KoalaBear field words.
pub fn canonical_rho(network: Hash, account: u8, counter: u64) -> Digest {
    let mut hash = blake3::Hasher::new_derive_key("siworld native development fund note rho v1");
    hash.update(&network);
    hash.update(&[account]);
    hash.update(&counter.to_le_bytes());
    let mut reader = hash.finalize_xof();
    let mut out = [F::ZERO; 12];
    for value in &mut out {
        loop {
            let mut word = [0; 4];
            reader.fill(&mut word);
            let raw = u32::from_le_bytes(word);
            if raw < F::ORDER_U32 {
                *value = F::from_u32(raw);
                break;
            }
        }
    }
    out
}

impl FundSpend {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENCODED_BYTES);
        out.push(self.account);
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        for value in [&self.owner, &self.rho, &self.rseed, &self.commitment] {
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.verifying_key);
        out.extend_from_slice(&self.signature);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != ENCODED_BYTES
            || usize::from(bytes[0]) >= siworld_core::v1_economics::MAX_FUND_WALLETS
        {
            return Err("noncanonical fund payout encoding".into());
        }
        let array = |offset: usize| {
            bytes[offset..offset + 48]
                .try_into()
                .expect("fixed payout digest")
        };
        let result = Self {
            account: bytes[0],
            counter: u64::from_le_bytes(bytes[1..9].try_into().expect("fixed counter")),
            amount: u64::from_le_bytes(bytes[9..17].try_into().expect("fixed amount")),
            owner: array(17),
            rho: array(65),
            rseed: array(113),
            commitment: array(161),
            ciphertext: bytes[209..1522].try_into().expect("fixed ciphertext"),
            verifying_key: bytes[1522..3474]
                .try_into()
                .expect("fixed verification key"),
            signature: bytes[3474..].try_into().expect("fixed signature"),
        };
        result.note()?;
        Ok(result)
    }
    fn note(&self) -> Result<Note, String> {
        if usize::from(self.account) >= siworld_core::v1_economics::MAX_FUND_WALLETS
            || self.amount == 0
        {
            return Err("invalid fund account or amount".into());
        }
        let digest = |value: &DigestBytes| {
            decode_digest(value).map_err(|_| "noncanonical fund note opening".to_owned())
        };
        Ok(Note {
            asset_id: SIP_ASSET_ID,
            owner: digest(&self.owner)?,
            value: self.amount,
            unlock_height: 0,
            rho: digest(&self.rho)?,
            rseed: digest(&self.rseed)?,
        })
    }
    pub fn message(&self, network: Hash) -> Vec<u8> {
        let mut result = b"siworld native development fund spend v1".to_vec();
        result.extend_from_slice(&network);
        result.extend_from_slice(&self.encode()[..SIGNED_BYTES]);
        result
    }
    /// Signature and disclosed opening checks precede the ledger's atomic
    /// unlocked-entitlement and strictly increasing counter checks.
    pub fn verify(
        &self,
        network: Hash,
        genesis_key: &[u8; VERIFYING_KEY_BYTES],
    ) -> Result<Note, String> {
        self.verify_signed_message(network, genesis_key, &self.message(network), CONTEXT)
    }
    /// Shared opening and immutable-authority checks with a versioned signature
    /// message supplied only by an enclosing native protocol implementation.
    pub(crate) fn verify_signed_message(
        &self,
        network: Hash,
        genesis_key: &[u8; VERIFYING_KEY_BYTES],
        message: &[u8],
        context: &[u8],
    ) -> Result<Note, String> {
        let note = self.note()?;
        if note.rho != canonical_rho(network, self.account, self.counter) {
            return Err("fund payout nonce differs from authorized wallet counter".into());
        }
        if self.verifying_key != *genesis_key || genesis_key.iter().all(|byte| *byte == 0) {
            return Err("fund verification key is not configured by genesis".into());
        }
        if encode_digest(&Hasher::new().note_cm(&note)) != self.commitment {
            return Err("fund payout opening does not match commitment".into());
        }
        let vk = MLDSA65VerificationKey::new(self.verifying_key);
        let signature = MLDSA65Signature::new(self.signature);
        ml_dsa_65::verify(&vk, message, context, &signature)
            .map_err(|_| "fund payout ML-DSA-65 signature failed".to_owned())?;
        Ok(note)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use native::multi_asset::F;

    fn signed() -> (FundSpend, Hash, [u8; VERIFYING_KEY_BYTES]) {
        let network = [81; 32];
        let pair = ml_dsa_65::generate_key_pair([83; 32]);
        let value = |x| encode_digest(&[F::from_u32(x); 12]);
        let mut spend = FundSpend {
            account: 0,
            counter: 0,
            amount: 123,
            owner: value(1),
            rho: encode_digest(&canonical_rho(network, 0, 0)),
            rseed: value(3),
            commitment: [0; 48],
            ciphertext: [4; 1313],
            verifying_key: *pair.verification_key.as_ref(),
            signature: [0; SIGNATURE_BYTES],
        };
        let note = spend.note().unwrap();
        spend.commitment = encode_digest(&Hasher::new().note_cm(&note));
        spend.signature = *ml_dsa_65::sign(
            &pair.signing_key,
            &spend.message(network),
            CONTEXT,
            [84; 32],
        )
        .unwrap()
        .as_ref();
        let key = spend.verifying_key;
        (spend, network, key)
    }

    #[test]
    fn signature_binds_every_public_payout_field_and_network() {
        let (spend, network, key) = signed();
        assert_eq!(spend.verify(network, &key).unwrap().unlock_height, 0);
        assert!(spend.verify([82; 32], &key).is_err());
        assert!(spend.verify(network, &[0; VERIFYING_KEY_BYTES]).is_err());
        assert!(spend.verify(network, &[1; VERIFYING_KEY_BYTES]).is_err());
        for offset in [
            0,
            1,
            9,
            17,
            65,
            113,
            161,
            209,
            1522,
            3474,
            ENCODED_BYTES - 1,
        ] {
            let mut bytes = spend.encode();
            bytes[offset] ^= 1;
            assert!(
                FundSpend::decode(&bytes)
                    .and_then(|s| s.verify(network, &key))
                    .is_err(),
                "offset {offset}"
            );
        }
    }
    #[test]
    fn canonical_fixed_payout_rejects_invalid_account_length_and_commitment() {
        let (spend, network, key) = signed();
        assert_eq!(FundSpend::decode(&spend.encode()).unwrap(), spend);
        assert!(FundSpend::decode(&spend.encode()[..ENCODED_BYTES - 1]).is_err());
        let mut invalid = spend.clone();
        invalid.account = 32;
        assert!(invalid.verify(network, &key).is_err());
        invalid = spend;
        invalid.owner[..4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
        assert!(invalid.verify(network, &key).is_err());
    }
}
