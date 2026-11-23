//! Shared checkpoint statement framing and signature verification.
use crate::wire::Hash;

pub const STATEMENT_BYTES: usize = 158;
pub const SIGNATURE_BYTES: usize = 3309;
pub const VERIFYING_KEY_BYTES: usize = 1952;
pub const REQUIRED_CHECKPOINT_DEPTH: u64 = 24;
pub const CERTIFICATE_BYTES: usize = STATEMENT_BYTES + 2 * (1 + SIGNATURE_BYTES);
const DOMAIN: &[u8] = b"siworld eng2 checkpoint context v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub network: Hash,
    pub checkpoint_height: u64,
    pub checkpoint_block: Hash,
    pub authorization_height: u64,
    pub authorization_block: Hash,
    pub roster_sequence: u64,
    pub roster_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub slot: u8,
    pub signature: [u8; SIGNATURE_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub statement: Statement,
    pub votes: [Vote; 2],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertificateError {
    Encoding,
    Network,
    Height,
    Slots,
    Keys,
    Signature,
    Witness,
    Bounds,
    AboveHead,
}

impl Statement {
    pub fn signing_context() -> &'static [u8] {
        DOMAIN
    }
    pub fn encode(&self) -> Result<[u8; STATEMENT_BYTES], CertificateError> {
        if self.network == [0; 32] {
            return Err(CertificateError::Network);
        }
        if self.authorization_height < self.checkpoint_height {
            return Err(CertificateError::Height);
        }
        let mut bytes = [0; STATEMENT_BYTES];
        bytes[..6].copy_from_slice(b"SW2C\x01\x00");
        bytes[6..38].copy_from_slice(&self.network);
        bytes[38..46].copy_from_slice(&self.checkpoint_height.to_le_bytes());
        bytes[46..78].copy_from_slice(&self.checkpoint_block);
        bytes[78..86].copy_from_slice(&self.authorization_height.to_le_bytes());
        bytes[86..118].copy_from_slice(&self.authorization_block);
        bytes[118..126].copy_from_slice(&self.roster_sequence.to_le_bytes());
        bytes[126..158].copy_from_slice(&self.roster_digest);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], network: Hash) -> Result<Self, CertificateError> {
        if bytes.len() != STATEMENT_BYTES || &bytes[..6] != b"SW2C\x01\x00" {
            return Err(CertificateError::Encoding);
        }
        if network == [0; 32] || bytes[6..38] != network {
            return Err(CertificateError::Network);
        }
        let statement = Self {
            network,
            checkpoint_height: u64::from_le_bytes(bytes[38..46].try_into().expect("fixed height")),
            checkpoint_block: bytes[46..78].try_into().expect("fixed checkpoint identity"),
            authorization_height: u64::from_le_bytes(
                bytes[78..86]
                    .try_into()
                    .expect("fixed authorization height"),
            ),
            authorization_block: bytes[86..118]
                .try_into()
                .expect("fixed authorization identity"),
            roster_sequence: u64::from_le_bytes(
                bytes[118..126].try_into().expect("fixed roster sequence"),
            ),
            roster_digest: bytes[126..158].try_into().expect("fixed roster digest"),
        };
        statement.encode()?;
        Ok(statement)
    }
}
impl Certificate {
    pub fn encode(&self) -> Result<[u8; CERTIFICATE_BYTES], CertificateError> {
        self.check_slots()?;
        let mut bytes = [0; CERTIFICATE_BYTES];
        bytes[..STATEMENT_BYTES].copy_from_slice(&self.statement.encode()?);
        for (index, vote) in self.votes.iter().enumerate() {
            let offset = STATEMENT_BYTES + index * (1 + SIGNATURE_BYTES);
            bytes[offset] = vote.slot;
            bytes[offset + 1..offset + 1 + SIGNATURE_BYTES].copy_from_slice(&vote.signature);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], network: Hash) -> Result<Self, CertificateError> {
        if bytes.len() != CERTIFICATE_BYTES {
            return Err(CertificateError::Encoding);
        }
        let statement = Statement::decode(&bytes[..STATEMENT_BYTES], network)?;
        let votes = core::array::from_fn(|index| {
            let offset = STATEMENT_BYTES + index * (1 + SIGNATURE_BYTES);
            Vote {
                slot: bytes[offset],
                signature: bytes[offset + 1..offset + 1 + SIGNATURE_BYTES]
                    .try_into()
                    .expect("fixed signature"),
            }
        });
        let certificate = Self { statement, votes };
        certificate.check_slots()?;
        Ok(certificate)
    }
    /// Cryptographic verification only; these keys still require authenticated
    /// current-epoch authorization before a contradiction can stop admission.
    pub fn check_signatures(
        &self,
        keys: &[[u8; VERIFYING_KEY_BYTES]; 3],
    ) -> Result<(), CertificateError> {
        use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65Signature, MLDSA65VerificationKey};
        self.check_slots()?;
        if keys
            .iter()
            .enumerate()
            .any(|(index, key)| key.iter().all(|b| *b == 0) || keys[..index].contains(key))
        {
            return Err(CertificateError::Keys);
        }
        let statement = self.statement.encode()?;
        for vote in &self.votes {
            let key = MLDSA65VerificationKey::new(keys[usize::from(vote.slot)]);
            let signature = MLDSA65Signature::new(vote.signature);
            ml_dsa_65::verify(&key, &statement, DOMAIN, &signature)
                .map_err(|_| CertificateError::Signature)?;
        }
        Ok(())
    }
    fn check_slots(&self) -> Result<(), CertificateError> {
        if self.votes[0].slot >= self.votes[1].slot || self.votes[1].slot >= 3 {
            return Err(CertificateError::Slots);
        }
        Ok(())
    }
}
