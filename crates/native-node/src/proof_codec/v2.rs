//! Explicit framing for the native hiding proof profile.
//!
//! Framing authenticates neither a profile nor a proof. The expected identity
//! must come from trusted network configuration; callers must also preflight
//! the complete typed body and verify its independently rebuilt statement.

#[path = "v2/backend/mod.rs"]
pub mod backend;

#[path = "v2/batch.rs"]
pub mod batch;

#[path = "v2/complete_fee/mod.rs"]
pub mod complete_fee;

#[cfg(not(target_family = "wasm"))]
#[path = "v2/fee_guard.rs"]
pub mod fee_guard;
#[path = "v2/native.rs"]
pub mod native;
#[path = "v2/receive.rs"]
pub mod receive;

pub const MAX_TRANSACTION_PROOF_BYTES: usize = 655_360;
pub const MAX_FEE_PROOF_BYTES: usize = 5_242_880;
pub const MAX_ISSUANCE_PROOF_BYTES: usize = 524_288;
/// Transaction compatibility name. Other relations have independent limits.
pub const MAX_PROOF_BYTES: usize = MAX_TRANSACTION_PROOF_BYTES;
pub const FRAME_BYTES: usize = 48;
pub const MAX_BODY_BYTES: usize = MAX_PROOF_BYTES - FRAME_BYTES;
const MAGIC: &[u8; 8] = b"SIWZKP2\0";
const VERSION: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Relation {
    Transaction = 1,
    Settlement = 2,
    Issuance = 3,
    CompleteFee = 4,
}
impl Relation {
    pub const fn maximum_frame_bytes(self) -> usize {
        match self {
            Self::Transaction => MAX_TRANSACTION_PROOF_BYTES,
            Self::Settlement | Self::CompleteFee => MAX_FEE_PROOF_BYTES,
            Self::Issuance => MAX_ISSUANCE_PROOF_BYTES,
        }
    }
}

/// Canonical consensus-parameter record for a new V2 genesis. This inactive
/// record does not alter the retained engineering genesis or enable admission.
/// The rules commitment and genesis registry must include these exact bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusProofLimits;
impl ConsensusProofLimits {
    pub const BYTES: usize = 24;
    pub const FEE_PROOFS_PER_BLOCK: u8 = 1;
    pub fn encode(self) -> [u8; Self::BYTES] {
        let mut bytes = [0; Self::BYTES];
        bytes[..8].copy_from_slice(b"SW2PLM01");
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10..14].copy_from_slice(&(MAX_TRANSACTION_PROOF_BYTES as u32).to_le_bytes());
        bytes[14..18].copy_from_slice(&(MAX_FEE_PROOF_BYTES as u32).to_le_bytes());
        bytes[18..22].copy_from_slice(&(MAX_ISSUANCE_PROOF_BYTES as u32).to_le_bytes());
        bytes[22] = Self::FEE_PROOFS_PER_BLOCK;
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes != Self.encode() {
            return Err(FrameError::InvalidLimit);
        }
        Ok(Self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub relation: Relation,
    /// Binds the backend, relation, AIR, key, codec, and network configuration.
    /// A backend parameter digest alone is insufficient.
    pub profile: [u8; 32],
}

/// Authenticated protocol inputs, selected locally rather than from a proof.
/// `air` identifies the complete constraint program and relation parameters;
/// dimensions alone do not identify an AIR. These values require a matching
/// genesis registry before this candidate format can be admitted by a network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolBinding {
    pub genesis: [u8; 32],
    pub rules: [u8; 32],
    pub air: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    InvalidLimit,
    Size,
    Header,
    Identity,
}

fn checked_limit(relation: Relation, limit: usize) -> Result<(), FrameError> {
    if !(FRAME_BYTES + 1..=relation.maximum_frame_bytes()).contains(&limit) {
        return Err(FrameError::InvalidLimit);
    }
    Ok(())
}

/// Encode an already validated body. The limit includes the entire frame.
pub fn encode(identity: Identity, body: &[u8], limit: usize) -> Result<Vec<u8>, FrameError> {
    checked_limit(identity.relation, limit)?;
    if body.is_empty() || body.len() > limit - FRAME_BYTES {
        return Err(FrameError::Size);
    }
    let mut bytes = Vec::with_capacity(FRAME_BYTES + body.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.push(identity.relation as u8);
    bytes.push(0);
    bytes.extend_from_slice(&identity.profile);
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    Ok(bytes)
}

/// Borrow the bounded body without allocating or falling back to older formats.
pub fn parse(bytes: &[u8], expected: Identity, limit: usize) -> Result<&[u8], FrameError> {
    checked_limit(expected.relation, limit)?;
    let header = bytes.get(..FRAME_BYTES).ok_or(FrameError::Size)?;
    preflight_header(header.try_into().unwrap(), expected, bytes.len(), limit)?;
    Ok(&bytes[FRAME_BYTES..])
}

pub(super) fn admit_declared_size(
    relation: Relation,
    declared: usize,
    limit: usize,
) -> Result<(), FrameError> {
    checked_limit(relation, limit)?;
    if declared <= FRAME_BYTES || declared > limit {
        return Err(FrameError::Size);
    }
    Ok(())
}

pub(super) fn preflight_header(
    bytes: &[u8; FRAME_BYTES],
    expected: Identity,
    declared: usize,
    limit: usize,
) -> Result<usize, FrameError> {
    checked_limit(expected.relation, limit)?;
    admit_declared_size(expected.relation, declared, limit)?;
    if &bytes[..8] != MAGIC || bytes[8..10] != VERSION.to_le_bytes() || bytes[11] != 0 {
        return Err(FrameError::Header);
    }
    if bytes[10] != expected.relation as u8 || bytes[12..44] != expected.profile {
        return Err(FrameError::Identity);
    }
    let body_len = u32::from_le_bytes(bytes[44..48].try_into().unwrap()) as usize;
    if body_len == 0 || body_len != declared - FRAME_BYTES {
        return Err(FrameError::Size);
    }
    Ok(body_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: Identity = Identity {
        relation: Relation::Transaction,
        profile: [17; 32],
    };

    #[test]
    fn complete_frame_obeys_the_existing_cap() {
        let body = vec![7; MAX_BODY_BYTES];
        let frame = encode(IDENTITY, &body, MAX_PROOF_BYTES).unwrap();
        assert_eq!(frame.len(), MAX_PROOF_BYTES);
        assert_eq!(
            parse(&frame, IDENTITY, MAX_PROOF_BYTES),
            Ok(body.as_slice())
        );
        assert_eq!(
            encode(IDENTITY, &vec![7; MAX_BODY_BYTES + 1], MAX_PROOF_BYTES),
            Err(FrameError::Size)
        );
    }

    #[test]
    fn framing_rejects_wrong_identity_old_versions_and_trailing_bytes() {
        let frame = encode(IDENTITY, &[1, 2, 3], MAX_PROOF_BYTES).unwrap();
        for offset in [0, 8, 10, 11, 12, 44] {
            let mut changed = frame.clone();
            changed[offset] ^= 1;
            assert!(parse(&changed, IDENTITY, MAX_PROOF_BYTES).is_err());
        }
        for end in 0..frame.len() {
            assert!(parse(&frame[..end], IDENTITY, MAX_PROOF_BYTES).is_err());
        }
        let mut trailing = frame;
        trailing.push(0);
        assert_eq!(
            parse(&trailing, IDENTITY, MAX_PROOF_BYTES),
            Err(FrameError::Size)
        );
    }

    #[test]
    fn issuance_can_retain_its_stricter_existing_limit() {
        let identity = Identity {
            relation: Relation::Issuance,
            ..IDENTITY
        };
        let limit = 524_288;
        assert_eq!(
            encode(identity, &vec![0; limit - FRAME_BYTES], limit)
                .unwrap()
                .len(),
            limit
        );
        assert_eq!(
            encode(identity, &vec![0; limit - FRAME_BYTES + 1], limit),
            Err(FrameError::Size)
        );
        assert_eq!(
            parse(&[], identity, MAX_PROOF_BYTES + 1),
            Err(FrameError::InvalidLimit)
        );
    }

    #[test]
    fn fee_frame_has_an_independent_five_mib_consensus_limit() {
        let fee = Identity {
            relation: Relation::CompleteFee,
            ..IDENTITY
        };
        let body = vec![0; MAX_FEE_PROOF_BYTES - FRAME_BYTES];
        let frame = encode(fee, &body, MAX_FEE_PROOF_BYTES).unwrap();
        assert_eq!(frame.len(), 5_242_880);
        assert_eq!(parse(&frame, fee, MAX_FEE_PROOF_BYTES), Ok(body.as_slice()));
        assert_eq!(
            encode(IDENTITY, &[1], MAX_FEE_PROOF_BYTES),
            Err(FrameError::InvalidLimit)
        );
        assert_eq!(
            encode(fee, &vec![0; body.len() + 1], MAX_FEE_PROOF_BYTES),
            Err(FrameError::Size)
        );
    }

    #[test]
    fn genesis_limit_record_binds_each_limit_and_one_fee_proof() {
        let bytes = ConsensusProofLimits.encode();
        assert_eq!(
            ConsensusProofLimits::decode(&bytes),
            Ok(ConsensusProofLimits)
        );
        assert_eq!(
            u32::from_le_bytes(bytes[10..14].try_into().unwrap()),
            655_360
        );
        assert_eq!(
            u32::from_le_bytes(bytes[14..18].try_into().unwrap()),
            5_242_880
        );
        assert_eq!(bytes[22], 1);
        for i in 0..bytes.len() {
            let mut changed = bytes;
            changed[i] ^= 1;
            assert_eq!(
                ConsensusProofLimits::decode(&changed),
                Err(FrameError::InvalidLimit)
            );
        }
    }
}
