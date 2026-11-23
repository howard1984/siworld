//! Canonical owner-signed positions for the portable three-word assignment.

use libcrux_ml_dsa::ml_dsa_65::{MLDSA65Signature, MLDSA65VerificationKey};
use sivault_core::{
    Error, Result,
    owner::{OwnerIdentity, RecoveryPositions, verify_command},
};

use crate::ledger::SlotIdentity;

const LABEL: &[u8] = b"sivault/recovery/assignment/v1\0";
const WORD_LIST: u8 = 1; // BIP-39 English
const POSITION_BYTES: usize = 4;
pub const RECORD_BYTES: usize = POSITION_BYTES + MLDSA65Signature::len();

pub fn sign(
    owner: &OwnerIdentity,
    slot: SlotIdentity,
    positions: RecoveryPositions,
) -> Result<[u8; RECORD_BYTES]> {
    let [a, b, c] = positions.positions();
    let fields = [WORD_LIST, a, b, c];
    let signature = owner.sign_command(&transcript(slot, fields))?;
    let mut bytes = [0; RECORD_BYTES];
    bytes[..POSITION_BYTES].copy_from_slice(&fields);
    bytes[POSITION_BYTES..].copy_from_slice(signature.as_slice());
    Ok(bytes)
}

/// The expected owner key must come from an authenticated enrollment.
pub fn verify(
    owner: &MLDSA65VerificationKey,
    slot: SlotIdentity,
    bytes: &[u8],
) -> Result<RecoveryPositions> {
    if bytes.len() != RECORD_BYTES || bytes[0] != WORD_LIST {
        return Err(Error::InvalidFormat);
    }
    let fields: [u8; POSITION_BYTES] = bytes[..POSITION_BYTES]
        .try_into()
        .map_err(|_| Error::InvalidFormat)?;
    let positions = RecoveryPositions::from_positions([fields[1], fields[2], fields[3]])?;
    let signature = MLDSA65Signature::new(
        bytes[POSITION_BYTES..]
            .try_into()
            .map_err(|_| Error::InvalidFormat)?,
    );
    verify_command(owner, &transcript(slot, fields), &signature)?;
    Ok(positions)
}

fn transcript(slot: SlotIdentity, fields: [u8; POSITION_BYTES]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(LABEL.len() + 2 + 4 * 32 + POSITION_BYTES);
    transcript.extend_from_slice(LABEL);
    transcript.extend_from_slice(&slot.suite.to_be_bytes());
    for id in [slot.network, slot.safe, slot.slot, slot.ledger] {
        transcript.extend_from_slice(&id.0);
    }
    transcript.extend_from_slice(&fields);
    transcript
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Id;
    use zeroize::Zeroizing;

    #[test]
    fn assignment_copies_preserve_order_and_reject_substitution() {
        let owner = OwnerIdentity::derive(&Zeroizing::new([42; 32]));
        let other = OwnerIdentity::derive(&Zeroizing::new([43; 32]));
        let slot = SlotIdentity {
            suite: 1,
            network: Id([1; 32]),
            safe: Id([2; 32]),
            slot: Id([3; 32]),
            ledger: Id([4; 32]),
        };
        let positions = RecoveryPositions::from_positions([24, 3, 16]).unwrap();
        let record = sign(&owner, slot, positions).unwrap();
        assert_eq!(&record[..POSITION_BYTES], &[1, 24, 3, 16]);
        let copy = record.to_vec();
        assert!(verify(owner.verification_key(), slot, &copy).unwrap() == positions);
        assert!(verify(other.verification_key(), slot, &record).is_err());
        for wrong in [
            SlotIdentity { suite: 2, ..slot },
            SlotIdentity {
                network: Id([9; 32]),
                ..slot
            },
            SlotIdentity {
                safe: Id([9; 32]),
                ..slot
            },
            SlotIdentity {
                slot: Id([9; 32]),
                ..slot
            },
            SlotIdentity {
                ledger: Id([9; 32]),
                ..slot
            },
        ] {
            assert!(verify(owner.verification_key(), wrong, &record).is_err());
        }
        let mut swapped = record;
        swapped.swap(1, 2);
        assert!(verify(owner.verification_key(), slot, &swapped).is_err());
        let mut duplicate = record;
        duplicate[1] = duplicate[2];
        assert!(verify(owner.verification_key(), slot, &duplicate).is_err());
        let mut unknown_list = record;
        unknown_list[0] = 2;
        assert!(verify(owner.verification_key(), slot, &unknown_list).is_err());
        assert!(verify(owner.verification_key(), slot, &copy[..copy.len() - 1]).is_err());
    }
}
