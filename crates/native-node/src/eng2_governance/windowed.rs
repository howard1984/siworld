//! Explicitly versioned governance authorization with a signed inclusion window.
//! This format does not alter the legacy action codec or genesis selection.
use super::*;

const MAGIC: &[u8; 8] = b"SWG2WIN2";
const PREFIX_BYTES: usize = 28;
pub const MIN_VALIDITY_BLOCKS: u64 = 288;
const CONTEXT: &[u8] = b"siworld eng2 governance window v2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowedSignedAction {
    pub signed: SignedAction,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl WindowedSignedAction {
    pub const MAX_ENCODED_BYTES: usize = PREFIX_BYTES + SignedAction::MAX_ENCODED_BYTES;

    pub fn validate_window(&self) -> Result<(), String> {
        let minimum_end = self
            .valid_from
            .checked_add(MIN_VALIDITY_BLOCKS - 1)
            .ok_or("governance authorization window overflows")?;
        require(
            self.valid_from > 0 && self.valid_until >= minimum_end,
            "governance authorization window is shorter than 288 blocks",
        )
    }

    /// Canonical action and interval, excluding all signature fields.
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate_window()?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&self.valid_from.to_le_bytes());
        bytes.extend_from_slice(&self.valid_until.to_le_bytes());
        bytes.extend_from_slice(&self.signed.action.unsigned_bytes()?);
        Ok(bytes)
    }

    pub fn signing_bytes(&self, role: SignerRole) -> Result<Vec<u8>, String> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.push(match role {
            SignerRole::Founder => 0,
            SignerRole::Revocation => 1,
            SignerRole::Checkpoint(slot) if slot < 3 => 2 + slot,
            _ => return Err("unknown windowed governance signer role".into()),
        });
        Ok(bytes)
    }

    pub fn signature_context() -> &'static [u8] {
        CONTEXT
    }

    pub fn decode_unsigned(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 24 || bytes.len() > 24 + 8192 || &bytes[..8] != MAGIC {
            return Err("noncanonical unsigned windowed governance action".into());
        }
        let value = Self {
            valid_from: u64::from_le_bytes(bytes[8..16].try_into().expect("fixed start")),
            valid_until: u64::from_le_bytes(bytes[16..24].try_into().expect("fixed end")),
            signed: SignedAction {
                action: Action::decode_unsigned(&bytes[24..])?,
                signatures: Vec::new(),
            },
        };
        value.validate_window()?;
        if value.unsigned_bytes()? != bytes {
            return Err("noncanonical unsigned windowed action".into());
        }
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate_window()?;
        let signed = self.signed.encode()?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&self.valid_from.to_le_bytes());
        bytes.extend_from_slice(&self.valid_until.to_le_bytes());
        bytes.extend_from_slice(&(signed.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&signed);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < PREFIX_BYTES
            || bytes.len() > Self::MAX_ENCODED_BYTES
            || &bytes[..8] != MAGIC
        {
            return Err("noncanonical windowed governance encoding".into());
        }
        let length = u32::from_le_bytes(bytes[24..28].try_into().expect("fixed length")) as usize;
        if length != bytes.len() - PREFIX_BYTES {
            return Err("windowed governance length differs".into());
        }
        let value = Self {
            valid_from: u64::from_le_bytes(bytes[8..16].try_into().expect("fixed start")),
            valid_until: u64::from_le_bytes(bytes[16..24].try_into().expect("fixed end")),
            signed: SignedAction::decode(&bytes[PREFIX_BYTES..])?,
        };
        value.validate_window()?;
        if value.encode()? != bytes {
            return Err("noncanonical windowed governance action".into());
        }
        Ok(value)
    }
}

impl GovernanceState {
    /// Candidate execution with the same activation, role, sequence and action
    /// transition as legacy execution. This method does not select a genesis.
    /// Every rejection leaves this state unchanged, including activation work.
    pub fn apply_windowed_block(
        &mut self,
        height: u64,
        actions: &[WindowedSignedAction],
    ) -> Result<Vec<Inclusion>, String> {
        require(
            self.height.checked_add(1) == Some(height),
            "governance height must advance exactly one block",
        )?;
        require(
            actions.len() <= MAX_ACTIONS_PER_BLOCK,
            "governance action count exceeds block bound",
        )?;
        let mut staged = self.clone();
        staged.activate(height)?;
        let mut events = Vec::with_capacity(actions.len());
        for action in actions {
            action.validate_window()?;
            require(
                (action.valid_from..=action.valid_until).contains(&height),
                "governance authorization is outside its signed window",
            )?;
            staged.authenticate_message(
                &action.signed,
                |role| action.signing_bytes(role),
                CONTEXT,
            )?;
            let digest = blake3::derive_key(
                "siworld eng2 governance action window v2",
                &action.unsigned_bytes()?,
            );
            events.push(staged.include_authenticated(height, &action.signed.action, digest)?);
        }
        staged.height = height;
        staged.validate()?;
        *self = staged;
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::WalletKeys;
    use zeroize::Zeroizing;

    fn fixture() -> (GovernanceState, WindowedSignedAction) {
        let key = |seed| {
            *ml_dsa_65::generate_key_pair([seed; 32])
                .verification_key
                .as_ref()
        };
        let address = |seed| {
            WalletKeys::from_seed([7; 32], Zeroizing::new([seed; 32]), 0)
                .unwrap()
                .address()
        };
        let state = GovernanceState::new(
            [7; 32],
            key(1),
            key(2),
            [3, 4, 5].map(key),
            address(6),
            vec![address(8)],
        )
        .unwrap();
        let mut action = WindowedSignedAction {
            signed: SignedAction {
                action: Action {
                    network: [7; 32],
                    sequence: 1,
                    kind: ActionKind::ProposeIssuanceFee {
                        amount_atoms: 100_000_000,
                    },
                },
                signatures: vec![Authorization {
                    role: SignerRole::Founder,
                    signature: [0; SIGNATURE_BYTES],
                }],
            },
            valid_from: 2,
            valid_until: 289,
        };
        action.signed.signatures[0].signature = *ml_dsa_65::sign(
            &ml_dsa_65::generate_key_pair([1; 32]).signing_key,
            &action.signing_bytes(SignerRole::Founder).unwrap(),
            CONTEXT,
            [41; 32],
        )
        .unwrap()
        .as_ref();
        (state, action)
    }

    #[test]
    fn exact_interval_replay_and_format_boundaries() {
        let (state, action) = fixture();
        let bytes = action.encode().unwrap();
        assert_eq!(WindowedSignedAction::decode(&bytes).unwrap(), action);
        assert!(SignedAction::decode(&bytes).is_err());
        assert!(WindowedSignedAction::decode(&action.signed.encode().unwrap()).is_err());
        for height in [1, 2, 289, 290] {
            let mut current = state.clone();
            while current.height() + 1 < height {
                current.apply_block(current.height() + 1, &[]).unwrap();
            }
            let before = current.clone();
            let result = current.apply_windowed_block(height, std::slice::from_ref(&action));
            if [2, 289].contains(&height) {
                assert_eq!(result.unwrap()[0].included_height, height);
                let accepted = current.clone();
                assert!(
                    current
                        .apply_windowed_block(height + 1, std::slice::from_ref(&action))
                        .is_err()
                );
                assert_eq!(current, accepted);
            } else {
                assert!(result.is_err());
                assert_eq!(current, before);
            }
        }
        for end in [288, u64::MAX] {
            let mut changed = action.clone();
            changed.valid_until = end;
            let mut current = state.clone();
            current.apply_block(1, &[]).unwrap();
            let before = current.clone();
            assert!(current.apply_windowed_block(2, &[changed]).is_err());
            assert_eq!(current, before);
        }
        assert!(WindowedSignedAction::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(WindowedSignedAction::decode(&trailing).is_err());
    }

    #[test]
    fn restored_state_reincludes_unchanged_authorization_only_before_expiry() {
        let (mut state, action) = fixture();
        state.apply_block(1, &[]).unwrap();
        let savepoint = state.clone();
        let signed_bytes = action.encode().unwrap();
        let first = state
            .apply_windowed_block(2, std::slice::from_ref(&action))
            .unwrap();
        let consumed = state.clone();
        assert!(
            state
                .apply_windowed_block(3, std::slice::from_ref(&action))
                .is_err()
        );
        assert_eq!(state, consumed);

        // This models restored authorization state, not a durable-store reorg.
        state = savepoint.clone();
        for height in 2..289 {
            state.apply_block(height, &[]).unwrap();
        }
        let replacement = state
            .apply_windowed_block(289, std::slice::from_ref(&action))
            .unwrap();
        assert_eq!(first[0].action_digest, replacement[0].action_digest);
        assert_eq!(first[0].included_height, 2);
        assert_eq!(replacement[0].included_height, 289);
        assert_eq!(action.encode().unwrap(), signed_bytes);

        state = savepoint;
        for height in 2..290 {
            state.apply_block(height, &[]).unwrap();
        }
        let expired = state.clone();
        assert!(
            state
                .apply_windowed_block(290, std::slice::from_ref(&action))
                .is_err()
        );
        assert_eq!(state, expired);
    }

    #[test]
    fn failing_later_action_does_not_publish_earlier_action() {
        let (mut state, action) = fixture();
        state.apply_block(1, &[]).unwrap();
        let before = state.clone();
        let mut bad = action.clone();
        bad.signed.action.sequence = 2;
        assert!(state.apply_windowed_block(2, &[action, bad]).is_err());
        assert_eq!(state, before);
    }
}
