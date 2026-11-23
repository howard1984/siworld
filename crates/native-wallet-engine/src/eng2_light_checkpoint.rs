//! Verify finality on an already receipt-authenticated wallet history.
use super::*;
use crate::{
    eng2_certificate::{Certificate, REQUIRED_CHECKPOINT_DEPTH},
    eng2_governance::SignedAction,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    genesis: Hash,
    anchor: Snapshot,
}
impl VerifiedCheckpoint {
    pub fn anchor(self) -> Snapshot {
        self.anchor
    }
    /// Only use this sealed-local format after authenticating the wallet's
    /// private checkpoint envelope. It grants no authority as network data.
    pub fn local_record(self) -> [u8; 72] {
        let mut bytes = [0; 72];
        bytes[..32].copy_from_slice(&self.genesis);
        bytes[32..40].copy_from_slice(&self.anchor.height.to_le_bytes());
        bytes[40..].copy_from_slice(&self.anchor.block_id);
        bytes
    }
}
impl Eng2LightState {
    pub fn checkpoint_replay_required(&self) -> bool {
        self.checkpoint_replay_required
    }
    pub(super) fn checkpoint_after_receipt(
        &self,
        receipt: &ReceiptBlock,
    ) -> Option<GovernanceState> {
        let mut state = self.checkpoint_governance.clone()?;
        let actions = receipt
            .governance_records()
            .iter()
            .map(|raw| SignedAction::decode(raw))
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        state.apply_block(receipt.header().height, &actions).ok()?;
        Some(state)
    }
    /// No service assertion, unsigned height, or obsolete roster is authority.
    /// Every header on this path came from the accepted complete receipt scan.
    pub fn verify_checkpoint(&self, bytes: &[u8]) -> Result<VerifiedCheckpoint, String> {
        let network = self.context.config().network;
        let certificate =
            Certificate::decode(bytes, network).map_err(|_| "eng2 checkpoint framing rejected")?;
        let statement = &certificate.statement;
        let governance = self
            .checkpoint_governance
            .as_ref()
            .filter(|state| state.height() == self.height())
            .ok_or("eng2 authenticated checkpoint roster unavailable")?;
        let genesis = self
            .genesis_governance
            .as_ref()
            .ok_or("eng2 genesis checkpoint roster unavailable")?;
        let roster = genesis.active_roster();
        // Never accept an unpinned key set. Authenticated rotation also
        // removes authority from the old keys until this client can verify
        // the supported recovery proof.
        if roster != governance.active_roster()
            || roster.epoch_sequence != statement.roster_sequence
            || roster.digest(network) != statement.roster_digest
            || roster.activated_height > statement.authorization_height
            || statement.checkpoint_height == 0
            || statement
                .authorization_height
                .checked_sub(statement.checkpoint_height)
                .is_none_or(|depth| depth < REQUIRED_CHECKPOINT_DEPTH)
            || !self.payment_inclusion_valid(
                statement.authorization_height,
                statement.authorization_block,
            )
            || !self
                .payment_inclusion_valid(statement.checkpoint_height, statement.checkpoint_block)
        {
            return Err("eng2 checkpoint does not match the selected chain and roster".into());
        }
        certificate
            .check_signatures(roster.keys())
            .map_err(|_| "eng2 checkpoint signatures rejected")?;
        Ok(VerifiedCheckpoint {
            genesis: self.context.genesis(),
            anchor: Snapshot {
                height: statement.checkpoint_height,
                block_id: statement.checkpoint_block,
            },
        })
    }
    pub fn checkpoint_covers_inclusion(
        &self,
        floor: VerifiedCheckpoint,
        inclusion: Snapshot,
    ) -> bool {
        inclusion.height > 0
            && inclusion.height <= floor.anchor.height
            && self.preserves_checkpoint(floor)
            && self.payment_inclusion_valid(inclusion.height, inclusion.block_id)
    }

    /// Both views must have independently verified the relevant certificate
    /// against their complete receipt history. A divergent tip alone is not
    /// evidence of a quorum conflict.
    pub fn checkpoint_conflicts(
        &self,
        floor: VerifiedCheckpoint,
        candidate: &Self,
        candidate_certificate: &[u8],
    ) -> Result<bool, String> {
        if !self.preserves_checkpoint(floor)
            || self.context.genesis() != candidate.context.genesis()
        {
            return Err("eng2 checkpoint conflict context rejected".into());
        }
        let next = candidate.verify_checkpoint(candidate_certificate)?;
        let common = floor.anchor.height.min(next.anchor.height);
        let a = self.header(common).and_then(|header| header.id().ok());
        let b = candidate.header(common).and_then(|header| header.id().ok());
        match (a, b) {
            (Some(a), Some(b)) => Ok(a != b),
            _ => Err("eng2 checkpoint conflict history unavailable".into()),
        }
    }

    /// Restore after the host has opened a private authenticated local record.
    /// The former authorization block may have been replaced above this floor.
    pub fn restore_local_checkpoint(&self, bytes: &[u8]) -> Result<VerifiedCheckpoint, String> {
        let bytes: &[u8; 72] = bytes
            .try_into()
            .map_err(|_| "eng2 local checkpoint width rejected")?;
        let floor = VerifiedCheckpoint {
            genesis: bytes[..32].try_into().unwrap(),
            anchor: Snapshot {
                height: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
                block_id: bytes[40..].try_into().unwrap(),
            },
        };
        if !self.preserves_checkpoint(floor) {
            return Err("eng2 local checkpoint conflicts with selected chain".into());
        }
        Ok(floor)
    }
    pub fn preserves_checkpoint(&self, floor: VerifiedCheckpoint) -> bool {
        self.context.genesis() == floor.genesis
            && self.payment_inclusion_valid(floor.anchor.height, floor.anchor.block_id)
    }
}
