//! Version-two fee policy and private settlement witness checks.
//!
//! This module is a witness specification, not a proof verifier or an activated
//! network rule. Its corresponding AIR and authenticated state adapters must
//! enforce the same relation before any version-two block can be accepted.
use native::confidential_fees::SettlementSlot;
use native::multi_asset::{Digest, Hasher, Note, SIP_ASSET_ID};
use native::settlement::RewardPlan;

pub const MAX_SETTLEMENT_SLOTS: usize = 576;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeSchedule {
    standard: u64,
    priority: u64,
}

impl FeeSchedule {
    /// Divide the previous standard tier first, then derive the priority tier.
    pub fn from_previous_standard(previous_standard: u64) -> Result<Self, String> {
        let standard = previous_standard / 10;
        let priority = standard.checked_mul(4).ok_or("priority fee overflow")?;
        Ok(Self { standard, priority })
    }

    pub fn standard(self) -> u64 {
        self.standard
    }

    pub fn priority(self) -> u64 {
        self.priority
    }
}

/// Values derived by the caller from the authenticated, activated block state.
pub struct SettlementPolicy {
    pub plan: RewardPlan,
    pub fee_owner: Digest,
    pub fees: FeeSchedule,
    pub max_slots: usize,
}

/// Private witness only. Never serialize this structure into a public export.
/// The fee output always exists, including when its value is zero.
pub struct PrivateSettlement {
    pub rewards: Vec<Note>,
    pub fee_note: Note,
    pub slots: Vec<SettlementSlot>,
}

impl PrivateSettlement {
    /// Check the witness before trace construction. Success does not establish
    /// possession of a proof and cannot authorize a consensus state transition.
    pub fn validate(&self, policy: &SettlementPolicy) -> Result<(), String> {
        policy.plan.validate()?;
        if !(1..=MAX_SETTLEMENT_SLOTS).contains(&policy.max_slots)
            || self.slots.is_empty()
            || self.slots.len() > policy.max_slots
            || self.rewards.len() != policy.plan.mode.note_count()
        {
            return Err("invalid settlement capacity or reward count".into());
        }
        let hasher = Hasher::new();
        let mut total = 0u64;
        for (index, slot) in self.slots.iter().enumerate() {
            let opening = &slot.opening;
            if opening.dummy {
                if opening.fee != 0 || opening.priority {
                    return Err("invalid padding fee witness".into());
                }
            } else {
                let expected = if opening.priority {
                    policy.fees.priority
                } else {
                    policy.fees.standard
                };
                if opening.fee == 0 || opening.fee != expected {
                    return Err("invalid fee tier witness".into());
                }
            }
            if hasher.fee_commit(opening.fee, &opening.blind) != slot.commitment
                || self.slots[..index]
                    .iter()
                    .any(|old| old.commitment == slot.commitment)
            {
                return Err("invalid or duplicate fee commitment".into());
            }
            total = total
                .checked_add(opening.fee)
                .ok_or("private fee sum overflow")?;
        }
        if self.fee_note.asset_id != SIP_ASSET_ID
            || self.fee_note.owner != policy.fee_owner
            || self.fee_note.value != total
            || self.fee_note.unlock_height != 0
        {
            return Err("invalid private fee destination output".into());
        }
        for (index, (note, allocation)) in self
            .rewards
            .iter()
            .zip(&policy.plan.allocations)
            .enumerate()
        {
            if note.asset_id != SIP_ASSET_ID
                || note.value != allocation.amount
                || note.unlock_height != allocation.unlock_height
                || note.rho != hasher.reward_rho(policy.plan.block_height, index)
            {
                return Err("invalid subsidy-only reward witness".into());
            }
        }
        let fee_commitment = hasher.note_cm(&self.fee_note);
        let mut reward_commitments = Vec::with_capacity(self.rewards.len());
        for note in &self.rewards {
            let commitment = hasher.note_cm(note);
            if commitment == fee_commitment || reward_commitments.contains(&commitment) {
                return Err("duplicate settlement output".into());
            }
            reward_commitments.push(commitment);
        }
        Ok(())
    }
}
