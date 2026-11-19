//! Inactive fee policy inputs, supplied by authenticated block state.
use ::native::multi_asset::Digest;
use ::native::settlement::RewardPlan;
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
