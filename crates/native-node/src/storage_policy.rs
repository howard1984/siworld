//! Local proof-retention decisions. No value in this module changes validity,
//! reward maturity, fork selection, or the protocol's reorganization bound.
use crate::state::MAX_REORG_DEPTH;
use crate::wire::Hash;

pub const SERVICE_RETENTION_SECONDS: u64 = 24 * 60 * 60;
pub const CHECKPOINT_PUBLICATION_SECONDS: u64 = 6 * 60 * 60;
pub const LOCAL_PROOF_BLOCKS: u64 = 96;
pub const MIN_LOCAL_PROOF_BLOCKS: u64 = 24;
pub const CHECKPOINT_MAX_AGE_SECONDS: u64 = crate::engineering_checkpoint::MAX_AGE_SECONDS;
/// Capacity estimate at a five-minute target, not an expiration condition.
pub const NOMINAL_SERVICE_PROOF_BLOCKS: u64 = 312;

/// Process-local checkpoint age for service proof deletion and its alarm.
/// Certificate validity, catchup eligibility, and publication cadence are
/// unchanged. Production builds reject an environment override.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointPruning {
    max_age_seconds: u64,
}
impl Default for CheckpointPruning {
    fn default() -> Self {
        Self {
            max_age_seconds: CHECKPOINT_MAX_AGE_SECONDS,
        }
    }
}
impl CheckpointPruning {
    pub fn from_override(value: Option<&str>) -> Result<Self, String> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        #[cfg(not(feature = "checkpoint-stale-acceptance"))]
        {
            let _ = value;
            Err("checkpoint age override requires the explicit acceptance build".into())
        }
        #[cfg(feature = "checkpoint-stale-acceptance")]
        {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("checkpoint age override requires unsigned integer seconds".into());
            }
            let seconds = value
                .parse::<u64>()
                .map_err(|_| "invalid checkpoint age override")?;
            Self::shortened_for_acceptance(seconds)
        }
    }
    pub(crate) fn from_environment() -> Result<Self, String> {
        let value = match std::env::var("SIWORLD_CHECKPOINT_STALE_SECONDS") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err("invalid checkpoint age override encoding".into());
            }
        };
        Self::from_override(value.as_deref())
    }
    #[cfg(any(test, feature = "checkpoint-stale-acceptance"))]
    pub(crate) fn shortened_for_acceptance(seconds: u64) -> Result<Self, String> {
        if !(1200..=CHECKPOINT_MAX_AGE_SECONDS).contains(&seconds) {
            return Err("checkpoint age override must be between 1200 and 64800 seconds".into());
        }
        Ok(Self {
            max_age_seconds: seconds,
        })
    }
    pub fn max_age_seconds(self) -> u64 {
        self.max_age_seconds
    }
    pub fn fresh(self, issued_unix_seconds: u64, now: u64) -> bool {
        now.checked_sub(issued_unix_seconds)
            .is_some_and(|age| age <= self.max_age_seconds)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Bootstrap,
    Validator,
    Miner,
    Ordinary,
}
impl Role {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "bootstrap" => Ok(Self::Bootstrap),
            "validator" => Ok(Self::Validator),
            "miner" => Ok(Self::Miner),
            "ordinary" => Ok(Self::Ordinary),
            _ => Err("unknown local storage role".into()),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Validator => "validator",
            Self::Miner => "miner",
            Self::Ordinary => "ordinary",
        }
    }
    pub fn serves_historical_proofs(self) -> bool {
        matches!(self, Self::Bootstrap | Self::Validator)
    }
}

/// Explicit operator opt-in for an existing store. Absence preserves the
/// persisted policy, including an unmigrated store's complete history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupPolicy {
    pub role: Role,
    pub local_blocks: Option<u64>,
}
impl StartupPolicy {
    pub fn parse(role: Option<&str>, blocks: Option<&str>) -> Result<Option<Self>, String> {
        let Some(role) = role else {
            return if blocks.is_some() {
                Err("retained proof count requires an explicit storage role".into())
            } else {
                Ok(None)
            };
        };
        let role = Role::parse(role)?;
        let local_blocks = blocks
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| "invalid retained proof count")
            })
            .transpose()?;
        if local_blocks.is_some_and(|n| n < MIN_LOCAL_PROOF_BLOCKS)
            || (role.serves_historical_proofs() && local_blocks.is_some())
        {
            return Err("proof window requires a local role and at least 24 blocks".into());
        }
        Ok(Some(Self { role, local_blocks }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepReason {
    RollbackWindow,
    LocalWindow,
    FinalityUnobserved,
    ServiceTimeWindow,
    ClockUncertain,
    CheckpointUnavailable,
    RecoveryTailUnavailable,
}

/// Observed finality belongs to this exact canonical block. Block timestamps
/// cannot substitute for local finality observation times.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalityObservation {
    pub block_id: Hash,
    pub observed_unix_seconds: u64,
}

/// Evidence supplied by the owner for a newly sealed local replay base and its
/// verified proof tail. This is not a remote checkpoint or publication receipt.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RecoveryBoundary {
    pub height: u64,
    pub sealed_unix_seconds: u64,
    pub tail_complete: bool,
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn expired(
    role: Role,
    height: u64,
    block_id: Hash,
    tip: u64,
    finality: Option<FinalityObservation>,
    now: u64,
    clock_certain: bool,
    recovery: Option<RecoveryBoundary>,
) -> Result<(), KeepReason> {
    expired_with_local_blocks(
        role,
        height,
        block_id,
        tip,
        finality,
        now,
        clock_certain,
        recovery,
        LOCAL_PROOF_BLOCKS,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn expired_with_local_blocks(
    role: Role,
    height: u64,
    block_id: Hash,
    tip: u64,
    finality: Option<FinalityObservation>,
    now: u64,
    clock_certain: bool,
    recovery: Option<RecoveryBoundary>,
    local_blocks: u64,
) -> Result<(), KeepReason> {
    if local_blocks < MIN_LOCAL_PROOF_BLOCKS {
        return Err(KeepReason::LocalWindow);
    }
    if height == 0 || height > tip.saturating_sub(MAX_REORG_DEPTH) {
        return Err(KeepReason::RollbackWindow);
    }
    if !clock_certain {
        return Err(KeepReason::ClockUncertain);
    }
    if role.serves_historical_proofs() {
        let observed = finality
            .filter(|value| value.block_id == block_id)
            .ok_or(KeepReason::FinalityUnobserved)?;
        if now
            .checked_sub(observed.observed_unix_seconds)
            .is_none_or(|age| age < SERVICE_RETENTION_SECONDS)
        {
            return Err(KeepReason::ServiceTimeWindow);
        }
    } else if height > tip.saturating_sub(local_blocks) {
        return Err(KeepReason::LocalWindow);
    }
    let recovery = recovery.ok_or(KeepReason::CheckpointUnavailable)?;
    if recovery.height < height
        || recovery.height > tip.saturating_sub(MAX_REORG_DEPTH)
        || now
            .checked_sub(recovery.sealed_unix_seconds)
            .is_none_or(|age| age > CHECKPOINT_MAX_AGE_SECONDS)
    {
        return Err(KeepReason::CheckpointUnavailable);
    }
    if !recovery.tail_complete {
        return Err(KeepReason::RecoveryTailUnavailable);
    }
    Ok(())
}

pub fn checkpoint_publication_due(last_publication: Option<u64>, now: u64) -> bool {
    last_publication.is_none_or(|last| {
        now.checked_sub(last)
            .is_none_or(|age| age >= CHECKPOINT_PUBLICATION_SECONDS)
    })
}

#[cfg(test)]
mod tests;
