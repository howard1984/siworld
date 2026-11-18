//! Local proof-body retention. These decisions never grant signing authority,
//! select a chain, or delete permanent public records.

pub const DEFAULT_MINER_BLOCKS: u64 = 96;
pub const MIN_MINER_BLOCKS: u64 = 24;
pub const SERVICE_BLOCKS: u64 = 312;
pub const SERVICE_SECONDS: u64 = 24 * 60 * 60;
pub const CHECKPOINT_STALE_SECONDS: u64 = 18 * 60 * 60;
const MAX_OBSERVATION_GAP: u64 = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Policy {
    Miner { blocks: u64 },
    Service,
}
impl Policy {
    pub fn miner(blocks: Option<u64>) -> Result<Self, &'static str> {
        let blocks = blocks.unwrap_or(DEFAULT_MINER_BLOCKS);
        if blocks < MIN_MINER_BLOCKS {
            return Err("miner proof retention requires at least 24 blocks");
        }
        Ok(Self::Miner { blocks })
    }
    pub fn retained_blocks(self) -> u64 {
        match self {
            Self::Miner { blocks } => blocks,
            Self::Service => SERVICE_BLOCKS,
        }
    }
}

/// Opt-in resident configuration. Omission or null preserves existing storage.
/// The local configured role determines retention; remote peers cannot select it.
#[cfg(feature = "eng2-runtime")]
pub(crate) fn configured(
    value: Option<&serde_json::Value>,
    role: crate::p2p::Role,
) -> Result<Option<Policy>, String> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .ok_or("proof retention requires an object or null")?;
    if object.get("enabled") != Some(&serde_json::Value::Bool(true)) {
        return Err("proof retention requires explicit enabled=true".into());
    }
    match role {
        crate::p2p::Role::Miner => {
            if object.len() != 1 + usize::from(object.contains_key("miner_blocks")) {
                return Err("unknown miner proof retention field".into());
            }
            let blocks = object
                .get("miner_blocks")
                .map(|value| {
                    value
                        .as_u64()
                        .ok_or("miner proof retention requires an unsigned block count")
                })
                .transpose()?;
            Policy::miner(blocks).map(Some).map_err(str::to_owned)
        }
        crate::p2p::Role::Bootstrap | crate::p2p::Role::Validator => {
            if object.len() != 1 {
                return Err("service proof retention has fixed time and block floors".into());
            }
            Ok(Some(Policy::Service))
        }
        _ => Err("proof retention requires an independently validating role".into()),
    }
}

/// Constructed only from an authenticated current checkpoint capability by the
/// local Store adapter. Wire bytes and a claimed checkpoint height are not one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Checkpoint {
    pub(super) height: u64,
    pub(super) block: [u8; 32],
    pub(super) published: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pause {
    CheckpointUnavailable,
    CheckpointStale,
    ClockUncertain,
}
impl Pause {
    pub fn code(self) -> &'static str {
        match self {
            Self::CheckpointUnavailable => "proof_pruning_checkpoint_unavailable",
            Self::CheckpointStale => "proof_pruning_checkpoint_stale",
            Self::ClockUncertain => "proof_pruning_clock_uncertain",
        }
    }
}

/// Accumulated observed runtime, not block timestamps or elapsed downtime.
/// The Store persists `credited_seconds`; each new process starts without a
/// previous sample, so a restart cannot credit an unobserved finality interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Clock {
    pub(super) credited_seconds: u64,
    previous: Option<(u64, u64)>,
}
impl Clock {
    pub(super) fn resume(credited_seconds: u64) -> Self {
        Self {
            credited_seconds,
            previous: None,
        }
    }
    /// The monotonic sample comes from the current owner, never a peer.
    pub(super) fn observe(&mut self, wall: u64, monotonic: u64) -> Result<(), Pause> {
        let previous = self.previous.replace((wall, monotonic));
        let Some((old_wall, old_monotonic)) = previous else {
            return Err(Pause::ClockUncertain);
        };
        let wall_delta = wall.checked_sub(old_wall).ok_or(Pause::ClockUncertain)?;
        let delta = monotonic
            .checked_sub(old_monotonic)
            .ok_or(Pause::ClockUncertain)?;
        if delta > MAX_OBSERVATION_GAP || wall_delta.abs_diff(delta) > 2 {
            return Err(Pause::ClockUncertain);
        }
        self.credited_seconds = self
            .credited_seconds
            .checked_add(delta)
            .ok_or(Pause::ClockUncertain)?;
        Ok(())
    }
}

/// A first observed finality interval belongs to this exact accepted block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Finality {
    pub(super) block: [u8; 32],
    pub(super) credited_at: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    Keep,
    ExpireProofBody,
    Paused(Pause),
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn decide(
    policy: Policy,
    height: u64,
    block: [u8; 32],
    head: u64,
    checkpoint: Option<Checkpoint>,
    now: u64,
    clock_certain: bool,
    credited_seconds: u64,
    finality: Option<Finality>,
) -> Decision {
    let Some(checkpoint) =
        checkpoint.filter(|cp| cp.height > 0 && cp.height <= head.saturating_sub(24))
    else {
        return Decision::Paused(Pause::CheckpointUnavailable);
    };
    let Some(age) = now.checked_sub(checkpoint.published) else {
        return Decision::Paused(Pause::ClockUncertain);
    };
    if age > CHECKPOINT_STALE_SECONDS {
        return Decision::Paused(Pause::CheckpointStale);
    }
    if !clock_certain {
        return Decision::Paused(Pause::ClockUncertain);
    }
    let keep = policy.retained_blocks();
    if matches!(policy, Policy::Miner { blocks } if blocks < MIN_MINER_BLOCKS)
        || height == 0
        || height > head.saturating_sub(keep)
        || height > checkpoint.height
    {
        return Decision::Keep;
    }
    if policy == Policy::Service {
        let Some(finality) = finality.filter(|f| f.block == block) else {
            return Decision::Keep;
        };
        if credited_seconds
            .checked_sub(finality.credited_at)
            .is_none_or(|age| age < SERVICE_SECONDS)
        {
            return Decision::Keep;
        }
    }
    Decision::ExpireProofBody
}

#[cfg(test)]
mod tests {
    use super::*;
    fn checkpoint() -> Checkpoint {
        Checkpoint {
            height: 400,
            block: [4; 32],
            published: 100_000,
        }
    }
    fn decision(policy: Policy, height: u64, head: u64) -> Decision {
        decide(
            policy,
            height,
            [1; 32],
            head,
            Some(checkpoint()),
            100_100,
            true,
            SERVICE_SECONDS,
            Some(Finality {
                block: [1; 32],
                credited_at: 0,
            }),
        )
    }
    #[test]
    fn miners_retain_96_by_default_and_never_less_than_24() {
        assert_eq!(Policy::miner(None).unwrap().retained_blocks(), 96);
        assert!(Policy::miner(Some(23)).is_err());
        assert!(Policy::miner(Some(0)).is_err());
        assert_eq!(
            decision(Policy::miner(None).unwrap(), 400, 496),
            Decision::ExpireProofBody
        );
        assert_eq!(
            decision(Policy::miner(None).unwrap(), 400, 495),
            Decision::Keep
        );
        assert_eq!(
            decision(Policy::miner(Some(24)).unwrap(), 400, 424),
            Decision::ExpireProofBody
        );
        assert_eq!(
            decision(Policy::Miner { blocks: 1 }, 400, 500),
            Decision::Keep
        );
    }
    #[test]
    fn proof_tail_after_the_latest_checkpoint_is_always_retained() {
        for policy in [
            Policy::Service,
            Policy::miner(None).unwrap(),
            Policy::miner(Some(24)).unwrap(),
        ] {
            for height in 401..=1000 {
                assert_eq!(decision(policy, height, 1000), Decision::Keep);
            }
        }
    }
    #[test]
    fn service_requires_both_observed_24_hours_and_312_blocks() {
        assert_eq!(
            decision(Policy::Service, 400, 712),
            Decision::ExpireProofBody
        );
        assert_eq!(decision(Policy::Service, 400, 711), Decision::Keep);
        for age in [0, 1, SERVICE_SECONDS - 1] {
            assert_eq!(
                decide(
                    Policy::Service,
                    400,
                    [1; 32],
                    712,
                    Some(checkpoint()),
                    100_100,
                    true,
                    age,
                    Some(Finality {
                        block: [1; 32],
                        credited_at: 0
                    })
                ),
                Decision::Keep
            );
        }
        for finality in [
            None,
            Some(Finality {
                block: [2; 32],
                credited_at: 0,
            }),
            Some(Finality {
                block: [1; 32],
                credited_at: SERVICE_SECONDS + 1,
            }),
        ] {
            assert_eq!(
                decide(
                    Policy::Service,
                    400,
                    [1; 32],
                    712,
                    Some(checkpoint()),
                    100_100,
                    true,
                    SERVICE_SECONDS,
                    finality
                ),
                Decision::Keep
            );
        }
    }
    #[test]
    fn stale_checkpoint_pauses_every_role_and_repeated_reads_do_not_renew_it() {
        for policy in [Policy::Service, Policy::miner(None).unwrap()] {
            assert_eq!(
                decide(
                    policy,
                    1,
                    [1; 32],
                    1000,
                    Some(checkpoint()),
                    100_000 + CHECKPOINT_STALE_SECONDS,
                    true,
                    SERVICE_SECONDS,
                    Some(Finality {
                        block: [1; 32],
                        credited_at: 0
                    })
                ),
                Decision::ExpireProofBody
            );
            for _ in 0..10 {
                assert_eq!(
                    decide(
                        policy,
                        1,
                        [1; 32],
                        1000,
                        Some(checkpoint()),
                        100_001 + CHECKPOINT_STALE_SECONDS,
                        true,
                        SERVICE_SECONDS,
                        None
                    ),
                    Decision::Paused(Pause::CheckpointStale)
                );
            }
        }
    }
    #[test]
    fn missing_unconfirmed_future_or_uncertain_checkpoint_cannot_authorize_expiry() {
        let policy = Policy::miner(None).unwrap();
        assert_eq!(
            decide(policy, 1, [1; 32], 1000, None, 100_100, true, 0, None),
            Decision::Paused(Pause::CheckpointUnavailable)
        );
        let mut cp = checkpoint();
        cp.height = 977;
        assert_eq!(
            decide(policy, 1, [1; 32], 1000, Some(cp), 100_100, true, 0, None),
            Decision::Paused(Pause::CheckpointUnavailable)
        );
        assert_eq!(
            decide(
                policy,
                1,
                [1; 32],
                1000,
                Some(checkpoint()),
                99_999,
                true,
                0,
                None
            ),
            Decision::Paused(Pause::ClockUncertain)
        );
        assert_eq!(
            decide(
                policy,
                1,
                [1; 32],
                1000,
                Some(checkpoint()),
                100_100,
                false,
                0,
                None
            ),
            Decision::Paused(Pause::ClockUncertain)
        );
    }
    #[test]
    fn downtime_and_wall_clock_changes_never_advance_service_retention() {
        let mut clock = Clock::resume(50);
        assert_eq!(clock.observe(100, 0), Err(Pause::ClockUncertain));
        clock.observe(160, 60).unwrap();
        assert_eq!(clock.credited_seconds, 110);
        assert_eq!(clock.observe(100_000, 120), Err(Pause::ClockUncertain));
        assert_eq!(clock.credited_seconds, 110);
        clock.observe(100_060, 180).unwrap();
        assert_eq!(clock.credited_seconds, 170);
        assert_eq!(clock.observe(99_999, 240), Err(Pause::ClockUncertain));
        assert_eq!(clock.credited_seconds, 170);
        let mut restarted = Clock::resume(clock.credited_seconds);
        assert_eq!(restarted.observe(200_000, 0), Err(Pause::ClockUncertain));
        assert_eq!(restarted.credited_seconds, 170);
        assert_eq!(restarted.observe(201_000, 1000), Err(Pause::ClockUncertain));
        assert_eq!(restarted.credited_seconds, 170);
    }
    #[test]
    #[cfg(feature = "eng2-runtime")]
    fn resident_configuration_is_opt_in_and_role_bound() {
        use crate::p2p::Role;
        use serde_json::json;
        for role in [Role::Miner, Role::Bootstrap, Role::Validator, Role::Wallet] {
            assert_eq!(configured(None, role).unwrap(), None);
            assert_eq!(configured(Some(&json!(null)), role).unwrap(), None);
        }
        assert_eq!(
            configured(Some(&json!({"enabled":true})), Role::Miner).unwrap(),
            Some(Policy::Miner { blocks: 96 })
        );
        assert_eq!(
            configured(
                Some(&json!({"enabled":true,"miner_blocks":24})),
                Role::Miner
            )
            .unwrap(),
            Some(Policy::Miner { blocks: 24 })
        );
        assert_eq!(
            configured(Some(&json!({"enabled":true})), Role::Validator).unwrap(),
            Some(Policy::Service)
        );
        for value in [
            json!({}),
            json!({"enabled":false}),
            json!({"enabled":true,"miner_blocks":23}),
            json!({"enabled":true,"miner_blocks":"96"}),
            json!({"enabled":true,"unknown":1}),
        ] {
            assert!(configured(Some(&value), Role::Miner).is_err());
        }
        assert!(
            configured(
                Some(&json!({"enabled":true,"miner_blocks":312})),
                Role::Bootstrap
            )
            .is_err()
        );
        assert!(configured(Some(&json!({"enabled":true})), Role::Wallet).is_err());
    }
}
