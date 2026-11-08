use super::*;

#[test]
fn checkpoint_pruning_override_preserves_the_production_default_and_upper_bound() {
    let default = CheckpointPruning::from_override(None).unwrap();
    assert_eq!(default.max_age_seconds(), 64_800);
    assert_eq!(CHECKPOINT_MAX_AGE_SECONDS, 64_800);
    assert_eq!(crate::engineering_checkpoint::MAX_AGE_SECONDS, 64_800);
    assert!(default.fresh(21_600, 21_600 + 64_800));
    assert!(!default.fresh(21_600, 21_600 + 64_801));
    assert!(!default.fresh(21_600, 21_599));
    for invalid in ["0", "1199", "64801", "-1", "+1200", "1200.0", " 1200", ""] {
        assert!(CheckpointPruning::from_override(Some(invalid)).is_err());
    }
    let shortened = CheckpointPruning::from_override(Some("1200"));
    if cfg!(feature = "checkpoint-stale-acceptance") {
        assert_eq!(shortened.unwrap().max_age_seconds(), 1200);
    } else {
        assert!(shortened.is_err());
    }
}

#[test]
fn shortened_checkpoint_pruning_clock_pauses_only_after_the_age_boundary() {
    let policy = CheckpointPruning::shortened_for_acceptance(1200).unwrap();
    assert!(policy.fresh(21_600, 22_799));
    assert!(policy.fresh(21_600, 22_800));
    assert!(!policy.fresh(21_600, 22_801));
    assert!(!policy.fresh(21_600, 21_599));
    assert!(policy.fresh(22_802, 22_802));
    for invalid in [0, 1199, 64_801, u64::MAX] {
        assert!(CheckpointPruning::shortened_for_acceptance(invalid).is_err());
    }
}

#[test]
fn startup_policy_requires_explicit_role_and_respects_local_minimum() {
    assert_eq!(StartupPolicy::parse(None, None).unwrap(), None);
    assert!(StartupPolicy::parse(None, Some("96")).is_err());
    assert!(StartupPolicy::parse(Some("miner"), Some("23")).is_err());
    assert!(StartupPolicy::parse(Some("miner"), Some("invalid")).is_err());
    assert!(StartupPolicy::parse(Some("validator"), Some("96")).is_err());
    assert_eq!(
        StartupPolicy::parse(Some("miner"), Some("96")).unwrap(),
        Some(StartupPolicy {
            role: Role::Miner,
            local_blocks: Some(96)
        })
    );
    assert_eq!(
        StartupPolicy::parse(Some("bootstrap"), None).unwrap(),
        Some(StartupPolicy {
            role: Role::Bootstrap,
            local_blocks: None
        })
    );
}

fn recovery(now: u64) -> Option<RecoveryBoundary> {
    Some(RecoveryBoundary {
        height: 904,
        sealed_unix_seconds: now,
        tail_complete: true,
    })
}
fn observed(at: u64) -> Option<FinalityObservation> {
    Some(FinalityObservation {
        block_id: [1; 32],
        observed_unix_seconds: at,
    })
}

#[test]
fn bootstrap_and_validator_keep_twenty_four_hours_after_observed_finality() {
    assert_eq!(SERVICE_RETENTION_SECONDS, 86_400);
    assert_eq!(NOMINAL_SERVICE_PROOF_BLOCKS, 312);
    let at = 1000;
    for role in [Role::Bootstrap, Role::Validator] {
        let before = at + SERVICE_RETENTION_SECONDS - 1;
        assert_eq!(
            expired(
                role,
                1,
                [1; 32],
                2000,
                observed(at),
                before,
                true,
                recovery(before)
            ),
            Err(KeepReason::ServiceTimeWindow)
        );
        let boundary = before + 1;
        assert!(
            expired(
                role,
                1,
                [1; 32],
                2000,
                observed(at),
                boundary,
                true,
                recovery(boundary)
            )
            .is_ok()
        );
    }
}

#[test]
fn rapid_blocks_do_not_shorten_the_service_time_window() {
    assert_eq!(
        expired(
            Role::Validator,
            1,
            [1; 32],
            100_000,
            observed(1000),
            1001,
            true,
            recovery(1001)
        ),
        Err(KeepReason::ServiceTimeWindow)
    );
}

#[test]
fn miner_and_ordinary_keep_exactly_the_last_ninety_six_blocks() {
    for role in [Role::Miner, Role::Ordinary] {
        assert!(expired(role, 904, [1; 32], 1000, None, 1000, true, recovery(1000)).is_ok());
        assert_eq!(
            expired(role, 905, [1; 32], 1000, None, 1000, true, recovery(1000)),
            Err(KeepReason::LocalWindow)
        );
    }
    assert_eq!(MAX_REORG_DEPTH, 24);
}

#[test]
fn incomplete_or_stale_recovery_never_allows_deletion() {
    assert_eq!(
        expired(Role::Miner, 1, [1; 32], 1000, None, 1000, true, None),
        Err(KeepReason::CheckpointUnavailable)
    );
    let mut cp = recovery(1000).unwrap();
    cp.tail_complete = false;
    assert_eq!(
        expired(Role::Miner, 1, [1; 32], 1000, None, 1000, true, Some(cp)),
        Err(KeepReason::RecoveryTailUnavailable)
    );
    cp.tail_complete = true;
    assert_eq!(
        expired(
            Role::Miner,
            1,
            [1; 32],
            1000,
            None,
            1000 + CHECKPOINT_MAX_AGE_SECONDS + 1,
            true,
            Some(cp)
        ),
        Err(KeepReason::CheckpointUnavailable)
    );
    cp.height = 0;
    assert_eq!(
        expired(Role::Miner, 1, [1; 32], 1000, None, 1000, true, Some(cp)),
        Err(KeepReason::CheckpointUnavailable)
    );
}

#[test]
fn finality_observation_cannot_be_reused_for_a_different_fork() {
    let now = SERVICE_RETENTION_SECONDS + 1000;
    assert_eq!(
        expired(
            Role::Validator,
            1,
            [2; 32],
            1000,
            observed(1000),
            now,
            true,
            recovery(now)
        ),
        Err(KeepReason::FinalityUnobserved)
    );
}

#[test]
fn clock_uncertainty_and_backward_clock_extend_retention() {
    assert_eq!(
        expired(
            Role::Miner,
            1,
            [1; 32],
            1000,
            None,
            1000,
            false,
            recovery(1000)
        ),
        Err(KeepReason::ClockUncertain)
    );
    assert_eq!(
        expired(
            Role::Validator,
            1,
            [1; 32],
            1000,
            observed(1001),
            1000,
            true,
            recovery(1000)
        ),
        Err(KeepReason::ServiceTimeWindow)
    );
    assert_eq!(
        expired(
            Role::Miner,
            1,
            [1; 32],
            1000,
            None,
            999,
            true,
            recovery(1000)
        ),
        Err(KeepReason::CheckpointUnavailable)
    );
}

#[test]
fn recent_unfinalized_blocks_and_genesis_cannot_expire() {
    for height in [0, 977, 1000, 1001] {
        assert_eq!(
            expired(
                Role::Miner,
                height,
                [1; 32],
                1000,
                None,
                1000,
                true,
                recovery(1000)
            ),
            Err(KeepReason::RollbackWindow)
        );
    }
}

#[test]
fn role_names_and_historical_proof_advertisement_are_explicit() {
    for name in ["bootstrap", "validator", "miner", "ordinary"] {
        let role = Role::parse(name).unwrap();
        assert_eq!(role.name(), name);
        assert_eq!(
            role.serves_historical_proofs(),
            matches!(name, "bootstrap" | "validator")
        );
    }
    assert!(Role::parse("archive").is_err());
}

#[test]
fn checkpoint_publication_is_due_every_six_hours_and_on_clock_uncertainty() {
    assert_eq!(CHECKPOINT_PUBLICATION_SECONDS, 21_600);
    assert!(checkpoint_publication_due(None, 1000));
    assert!(!checkpoint_publication_due(
        Some(1000),
        1000 + CHECKPOINT_PUBLICATION_SECONDS - 1
    ));
    assert!(checkpoint_publication_due(
        Some(1000),
        1000 + CHECKPOINT_PUBLICATION_SECONDS
    ));
    assert!(checkpoint_publication_due(Some(1001), 1000));
}

#[test]
fn configured_local_retention_never_falls_below_twenty_four_blocks() {
    for role in [Role::Miner, Role::Ordinary] {
        assert!(
            expired_with_local_blocks(
                role,
                976,
                [1; 32],
                1000,
                None,
                1000,
                true,
                Some(RecoveryBoundary {
                    height: 976,
                    sealed_unix_seconds: 1000,
                    tail_complete: true
                }),
                24
            )
            .is_ok()
        );
        assert!(
            expired_with_local_blocks(
                role,
                976,
                [1; 32],
                1000,
                None,
                1000,
                true,
                recovery(1000),
                23
            )
            .is_err()
        );
        assert!(
            expired_with_local_blocks(
                role,
                905,
                [1; 32],
                1000,
                None,
                1000,
                true,
                recovery(1000),
                120
            )
            .is_err()
        );
    }
}
