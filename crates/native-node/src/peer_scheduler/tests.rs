use super::*;

fn scheduler() -> Scheduler {
    Scheduler::new([1; 32], &[[2; 32], [3; 32]], Budget::new(1024 * 1024), 0).unwrap()
}

#[test]
fn unknown_duplicate_and_self_peers_cannot_allocate_attempts() {
    let budget = Budget::new(1024 * 1024);
    assert!(Scheduler::new([0; 32], &[], budget.clone(), 0).is_err());
    assert!(Scheduler::new([1; 32], &[[1; 32]], budget.clone(), 0).is_err());
    assert!(Scheduler::new([1; 32], &[[2; 32], [2; 32]], budget, 0).is_err());
    let mut scheduler = scheduler();
    assert_eq!(
        scheduler.begin([8; 32], Direction::Outbound, 0).err(),
        Some(Error::UnknownPeer)
    );
    assert_eq!(scheduler.status().pending, 0);
}

#[test]
fn simultaneous_dials_choose_one_direction_without_releasing_cancelled_resources() {
    let mut scheduler = scheduler();
    let inbound = scheduler.begin([2; 32], Direction::Inbound, 0).unwrap();
    let outbound = scheduler.begin([2; 32], Direction::Outbound, 0).unwrap();
    assert_eq!(outbound.cancel, Some(inbound.token));
    assert_eq!(
        (scheduler.status().pending, scheduler.status().closing),
        (2, 1)
    );
    assert_eq!(
        scheduler.authenticated(inbound.token, 1),
        Err(Error::StaleAttempt)
    );
    scheduler
        .closed(inbound.token, Failure::Unavailable, 1)
        .unwrap();
    scheduler.authenticated(outbound.token, 2).unwrap();
    assert_eq!(
        (scheduler.status().pending, scheduler.status().established),
        (0, 1)
    );
    assert_eq!(
        scheduler.begin([2; 32], Direction::Inbound, 3).err(),
        Some(Error::Duplicate)
    );
}

#[test]
fn failures_back_off_without_identity_replacement_or_weaker_retry() {
    let mut scheduler = scheduler();
    let attempt = scheduler
        .begin([2; 32], Direction::Outbound, 0)
        .unwrap()
        .token;
    scheduler.closed(attempt, Failure::Unavailable, 1).unwrap();
    assert_eq!(
        scheduler.begin([2; 32], Direction::Outbound, 2).err(),
        Some(Error::Backoff)
    );
    let next = scheduler
        .begin([2; 32], Direction::Outbound, MAX_BACKOFF_MS + 1)
        .unwrap()
        .token;
    assert_eq!(next.peer(), attempt.peer());
    assert_ne!(next, attempt);
    assert_eq!(
        scheduler.authenticated(attempt, MAX_BACKOFF_MS + 2),
        Err(Error::StaleAttempt)
    );
    scheduler
        .closed(next, Failure::Authentication, MAX_BACKOFF_MS + 2)
        .unwrap();
    assert_eq!(scheduler.status().disabled, 0);
    let retry = scheduler
        .begin([2; 32], Direction::Outbound, MAX_BACKOFF_MS * 100)
        .unwrap()
        .token;
    assert_eq!(
        scheduler.disable([2; 32], MAX_BACKOFF_MS * 100).unwrap(),
        Some(retry)
    );
    assert_eq!(
        scheduler
            .begin([2; 32], Direction::Outbound, MAX_BACKOFF_MS * 100)
            .err(),
        Some(Error::Disabled)
    );
    assert_eq!(scheduler.status().disabled, 1);
}

#[test]
fn unauthenticated_claims_cannot_quarantine_a_legitimate_pinned_peer() {
    for failure in [Failure::Authentication, Failure::Protocol] {
        let mut scheduler = scheduler();
        let token = scheduler
            .begin([2; 32], Direction::Inbound, 0)
            .unwrap()
            .token;
        scheduler.closed(token, failure, 1).unwrap();
        assert_eq!(scheduler.status().disabled, 0);
        assert!(
            scheduler
                .begin([2; 32], Direction::Outbound, MAX_BACKOFF_MS + 1)
                .is_ok()
        );
    }
    let mut scheduler = scheduler();
    let token = scheduler
        .begin([2; 32], Direction::Outbound, 0)
        .unwrap()
        .token;
    scheduler.authenticated(token, 1).unwrap();
    scheduler.closed(token, Failure::Protocol, 2).unwrap();
    assert_eq!(scheduler.status().disabled, 1);
}

#[test]
fn deadlines_and_shutdown_retain_reservations_until_close_acknowledgment() {
    let budget = Budget::new(4096);
    let initial = budget.available().unwrap();
    let mut scheduler = Scheduler::new([1; 32], &[[2; 32]], budget.clone(), 0).unwrap();
    let configured = budget.available().unwrap();
    let attempt = scheduler
        .begin([2; 32], Direction::Outbound, 0)
        .unwrap()
        .token;
    assert_eq!(scheduler.poll(ADMISSION_MS).unwrap(), vec![attempt]);
    assert_eq!(scheduler.status().closing, 1);
    assert!(budget.available().unwrap() < configured);
    scheduler
        .closed(attempt, Failure::Unavailable, ADMISSION_MS)
        .unwrap();
    assert_eq!(budget.available().unwrap(), configured);
    let next = scheduler
        .begin([2; 32], Direction::Outbound, MAX_BACKOFF_MS)
        .unwrap()
        .token;
    scheduler.authenticated(next, MAX_BACKOFF_MS + 1).unwrap();
    assert_eq!(scheduler.shutdown(MAX_BACKOFF_MS + 2).unwrap(), vec![next]);
    assert_eq!(
        scheduler
            .begin([2; 32], Direction::Outbound, MAX_BACKOFF_MS + 3)
            .err(),
        Some(Error::Stopped)
    );
    scheduler
        .closed(next, Failure::LocalResource, MAX_BACKOFF_MS + 3)
        .unwrap();
    drop(scheduler);
    assert_eq!(budget.available().unwrap(), initial);
}

#[test]
fn resource_limits_and_clock_regression_fail_without_extra_attempts() {
    let peers: Vec<_> = (2u8..=MAX_PEERS as u8 + 1).map(|x| [x; 32]).collect();
    let mut scheduler = Scheduler::new([1; 32], &peers, Budget::new(1024 * 1024), 0).unwrap();
    for peer in peers.iter().take(MAX_PENDING) {
        scheduler.begin(*peer, Direction::Outbound, 10).unwrap();
    }
    assert_eq!(
        scheduler
            .begin(peers[MAX_PENDING], Direction::Outbound, 10)
            .err(),
        Some(Error::Capacity)
    );
    assert_eq!(scheduler.poll(9).err(), Some(Error::ClockRegression));
    assert_eq!(scheduler.status().pending, MAX_PENDING);
    let budget = Budget::new(PEER_BYTES);
    let mut constrained = Scheduler::new([1; 32], &[[2; 32]], budget, 0).unwrap();
    assert_eq!(
        constrained.begin([2; 32], Direction::Outbound, 0).err(),
        Some(Error::Capacity)
    );
    assert_eq!(constrained.status().pending, 0);
}

#[test]
fn established_sessions_require_a_fresh_attempt_after_the_lifetime_bound() {
    let mut scheduler = scheduler();
    let attempt = scheduler
        .begin([2; 32], Direction::Outbound, 0)
        .unwrap()
        .token;
    scheduler.authenticated(attempt, 1).unwrap();
    assert!(scheduler.poll(SESSION_MS).unwrap().is_empty());
    assert_eq!(scheduler.poll(SESSION_MS + 1).unwrap(), vec![attempt]);
    scheduler
        .closed(attempt, Failure::Unavailable, SESSION_MS + 1)
        .unwrap();
    let next = scheduler
        .begin([2; 32], Direction::Outbound, SESSION_MS + MAX_BACKOFF_MS)
        .unwrap()
        .token;
    assert_ne!(attempt, next);
    assert_eq!(scheduler.status().established, 0);
}

#[test]
fn a_callback_from_another_scheduler_cannot_establish_or_close_a_new_attempt() {
    let mut first = scheduler();
    let mut second = scheduler();
    let old = first.begin([2; 32], Direction::Outbound, 0).unwrap().token;
    let current = second.begin([2; 32], Direction::Outbound, 0).unwrap().token;
    assert_ne!(old, current);
    assert_eq!(second.authenticated(old, 1), Err(Error::StaleAttempt));
    assert_eq!(
        second.closed(old, Failure::Protocol, 1),
        Err(Error::StaleAttempt)
    );
    second.authenticated(current, 1).unwrap();
    assert_eq!(second.status().disabled, 0);
}

#[test]
fn backoff_is_bounded_and_ready_lists_do_not_bypass_it() {
    let mut scheduler = scheduler();
    let mut now = 0;
    for _ in 0..20 {
        let token = scheduler
            .begin([2; 32], Direction::Outbound, now)
            .unwrap()
            .token;
        scheduler
            .closed(token, Failure::LocalResource, now)
            .unwrap();
        assert!(!scheduler.ready_outbound(now).unwrap().contains(&[2; 32]));
        now += MAX_BACKOFF_MS;
        assert!(scheduler.ready_outbound(now).unwrap().contains(&[2; 32]));
    }
    assert_eq!(scheduler.status().disabled, 0);
}

#[test]
fn established_and_retiring_sessions_share_the_established_cap() {
    let peers: Vec<_> = (2u8..=MAX_PEERS as u8 + 1).map(|x| [x; 32]).collect();
    let mut scheduler = Scheduler::new([1; 32], &peers, Budget::new(1024 * 1024), 0).unwrap();
    for peer in peers.iter().take(MAX_ESTABLISHED) {
        let token = scheduler
            .begin(*peer, Direction::Outbound, 1)
            .unwrap()
            .token;
        scheduler.authenticated(token, 1).unwrap();
    }
    let next = scheduler
        .begin(peers[MAX_ESTABLISHED], Direction::Outbound, 1)
        .unwrap()
        .token;
    assert_eq!(scheduler.authenticated(next, 2), Err(Error::Capacity));
    let expired = scheduler.poll(SESSION_MS + 1).unwrap();
    assert_eq!(scheduler.status().established, MAX_ESTABLISHED);
    assert_eq!(expired.len(), MAX_ESTABLISHED + 1);
    for token in expired {
        scheduler
            .closed(token, Failure::Unavailable, SESSION_MS + 1)
            .unwrap();
    }
    assert_eq!(scheduler.status().established, 0);
}
