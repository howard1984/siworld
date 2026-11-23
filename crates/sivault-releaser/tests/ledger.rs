mod support;

use std::sync::{Arc, Barrier, Mutex};

use sivault_releaser::ledger::*;
use sivault_releaser::message::{AckPhase, Action, Body, Domain, Operation};
use support::*;

// Test-only transactional reference store. This models the adapter contract;
// it supplies no real rollback resistance, owner authentication or proof checks.
#[derive(Clone)]
struct ModelAuthority(Arc<Mutex<Store>>);
struct Store {
    current: Ledger,
    presented_backup: Option<Ledger>,
    available: bool,
    exclusive: bool,
    evidence_accepted: bool,
    fail: Option<CommitFailure>,
}
#[derive(Clone, Copy)]
enum CommitFailure {
    Before,
    After,
}

impl ModelAuthority {
    fn new(ledger: Ledger) -> Self {
        Self(Arc::new(Mutex::new(Store {
            current: ledger,
            presented_backup: None,
            available: true,
            exclusive: true,
            evidence_accepted: true,
            fail: None,
        })))
    }
    fn ledger(&self) -> Ledger {
        self.0.lock().unwrap().current.clone()
    }
    fn service(&self) -> Releaser<Self> {
        let mut service = Releaser::new(self.clone());
        service.recover(slot()).unwrap();
        service
    }
}

impl DurableAuthority for ModelAuthority {
    fn recover_exclusive(&mut self, slot: SlotIdentity) -> Result<Ledger, AuthorityError> {
        let state = self.0.lock().unwrap();
        if !state.available {
            return Err(AuthorityError::Unavailable);
        }
        if !state.exclusive {
            return Err(AuthorityError::NotExclusive);
        }
        if let Some(backup) = &state.presented_backup
            && backup != &state.current
        {
            return Err(AuthorityError::Stale);
        }
        if slot != state.current.identity() {
            return Err(AuthorityError::InvalidEvidence);
        }
        Ok(state.current.clone())
    }
    fn commit(&mut self, expected: &Ledger, transition: &Transition) -> Result<(), AuthorityError> {
        let mut state = self.0.lock().unwrap();
        if !state.available {
            return Err(AuthorityError::Unavailable);
        }
        if !state.exclusive {
            return Err(AuthorityError::NotExclusive);
        }
        if !state.evidence_accepted {
            return Err(AuthorityError::InvalidEvidence);
        }
        if &state.current != expected {
            return Err(AuthorityError::Stale);
        }
        let fail = state.fail.take();
        if matches!(fail, Some(CommitFailure::Before)) {
            return Err(AuthorityError::Unavailable);
        }
        state.current = transition.next().clone();
        if matches!(fail, Some(CommitFailure::After)) {
            return Err(AuthorityError::Unavailable);
        }
        Ok(())
    }
}

fn step(ledger: &Ledger, event: Event) -> Ledger {
    ledger.transition(event).unwrap().next().clone()
}
fn policy_error(ledger: &Ledger, event: Event, expected: PolicyError) {
    assert_eq!(ledger.transition(event).unwrap_err(), expected);
}

#[test]
fn default_and_new_services_are_quarantined_until_authority_recovery() {
    let mut service = Releaser::default();
    assert!(service.is_quarantined());
    assert_eq!(
        service.apply(register(&attempt(1))).unwrap_err(),
        Error::Quarantined
    );
    assert_eq!(
        service.recover(slot()),
        Err(Error::Authority(AuthorityError::Unavailable))
    );
    let authority = ModelAuthority::new(ledger(2));
    let mut service = Releaser::new(authority.clone());
    assert_eq!(
        service.apply(command(restore(1))).unwrap_err(),
        Error::Quarantined
    );
    service.recover(slot()).unwrap();
    assert!(!service.is_quarantined());
    authority.0.lock().unwrap().exclusive = false;
    assert_eq!(
        service.recover(slot()),
        Err(Error::Authority(AuthorityError::NotExclusive))
    );
    assert!(service.is_quarantined());
}

#[test]
fn pure_proposals_do_not_mutate_state_and_commit_precedes_admission() {
    let authority = ModelAuthority::new(ledger(2));
    let mut service = authority.service();
    let a = attempt(1);
    service.apply(register(&a)).unwrap();
    let before = authority.ledger();
    let proposal = before.transition(charge(&a)).unwrap();
    assert_eq!(before.spent(), 0);
    assert_eq!(authority.ledger(), before);
    assert_eq!(proposal.next().spent(), 1);
    let outcome = service.apply(charge(&a)).unwrap();
    let Outcome::CredentialReady(token) = outcome else {
        panic!("admission token expected");
    };
    assert_eq!(authority.ledger().spent(), 1);
    assert_eq!(
        authority.ledger().consumed().get(&a.domain.request),
        Some(&a)
    );
    assert_eq!(token.attempt(), &a);
    assert_eq!(token.revision(), authority.ledger().revision());
    assert_eq!(token.into_attempt(), a);
    assert_eq!(
        service.apply(charge(&a)).unwrap_err(),
        Error::Policy(PolicyError::Replay)
    );
    assert_eq!(authority.ledger().spent(), 1);
}

#[test]
fn uncertain_commit_never_returns_a_token_and_durable_charge_cannot_be_replayed() {
    for failure in [CommitFailure::Before, CommitFailure::After] {
        let authority = ModelAuthority::new(ledger(1));
        let mut service = authority.service();
        let a = attempt(1);
        service.apply(register(&a)).unwrap();
        authority.0.lock().unwrap().fail = Some(failure);
        assert_eq!(
            service.apply(charge(&a)).unwrap_err(),
            Error::Authority(AuthorityError::Unavailable)
        );
        assert!(service.is_quarantined());
        assert_eq!(service.apply(charge(&a)).unwrap_err(), Error::Quarantined);
        service.recover(slot()).unwrap();
        match failure {
            CommitFailure::Before => assert!(matches!(
                service.apply(charge(&a)),
                Ok(Outcome::CredentialReady(_))
            )),
            CommitFailure::After => assert_eq!(
                service.apply(charge(&a)).unwrap_err(),
                Error::Policy(PolicyError::Replay)
            ),
        }
        assert_eq!(authority.ledger().spent(), 1);
    }
}

#[test]
fn rejected_adapter_evidence_never_releases_a_token() {
    let authority = ModelAuthority::new(ledger(2));
    let mut service = authority.service();
    let a = attempt(1);
    service.apply(register(&a)).unwrap();
    authority.0.lock().unwrap().evidence_accepted = false;
    assert_eq!(
        service.apply(charge(&a)).unwrap_err(),
        Error::Authority(AuthorityError::InvalidEvidence)
    );
    assert!(service.is_quarantined());
    assert_eq!(authority.ledger().spent(), 0);
}

#[test]
fn concurrent_copies_share_one_atomic_charge_and_dedup_boundary() {
    let authority = ModelAuthority::new(ledger(1));
    let a = attempt(1);
    authority.service().apply(register(&a)).unwrap();
    let services = [authority.service(), authority.service()];
    let barrier = Arc::new(Barrier::new(2));
    let workers = services
        .into_iter()
        .map(|mut service| {
            let barrier = barrier.clone();
            let a = a.clone();
            std::thread::spawn(move || {
                barrier.wait();
                service.apply(charge(&a))
            })
        })
        .collect::<Vec<_>>();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, Ok(Outcome::CredentialReady(_))))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, Err(Error::Authority(AuthorityError::Stale))))
            .count(),
        1
    );
    assert_eq!(authority.ledger().spent(), 1);
    assert_eq!(authority.ledger().consumed().len(), 1);
}

#[test]
fn stale_backup_cannot_recover_attempts_or_reenroll_a_permanent_slot() {
    let original = ledger(1);
    let authority = ModelAuthority::new(original.clone());
    let mut service = authority.service();
    let a = attempt(1);
    service.apply(register(&a)).unwrap();
    service.apply(charge(&a)).unwrap();
    // This also models a fresh enrollment snapshot offered for an existing slot.
    authority.0.lock().unwrap().presented_backup = Some(original);
    assert_eq!(
        service.recover(slot()),
        Err(Error::Authority(AuthorityError::Stale))
    );
    assert!(service.is_quarantined());
    assert_eq!(authority.ledger().remaining(), 0);
    authority.0.lock().unwrap().presented_backup = None;
    service.recover(slot()).unwrap();
    assert_eq!(service.snapshot().unwrap().remaining(), 0);
}

#[test]
fn failed_possession_missing_expired_or_changed_challenges_never_charge() {
    let initial = ledger(2);
    let a = attempt(1);
    policy_error(&initial, charge(&a), PolicyError::MissingChallenge);
    let current = step(&initial, register(&a));
    policy_error(
        &current,
        Event::Charge {
            attempt: a.clone(),
            possession: Possession::Rejected,
            now: 2,
        },
        PolicyError::PossessionRejected,
    );
    policy_error(
        &current,
        Event::Charge {
            attempt: a.clone(),
            possession: Possession::Accepted,
            now: 100,
        },
        PolicyError::Expired,
    );
    let mut changed = a.clone();
    changed.reply_key_digest = id(99);
    policy_error(&current, charge(&changed), PolicyError::Conflict);
    assert_eq!(current.spent(), 0);
    let spent = step(&current, charge(&a));
    policy_error(&spent, charge(&changed), PolicyError::Conflict);
}

#[test]
fn every_attempt_binding_is_checked_against_registered_challenge() {
    let a = attempt(1);
    let current = step(&ledger(2), register(&a));
    let mut changes = Vec::new();
    for field in 0..16 {
        let mut b = a.clone();
        match field {
            0 => b.domain.suite += 1,
            1 => b.domain.network = id(99),
            2 => b.domain.safe = id(99),
            3 => b.domain.generation += 1,
            4 => b.domain.slot = id(99),
            5 => b.domain.incarnation = id(99),
            6 => b.domain.request = id(99),
            7 => b.domain.operation = Operation::Recovery,
            8 => b.selected_record = id(99),
            9 => b.challenge = id(99),
            10 => b.init_digest = id(99),
            11 => b.challenge_digest = id(99),
            12 => b.client_nonce = id(99),
            13 => b.server_nonce = id(99),
            14 => b.reply_key_digest = id(99),
            15 => b.deadline += 1,
            _ => unreachable!(),
        }
        changes.push(b);
    }
    for changed in changes {
        assert!(current.transition(charge(&changed)).is_err());
    }
    assert_eq!(current.spent(), 0);
}

#[test]
fn expired_pending_cleanup_does_not_allow_identity_reuse() {
    let a = attempt(1);
    let first = step(&ledger(3), register(&a));
    let mut b = attempt(2);
    b.deadline = 200;
    let second = step(
        &first,
        Event::RegisterChallenge {
            attempt: b,
            now: 101,
        },
    );
    let mut changed = a.clone();
    changed.deadline = 200;
    policy_error(
        &second,
        Event::RegisterChallenge {
            attempt: changed,
            now: 101,
        },
        PolicyError::Conflict,
    );
    let mut reused_challenge = attempt(3);
    reused_challenge.challenge = a.challenge;
    reused_challenge.deadline = 200;
    policy_error(
        &second,
        Event::RegisterChallenge {
            attempt: reused_challenge,
            now: 101,
        },
        PolicyError::Conflict,
    );
}

#[test]
fn operation_domains_do_not_create_separate_allowances() {
    let mut current = ledger(2);
    for (request, operation) in [(1, Operation::Normal), (2, Operation::Recovery)] {
        let mut a = attempt(request);
        a.domain.operation = operation;
        current = step(&current, register(&a));
        current = step(&current, charge(&a));
    }
    let mut decoy = attempt(3);
    decoy.domain.operation = Operation::Decoy;
    policy_error(&current, register(&decoy), PolicyError::Exhausted);
    assert_eq!(current.spent(), 2);
    assert_eq!(current.initial_allowance(), 2);
}

#[test]
fn pending_challenges_do_not_reserve_or_overdraw_budget() {
    let a = attempt(1);
    let b = attempt(2);
    let current = step(&step(&ledger(1), register(&a)), register(&b));
    let current = step(&current, charge(&a));
    policy_error(&current, charge(&b), PolicyError::Exhausted);
    policy_error(&ledger(0), register(&a), PolicyError::Exhausted);
}

#[test]
fn explicit_grants_and_monotonic_commands_are_idempotent_and_bounded() {
    let first = refill(1, 2, 3);
    let current = step(&ledger(2), command(first.clone()));
    assert_eq!(current.grant_total(), 5);
    assert_eq!(current.command_counter(), 1);
    let duplicate = current.transition(command(first.clone())).unwrap();
    assert_eq!(duplicate.next(), &current);
    let mut altered = first;
    altered.domain.request = id(99);
    policy_error(&current, command(altered), PolicyError::Conflict);
    let mut reused_counter = refill(1, 5, 1);
    if let Body::Owner { meta, .. } = &mut reused_counter.body {
        meta.command = id(99);
    }
    policy_error(&current, command(reused_counter), PolicyError::StaleCommand);
    policy_error(
        &current,
        command(refill(2, 2, 1)),
        PolicyError::InvalidGrant,
    );
    policy_error(
        &current,
        command(refill(2, 5, 0)),
        PolicyError::InvalidGrant,
    );
    let overflow = owner(
        2,
        Action::Refill {
            ledger: id(6),
            delta: 1,
            expected_total: u64::MAX,
            new_total: 0,
        },
    );
    policy_error(
        &ledger(u64::MAX),
        command(overflow),
        PolicyError::InvalidGrant,
    );
    let next = step(&current, command(refill(7, 5, 1)));
    assert_eq!(next.grant_total(), 6);
    assert_eq!(next.initial_allowance(), 2);
}

#[test]
fn command_retries_return_original_receipt_without_reapplying_even_after_expiry() {
    let authority = ModelAuthority::new(ledger(2));
    let mut service = authority.service();
    let event = command(refill(1, 2, 1));
    let Outcome::Command(first) = service.apply(event.clone()).unwrap() else {
        panic!("command receipt expected");
    };
    let mut expired = event;
    if let Event::Owner { now, .. } = &mut expired {
        *now = 1000;
    }
    let Outcome::Command(retry) = service.apply(expired).unwrap() else {
        panic!("command receipt expected");
    };
    assert_eq!(retry, first);
    assert_eq!(authority.ledger().grant_total(), 3);
    assert_eq!(authority.ledger().revision(), first.revision);
}

#[test]
fn rotation_stages_without_serving_and_keeps_permanent_history() {
    let initial = ledger(2);
    policy_error(&initial, command(commit(1)), PolicyError::InvalidPhase);
    let staged = step(&initial, command(prepare(1)));
    assert_eq!(staged.active(), initial.active());
    assert!(staged.prepared().is_some());
    let a = attempt(1);
    let staged = step(&step(&staged, register(&a)), charge(&a));
    let mut future = attempt(2);
    future.domain.generation = 2;
    future.domain.incarnation = id(34);
    future.record_manifest = id(33);
    policy_error(&staged, register(&future), PolicyError::DomainMismatch);
    let activated = step(&staged, command(commit(2)));
    assert_eq!(activated.spent(), 1);
    assert_eq!(activated.grant_total(), 2);
    assert_eq!(activated.consumed(), staged.consumed());
    policy_error(
        &activated,
        register(&attempt(3)),
        PolicyError::DomainMismatch,
    );
    let activated = step(&step(&activated, register(&future)), charge(&future));
    assert_eq!(activated.remaining(), 0);
    assert_eq!(activated.retirements().len(), 1);
    policy_error(
        &activated,
        command(refill(3, 2, 1)),
        PolicyError::DomainMismatch,
    );
    let mut new_refill = refill(3, 2, 1);
    new_refill.domain.generation = 2;
    new_refill.domain.incarnation = id(34);
    let activated = step(&activated, command(new_refill));
    assert_eq!(activated.remaining(), 1);
    assert_eq!(activated.spent(), 2);
}

#[test]
fn fence_precedes_tombstone_and_removal_confirmation_is_separate() {
    let initial = ledger(2);
    let rotated = step(&step(&initial, command(prepare(1))), command(commit(2)));
    policy_error(&rotated, command(delete(3, 2)), PolicyError::InvalidPhase);
    let retired = step(&rotated, command(retire(3)));
    let pending = step(&retired, command(delete(4, 3)));
    let old = pending.retirements().get(&(1, id(4))).unwrap();
    assert!(old.fence.is_some());
    assert_eq!(old.tombstone, Some(id(154)));
    assert!(!old.deletion_confirmed);
    policy_error(
        &pending,
        Event::ConfirmDeletion {
            generation: 1,
            incarnation: id(4),
            tombstone: id(99),
        },
        PolicyError::InvalidPhase,
    );
    let removed = step(
        &pending,
        Event::ConfirmDeletion {
            generation: 1,
            incarnation: id(4),
            tombstone: id(154),
        },
    );
    assert!(
        removed
            .retirements()
            .get(&(1, id(4)))
            .unwrap()
            .deletion_confirmed
    );
    assert_eq!(removed.spent(), initial.spent());
    assert_eq!(removed.grant_total(), initial.grant_total());
}

#[test]
fn removed_offline_endpoint_can_fence_and_delete_without_successor_records() {
    let a = attempt(1);
    let initial = step(&ledger(2), register(&a));
    let retired = step(&initial, command(retire(1)));
    assert!(!retired.is_serving());
    assert!(retired.prepared().is_none());
    policy_error(&retired, charge(&a), PolicyError::InvalidPhase);
    let deleted = step(&retired, command(delete(2, 1)));
    policy_error(&deleted, command(restore(3)), PolicyError::InvalidPhase);
    policy_error(
        &deleted,
        command(refill(3, 2, 1)),
        PolicyError::InvalidPhase,
    );
    assert_eq!(deleted.initial_allowance(), 2);
    assert_eq!(deleted.grant_total(), 2);
}

#[test]
fn incarnation_replacement_preserves_spend_and_commands() {
    let a = attempt(1);
    let before = step(&step(&ledger(1), register(&a)), charge(&a));
    let replacement = step(&before, command(restore(1)));
    assert_eq!(replacement.spent(), 1);
    assert_eq!(replacement.grant_total(), 1);
    assert_eq!(replacement.consumed(), before.consumed());
    assert_eq!(replacement.active().incarnation, id(52));
    policy_error(
        &replacement,
        register(&attempt(2)),
        PolicyError::DomainMismatch,
    );
    let mut new = attempt(2);
    new.domain.incarnation = id(52);
    policy_error(&replacement, register(&new), PolicyError::Exhausted);
    let mut old_command = refill(2, 1, 1);
    policy_error(
        &replacement,
        command(old_command.clone()),
        PolicyError::DomainMismatch,
    );
    old_command.domain.incarnation = id(52);
    let granted = step(&replacement, command(old_command));
    assert_eq!(granted.remaining(), 1);
    assert_eq!(granted.command_counter(), 2);
    let mut reuse = restore(3);
    reuse.domain.incarnation = id(52);
    if let Body::Owner {
        action: Action::RestoreService {
            target_incarnation, ..
        },
        ..
    } = &mut reuse.body
    {
        *target_incarnation = id(4);
    }
    policy_error(&granted, command(reuse), PolicyError::InvalidPhase);
}

#[test]
fn owner_command_bindings_are_not_transferable_between_slots() {
    let base = refill(1, 2, 1);
    let d = base.domain;
    for domain in [
        Domain { suite: 99, ..d },
        Domain {
            network: id(99),
            ..d
        },
        Domain { safe: id(99), ..d },
        Domain { slot: id(99), ..d },
        Domain {
            generation: 99,
            ..d
        },
        Domain {
            incarnation: id(99),
            ..d
        },
    ] {
        let mut changed = base.clone();
        changed.domain = domain;
        policy_error(&ledger(2), command(changed), PolicyError::DomainMismatch);
    }
    let mut wrong_operation = base;
    wrong_operation.domain.operation = Operation::Normal;
    policy_error(
        &ledger(2),
        command(wrong_operation),
        PolicyError::InvalidCommand,
    );
}

#[test]
fn explicit_retirement_and_deletion_receipts_are_durable_before_reporting() {
    let authority = ModelAuthority::new(ledger(1));
    let mut service = authority.service();
    let Outcome::Command(receipt) = service.apply(command(retire(1))).unwrap() else {
        panic!("fence receipt expected");
    };
    assert_eq!(receipt.phase, AckPhase::Fenced);
    assert!(!authority.ledger().is_serving());
    let Outcome::Command(receipt) = service.apply(command(delete(2, 1))).unwrap() else {
        panic!("tombstone receipt expected");
    };
    assert_eq!(receipt.phase, AckPhase::DeletionPending);
    assert!(
        !authority
            .ledger()
            .retirements()
            .get(&(1, id(4)))
            .unwrap()
            .deletion_confirmed
    );
    authority.0.lock().unwrap().fail = Some(CommitFailure::Before);
    let confirm = Event::ConfirmDeletion {
        generation: 1,
        incarnation: id(4),
        tombstone: id(152),
    };
    assert!(service.apply(confirm.clone()).is_err());
    assert!(service.is_quarantined());
    service.recover(slot()).unwrap();
    assert!(matches!(
        service.apply(confirm),
        Ok(Outcome::DeletionConfirmed)
    ));
    assert!(
        authority
            .ledger()
            .retirements()
            .get(&(1, id(4)))
            .unwrap()
            .deletion_confirmed
    );
}

fn sequence_id(prefix: u8, number: u64) -> sivault_releaser::message::Id {
    let mut bytes = [0; 32];
    bytes[0] = prefix;
    bytes[1..9].copy_from_slice(&number.to_be_bytes());
    sivault_releaser::message::Id(bytes)
}

#[test]
fn deadline_cycling_hits_permanent_history_cap_without_pruning_or_rebudgeting() {
    let mut current = ledger(4);
    let mut last = attempt(1);
    for i in 0..MAX_ISSUED_HISTORY as u64 {
        let mut a = attempt(1);
        a.domain.request = sequence_id(1, i);
        a.challenge = sequence_id(2, i);
        a.deadline = i + 2;
        current = step(
            &current,
            Event::RegisterChallenge {
                attempt: a.clone(),
                now: i + 1,
            },
        );
        last = a;
    }
    assert_eq!(current.issued_count(), MAX_ISSUED_HISTORY);
    assert_eq!(current.spent(), 0);
    let mut extra = attempt(2);
    extra.deadline = u64::MAX;
    policy_error(
        &current,
        Event::RegisterChallenge {
            attempt: extra.clone(),
            now: MAX_ISSUED_HISTORY as u64 + 1,
        },
        PolicyError::HistoryCapacity,
    );
    // A live challenge admitted at capacity still has exactly one atomic charge.
    current = step(
        &current,
        Event::Charge {
            attempt: last.clone(),
            possession: Possession::Accepted,
            now: last.deadline - 1,
        },
    );
    assert_eq!(current.spent(), 1);
    policy_error(&current, charge(&last), PolicyError::Replay);
    current = step(&step(&current, command(prepare(1))), command(commit(2)));
    extra.domain.generation = 2;
    extra.domain.incarnation = id(34);
    extra.record_manifest = id(33);
    policy_error(&current, register(&extra), PolicyError::HistoryCapacity);
    let mut replacement = restore(3);
    replacement.domain.generation = 2;
    replacement.domain.incarnation = id(34);
    if let Body::Owner {
        action: Action::RestoreService { exact_record, .. },
        ..
    } = &mut replacement.body
    {
        *exact_record = id(33);
    }
    current = step(&current, command(replacement));
    extra.domain.incarnation = id(52);
    policy_error(&current, register(&extra), PolicyError::HistoryCapacity);
    assert_eq!(current.issued_count(), MAX_ISSUED_HISTORY);
    assert_eq!(current.grant_total(), 4);
    assert_eq!(current.spent(), 1);
}

#[test]
fn command_history_has_a_hard_cap_but_preserves_identical_receipts() {
    let mut current = ledger(1);
    let mut first = None;
    for i in 1..=MAX_COMMAND_HISTORY as u64 {
        let mut message = refill(i, i, 1);
        if let Body::Owner { meta, .. } = &mut message.body {
            meta.command = sequence_id(3, i);
        }
        message.domain.request = sequence_id(4, i);
        let event = Event::Owner {
            message: Box::new(message),
            digest: sequence_id(5, i),
            now: 3,
        };
        if first.is_none() {
            first = Some(event.clone());
        }
        current = step(&current, event);
    }
    assert_eq!(current.command_count(), MAX_COMMAND_HISTORY);
    let retry = current.transition(first.unwrap()).unwrap();
    assert_eq!(retry.next(), &current);
    policy_error(
        &current,
        command(refill(
            MAX_COMMAND_HISTORY as u64 + 1,
            current.grant_total(),
            1,
        )),
        PolicyError::HistoryCapacity,
    );
    assert_eq!(current.spent(), 0);
    assert_eq!(current.grant_total(), MAX_COMMAND_HISTORY as u64 + 1);
}

#[test]
fn replacement_cannot_clear_prior_deletion_tombstones() {
    let mut current = ledger(2);
    for message in [prepare(1), commit(2), retire(3), delete(4, 3)] {
        current = step(&current, command(message));
    }
    current = step(
        &current,
        Event::ConfirmDeletion {
            generation: 1,
            incarnation: id(4),
            tombstone: id(154),
        },
    );
    let before = current.retirements().clone();
    let mut replacement = restore(5);
    replacement.domain.generation = 2;
    replacement.domain.incarnation = id(34);
    if let Body::Owner {
        action: Action::RestoreService { exact_record, .. },
        ..
    } = &mut replacement.body
    {
        *exact_record = id(33);
    }
    current = step(&current, command(replacement));
    assert_eq!(current.retirements(), &before);
    assert!(
        current
            .retirements()
            .get(&(1, id(4)))
            .unwrap()
            .deletion_confirmed
    );
    let mut resurrect = restore(6);
    resurrect.domain.generation = 2;
    resurrect.domain.incarnation = id(52);
    if let Body::Owner {
        action:
            Action::RestoreService {
                target_incarnation,
                exact_record,
                ..
            },
        ..
    } = &mut resurrect.body
    {
        *target_incarnation = id(4);
        *exact_record = id(33);
    }
    policy_error(&current, command(resurrect), PolicyError::InvalidPhase);
}
