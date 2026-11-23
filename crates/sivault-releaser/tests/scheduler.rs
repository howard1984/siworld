mod support;

use sivault_releaser::message::{Domain, Operation};
use sivault_releaser::scheduler::*;
use support::*;

fn plan() -> Vec<Domain> {
    vec![
        domain(),
        Domain {
            slot: id(20),
            incarnation: id(21),
            request: id(22),
            ..domain()
        },
    ]
}

#[test]
fn wrong_credential_is_terminal_and_cannot_fan_out() {
    let mut client = Scheduler::new(plan()).unwrap();
    let first = client.begin_next().unwrap();
    assert_eq!(client.begin_next(), Err(SchedulerError::AlreadyInFlight));
    client
        .complete(first, ClientResult::WrongCredential)
        .unwrap();
    assert_eq!(client.state(), State::Finished(Terminal::WrongCredential));
    assert_eq!(client.begin_next(), Err(SchedulerError::Finished));
    assert!(client.possibly_charged().is_empty());
}

#[test]
fn only_timeout_and_unavailability_allow_next_slot_and_remain_possibly_charged() {
    for result in [ClientResult::Timeout, ClientResult::Unavailable] {
        let mut client = Scheduler::new(plan()).unwrap();
        let first = client.begin_next().unwrap();
        client.complete(first, result).unwrap();
        assert_eq!(client.possibly_charged(), &[first]);
        let second = client.begin_next().unwrap();
        assert_ne!(first.slot, second.slot);
        assert_eq!(
            client.complete(first, ClientResult::Approved),
            Err(SchedulerError::UnexpectedResponse)
        );
        assert_eq!(client.state(), State::InFlight(second));
        client.complete(second, ClientResult::Timeout).unwrap();
        assert_eq!(client.state(), State::Finished(Terminal::NoEligibleSlots));
        assert_eq!(client.possibly_charged(), &[first, second]);
        assert_eq!(client.begin_next(), Err(SchedulerError::Finished));
    }
}

#[test]
fn completion_and_close_never_leave_live_requests() {
    for (result, terminal) in [
        (ClientResult::Approved, Terminal::Approved),
        (ClientResult::Rejected, Terminal::Rejected),
    ] {
        let mut client = Scheduler::new(plan()).unwrap();
        let target = client.begin_next().unwrap();
        client.complete(target, result).unwrap();
        assert_eq!(client.state(), State::Finished(terminal));
        assert_eq!(
            client.complete(target, result),
            Err(SchedulerError::UnexpectedResponse)
        );
        assert_eq!(client.begin_next(), Err(SchedulerError::Finished));
    }
    let mut client = Scheduler::new(plan()).unwrap();
    let target = client.begin_next().unwrap();
    client.close();
    client.close();
    assert_eq!(client.possibly_charged(), &[target]);
    assert_eq!(
        client.complete(target, ClientResult::Approved),
        Err(SchedulerError::UnexpectedResponse)
    );
}

#[test]
fn no_mixed_opening_duplicate_slot_or_reused_request_in_plan() {
    assert!(matches!(
        Scheduler::new(vec![]),
        Err(SchedulerError::InvalidPlan)
    ));
    for d in [
        domain(),
        Domain {
            suite: 99,
            ..plan()[1]
        },
        Domain {
            network: id(99),
            ..plan()[1]
        },
        Domain {
            safe: id(99),
            ..plan()[1]
        },
        Domain {
            generation: 99,
            ..plan()[1]
        },
        Domain {
            operation: Operation::Recovery,
            ..plan()[1]
        },
        Domain {
            request: domain().request,
            ..plan()[1]
        },
        Domain {
            slot: domain().slot,
            ..plan()[1]
        },
    ] {
        assert!(matches!(
            Scheduler::new(vec![domain(), d]),
            Err(SchedulerError::InvalidPlan)
        ));
    }
    let mut d = domain();
    d.operation = Operation::Owner;
    assert!(matches!(
        Scheduler::new(vec![d]),
        Err(SchedulerError::InvalidPlan)
    ));
}

#[test]
fn response_must_match_all_outstanding_domain_fields() {
    let mut client = Scheduler::new(plan()).unwrap();
    let d = client.begin_next().unwrap();
    for response in [
        Domain { safe: id(99), ..d },
        Domain {
            generation: 99,
            ..d
        },
        Domain { slot: id(99), ..d },
        Domain {
            incarnation: id(99),
            ..d
        },
        Domain {
            request: id(99),
            ..d
        },
        Domain {
            operation: Operation::Recovery,
            ..d
        },
    ] {
        assert_eq!(
            client.complete(response, ClientResult::WrongCredential),
            Err(SchedulerError::UnexpectedResponse)
        );
        assert_eq!(client.state(), State::InFlight(d));
    }
}
