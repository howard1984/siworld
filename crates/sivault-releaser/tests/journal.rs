#![cfg(not(target_arch = "wasm32"))]

mod support;

use std::{
    fs::{self, OpenOptions},
    io::Write,
    sync::{Arc, Mutex},
};

use sivault_releaser::{
    journal::{Checkpoint, Journal, MarkerStore},
    ledger::{
        AuthorityError, Error, Event, Outcome, PolicyError, RecoveryActivation, Releaser,
        SlotIdentity,
    },
    message::Operation,
};
use support::*;

#[derive(Default)]
struct State {
    checkpoint: Option<Checkpoint>,
    fail_write: bool,
}

#[derive(Clone, Default)]
struct TestMarker(Arc<Mutex<State>>);

impl MarkerStore for TestMarker {
    fn load(&mut self, _: SlotIdentity) -> Result<Option<Checkpoint>, AuthorityError> {
        Ok(self.0.lock().unwrap().checkpoint)
    }

    fn compare_and_store(
        &mut self,
        _: SlotIdentity,
        expected: Option<Checkpoint>,
        next: Checkpoint,
    ) -> Result<(), AuthorityError> {
        let mut state = self.0.lock().unwrap();
        if state.fail_write {
            return Err(AuthorityError::Unavailable);
        }
        if state.checkpoint != expected {
            return Err(AuthorityError::Stale);
        }
        state.checkpoint = Some(next);
        Ok(())
    }
}

fn service(journal: Journal<TestMarker>) -> Releaser<Journal<TestMarker>> {
    let mut service = Releaser::new(journal);
    service.recover(slot()).unwrap();
    service
}

#[test]
fn journal_preserves_consumed_attempts_refill_and_retirement_across_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ledger");
    let marker = TestMarker::default();
    let mut releaser =
        service(Journal::provision(&path, marker.clone(), slot(), id(90), 1, record()).unwrap());
    assert!(matches!(
        Journal::open(&path, marker.clone(), slot()),
        Err(AuthorityError::NotExclusive)
    ));
    let first = attempt(1);
    releaser.apply(register(&first)).unwrap();
    assert!(matches!(
        releaser.apply(charge(&first)).unwrap(),
        Outcome::CredentialReady(_)
    ));
    drop(releaser);

    let mut releaser = service(Journal::open(&path, marker.clone(), slot()).unwrap());
    assert_eq!(releaser.snapshot().unwrap().spent(), 1);
    assert_eq!(
        releaser.apply(charge(&first)).unwrap_err(),
        Error::Policy(PolicyError::Replay)
    );
    assert_eq!(
        releaser.apply(register(&attempt(2))).unwrap_err(),
        Error::Policy(PolicyError::Exhausted)
    );
    releaser.apply(command(refill(1, 1, 2))).unwrap();
    releaser.apply(command(retire(2))).unwrap();
    drop(releaser);

    let mut releaser = service(Journal::open(&path, marker, slot()).unwrap());
    assert_eq!(releaser.snapshot().unwrap().remaining(), 2);
    assert!(!releaser.snapshot().unwrap().is_serving());
    assert_eq!(
        releaser.apply(register(&attempt(2))).unwrap_err(),
        Error::Policy(PolicyError::InvalidPhase)
    );
}

#[test]
fn older_snapshot_and_torn_tail_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ledger");
    let marker = TestMarker::default();
    let mut releaser =
        service(Journal::provision(&path, marker.clone(), slot(), id(90), 1, record()).unwrap());
    let initial = fs::read(&path).unwrap();
    releaser.apply(register(&attempt(1))).unwrap();
    drop(releaser);
    let latest = fs::read(&path).unwrap();
    fs::write(&path, initial).unwrap();
    assert!(matches!(
        Journal::open(&path, marker.clone(), slot()),
        Err(AuthorityError::InvalidEvidence)
    ));
    fs::write(&path, latest).unwrap();
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&[0, 0, 0])
        .unwrap();
    assert!(matches!(
        Journal::open(&path, marker, slot()),
        Err(AuthorityError::InvalidEvidence)
    ));
}

#[test]
fn uncertain_marker_update_never_authorizes_a_charge() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ledger");
    let marker = TestMarker::default();
    let mut releaser =
        service(Journal::provision(&path, marker.clone(), slot(), id(90), 1, record()).unwrap());
    let first = attempt(1);
    releaser.apply(register(&first)).unwrap();
    marker.0.lock().unwrap().fail_write = true;
    assert_eq!(
        releaser.apply(charge(&first)).unwrap_err(),
        Error::Authority(AuthorityError::Unavailable)
    );
    assert!(releaser.is_quarantined());
    drop(releaser);
    assert!(matches!(
        Journal::open(&path, marker, slot()),
        Err(AuthorityError::InvalidEvidence)
    ));
}

#[test]
fn recovery_activation_survives_restart_and_cannot_restore_allowance_or_override_revocation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ledger");
    let marker = TestMarker::default();
    let mut releaser =
        service(Journal::provision(&path, marker.clone(), slot(), id(90), 3, record()).unwrap());
    let previous = attempt(1);
    releaser.apply(register(&previous)).unwrap();
    releaser.apply(charge(&previous)).unwrap();
    let mut recovery = attempt(2);
    recovery.domain.operation = Operation::Recovery;
    releaser.apply(register(&recovery)).unwrap();
    let change = RecoveryActivation {
        domain: recovery.domain,
        previous_version: 1,
        next_record: id(99),
        commitment: id(100),
        sealed_material: id(101),
    };
    let activation = Event::ActivateRecovery(change);
    assert_eq!(
        releaser.apply(activation.clone()).unwrap_err(),
        Error::Policy(PolicyError::MissingChallenge)
    );
    releaser.apply(charge(&recovery)).unwrap();
    assert!(matches!(
        releaser.apply(activation.clone()),
        Ok(Outcome::RecoveryActivated)
    ));
    let after = releaser.snapshot().unwrap().clone();
    assert_eq!(after.normal_version(), 2);
    assert_eq!(after.latest_replacement(), Some(&change));
    assert_eq!(after.remaining(), 1);
    drop(releaser);

    let mut releaser = service(Journal::open(&path, marker, slot()).unwrap());
    assert!(matches!(
        releaser.apply(activation.clone()),
        Ok(Outcome::RecoveryActivated)
    ));
    assert_eq!(releaser.snapshot().unwrap(), &after);
    let different = RecoveryActivation {
        commitment: id(102),
        ..change
    };
    assert_eq!(
        releaser
            .apply(Event::ActivateRecovery(different))
            .unwrap_err(),
        Error::Policy(PolicyError::Conflict)
    );
    assert_eq!(
        releaser.apply(register(&attempt(3))).unwrap_err(),
        Error::Policy(PolicyError::WrongRecord)
    );
    releaser.apply(command(retire(1))).unwrap();
    assert_eq!(
        releaser.apply(activation).unwrap_err(),
        Error::Policy(PolicyError::InvalidPhase)
    );
    assert_eq!(releaser.snapshot().unwrap().remaining(), 1);
}
