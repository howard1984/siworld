//! Bounded model of folder publication and releaser activation under interruption.
//! No modeled authentication predicate substitutes for a protocol implementation.

use std::collections::{HashSet, VecDeque};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Authorization {
    session: u8,
    slot: u8,
    generation: u8,
    old_version: u8,
    proposal: u8,
}

const GOOD: Authorization = Authorization {
    session: 1,
    slot: 1,
    generation: 1,
    old_version: 1,
    proposal: 1,
};

const START_ALLOWANCE: u8 = 3;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
struct Model {
    // Folder-persisted state.
    pending: Option<u8>,
    folder_applied: bool,
    // Releaser-persisted state.
    spent: u8,
    revoked: bool,
    quarantined: bool,
    active_version: u8,
    receipt: Option<Authorization>,
    notice: bool,
    // Process-local recovery session.
    authorized: Option<Authorization>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Input {
    NormalAttempt(u8),
    RecoveryAttempt {
        words_match: bool,
    },
    Stage(u8),
    Activate {
        authorization: Authorization,
        readback: u8,
    },
    Finalize,
    Restart,
    Revoke,
    Quarantine,
    OwnerContact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Result {
    None,
    Denied,
    Opened,
    Activated,
    AlreadyActivated,
    Alert,
}

impl Model {
    fn initial() -> Self {
        Self {
            active_version: 1,
            ..Self::default()
        }
    }

    fn serving(self) -> bool {
        !self.revoked && !self.quarantined
    }

    fn uses_folder_wrap(self, version: u8) -> bool {
        self.serving()
            && self.active_version == version
            && if version == 1 {
                !self.folder_applied
            } else {
                self.pending == Some(1) || self.folder_applied
            }
    }

    fn transition(mut self, input: Input) -> (Self, Result) {
        use Input::*;
        let outcome = match input {
            NormalAttempt(version)
                if self.serving()
                    && self.spent < START_ALLOWANCE
                    && self.active_version == version =>
            {
                self.spent += 1;
                Result::Opened
            }
            RecoveryAttempt { words_match } if self.serving() && self.spent < START_ALLOWANCE => {
                self.spent += 1;
                if words_match {
                    if self.receipt.is_none() {
                        self.authorized = Some(GOOD);
                    }
                    Result::Opened
                } else {
                    Result::Denied
                }
            }
            Stage(proposal) if self.receipt.is_none() => {
                self.pending = Some(proposal);
                Result::None
            }
            Activate {
                authorization,
                readback,
            } if self.serving() => {
                if self.receipt == Some(authorization) && readback == authorization.proposal {
                    Result::AlreadyActivated
                } else if self.authorized == Some(authorization)
                    && self.receipt.is_none()
                    && authorization.old_version == self.active_version
                    && readback == authorization.proposal
                    && self.pending == Some(readback)
                {
                    self.receipt = Some(authorization);
                    self.authorized = None;
                    self.active_version += 1;
                    self.notice = true;
                    Result::Activated
                } else {
                    Result::Denied
                }
            }
            Finalize if self.receipt.is_some() => {
                self.folder_applied = true;
                self.pending = None;
                Result::None
            }
            Restart => {
                self.authorized = None;
                Result::None
            }
            Revoke => {
                self.revoked = true;
                self.authorized = None;
                Result::None
            }
            Quarantine => {
                self.quarantined = true;
                self.authorized = None;
                Result::None
            }
            OwnerContact if self.notice => Result::Alert,
            _ => Result::Denied,
        };
        (self, outcome)
    }
}

#[test]
fn explores_all_reachable_interruption_and_scope_states() {
    use Input::*;
    let mut actions = vec![
        NormalAttempt(1),
        NormalAttempt(2),
        RecoveryAttempt { words_match: false },
        RecoveryAttempt { words_match: true },
        Stage(1),
        Stage(2),
        Finalize,
        Restart,
        Revoke,
        Quarantine,
        OwnerContact,
    ];
    for authorization in [
        GOOD,
        Authorization { session: 2, ..GOOD },
        Authorization { slot: 2, ..GOOD },
        Authorization {
            generation: 2,
            ..GOOD
        },
        Authorization {
            old_version: 2,
            ..GOOD
        },
        Authorization {
            proposal: 2,
            ..GOOD
        },
    ] {
        actions.extend([1, 2].map(|readback| Activate {
            authorization,
            readback,
        }));
    }
    let initial = Model::initial();
    let mut seen = HashSet::from([initial]);
    let mut queue = VecDeque::from([initial]);
    let mut activations = 0;
    let mut retries = 0;
    while let Some(before) = queue.pop_front() {
        for input in actions.iter().copied() {
            let (after, result) = before.transition(input);
            assert!(after.spent >= before.spent && after.spent <= START_ALLOWANCE);
            assert!(!before.revoked || after.revoked);
            assert!(!before.quarantined || after.quarantined);
            assert!(!before.notice || after.notice);
            assert_eq!(
                after.uses_folder_wrap(1),
                after.serving() && after.receipt.is_none()
            );
            assert_eq!(
                after.uses_folder_wrap(2),
                after.serving() && after.receipt.is_some()
            );
            if !before.serving() {
                assert!(!matches!(result, Result::Opened | Result::Activated));
            }
            if let Activate {
                authorization,
                readback,
            } = input
            {
                assert_eq!(after.spent, before.spent);
                if result == Result::Activated {
                    activations += 1;
                    assert_eq!(authorization, GOOD);
                    assert_eq!(before.pending, Some(readback));
                    assert_eq!(before.receipt, None);
                    assert_eq!(after.active_version, 2);
                    assert!(after.notice);
                } else {
                    retries += usize::from(result == Result::AlreadyActivated);
                    assert_eq!(after, before);
                }
            }
            if input == Restart {
                assert_eq!(
                    after,
                    Model {
                        authorized: None,
                        ..before
                    }
                );
            }
            if input == OwnerContact && before.receipt.is_some() {
                assert_eq!(result, Result::Alert);
            }
            if seen.insert(after) {
                queue.push_back(after);
            }
        }
    }
    assert!(seen.len() >= 40);
    assert!(activations > 0 && retries > 0);
}

#[test]
fn exhaustion_shared_and_lost_activation_reply_is_idempotent() {
    use Input::*;
    let (model, _) = Model::initial().transition(NormalAttempt(1));
    let (model, _) = model.transition(RecoveryAttempt { words_match: false });
    let (model, result) = model.transition(RecoveryAttempt { words_match: true });
    assert_eq!(result, Result::Opened);
    assert_eq!(model.transition(NormalAttempt(1)).1, Result::Denied);
    assert_eq!(
        model.transition(RecoveryAttempt { words_match: true }).1,
        Result::Denied
    );
    let (model, _) = model.transition(Stage(1));
    let change = Activate {
        authorization: GOOD,
        readback: 1,
    };
    assert_eq!(
        model.transition(Revoke).0.transition(change).1,
        Result::Denied
    );
    let (model, result) = model.transition(change);
    assert_eq!(result, Result::Activated);
    let (model, _) = model.transition(Restart);
    assert_eq!(model.transition(change), (model, Result::AlreadyActivated));
    assert_eq!(model.transition(OwnerContact).1, Result::Alert);
    assert_eq!(model.spent, START_ALLOWANCE);
}
