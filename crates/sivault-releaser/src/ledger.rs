//! Permanent per-slot admission ledger and the required durable authority port.
//!
//! `Ledger::transition` is a pure proposal. It grants no permission to evaluate
//! credentials. Only `Releaser::apply`, after the authority commits the complete
//! transition, can return a non-cloneable `CredentialReady` token. Such a token
//! contains transcript metadata, never an approval, share, or credential result.

use std::collections::{BTreeMap, BTreeSet};

use crate::message::{AckPhase, Action, Body, Domain, Id, Message, Operation};

pub const MAX_PENDING_CHALLENGES: usize = 128;
/// Prototype fail-closed storage limits. Reaching these limits is not permission
/// to prune identities, reset the slot, or replace it with a fresh allowance.
pub const MAX_ISSUED_HISTORY: usize = 1024;
pub const MAX_COMMAND_HISTORY: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(target_arch = "wasm32"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct SlotIdentity {
    pub suite: u16,
    pub network: Id,
    pub safe: Id,
    pub slot: Id,
    pub ledger: Id,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(target_arch = "wasm32"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Record {
    pub generation: u64,
    pub incarnation: Id,
    pub manifest: Id,
    pub root: Id,
}

/// Exact noncredential attempt binding. Digests must be computed and checked by
/// the authenticated protocol integration. `record_manifest` identifies the
/// active provisioned record set; the adapter validates `selected_record` in it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(target_arch = "wasm32"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Attempt {
    pub domain: Domain,
    pub record_manifest: Id,
    pub selected_record: Id,
    pub challenge: Id,
    pub init_digest: Id,
    pub challenge_digest: Id,
    pub client_nonce: Id,
    pub server_nonce: Id,
    pub reply_key_digest: Id,
    pub deadline: u64,
}

/// An externally established verdict, not a proof implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Possession {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    RegisterChallenge {
        attempt: Attempt,
        now: u64,
    },
    Charge {
        attempt: Attempt,
        possession: Possession,
        now: u64,
    },
    /// The adapter authenticates the entire message and verifies its digest.
    Owner {
        message: Box<Message>,
        digest: Id,
        now: u64,
    },
    /// The adapter must verify actual removal of all targeted live records.
    ConfirmDeletion {
        generation: u64,
        incarnation: Id,
        tombstone: Id,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Prepared {
    pub rotation: Id,
    pub old_root: Id,
    pub next: Record,
    pub next_manifest: Id,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Retirement {
    pub record: Record,
    pub rotation: Id,
    pub next_root: Id,
    pub certificate: Id,
    pub fence: Option<Id>,
    pub tombstone: Option<Id>,
    pub deletion_confirmed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AppliedCommand {
    message: Message,
    digest: Id,
    receipt: CommandReceipt,
}

/// A pure snapshot. Possessing or constructing this value proves neither
/// freshness nor exclusive ownership. Its histories must never be pruned unless
/// an equivalent authenticated checkpoint preserves all replay protections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ledger {
    identity: SlotIdentity,
    initial_allowance: u64,
    grant_total: u64,
    spent: u64,
    revision: u64,
    command_counter: u64,
    active: Record,
    serving: bool,
    prepared: Option<Prepared>,
    retired: BTreeMap<(u64, Id), Retirement>,
    incarnations: BTreeSet<Id>,
    pending: BTreeMap<Id, Attempt>,
    issued: BTreeMap<Id, Attempt>,
    consumed: BTreeMap<Id, Attempt>,
    commands: BTreeMap<Id, AppliedCommand>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    DomainMismatch,
    WrongRecord,
    Expired,
    Replay,
    Conflict,
    MissingChallenge,
    PossessionRejected,
    Exhausted,
    PendingLimit,
    HistoryCapacity,
    InvalidCommand,
    StaleCommand,
    InvalidGrant,
    InvalidPhase,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandReceipt {
    pub command: Id,
    pub digest: Id,
    pub counter: u64,
    pub revision: u64,
    pub phase: AckPhase,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Effect {
    ChallengeRecorded,
    CredentialReady(Box<Attempt>),
    Command(CommandReceipt),
    DeletionConfirmed,
}

/// A proposal for one atomic durable transition, including its authenticated
/// inputs. Inspecting `next()` does not authorize any credential processing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transition {
    next: Ledger,
    event: Event,
    effect: Effect,
}

impl Transition {
    pub fn next(&self) -> &Ledger {
        &self.next
    }
    pub fn event(&self) -> &Event {
        &self.event
    }
}

impl Ledger {
    /// Initial provisioning only. A durable authority must refuse enrollment
    /// over an existing slot, including a reserve, retired or exhausted slot.
    /// Replacement and rotation carry this exact ledger forward instead.
    pub fn enrollment(identity: SlotIdentity, allowance: u64, record: Record) -> Self {
        Self {
            identity,
            initial_allowance: allowance,
            grant_total: allowance,
            spent: 0,
            revision: 0,
            command_counter: 0,
            active: record,
            serving: true,
            prepared: None,
            retired: BTreeMap::new(),
            incarnations: BTreeSet::from([record.incarnation]),
            pending: BTreeMap::new(),
            issued: BTreeMap::new(),
            consumed: BTreeMap::new(),
            commands: BTreeMap::new(),
        }
    }

    pub fn identity(&self) -> SlotIdentity {
        self.identity
    }
    pub fn initial_allowance(&self) -> u64 {
        self.initial_allowance
    }
    pub fn grant_total(&self) -> u64 {
        self.grant_total
    }
    pub fn spent(&self) -> u64 {
        self.spent
    }
    pub fn remaining(&self) -> u64 {
        self.grant_total - self.spent
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn command_counter(&self) -> u64 {
        self.command_counter
    }
    pub fn active(&self) -> Record {
        self.active
    }
    pub fn is_serving(&self) -> bool {
        self.serving
    }
    pub fn prepared(&self) -> Option<&Prepared> {
        self.prepared.as_ref()
    }
    pub fn retirements(&self) -> &BTreeMap<(u64, Id), Retirement> {
        &self.retired
    }
    pub fn consumed(&self) -> &BTreeMap<Id, Attempt> {
        &self.consumed
    }
    pub fn issued_count(&self) -> usize {
        self.issued.len()
    }
    pub fn command_count(&self) -> usize {
        self.commands.len()
    }

    pub fn transition(&self, event: Event) -> Result<Transition, PolicyError> {
        let mut next = self.clone();
        let (effect, changed) = next.apply(&event)?;
        if changed {
            next.revision = self.revision.checked_add(1).ok_or(PolicyError::Overflow)?;
        }
        Ok(Transition {
            next,
            event,
            effect,
        })
    }

    fn slot_matches(&self, d: &Domain) -> bool {
        d.suite == self.identity.suite
            && d.network == self.identity.network
            && d.safe == self.identity.safe
            && d.slot == self.identity.slot
    }

    fn active_matches(&self, d: &Domain) -> bool {
        self.slot_matches(d)
            && d.generation == self.active.generation
            && d.incarnation == self.active.incarnation
    }

    fn check_attempt(&self, a: &Attempt, now: u64) -> Result<(), PolicyError> {
        if !self.serving {
            return Err(PolicyError::InvalidPhase);
        }
        if !self.active_matches(&a.domain) || a.domain.operation == Operation::Owner {
            return Err(PolicyError::DomainMismatch);
        }
        if a.record_manifest != self.active.manifest {
            return Err(PolicyError::WrongRecord);
        }
        if now >= a.deadline {
            return Err(PolicyError::Expired);
        }
        Ok(())
    }

    fn apply(&mut self, event: &Event) -> Result<(Effect, bool), PolicyError> {
        match event {
            Event::RegisterChallenge { attempt, now } => {
                self.check_attempt(attempt, *now)?;
                if let Some(old) = self.consumed.get(&attempt.domain.request) {
                    return Err(if old == attempt {
                        PolicyError::Replay
                    } else {
                        PolicyError::Conflict
                    });
                }
                if let Some(old) = self.issued.get(&attempt.domain.request) {
                    if old != attempt {
                        return Err(PolicyError::Conflict);
                    }
                    return if self.pending.contains_key(&attempt.domain.request) {
                        Ok((Effect::ChallengeRecorded, false))
                    } else {
                        Err(PolicyError::Replay)
                    };
                }
                if self
                    .issued
                    .values()
                    .any(|a| a.challenge == attempt.challenge)
                {
                    return Err(PolicyError::Conflict);
                }
                if self.issued.len() >= MAX_ISSUED_HISTORY {
                    return Err(PolicyError::HistoryCapacity);
                }
                if self.remaining() == 0 {
                    return Err(PolicyError::Exhausted);
                }
                // Expired pending entries can be dropped; permanent issued
                // bindings still prevent request/challenge identity reuse.
                self.pending.retain(|_, a| a.deadline > *now);
                if self.pending.len() >= MAX_PENDING_CHALLENGES {
                    return Err(PolicyError::PendingLimit);
                }
                self.pending.insert(attempt.domain.request, attempt.clone());
                self.issued.insert(attempt.domain.request, attempt.clone());
                Ok((Effect::ChallengeRecorded, true))
            }
            Event::Charge {
                attempt,
                possession,
                now,
            } => {
                if let Some(old) = self.consumed.get(&attempt.domain.request) {
                    return Err(if old == attempt {
                        PolicyError::Replay
                    } else {
                        PolicyError::Conflict
                    });
                }
                self.check_attempt(attempt, *now)?;
                let pending = self
                    .pending
                    .get(&attempt.domain.request)
                    .ok_or(PolicyError::MissingChallenge)?;
                if pending != attempt {
                    return Err(PolicyError::Conflict);
                }
                if *possession != Possession::Accepted {
                    return Err(PolicyError::PossessionRejected);
                }
                if self.remaining() == 0 {
                    return Err(PolicyError::Exhausted);
                }
                self.spent = self.spent.checked_add(1).ok_or(PolicyError::Overflow)?;
                self.pending.remove(&attempt.domain.request);
                self.consumed
                    .insert(attempt.domain.request, attempt.clone());
                Ok((Effect::CredentialReady(Box::new(attempt.clone())), true))
            }
            Event::Owner {
                message,
                digest,
                now,
            } => self.owner(message, *digest, *now),
            Event::ConfirmDeletion {
                generation,
                incarnation,
                tombstone,
            } => {
                let old = self
                    .retired
                    .get_mut(&(*generation, *incarnation))
                    .ok_or(PolicyError::WrongRecord)?;
                if old.tombstone != Some(*tombstone) {
                    return Err(PolicyError::InvalidPhase);
                }
                let changed = !old.deletion_confirmed;
                old.deletion_confirmed = true;
                Ok((Effect::DeletionConfirmed, changed))
            }
        }
    }

    fn owner(
        &mut self,
        message: &Message,
        digest: Id,
        now: u64,
    ) -> Result<(Effect, bool), PolicyError> {
        message
            .validate()
            .map_err(|_| PolicyError::InvalidCommand)?;
        let Body::Owner { meta, action } = &message.body else {
            return Err(PolicyError::InvalidCommand);
        };
        if !self.slot_matches(&message.domain) {
            return Err(PolicyError::DomainMismatch);
        }
        if let Some(old) = self.commands.get(&meta.command) {
            return if old.message == *message && old.digest == digest {
                Ok((Effect::Command(old.receipt), false))
            } else {
                Err(PolicyError::Conflict)
            };
        }
        if self.commands.len() >= MAX_COMMAND_HISTORY {
            return Err(PolicyError::HistoryCapacity);
        }
        if meta.counter <= self.command_counter {
            return Err(PolicyError::StaleCommand);
        }
        if now >= meta.expiry {
            return Err(PolicyError::Expired);
        }
        let targets_retired = matches!(action, Action::Retire { .. } | Action::Delete { .. });
        if !targets_retired && !self.active_matches(&message.domain) {
            return Err(PolicyError::DomainMismatch);
        }
        if !targets_retired && !self.serving {
            return Err(PolicyError::InvalidPhase);
        }
        let phase = match action {
            Action::Revoke { ledger, record } => {
                if *ledger != self.identity.ledger || *record != self.active.manifest {
                    return Err(PolicyError::DomainMismatch);
                }
                if self.prepared.is_some() {
                    return Err(PolicyError::InvalidPhase);
                }
                self.retired.insert(
                    (self.active.generation, self.active.incarnation),
                    Retirement {
                        record: self.active,
                        rotation: meta.command,
                        next_root: Id::default(),
                        certificate: Id::default(),
                        fence: Some(digest),
                        tombstone: Some(digest),
                        deletion_confirmed: false,
                    },
                );
                self.serving = false;
                self.pending.clear();
                AckPhase::DeletionPending
            }
            Action::Refill {
                ledger,
                delta,
                expected_total,
                new_total,
            } => {
                if *ledger != self.identity.ledger {
                    return Err(PolicyError::DomainMismatch);
                }
                if *delta == 0
                    || *expected_total != self.grant_total
                    || expected_total.checked_add(*delta) != Some(*new_total)
                {
                    return Err(PolicyError::InvalidGrant);
                }
                self.grant_total = *new_total;
                AckPhase::Active
            }
            Action::Prepare {
                rotation,
                old_root,
                next_generation,
                next_manifest,
                next_root,
                successor_record,
                successor_incarnation,
                ..
            } => {
                if self.prepared.is_some()
                    || *next_generation <= self.active.generation
                    || *old_root != self.active.root
                {
                    return Err(PolicyError::InvalidPhase);
                }
                if *successor_incarnation != self.active.incarnation
                    && self.incarnations.contains(successor_incarnation)
                {
                    return Err(PolicyError::Conflict);
                }
                self.incarnations.insert(*successor_incarnation);
                self.prepared = Some(Prepared {
                    rotation: *rotation,
                    old_root: *old_root,
                    next_manifest: *next_manifest,
                    next: Record {
                        generation: *next_generation,
                        incarnation: *successor_incarnation,
                        manifest: *successor_record,
                        root: *next_root,
                    },
                });
                AckPhase::Prepared
            }
            Action::Commit {
                rotation,
                old_root,
                next_root,
                certificate,
                ..
            } => {
                let p = self.prepared.as_ref().ok_or(PolicyError::InvalidPhase)?;
                if p.rotation != *rotation
                    || p.old_root != *old_root
                    || p.next.root != *next_root
                    || p.next_manifest != meta.manifest
                {
                    return Err(PolicyError::InvalidPhase);
                }
                self.retired.insert(
                    (self.active.generation, self.active.incarnation),
                    Retirement {
                        record: self.active,
                        rotation: *rotation,
                        next_root: *next_root,
                        certificate: *certificate,
                        fence: None,
                        tombstone: None,
                        deletion_confirmed: false,
                    },
                );
                self.active = p.next;
                self.prepared = None;
                self.pending.clear();
                AckPhase::Active
            }
            Action::Retire {
                rotation,
                old_root,
                next_root,
                certificate,
            } => {
                // A removed endpoint need not hold or prepare successor records.
                // The adapter authenticates the external commit certificate.
                if self.active_matches(&message.domain) && self.serving {
                    if self.active.root != *old_root {
                        return Err(PolicyError::InvalidPhase);
                    }
                    self.retired.insert(
                        (self.active.generation, self.active.incarnation),
                        Retirement {
                            record: self.active,
                            rotation: *rotation,
                            next_root: *next_root,
                            certificate: *certificate,
                            fence: None,
                            tombstone: None,
                            deletion_confirmed: false,
                        },
                    );
                    self.serving = false;
                    self.pending.clear();
                }
                let old = self
                    .retired
                    .get_mut(&(message.domain.generation, message.domain.incarnation))
                    .ok_or(PolicyError::InvalidPhase)?;
                if old.rotation != *rotation
                    || old.record.root != *old_root
                    || old.next_root != *next_root
                    || old.certificate != *certificate
                    || old.fence.is_some()
                {
                    return Err(PolicyError::InvalidPhase);
                }
                old.fence = Some(digest);
                AckPhase::Fenced
            }
            Action::Delete {
                rotation,
                retired_record,
                expected_fence,
                ..
            } => {
                let old = self
                    .retired
                    .get_mut(&(message.domain.generation, message.domain.incarnation))
                    .ok_or(PolicyError::InvalidPhase)?;
                if old.rotation != *rotation
                    || old.record.manifest != *retired_record
                    || old.fence != Some(*expected_fence)
                    || old.tombstone.is_some()
                {
                    return Err(PolicyError::InvalidPhase);
                }
                old.tombstone = Some(digest);
                AckPhase::DeletionPending
            }
            Action::RestoreService {
                ledger,
                exact_record,
                target_incarnation,
                ..
            } => {
                if *ledger != self.identity.ledger || *exact_record != self.active.manifest {
                    return Err(PolicyError::WrongRecord);
                }
                if self.incarnations.contains(target_incarnation) || self.prepared.is_some() {
                    return Err(PolicyError::InvalidPhase);
                }
                // The adapter must fence the old authority and validate exact
                // ledger/head/tombstone continuity before committing this change.
                self.incarnations.insert(*target_incarnation);
                self.active.incarnation = *target_incarnation;
                self.pending.clear();
                AckPhase::Active
            }
        };
        self.command_counter = meta.counter;
        let receipt = CommandReceipt {
            command: meta.command,
            digest,
            counter: meta.counter,
            revision: self.revision.checked_add(1).ok_or(PolicyError::Overflow)?,
            phase,
        };
        self.commands.insert(
            meta.command,
            AppliedCommand {
                message: message.clone(),
                digest,
                receipt,
            },
        );
        Ok((Effect::Command(receipt), true))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    Unavailable,
    Stale,
    NotExclusive,
    InvalidEvidence,
}

/// Trusted deployment adapter; no implementation is provided by this crate.
///
/// Recovery requires exclusive access and checking the journal against state
/// outside the normal backup domain. Unknown or mismatched state fails closed.
/// A simultaneous restore of both stores can evade best-effort detection.
/// Initial enrollment must be installed once, never overwrite an existing slot.
///
/// Commit must compare the entire expected ledger with protected current state,
/// serialize writers and durably commit ALL of `transition.next()` atomically.
/// No successful return before persistence. An uncertain commit is an error;
/// recovery must retain any charge that did reach storage. Even no-op retries
/// require the exclusive current-state check. The calling protocol must
/// authenticate event inputs, check time/deadlines and possession verdicts,
/// compute/check transcript and command digests, and validate selected records.
/// Owner commands additionally require authenticated owner/manifest/predecessor,
/// expected ledger-head and tombstone digests, commit/readiness certificates,
/// replacement-authority fencing and deletion receipts as applicable. This
/// interface does not supply or approve any such mechanism or cryptography.
pub trait DurableAuthority {
    fn recover_exclusive(&mut self, slot: SlotIdentity) -> Result<Ledger, AuthorityError>;
    fn commit(&mut self, expected: &Ledger, transition: &Transition) -> Result<(), AuthorityError>;
}

#[derive(Debug, Default)]
pub struct UnavailableAuthority;
impl DurableAuthority for UnavailableAuthority {
    fn recover_exclusive(&mut self, _: SlotIdentity) -> Result<Ledger, AuthorityError> {
        Err(AuthorityError::Unavailable)
    }
    fn commit(&mut self, _: &Ledger, _: &Transition) -> Result<(), AuthorityError> {
        Err(AuthorityError::Unavailable)
    }
}

/// An admission token for exactly this committed attempt. Intentionally neither
/// Clone nor serializable. It is not an approval and carries no result bytes.
#[derive(Debug)]
#[must_use]
pub struct CredentialReady {
    attempt: Box<Attempt>,
    revision: u64,
}
impl CredentialReady {
    pub fn attempt(&self) -> &Attempt {
        &self.attempt
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn into_attempt(self) -> Attempt {
        *self.attempt
    }
}

#[derive(Debug)]
pub enum Outcome {
    ChallengeRecorded,
    CredentialReady(CredentialReady),
    Command(CommandReceipt),
    DeletionConfirmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Quarantined,
    Policy(PolicyError),
    Authority(AuthorityError),
}

/// Starts quarantined, including when a caller already has a Ledger snapshot.
/// Quarantine is cleared only by a successful exact/exclusive authority recovery.
pub struct Releaser<A = UnavailableAuthority> {
    authority: A,
    ledger: Option<Ledger>,
}

impl Default for Releaser {
    fn default() -> Self {
        Self::new(UnavailableAuthority)
    }
}

impl<A: DurableAuthority> Releaser<A> {
    pub fn new(authority: A) -> Self {
        Self {
            authority,
            ledger: None,
        }
    }
    pub fn is_quarantined(&self) -> bool {
        self.ledger.is_none()
    }
    pub fn snapshot(&self) -> Option<&Ledger> {
        self.ledger.as_ref()
    }
    pub(crate) fn authority(&self) -> &A {
        &self.authority
    }
    pub fn quarantine(&mut self) {
        self.ledger = None;
    }

    pub fn recover(&mut self, slot: SlotIdentity) -> Result<(), Error> {
        self.quarantine();
        let ledger = self
            .authority
            .recover_exclusive(slot)
            .map_err(Error::Authority)?;
        if ledger.identity != slot {
            return Err(Error::Authority(AuthorityError::InvalidEvidence));
        }
        self.ledger = Some(ledger);
        Ok(())
    }

    pub fn apply(&mut self, event: Event) -> Result<Outcome, Error> {
        let current = self.ledger.as_ref().ok_or(Error::Quarantined)?;
        let transition = current.transition(event).map_err(Error::Policy)?;
        if let Err(error) = self.authority.commit(current, &transition) {
            self.quarantine();
            return Err(Error::Authority(error));
        }
        let revision = transition.next.revision;
        self.ledger = Some(transition.next);
        Ok(match transition.effect {
            Effect::ChallengeRecorded => Outcome::ChallengeRecorded,
            Effect::CredentialReady(attempt) => {
                Outcome::CredentialReady(CredentialReady { attempt, revision })
            }
            Effect::Command(receipt) => Outcome::Command(receipt),
            Effect::DeletionConfirmed => Outcome::DeletionConfirmed,
        })
    }
}
