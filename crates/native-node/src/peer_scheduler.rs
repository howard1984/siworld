//! Bounded peer lifecycle policy for a future resident transport driver.
//!
//! This module owns no sockets, identities, database or cryptographic provider.
//! Callers supply elapsed monotonic milliseconds and acknowledge actual socket
//! closure before reservations are released. No retry selects weaker transport.
use crate::p2p::{Budget, Reservation};
use crate::wire::Hash;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

pub const MAX_PEERS: usize = 64;
pub const MAX_PENDING: usize = 16;
pub const MAX_ESTABLISHED: usize = 16;
pub const ADMISSION_MS: u64 = 5_000;
pub const SESSION_MS: u64 = 3_600_000;
pub const MAX_BACKOFF_MS: u64 = 60_000;
const BASE_BACKOFF_MS: u64 = 1_000;
const PEER_BYTES: usize = 256;
const ATTEMPT_BYTES: usize = 512;
static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Unavailable,
    Authentication,
    Protocol,
    LocalResource,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidIdentity,
    UnknownPeer,
    Duplicate,
    Backoff,
    Disabled,
    Capacity,
    ClockRegression,
    StaleAttempt,
    Expired,
    Stopped,
    Exhausted,
}

/// An opaque generation prevents stale worker results affecting a new session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt {
    peer: Hash,
    instance: u64,
    generation: u64,
    direction: Direction,
}
impl Attempt {
    pub fn peer(&self) -> Hash {
        self.peer
    }
}
pub struct Start {
    pub token: Attempt,
    pub cancel: Option<Attempt>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Ready(u64),
    Active(u64),
    Disabled,
}
struct Peer {
    phase: Phase,
    failures: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Pending,
    Established,
    RetiringPending,
    RetiringEstablished,
}
impl Stage {
    fn established(self) -> bool {
        matches!(self, Self::Established | Self::RetiringEstablished)
    }
    fn retiring(self) -> bool {
        matches!(self, Self::RetiringPending | Self::RetiringEstablished)
    }
    fn retire(self) -> Self {
        if self.established() {
            Self::RetiringEstablished
        } else {
            Self::RetiringPending
        }
    }
}
struct OwnedAttempt {
    token: Attempt,
    stage: Stage,
    deadline: u64,
    _reservation: Reservation,
}
/// Aggregate status excludes endpoint addresses, peer fingerprints and traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub configured: usize,
    pub pending: usize,
    pub established: usize,
    pub closing: usize,
    pub disabled: usize,
    pub stopped: bool,
}
pub struct Scheduler {
    local: Hash,
    peers: BTreeMap<Hash, Peer>,
    attempts: BTreeMap<u64, OwnedAttempt>,
    budget: Budget,
    _configured: Reservation,
    instance: u64,
    last_ms: u64,
    next: u64,
    stopped: bool,
}
impl Scheduler {
    /// Peers must be fingerprints from independently authenticated pins. This
    /// constructor neither discovers peers nor authenticates supplied pins.
    pub fn new(local: Hash, peers: &[Hash], budget: Budget, now_ms: u64) -> Result<Self, Error> {
        if local == [0; 32] || peers.len() > MAX_PEERS {
            return Err(Error::InvalidIdentity);
        }
        let mut configured = BTreeMap::new();
        for peer in peers {
            if *peer == [0; 32]
                || *peer == local
                || configured
                    .insert(
                        *peer,
                        Peer {
                            phase: Phase::Ready(now_ms),
                            failures: 0,
                        },
                    )
                    .is_some()
            {
                return Err(Error::InvalidIdentity);
            }
        }
        let reservation = budget
            .reserve(peers.len() * PEER_BYTES)
            .map_err(|_| Error::Capacity)?;
        let instance = NEXT_INSTANCE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::Exhausted)?;
        Ok(Self {
            local,
            peers: configured,
            attempts: BTreeMap::new(),
            budget,
            _configured: reservation,
            instance,
            last_ms: now_ms,
            next: 0,
            stopped: false,
        })
    }
    fn clock(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_ms {
            return Err(Error::ClockRegression);
        }
        self.last_ms = now;
        Ok(())
    }
    pub fn status(&self) -> Status {
        Status {
            configured: self.peers.len(),
            pending: self
                .attempts
                .values()
                .filter(|a| !a.stage.established())
                .count(),
            established: self
                .attempts
                .values()
                .filter(|a| a.stage.established())
                .count(),
            closing: self
                .attempts
                .values()
                .filter(|a| a.stage.retiring())
                .count(),
            disabled: self
                .peers
                .values()
                .filter(|p| p.phase == Phase::Disabled)
                .count(),
            stopped: self.stopped,
        }
    }
    /// Bounded configured-peer work list for an external dial driver. It contains
    /// no discovered identity, endpoint address or untrusted peer advertisement.
    pub fn ready_outbound(&mut self, now: u64) -> Result<Vec<Hash>, Error> {
        self.clock(now)?;
        if self.stopped {
            return Err(Error::Stopped);
        }
        Ok(self
            .peers
            .iter()
            .filter_map(|(id, peer)| {
                matches!(peer.phase, Phase::Ready(at) if at <= now).then_some(*id)
            })
            .collect())
    }
    /// A preferred simultaneous connection may supersede a pending attempt.
    /// Its reservation remains charged until the driver closes that old socket.
    /// The smaller pinned identity is the preferred connection initiator.
    pub fn begin(&mut self, peer: Hash, direction: Direction, now: u64) -> Result<Start, Error> {
        self.clock(now)?;
        if self.stopped {
            return Err(Error::Stopped);
        }
        let entry = self.peers.get(&peer).ok_or(Error::UnknownPeer)?;
        let preferred = if self.local < peer {
            Direction::Outbound
        } else {
            Direction::Inbound
        };
        let cancel = match entry.phase {
            Phase::Disabled => return Err(Error::Disabled),
            Phase::Ready(at) if now < at => return Err(Error::Backoff),
            Phase::Ready(_) => None,
            Phase::Active(id) => {
                let old = self.attempts.get(&id).ok_or(Error::StaleAttempt)?;
                if old.stage != Stage::Pending
                    || direction != preferred
                    || old.token.direction == preferred
                {
                    return Err(Error::Duplicate);
                }
                Some(old.token)
            }
        };
        if self.status().pending >= MAX_PENDING {
            return Err(Error::Capacity);
        }
        let generation = self.next.checked_add(1).ok_or(Error::Exhausted)?;
        let deadline = now.checked_add(ADMISSION_MS).ok_or(Error::Exhausted)?;
        let reservation = self
            .budget
            .reserve(ATTEMPT_BYTES)
            .map_err(|_| Error::Capacity)?;
        if let Some(old) = cancel {
            self.attempts
                .get_mut(&old.generation)
                .expect("active pending attempt")
                .stage = Stage::RetiringPending;
        }
        let token = Attempt {
            peer,
            instance: self.instance,
            generation,
            direction,
        };
        self.attempts.insert(
            generation,
            OwnedAttempt {
                token,
                stage: Stage::Pending,
                deadline,
                _reservation: reservation,
            },
        );
        self.peers.get_mut(&peer).expect("configured peer").phase = Phase::Active(generation);
        self.next = generation;
        Ok(Start { token, cancel })
    }
    /// Call only after the real provider and native Hello succeed. This method
    /// cannot construct a transport Authenticated capability or verify a peer.
    pub fn authenticated(&mut self, token: Attempt, now: u64) -> Result<(), Error> {
        self.clock(now)?;
        if self.stopped {
            return Err(Error::Stopped);
        }
        let owned = self
            .attempts
            .get(&token.generation)
            .ok_or(Error::StaleAttempt)?;
        if owned.token != token
            || owned.stage != Stage::Pending
            || self.peers.get(&token.peer).map(|p| p.phase) != Some(Phase::Active(token.generation))
        {
            return Err(Error::StaleAttempt);
        }
        if now >= owned.deadline {
            return Err(Error::Expired);
        }
        if self.status().established >= MAX_ESTABLISHED {
            return Err(Error::Capacity);
        }
        let deadline = now.checked_add(SESSION_MS).ok_or(Error::Exhausted)?;
        let owned = self
            .attempts
            .get_mut(&token.generation)
            .expect("checked pending attempt");
        owned.stage = Stage::Established;
        owned.deadline = deadline;
        self.peers
            .get_mut(&token.peer)
            .expect("configured peer")
            .failures = 0;
        Ok(())
    }
    fn failed_peer(&mut self, peer: Hash, failure: Failure, authenticated: bool, now: u64) {
        let entry = self.peers.get_mut(&peer).expect("configured peer");
        // An unauthenticated claim must not quarantine the legitimate pin.
        // Record-authentication failure also does not authenticate its sender.
        if self.stopped || (authenticated && failure == Failure::Protocol) {
            entry.phase = Phase::Disabled;
            return;
        }
        entry.failures = entry.failures.saturating_add(1);
        let exponent = entry.failures.saturating_sub(1).min(16);
        let base = BASE_BACKOFF_MS
            .saturating_mul(1u64 << exponent)
            .min(MAX_BACKOFF_MS);
        // Stable bounded scheduling jitter, not cryptographic randomness.
        let seed = u64::from_le_bytes(peer[..8].try_into().expect("fingerprint prefix"))
            ^ u64::from_le_bytes(self.local[..8].try_into().expect("fingerprint prefix"));
        let delay = base
            .saturating_add(seed % (base / 4 + 1))
            .min(MAX_BACKOFF_MS);
        entry.phase = Phase::Ready(now.saturating_add(delay));
    }
    /// Closing an expired/superseded attempt cannot penalize its replacement.
    /// The driver must invoke this only after actual I/O and worker cleanup.
    pub fn closed(&mut self, token: Attempt, failure: Failure, now: u64) -> Result<(), Error> {
        self.clock(now)?;
        if self.attempts.get(&token.generation).map(|a| a.token) != Some(token) {
            return Err(Error::StaleAttempt);
        }
        let owned = self
            .attempts
            .remove(&token.generation)
            .expect("checked attempt");
        if !owned.stage.retiring() {
            self.failed_peer(token.peer, failure, owned.stage == Stage::Established, now);
        }
        Ok(())
    }
    /// Trusted local policy may disable a configured pin until reconfiguration.
    /// Never call this on the strength of an unauthenticated peer claim.
    pub fn disable(&mut self, peer: Hash, now: u64) -> Result<Option<Attempt>, Error> {
        self.clock(now)?;
        let entry = self.peers.get_mut(&peer).ok_or(Error::UnknownPeer)?;
        let cancel = if let Phase::Active(id) = entry.phase {
            let owned = self.attempts.get_mut(&id).ok_or(Error::StaleAttempt)?;
            owned.stage = owned.stage.retire();
            Some(owned.token)
        } else {
            None
        };
        entry.phase = Phase::Disabled;
        Ok(cancel)
    }
    /// Return sockets to cancel once, while retaining every closing reservation.
    pub fn poll(&mut self, now: u64) -> Result<Vec<Attempt>, Error> {
        self.clock(now)?;
        let expired: Vec<_> = self
            .attempts
            .values()
            .filter(|a| !a.stage.retiring() && now >= a.deadline)
            .map(|a| a.token)
            .collect();
        for token in &expired {
            let owned = self
                .attempts
                .get_mut(&token.generation)
                .expect("selected attempt");
            owned.stage = owned.stage.retire();
            self.failed_peer(token.peer, Failure::Unavailable, false, now);
        }
        Ok(expired)
    }
    pub fn shutdown(&mut self, now: u64) -> Result<Vec<Attempt>, Error> {
        self.clock(now)?;
        self.stopped = true;
        for peer in self.peers.values_mut() {
            peer.phase = Phase::Disabled;
        }
        let mut cancel = Vec::new();
        for owned in self.attempts.values_mut() {
            if !owned.stage.retiring() {
                cancel.push(owned.token);
                owned.stage = owned.stage.retire();
            }
        }
        Ok(cancel)
    }
}

#[cfg(test)]
mod tests;
