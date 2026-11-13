//! Node-owned ancestor discovery accounting. Keep one ledger across peers,
//! connections and rounds; no network I/O occurs while it is borrowed.
//!
//! Returned headers have exact framing and links only. They do not authorize
//! native execution, cumulative-work selection or a canonical state change.

use crate::{eng2::header::Header, wire::Hash};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicU64, Ordering},
};

pub mod runtime;

static NEXT_LEDGER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub maximum_candidates: usize,
    pub maximum_peers: usize,
    pub maximum_requests: u64,
    pub maximum_headers: usize,
    pub maximum_body_bytes: u64,
    /// Independent resource bound, not the canonical rollback-depth bound.
    pub maximum_headers_per_candidate: usize,
    pub maximum_attempts_per_header: usize,
    pub candidate_lifetime_ms: u64,
    pub window_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Clock,
    Expired,
    Capacity,
    UnknownCandidate,
    DuplicatePeer,
    InFlight,
    Complete,
    StaleRequest,
    InvalidHeader,
    Cycle,
    AncestorMismatch,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ancestor discovery: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Linear request ownership. Failure still consumes the attempt; a reconnect
/// or another round cannot reset it. This value is deliberately not Clone.
#[derive(Debug)]
pub struct HeaderRequest {
    ledger: u64,
    sequence: u64,
    candidate: Hash,
    peer: Hash,
    height: u64,
    id: Hash,
    body: bool,
}
impl HeaderRequest {
    pub fn query(&self) -> (u64, Hash) {
        (self.height, self.id)
    }
    pub fn is_body(&self) -> bool {
        self.body
    }
    pub fn peer(&self) -> Hash {
        self.peer
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub height: u64,
    pub id: Hash,
    pub ancestor_confirmed: bool,
}

#[derive(Debug)]
struct Candidate {
    cursor: Cursor,
    expires_ms: u64,
    descending: Vec<Header>,
    seen: BTreeSet<Hash>,
    attempted_peers: BTreeSet<Hash>,
    pending: Option<u64>,
    body_attempts: BTreeMap<Hash, BTreeSet<Hash>>,
    received_bodies: BTreeSet<Hash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    pub candidates: usize,
    pub peers: usize,
    pub requests: u64,
    pub headers: usize,
    pub body_bytes: u64,
}

/// A fixed, nonrenewing accounting window. Candidate expiry, retries and tip
/// changes never remove counts or release slots inside this window. The owner
/// may explicitly replace an expired window after its local policy cooldown;
/// it must not construct one per connection, round or candidate advertisement.
pub struct Ledger {
    identity: u64,
    network: Hash,
    genesis: Hash,
    limits: Limits,
    last_ms: u64,
    expires_ms: u64,
    clock_failed: bool,
    requests: u64,
    headers: usize,
    body_bytes: u64,
    peers: BTreeSet<Hash>,
    candidates: BTreeMap<Hash, Candidate>,
}
impl Ledger {
    pub fn new(network: Hash, genesis: Hash, limits: Limits, now_ms: u64) -> Result<Self, Error> {
        if network == [0; 32]
            || genesis == [0; 32]
            || limits.maximum_candidates == 0
            || limits.maximum_peers == 0
            || limits.maximum_requests == 0
            || limits.maximum_headers == 0
            || limits.maximum_body_bytes == 0
            || limits.maximum_headers_per_candidate == 0
            || limits.maximum_headers_per_candidate > limits.maximum_headers
            || limits.maximum_attempts_per_header == 0
            || limits.maximum_attempts_per_header > limits.maximum_peers
            || limits.candidate_lifetime_ms == 0
            || limits.window_ms == 0
            || limits.candidate_lifetime_ms > limits.window_ms
        {
            return Err(Error::Configuration);
        }
        let expires_ms = now_ms
            .checked_add(limits.window_ms)
            .ok_or(Error::Configuration)?;
        let identity = NEXT_LEDGER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            identity,
            network,
            genesis,
            limits,
            last_ms: now_ms,
            expires_ms,
            clock_failed: false,
            requests: 0,
            headers: 0,
            body_bytes: 0,
            peers: BTreeSet::new(),
            candidates: BTreeMap::new(),
        })
    }
    fn time(&mut self, now_ms: u64) -> Result<(), Error> {
        if self.clock_failed || now_ms < self.last_ms {
            self.clock_failed = true;
            return Err(Error::Clock);
        }
        self.last_ms = now_ms;
        if now_ms >= self.expires_ms {
            return Err(Error::Expired);
        }
        Ok(())
    }
    /// Roll the node-wide rate window only after its fixed end. This does not
    /// refresh a live candidate, and stale linear tickets remain invalid.
    pub fn renew_expired_window(&mut self, now_ms: u64) -> Result<bool, Error> {
        if self.clock_failed || now_ms < self.last_ms {
            self.clock_failed = true;
            return Err(Error::Clock);
        }
        if now_ms < self.expires_ms {
            return Ok(false);
        }
        *self = Self::new(self.network, self.genesis, self.limits, now_ms)?;
        Ok(true)
    }
    pub fn usage(&self) -> Usage {
        Usage {
            candidates: self.candidates.len(),
            peers: self.peers.len(),
            requests: self.requests,
            headers: self.headers,
            body_bytes: self.body_bytes,
        }
    }
    /// Duplicate advertisements preserve the original lifetime and accounting.
    pub fn begin(&mut self, height: u64, id: Hash, now_ms: u64) -> Result<Cursor, Error> {
        self.time(now_ms)?;
        if height == 0 || id == self.genesis || id == [0; 32] {
            return Err(Error::Configuration);
        }
        if let Some(candidate) = self.candidates.get(&id) {
            if now_ms >= candidate.expires_ms {
                return Err(Error::Expired);
            }
            let expected_height = candidate
                .descending
                .first()
                .map_or(candidate.cursor.height, |h| h.height);
            if expected_height != height {
                return Err(Error::InvalidHeader);
            }
            return Ok(candidate.cursor);
        }
        if self.candidates.len() >= self.limits.maximum_candidates {
            return Err(Error::Capacity);
        }
        let expires_ms = now_ms
            .saturating_add(self.limits.candidate_lifetime_ms)
            .min(self.expires_ms);
        let cursor = Cursor {
            height,
            id,
            ancestor_confirmed: false,
        };
        self.candidates.insert(
            id,
            Candidate {
                cursor,
                expires_ms,
                descending: Vec::new(),
                seen: BTreeSet::new(),
                attempted_peers: BTreeSet::new(),
                pending: None,
                body_attempts: BTreeMap::new(),
                received_bodies: BTreeSet::new(),
            },
        );
        Ok(cursor)
    }
    pub fn cursor(&mut self, candidate: Hash, now_ms: u64) -> Result<Cursor, Error> {
        self.time(now_ms)?;
        let entry = self
            .candidates
            .get(&candidate)
            .ok_or(Error::UnknownCandidate)?;
        if now_ms >= entry.expires_ms {
            return Err(Error::Expired);
        }
        Ok(entry.cursor)
    }
    /// The caller must supply an independently checked local canonical point.
    /// A peer-provided claim cannot authorize this operation. Only the exact
    /// current parent cursor can close the path; no headers are skipped.
    pub fn confirm_ancestor(
        &mut self,
        candidate: Hash,
        height: u64,
        id: Hash,
        now_ms: u64,
    ) -> Result<(), Error> {
        let cursor = self.cursor(candidate, now_ms)?;
        if cursor.height != height || cursor.id != id {
            return Err(Error::AncestorMismatch);
        }
        let entry = self.candidates.get_mut(&candidate).unwrap();
        if entry.pending.is_some() {
            return Err(Error::InFlight);
        }
        entry.cursor.ancestor_confirmed = true;
        Ok(())
    }
    /// Reserve globally before issuing any network request. One candidate has
    /// at most one in-flight header, and one authenticated source is tried once
    /// for each cursor. Switching peer or reconnecting never refunds attempts.
    pub fn request(
        &mut self,
        candidate: Hash,
        peer: Hash,
        now_ms: u64,
    ) -> Result<HeaderRequest, Error> {
        let cursor = self.cursor(candidate, now_ms)?;
        if cursor.ancestor_confirmed {
            return Err(Error::Complete);
        }
        if cursor.height == 0 {
            return Err(Error::AncestorMismatch);
        }
        let entry = self.candidates.get(&candidate).unwrap();
        if entry.pending.is_some() {
            return Err(Error::InFlight);
        }
        if entry.attempted_peers.contains(&peer) {
            return Err(Error::DuplicatePeer);
        }
        if self.requests >= self.limits.maximum_requests
            || self.headers >= self.limits.maximum_headers
            || entry.descending.len() >= self.limits.maximum_headers_per_candidate
            || entry.attempted_peers.len() >= self.limits.maximum_attempts_per_header
            || (!self.peers.contains(&peer) && self.peers.len() >= self.limits.maximum_peers)
        {
            return Err(Error::Capacity);
        }
        self.requests += 1;
        let sequence = self.requests;
        self.peers.insert(peer);
        let entry = self.candidates.get_mut(&candidate).unwrap();
        entry.attempted_peers.insert(peer);
        entry.pending = Some(sequence);
        Ok(HeaderRequest {
            ledger: self.identity,
            sequence,
            candidate,
            peer,
            height: cursor.height,
            id: cursor.id,
            body: false,
        })
    }
    /// Body requests consume the same node-wide request and peer caps. A
    /// successful body is never requested twice inside this candidate window.
    pub fn request_body(
        &mut self,
        candidate: Hash,
        id: Hash,
        peer: Hash,
        now_ms: u64,
    ) -> Result<HeaderRequest, Error> {
        let cursor = self.cursor(candidate, now_ms)?;
        if !cursor.ancestor_confirmed {
            return Err(Error::AncestorMismatch);
        }
        let entry = self.candidates.get(&candidate).unwrap();
        if entry.pending.is_some() {
            return Err(Error::InFlight);
        }
        if entry.received_bodies.contains(&id) {
            return Err(Error::Complete);
        }
        let header = entry
            .descending
            .iter()
            .find(|h| h.id().ok() == Some(id))
            .ok_or(Error::InvalidHeader)?;
        let height = header.height;
        let tried = entry.body_attempts.get(&id);
        if tried.is_some_and(|tried| tried.contains(&peer)) {
            return Err(Error::DuplicatePeer);
        }
        if self.requests >= self.limits.maximum_requests
            || tried.is_some_and(|tried| tried.len() >= self.limits.maximum_attempts_per_header)
            || (!self.peers.contains(&peer) && self.peers.len() >= self.limits.maximum_peers)
            || self.body_bytes >= self.limits.maximum_body_bytes
        {
            return Err(Error::Capacity);
        }
        self.requests += 1;
        self.peers.insert(peer);
        let entry = self.candidates.get_mut(&candidate).unwrap();
        entry.body_attempts.entry(id).or_default().insert(peer);
        entry.pending = Some(self.requests);
        Ok(HeaderRequest {
            ledger: self.identity,
            sequence: self.requests,
            candidate,
            peer,
            height,
            id,
            body: true,
        })
    }
    fn finish_request(
        &mut self,
        request: HeaderRequest,
        now_ms: u64,
    ) -> Result<(Hash, Cursor), Error> {
        self.time(now_ms)?;
        if request.ledger != self.identity {
            return Err(Error::StaleRequest);
        }
        let entry = self
            .candidates
            .get_mut(&request.candidate)
            .ok_or(Error::UnknownCandidate)?;
        if now_ms >= entry.expires_ms {
            return Err(Error::Expired);
        }
        let identity_matches = if request.body {
            entry.cursor.ancestor_confirmed
                && entry
                    .body_attempts
                    .get(&request.id)
                    .is_some_and(|peers| peers.contains(&request.peer))
                && entry.descending.iter().any(|header| {
                    header.height == request.height && header.id().ok() == Some(request.id)
                })
        } else {
            entry.cursor.height == request.height
                && entry.cursor.id == request.id
                && entry.attempted_peers.contains(&request.peer)
        };
        if entry.pending != Some(request.sequence) || !identity_matches {
            return Err(Error::StaleRequest);
        }
        entry.pending = None;
        Ok((request.candidate, entry.cursor))
    }
    /// Transport failure or a missing answer consumes the attempt but leaves
    /// the same cursor for a different authenticated source within the caps.
    pub fn defer(&mut self, request: HeaderRequest, now_ms: u64) -> Result<(), Error> {
        self.finish_request(request, now_ms).map(|_| ())
    }
    /// Call only after the exact body passed framing/commitment checks and was
    /// retained. Native validity remains a separate complete-verifier gate.
    pub fn body_retained(
        &mut self,
        request: HeaderRequest,
        encoded_bytes: usize,
        now_ms: u64,
    ) -> Result<(), Error> {
        if !request.body {
            return Err(Error::StaleRequest);
        }
        let id = request.id;
        let (candidate, _) = self.finish_request(request, now_ms)?;
        let total = self
            .body_bytes
            .checked_add(encoded_bytes as u64)
            .ok_or(Error::Capacity)?;
        if encoded_bytes == 0 || total > self.limits.maximum_body_bytes {
            return Err(Error::Capacity);
        }
        self.body_bytes = total;
        self.candidates
            .get_mut(&candidate)
            .unwrap()
            .received_bodies
            .insert(id);
        Ok(())
    }
    pub fn receive(
        &mut self,
        request: HeaderRequest,
        header: Header,
        now_ms: u64,
    ) -> Result<Cursor, Error> {
        if request.body {
            return Err(Error::StaleRequest);
        }
        let (candidate, cursor) = self.finish_request(request, now_ms)?;
        self.accept_header(candidate, cursor, header)
    }
    pub fn receive_local(
        &mut self,
        candidate: Hash,
        header: Header,
        now_ms: u64,
    ) -> Result<Cursor, Error> {
        let cursor = self.cursor(candidate, now_ms)?;
        let entry = self.candidates.get(&candidate).unwrap();
        if entry.pending.is_some() {
            return Err(Error::InFlight);
        }
        if cursor.ancestor_confirmed {
            return Err(Error::Complete);
        }
        self.accept_header(candidate, cursor, header)
    }
    fn accept_header(
        &mut self,
        candidate: Hash,
        cursor: Cursor,
        header: Header,
    ) -> Result<Cursor, Error> {
        let id = header.id().map_err(|_| Error::InvalidHeader)?;
        if header.network != self.network || header.height != cursor.height || id != cursor.id {
            return Err(Error::InvalidHeader);
        }
        let entry = self.candidates.get_mut(&candidate).unwrap();
        if header.parent == id || entry.seen.contains(&header.parent) || entry.seen.contains(&id) {
            return Err(Error::Cycle);
        }
        if header.height == 1 && header.parent != self.genesis {
            return Err(Error::InvalidHeader);
        }
        if self.headers >= self.limits.maximum_headers
            || entry.descending.len() >= self.limits.maximum_headers_per_candidate
        {
            return Err(Error::Capacity);
        }
        entry.seen.insert(id);
        entry.cursor = Cursor {
            height: header.height - 1,
            id: header.parent,
            ancestor_confirmed: header.height == 1,
        };
        entry.attempted_peers.clear();
        entry.descending.push(header);
        self.headers += 1;
        Ok(entry.cursor)
    }
    pub fn remaining_body_bytes(&self) -> u64 {
        self.limits
            .maximum_body_bytes
            .saturating_sub(self.body_bytes)
    }
    /// Exact reverse links are returned in ancestor-to-tip order, with no native
    /// or proof-of-work validity claim. Qualify with the complete local prefix.
    pub fn path(&mut self, candidate: Hash, now_ms: u64) -> Result<Vec<Header>, Error> {
        let cursor = self.cursor(candidate, now_ms)?;
        if !cursor.ancestor_confirmed {
            return Err(Error::AncestorMismatch);
        }
        Ok(self
            .candidates
            .get(&candidate)
            .unwrap()
            .descending
            .iter()
            .rev()
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests;
