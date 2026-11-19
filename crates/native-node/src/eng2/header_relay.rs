//! Bounded header-only relay scheduling over independently checked paths.
//! This component grants no body validity, canonical state or mining template.
use super::{
    header::Header,
    selection::{HeaderRules, VerifiedHeaders},
};
use crate::wire::Hash;
use siworld_core::pow::Work;
use std::collections::{BTreeMap, VecDeque};

const MAX_PENDING: usize = 64;
const MAX_PEERS: usize = 8;
const MAX_OFFERS_PER_SECOND: u64 = 32;
const PEER_INTERVAL_MS: u64 = 50;
const RETAIN_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Context,
    WorkFloor,
    Clock,
    Capacity,
}
#[derive(Clone, Debug)]
pub struct Announcement {
    header: Header,
    work: Work,
    sequence: u64,
    first_qualified_ms: u64,
    source_peer: Hash,
}
impl Announcement {
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn cumulative_work(&self) -> Work {
        self.work
    }
    pub fn first_qualified_ms(&self) -> u64 {
        self.first_qualified_ms
    }
    pub fn requires_validated_parent_state(&self) -> bool {
        true
    }
}
struct PeerCursor {
    sequence: u64,
    last_sent_ms: Option<u64>,
}
pub struct Relay {
    rules: HeaderRules,
    queue: VecDeque<Announcement>,
    peers: BTreeMap<Hash, PeerCursor>,
    sequence: u64,
    now_ms: u64,
    clock_failed: bool,
    window_ms: u64,
    window_offers: u64,
}
impl Relay {
    pub fn new(rules: HeaderRules, now_ms: u64) -> Self {
        Self {
            rules,
            queue: VecDeque::new(),
            peers: BTreeMap::new(),
            sequence: 0,
            now_ms,
            clock_failed: false,
            window_ms: now_ms,
            window_offers: 0,
        }
    }
    fn time(&mut self, now_ms: u64) -> Result<(), Error> {
        if self.clock_failed || now_ms < self.now_ms {
            self.clock_failed = true;
            return Err(Error::Clock);
        }
        self.now_ms = now_ms;
        self.queue
            .retain(|entry| now_ms.saturating_sub(entry.first_qualified_ms) < RETAIN_MS);
        if now_ms.saturating_sub(self.window_ms) >= 1000 {
            self.window_ms = now_ms;
            self.window_offers = 0;
        }
        Ok(())
    }
    /// Both paths are locally verified from the same immutable genesis/rules.
    /// Advertised remote work or an isolated framed header cannot enter here.
    pub fn offer(
        &mut self,
        canonical: &VerifiedHeaders,
        candidate: &VerifiedHeaders,
        source_peer: Hash,
        now_ms: u64,
    ) -> Result<bool, Error> {
        self.time(now_ms)?;
        if canonical.rules() != &self.rules
            || candidate.rules() != &self.rules
            || candidate.height() == 0
            || source_peer == [0; 32]
        {
            return Err(Error::Context);
        }
        if candidate.cumulative_work() < canonical.cumulative_work() {
            return Err(Error::WorkFloor);
        }
        let header = candidate.header(candidate.height()).ok_or(Error::Context)?;
        let id = header.id().map_err(|_| Error::Context)?;
        if self.queue.iter().any(|entry| entry.header.id() == Ok(id)) {
            return Ok(false);
        }
        if self.queue.len() >= MAX_PENDING || self.window_offers >= MAX_OFFERS_PER_SECOND {
            return Err(Error::Capacity);
        }
        let sequence = self.sequence.checked_add(1).ok_or(Error::Capacity)?;
        self.queue.push_back(Announcement {
            header: header.clone(),
            work: candidate.cumulative_work(),
            sequence,
            first_qualified_ms: now_ms,
            source_peer,
        });
        self.sequence = sequence;
        self.window_offers += 1;
        Ok(true)
    }
    /// Returns one bounded per-peer transmission attempt. The caller supplies
    /// the authenticated configured peer identity and owns actual socket I/O.
    /// A failed/partial send must close its session; the next connection can
    /// register a fresh cursor with `disconnected` after its retained cleanup.
    pub fn next_for_peer(
        &mut self,
        peer: Hash,
        canonical: &VerifiedHeaders,
        now_ms: u64,
    ) -> Result<Option<Announcement>, Error> {
        self.time(now_ms)?;
        if canonical.rules() != &self.rules || peer == [0; 32] {
            return Err(Error::Context);
        }
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_PEERS {
            return Err(Error::Capacity);
        }
        let cursor = self.peers.entry(peer).or_insert(PeerCursor {
            sequence: 0,
            last_sent_ms: None,
        });
        if cursor
            .last_sent_ms
            .is_some_and(|last| now_ms.saturating_sub(last) < PEER_INTERVAL_MS)
        {
            return Ok(None);
        }
        let value = self
            .queue
            .iter()
            .find(|entry| {
                entry.sequence > cursor.sequence
                    && entry.source_peer != peer
                    && entry.work >= canonical.cumulative_work()
            })
            .cloned();
        if let Some(entry) = &value {
            cursor.sequence = entry.sequence;
            cursor.last_sent_ms = Some(now_ms);
        }
        Ok(value)
    }
    pub fn disconnected(&mut self, peer: Hash) {
        self.peers.remove(&peer);
    }
}

#[cfg(test)]
mod tests;
