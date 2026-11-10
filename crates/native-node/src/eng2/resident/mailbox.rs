//! Bounded retained checkpoint messages; authentication and decoding precede enqueue.

use super::*;
use crate::eng2::checkpoint_wire::{Incoming, MAX_MESSAGES_PER_TICK};
use std::collections::VecDeque;

const MAX_QUEUED: usize = 24;
const MAX_RECENT: usize = 128;
const RECENT_LIFETIME: Duration = Duration::from_secs(60);
struct Recent {
    digest: Hash,
    consumed: Instant,
}
#[derive(Default)]
struct Inbox {
    queue: VecDeque<Queued>,
    recent: VecDeque<Recent>,
    _recent_charge: Option<p2p::Reservation>,
}
impl Inbox {
    fn expire(&mut self, now: Instant) {
        self.recent
            .retain(|entry| now.saturating_duration_since(entry.consumed) < RECENT_LIFETIME);
    }
}

struct Queued {
    value: Incoming,
    digest: Hash,
    _wire: p2p::Reservation,
    _decoded: p2p::Reservation,
}
pub(super) struct Batch {
    pub messages: Vec<Incoming>,
    _charges: Vec<(p2p::Reservation, p2p::Reservation)>,
    digests: Vec<Hash>,
}
pub struct CheckpointMailbox {
    budget: p2p::Budget,
    incoming: Mutex<Inbox>,
    outgoing: Mutex<(Vec<Vec<u8>>, Option<p2p::Reservation>)>,
}
impl CheckpointMailbox {
    pub fn new(budget: p2p::Budget) -> Self {
        Self {
            budget,
            incoming: Mutex::new(Inbox::default()),
            outgoing: Mutex::new((Vec::new(), None)),
        }
    }
    pub fn enqueue(&self, value: Incoming, wire: p2p::Reservation) -> Result<(), String> {
        self.enqueue_at(value, wire, Instant::now())
    }
    fn enqueue_at(
        &self,
        value: Incoming,
        wire: p2p::Reservation,
        now: Instant,
    ) -> Result<(), String> {
        let bytes = value.encode(limits().chain.max_component_bytes)?;
        if !wire.covers(&self.budget, bytes.len()) {
            return Err("checkpoint message lacks its original shared byte reservation".into());
        }
        // Hash the complete canonical packet, including kind, network, statement
        // and roster epoch. Another statement or signer is never suppressed.
        let mut hasher =
            blake3::Hasher::new_derive_key("siworld eng2 checkpoint mailbox packet v1");
        hasher.update(&bytes);
        let digest = *hasher.finalize().as_bytes();
        let mut inbox = self
            .incoming
            .lock()
            .map_err(|_| "checkpoint inbox lock poisoned")?;
        inbox.expire(now);
        if inbox.queue.iter().any(|queued| queued.digest == digest)
            || inbox.recent.iter().any(|entry| entry.digest == digest)
        {
            // The duplicate's value, canonical scratch bytes and original
            // reservation are dropped together on this successful return.
            return Ok(());
        }
        if inbox.queue.len() >= MAX_QUEUED {
            return Err("checkpoint inbox full".into());
        }
        if inbox._recent_charge.is_none() {
            let charge = self
                .budget
                .reserve(MAX_RECENT * std::mem::size_of::<Recent>() + 4096)
                .map_err(|_| "checkpoint replay cache budget exhausted")?;
            inbox
                .recent
                .try_reserve_exact(MAX_RECENT)
                .map_err(|_| "checkpoint replay cache allocation failed")?;
            inbox._recent_charge = Some(charge);
        }
        let decoded = self
            .budget
            .reserve(
                bytes
                    .len()
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(4096))
                    .ok_or("checkpoint retention size overflow")?,
            )
            .map_err(|_| "checkpoint retention budget exhausted")?;
        inbox.queue.push_back(Queued {
            value,
            digest,
            _wire: wire,
            _decoded: decoded,
        });
        Ok(())
    }
    pub(super) fn drain(&self) -> Result<Batch, String> {
        let mut inbox = self
            .incoming
            .lock()
            .map_err(|_| "checkpoint inbox lock poisoned")?;
        let queue = &mut inbox.queue;
        let mut messages = Vec::new();
        let mut charges = Vec::new();
        let mut digests = Vec::new();
        let mut proposal = false;
        let mut certificate = false;
        let pending = queue.len();
        for _ in 0..pending {
            let Some(value) = queue.pop_front() else {
                break;
            };
            let is_proposal = matches!(value.value, Incoming::Proposal(_));
            let is_certificate = matches!(value.value, Incoming::Certified { .. });
            if messages.len() >= MAX_MESSAGES_PER_TICK
                || (is_proposal && proposal)
                || (is_certificate && certificate)
            {
                queue.push_back(value);
                continue;
            }
            proposal |= is_proposal;
            certificate |= is_certificate;
            digests.push(value.digest);
            messages.push(value.value);
            charges.push((value._wire, value._decoded));
        }
        Ok(Batch {
            messages,
            _charges: charges,
            digests,
        })
    }
    /// Remember only a fully successful Host tick. A rejected batch must not
    /// suppress later retries of messages that Host did not reach.
    pub(super) fn acknowledge(&self, batch: &Batch) -> Result<(), String> {
        self.acknowledge_at(batch, Instant::now())
    }
    fn acknowledge_at(&self, batch: &Batch, now: Instant) -> Result<(), String> {
        let mut inbox = self
            .incoming
            .lock()
            .map_err(|_| "checkpoint inbox lock poisoned")?;
        inbox.expire(now);
        for digest in &batch.digests {
            if !inbox.recent.iter().any(|entry| entry.digest == *digest) {
                if inbox.recent.len() == MAX_RECENT {
                    inbox.recent.pop_front();
                }
                inbox.recent.push_back(Recent {
                    digest: *digest,
                    consumed: now,
                });
            }
        }
        // A peer may replay while Host consumes the drained batch. Drop those
        // newly queued duplicates and their charges once success is known.
        inbox
            .queue
            .retain(|queued| !batch.digests.contains(&queued.digest));
        Ok(())
    }
    pub(super) fn publish(&self, messages: &[Incoming]) -> Result<(), String> {
        if messages.len() > MAX_MESSAGES_PER_TICK {
            return Err("checkpoint outgoing message bound".into());
        }
        let maximum = super::super::checkpoint_wire::MAX_CHECKPOINT_PACKET_BYTES;
        let charge = self
            .budget
            .reserve(
                messages
                    .len()
                    .checked_mul(maximum + 4096)
                    .ok_or("checkpoint outgoing size overflow")?,
            )
            .map_err(|_| "checkpoint outgoing budget exhausted")?;
        let bytes = messages
            .iter()
            .map(|m| m.encode(limits().chain.max_component_bytes))
            .collect::<Result<Vec<_>, _>>()?;
        *self
            .outgoing
            .lock()
            .map_err(|_| "checkpoint outbox lock poisoned")? = (bytes, Some(charge));
        Ok(())
    }
    /// The caller reserves a bounded per-peer control phase before cloning.
    pub fn outgoing(&self) -> Result<Vec<Vec<u8>>, String> {
        Ok(self
            .outgoing
            .lock()
            .map_err(|_| "checkpoint outbox lock poisoned")?
            .0
            .clone())
    }
}

#[cfg(test)]
mod tests;
