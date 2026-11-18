//! Additional fixed-peer relay limits. This policy neither authenticates peers
//! nor validates headers, grants body ownership, or replaces transport budgets.
//!
//! The caller supplies only independently pinned peers, verified header offers,
//! the original candidate expiry, and its existing authenticated session id.
//! Offer, credit and body framing must also use the original transport ledger.

type Hash = [u8; 32];
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_POLICY: AtomicU64 = AtomicU64::new(1);
const MAX_PEERS: usize = 8;
const MAX_RECORDS: usize = 32;
const MAX_SOURCES: usize = 4;
const MAX_LIFETIME_MS: u64 = 180_000;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub maximum_body_bytes: u64,
    pub maximum_credit_wire_bytes: u64,
    pub window_ms: u64,
    pub offers_per_window: usize,
    pub peer_offers_per_window: usize,
    pub wire_per_window: u64,
    pub peer_wire_per_window: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Configuration,
    Unconfigured,
    Clock,
    Capacity,
    Duplicate,
    Expired,
    Binding,
    Wire,
}

#[derive(Clone, Copy)]
struct Record {
    nonce: u64,
    peer: Hash,
    session: u64,
    block: Hash,
    height: u64,
    request: u64,
    opened_ms: u64,
    expires_ms: u64,
    retain_until_ms: u64,
    reserved_wire: u64,
    actual_wire: u64,
    credited: bool,
    closed: bool,
}

/// A single offer attempt, including failed or disconnected attempts. Neither
/// ticket nor permit is Clone; reconnecting cannot renew an existing attempt.
pub(crate) struct Ticket {
    policy: u64,
    slot: usize,
    nonce: u64,
    peer: Hash,
    session: u64,
    block: Hash,
    height: u64,
    request: u64,
}

pub(crate) struct OfferContext {
    pub peer: Hash,
    pub session: u64,
    pub block: Hash,
    pub height: u64,
    pub request: u64,
    pub body_bytes: u64,
    pub original_expires_ms: u64,
}

pub(crate) struct Permit(Ticket);

pub(crate) struct Policy {
    id: u64,
    peers: [Option<Hash>; MAX_PEERS],
    limits: Limits,
    records: [Option<Record>; MAX_RECORDS],
    sequence: u64,
    now_ms: u64,
    clock_failed: bool,
}

impl Policy {
    /// `selected` is an explicit subset of the existing independently pinned
    /// configuration. No address discovery or additional endpoint is performed.
    pub(crate) fn new(
        pinned: &[Hash],
        selected: &[Hash],
        limits: Limits,
        now_ms: u64,
    ) -> Result<Self, Error> {
        if selected.is_empty()
            || selected.len() > MAX_PEERS
            || limits.maximum_body_bytes == 0
            || limits.maximum_body_bytes > 1 << 30
            || limits.maximum_credit_wire_bytes < limits.maximum_body_bytes
            || limits.window_ms == 0
            || limits.window_ms > MAX_LIFETIME_MS
            || limits.offers_per_window == 0
            || limits.offers_per_window > MAX_RECORDS
            || limits.peer_offers_per_window == 0
            || limits.peer_offers_per_window > limits.offers_per_window
            || limits.peer_wire_per_window > limits.wire_per_window
            || limits.peer_wire_per_window < limits.maximum_credit_wire_bytes
        {
            return Err(Error::Configuration);
        }
        let mut peers = [None; MAX_PEERS];
        for (index, peer) in selected.iter().enumerate() {
            if *peer == [0; 32] || !pinned.contains(peer) || selected[..index].contains(peer) {
                return Err(Error::Configuration);
            }
            peers[index] = Some(*peer);
        }
        Ok(Self {
            id: NEXT_POLICY
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| Error::Capacity)?,
            peers,
            limits,
            records: [None; MAX_RECORDS],
            sequence: 0,
            now_ms,
            clock_failed: false,
        })
    }

    fn time(&mut self, now_ms: u64) -> Result<(), Error> {
        if self.clock_failed || now_ms < self.now_ms {
            self.clock_failed = true;
            return Err(Error::Clock);
        }
        self.now_ms = now_ms;
        for slot in &mut self.records {
            if slot.is_some_and(|record| now_ms >= record.retain_until_ms) {
                *slot = None;
            }
        }
        Ok(())
    }

    /// Called before sending an offer or responding to one. It consumes the
    /// rate allowance immediately, including unsuccessful handshakes. Header
    /// validity and higher-work/known-parent policy are checked by the Hub.
    pub(crate) fn open_offer(&mut self, offer: OfferContext, now_ms: u64) -> Result<Ticket, Error> {
        let OfferContext {
            peer,
            session,
            block,
            height,
            request,
            body_bytes,
            original_expires_ms,
        } = offer;
        self.time(now_ms)?;
        if !self.peers.contains(&Some(peer)) {
            return Err(Error::Unconfigured);
        }
        if session == 0 || block == [0; 32] || height == 0 || request == 0 {
            return Err(Error::Binding);
        }
        if body_bytes == 0 || body_bytes > self.limits.maximum_body_bytes {
            return Err(Error::Wire);
        }
        let remaining = original_expires_ms
            .checked_sub(now_ms)
            .ok_or(Error::Expired)?;
        if remaining == 0 || remaining > MAX_LIFETIME_MS {
            return Err(Error::Expired);
        }
        let mut global_count = 0;
        let mut peer_count = 0;
        let mut sources = 0;
        for record in self.records.iter().flatten() {
            if record.peer == peer
                && record.session == session
                && record.request == request
                && now_ms < record.expires_ms
            {
                return Err(Error::Duplicate);
            }
            if record.block == block && now_ms < record.expires_ms {
                if record.expires_ms != original_expires_ms {
                    return Err(Error::Binding);
                }
                sources += 1;
                if record.peer == peer {
                    return Err(Error::Duplicate);
                }
            }
            if now_ms.saturating_sub(record.opened_ms) < self.limits.window_ms {
                global_count += 1;
                peer_count += usize::from(record.peer == peer);
            }
        }
        if global_count >= self.limits.offers_per_window
            || peer_count >= self.limits.peer_offers_per_window
            || sources >= MAX_SOURCES
        {
            return Err(Error::Capacity);
        }
        let slot = self
            .records
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let sequence = self.sequence.checked_add(1).ok_or(Error::Capacity)?;
        // Keep the entire reservation through one window after the last
        // possible byte. Delaying a grant or sending near expiry must not move
        // bytes outside their originally charged rate window.
        let retain_until_ms = original_expires_ms
            .checked_add(self.limits.window_ms)
            .ok_or(Error::Clock)?;
        self.records[slot] = Some(Record {
            nonce: sequence,
            peer,
            session,
            block,
            height,
            request,
            opened_ms: now_ms,
            expires_ms: original_expires_ms,
            retain_until_ms,
            reserved_wire: 0,
            actual_wire: 0,
            credited: false,
            closed: false,
        });
        self.sequence = sequence;
        Ok(Ticket {
            policy: self.id,
            slot,
            nonce: sequence,
            peer,
            session,
            block,
            height,
            request,
        })
    }

    fn record(&mut self, ticket: &Ticket, now_ms: u64) -> Result<&mut Record, Error> {
        self.time(now_ms)?;
        if ticket.policy != self.id {
            return Err(Error::Binding);
        }
        let record = self
            .records
            .get_mut(ticket.slot)
            .and_then(Option::as_mut)
            .ok_or(Error::Expired)?;
        if record.nonce != ticket.nonce
            || record.peer != ticket.peer
            || record.session != ticket.session
            || record.block != ticket.block
            || record.height != ticket.height
            || record.request != ticket.request
        {
            return Err(Error::Binding);
        }
        if record.closed || now_ms >= record.expires_ms {
            return Err(Error::Expired);
        }
        Ok(record)
    }

    /// The receiver must already own the unique candidate claim and descriptor
    /// ledger reservation. `maximum_wire` includes offer/credit/metadata framing
    /// and encrypted overhead, not merely decoded body bytes. Reserving the full
    /// amount before I/O prevents a failed transfer from freeing rate allowance.
    pub(crate) fn credit(
        &mut self,
        ticket: Ticket,
        authenticated_session: u64,
        maximum_wire: u64,
        now_ms: u64,
    ) -> Result<Permit, Error> {
        self.record(&ticket, now_ms)?;
        if ticket.session != authenticated_session
            || maximum_wire == 0
            || maximum_wire > self.limits.maximum_credit_wire_bytes
        {
            return Err(Error::Binding);
        }
        let mut global_wire = 0u64;
        let mut peer_wire = 0u64;
        for record in self.records.iter().flatten() {
            global_wire = global_wire
                .checked_add(record.reserved_wire)
                .ok_or(Error::Wire)?;
            if record.peer == ticket.peer {
                peer_wire = peer_wire
                    .checked_add(record.reserved_wire)
                    .ok_or(Error::Wire)?;
            }
        }
        if global_wire
            .checked_add(maximum_wire)
            .is_none_or(|n| n > self.limits.wire_per_window)
            || peer_wire
                .checked_add(maximum_wire)
                .is_none_or(|n| n > self.limits.peer_wire_per_window)
        {
            return Err(Error::Capacity);
        }
        let record = self.record(&ticket, now_ms)?;
        if record.credited {
            return Err(Error::Duplicate);
        }
        record.credited = true;
        record.reserved_wire = maximum_wire;
        Ok(Permit(ticket))
    }

    /// Check a bounded frame before its allocation or socket I/O. This does
    /// not consume or refund bytes and cannot renew the original expiry.
    pub(crate) fn check_wire(
        &mut self,
        permit: &Permit,
        bytes: u64,
        now_ms: u64,
    ) -> Result<(), Error> {
        let record = self.record(&permit.0, now_ms)?;
        if !record.credited
            || record
                .actual_wire
                .checked_add(bytes)
                .is_none_or(|n| n > record.reserved_wire)
        {
            record.closed = true;
            return Err(Error::Wire);
        }
        Ok(())
    }
    /// Apply actual wire counts before the corresponding frame allocation or
    /// socket write. A rejected overrun permanently closes this attempt.
    pub(crate) fn account_wire(
        &mut self,
        permit: &Permit,
        bytes: u64,
        now_ms: u64,
    ) -> Result<(), Error> {
        let record = self.record(&permit.0, now_ms)?;
        let next = record.actual_wire.checked_add(bytes);
        if !record.credited || next.is_none_or(|n| n > record.reserved_wire) {
            record.closed = true;
            return Err(Error::Wire);
        }
        record.actual_wire = next.expect("checked wire addition");
        Ok(())
    }

    pub(crate) fn close(&mut self, permit: Permit, now_ms: u64) -> Result<(), Error> {
        self.record(&permit.0, now_ms)?.closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PEER: Hash = [1; 32];
    const SESSION: u64 = 2;
    const BLOCK: Hash = [3; 32];
    fn limits() -> Limits {
        Limits {
            maximum_body_bytes: 1000,
            maximum_credit_wire_bytes: 1200,
            window_ms: 1000,
            offers_per_window: 8,
            peer_offers_per_window: 4,
            wire_per_window: 4800,
            peer_wire_per_window: 2400,
        }
    }
    fn policy() -> Policy {
        Policy::new(&[PEER, [4; 32]], &[PEER, [4; 32]], limits(), 0).unwrap()
    }
    fn offer(policy: &mut Policy, block: Hash, now: u64, expiry: u64) -> Ticket {
        policy
            .open_offer(
                OfferContext {
                    peer: PEER,
                    session: SESSION,
                    block,
                    height: 1,
                    request: u64::from(block[0]) + 1,
                    body_bytes: 1000,
                    original_expires_ms: expiry,
                },
                now,
            )
            .unwrap()
    }
    #[test]
    fn configuration_requires_an_explicit_unique_pinned_subset() {
        assert!(matches!(
            Policy::new(&[PEER], &[[4; 32]], limits(), 0),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            Policy::new(&[PEER], &[PEER, PEER], limits(), 0),
            Err(Error::Configuration)
        ));
        assert!(matches!(
            Policy::new(&[PEER], &[], limits(), 0),
            Err(Error::Configuration)
        ));
        let mut p = policy();
        assert!(matches!(
            p.open_offer(
                OfferContext {
                    peer: [9; 32],
                    session: SESSION,
                    block: BLOCK,
                    height: 1,
                    request: 1,
                    body_bytes: 1000,
                    original_expires_ms: 100
                },
                0
            ),
            Err(Error::Unconfigured)
        ));
    }
    #[test]
    fn credit_is_session_bound_and_partial_transfer_cannot_overrun() {
        let mut p = policy();
        let t = offer(&mut p, BLOCK, 0, 1000);
        let permit = p.credit(t, SESSION, 1200, 1).unwrap();
        p.account_wire(&permit, 100, 2).unwrap();
        p.account_wire(&permit, 1100, 3).unwrap();
        assert_eq!(p.account_wire(&permit, 1, 4), Err(Error::Wire));
        assert_eq!(p.account_wire(&permit, 0, 5), Err(Error::Expired));
        let t = offer(&mut p, [5; 32], 6, 1000);
        assert!(matches!(p.credit(t, 6, 100, 7), Err(Error::Binding)));
    }
    #[test]
    fn reconnect_and_failures_do_not_reset_candidate_or_rate_limits() {
        let mut p = policy();
        let t = offer(&mut p, BLOCK, 0, 100);
        let permit = p.credit(t, SESSION, 1200, 1).unwrap();
        p.close(permit, 2).unwrap();
        assert!(matches!(
            p.open_offer(
                OfferContext {
                    peer: PEER,
                    session: 8,
                    block: BLOCK,
                    height: 1,
                    request: 2,
                    body_bytes: 1000,
                    original_expires_ms: 100
                },
                3
            ),
            Err(Error::Duplicate)
        ));
        let t = offer(&mut p, [5; 32], 4, 100);
        let permit = p.credit(t, SESSION, 1200, 5).unwrap();
        p.close(permit, 6).unwrap();
        let t = offer(&mut p, [6; 32], 101, 200);
        assert!(matches!(p.credit(t, SESSION, 1, 102), Err(Error::Capacity)));
        // Expired candidate reservations remain charged in the sliding window.
        let t = offer(&mut p, BLOCK, 1101, 1200);
        assert!(p.credit(t, SESSION, 1200, 1102).is_ok());
    }
    #[test]
    fn original_expiry_is_not_renewed_by_credit_or_continuous_bytes() {
        let mut p = policy();
        let t = offer(&mut p, BLOCK, 0, 100);
        let permit = p.credit(t, SESSION, 1200, 90).unwrap();
        p.account_wire(&permit, 1, 99).unwrap();
        assert_eq!(p.account_wire(&permit, 1, 100), Err(Error::Expired));
    }
    #[test]
    fn clock_regression_stays_closed_even_after_time_recovers() {
        let mut p = policy();
        let t = offer(&mut p, BLOCK, 10, 100);
        assert!(matches!(p.credit(t, SESSION, 100, 9), Err(Error::Clock)));
        assert!(matches!(
            p.open_offer(
                OfferContext {
                    peer: PEER,
                    session: SESSION,
                    block: BLOCK,
                    height: 1,
                    request: 1,
                    body_bytes: 1000,
                    original_expires_ms: 100
                },
                11
            ),
            Err(Error::Clock)
        ));
    }
    #[test]
    fn global_bytes_are_shared_across_configured_sources() {
        let mut l = limits();
        l.wire_per_window = 2400;
        let mut p = Policy::new(&[PEER, [4; 32]], &[PEER, [4; 32]], l, 0).unwrap();
        let t = offer(&mut p, BLOCK, 0, 1000);
        p.credit(t, SESSION, 1200, 1).unwrap();
        let t = p
            .open_offer(
                OfferContext {
                    peer: [4; 32],
                    session: SESSION,
                    block: BLOCK,
                    height: 1,
                    request: 1,
                    body_bytes: 1000,
                    original_expires_ms: 1000,
                },
                2,
            )
            .unwrap();
        p.credit(t, SESSION, 1200, 3).unwrap();
        let t = p
            .open_offer(
                OfferContext {
                    peer: [4; 32],
                    session: SESSION,
                    block: [9; 32],
                    height: 1,
                    request: 2,
                    body_bytes: 1000,
                    original_expires_ms: 1000,
                },
                4,
            )
            .unwrap();
        assert!(matches!(p.credit(t, SESSION, 1, 5), Err(Error::Capacity)));
    }
    #[test]
    fn failed_offer_handshakes_still_consume_frequency_and_capacity() {
        let mut p = policy();
        for n in 10..14 {
            let _ = offer(&mut p, [n; 32], 0, 1);
        }
        assert!(matches!(
            p.open_offer(
                OfferContext {
                    peer: PEER,
                    session: SESSION,
                    block: BLOCK,
                    height: 1,
                    request: 1,
                    body_bytes: 1000,
                    original_expires_ms: 100
                },
                2
            ),
            Err(Error::Capacity)
        ));
        assert!(
            p.open_offer(
                OfferContext {
                    peer: PEER,
                    session: SESSION,
                    block: BLOCK,
                    height: 1,
                    request: 1,
                    body_bytes: 1000,
                    original_expires_ms: 1100
                },
                1000
            )
            .is_ok()
        );
    }
    #[test]
    fn ticket_from_another_policy_cannot_authorize_credit() {
        let mut a = policy();
        let mut b = policy();
        let ta = offer(&mut a, BLOCK, 0, 1000);
        let _tb = offer(&mut b, BLOCK, 0, 1000);
        assert!(matches!(
            b.credit(ta, SESSION, 1200, 1),
            Err(Error::Binding)
        ));
    }
    #[test]
    fn offer_request_and_absolute_candidate_expiry_cannot_be_rebound() {
        let mut p = policy();
        let _ = offer(&mut p, BLOCK, 0, 1000);
        assert!(matches!(
            p.open_offer(
                OfferContext {
                    peer: PEER,
                    session: SESSION,
                    block: [5; 32],
                    height: 1,
                    request: 4,
                    body_bytes: 1000,
                    original_expires_ms: 1000
                },
                1
            ),
            Err(Error::Duplicate)
        ));
        assert!(matches!(
            p.open_offer(
                OfferContext {
                    peer: [4; 32],
                    session: SESSION,
                    block: BLOCK,
                    height: 1,
                    request: 8,
                    body_bytes: 1000,
                    original_expires_ms: 1100
                },
                2
            ),
            Err(Error::Binding)
        ));
    }
    #[test]
    fn fifth_source_and_unframed_or_oversized_offers_are_rejected() {
        let peers: Vec<Hash> = (1..=5).map(|n| [n; 32]).collect();
        let mut p = Policy::new(&peers, &peers, limits(), 0).unwrap();
        for peer in &peers[..4] {
            p.open_offer(
                OfferContext {
                    peer: *peer,
                    session: SESSION,
                    block: BLOCK,
                    height: 1,
                    request: 1,
                    body_bytes: 1000,
                    original_expires_ms: 1000,
                },
                0,
            )
            .unwrap();
        }
        assert!(matches!(
            p.open_offer(
                OfferContext {
                    peer: peers[4],
                    session: SESSION,
                    block: BLOCK,
                    height: 1,
                    request: 1,
                    body_bytes: 1000,
                    original_expires_ms: 1000
                },
                1
            ),
            Err(Error::Capacity)
        ));
        assert!(matches!(
            p.open_offer(
                OfferContext {
                    peer: peers[4],
                    session: SESSION,
                    block: [8; 32],
                    height: 1,
                    request: 0,
                    body_bytes: 1000,
                    original_expires_ms: 1000
                },
                2
            ),
            Err(Error::Binding)
        ));
        assert!(matches!(
            p.open_offer(
                OfferContext {
                    peer: peers[4],
                    session: SESSION,
                    block: [8; 32],
                    height: 1,
                    request: 1,
                    body_bytes: 1001,
                    original_expires_ms: 1000
                },
                3
            ),
            Err(Error::Wire)
        ));
    }
    #[test]
    fn delayed_credit_and_last_byte_keep_full_reserved_rate_allowance() {
        let mut p = policy();
        let a = offer(&mut p, BLOCK, 0, 5000);
        let b = offer(&mut p, [5; 32], 1, 5000);
        let first = p.credit(a, SESSION, 1200, 2000).unwrap();
        let second = p.credit(b, SESSION, 1200, 2001).unwrap();
        p.account_wire(&first, 1200, 4998).unwrap();
        p.account_wire(&second, 1200, 4999).unwrap();
        let c = offer(&mut p, [6; 32], 5001, 7000);
        assert!(matches!(
            p.credit(c, SESSION, 1, 5002),
            Err(Error::Capacity)
        ));
        let d = offer(&mut p, [7; 32], 6001, 7000);
        assert!(p.credit(d, SESSION, 1200, 6002).is_ok());
    }
}
