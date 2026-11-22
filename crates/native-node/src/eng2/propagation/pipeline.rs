//! Finite multi-source piece scheduling with one nonrenewable lifetime.

use super::authentication::{self, Authenticated, VerifiedPiece};
use crate::{
    eng2::{
        body::{Body, Policy as BodyPolicy},
        header::Header,
        transport::ReceivedBody,
    },
    p2p,
    wire::Hash,
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

// These include application identity/index framing and an allowance for the
// existing encrypted record overhead. A transport must reject a frame before
// exceeding its request's reserved wire bytes, rather than allocate then count.
pub const REQUEST_WIRE_BYTES: u64 = 128;
pub const RESPONSE_OVERHEAD: u64 = 128;
const MAX_PEERS: usize = 8;
const MAX_ATTEMPTS: usize = 4;

#[derive(Clone, Copy)]
pub struct Limits {
    pub requests: u64,
    pub wire_bytes: u64,
    pub peer_requests: u64,
    pub peer_wire_bytes: u64,
    pub parallel: usize,
    pub lifetime: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Resources,
    Expired,
    Cancelled,
    Peer,
    Request,
    Authentication(authentication::Error),
    Incomplete,
    Framing,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceBytes {
    pub peer: Hash,
    /// Logical source attempts, limited to one for this candidate and peer.
    pub requested: u64,
    /// Actual application queries, including the descriptor continuation.
    pub queries: u64,
    pub received: u64,
    pub sent: u64,
    pub reserved_wire: u64,
    pub bad_pieces: u64,
    pub failures: u64,
}

struct Source {
    bytes: SourceBytes,
    connected: bool,
    descriptor_attempt: Option<u64>,
    metadata_confirmed: bool,
    continuation_wire: u64,
    body_batch_used: bool,
    batch_transmitted: bool,
}

/// Candidate-owned accounting starts before the first descriptor request and
/// moves into the body transfer without resetting attempts, bytes or time.
pub struct DescriptorLedger {
    block: Hash,
    sources: BTreeMap<Hash, Source>,
    limits: Limits,
    started: Instant,
    requests: u64,
    reserved_wire: u64,
    pending: Option<DescriptorAttempt>,
    successful: bool,
    failed: bool,
    cancellation: p2p::Cancellation,
    binding: Option<p2p::Binding>,
    original_deadline: Option<p2p::Deadline>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorAttempt {
    sequence: u64,
    peer: Hash,
    maximum_wire: u64,
}
impl DescriptorAttempt {
    pub(crate) fn sequence(self) -> u64 {
        self.sequence
    }
}

impl DescriptorLedger {
    pub fn new(
        block: Hash,
        configured: &[Hash],
        limits: Limits,
        started: Instant,
    ) -> Result<Self, Error> {
        if configured.is_empty()
            || configured.len() > MAX_PEERS
            || !(1..=MAX_PEERS).contains(&limits.parallel)
            || limits.lifetime.is_zero()
            || limits.lifetime > Duration::from_secs(180)
            || !(1..=4).contains(&limits.requests)
            || limits.peer_requests != 1
        {
            return Err(Error::Bounds);
        }
        let mut sources = BTreeMap::new();
        for &peer in configured {
            if sources
                .insert(
                    peer,
                    Source {
                        bytes: SourceBytes {
                            peer,
                            ..Default::default()
                        },
                        connected: true,
                        descriptor_attempt: None,
                        metadata_confirmed: false,
                        continuation_wire: 0,
                        body_batch_used: false,
                        batch_transmitted: false,
                    },
                )
                .is_some()
            {
                return Err(Error::Peer);
            }
        }
        let ledger = Self {
            block,
            sources,
            limits,
            started,
            requests: 0,
            reserved_wire: 0,
            pending: None,
            successful: false,
            failed: false,
            cancellation: p2p::Cancellation::default(),
            binding: None,
            original_deadline: None,
        };
        ledger.check(Instant::now())?;
        Ok(ledger)
    }
    fn check(&self, now: Instant) -> Result<(), Error> {
        if self
            .original_deadline
            .as_ref()
            .is_some_and(|deadline| deadline.check_at(now).is_err())
        {
            return Err(Error::Expired);
        }
        if self.cancellation.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if self.failed {
            return Err(Error::Bounds);
        }
        if now.saturating_duration_since(self.started) >= self.limits.lifetime {
            return Err(Error::Expired);
        }
        Ok(())
    }
    pub fn cancellation(&self) -> p2p::Cancellation {
        self.cancellation.clone()
    }
    pub fn block(&self) -> Hash {
        self.block
    }
    pub(crate) fn io_deadline(&self) -> p2p::Deadline {
        self.original_deadline.clone().unwrap_or_else(|| {
            p2p::Deadline::from_started(
                self.started,
                self.limits.lifetime,
                self.cancellation.clone(),
            )
        })
    }
    pub(crate) fn bind_claim(
        &mut self,
        binding: p2p::Binding,
        ownership: &p2p::BodyClaim,
    ) -> Result<(), Error> {
        if self.binding.is_some_and(|previous| previous != binding) {
            return Err(Error::Framing);
        }
        self.original_deadline = Some(self.io_deadline().for_body_claim(ownership));
        self.binding = Some(binding);
        self.check(Instant::now())
    }
    pub(crate) fn sent(
        &mut self,
        attempt: DescriptorAttempt,
        wire_bytes: u64,
    ) -> Result<(), Error> {
        if self.pending != Some(attempt) {
            return Err(Error::Request);
        }
        let source = self.sources.get_mut(&attempt.peer).ok_or(Error::Peer)?;
        source.bytes.sent = source
            .bytes
            .sent
            .checked_add(wire_bytes)
            .ok_or(Error::Bounds)?;
        if source.bytes.sent > REQUEST_WIRE_BYTES
            || source
                .bytes
                .sent
                .checked_add(source.bytes.received)
                .is_none_or(|bytes| bytes > source.bytes.reserved_wire)
        {
            self.failed = true;
            return Err(Error::Bounds);
        }
        Ok(())
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn observed_sources(&self) -> impl Iterator<Item = SourceBytes> + '_ {
        self.sources
            .values()
            .map(|source| source.bytes)
            .filter(|source| source.queries > 0)
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn started(&self) -> Instant {
        self.started
    }

    /// Reserve the complete maximum response and request, including descriptor,
    /// authentication pieces and transport framing, before sending or decoding.
    pub fn begin(
        &mut self,
        peer: Hash,
        maximum_wire: u64,
        now: Instant,
    ) -> Result<DescriptorAttempt, Error> {
        self.check(now)?;
        if self.pending.is_some() || self.successful || maximum_wire == 0 {
            return Err(Error::Request);
        }
        let source = self.sources.get_mut(&peer).ok_or(Error::Peer)?;
        let wire = self
            .reserved_wire
            .checked_add(maximum_wire)
            .ok_or(Error::Bounds)?;
        let peer_wire = source
            .bytes
            .reserved_wire
            .checked_add(maximum_wire)
            .ok_or(Error::Bounds)?;
        if !source.connected
            || self.requests >= self.limits.requests
            || source.bytes.requested >= self.limits.peer_requests
            || wire > self.limits.wire_bytes
            || peer_wire > self.limits.peer_wire_bytes
        {
            return Err(Error::Bounds);
        }
        self.requests += 1;
        self.reserved_wire = wire;
        source.bytes.requested += 1;
        source.bytes.queries += 1;
        source.bytes.reserved_wire = peer_wire;
        source.descriptor_attempt = Some(self.requests);
        let attempt = DescriptorAttempt {
            sequence: self.requests,
            peer,
            maximum_wire,
        };
        self.pending = Some(attempt);
        Ok(attempt)
    }
    /// A failed or partial descriptor response still consumes its original
    /// request and full byte reservation. Authentication success is checked
    /// independently again through the typed descriptor supplied to Transfer.
    pub fn completed(
        &mut self,
        attempt: DescriptorAttempt,
        received_wire: u64,
        authenticated: bool,
        now: Instant,
    ) -> Result<(), Error> {
        if self.pending != Some(attempt) {
            return Err(Error::Request);
        }
        self.pending = None;
        let source = self.sources.get_mut(&attempt.peer).ok_or(Error::Peer)?;
        source.bytes.received = source
            .bytes
            .received
            .checked_add(received_wire)
            .ok_or(Error::Bounds)?;
        if now.saturating_duration_since(self.started) >= self.limits.lifetime
            || self.cancellation.is_cancelled()
        {
            source.connected = false;
            source.bytes.failures += 1;
            return if self.cancellation.is_cancelled() {
                Err(Error::Cancelled)
            } else {
                Err(Error::Expired)
            };
        }
        if received_wire
            .checked_add(REQUEST_WIRE_BYTES)
            .is_none_or(|wire| wire > attempt.maximum_wire)
        {
            source.bytes.failures += 1;
            self.failed = true;
            return Err(Error::Bounds);
        }
        if !authenticated {
            source.bytes.failures += 1;
            source.connected = false;
        } else {
            source.continuation_wire = attempt.maximum_wire - received_wire - REQUEST_WIRE_BYTES;
        }
        source.metadata_confirmed = authenticated;
        self.successful = authenticated;
        Ok(())
    }
}

/// One exact request, assigned once to a configured authenticated source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub sequence: u64,
    pub block: Hash,
    pub piece: usize,
    pub peer: Hash,
    pub maximum_response_wire: u64,
}

struct Piece {
    complete: bool,
    attempts: Vec<Hash>,
    pending: Option<u64>,
}

/// The same instance must remain retained for the candidate's entire lifetime.
/// Reconnection does not create another deadline or reset cumulative usage.
pub struct Transfer {
    authenticated: Authenticated,
    encoded: Vec<u8>,
    pieces: Vec<Piece>,
    sources: BTreeMap<Hash, Source>,
    pending: BTreeMap<(u64, usize), Request>,
    confirmation_pending: Option<DescriptorAttempt>,
    limits: Limits,
    started: Instant,
    next: u64,
    queries: u64,
    reserved_wire: u64,
    cancelled: bool,
    streaming: Option<Hash>,
    cancellation: p2p::Cancellation,
    binding: Option<p2p::Binding>,
    original_deadline: Option<p2p::Deadline>,
    budget: p2p::Budget,
    verified_bytes: usize,
    #[cfg(feature = "eng2-runtime")]
    descriptor_peer: Hash,
    #[cfg(feature = "eng2-runtime")]
    metadata_complete: Instant,
    #[cfg(feature = "eng2-runtime")]
    body_complete: Option<Instant>,
    #[cfg(feature = "eng2-runtime")]
    forwarding_candidate: Option<p2p::ForwardingCandidate>,
    _encoded_reservation: p2p::Reservation,
    decode_reservation: Option<p2p::Reservation>,
}

impl Transfer {
    /// Move the same candidate-owned descriptor ledger into the body transfer.
    /// Neither a failed descriptor nor a successful one resets cumulative usage.
    pub fn new(
        authenticated: Authenticated,
        first: VerifiedPiece,
        ledger: DescriptorLedger,
        budget: &p2p::Budget,
    ) -> Result<Self, Error> {
        ledger.check(Instant::now())?;
        if !ledger.successful
            || ledger.pending.is_some()
            || ledger.block != authenticated.block()
            || first.block() != authenticated.block()
            || first.index() != 0
        {
            return Err(Error::Bounds);
        }
        #[cfg(feature = "eng2-runtime")]
        let descriptor_peer = ledger
            .sources
            .values()
            .find(|source| source.connected && source.metadata_confirmed)
            .map(|source| source.bytes.peer)
            .ok_or(Error::Peer)?;
        let DescriptorLedger {
            sources,
            limits,
            started,
            requests,
            reserved_wire,
            cancellation,
            binding,
            original_deadline,
            ..
        } = ledger;
        let count = authenticated.piece_count();
        // Match the existing body ownership factor and retain all metadata and
        // bounded concurrent piece buffers in the same global logical budget.
        let charge = authenticated
            .body_bytes()
            .checked_mul(3)
            .and_then(|v| v.checked_add(count.checked_mul(512)?))
            .and_then(|v| v.checked_add(4096))
            .and_then(|v| {
                v.checked_add(
                    limits
                        .parallel
                        .checked_mul(authentication::PIECE_BYTES + 256)?,
                )
            })
            .ok_or(Error::Resources)?;
        let decode_charge = authenticated
            .body_bytes()
            .checked_mul(2)
            .ok_or(Error::Resources)?;
        let encoded_reservation = budget
            .reserve(charge - decode_charge)
            .map_err(|_| Error::Resources)?;
        let decode_reservation = budget
            .reserve(decode_charge)
            .map_err(|_| Error::Resources)?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(authenticated.body_bytes())
            .map_err(|_| Error::Resources)?;
        encoded.resize(authenticated.body_bytes(), 0);
        let mut pieces = Vec::with_capacity(count);
        for _ in 0..count {
            pieces.push(Piece {
                complete: false,
                attempts: Vec::with_capacity(MAX_ATTEMPTS),
                pending: None,
            });
        }
        let mut transfer = Self {
            authenticated,
            encoded,
            pieces,
            sources,
            pending: BTreeMap::new(),
            confirmation_pending: None,
            limits,
            started,
            next: requests,
            queries: requests,
            reserved_wire,
            cancelled: false,
            streaming: None,
            cancellation,
            binding,
            original_deadline,
            budget: budget.clone(),
            verified_bytes: 0,
            #[cfg(feature = "eng2-runtime")]
            descriptor_peer,
            #[cfg(feature = "eng2-runtime")]
            metadata_complete: Instant::now(),
            #[cfg(feature = "eng2-runtime")]
            body_complete: None,
            #[cfg(feature = "eng2-runtime")]
            forwarding_candidate: None,
            _encoded_reservation: encoded_reservation,
            decode_reservation: Some(decode_reservation),
        };
        transfer.check(Instant::now())?;
        transfer.install(first)?;
        Ok(transfer)
    }

    fn check(&self, now: Instant) -> Result<(), Error> {
        if self
            .original_deadline
            .as_ref()
            .is_some_and(|deadline| deadline.check_at(now).is_err())
        {
            return Err(Error::Expired);
        }
        if self.cancelled || self.cancellation.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if now.saturating_duration_since(self.started) >= self.limits.lifetime {
            return Err(Error::Expired);
        }
        Ok(())
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.cancellation.cancel();
        self.pending.clear();
    }
    pub(crate) fn io_deadline(&self) -> p2p::Deadline {
        self.original_deadline.clone().unwrap_or_else(|| {
            p2p::Deadline::from_started(
                self.started,
                self.limits.lifetime,
                self.cancellation.clone(),
            )
        })
    }
    /// Only an actual alternate body-lane turn can start confirmation. No
    /// first-source wait, new ownership lease or renewed budget is created.
    #[cfg(all(test, feature = "eng2-runtime"))]
    pub(crate) fn confirmation_available(&self, peer: Hash, ownership: &p2p::BodyClaim) -> bool {
        let confirmed = self
            .sources
            .values()
            .filter(|s| s.metadata_confirmed)
            .count();
        self.check(Instant::now()).is_ok()
            && self.verified_bytes < self.body_bytes()
            && self.confirmation_pending.is_none()
            && !self.sources.values().any(|s| s.body_batch_used)
            && confirmed == 1
            && self.limits.requests.saturating_sub(self.queries) >= 3
            && self
                .sources
                .get(&peer)
                .is_some_and(|s| s.connected && s.bytes.requested == 0)
            && ownership.can_query(peer, 3)
    }

    #[cfg(all(test, feature = "eng2-runtime"))]
    pub(crate) fn begin_confirmation(
        &mut self,
        peer: Hash,
        maximum_wire: u64,
        ownership: &p2p::BodyClaim,
    ) -> Result<Option<(DescriptorAttempt, p2p::Deadline)>, Error> {
        if !self.confirmation_available(peer, ownership) {
            return Ok(None);
        }
        let body_deadline = self.io_deadline().for_body_claim(ownership);
        let now = Instant::now();
        let remaining = body_deadline.expires_at().saturating_duration_since(now);
        // Optional metadata must leave time for the original body transfer.
        let confirmation_budget = (remaining / 2).min(Duration::from_secs(5));
        if confirmation_budget.is_zero() {
            return Ok(None);
        }
        let binding = self.binding.ok_or(Error::Framing)?;
        if !ownership.matches(
            &self.budget,
            binding,
            self.authenticated.height(),
            self.block(),
        ) {
            return Err(Error::Framing);
        }
        let source = self.sources.get_mut(&peer).ok_or(Error::Peer)?;
        let wire = self
            .reserved_wire
            .checked_add(maximum_wire)
            .ok_or(Error::Bounds)?;
        let peer_wire = source
            .bytes
            .reserved_wire
            .checked_add(maximum_wire)
            .ok_or(Error::Bounds)?;
        let sequence = self.next.checked_add(1).ok_or(Error::Bounds)?;
        if maximum_wire == 0
            || sequence > self.limits.requests
            || wire > self.limits.wire_bytes
            || peer_wire > self.limits.peer_wire_bytes
        {
            return Err(Error::Bounds);
        }
        source.bytes.requested += 1;
        source.bytes.queries += 1;
        source.bytes.reserved_wire = peer_wire;
        source.descriptor_attempt = Some(sequence);
        self.next = sequence;
        self.queries += 1;
        self.reserved_wire = wire;
        let attempt = DescriptorAttempt {
            sequence,
            peer,
            maximum_wire,
        };
        self.confirmation_pending = Some(attempt);
        Ok(Some((
            attempt,
            body_deadline.capped_at(now + confirmation_budget),
        )))
    }

    #[cfg(all(test, feature = "eng2-runtime"))]
    pub(crate) fn complete_confirmation(
        &mut self,
        attempt: DescriptorAttempt,
        sent: u64,
        received: u64,
        authenticated: Option<&Authenticated>,
    ) -> Result<(), Error> {
        if self.confirmation_pending != Some(attempt) {
            return Err(Error::Request);
        }
        self.confirmation_pending = None;
        let matched = authenticated.is_some_and(|v| self.authenticated.same_descriptor(v));
        let source = self.sources.get_mut(&attempt.peer).ok_or(Error::Peer)?;
        source.bytes.sent = source.bytes.sent.checked_add(sent).ok_or(Error::Bounds)?;
        source.bytes.received = source
            .bytes
            .received
            .checked_add(received)
            .ok_or(Error::Bounds)?;
        let charged = received
            .checked_add(REQUEST_WIRE_BYTES)
            .ok_or(Error::Bounds)?;
        if sent > REQUEST_WIRE_BYTES || charged > attempt.maximum_wire {
            source.connected = false;
            source.bytes.failures += 1;
            self.cancel();
            return Err(Error::Bounds);
        }
        if matched {
            source.metadata_confirmed = true;
            source.continuation_wire = attempt.maximum_wire - charged;
        } else {
            source.connected = false;
            source.bytes.failures += 1;
        }
        self.check(Instant::now())?;
        if authenticated.is_some() && !matched {
            return Err(Error::Framing);
        }
        Ok(())
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn confirmed_source(&self, peer: Hash) -> bool {
        self.sources
            .get(&peer)
            .is_some_and(|s| s.connected && s.metadata_confirmed)
    }

    pub(crate) fn prepare_io(
        &mut self,
        requests: &[Request],
        ownership: &p2p::BodyClaim,
    ) -> Result<(p2p::Deadline, usize, u64), Error> {
        self.check(Instant::now())?;
        if self.binding.is_none_or(|binding| {
            !ownership.matches(
                &self.budget,
                binding,
                self.authenticated.height(),
                self.block(),
            )
        }) {
            return Err(Error::Framing);
        }
        let first = requests.first().ok_or(Error::Request)?;
        for request in requests {
            if request.peer != first.peer
                || request.sequence != first.sequence
                || request.block != self.block()
                || self.pending.get(&(request.sequence, request.piece)) != Some(request)
            {
                return Err(Error::Request);
            }
        }
        let source = self.sources.get_mut(&first.peer).ok_or(Error::Peer)?;
        if source.batch_transmitted {
            return Err(Error::Request);
        }
        source.batch_transmitted = true;
        Ok((
            self.io_deadline().for_body_claim(ownership),
            self.authenticated.piece_count(),
            self.authenticated.height(),
        ))
    }

    /// Prefer an authenticated transaction range by asking for its containing
    /// pieces in order. Other sources may simultaneously acquire other pieces.
    /// The optional hint is local scheduling information, never authenticated
    /// framing and never an authorization to allocate or verify a transaction.
    pub fn next_batch(
        &mut self,
        peer: Hash,
        preferred_piece: Option<usize>,
        maximum_pieces: usize,
        now: Instant,
    ) -> Result<Vec<Request>, Error> {
        self.check(now)?;
        if self.streaming.is_some() {
            return Ok(vec![]);
        }
        if self
            .confirmation_pending
            .is_some_and(|attempt| attempt.peer == peer || self.limits.parallel == 1)
        {
            return Ok(vec![]);
        }
        let source = self.sources.get(&peer).ok_or(Error::Peer)?;
        if !source.connected {
            return Err(Error::Peer);
        }
        if maximum_pieces == 0 {
            return Err(Error::Bounds);
        }
        let active = self
            .pending
            .values()
            .map(|request| request.peer)
            .collect::<std::collections::BTreeSet<_>>();
        if active.len() >= self.limits.parallel || active.contains(&peer) {
            return Ok(vec![]);
        }
        let eligible = |piece: &Piece| {
            !piece.complete
                && piece.pending.is_none()
                && piece.attempts.len() < MAX_ATTEMPTS
                && !piece.attempts.contains(&peer)
        };
        let mut selected = Vec::with_capacity(maximum_pieces.min(self.pieces.len()));
        if let Some(piece) = preferred_piece.filter(|&i| self.pieces.get(i).is_some_and(eligible)) {
            selected.push(piece);
        }
        for (index, piece) in self.pieces.iter().enumerate() {
            if selected.len() >= maximum_pieces {
                break;
            }
            if Some(index) != preferred_piece && eligible(piece) {
                selected.push(index);
            }
        }
        if selected.is_empty() {
            return Ok(vec![]);
        }
        if source.body_batch_used {
            return Err(Error::Peer);
        }
        if self.queries >= self.limits.requests {
            return Err(Error::Bounds);
        }
        // A disjoint piece can require an eight-byte run. Charge that worst
        // case plus fixed framing before assigning the one bounded query.
        let mut charge = REQUEST_WIRE_BYTES
            .checked_add(
                (selected.len() as u64)
                    .checked_mul(8)
                    .ok_or(Error::Bounds)?,
            )
            .ok_or(Error::Bounds)?;
        for &piece in &selected {
            let response = self
                .authenticated
                .range(piece)
                .map_err(Error::Authentication)?
                .len() as u64
                + RESPONSE_OVERHEAD;
            charge = charge.checked_add(response).ok_or(Error::Bounds)?;
        }
        // The descriptor source continues its original two-phase attempt. Its
        // complete maximum was reserved before metadata was requested. Other
        // sources each start exactly one separately charged attempt.
        let (sequence, wire, peer_wire, new_attempt) =
            if let Some(sequence) = source.descriptor_attempt {
                if charge > source.continuation_wire {
                    return Err(Error::Bounds);
                }
                (
                    sequence,
                    self.reserved_wire,
                    source.bytes.reserved_wire,
                    false,
                )
            } else {
                let sequence = self.next.checked_add(1).ok_or(Error::Bounds)?;
                let wire = self
                    .reserved_wire
                    .checked_add(charge)
                    .ok_or(Error::Bounds)?;
                let peer_wire = source
                    .bytes
                    .reserved_wire
                    .checked_add(charge)
                    .ok_or(Error::Bounds)?;
                if sequence > self.limits.requests
                    || source.bytes.requested >= self.limits.peer_requests
                    || wire > self.limits.wire_bytes
                    || peer_wire > self.limits.peer_wire_bytes
                {
                    return Err(Error::Bounds);
                }
                (sequence, wire, peer_wire, true)
            };
        let source = self.sources.get_mut(&peer).ok_or(Error::Peer)?;
        source.body_batch_used = true;
        source.bytes.queries += 1;
        self.queries += 1;
        if new_attempt {
            source.bytes.requested += 1;
            self.next = sequence;
        } else {
            source.continuation_wire -= charge;
        }
        source.bytes.reserved_wire = peer_wire;
        self.reserved_wire = wire;
        let mut requests = Vec::with_capacity(selected.len());
        for piece in selected {
            let response = self
                .authenticated
                .range(piece)
                .map_err(Error::Authentication)?
                .len() as u64
                + RESPONSE_OVERHEAD;
            let request = Request {
                sequence,
                block: self.authenticated.block(),
                piece,
                peer,
                maximum_response_wire: response,
            };
            self.pieces[piece].pending = Some(sequence);
            self.pieces[piece].attempts.push(peer);
            self.pending.insert((sequence, piece), request);
            requests.push(request);
        }
        Ok(requests)
    }

    pub fn next(
        &mut self,
        peer: Hash,
        preferred_piece: Option<usize>,
        now: Instant,
    ) -> Result<Option<Request>, Error> {
        Ok(self.next_batch(peer, preferred_piece, 1, now)?.pop())
    }

    /// Call for success and partial failure alike. Bytes include all response
    /// framing. The exact assigned request is consumed before authentication.
    pub fn received(
        &mut self,
        request: Request,
        bytes: Vec<u8>,
        wire_bytes: u64,
        now: Instant,
    ) -> Result<(), Error> {
        // Account the authenticated source before matching its response. Stale,
        // duplicate and malformed replies consume bytes even when they cannot
        // consume a live piece assignment.
        let source = self.sources.get_mut(&request.peer).ok_or(Error::Peer)?;
        source.bytes.received = source
            .bytes
            .received
            .checked_add(wire_bytes)
            .ok_or(Error::Bounds)?;
        if source
            .bytes
            .received
            .checked_add(source.bytes.sent)
            .is_none_or(|bytes| bytes > source.bytes.reserved_wire)
        {
            source.connected = false;
            source.bytes.failures += 1;
            return Err(Error::Bounds);
        }
        self.check(now)?;
        let key = (request.sequence, request.piece);
        let pending = self.pending.get(&key).ok_or(Error::Request)?;
        if pending != &request {
            return Err(Error::Request);
        }
        self.pending.remove(&key);
        self.pieces[request.piece].pending = None;
        let source = self.sources.get_mut(&request.peer).ok_or(Error::Peer)?;
        if wire_bytes < bytes.len() as u64 || wire_bytes > request.maximum_response_wire {
            source.connected = false;
            source.bytes.failures += 1;
            return Err(Error::Bounds);
        }
        let piece = match self.authenticated.verify(request.piece, bytes) {
            Ok(piece) => piece,
            Err(error) => {
                source.bytes.bad_pieces += 1;
                source.connected = false;
                return Err(Error::Authentication(error));
            }
        };
        self.install(piece)
    }

    /// A disconnected or timed-out source keeps all cumulative charges. Other
    /// configured sources can acquire its unfinished pieces without extending
    /// the original transfer deadline.
    pub fn disconnected(
        &mut self,
        peer: Hash,
        partial_wire_bytes: u64,
        now: Instant,
    ) -> Result<(), Error> {
        self.check(now)?;
        let source = self.sources.get_mut(&peer).ok_or(Error::Peer)?;
        let allowance: u64 = self
            .pending
            .values()
            .filter(|r| r.peer == peer)
            .map(|r| r.maximum_response_wire)
            .sum();
        if partial_wire_bytes > allowance {
            return Err(Error::Bounds);
        }
        source.bytes.received = source
            .bytes
            .received
            .checked_add(partial_wire_bytes)
            .ok_or(Error::Bounds)?;
        source.bytes.failures += 1;
        source.connected = false;
        self.pending.retain(|_, request| {
            if request.peer == peer {
                self.pieces[request.piece].pending = None;
                false
            } else {
                true
            }
        });
        Ok(())
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn abandon_batch(&mut self, peer: Hash, sequence: u64, now: Instant) {
        if self
            .pending
            .values()
            .any(|request| request.peer == peer && request.sequence == sequence)
        {
            let _ = self.disconnected(peer, 0, now);
        }
    }

    fn install(&mut self, piece: VerifiedPiece) -> Result<(), Error> {
        if piece.block() != self.authenticated.block() || piece.index() >= self.pieces.len() {
            return Err(Error::Request);
        }
        let state = &mut self.pieces[piece.index()];
        if state.complete {
            return Err(Error::Request);
        }
        self.encoded[piece.range()].copy_from_slice(piece.bytes());
        self.verified_bytes += piece.bytes().len();
        state.complete = true;
        #[cfg(feature = "eng2-runtime")]
        if self.verified_bytes == self.encoded.len() {
            self.body_complete = Some(Instant::now());
        }
        Ok(())
    }

    /// Install a descriptor response's indexing piece. Its wire bytes and
    /// allocation must remain charged by the same descriptor ledger/packet
    /// reservation moved through construction. The typed value can only be
    /// obtained by authenticating these exact bytes against this exact block.
    pub fn index_piece(&mut self, piece: VerifiedPiece, now: Instant) -> Result<(), Error> {
        self.check(now)?;
        if !self.pending.is_empty()
            || self
                .pieces
                .get(piece.index())
                .is_none_or(|state| state.pending.is_some())
        {
            return Err(Error::Request);
        }
        self.install(piece)
    }

    /// Continue the credited descriptor exchange without a second body query.
    pub(crate) fn begin_stream(&mut self, peer: Hash) -> Result<(), Error> {
        self.check(Instant::now())?;
        let source = self.sources.get(&peer).ok_or(Error::Peer)?;
        if self.streaming.is_some()
            || !self.pending.is_empty()
            || !source.connected
            || !source.metadata_confirmed
            || source.body_batch_used
        {
            return Err(Error::Request);
        }
        self.streaming = Some(peer);
        Ok(())
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn streamed_piece(
        &mut self,
        peer: Hash,
        index: usize,
        bytes: Vec<u8>,
        wire: u64,
    ) -> Result<(), Error> {
        self.check(Instant::now())?;
        if self.streaming != Some(peer) {
            return Err(Error::Request);
        }
        let source = self.sources.get_mut(&peer).ok_or(Error::Peer)?;
        source.bytes.received = source
            .bytes
            .received
            .checked_add(wire)
            .ok_or(Error::Bounds)?;
        if wire < bytes.len() as u64
            || wire > source.continuation_wire
            || source
                .bytes
                .received
                .checked_add(source.bytes.sent)
                .is_none_or(|total| total > source.bytes.reserved_wire)
        {
            return Err(Error::Bounds);
        }
        source.continuation_wire -= wire;
        let piece = self.authenticated.verify(index, bytes).map_err(|error| {
            source.bytes.bad_pieces += 1;
            Error::Authentication(error)
        })?;
        self.install(piece)
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn end_stream(&mut self, peer: Hash, succeeded: bool, partial_wire: u64) {
        if self.streaming != Some(peer) {
            return;
        }
        self.streaming = None;
        if let Some(source) = self.sources.get_mut(&peer) {
            source.bytes.received = source.bytes.received.saturating_add(partial_wire);
            source.continuation_wire = source.continuation_wire.saturating_sub(partial_wire);
            if !succeeded {
                source.connected = false;
                source.bytes.failures += 1;
            }
        }
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn stream_active(&self) -> bool {
        self.streaming.is_some()
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn height(&self) -> u64 {
        self.authenticated.height()
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn bind_forwarding_candidate(&mut self, candidate: p2p::ForwardingCandidate) {
        self.forwarding_candidate = Some(candidate);
    }

    /// Successful local admission can retire the lease without shortening
    /// an existing forwarding exchange or extending its original cutoff.
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn forwarding_deadline(&self, shutdown: p2p::Cancellation) -> p2p::Deadline {
        let deadline = self.io_deadline();
        match &self.forwarding_candidate {
            Some(candidate) => deadline.for_candidate_forwarding(
                shutdown,
                self.cancellation.clone(),
                candidate.clone(),
            ),
            None => deadline,
        }
    }

    #[cfg(feature = "eng2-runtime")]
    fn check_forwarding(&self) -> Result<(), Error> {
        if self.cancelled {
            return Err(Error::Cancelled);
        }
        self.forwarding_deadline(self.cancellation.clone())
            .check()
            .map_err(|_| Error::Expired)
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn forwarding_descriptor(&self) -> Result<Vec<u8>, Error> {
        self.check_forwarding()?;
        self.authenticated
            .encoded_descriptor()
            .map_err(Error::Authentication)
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn forwarding_piece(&self, index: usize) -> Result<Option<Vec<u8>>, Error> {
        self.check_forwarding()?;
        let state = self.pieces.get(index).ok_or(Error::Bounds)?;
        if !state.complete {
            return Ok(None);
        }
        let range = self
            .authenticated
            .range(index)
            .map_err(Error::Authentication)?;
        let mut bytes = Vec::with_capacity(range.len() + if index == 0 { 8 } else { 0 });
        if index == 0 {
            bytes.extend_from_slice(&(self.body_bytes() as u64).to_le_bytes());
        }
        bytes.extend_from_slice(&self.encoded[range]);
        Ok(Some(bytes))
    }

    /// Return only already authenticated bytes. A range crossing an unfinished
    /// piece remains unavailable even if its backing allocation contains zeros.
    pub fn authenticated_bytes(&self, range: std::ops::Range<usize>) -> Option<&[u8]> {
        if range.start >= range.end || range.end > self.encoded.len() {
            return None;
        }
        let first = (range.start + 8) / authentication::PIECE_BYTES;
        let last = (range.end - 1 + 8) / authentication::PIECE_BYTES;
        if self.pieces[first..=last]
            .iter()
            .any(|piece| !piece.complete)
        {
            return None;
        }
        Some(&self.encoded[range])
    }

    /// Size one source's only batch from actual unassigned authenticated pieces
    /// and the remaining query/source allowance, including the descriptor query.
    #[cfg(all(test, feature = "eng2-runtime"))]
    pub(crate) fn batch_capacity(&self, connected: &std::collections::BTreeSet<Hash>) -> usize {
        if self.confirmation_pending.is_some() && self.limits.parallel == 1 {
            return 0;
        }
        self.batch_capacity_matching(4, |peer, source| {
            connected.contains(peer) && source.metadata_confirmed
        })
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn qualified_batch_capacity(
        &self,
        peer: Hash,
        connected: &std::collections::BTreeSet<Hash>,
        holders: &std::collections::BTreeSet<Hash>,
        ownership: &p2p::BodyClaim,
    ) -> usize {
        let queries = (1..=4)
            .rev()
            .find(|&count| ownership.can_query(peer, count))
            .unwrap_or(0);
        self.batch_capacity_matching(usize::from(queries), |source, state| {
            (holders.contains(source)
                || (state.metadata_confirmed && (*source == peer || connected.contains(source))))
                && ownership.can_query(*source, 1)
        })
    }

    #[cfg(feature = "eng2-runtime")]
    fn batch_capacity_matching(
        &self,
        queries: usize,
        eligible: impl Fn(&Hash, &Source) -> bool,
    ) -> usize {
        let missing = self
            .pieces
            .iter()
            .filter(|p| !p.complete && p.pending.is_none())
            .count();
        let sources = self
            .sources
            .iter()
            .filter(|(peer, source)| {
                source.connected && !source.body_batch_used && eligible(peer, source)
            })
            .count();
        let queries = queries.min(self.limits.requests.saturating_sub(self.queries) as usize);
        let remaining = sources.min(queries);
        if remaining == 0 {
            0
        } else {
            missing.div_ceil(remaining)
        }
    }
    pub fn body_bytes(&self) -> usize {
        self.encoded.len()
    }
    pub fn piece_count(&self) -> usize {
        self.authenticated.piece_count()
    }
    pub fn verified_bytes(&self) -> usize {
        self.verified_bytes
    }

    pub fn block(&self) -> Hash {
        self.authenticated.block()
    }

    /// Reuse bytes from an existing locally qualified complete envelope. This
    /// does not reuse a proof result or relax any state-dependent admission.
    /// Boundary pieces must already be authenticated. Every missing interior
    /// piece is independently checked before any candidate bytes are installed.
    /// A different encoding or proof returns zero without blaming a peer.
    pub fn reuse_local_envelope(
        &mut self,
        slot: &super::framing::Slot,
        envelope: &[u8],
        now: Instant,
    ) -> Result<usize, Error> {
        self.check(now)?;
        if slot.block() != self.block() {
            return Err(Error::Framing);
        }
        let range = slot.range();
        if range.len() != envelope.len() {
            return Ok(0);
        }
        let first = (range.start + 8) / authentication::PIECE_BYTES;
        let last = (range.end - 1 + 8) / authentication::PIECE_BYTES;
        let mut verified = Vec::with_capacity(last - first + 1);
        let mut reused = 0;
        for index in first..=last {
            let piece_range = self
                .authenticated
                .range(index)
                .map_err(Error::Authentication)?;
            let overlap = piece_range.start.max(range.start)..piece_range.end.min(range.end);
            let local = &envelope[overlap.start - range.start..overlap.end - range.start];
            if self.pieces[index].complete {
                if self.authenticated_bytes(overlap).ok_or(Error::Framing)? != local {
                    return Ok(0);
                }
                continue;
            }
            if piece_range.start < range.start
                || piece_range.end > range.end
                || self.pieces[index].pending.is_some()
            {
                return Ok(0);
            }
            let candidate =
                envelope[piece_range.start - range.start..piece_range.end - range.start].to_vec();
            match self.authenticated.verify(index, candidate) {
                Ok(piece) => {
                    reused += piece.bytes().len();
                    verified.push(piece);
                }
                Err(_) => return Ok(0),
            }
        }
        self.check(Instant::now())?;
        for piece in verified {
            self.install(piece)?;
        }
        Ok(reused)
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn observed_sources(&self) -> impl Iterator<Item = SourceBytes> + '_ {
        self.sources
            .values()
            .map(|source| source.bytes)
            .filter(|source| source.queries > 0)
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn fetch_timing(
        &self,
        header: &Header,
        ownership: &p2p::BodyClaim,
    ) -> crate::eng2::accept_observation::FetchTiming {
        crate::eng2::accept_observation::FetchTiming {
            connection: 0,
            attempt: ownership
                .progress_attempt()
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(0),
            height: header.height,
            block: self.block(),
            bytes: self.encoded.len() as u64,
            received_bytes: self.verified_bytes as u64,
            start: Some(self.started),
            body_start: Some(self.metadata_complete),
            chunks_end: self.body_complete,
            end: Some(Instant::now()),
            ..Default::default()
        }
    }
    pub fn sources(&self) -> Vec<SourceBytes> {
        self.sources.values().map(|source| source.bytes).collect()
    }

    pub fn sent(&mut self, peer: Hash, wire_bytes: u64, now: Instant) -> Result<(), Error> {
        let source = self.sources.get_mut(&peer).ok_or(Error::Peer)?;
        source.bytes.sent = source
            .bytes
            .sent
            .checked_add(wire_bytes)
            .ok_or(Error::Bounds)?;
        if source
            .bytes
            .sent
            .checked_add(source.bytes.received)
            .is_none_or(|bytes| bytes > source.bytes.reserved_wire)
        {
            source.connected = false;
            source.bytes.failures += 1;
            return Err(Error::Bounds);
        }
        self.check(now)
    }

    /// Completion still performs unchanged full-body commitment and canonical
    /// decode. This yields transport material, never an accepted block.
    pub fn finish(
        mut self,
        header: &Header,
        policy: BodyPolicy,
        now: Instant,
        ownership: p2p::BodyClaim,
    ) -> Result<ReceivedBody, Error> {
        self.finish_retained(header, policy, now, ownership)
    }

    /// Decode once while authenticated encoded pieces remain available to
    /// bounded downstream exchanges. Only the decoded allocation reservation
    /// moves into local admission; relays retain the shared encoded allocation.
    pub(crate) fn finish_retained(
        &mut self,
        header: &Header,
        policy: BodyPolicy,
        now: Instant,
        ownership: p2p::BodyClaim,
    ) -> Result<ReceivedBody, Error> {
        if self.decode_reservation.is_none() {
            return Err(Error::Resources);
        }
        self.check(now)?;
        if self.pieces.iter().any(|piece| !piece.complete) {
            return Err(Error::Incomplete);
        }
        if header.id().map_err(|_| Error::Framing)? != self.authenticated.block() {
            return Err(Error::Framing);
        }
        if self.binding.is_none_or(|binding| {
            !ownership.matches(&self.budget, binding, header.height, self.block())
        }) {
            return Err(Error::Framing);
        }
        header
            .verify_body(&self.encoded, policy.max_body_bytes)
            .map_err(|_| Error::Framing)?;
        ownership.decoded().map_err(|_| Error::Expired)?;
        #[cfg(feature = "eng2-runtime")]
        let mut timing = self.fetch_timing(header, &ownership);
        let body = Body::decode(&self.encoded, header.network, header.height, policy)
            .map_err(|_| Error::Framing)?;
        self.check(Instant::now())?;
        ownership.check_active().map_err(|_| Error::Expired)?;
        #[cfg(feature = "eng2-runtime")]
        let observation = {
            timing.decoded = Some(Instant::now());
            timing.end = timing.decoded;
            timing.outcome = 1;
            crate::eng2::accept_observation::FrameIdentity::after_authenticated_decode(
                self.descriptor_peer,
                header,
                &self.encoded,
                policy.max_body_bytes,
            )
            .map(|frame| frame.with_fetch_timing(timing))
        };
        let reservation = self.decode_reservation.take().ok_or(Error::Resources)?;
        #[cfg(feature = "eng2-runtime")]
        if let Some(candidate) = &self.forwarding_candidate {
            candidate.authenticated();
        }
        Ok(ReceivedBody {
            #[cfg(feature = "eng2-runtime")]
            receipts: None,
            ownership,
            body,
            reservation,
            #[cfg(feature = "eng2-runtime")]
            observation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::authentication::{Descriptor, PIECE_BYTES, encoded_piece};
    use super::*;

    fn limits(length: usize) -> Limits {
        Limits {
            requests: 4,
            wire_bytes: (length * 5) as u64,
            peer_requests: 1,
            peer_wire_bytes: (length * 5) as u64,
            parallel: 3,
            lifetime: Duration::from_secs(3),
        }
    }
    fn fixture() -> (Header, BodyPolicy, Vec<u8>) {
        let mut body = crate::eng2::body::tests::body();
        body.governance.clear();
        body.fund_claims.clear();
        body.settlement_proof = vec![8; 3 * PIECE_BYTES + 7];
        let policy = BodyPolicy {
            profile: body.profile,
            max_body_bytes: 1024 * 1024,
            slot_rule: crate::wire::SlotRule::Legacy,
            max_settlement_proof_bytes: 1024 * 1024,
        };
        let encoded = body.encode(policy).unwrap();
        let header = Header {
            network: body.network,
            height: body.height,
            parent: [2; 32],
            timestamp: 1,
            target: [255; 32],
            execution_commitment: [3; 32],
            body_commitment: body.commitment(policy).unwrap(),
            nonce: 0,
        };
        (header, policy, encoded)
    }
    fn transfer(
        header: &Header,
        body: &[u8],
        limits: Limits,
        budget: &p2p::Budget,
        started: Instant,
    ) -> Transfer {
        let (authenticated, first) = Descriptor::build(body, body.len())
            .unwrap()
            .authenticate(header, encoded_piece(body, 0).unwrap(), body.len())
            .unwrap();
        Transfer::new(
            authenticated,
            first,
            ledger(header, limits, started),
            budget,
        )
        .unwrap()
    }
    fn ledger(header: &Header, limits: Limits, started: Instant) -> DescriptorLedger {
        let mut ledger = DescriptorLedger::new(
            header.id().unwrap(),
            &[[1; 32], [2; 32], [3; 32]],
            limits,
            started,
        )
        .unwrap();
        let wire = (3 * PIECE_BYTES as u64 + 8192)
            .min(limits.wire_bytes)
            .min(limits.peer_wire_bytes);
        let attempt = ledger.begin([1; 32], wire, Instant::now()).unwrap();
        ledger
            .completed(
                attempt,
                8192.min(wire - REQUEST_WIRE_BYTES),
                true,
                Instant::now(),
            )
            .unwrap();
        ledger.binding = Some(p2p::Binding {
            network: header.network,
            genesis: [7; 32],
            verifier: [8; 32],
        });
        ledger
    }
    fn finish(
        transfer: Transfer,
        header: &Header,
        policy: BodyPolicy,
        now: Instant,
    ) -> Result<ReceivedBody, Error> {
        let ownership = transfer
            .budget
            .claim_body(
                transfer.binding.unwrap(),
                header.height,
                header.id().unwrap(),
                [1; 32],
                p2p::BodyMode::Pieces,
                &transfer.io_deadline(),
            )
            .unwrap();
        let received = transfer.finish(header, policy, now, ownership)?;
        #[cfg(feature = "eng2-runtime")]
        {
            let observation = received
                .observation
                .expect("authenticated pieces retain frame identity");
            assert_eq!(observation.header_id(), header.id().unwrap());
            assert_eq!(observation.height(), header.height);
            let timing = observation.fetch_timing().unwrap();
            assert!(timing.start <= timing.body_start);
            assert!(timing.body_start <= timing.chunks_end);
            assert!(timing.chunks_end <= timing.decoded);
            assert!(timing.decoded <= timing.end);
            assert_eq!(timing.outcome, 1);
        }
        Ok(received)
    }

    #[test]
    fn exact_body_piece_multiple_keeps_its_length_prefix_tail_within_four_queries() {
        let (original, policy, encoded) = fixture();
        let mut body = Body::decode(&encoded, original.network, original.height, policy).unwrap();
        let length = body.encoded_len(policy).unwrap();
        let padding = (authentication::PIECE_BYTES - length % authentication::PIECE_BYTES)
            % authentication::PIECE_BYTES;
        body.settlement_proof
            .extend(std::iter::repeat_n(8, padding));
        let encoded = body.encode(policy).unwrap();
        assert_eq!(encoded.len() % authentication::PIECE_BYTES, 0);
        let header = Header {
            network: body.network,
            height: body.height,
            parent: [2; 32],
            timestamp: 1,
            target: [255; 32],
            execution_commitment: [3; 32],
            body_commitment: body.commitment(policy).unwrap(),
            nonce: 0,
        };
        let budget = p2p::Budget::new(8 * encoded.len());
        let started = Instant::now();
        let limits = limits(encoded.len());
        let mut ledger = DescriptorLedger::new(
            header.id().unwrap(),
            &[[1; 32], [2; 32], [3; 32]],
            limits,
            started,
        )
        .unwrap();
        let attempt = ledger
            .begin([1; 32], (2 * encoded.len()) as u64, started)
            .unwrap();
        ledger.completed(attempt, 8192, true, started).unwrap();
        ledger.binding = Some(p2p::Binding {
            network: header.network,
            genesis: [7; 32],
            verifier: [8; 32],
        });
        let (authenticated, first) = Descriptor::build(&encoded, encoded.len())
            .unwrap()
            .authenticate(&header, encoded_piece(&encoded, 0).unwrap(), encoded.len())
            .unwrap();
        let mut transfer = Transfer::new(authenticated, first, ledger, &budget).unwrap();
        assert_eq!(
            transfer.piece_count(),
            encoded.len() / authentication::PIECE_BYTES + 1
        );
        let maximum = transfer.piece_count().div_ceil(3);
        let tail = transfer.piece_count() - 1;
        let mut saw_tail = false;
        for peer in [[1; 32], [2; 32], [3; 32]] {
            let batch = transfer
                .next_batch(peer, None, maximum, Instant::now())
                .unwrap();
            for request in batch {
                saw_tail |= request.piece == tail;
                let bytes = encoded_piece(&encoded, request.piece).unwrap();
                transfer
                    .received(
                        request,
                        bytes.clone(),
                        bytes.len() as u64 + RESPONSE_OVERHEAD,
                        Instant::now(),
                    )
                    .unwrap();
            }
        }
        assert!(saw_tail);
        assert_eq!(transfer.verified_bytes(), encoded.len());
        assert_eq!(
            transfer
                .sources()
                .iter()
                .map(|source| source.queries)
                .sum::<u64>(),
            4
        );
        assert_eq!(
            finish(transfer, &header, policy, Instant::now())
                .unwrap()
                .body
                .encode(policy)
                .unwrap(),
            encoded
        );
    }

    #[test]
    fn independent_sources_finish_once_and_retain_shared_ownership_through_decode() {
        let (header, policy, body) = fixture();
        let budget = p2p::Budget::new(8 * body.len());
        let available = budget.available().unwrap();
        let mut transfer = transfer(&header, &body, limits(body.len()), &budget, Instant::now());
        let first = transfer
            .next([1; 32], None, Instant::now())
            .unwrap()
            .unwrap();
        let second = transfer
            .next([2; 32], None, Instant::now())
            .unwrap()
            .unwrap();
        assert_ne!(first.piece, second.piece);
        assert_eq!(first.sequence, 1);
        assert_eq!(transfer.sources()[0].requested, 1);
        assert_eq!(transfer.sources()[0].queries, 2);
        assert!(
            transfer
                .next([1; 32], None, Instant::now())
                .unwrap()
                .is_none()
        );
        for request in [second, first] {
            let bytes = encoded_piece(&body, request.piece).unwrap();
            let wire = bytes.len() as u64 + RESPONSE_OVERHEAD;
            transfer
                .received(request, bytes, wire, Instant::now())
                .unwrap();
        }
        assert!(transfer.received(first, vec![], 1, Instant::now()).is_err());
        assert_eq!(
            transfer.next([1; 32], None, Instant::now()),
            Err(Error::Peer)
        );
        for request in transfer
            .next_batch([3; 32], None, 128, Instant::now())
            .unwrap()
        {
            let bytes = encoded_piece(&body, request.piece).unwrap();
            let wire = bytes.len() as u64 + RESPONSE_OVERHEAD;
            transfer
                .received(request, bytes, wire, Instant::now())
                .unwrap();
        }
        assert_eq!(transfer.authenticated_bytes(0..body.len()).unwrap(), body);
        assert!(
            transfer
                .sources()
                .iter()
                .all(|source| source.received <= source.reserved_wire)
        );
        let decoded = finish(transfer, &header, policy, Instant::now()).unwrap();
        let (accounts, metadata) = budget.retained_body_accounting();
        assert_eq!(accounts, 1);
        assert!(metadata > 0);
        assert!(budget.available().unwrap() + metadata < available);
        assert_eq!(decoded.body.encode(policy).unwrap(), body);
        drop(decoded);
        let (accounts, metadata) = budget.retained_body_accounting();
        assert_eq!(accounts, 1);
        assert!(metadata > 0);
        assert_eq!(budget.available().unwrap() + metadata, available);
        let binding = p2p::Binding {
            network: header.network,
            genesis: [7; 32],
            verifier: [8; 32],
        };
        let deadline = p2p::Deadline::new(Duration::from_secs(3));
        assert!(
            budget
                .claim_body(
                    binding,
                    header.height,
                    header.id().unwrap(),
                    [4; 32],
                    p2p::BodyMode::Legacy,
                    &deadline,
                )
                .is_ok()
        );
    }

    #[test]
    fn corrupt_and_disconnected_sources_release_pieces_without_erasing_charges() {
        let (header, _, body) = fixture();
        let budget = p2p::Budget::new(8 * body.len());
        let mut transfer = transfer(&header, &body, limits(body.len()), &budget, Instant::now());
        let corrupt = transfer
            .next([1; 32], None, Instant::now())
            .unwrap()
            .unwrap();
        let bytes = encoded_piece(&body, corrupt.piece).unwrap();
        let mut bad = bytes.clone();
        bad[1] ^= 1;
        assert!(matches!(
            transfer.received(corrupt, bad, bytes.len() as u64 + 10, Instant::now()),
            Err(Error::Authentication(_))
        ));
        assert!(transfer.next([1; 32], None, Instant::now()).is_err());
        let retry = transfer
            .next([2; 32], None, Instant::now())
            .unwrap()
            .unwrap();
        assert_eq!(retry.piece, corrupt.piece);
        transfer.disconnected([2; 32], 101, Instant::now()).unwrap();
        let final_try = transfer
            .next([3; 32], None, Instant::now())
            .unwrap()
            .unwrap();
        assert_eq!(final_try.piece, retry.piece);
        transfer
            .received(
                final_try,
                bytes.clone(),
                bytes.len() as u64 + 10,
                Instant::now(),
            )
            .unwrap();
        let sources = transfer.sources();
        assert_eq!(sources[0].bad_pieces, 1);
        assert_eq!(sources[1].received, 101);
        assert!(sources[1].reserved_wire > 101);
    }

    #[test]
    fn progress_and_new_sources_never_renew_the_absolute_lifetime() {
        let (header, policy, body) = fixture();
        let start = Instant::now();
        let budget = p2p::Budget::new(8 * body.len());
        let mut transfer = transfer(&header, &body, limits(body.len()), &budget, start);
        let request = transfer
            .next([1; 32], None, start + Duration::from_secs(1))
            .unwrap()
            .unwrap();
        let bytes = encoded_piece(&body, request.piece).unwrap();
        transfer
            .received(
                request,
                bytes.clone(),
                bytes.len() as u64 + 10,
                start + Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(
            transfer.next([2; 32], None, start + Duration::from_secs(3)),
            Err(Error::Expired)
        );
        assert!(matches!(
            finish(transfer, &header, policy, start + Duration::from_secs(3)),
            Err(Error::Expired)
        ));
    }

    #[test]
    fn cancellation_and_wrong_block_cannot_publish_transport_material() {
        let (header, policy, body) = fixture();
        let budget = p2p::Budget::new(8 * body.len());
        let mut cancelled = transfer(&header, &body, limits(body.len()), &budget, Instant::now());
        cancelled.cancel();
        assert_eq!(
            cancelled.next([1; 32], None, Instant::now()),
            Err(Error::Cancelled)
        );
        assert!(matches!(
            finish(cancelled, &header, policy, Instant::now()),
            Err(Error::Cancelled)
        ));
        let mut alternate = header.clone();
        alternate.nonce = 1;
        let (auth, first) = Descriptor::build(&body, body.len())
            .unwrap()
            .authenticate(&header, encoded_piece(&body, 0).unwrap(), body.len())
            .unwrap();
        let (_, foreign) = Descriptor::build(&body, body.len())
            .unwrap()
            .authenticate(&alternate, encoded_piece(&body, 0).unwrap(), body.len())
            .unwrap();
        assert!(matches!(
            Transfer::new(
                auth,
                foreign,
                ledger(&header, limits(body.len()), Instant::now()),
                &budget,
            ),
            Err(Error::Bounds)
        ));
        assert_eq!(first.block(), header.id().unwrap());
    }

    #[test]
    fn all_request_and_framing_budgets_are_precharged() {
        let (header, _, body) = fixture();
        let budget = p2p::Budget::new(8 * body.len());
        let mut limit = limits(body.len());
        limit.requests = 1;
        let mut bounded = transfer(&header, &body, limit, &budget, Instant::now());
        assert_eq!(
            bounded.next([2; 32], None, Instant::now()),
            Err(Error::Bounds)
        );
        let mut limit = limits(body.len());
        limit.wire_bytes = PIECE_BYTES as u64 + 4096;
        let mut bounded = transfer(&header, &body, limit, &budget, Instant::now());
        assert_eq!(
            bounded.next([1; 32], None, Instant::now()),
            Err(Error::Bounds)
        );
        let (auth, first) = Descriptor::build(&body, body.len())
            .unwrap()
            .authenticate(&header, encoded_piece(&body, 0).unwrap(), body.len())
            .unwrap();
        assert!(matches!(
            Transfer::new(
                auth,
                first,
                ledger(&header, limits(body.len()), Instant::now()),
                &p2p::Budget::new(1),
            ),
            Err(Error::Resources)
        ));
    }

    #[test]
    fn failed_descriptors_and_body_batches_share_four_requests_and_one_deadline() {
        let (header, _, body) = fixture();
        let start = Instant::now();
        let mut ledger = DescriptorLedger::new(
            header.id().unwrap(),
            &[[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]],
            limits(body.len()),
            start,
        )
        .unwrap();
        let failed = ledger.begin([1; 32], 8192, start).unwrap();
        ledger.completed(failed, 111, false, start).unwrap();
        let successful = ledger
            .begin([2; 32], 8192, start + Duration::from_millis(100))
            .unwrap();
        ledger
            .completed(successful, 8000, true, start + Duration::from_millis(200))
            .unwrap();
        let (auth, first) = Descriptor::build(&body, body.len())
            .unwrap()
            .authenticate(&header, encoded_piece(&body, 0).unwrap(), body.len())
            .unwrap();
        let budget = p2p::Budget::new(8 * body.len());
        let mut transfer = Transfer::new(auth, first, ledger, &budget).unwrap();
        assert_eq!(
            transfer.next([1; 32], None, start + Duration::from_secs(1)),
            Err(Error::Peer)
        );
        let third = transfer
            .next([3; 32], None, start + Duration::from_secs(1))
            .unwrap()
            .unwrap();
        let fourth = transfer
            .next([4; 32], None, start + Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(third.sequence, 3);
        assert_eq!(fourth.sequence, 4);
        assert_eq!(
            transfer.next([5; 32], None, start + Duration::from_secs(1)),
            Err(Error::Bounds)
        );
        assert_eq!(
            transfer
                .sources()
                .iter()
                .map(|source| source.requested)
                .sum::<u64>(),
            4
        );
        assert_eq!(transfer.sources()[0].failures, 1);
        assert_eq!(transfer.sources()[0].received, 111);
        assert!(
            transfer
                .sources()
                .iter()
                .all(|source| source.requested <= 1)
        );
        transfer
            .disconnected([3; 32], 7, start + Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            transfer.next([3; 32], None, start + Duration::from_secs(3)),
            Err(Error::Expired)
        );
    }

    #[test]
    fn descriptor_continuation_counts_as_a_real_query_and_the_fifth_is_rejected() {
        let (header, _, body) = fixture();
        let mut ledger = DescriptorLedger::new(
            header.id().unwrap(),
            &[[1; 32], [2; 32], [3; 32], [4; 32]],
            limits(body.len()),
            Instant::now(),
        )
        .unwrap();
        let descriptor = ledger.begin([1; 32], 20480, Instant::now()).unwrap();
        ledger
            .completed(descriptor, 8192, true, Instant::now())
            .unwrap();
        let (auth, first) = Descriptor::build(&body, body.len())
            .unwrap()
            .authenticate(&header, encoded_piece(&body, 0).unwrap(), body.len())
            .unwrap();
        let budget = p2p::Budget::new(8 * body.len());
        let mut transfer = Transfer::new(auth, first, ledger, &budget).unwrap();
        let continuation = transfer
            .next([1; 32], None, Instant::now())
            .unwrap()
            .unwrap();
        let _third = transfer
            .next([2; 32], None, Instant::now())
            .unwrap()
            .unwrap();
        let _fourth = transfer
            .next([3; 32], None, Instant::now())
            .unwrap()
            .unwrap();
        let bytes = encoded_piece(&body, continuation.piece).unwrap();
        let wire = bytes.len() as u64 + 64;
        transfer
            .received(continuation, bytes, wire, Instant::now())
            .unwrap();
        assert_eq!(
            transfer
                .sources()
                .iter()
                .map(|source| source.queries)
                .sum::<u64>(),
            4
        );
        assert_eq!(
            transfer
                .sources()
                .iter()
                .map(|source| source.requested)
                .sum::<u64>(),
            3
        );
        assert_eq!(
            transfer.next([4; 32], None, Instant::now()),
            Err(Error::Bounds)
        );
        assert_eq!(transfer.sources()[3].queries, 0);
        assert_eq!(transfer.sources()[3].reserved_wire, 0);
    }

    #[test]
    fn authenticated_framing_and_complete_envelope_reuse_do_not_trust_remote_boundaries() {
        let mut body = crate::eng2::body::tests::body();
        body.governance.clear();
        body.fund_claims.clear();
        body.transactions[0].proof = vec![11; 9 * PIECE_BYTES + 17];
        let policy = BodyPolicy {
            profile: body.profile,
            max_body_bytes: 1024 * 1024,
            slot_rule: crate::wire::SlotRule::Legacy,
            max_settlement_proof_bytes: 1024 * 1024,
        };
        let encoded = body.encode(policy).unwrap();
        let header = Header {
            network: body.network,
            height: body.height,
            parent: [2; 32],
            timestamp: 1,
            target: [255; 32],
            execution_commitment: [3; 32],
            body_commitment: body.commitment(policy).unwrap(),
            nonce: 0,
        };
        let budget = p2p::Budget::new(8 * encoded.len());
        let mut transfer = transfer(
            &header,
            &encoded,
            limits(encoded.len()),
            &budget,
            Instant::now(),
        );
        assert!(matches!(
            super::super::framing::inspect(&transfer, &header, policy),
            Err(super::super::framing::Error::NeedPiece(_))
        ));
        // The descriptor provides only canonical indexing pieces. The first
        // envelope's interior remains missing and can be filled from the pool.
        let start = crate::eng2::body::PREFIX_BYTES
            + (body.rewards.len() + 1) * crate::wire::REWARD_RECORD_BYTES
            + 4;
        let envelope = body.transactions[0].encode_envelope(&body.network).unwrap();
        let end = start + envelope.len();
        for index in super::super::framing::index_pieces(&body, policy)
            .unwrap()
            .into_iter()
            .filter(|&index| index != 0)
        {
            let piece = transfer
                .authenticated
                .verify(index, encoded_piece(&encoded, index).unwrap())
                .unwrap();
            transfer.index_piece(piece, Instant::now()).unwrap();
        }
        let layout = super::super::framing::inspect(&transfer, &header, policy).unwrap();
        assert_eq!(layout.slots.len(), body.transactions.len());
        assert_eq!(layout.slots[0].range(), start..end);
        assert!(layout.slots[0].envelope(&transfer).is_err());
        let mut wrong = envelope.clone();
        wrong[crate::wire::TX_PREFIX_BYTES + PIECE_BYTES] ^= 1;
        assert_eq!(
            transfer
                .reuse_local_envelope(&layout.slots[0], &wrong, Instant::now())
                .unwrap(),
            0
        );
        assert!(layout.slots[0].envelope(&transfer).is_err());
        let reused = transfer
            .reuse_local_envelope(&layout.slots[0], &envelope, Instant::now())
            .unwrap();
        assert!(reused >= 7 * PIECE_BYTES);
        assert_eq!(layout.slots[0].envelope(&transfer).unwrap(), envelope);
        for request in transfer
            .next_batch([2; 32], None, usize::MAX, Instant::now())
            .unwrap()
        {
            let bytes = encoded_piece(&encoded, request.piece).unwrap();
            let wire = bytes.len() as u64 + 64;
            transfer
                .received(request, bytes, wire, Instant::now())
                .unwrap();
        }
        assert_eq!(
            transfer.authenticated_bytes(0..encoded.len()).unwrap(),
            encoded
        );
        finish(transfer, &header, policy, Instant::now()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn three_local_socket_sources_stream_one_batch_each_with_out_of_order_pieces() {
        use super::super::wire as codec;
        use std::{
            io::{Read, Write},
            os::unix::net::UnixStream,
            sync::{
                Arc, Mutex,
                atomic::{AtomicU64, Ordering},
            },
        };
        struct Counted {
            socket: UnixStream,
            received: Arc<AtomicU64>,
            sent: Arc<AtomicU64>,
        }
        impl Read for Counted {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                let count = self.socket.read(bytes)?;
                self.received.fetch_add(count as u64, Ordering::Relaxed);
                Ok(count)
            }
        }
        impl Write for Counted {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let count = self.socket.write(bytes)?;
                self.sent.fetch_add(count as u64, Ordering::Relaxed);
                Ok(count)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.socket.flush()
            }
        }
        let (header, policy, body) = fixture();
        let budget = p2p::Budget::new(8 * body.len());
        let deadline = p2p::Deadline::new(Duration::from_secs(3));
        let mut transfer = transfer(&header, &body, limits(body.len()), &budget, Instant::now());
        let count = transfer.authenticated.piece_count();
        let assignments = [
            transfer
                .next_batch([1; 32], None, 1, Instant::now())
                .unwrap(),
            transfer
                .next_batch([2; 32], None, count / 2, Instant::now())
                .unwrap(),
            transfer
                .next_batch([3; 32], None, count, Instant::now())
                .unwrap(),
        ];
        assert!(assignments.iter().all(|batch| !batch.is_empty()));
        let shared = Arc::new(Mutex::new(transfer));
        let body = Arc::new(body);
        let binding = p2p::Binding {
            network: header.network,
            genesis: [7; 32],
            verifier: [8; 32],
        };
        std::thread::scope(|scope| {
            for batch in assignments {
                let (client, server) = UnixStream::pair().unwrap();
                for socket in [&client, &server] {
                    socket
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                }
                let server_deadline = deadline.clone();
                let server_body = body.clone();
                let server_budget = budget.clone();
                scope.spawn(move || {
                    let mut session =
                        p2p::Session::from_test_channel(server, binding, server_budget);
                    let p2p::Packet::Control {
                        request,
                        body: bytes,
                        reservation,
                        ..
                    } = session
                        .receive_eng2_application_before(&server_deadline, p2p::MAX_CONTROL_BYTES)
                        .unwrap()
                    else {
                        panic!("expected bounded eng2 query");
                    };
                    let query = codec::decode_query(&bytes, count).unwrap();
                    drop(bytes);
                    drop(reservation);
                    for index in query.pieces.into_iter().rev() {
                        let piece = encoded_piece(&server_body, index).unwrap();
                        let frame = codec::encode_piece(query.block, index, &piece).unwrap();
                        session
                            .send_control_before(
                                p2p::ENG2_MESSAGE,
                                request,
                                &frame,
                                &server_deadline,
                            )
                            .unwrap();
                    }
                });
                let client_deadline = deadline.clone();
                let client_shared = shared.clone();
                let client_budget = budget.clone();
                let received = Arc::new(AtomicU64::new(0));
                let sent = Arc::new(AtomicU64::new(0));
                let channel = Counted {
                    socket: client,
                    received: received.clone(),
                    sent: sent.clone(),
                };
                let height = header.height;
                scope.spawn(move || {
                    let mut session =
                        p2p::Session::from_test_channel(channel, binding, client_budget);
                    let query = codec::encode_query(height, &batch, count).unwrap();
                    session
                        .send_control_before(
                            p2p::ENG2_MESSAGE,
                            batch[0].sequence,
                            &query,
                            &client_deadline,
                        )
                        .unwrap();
                    client_shared
                        .lock()
                        .unwrap()
                        .sent(batch[0].peer, sent.load(Ordering::Relaxed), Instant::now())
                        .unwrap();
                    let mut previous = 0;
                    for _ in 0..batch.len() {
                        let p2p::Packet::Control {
                            request,
                            body: frame,
                            reservation,
                            ..
                        } = session
                            .receive_eng2_application_before(&client_deadline, PIECE_BYTES + 128)
                            .unwrap()
                        else {
                            panic!("expected bounded eng2 piece");
                        };
                        let piece = codec::decode_piece(&frame, count).unwrap();
                        let assigned = batch
                            .iter()
                            .find(|assigned| assigned.piece == piece.index)
                            .unwrap();
                        assert_eq!(assigned.sequence, request);
                        assert_eq!(assigned.block, piece.block);
                        let current = received.load(Ordering::Relaxed);
                        client_shared
                            .lock()
                            .unwrap()
                            .received(
                                *assigned,
                                piece.bytes.to_vec(),
                                current - previous,
                                Instant::now(),
                            )
                            .unwrap();
                        previous = current;
                        drop(frame);
                        drop(reservation);
                    }
                });
            }
        });
        let transfer = Arc::try_unwrap(shared).ok().unwrap().into_inner().unwrap();
        assert!(
            transfer
                .sources()
                .iter()
                .all(|source| source.requested == 1 && source.sent > 0 && source.received > 0)
        );
        let received = finish(transfer, &header, policy, Instant::now()).unwrap();
        assert_eq!(received.body.encode(policy).unwrap(), *body);
    }

    #[cfg(feature = "eng2-runtime")]
    fn source_confirmation_fixture() -> (Transfer, p2p::BodyClaim, Header, Vec<u8>, BodyPolicy) {
        let (header, policy, body) = fixture();
        let budget = p2p::Budget::new(8 * body.len());
        let start = Instant::now();
        let binding = p2p::Binding {
            network: header.network,
            genesis: [7; 32],
            verifier: [8; 32],
        };
        let ownership = budget
            .claim_body(
                binding,
                header.height,
                header.id().unwrap(),
                [1; 32],
                p2p::BodyMode::Pieces,
                &p2p::Deadline::new(Duration::from_secs(3)),
            )
            .unwrap();
        ownership.begin_query([1; 32]).unwrap();
        let mut ledger = DescriptorLedger::new(
            header.id().unwrap(),
            &[[1; 32], [2; 32], [3; 32]],
            limits(body.len()),
            start,
        )
        .unwrap();
        ledger.bind_claim(binding, &ownership).unwrap();
        let attempt = ledger
            .begin([1; 32], (2 * body.len()) as u64, start)
            .unwrap();
        ledger.sent(attempt, 93).unwrap();
        ledger.completed(attempt, 8192, true, start).unwrap();
        let (authenticated, first) = Descriptor::build(&body, body.len())
            .unwrap()
            .authenticate(&header, encoded_piece(&body, 0).unwrap(), body.len())
            .unwrap();
        (
            Transfer::new(authenticated, first, ledger, &budget).unwrap(),
            ownership,
            header,
            body,
            policy,
        )
    }

    #[cfg(feature = "eng2-runtime")]
    fn source_confirmation_auth(header: &Header, body: &[u8]) -> Authenticated {
        Descriptor::build(body, body.len())
            .unwrap()
            .authenticate(header, encoded_piece(body, 0).unwrap(), body.len())
            .unwrap()
            .0
    }

    #[cfg(feature = "eng2-runtime")]
    fn source_confirmation_receive(transfer: &mut Transfer, requests: Vec<Request>, body: &[u8]) {
        for request in requests {
            let bytes = encoded_piece(body, request.piece).unwrap();
            let wire = bytes.len() as u64 + RESPONSE_OVERHEAD;
            transfer
                .received(request, bytes, wire, Instant::now())
                .unwrap();
        }
    }

    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn qualified_piece_sources_reassign_only_failed_ranges_within_the_query_ceiling() {
        let (mut transfer, owner, header, body, policy) = source_confirmation_fixture();
        let connected = std::collections::BTreeSet::from([[1; 32], [2; 32], [3; 32]]);
        let mut holders = std::collections::BTreeSet::from([[2; 32]]);
        let expiry = owner.deadline().expires_at();
        let capacity = transfer.qualified_batch_capacity([1; 32], &connected, &holders, &owner);
        let first = transfer
            .next_batch([1; 32], None, capacity, Instant::now())
            .unwrap();
        owner.begin_query([1; 32]).unwrap();
        let capacity = transfer.qualified_batch_capacity([2; 32], &connected, &holders, &owner);
        let failed = transfer
            .next_batch([2; 32], None, capacity, Instant::now())
            .unwrap();
        owner.begin_query([2; 32]).unwrap();
        assert!(!first.is_empty() && !failed.is_empty());
        assert!(
            first
                .iter()
                .all(|one| failed.iter().all(|two| one.piece != two.piece))
        );
        source_confirmation_receive(&mut transfer, first, &body);
        transfer.disconnected([2; 32], 60, Instant::now()).unwrap();
        holders.insert([3; 32]);
        let capacity = transfer.qualified_batch_capacity([3; 32], &connected, &holders, &owner);
        let retry = transfer
            .next_batch([3; 32], None, capacity, Instant::now())
            .unwrap();
        assert_eq!(
            retry.iter().map(|r| r.piece).collect::<Vec<_>>(),
            failed.iter().map(|r| r.piece).collect::<Vec<_>>()
        );
        owner.begin_query([3; 32]).unwrap();
        source_confirmation_receive(&mut transfer, retry, &body);
        assert_eq!(transfer.queries, 4);
        assert!(!owner.can_query([3; 32], 1));
        assert_eq!(owner.deadline().expires_at(), expiry);
        assert_eq!(
            transfer
                .finish(&header, policy, Instant::now(), owner)
                .unwrap()
                .body
                .encode(policy)
                .unwrap(),
            body
        );
    }

    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn pending_confirmation_does_not_block_an_authenticated_source() {
        let (mut transfer, owner, header, body, policy) = source_confirmation_fixture();
        let connected = std::collections::BTreeSet::from([[1; 32], [2; 32]]);
        let original_end = transfer.io_deadline().expires_at();
        let (probe, deadline) = transfer
            .begin_confirmation([2; 32], (2 * body.len()) as u64, &owner)
            .unwrap()
            .unwrap();
        owner.begin_query([2; 32]).unwrap();
        assert!(deadline.expires_at() < original_end);
        assert!(deadline.expires_at() <= Instant::now() + Duration::from_secs(5));
        assert_eq!(transfer.io_deadline().expires_at(), original_end);
        assert!(transfer.confirmed_source([1; 32]));
        assert!(!transfer.confirmed_source([2; 32]));
        assert!(
            transfer
                .next_batch([2; 32], None, 1, Instant::now())
                .unwrap()
                .is_empty()
        );
        let maximum = transfer.batch_capacity(&connected);
        let batch = transfer
            .next_batch([1; 32], None, maximum, Instant::now())
            .unwrap();
        assert_eq!(batch.len(), transfer.piece_count() - 1);
        owner.begin_query([1; 32]).unwrap();
        source_confirmation_receive(&mut transfer, batch, &body);
        transfer.complete_confirmation(probe, 93, 60, None).unwrap();
        assert_eq!(transfer.queries, 3);
        assert_eq!(transfer.batch_capacity(&connected), 0);
        assert_eq!(
            transfer
                .finish(&header, policy, Instant::now(), owner)
                .unwrap()
                .body
                .encode(policy)
                .unwrap(),
            body
        );
    }

    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn only_confirmed_body_holder_completes_with_connected_nonholder() {
        let (mut transfer, owner, header, body, policy) = source_confirmation_fixture();
        let connected = std::collections::BTreeSet::from([[1; 32], [2; 32]]);
        let original_end = transfer.io_deadline().expires_at();
        assert!(original_end <= owner.deadline().expires_at());
        let (probe, end) = transfer
            .begin_confirmation([2; 32], (2 * body.len()) as u64, &owner)
            .unwrap()
            .unwrap();
        assert!(end.expires_at() < original_end);
        owner.begin_query([2; 32]).unwrap();
        transfer.complete_confirmation(probe, 93, 60, None).unwrap();
        assert!(transfer.confirmed_source([1; 32]));
        assert!(!transfer.confirmed_source([2; 32]));
        let maximum = transfer.batch_capacity(&connected);
        let batch = transfer
            .next_batch([1; 32], None, maximum, Instant::now())
            .unwrap();
        assert_eq!(batch.len(), transfer.piece_count() - 1);
        owner.begin_query([1; 32]).unwrap();
        source_confirmation_receive(&mut transfer, batch, &body);
        assert_eq!(transfer.queries, 3);
        assert!(transfer.sources().iter().all(|s| s.requested <= 1));
        assert!(!transfer.confirmation_available([3; 32], &owner));
        assert_eq!(
            transfer
                .finish(&header, policy, Instant::now(), owner)
                .unwrap()
                .body
                .encode(policy)
                .unwrap(),
            body
        );
    }

    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn source_confirmation_two_holders_keep_disjoint_work_pending_concurrently() {
        let (mut transfer, owner, header, body, policy) = source_confirmation_fixture();
        let (probe, _) = transfer
            .begin_confirmation([2; 32], (2 * body.len()) as u64, &owner)
            .unwrap()
            .unwrap();
        owner.begin_query([2; 32]).unwrap();
        let second = source_confirmation_auth(&header, &body);
        transfer
            .complete_confirmation(probe, 93, 8192, Some(&second))
            .unwrap();
        let connected = std::collections::BTreeSet::from([[1; 32], [2; 32], [3; 32]]);
        let maximum = transfer.batch_capacity(&connected);
        let first = transfer
            .next_batch([1; 32], None, maximum, Instant::now())
            .unwrap();
        let maximum = transfer.batch_capacity(&connected);
        let other = transfer
            .next_batch([2; 32], None, maximum, Instant::now())
            .unwrap();
        assert!(!first.is_empty() && !other.is_empty());
        assert!(
            first
                .iter()
                .all(|a| other.iter().all(|b| a.piece != b.piece))
        );
        assert_eq!(
            transfer
                .pending
                .values()
                .map(|v| v.peer)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            2
        );
        owner.begin_query([1; 32]).unwrap();
        owner.begin_query([2; 32]).unwrap();
        assert!(!owner.can_query([3; 32], 1));
        source_confirmation_receive(&mut transfer, first, &body);
        source_confirmation_receive(&mut transfer, other, &body);
        assert_eq!(transfer.queries, 4);
        assert!(transfer.sources().iter().all(|s| s.requested <= 1));
        assert_eq!(
            transfer
                .finish(&header, policy, Instant::now(), owner)
                .unwrap()
                .body
                .encode(policy)
                .unwrap(),
            body
        );
    }

    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn source_confirmation_absent_worker_never_delays_the_first_holder() {
        let (mut transfer, owner, header, body, policy) = source_confirmation_fixture();
        let connected = std::collections::BTreeSet::from([[1; 32], [2; 32]]);
        let maximum = transfer.batch_capacity(&connected);
        let batch = transfer
            .next_batch([1; 32], None, maximum, Instant::now())
            .unwrap();
        assert!(
            transfer
                .begin_confirmation([2; 32], (2 * body.len()) as u64, &owner)
                .unwrap()
                .is_none()
        );
        owner.begin_query([1; 32]).unwrap();
        source_confirmation_receive(&mut transfer, batch, &body);
        assert_eq!(transfer.queries, 2);
        assert_eq!(
            transfer
                .finish(&header, policy, Instant::now(), owner)
                .unwrap()
                .body
                .encode(policy)
                .unwrap(),
            body
        );
    }

    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn source_confirmation_bad_descriptor_preserves_the_original_holder() {
        let (mut transfer, owner, _, body, _) = source_confirmation_fixture();
        let (probe, _) = transfer
            .begin_confirmation([2; 32], (2 * body.len()) as u64, &owner)
            .unwrap()
            .unwrap();
        owner.begin_query([2; 32]).unwrap();
        let (mut wrong, _, _) = fixture();
        wrong.nonce += 1;
        let wrong = source_confirmation_auth(&wrong, &body);
        assert_eq!(
            transfer.complete_confirmation(probe, 93, 8192, Some(&wrong)),
            Err(Error::Framing)
        );
        assert!(transfer.confirmed_source([1; 32]));
        assert!(!transfer.confirmed_source([2; 32]));
        assert_eq!(transfer.queries, 2);
        assert_eq!(transfer.sources()[1].failures, 1);
    }

    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn source_confirmation_post_assignment_loss_is_bounded_failure() {
        let (mut transfer, owner, header, body, _) = source_confirmation_fixture();
        let (probe, _) = transfer
            .begin_confirmation([2; 32], (2 * body.len()) as u64, &owner)
            .unwrap()
            .unwrap();
        owner.begin_query([2; 32]).unwrap();
        let second = source_confirmation_auth(&header, &body);
        transfer
            .complete_confirmation(probe, 93, 8192, Some(&second))
            .unwrap();
        let connected = std::collections::BTreeSet::from([[1; 32], [2; 32]]);
        let maximum = transfer.batch_capacity(&connected);
        let first = transfer
            .next_batch([1; 32], None, maximum, Instant::now())
            .unwrap();
        let maximum = transfer.batch_capacity(&connected);
        let other = transfer
            .next_batch([2; 32], None, maximum, Instant::now())
            .unwrap();
        assert!(!other.is_empty());
        source_confirmation_receive(&mut transfer, first, &body);
        transfer.disconnected([2; 32], 60, Instant::now()).unwrap();
        assert_eq!(
            transfer.next_batch([1; 32], None, transfer.piece_count(), Instant::now()),
            Err(Error::Peer)
        );
        assert!(transfer.verified_bytes() < transfer.body_bytes());
        assert_eq!(transfer.queries, 4);
    }

    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn source_confirmation_prior_queries_reduce_capacity_without_refund() {
        let (mut transfer, owner, header, body, policy) = source_confirmation_fixture();
        // The authoritative account has prior work absent from this local
        // scheduling ledger. It must still constrain confirmation planning.
        owner.begin_query([3; 32]).unwrap();
        assert!(!transfer.confirmation_available([2; 32], &owner));
        assert!(
            transfer
                .begin_confirmation([2; 32], (2 * body.len()) as u64, &owner)
                .unwrap()
                .is_none()
        );
        let connected = std::collections::BTreeSet::from([[1; 32], [2; 32]]);
        let maximum = transfer.batch_capacity(&connected);
        let batch = transfer
            .next_batch([1; 32], None, maximum, Instant::now())
            .unwrap();
        owner.begin_query([1; 32]).unwrap();
        assert!(!owner.can_query([2; 32], 2));
        source_confirmation_receive(&mut transfer, batch, &body);
        assert_eq!(
            transfer
                .finish(&header, policy, Instant::now(), owner)
                .unwrap()
                .body
                .encode(policy)
                .unwrap(),
            body
        );
    }

    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn source_confirmation_rejected_wire_and_cancellation_create_no_probe_budget() {
        let (mut transfer, owner, _, _, _) = source_confirmation_fixture();
        let before = transfer.queries;
        assert!(matches!(
            transfer.begin_confirmation([2; 32], u64::MAX, &owner),
            Err(Error::Bounds)
        ));
        assert_eq!(transfer.queries, before);
        assert!(transfer.confirmation_pending.is_none());
        owner.cancellation().cancel();
        assert!(
            transfer
                .begin_confirmation([2; 32], 8192, &owner)
                .unwrap()
                .is_none()
        );
        assert_eq!(transfer.queries, before);
        assert!(transfer.confirmation_pending.is_none());
    }
}
