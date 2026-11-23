//! Bounded native protocol over an independently pinned hybrid channel.
//! The optional engineering transport requires composition and resource review.
//! No classical or plaintext fallback is supplied.
use crate::identity::{Descriptor, PeerPin};
use crate::state::Config;
use crate::wire::{Block, Hash, MAX_BLOCK_BYTES, MAX_ENVELOPE_BYTES, SUITE_ID};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// The candidate-only feature is opaque. native-p2p explicitly adds the
// engineering bridge; the complete composition still requires review.
#[cfg(feature = "hybrid-tls-candidate")]
#[allow(dead_code)]
pub(crate) mod hybrid_tls;
#[cfg(feature = "native-p2p")]
pub use hybrid_tls::native::{NativeTlsAuthenticator, NativeTlsChannel};

mod body_ownership;
pub use body_ownership::Authorization as BodyAuthorization;
pub(crate) use body_ownership::Scope as BodyScope;
pub use body_ownership::{ClaimError as BodyClaimError, Mode as BodyMode};
pub const VERSION: u16 = 1;
pub const MAX_CONTROL_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_CHECKPOINT_EXCHANGE_BYTES: usize = 16 * 1024;
/// Compact skeletons include bounded native issuance records and their
/// independent proofs. Ordinary control messages retain the smaller cap.
pub const MAX_COMPACT_BYTES: usize = MAX_CONTROL_BYTES
    + crate::issuance::RECORDS_CODEC_LIMIT * (4 + crate::issuance::MAX_RECORD_BYTES);
pub const CONNECTION_BYTES: usize = 640 * 1024 * 1024;
pub const HELLO_BYTES: usize = 103;
pub const HEADER_BYTES: usize = 51;
pub const GET_BLOCKS: u8 = 1;
pub const SYNC_META: u8 = 2;
pub const COMPACT_BLOCK: u8 = 3;
pub const BLOCK: u8 = 4;
pub const TRANSACTION: u8 = 5;
pub const GET_TRANSACTIONS: u8 = 6;
pub const UNAVAILABLE: u8 = 7;
pub const END_BATCH: u8 = 8;
pub const CHECKPOINT: u8 = 9;
pub const GET_CHECKPOINT_DATA: u8 = 10;
/// Versioned eng-2 messages remain bounded control frames.
pub(crate) const ENG2_MESSAGE: u8 = 11;
pub(crate) const CHECKPOINT_ALPN: &[u8] = b"/siworld/native-hybrid/checkpoint/1";
pub const MAX_HANDSHAKES: usize = 16;
pub const HANDSHAKE_BYTES: usize = 256 * 1024;
pub const HANDSHAKE_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const BLOCK_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidProtocol,
    Unavailable,
    ResourceExhausted,
    Unconfigured,
}
fn io_error(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::InvalidData {
        Error::InvalidProtocol
    } else {
        Error::Unavailable
    }
}

#[derive(Default, Debug)]
struct Usage {
    bytes: usize,
    peak: usize,
    handshakes: usize,
    handshake_bytes: usize,
}
#[derive(Debug)]
struct BudgetInner {
    bodies: Arc<body_ownership::Registry>,
    maximum: usize,
    usage: Mutex<Usage>,
}
/// Atomic logical byte counters observed during one admission attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ByteUsage {
    pub maximum: usize,
    pub used: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReserveFailure {
    Exhausted(ByteUsage),
    Overflow,
    Unavailable,
}
/// Shared logical ownership budget. Every listener, outbound connection and
/// retained packet for one node must receive clones of the same instance.
/// Handshake reservations consume this same maximum, in addition to their
/// category-specific count and byte caps.
/// This does not replace a process-level charged-memory guard.
#[derive(Clone, Debug)]
pub struct Budget(Arc<BudgetInner>);
impl Budget {
    #[cfg(all(test, feature = "eng2-runtime"))]
    pub(crate) fn age_test_body_accounts(&self, age: Duration) {
        self.0.bodies.age_test_accounts(age);
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn body_registry_diagnostic(&self) -> serde_json::Value {
        let Some(d) = self.0.bodies.last_decision() else {
            return serde_json::Value::Null;
        };
        let code = match d.error {
            None => "granted",
            Some(BodyClaimError::Busy) => "busy",
            Some(BodyClaimError::Expired) => "expired",
            Some(BodyClaimError::Capacity) => "capacity",
            Some(BodyClaimError::SourceUsed) => "source_used",
            Some(BodyClaimError::PreferUnused) => "unused_source_preferred",
            Some(BodyClaimError::QueryLimit) => "query_limit",
            Some(BodyClaimError::Unavailable) => "unavailable",
        };
        let wire = self.0.bodies.wire_usage();
        serde_json::json!({"wire_charged_bytes":wire.map(|w|w.0),"wire_reserved_bytes":wire.map(|w|w.1),"wire_maximum_bytes":wire.map(|w|w.2),"scope":"last_exact_body_decision","sequence":d.sequence,"phase":d.phase,"code":code,
            "height":d.height,"account":d.account,"generation":d.generation,"queries":d.queries,
            "window_queries":d.window_queries,"age_ms":d.age_ms,"remaining_ms":d.remaining_ms,"terminal":d.terminal})
    }
    pub fn new(maximum: usize) -> Self {
        Self(Arc::new(BudgetInner {
            bodies: Arc::new(body_ownership::Registry::default()),
            maximum,
            usage: Mutex::new(Usage::default()),
        }))
    }
    #[cfg(any(feature = "eng2-runtime", test))]
    pub(crate) fn accepted_body(
        &self,
        binding: Binding,
        height: u64,
        id: Hash,
    ) -> Result<bool, BodyClaimError> {
        self.0.bodies.accepted(body_ownership::Key {
            context: [binding.network, binding.genesis, binding.verifier],
            height,
            id,
        })
    }
    fn body_book_charge(&self, bytes: usize) -> Result<BodyBookCharge, BodyClaimError> {
        let mut reservation = self.reserve(bytes).map_err(|_| BodyClaimError::Capacity)?;
        reservation.bytes = 0;
        Ok(BodyBookCharge {
            budget: std::sync::Arc::downgrade(&self.0),
            bytes,
        })
    }
    pub(crate) fn resident_body_scope(
        &self,
        identity: u64,
        expires: std::time::Instant,
    ) -> Result<BodyScope, BodyClaimError> {
        self.0.bodies.resident_scope_charged(
            identity,
            std::time::Instant::now(),
            expires,
            Some(self.body_book_charge(body_ownership::scope_charge())?),
        )
    }
    pub(crate) fn restrict_body_wire_limit(
        &self,
        scope: &BodyScope,
        maximum: u64,
    ) -> Result<(), BodyClaimError> {
        self.0.bodies.restrict_wire(scope, maximum)
    }
    #[cfg(test)]
    pub(crate) fn body_wire_usage(&self) -> (u64, u64, u64) {
        self.0.bodies.wire_usage().unwrap()
    }
    pub(crate) fn restrict_body_limits(
        &self,
        scope: &BodyScope,
        maximum_entries: usize,
        maximum_queries: u64,
    ) -> Result<(), BodyClaimError> {
        self.0
            .bodies
            .restrict_limits(scope, maximum_entries, maximum_queries)
    }
    pub(crate) fn owns_body_scope(&self, scope: &BodyScope) -> bool {
        scope.matches(&self.0.bodies)
    }
    pub(crate) fn bootstrap_body_scope(
        &self,
        expires: std::time::Instant,
    ) -> Result<BodyScope, BodyClaimError> {
        self.0.bodies.bootstrap_scope_charged(
            std::time::Instant::now(),
            expires,
            Some(self.body_book_charge(body_ownership::scope_charge())?),
        )
    }
    pub(crate) fn advance_body_window(
        &self,
        advance: &crate::eng2::branches::discovery::BodyWindowAdvance,
    ) -> Result<(), BodyClaimError> {
        let (old, new) = advance.identities();
        let now = std::time::Instant::now();
        self.0.bodies.advance_window(
            old,
            new,
            now,
            now + std::time::Duration::from_millis(advance.remaining()),
        )
    }
    pub(crate) fn authorize_body(
        &self,
        scope: &BodyScope,
        binding: Binding,
        height: u64,
        id: Hash,
        deadline: &Deadline,
    ) -> Result<BodyAuthorization, BodyClaimError> {
        let record_charge = self.body_book_charge(body_ownership::record_charge())?;
        let pin_charge = self.body_book_charge(body_ownership::pin_charge())?;
        self.0.bodies.authorize(
            scope,
            body_ownership::Key {
                context: [binding.network, binding.genesis, binding.verifier],
                height,
                id,
            },
            std::time::Instant::now(),
            deadline.expires_at(),
            Some((record_charge, pin_charge)),
        )
    }
    pub(crate) fn authorization_matches(
        &self,
        authorization: &BodyAuthorization,
        binding: Binding,
        height: u64,
        id: Hash,
    ) -> bool {
        authorization.matches(
            body_ownership::Key {
                context: [binding.network, binding.genesis, binding.verifier],
                height,
                id,
            },
            &self.0.bodies,
        )
    }
    pub(crate) fn claim_body_authorized(
        &self,
        authorization: &BodyAuthorization,
        source: Hash,
        mode: BodyMode,
    ) -> Result<BodyClaim, BodyClaimError> {
        self.claim_body_preferred(authorization, source, mode, std::iter::empty())
    }
    pub(crate) fn claim_body_preferred(
        &self,
        authorization: &BodyAuthorization,
        source: Hash,
        mode: BodyMode,
        alternatives: impl IntoIterator<Item = Hash>,
    ) -> Result<BodyClaim, BodyClaimError> {
        let charge = self
            .reserve(std::mem::size_of::<BodyClaim>() + std::mem::size_of::<body_ownership::Key>())
            .map_err(|_| BodyClaimError::Capacity)?;
        let lease = self.0.bodies.claim_preferred(
            authorization,
            source,
            mode,
            std::time::Instant::now(),
            alternatives,
        )?;
        let deadline = Deadline::new(std::time::Duration::from_secs(180)).for_body_lease(&lease);
        let wire = Arc::new(lease.wire_account(Some(
            self.body_book_charge(std::mem::size_of::<body_ownership::WireAccount>() + 64)?,
        )));
        Ok(BodyClaim {
            wire,
            lease,
            deadline,
            _charge: charge,
        })
    }
    #[cfg(test)]
    pub(crate) fn claim_body(
        &self,
        binding: Binding,
        height: u64,
        id: Hash,
        source: Hash,
        mode: BodyMode,
        deadline: &Deadline,
    ) -> Result<BodyClaim, BodyClaimError> {
        let scope = self.resident_body_scope(
            1,
            std::time::Instant::now() + std::time::Duration::from_secs(3600),
        )?;
        let authorization = self.authorize_body(&scope, binding, height, id, deadline)?;
        self.claim_body_authorized(&authorization, source, mode)
    }
    #[cfg(test)]
    pub(crate) fn retained_body_accounting(&self) -> (usize, usize) {
        self.0.bodies.retained_accounting()
    }
    pub fn reserve(&self, bytes: usize) -> Result<Reservation, Error> {
        let mut usage = self.0.usage.lock().map_err(|_| Error::Unavailable)?;
        let next = usage
            .bytes
            .checked_add(bytes)
            .ok_or(Error::ResourceExhausted)?;
        if next > self.0.maximum {
            return Err(Error::ResourceExhausted);
        }
        usage.bytes = next;
        usage.peak = usage.peak.max(next);
        Ok(Reservation {
            budget: self.0.clone(),
            bytes,
        })
    }
    /// Preserve the failure category and counters under the same budget lock.
    /// This acquires exactly the requested bytes or changes no ownership.
    pub(crate) fn reserve_observed(
        &self,
        bytes: usize,
    ) -> Result<(Reservation, ByteUsage), ReserveFailure> {
        let mut usage = self
            .0
            .usage
            .lock()
            .map_err(|_| ReserveFailure::Unavailable)?;
        let observed = ByteUsage {
            maximum: self.0.maximum,
            used: usage.bytes,
        };
        let next = usage
            .bytes
            .checked_add(bytes)
            .ok_or(ReserveFailure::Overflow)?;
        if next > self.0.maximum {
            return Err(ReserveFailure::Exhausted(observed));
        }
        usage.bytes = next;
        usage.peak = usage.peak.max(next);
        Ok((
            Reservation {
                budget: self.0.clone(),
                bytes,
            },
            ByteUsage {
                maximum: self.0.maximum,
                used: next,
            },
        ))
    }
    #[cfg(all(unix, feature = "eng2-runtime"))]
    pub(crate) fn reservation_peak(&self) -> Result<usize, Error> {
        let usage = self.0.usage.lock().map_err(|_| Error::Unavailable)?;
        Ok(usage.peak)
    }
    pub(crate) fn available(&self) -> Result<usize, Error> {
        let usage = self.0.usage.lock().map_err(|_| Error::Unavailable)?;
        Ok(self.0.maximum.saturating_sub(usage.bytes))
    }
    fn handshake(&self) -> Result<HandshakeReservation, Error> {
        let mut usage = self.0.usage.lock().map_err(|_| Error::Unavailable)?;
        let next_bytes = usage
            .bytes
            .checked_add(HANDSHAKE_BYTES)
            .ok_or(Error::ResourceExhausted)?;
        let next_handshake_bytes = usage
            .handshake_bytes
            .checked_add(HANDSHAKE_BYTES)
            .ok_or(Error::ResourceExhausted)?;
        if next_bytes > self.0.maximum
            || usage.handshakes >= MAX_HANDSHAKES
            || next_handshake_bytes > HANDSHAKE_TOTAL_BYTES
        {
            return Err(Error::ResourceExhausted);
        }
        usage.bytes = next_bytes;
        usage.peak = usage.peak.max(next_bytes);
        usage.handshakes += 1;
        usage.handshake_bytes = next_handshake_bytes;
        Ok(HandshakeReservation(self.0.clone(), true))
    }
}
impl Default for Budget {
    fn default() -> Self {
        Self::new(CONNECTION_BYTES)
    }
}
/// One exact candidate owner across Legacy and Pieces. Piece requests borrow it.
#[derive(Debug)]
pub struct BodyClaim {
    wire: Arc<body_ownership::WireAccount>,
    lease: body_ownership::Lease,
    deadline: Deadline,
    _charge: Reservation,
}
impl BodyClaim {
    pub(crate) fn account_identity(&self) -> u64 {
        self.lease.account_identity()
    }
    pub(crate) fn account_received_offer(&self, bytes: u64) -> Result<(), Error> {
        self.wire
            .reserve(bytes, Instant::now())
            .and_then(|ticket| ticket.finish(bytes))
            .map_err(|_| Error::ResourceExhausted)
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn cancellation(&self) -> Cancellation {
        Cancellation(self.lease.cancel.clone())
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn progress_attempt(&self) -> Option<usize> {
        usize::try_from(self.lease.generation()).ok()
    }
    #[cfg(any(feature = "eng2-runtime", test))]
    pub(crate) fn source_ordinal(&self) -> Option<usize> {
        self.deadline.check().ok()?;
        self.lease.source_ordinal()
    }
    /// A conservative planning read, never an allocation or query grant.
    pub(crate) fn can_query(&self, source: Hash, reserve: u8) -> bool {
        self.deadline.check().is_ok() && self.lease.can_query(source, reserve, Instant::now())
    }

    pub(crate) fn begin_query(&self, source: Hash) -> Result<(), Error> {
        self.deadline.check().map_err(io_error)?;
        self.lease
            .begin_query(source, Instant::now())
            .map_err(|error| match error {
                BodyClaimError::Capacity
                | BodyClaimError::SourceUsed
                | BodyClaimError::PreferUnused
                | BodyClaimError::QueryLimit => Error::ResourceExhausted,
                _ => Error::Unavailable,
            })
    }

    pub(crate) fn deadline(&self) -> &Deadline {
        &self.deadline
    }
    pub(crate) fn received(&self, bytes: usize, total: usize) -> Result<(), Error> {
        self.lease
            .received(bytes as u64, total as u64, Instant::now())
            .map_err(|_| Error::Unavailable)
    }
    pub(crate) fn decoded(&self) -> Result<(), Error> {
        self.deadline.check().map_err(io_error)?;
        self.lease
            .decoded(Instant::now())
            .map_err(|_| Error::Unavailable)
    }
    pub(crate) fn check_active(&self) -> Result<(), Error> {
        self.deadline.check().map_err(io_error)?;
        self.lease
            .check_active(Instant::now())
            .map_err(|_| Error::Unavailable)
    }
    pub(crate) fn complete(&self) {
        self.lease.complete();
    }
    pub(crate) fn matches(&self, budget: &Budget, binding: Binding, height: u64, id: Hash) -> bool {
        self.lease.matches(
            body_ownership::Key {
                context: [binding.network, binding.genesis, binding.verifier],
                height,
                id,
            },
            &budget.0.bodies,
        )
    }
}
#[derive(Debug)]
struct BodyBookCharge {
    budget: std::sync::Weak<BudgetInner>,
    bytes: usize,
}
impl Drop for BodyBookCharge {
    fn drop(&mut self) {
        if let Some(budget) = self.budget.upgrade() {
            let mut usage = budget.usage.lock().unwrap_or_else(|e| e.into_inner());
            usage.bytes = usage.bytes.saturating_sub(self.bytes);
        }
    }
}
/// Retain this guard for as long as the associated packet or extracted buffers
/// remain owned. Moving a payload out of Packet also requires moving its guard.
#[derive(Debug)]
pub struct Reservation {
    budget: Arc<BudgetInner>,
    bytes: usize,
}
impl Reservation {
    /// Return temporary workspace while retaining the charge for live buffers.
    /// This operation cannot acquire bytes or change the shared maximum.
    pub(crate) fn shrink_to(&mut self, bytes: usize) -> Result<(), Error> {
        if bytes > self.bytes {
            return Err(Error::ResourceExhausted);
        }
        let mut usage = self.budget.usage.lock().map_err(|_| Error::Unavailable)?;
        usage.bytes = usage
            .bytes
            .checked_sub(self.bytes - bytes)
            .ok_or(Error::Unavailable)?;
        self.bytes = bytes;
        Ok(())
    }
    #[cfg(feature = "native-p2p")]
    pub(crate) fn covers(&self, budget: &Budget, bytes: usize) -> bool {
        Arc::ptr_eq(&self.budget, &budget.0) && self.bytes >= bytes
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut usage = self
            .budget
            .usage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        usage.bytes = usage.bytes.saturating_sub(self.bytes);
    }
}
/// Opaque admission ownership, transferred by a provider without releasing its
/// shared byte charge. Only the node budget can create this guard.
pub struct HandshakeReservation(Arc<BudgetInner>, bool);
impl HandshakeReservation {
    fn established(mut self) -> Reservation {
        let budget = self.0.clone();
        {
            let mut usage = budget.usage.lock().unwrap_or_else(|p| p.into_inner());
            usage.handshakes = usage.handshakes.saturating_sub(1);
            usage.handshake_bytes = usage.handshake_bytes.saturating_sub(HANDSHAKE_BYTES);
        }
        // The reservation moves from the admission category to established
        // ownership in the same locked state; its byte charge never disappears.
        self.1 = false;
        Reservation {
            budget,
            bytes: HANDSHAKE_BYTES,
        }
    }
}
impl Drop for HandshakeReservation {
    fn drop(&mut self) {
        if !self.1 {
            return;
        }
        let mut usage = self
            .0
            .usage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        usage.bytes = usage.bytes.saturating_sub(HANDSHAKE_BYTES);
        usage.handshakes = usage.handshakes.saturating_sub(1);
        usage.handshake_bytes = usage.handshake_bytes.saturating_sub(HANDSHAKE_BYTES);
    }
}

#[cfg(feature = "eng2-runtime")]
#[derive(Clone, Debug, Default)]
pub(crate) struct ForwardingCandidate {
    outcome: Arc<std::sync::atomic::AtomicU8>,
    header_revoked: Cancellation,
    context_revoked: Cancellation,
}

#[cfg(feature = "eng2-runtime")]
impl ForwardingCandidate {
    pub(crate) fn new(header_revoked: Cancellation, context_revoked: Cancellation) -> Self {
        Self {
            header_revoked,
            context_revoked,
            ..Self::default()
        }
    }

    const AUTHENTICATED: u8 = 1;
    const ACCEPTED: u8 = 2;
    const DRAIN: u8 = Self::AUTHENTICATED | Self::ACCEPTED;
    const ABANDONED: u8 = 4;

    pub(crate) fn authenticated(&self) {
        self.outcome
            .fetch_or(Self::AUTHENTICATED, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn accepted(&self) {
        self.outcome
            .fetch_or(Self::ACCEPTED, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn abandon_unless_accepted(&self) {
        use std::sync::atomic::Ordering;
        let _ = self
            .outcome
            .try_update(Ordering::AcqRel, Ordering::Acquire, |outcome| {
                (outcome & Self::DRAIN != Self::DRAIN).then_some(outcome | Self::ABANDONED)
            });
    }

    #[cfg(unix)]
    pub(crate) fn is_revoked(&self) -> bool {
        self.status().0
    }

    fn status(&self) -> (bool, bool) {
        let outcome = self.outcome.load(std::sync::atomic::Ordering::Acquire);
        let revoked = outcome & Self::ABANDONED != 0
            || self.header_revoked.is_cancelled()
            || self.context_revoked.is_cancelled();
        (revoked, outcome & Self::DRAIN == Self::DRAIN)
    }
}

#[cfg(feature = "eng2-runtime")]
#[derive(Clone, Debug)]
struct ForwardingGuard {
    shutdown: Cancellation,
    transfer_cancelled: Cancellation,
    candidate: ForwardingCandidate,
}

#[derive(Clone, Debug)]
pub(crate) struct Deadline {
    started: Instant,
    limit: Duration,
    cancellation: Cancellation,
    body_cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
    #[cfg(feature = "eng2-runtime")]
    read_completion: Option<Cancellation>,
    #[cfg(feature = "eng2-runtime")]
    forwarding: Option<ForwardingGuard>,
    #[cfg(test)]
    elapsed: Option<Arc<std::sync::atomic::AtomicU64>>,
}
impl Deadline {
    pub(crate) fn from_started(
        started: Instant,
        limit: Duration,
        cancellation: Cancellation,
    ) -> Self {
        Self {
            started,
            limit,
            cancellation,
            body_cancellation: None,
            #[cfg(feature = "eng2-runtime")]
            read_completion: None,
            #[cfg(feature = "eng2-runtime")]
            forwarding: None,
            #[cfg(test)]
            elapsed: None,
        }
    }
    pub(crate) fn new(limit: Duration) -> Self {
        Self::from_started(Instant::now(), limit, Cancellation::default())
    }
    #[cfg(any(feature = "eng2-runtime", test))]
    pub(crate) fn cancellable(limit: Duration, cancellation: Cancellation) -> Self {
        let mut deadline = Self::new(limit);
        deadline.cancellation = cancellation;
        deadline
    }
    #[cfg(test)]
    pub(crate) fn test_clock(limit: Duration, clock: Arc<std::sync::atomic::AtomicU64>) -> Self {
        let mut deadline = Self::new(limit);
        deadline.elapsed = Some(clock);
        deadline
    }
    #[cfg(all(unix, feature = "eng2-runtime"))]
    pub(crate) fn cancellation(&self) -> &Cancellation {
        &self.cancellation
    }
    pub(crate) fn for_body_claim(&self, claim: &BodyClaim) -> Self {
        self.for_body_lease(&claim.lease)
    }
    fn for_body_lease(&self, lease: &body_ownership::Lease) -> Self {
        let mut result = self.clone();
        let expires = result.expires_at().min(lease.expires);
        result.started = lease.first;
        result.limit = expires.saturating_duration_since(lease.first);
        result.body_cancellation = Some(lease.cancel.clone());
        result
    }
    /// An already authorized forwarding exchange may drain its authenticated
    /// bytes after local admission releases its claim. It keeps the original
    /// absolute deadline and remains interruptible by resident shutdown.
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn for_candidate_forwarding(
        mut self,
        shutdown: Cancellation,
        transfer_cancelled: Cancellation,
        candidate: ForwardingCandidate,
    ) -> Self {
        self.forwarding = Some(ForwardingGuard {
            shutdown,
            transfer_cancelled,
            candidate,
        });
        self
    }
    /// A sibling lane completed this exact body. Cancel only redundant reads;
    /// the owner deadline and downstream forwarding remain unchanged.
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn until_body_read_complete(mut self, completion: Cancellation) -> Self {
        self.read_completion = Some(completion);
        self
    }
    pub(crate) fn capped_at(mut self, expires: Instant) -> Self {
        self.limit = self
            .limit
            .min(expires.saturating_duration_since(self.started));
        self
    }
    pub(crate) fn expires_at(&self) -> Instant {
        self.started + self.limit
    }
    pub(crate) fn check(&self) -> io::Result<()> {
        self.check_at(Instant::now())
    }
    pub(crate) fn check_at(&self, now: Instant) -> io::Result<()> {
        #[cfg(feature = "eng2-runtime")]
        if self
            .read_completion
            .as_ref()
            .is_some_and(Cancellation::is_cancelled)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "body already received",
            ));
        }
        // Read lease retirement before the admission outcome. Successful
        // admission publishes the outcome before retiring the exact lease.
        let lease_cancelled = self.cancellation.is_cancelled()
            || self
                .body_cancellation
                .as_ref()
                .is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire));
        #[cfg(feature = "eng2-runtime")]
        let forwarding = self.forwarding.as_ref();
        #[cfg(feature = "eng2-runtime")]
        let (shutdown, drain) = forwarding.map_or((false, false), |guard| {
            let (revoked, drain) = guard.candidate.status();
            (
                revoked || guard.shutdown.is_cancelled() || guard.transfer_cancelled.is_cancelled(),
                drain,
            )
        });
        #[cfg(not(feature = "eng2-runtime"))]
        let (shutdown, drain) = (false, false);
        if shutdown || (!drain && lease_cancelled) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native admission cancelled",
            ));
        }
        #[cfg(test)]
        let elapsed = self.elapsed.as_ref().map_or_else(
            || now.saturating_duration_since(self.started),
            |clock| Duration::from_millis(clock.load(std::sync::atomic::Ordering::Relaxed)),
        );
        #[cfg(not(test))]
        let elapsed = now.saturating_duration_since(self.started);
        if elapsed >= self.limit {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native operation deadline",
            ));
        }
        Ok(())
    }
}

/// A handshake role, independent of a peer's mining or validation role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionRole {
    Initiator,
    Responder,
}

/// Cooperative admission cancellation. A provider must additionally interrupt
/// blocked I/O; observing this flag only before and after a read is insufficient.
#[derive(Clone, Debug, Default)]
pub struct Cancellation(Arc<std::sync::atomic::AtomicBool>);
impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Expected cryptographic identity. Outbound destinations require an independent
/// pin; an inbound miner may instead present a signed, network-bound descriptor.
#[derive(Clone, Debug)]
pub struct ExpectedPeer {
    binding: Binding,
    descriptor: Descriptor,
    pin: Option<PeerPin>,
}
impl ExpectedPeer {
    pub fn from_pinned_descriptor(
        binding: Binding,
        descriptor: Descriptor,
        pin: PeerPin,
    ) -> Result<Self, Error> {
        if descriptor.binding() != binding {
            return Err(Error::InvalidProtocol);
        }
        pin.verify(&descriptor)
            .map_err(|_| Error::InvalidProtocol)?;
        Ok(Self {
            binding,
            descriptor,
            pin: Some(pin),
        })
    }
    /// Possession is still verified by the complete hybrid handshake. This
    /// grants no checkpoint-signing or control-plane authority.
    #[cfg(feature = "native-p2p")]
    pub(crate) fn from_presented_descriptor(
        binding: Binding,
        descriptor: Descriptor,
    ) -> Result<Self, Error> {
        if descriptor.binding() != binding {
            return Err(Error::InvalidProtocol);
        }
        Ok(Self {
            binding,
            descriptor,
            pin: None,
        })
    }
    pub(crate) fn independently_pinned(&self) -> bool {
        self.pin.is_some()
    }
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub fn fingerprint(&self) -> Hash {
        self.descriptor.fingerprint()
    }
}

/// Immutable expected identity, connection role and one provider-to-Hello
/// admission budget. The caller fixes the expected identity before TLS; the
/// provider cannot replace it. Unregistered identities are inbound-only.
#[derive(Clone)]
pub struct AdmissionContext {
    expected: ExpectedPeer,
    role: ConnectionRole,
    deadline: Deadline,
}
impl AdmissionContext {
    pub fn new(expected: ExpectedPeer, role: ConnectionRole, cancellation: Cancellation) -> Self {
        Self::new_started(expected, role, cancellation, Instant::now())
    }
    /// Starts the shared deadline before routing or dialing a peer.
    pub fn new_started(
        expected: ExpectedPeer,
        role: ConnectionRole,
        cancellation: Cancellation,
        started: Instant,
    ) -> Self {
        let mut deadline = Deadline::new(HELLO_TIMEOUT);
        deadline.started = started;
        deadline.cancellation = cancellation;
        Self {
            expected,
            role,
            deadline,
        }
    }
    pub fn binding(&self) -> Binding {
        self.expected.binding
    }
    pub fn role(&self) -> ConnectionRole {
        self.role
    }
    pub fn expected_peer(&self) -> &ExpectedPeer {
        &self.expected
    }
    pub fn deadline(&self) -> Instant {
        self.deadline.started + self.deadline.limit
    }
    pub fn cancellation(&self) -> &Cancellation {
        &self.deadline.cancellation
    }
    pub fn check(&self) -> Result<(), Error> {
        if !self.expected.independently_pinned() && self.role != ConnectionRole::Responder {
            return Err(Error::InvalidProtocol);
        }
        self.deadline.check().map_err(io_error)
    }
    fn same_attempt(&self, other: &Self) -> bool {
        self.binding() == other.binding()
            && self.role == other.role
            && self.expected.fingerprint() == other.expected.fingerprint()
            && self.deadline.started == other.deadline.started
            && self.deadline.limit == other.deadline.limit
            && Arc::ptr_eq(
                &self.deadline.cancellation.0,
                &other.deadline.cancellation.0,
            )
    }
}

/// Parameters reported by a reviewed provider from its completed TLS state.
/// Validating these values is only an interface guard, not evidence that TLS,
/// either identity signature or the exporter binding was actually verified.
pub struct NegotiatedParameters<'a> {
    pub tls_version: u16,
    pub group: u16,
    pub cipher_suite: u16,
    pub alpn: &'a [u8],
    pub resumed: bool,
    pub early_data: bool,
}
impl NegotiatedParameters<'_> {
    fn validate(&self) -> Result<(), Error> {
        if self.tls_version != 0x0304
            || self.group != 0x11ec
            || self.cipher_suite != 0x1303
            || !(self.alpn == b"/siworld/native-hybrid/1" || self.alpn == CHECKPOINT_ALPN)
            || self.resumed
            || self.early_data
        {
            return Err(Error::InvalidProtocol);
        }
        Ok(())
    }
}
pub(crate) trait WireFence: Send + Sync {
    /// Check the complete bounded frame/range before allocation or I/O.
    fn check_wire(&self, bytes: u64) -> io::Result<()>;
    /// Record only actual bytes, including a partial failed frame.
    fn account_wire(&self, bytes: u64) -> io::Result<()>;
}
struct Timed<'a, S> {
    fence: Option<&'a dyn WireFence>,
    body_wire: Option<&'a body_ownership::WireAccount>,
    channel: &'a mut S,
    deadline: Deadline,
    totals: Option<&'a mut IoTotals>,
}
impl<S: Read> Read for Timed<'_, S> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.deadline.check()?;
        if let Some(fence) = self.fence {
            fence.check_wire(bytes.len() as u64)?;
        }
        let ticket = self
            .body_wire
            .map(|wire| wire.reserve(bytes.len() as u64, Instant::now()))
            .transpose()
            .map_err(|_| io::Error::other("body wire budget unavailable"))?;
        let result = self.channel.read(bytes);
        let actual = result.as_ref().copied().unwrap_or(0);
        let counted = self.totals.as_mut().map_or(Ok(()), |totals| {
            totals
                .received
                .checked_add(actual as u64)
                .map(|next| totals.received = next)
                .ok_or_else(|| io::Error::other("application byte counter exhausted"))
        });
        let charged = ticket.map(|t| t.finish(actual as u64)).transpose();
        let outer = self
            .fence
            .map(|f| f.account_wire(actual as u64))
            .transpose();
        // Settle both accounts before returning any counter or meter error.
        counted?;
        charged.map_err(|_| io::Error::other("body wire accounting unavailable"))?;
        outer?;
        let read = result?;
        self.deadline.check()?;
        Ok(read)
    }
}
impl<S: Write> Write for Timed<'_, S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.deadline.check()?;
        if let Some(fence) = self.fence {
            fence.check_wire(bytes.len() as u64)?;
        }
        let ticket = self
            .body_wire
            .map(|wire| wire.reserve(bytes.len() as u64, Instant::now()))
            .transpose()
            .map_err(|_| io::Error::other("body wire budget unavailable"))?;
        let result = self.channel.write(bytes);
        let actual = result.as_ref().copied().unwrap_or(0);
        let counted = self.totals.as_mut().map_or(Ok(()), |totals| {
            totals
                .sent
                .checked_add(actual as u64)
                .map(|next| totals.sent = next)
                .ok_or_else(|| io::Error::other("application byte counter exhausted"))
        });
        let charged = ticket.map(|t| t.finish(actual as u64)).transpose();
        let outer = self
            .fence
            .map(|f| f.account_wire(actual as u64))
            .transpose();
        // Settle both accounts before returning any counter or meter error.
        counted?;
        charged.map_err(|_| io::Error::other("body wire accounting unavailable"))?;
        outer?;
        let written = result?;
        self.deadline.check()?;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.deadline.check()?;
        loop {
            self.deadline.check()?;
            match self.channel.flush() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => {
                    result?;
                    return self.deadline.check();
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Bootstrap = 1,
    Validator = 2,
    Miner = 3,
    Wallet = 4,
}
impl Role {
    fn decode(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Bootstrap),
            2 => Ok(Self::Validator),
            3 => Ok(Self::Miner),
            4 => Ok(Self::Wallet),
            _ => Err(Error::InvalidProtocol),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub network: Hash,
    pub genesis: Hash,
    pub verifier: Hash,
}
impl Binding {
    pub fn new(config: &Config) -> Self {
        let mut hash = blake3::Hasher::new_derive_key("siworld native peer verifier manifest v1");
        hash.update(SUITE_ID);
        hash.update(include_bytes!(
            "../../bench-multi-asset/artifacts/v1-native-proof-profiles.json"
        ));
        Self {
            network: config.network,
            genesis: config.genesis_id(),
            verifier: *hash.finalize().as_bytes(),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello {
    pub binding: Binding,
    pub role: Role,
}
impl Hello {
    pub fn encode(self) -> [u8; HELLO_BYTES] {
        let mut out = [0; HELLO_BYTES];
        out[..4].copy_from_slice(b"SWPH");
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[6..38].copy_from_slice(&self.binding.network);
        out[38..70].copy_from_slice(&self.binding.genesis);
        out[70..102].copy_from_slice(&self.binding.verifier);
        out[102] = self.role as u8;
        out
    }
    pub fn decode(bytes: &[u8; HELLO_BYTES], expected: &Binding) -> Result<Self, Error> {
        if &bytes[..4] != b"SWPH"
            || bytes[4..6] != VERSION.to_le_bytes()
            || bytes[6..38] != expected.network
            || bytes[38..70] != expected.genesis
            || bytes[70..102] != expected.verifier
        {
            return Err(Error::InvalidProtocol);
        }
        Ok(Self {
            binding: *expected,
            role: Role::decode(bytes[102])?,
        })
    }
}
/// Capability produced only inside this crate after a reviewed provider verifies
/// hybrid identity, transcript and both key confirmations. The opt-in
/// engineering provider owns record authentication, sequence numbers,
/// connection limits and secret cleanup.
pub struct Authenticated<S> {
    channel: S,
    admission: AdmissionContext,
    #[cfg(feature = "native-p2p")]
    checkpoints: bool,
}
impl<S> Authenticated<S> {
    // Reserved for a separately reviewed in-crate hybrid provider. Keeping the
    // constructor crate-private prevents external callers minting capabilities.
    #[allow(dead_code)]
    pub(crate) fn from_verified_provider(
        channel: S,
        admission: &AdmissionContext,
        observed_role: ConnectionRole,
        observed_peer: &Descriptor,
        parameters: NegotiatedParameters<'_>,
    ) -> Result<Self, Error> {
        admission.check()?;
        parameters.validate()?;
        if observed_role != admission.role || observed_peer.binding() != admission.binding() {
            return Err(Error::InvalidProtocol);
        }
        if observed_peer.fingerprint() != admission.expected.fingerprint()
            || observed_peer.ed25519_public() != admission.expected.descriptor.ed25519_public()
            || observed_peer.ml_dsa_public() != admission.expected.descriptor.ml_dsa_public()
        {
            return Err(Error::InvalidProtocol);
        }
        if let Some(pin) = &admission.expected.pin {
            pin.verify(observed_peer)
                .map_err(|_| Error::InvalidProtocol)?;
        }
        admission.check()?;
        Ok(Self {
            channel,
            admission: admission.clone(),
            #[cfg(feature = "native-p2p")]
            checkpoints: parameters.alpn == CHECKPOINT_ALPN,
        })
    }
}
pub trait HybridAuthenticator {
    type Channel: Read + Write;
    /// Must complete X25519+ML-KEM and Ed25519+ML-DSA authentication by the
    /// context's role, fixed expected full descriptor and original
    /// absolute deadline, with no classical fallback. Provider state must fit
    /// HANDSHAKE_BYTES. It must interrupt blocked I/O on deadline/cancellation;
    /// a cooperative flag or a wrapper cannot preempt blocked I/O by itself.
    fn authenticate(
        &mut self,
        socket: TcpStream,
        admission: &AdmissionContext,
    ) -> Result<Authenticated<Self::Channel>, Error>;
    /// Keeps the node's original reservation through provider authentication.
    /// Concrete providers may consume it internally, but must return the same
    /// live guard after success. Failure drops all admission-owned state.
    fn authenticate_reserved(
        &mut self,
        socket: TcpStream,
        admission: &AdmissionContext,
        permit: HandshakeReservation,
    ) -> Result<(Authenticated<Self::Channel>, HandshakeReservation), Error> {
        self.authenticate(socket, admission)
            .map(|auth| (auth, permit))
    }
}
/// No default authenticator or unauthenticated production constructor exists.
/// Discard a session after any framing/I/O error; reconnecting requires a fresh
/// provider authentication rather than continuing a partially consumed frame.
/// Authenticated application-stream bytes, including frame headers and partial
/// transfers. These counters exclude the underlying encrypted record format.
#[derive(Clone, Copy, Debug, Default)]
pub struct IoTotals {
    pub received: u64,
    pub sent: u64,
}

pub struct Session<S> {
    body_wire: Option<Arc<body_ownership::WireAccount>>,
    wire_fence: Option<Arc<dyn WireFence>>,
    channel: S,
    binding: Binding,
    peer: Hash,
    role: Role,
    budget: Budget,
    totals: IoTotals,
    _transport: Option<Reservation>,
    #[cfg(feature = "native-p2p")]
    checkpoints: bool,
}
pub enum Packet {
    Control {
        kind: u8,
        request: u64,
        body: Vec<u8>,
        reservation: Reservation,
    },
    Block {
        request: u64,
        block: Box<Block>,
        reservation: Reservation,
    },
}
impl<S: Read + Write> Session<S> {
    pub fn establish(
        auth: Authenticated<S>,
        admission: &AdmissionContext,
        role: Role,
        budget: Budget,
    ) -> Result<Self, Error> {
        let permit = budget.handshake()?;
        Self::establish_reserved(auth, admission, role, budget, permit)
    }
    fn establish_reserved(
        auth: Authenticated<S>,
        admission: &AdmissionContext,
        role: Role,
        budget: Budget,
        permit: HandshakeReservation,
    ) -> Result<Self, Error> {
        if !auth.admission.same_attempt(admission) || !Arc::ptr_eq(&permit.0, &budget.0) {
            return Err(Error::InvalidProtocol);
        }
        admission.check()?;
        let binding = admission.binding();
        #[cfg(feature = "native-p2p")]
        let checkpoints = auth.checkpoints;
        let mut channel = auth.channel;
        let mut timed = Timed {
            channel: &mut channel,
            deadline: admission.deadline.clone(),
            fence: None,
            body_wire: None,
            totals: None,
        };
        timed
            .write_all(&Hello { binding, role }.encode())
            .map_err(io_error)?;
        timed.flush().map_err(io_error)?;
        let mut hello = [0; HELLO_BYTES];
        timed.read_exact(&mut hello).map_err(io_error)?;
        let hello = Hello::decode(&hello, &binding)?;
        admission.check()?;
        Ok(Self {
            channel,
            binding,
            peer: admission.expected.fingerprint(),
            role: hello.role,
            budget,
            totals: IoTotals::default(),
            wire_fence: None,
            body_wire: None,
            _transport: Some(permit.established()),
            #[cfg(feature = "native-p2p")]
            checkpoints,
        })
    }
    pub(crate) fn shares_budget(&self, budget: &Budget) -> bool {
        Arc::ptr_eq(&self.budget.0, &budget.0)
    }
    #[cfg(any(feature = "eng2-runtime", test))]
    pub(crate) fn set_wire_fence(
        &mut self,
        fence: Option<Arc<dyn WireFence>>,
    ) -> Result<(), Error> {
        if self.wire_fence.is_some() && fence.is_some() {
            return Err(Error::InvalidProtocol);
        }
        self.wire_fence = fence;
        Ok(())
    }
    pub(crate) fn set_body_accounting(&mut self, claim: Option<&BodyClaim>) -> Result<(), Error> {
        if self.body_wire.is_some() && claim.is_some() {
            return Err(Error::InvalidProtocol);
        }
        self.body_wire = claim.map(|c| c.wire.clone());
        Ok(())
    }
    fn check_wire(&self, bytes: usize) -> Result<(), Error> {
        if let Some(wire) = &self.body_wire {
            wire.check(bytes as u64, Instant::now())
                .map_err(|_| Error::ResourceExhausted)?;
        }
        if let Some(fence) = &self.wire_fence {
            fence.check_wire(bytes as u64).map_err(io_error)?;
        }
        Ok(())
    }
    pub fn io_totals(&self) -> IoTotals {
        self.totals
    }
    pub(crate) fn binding(&self) -> Binding {
        self.binding
    }
    pub(crate) fn shared_budget(&self) -> Budget {
        self.budget.clone()
    }
    #[cfg(feature = "native-p2p")]
    pub(crate) fn checkpoints_enabled(&self) -> bool {
        self.checkpoints
    }
    pub fn peer(&self) -> Hash {
        self.peer
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn send_control(&mut self, kind: u8, request: u64, body: &[u8]) -> Result<(), Error> {
        self.send_control_before(kind, request, body, &Deadline::new(CONTROL_TIMEOUT))
    }
    /// Keep the caller's absolute phase deadline across every write and flush.
    pub(crate) fn send_control_before(
        &mut self,
        kind: u8,
        request: u64,
        body: &[u8],
        deadline: &Deadline,
    ) -> Result<(), Error> {
        if kind == BLOCK {
            return Err(Error::InvalidProtocol);
        }
        let header = frame_header(kind, request, &self.binding.network, body.len())?;
        self.check_wire(
            HEADER_BYTES
                .checked_add(body.len())
                .ok_or(Error::ResourceExhausted)?,
        )?;
        let _reservation = self.budget.reserve(
            body.len()
                .checked_add(HEADER_BYTES + 64)
                .ok_or(Error::ResourceExhausted)?,
        )?;
        let mut timed = Timed {
            channel: &mut self.channel,
            deadline: deadline.clone(),
            totals: Some(&mut self.totals),
            fence: self.wire_fence.as_deref(),
            body_wire: self.body_wire.as_deref(),
        };
        timed.write_all(&header).map_err(io_error)?;
        timed.write_all(body).map_err(io_error)?;
        timed.flush().map_err(io_error)
    }
    pub fn send_block(&mut self, request: u64, block: &Block) -> Result<(), Error> {
        // Refuse malformed local state before emitting even a frame header.
        if block.network != self.binding.network {
            return Err(Error::InvalidProtocol);
        }
        block.validate_shape().map_err(|_| Error::InvalidProtocol)?;
        let length = block.encoded_len().map_err(|_| Error::InvalidProtocol)?;
        let reservation = self
            .budget
            .reserve(length.checked_add(65536).ok_or(Error::ResourceExhausted)?)?;
        self.send_reserved_block(request, block, &reservation)
    }
    /// Stream buffers already covered by the same node's batch reservation.
    /// The caller retains that guard until every owned batch block is dropped.
    pub(crate) fn send_reserved_block(
        &mut self,
        request: u64,
        block: &Block,
        reservation: &Reservation,
    ) -> Result<(), Error> {
        if block.network != self.binding.network
            || !Arc::ptr_eq(&reservation.budget, &self.budget.0)
        {
            return Err(Error::InvalidProtocol);
        }
        block.validate_shape().map_err(|_| Error::InvalidProtocol)?;
        let length = block.encoded_len().map_err(|_| Error::InvalidProtocol)?;
        if length
            .checked_add(65536)
            .is_none_or(|n| n > reservation.bytes)
        {
            return Err(Error::ResourceExhausted);
        }
        let header = frame_header(BLOCK, request, &self.binding.network, length)?;
        let mut timed = Timed {
            channel: &mut self.channel,
            deadline: Deadline::new(BLOCK_TIMEOUT),
            totals: Some(&mut self.totals),
            fence: self.wire_fence.as_deref(),
            body_wire: self.body_wire.as_deref(),
        };
        timed.write_all(&header).map_err(io_error)?;
        block.write_to(&mut timed).map_err(io_error)?;
        timed.flush().map_err(io_error)
    }
    pub fn receive(&mut self) -> Result<Packet, Error> {
        self.receive_deadline(Deadline::new(CONTROL_TIMEOUT))
    }
    /// Reuses one monotonic deadline across a multi-frame exchange. Giving
    /// each missing-slot envelope a fresh deadline would let a slow sender
    /// extend one compact recovery for every transaction in the block.
    pub(crate) fn receive_before(&mut self, deadline: &Deadline) -> Result<Packet, Error> {
        self.receive_deadline(deadline.clone())
    }
    /// Eng-2 rejects V1 block frames before their payload is allocated.
    pub(crate) fn receive_eng2_before(&mut self, deadline: &Deadline) -> Result<Packet, Error> {
        self.receive_frame(deadline.clone(), Some(&[ENG2_MESSAGE]))
    }
    /// An eng-2 application phase bounds both header and body by the same
    /// absolute deadline and rejects its smaller frame cap before allocation.
    pub(crate) fn receive_eng2_application_before(
        &mut self,
        deadline: &Deadline,
        maximum: usize,
    ) -> Result<Packet, Error> {
        self.receive_frame_policy(
            deadline.clone(),
            Some(&[ENG2_MESSAGE]),
            Some(maximum),
            false,
        )
    }
    /// A paired sync request may follow synchronous proof verification by the
    /// remote owner. Only its header uses the caller's absolute wait bound;
    /// its bounded control body still has the ordinary ten-second deadline.
    #[cfg(any(feature = "native-p2p", test))]
    pub(crate) fn receive_sync_request_before(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Packet, Error> {
        self.receive_frame(deadline.clone(), Some(&[GET_BLOCKS]))
    }
    #[cfg(feature = "native-p2p")]
    pub(crate) fn receive_checkpoint_before(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Packet, Error> {
        if !self.checkpoints {
            return Err(Error::InvalidProtocol);
        }
        self.receive_frame(deadline.clone(), Some(&[CHECKPOINT]))
    }
    /// A resident relay follows remote canonical validation. Wait for its
    /// header within one exchange, then retain the ten-second body limit.
    #[cfg(feature = "native-p2p")]
    pub(crate) fn receive_relay_before(&mut self, deadline: &Deadline) -> Result<Packet, Error> {
        self.receive_frame(
            deadline.clone(),
            Some(&[TRANSACTION, END_BATCH, UNAVAILABLE]),
        )
    }
    fn receive_deadline(&mut self, deadline: Deadline) -> Result<Packet, Error> {
        self.receive_frame(deadline, None)
    }
    fn receive_frame(
        &mut self,
        deadline: Deadline,
        permitted_control: Option<&[u8]>,
    ) -> Result<Packet, Error> {
        self.receive_frame_policy(deadline, permitted_control, None, true)
    }
    fn receive_frame_policy(
        &mut self,
        mut deadline: Deadline,
        permitted_control: Option<&[u8]>,
        maximum: Option<usize>,
        reset_body_deadline: bool,
    ) -> Result<Packet, Error> {
        let mut header = [0; HEADER_BYTES];
        Timed {
            channel: &mut self.channel,
            deadline: deadline.clone(),
            totals: Some(&mut self.totals),
            fence: self.wire_fence.as_deref(),
            body_wire: self.body_wire.as_deref(),
        }
        .read_exact(&mut header)
        .map_err(io_error)?;
        if &header[..4] != b"SWPF"
            || header[4..6] != VERSION.to_le_bytes()
            || header[15..47] != self.binding.network
        {
            return Err(Error::InvalidProtocol);
        }
        let kind = header[6];
        let request = u64::from_le_bytes(header[7..15].try_into().expect("fixed request"));
        let length = u32::from_le_bytes(header[47..51].try_into().expect("fixed length")) as usize;
        if permitted_control.is_some_and(|allowed| !allowed.contains(&kind)) {
            return Err(Error::InvalidProtocol);
        }
        frame_header(kind, request, &self.binding.network, length)?;
        if maximum.is_some_and(|maximum| length > maximum) {
            return Err(Error::ResourceExhausted);
        }
        if permitted_control.is_some() && reset_body_deadline {
            let mut body_deadline = Deadline::new(CONTROL_TIMEOUT);
            body_deadline.cancellation = deadline.cancellation.clone();
            deadline = body_deadline;
        }
        self.check_wire(length)?;
        let extra = if kind == BLOCK {
            MAX_ENVELOPE_BYTES + 65536
        } else {
            64
        };
        let reservation = self
            .budget
            .reserve(length.checked_add(extra).ok_or(Error::ResourceExhausted)?)?;
        if kind == BLOCK {
            deadline.limit = BLOCK_TIMEOUT;
            let mut timed = Timed {
                channel: &mut self.channel,
                deadline,
                totals: Some(&mut self.totals),
                fence: self.wire_fence.as_deref(),
                body_wire: self.body_wire.as_deref(),
            };
            let block =
                Block::read_from(&mut timed, length, &self.binding.network).map_err(io_error)?;
            timed.deadline.check().map_err(io_error)?;
            Ok(Packet::Block {
                request,
                block: Box::new(block),
                reservation,
            })
        } else {
            let mut body = Vec::new();
            body.try_reserve_exact(length)
                .map_err(|_| Error::ResourceExhausted)?;
            body.resize(length, 0);
            let mut timed = Timed {
                channel: &mut self.channel,
                deadline,
                totals: Some(&mut self.totals),
                fence: self.wire_fence.as_deref(),
                body_wire: self.body_wire.as_deref(),
            };
            timed.read_exact(&mut body).map_err(io_error)?;
            timed.deadline.check().map_err(io_error)?;
            Ok(Packet::Control {
                kind,
                request,
                body,
                reservation,
            })
        }
    }
    #[cfg(test)]
    pub(crate) fn test_channel(&self) -> &S {
        &self.channel
    }
    #[cfg(all(test, feature = "eng2-runtime"))]
    pub(crate) fn from_test_peer_channel(
        channel: S,
        binding: Binding,
        budget: Budget,
        peer: Hash,
        role: Role,
    ) -> Self {
        let mut session = Self::from_test_channel(channel, binding, budget);
        session.peer = peer;
        session.role = role;
        session
    }
    #[cfg(test)]
    pub(crate) fn from_test_channel(channel: S, binding: Binding, budget: Budget) -> Self {
        Self {
            channel,
            binding,
            peer: [9; 32],
            role: Role::Validator,
            budget,
            totals: IoTotals::default(),
            wire_fence: None,
            body_wire: None,
            _transport: None,
            #[cfg(feature = "native-p2p")]
            checkpoints: false,
        }
    }
}
fn frame_header(
    kind: u8,
    request: u64,
    network: &Hash,
    length: usize,
) -> Result<[u8; HEADER_BYTES], Error> {
    if !(GET_BLOCKS..=ENG2_MESSAGE).contains(&kind) {
        return Err(Error::InvalidProtocol);
    }
    let maximum = if kind == BLOCK {
        MAX_BLOCK_BYTES
    } else if kind == GET_CHECKPOINT_DATA {
        41
    } else if kind == CHECKPOINT {
        MAX_CHECKPOINT_EXCHANGE_BYTES
    } else if kind == COMPACT_BLOCK {
        MAX_COMPACT_BYTES
    } else {
        MAX_CONTROL_BYTES
    };
    if length > maximum {
        return Err(Error::ResourceExhausted);
    }
    let mut header = [0; HEADER_BYTES];
    header[..4].copy_from_slice(b"SWPF");
    header[4..6].copy_from_slice(&VERSION.to_le_bytes());
    header[6] = kind;
    header[7..15].copy_from_slice(&request.to_le_bytes());
    header[15..47].copy_from_slice(network);
    header[47..].copy_from_slice(&(length as u32).to_le_bytes());
    Ok(header)
}
fn timeout(socket: &TcpStream) -> Result<(), Error> {
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(io_error)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(io_error)
}
pub fn accept_once<A: HybridAuthenticator>(
    listener: &TcpListener,
    auth: &mut A,
    expected: &ExpectedPeer,
    role: Role,
    budget: Budget,
    cancellation: Cancellation,
) -> Result<Session<A::Channel>, Error> {
    let (socket, _) = listener.accept().map_err(io_error)?;
    let admission =
        AdmissionContext::new(expected.clone(), ConnectionRole::Responder, cancellation);
    establish_socket(socket, auth, &admission, role, budget)
}
/// Completes one already accepted or dialed socket using a context created
/// before any routing prefix. No peer may refresh the context after TLS starts.
pub fn establish_socket<A: HybridAuthenticator>(
    socket: TcpStream,
    auth: &mut A,
    admission: &AdmissionContext,
    role: Role,
    budget: Budget,
) -> Result<Session<A::Channel>, Error> {
    admission.check()?;
    let permit = budget.handshake()?;
    timeout(&socket)?;
    let (channel, permit) = auth.authenticate_reserved(socket, admission, permit)?;
    admission.check()?;
    Session::establish_reserved(channel, admission, role, budget, permit)
}

pub fn connect<A: HybridAuthenticator>(
    endpoint: SocketAddr,
    auth: &mut A,
    expected: &ExpectedPeer,
    role: Role,
    budget: Budget,
    cancellation: Cancellation,
) -> Result<Session<A::Channel>, Error> {
    let permit = budget.handshake()?;
    let admission =
        AdmissionContext::new(expected.clone(), ConnectionRole::Initiator, cancellation);
    admission.check()?;
    let remaining = admission
        .deadline()
        .saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Error::Unavailable);
    }
    let socket = TcpStream::connect_timeout(&endpoint, remaining).map_err(io_error)?;
    admission.check()?;
    timeout(&socket)?;
    let (channel, permit) = auth.authenticate_reserved(socket, &admission, permit)?;
    admission.check()?;
    Session::establish_reserved(channel, &admission, role, budget, permit)
}
#[cfg(test)]
mod admission_tests;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod observed_budget_tests {
    use super::*;
    #[test]
    fn observed_reservation_distinguishes_contention_overflow_and_poison() {
        let budget = Budget::new(100);
        let held = budget.reserve(80).unwrap();
        assert!(matches!(
            budget.reserve_observed(21),
            Err(ReserveFailure::Exhausted(ByteUsage {
                maximum: 100,
                used: 80
            }))
        ));
        assert_eq!(budget.available().unwrap(), 20);
        assert!(matches!(
            budget.reserve_observed(usize::MAX),
            Err(ReserveFailure::Overflow)
        ));
        assert_eq!(budget.available().unwrap(), 20);
        drop(held);
        let (owned, observed) = budget.reserve_observed(21).unwrap();
        assert_eq!(
            observed,
            ByteUsage {
                maximum: 100,
                used: 21
            }
        );
        drop(owned);
        assert_eq!(budget.available().unwrap(), 100);
        let poisoned = budget.clone();
        assert!(
            std::thread::spawn(move || {
                let _lock = poisoned.0.usage.lock().unwrap();
                panic!("bounded budget poison fixture");
            })
            .join()
            .is_err()
        );
        assert!(matches!(
            budget.reserve_observed(1),
            Err(ReserveFailure::Unavailable)
        ));
    }
}
