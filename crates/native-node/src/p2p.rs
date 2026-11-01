//! Bounded native protocol over an externally authenticated hybrid channel.
//! No production authenticator or classical/plaintext fallback is supplied.
//! The identity, combiner and record-layer implementation require separate review.
use crate::identity::{Descriptor, PeerPin};
use crate::state::Config;
use crate::wire::{Block, Hash, MAX_BLOCK_BYTES, MAX_ENVELOPE_BYTES, SUITE_ID};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const VERSION: u16 = 1;
pub const MAX_CONTROL_BYTES: usize = 1024 * 1024;
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
    handshakes: usize,
    handshake_bytes: usize,
}
#[derive(Debug)]
struct BudgetInner {
    maximum: usize,
    usage: Mutex<Usage>,
}
/// Shared logical ownership budget. Every listener, outbound connection and
/// retained packet for one node must receive clones of the same instance.
/// Handshake reservations consume this same maximum, in addition to their
/// category-specific count and byte caps.
/// This does not replace a process-level charged-memory guard.
#[derive(Clone, Debug)]
pub struct Budget(Arc<BudgetInner>);
impl Budget {
    pub fn new(maximum: usize) -> Self {
        Self(Arc::new(BudgetInner {
            maximum,
            usage: Mutex::new(Usage::default()),
        }))
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
        Ok(Reservation {
            budget: self.0.clone(),
            bytes,
        })
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
        usage.handshakes += 1;
        usage.handshake_bytes = next_handshake_bytes;
        Ok(HandshakeReservation(self.0.clone()))
    }
}
impl Default for Budget {
    fn default() -> Self {
        Self::new(CONNECTION_BYTES)
    }
}
/// Retain this guard for as long as the associated packet or extracted buffers
/// remain owned. Moving a payload out of Packet also requires moving its guard.
#[derive(Debug)]
pub struct Reservation {
    budget: Arc<BudgetInner>,
    bytes: usize,
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
struct HandshakeReservation(Arc<BudgetInner>);
impl Drop for HandshakeReservation {
    fn drop(&mut self) {
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

#[derive(Clone)]
pub(crate) struct Deadline {
    started: Instant,
    limit: Duration,
    cancellation: Cancellation,
    #[cfg(test)]
    elapsed: Option<Arc<std::sync::atomic::AtomicU64>>,
}
impl Deadline {
    pub(crate) fn new(limit: Duration) -> Self {
        Self {
            started: Instant::now(),
            limit,
            cancellation: Cancellation::default(),
            #[cfg(test)]
            elapsed: None,
        }
    }
    fn check(&self) -> io::Result<()> {
        if self.cancellation.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native admission cancelled",
            ));
        }
        #[cfg(test)]
        let elapsed = self.elapsed.as_ref().map_or_else(
            || self.started.elapsed(),
            |clock| Duration::from_millis(clock.load(std::sync::atomic::Ordering::Relaxed)),
        );
        #[cfg(not(test))]
        let elapsed = self.started.elapsed();
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

/// Full public identity and its independently authenticated pin. Receiving a
/// self-signed descriptor on the connection is not independent authentication.
#[derive(Clone, Debug)]
pub struct ExpectedPeer {
    binding: Binding,
    descriptor: Descriptor,
    pin: PeerPin,
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
            pin,
        })
    }
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub fn fingerprint(&self) -> Hash {
        self.pin.fingerprint()
    }
}

/// Immutable expected identity, connection role and one provider-to-Hello
/// admission budget. The caller obtains the peer configuration before dialing
/// or accepting; the provider cannot replace it with a received descriptor.
#[derive(Clone)]
pub struct AdmissionContext {
    expected: ExpectedPeer,
    role: ConnectionRole,
    deadline: Deadline,
}
impl AdmissionContext {
    pub fn new(expected: ExpectedPeer, role: ConnectionRole, cancellation: Cancellation) -> Self {
        let mut deadline = Deadline::new(HELLO_TIMEOUT);
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
            || self.alpn != b"/siworld/native-hybrid/1"
            || self.resumed
            || self.early_data
        {
            return Err(Error::InvalidProtocol);
        }
        Ok(())
    }
}
struct Timed<'a, S> {
    channel: &'a mut S,
    deadline: Deadline,
}
impl<S: Read> Read for Timed<'_, S> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.deadline.check()?;
        let read = self.channel.read(bytes)?;
        self.deadline.check()?;
        Ok(read)
    }
}
impl<S: Write> Write for Timed<'_, S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.deadline.check()?;
        let written = self.channel.write(bytes)?;
        self.deadline.check()?;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.deadline.check()?;
        self.channel.flush()?;
        self.deadline.check()
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
/// pinned hybrid identity, transcript and both key confirmations. No production
/// provider is implemented here. The provider owns record authentication,
/// sequence numbers, nonce limits, secret cleanup and rekeying.
pub struct Authenticated<S> {
    channel: S,
    admission: AdmissionContext,
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
        admission
            .expected
            .pin
            .verify(observed_peer)
            .map_err(|_| Error::InvalidProtocol)?;
        admission.check()?;
        Ok(Self {
            channel,
            admission: admission.clone(),
        })
    }
}
pub trait HybridAuthenticator {
    type Channel: Read + Write;
    /// Must complete X25519+ML-KEM and Ed25519+ML-DSA authentication by the
    /// context's role, independently pinned full descriptor and original
    /// absolute deadline, with no classical fallback. Provider state must fit
    /// HANDSHAKE_BYTES. It must interrupt blocked I/O on deadline/cancellation;
    /// a cooperative flag or a wrapper cannot preempt blocked I/O by itself.
    fn authenticate(
        &mut self,
        socket: TcpStream,
        admission: &AdmissionContext,
    ) -> Result<Authenticated<Self::Channel>, Error>;
}
/// No default authenticator or unauthenticated production constructor exists.
/// Discard a session after any framing/I/O error; reconnecting requires a fresh
/// provider authentication rather than continuing a partially consumed frame.
pub struct Session<S> {
    channel: S,
    binding: Binding,
    peer: Hash,
    role: Role,
    budget: Budget,
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
        _permit: HandshakeReservation,
    ) -> Result<Self, Error> {
        if !auth.admission.same_attempt(admission) {
            return Err(Error::InvalidProtocol);
        }
        admission.check()?;
        let binding = admission.binding();
        let mut channel = auth.channel;
        let mut timed = Timed {
            channel: &mut channel,
            deadline: admission.deadline.clone(),
        };
        timed
            .write_all(&Hello { binding, role }.encode())
            .map_err(io_error)?;
        timed.flush().map_err(io_error)?;
        let mut hello = [0; HELLO_BYTES];
        timed.read_exact(&mut hello).map_err(io_error)?;
        let hello = Hello::decode(&hello, &binding)?;
        Ok(Self {
            channel,
            binding,
            peer: admission.expected.fingerprint(),
            role: hello.role,
            budget,
        })
    }
    pub(crate) fn shares_budget(&self, budget: &Budget) -> bool {
        Arc::ptr_eq(&self.budget.0, &budget.0)
    }
    pub(crate) fn binding(&self) -> Binding {
        self.binding
    }
    pub fn peer(&self) -> Hash {
        self.peer
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn send_control(&mut self, kind: u8, request: u64, body: &[u8]) -> Result<(), Error> {
        if kind == BLOCK {
            return Err(Error::InvalidProtocol);
        }
        let header = frame_header(kind, request, &self.binding.network, body.len())?;
        let _reservation = self.budget.reserve(
            body.len()
                .checked_add(HEADER_BYTES + 64)
                .ok_or(Error::ResourceExhausted)?,
        )?;
        let mut timed = Timed {
            channel: &mut self.channel,
            deadline: Deadline::new(CONTROL_TIMEOUT),
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
    fn receive_deadline(&mut self, mut deadline: Deadline) -> Result<Packet, Error> {
        let mut header = [0; HEADER_BYTES];
        Timed {
            channel: &mut self.channel,
            deadline: deadline.clone(),
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
        frame_header(kind, request, &self.binding.network, length)?;
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
    fn from_test_channel(channel: S, binding: Binding, budget: Budget) -> Self {
        Self {
            channel,
            binding,
            peer: [9; 32],
            role: Role::Validator,
            budget,
        }
    }
}
fn frame_header(
    kind: u8,
    request: u64,
    network: &Hash,
    length: usize,
) -> Result<[u8; HEADER_BYTES], Error> {
    if !(GET_BLOCKS..=END_BATCH).contains(&kind) {
        return Err(Error::InvalidProtocol);
    }
    let maximum = if kind == BLOCK {
        MAX_BLOCK_BYTES
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
    let permit = budget.handshake()?;
    let admission =
        AdmissionContext::new(expected.clone(), ConnectionRole::Responder, cancellation);
    admission.check()?;
    timeout(&socket)?;
    let channel = auth.authenticate(socket, &admission)?;
    admission.check()?;
    Session::establish_reserved(channel, &admission, role, budget, permit)
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
    let channel = auth.authenticate(socket, &admission)?;
    admission.check()?;
    Session::establish_reserved(channel, &admission, role, budget, permit)
}
#[cfg(test)]
mod admission_tests;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
