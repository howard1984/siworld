//! Bounded eng-2 exchanges over the existing authenticated hybrid session.
//!
//! Framing does not validate proof semantics, select forks or commit state.
//! The resident owner must admit returned blocks through `Store::append`.

use super::{
    body::{Body, Policy},
    genesis::Genesis,
    header::Header,
};
use crate::{p2p, wire::Hash};
use std::io::{self, Read, Write};
mod bootstrap;
pub use bootstrap::{ChunkRequest, ReceivedChunk, ReceivedManifest};

const TIP: u8 = 1;
const GET_HEADER: u8 = 2;
const HEADER: u8 = 3;
const GET_BODY: u8 = 4;
const BODY_START: u8 = 5;
const BODY_CHUNK: u8 = 6;
const UNAVAILABLE: u8 = 7;
const GET_TIP: u8 = 8;
const ROUND_DONE: u8 = 9;
const GET_HEADER_BY_ID: u8 = 15;
const UNAVAILABLE_ID: u8 = 16;
const EXACT_CAPABILITIES: u8 = 17;
const EXACT_VERSION: u16 = 1;
const CHUNK_BYTES: usize = p2p::MAX_CONTROL_BYTES - 9;

/// Immutable application binding is checked by the encrypted handshake and
/// native hello before an eng-2 wrapper can be constructed.
pub fn binding(genesis: &Genesis) -> p2p::Binding {
    genesis.peer_binding()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    GetTip,
    RoundDone,
    Tip { height: u64, id: Hash },
    Header { height: u64 },
    HeaderById { height: u64, id: Hash },
    Body { height: u64, id: Hash },
    BootstrapManifest { bundle: Option<Hash> },
    BootstrapChunk(ChunkRequest),
}

/// The allocation charge lives as long as the decoded body. Moving the body
/// out requires retaining this guard until admission and all consumers finish.
pub struct ReceivedBody {
    pub body: Body,
    pub reservation: p2p::Reservation,
}

#[derive(Clone, Copy)]
struct CompetingHead {
    local: (u64, Hash),
    remote: (u64, Hash),
}

/// No public plaintext or unauthenticated constructor is provided. Discard
/// the peer after an exchange error: a partial stream must not be reused.
pub struct Peer<S> {
    session: p2p::Session<S>,
    policy: Policy,
    exact_blocks: Option<bool>,
    competing_head: Option<CompetingHead>,
}
impl<S: Read + Write> Peer<S> {
    pub fn new(
        session: p2p::Session<S>,
        genesis: &Genesis,
        policy: Policy,
    ) -> Result<Self, p2p::Error> {
        if session.binding() != binding(genesis)
            || policy.profile != crate::proofs::protocol_profile_fingerprint()
            || policy.max_body_bytes == 0
            || policy.max_settlement_proof_bytes == 0
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        Ok(Self {
            session,
            policy,
            exact_blocks: None,
            competing_head: None,
        })
    }
    pub fn genesis_id(&self) -> Hash {
        self.session.binding().genesis
    }
    pub fn peer(&self) -> Hash {
        self.session.peer()
    }
    pub fn role(&self) -> p2p::Role {
        self.session.role()
    }
    /// Scheduling hint only, scoped to an unchanged pair of advertised tips.
    /// It never establishes validity or bypasses discovery accounting.
    pub(crate) fn remember_competing_head(&mut self, local: (u64, Hash), remote: (u64, Hash)) {
        self.competing_head = Some(CompetingHead { local, remote });
    }
    pub(crate) fn competing_head_matches(&self, local: (u64, Hash), remote: (u64, Hash)) -> bool {
        self.competing_head
            .is_some_and(|known| known.local == local && known.remote == remote)
    }

    pub fn fetch_tip(&mut self, request: u64) -> Result<(u64, Hash), p2p::Error> {
        self.send(request, &[GET_TIP])?;
        let (received, bytes, _charge) = self.receive()?;
        if received != request || bytes.len() != 41 || bytes[0] != TIP {
            return Err(p2p::Error::InvalidProtocol);
        }
        Ok((number(&bytes[1..9]), digest(&bytes[9..41])))
    }
    pub fn finish_round(&mut self, request: u64) -> Result<(), p2p::Error> {
        self.send(request, &[ROUND_DONE])
    }
    pub(crate) fn reserve_body(&self, length: usize) -> Result<p2p::Reservation, p2p::Error> {
        if length == 0 || length > self.policy.max_body_bytes {
            return Err(p2p::Error::ResourceExhausted);
        }
        let charge = length
            .checked_mul(3)
            .and_then(|n| n.checked_add(65_536))
            .ok_or(p2p::Error::ResourceExhausted)?;
        self.session.shared_budget().reserve(charge)
    }
    pub fn advertise_tip(&mut self, request: u64, height: u64, id: Hash) -> Result<(), p2p::Error> {
        self.send_identity(TIP, request, height, id)
    }
    pub fn send_unavailable(&mut self, request: u64, height: u64) -> Result<(), p2p::Error> {
        let mut bytes = [0; 9];
        bytes[0] = UNAVAILABLE;
        bytes[1..].copy_from_slice(&height.to_le_bytes());
        self.send(request, &bytes)
    }
    pub fn send_unavailable_id(
        &mut self,
        request: u64,
        height: u64,
        id: Hash,
    ) -> Result<(), p2p::Error> {
        self.send_identity(UNAVAILABLE_ID, request, height, id)
    }
    /// Consume only request/notice messages; response frames arriving outside
    /// the matching exchange are rejected rather than buffered without a cap.
    pub fn receive_request(&mut self) -> Result<(u64, Request), p2p::Error> {
        let (request, bytes, _charge) = self.receive()?;
        let message = match bytes.first().copied() {
            Some(GET_TIP) if bytes.len() == 1 => Request::GetTip,
            Some(ROUND_DONE) if bytes.len() == 1 => Request::RoundDone,
            Some(TIP) if bytes.len() == 41 => Request::Tip {
                height: number(&bytes[1..9]),
                id: digest(&bytes[9..41]),
            },
            Some(GET_HEADER) if bytes.len() == 9 => Request::Header {
                height: number(&bytes[1..9]),
            },
            Some(GET_HEADER_BY_ID) if bytes.len() == 41 && number(&bytes[1..9]) != 0 => {
                Request::HeaderById {
                    height: number(&bytes[1..9]),
                    id: digest(&bytes[9..41]),
                }
            }
            Some(GET_BODY) if bytes.len() == 41 => Request::Body {
                height: number(&bytes[1..9]),
                id: digest(&bytes[9..41]),
            },
            _ => bootstrap::request(&bytes).ok_or(p2p::Error::InvalidProtocol)?,
        };
        Ok((request, message))
    }
    pub fn send_header(&mut self, request: u64, header: &Header) -> Result<(), p2p::Error> {
        if header.network != self.session.binding().network || header.height == 0 {
            return Err(p2p::Error::InvalidProtocol);
        }
        let encoded = header.encode().map_err(|_| p2p::Error::InvalidProtocol)?;
        let mut bytes = [0; 1 + super::header::HEADER_BYTES];
        bytes[0] = HEADER;
        bytes[1..].copy_from_slice(&encoded);
        self.send(request, &bytes)
    }
    pub fn fetch_header(
        &mut self,
        request: u64,
        height: u64,
    ) -> Result<Option<Header>, p2p::Error> {
        if height == 0 {
            return Err(p2p::Error::InvalidProtocol);
        }
        let mut query = [0; 9];
        query[0] = GET_HEADER;
        query[1..].copy_from_slice(&height.to_le_bytes());
        self.send(request, &query)?;
        let (received, bytes, _charge) = self.receive()?;
        if received != request {
            return Err(p2p::Error::InvalidProtocol);
        }
        if bytes.len() == 9 && bytes[0] == UNAVAILABLE && number(&bytes[1..]) == height {
            return Ok(None);
        }
        if bytes.len() != 1 + super::header::HEADER_BYTES || bytes[0] != HEADER {
            return Err(p2p::Error::InvalidProtocol);
        }
        let header = Header::decode(&bytes[1..], &self.session.binding().network)
            .map_err(|_| p2p::Error::InvalidProtocol)?;
        if header.height != height {
            return Err(p2p::Error::InvalidProtocol);
        }
        Ok(Some(header))
    }
    /// Height zero is not a block header. Legacy ordinary responders answer
    /// this already-known request with UNAVAILABLE(0), without closing the round.
    /// A positive answer is scoped to this authenticated session only.
    pub fn probe_exact_blocks(&mut self, request: u64) -> Result<bool, p2p::Error> {
        if let Some(available) = self.exact_blocks {
            return Ok(available);
        }
        let mut query = [0; 9];
        query[0] = GET_HEADER;
        self.send(request, &query)?;
        let (received, bytes, _charge) = self.receive()?;
        if received != request {
            return Err(p2p::Error::InvalidProtocol);
        }
        let available = if bytes.len() == 9 && bytes[0] == UNAVAILABLE && number(&bytes[1..]) == 0 {
            false
        } else if bytes.len() == 4
            && bytes[0] == EXACT_CAPABILITIES
            && u16::from_le_bytes(bytes[1..3].try_into().unwrap()) == EXACT_VERSION
            && bytes[3] <= 1
        {
            bytes[3] == 1
        } else {
            return Err(p2p::Error::InvalidProtocol);
        };
        self.exact_blocks = Some(available);
        Ok(available)
    }
    pub fn exact_blocks_supported(&self) -> bool {
        self.exact_blocks == Some(true)
    }
    pub fn send_exact_capabilities(
        &mut self,
        request: u64,
        available: bool,
    ) -> Result<(), p2p::Error> {
        self.send(request, &[EXACT_CAPABILITIES, 1, 0, u8::from(available)])
    }
    /// Fetch an exact ancestor or competitor. Height is an additional binding,
    /// never a replacement for the requested block identity. This exchange does
    /// not qualify proof-of-work, ancestry, native proofs or execution state.
    pub fn fetch_header_by_id(
        &mut self,
        request: u64,
        height: u64,
        id: Hash,
    ) -> Result<Option<Header>, p2p::Error> {
        if !self.exact_blocks_supported() {
            return Err(p2p::Error::Unconfigured);
        }
        if height == 0 {
            return Err(p2p::Error::InvalidProtocol);
        }
        self.send_identity(GET_HEADER_BY_ID, request, height, id)?;
        let (received, bytes, _charge) = self.receive()?;
        if received != request {
            return Err(p2p::Error::InvalidProtocol);
        }
        if bytes.len() == 41 && bytes[0] == UNAVAILABLE_ID {
            return if number(&bytes[1..9]) == height && digest(&bytes[9..41]) == id {
                Ok(None)
            } else {
                Err(p2p::Error::InvalidProtocol)
            };
        }
        if bytes.len() != 1 + super::header::HEADER_BYTES || bytes[0] != HEADER {
            return Err(p2p::Error::InvalidProtocol);
        }
        let header = Header::decode(&bytes[1..], &self.session.binding().network)
            .map_err(|_| p2p::Error::InvalidProtocol)?;
        if header.height != height || header.id().map_err(|_| p2p::Error::InvalidProtocol)? != id {
            return Err(p2p::Error::InvalidProtocol);
        }
        Ok(Some(header))
    }
    /// Stream canonical bytes in bounded chunks without a second full encoded
    /// copy. The caller retains body ownership and its node budget reservation.
    pub fn send_body(
        &mut self,
        request: u64,
        header: &Header,
        body: &Body,
    ) -> Result<(), p2p::Error> {
        if header.network != self.session.binding().network
            || body.network != header.network
            || body.height != header.height
            || body
                .commitment(self.policy)
                .map_err(|_| p2p::Error::InvalidProtocol)?
                != header.body_commitment
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        let length = body
            .encoded_len(self.policy)
            .map_err(|_| p2p::Error::InvalidProtocol)?;
        let id = header.id().map_err(|_| p2p::Error::InvalidProtocol)?;
        let mut start = [0; 49];
        start[0] = BODY_START;
        start[1..9].copy_from_slice(&header.height.to_le_bytes());
        start[9..41].copy_from_slice(&id);
        start[41..].copy_from_slice(&(length as u64).to_le_bytes());
        // Reserve the only encoder scratch allocation before writing a frame.
        let budget = self.session.shared_budget();
        let _scratch = budget.reserve(CHUNK_BYTES + 9)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(CHUNK_BYTES + 9)
            .map_err(|_| p2p::Error::ResourceExhausted)?;
        self.send(request, &start)?;
        let mut writer = ChunkWriter {
            peer: self,
            request,
            offset: 0,
            buffer,
        };
        writer.buffer.extend_from_slice(&[BODY_CHUNK; 9]);
        let policy = writer.peer.policy;
        body.write_to(&mut writer, policy)
            .map_err(|_| p2p::Error::Unavailable)?;
        writer.flush().map_err(|_| p2p::Error::Unavailable)?;
        if writer.offset != length {
            return Err(p2p::Error::InvalidProtocol);
        }
        Ok(())
    }
    pub fn fetch_body(
        &mut self,
        request: u64,
        header: &Header,
    ) -> Result<Option<ReceivedBody>, p2p::Error> {
        if header.network != self.session.binding().network || header.height == 0 {
            return Err(p2p::Error::InvalidProtocol);
        }
        let id = header.id().map_err(|_| p2p::Error::InvalidProtocol)?;
        self.send_identity(GET_BODY, request, header.height, id)?;
        let (received, start, start_charge) = self.receive()?;
        if received != request {
            return Err(p2p::Error::InvalidProtocol);
        }
        if start.len() == 9 && start[0] == UNAVAILABLE && number(&start[1..]) == header.height {
            return Ok(None);
        }
        if start.len() != 49
            || start[0] != BODY_START
            || number(&start[1..9]) != header.height
            || digest(&start[9..41]) != id
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        let length =
            usize::try_from(number(&start[41..])).map_err(|_| p2p::Error::ResourceExhausted)?;
        if length == 0 || length > self.policy.max_body_bytes {
            return Err(p2p::Error::ResourceExhausted);
        }
        drop(start);
        drop(start_charge);
        // Wire ownership plus decoded proof/ciphertext buffers and object
        // overhead remain charged together until the returned guard is dropped.
        let reservation = self.reserve_body(length)?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(length)
            .map_err(|_| p2p::Error::ResourceExhausted)?;
        let deadline = p2p::Deadline::new(std::time::Duration::from_secs(180));
        while encoded.len() < length {
            let (received, chunk, _charge) = self.receive_before(&deadline)?;
            if received != request
                || chunk.len() <= 9
                || chunk[0] != BODY_CHUNK
                || number(&chunk[1..9]) != encoded.len() as u64
                || chunk.len() - 9 != CHUNK_BYTES.min(length - encoded.len())
            {
                return Err(p2p::Error::InvalidProtocol);
            }
            encoded.extend_from_slice(&chunk[9..]);
        }
        header
            .verify_body(&encoded, self.policy.max_body_bytes)
            .map_err(|_| p2p::Error::InvalidProtocol)?;
        let body = Body::decode(&encoded, header.network, header.height, self.policy)
            .map_err(|_| p2p::Error::InvalidProtocol)?;
        Ok(Some(ReceivedBody { body, reservation }))
    }
    pub(crate) fn application_network(&self) -> Hash {
        self.session.binding().network
    }
    pub(crate) fn reserve_application(
        &self,
        length: usize,
    ) -> Result<p2p::Reservation, p2p::Error> {
        let bytes = length
            .checked_mul(3)
            .and_then(|n| n.checked_add(65_536))
            .ok_or(p2p::Error::ResourceExhausted)?;
        self.session.shared_budget().reserve(bytes)
    }
    pub(crate) fn send_application_before(
        &mut self,
        request: u64,
        bytes: &[u8],
        deadline: &p2p::Deadline,
    ) -> Result<(), p2p::Error> {
        self.session
            .send_control_before(p2p::ENG2_MESSAGE, request, bytes, deadline)
    }
    pub(crate) fn receive_application_before(
        &mut self,
        deadline: &p2p::Deadline,
        maximum: usize,
    ) -> Result<(u64, Vec<u8>, p2p::Reservation), p2p::Error> {
        match self
            .session
            .receive_eng2_application_before(deadline, maximum)?
        {
            p2p::Packet::Control {
                kind: p2p::ENG2_MESSAGE,
                request,
                body,
                reservation,
            } => Ok((request, body, reservation)),
            _ => Err(p2p::Error::InvalidProtocol),
        }
    }
    fn send_identity(
        &mut self,
        kind: u8,
        request: u64,
        height: u64,
        id: Hash,
    ) -> Result<(), p2p::Error> {
        let mut bytes = [0; 41];
        bytes[0] = kind;
        bytes[1..9].copy_from_slice(&height.to_le_bytes());
        bytes[9..].copy_from_slice(&id);
        self.send(request, &bytes)
    }
    fn send(&mut self, request: u64, bytes: &[u8]) -> Result<(), p2p::Error> {
        self.session.send_control(p2p::ENG2_MESSAGE, request, bytes)
    }
    fn receive(&mut self) -> Result<(u64, Vec<u8>, p2p::Reservation), p2p::Error> {
        self.receive_before(&p2p::Deadline::new(std::time::Duration::from_secs(10)))
    }
    fn receive_before(
        &mut self,
        deadline: &p2p::Deadline,
    ) -> Result<(u64, Vec<u8>, p2p::Reservation), p2p::Error> {
        match self.session.receive_eng2_before(deadline)? {
            p2p::Packet::Control {
                kind: p2p::ENG2_MESSAGE,
                request,
                body,
                reservation,
            } => Ok((request, body, reservation)),
            _ => Err(p2p::Error::InvalidProtocol),
        }
    }
}
fn number(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("validated u64 width"))
}
fn digest(bytes: &[u8]) -> Hash {
    bytes.try_into().expect("validated hash width")
}
struct ChunkWriter<'a, S> {
    peer: &'a mut Peer<S>,
    request: u64,
    offset: usize,
    buffer: Vec<u8>,
}
impl<S: Read + Write> Write for ChunkWriter<'_, S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(CHUNK_BYTES + 9 - self.buffer.len());
        self.buffer.extend_from_slice(&bytes[..count]);
        if self.buffer.len() == CHUNK_BYTES + 9 {
            self.flush()?;
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.buffer.len() == 9 {
            return Ok(());
        }
        self.buffer[0] = BODY_CHUNK;
        self.buffer[1..9].copy_from_slice(&(self.offset as u64).to_le_bytes());
        self.peer
            .send(self.request, &self.buffer)
            .map_err(|_| io::Error::other("eng2 chunk send failed"))?;
        self.offset += self.buffer.len() - 9;
        self.buffer.truncate(9);
        Ok(())
    }
}

#[cfg(feature = "native-p2p")]
impl Peer<p2p::NativeTlsChannel> {
    /// Aggregate received/sent encrypted stream bytes, including handshake.
    pub fn encrypted_stream_bytes(&self) -> (u64, u64) {
        self.session.encrypted_stream_bytes()
    }
    /// Retire the authenticated stream before starting a full application cycle
    /// that cannot fit within its unchanged wire, record or lifetime limits.
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn ready_for_cycle(&self) -> bool {
        self.session.ready_for_cycle()
    }
    /// Authenticate an already accepted or dialed socket. The listener/routing
    /// owner retains endpoint policy and creates the original admission deadline.
    pub fn establish(
        socket: std::net::TcpStream,
        identity: std::sync::Arc<crate::identity::NativeIdentity>,
        admission: &p2p::AdmissionContext,
        role: p2p::Role,
        budget: p2p::Budget,
        genesis: &Genesis,
        policy: Policy,
    ) -> Result<Self, p2p::Error> {
        if admission.binding() != genesis.peer_binding() {
            return Err(p2p::Error::InvalidProtocol);
        }
        let mut provider = p2p::NativeTlsAuthenticator::new(identity, budget.clone());
        let session = p2p::establish_socket(socket, &mut provider, admission, role, budget)?;
        Self::new(session, genesis, policy)
    }
}

#[cfg(test)]
mod tests {
    use super::super::genesis::FeeMode;
    use super::*;
    use std::io::Cursor;

    #[derive(Default)]
    struct Script {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Script {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.input.read(bytes)
        }
    }
    impl Write for Script {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn genesis() -> Genesis {
        let state = crate::eng2::snapshot::tests::bootstrap();
        Genesis::seal(
            state.chain.config.clone(),
            state.governance.clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap()
    }
    fn policy() -> Policy {
        Policy {
            profile: crate::proofs::protocol_profile_fingerprint(),
            max_body_bytes: 4 * 1024 * 1024,
            max_settlement_proof_bytes: 3 * 1024 * 1024,
        }
    }
    fn session(input: Vec<u8>, binding: p2p::Binding, budget: p2p::Budget) -> p2p::Session<Script> {
        p2p::Session::from_test_channel(
            Script {
                input: Cursor::new(input),
                output: Vec::new(),
            },
            binding,
            budget,
        )
    }
    fn frame(request: u64, bytes: &[u8], binding: p2p::Binding) -> Vec<u8> {
        let mut wire = b"SWPF".to_vec();
        wire.extend_from_slice(&p2p::VERSION.to_le_bytes());
        wire.push(p2p::ENG2_MESSAGE);
        wire.extend_from_slice(&request.to_le_bytes());
        wire.extend_from_slice(&binding.network);
        wire.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        wire.extend_from_slice(bytes);
        wire
    }
    fn body_header(g: &Genesis) -> (Body, Header) {
        let mut body = crate::eng2::body::tests::body();
        body.network = g.config().network;
        body.profile = policy().profile;
        body.governance.clear();
        body.fund_claims.clear();
        body.transactions
            .sort_by_key(|tx| tx.record.statement_id(&body.network));
        body.settlement_proof = vec![8; CHUNK_BYTES + 100];
        let header = Header {
            network: body.network,
            height: body.height,
            parent: g.id(),
            timestamp: 123,
            target: [255; 32],
            execution_commitment: [2; 32],
            body_commitment: body.commitment(policy()).unwrap(),
            nonce: 1,
        };
        (body, header)
    }
    fn start(header: &Header, length: usize) -> Vec<u8> {
        let mut bytes = vec![BODY_START];
        bytes.extend_from_slice(&header.height.to_le_bytes());
        bytes.extend_from_slice(&header.id().unwrap());
        bytes.extend_from_slice(&(length as u64).to_le_bytes());
        bytes
    }
    #[test]
    fn binding_rejects_v1_and_changed_rules_or_profile_before_an_exchange() {
        let g = genesis();
        let expected = binding(&g);
        let old = p2p::Binding::new(g.config());
        assert_ne!(old, expected);
        assert!(Peer::new(session(vec![], old, p2p::Budget::default()), &g, policy()).is_err());
        let mut different = expected;
        different.verifier[0] ^= 1;
        assert!(
            Peer::new(
                session(vec![], different, p2p::Budget::default()),
                &g,
                policy()
            )
            .is_err()
        );
        let mut p = policy();
        p.profile[0] ^= 1;
        assert!(Peer::new(session(vec![], expected, p2p::Budget::default()), &g, p).is_err());
    }
    #[test]
    fn header_exchange_checks_request_height_network_and_exact_encoding() {
        let g = genesis();
        let (_, header) = body_header(&g);
        let b = binding(&g);
        let mut message = vec![HEADER];
        message.extend_from_slice(&header.encode().unwrap());
        let mut peer = Peer::new(
            session(frame(10, &message, b), b, p2p::Budget::default()),
            &g,
            policy(),
        )
        .unwrap();
        assert_eq!(
            peer.fetch_header(10, header.height).unwrap(),
            Some(header.clone())
        );
        for (request, height) in [(11, header.height), (10, header.height + 1)] {
            let mut peer = Peer::new(
                session(frame(10, &message, b), b, p2p::Budget::default()),
                &g,
                policy(),
            )
            .unwrap();
            assert_eq!(
                peer.fetch_header(request, height),
                Err(p2p::Error::InvalidProtocol)
            );
        }
    }
    #[test]
    fn exact_requests_write_nothing_before_a_live_positive_probe() {
        let g = genesis();
        let b = binding(&g);
        let mut peer = Peer::new(session(vec![], b, p2p::Budget::default()), &g, policy()).unwrap();
        assert_eq!(
            peer.fetch_header_by_id(2, 1, [8; 32]),
            Err(p2p::Error::Unconfigured)
        );
        assert!(peer.session.test_channel().output.is_empty());
        let mut peer = Peer::new(
            session(
                frame(1, &[EXACT_CAPABILITIES, 1, 0, 1], b),
                b,
                p2p::Budget::default(),
            ),
            &g,
            policy(),
        )
        .unwrap();
        assert!(peer.probe_exact_blocks(1).unwrap());
        let length = peer.session.test_channel().output.len();
        assert!(peer.probe_exact_blocks(3).unwrap());
        assert_eq!(peer.session.test_channel().output.len(), length);
        let peer = Peer::new(session(vec![], b, p2p::Budget::default()), &g, policy()).unwrap();
        assert!(!peer.exact_blocks_supported());
    }
    #[test]
    fn capability_probe_rejects_cross_request_version_flags_and_trailing_bytes() {
        let g = genesis();
        let b = binding(&g);
        for (request, message) in [
            (2, vec![EXACT_CAPABILITIES, 1, 0, 1]),
            (1, vec![EXACT_CAPABILITIES, 2, 0, 1]),
            (1, vec![EXACT_CAPABILITIES, 1, 0, 2]),
            (1, vec![EXACT_CAPABILITIES, 1, 0, 1, 0]),
        ] {
            let mut peer = Peer::new(
                session(frame(request, &message, b), b, p2p::Budget::default()),
                &g,
                policy(),
            )
            .unwrap();
            assert_eq!(peer.probe_exact_blocks(1), Err(p2p::Error::InvalidProtocol));
            assert!(!peer.exact_blocks_supported());
        }
    }
    #[test]
    fn exact_header_exchange_binds_request_height_and_identity() {
        let g = genesis();
        let (_, header) = body_header(&g);
        let b = binding(&g);
        let id = header.id().unwrap();
        let mut message = vec![HEADER];
        message.extend_from_slice(&header.encode().unwrap());
        for (request, height, wanted, valid) in [
            (10, header.height, id, true),
            (11, header.height, id, false),
            (10, header.height + 1, id, false),
            (10, header.height, [19; 32], false),
        ] {
            let mut peer = Peer::new(
                session(frame(10, &message, b), b, p2p::Budget::default()),
                &g,
                policy(),
            )
            .unwrap();
            peer.exact_blocks = Some(true);
            let result = peer.fetch_header_by_id(request, height, wanted);
            if valid {
                assert_eq!(result.unwrap(), Some(header.clone()));
            } else {
                assert_eq!(result, Err(p2p::Error::InvalidProtocol));
            }
        }
    }
    #[test]
    fn exact_missing_header_binds_identity_and_rejects_height_only_missing() {
        let g = genesis();
        let b = binding(&g);
        let id = [7; 32];
        let mut exact = vec![UNAVAILABLE_ID];
        exact.extend_from_slice(&1u64.to_le_bytes());
        exact.extend_from_slice(&id);
        let mut height_only = vec![UNAVAILABLE];
        height_only.extend_from_slice(&1u64.to_le_bytes());
        for (message, wanted, valid) in [
            (exact.clone(), id, true),
            (exact, [8; 32], false),
            (height_only, id, false),
        ] {
            let mut peer = Peer::new(
                session(frame(9, &message, b), b, p2p::Budget::default()),
                &g,
                policy(),
            )
            .unwrap();
            peer.exact_blocks = Some(true);
            let result = peer.fetch_header_by_id(9, 1, wanted);
            if valid {
                assert_eq!(result.unwrap(), None);
            } else {
                assert_eq!(result, Err(p2p::Error::InvalidProtocol));
            }
        }
    }
    #[test]
    fn canonical_multichunk_roundtrip_retains_one_node_budget_until_body_drop() {
        let g = genesis();
        let (body, header) = body_header(&g);
        let b = binding(&g);
        let mut sender =
            Peer::new(session(vec![], b, p2p::Budget::default()), &g, policy()).unwrap();
        sender.send_body(5, &header, &body).unwrap();
        let budget = p2p::Budget::new(20 * 1024 * 1024);
        let before = budget.available().unwrap();
        let mut receiver = Peer::new(
            session(
                sender.session.test_channel().output.clone(),
                b,
                budget.clone(),
            ),
            &g,
            policy(),
        )
        .unwrap();
        let received = receiver.fetch_body(5, &header).unwrap().unwrap();
        assert_eq!(received.body, body);
        assert!(budget.available().unwrap() < before);
        drop(received);
        assert_eq!(budget.available().unwrap(), before);
    }
    #[test]
    fn oversize_and_budget_exhaustion_fail_before_body_allocation() {
        let g = genesis();
        let (_, header) = body_header(&g);
        let b = binding(&g);
        let budget = p2p::Budget::new(1024);
        let before = budget.available().unwrap();
        let wire = frame(5, &start(&header, 2000), b);
        let mut peer = Peer::new(session(wire, b, budget.clone()), &g, policy()).unwrap();
        assert!(matches!(
            peer.fetch_body(5, &header),
            Err(p2p::Error::ResourceExhausted)
        ));
        assert_eq!(budget.available().unwrap(), before);
        let wire = frame(5, &start(&header, policy().max_body_bytes + 1), b);
        let mut peer = Peer::new(session(wire, b, budget.clone()), &g, policy()).unwrap();
        assert!(matches!(
            peer.fetch_body(5, &header),
            Err(p2p::Error::ResourceExhausted)
        ));
        assert_eq!(budget.available().unwrap(), before);
    }
    #[test]
    fn rejects_duplicate_offsets_wrong_ids_and_unsolicited_response_frames() {
        let g = genesis();
        let (_, header) = body_header(&g);
        let b = binding(&g);
        let mut bytes = start(&header, 10);
        let mut wire = frame(5, &bytes, b);
        let mut chunk = vec![BODY_CHUNK];
        chunk.extend_from_slice(&1u64.to_le_bytes());
        chunk.push(1);
        wire.extend_from_slice(&frame(5, &chunk, b));
        let mut peer = Peer::new(session(wire, b, p2p::Budget::default()), &g, policy()).unwrap();
        assert!(matches!(
            peer.fetch_body(5, &header),
            Err(p2p::Error::InvalidProtocol)
        ));
        bytes[9] ^= 1;
        let mut peer = Peer::new(
            session(frame(5, &bytes, b), b, p2p::Budget::default()),
            &g,
            policy(),
        )
        .unwrap();
        assert!(matches!(
            peer.fetch_body(5, &header),
            Err(p2p::Error::InvalidProtocol)
        ));
        let mut peer = Peer::new(
            session(frame(5, &chunk, b), b, p2p::Budget::default()),
            &g,
            policy(),
        )
        .unwrap();
        assert!(matches!(
            peer.receive_request(),
            Err(p2p::Error::InvalidProtocol)
        ));
    }
    #[test]
    fn rejects_v1_block_before_reserving_or_reading_its_payload() {
        let g = genesis();
        let b = binding(&g);
        let mut wire = b"SWPF".to_vec();
        wire.extend_from_slice(&p2p::VERSION.to_le_bytes());
        wire.push(p2p::BLOCK);
        wire.extend_from_slice(&5u64.to_le_bytes());
        wire.extend_from_slice(&b.network);
        wire.extend_from_slice(&(100_000_000u32).to_le_bytes());
        let budget = p2p::Budget::new(1024);
        let mut peer = Peer::new(session(wire, b, budget.clone()), &g, policy()).unwrap();
        assert!(matches!(
            peer.receive_request(),
            Err(p2p::Error::InvalidProtocol)
        ));
        assert_eq!(budget.available().unwrap(), 1024);
    }
    #[test]
    fn rejects_mutated_canonical_body_after_full_transfer_and_releases_budget() {
        let g = genesis();
        let (body, header) = body_header(&g);
        let b = binding(&g);
        let mut sender =
            Peer::new(session(vec![], b, p2p::Budget::default()), &g, policy()).unwrap();
        sender.send_body(5, &header, &body).unwrap();
        let mut wire = sender.session.test_channel().output.clone();
        *wire.last_mut().unwrap() ^= 1;
        let budget = p2p::Budget::new(20 * 1024 * 1024);
        let before = budget.available().unwrap();
        let mut receiver = Peer::new(session(wire, b, budget.clone()), &g, policy()).unwrap();
        assert!(matches!(
            receiver.fetch_body(5, &header),
            Err(p2p::Error::InvalidProtocol)
        ));
        assert_eq!(budget.available().unwrap(), before);
    }
    #[cfg(feature = "native-p2p")]
    #[test]
    fn actual_hybrid_session_exchanges_versioned_header_and_multichunk_body() {
        use crate::identity::{NativeIdentity, PeerPin};
        use std::{
            net::{Ipv4Addr, TcpListener, TcpStream},
            sync::Arc,
        };
        fn identity(g: &Genesis, suffix: &str) -> Arc<NativeIdentity> {
            let path = std::env::temp_dir()
                .join(format!("eng2-transport-{}-{suffix}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let result =
                NativeIdentity::initialize(&path.canonicalize().unwrap(), g.peer_binding())
                    .unwrap();
            std::fs::remove_dir_all(path).unwrap();
            Arc::new(result)
        }
        fn admission(
            peer: &NativeIdentity,
            g: &Genesis,
            role: p2p::ConnectionRole,
        ) -> p2p::AdmissionContext {
            let descriptor = peer.descriptor().unwrap();
            let pin = PeerPin::from_trusted_descriptor(&descriptor, &g.peer_binding()).unwrap();
            let expected =
                p2p::ExpectedPeer::from_pinned_descriptor(g.peer_binding(), descriptor, pin)
                    .unwrap();
            p2p::AdmissionContext::new(expected, role, p2p::Cancellation::default())
        }
        let g = genesis();
        let a = identity(&g, "a");
        let b = identity(&g, "b");
        let budget = p2p::Budget::default();
        let before = budget.available().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let client_admission = admission(&b, &g, p2p::ConnectionRole::Initiator);
        let server_admission = admission(&a, &g, p2p::ConnectionRole::Responder);
        let server_budget = budget.clone();
        let server_g = genesis();
        let (body, header) = body_header(&g);
        let expected_body = body.clone();
        let expected_header = header.clone();
        let worker = std::thread::spawn(move || {
            let mut peer = Peer::establish(
                server,
                b,
                &server_admission,
                p2p::Role::Validator,
                server_budget,
                &server_g,
                policy(),
            )
            .unwrap();
            assert_eq!(
                peer.receive_request().unwrap(),
                (
                    1,
                    Request::Header {
                        height: header.height
                    }
                )
            );
            peer.send_header(1, &header).unwrap();
            assert_eq!(
                peer.receive_request().unwrap(),
                (
                    2,
                    Request::Body {
                        height: header.height,
                        id: header.id().unwrap()
                    }
                )
            );
            peer.send_body(2, &header, &body).unwrap();
        });
        let mut peer = Peer::establish(
            client,
            a,
            &client_admission,
            p2p::Role::Miner,
            budget.clone(),
            &g,
            policy(),
        )
        .unwrap();
        let header = peer
            .fetch_header(1, expected_header.height)
            .unwrap()
            .unwrap();
        assert_eq!(header, expected_header);
        let received = peer.fetch_body(2, &header).unwrap().unwrap();
        assert_eq!(received.body, expected_body);
        drop(received);
        drop(peer);
        worker.join().unwrap();
        assert_eq!(budget.available().unwrap(), before);
    }
}
