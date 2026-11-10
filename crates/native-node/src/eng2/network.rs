//! Sequential bidirectional rounds over an established eng-2 session.
//!
//! The initiator first pulls, then advertises its tip and serves the responder's
//! pull. This allows outbound miners to relay blocks without a new listener.
//! Fork choice, reorganization and automatic checkpoints are not implemented.

use super::{
    body::Body,
    header::Header,
    transport::{Peer, Request},
};
use crate::{p2p, wire::Hash};
use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
};

/// The resident owner authenticates every accepted block with its native engine
/// and commits only through `Store::append`. No socket I/O occurs under this lock.
pub trait Owner: Send {
    fn head(&self) -> Result<(u64, Hash), String>;
    fn header(&self, height: u64) -> Result<Option<Header>, String>;
    /// Reads the persisted encoded length without copying or decoding a body.
    fn block_size(&self, height: u64) -> Result<Option<usize>, String>;
    fn block(&self, height: u64) -> Result<(Header, Body), String>;
    fn accept(&mut self, header: &Header, body: &Body) -> Result<(), String>;
    /// Explicit service capability only. Ordinary and miner owners expose none.
    fn bootstrap_manifest(
        &mut self,
        _authenticated_peer: Hash,
        _requested_bundle: Option<Hash>,
    ) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
    fn bootstrap_chunk(
        &mut self,
        _authenticated_peer: Hash,
        _query: super::transport::ChunkRequest,
    ) -> Result<Option<super::bootstrap::Chunk>, String> {
        Ok(None)
    }
}
#[derive(Debug)]
pub enum Error {
    Transport(p2p::Error),
    Owner(String),
    Protocol,
    ForkUnsupported,
    Unavailable,
    RequestLimit,
}
impl From<p2p::Error> for Error {
    fn from(value: p2p::Error) -> Self {
        Self::Transport(value)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "eng2 sequential exchange: {self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy)]
pub struct Limits {
    /// Maximum blocks admitted in each direction in one round.
    pub blocks: u16,
}
impl Limits {
    fn check(self) -> Result<(), Error> {
        if !(1..=32).contains(&self.blocks) {
            return Err(Error::RequestLimit);
        }
        Ok(())
    }
    fn requests(self) -> usize {
        usize::from(self.blocks) * 2 + 2
    }
}
impl Default for Limits {
    fn default() -> Self {
        Self { blocks: 8 }
    }
}
#[derive(Default)]
pub struct Sequence(u64);
impl Sequence {
    fn next(&mut self) -> Result<u64, Error> {
        self.0 = self.0.checked_add(1).ok_or(Error::RequestLimit)?;
        Ok(self.0)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Round {
    pub accepted: u16,
    pub served_bodies: u16,
}

/// Run on the initiator side of a connection; retain the sequence across rounds.
pub fn initiate<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    sequence: &mut Sequence,
    limits: Limits,
) -> Result<Round, Error> {
    limits.check()?;
    let remote = peer.fetch_tip(sequence.next()?)?;
    let accepted = pull(peer, owner, sequence, remote, limits)?;
    let local = with_owner(owner, |o| o.head())?;
    let notice = sequence.next()?;
    peer.advertise_tip(notice, local.0, local.1)?;
    let mut served = 0;
    for _ in 0..limits.requests() {
        let (request, message) = peer.receive_request()?;
        if message == Request::RoundDone {
            if request != notice {
                return Err(Error::Protocol);
            }
            return Ok(Round {
                accepted,
                served_bodies: served,
            });
        }
        served += serve(peer, owner, request, message)?;
    }
    Err(Error::RequestLimit)
}

/// Run on the responder side; service the bounded forward pull before pulling
/// back announced blocks. The same policy and owner validate both directions.
pub fn respond<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    sequence: &mut Sequence,
    limits: Limits,
) -> Result<Round, Error> {
    limits.check()?;
    let mut served = 0;
    for _ in 0..limits.requests() {
        let (request, message) = peer.receive_request()?;
        if let Request::Tip { height, id } = message {
            let accepted = pull(peer, owner, sequence, (height, id), limits)?;
            peer.finish_round(request)?;
            return Ok(Round {
                accepted,
                served_bodies: served,
            });
        }
        if message == Request::RoundDone {
            return Err(Error::Protocol);
        }
        served += serve(peer, owner, request, message)?;
    }
    Err(Error::RequestLimit)
}
fn pull<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    sequence: &mut Sequence,
    remote: (u64, Hash),
    limits: Limits,
) -> Result<u16, Error> {
    let mut accepted = 0;
    while accepted < limits.blocks {
        let local = with_owner(owner, |o| o.head())?;
        if local.0 == remote.0 {
            if local.1 != remote.1 {
                return Err(Error::ForkUnsupported);
            }
            break;
        }
        if local.0 > remote.0 {
            let known = if remote.0 == 0 {
                peer.genesis_id()
            } else {
                with_owner(owner, |o| o.header(remote.0))?
                    .ok_or(Error::Unavailable)?
                    .id()
                    .map_err(|_| Error::Protocol)?
            };
            if known != remote.1 {
                return Err(Error::ForkUnsupported);
            }
            break;
        }
        let next = local.0.checked_add(1).ok_or(Error::Protocol)?;
        let header = peer
            .fetch_header(sequence.next()?, next)?
            .ok_or(Error::Unavailable)?;
        if header.parent != local.1 {
            return Err(Error::ForkUnsupported);
        }
        if next == remote.0 && header.id().map_err(|_| Error::Protocol)? != remote.1 {
            return Err(Error::Protocol);
        }
        let received = peer
            .fetch_body(sequence.next()?, &header)?
            .ok_or(Error::Unavailable)?;
        // The transport reservation stays live during full native admission.
        with_owner(owner, |o| o.accept(&header, &received.body))?;
        drop(received);
        accepted += 1;
    }
    Ok(accepted)
}
fn serve<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    request: u64,
    message: Request,
) -> Result<u16, Error> {
    match message {
        Request::BootstrapManifest { bundle } => {
            let _charge = peer.reserve_bootstrap(super::bootstrap::MAX_MANIFEST_BYTES + 1)?;
            let authenticated_peer = peer.peer();
            let provider = with_owner(owner, |o| o.bootstrap_manifest(authenticated_peer, bundle))?;
            match provider {
                Some(manifest) => peer.send_bootstrap_manifest(request, &manifest)?,
                None => peer.send_bootstrap_missing(request)?,
            }
        }
        Request::BootstrapChunk(query) => {
            let _charge = peer.reserve_bootstrap(query.maximum as usize + 160)?;
            let authenticated_peer = peer.peer();
            let chunk = with_owner(owner, |o| o.bootstrap_chunk(authenticated_peer, query))?;
            match chunk {
                Some(chunk) => peer.send_bootstrap_chunk(request, query, &chunk)?,
                None => peer.send_bootstrap_missing(request)?,
            }
        }
        Request::GetTip => {
            let head = with_owner(owner, |o| o.head())?;
            peer.advertise_tip(request, head.0, head.1)?;
        }
        Request::Header { height } => match with_owner(owner, |o| o.header(height))? {
            Some(header) => peer.send_header(request, &header)?,
            None => peer.send_unavailable(request, height)?,
        },
        Request::Body { height, id } => {
            // The same owner lock covers metadata and extraction. Shared memory
            // is charged before the store allocates an encoded/decoded block.
            let prepared = {
                let guard = owner
                    .lock()
                    .map_err(|_| Error::Owner("owner lock poisoned".into()))?;
                match guard.header(height).map_err(Error::Owner)? {
                    Some(header) if header.id().map_err(|_| Error::Protocol)? == id => {
                        let Some(length) = guard.block_size(height).map_err(Error::Owner)? else {
                            drop(guard);
                            peer.send_unavailable(request, height)?;
                            return Ok(0);
                        };
                        let charge = peer.reserve_body(length)?;
                        let (header, body) = guard.block(height).map_err(Error::Owner)?;
                        Some((header, body, charge))
                    }
                    _ => None,
                }
            };
            match prepared {
                Some((header, body, _charge)) => {
                    peer.send_body(request, &header, &body)?;
                    return Ok(1);
                }
                None => peer.send_unavailable(request, height)?,
            }
        }
        Request::Tip { .. } | Request::RoundDone => return Err(Error::Protocol),
    }
    Ok(0)
}

/// Bounded cold-client requests within the ordinary forward round. Quarantine
/// progress never changes the local owner or its advertised accepted head.
pub struct BootstrapPull<'a, S> {
    peer: &'a mut Peer<S>,
    sequence: &'a mut Sequence,
    remaining: usize,
    deadline: p2p::Deadline,
}
impl<S: Read + Write> BootstrapPull<'_, S> {
    fn request(&mut self) -> Result<u64, Error> {
        self.deadline.check().map_err(|_| p2p::Error::Unavailable)?;
        self.remaining = self.remaining.checked_sub(1).ok_or(Error::RequestLimit)?;
        self.sequence.next()
    }
    pub fn manifest(&mut self) -> Result<Option<super::transport::ReceivedManifest>, Error> {
        self.exact_manifest(None)
    }
    pub fn exact_manifest(
        &mut self,
        bundle: Option<Hash>,
    ) -> Result<Option<super::transport::ReceivedManifest>, Error> {
        let request = self.request()?;
        Ok(self
            .peer
            .fetch_bootstrap_manifest_before(request, bundle, &self.deadline)?)
    }
    pub fn chunk(
        &mut self,
        query: super::transport::ChunkRequest,
    ) -> Result<Option<super::transport::ReceivedChunk>, Error> {
        let request = self.request()?;
        Ok(self
            .peer
            .fetch_bootstrap_chunk_before(request, query, &self.deadline)?)
    }
    pub fn header(&mut self, height: u64) -> Result<Option<Header>, Error> {
        let request = self.request()?;
        let result = self.peer.fetch_header(request, height)?;
        self.deadline.check().map_err(|_| p2p::Error::Unavailable)?;
        Ok(result)
    }
    pub fn body(
        &mut self,
        header: &Header,
    ) -> Result<Option<super::transport::ReceivedBody>, Error> {
        let request = self.request()?;
        let result = self.peer.fetch_body(request, header)?;
        self.deadline.check().map_err(|_| p2p::Error::Unavailable)?;
        Ok(result)
    }
}
/// A cold client requests at most the normal forward budget, then advertises
/// its actual admitted head and serves the reverse pull. The caller must still
/// run the universal checkpoint/transaction phases after this ordinary round.
pub fn initiate_bootstrap<S: Read + Write, O: Owner, T>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    sequence: &mut Sequence,
    limits: Limits,
    pull: impl FnOnce(&mut BootstrapPull<'_, S>) -> Result<T, Error>,
) -> Result<(Round, T), Error> {
    limits.check()?;
    let result = pull(&mut BootstrapPull {
        peer,
        sequence,
        remaining: limits.requests() - 1,
        // Full native bodies use the ordinary transport's 180-second cap.
        // A shorter outer cap would discard an otherwise valid completed body
        // on slow outbound links and make every resumed attempt start over.
        deadline: p2p::Deadline::new(std::time::Duration::from_secs(180)),
    })?;
    let local = with_owner(owner, |o| o.head())?;
    let notice = sequence.next()?;
    peer.advertise_tip(notice, local.0, local.1)?;
    let mut served = 0;
    for _ in 0..limits.requests() {
        let (request, message) = peer.receive_request()?;
        if message == Request::RoundDone {
            if request != notice {
                return Err(Error::Protocol);
            }
            return Ok((
                Round {
                    accepted: 0,
                    served_bodies: served,
                },
                result,
            ));
        }
        served += serve(peer, owner, request, message)?;
    }
    Err(Error::RequestLimit)
}
fn with_owner<O: Owner, T>(
    owner: &Arc<Mutex<O>>,
    f: impl FnOnce(&mut O) -> Result<T, String>,
) -> Result<T, Error> {
    f(&mut *owner
        .lock()
        .map_err(|_| Error::Owner("owner lock poisoned".into()))?)
    .map_err(Error::Owner)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::eng2::{
        body::Policy,
        genesis::{FeeMode, Genesis},
    };
    use std::os::unix::net::UnixStream;
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
            max_settlement_proof_bytes: 4096,
        }
    }
    /// Framing-only fixture. This owner does not stand in for native proof or
    /// consensus acceptance; production uses the resident Driver/Store path.
    struct Fixture {
        genesis: Hash,
        blocks: Vec<(Header, Body)>,
        fail: bool,
    }
    impl Owner for Fixture {
        fn head(&self) -> Result<(u64, Hash), String> {
            if self.fail {
                return Err("synthetic storage failure".into());
            }
            match self.blocks.last() {
                Some((h, _)) => Ok((h.height, h.id().unwrap())),
                None => Ok((0, self.genesis)),
            }
        }
        fn header(&self, height: u64) -> Result<Option<Header>, String> {
            if self.fail {
                return Err("synthetic storage failure".into());
            }
            Ok(self
                .blocks
                .iter()
                .find(|(h, _)| h.height == height)
                .map(|(h, _)| h.clone()))
        }
        fn block_size(&self, height: u64) -> Result<Option<usize>, String> {
            self.blocks
                .iter()
                .find(|(h, _)| h.height == height)
                .map(|(_, b)| b.encoded_len(policy()))
                .transpose()
        }
        fn block(&self, height: u64) -> Result<(Header, Body), String> {
            self.blocks
                .iter()
                .find(|(h, _)| h.height == height)
                .cloned()
                .ok_or("missing synthetic block".into())
        }
        fn accept(&mut self, h: &Header, b: &Body) -> Result<(), String> {
            let head = self.head()?;
            if h.height != head.0 + 1
                || h.parent != head.1
                || b.commitment(policy())? != h.body_commitment
            {
                return Err("synthetic sequence mismatch".into());
            }
            self.blocks.push((h.clone(), b.clone()));
            Ok(())
        }
    }
    fn fixture(count: u64) -> Fixture {
        let g = genesis();
        let mut out = Fixture {
            genesis: g.id(),
            blocks: vec![],
            fail: false,
        };
        for height in 1..=count {
            let mut body = crate::eng2::body::tests::body();
            body.network = g.config().network;
            body.height = height;
            body.profile = policy().profile;
            body.governance.clear();
            body.fund_claims.clear();
            body.transactions
                .sort_by_key(|t| t.record.statement_id(&body.network));
            let header = Header {
                network: body.network,
                height,
                parent: out.head().unwrap().1,
                timestamp: height * 300,
                target: [255; 32],
                execution_commitment: [4; 32],
                body_commitment: body.commitment(policy()).unwrap(),
                nonce: height,
            };
            out.blocks.push((header, body));
        }
        out
    }
    fn peers() -> (Peer<UnixStream>, Peer<UnixStream>, p2p::Budget) {
        let (a, b) = UnixStream::pair().unwrap();
        for socket in [&a, &b] {
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
        }
        let g = genesis();
        let budget = p2p::Budget::default();
        let a = p2p::Session::from_test_channel(a, g.peer_binding(), budget.clone());
        let b = p2p::Session::from_test_channel(b, g.peer_binding(), budget.clone());
        (
            Peer::new(a, &g, policy()).unwrap(),
            Peer::new(b, &g, policy()).unwrap(),
            budget,
        )
    }
    fn rounds(client_count: u64, server_count: u64) -> (Round, Round) {
        let (mut a, mut b, budget) = peers();
        let before = budget.available().unwrap();
        let client = Arc::new(Mutex::new(fixture(client_count)));
        let server = Arc::new(Mutex::new(fixture(server_count)));
        let server_thread = server.clone();
        let thread = std::thread::spawn(move || {
            let mut sequence = Sequence::default();
            let mut result = Round::default();
            for _ in 0..2 {
                let round =
                    respond(&mut b, &server_thread, &mut sequence, Limits { blocks: 1 }).unwrap();
                result.accepted += round.accepted;
                result.served_bodies += round.served_bodies;
            }
            result
        });
        let mut sequence = Sequence::default();
        let mut result = Round::default();
        for _ in 0..2 {
            let round = initiate(&mut a, &client, &mut sequence, Limits { blocks: 1 }).unwrap();
            result.accepted += round.accepted;
            result.served_bodies += round.served_bodies;
        }
        let remote = thread.join().unwrap();
        assert_eq!(
            client.lock().unwrap().head().unwrap(),
            server.lock().unwrap().head().unwrap()
        );
        assert_eq!(budget.available().unwrap(), before);
        (result, remote)
    }
    #[test]
    fn initiator_pulls_in_bounded_rounds_and_releases_frame_ownership() {
        let (a, b) = rounds(0, 2);
        assert_eq!(a.accepted, 2);
        assert_eq!(b.served_bodies, 2);
    }
    #[test]
    fn outbound_only_initiator_relays_blocks_during_reverse_phase() {
        let (a, b) = rounds(2, 0);
        assert_eq!(b.accepted, 2);
        assert_eq!(a.served_bodies, 2);
    }
    #[test]
    fn equal_height_unknown_fork_is_rejected_without_state_mutation() {
        let (mut a, mut b, _) = peers();
        let client = Arc::new(Mutex::new(fixture(1)));
        let mut other = fixture(1);
        other.blocks[0].0.nonce += 1;
        let server = Arc::new(Mutex::new(other));
        let server_thread = server.clone();
        let thread = std::thread::spawn(move || {
            respond(
                &mut b,
                &server_thread,
                &mut Sequence::default(),
                Limits { blocks: 1 },
            )
        });
        let before = client.lock().unwrap().head().unwrap();
        assert!(matches!(
            initiate(
                &mut a,
                &client,
                &mut Sequence::default(),
                Limits { blocks: 1 }
            ),
            Err(Error::ForkUnsupported)
        ));
        assert_eq!(client.lock().unwrap().head().unwrap(), before);
        drop(a);
        assert!(thread.join().unwrap().is_err());
    }
    #[test]
    fn real_storage_failures_are_not_converted_to_missing_blocks() {
        let (mut a, _, _) = peers();
        let mut fixture = fixture(1);
        fixture.fail = true;
        let owner = Arc::new(Mutex::new(fixture));
        assert!(matches!(
            serve(&mut a, &owner, 1, Request::Header { height: 1 }),
            Err(Error::Owner(_))
        ));
    }
    #[test]
    fn lower_height_unknown_fork_is_rejected_before_reverse_admission() {
        let (mut a, mut b, _) = peers();
        let client = Arc::new(Mutex::new(fixture(2)));
        let mut other = fixture(1);
        other.blocks[0].0.nonce += 1;
        let server = Arc::new(Mutex::new(other));
        let thread = std::thread::spawn(move || {
            respond(
                &mut b,
                &server,
                &mut Sequence::default(),
                Limits { blocks: 1 },
            )
        });
        assert!(matches!(
            initiate(
                &mut a,
                &client,
                &mut Sequence::default(),
                Limits { blocks: 1 }
            ),
            Err(Error::ForkUnsupported)
        ));
        assert_eq!(client.lock().unwrap().head().unwrap().0, 2);
        drop(a);
        assert!(thread.join().unwrap().is_err());
    }
}
