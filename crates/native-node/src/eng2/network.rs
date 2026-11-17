//! Sequential bidirectional rounds over an established eng-2 session.
//!
//! The initiator first pulls, then advertises its tip and serves the responder's
//! pull. This allows outbound miners to relay blocks without a new listener.
//! Enabled owners retain competing raw branches through bounded discovery.
//! Fork selection and append-based switching belong to the driver owner; see
//! `docs/eng2-reorganization.md` for state and acceptance boundaries.

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
pub type BodyProgress = Box<dyn Fn(usize, usize) + Send + Sync>;
pub trait Owner: Send {
    fn head(&self) -> Result<(u64, Hash), String>;
    fn header(&self, height: u64) -> Result<Option<Header>, String>;
    /// Reads the persisted encoded length without copying or decoding a body.
    fn block_size(&self, height: u64) -> Result<Option<usize>, String>;
    fn block(&self, height: u64) -> Result<(Header, Body), String>;
    fn accept(&mut self, header: &Header, body: &Body) -> Result<(), String>;
    fn authorize_body(
        &mut self,
        header: &Header,
        budget: &p2p::Budget,
        binding: p2p::Binding,
        expires: std::time::Instant,
    ) -> Result<Option<p2p::BodyAuthorization>, String> {
        let now = std::time::Instant::now();
        let deadline = &crate::p2p::Deadline::from_started(
            now,
            expires.saturating_duration_since(now),
            crate::p2p::Cancellation::default(),
        );
        #[cfg(test)]
        {
            let scope = budget
                .resident_body_scope(
                    1,
                    std::time::Instant::now() + std::time::Duration::from_secs(3600),
                )
                .map_err(|_| "test body scope unavailable")?;
            budget
                .authorize_body(
                    &scope,
                    binding,
                    header.height,
                    header.id().map_err(|_| "test header invalid")?,
                    deadline,
                )
                .map(Some)
                .map_err(|_| "test body authorization unavailable".into())
        }
        #[cfg(not(test))]
        {
            let _ = (header, budget, binding, deadline);
            Err("body lifecycle owner unavailable".into())
        }
    }
    #[cfg(feature = "eng2-runtime")]
    fn body_progress(
        &self,
        _header: &Header,
        _peer: Hash,
        _claim: &p2p::BodyClaim,
    ) -> Result<Option<BodyProgress>, String> {
        Ok(None)
    }
    #[cfg(feature = "eng2-runtime")]
    fn accept_received(
        &mut self,
        header: &Header,
        received: &super::transport::ReceivedBody,
    ) -> Result<(), String> {
        self.accept(header, &received.body)
    }
    /// Opt in only when exact canonical and independent raw-branch queries are
    /// wired. Advertising this does not assert that any competitor is valid.
    fn exact_exchange_enabled(&self) -> bool {
        false
    }
    fn branch_discovery_next(
        &mut self,
        _remote: (u64, Hash),
        _authenticated_peer: Hash,
        _now_ms: u64,
    ) -> Result<DiscoveryAction, String> {
        Ok(DiscoveryAction::Deferred)
    }
    fn branch_discovery_received(
        &mut self,
        _request: super::branches::discovery::HeaderRequest,
        _header: Option<Header>,
        _now_ms: u64,
    ) -> Result<(), String> {
        Err("branch discovery owner unavailable".into())
    }
    fn checkpoint_headers_next(
        &mut self,
        _remote: (u64, Hash),
        _authenticated_peer: Hash,
        _now_ms: u64,
    ) -> Result<DiscoveryAction, String> {
        Ok(DiscoveryAction::Deferred)
    }
    fn branch_discovery_deferred(
        &mut self,
        _request: super::branches::discovery::HeaderRequest,
        _now_ms: u64,
    ) -> Result<(), String> {
        Err("branch discovery owner unavailable".into())
    }
    fn branch_discovery_body(
        &mut self,
        _request: super::branches::discovery::HeaderRequest,
        _header: &Header,
        _body: &Body,
        _now_ms: u64,
    ) -> Result<(), String> {
        Err("branch discovery owner unavailable".into())
    }
    /// Optional independent raw-branch storage. Header/body retention does not
    /// assert complete native validity or change the owner's canonical head.
    fn branch_header(&self, _id: Hash) -> Result<Option<Header>, String> {
        Ok(None)
    }
    /// Persisted encoded length, read before any raw body allocation.
    fn branch_block_size(&self, _id: Hash) -> Result<Option<usize>, String> {
        Ok(None)
    }
    fn branch_block(&self, _id: Hash) -> Result<(Header, Body), String> {
        Err("independent branch body unavailable".into())
    }
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
/// Owner-reserved work only; Ready means raw materials, never canonical adoption.
pub enum DiscoveryAction {
    Header(super::branches::discovery::HeaderRequest),
    Body {
        request: super::branches::discovery::HeaderRequest,
        header: Header,
        ownership: Box<p2p::BodyClaim>,
    },
    Ready,
    Deferred,
}
/// Use this same process-local clock when constructing the node discovery ledger.
pub fn discovery_now_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    u64::try_from(
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}
#[derive(Debug)]
pub enum Error {
    Transport(p2p::Error),
    Owner(String),
    Protocol,
    ForkUnsupported,
    Unavailable,
    RequestLimit,
    Discovery(super::branches::discovery::Error),
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
    pub(crate) fn next(&mut self) -> Result<u64, Error> {
        self.0 = self.0.checked_add(1).ok_or(Error::RequestLimit)?;
        Ok(self.0)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Round {
    pub accepted: u16,
    pub served_bodies: u16,
    /// Local head checked under the owner lock against the peer's advertised
    /// tip or known prefix. A full pull batch carries no exhausted-tip evidence.
    pub checked_head: Option<(u64, Hash)>,
}
struct Pulled {
    accepted: u16,
    checked_head: Option<(u64, Hash)>,
}

/// Run on the initiator side of a connection; retain the sequence across rounds.
pub fn initiate<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    sequence: &mut Sequence,
    limits: Limits,
) -> Result<Round, Error> {
    initiate_with_checkpoint_headers(peer, owner, sequence, limits, None)
}
pub(crate) fn initiate_with_checkpoint_headers<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    sequence: &mut Sequence,
    limits: Limits,
    checkpoint: Option<(u64, Hash)>,
) -> Result<Round, Error> {
    limits.check()?;
    let remote = peer.fetch_tip(sequence.next()?)?;
    let pulled = pull_with_checkpoint_headers(peer, owner, sequence, remote, limits, checkpoint)?;
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
                accepted: pulled.accepted,
                served_bodies: served,
                checked_head: pulled.checked_head,
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
    respond_with_round_start(peer, owner, sequence, limits, || Ok(()))
}
/// Notify the resident only after the first actual authenticated request has
/// arrived. Idle responders retain completed-round evidence until its expiry.
pub(crate) fn respond_with_round_start<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    sequence: &mut Sequence,
    limits: Limits,
    on_round_started: impl FnOnce() -> Result<(), String>,
) -> Result<Round, Error> {
    respond_with_checkpoint_headers(peer, owner, sequence, limits, on_round_started, None)
}
pub(crate) fn respond_with_checkpoint_headers<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    sequence: &mut Sequence,
    limits: Limits,
    on_round_started: impl FnOnce() -> Result<(), String>,
    checkpoint: Option<(u64, Hash)>,
) -> Result<Round, Error> {
    limits.check()?;
    let mut started = Some(on_round_started);
    let mut served = 0;
    for _ in 0..limits.requests() {
        let (request, message) = peer.receive_request()?;
        if let Some(notify) = started.take() {
            notify().map_err(Error::Owner)?;
        }
        if let Request::Tip { height, id } = message {
            let pulled = pull_with_checkpoint_headers(
                peer,
                owner,
                sequence,
                (height, id),
                limits,
                checkpoint,
            )?;
            peer.finish_round(request)?;
            return Ok(Round {
                accepted: pulled.accepted,
                served_bodies: served,
                checked_head: pulled.checked_head,
            });
        }
        if message == Request::RoundDone {
            return Err(Error::Protocol);
        }
        served += serve(peer, owner, request, message)?;
    }
    Err(Error::RequestLimit)
}
#[cfg(test)]
fn pull<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    sequence: &mut Sequence,
    remote: (u64, Hash),
    limits: Limits,
) -> Result<Pulled, Error> {
    pull_with_checkpoint_headers(peer, owner, sequence, remote, limits, None)
}
fn pull_with_checkpoint_headers<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    sequence: &mut Sequence,
    remote: (u64, Hash),
    limits: Limits,
    checkpoint: Option<(u64, Hash)>,
) -> Result<Pulled, Error> {
    let mut accepted = 0;
    let mut used_requests = 0;
    while accepted < limits.blocks {
        // Bind the reported head and the remote-prefix comparison in one
        // owner critical section. Later phases cannot relabel this evidence.
        let comparison = with_owner(owner, |o| {
            let local = o.head()?;
            if local.0 < remote.0 {
                if peer.competing_head_matches(local, remote) {
                    return Ok(Err(Error::ForkUnsupported));
                }
                return Ok(Ok((local, false)));
            }
            let known = if local.0 == remote.0 {
                Ok(local.1)
            } else if remote.0 == 0 {
                Ok(peer.genesis_id())
            } else {
                match o.header(remote.0)? {
                    Some(header) => header.id().map_err(|_| Error::Protocol),
                    None => Err(Error::Unavailable),
                }
            };
            Ok(known.and_then(|id| {
                if id != remote.1 {
                    Err(Error::ForkUnsupported)
                } else {
                    Ok((local, true))
                }
            }))
        })?;
        let (local, caught_up) = match comparison {
            Ok(value) => value,
            Err(Error::ForkUnsupported) => {
                discover_fork(
                    peer,
                    owner,
                    sequence,
                    remote,
                    usize::from(limits.blocks) * 2 - used_requests,
                )?;
                return Ok(Pulled {
                    accepted,
                    checked_head: None,
                });
            }
            Err(error) => return Err(error),
        };
        if caught_up {
            if let Some(target) = checkpoint {
                discover_fork_kind(
                    peer,
                    owner,
                    sequence,
                    target,
                    usize::from(limits.blocks) * 2 - used_requests,
                    true,
                )?;
            }
            return Ok(Pulled {
                accepted,
                checked_head: Some(local),
            });
        }
        if used_requests >= usize::from(limits.blocks) * 2 {
            break;
        }
        let next = local.0.checked_add(1).ok_or(Error::Protocol)?;
        let header = peer
            .fetch_header(sequence.next()?, next)?
            .ok_or(Error::Unavailable)?;
        used_requests += 1;
        if header.parent != local.1 {
            // Preserve the scheduling decision across rounds: with one-block
            // rounds the ordinary header leaves no room for probe + object.
            // An unchanged pair starts discovery directly in the next round.
            peer.remember_competing_head(local, remote);
            discover_fork(
                peer,
                owner,
                sequence,
                remote,
                usize::from(limits.blocks) * 2 - used_requests,
            )?;
            return Ok(Pulled {
                accepted,
                checked_head: None,
            });
        }
        if next == remote.0 && header.id().map_err(|_| Error::Protocol)? != remote.1 {
            return Err(Error::Protocol);
        }
        // A concurrent connection may have committed this exact block while
        // the header was in flight. Avoid fetching its body again.
        if with_owner(owner, |o| canonical_contains(o, &header))? {
            continue;
        }
        if used_requests >= usize::from(limits.blocks) * 2 {
            break;
        }
        let deadline = p2p::Deadline::new(super::transport::BODY_FETCH_TIMEOUT);
        let authorization = with_owner(owner, |o| {
            o.authorize_body(
                &header,
                &peer.body_budget(),
                peer.body_binding(),
                deadline.expires_at(),
            )
        })?;
        let Some(authorization) = authorization else {
            continue;
        };
        let ownership =
            match peer.claim_body_authorized(&header, &authorization, p2p::BodyMode::Legacy) {
                Ok(claim) => claim,
                Err(
                    p2p::BodyClaimError::Busy
                    | p2p::BodyClaimError::Capacity
                    | p2p::BodyClaimError::Expired
                    | p2p::BodyClaimError::SourceUsed
                    | p2p::BodyClaimError::QueryLimit,
                ) => {
                    return Ok(Pulled {
                        accepted,
                        checked_head: None,
                    });
                }
                Err(_) => return Err(Error::Unavailable),
            };
        #[cfg(feature = "eng2-runtime")]
        let progress = with_owner(owner, |o| o.body_progress(&header, peer.peer(), &ownership))?;
        #[cfg(not(feature = "eng2-runtime"))]
        let progress: Option<Box<dyn Fn(usize, usize) + Send + Sync>> = None;
        let result = peer.fetch_body_owned(
            sequence.next()?,
            &header,
            ownership,
            progress.as_deref().map(|p| p as &dyn Fn(usize, usize)),
        );
        drop(progress);
        let received = result?.ok_or(Error::Unavailable)?;
        used_requests += 1;
        // The transport reservation stays live during full native admission.
        let newly_accepted = accept_pulled(owner, &header, &received)?;
        received.ownership.complete();
        drop(received);
        accepted += u16::from(newly_accepted);
    }
    Ok(Pulled {
        accepted,
        checked_head: None,
    })
}
fn canonical_contains<O: Owner>(owner: &O, header: &Header) -> Result<bool, String> {
    if owner.head()?.0 < header.height {
        return Ok(false);
    }
    match owner.header(header.height)? {
        Some(canonical) => Ok(canonical.id().map_err(|e| format!("{e:?}"))?
            == header.id().map_err(|e| format!("{e:?}"))?),
        None => Ok(false),
    }
}
fn discover_fork<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    sequence: &mut Sequence,
    remote: (u64, Hash),
    remaining: usize,
) -> Result<(), Error> {
    discover_fork_kind(peer, owner, sequence, remote, remaining, false)
}
fn discover_fork_kind<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    sequence: &mut Sequence,
    remote: (u64, Hash),
    mut remaining: usize,
    headers_only: bool,
) -> Result<(), Error> {
    if !with_owner(owner, |o| Ok(o.exact_exchange_enabled()))? {
        return Err(Error::ForkUnsupported);
    }
    while remaining > 0 {
        // A new live session needs both its compatibility probe and object
        // request in this round. Do not consume a source attempt when only
        // the probe fits; the next round retains its full object allowance.
        if !peer.exact_blocks_supported() && remaining < 2 {
            return Ok(());
        }
        // Reserve before probing: negative capability and repeated reconnects
        // consume the same node-wide source attempt, rather than bypassing it.
        let action = with_owner(owner, |o| {
            if headers_only {
                o.checkpoint_headers_next(remote, peer.peer(), discovery_now_ms())
            } else {
                o.branch_discovery_next(remote, peer.peer(), discovery_now_ms())
            }
        })?;
        let (ticket, body_header, ownership) = match action {
            DiscoveryAction::Ready | DiscoveryAction::Deferred => return Ok(()),
            DiscoveryAction::Header(ticket) => (ticket, None, None),
            DiscoveryAction::Body {
                request,
                header,
                ownership,
            } => (request, Some(header), Some(*ownership)),
        };
        if ticket.peer() != peer.peer() || ticket.is_body() != body_header.is_some() {
            return Err(Error::Protocol);
        }
        if headers_only
            && (body_header.is_some() || remote.0.saturating_sub(ticket.query().0) >= 24)
        {
            with_owner(owner, |o| {
                o.branch_discovery_deferred(ticket, discovery_now_ms())
            })?;
            return Ok(());
        }
        if !peer.exact_blocks_supported() {
            remaining -= 1;
            let available = peer.probe_exact_blocks(sequence.next()?);
            match available {
                Ok(true) if remaining > 0 => (),
                Ok(_) => {
                    with_owner(owner, |o| {
                        o.branch_discovery_deferred(ticket, discovery_now_ms())
                    })?;
                    return Ok(());
                }
                Err(error) => {
                    with_owner(owner, |o| {
                        o.branch_discovery_deferred(ticket, discovery_now_ms())
                    })?;
                    return Err(error.into());
                }
            }
        }
        remaining -= 1;
        if let Some(header) = body_header {
            if ticket.query() != (header.height, header.id().map_err(|_| Error::Protocol)?) {
                return Err(Error::Protocol);
            }
            let ownership = ownership.ok_or(Error::Protocol)?;
            #[cfg(feature = "eng2-runtime")]
            let progress =
                with_owner(owner, |o| o.body_progress(&header, peer.peer(), &ownership))?;
            #[cfg(not(feature = "eng2-runtime"))]
            let progress: Option<Box<dyn Fn(usize, usize) + Send + Sync>> = None;
            let result = peer.fetch_body_owned(
                sequence.next()?,
                &header,
                ownership,
                progress.as_deref().map(|p| p as &dyn Fn(usize, usize)),
            );
            drop(progress);
            match result {
                Ok(Some(received)) => {
                    with_owner(owner, |o| {
                        received
                            .ownership
                            .check_active()
                            .map_err(|_| "body ownership expired before retention".to_string())?;
                        o.branch_discovery_body(ticket, &header, &received.body, discovery_now_ms())
                    })?;
                    received.ownership.complete();
                    drop(received);
                }
                Ok(None) => with_owner(owner, |o| {
                    o.branch_discovery_deferred(ticket, discovery_now_ms())
                })?,
                Err(error) => {
                    with_owner(owner, |o| {
                        o.branch_discovery_deferred(ticket, discovery_now_ms())
                    })?;
                    return Err(error.into());
                }
            }
        } else {
            let (height, id) = ticket.query();
            match peer.fetch_header_by_id(sequence.next()?, height, id) {
                Ok(header) => with_owner(owner, |o| {
                    o.branch_discovery_received(ticket, header, discovery_now_ms())
                })?,
                Err(error) => {
                    with_owner(owner, |o| {
                        o.branch_discovery_deferred(ticket, discovery_now_ms())
                    })?;
                    return Err(error.into());
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn serve<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    request: u64,
    message: Request,
) -> Result<u16, Error> {
    match message {
        Request::Propagation(_) => return Err(Error::Protocol),
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
        Request::Header {
            height: super::transport::lanes::CAPABILITY_HEIGHT,
        } => {
            peer.send_lane_capabilities(request)?;
        }
        Request::Header {
            height: super::transport::propagation::CAPABILITY_HEIGHT,
        } => {
            peer.send_unavailable(request, super::transport::propagation::CAPABILITY_HEIGHT)?;
        }
        Request::Header { height: 0 } => {
            let available = with_owner(owner, |o| Ok(o.exact_exchange_enabled()))?;
            if available {
                peer.send_exact_capabilities(request, true)?;
            } else {
                // Preserve the old response until an owner enables the feature.
                peer.send_unavailable(request, 0)?;
            }
        }
        Request::Header { height } => match with_owner(owner, |o| o.header(height))? {
            Some(header) => peer.send_header(request, &header)?,
            None => peer.send_unavailable(request, height)?,
        },
        Request::HeaderById { height, id } => {
            let header = with_owner(owner, |o| match o.header(height)? {
                Some(header) if header.id().map_err(|_| "canonical identity rejected")? == id => {
                    Ok(Some(header))
                }
                _ => o.branch_header(id),
            })?;
            match header {
                Some(header)
                    if header.height == height
                        && header.id().map_err(|_| Error::Protocol)? == id =>
                {
                    peer.send_header(request, &header)?;
                }
                Some(_) => return Err(Error::Protocol),
                None => peer.send_unavailable_id(request, height, id)?,
            }
        }
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
                    _ => match guard.branch_header(id).map_err(Error::Owner)? {
                        Some(header) => {
                            if header.height != height
                                || header.id().map_err(|_| Error::Protocol)? != id
                            {
                                return Err(Error::Protocol);
                            }
                            let Some(length) = guard.branch_block_size(id).map_err(Error::Owner)?
                            else {
                                drop(guard);
                                peer.send_unavailable(request, height)?;
                                return Ok(0);
                            };
                            let charge = peer.reserve_body(length)?;
                            let (stored_header, body) =
                                guard.branch_block(id).map_err(Error::Owner)?;
                            if stored_header != header {
                                return Err(Error::Protocol);
                            }
                            Some((stored_header, body, charge))
                        }
                        None => None,
                    },
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

/// Linear completion returned without retaining the node's discovery lock
/// during socket I/O. Finish it against the same shared ledger afterwards.
pub struct DiscoveryResponse {
    request: super::branches::discovery::HeaderRequest,
    result: Result<Option<Header>, Error>,
}
impl DiscoveryResponse {
    pub fn finish(
        self,
        ledger: &mut super::branches::discovery::Ledger,
        now_ms: u64,
    ) -> Result<Option<super::branches::discovery::Cursor>, Error> {
        match self.result {
            Ok(Some(header)) => ledger
                .receive(self.request, header, now_ms)
                .map(Some)
                .map_err(Error::Discovery),
            other => {
                ledger
                    .defer(self.request, now_ms)
                    .map_err(Error::Discovery)?;
                other.map(|_| None)
            }
        }
    }
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
    /// The compatible height-zero probe consumes one ordinary round request.
    /// Its result is cached by the live peer, never by an identity across reconnects.
    pub fn probe_exact_blocks(&mut self) -> Result<bool, Error> {
        let request = self.request()?;
        let result = self.peer.probe_exact_blocks(request)?;
        self.deadline.check().map_err(|_| p2p::Error::Unavailable)?;
        Ok(result)
    }
    /// Exact ancestors share the ordinary bounded round request budget.
    pub fn header_by_id(&mut self, height: u64, id: Hash) -> Result<Option<Header>, Error> {
        let request = self.request()?;
        let result = self.peer.fetch_header_by_id(request, height, id)?;
        self.deadline.check().map_err(|_| p2p::Error::Unavailable)?;
        Ok(result)
    }
    /// The request was reserved under a short node-ledger lock. This method
    /// owns it across I/O, checks the authenticated source and returns it for
    /// completion; no request or candidate quota is refunded on failure.
    pub fn discovery_header(
        &mut self,
        request: super::branches::discovery::HeaderRequest,
    ) -> DiscoveryResponse {
        let (height, id) = request.query();
        let result = if request.peer() != self.peer.peer() {
            Err(Error::Protocol)
        } else {
            self.header_by_id(height, id)
        };
        DiscoveryResponse { request, result }
    }
    pub(crate) fn authorize_body(
        &self,
        scope: &p2p::BodyScope,
        binding: p2p::Binding,
        header: &Header,
    ) -> Result<p2p::BodyAuthorization, Error> {
        if binding != self.peer.body_binding() {
            return Err(Error::Protocol);
        }
        let deadline = p2p::Deadline::new(super::transport::BODY_FETCH_TIMEOUT);
        self.peer
            .body_budget()
            .authorize_body(
                scope,
                binding,
                header.height,
                header.id().map_err(|_| Error::Protocol)?,
                &deadline,
            )
            .map_err(|_| Error::Unavailable)
    }
    pub(crate) fn body_authorized(
        &mut self,
        header: &Header,
        authorization: &p2p::BodyAuthorization,
    ) -> Result<Option<super::transport::ReceivedBody>, Error> {
        let request = self.request()?;
        let ownership = self
            .peer
            .claim_body_authorized(header, authorization, p2p::BodyMode::Legacy)
            .map_err(|_| Error::Unavailable)?;
        let result = self
            .peer
            .fetch_body_owned(request, header, ownership, None)?;
        self.deadline.check().map_err(|_| p2p::Error::Unavailable)?;
        Ok(result)
    }
    #[cfg(test)]
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
                    checked_head: None,
                },
                result,
            ));
        }
        served += serve(peer, owner, request, message)?;
    }
    Err(Error::RequestLimit)
}
fn accept_pulled<O: Owner>(
    owner: &Arc<Mutex<O>>,
    header: &Header,
    received: &super::transport::ReceivedBody,
) -> Result<bool, Error> {
    with_owner(owner, |owner| {
        // An independently committed exact duplicate publishes nothing new.
        // Check it under the same lock before enforcing the download lifetime.
        if canonical_contains(owner, header)? {
            return Ok(false);
        }
        received
            .ownership
            .check_active()
            .map_err(|_| "body ownership expired before admission".to_string())?;
        #[cfg(feature = "eng2-runtime")]
        owner.accept_received(header, received)?;
        #[cfg(not(feature = "eng2-runtime"))]
        owner.accept(header, &received.body)?;
        Ok(true)
    })
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
    #[test]
    fn ordinary_channel_declines_piece_capability_and_keeps_the_following_turn_usable() {
        let (mut client, mut server, _) = peers();
        let owner = Arc::new(Mutex::new(fixture(1)));
        let expected = owner.lock().unwrap().head().unwrap();
        let worker = std::thread::spawn(move || {
            for _ in 0..2 {
                let (request, message) = server.receive_request().unwrap();
                serve(&mut server, &owner, request, message).unwrap();
            }
            let (request, message) = server.receive_request().unwrap();
            assert!(matches!(message, Request::RoundDone));
            server.finish_round(request).unwrap();
        });
        assert!(!client.probe_propagation(1).unwrap());
        assert!(!client.propagation_supported());
        assert_eq!(client.fetch_tip(2).unwrap(), expected);
        client.finish_round(3).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn concurrent_canonical_acceptance_before_header_response_avoids_body_download() {
        let (mut client_peer, mut server_peer, _) = peers();
        let client = Arc::new(Mutex::new(fixture(0)));
        let advance = client.clone();
        let remote = Arc::new(Mutex::new(fixture(1)));
        let target = remote.lock().unwrap().head().unwrap();
        let worker = std::thread::spawn(move || {
            let (request, message) = server_peer.receive_request().unwrap();
            assert!(matches!(message, Request::Header { height: 1 }));
            *advance.lock().unwrap() = fixture(1);
            serve(&mut server_peer, &remote, request, message).unwrap();
            // No body frame is provided. The independently committed exact
            // canonical header must make another body fetch unnecessary.
        });
        let result = pull(
            &mut client_peer,
            &client,
            &mut Sequence::default(),
            target,
            Limits::default(),
        );
        worker.join().unwrap();
        let result = result.expect("the exact canonical block is already committed");
        assert_eq!(result.accepted, 0);
        assert_eq!(result.checked_head, Some(target));
        assert_eq!(client.lock().unwrap().blocks.len(), 1);
    }
    #[test]
    fn concurrent_canonical_acceptance_during_body_response_preserves_the_round() {
        let (mut client_peer, mut server_peer, _) = peers();
        let client = Arc::new(Mutex::new(fixture(0)));
        let advance = client.clone();
        let remote = Arc::new(Mutex::new(fixture(1)));
        let target = remote.lock().unwrap().head().unwrap();
        let worker = std::thread::spawn(move || {
            let (request, message) = server_peer.receive_request().unwrap();
            assert!(matches!(message, Request::Header { height: 1 }));
            serve(&mut server_peer, &remote, request, message).unwrap();
            let (request, message) = server_peer.receive_request().unwrap();
            assert!(matches!(message, Request::Body { height: 1, .. }));
            *advance.lock().unwrap() = fixture(1);
            serve(&mut server_peer, &remote, request, message).unwrap();
        });
        let result = pull(
            &mut client_peer,
            &client,
            &mut Sequence::default(),
            target,
            Limits::default(),
        );
        worker.join().unwrap();
        let result = result.expect("a competing successful download is not a peer failure");
        assert_eq!(result.accepted, 0);
        assert_eq!(result.checked_head, Some(target));
        assert_eq!(client.lock().unwrap().blocks.len(), 1);
    }
    #[test]
    fn concurrent_conflicting_head_does_not_make_a_downloaded_block_canonical() {
        let (mut client_peer, mut server_peer, _) = peers();
        let client = Arc::new(Mutex::new(fixture(0)));
        let advance = client.clone();
        let remote = Arc::new(Mutex::new(fixture(1)));
        let target = remote.lock().unwrap().head().unwrap();
        let worker = std::thread::spawn(move || {
            let (request, message) = server_peer.receive_request().unwrap();
            serve(&mut server_peer, &remote, request, message).unwrap();
            let (request, message) = server_peer.receive_request().unwrap();
            assert!(matches!(message, Request::Body { height: 1, .. }));
            let mut competing = fixture(1);
            competing.blocks[0].0.nonce += 1;
            *advance.lock().unwrap() = competing;
            serve(&mut server_peer, &remote, request, message).unwrap();
        });
        let result = pull(
            &mut client_peer,
            &client,
            &mut Sequence::default(),
            target,
            Limits::default(),
        );
        worker.join().unwrap();
        assert!(matches!(result, Err(Error::Owner(_))));
        assert_ne!(client.lock().unwrap().head().unwrap(), target);
        assert_eq!(client.lock().unwrap().blocks.len(), 1);
    }
    #[test]
    fn concurrent_canonical_advances_preserve_the_round_request_limit() {
        let (mut client_peer, mut server_peer, _) = peers();
        let client = Arc::new(Mutex::new(fixture(0)));
        let advance = client.clone();
        let remote = Arc::new(Mutex::new(fixture(3)));
        let target = remote.lock().unwrap().head().unwrap();
        let worker = std::thread::spawn(move || {
            for height in 1..=2 {
                let (request, message) = server_peer.receive_request().unwrap();
                assert!(matches!(message, Request::Header { height: h } if h == height));
                *advance.lock().unwrap() = fixture(height);
                serve(&mut server_peer, &remote, request, message).unwrap();
            }
            // A one-block pull has at most two header/body requests, even
            // when another connection commits every requested block.
        });
        let result = pull(
            &mut client_peer,
            &client,
            &mut Sequence::default(),
            target,
            Limits { blocks: 1 },
        );
        worker.join().unwrap();
        let result = result.expect("concurrent advances must not exhaust the transport");
        assert_eq!(result.accepted, 0);
        assert_eq!(result.checked_head, None);
        assert_eq!(client.lock().unwrap().head().unwrap().0, 2);
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
        // Payload/frame ownership is released; exact-account records remain charged
        // until the original owner lawfully advances its fixed lifecycle window.
        let (accounts, metadata) = budget.retained_body_accounting();
        assert_eq!(accounts, 2);
        assert!(metadata > 0);
        assert_eq!(budget.available().unwrap() + metadata, before);
        (result, remote)
    }
    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn idle_responder_preserves_evidence_until_the_first_actual_request_and_complete_round() {
        use crate::eng2::resident::peers::NetworkStatus;
        let (mut client_peer, mut server_peer, _) = peers();
        let owner = Arc::new(Mutex::new(fixture(0)));
        let head = owner.lock().unwrap().head().unwrap();
        let network = Arc::new(NetworkStatus::new([[1; 32]]));
        let _connection = network.connected([1; 32]).unwrap();
        network.round([1; 32], 0, Some(head)).unwrap();
        let reference = network.clone();
        let (idle, awaiting) = std::sync::mpsc::channel();
        let (started, revoked) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            idle.send(()).unwrap();
            let round = respond_with_round_start(
                &mut server_peer,
                &owner,
                &mut Sequence::default(),
                Limits::default(),
                || {
                    reference.begin_round([1; 32])?;
                    started.send(()).unwrap();
                    Ok(())
                },
            )
            .unwrap();
            reference
                .round([1; 32], round.accepted, round.checked_head)
                .unwrap();
        });
        awaiting
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        assert!(network.checkpoint_ready(head).is_ok());
        assert_eq!(client_peer.fetch_tip(1).unwrap(), head);
        revoked
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        assert!(network.checkpoint_ready(head).is_err());
        client_peer.advertise_tip(2, head.0, head.1).unwrap();
        let (request, done) = client_peer.receive_request().unwrap();
        assert_eq!(request, 2);
        assert_eq!(done, Request::RoundDone);
        worker.join().unwrap();
        assert!(network.checkpoint_ready(head).is_ok());
    }
    #[test]
    fn completed_round_head_evidence_cannot_follow_a_later_concurrent_owner_advance() {
        let (mut client_peer, mut server_peer, _) = peers();
        let client = Arc::new(Mutex::new(fixture(0)));
        let old = client.lock().unwrap().head().unwrap();
        let advance = client.clone();
        let server = Arc::new(Mutex::new(fixture(0)));
        let worker = std::thread::spawn(move || {
            let (request, message) = server_peer.receive_request().unwrap();
            serve(&mut server_peer, &server, request, message).unwrap();
            let (request, message) = server_peer.receive_request().unwrap();
            assert!(matches!(message, Request::Tip { .. }));
            // The client completed its pull and advertised the old local head.
            // Another owner may now advance during the remaining round phases.
            *advance.lock().unwrap() = fixture(1);
            server_peer.finish_round(request).unwrap();
        });
        let round = initiate(
            &mut client_peer,
            &client,
            &mut Sequence::default(),
            Limits::default(),
        )
        .unwrap();
        worker.join().unwrap();
        assert_eq!(round.accepted, 0);
        assert_eq!(round.checked_head, Some(old));
        assert_ne!(
            round.checked_head,
            Some(client.lock().unwrap().head().unwrap())
        );
    }
    #[test]
    fn exhausted_pull_evidence_identifies_local_head_not_a_claimed_equal_peer_tip() {
        let (mut peer, _, _) = peers();
        let local = Arc::new(Mutex::new(fixture(1)));
        let current = local.lock().unwrap().head().unwrap();
        let remote_genesis = peer.genesis_id();
        let pulled = pull(
            &mut peer,
            &local,
            &mut Sequence::default(),
            (0, remote_genesis),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(pulled.accepted, 0);
        assert_eq!(pulled.checked_head, Some(current));
        assert_ne!(current, (0, remote_genesis));
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
    fn legacy_zero_height_probe_keeps_the_connection_and_canonical_state() {
        let (mut a, mut b, _) = peers();
        let owner = fixture(1);
        let before = owner.head().unwrap();
        let expected = owner.blocks[0].0.clone();
        let thread = std::thread::spawn(move || {
            // Exact legacy GET_HEADER behavior, without the new serve handler.
            for _ in 0..2 {
                let (request, message) = b.receive_request().unwrap();
                let Request::Header { height } = message else {
                    panic!("legacy request expected")
                };
                match owner.header(height).unwrap() {
                    Some(header) => b.send_header(request, &header).unwrap(),
                    None => b.send_unavailable(request, height).unwrap(),
                }
            }
            assert_eq!(owner.head().unwrap(), before);
        });
        assert!(!a.probe_exact_blocks(1).unwrap());
        assert!(matches!(
            a.fetch_header_by_id(2, 1, expected.id().unwrap()),
            Err(p2p::Error::Unconfigured)
        ));
        assert_eq!(a.fetch_header(2, 1).unwrap(), Some(expected));
        thread.join().unwrap();
    }
    #[test]
    fn legacy_reconnects_and_negative_probes_cannot_reset_node_discovery_attempts() {
        use crate::eng2::branches::discovery::{Ledger, Limits as DiscoveryLimits};
        struct LegacyOwner {
            inner: Fixture,
            ledger: Ledger,
        }
        impl Owner for LegacyOwner {
            fn exact_exchange_enabled(&self) -> bool {
                true
            }
            fn head(&self) -> Result<(u64, Hash), String> {
                self.inner.head()
            }
            fn header(&self, h: u64) -> Result<Option<Header>, String> {
                self.inner.header(h)
            }
            fn block_size(&self, h: u64) -> Result<Option<usize>, String> {
                self.inner.block_size(h)
            }
            fn block(&self, h: u64) -> Result<(Header, Body), String> {
                self.inner.block(h)
            }
            fn accept(&mut self, h: &Header, b: &Body) -> Result<(), String> {
                self.inner.accept(h, b)
            }
            fn branch_discovery_next(
                &mut self,
                remote: (u64, Hash),
                peer: Hash,
                now: u64,
            ) -> Result<DiscoveryAction, String> {
                self.ledger
                    .begin(remote.0, remote.1, now)
                    .map_err(|e| e.to_string())?;
                match self.ledger.request(remote.1, peer, now) {
                    Ok(request) => Ok(DiscoveryAction::Header(request)),
                    Err(_) => Ok(DiscoveryAction::Deferred),
                }
            }
            fn branch_discovery_deferred(
                &mut self,
                request: crate::eng2::branches::discovery::HeaderRequest,
                now: u64,
            ) -> Result<(), String> {
                self.ledger.defer(request, now).map_err(|e| e.to_string())
            }
        }
        let inner = fixture(1);
        let g = genesis();
        let owner = Arc::new(Mutex::new(LegacyOwner {
            inner,
            ledger: Ledger::new(
                g.config().network,
                g.id(),
                DiscoveryLimits {
                    maximum_candidates: 2,
                    maximum_peers: 2,
                    maximum_requests: 4,
                    maximum_headers: 4,
                    maximum_body_bytes: 1024 * 1024,
                    maximum_headers_per_candidate: 4,
                    maximum_attempts_per_header: 2,
                    candidate_lifetime_ms: 10_000,
                    window_ms: 20_000,
                },
                discovery_now_ms(),
            )
            .unwrap(),
        }));
        let remote = (1, [19; 32]);
        // One remaining wire slot cannot hold a new session's probe and its
        // object request. No peer attempt or I/O is consumed in that case.
        let (mut insufficient, _, _) = peers();
        discover_fork(
            &mut insufficient,
            &owner,
            &mut Sequence::default(),
            remote,
            1,
        )
        .unwrap();
        assert_eq!(owner.lock().unwrap().ledger.usage().requests, 0);
        let (mut a, mut b, _) = peers();
        let old = std::thread::spawn(move || {
            let (request, message) = b.receive_request().unwrap();
            assert_eq!(message, Request::Header { height: 0 });
            b.send_unavailable(request, 0).unwrap();
        });
        discover_fork(&mut a, &owner, &mut Sequence::default(), remote, 2).unwrap();
        old.join().unwrap();
        assert_eq!(owner.lock().unwrap().ledger.usage().requests, 1);
        // New authenticated test-channel object has the same peer identity.
        // No responder is needed: duplicate accounting rejects before any I/O.
        let (mut reconnected, _, _) = peers();
        discover_fork(
            &mut reconnected,
            &owner,
            &mut Sequence::default(),
            remote,
            2,
        )
        .unwrap();
        assert_eq!(owner.lock().unwrap().ledger.usage().requests, 1);
    }
    #[test]
    fn one_block_round_resumes_a_higher_competing_head_before_refetching_its_prefix() {
        struct DiscoveryCounter {
            inner: Fixture,
            calls: usize,
        }
        impl Owner for DiscoveryCounter {
            fn exact_exchange_enabled(&self) -> bool {
                true
            }
            fn head(&self) -> Result<(u64, Hash), String> {
                self.inner.head()
            }
            fn header(&self, height: u64) -> Result<Option<Header>, String> {
                self.inner.header(height)
            }
            fn block_size(&self, height: u64) -> Result<Option<usize>, String> {
                self.inner.block_size(height)
            }
            fn block(&self, height: u64) -> Result<(Header, Body), String> {
                self.inner.block(height)
            }
            fn accept(&mut self, header: &Header, body: &Body) -> Result<(), String> {
                self.inner.accept(header, body)
            }
            fn branch_discovery_next(
                &mut self,
                _: (u64, Hash),
                _: Hash,
                _: u64,
            ) -> Result<DiscoveryAction, String> {
                self.calls += 1;
                Ok(DiscoveryAction::Deferred)
            }
        }
        let (mut client, mut server, _) = peers();
        let owner = Arc::new(Mutex::new(DiscoveryCounter {
            inner: fixture(1),
            calls: 0,
        }));
        let mut branch = fixture(2);
        branch.blocks[0].0.nonce += 1;
        branch.blocks[1].0.parent = branch.blocks[0].0.id().unwrap();
        let remote = branch.head().unwrap();
        let expected = branch.blocks[1].0.clone();
        let thread = std::thread::spawn(move || {
            let (request, query) = server.receive_request().unwrap();
            assert_eq!(query, Request::Header { height: 2 });
            server.send_header(request, &expected).unwrap();
        });
        let mut sequence = Sequence::default();
        pull(
            &mut client,
            &owner,
            &mut sequence,
            remote,
            Limits { blocks: 1 },
        )
        .unwrap();
        thread.join().unwrap();
        assert_eq!(owner.lock().unwrap().calls, 0);
        // The responder is now closed. A repeated ordinary header would fail;
        // the saved hint instead reaches the owner with the full round budget.
        pull(
            &mut client,
            &owner,
            &mut sequence,
            remote,
            Limits { blocks: 1 },
        )
        .unwrap();
        assert_eq!(owner.lock().unwrap().calls, 1);
        let local = owner.lock().unwrap().head().unwrap();
        assert_eq!(local.0, 1);
        assert!(client.competing_head_matches(local, remote));
        assert!(!client.competing_head_matches((local.0 + 1, [8; 32]), remote));
        assert!(!client.competing_head_matches(local, (remote.0 + 1, remote.1)));
    }

    fn selected_bootstrap_body_fixture(
        count: u64,
        maximum_cache_bytes: u64,
    ) -> (
        Genesis,
        crate::eng2::bootstrap::client::Client,
        Vec<(Header, Body)>,
        p2p::Budget,
        std::path::PathBuf,
    ) {
        use crate::eng2::bootstrap::{
            self, Chunk, Descriptor, Object,
            cache::{Policy as CachePolicy, Quarantine},
            client::Candidate,
        };
        use siworld_core::pow::Work;
        let (genesis, imports, _) = bootstrap::tests::framing_fixture();
        let mut records = fixture(count).blocks;
        let mut parent = genesis.id();
        for (header, _) in &mut records {
            header.parent = parent;
            header.timestamp = genesis.config().genesis_timestamp + header.height * 300;
            parent = header.id().unwrap();
        }
        let headers: Vec<_> = records.iter().map(|(header, _)| header.clone()).collect();
        let manifest = bootstrap::tests::framing_tail_manifest(&headers);
        let mut entropy = [0; 16];
        getrandom::fill(&mut entropy).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "bootstrap-body-authority-{}",
            crate::local::hex(&entropy)
        ));
        let budget = p2p::Budget::new(256 * 1024 * 1024);
        let mut cache = Quarantine::create(
            &directory,
            manifest,
            CachePolicy {
                max_bytes: maximum_cache_bytes,
                max_chunks_per_object: 16,
                max_body_bytes: policy().max_body_bytes,
            },
            budget.clone(),
        )
        .unwrap();
        for (header, _) in &records {
            cache.put_header(header).unwrap();
        }
        cache
            .push(
                Object::Snapshot,
                0,
                &Chunk {
                    descriptor: cache.manifest().snapshot,
                    bytes: b"fixture".to_vec(),
                },
            )
            .unwrap();
        for (header, _) in records.iter().take(72) {
            let bytes = b"synthetic receipt";
            cache
                .push(
                    Object::Receipt {
                        height: header.height,
                        id: header.id().unwrap(),
                    },
                    0,
                    &Chunk {
                        descriptor: Descriptor {
                            length: bytes.len() as u64,
                            digest: *blake3::hash(bytes).as_bytes(),
                        },
                        bytes: bytes.to_vec(),
                    },
                )
                .unwrap();
        }
        let candidate = Candidate::new(
            cache,
            &genesis,
            crate::eng2::import::Policy {
                state: imports,
                max_headers: 1000,
                max_verification_bytes: 512 * 1024 * 1024,
            },
            policy(),
        )
        .unwrap();
        let prepared = candidate.prepare(&genesis, Work::one()).unwrap();
        let client = bootstrap::client::select(vec![prepared], Work::one()).unwrap();
        (genesis, client, records, budget, directory)
    }
    #[test]
    fn selected_bootstrap_client_downloads_240_tail_bodies_with_one_original_operation() {
        use crate::eng2::bootstrap::client::Progress;
        let (genesis, mut client, records, budget, directory) =
            selected_bootstrap_body_fixture(312, 256 * 1024 * 1024);
        client
            .bind_body_operation(
                &budget,
                std::time::Instant::now() + std::time::Duration::from_secs(180),
            )
            .unwrap();
        assert_eq!(
            client.progress().unwrap(),
            Progress::NativeTail {
                next: 73,
                total: 312
            }
        );
        for (header, body) in records.into_iter().skip(72) {
            let (a, b) = UnixStream::pair().unwrap();
            for socket in [&a, &b] {
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                    .unwrap();
            }
            let mut receiver = Peer::new(
                p2p::Session::from_test_channel(a, genesis.peer_binding(), budget.clone()),
                &genesis,
                policy(),
            )
            .unwrap();
            let mut sender = Peer::new(
                p2p::Session::from_test_channel(b, genesis.peer_binding(), budget.clone()),
                &genesis,
                policy(),
            )
            .unwrap();
            let height = header.height;
            let server = std::thread::spawn(move || {
                let (request, message) = sender.receive_request().unwrap();
                assert!(
                    matches!(message, Request::Body { height: requested, .. } if requested == height)
                );
                sender.send_body(request, &header, &body).unwrap();
            });
            let mut sequence = Sequence::default();
            let mut pull = BootstrapPull {
                peer: &mut receiver,
                sequence: &mut sequence,
                remaining: 1,
                deadline: p2p::Deadline::new(std::time::Duration::from_secs(180)),
            };
            client.pull_step(&mut pull).unwrap();
            server.join().unwrap();
            assert!(
                client
                    .bind_body_operation(
                        &budget,
                        std::time::Instant::now() + std::time::Duration::from_secs(180)
                    )
                    .is_err()
            );
        }
        assert_eq!(client.progress().unwrap(), Progress::Downloaded);
        assert_eq!(budget.retained_body_accounting().0, 240);
        // Framing and immutable-plan acquisition do not admit synthetic proofs or certificates.
        drop(client);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn selected_bootstrap_cache_failure_preserves_candidate_and_never_completes_its_account() {
        use crate::eng2::bootstrap::client::Progress;
        let maximum = 96 * crate::eng2::header::HEADER_BYTES as u64
            + 7
            + 72 * b"synthetic receipt".len() as u64
            + 1;
        let (genesis, mut client, records, budget, directory) =
            selected_bootstrap_body_fixture(96, maximum);
        client
            .bind_body_operation(
                &budget,
                std::time::Instant::now() + super::super::transport::BODY_FETCH_TIMEOUT,
            )
            .unwrap();
        let (header, body) = records[72].clone();
        for source in [8u8, 9] {
            let (a, b) = UnixStream::pair().unwrap();
            a.set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            b.set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut receiver = Peer::new(
                p2p::Session::from_test_peer_channel(
                    a,
                    genesis.peer_binding(),
                    budget.clone(),
                    [source; 32],
                    p2p::Role::Validator,
                ),
                &genesis,
                policy(),
            )
            .unwrap();
            let mut sender = Peer::new(
                p2p::Session::from_test_channel(b, genesis.peer_binding(), budget.clone()),
                &genesis,
                policy(),
            )
            .unwrap();
            let header = header.clone();
            let body = body.clone();
            let server = std::thread::spawn(move || {
                let (request, message) = sender.receive_request().unwrap();
                assert!(matches!(message, Request::Body { height: 73, .. }));
                sender.send_body(request, &header, &body).unwrap();
            });
            let mut sequence = Sequence::default();
            let mut pull = BootstrapPull {
                peer: &mut receiver,
                sequence: &mut sequence,
                remaining: 1,
                deadline: p2p::Deadline::new(super::super::transport::BODY_FETCH_TIMEOUT),
            };
            assert!(
                matches!(client.pull_step(&mut pull), Err(Error::Owner(reason)) if reason.contains("byte budget exceeded"))
            );
            server.join().unwrap();
            assert_eq!(
                client.progress().unwrap(),
                Progress::NativeTail {
                    next: 73,
                    total: 96
                }
            );
            assert_eq!(budget.retained_body_accounting().0, 1);
        }
        client.cancel_body_operation();
        drop(client);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn independently_accepted_registry_terminal_body_is_discarded_without_failing_the_round() {
        let genesis = genesis();
        let (mut receiver, mut sender, budget) = peers();
        let remote = fixture(1);
        let (header, body) = remote.blocks[0].clone();
        let discovery = crate::eng2::branches::discovery::runtime::Discovery::new(
            genesis.config().network,
            genesis.id(),
            crate::eng2::branches::discovery::runtime::resident_limits(),
            discovery_now_ms(),
            budget.clone(),
        )
        .unwrap();
        let auth = budget
            .authorize_body(
                &discovery.body_scope(),
                genesis.peer_binding(),
                header.height,
                header.id().unwrap(),
                &p2p::Deadline::new(super::super::transport::BODY_FETCH_TIMEOUT),
            )
            .unwrap();
        let sent_header = header.clone();
        let worker = std::thread::spawn(move || {
            let (request, message) = sender.receive_request().unwrap();
            assert!(matches!(message, Request::Body { height: 1, .. }));
            sender.send_body(request, &sent_header, &body).unwrap();
        });
        let lease = receiver
            .claim_body_authorized(&header, &auth, p2p::BodyMode::Legacy)
            .unwrap();
        let received = receiver
            .fetch_body_owned(1, &header, lease, None)
            .unwrap()
            .unwrap();
        worker.join().unwrap();
        // Interleave the real terminal transition between decoded transport and
        // acquisition of the ordinary owner's publication lock.
        assert!(
            budget
                .accepted_body(genesis.peer_binding(), header.height, header.id().unwrap())
                .unwrap()
        );
        assert!(received.ownership.check_active().is_err());
        let owner = Arc::new(Mutex::new(fixture(0)));
        assert!(accept_pulled(&owner, &header, &received).is_err());
        assert_eq!(owner.lock().unwrap().head().unwrap().0, 0);
        *owner.lock().unwrap() = remote;
        assert!(!accept_pulled(&owner, &header, &received).unwrap());
        assert_eq!(owner.lock().unwrap().head().unwrap().0, 1);
        drop(received);
    }
    #[test]
    fn probe_and_exact_requests_share_the_same_round_budget() {
        let (mut peer, _, _) = peers();
        let mut sequence = Sequence::default();
        let mut pull = BootstrapPull {
            peer: &mut peer,
            sequence: &mut sequence,
            remaining: 0,
            deadline: p2p::Deadline::new(std::time::Duration::from_secs(1)),
        };
        assert!(matches!(
            pull.probe_exact_blocks(),
            Err(Error::RequestLimit)
        ));
    }
    struct RawBranchFixture {
        canonical: Fixture,
        branch: (Header, Body),
        declared_size: usize,
        reads: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Owner for RawBranchFixture {
        fn exact_exchange_enabled(&self) -> bool {
            true
        }
        fn head(&self) -> Result<(u64, Hash), String> {
            self.canonical.head()
        }
        fn header(&self, height: u64) -> Result<Option<Header>, String> {
            self.canonical.header(height)
        }
        fn block_size(&self, height: u64) -> Result<Option<usize>, String> {
            self.canonical.block_size(height)
        }
        fn block(&self, height: u64) -> Result<(Header, Body), String> {
            self.canonical.block(height)
        }
        fn accept(&mut self, header: &Header, body: &Body) -> Result<(), String> {
            self.canonical.accept(header, body)
        }
        fn branch_header(&self, id: Hash) -> Result<Option<Header>, String> {
            Ok((self.branch.0.id().unwrap() == id).then(|| self.branch.0.clone()))
        }
        fn branch_block_size(&self, id: Hash) -> Result<Option<usize>, String> {
            Ok((self.branch.0.id().unwrap() == id).then_some(self.declared_size))
        }
        fn branch_block(&self, id: Hash) -> Result<(Header, Body), String> {
            if self.branch.0.id().unwrap() != id {
                return Err("raw identity mismatch".into());
            }
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(self.branch.clone())
        }
    }
    fn raw_branch_fixture() -> RawBranchFixture {
        let canonical = fixture(1);
        let mut branch = canonical.blocks[0].clone();
        branch.0.nonce += 1;
        RawBranchFixture {
            canonical,
            declared_size: branch.1.encoded_len(policy()).unwrap(),
            branch,
            reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
    #[test]
    fn exact_competitor_header_and_body_are_served_without_adoption() {
        let (mut a, mut b, budget) = peers();
        let available = budget.available().unwrap();
        let fixture = raw_branch_fixture();
        let branch = fixture.branch.clone();
        let before = fixture.head().unwrap();
        let owner = Arc::new(Mutex::new(fixture));
        let remote = owner.clone();
        let thread = std::thread::spawn(move || {
            for _ in 0..3 {
                let (request, message) = b.receive_request().unwrap();
                serve(&mut b, &remote, request, message).unwrap();
            }
        });
        assert!(a.probe_exact_blocks(3).unwrap());
        assert_eq!(
            a.fetch_header_by_id(4, 1, branch.0.id().unwrap()).unwrap(),
            Some(branch.0.clone())
        );
        let body = a.fetch_body(5, &branch.0).unwrap().unwrap();
        assert_eq!(body.body, branch.1);
        thread.join().unwrap();
        assert_eq!(owner.lock().unwrap().head().unwrap(), before);
        assert_eq!(
            owner
                .lock()
                .unwrap()
                .reads
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        drop(body);
        let (accounts, metadata) = budget.retained_body_accounting();
        assert_eq!(accounts, 1);
        assert!(metadata > 0);
        assert_eq!(budget.available().unwrap() + metadata, available);
    }
    #[test]
    fn discovery_response_returns_linear_request_to_the_same_node_ledger() {
        use super::super::branches::discovery::{Ledger, Limits as DiscoveryLimits};
        let (mut a, mut b, _) = peers();
        let fixture = raw_branch_fixture();
        let header = fixture.branch.0.clone();
        let id = header.id().unwrap();
        let owner = Arc::new(Mutex::new(fixture));
        let remote = owner.clone();
        let thread = std::thread::spawn(move || {
            for _ in 0..2 {
                let (request, message) = b.receive_request().unwrap();
                serve(&mut b, &remote, request, message).unwrap();
            }
        });
        let mut ledger = Ledger::new(
            header.network,
            header.parent,
            DiscoveryLimits {
                maximum_candidates: 1,
                maximum_peers: 1,
                maximum_requests: 2,
                maximum_headers: 2,
                maximum_body_bytes: 1024 * 1024,
                maximum_headers_per_candidate: 2,
                maximum_attempts_per_header: 1,
                candidate_lifetime_ms: 100,
                window_ms: 100,
            },
            1,
        )
        .unwrap();
        ledger.begin(1, id, 1).unwrap();
        let ticket = ledger.request(id, a.peer(), 2).unwrap();
        let mut sequence = Sequence::default();
        let mut pull = BootstrapPull {
            peer: &mut a,
            sequence: &mut sequence,
            remaining: 2,
            deadline: p2p::Deadline::new(std::time::Duration::from_secs(3)),
        };
        assert!(pull.probe_exact_blocks().unwrap());
        let response = pull.discovery_header(ticket);
        let cursor = response.finish(&mut ledger, 3).unwrap().unwrap();
        assert!(cursor.ancestor_confirmed);
        assert_eq!(ledger.path(id, 3).unwrap(), vec![header]);
        assert_eq!(pull.remaining, 0);
        thread.join().unwrap();
        assert_eq!(ledger.usage().requests, 1);
    }
    #[test]
    fn raw_branch_body_is_not_loaded_before_size_and_budget_admission() {
        for oversized in [true, false] {
            let (mut peer, _, budget) = peers();
            let mut fixture = raw_branch_fixture();
            let _exhausted = if oversized {
                fixture.declared_size = policy().max_body_bytes + 1;
                None
            } else {
                Some(budget.reserve(budget.available().unwrap()).unwrap())
            };
            let id = fixture.branch.0.id().unwrap();
            let reads = fixture.reads.clone();
            let owner = Arc::new(Mutex::new(fixture));
            assert!(matches!(
                serve(&mut peer, &owner, 1, Request::Body { height: 1, id }),
                Err(Error::Transport(p2p::Error::ResourceExhausted))
            ));
            assert_eq!(reads.load(std::sync::atomic::Ordering::Relaxed), 0);
        }
    }
    #[test]
    fn exact_header_requests_share_the_bounded_round_allowance() {
        let (mut peer, _, _) = peers();
        let mut sequence = Sequence::default();
        let mut pull = BootstrapPull {
            peer: &mut peer,
            sequence: &mut sequence,
            remaining: 0,
            deadline: p2p::Deadline::new(std::time::Duration::from_secs(1)),
        };
        assert!(matches!(
            pull.header_by_id(1, [9; 32]),
            Err(Error::RequestLimit)
        ));
    }
    #[test]
    fn same_head_checkpoint_retrieval_qualifies_headers_without_fetching_bodies() {
        use crate::eng2::{
            branches::{
                BranchStore,
                discovery::{Limits as DiscoveryLimits, runtime::Discovery},
            },
            selection::{HeaderRules, VerifiedHeaders},
            state_components,
            store::Store,
        };
        struct HeaderOwner {
            canonical: Store,
            branches: BranchStore,
            discovery: Discovery,
        }
        impl Owner for HeaderOwner {
            fn exact_exchange_enabled(&self) -> bool {
                true
            }
            fn head(&self) -> Result<(u64, Hash), String> {
                Ok((
                    self.canonical.engine().state().height(),
                    self.canonical.engine().state().tip(),
                ))
            }
            fn header(&self, height: u64) -> Result<Option<Header>, String> {
                if height == 0 || height > self.canonical.engine().state().height() {
                    Ok(None)
                } else {
                    self.canonical.header(height).map(Some)
                }
            }
            fn block_size(&self, _: u64) -> Result<Option<usize>, String> {
                panic!("header-only retrieval must not read bodies")
            }
            fn block(&self, _: u64) -> Result<(Header, Body), String> {
                panic!("header-only retrieval must not read bodies")
            }
            fn accept(&mut self, _: &Header, _: &Body) -> Result<(), String> {
                panic!("header-only retrieval must not adopt blocks")
            }
            fn branch_header(&self, id: Hash) -> Result<Option<Header>, String> {
                Ok(self.branches.entry(id)?.map(|entry| entry.header))
            }
            fn checkpoint_headers_next(
                &mut self,
                remote: (u64, Hash),
                peer: Hash,
                now: u64,
            ) -> Result<DiscoveryAction, String> {
                self.discovery
                    .next_headers(&mut self.branches, &self.canonical, remote, peer, now)
            }
            fn branch_discovery_received(
                &mut self,
                request: crate::eng2::branches::discovery::HeaderRequest,
                header: Option<Header>,
                now: u64,
            ) -> Result<(), String> {
                self.discovery.received(request, header, now)
            }
            fn branch_discovery_deferred(
                &mut self,
                request: crate::eng2::branches::discovery::HeaderRequest,
                now: u64,
            ) -> Result<(), String> {
                self.discovery.deferred(request, now)
            }
        }
        fn owner(directory: &std::path::Path) -> HeaderOwner {
            let g = genesis();
            let canonical = Store::create(
                &directory.join("canonical.redb"),
                Genesis::decode(&g.encode().unwrap()).unwrap(),
                state_components::Limits {
                    max_leaves: 1_000_000,
                    max_nullifiers: 1_000_000,
                    max_component_bytes: 64 * 1024 * 1024,
                },
            )
            .unwrap();
            let branches = BranchStore::create(
                &directory.join("branches.redb"),
                HeaderRules {
                    network: g.config().network,
                    genesis: g.id(),
                    genesis_timestamp: g.config().genesis_timestamp,
                    genesis_target: g.config().genesis_target,
                    target_interval: 300,
                    pow_iterations: 0,
                    max_headers: 128,
                },
                crate::eng2::branches::Limits {
                    maximum_headers: 128,
                    maximum_body_bytes: 64 * 1024 * 1024,
                },
            )
            .unwrap();
            let discovery = Discovery::new(
                g.config().network,
                g.id(),
                DiscoveryLimits {
                    maximum_candidates: 4,
                    maximum_peers: 3,
                    maximum_requests: 32,
                    maximum_headers: 32,
                    maximum_body_bytes: 64 * 1024 * 1024,
                    maximum_headers_per_candidate: 32,
                    maximum_attempts_per_header: 2,
                    candidate_lifetime_ms: 1000,
                    window_ms: 4000,
                },
                discovery_now_ms(),
                crate::p2p::Budget::default(),
            )
            .unwrap();
            HeaderOwner {
                canonical,
                branches,
                discovery,
            }
        }
        let left = crate::eng2::branches::tests::Fixture::new();
        let right = crate::eng2::branches::tests::Fixture::new();
        let client = Arc::new(Mutex::new(owner(&left.0)));
        let server = Arc::new(Mutex::new(owner(&right.0)));
        let header = fixture(1).blocks.remove(0).0;
        let target = (header.height, header.id().unwrap());
        {
            let mut server = server.lock().unwrap();
            let g = genesis();
            let qualified = VerifiedHeaders::verify(
                HeaderRules {
                    network: g.config().network,
                    genesis: g.id(),
                    genesis_timestamp: g.config().genesis_timestamp,
                    genesis_target: g.config().genesis_target,
                    target_interval: 300,
                    pow_iterations: 0,
                    max_headers: 128,
                },
                vec![header],
            )
            .unwrap();
            server.branches.retain_verified_headers(&qualified).unwrap();
        }
        let (mut a, mut b, budget) = peers();
        let before = budget.available().unwrap();
        let remote = server.clone();
        let worker = std::thread::spawn(move || {
            respond(&mut b, &remote, &mut Sequence::default(), Limits::default()).unwrap()
        });
        let round = initiate_with_checkpoint_headers(
            &mut a,
            &client,
            &mut Sequence::default(),
            Limits::default(),
            Some(target),
        )
        .unwrap();
        assert_eq!(round.accepted, 0);
        assert_eq!(worker.join().unwrap().accepted, 0);
        let client = client.lock().unwrap();
        assert_eq!(client.head().unwrap().0, 0);
        assert_eq!(client.discovery.usage().requests, 1);
        assert_eq!(client.discovery.usage().headers, 1);
        assert_eq!(client.discovery.usage().body_bytes, 0);
        assert_eq!(
            client.branches.entry(target.1).unwrap().unwrap().status,
            crate::eng2::branches::Status::HeaderQualified
        );
        assert!(client.branches.body_size(target.1).unwrap().is_none());
        drop(a);
        assert_eq!(budget.available().unwrap(), before);
    }
    #[test]
    #[ignore = "owner-operated existing native fixture transfer; never selected by CI"]
    fn actual_native_equal_height_competitor_is_discovered_across_rounds_without_adoption() {
        use crate::eng2::{
            branches::{
                BranchStore, Limits as BranchLimits,
                discovery::{Limits as DiscoveryLimits, runtime::Discovery},
            },
            genesis::Genesis,
            selection::HeaderRules,
            state_components,
            store::Store,
        };
        use redb::{ReadableDatabase, TableDefinition};
        assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
        struct DiscoveryOwner {
            canonical: Store,
            branches: BranchStore,
            discovery: Discovery,
        }
        impl Owner for DiscoveryOwner {
            fn exact_exchange_enabled(&self) -> bool {
                true
            }
            fn head(&self) -> Result<(u64, Hash), String> {
                Ok((
                    self.canonical.engine().state().height(),
                    self.canonical.engine().state().tip(),
                ))
            }
            fn header(&self, height: u64) -> Result<Option<Header>, String> {
                if height == 0 || height > self.canonical.engine().state().height() {
                    Ok(None)
                } else {
                    self.canonical.header(height).map(Some)
                }
            }
            fn block_size(&self, height: u64) -> Result<Option<usize>, String> {
                self.canonical.block_size(height).map(Some)
            }
            fn block(&self, height: u64) -> Result<(Header, Body), String> {
                self.canonical.block(height)
            }
            fn accept(&mut self, _: &Header, _: &Body) -> Result<(), String> {
                Err("discovery test must not adopt blocks".into())
            }
            fn branch_discovery_next(
                &mut self,
                remote: (u64, Hash),
                peer: Hash,
                now: u64,
            ) -> Result<DiscoveryAction, String> {
                self.discovery
                    .next(&mut self.branches, &self.canonical, remote, peer, now)
            }
            fn branch_discovery_received(
                &mut self,
                request: crate::eng2::branches::discovery::HeaderRequest,
                header: Option<Header>,
                now: u64,
            ) -> Result<(), String> {
                self.discovery.received(request, header, now)
            }
            fn branch_discovery_deferred(
                &mut self,
                request: crate::eng2::branches::discovery::HeaderRequest,
                now: u64,
            ) -> Result<(), String> {
                self.discovery.deferred(request, now)
            }
            fn branch_discovery_body(
                &mut self,
                request: crate::eng2::branches::discovery::HeaderRequest,
                header: &Header,
                body: &Body,
                now: u64,
            ) -> Result<(), String> {
                self.discovery.body(
                    &mut self.branches,
                    request,
                    header,
                    body,
                    self.canonical.engine().body_policy(),
                    now,
                )
            }
        }
        let source = std::path::PathBuf::from(
            std::env::var_os("SIWORLD_REORG_NATIVE_SOURCE").expect("explicit closed native source"),
        );
        assert!(source.is_absolute() && source.join("disposable-fixture").is_file());
        let genesis = Genesis::decode(&std::fs::read(source.join("genesis.bin")).unwrap()).unwrap();
        assert!(genesis.config().fixture);
        assert_eq!(genesis.config().pow_iterations, 0);
        let directory = crate::eng2::branches::tests::Fixture::new();
        let mut canonical = Store::create(
            &directory.0.join("canonical.redb"),
            Genesis::decode(&genesis.encode().unwrap()).unwrap(),
            state_components::Limits {
                max_leaves: 1_000_000,
                max_nullifiers: 1_000_000,
                max_component_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap();
        let policy = canonical.engine().body_policy();
        let table: TableDefinition<u64, &[u8]> = TableDefinition::new("eng2-canonical-blocks-v1");
        let database = redb::ReadOnlyDatabase::open(source.join("chain.redb")).unwrap();
        let transaction = database.begin_read().unwrap();
        let blocks = transaction.open_table(table).unwrap();
        let row = blocks.get(1).unwrap().unwrap();
        let bytes = row.value();
        let header = Header::decode(
            &bytes[..crate::eng2::header::HEADER_BYTES],
            &genesis.config().network,
        )
        .unwrap();
        let body = Body::decode(
            &bytes[crate::eng2::header::HEADER_BYTES..],
            header.network,
            1,
            policy,
        )
        .unwrap();
        let verifier = crate::proofs::NativeVerifier::new().unwrap();
        canonical.append(&header, &body, &verifier).unwrap();
        let rules = HeaderRules {
            network: genesis.config().network,
            genesis: genesis.id(),
            genesis_timestamp: genesis.config().genesis_timestamp,
            genesis_target: genesis.config().genesis_target,
            target_interval: 300,
            pow_iterations: 0,
            max_headers: 128,
        };
        let mut branches = BranchStore::create(
            &directory.path(),
            rules,
            BranchLimits {
                maximum_headers: 128,
                maximum_body_bytes: 256 * 1024 * 1024,
            },
        )
        .unwrap();
        branches.archive_canonical_suffix(&canonical, 1).unwrap();
        let discovery = Discovery::new(
            genesis.config().network,
            genesis.id(),
            DiscoveryLimits {
                maximum_candidates: 4,
                maximum_peers: 3,
                maximum_requests: 32,
                maximum_headers: 32,
                maximum_body_bytes: 256 * 1024 * 1024,
                maximum_headers_per_candidate: 32,
                maximum_attempts_per_header: 2,
                candidate_lifetime_ms: 60_000,
                window_ms: 120_000,
            },
            discovery_now_ms(),
            crate::p2p::Budget::default(),
        )
        .unwrap();
        let owner = Arc::new(Mutex::new(DiscoveryOwner {
            canonical,
            branches,
            discovery,
        }));
        let mut competitor = header.clone();
        competitor.nonce = competitor.nonce.checked_add(1).unwrap();
        let competitor_id = competitor.id().unwrap();
        let mut server_fixture = fixture(0);
        server_fixture.genesis = genesis.id();
        server_fixture
            .blocks
            .push((competitor.clone(), body.clone()));
        let server = Arc::new(Mutex::new(RawBranchFixture {
            canonical: server_fixture,
            branch: (competitor.clone(), body),
            declared_size: 0,
            reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }));
        let (client_socket, server_socket) = UnixStream::pair().unwrap();
        for socket in [&client_socket, &server_socket] {
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
        }
        let budget = p2p::Budget::new(512 * 1024 * 1024);
        let mut client = Peer::new(
            p2p::Session::from_test_channel(client_socket, genesis.peer_binding(), budget.clone()),
            &genesis,
            policy,
        )
        .unwrap();
        let mut remote = Peer::new(
            p2p::Session::from_test_channel(server_socket, genesis.peer_binding(), budget),
            &genesis,
            policy,
        )
        .unwrap();
        // The server owner has synthetic selection only; replace size lookup by
        // the same exact native body framing policy through this local wrapper.
        struct Server {
            inner: Arc<Mutex<RawBranchFixture>>,
            policy: crate::eng2::body::Policy,
        }
        impl Owner for Server {
            fn exact_exchange_enabled(&self) -> bool {
                true
            }
            fn head(&self) -> Result<(u64, Hash), String> {
                self.inner.lock().unwrap().head()
            }
            fn header(&self, h: u64) -> Result<Option<Header>, String> {
                self.inner.lock().unwrap().header(h)
            }
            fn block_size(&self, h: u64) -> Result<Option<usize>, String> {
                self.inner
                    .lock()
                    .unwrap()
                    .block(h)
                    .and_then(|(_, b)| b.encoded_len(self.policy))
                    .map(Some)
            }
            fn block(&self, h: u64) -> Result<(Header, Body), String> {
                self.inner.lock().unwrap().block(h)
            }
            fn accept(&mut self, _: &Header, _: &Body) -> Result<(), String> {
                Err("no reverse adoption in framing test".into())
            }
        }
        let server = Arc::new(Mutex::new(Server {
            inner: server,
            policy,
        }));
        let thread = std::thread::spawn(move || {
            let mut sequence = Sequence::default();
            for _ in 0..2 {
                respond(&mut remote, &server, &mut sequence, Limits { blocks: 1 }).unwrap();
            }
        });
        let before = owner.lock().unwrap().head().unwrap();
        let mut sequence = Sequence::default();
        for _ in 0..2 {
            let round = initiate(&mut client, &owner, &mut sequence, Limits { blocks: 1 }).unwrap();
            assert_eq!(round.accepted, 0);
            assert_eq!(round.checked_head, None);
        }
        thread.join().unwrap();
        let guard = owner.lock().unwrap();
        assert_eq!(guard.head().unwrap(), before);
        assert_eq!(
            guard.branches.entry(competitor_id).unwrap().unwrap().status,
            crate::eng2::branches::Status::BodyRetained
        );
        assert!(guard.branches.body_size(competitor_id).unwrap().is_some());
        assert_eq!(guard.discovery.usage().requests, 2);
        println!(
            "native_source_blocks_verified=1; discovery_rounds=2; canonical_adoption=false; raw_competitor_retained=true"
        );
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
