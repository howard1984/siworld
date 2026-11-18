//! Bounded owner-captured historical frames, separate from current readiness.
//!
//! Storage provenance is not a validity capability. Independent consumers must
//! replay original bodies and authenticate the exact requested checkpoint.
use super::{
    branches,
    driver::Driver,
    genesis::Genesis,
    header::{HEADER_BYTES, Header},
    selection::{HeaderRules, VerifiedHeaders},
    store,
};
use crate::{
    p2p::{self, Budget},
    wire::Hash,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use siworld_core::pow::Work;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

mod memory;
mod replay;
pub use replay::{Archive, ReplayReceipt, replay};
#[cfg(unix)]
mod cache;
#[cfg(unix)]
pub use cache::{CheckpointReceipt, FileArchive, VerifiedPrefix};
#[cfg(unix)]
mod session;
#[cfg(unix)]
pub use session::verify_session;

pub const MAX_HEADERS: usize = 4096;
pub const MAX_CHUNK: usize = 65536;
pub const MAX_BATCH: usize = 8;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    ContextMismatch,
    BranchNotRetained,
    BodyUnavailable,
    AnchorNotAncestor,
    CapacityExceeded,
    CaptureExpired,
    CaptureFailed,
}
impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::ContextMismatch => "CONTEXT_MISMATCH",
            Self::BranchNotRetained => "BRANCH_NOT_RETAINED",
            Self::BodyUnavailable => "BODY_UNAVAILABLE",
            Self::AnchorNotAncestor => "ANCHOR_NOT_ANCESTOR",
            Self::CapacityExceeded => "CAPACITY_EXCEEDED",
            Self::CaptureExpired => "CAPTURE_EXPIRED",
            Self::CaptureFailed => "CAPTURE_FAILED",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub release: Hash,
    pub process_run: Hash,
    pub executable: Hash,
    pub source_node: Hash,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub network: Hash,
    pub genesis: Hash,
    pub rules: Hash,
    pub proof_profile: Hash,
}
/// Original owner-read selector metadata, never a validity capability.
#[derive(Serialize)]
pub struct HeaderObservation {
    pub identity: Identity,
    pub context: Context,
    pub height: u64,
    pub tip: Hash,
    pub execution: Hash,
    pub header: Vec<u8>,
    pub origin: HeaderOrigin,
    pub source_validity_authority: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderOrigin {
    Canonical,
    RetainedBranch,
}
impl Context {
    pub fn for_genesis(g: &Genesis) -> Self {
        Self {
            network: g.config().network,
            genesis: g.id(),
            rules: g.rules_commitment(),
            proof_profile: crate::proofs::protocol_profile_fingerprint(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub height: u64,
    pub tip: Hash,
    #[serde(with = "work_codec")]
    pub work: Work,
    pub execution: Hash,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prefix {
    pub cache: Hash,
    pub target: Target,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub height: u64,
    pub id: Hash,
    pub certificate: Hash,
    pub witness: Hash,
    pub snapshot: Hash,
}
impl Anchor {
    pub fn genesis(id: Hash) -> Self {
        Self {
            height: 0,
            id,
            certificate: [0; 32],
            witness: [0; 32],
            snapshot: [0; 32],
        }
    }
}
/// Original immutable public artifacts selected by the owner, never caller paths.
#[derive(Clone)]
pub struct Materials {
    pub certificate: Arc<[u8]>,
    pub witness: Arc<[u8]>,
    pub snapshot: Arc<[u8]>,
}
impl Materials {
    pub fn anchor(&self, height: u64, id: Hash) -> Anchor {
        Anchor {
            height,
            id,
            certificate: digest(&self.certificate),
            witness: digest(&self.witness),
            snapshot: digest(&self.snapshot),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub headers: usize,
    pub frame_bytes: u64,
    pub object_bytes: u64,
    pub memory_bytes: usize,
    pub wall: Duration,
    pub expiry: Duration,
}
impl Limits {
    fn admitted(self, max: Self) -> bool {
        self.headers > 0
            && self.headers <= MAX_HEADERS
            && self.headers <= max.headers
            && self.frame_bytes > 0
            && self.frame_bytes <= max.frame_bytes
            && self.object_bytes > 0
            && self.object_bytes <= max.object_bytes
            && self.memory_bytes > 0
            && self.memory_bytes <= max.memory_bytes
            && !self.wall.is_zero()
            && self.wall <= max.wall
            && !self.expiry.is_zero()
            && self.expiry <= max.expiry
            && self.wall <= self.expiry
            && self.expiry <= Duration::from_secs(300)
            && self.wall <= Duration::from_secs(60)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub request_id: Hash,
    pub identity: Identity,
    pub context: Context,
    pub target: Target,
    pub observation: Hash,
    pub observation_source: Hash,
    pub anchor: Anchor,
    #[serde(default)]
    pub prefix: Option<Prefix>,
    pub limits: Limits,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Genesis,
    Certificate,
    Witness,
    Snapshot,
    Frame { height: u64, retained_branch: bool },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub kind: Kind,
    pub bytes: usize,
    pub sha256: Hash,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub capture_id: Hash,
    pub request: Request,
    pub canonical_height: u64,
    pub canonical_tip: Hash,
    pub objects: Vec<Object>,
    pub total_bytes: u64,
    pub digest: Hash,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Chunk {
    pub object: usize,
    pub offset: usize,
    pub total: usize,
    pub object_digest: Hash,
    pub sha256: Hash,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Range {
    pub object: usize,
    pub offset: usize,
    pub length: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Closed {
    pub capture_id: Hash,
    pub inventory_digest: Hash,
    pub bytes: u64,
}

pub(crate) fn digest(b: &[u8]) -> Hash {
    Sha256::digest(b).into()
}
fn inventory_digest(v: &Inventory) -> Hash {
    let mut h = Sha256::new();
    h.update(b"siworld historical inventory v1");
    h.update(v.capture_id);
    let r = &v.request;
    if let Some(prefix) = &r.prefix {
        h.update([1]);
        h.update(prefix.cache);
        h.update(prefix.target.height.to_le_bytes());
        h.update(prefix.target.tip);
        h.update(prefix.target.work.to_big_endian());
        h.update(prefix.target.execution);
    } else {
        h.update([0]);
    }
    for p in [
        r.request_id,
        r.identity.release,
        r.identity.process_run,
        r.identity.executable,
        r.identity.source_node,
        r.context.network,
        r.context.genesis,
        r.context.rules,
        r.context.proof_profile,
        r.target.tip,
        r.target.execution,
        r.observation,
        r.observation_source,
        r.anchor.id,
        r.anchor.certificate,
        r.anchor.witness,
        r.anchor.snapshot,
        v.canonical_tip,
    ] {
        h.update(p);
    }
    for n in [
        u64::from(r.version),
        r.target.height,
        r.anchor.height,
        r.limits.headers as u64,
        r.limits.frame_bytes,
        r.limits.object_bytes,
        r.limits.memory_bytes as u64,
        r.limits.wall.as_nanos() as u64,
        r.limits.expiry.as_nanos() as u64,
        v.canonical_height,
        v.total_bytes,
        v.objects.len() as u64,
    ] {
        h.update(n.to_le_bytes());
    }
    h.update(r.target.work.to_big_endian());
    for o in &v.objects {
        let (tag, height) = match o.kind {
            Kind::Genesis => (0, 0),
            Kind::Certificate => (1, 0),
            Kind::Witness => (2, 0),
            Kind::Snapshot => (3, 0),
            Kind::Frame {
                height,
                retained_branch,
            } => (if retained_branch { 5 } else { 4 }, height),
        };
        h.update([tag]);
        h.update(height.to_le_bytes());
        h.update((o.bytes as u64).to_le_bytes());
        h.update(o.sha256);
    }
    h.finalize().into()
}

/// One instance is attached to one existing Driver owner. Clones share its slot.
#[derive(Clone)]
pub struct Control {
    owner: Arc<Mutex<Driver>>,
    identity: Identity,
    context: Context,
    genesis: Arc<[u8]>,
    rules: HeaderRules,
    maximum: Limits,
    budget: Budget,
    active: Arc<AtomicBool>,
}
impl Control {
    /// Prepare outside the owner mutex; the resident supplies its exact pinned
    /// identity. This constructor grants no signing, publication or readiness.
    pub fn new(
        owner: Arc<Mutex<Driver>>,
        identity: Identity,
        genesis: &[u8],
        maximum: Limits,
        budget: Budget,
    ) -> Result<Self> {
        if !maximum.admitted(maximum)
            || genesis.len() > 1024 * 1024
            || [
                &identity.release,
                &identity.process_run,
                &identity.executable,
                &identity.source_node,
            ]
            .contains(&&[0; 32])
        {
            return Err(Error::ContextMismatch);
        }
        let g = Genesis::decode(genesis).map_err(|_| Error::ContextMismatch)?;
        let c = g.config();
        let context = Context::for_genesis(&g);
        let rules = HeaderRules {
            network: c.network,
            genesis: g.id(),
            genesis_timestamp: c.genesis_timestamp,
            genesis_target: c.genesis_target,
            target_interval: c.target_interval,
            pow_iterations: c.pow_iterations,
            max_headers: maximum.headers,
        };
        let active = {
            let d = owner.lock().map_err(|_| Error::CaptureFailed)?;
            if Context::for_genesis(d.engine().genesis()) != context {
                return Err(Error::ContextMismatch);
            }
            d.historical_slot()
        };
        Ok(Self {
            owner,
            identity,
            context,
            genesis: genesis.into(),
            rules,
            maximum,
            budget,
            active,
        })
    }
    pub fn begin(&self, request: Request, materials: Option<Materials>) -> Result<Capture> {
        self.begin_reserved(request, materials, None)
    }
    pub(crate) fn begin_charged(
        &self,
        request: Request,
        materials: Option<Materials>,
        reservation: p2p::Reservation,
    ) -> Result<Capture> {
        self.begin_reserved(request, materials, Some(reservation))
    }
    fn begin_reserved(
        &self,
        request: Request,
        materials: Option<Materials>,
        reservation: Option<p2p::Reservation>,
    ) -> Result<Capture> {
        if request.version != 1
            || request.request_id == [0; 32]
            || request.observation == [0; 32]
            || request.observation_source == [0; 32]
            || request.identity != self.identity
            || request.context != self.context
        {
            return Err(Error::ContextMismatch);
        }
        if !request.limits.admitted(self.maximum)
            || request.target.height > request.limits.headers as u64
        {
            return Err(Error::CapacityExceeded);
        }
        if request.anchor.height == 0 {
            if request.anchor != Anchor::genesis(self.context.genesis) || materials.is_some() {
                return Err(Error::AnchorNotAncestor);
            }
        } else {
            let m = materials.as_ref().ok_or(Error::BodyUnavailable)?;
            // Hash large artifacts on this caller, before acquiring the owner.
            if m.anchor(request.anchor.height, request.anchor.id) != request.anchor {
                return Err(Error::ContextMismatch);
            }
        }
        let object_memory = materials.as_ref().map_or(0, |m| {
            m.certificate
                .len()
                .saturating_add(m.witness.len())
                .saturating_add(m.snapshot.len())
        });
        let _metadata_bytes = request
            .limits
            .headers
            .checked_mul(4 * (std::mem::size_of::<Header>() + std::mem::size_of::<Object>() + 64))
            .and_then(|v| {
                v.checked_add(2 * MAX_CHUNK + 24 * 1024 * 1024 + object_memory + self.genesis.len())
            })
            .filter(|v| *v <= request.limits.memory_bytes)
            .ok_or(Error::CapacityExceeded)?;
        let reserved = if let Some(mut reservation) = reservation {
            if !reservation.covers(&self.budget, request.limits.memory_bytes) {
                return Err(Error::CapacityExceeded);
            }
            reservation
                .shrink_to(request.limits.memory_bytes)
                .map_err(|_| Error::CapacityExceeded)?;
            reservation
        } else {
            self.budget
                .reserve(request.limits.memory_bytes)
                .map_err(|_| Error::CapacityExceeded)?
        };
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::CapacityExceeded)?;
        let lease = Lease(self.active.clone());
        let (canonical, branches) = {
            let d = self.owner.lock().map_err(|_| Error::CaptureFailed)?;
            d.capture_history()?
        };
        let mut capture_id = [0; 32];
        getrandom::fill(&mut capture_id).map_err(|_| Error::CaptureFailed)?;
        let started = Instant::now();
        let (commands, rx) = mpsc::sync_channel(1);
        let (ready_tx, ready) = mpsc::sync_channel(1);
        let canceled = Arc::new(AtomicBool::new(false));
        let cancel = canceled.clone();
        let genesis = self.genesis.clone();
        let rules = self.rules.clone();
        let expires = started + request.limits.expiry;
        let handle = std::thread::Builder::new()
            .name("historical-read".into())
            .spawn(move || {
                let _lease = lease;
                let _reserved = reserved;
                let work = WorkRead {
                    canonical,
                    branches,
                    genesis,
                    materials,
                };
                let prepared = work.prepare(capture_id, request, rules, started, &cancel);
                match prepared {
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                    Ok((inventory, frames)) => {
                        if ready_tx.send(Ok(inventory.clone())).is_err() {
                            return;
                        }
                        let mut cached_frame = None;
                        loop {
                            if cancel.load(Ordering::Acquire) || Instant::now() >= expires {
                                return;
                            }
                            let command = match rx.recv_timeout(
                                expires
                                    .saturating_duration_since(Instant::now())
                                    .min(Duration::from_millis(50)),
                            ) {
                                Ok(c) => c,
                                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                                Err(_) => return,
                            };
                            match command {
                                Command::Read {
                                    object,
                                    offset,
                                    length,
                                    reply,
                                } => {
                                    let value = work.chunk(
                                        &inventory,
                                        &frames,
                                        &mut cached_frame,
                                        object,
                                        offset,
                                        length,
                                    );
                                    if Instant::now() >= expires {
                                        let _ = reply.send(Err(Error::CaptureExpired));
                                        return;
                                    }
                                    let _ = reply.send(value);
                                }
                            }
                        }
                    }
                }
            })
            .map_err(|_| Error::CaptureFailed)?;
        let result = ready
            .recv_timeout(expires.saturating_duration_since(Instant::now()))
            .map_err(|_| Error::CaptureExpired)
            .and_then(|v| v);
        match result {
            Ok(inventory) => Ok(Capture {
                inventory,
                commands: Some(commands),
                handle: Some(handle),
                canceled,
                expires,
                object: 0,
                offset: 0,
                read_bytes: 0,
            }),
            Err(e) => {
                canceled.store(true, Ordering::Release);
                drop(commands);
                let _ = handle.join();
                Err(e)
            }
        }
    }
    /// A fixed-width original header supplies a missing execution selector.
    /// This is source metadata; only independent replay establishes validity.
    pub fn original_header(&self, height: u64, tip: Hash) -> Result<HeaderObservation> {
        if height == 0 || height > self.maximum.headers as u64 || tip == [0; 32] {
            return Err(Error::ContextMismatch);
        }
        let (canonical, branches) = {
            let d = self.owner.lock().map_err(|_| Error::CaptureFailed)?;
            d.capture_history()?
        };
        let (header, origin) = if let Some(h) = canonical
            .header(height)?
            .filter(|h| h.id().ok() == Some(tip))
        {
            (h, HeaderOrigin::Canonical)
        } else {
            let h = branches
                .as_ref()
                .map(|b| b.header(tip))
                .transpose()?
                .flatten()
                .ok_or(Error::BranchNotRetained)?;
            (h, HeaderOrigin::RetainedBranch)
        };
        if header.height != height || header.id().ok() != Some(tip) {
            return Err(Error::ContextMismatch);
        }
        Ok(HeaderObservation {
            identity: self.identity.clone(),
            context: self.context.clone(),
            height,
            tip,
            execution: header.execution_commitment,
            header: header.encode().map_err(|_| Error::CaptureFailed)?.to_vec(),
            origin,
            source_validity_authority: false,
        })
    }
    pub fn active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}
struct Lease(Arc<AtomicBool>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
enum Command {
    Read {
        object: usize,
        offset: usize,
        length: usize,
        reply: mpsc::SyncSender<Result<Chunk>>,
    },
}
pub struct Capture {
    inventory: Inventory,
    commands: Option<mpsc::SyncSender<Command>>,
    handle: Option<JoinHandle<()>>,
    canceled: Arc<AtomicBool>,
    expires: Instant,
    object: usize,
    offset: usize,
    read_bytes: u64,
}
impl Capture {
    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }
    /// A finite batch preserves ordered complete coverage and the per-chunk
    /// bound. Rejected or interrupted batches cannot leave partial authority.
    pub fn read_batch(&mut self, id: Hash, ranges: &[Range]) -> Result<Vec<Chunk>> {
        if id != self.inventory.capture_id {
            return Err(Error::ContextMismatch);
        }
        if ranges.is_empty() || ranges.len() > MAX_BATCH {
            return Err(Error::CapacityExceeded);
        }
        let (mut object, mut offset) = (self.object, self.offset);
        for r in ranges {
            let pin = self
                .inventory
                .objects
                .get(object)
                .ok_or(Error::ContextMismatch)?;
            if r.object != object
                || r.offset != offset
                || r.length == 0
                || r.length > MAX_CHUNK
                || offset.checked_add(r.length).is_none_or(|n| n > pin.bytes)
            {
                return Err(Error::ContextMismatch);
            }
            offset += r.length;
            if offset == pin.bytes {
                object += 1;
                offset = 0;
            }
        }
        let result: Result<Vec<Chunk>> = ranges
            .iter()
            .map(|r| self.read(id, r.object, r.offset, r.length))
            .collect();
        if result.is_err() {
            self.cancel();
        }
        result
    }
    /// Ordered transfer makes complete coverage explicit and keeps receipt
    /// bookkeeping bounded independently of caller-chosen offsets.
    pub fn read(&mut self, id: Hash, object: usize, offset: usize, length: usize) -> Result<Chunk> {
        if id != self.inventory.capture_id {
            return Err(Error::ContextMismatch);
        }
        if Instant::now() >= self.expires {
            self.cancel();
            return Err(Error::CaptureExpired);
        }
        if length == 0 || length > MAX_CHUNK || object != self.object || offset != self.offset {
            return Err(Error::ContextMismatch);
        }
        let pin = self
            .inventory
            .objects
            .get(object)
            .ok_or(Error::ContextMismatch)?;
        if offset.checked_add(length).is_none_or(|v| v > pin.bytes) {
            return Err(Error::ContextMismatch);
        }
        let total = pin.bytes;
        let (tx, rx) = mpsc::sync_channel(1);
        self.commands
            .as_ref()
            .ok_or(Error::CaptureExpired)?
            .send(Command::Read {
                object,
                offset,
                length,
                reply: tx,
            })
            .map_err(|_| Error::CaptureExpired)?;
        let value = rx
            .recv_timeout(self.expires.saturating_duration_since(Instant::now()))
            .map_err(|_| Error::CaptureExpired)??;
        self.offset += length;
        self.read_bytes += length as u64;
        if self.offset == total {
            self.object += 1;
            self.offset = 0;
        }
        Ok(value)
    }
    pub fn close(mut self) -> Result<Closed> {
        if Instant::now() >= self.expires {
            return Err(Error::CaptureExpired);
        }
        if self.object != self.inventory.objects.len()
            || self.read_bytes != self.inventory.total_bytes
        {
            return Err(Error::CaptureFailed);
        }
        self.cancel();
        Ok(Closed {
            capture_id: self.inventory.capture_id,
            inventory_digest: self.inventory.digest,
            bytes: self.read_bytes,
        })
    }
    pub fn cancel(&mut self) {
        self.canceled.store(true, Ordering::Release);
        self.commands.take();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.cancel();
    }
}

struct WorkRead {
    canonical: store::history::Read,
    branches: Option<branches::history::Read>,
    genesis: Arc<[u8]>,
    materials: Option<Materials>,
}
struct Frame {
    header: Header,
    branch: bool,
}
impl WorkRead {
    fn frame_bytes(&self, f: &Frame) -> Result<Vec<u8>> {
        if f.branch {
            self.branches
                .as_ref()
                .ok_or(Error::BranchNotRetained)?
                .frame(&f.header)
        } else {
            self.canonical.frame(&f.header)
        }
    }
    fn prepare(
        &self,
        id: Hash,
        request: Request,
        mut rules: HeaderRules,
        started: Instant,
        cancel: &AtomicBool,
    ) -> Result<(Inventory, Vec<Frame>)> {
        let check = || {
            if cancel.load(Ordering::Acquire) || started.elapsed() >= request.limits.wall {
                Err(Error::CaptureExpired)
            } else {
                Ok(())
            }
        };
        let mut frames = Vec::with_capacity(request.target.height as usize);
        let mut wanted = request.target.tip;
        for height in (1..=request.target.height).rev() {
            check()?;
            let canonical = self
                .canonical
                .header(height)?
                .filter(|h| h.id().ok() == Some(wanted));
            let (header, branch) = match canonical {
                Some(h) => (h, false),
                None => (
                    self.branches
                        .as_ref()
                        .ok_or(Error::BranchNotRetained)?
                        .header(wanted)?
                        .filter(|h| h.height == height)
                        .ok_or(Error::BranchNotRetained)?,
                    true,
                ),
            };
            wanted = header.parent;
            frames.push(Frame { header, branch });
        }
        if wanted != request.context.genesis {
            return Err(Error::BranchNotRetained);
        }
        frames.reverse();
        rules.max_headers = request.limits.headers;
        let verified = VerifiedHeaders::verify_bounded(
            rules,
            frames.iter().map(|f| f.header.clone()).collect(),
            || check().is_ok(),
        );
        check()?;
        let verified = verified.map_err(|_| Error::CaptureFailed)?;
        if verified.id(request.target.height).ok() != Some(request.target.tip)
            || verified.cumulative_work() != request.target.work
            || frames
                .last()
                .is_none_or(|f| f.header.execution_commitment != request.target.execution)
        {
            return Err(Error::ContextMismatch);
        }
        if request.anchor.height > request.target.height
            || (request.anchor.height > 0
                && verified
                    .header(request.anchor.height)
                    .is_none_or(|h| h.id().ok() != Some(request.anchor.id)))
        {
            return Err(Error::AnchorNotAncestor);
        }
        let first = if let Some(prefix) = &request.prefix {
            let p = &prefix.target;
            if prefix.cache == [0; 32]
                || p.height == 0
                || p.height > request.target.height
                || verified.id(p.height).ok() != Some(p.tip)
                || verified.work_at(p.height).ok() != Some(p.work)
                || verified
                    .header(p.height)
                    .is_none_or(|h| h.execution_commitment != p.execution)
            {
                return Err(Error::AnchorNotAncestor);
            }
            p.height as usize
        } else {
            0
        };
        let mut objects = vec![Object {
            kind: Kind::Genesis,
            bytes: self.genesis.len(),
            sha256: digest(&self.genesis),
        }];
        if let Some(m) = &self.materials {
            for (kind, b) in [
                (Kind::Certificate, &m.certificate),
                (Kind::Witness, &m.witness),
                (Kind::Snapshot, &m.snapshot),
            ] {
                check()?;
                if b.is_empty() {
                    return Err(Error::BodyUnavailable);
                }
                objects.push(Object {
                    kind,
                    bytes: b.len(),
                    sha256: digest(b),
                });
            }
        }
        let mut total = objects
            .iter()
            .try_fold(0u64, |n, o| n.checked_add(o.bytes as u64))
            .ok_or(Error::CapacityExceeded)?;
        let mut frame_total = 0u64;
        if total > request.limits.object_bytes {
            return Err(Error::CapacityExceeded);
        }
        for f in &frames[first..] {
            check()?;
            let size = if f.branch {
                self.branches
                    .as_ref()
                    .ok_or(Error::BranchNotRetained)?
                    .size(&f.header, self.canonical.policy.max_body_bytes)?
            } else {
                self.canonical.size(&f.header)?
            };
            frame_total = frame_total
                .checked_add(size as u64)
                .filter(|n| *n <= request.limits.frame_bytes)
                .ok_or(Error::CapacityExceeded)?;
            total = total
                .checked_add(size as u64)
                .filter(|n| *n <= request.limits.object_bytes)
                .ok_or(Error::CapacityExceeded)?;
            // redb may assemble an overflow value for each lookup. Read a
            // complete frame once rather than looking it up for every chunk.
            // Charge both that assembly and the owned frame before allocation.
            let metadata = request
                .limits
                .headers
                .saturating_mul(
                    4 * (std::mem::size_of::<Header>() + std::mem::size_of::<Object>() + 64),
                )
                .saturating_add(2 * MAX_CHUNK + 24 * 1024 * 1024 + self.genesis.len())
                .saturating_add(self.materials.as_ref().map_or(0, |m| {
                    m.certificate.len() + m.witness.len() + m.snapshot.len()
                }));
            if size
                .checked_mul(2)
                .and_then(|n| n.checked_add(metadata))
                .is_none_or(|n| n > request.limits.memory_bytes)
            {
                return Err(Error::CapacityExceeded);
            }
            let bytes = self.frame_bytes(f)?;
            if bytes.len() != size {
                return Err(Error::BodyUnavailable);
            }
            check()?;
            objects.push(Object {
                kind: Kind::Frame {
                    height: f.header.height,
                    retained_branch: f.branch,
                },
                bytes: size,
                sha256: digest(&bytes),
            });
        }
        check()?;
        let mut inventory = Inventory {
            capture_id: id,
            request,
            canonical_height: self.canonical.height,
            canonical_tip: self.canonical.tip,
            objects,
            total_bytes: total,
            digest: [0; 32],
        };
        inventory.digest = inventory_digest(&inventory);
        Ok((inventory, frames))
    }
    fn chunk(
        &self,
        inventory: &Inventory,
        frames: &[Frame],
        cached_frame: &mut Option<(usize, Vec<u8>)>,
        object: usize,
        offset: usize,
        length: usize,
    ) -> Result<Chunk> {
        let pin = inventory
            .objects
            .get(object)
            .ok_or(Error::ContextMismatch)?;
        if length == 0
            || length > MAX_CHUNK
            || offset.checked_add(length).is_none_or(|v| v > pin.bytes)
        {
            return Err(Error::ContextMismatch);
        }
        let memory = match pin.kind {
            Kind::Genesis => Some(self.genesis.as_ref()),
            Kind::Certificate => self.materials.as_ref().map(|m| m.certificate.as_ref()),
            Kind::Witness => self.materials.as_ref().map(|m| m.witness.as_ref()),
            Kind::Snapshot => self.materials.as_ref().map(|m| m.snapshot.as_ref()),
            Kind::Frame { .. } => None,
        };
        let bytes = if let Some(b) = memory {
            b[offset..offset + length].to_vec()
        } else if let Kind::Frame { height, .. } = pin.kind {
            if cached_frame.as_ref().is_none_or(|(i, _)| *i != object) {
                *cached_frame = None;
                let bytes = self.frame_bytes(
                    frames
                        .get(height as usize - 1)
                        .ok_or(Error::CaptureFailed)?,
                )?;
                if bytes.len() != pin.bytes || digest(&bytes) != pin.sha256 {
                    return Err(Error::CaptureFailed);
                }
                *cached_frame = Some((object, bytes));
            }
            let bytes = cached_frame
                .as_ref()
                .ok_or(Error::CaptureFailed)?
                .1
                .get(offset..offset + length)
                .ok_or(Error::BodyUnavailable)?
                .to_vec();
            if offset + length == pin.bytes {
                *cached_frame = None;
            }
            bytes
        } else {
            return Err(Error::BodyUnavailable);
        };
        Ok(Chunk {
            object,
            offset,
            total: pin.bytes,
            object_digest: pin.sha256,
            sha256: digest(&bytes),
            bytes,
        })
    }
}

mod work_codec {
    use super::*;
    pub(super) fn serialize<S: serde::Serializer>(
        v: &Work,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&crate::local::hex(&v.to_big_endian()))
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<Work, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 128
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(serde::de::Error::custom("invalid work"));
        }
        let mut b = [0; 64];
        for (i, p) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            b[i] = u8::from_str_radix(
                std::str::from_utf8(p).map_err(serde::de::Error::custom)?,
                16,
            )
            .map_err(serde::de::Error::custom)?;
        }
        Ok(Work::from_big_endian(&b))
    }
}
