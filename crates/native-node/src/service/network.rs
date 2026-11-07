//! Opt-in, pinned engineering networking with a single canonical-state owner.
//! Socket workers own framing only. Bounded, charged messages cross into the
//! owner; no worker can open a store or hold its lock while waiting on a peer.
use super::*;
use crate::identity::{Descriptor, NativeIdentity, PeerPin};
use crate::p2p::{
    self, AdmissionContext, Budget, Cancellation, ConnectionRole, ExpectedPeer, Packet,
    Reservation, Role, Session,
};
use crate::peer_scheduler::{self, Attempt, Direction, Failure, Scheduler};
use crate::runtime::resident::{OwnedRelay, OwnedSyncReply, ReplyMeta};
use crate::runtime::{self, Node, PreparedBlock, SyncAttempt};
use crate::state::BlockVerifier;
use crate::sync::Batch;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::JoinHandle;

const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_WORKERS: usize = 16;
const COMMAND_SLOTS: usize = 32;
const COMMAND_BYTES: usize = 8192;
const WORKER_STACK: usize = 1024 * 1024;
const RELAY_TRACKING_BYTES: usize = 256 * 1024;
const PRODUCER_JOB_BYTES: usize = 256 * 1024 * 1024;
const PRODUCER_TOTAL_BYTES: usize = 2 * PRODUCER_JOB_BYTES;
const POLL: Duration = Duration::from_millis(20);
const CYCLE: Duration = Duration::from_secs(1);
const EXCHANGE: Duration = Duration::from_secs(180);
const ROUTE_MAGIC: &[u8; 4] = b"SWP2";

#[derive(Clone)]
struct Peer {
    endpoint: SocketAddr,
    dial: bool,
    expected: ExpectedPeer,
}
pub(super) struct Configuration {
    listen: Option<SocketAddr>,
    mining: bool,
    peers: Arc<BTreeMap<Hash, Peer>>,
    digest: String,
}
fn decode_hex(text: &str, maximum: usize) -> Result<Vec<u8>, String> {
    if text.len() > maximum * 2 || !text.len().is_multiple_of(2) {
        return Err("invalid public record length".into());
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |x| match x {
                b'0'..=b'9' => Some(x - b'0'),
                b'a'..=b'f' => Some(x - b'a' + 10),
                _ => None,
            };
            Some((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "invalid public record encoding".into())
}
/// Pin creation requires an independently checked fingerprint. A descriptor
/// received on a socket or merely present in configuration is never trusted.
pub fn pin_peer(directory: &Path, descriptor_file: &Path, fingerprint: &str) -> Result<(), String> {
    let binding = p2p::Binding::new(&local::load(directory)?);
    let mut bytes = Vec::new();
    local::regular_read(descriptor_file, false, 32768)?
        .read_to_end(&mut bytes)
        .map_err(|_| "public identity file unavailable")?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid public identity file")?;
    let object = value.as_object().ok_or("invalid public identity object")?;
    if object.len() != 3
        || value["version"] != crate::identity::VERSION
        || value["fingerprint"] != fingerprint
    {
        return Err("public identity and independently checked fingerprint differ".into());
    }
    let expected = decode_hex(fingerprint, 32)?;
    let descriptor = Descriptor::decode(
        &decode_hex(
            value["descriptor"].as_str().ok_or("missing descriptor")?,
            crate::identity::DESCRIPTOR_BYTES,
        )?,
        &binding,
    )
    .map_err(|_| "public identity verification rejected")?;
    if expected.as_slice() != descriptor.fingerprint() {
        return Err("public identity fingerprint mismatch".into());
    }
    let pin = PeerPin::from_trusted_descriptor(&descriptor, &binding)
        .map_err(|_| "public pin rejected")?;
    pin.persist(directory)
        .map_err(|_| "public pin persistence rejected".to_owned())
}
impl Configuration {
    pub(super) fn listening_enabled(&self) -> bool {
        self.listen.is_some()
    }
    pub(super) fn mining_enabled(&self) -> bool {
        self.mining
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn load(
        directory: &Path,
        path: &Path,
        binding: p2p::Binding,
        local_id: Hash,
    ) -> Result<Self, String> {
        let mut bytes = Vec::new();
        local::regular_read(path, true, MAX_CONFIG_BYTES)?
            .read_to_end(&mut bytes)
            .map_err(|_| "peer configuration unavailable")?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid peer configuration")?;
        let object = value
            .as_object()
            .ok_or("invalid peer configuration object")?;
        if object.len() != 5 || value["version"] != 1 || value["engineering"] != true {
            return Err("explicit engineering peer configuration required".into());
        }
        let listen_value = value
            .get("listen")
            .ok_or("Explicit listen selection is required")?;
        let listen = if listen_value.is_null() {
            None
        } else {
            Some(
                listen_value
                    .as_str()
                    .ok_or("invalid listen selection")?
                    .parse()
                    .map_err(|_| "invalid listen endpoint")?,
            )
        };
        let mining = value["mining"]
            .as_bool()
            .ok_or("explicit mining selection required")?;
        let values = value["peers"]
            .as_array()
            .ok_or("missing configured peers")?;
        if values.len() > peer_scheduler::MAX_PEERS {
            return Err("configured peer limit".into());
        }
        let mut peers = BTreeMap::new();
        let mut endpoints = BTreeSet::new();
        for value in values {
            let entry = value.as_object().ok_or("invalid peer entry")?;
            if entry.len() != 3 && !(entry.len() == 4 && entry.contains_key("dial")) {
                return Err("unexpected peer entry field".into());
            }
            let dial = match value.get("dial") {
                None => true,
                Some(v) => v.as_bool().ok_or("invalid peer dial selection")?,
            };
            let endpoint: SocketAddr = value["endpoint"]
                .as_str()
                .ok_or("missing peer endpoint")?
                .parse()
                .map_err(|_| "invalid peer endpoint")?;
            if endpoint.port() == 0
                || endpoint.ip().is_unspecified()
                || endpoint.ip().is_multicast()
                || !endpoints.insert(endpoint)
            {
                return Err("invalid or duplicate configured endpoint".into());
            }
            let fingerprint: Hash = decode_hex(
                value["fingerprint"]
                    .as_str()
                    .ok_or("missing peer fingerprint")?,
                32,
            )?
            .try_into()
            .map_err(|_| "invalid peer fingerprint")?;
            let descriptor = Descriptor::decode(
                &decode_hex(
                    value["descriptor"]
                        .as_str()
                        .ok_or("missing peer descriptor")?,
                    crate::identity::DESCRIPTOR_BYTES,
                )?,
                &binding,
            )
            .map_err(|_| "peer descriptor rejected")?;
            let pin = PeerPin::load(directory, fingerprint, &binding)
                .map_err(|_| "peer is not independently pinned")?;
            let expected = ExpectedPeer::from_pinned_descriptor(binding, descriptor, pin)
                .map_err(|_| "configured peer mismatch")?;
            if fingerprint == local_id
                || peers
                    .insert(
                        fingerprint,
                        Peer {
                            endpoint,
                            dial,
                            expected,
                        },
                    )
                    .is_some()
            {
                return Err("duplicate or local configured identity".into());
            }
        }
        Ok(Self {
            listen,
            mining,
            peers: Arc::new(peers),
            digest: local::hex(&Sha256::digest(&bytes)),
        })
    }
}

type Answer<T> = SyncSender<Result<T, runtime::Error>>;
enum Command {
    RelayNext {
        id: u64,
        reply: Answer<Option<OwnedRelay>>,
    },
    RelayAcknowledged {
        id: u64,
        statement: Hash,
        reply: Answer<()>,
    },
    RelayAdmit {
        id: u64,
        body: Vec<u8>,
        guard: Reservation,
        reply: Answer<Hash>,
    },
    Authenticated {
        id: u64,
        peer: Hash,
        reply: Answer<()>,
    },
    Pull {
        id: u64,
        reply: Answer<Vec<u8>>,
    },
    Begin {
        id: u64,
        meta: ReplyMeta,
        reply: Answer<()>,
    },
    Apply {
        id: u64,
        batch: Batch,
        guards: Vec<Reservation>,
        reply: Answer<bool>,
    },
    Serve {
        id: u64,
        body: Vec<u8>,
        reply: Answer<OwnedSyncReply>,
    },
}
struct ChargedCommand {
    command: Command,
    _reservation: Reservation,
}
fn unavailable() -> runtime::Error {
    p2p::Error::Unavailable.into()
}
fn invalid() -> runtime::Error {
    p2p::Error::InvalidProtocol.into()
}
fn call<T>(
    tx: &SyncSender<ChargedCommand>,
    budget: &Budget,
    cancel: &Cancellation,
    make: impl FnOnce(Answer<T>) -> Command,
) -> Result<T, runtime::Error> {
    let (reply, receive) = mpsc::sync_channel(1);
    let mut command = ChargedCommand {
        command: make(reply),
        _reservation: budget.reserve(COMMAND_BYTES)?,
    };
    loop {
        if cancel.is_cancelled() {
            return Err(unavailable());
        }
        match tx.try_send(command) {
            Ok(()) => break,
            Err(TrySendError::Full(value)) => {
                command = value;
                std::thread::sleep(POLL);
            }
            Err(TrySendError::Disconnected(_)) => return Err(unavailable()),
        }
    }
    loop {
        if cancel.is_cancelled() {
            return Err(unavailable());
        }
        match receive.recv_timeout(POLL) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(_) => return Err(unavailable()),
        }
    }
}

struct Worker {
    peer: Option<Hash>,
    token: Option<Attempt>,
    cancel: Cancellation,
    join: JoinHandle<Failure>,
    sync: SyncAttempt,
    acknowledged: BTreeSet<Hash>,
    sync_goal: Option<u64>,
    sync_more: bool,
    sync_complete: bool,
    _reservation: Reservation,
}
struct PendingAuthentication {
    id: u64,
    reply: Answer<()>,
    deadline: u64,
    _reservation: Reservation,
}
enum Admission {
    Established,
    Waiting,
}
struct Driver {
    listener: Option<TcpListener>,
    identity: Arc<NativeIdentity>,
    local: Hash,
    peers: Arc<BTreeMap<Hash, Peer>>,
    budget: Budget,
    scheduler: Scheduler,
    started: Instant,
    next_id: u64,
    workers: BTreeMap<u64, Worker>,
    pending_authentication: BTreeMap<Hash, PendingAuthentication>,
    tx: SyncSender<ChargedCommand>,
    rx: Receiver<ChargedCommand>,
    role: Role,
    connections: u64,
    failures: u64,
    _configuration: Reservation,
}
impl Driver {
    fn new(
        identity: Arc<NativeIdentity>,
        config: Configuration,
        budget: Budget,
    ) -> Result<Self, String> {
        let local = identity
            .descriptor()
            .map_err(|_| "local descriptor unavailable")?
            .fingerprint();
        let scheduler = Scheduler::new(
            local,
            &config.peers.keys().copied().collect::<Vec<_>>(),
            budget.clone(),
            0,
        )
        .map_err(|_| "peer scheduling rejected")?;
        let listener = config
            .listen
            .map(|address| {
                let listener =
                    TcpListener::bind(address).map_err(|_| "native listener unavailable")?;
                listener
                    .set_nonblocking(true)
                    .map_err(|_| "native listener mode unavailable")?;
                Ok::<_, String>(listener)
            })
            .transpose()?;
        let configuration = budget
            .reserve(MAX_CONFIG_BYTES)
            .map_err(|_| "peer configuration budget unavailable")?;
        let (tx, rx) = mpsc::sync_channel(COMMAND_SLOTS);
        Ok(Self {
            listener,
            identity,
            local,
            peers: config.peers,
            budget,
            scheduler,
            started: Instant::now(),
            next_id: 0,
            workers: BTreeMap::new(),
            pending_authentication: BTreeMap::new(),
            tx,
            rx,
            role: if config.mining {
                Role::Miner
            } else {
                Role::Validator
            },
            connections: 0,
            failures: 0,
            _configuration: configuration,
        })
    }
    fn has_synced_peer(&self) -> bool {
        self.workers.values().any(|w| {
            w.token.is_some() && w.peer.is_some() && !w.cancel.is_cancelled() && w.sync_complete
        })
    }
    fn sync_goal(&self) -> Option<u64> {
        self.workers
            .values()
            .filter(|w| !w.cancel.is_cancelled())
            .filter_map(|w| w.sync_goal)
            .max()
    }
    fn status(&self, mining: bool) -> Value {
        let status = self.scheduler.status();
        json!({"configured":status.configured,"pending":status.pending,
            "connected":status.established,"closing":status.closing,
            "disabled":status.disabled,"workers":self.workers.len(),
            "authenticated_connections":self.connections,"closed_connections":self.failures,
            "mining":mining})
    }
    fn now(&self) -> u64 {
        elapsed_ms(self.started, Instant::now())
    }
    fn cancel_attempt(&self, token: Attempt) {
        for worker in self.workers.values().filter(|w| w.token == Some(token)) {
            worker.cancel.cancel();
        }
    }
    fn spawn(
        &mut self,
        socket: Option<TcpStream>,
        peer: Option<Hash>,
        token: Option<Attempt>,
    ) -> Result<(), String> {
        if self.workers.len() >= MAX_WORKERS {
            return Err("resident worker capacity".into());
        }
        let reservation = self
            .budget
            .reserve(WORKER_STACK + RELAY_TRACKING_BYTES)
            .map_err(|_| "resident worker budget unavailable")?;
        let id = self
            .next_id
            .checked_add(1)
            .ok_or("resident worker generation exhausted")?;
        self.next_id = id;
        let cancel = Cancellation::default();
        let cancellation = cancel.clone();
        let identity = self.identity.clone();
        let peers = self.peers.clone();
        let budget = self.budget.clone();
        let tx = self.tx.clone();
        let local = self.local;
        let role = self.role;
        let accepted = Instant::now();
        let join = std::thread::Builder::new()
            .name("native-peer".into())
            .stack_size(WORKER_STACK)
            .spawn(move || {
                let result = connection(
                    id,
                    socket,
                    peer,
                    accepted,
                    local,
                    identity,
                    peers,
                    role,
                    budget,
                    tx,
                    cancellation,
                );
                match result {
                    Ok(()) => Failure::Unavailable,
                    Err(runtime::Error::Transport(p2p::Error::InvalidProtocol)) => {
                        Failure::Protocol
                    }
                    Err(runtime::Error::Transport(p2p::Error::ResourceExhausted)) => {
                        Failure::LocalResource
                    }
                    Err(runtime::Error::Admission(_))
                    | Err(runtime::Error::Chain(crate::chain::ChainError::Invalid(_))) => {
                        Failure::Protocol
                    }
                    Err(_) => Failure::Unavailable,
                }
            })
            .map_err(|_| "native peer worker unavailable")?;
        self.workers.insert(
            id,
            Worker {
                peer,
                token,
                cancel,
                join,
                sync: SyncAttempt::default(),
                acknowledged: BTreeSet::new(),
                sync_goal: None,
                sync_more: true,
                sync_complete: false,
                _reservation: reservation,
            },
        );
        Ok(())
    }
    fn poll(&mut self) -> Result<(), String> {
        let finished: Vec<_> = self
            .workers
            .iter()
            .filter_map(|(id, w)| w.join.is_finished().then_some(*id))
            .collect();
        for id in finished {
            let worker = self.workers.remove(&id).expect("selected worker");
            let failure = worker.join.join().unwrap_or(Failure::LocalResource);
            if let Some(token) = worker.token {
                self.scheduler
                    .closed(token, failure, self.now())
                    .map_err(|_| "peer closure state mismatch")?;
            }
            self.failures = self.failures.saturating_add(1);
        }
        for token in self
            .scheduler
            .poll(self.now())
            .map_err(|_| "peer expiry state mismatch")?
        {
            self.cancel_attempt(token);
        }
        self.poll_authentication();
        // Bound accepts per owner turn, including sockets rejected at capacity.
        for _ in 0..4 {
            let Some(listener) = &self.listener else {
                break;
            };
            match listener.accept() {
                Ok((socket, _)) if self.workers.len() < MAX_WORKERS => {
                    self.spawn(Some(socket), None, None)?;
                }
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => return Err("native listener failed".into()),
            }
        }
        let ready = self
            .scheduler
            .ready_outbound(self.now())
            .map_err(|_| "peer dial scheduling failed")?;
        // This explicit engineering topology requires both endpoints to load
        // each other's trusted descriptor and reachable listen address. Only
        // the smaller pinned identity initiates, on every reconnect. Deferring
        // inbound scheduling until authentication prevents forged routing
        // hints from changing policy, but simultaneous outbound handshakes
        // could otherwise establish on both sides before duplicate rejection.
        // A single initiator avoids that race; the accepted connection still
        // synchronizes both directions in every paired cycle.
        let local = self.local;
        let outbound_only = self.listener.is_none();
        let ready: Vec<_> = ready
            .into_iter()
            .filter(|peer| self.peers[peer].dial && (outbound_only || local < *peer))
            .collect();
        for peer in ready {
            if self.workers.len() >= MAX_WORKERS {
                break;
            }
            let start = match self.scheduler.begin(peer, Direction::Outbound, self.now()) {
                Ok(x) => x,
                Err(_) => continue,
            };
            if let Some(old) = start.cancel {
                self.cancel_attempt(old);
            }
            if self.spawn(None, Some(peer), Some(start.token)).is_err() {
                self.scheduler
                    .closed(start.token, Failure::LocalResource, self.now())
                    .map_err(|_| "failed dial cleanup mismatch")?;
            }
        }
        Ok(())
    }
    fn admit_authenticated(&mut self, id: u64, peer: Hash) -> Result<Admission, runtime::Error> {
        let worker = self.workers.get(&id).ok_or_else(unavailable)?;
        if worker.cancel.is_cancelled()
            || worker.join.is_finished()
            || !self.peers.contains_key(&peer)
        {
            return Err(unavailable());
        }
        let token = if let Some(token) = worker.token {
            if worker.peer != Some(peer) {
                return Err(invalid());
            }
            token
        } else {
            // Only fully authenticated inbound sessions can affect scheduling
            // for a configured identity. A retiring worker still owns its
            // established slot until poll joins it and applies normal backoff.
            let start = match self.scheduler.begin(peer, Direction::Inbound, self.now()) {
                Ok(start) => start,
                Err(peer_scheduler::Error::Duplicate | peer_scheduler::Error::Backoff)
                    if self.local > peer =>
                {
                    return Ok(Admission::Waiting);
                }
                Err(_) => return Err(unavailable()),
            };
            if let Some(old) = start.cancel {
                self.cancel_attempt(old);
            }
            let worker = self.workers.get_mut(&id).expect("checked worker");
            worker.peer = Some(peer);
            worker.token = Some(start.token);
            start.token
        };
        self.scheduler
            .authenticated(token, self.now())
            .map_err(|_| unavailable())?;
        self.connections = self.connections.saturating_add(1);
        Ok(Admission::Established)
    }
    fn poll_authentication(&mut self) {
        // At most one charged waiter per peer and worker is retained. Retrying
        // after actual retirement preserves scheduler capacity and backoff;
        // the original deadline is never extended by owner polling.
        for (peer, pending) in std::mem::take(&mut self.pending_authentication) {
            let result = if self.now() >= pending.deadline {
                Err(unavailable())
            } else {
                self.admit_authenticated(pending.id, peer)
            };
            match result {
                Ok(Admission::Waiting) => {
                    self.pending_authentication.insert(peer, pending);
                }
                Ok(Admission::Established) => {
                    let _ = pending.reply.send(Ok(()));
                }
                Err(error) => {
                    let _ = pending.reply.send(Err(error));
                }
            }
        }
    }
    fn handle<V: BlockVerifier>(
        &mut self,
        node: &mut Node<V>,
        charged: ChargedCommand,
    ) -> Result<(), String> {
        let charge = charged._reservation;
        match charged.command {
            Command::RelayNext { id, reply } => {
                let result = self
                    .active_mut(id)
                    .and_then(|worker| node.resident_relay_next(&mut worker.acknowledged));
                let _ = reply.send(result);
            }
            Command::RelayAcknowledged {
                id,
                statement,
                reply,
            } => {
                let result = self.active_mut(id).and_then(|worker| {
                    // The fixed production pool cannot exceed 2,048 entries.
                    // Prune before inserting to bound a long-lived connection.
                    worker.acknowledged.retain(|id| node.mempool().contains(id));
                    if node.mempool().contains(&statement) {
                        if worker.acknowledged.len() >= 2048
                            && !worker.acknowledged.contains(&statement)
                        {
                            return Err(unavailable());
                        }
                        worker.acknowledged.insert(statement);
                    }
                    Ok(())
                });
                let _ = reply.send(result);
            }
            Command::RelayAdmit {
                id,
                body,
                guard,
                reply,
            } => {
                let _guard = guard;
                let result = self.active(id).and_then(|worker| {
                    node.resident_admit_relay(worker.peer.expect("authenticated peer"), &body)
                });
                let _ = reply.send(result);
            }
            Command::Authenticated { id, peer, reply } => {
                if self.pending_authentication.contains_key(&peer)
                    || self
                        .pending_authentication
                        .values()
                        .any(|pending| pending.id == id)
                {
                    let _ = reply.send(Err(unavailable()));
                    return Ok(());
                }
                match self.admit_authenticated(id, peer) {
                    Ok(Admission::Waiting) if self.pending_authentication.len() < MAX_WORKERS => {
                        let deadline = self.now().checked_add(peer_scheduler::ADMISSION_MS);
                        if let Some(deadline) = deadline {
                            self.pending_authentication.insert(
                                peer,
                                PendingAuthentication {
                                    id,
                                    reply,
                                    deadline,
                                    _reservation: charge,
                                },
                            );
                        } else {
                            let _ = reply.send(Err(unavailable()));
                        }
                    }
                    Ok(Admission::Waiting) => {
                        let _ = reply.send(Err(unavailable()));
                    }
                    Ok(Admission::Established) => {
                        let _ = reply.send(Ok(()));
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error));
                    }
                }
            }
            Command::Pull { id, reply } => {
                let result = self.active(id).and_then(|w| {
                    node.resident_sync_request(w.peer.expect("authenticated peer"), &w.sync)
                });
                let _ = reply.send(result);
            }
            Command::Begin { id, meta, reply } => {
                let result = self.active_mut(id).and_then(|w| {
                    node.resident_begin_batch(
                        w.peer.expect("authenticated peer"),
                        &mut w.sync,
                        &meta,
                    )?;
                    w.sync_goal = Some(meta.after.height);
                    w.sync_more = meta.more;
                    w.sync_complete = meta.count == 0 && !meta.more;
                    Ok(())
                });
                let _ = reply.send(result);
            }
            Command::Apply {
                id,
                batch,
                guards,
                reply,
            } => {
                let result = self.active_mut(id).and_then(|w| {
                    let changed = node.resident_accept_batch(
                        w.peer.expect("authenticated peer"),
                        &mut w.sync,
                        batch,
                        guards,
                    )?;
                    w.sync_complete = !w.sync_more;
                    Ok(changed)
                });
                let _ = reply.send(result);
            }
            Command::Serve { id, body, reply } => {
                let result = self
                    .active(id)
                    .and_then(|_| node.resident_serve_sync(&body));
                let _ = reply.send(result);
            }
        }
        Ok(())
    }
    fn active(&self, id: u64) -> Result<&Worker, runtime::Error> {
        self.workers
            .get(&id)
            .filter(|w| w.token.is_some() && w.peer.is_some() && !w.cancel.is_cancelled())
            .ok_or_else(unavailable)
    }
    fn active_mut(&mut self, id: u64) -> Result<&mut Worker, runtime::Error> {
        self.workers
            .get_mut(&id)
            .filter(|w| w.token.is_some() && w.peer.is_some() && !w.cancel.is_cancelled())
            .ok_or_else(unavailable)
    }
    fn shutdown(&mut self) -> Result<(), String> {
        self.scheduler
            .shutdown(self.now())
            .map_err(|_| "peer shutdown state mismatch")?;
        for worker in self.workers.values() {
            worker.cancel.cancel();
        }
        let deadline = Instant::now() + Duration::from_secs(6);
        while self.workers.values().any(|w| !w.join.is_finished()) {
            if Instant::now() >= deadline {
                return Err(
                    "native peer workers did not stop within the cancellation bound".into(),
                );
            }
            std::thread::sleep(POLL);
        }
        for (_, worker) in std::mem::take(&mut self.workers) {
            worker
                .join
                .join()
                .map_err(|_| "native peer worker panicked during shutdown")?;
            if let Some(token) = worker.token {
                self.scheduler
                    .closed(token, Failure::Unavailable, self.now())
                    .map_err(|_| "peer shutdown cleanup mismatch")?;
            }
        }
        // Cancelled callers can leave already queued packets behind. No worker
        // remains able to enqueue or consume a reply after the joins above.
        // Release those packet/command guards before the final offline replay.
        self.pending_authentication.clear();
        while self.rx.try_recv().is_ok() {}
        Ok(())
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        for worker in self.workers.values() {
            worker.cancel.cancel();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn connection(
    id: u64,
    socket: Option<TcpStream>,
    outgoing: Option<Hash>,
    accepted: Instant,
    local: Hash,
    identity: Arc<NativeIdentity>,
    peers: Arc<BTreeMap<Hash, Peer>>,
    role: Role,
    budget: Budget,
    tx: SyncSender<ChargedCommand>,
    cancel: Cancellation,
) -> Result<(), runtime::Error> {
    let initiator = socket.is_none();
    let (mut socket, peer) = if let Some(socket) = socket {
        (socket, None)
    } else {
        let peer = outgoing.ok_or_else(invalid)?;
        let endpoint = peers.get(&peer).ok_or_else(invalid)?.endpoint;
        let remaining = Duration::from_secs(5).saturating_sub(accepted.elapsed());
        if remaining.is_zero() {
            return Err(unavailable());
        }
        (
            TcpStream::connect_timeout(&endpoint, remaining).map_err(|_| unavailable())?,
            Some(peer),
        )
    };
    socket
        .set_read_timeout(Some(POLL))
        .and_then(|_| socket.set_write_timeout(Some(POLL)))
        .map_err(|_| unavailable())?;
    let mut route = [0; 36];
    let peer = if let Some(peer) = peer {
        route[..4].copy_from_slice(ROUTE_MAGIC);
        route[4..].copy_from_slice(&local);
        route_io(&mut socket, &mut route, true, accepted, &cancel)?;
        peer
    } else {
        route_io(&mut socket, &mut route, false, accepted, &cancel)?;
        if &route[..4] != ROUTE_MAGIC {
            return Err(invalid());
        }
        route[4..].try_into().expect("fixed route hint")
    };
    let expected = peers.get(&peer).ok_or_else(invalid)?.expected.clone();
    let admission = AdmissionContext::new_started(
        expected,
        if initiator {
            ConnectionRole::Initiator
        } else {
            ConnectionRole::Responder
        },
        cancel.clone(),
        accepted,
    );
    let mut auth = p2p::NativeTlsAuthenticator::new(identity, budget.clone());
    let mut session = p2p::establish_socket(socket, &mut auth, &admission, role, budget.clone())?;
    call(&tx, &budget, &cancel, |reply| Command::Authenticated {
        id,
        peer,
        reply,
    })?;
    let mut request = 0u64;
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        if !session.ready_for_cycle() {
            return Err(unavailable());
        }
        request = request.checked_add(1).ok_or_else(invalid)?;
        // Identical deterministic turns avoid simultaneous sync requests. Each
        // peer gets both directions every cycle; no advertised work is trusted.
        if initiator {
            pull_turn(id, request, &mut session, &budget, &tx, &cancel)?;
            serve_turn(id, &mut session, &budget, &tx, &cancel)?;
        } else {
            serve_turn(id, &mut session, &budget, &tx, &cancel)?;
            pull_turn(id, request, &mut session, &budget, &tx, &cancel)?;
        }
        // Revision-two resident turns relay verified pending transactions in
        // both directions before their inclusion in a later block.
        if initiator {
            relay_send(id, request, &mut session, &budget, &tx, &cancel)?;
            relay_receive(id, request, &mut session, &budget, &tx, &cancel)?;
        } else {
            relay_receive(id, request, &mut session, &budget, &tx, &cancel)?;
            relay_send(id, request, &mut session, &budget, &tx, &cancel)?;
        }
        let next = Instant::now() + CYCLE;
        while Instant::now() < next {
            if cancel.is_cancelled() {
                return Ok(());
            }
            std::thread::sleep(POLL);
        }
    }
}
fn relay_send<S: Read + Write>(
    id: u64,
    request: u64,
    session: &mut Session<S>,
    budget: &Budget,
    tx: &SyncSender<ChargedCommand>,
    cancel: &Cancellation,
) -> Result<(), runtime::Error> {
    let packet = call(tx, budget, cancel, |reply| Command::RelayNext { id, reply })?;
    if let Some(packet) = packet {
        session.send_control(p2p::TRANSACTION, request, &packet.body)?;
        match session.receive_relay_before(&p2p::Deadline::new(EXCHANGE))? {
            Packet::Control {
                kind: p2p::END_BATCH,
                request: r,
                body,
                ..
            } if r == request && body.is_empty() => (),
            Packet::Control {
                kind: p2p::UNAVAILABLE,
                request: r,
                body,
                ..
            } if r == request && body.is_empty() => return Ok(()),
            _ => return Err(invalid()),
        }
        call(tx, budget, cancel, |reply| Command::RelayAcknowledged {
            id,
            statement: packet.statement,
            reply,
        })?;
    } else {
        session.send_control(p2p::END_BATCH, request, &[])?;
    }
    Ok(())
}
fn relay_receive<S: Read + Write>(
    id: u64,
    request: u64,
    session: &mut Session<S>,
    budget: &Budget,
    tx: &SyncSender<ChargedCommand>,
    cancel: &Cancellation,
) -> Result<(), runtime::Error> {
    match session.receive_relay_before(&p2p::Deadline::new(EXCHANGE))? {
        Packet::Control {
            kind: p2p::END_BATCH,
            request: r,
            body,
            ..
        } if r == request && body.is_empty() => Ok(()),
        Packet::Control {
            kind: p2p::TRANSACTION,
            request: r,
            body,
            reservation,
        } if r == request => {
            let statement = match call(tx, budget, cancel, |reply| Command::RelayAdmit {
                id,
                body,
                guard: reservation,
                reply,
            }) {
                Ok(statement) => statement,
                Err(runtime::Error::Transport(
                    p2p::Error::Unavailable | p2p::Error::ResourceExhausted,
                ))
                | Err(runtime::Error::Admission(crate::admission::AdmissionError::Unavailable(
                    _,
                ))) => {
                    session.send_control(p2p::UNAVAILABLE, request, &[])?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            // Do not echo the same verified packet to its sending peer.
            call(tx, budget, cancel, |reply| Command::RelayAcknowledged {
                id,
                statement,
                reply,
            })?;
            session.send_control(p2p::END_BATCH, request, &[])?;
            Ok(())
        }
        _ => Err(invalid()),
    }
}
fn route_io(
    socket: &mut TcpStream,
    route: &mut [u8; 36],
    write: bool,
    accepted: Instant,
    cancel: &Cancellation,
) -> Result<(), runtime::Error> {
    let mut position = 0;
    while position < route.len() {
        if cancel.is_cancelled() || accepted.elapsed() >= Duration::from_secs(5) {
            return Err(unavailable());
        }
        let result = if write {
            socket.write(&route[position..])
        } else {
            socket.read(&mut route[position..])
        };
        match result {
            Ok(0) => return Err(unavailable()),
            Ok(n) => position += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(unavailable()),
        }
    }
    Ok(())
}
fn pull_turn<S: Read + Write>(
    id: u64,
    request: u64,
    session: &mut Session<S>,
    budget: &Budget,
    tx: &SyncSender<ChargedCommand>,
    cancel: &Cancellation,
) -> Result<(), runtime::Error> {
    let _command_charge = budget.reserve(COMMAND_BYTES)?;
    let body = call(tx, budget, cancel, |reply| Command::Pull { id, reply })?;
    session.send_control(p2p::GET_BLOCKS, request, &body)?;
    let deadline = p2p::Deadline::new(EXCHANGE);
    let meta = match session.receive_before(&deadline)? {
        Packet::Control {
            kind: p2p::SYNC_META,
            request: r,
            body,
            ..
        } if r == request => ReplyMeta::decode(&body)?,
        Packet::Control {
            kind: p2p::UNAVAILABLE,
            request: r,
            ..
        } if r == request => return Err(unavailable()),
        _ => return Err(invalid()),
    };
    call(tx, budget, cancel, |reply| Command::Begin {
        id,
        meta,
        reply,
    })?;
    let _vectors = budget.reserve(65536)?;
    let mut blocks = Vec::with_capacity(usize::from(meta.count));
    let mut guards = Vec::with_capacity(usize::from(meta.count));
    for _ in 0..meta.count {
        match session.receive_before(&deadline)? {
            Packet::Block {
                request: r,
                block,
                reservation,
            } if r == request => {
                blocks.push(*block);
                guards.push(reservation);
            }
            _ => return Err(invalid()),
        }
    }
    match session.receive_before(&deadline)? {
        Packet::Control {
            kind: p2p::END_BATCH,
            request: r,
            body,
            ..
        } if r == request && body.is_empty() => (),
        _ => return Err(invalid()),
    }
    call(tx, budget, cancel, |reply| Command::Apply {
        id,
        batch: Batch {
            ancestor: meta.ancestor,
            after: meta.after,
            blocks,
            more: meta.more,
        },
        guards,
        reply,
    })?;
    Ok(())
}
fn serve_turn<S: Read + Write>(
    id: u64,
    session: &mut Session<S>,
    budget: &Budget,
    tx: &SyncSender<ChargedCommand>,
    cancel: &Cancellation,
) -> Result<(), runtime::Error> {
    // The remote consensus owner can still be verifying the preceding proof
    // batch before it can create this paired request. Bound that header wait
    // by one exchange, without renewing it on partial input or extending the
    // normal control-body deadline. Admission, framing and queue caps remain
    // shared with all other workers.
    let deadline = p2p::Deadline::new(EXCHANGE);
    let Packet::Control {
        kind: p2p::GET_BLOCKS,
        request,
        body,
        reservation,
    } = session.receive_sync_request_before(&deadline)?
    else {
        return Err(invalid());
    };
    let _request_guard = reservation;
    let owned = call(tx, budget, cancel, |reply| Command::Serve {
        id,
        body,
        reply,
    })?;
    let meta = ReplyMeta {
        ancestor: owned.batch.ancestor,
        after: owned.batch.after,
        count: owned.batch.blocks.len() as u16,
        more: owned.batch.more,
    };
    session.send_control(p2p::SYNC_META, request, &meta.encode())?;
    for block in &owned.batch.blocks {
        session.send_reserved_block(request, block, &owned.reservation)?;
    }
    session.send_control(p2p::END_BATCH, request, &[])?;
    Ok(())
}

enum ProofInput {
    Padding,
    Block {
        inputs: crate::runtime::resident::ProductionInputs,
        timestamp: u64,
        settings: Box<producer::MiningSettings>,
    },
}
struct BlockProofOutput {
    generation_ms: u64,
    permit: runtime::ProductionPermit,
    produced: producer::ProducedBlock,
    state: State,
}
enum ProofOutput {
    Padding(Box<crate::pool::Padding>),
    Block(Box<BlockProofOutput>),
}
/// Exactly one owned prover job exists at a time. The sole consensus owner
/// never performs transaction/settlement proving or waits for a live proof.
/// Synchronous prover calls are cooperatively cancelled between operations;
/// their snapshot and result reservations remain charged until the worker ends.
struct ProofTask {
    cancel: Arc<AtomicBool>,
    fingerprint: Hash,
    join: JoinHandle<Result<(NativeProver, Option<ProofOutput>), String>>,
    reservation: Reservation,
}
impl ProofTask {
    fn start(
        node: &mut Node<NativeVerifier>,
        prover: Option<NativeProver>,
        block: bool,
        directory: &Path,
        control: &Control,
        producer_budget: &Budget,
        reservation: Reservation,
    ) -> Result<Self, String> {
        // Account for the original before allocating a cloned state. The
        // fixed allowance covers the owned snapshot and a 64-slot candidate;
        // it is a logical ownership limit, not a prover RSS measurement.
        crate::chain::check_state_budget(
            node.state(),
            96 * 1024 * 1024,
            crate::chain::CandidatePolicy {
                max_bytes: PRODUCER_JOB_BYTES,
                ..Default::default()
            },
        )
        .map_err(|_| "producer state snapshot exceeds allowance")?;
        if !reservation.covers(producer_budget, PRODUCER_JOB_BYTES) {
            return Err("producer work reservation mismatch".into());
        }
        let input = if block {
            let settings = crate::mining::load(directory, node.state().config.network)?;
            let timestamp = (control.checked_wall()? / 1000).max(
                node.state()
                    .median_time_past()
                    .checked_add(1)
                    .ok_or("timestamp exhausted")?,
            );
            let inputs = node
                .resident_production_inputs(MIN_READY)
                .map_err(|_| "native producer inputs unavailable")?;
            ProofInput::Block {
                inputs,
                timestamp,
                settings: Box::new(settings),
            }
        } else {
            ProofInput::Padding
        };
        let state = node.state().clone();
        let fingerprint = state.fingerprint();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancelled = cancel.clone();
        let join = std::thread::Builder::new()
            .name("native-prover".into())
            .spawn(move || {
                let prover = match prover {
                    Some(prover) => prover,
                    None => NativeProver::new()?,
                };
                if cancelled.load(Ordering::SeqCst) {
                    return Ok((prover, None));
                }
                let output = match input {
                    ProofInput::Padding => {
                        ProofOutput::Padding(Box::new(producer::prepare_padding(&state, &prover)?))
                    }
                    ProofInput::Block {
                        inputs,
                        timestamp,
                        settings,
                    } => {
                        let started = Instant::now();
                        let mut produced = producer::assemble(
                            &state,
                            &prover,
                            inputs.positions,
                            timestamp,
                            &settings,
                        )?;
                        produced.block.issuances = inputs.issuances;
                        produced.block.validate_shape()?;
                        let generation_ms = elapsed_ms(started, Instant::now());
                        ProofOutput::Block(Box::new(BlockProofOutput {
                            generation_ms,
                            permit: inputs.permit,
                            produced,
                            state,
                        }))
                    }
                };
                if cancelled.load(Ordering::SeqCst) {
                    // Includes erasure of any stale private reward receipt.
                    drop(output);
                    Ok((prover, None))
                } else {
                    Ok((prover, Some(output)))
                }
            })
            .map_err(|_| "native producer thread unavailable")?;
        Ok(Self {
            cancel,
            fingerprint,
            join,
            reservation,
        })
    }
}
struct Mining {
    cancel: Arc<AtomicBool>,
    fingerprint: Hash,
    join: JoinHandle<Result<Option<PreparedBlock>, String>>,
    _reservation: Reservation,
}
impl Mining {
    fn start(
        mut prepared: PreparedBlock,
        state: State,
        control: Arc<Control>,
        reservation: Reservation,
    ) -> Result<Self, String> {
        let fingerprint = state.fingerprint();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancelled = cancel.clone();
        let join = std::thread::Builder::new()
            .name("native-pow".into())
            .spawn(move || {
                let done = AtomicBool::new(false);
                if super::mine_guarded(
                    prepared.block_mut(),
                    &state,
                    &control,
                    &done,
                    Some(&cancelled),
                )? {
                    Ok(Some(prepared))
                } else {
                    Ok(None)
                }
            })
            .map_err(|_| "native work thread unavailable")?;
        Ok(Self {
            cancel,
            fingerprint,
            join,
            _reservation: reservation,
        })
    }
}
pub(super) fn continuous(
    directory: &Path,
    control: &Arc<Control>,
    config: Configuration,
) -> Result<(), String> {
    let mining = config.mining;
    let chain = local::load(directory)?;
    let verifier = NativeVerifier::new()?;
    let mut store = Store::open_existing(directory.join("chain.redb"), chain.clone(), &verifier)?;
    super::configure_storage_startup(&mut store)?;
    store.require_local_reward_index()?;
    store.verify_local_rewards()?;
    let identity = Arc::new(
        NativeIdentity::load(directory, &p2p::Binding::new(&chain))
            .map_err(|_| "persistent native identity unavailable")?,
    );
    let mut node = Node::new(store, verifier);
    let mut driver = Driver::new(identity, config, node.transport_budget())?;
    #[cfg(all(feature = "wallet-light-gateway", unix))]
    let mut wallet_gateway = crate::wallet_gateway::Gateway::from_environment()?;
    // Independent local-job ownership allowance: at most one prover and one
    // PoW task, each retaining a bounded snapshot/result. Sharing these 512 MiB
    // with peers would starve maximum-block locator/synchronization admission.
    // Both categories still require process-level RSS and proof working-space
    // limits; neither logical budget accounts for the allocator or all prover
    // temporaries.
    let producer_budget = Budget::new(PRODUCER_TOTAL_BYTES);
    let mut prover: Option<NativeProver> = None;
    let mut proof: Option<ProofTask> = None;
    let mut work: Option<Mining> = None;
    let mut last_private_view = Instant::now();
    let mut last_storage_maintenance: Option<Instant> = None;
    let mut storage_maintenance_interval = Duration::from_secs(60);
    let mut reward_fingerprint = None;
    let mut reward_view = Value::Null;
    control.state(node.state())?;
    control.phase("networking")?;
    let result: Result<(), String> = (|| {
        while !control.stop()? {
            if last_storage_maintenance
                .is_none_or(|last| last.elapsed() >= storage_maintenance_interval)
            {
                let now = control.checked_wall()? / 1000;
                let expired = node.maintain_storage(now, true)?;
                storage_maintenance_interval =
                    Duration::from_secs(if expired > 0 { 5 } else { 60 });
                control.phase("networking")?;
                control
                    .status
                    .lock()
                    .map_err(|_| "storage status unavailable")?
                    .storage_metrics = node.store().storage_metrics().ok();
                last_storage_maintenance = Some(Instant::now());
            }
            driver.poll()?;
            #[cfg(all(feature = "wallet-light-gateway", unix))]
            if let Some(gateway) = &mut wallet_gateway {
                gateway.poll(&mut node);
            }
            for _ in 0..COMMAND_SLOTS {
                match driver.rx.try_recv() {
                    Ok(command) => {
                        driver.handle(&mut node, command)?;
                        control.state(node.state())?;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(_) => return Err("resident owner command channel closed".into()),
                }
            }
            let mining_ready = !control.private_miner_view || driver.has_synced_peer();
            if let Some(current) = &work {
                if !mining_ready || current.fingerprint != node.state().fingerprint() {
                    current.cancel.store(true, Ordering::SeqCst);
                }
                if current.join.is_finished() {
                    let completed = work.take().expect("selected work");
                    let stale = !mining_ready
                        || completed.cancel.load(Ordering::SeqCst)
                        || completed.fingerprint != node.state().fingerprint();
                    let candidate = completed
                        .join
                        .join()
                        .map_err(|_| "native work thread panicked")??;
                    if !stale
                        && let Some(prepared) = candidate
                        && node.resident_prepared_is_current(&prepared)
                    {
                        node.commit_produced(prepared)
                            .map_err(|_| "native reward commit failed")?;
                        control.state(node.state())?;
                        control.event("block_accepted")?;
                    }
                }
            }
            {
                let mut status = control
                    .status
                    .lock()
                    .map_err(|_| "service status lock poisoned")?;
                status.network_status = Some(driver.status(mining));
                status.progress()?;
            }
            if let Some(current) = &proof {
                if !mining_ready || current.fingerprint != node.state().fingerprint() {
                    current.cancel.store(true, Ordering::SeqCst);
                }
                if current.join.is_finished() {
                    let completed = proof.take().expect("selected proof work");
                    let stale = completed.fingerprint != node.state().fingerprint()
                        || completed.cancel.load(Ordering::SeqCst);
                    let (returned_prover, output) = completed
                        .join
                        .join()
                        .map_err(|_| "native producer thread panicked")??;
                    prover = Some(returned_prover);
                    if !stale && let Some(output) = output {
                        match output {
                            ProofOutput::Padding(value) => node
                                .resident_insert_padding(*value)
                                .map_err(|_| "native private queue verification failed")?,
                            ProofOutput::Block(output) => {
                                let BlockProofOutput {
                                    generation_ms,
                                    permit,
                                    produced,
                                    state,
                                } = *output;
                                if !node.resident_permit_is_current(&permit) {
                                    // A canonical fingerprint can recur after
                                    // the authorization generation retired.
                                    // Discard local work before binding/writing.
                                    continue;
                                }
                                control
                                    .status
                                    .lock()
                                    .map_err(|_| "service status lock poisoned")?
                                    .template_generation_ms = Some(generation_ms);
                                let prepared = node
                                    .bind_produced(permit, produced)
                                    .map_err(|_| "native producer result became stale")?;
                                work = Some(Mining::start(
                                    prepared,
                                    state,
                                    control.clone(),
                                    completed.reservation,
                                )?);
                            }
                        }
                    }
                }
            }
            if mining && mining_ready && proof.is_none() {
                let block = work.is_none() && node.resident_padding_ready();
                if block || node.resident_padding_can_grow() {
                    // Local-job pressure is backpressure. It must
                    // neither kill the owner nor consume the resident prover.
                    match producer_budget.reserve(PRODUCER_JOB_BYTES) {
                        Ok(reservation) => {
                            proof = Some(ProofTask::start(
                                &mut node,
                                prover.take(),
                                block,
                                directory,
                                control,
                                &producer_budget,
                                reservation,
                            )?);
                        }
                        Err(p2p::Error::ResourceExhausted) => (),
                        Err(_) => return Err("producer ownership budget unavailable".into()),
                    }
                }
            }
            if control.private_miner_view && last_private_view.elapsed() >= Duration::from_secs(1) {
                let fingerprint = node.state().fingerprint();
                if reward_fingerprint != Some(fingerprint) {
                    reward_view = node.store().miner_reward_view()?;
                    reward_fingerprint = Some(fingerprint);
                }
                let connected = driver.scheduler.status().established;
                let phase = if connected == 0 {
                    "waiting_for_authenticated_peers"
                } else if !driver.has_synced_peer() {
                    "synchronizing"
                } else if work.is_some() {
                    "pow_search"
                } else {
                    "template_preparation"
                };
                let status = control
                    .status
                    .lock()
                    .map_err(|_| "private miner status unavailable")?;
                let view = json!({"schema":1,"run_id":control.identity.run_id,"updated_unix_ms":wall_ms()?,
                    "height":node.state().height,"batch_goal_unverified":driver.sync_goal(),
                    "phase":phase,"authenticated_peers":connected,"inbound_listener":driver.listener.is_some(),
                    "pow_attempts":status.pow_attempts,"elapsed_monotonic_ms":elapsed_ms(status.started,Instant::now()),
                    "rewards":reward_view});
                drop(status);
                atomic_json(&directory.join("miner-private-status.json"), &view)?;
                last_private_view = Instant::now();
            }
            std::thread::sleep(POLL);
        }
        Ok(())
    })();
    // Cancel networking first. Proof APIs expose no safe preemption inside a
    // synchronous call, so stop waits for that one owned worker without allowing
    // another job, new handshake or stale result to become a durable reward.
    if let Some(current) = &proof {
        current.cancel.store(true, Ordering::SeqCst);
    }
    if let Some(current) = &work {
        current.cancel.store(true, Ordering::SeqCst);
    }
    let network_cleanup = driver.shutdown();
    let proof_cleanup = match proof {
        Some(proof) => proof
            .join
            .join()
            .map_err(|_| "native producer shutdown panicked".to_owned())
            .and_then(|result| result.map(|_| ())),
        None => Ok(()),
    };
    let work_cleanup = match work {
        Some(work) => work
            .join
            .join()
            .map_err(|_| "native work shutdown panicked".to_owned())
            .and_then(|result| result.map(|_| ())),
        None => Ok(()),
    };
    // Join every owned worker even when an earlier cleanup fails. Preserve the
    // operation error before reporting secondary shutdown errors.
    result?;
    network_cleanup?;
    proof_cleanup?;
    work_cleanup?;
    control.phase("stopping")?;
    let expected = (
        node.state().height,
        node.state().tip,
        node.state().fingerprint(),
        node.state().cumulative_work,
    );
    drop(node);
    let replayed =
        Store::open_existing(directory.join("chain.redb"), chain, &NativeVerifier::new()?)?;
    replayed.require_local_reward_index()?;
    replayed.verify_local_rewards()?;
    let actual = (
        replayed.state().height,
        replayed.state().tip,
        replayed.state().fingerprint(),
        replayed.state().cumulative_work,
    );
    if expected != actual {
        return Err("resident final replay changed accepted state".into());
    }
    control.state(replayed.state())?;
    if control.private_miner_view {
        let status = control
            .status
            .lock()
            .map_err(|_| "private final miner status unavailable")?;
        let view = json!({"schema":1,"run_id":control.identity.run_id,"updated_unix_ms":wall_ms()?,
            "height":replayed.state().height,"batch_goal_unverified":null,"phase":"stopped",
            "authenticated_peers":0,"inbound_listener":false,"pow_attempts":status.pow_attempts,
            "elapsed_monotonic_ms":elapsed_ms(status.started,Instant::now()),"rewards":replayed.miner_reward_view()?});
        drop(status);
        atomic_json(&directory.join("miner-private-status.json"), &view)?;
    }
    control.phase("stopped")?;
    control.event("service_stopped")
}

#[cfg(test)]
mod genuine;
#[cfg(test)]
mod tests;

#[cfg(feature = "peer-qualification")]
pub mod qualification;
