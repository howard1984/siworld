//! The running testnet node: the node core driven by the network, a miner
//! thread, one background candidate task, and a local RPC port.
//!
//! One task owns the [`Node`] and handles, one at a time, peer messages,
//! blocks found by the miner, RPC calls, and a periodic tick. The miner
//! task builds from an owned snapshot while the event loop remains available.
//! Tip, pending-work and mining-permission changes invalidate the candidate;
//! stale proof and nonce-search results are discarded by generation and parent.
//! Ticks refresh ready headers without restarting an in-flight proof. See
//! docs/architecture.md for cancellation and responsiveness limits.
//!
//! A peer that sends an invalid block or message, or keeps sending invalid
//! transactions, is disconnected and banned (see [`crate::gate`]). Each
//! connection carries at most [`MAX_STREAMS`] requests at a time, and a node
//! asks each peer for one batch of blocks at a time.
//!
//! A node with configured peers mines only once it has synced with a peer,
//! and stops while it has none. A stale tip is far behind ASERT's schedule,
//! so blocks on it cost almost nothing, and a node mining alone could bury
//! its tip more than `MAX_REORG_DEPTH` blocks deep in its own branch before
//! it hears of the network's, and could never follow the network after that.
//!
//! Logs name blocks and counts only: never peer addresses or identities, and
//! nothing about transactions (CONTRIBUTING.md privacy invariants).

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use libp2p::request_response::{
    self, InboundFailure, Message, OutboundFailure, OutboundRequestId, ProtocolSupport,
};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{ConnectionId, NetworkBehaviour, SwarmEvent};
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, Swarm};
use serde_json::{json, Value};
use siworld_consensus::{beyond_future_limit, median_time_past, mine_some, BlockError, TipChange};
use siworld_core::{Block, DevAccount, Header};
use siworld_crypto::domain_hash;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, Semaphore};
use zeroize::{Zeroize, Zeroizing};

use crate::rpc_auth::{Permission, RpcAuth, RpcToken};

use crate::address::{encode_address, parse_address};
use crate::amount::{format_sip, parse_sip};
use crate::gate::{Gate, INVALID_TX_SCORE};
use crate::hex;
use crate::mempool::MempoolError;
use crate::node::{AcceptError, Node, TemplateError};
use crate::p2p::{self, Codec, Request, Response, MAX_BATCH, MAX_RESPONSE};
use crate::payments::{PaymentError, PaymentId, PaymentReceipt};
use crate::wallet::PayError;
use crate::wire::{decode_tx, encode_tx};
use crate::worker_transport::{WorkerConfig, WorkerListener};

pub struct Config {
    /// Addresses to accept peers on, e.g. `/ip4/0.0.0.0/tcp/30333`.
    pub listen: Vec<Multiaddr>,
    /// Peers to dial and redial while disconnected, e.g.
    /// `/ip4/203.0.113.7/tcp/30333`.
    pub peers: Vec<Multiaddr>,
    /// Authenticated JSON-lines RPC, restricted to loopback.
    pub rpc: Option<RpcConfig>,
    pub mine: bool,
    /// Optional authenticated local worker control listener. Disabled by default.
    pub worker: Option<WorkerConfig>,
}

pub struct RpcConfig {
    pub address: SocketAddr,
    pub auth: RpcAuth,
}

const RPC_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RPC_CONNECTIONS: usize = 32;

const TICK: Duration = Duration::from_secs(10);
/// Most requests in flight on one connection, inbound and outbound together.
pub const MAX_STREAMS: usize = 8;
/// Longest RPC request line.
pub const MAX_RPC_LINE: usize = 64 << 10;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    /// First, so that it refuses a connection before the others see it.
    gate: Gate,
    messages: request_response::Behaviour<Codec>,
}

type Event = request_response::Event<Request, Response>;
struct ErasingRequest(Value);
impl Drop for ErasingRequest {
    fn drop(&mut self) {
        crate::rpc_auth::erase_json(&mut self.0);
    }
}
type RpcCall = (ErasingRequest, Permission, oneshot::Sender<Value>);

struct RpcServer(tokio::task::JoinHandle<()>);
impl Drop for RpcServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Refuses an RPC address other machines could reach.
pub fn check_rpc_address(address: SocketAddr) -> Result<SocketAddr, String> {
    if address.ip().is_loopback() {
        Ok(address)
    } else {
        Err(format!(
            "the RPC address {address} is not a loopback address; RPC requires a protected \
             transport; reach it remotely through an SSH tunnel"
        ))
    }
}

/// Runs the node until `shutdown` completes or the block store fails.
pub async fn run(
    node: Node,
    config: Config,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Box<dyn Error>> {
    run_inner(node, config, shutdown, None).await
}

/// Runs the node using an already-bound RPC listener.
///
/// This is primarily useful to tests that need to reserve an ephemeral port
/// without a probe-then-bind race. Production callers should use [`run`],
/// which binds the configured address itself.
pub async fn run_with_rpc_listener(
    node: Node,
    config: Config,
    rpc_listener: std::net::TcpListener,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Box<dyn Error>> {
    run_inner(node, config, shutdown, Some(rpc_listener)).await
}

async fn run_inner(
    node: Node,
    config: Config,
    shutdown: impl Future<Output = ()>,
    rpc_listener: Option<std::net::TcpListener>,
) -> Result<(), Box<dyn Error>> {
    if config
        .worker
        .as_ref()
        .is_some_and(|worker| worker.expected.container_size != node.chain.params.container_size)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "worker container size differs from genesis",
        )
        .into());
    }
    if let Some(rpc) = &config.rpc {
        check_rpc_address(rpc.address)?;
    }
    let behaviour = Behaviour {
        gate: Gate::default(),
        messages: request_response::Behaviour::with_codec(
            Codec::default(),
            [(p2p::protocol(&node.genesis.id), ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(60))
                .with_max_concurrent_streams(MAX_STREAMS),
        ),
    };
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_dns()?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(3600)))
        .build();
    for address in &config.listen {
        swarm.listen_on(address.clone())?;
    }

    let (found_tx, mut found_rx) = mpsc::channel(1);
    let (rpc_tx, mut rpc_rx) = mpsc::channel::<RpcCall>(16);
    let _rpc_server = if let Some(rpc) = config.rpc {
        let listener = if let Some(listener) = rpc_listener {
            listener.set_nonblocking(true)?;
            let bound = listener.local_addr()?;
            check_rpc_address(bound)?;
            TcpListener::from_std(listener)?
        } else {
            TcpListener::bind(rpc.address).await?
        };
        eprintln!("rpc on {}", listener.local_addr()?);
        Some(RpcServer(tokio::spawn(serve_rpc(
            listener,
            rpc_tx,
            Arc::new(rpc.auth),
        ))))
    } else {
        None
    };

    // The listener is independent of proof job admission and closes on shutdown.
    let worker_server = if let Some(worker) = config.worker {
        let listener = WorkerListener::bind(worker).await?;
        Some(RpcServer(tokio::spawn(listener.serve())))
    } else {
        None
    };

    let miner = config
        .mine
        .then(|| Miner::spawn(node.chain.params.pow_iterations, found_tx))
        .transpose()?;
    let (prepared, mut prepared_rx) = mpsc::channel(1);
    let mut service = Service {
        node,
        swarm,
        peers: HashSet::new(),
        statics: config.peers.clone(),
        connected_statics: HashMap::new(),
        dialing: HashMap::new(),
        syncing: HashMap::new(),
        synced: config.peers.is_empty(),
        miner,
        generation: 0,
        proving: None,
        needs_template: false,
        ready: None,
        prepared,
        fatal: None,
    };
    eprintln!(
        "network {} at height {}",
        service.node.genesis.network,
        service.node.height()
    );
    service.redial();
    service.refresh_template();

    let mut tick = tokio::time::interval(TICK);
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            () = &mut shutdown => break Ok(()),
            event = service.swarm.select_next_some() => service.on_swarm(event),
            Some(block) = found_rx.recv() => service.on_mined(block),
            Some((generation, header)) = prepared_rx.recv() => service.on_prepared(generation, header),
            result = completed_template(&mut service.proving) => service.on_proved(result),
            Some((request, permission, reply)) = rpc_rx.recv() => {
                let result = service.on_rpc(&request.0, permission);
                let _ = reply.send(result);
            }
            _ = tick.tick() => service.on_tick(),
            () = wallet_expiry(service.node.wallet_unlock_deadline()) => service.node.expire_wallet(Instant::now()),
            () = wallet_expiry(service.node.fund_unlock_deadline()) => service.node.expire_fund(Instant::now()),
        }
        if let Some(e) = service.fatal.take() {
            break Err(e.into());
        }
    };
    // Close client tasks before waiting for the non-preemptible proof kernel.
    drop(_rpc_server);
    drop(worker_server);
    drop(rpc_rx);
    drop(prepared_rx);
    service.node.lock_fund();
    service.node.lock_wallet();
    if let Some(task) = &service.proving {
        task.cancelled.store(true, Ordering::Release);
    }
    if let Some(miner) = service.miner.take() {
        miner.stop();
    }
    if let Some(task) = service.proving.take() {
        let _ = task.handle.await;
    }
    result
}

async fn wallet_expiry(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at.into()).await,
        None => std::future::pending().await,
    }
}

type TemplateResult = Result<Option<Result<Block, TemplateError>>, tokio::task::JoinError>;

struct CandidateTask {
    generation: u64,
    cancelled: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<Option<Result<Block, TemplateError>>>,
}

async fn completed_template(task: &mut Option<CandidateTask>) -> TemplateResult {
    match task {
        Some(task) => (&mut task.handle).await,
        None => std::future::pending().await,
    }
}

struct Service {
    node: Node,
    swarm: Swarm<Behaviour>,
    /// Connected peers.
    peers: HashSet<PeerId>,
    /// Configured peer addresses.
    statics: Vec<Multiaddr>,
    /// Configured addresses with a connection, and the peer behind each.
    connected_statics: HashMap<Multiaddr, PeerId>,
    /// Dials in progress to configured addresses.
    dialing: HashMap<ConnectionId, Multiaddr>,
    /// The block request in flight to each peer.
    syncing: HashMap<PeerId, OutboundRequestId>,
    /// Whether a peer has had no blocks after our tip since we last had no
    /// peers; always true without configured peers.
    synced: bool,
    miner: Option<Miner>,
    generation: u64,
    proving: Option<CandidateTask>,
    /// A coalesced request, never a queued snapshot.
    needs_template: bool,
    ready: Option<Candidate>,
    prepared: mpsc::Sender<(u64, Header)>,
    /// Set when the node must stop.
    fatal: Option<String>,
}

impl Service {
    fn on_swarm(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Messages(event)) => self.on_message(event),
            SwarmEvent::Behaviour(BehaviourEvent::Gate(never)) => match never {},
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                ..
            } => {
                if let Some(address) = self.dialing.remove(&connection_id) {
                    self.connected_statics.insert(address, peer_id);
                }
                if self.peers.insert(peer_id) {
                    eprintln!("peers: {}", self.peers.len());
                    self.request_blocks(peer_id);
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                ..
            } => {
                self.peers.remove(&peer_id);
                self.syncing.remove(&peer_id);
                self.connected_statics.retain(|_, p| *p != peer_id);
                eprintln!("peers: {}", self.peers.len());
                if self.peers.is_empty() && !self.statics.is_empty() {
                    self.synced = false;
                    self.refresh_template();
                }
            }
            SwarmEvent::OutgoingConnectionError { connection_id, .. } => {
                if self.dialing.remove(&connection_id).is_some() {
                    eprintln!("a configured peer is unreachable; retrying");
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => eprintln!("listening on {address}"),
            _ => {}
        }
    }

    fn on_message(&mut self, event: Event) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                Message::Request {
                    request, channel, ..
                } => {
                    let response = self.on_request(peer, request);
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .messages
                        .send_response(channel, response);
                }
                Message::Response {
                    request_id,
                    response,
                } => self.on_response(peer, request_id, response),
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                if self.syncing.get(&peer) == Some(&request_id) {
                    self.syncing.remove(&peer);
                }
                if let OutboundFailure::Io(e) = error {
                    self.on_io_error(peer, &e);
                }
            }
            request_response::Event::InboundFailure {
                peer,
                error: InboundFailure::Io(e),
                ..
            } => self.on_io_error(peer, &e),
            _ => {}
        }
    }

    /// Bans a peer whose message did not decode or exceeded its limit.
    fn on_io_error(&mut self, peer: PeerId, error: &io::Error) {
        if error.kind() == io::ErrorKind::InvalidData {
            self.ban(peer);
        }
    }

    fn ban(&mut self, peer: PeerId) {
        self.swarm.behaviour_mut().gate.ban(peer, Instant::now());
        self.banned(peer);
    }

    fn banned(&mut self, peer: PeerId) {
        eprintln!("banned a misbehaving peer");
        let _ = self.swarm.disconnect_peer_id(peer);
    }

    fn on_request(&mut self, peer: PeerId, request: Request) -> Response {
        match request {
            Request::Block(bytes) => {
                match Block::decode(&bytes) {
                    Ok(block) => {
                        if self.receive_block(Some(peer), &block, Some(bytes)) == Received::Orphan {
                            self.request_blocks(peer);
                        }
                    }
                    Err(_) => self.ban(peer),
                }
                Response::Ack
            }
            Request::Tx(bytes) => {
                // The peer is identified to the mempool by an opaque hash so
                // that its per-peer limit applies without its id being kept.
                let source = domain_hash("siworld testnet mempool source", &[&peer.to_bytes()]);
                let result = decode_tx(&bytes)
                    .map_err(|_| MempoolError::NonCanonical)
                    .and_then(|tx| self.node.submit_tx(tx, Some(source)));
                match result {
                    Ok(()) => {
                        self.broadcast(&Request::Tx(bytes), Some(peer));
                        self.refresh_template();
                    }
                    Err(e) if is_invalid_tx(&e) => {
                        let gate = &mut self.swarm.behaviour_mut().gate;
                        if gate.penalize(peer, INVALID_TX_SCORE, Instant::now()) {
                            self.banned(peer);
                        }
                    }
                    Err(_) => {}
                }
                Response::Ack
            }
            Request::GetBlocks(locator) => {
                let mut blocks = Vec::new();
                let mut size = 5usize;
                for block in self.node.chain.blocks_after(&locator, MAX_BATCH) {
                    let bytes = block.encode();
                    size += 4 + bytes.len();
                    if size > MAX_RESPONSE && !blocks.is_empty() {
                        break;
                    }
                    blocks.push(bytes);
                }
                Response::Blocks(blocks)
            }
        }
    }

    fn on_response(&mut self, peer: PeerId, request: OutboundRequestId, response: Response) {
        let solicited = self.syncing.get(&peer) == Some(&request);
        let blocks = match response {
            Response::Blocks(blocks) if solicited => blocks,
            Response::Blocks(_) => return self.ban(peer),
            Response::Ack => return,
        };
        self.syncing.remove(&peer);
        let full = blocks.len() == MAX_BATCH;
        let mut progressed = false;
        for bytes in blocks {
            let Ok(block) = Block::decode(&bytes) else {
                return self.ban(peer);
            };
            match self.receive_block(Some(peer), &block, None) {
                Received::New => progressed = true,
                Received::Old => {}
                Received::Orphan | Received::Rejected => return,
            }
        }
        if full && progressed {
            self.request_blocks(peer);
        } else if !full && !self.synced {
            self.synced = true;
            self.refresh_template();
        }
    }

    /// Whether the miner may work: see the module documentation.
    fn may_mine(&self) -> bool {
        self.statics.is_empty() || (self.synced && !self.peers.is_empty())
    }

    /// Accepts a block from `from` (the miner if `None`) and announces it to
    /// the other peers when `relay` holds its bytes. Bans `from` if the block
    /// is invalid.
    fn receive_block(
        &mut self,
        from: Option<PeerId>,
        block: &Block,
        relay: Option<Vec<u8>>,
    ) -> Received {
        if beyond_future_limit(block.header.timestamp, now()) {
            return Received::Rejected;
        }
        match self.node.accept(block) {
            Ok(change) => {
                match change {
                    TipChange::None => {}
                    TipChange::Extended => {
                        eprintln!("block {} {}", block.header.height, hex(&self.node.tip()))
                    }
                    TipChange::Reorg { fork } => eprintln!(
                        "block {} {} (reorganized above {fork})",
                        block.header.height,
                        hex(&self.node.tip())
                    ),
                }
                if let Some(bytes) = relay {
                    self.broadcast(&Request::Block(bytes), from);
                }
                if change != TipChange::None {
                    self.refresh_template();
                }
                Received::New
            }
            Err(AcceptError::Block(BlockError::BadParent)) => Received::Orphan,
            Err(AcceptError::Block(BlockError::AlreadyKnown)) => Received::Old,
            // Not the sender's fault: a new miner mines on genesis until it
            // has synced.
            Err(AcceptError::Block(BlockError::ReorgTooDeep)) => Received::Rejected,
            Err(AcceptError::Block(_)) => {
                if let Some(peer) = from {
                    self.ban(peer);
                }
                Received::Rejected
            }
            Err(e @ AcceptError::Store(_)) => {
                self.fatal = Some(e.to_string());
                Received::Rejected
            }
        }
    }

    fn on_mined(&mut self, job: Job) {
        if job.generation == self.generation
            && self.may_mine()
            && job.header.parent == self.node.tip()
        {
            if let Some(candidate) = &mut self.ready {
                let mut identity = job.header;
                identity.timestamp = candidate.original.timestamp;
                identity.nonce = candidate.original.nonce;
                if candidate.generation == job.generation && identity == candidate.original {
                    candidate.mined = Some(job.header);
                    if let Some(miner) = &self.miner {
                        miner.set(None);
                    }
                    self.publish_ready();
                }
            }
        }
    }

    fn on_prepared(&mut self, generation: u64, header: Header) {
        if generation != self.generation
            || !self.may_mine()
            || header.parent != self.node.tip()
            || self.ready.is_some()
        {
            return;
        }
        self.ready = Some(Candidate {
            generation,
            original: header,
            block: None,
            mined: None,
        });
        self.refresh_timestamp();
    }

    fn publish_ready(&mut self) {
        if !self
            .ready
            .as_ref()
            .is_some_and(|c| c.block.is_some() && c.mined.is_some())
        {
            return;
        }
        let candidate = self.ready.take().expect("ready candidate");
        if candidate.generation != self.generation || !self.may_mine() {
            return;
        }
        let mut block = candidate.block.expect("checked proof");
        block.header = candidate.mined.expect("sealed header");
        if block.header.parent == self.node.tip() {
            let bytes = block.encode();
            self.receive_block(None, &block, Some(bytes));
        }
    }

    fn on_tick(&mut self) {
        self.swarm.behaviour_mut().gate.decay(Instant::now());
        self.redial();
        let peers: Vec<PeerId> = self.peers.iter().copied().collect();
        for peer in peers {
            self.request_blocks(peer);
        }
        self.refresh_timestamp();
        self.start_template();
    }

    fn redial(&mut self) {
        for address in &self.statics {
            if self.connected_statics.contains_key(address)
                || self.dialing.values().any(|a| a == address)
            {
                continue;
            }
            let opts = DialOpts::unknown_peer_id()
                .address(address.clone())
                // A fresh local port: reusing the listening port fails while
                // the previous run's connection is in TIME_WAIT.
                .allocate_new_port()
                .build();
            let id = opts.connection_id();
            if self.swarm.dial(opts).is_ok() {
                self.dialing.insert(id, address.clone());
            }
        }
    }

    /// Asks `peer` for the blocks after our tip, unless a request is in
    /// flight.
    fn request_blocks(&mut self, peer: PeerId) {
        if self.syncing.contains_key(&peer) {
            return;
        }
        let locator = self.node.chain.locator();
        let id = self
            .swarm
            .behaviour_mut()
            .messages
            .send_request(&peer, Request::GetBlocks(locator));
        self.syncing.insert(peer, id);
    }

    fn broadcast(&mut self, request: &Request, except: Option<PeerId>) {
        for peer in &self.peers {
            if Some(*peer) != except {
                self.swarm
                    .behaviour_mut()
                    .messages
                    .send_request(peer, request.clone());
            }
        }
    }

    fn refresh_template(&mut self) {
        if self.miner.is_none() {
            return;
        }
        if let Some(task) = &self.proving {
            task.cancelled.store(true, Ordering::Release);
        }
        self.ready = None;
        self.miner.as_ref().expect("checked above").set(None);
        let Some(next) = self.generation.checked_add(1) else {
            self.needs_template = false;
            self.fatal = Some("candidate generation exhausted".into());
            return;
        };
        self.generation = next;
        self.needs_template = self.may_mine();
        self.start_template();
    }

    fn start_template(&mut self) {
        if !self.needs_template || self.proving.is_some() || !self.may_mine() {
            return;
        }
        self.needs_template = false;
        let work = self.node.template_work(now());
        let cancelled = Arc::new(AtomicBool::new(false));
        let check = cancelled.clone();
        let notify_check = cancelled.clone();
        let prepared = self.prepared.clone();
        let generation = self.generation;
        self.proving = Some(CandidateTask {
            generation: self.generation,
            cancelled,
            handle: tokio::task::spawn_blocking(move || {
                if check.load(Ordering::Acquire) {
                    return None;
                }
                let result = work.build_with_header(move |header| {
                    if !notify_check.load(Ordering::Acquire) {
                        let _ = prepared.blocking_send((generation, header));
                    }
                });
                (!check.load(Ordering::Acquire)).then_some(result)
            }),
        });
    }

    fn on_proved(&mut self, result: TemplateResult) {
        let task = self.proving.take().expect("completed task");
        let Ok(result) = result else {
            self.fatal = Some("candidate worker panicked".into());
            return;
        };
        if task.generation != self.generation || !self.may_mine() {
            self.start_template();
            return;
        }
        match result {
            Some(Ok(block)) if block.header.parent == self.node.tip() => {
                // A fast proof can complete before the event loop consumes its
                // prepared-header message. Do not reset an existing PoW result.
                self.on_prepared(task.generation, block.header);
                if let Some(candidate) = &mut self.ready {
                    if candidate.original != block.header {
                        self.fatal = Some("candidate header/proof mismatch".into());
                        return;
                    }
                    candidate.block = Some(block);
                }
                self.publish_ready();
            }
            _ => {
                // No live queue mutation and no immediate failure retry loop.
                eprintln!("cannot build a block template; retrying on a later tick");
                self.ready = None;
                if let Some(miner) = &self.miner {
                    miner.set(None);
                }
                let Some(next) = self.generation.checked_add(1) else {
                    self.fatal = Some("candidate generation exhausted".into());
                    return;
                };
                self.generation = next;
                self.needs_template = true;
            }
        }
    }

    fn refresh_timestamp(&mut self) {
        if let Some(candidate) = &self.ready {
            if candidate.mined.is_some() {
                return;
            }
            let mut header = candidate.original;
            header.timestamp = now().max(median_time_past(&self.node.chain.state) + 1);
            header.nonce = 0;
            if let Some(miner) = &self.miner {
                miner.set(Some(Job {
                    generation: candidate.generation,
                    header,
                }));
            }
        }
    }

    fn on_rpc(&mut self, request: &Value, permission: Permission) -> Value {
        self.node.expire_wallet(Instant::now());
        self.node.expire_fund(Instant::now());
        let method = request["method"].as_str().unwrap_or("");
        if !permission.allows(method) {
            return json!({"error": "forbidden"});
        }
        match method {
            "info" => json!({
                "network": self.node.genesis.network,
                "genesis": hex(&self.node.genesis.id),
                "height": self.node.height(),
                "tip": hex(&self.node.tip()),
                "peers": self.peers.len(),
                "mining": self.miner.is_some(),
                "synced": self.may_mine(),
                "mempool": self.node.mempool.len(),
                "dev_fund": {
                    "direct": format_sip(self.node.dev_fund().spendable(DevAccount::Direct)),
                    "lock": format_sip(self.node.dev_fund().spendable(DevAccount::Lock)),
                    "payouts": self.node.dev_fund().payouts(DevAccount::Direct)
                        + self.node.dev_fund().payouts(DevAccount::Lock),
                },
            }),
            "address" => json!({ "address": encode_address(&self.node.address()) }),
            "walletstatus" => json!({
                "encrypted": self.node.wallet_is_protected(),
                "payment_recovery_required": self.node.payment_recovery_required(),
                "locked": self.node.wallet_is_locked(),
                "unlock_seconds_remaining": self.node.wallet_unlock_deadline().map(|d| d.saturating_duration_since(Instant::now()).as_secs()),
            }),
            "walletlock" => {
                if !self.node.wallet_is_protected() {
                    return json!({"error": "migrate the legacy wallet before using wallet locking"});
                }
                self.node.lock_wallet();
                json!({"locked": true})
            }
            "walletunlock" => {
                let Some(password) = request["password"].as_str() else {
                    return json!({"error": "wallet password is required"});
                };
                let Some(seconds) = request["seconds"].as_u64() else {
                    return json!({"error": "unlock timeout is required"});
                };
                match self.node.unlock_wallet(password, seconds) {
                    Ok(()) => json!({"locked": false}),
                    Err(e) => json!({"error": e}),
                }
            }
            "balance" => {
                let b = match self.node.balance() {
                    Ok(b) => b,
                    Err(e) => return json!({"error": e.to_string()}),
                };
                json!({
                    "total": format_sip(b.total),
                    "spendable": format_sip(b.spendable),
                    "pending": format_sip(b.pending),
                })
            }
            "send" => {
                let Some(to) = request["to"].as_str().and_then(parse_address) else {
                    return json!({ "error": "invalid address" });
                };
                let Some(amount) = request["amount"].as_str().and_then(parse_sip) else {
                    return json!({ "error": "invalid amount" });
                };
                let priority = request["priority"].as_bool().unwrap_or(false);
                let Some(id) = request["payment_id"]
                    .as_str()
                    .and_then(|s| PaymentId::parse(s).ok())
                else {
                    return json!({"error":"invalid_payment_id"});
                };
                if request.get("priority").is_some_and(|v| !v.is_boolean()) {
                    return json!({"error":"invalid priority"});
                }
                match self.node.pay_with_id(id, &to, amount, priority) {
                    Ok(outcome) => {
                        let relayed = outcome.relay.is_some();
                        if let Some(tx) = outcome.relay {
                            self.broadcast(&Request::Tx(encode_tx(&tx)), None);
                            self.refresh_template();
                        }
                        let mut reply = payment_receipt(&outcome.receipt);
                        // Retain the legacy amount response only for a live pending payment.
                        if relayed {
                            reply["sent"] = json!(format_sip(amount));
                        }
                        reply["relayed"] = json!(relayed);
                        reply["relay_error"] = outcome
                            .relay_error
                            .map(|_| json!("mempool_rejected_retry_same_id"))
                            .unwrap_or(Value::Null);
                        reply
                    }
                    Err(PaymentError::Build(e @ PayError::FundsPending { pending })) => {
                        json!({"error":e.to_string(),"code":"payment_build_failed","pending":format_sip(pending)})
                    }
                    Err(e) => json!({"error":e.to_string(),"code":e.code()}),
                }
            }
            "paymentstatus" => {
                let Some(id) = request["payment_id"]
                    .as_str()
                    .and_then(|s| PaymentId::parse(s).ok())
                else {
                    return json!({"error":"invalid_payment_id"});
                };
                match self.node.payment(id) {
                    Ok(r) => payment_receipt(&r),
                    Err(e) => json!({"error":e.to_string(),"code":e.code()}),
                }
            }
            "fundapprovals" => {
                let offset = request.get("offset").map_or(Some(0), |v| {
                    v.as_u64().and_then(|n| usize::try_from(n).ok())
                });
                let limit = request.get("limit").map_or(Some(1), |v| {
                    v.as_u64().and_then(|n| usize::try_from(n).ok())
                });
                let (Some(offset), Some(limit)) = (offset, limit) else {
                    return json!({"error":"invalid fund audit pagination"});
                };
                match self.node.fund_approvals(offset, limit) {
                    Ok(audit) => {
                        let value = serde_json::to_value(audit).expect("fund audit");
                        if serde_json::to_vec(&value).map_or(true, |b| b.len() > MAX_RPC_LINE) {
                            json!({"error":"fund audit page exceeds RPC response limit; request a smaller page"})
                        } else {
                            value
                        }
                    }
                    Err(e) => json!({"error":e.to_string()}),
                }
            }
            "fundbudgethistory" => {
                let offset = request.get("offset").map_or(Some(0), |v| {
                    v.as_u64().and_then(|n| usize::try_from(n).ok())
                });
                let limit = request.get("limit").map_or(Some(1), |v| {
                    v.as_u64().and_then(|n| usize::try_from(n).ok())
                });
                let (Some(offset), Some(limit)) = (offset, limit) else {
                    return json!({"error":"invalid budget history pagination"});
                };
                match self.node.fund_budget_history(offset, limit) {
                    Ok(history) => {
                        let value = serde_json::to_value(history).expect("budget history");
                        if serde_json::to_vec(&value).map_or(true, |b| b.len() > MAX_RPC_LINE) {
                            json!({"error":"budget history page exceeds RPC response limit; request a smaller page"})
                        } else {
                            value
                        }
                    }
                    Err(e) => json!({"error":e.to_string()}),
                }
            }
            "fundstatus" => {
                let status = self.node.fund_status();
                json!({"configured":status.configured,"locked":status.locked,
                    "genesis":hex(&self.node.genesis.id),
                    "direct_remaining":format_sip(status.direct_remaining),
                    "lock_remaining":format_sip(status.lock_remaining),
                    "max_payout":format_sip(status.max_payout),
                    "unlock_seconds_remaining":self.node.fund_unlock_deadline().map(|d|d.saturating_duration_since(Instant::now()).as_secs())})
            }
            "fundlock" => {
                self.node.lock_fund();
                json!({"locked":true})
            }
            "fundunlock" => {
                let Some(password) = request["password"].as_str() else {
                    return json!({"error":"fund password is required"});
                };
                let Ok(grant) =
                    serde_json::from_value::<crate::fund_keys::FundGrant>(request["grant"].clone())
                else {
                    return json!({"error":"invalid fund authorization"});
                };
                match self.node.unlock_fund(password, &grant) {
                    Ok(()) => json!({"locked":false}),
                    Err(e) => json!({"error":e}),
                }
            }
            "fundpayoutstatus" => {
                let Some(id) = request["payout_id"]
                    .as_str()
                    .and_then(|s| crate::fund_payments::PayoutId::parse(s).ok())
                else {
                    return json!({"error":"invalid_payout_id"});
                };
                match self.node.fund_payout_status(id) {
                    Ok(r) => serde_json::to_value(r).expect("receipt"),
                    Err(e) => json!({"error":e.to_string()}),
                }
            }
            "devfund" => {
                let Some(id) = request["payout_id"]
                    .as_str()
                    .and_then(|s| crate::fund_payments::PayoutId::parse(s).ok())
                else {
                    return json!({"error":"payout_id is required; retain and retry the same ID"});
                };
                let account = match request["account"].as_str() {
                    Some("direct") => DevAccount::Direct,
                    Some("lock") => DevAccount::Lock,
                    _ => return json!({ "error": "account must be \"direct\" or \"lock\"" }),
                };
                let Some(to) = request["to"].as_str().and_then(parse_address) else {
                    return json!({ "error": "invalid address" });
                };
                let Some(amount) = request["amount"].as_str().and_then(parse_sip) else {
                    return json!({ "error": "invalid amount" });
                };
                let before = self.node.payouts.pending().to_vec();
                match self.node.payout(id, account, &to, amount) {
                    Ok(_) => {
                        if before != self.node.payouts.pending() {
                            self.refresh_template();
                        }
                        match self.node.fund_payout_status(id) {
                            Ok(r) => serde_json::to_value(r).expect("receipt"),
                            Err(e) => json!({"error":e.to_string()}),
                        }
                    }
                    Err(e) => json!({ "error": e.to_string() }),
                }
            }
            other => json!({ "error": format!("unknown method {other:?}") }),
        }
    }
}

fn payment_receipt(receipt: &PaymentReceipt) -> Value {
    json!({"payment_id":receipt.id.to_string(),"state":receipt.state.as_str(),"slot_id":receipt.slot_id.as_ref().map(crate::hex),"confirmed_height":receipt.confirmed_height})
}

/// Authenticate every request, before it reaches the node's event queue.
/// HTTP and malformed JSON terminate the connection without dispatching a body.
async fn serve_rpc(listener: TcpListener, calls: mpsc::Sender<RpcCall>, auth: Arc<RpcAuth>) {
    let limit = Arc::new(Semaphore::new(MAX_RPC_CONNECTIONS));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let stream = tokio::select! {
            result = listener.accept() => match result {
                Ok((stream, _)) => stream,
                Err(_) => { tokio::time::sleep(Duration::from_millis(100)).await; continue; }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => continue,
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let (calls, auth) = (calls.clone(), auth.clone());
        connections.spawn(async move {
            let _permit = permit;
            let (read, mut write) = stream.into_split();
            // Avoid prefetching credentials into a long-lived reader buffer.
            let mut read = BufReader::with_capacity(1, read.take(0));
            let mut line = Zeroizing::new(Vec::with_capacity(MAX_RPC_LINE + 1));
            loop {
                line.zeroize();
                read.get_mut().set_limit(MAX_RPC_LINE as u64 + 1);
                match tokio::time::timeout(RPC_IO_TIMEOUT, read.read_until(b'\n', &mut line)).await {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(_)) => {}
                }
                if line.len() > MAX_RPC_LINE {
                    let _ = tokio::time::timeout(RPC_IO_TIMEOUT,
                        write.write_all(b"{\"error\":\"request too long\"}\n")).await;
                    break;
                }
                let parsed = serde_json::from_slice::<Value>(&line);
                line.zeroize();
                let (reply, more) = match parsed {
                    Ok(mut request) => match auth.authenticate(&mut request) {
                        Some(permission) if permission.allows(request["method"].as_str().unwrap_or("")) => {
                            let (tx, rx) = oneshot::channel();
                            if calls.send((ErasingRequest(request), permission, tx)).await.is_err() { break; }
                            (rx.await.unwrap_or_else(|_| json!({"error": "the node stopped"})), true)
                        }
                        result => {
                            crate::rpc_auth::erase_json(&mut request);
                            (json!({"error": if result.is_some() { "forbidden" } else { "unauthorized" }}), true)
                        }
                    },
                    Err(_) => (json!({"error": "invalid JSON"}), false),
                };
                let reply = Zeroizing::new(format!("{reply}\n"));
                if !matches!(tokio::time::timeout(RPC_IO_TIMEOUT, write.write_all(reply.as_bytes())).await,
                    Ok(Ok(()))) || !more { break; }
            }
        });
    }
}

/// What became of a received block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Received {
    /// It was new and valid.
    New,
    /// It was already known.
    Old,
    /// Its parent is unknown.
    Orphan,
    /// It was invalid, or is not accepted now.
    Rejected,
}

/// Whether a transaction could never have been valid, so that the peer that
/// sent it misbehaved. A transaction the mempool turns away as spent, expired,
/// conflicting or crowded out may have been valid when the peer sent it.
fn is_invalid_tx(e: &MempoolError) -> bool {
    match e {
        MempoolError::NonCanonical
        | MempoolError::BadPow
        | MempoolError::BadProof
        | MempoolError::FeeOpeningMismatch
        | MempoolError::ZeroFee
        | MempoolError::DuplicateInSlot => true,
        MempoolError::AnchorExpired
        | MempoolError::AlreadySpent(_)
        | MempoolError::Conflict(_)
        | MempoolError::Full
        | MempoolError::PeerLimit => false,
    }
}

/// Sends an unauthenticated request (servers reject it). Useful for probes.
pub fn call(address: &str, request: &Value) -> Result<Value, String> {
    call_bytes(address, &Zeroizing::new(format!("{request}\n")))
}

/// Sends a request using a credential read from an owner-only file. The raw
/// credential is not passed as a command-line argument or retained in a Value.
pub fn call_authenticated(
    address: &str,
    request: &Value,
    token: &RpcToken,
) -> Result<Value, String> {
    let object = request.as_object().ok_or("RPC request must be an object")?;
    if object.contains_key("auth") {
        return Err("request already has an auth field".into());
    }
    let mut encoded =
        Zeroizing::new(serde_json::to_string(request).map_err(|_| "cannot encode request")?);
    encoded.reserve(80);
    encoded.pop();
    if !object.is_empty() {
        encoded.push(',');
    }
    encoded.push_str("\"auth\":\"");
    encoded.push_str(&token.to_hex());
    encoded.push_str("\"}\n");
    call_bytes(address, &encoded)
}

fn call_bytes(address: &str, encoded: &str) -> Result<Value, String> {
    use std::io::{BufRead, Read, Write};
    let socket = address
        .parse()
        .map_err(|_| "RPC requires a numeric loopback address")?;
    check_rpc_address(socket)?;
    let stream = std::net::TcpStream::connect(socket)
        .map_err(|e| format!("cannot reach the node at {address}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(RPC_IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    writer
        .write_all(encoded.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut line = Zeroizing::new(String::new());
    std::io::BufReader::new(stream)
        .take(MAX_RPC_LINE as u64 + 1)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if line.len() > MAX_RPC_LINE {
        return Err("RPC reply too long".into());
    }
    serde_json::from_str(&line).map_err(|_| "invalid RPC reply".into())
}

/// The template the miner thread works on.
#[derive(Clone)]
struct Job {
    generation: u64,
    header: Header,
}

struct Candidate {
    generation: u64,
    original: Header,
    block: Option<Block>,
    mined: Option<Header>,
}

#[derive(Clone)]
struct MiningJob {
    revision: u64,
    candidate: Job,
}

struct Miner {
    job: Arc<Mutex<Option<MiningJob>>>,
    generation: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Miner {
    /// Starts the miner thread; it sends each block it seals to `found`.
    fn spawn(iterations: u64, found: mpsc::Sender<Job>) -> io::Result<Self> {
        if std::env::var_os("GITHUB_ACTIONS").as_deref() == Some(std::ffi::OsStr::new("true")) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "miner execution is prohibited on GitHub Actions",
            ));
        }
        let job: Arc<Mutex<Option<MiningJob>>> = Arc::default();
        let generation = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        // About 10^6 hashes per batch, so a new template is picked up within
        // a fraction of a second.
        let tries = (1_000_000 / iterations).max(1);
        let thread = {
            let (job, generation, stop) = (job.clone(), generation.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut current: Option<MiningJob> = None;
                let mut done = false;
                while !stop.load(Ordering::Relaxed) {
                    let latest = generation.load(Ordering::Acquire);
                    if current.as_ref().map(|j| j.revision) != Some(latest) {
                        current = job.lock().expect("miner lock").clone();
                        done = false;
                    }
                    let Some(j) = current.as_mut().filter(|_| !done) else {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    };
                    match mine_some(&mut j.candidate.header, iterations, tries) {
                        Some(true) => {
                            done = true;
                            if generation.load(Ordering::Acquire) == j.revision
                                && !stop.load(Ordering::Relaxed)
                            {
                                match found.try_send(j.candidate.clone()) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Closed(_)) => return,
                                    // Retry once the event loop drains the one result.
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        done = false;
                                        std::thread::sleep(Duration::from_millis(10));
                                    }
                                }
                            }
                        }
                        Some(false) => done = true,
                        None => {}
                    }
                }
            })
        };
        Ok(Self {
            job,
            generation,
            stop,
            thread: Some(thread),
        })
    }

    /// Replaces the template; `None` pauses mining.
    fn set(&self, candidate: Option<Job>) {
        let mut job = self.job.lock().expect("miner lock");
        let Some(generation) = self.generation.load(Ordering::Relaxed).checked_add(1) else {
            self.stop.store(true, Ordering::Relaxed);
            *job = None;
            return;
        };
        *job = candidate.map(|candidate| MiningJob {
            revision: generation,
            candidate,
        });
        self.generation.store(generation, Ordering::Release);
    }

    fn stop(self) {
        drop(self);
    }
}

impl Drop for Miner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{Genesis, GenesisFile, ProofsFile};
    use siworld_circuits::MockProver;
    use siworld_crypto::{SecretSeed, SpendKey};

    #[test]
    fn github_actions_refuses_miner_startup() {
        if std::env::var_os("GITHUB_ACTIONS").as_deref() == Some(std::ffi::OsStr::new("true")) {
            let (send, _receive) = mpsc::channel(1);
            // Zero iterations would panic before thread creation if the guard
            // were removed; this negative test cannot execute mining work.
            let error = match Miner::spawn(0, send) {
                Err(error) => error,
                Ok(miner) => {
                    miner.stop();
                    panic!("GitHub Actions unexpectedly started a miner");
                }
            };
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                error.to_string(),
                "miner execution is prohibited on GitHub Actions"
            );
            return;
        }
        // A child process exercises the real environment without mutating the
        // environment shared by concurrent tests or spawning a miner locally.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "service::tests::github_actions_refuses_miner_startup",
                "--nocapture",
            ])
            .env("GITHUB_ACTIONS", "true")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }

    fn service() -> Service {
        let genesis = Genesis::from_file(&GenesisFile {
            network: "queued-miner-test".into(),
            timestamp: now(),
            block_time: 60,
            pow_iterations: 1,
            target: "ff".repeat(32),
            container_size: 2,
            proofs: ProofsFile::Mock,
            dev_fund: None,
            allocations: vec![],
        })
        .unwrap();
        let node = Node::open(
            genesis,
            SpendKey::from_digest(siworld_core::Digest([1; 32])),
            SecretSeed::from_os_rng().unwrap(),
            None,
            Arc::new(MockProver),
        )
        .unwrap();
        let behaviour = Behaviour {
            gate: Gate::default(),
            messages: request_response::Behaviour::with_codec(
                Codec::default(),
                [(p2p::protocol(&node.genesis.id), ProtocolSupport::Full)],
                request_response::Config::default(),
            ),
        };
        let swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| behaviour)
            .unwrap()
            .build();
        Service {
            node,
            swarm,
            peers: HashSet::new(),
            statics: vec![],
            connected_statics: HashMap::new(),
            dialing: HashMap::new(),
            syncing: HashMap::new(),
            synced: true,
            miner: None,
            generation: 2,
            proving: None,
            needs_template: false,
            ready: None,
            prepared: mpsc::channel(1).0,
            fatal: None,
        }
    }

    #[tokio::test]
    async fn queued_nonce_result_from_an_old_generation_is_not_accepted_on_the_same_parent() {
        let mut service = service();
        let mut block = service.node.template(now() + 1).unwrap();
        assert!(siworld_consensus::mine(&mut block.header, 1));
        service.on_prepared(2, block.header);
        service.ready.as_mut().unwrap().block = Some(block.clone());
        service.on_mined(Job {
            generation: 1,
            header: block.header,
        });
        assert_eq!(service.node.height(), 0);
        service.on_mined(Job {
            generation: 2,
            header: block.header,
        });
        assert_eq!(service.node.height(), 1);
    }

    #[tokio::test]
    #[ignore = "owner-local only: spawns miner"]
    async fn pow_can_finish_before_proof_and_survives_timestamp_refresh() {
        let mut service = service();
        let block = service.node.template(now() + 1).unwrap();
        let (send, mut receive) = mpsc::channel(1);
        service.miner = Some(Miner::spawn(1, send).unwrap());
        service.on_prepared(2, block.header);
        let mined = tokio::time::timeout(Duration::from_secs(2), receive.recv())
            .await
            .unwrap()
            .unwrap();
        service.on_mined(mined);
        assert_eq!(service.node.height(), 0, "never publish before proof");
        let nonce = service.ready.as_ref().unwrap().mined.unwrap();
        service.refresh_timestamp();
        assert_eq!(service.ready.as_ref().unwrap().mined, Some(nonce));
        service.ready.as_mut().unwrap().block = Some(block);
        service.publish_ready();
        assert_eq!(service.node.height(), 1);
        service.miner.take().unwrap().stop();
        if let Some(task) = service.proving.take() {
            task.handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn failed_proof_discards_early_nonce_and_late_prepared_header() {
        let mut service = service();
        let mut block = service.node.template(now() + 1).unwrap();
        assert!(siworld_consensus::mine(&mut block.header, 1));
        service.on_prepared(2, block.header);
        service.on_mined(Job {
            generation: 2,
            header: block.header,
        });
        service.proving = Some(CandidateTask {
            generation: 2,
            cancelled: Arc::new(AtomicBool::new(false)),
            handle: tokio::spawn(async { None }),
        });
        service.on_proved(Ok(Some(Err(TemplateError::Randomness))));
        assert_eq!(service.generation, 3);
        service.on_prepared(2, block.header);
        service.on_mined(Job {
            generation: 2,
            header: block.header,
        });
        assert!(service.ready.is_none());
        assert!(service.needs_template);
        assert_eq!(service.node.height(), 0);
    }

    #[tokio::test]
    #[ignore = "owner-local only: spawns miner"]
    async fn candidate_generation_exhaustion_fails_closed() {
        let mut service = service();
        let (send, _receive) = mpsc::channel(1);
        service.miner = Some(Miner::spawn(1, send).unwrap());
        service.generation = u64::MAX;
        service.refresh_template();
        assert!(service.fatal.is_some());
        assert!(!service.needs_template);
        assert!(service.proving.is_none());
        service.miner.take().unwrap().stop();
    }

    #[test]
    #[ignore = "owner-local only: spawns miner"]
    fn dropping_the_miner_also_stops_its_thread() {
        let (send, _receive) = mpsc::channel(1);
        let miner = Miner::spawn(1, send).unwrap();
        let stopped = miner.stop.clone();
        drop(miner);
        let was_stopped = stopped.load(Ordering::Relaxed);
        // Keep a failing regression from leaving a stray test thread.
        stopped.store(true, Ordering::Relaxed);
        assert!(was_stopped);
    }
}
