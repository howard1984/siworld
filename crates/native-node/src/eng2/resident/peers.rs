//! Bounded fixed-destination connection lifecycle. Endpoint values never enter status.

use super::super::{connector::Connector, network, transport::Peer};
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{SocketAddr, TcpListener, TcpStream},
    thread::JoinHandle,
};

const MAX_WORKERS: usize = 8;
const WORKER_BYTES: usize = 2 * 1024 * 1024 + 65536;
const ROUND_BLOCKS: u16 = 8;
struct Connection {
    last_round: Option<Instant>,
    caught_up: bool,
    checkpoint_head: Option<(u64, Hash)>,
    completed_head: Option<(u64, Hash)>,
}
#[derive(Default)]
struct StatusInner {
    connections: BTreeMap<Hash, Connection>,
    rounds: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PeerReadiness {
    Ready,
    NoConnectedPeers,
    NoCompletedPeerRound,
    PeerRoundStale,
    PeerRoundHeadMismatch,
    PeerRoundHeadUnavailable,
    PeerCatchupInProgress,
}
impl PeerReadiness {
    pub(super) fn is_ready(self) -> bool {
        self == Self::Ready
    }
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NoConnectedPeers => "no_connected_peers",
            Self::NoCompletedPeerRound => "no_completed_peer_round",
            Self::PeerRoundStale => "peer_round_stale",
            Self::PeerRoundHeadMismatch => "peer_round_head_mismatch",
            Self::PeerRoundHeadUnavailable => "peer_round_head_unavailable",
            Self::PeerCatchupInProgress => "peer_catchup_in_progress",
        }
    }
    fn classify(status: &StatusInner, head: (u64, Hash), now: Instant) -> Self {
        if status.connections.is_empty() {
            return Self::NoConnectedPeers;
        }
        if status
            .connections
            .values()
            .all(|connection| connection.last_round.is_none())
        {
            return Self::NoCompletedPeerRound;
        }
        let fresh = |connection: &&Connection| {
            connection
                .last_round
                .is_some_and(|last| now.saturating_duration_since(last) <= READY_FRESHNESS)
        };
        if status
            .connections
            .values()
            .filter(fresh)
            .any(|connection| connection.caught_up && connection.completed_head == Some(head))
        {
            return Self::Ready;
        }
        if !status
            .connections
            .values()
            .any(|connection| fresh(&connection))
        {
            return Self::PeerRoundStale;
        }
        // Report the most complete fresh evidence. A new wrong-head round
        // cannot refresh a stale matching-head round from a different peer.
        if status
            .connections
            .values()
            .filter(fresh)
            .any(|connection| connection.caught_up && connection.completed_head.is_some())
        {
            return Self::PeerRoundHeadMismatch;
        }
        if status
            .connections
            .values()
            .filter(fresh)
            .any(|connection| connection.caught_up)
        {
            return Self::PeerRoundHeadUnavailable;
        }
        Self::PeerCatchupInProgress
    }
}
#[derive(Default)]
pub(crate) struct NetworkStatus {
    inner: Mutex<StatusInner>,
    checkpoint_references: BTreeSet<Hash>,
}
pub(super) struct Snapshot {
    pub connections: usize,
    #[cfg(test)]
    pub ready: bool,
    pub last_round_age_ms: Option<String>,
    pub rounds: u64,
}
pub(crate) struct Connected {
    status: Arc<NetworkStatus>,
    peer: Hash,
}
impl Drop for Connected {
    fn drop(&mut self) {
        if let Ok(mut status) = self.status.inner.lock() {
            status.connections.remove(&self.peer);
        }
    }
}
pub(crate) struct CheckpointReady<'a> {
    _guard: std::sync::MutexGuard<'a, StatusInner>,
}
impl NetworkStatus {
    #[cfg(test)]
    pub(crate) fn expire_checkpoint_round_for_test(&self, peer: Hash) {
        self.inner
            .lock()
            .unwrap()
            .connections
            .get_mut(&peer)
            .unwrap()
            .last_round = Some(Instant::now() - Duration::from_secs(31));
    }
    /// Only independently pinned configuration identities can establish or block
    /// checkpoint readiness. Open miner ingress supplies no reference evidence.
    pub(crate) fn new(checkpoint_references: impl IntoIterator<Item = Hash>) -> Self {
        Self {
            inner: Mutex::default(),
            checkpoint_references: checkpoint_references.into_iter().collect(),
        }
    }
    pub(crate) fn connected(self: &Arc<Self>, peer: Hash) -> Result<Connected, String> {
        let mut status = self
            .inner
            .lock()
            .map_err(|_| "connection registry lock poisoned")?;
        if status.connections.len() >= MAX_WORKERS || status.connections.contains_key(&peer) {
            return Err("duplicate or excessive established session".into());
        }
        status.connections.insert(
            peer,
            Connection {
                last_round: None,
                caught_up: false,
                checkpoint_head: None,
                completed_head: None,
            },
        );
        Ok(Connected {
            status: self.clone(),
            peer,
        })
    }
    pub(crate) fn begin_round(&self, peer: Hash) -> Result<(), String> {
        self.inner
            .lock()
            .map_err(|_| "connection registry lock poisoned")?
            .connections
            .get_mut(&peer)
            .ok_or("established session disappeared")?
            .checkpoint_head = None;
        Ok(())
    }
    /// Evidence comes from the block pull's owner critical section, carried
    /// unchanged through completion of the checkpoint and transaction phases.
    pub(crate) fn round(
        &self,
        peer: Hash,
        accepted: u16,
        checked_head: Option<(u64, Hash)>,
    ) -> Result<(), String> {
        let mut status = self
            .inner
            .lock()
            .map_err(|_| "connection registry lock poisoned")?;
        let entry = status
            .connections
            .get_mut(&peer)
            .ok_or("established session disappeared")?;
        entry.last_round = Some(Instant::now());
        entry.caught_up = accepted < ROUND_BLOCKS;
        entry.checkpoint_head = if entry.caught_up { checked_head } else { None };
        entry.completed_head = entry.checkpoint_head;
        status.rounds = status
            .rounds
            .checked_add(1)
            .ok_or("connection round counter exhausted")?;
        Ok(())
    }
    /// This guard cannot be created from a caller's asserted readiness boolean.
    /// Hold it through proposal creation or signing; disconnect and round-start
    /// updates cannot race between this check and the protected operation.
    pub(crate) fn checkpoint_ready(
        &self,
        head: (u64, Hash),
    ) -> Result<CheckpointReady<'_>, String> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| "connection registry lock poisoned")?;
        let mut references = guard
            .connections
            .iter()
            .filter(|(peer, _)| self.checkpoint_references.contains(*peer))
            .map(|(_, connection)| connection)
            .peekable();
        if references.peek().is_none()
            || !references.all(|connection| {
                connection.checkpoint_head == Some(head)
                    && connection.caught_up
                    && connection
                        .last_round
                        .is_some_and(|last| last.elapsed() <= READY_FRESHNESS)
            })
        {
            return Err(
                "checkpoint signer is waiting for a current authenticated peer round".into(),
            );
        }
        Ok(CheckpointReady { _guard: guard })
    }
    /// A completed round for another tip cannot authorize work on this one.
    pub(super) fn ready_at(&self, head: (u64, Hash)) -> Result<bool, String> {
        Ok(self.readiness_at(head)?.is_ready())
    }
    /// Classification and the original readiness predicate use the same lock
    /// and monotonic instant. Codes confer no synchronization authority.
    pub(super) fn readiness_at(&self, head: (u64, Hash)) -> Result<PeerReadiness, String> {
        let status = self
            .inner
            .lock()
            .map_err(|_| "connection registry lock poisoned")?;
        Ok(PeerReadiness::classify(&status, head, Instant::now()))
    }
    pub(super) fn invalidate_head_evidence(&self) -> Result<(), String> {
        let mut status = self
            .inner
            .lock()
            .map_err(|_| "connection registry lock poisoned")?;
        for connection in status.connections.values_mut() {
            connection.completed_head = None;
            connection.checkpoint_head = None;
            connection.caught_up = false;
        }
        Ok(())
    }
    pub(super) fn snapshot(&self) -> Result<Snapshot, String> {
        let status = self
            .inner
            .lock()
            .map_err(|_| "connection registry lock poisoned")?;
        Ok(Snapshot {
            connections: status.connections.len(),
            #[cfg(test)]
            ready: status.connections.values().any(|c| {
                c.caught_up && c.last_round.is_some_and(|t| t.elapsed() <= READY_FRESHNESS)
            }),
            last_round_age_ms: status
                .connections
                .values()
                .filter_map(|c| c.last_round)
                .max()
                .map(|t| t.elapsed().as_millis().to_string()),
            rounds: status.rounds,
        })
    }
}
enum Job {
    Dial(SocketAddr, Hash),
    Accept(TcpStream, Instant),
}
struct Worker {
    handle: JoinHandle<Result<(), String>>,
    outbound: Option<Hash>,
    started: Instant,
}
struct Backoff {
    failures: u32,
    until: Instant,
}
fn session(
    mut peer: Peer<p2p::NativeTlsChannel>,
    initiator: bool,
    shared: &Shared,
) -> Result<(), String> {
    let fingerprint = peer.peer();
    let _connected = shared.network.connected(fingerprint)?;
    let mut sequence = network::Sequence::default();
    while !shared.cancel.is_cancelled() {
        let round = if initiator {
            shared.network.begin_round(fingerprint)?;
            network::initiate(
                &mut peer,
                &shared.owner,
                &mut sequence,
                network::Limits {
                    blocks: ROUND_BLOCKS,
                },
            )
        } else {
            network::respond_with_round_start(
                &mut peer,
                &shared.owner,
                &mut sequence,
                network::Limits {
                    blocks: ROUND_BLOCKS,
                },
                || shared.network.begin_round(fingerprint),
            )
        }
        .map_err(|_| "peer round failed")?;
        checkpoint_phase(&mut peer, initiator, shared)?;
        if initiator {
            super::super::transaction_exchange::initiate(&mut peer, &shared.owner)
        } else {
            super::super::transaction_exchange::respond(&mut peer, &shared.owner)
        }
        .map_err(|_| "transaction peer phase failed")?;
        // Only a complete block → checkpoint → transaction round refreshes
        // networking. A certificate alone can never manufacture readiness.
        shared
            .network
            .round(fingerprint, round.accepted, round.checked_head)?;
        if initiator {
            for _ in 0..10 {
                if shared.cancel.is_cancelled() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(())
}
fn owner_before<'a>(
    shared: &'a Shared,
    deadline: &p2p::Deadline,
) -> Result<std::sync::MutexGuard<'a, Driver>, String> {
    loop {
        deadline
            .check()
            .map_err(|_| "checkpoint control phase deadline elapsed")?;
        match shared.owner.try_lock() {
            Ok(owner) => {
                deadline
                    .check()
                    .map_err(|_| "checkpoint control phase deadline elapsed")?;
                return Ok(owner);
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(_) => return Err("resident owner lock poisoned".into()),
        }
    }
}
fn checkpoint_phase(
    peer: &mut Peer<p2p::NativeTlsChannel>,
    initiator: bool,
    shared: &Shared,
) -> Result<(), String> {
    use super::super::checkpoint_exchange;
    let deadline = p2p::Deadline::new(checkpoint_exchange::PHASE_TIMEOUT);
    let maximum = super::super::checkpoint_wire::MAX_CHECKPOINT_PACKET_BYTES;
    let _phase = shared
        .budget
        .reserve(3 * (maximum + 4096))
        .map_err(|_| "checkpoint control phase budget exhausted")?;
    let _legacy_checkpoints = shared.legacy_checkpoint_peers.contains(&peer.peer());
    let (network, outgoing) = {
        let owner = owner_before(shared, &deadline)?;
        #[cfg(unix)]
        let outgoing = if owner.activities_allowed() {
            shared.mailbox.outgoing(_legacy_checkpoints)?
        } else {
            Vec::new()
        };
        #[cfg(not(unix))]
        let outgoing = Vec::new();
        (owner.head()?.network, outgoing)
    };
    let incoming = if initiator {
        checkpoint_exchange::initiate_before(peer, &outgoing, network, &deadline)
    } else {
        checkpoint_exchange::respond_before(peer, &outgoing, network, &deadline)
    }
    .map_err(|_| "checkpoint peer phase failed")?;
    for item in incoming {
        let outcome = {
            // Canonical owner → observer order also protects producer commit:
            // no block can commit between validating and latching a conflict.
            let owner = owner_before(shared, &deadline)?;
            if !owner.activities_allowed() {
                continue;
            }
            let mut observer = shared
                .checkpoint_observer
                .lock()
                .map_err(|_| "checkpoint observer lock poisoned")?;
            let was_conflicted = observer.conflicted();
            let outcome = observer.observe(owner.store(), unix_ms()? / 1000, &item.message);
            if was_conflicted && !observer.conflicted() {
                // Recovery must await an actual newly completed block →
                // checkpoint → transaction round at this exact canonical head.
                shared.network.invalidate_head_evidence()?;
            }
            outcome
        };
        if checkpoint_mailbox_admission(outcome)? {
            #[cfg(unix)]
            shared.mailbox.enqueue(item.message, item.reservation)?;
        }
        deadline
            .check()
            .map_err(|_| "checkpoint control phase deadline elapsed")?;
    }
    deadline
        .check()
        .map_err(|_| "checkpoint control phase deadline elapsed".into())
}
/// Pending authority keeps normal bounded synchronization alive, without
/// supplying publication material or swallowing rejected packets/hard faults.
fn checkpoint_mailbox_admission(
    outcome: Result<
        super::super::checkpoint_observer::Outcome,
        super::super::checkpoint_observer::Error,
    >,
) -> Result<bool, String> {
    use super::super::checkpoint_observer::{Error, Outcome};
    match outcome {
        Ok(Outcome::Historical | Outcome::PendingAuthorization) | Err(Error::Unavailable) => {
            Ok(false)
        }
        Ok(_) => Ok(true),
        Err(error) => Err(error.code().into()),
    }
}
#[derive(Debug)]
enum WorkerAdmission<T> {
    Deferred,
    Ready(T),
}

// Capacity pressure postpones new work while current owners release their
// reservations. Invariant failures still terminate the network owner.
fn admit_worker<T>(
    reservation: Result<(p2p::Reservation, p2p::ByteUsage), p2p::ReserveFailure>,
    start: impl FnOnce(p2p::Reservation) -> Result<T, String>,
) -> Result<WorkerAdmission<T>, String> {
    let charge = match reservation {
        Ok((charge, _)) => charge,
        Err(p2p::ReserveFailure::Exhausted(_)) => return Ok(WorkerAdmission::Deferred),
        Err(p2p::ReserveFailure::Overflow) => {
            return Err("peer worker byte budget overflow".into());
        }
        Err(p2p::ReserveFailure::Unavailable) => {
            return Err("peer worker byte budget unavailable".into());
        }
    };
    start(charge).map(WorkerAdmission::Ready)
}

fn spawn(
    job: Job,
    connector: Arc<Connector>,
    role: p2p::Role,
    shared: Arc<Shared>,
    reservation: p2p::Reservation,
) -> Result<Worker, String> {
    let outbound = match &job {
        Job::Dial(_, peer) => Some(*peer),
        _ => None,
    };
    let started = Instant::now();
    let handle = std::thread::Builder::new()
        .name("eng2-peer-worker".into())
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let _charge = reservation;
            let (peer, initiator) = match job {
                Job::Dial(endpoint, peer) => (
                    connector.connect(endpoint, peer, role, shared.cancel.clone()),
                    true,
                ),
                Job::Accept(socket, accepted) => (
                    connector.accept(socket, accepted, role, shared.cancel.clone()),
                    false,
                ),
            };
            session(
                peer.map_err(|_| "peer authentication unavailable")?,
                initiator,
                &shared,
            )
        })
        .map_err(|_| "peer worker creation failed")?;
    Ok(Worker {
        handle,
        outbound,
        started,
    })
}
pub(super) fn run(
    config: config::Configuration,
    genesis: Arc<Genesis>,
    identity: Arc<NativeIdentity>,
    shared: Arc<Shared>,
) -> Result<(), String> {
    let local = identity
        .descriptor()
        .map_err(|_| "local descriptor unavailable")?
        .fingerprint();
    let connector = Arc::new(
        Connector::new(
            genesis,
            identity,
            config.peers.iter().map(|p| p.expected.clone()).collect(),
            shared.budget.clone(),
            shared
                .owner
                .lock()
                .map_err(|_| "resident owner lock poisoned")?
                .engine()
                .body_policy(),
        )
        .map_err(|_| "resident connector configuration rejected")?,
    );
    let listener = config
        .listen
        .map(|address| {
            let socket =
                TcpListener::bind(address).map_err(|_| "explicit resident listener unavailable")?;
            socket
                .set_nonblocking(true)
                .map_err(|_| "resident listener mode unavailable")?;
            Ok::<_, String>(socket)
        })
        .transpose()?;
    let mut workers: Vec<Worker> = Vec::new();
    let mut backoff: BTreeMap<Hash, Backoff> = BTreeMap::new();
    let result = (|| {
        while !shared.cancel.is_cancelled() {
            let mut index = 0;
            while index < workers.len() {
                if workers[index].handle.is_finished() {
                    let worker = workers.swap_remove(index);
                    let stable = worker.started.elapsed() >= Duration::from_secs(60);
                    let _ = worker.handle.join();
                    if let Some(peer) = worker.outbound {
                        let failures = if stable {
                            0
                        } else {
                            backoff
                                .get(&peer)
                                .map_or(1, |b| b.failures.saturating_add(1))
                        };
                        backoff.insert(
                            peer,
                            Backoff {
                                failures,
                                until: Instant::now()
                                    + Duration::from_secs((1u64 << failures.min(6)).min(60)),
                            },
                        );
                    }
                } else {
                    index += 1;
                }
            }
            for destination in &config.peers {
                if workers.len() >= MAX_WORKERS {
                    break;
                }
                let peer = destination.expected.fingerprint();
                // One deterministic dialer for two listening service peers;
                // outbound-only miners always initiate their pinned route.
                if !destination.dial
                    || (listener.is_some() && local > peer)
                    || workers.iter().any(|w| w.outbound == Some(peer))
                    || backoff.get(&peer).is_some_and(|b| Instant::now() < b.until)
                {
                    continue;
                }
                if shared
                    .network
                    .inner
                    .lock()
                    .map_err(|_| "connection registry lock poisoned")?
                    .connections
                    .contains_key(&peer)
                {
                    continue;
                }
                match admit_worker(shared.budget.reserve_observed(WORKER_BYTES), |charge| {
                    spawn(
                        Job::Dial(destination.endpoint, peer),
                        connector.clone(),
                        config.role,
                        shared.clone(),
                        charge,
                    )
                })? {
                    WorkerAdmission::Ready(worker) => workers.push(worker),
                    WorkerAdmission::Deferred => break,
                }
            }
            for _ in 0..2 {
                if workers.len() >= MAX_WORKERS {
                    break;
                }
                let Some(listener) = &listener else {
                    break;
                };
                match admit_worker(shared.budget.reserve_observed(WORKER_BYTES), |charge| {
                    match listener.accept() {
                        Ok((socket, _)) => spawn(
                            Job::Accept(socket, Instant::now()),
                            connector.clone(),
                            config.role,
                            shared.clone(),
                            charge,
                        )
                        .map(Some),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                        Err(_) => Err("resident listener accept failed".into()),
                    }
                })? {
                    WorkerAdmission::Ready(Some(worker)) => workers.push(worker),
                    WorkerAdmission::Ready(None) | WorkerAdmission::Deferred => break,
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    })();
    shared.cancel.cancel();
    for worker in workers {
        let _ = worker.handle.join();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readiness_reasons_follow_live_connections_not_the_lifetime_round_counter() {
        let status = Arc::new(NetworkStatus::default());
        let head = (50, [2; 32]);
        assert_eq!(
            status.readiness_at(head).unwrap(),
            PeerReadiness::NoConnectedPeers
        );
        let connection = status.connected([1; 32]).unwrap();
        assert_eq!(
            status.readiness_at(head).unwrap(),
            PeerReadiness::NoCompletedPeerRound
        );
        status.round([1; 32], ROUND_BLOCKS, Some(head)).unwrap();
        assert_eq!(
            status.readiness_at(head).unwrap(),
            PeerReadiness::PeerCatchupInProgress
        );
        status.round([1; 32], 0, None).unwrap();
        assert_eq!(
            status.readiness_at(head).unwrap(),
            PeerReadiness::PeerRoundHeadUnavailable
        );
        status.round([1; 32], 0, Some((49, [3; 32]))).unwrap();
        assert_eq!(
            status.readiness_at(head).unwrap(),
            PeerReadiness::PeerRoundHeadMismatch
        );
        status.round([1; 32], 0, Some(head)).unwrap();
        assert_eq!(status.readiness_at(head).unwrap(), PeerReadiness::Ready);
        assert!(status.ready_at(head).unwrap());
        status.invalidate_head_evidence().unwrap();
        assert_eq!(
            status.readiness_at(head).unwrap(),
            PeerReadiness::PeerCatchupInProgress
        );
        assert!(!status.ready_at(head).unwrap());
        drop(connection);
        assert_eq!(
            status.readiness_at(head).unwrap(),
            PeerReadiness::NoConnectedPeers
        );
        let _reconnected = status.connected([1; 32]).unwrap();
        assert!(status.snapshot().unwrap().rounds > 0);
        assert_eq!(
            status.readiness_at(head).unwrap(),
            PeerReadiness::NoCompletedPeerRound
        );
    }

    #[test]
    fn a_fresh_wrong_head_cannot_refresh_a_stale_matching_round_and_boundary_is_inclusive() {
        let status = Arc::new(NetworkStatus::default());
        let _first = status.connected([1; 32]).unwrap();
        let _second = status.connected([2; 32]).unwrap();
        let head = (50, [3; 32]);
        status.round([1; 32], 0, Some(head)).unwrap();
        status.round([2; 32], 0, Some((50, [4; 32]))).unwrap();
        let now = Instant::now();
        let mut inner = status.inner.lock().unwrap();
        inner.connections.get_mut(&[1; 32]).unwrap().last_round = Some(now - READY_FRESHNESS);
        inner.connections.get_mut(&[2; 32]).unwrap().last_round = Some(now);
        assert_eq!(
            PeerReadiness::classify(&inner, head, now),
            PeerReadiness::Ready
        );
        inner.connections.get_mut(&[1; 32]).unwrap().last_round =
            Some(now - READY_FRESHNESS - Duration::from_nanos(1));
        assert_eq!(
            PeerReadiness::classify(&inner, head, now),
            PeerReadiness::PeerRoundHeadMismatch
        );
        inner.connections.get_mut(&[2; 32]).unwrap().last_round =
            Some(now - READY_FRESHNESS - Duration::from_nanos(1));
        assert_eq!(
            PeerReadiness::classify(&inner, head, now),
            PeerReadiness::PeerRoundStale
        );
        inner.connections.get_mut(&[1; 32]).unwrap().last_round = Some(now);
        assert_eq!(
            PeerReadiness::classify(&inner, head, now),
            PeerReadiness::Ready
        );
    }

    #[test]
    fn pending_checkpoint_allows_round_completion_but_recovery_requires_new_head_evidence() {
        use super::super::super::checkpoint_observer::{Error, Outcome};
        let status = Arc::new(NetworkStatus::new([[1; 32]]));
        let _connection = status.connected([1; 32]).unwrap();
        let head = (50, [2; 32]);
        status.round([1; 32], 0, Some(head)).unwrap();
        assert!(status.ready_at(head).unwrap());
        assert!(!checkpoint_mailbox_admission(Ok(Outcome::PendingAuthorization)).unwrap());
        // Actual rounds can still finish while the observer independently gates
        // mining/signing. A pending certificate creates no round by itself.
        status.round([1; 32], 0, Some(head)).unwrap();
        assert!(checkpoint_mailbox_admission(Ok(Outcome::CurrentCertificate(12))).unwrap());
        status.invalidate_head_evidence().unwrap();
        assert!(!status.ready_at(head).unwrap());
        assert!(status.checkpoint_ready(head).is_err());
        status.round([1; 32], 0, None).unwrap();
        assert!(!status.ready_at(head).unwrap());
        status.round([1; 32], 0, Some(head)).unwrap();
        assert!(status.ready_at(head).unwrap());
        assert!(status.checkpoint_ready(head).is_ok());
        for error in [Error::Rejected, Error::Conflict, Error::EvidenceUnavailable] {
            assert!(checkpoint_mailbox_admission(Err(error)).is_err());
        }
    }
    #[test]
    fn worker_admission_defers_capacity_without_starting_or_releasing_other_owners() {
        let budget = p2p::Budget::new(WORKER_BYTES + 9);
        let existing = budget.reserve(10).unwrap();
        let before = budget.available().unwrap();
        let called = std::cell::Cell::new(false);
        let result = admit_worker(budget.reserve_observed(WORKER_BYTES), |_| {
            called.set(true);
            Ok(())
        })
        .unwrap();
        assert!(matches!(result, WorkerAdmission::Deferred));
        assert!(!called.get());
        assert_eq!(budget.available().unwrap(), before);
        drop(existing);
        assert_eq!(budget.available().unwrap(), WORKER_BYTES + 9);
    }

    #[test]
    fn worker_admission_retries_after_release_and_retains_the_exact_worker_charge() {
        let budget = p2p::Budget::new(WORKER_BYTES);
        let pressure = budget.reserve(1).unwrap();
        assert!(matches!(
            admit_worker(budget.reserve_observed(WORKER_BYTES), Ok).unwrap(),
            WorkerAdmission::Deferred
        ));
        drop(pressure);
        let WorkerAdmission::Ready(charge) =
            admit_worker(budget.reserve_observed(WORKER_BYTES), Ok).unwrap()
        else {
            panic!("released capacity must admit a worker");
        };
        assert_eq!(budget.available().unwrap(), 0);
        drop(charge);
        assert_eq!(budget.available().unwrap(), WORKER_BYTES);
    }

    #[test]
    fn worker_admission_gates_accept_and_releases_an_empty_accept() {
        let budget = p2p::Budget::new(WORKER_BYTES);
        let pressure = budget.reserve(1).unwrap();
        let accepts = std::cell::Cell::new(0);
        let accept_empty = |_charge| {
            accepts.set(accepts.get() + 1);
            Ok::<Option<()>, String>(None)
        };
        assert!(matches!(
            admit_worker(budget.reserve_observed(WORKER_BYTES), accept_empty).unwrap(),
            WorkerAdmission::Deferred
        ));
        assert_eq!(accepts.get(), 0);
        drop(pressure);
        assert!(matches!(
            admit_worker(budget.reserve_observed(WORKER_BYTES), accept_empty).unwrap(),
            WorkerAdmission::Ready(None)
        ));
        assert_eq!(accepts.get(), 1);
        assert_eq!(budget.available().unwrap(), WORKER_BYTES);
    }

    #[test]
    fn worker_admission_start_failure_releases_only_its_reservation() {
        let budget = p2p::Budget::new(WORKER_BYTES + 17);
        let existing = budget.reserve(17).unwrap();
        let result = admit_worker(budget.reserve_observed(WORKER_BYTES), |_charge| {
            Err::<(), String>("peer worker creation failed".into())
        });
        assert_eq!(result.unwrap_err(), "peer worker creation failed");
        assert_eq!(budget.available().unwrap(), WORKER_BYTES);
        drop(existing);
        assert_eq!(budget.available().unwrap(), WORKER_BYTES + 17);
    }

    #[test]
    fn worker_admission_start_unwind_releases_its_reservation() {
        let budget = p2p::Budget::new(WORKER_BYTES);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = admit_worker(
                budget.reserve_observed(WORKER_BYTES),
                |_charge| -> Result<(), String> {
                    panic!("worker start unwind");
                },
            );
        }));
        assert!(result.is_err());
        assert_eq!(budget.available().unwrap(), WORKER_BYTES);
    }

    #[test]
    fn worker_admission_preserves_distinct_fatal_budget_failures() {
        for (failure, expected) in [
            (
                p2p::ReserveFailure::Overflow,
                "peer worker byte budget overflow",
            ),
            (
                p2p::ReserveFailure::Unavailable,
                "peer worker byte budget unavailable",
            ),
        ] {
            let called = std::cell::Cell::new(false);
            let result = admit_worker(Err(failure), |_| {
                called.set(true);
                Ok(())
            });
            assert_eq!(result.unwrap_err(), expected);
            assert!(!called.get());
        }
    }

    #[test]
    fn worker_admission_repeated_deferrals_do_not_accumulate_charges() {
        let budget = p2p::Budget::new(WORKER_BYTES);
        let pressure = budget.reserve(1).unwrap();
        let starts = std::cell::Cell::new(0);
        for _ in 0..32 {
            assert!(matches!(
                admit_worker(budget.reserve_observed(WORKER_BYTES), |_| {
                    starts.set(starts.get() + 1);
                    Ok(())
                })
                .unwrap(),
                WorkerAdmission::Deferred
            ));
            assert_eq!(budget.available().unwrap(), WORKER_BYTES - 1);
        }
        assert_eq!(starts.get(), 0);
        drop(pressure);
        assert_eq!(budget.available().unwrap(), WORKER_BYTES);
    }

    #[test]
    fn mining_readiness_requires_current_completed_head_and_switch_revalidation() {
        let status = Arc::new(NetworkStatus::default());
        let connection = status.connected([5; 32]).unwrap();
        let old = (5, [6; 32]);
        status.round([5; 32], 0, Some(old)).unwrap();
        assert!(status.ready_at(old).unwrap());
        assert!(!status.ready_at((6, [7; 32])).unwrap());
        status.begin_round([5; 32]).unwrap();
        assert!(status.ready_at(old).unwrap());
        status.invalidate_head_evidence().unwrap();
        assert!(!status.ready_at(old).unwrap());
        status.round([5; 32], 0, Some(old)).unwrap();
        drop(connection);
        assert!(!status.ready_at(old).unwrap());
    }
    #[test]
    fn checkpoint_ready_guard_pins_exact_head_and_expires_without_changing_mining_readiness() {
        let status = Arc::new(NetworkStatus::new([[1; 32]]));
        let _connection = status.connected([1; 32]).unwrap();
        let head = (96, [2; 32]);
        status.round([1; 32], 0, Some(head)).unwrap();
        {
            let _guard = status.checkpoint_ready(head).unwrap();
            assert!(matches!(
                status.inner.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
        }
        assert!(status.checkpoint_ready((97, [3; 32])).is_err());
        status.begin_round([1; 32]).unwrap();
        assert!(status.snapshot().unwrap().ready);
        assert!(status.checkpoint_ready(head).is_err());
        status.round([1; 32], 0, Some(head)).unwrap();
        status
            .inner
            .lock()
            .unwrap()
            .connections
            .get_mut(&[1; 32])
            .unwrap()
            .last_round = Some(Instant::now() - Duration::from_secs(31));
        assert!(status.checkpoint_ready(head).is_err());
        status.round([1; 32], 0, Some(head)).unwrap();
        assert!(status.checkpoint_ready(head).is_ok());
    }
    #[test]
    fn completed_round_readiness_expires_and_is_revoked_on_disconnect() {
        let status = Arc::new(NetworkStatus::default());
        let connection = status.connected([1; 32]).unwrap();
        assert!(!status.snapshot().unwrap().ready);
        status.round([1; 32], ROUND_BLOCKS, None).unwrap();
        assert!(!status.snapshot().unwrap().ready);
        status.round([1; 32], 0, Some((0, [0; 32]))).unwrap();
        assert!(status.snapshot().unwrap().ready);
        status
            .inner
            .lock()
            .unwrap()
            .connections
            .get_mut(&[1; 32])
            .unwrap()
            .last_round = Some(Instant::now() - Duration::from_secs(31));
        assert!(!status.snapshot().unwrap().ready);
        status.round([1; 32], 0, Some((0, [0; 32]))).unwrap();
        drop(connection);
        let snapshot = status.snapshot().unwrap();
        assert_eq!(snapshot.connections, 0);
        assert!(!snapshot.ready);
        assert_eq!(snapshot.rounds, 3);
    }
}
