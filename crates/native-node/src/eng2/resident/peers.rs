//! Bounded fixed-destination connection lifecycle. Endpoint values never enter status.

use super::super::{connector::Connector, network, transport::Peer};
use super::*;
use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener, TcpStream},
    thread::JoinHandle,
};

const MAX_WORKERS: usize = 8;
const WORKER_BYTES: usize = 2 * 1024 * 1024 + 65536;
const ROUND_BLOCKS: u16 = 8;
struct Connection {
    last_round: Option<Instant>,
    caught_up: bool,
}
#[derive(Default)]
struct StatusInner {
    connections: BTreeMap<Hash, Connection>,
    rounds: u64,
}
#[derive(Default)]
pub(super) struct NetworkStatus {
    inner: Mutex<StatusInner>,
}
pub(super) struct Snapshot {
    pub connections: usize,
    pub ready: bool,
    pub last_round_age_ms: Option<String>,
    pub rounds: u64,
}
struct Connected {
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
impl NetworkStatus {
    fn connected(self: &Arc<Self>, peer: Hash) -> Result<Connected, String> {
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
            },
        );
        Ok(Connected {
            status: self.clone(),
            peer,
        })
    }
    fn round(&self, peer: Hash, accepted: u16) -> Result<(), String> {
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
        status.rounds = status
            .rounds
            .checked_add(1)
            .ok_or("connection round counter exhausted")?;
        Ok(())
    }
    pub fn snapshot(&self) -> Result<Snapshot, String> {
        let status = self
            .inner
            .lock()
            .map_err(|_| "connection registry lock poisoned")?;
        Ok(Snapshot {
            connections: status.connections.len(),
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
            network::initiate(
                &mut peer,
                &shared.owner,
                &mut sequence,
                network::Limits {
                    blocks: ROUND_BLOCKS,
                },
            )
        } else {
            network::respond(
                &mut peer,
                &shared.owner,
                &mut sequence,
                network::Limits {
                    blocks: ROUND_BLOCKS,
                },
            )
        }
        .map_err(|_| "peer round failed")?;
        shared.network.round(fingerprint, round.accepted)?;
        #[cfg(unix)]
        {
            let maximum = super::super::runtime_export::host::MAX_CHECKPOINT_PACKET_BYTES;
            let _phase = shared
                .budget
                .reserve(3 * (maximum + 4096))
                .map_err(|_| "checkpoint control phase budget exhausted")?;
            let outgoing = shared.mailbox.outgoing()?;
            let network = shared
                .owner
                .lock()
                .map_err(|_| "resident owner lock poisoned")?
                .head()?
                .network;
            let incoming = if initiator {
                super::super::checkpoint_exchange::initiate(&mut peer, &outgoing, network)
            } else {
                super::super::checkpoint_exchange::respond(&mut peer, &outgoing, network)
            }
            .map_err(|_| "checkpoint peer phase failed")?;
            for item in incoming {
                shared.mailbox.enqueue(item.message, item.reservation)?;
            }
        }
        #[cfg(unix)]
        if initiator {
            super::super::transaction_exchange::initiate(&mut peer, &shared.owner)
        } else {
            super::super::transaction_exchange::respond(&mut peer, &shared.owner)
        }
        .map_err(|_| "transaction peer phase failed")?;
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
                let charge = shared
                    .budget
                    .reserve(WORKER_BYTES)
                    .map_err(|_| "peer worker byte budget exhausted")?;
                workers.push(spawn(
                    Job::Dial(destination.endpoint, peer),
                    connector.clone(),
                    config.role,
                    shared.clone(),
                    charge,
                )?);
            }
            for _ in 0..2 {
                if workers.len() >= MAX_WORKERS {
                    break;
                }
                let Some(listener) = &listener else {
                    break;
                };
                let charge = shared
                    .budget
                    .reserve(WORKER_BYTES)
                    .map_err(|_| "peer worker byte budget exhausted")?;
                match listener.accept() {
                    Ok((socket, _)) => workers.push(spawn(
                        Job::Accept(socket, Instant::now()),
                        connector.clone(),
                        config.role,
                        shared.clone(),
                        charge,
                    )?),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => return Err("resident listener accept failed".into()),
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
    fn completed_round_readiness_expires_and_is_revoked_on_disconnect() {
        let status = Arc::new(NetworkStatus::default());
        let connection = status.connected([1; 32]).unwrap();
        assert!(!status.snapshot().unwrap().ready);
        status.round([1; 32], ROUND_BLOCKS).unwrap();
        assert!(!status.snapshot().unwrap().ready);
        status.round([1; 32], 0).unwrap();
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
        status.round([1; 32], 0).unwrap();
        drop(connection);
        let snapshot = status.snapshot().unwrap();
        assert_eq!(snapshot.connections, 0);
        assert!(!snapshot.ready);
        assert_eq!(snapshot.rounds, 3);
    }
}
