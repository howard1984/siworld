//! Socket and owner-lifecycle tests use the synthetic block verifier only to
//! isolate networking. Cryptographic transport and both identity signatures
//! are real; these tests do not qualify transaction or settlement proofs.
use super::*;
use crate::chain::CandidatePolicy;
use crate::fixtures::{TestVerifier, candidate};
use crate::state::Config;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "siworld-resident-network-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        local::initialize_config(&path, configuration()).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn configuration() -> Config {
    Config::development([209; 32], 0).unwrap()
}
fn expected(identity: &NativeIdentity) -> ExpectedPeer {
    let binding = p2p::Binding::new(&configuration());
    let descriptor = identity.descriptor().unwrap();
    let pin = PeerPin::from_trusted_descriptor(&descriptor, &binding).unwrap();
    ExpectedPeer::from_pinned_descriptor(binding, descriptor, pin).unwrap()
}
struct Endpoint {
    driver: Driver,
    node: Option<Node<TestVerifier>>,
    directory: Directory,
}
impl Endpoint {
    fn new() -> Self {
        Self::with_storage_role(None)
    }
    fn with_storage_role(role: Option<crate::storage_policy::Role>) -> Self {
        let directory = Directory::new();
        let mut store = Store::open(
            directory.0.join("chain.redb"),
            configuration(),
            &TestVerifier,
        )
        .unwrap();
        let identity = Arc::new(
            NativeIdentity::initialize(&directory.0, p2p::Binding::new(&configuration())).unwrap(),
        );
        if let Some(role) = role {
            store.configure_storage(role).unwrap();
        }
        let node = Node::new(store, TestVerifier);
        let config = Configuration {
            listen: Some((Ipv4Addr::LOCALHOST, 0).into()),
            mining: false,
            peers: Arc::new(BTreeMap::new()),
            digest: "0".repeat(64),
        };
        let driver = Driver::new(identity, config, node.transport_budget()).unwrap();
        Self {
            driver,
            node: Some(node),
            directory,
        }
    }
    fn address(&self) -> SocketAddr {
        self.driver.listener.as_ref().unwrap().local_addr().unwrap()
    }
    fn follow(&mut self, other: &Self) {
        let peer = expected(&other.driver.identity);
        self.driver.peers = Arc::new(BTreeMap::from([(
            peer.fingerprint(),
            Peer {
                endpoint: other.address(),
                dial: true,
                expected: peer,
            },
        )]));
        self.driver.scheduler = Scheduler::new(
            self.driver.local,
            &self.driver.peers.keys().copied().collect::<Vec<_>>(),
            self.driver.budget.clone(),
            self.driver.now(),
        )
        .unwrap();
    }
    fn tick(&mut self) {
        self.driver.poll().unwrap();
        for _ in 0..COMMAND_SLOTS {
            match self.driver.rx.try_recv() {
                Ok(command) => self
                    .driver
                    .handle(self.node.as_mut().unwrap(), command)
                    .unwrap(),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    panic!("owner queue unexpectedly disconnected")
                }
            }
        }
    }
    fn append(&mut self, seed: u32) {
        let node = self.node.as_mut().unwrap();
        let block = candidate(node.state(), seed);
        node.import_branch(node.state().height, &[block], CandidatePolicy::default())
            .unwrap();
    }
    fn state(&self) -> &State {
        self.node.as_ref().unwrap().state()
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = self.driver.shutdown();
    }
}
fn until(
    a: &mut Endpoint,
    b: &mut Endpoint,
    mut condition: impl FnMut(&Endpoint, &Endpoint) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !condition(a, b) {
        assert!(
            Instant::now() < deadline,
            "resident loopback gate exceeded its bounded wait"
        );
        a.tick();
        b.tick();
        std::thread::sleep(POLL);
    }
}
fn connect_pair(a: &mut Endpoint, b: &mut Endpoint) {
    a.follow(b);
    b.follow(a);
    until(a, b, |a, b| {
        a.driver.scheduler.status().established == 1 && b.driver.scheduler.status().established == 1
    });
}

#[cfg(unix)]
#[test]
fn unavailable_checkpoint_observation_does_not_interrupt_canonical_validation() {
    use crate::{
        checkpoint_service::Coordinator, engineering_checkpoint::Roster,
        identity::checkpoint_authority::Authority,
    };
    let directory = Directory::new();
    let second = Directory::new();
    let binding = p2p::Binding::new(&configuration());
    let a = Authority::initialize(&directory.0, binding).unwrap();
    let b = Authority::initialize(&second.0, binding).unwrap();
    let roster = Roster::new(binding, [a.public_key(), b.public_key()]).unwrap();
    let mut coordinator = Coordinator::for_test(&directory.0, roster).unwrap();
    let store = Store::open(
        directory.0.join("chain.redb"),
        configuration(),
        &TestVerifier,
    )
    .unwrap();
    let mut node = Node::new(store, TestVerifier);
    let status = directory.0.join("checkpoint-service-status.json");
    std::fs::create_dir(&status).unwrap();
    let metrics = checkpoint_status_observation(&directory.0, &mut coordinator, 21_600);
    assert_eq!(metrics["alert"], "checkpoint_status_export_unavailable");
    let block = candidate(node.state(), 100_000);
    node.import_branch(0, &[block], CandidatePolicy::default())
        .unwrap();
    assert_eq!(node.state().height, 1);
    std::fs::remove_dir(&status).unwrap();
    let metrics = checkpoint_status_observation(&directory.0, &mut coordinator, 21_601);
    assert_eq!(metrics["alert"], "checkpoint_stale");
    assert!(coordinator.alert.is_none());
    let exported: Value = serde_json::from_slice(&std::fs::read(status).unwrap()).unwrap();
    assert_eq!(exported, metrics);
    assert_eq!(node.state().height, 1);
}

#[cfg(unix)]
#[test]
fn budget_alarm_does_not_interrupt_authenticated_peer_sync() {
    let mut source = Endpoint::new();
    let mut target = Endpoint::with_storage_role(Some(crate::storage_policy::Role::Validator));
    source.append(100_000);
    let pressure = target.directory.0.join("capacity-pressure.fixture");
    std::fs::File::create_new(&pressure)
        .unwrap()
        .set_len(200_000_000_001)
        .unwrap();
    assert!(
        target
            .node
            .as_ref()
            .unwrap()
            .store()
            .storage_ingestion_ready()
            .unwrap()
    );
    assert_eq!(
        target
            .node
            .as_ref()
            .unwrap()
            .store()
            .storage_metrics()
            .unwrap()["storage_budget_exceeded"],
        true
    );
    connect_pair(&mut source, &mut target);
    until(&mut source, &mut target, |a, b| {
        a.state().fingerprint() == b.state().fingerprint()
    });
    source.append(200_000);
    until(&mut source, &mut target, |a, b| {
        a.state().fingerprint() == b.state().fingerprint()
    });
    assert_eq!(target.state().height, 2);
    assert_eq!(target.driver.scheduler.status().disabled, 0);
    let expected = target.state().fingerprint();
    target.driver.shutdown().unwrap();
    drop(target.node.take());
    let reopened = Store::open_existing(
        target.directory.0.join("chain.redb"),
        configuration(),
        &TestVerifier,
    )
    .unwrap();
    assert_eq!(reopened.state().fingerprint(), expected);
    assert_eq!(
        reopened.storage_metrics().unwrap()["storage_budget_exceeded"],
        true
    );
}

#[test]
fn a_leading_initiator_syncs_a_peer_behind_its_finalized_prefix() {
    let mut source = Endpoint::new();
    let mut target = Endpoint::new();
    if source.driver.local > target.driver.local {
        std::mem::swap(&mut source, &mut target);
    }
    for n in 0..26 {
        source.append(5_000_000 + n * 1_000);
    }
    let before = source.state().fingerprint();
    connect_pair(&mut source, &mut target);
    until(&mut source, &mut target, |a, b| {
        b.state().height == 26 && a.state().fingerprint() == b.state().fingerprint()
    });
    assert_eq!(source.state().fingerprint(), before);
    assert_eq!(source.driver.scheduler.status().disabled, 0);
    assert_eq!(target.driver.scheduler.status().disabled, 0);
}

#[test]
fn actual_resident_tls_listeners_sync_and_restart_from_the_same_persisted_state() {
    let mut source = Endpoint::new();
    let mut target = Endpoint::new();
    source.append(100_000);
    source.append(200_000);
    connect_pair(&mut source, &mut target);
    until(&mut source, &mut target, |a, b| {
        b.state().height == 2 && a.state().fingerprint() == b.state().fingerprint()
    });
    assert!(source.driver.connections >= 1 && target.driver.connections >= 1);
    assert!(
        source.driver.workers.len() <= MAX_WORKERS && target.driver.workers.len() <= MAX_WORKERS
    );
    let fingerprint = target.state().fingerprint();
    let tip = target.state().tip;
    source.driver.shutdown().unwrap();
    target.driver.shutdown().unwrap();
    drop(target.node.take());
    let restored = Store::open_existing(
        target.directory.0.join("chain.redb"),
        configuration(),
        &TestVerifier,
    )
    .unwrap();
    assert_eq!(restored.state().height, 2);
    assert_eq!(restored.state().tip, tip);
    assert_eq!(restored.state().fingerprint(), fingerprint);
}

#[test]
fn resident_disconnect_reconnects_with_fresh_authentication_and_continues_sync() {
    let mut source = Endpoint::new();
    let mut target = Endpoint::new();
    connect_pair(&mut source, &mut target);
    let connections = (source.driver.connections, target.driver.connections);
    for worker in source.driver.workers.values() {
        worker.cancel.cancel();
    }
    for worker in target.driver.workers.values() {
        worker.cancel.cancel();
    }
    source.append(300_000);
    until(&mut source, &mut target, |a, b| {
        a.driver.connections > connections.0
            && b.driver.connections > connections.1
            && b.state().height == 1
            && a.state().fingerprint() == b.state().fingerprint()
    });
    assert!(source.driver.failures >= 1 && target.driver.failures >= 1);
    assert_eq!(source.driver.scheduler.status().established, 1);
    assert_eq!(target.driver.scheduler.status().established, 1);
}

fn waiting_worker(
    endpoint: &mut Endpoint,
    peer: Option<Hash>,
    token: Option<Attempt>,
) -> (u64, SyncSender<()>) {
    let id = endpoint.driver.next_id + 1;
    endpoint.driver.next_id = id;
    let cancel = Cancellation::default();
    let signal = cancel.clone();
    let (release, receive) = mpsc::sync_channel(1);
    let join = std::thread::spawn(move || {
        loop {
            if signal.is_cancelled() {
                return Failure::Unavailable;
            }
            match receive.recv_timeout(POLL) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return Failure::Unavailable,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
        }
    });
    endpoint.driver.workers.insert(
        id,
        Worker {
            sync_goal: None,
            sync_more: true,
            sync_complete: false,
            pull_fingerprint: None,
            peer,
            token,
            cancel,
            join,
            sync: SyncAttempt::default(),
            acknowledged: BTreeSet::new(),
            _reservation: endpoint
                .driver
                .budget
                .reserve(WORKER_STACK + RELAY_TRACKING_BYTES)
                .unwrap(),
        },
    );
    (id, release)
}

fn retiring_inbound_pair() -> (Endpoint, Endpoint, u64, SyncSender<()>) {
    let mut receiver = Endpoint::new();
    let mut sender = Endpoint::new();
    if receiver.driver.local < sender.driver.local {
        std::mem::swap(&mut receiver, &mut sender);
    }
    receiver.follow(&sender);
    sender.follow(&receiver);
    let token = receiver
        .driver
        .scheduler
        .begin(
            sender.driver.local,
            Direction::Inbound,
            receiver.driver.now(),
        )
        .unwrap()
        .token;
    receiver
        .driver
        .scheduler
        .authenticated(token, receiver.driver.now())
        .unwrap();
    receiver.driver.connections = 1;
    let (id, release) = waiting_worker(&mut receiver, Some(sender.driver.local), Some(token));
    (receiver, sender, id, release)
}

fn submit_authenticated(
    endpoint: &mut Endpoint,
    id: u64,
    peer: Hash,
) -> Receiver<Result<(), runtime::Error>> {
    let (reply, receive) = mpsc::sync_channel(1);
    let charged = ChargedCommand {
        command: Command::Authenticated { id, peer, reply },
        _reservation: endpoint.driver.budget.reserve(COMMAND_BYTES).unwrap(),
    };
    endpoint
        .driver
        .handle(endpoint.node.as_mut().unwrap(), charged)
        .unwrap();
    receive
}

fn await_retirement(endpoint: &mut Endpoint, id: u64) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while endpoint.driver.workers.contains_key(&id) {
        assert!(
            Instant::now() < deadline,
            "owned test worker did not retire"
        );
        endpoint.tick();
        std::thread::yield_now();
    }
}

#[test]
fn authenticated_replacement_waits_for_prior_worker_retirement_and_existing_backoff() {
    let (mut receiver, sender, old, release) = retiring_inbound_pair();
    let (new, _waiting) = waiting_worker(&mut receiver, None, None);
    let before = receiver.driver.budget.available().unwrap();
    let answer = submit_authenticated(&mut receiver, new, sender.driver.local);
    // Models the owner turn after Apply replies but before the old I/O thread
    // returns and poll can join it. Authentication has already succeeded.
    assert!(
        matches!(answer.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "a retiring established slot must defer the authenticated replacement"
    );
    assert_eq!(
        receiver.driver.budget.available().unwrap(),
        before - COMMAND_BYTES
    );
    assert_eq!(receiver.driver.connections, 1);
    release.send(()).unwrap();
    await_retirement(&mut receiver, old);
    assert!(
        matches!(answer.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "the existing scheduler backoff must still apply"
    );
    receiver.driver.started -= Duration::from_secs(2);
    receiver.tick();
    assert!(answer.try_recv().unwrap().is_ok());
    assert_eq!(receiver.driver.connections, 2);
    assert_eq!(receiver.driver.scheduler.status().established, 1);
    assert_eq!(
        receiver.driver.workers[&new].peer,
        Some(sender.driver.local)
    );
}

#[test]
fn deferred_authentication_has_one_original_five_second_deadline() {
    let (mut receiver, sender, _old, _release) = retiring_inbound_pair();
    let (new, _waiting) = waiting_worker(&mut receiver, None, None);
    let before = receiver.driver.budget.available().unwrap();
    let answer = submit_authenticated(&mut receiver, new, sender.driver.local);
    assert!(matches!(answer.try_recv(), Err(mpsc::TryRecvError::Empty)));
    receiver.driver.started -= Duration::from_secs(4);
    receiver.tick();
    assert!(matches!(answer.try_recv(), Err(mpsc::TryRecvError::Empty)));
    receiver.driver.started -= Duration::from_millis(1_100);
    receiver.tick();
    assert!(
        answer.try_recv().unwrap().is_err(),
        "polling must not renew the pending deadline"
    );
    assert_eq!(receiver.driver.budget.available().unwrap(), before);
    assert_eq!(receiver.driver.connections, 1);
}

#[test]
fn duplicate_deferred_authentication_cannot_replace_the_first_waiter() {
    let (mut receiver, sender, _old, _release) = retiring_inbound_pair();
    let (first, _first_wait) = waiting_worker(&mut receiver, None, None);
    let (second, _second_wait) = waiting_worker(&mut receiver, None, None);
    let before = receiver.driver.budget.available().unwrap();
    let first_answer = submit_authenticated(&mut receiver, first, sender.driver.local);
    assert!(matches!(
        first_answer.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let second_answer = submit_authenticated(&mut receiver, second, sender.driver.local);
    assert!(second_answer.try_recv().unwrap().is_err());
    assert!(matches!(
        first_answer.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert_eq!(
        receiver.driver.budget.available().unwrap(),
        before - COMMAND_BYTES
    );
    let repeated = submit_authenticated(&mut receiver, first, sender.driver.local);
    assert!(repeated.try_recv().unwrap().is_err());
    assert!(matches!(
        first_answer.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
}

#[test]
fn cancelled_deferred_authentication_releases_its_charge_without_admission() {
    let (mut receiver, sender, _old, _release) = retiring_inbound_pair();
    let (new, _waiting) = waiting_worker(&mut receiver, None, None);
    let answer = submit_authenticated(&mut receiver, new, sender.driver.local);
    assert!(matches!(answer.try_recv(), Err(mpsc::TryRecvError::Empty)));
    receiver.driver.workers[&new].cancel.cancel();
    receiver.tick();
    assert!(answer.try_recv().unwrap().is_err());
    assert_eq!(receiver.driver.connections, 1);
    assert_eq!(receiver.driver.scheduler.status().established, 1);
}

#[test]
fn deferred_authentication_never_reauthenticates_an_owned_established_worker() {
    let (mut receiver, sender, old, _release) = retiring_inbound_pair();
    let answer = submit_authenticated(&mut receiver, old, sender.driver.local);
    assert!(answer.try_recv().unwrap().is_err());
    assert_eq!(receiver.driver.connections, 1);
    assert_eq!(receiver.driver.scheduler.status().established, 1);
}

#[test]
fn finished_authenticated_worker_is_not_admitted_before_owner_retirement() {
    let (mut receiver, sender, _old, _release) = retiring_inbound_pair();
    let (new, release) = waiting_worker(&mut receiver, None, None);
    let before = receiver.driver.budget.available().unwrap();
    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !receiver.driver.workers[&new].join.is_finished() {
        assert!(Instant::now() < deadline, "test worker did not finish");
        std::thread::yield_now();
    }
    let answer = submit_authenticated(&mut receiver, new, sender.driver.local);
    assert!(answer.try_recv().unwrap().is_err());
    assert_eq!(receiver.driver.budget.available().unwrap(), before);
    assert_eq!(receiver.driver.connections, 1);
    assert_eq!(receiver.driver.scheduler.status().established, 1);
}

#[test]
fn deferred_authentication_shutdown_releases_pending_commands_and_worker_ownership() {
    let (mut receiver, sender, _old, _release) = retiring_inbound_pair();
    let (new, _waiting) = waiting_worker(&mut receiver, None, None);
    let answer = submit_authenticated(&mut receiver, new, sender.driver.local);
    assert!(matches!(answer.try_recv(), Err(mpsc::TryRecvError::Empty)));
    receiver.driver.shutdown().unwrap();
    assert!(answer.try_recv().is_err());
    assert!(receiver.driver.workers.is_empty());
    assert_eq!(receiver.driver.scheduler.status().established, 0);
    assert_eq!(receiver.driver.scheduler.status().pending, 0);
}

#[test]
fn actual_tls_replacement_survives_a_prior_authenticated_worker_still_returning_from_apply() {
    let (mut receiver, mut sender, old, release) = retiring_inbound_pair();
    sender.append(330_000);
    let deadline = Instant::now() + Duration::from_secs(5);
    let charged = loop {
        assert!(
            Instant::now() < deadline,
            "fresh authenticated ingress did not arrive"
        );
        sender.tick();
        receiver.driver.poll().unwrap();
        match receiver.driver.rx.recv_timeout(POLL) {
            Ok(command) if matches!(&command.command, Command::Authenticated { .. }) => {
                break command;
            }
            Ok(command) => receiver
                .driver
                .handle(receiver.node.as_mut().unwrap(), command)
                .unwrap(),
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(error) => panic!("owner command channel closed: {error}"),
        }
    };
    receiver
        .driver
        .handle(receiver.node.as_mut().unwrap(), charged)
        .unwrap();
    assert_eq!(receiver.driver.connections, 1);
    release.send(()).unwrap();
    until(&mut sender, &mut receiver, |a, b| {
        b.state().height == 1 && a.state().fingerprint() == b.state().fingerprint()
    });
    assert!(!receiver.driver.workers.contains_key(&old));
    assert_eq!(
        sender.driver.connections, 1,
        "the same fresh TLS session must be admitted"
    );
    assert_eq!(receiver.driver.connections, 2);
    assert_eq!(
        sender.driver.failures, 0,
        "receiver retirement must not trigger another dial"
    );
    assert_eq!(receiver.driver.failures, 1);
}

#[test]
fn proof_owner_delay_beyond_ten_seconds_preserves_the_paired_request_turn() {
    let mut initiator = Endpoint::new();
    let mut responder = Endpoint::new();
    if initiator.driver.local > responder.driver.local {
        std::mem::swap(&mut initiator, &mut responder);
    }
    initiator.append(350_000);
    initiator.follow(&responder);
    responder.follow(&initiator);
    let setup_deadline = Instant::now() + Duration::from_secs(5);
    let queued_pull = loop {
        assert!(
            Instant::now() < setup_deadline,
            "request turn was not reached"
        );
        initiator.driver.poll().unwrap();
        responder.tick();
        match initiator.driver.rx.recv_timeout(POLL) {
            Ok(charged) if matches!(&charged.command, Command::Pull { .. }) => break charged,
            Ok(charged) => initiator
                .driver
                .handle(initiator.node.as_mut().unwrap(), charged)
                .unwrap(),
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(error) => panic!("owner command channel closed: {error}"),
        }
    };
    // A synchronous proof batch occupies the sole consensus owner. Withhold
    // its queued next-request reply to reproduce the resulting socket state:
    // the other authenticated worker waits for GET_BLOCKS while no request can
    // yet be written. No synthetic proof is accepted as a cryptographic gate.
    let release_at = Instant::now() + Duration::from_millis(11_100);
    let (_keep_open, timer) = mpsc::channel::<()>();
    while Instant::now() < release_at {
        responder.tick();
        let _ = timer.recv_timeout(POLL);
    }
    assert_eq!(
        responder.driver.failures, 0,
        "the paired request expired while the remote proof owner was occupied"
    );
    assert_eq!(responder.driver.scheduler.status().established, 1);
    initiator
        .driver
        .handle(initiator.node.as_mut().unwrap(), queued_pull)
        .unwrap();
    until(&mut initiator, &mut responder, |a, b| {
        b.state().height == 1 && a.state().fingerprint() == b.state().fingerprint()
    });
    assert_eq!(initiator.driver.connections, 1);
    assert_eq!(responder.driver.connections, 1);
    assert_eq!(initiator.driver.failures, 0);
    assert_eq!(responder.driver.failures, 0);
}

#[test]
fn unauthenticated_slow_socket_never_holds_the_consensus_owner_or_peer_identity() {
    let mut node = Endpoint::new();
    let mut socket = TcpStream::connect(node.address()).unwrap();
    socket.write_all(ROUTE_MAGIC).unwrap();
    node.tick();
    assert_eq!(node.driver.workers.len(), 1);
    assert_eq!(node.driver.connections, 0);
    assert_eq!(node.driver.scheduler.status().pending, 0);
    assert!(
        node.driver
            .workers
            .values()
            .all(|worker| worker.peer.is_none() && worker.token.is_none())
    );
    // Only the owner touches the canonical store while socket admission waits.
    let started = Instant::now();
    node.append(400_000);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(node.state().height, 1);
    assert_eq!(node.driver.connections, 0);
    node.driver.shutdown().unwrap();
    assert!(node.driver.workers.is_empty());
    drop(socket);
}

#[test]
fn forged_routing_hint_cannot_penalize_or_establish_a_configured_identity() {
    let mut node = Endpoint::new();
    let peer = Endpoint::new();
    node.follow(&peer);
    let peer_id = peer.driver.local;
    // Suppress local dialing while exercising unauthenticated ingress. A routing
    // hint must not override this trusted local scheduling choice.
    node.driver
        .scheduler
        .disable(peer_id, node.driver.now())
        .unwrap();
    let mut socket = TcpStream::connect(node.address()).unwrap();
    let mut route = [0; 36];
    route[..4].copy_from_slice(ROUTE_MAGIC);
    route[4..].copy_from_slice(&peer_id);
    socket.write_all(&route).unwrap();
    node.tick();
    for _ in 0..4 {
        node.tick();
        std::thread::sleep(POLL);
    }
    assert_eq!(node.driver.connections, 0);
    let status = node.driver.scheduler.status();
    assert_eq!(
        (
            status.disabled,
            status.pending,
            status.established,
            status.closing
        ),
        (1, 0, 0, 0)
    );
    assert!(
        node.driver
            .workers
            .values()
            .all(|worker| worker.peer.is_none() && worker.token.is_none())
    );
    drop(socket);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !node.driver.workers.is_empty() {
        assert!(Instant::now() < deadline);
        node.tick();
        std::thread::sleep(POLL);
    }
    assert_eq!(node.driver.scheduler.status().disabled, 1);
}

#[test]
fn bounded_owner_command_wait_is_cancelled_without_needing_a_socket_response() {
    let budget = Budget::default();
    let cancellation = Cancellation::default();
    let signal = cancellation.clone();
    let inspected_budget = budget.clone();
    let (tx, receive) = mpsc::sync_channel(COMMAND_SLOTS);
    let thread = std::thread::spawn(move || {
        let started = Instant::now();
        let result: Result<Vec<u8>, runtime::Error> = call(&tx, &budget, &cancellation, |reply| {
            Command::Pull { id: 1, reply }
        });
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    });
    let queued = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    signal.cancel();
    thread.join().unwrap();
    assert!(inspected_budget.available().unwrap() < p2p::CONNECTION_BYTES);
    drop(queued);
    assert_eq!(inspected_budget.available().unwrap(), p2p::CONNECTION_BYTES);
}

#[test]
fn unpinned_configuration_is_rejected_even_with_a_valid_signed_descriptor() {
    let node = Endpoint::new();
    let peer = Endpoint::new();
    let descriptor = peer.driver.identity.descriptor().unwrap();
    let file = node.directory.0.join("peers.json");
    let value = json!({
        "version":1,"engineering":true,"listen":"127.0.0.1:0","mining":false,
        "peers":[{"endpoint":peer.address().to_string(),"fingerprint":local::hex(&descriptor.fingerprint()),"descriptor":local::hex(&descriptor.encode())}]
    });
    write_once(&file, &value).unwrap();
    assert!(
        Configuration::load(
            &node.directory.0,
            &file,
            p2p::Binding::new(&configuration()),
            node.driver.local
        )
        .is_err()
    );
    let pin = PeerPin::from_trusted_descriptor(&descriptor, &p2p::Binding::new(&configuration()))
        .unwrap();
    pin.persist(&node.directory.0).unwrap();
    let accepted = Configuration::load(
        &node.directory.0,
        &file,
        p2p::Binding::new(&configuration()),
        node.driver.local,
    )
    .unwrap();
    assert_eq!(accepted.peers.len(), 1);
    assert_eq!(
        accepted.peers.keys().copied().collect::<Vec<_>>(),
        vec![descriptor.fingerprint()]
    );
}

#[test]
fn public_resident_status_contains_only_aggregate_connection_health() {
    let mut node = Endpoint::new();
    let peer = Endpoint::new();
    node.follow(&peer);
    let status = node.driver.status(false);
    let object = status.as_object().unwrap();
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "authenticated_connections",
            "closed_connections",
            "closing",
            "configured",
            "connected",
            "disabled",
            "mining",
            "pending",
            "workers",
        ]
    );
    assert_eq!(status["configured"], 1);
    assert_eq!(status["connected"], 0);
    assert_eq!(status["mining"], false);
    let encoded = serde_json::to_string(&status).unwrap();
    assert!(!encoded.contains(&peer.address().to_string()));
    assert!(!encoded.contains(&local::hex(&peer.driver.local)));
    assert!(!encoded.contains("fee") && !encoded.contains("nullifier"));
}

#[test]
fn sixteenth_stalled_inbound_is_charged_and_seventeenth_is_closed_without_a_worker() {
    let mut node = Endpoint::new();
    let baseline = node.driver.budget.available().unwrap();
    let mut sockets: Vec<_> = (0..MAX_WORKERS + 1)
        .map(|_| TcpStream::connect(node.address()).unwrap())
        .collect();
    for _ in 0..5 {
        node.tick();
    }
    assert_eq!(node.driver.workers.len(), MAX_WORKERS);
    assert_eq!(node.driver.status(false)["workers"], MAX_WORKERS);
    assert_eq!(node.driver.connections, 0);
    assert!(
        node.driver
            .workers
            .values()
            .all(|worker| worker.peer.is_none() && worker.token.is_none())
    );
    let charged = baseline - node.driver.budget.available().unwrap();
    assert_eq!(charged, MAX_WORKERS * (WORKER_STACK + RELAY_TRACKING_BYTES));
    let mut excess = sockets.pop().unwrap();
    excess
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut byte = [0];
    match excess.read(&mut byte) {
        Ok(0) => (),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) => {}
        _ => panic!("excess inbound socket remained open"),
    }
    let started = Instant::now();
    node.driver.shutdown().unwrap();
    assert!(started.elapsed() < Duration::from_secs(6));
    assert!(node.driver.workers.is_empty());
    assert_eq!(node.driver.budget.available().unwrap(), baseline);
    assert_eq!(node.driver.scheduler.status().pending, 0);
    assert_eq!(node.driver.scheduler.status().established, 0);
    drop(sockets);
}

#[test]
fn cancelled_queued_apply_cannot_import_after_the_caller_has_left() {
    let mut owner = Endpoint::new();
    let peer = Endpoint::new();
    owner.follow(&peer);
    let budget = owner.driver.budget.clone();
    let baseline = budget.available().unwrap();
    let peer_id = peer.driver.local;
    let token = owner
        .driver
        .scheduler
        .begin(peer_id, Direction::Outbound, owner.driver.now())
        .unwrap()
        .token;
    owner
        .driver
        .scheduler
        .authenticated(token, owner.driver.now())
        .unwrap();
    let cancel = Cancellation::default();
    let worker_cancel = cancel.clone();
    let join = std::thread::spawn(move || {
        while !worker_cancel.is_cancelled() {
            std::thread::sleep(POLL);
        }
        Failure::Unavailable
    });
    let id = 1;
    owner.driver.workers.insert(
        id,
        Worker {
            sync_goal: None,
            sync_more: true,
            sync_complete: false,
            pull_fingerprint: None,
            peer: Some(peer_id),
            token: Some(token),
            cancel: cancel.clone(),
            join,
            sync: SyncAttempt::default(),
            acknowledged: BTreeSet::new(),
            _reservation: budget.reserve(WORKER_STACK + RELAY_TRACKING_BYTES).unwrap(),
        },
    );
    let base = owner.state().tip_snapshot().selector;
    owner_sync_command(&mut owner, |reply| Command::Pull { id, reply }).unwrap();
    let (begin_send, begin_receive) = mpsc::sync_channel(1);
    owner
        .driver
        .handle(
            owner.node.as_mut().unwrap(),
            ChargedCommand {
                command: Command::Begin {
                    id,
                    meta: ReplyMeta {
                        ancestor: base,
                        after: base,
                        count: 1,
                        more: false,
                    },
                    reply: begin_send,
                },
                _reservation: budget.reserve(COMMAND_BYTES).unwrap(),
            },
        )
        .unwrap();
    begin_receive
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap();
    let block = candidate(owner.state(), 500_000);
    let guard = budget
        .reserve(block.encoded_len().unwrap() + crate::wire::MAX_ENVELOPE_BYTES + 65536)
        .unwrap();
    let batch = Batch {
        ancestor: base,
        after: base,
        blocks: vec![block],
        more: false,
    };
    let tx = owner.driver.tx.clone();
    let waiter_cancel = cancel.clone();
    let waiter_budget = budget.clone();
    let waiter = std::thread::spawn(move || {
        let result: Result<bool, runtime::Error> =
            call(&tx, &waiter_budget, &waiter_cancel, |reply| {
                Command::Apply {
                    id,
                    batch,
                    guards: vec![guard],
                    reply,
                }
            });
        assert!(result.is_err());
    });
    let queued = owner
        .driver
        .rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let before = (
        owner.state().height,
        owner.state().tip,
        owner.state().fingerprint(),
    );
    cancel.cancel();
    waiter.join().unwrap();
    owner
        .driver
        .handle(owner.node.as_mut().unwrap(), queued)
        .unwrap();
    assert_eq!(
        (
            owner.state().height,
            owner.state().tip,
            owner.state().fingerprint()
        ),
        before
    );
    owner.driver.shutdown().unwrap();
    assert_eq!(budget.available().unwrap(), baseline);
}

#[test]
fn configuration_rejects_unknown_fields_missing_keys_and_implicit_engineering_mode() {
    let node = Endpoint::new();
    let binding = p2p::Binding::new(&configuration());
    let valid =
        json!({"version":1,"engineering":true,"listen":"127.0.0.1:0","mining":false,"peers":[]});
    let mut variants = Vec::new();
    let mut extra = valid.clone();
    extra["unknown"] = json!(true);
    variants.push(extra);
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("mining");
    variants.push(missing);
    let mut renamed = valid.clone();
    renamed.as_object_mut().unwrap().remove("mining");
    renamed["mine"] = json!(false);
    variants.push(renamed);
    let mut implicit = valid.clone();
    implicit["engineering"] = json!(false);
    variants.push(implicit);
    let mut invalid_peers = valid.clone();
    invalid_peers["peers"] = json!({});
    variants.push(invalid_peers);
    let mut invalid_bool = valid;
    invalid_bool["mining"] = json!(0);
    variants.push(invalid_bool);
    for (index, value) in variants.into_iter().enumerate() {
        let path = node.directory.0.join(format!("invalid-peers-{index}.json"));
        write_once(&path, &value).unwrap();
        assert!(Configuration::load(&node.directory.0, &path, binding, node.driver.local).is_err());
    }
}

#[test]
fn smaller_pinned_identity_alone_dials_and_both_sync_directions_survive_reconnect() {
    let mut smaller = Endpoint::new();
    let mut larger = Endpoint::new();
    if smaller.driver.local > larger.driver.local {
        std::mem::swap(&mut smaller, &mut larger);
    }
    smaller.follow(&larger);
    larger.follow(&smaller);
    larger.append(600_000);
    larger.tick();
    assert!(larger.driver.workers.is_empty());
    smaller.tick();
    assert_eq!(smaller.driver.workers.len(), 1);
    assert!(
        smaller
            .driver
            .workers
            .values()
            .all(|worker| worker.peer == Some(larger.driver.local) && worker.token.is_some())
    );
    until(&mut smaller, &mut larger, |a, b| {
        a.driver.scheduler.status().established == 1
            && b.driver.scheduler.status().established == 1
            && a.state().height == 1
            && a.state().fingerprint() == b.state().fingerprint()
    });
    let connections = (smaller.driver.connections, larger.driver.connections);
    for worker in smaller.driver.workers.values() {
        worker.cancel.cancel();
    }
    for worker in larger.driver.workers.values() {
        worker.cancel.cancel();
    }
    until(&mut smaller, &mut larger, |a, b| {
        a.driver.workers.is_empty() && b.driver.workers.is_empty()
    });
    // The other direction becomes the source after reconnect. Both configured
    // endpoint roles must still synchronize, although only one side dials.
    smaller.append(700_000);
    let ready = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < ready {
        larger.tick();
        assert!(larger.driver.workers.is_empty());
        std::thread::sleep(POLL);
    }
    smaller.tick();
    assert_eq!(smaller.driver.workers.len(), 1);
    assert!(
        smaller
            .driver
            .workers
            .values()
            .all(|worker| worker.peer == Some(larger.driver.local) && worker.token.is_some())
    );
    until(&mut smaller, &mut larger, |a, b| {
        a.driver.connections > connections.0
            && b.driver.connections > connections.1
            && b.state().height == 2
            && a.state().fingerprint() == b.state().fingerprint()
    });
    assert_eq!(smaller.driver.scheduler.status().established, 1);
    assert_eq!(larger.driver.scheduler.status().established, 1);
}

#[test]
fn two_producer_jobs_cannot_starve_maximum_block_peer_admission() {
    let producer = Budget::new(PRODUCER_TOTAL_BYTES);
    let peer = Budget::default();
    let baseline = peer.available().unwrap();
    let proving = producer.reserve(PRODUCER_JOB_BYTES).unwrap();
    let mining = producer.reserve(PRODUCER_JOB_BYTES).unwrap();
    assert_eq!(producer.available().unwrap(), 0);
    assert!(matches!(
        producer.reserve(PRODUCER_JOB_BYTES),
        Err(p2p::Error::ResourceExhausted)
    ));
    assert_eq!(peer.available().unwrap(), baseline);
    let imported = peer
        .reserve(crate::wire::MAX_BLOCK_BYTES + crate::wire::MAX_ENVELOPE_BYTES + 65536)
        .unwrap();
    assert!(peer.available().unwrap() < baseline);
    drop((proving, mining));
    assert_eq!(producer.available().unwrap(), PRODUCER_TOTAL_BYTES);
    drop(imported);
    assert_eq!(peer.available().unwrap(), baseline);
}

#[test]
fn pending_transaction_reaches_peer_before_block_inclusion_and_survives_reconnect() {
    use crate::wire::Sidecar;
    use native::codec::encode_digest;
    use native::multi_asset::{F, Hasher};
    use p3_field::PrimeCharacteristicRing;
    let mut a = Endpoint::new();
    let mut b = Endpoint::new();
    a.follow(&b);
    b.follow(&a);
    let mut tx = candidate(a.state(), 920_000).transactions.remove(0);
    tx.record.fee_commit = encode_digest(&Hasher::new().fee_commit(100, &[F::from_u32(33); 8]));
    let sidecar = Sidecar {
        transaction_id: tx.record.statement_id(&a.state().config.network),
        fee: 100,
        blind: [33; 8],
    };
    let envelope = tx.encode_envelope(&a.state().config.network).unwrap();
    let id = a
        .node
        .as_mut()
        .unwrap()
        .submit_local(&envelope, Some(&sidecar.encode().unwrap()))
        .unwrap();
    until(&mut a, &mut b, |a, b| {
        a.driver.connections > 0 && b.node.as_ref().unwrap().mempool().contains(&id)
    });
    assert_eq!(a.state().height, 0);
    assert_eq!(b.state().height, 0);
    let reconnects = a.driver.connections;
    for worker in a.driver.workers.values() {
        worker.cancel.cancel();
    }
    until(&mut a, &mut b, |a, b| {
        a.driver.connections > reconnects && b.driver.status(false)["connected"] == 1
    });
    assert_eq!(b.node.as_ref().unwrap().mempool().len(), 1);
    let node = a.node.as_mut().unwrap();
    let mut block = candidate(node.state(), 930_000);
    block.transactions[0] = tx;
    block
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&block.network));
    node.import_branch(0, &[block], CandidatePolicy::default())
        .unwrap();
    until(&mut a, &mut b, |a, b| {
        a.state().height == 1 && a.state().fingerprint() == b.state().fingerprint()
    });
    assert!(a.node.as_ref().unwrap().mempool().is_empty());
    assert!(b.node.as_ref().unwrap().mempool().is_empty());
}

#[test]
fn outbound_only_miner_with_larger_identity_syncs_without_a_listener() {
    let mut miner = Endpoint::new();
    let mut source = Endpoint::new();
    if miner.driver.local < source.driver.local {
        std::mem::swap(&mut miner, &mut source);
    }
    source.append(710_000);
    miner.follow(&source);
    source.follow(&miner);
    // The source knows this identity is an outbound-only client.
    let mut peers = (*source.driver.peers).clone();
    peers.get_mut(&miner.driver.local).unwrap().dial = false;
    source.driver.peers = Arc::new(peers);
    miner.driver.listener = None;
    until(&mut miner, &mut source, |miner, source| {
        miner.driver.scheduler.status().established == 1
            && source.driver.scheduler.status().established == 1
            && miner.state().tip == source.state().tip
            && miner.driver.has_synced_peer()
    });
    assert!(miner.driver.listener.is_none());
    assert_eq!(miner.state().height, 1);
}

#[cfg(unix)]
#[test]
fn fresh_peer_downloads_checkpoint_prefix_and_verified_tail_over_authenticated_p2p() {
    use crate::{
        checkpoint_service::Coordinator,
        engineering_checkpoint::{self as auth, Certificate, Roster},
        identity::checkpoint_authority::Authority,
        storage_policy::Role,
    };
    let mut source = Endpoint::with_storage_role(Some(Role::Bootstrap));
    let mut target = Endpoint::new();
    for index in 0..96 {
        source.append(950_000_000 + index * 100_000);
    }
    let second_key = Directory::new();
    let binding = p2p::Binding::new(&configuration());
    let a = Authority::initialize(&source.directory.0, binding).unwrap();
    let b = Authority::initialize(&second_key.0, binding).unwrap();
    let roster = Roster::new(binding, [a.public_key(), b.public_key()]).unwrap();
    let now = wall_ms().unwrap() / 1000;
    let sequence = now / auth::INTERVAL_SECONDS;
    let candidate = source
        .node
        .as_ref()
        .unwrap()
        .store()
        .engineering_checkpoint_candidate(
            &roster,
            72,
            sequence,
            sequence * auth::INTERVAL_SECONDS,
            &TestVerifier,
        )
        .unwrap();
    let certificate = Certificate {
        statement: candidate.statement().clone(),
        votes: vec![
            a.sign(&candidate, &roster).unwrap(),
            b.sign(&candidate, &roster).unwrap(),
        ],
    };
    source
        .node
        .as_mut()
        .unwrap()
        .resident_accept_checkpoint(&certificate, &roster, now, &candidate)
        .unwrap();
    let mut source_checkpoints =
        Coordinator::for_test(&source.directory.0, roster.clone()).unwrap();
    source_checkpoints
        .poll(source.node.as_mut().unwrap(), now)
        .unwrap();
    source.driver.checkpoints = Some(source_checkpoints);
    target.driver.checkpoints = Some(Coordinator::for_test(&target.directory.0, roster).unwrap());
    source.follow(&target);
    target.follow(&source);
    let started = Instant::now();
    while target.state().height != 96 {
        assert!(
            started.elapsed() < Duration::from_secs(300),
            "checkpoint loopback did not finish: {:?}",
            target
                .driver
                .checkpoints
                .as_ref()
                .unwrap()
                .metrics(wall_ms().unwrap() / 1000)
        );
        source.tick();
        target.tick();
        std::thread::sleep(POLL);
    }
    assert_eq!(target.state().fingerprint(), source.state().fingerprint());
    let store = target.node.as_ref().unwrap().store();
    assert_eq!(
        store
            .latest_engineering_checkpoint()
            .unwrap()
            .unwrap()
            .statement
            .height,
        72
    );
    // This distinguishes compact-prefix bootstrap from ordinary full history.
    assert!(store.block(1).is_err());
    assert!(store.public_compact_block(1).is_ok());
    assert!(store.block(73).is_ok());
    assert!(target.driver.checkpoints.as_ref().unwrap().alert.is_none());
    assert!(!target.driver.checkpoints.as_ref().unwrap().is_catching_up());
    let receipt: Value = serde_json::from_slice(
        &std::fs::read(target.directory.0.join("checkpoint-recovery-receipt.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["schema_version"], 1);
    assert_eq!(receipt["phase"], "completed");
    assert_eq!(receipt["checkpoint_height"], 72);
    assert_eq!(receipt["checkpoint_sequence"], sequence);
    assert_eq!(receipt["final_height"], 96);
    assert_eq!(receipt["final_tip"], local::hex(&target.state().tip));
    assert_eq!(
        receipt["final_state_fingerprint"],
        local::hex(&target.state().fingerprint())
    );
    assert_eq!(
        receipt["final_cumulative_work"],
        local::hex(&target.state().cumulative_work.to_big_endian())
    );
    let expected_bytes: u64 = (1..=72)
        .map(|height| store.public_compact_block(height).unwrap().len() as u64)
        .chain((73..=96).map(|height| store.block(height).unwrap().encoded_len().unwrap() as u64))
        .sum();
    assert_eq!(receipt["downloaded_bytes"], expected_bytes);
    assert!(receipt["elapsed_monotonic_ms"].as_u64().unwrap() > 0);
    assert!(
        receipt["started_unix_seconds"].as_u64().unwrap()
            <= receipt["completed_unix_seconds"].as_u64().unwrap()
    );
}

fn admit_fixture(provider: &mut Endpoint, fixture: &Endpoint) {
    let descriptor = fixture.driver.identity.descriptor().unwrap();
    let public = json!({"version":1,"fingerprint":local::hex(&descriptor.fingerprint()),
        "descriptor":local::hex(&descriptor.encode())});
    let public_file = fixture.directory.0.join("fixture-public.json");
    atomic_json(&public_file, &public).unwrap();
    let run = "a".repeat(64);
    atomic_json(
        &provider.directory.0.join(STATUS_FILE),
        &json!({"run_id":run,"phase":"networking","updated_unix_ms":wall_ms().unwrap()}),
    )
    .unwrap();
    super::super::fixture_control::request_fixture_admission(
        &provider.directory.0,
        &run,
        "checkpoint-test",
        &public_file,
        public["fingerprint"].as_str().unwrap(),
    )
    .unwrap();
    // The test coordinator has the same public roster, without authority keys.
    let second = Directory::new();
    let binding = p2p::Binding::new(&configuration());
    let a = crate::identity::checkpoint_authority::Authority::initialize(
        &provider.directory.0,
        binding,
    )
    .unwrap();
    let b =
        crate::identity::checkpoint_authority::Authority::initialize(&second.0, binding).unwrap();
    let roster =
        crate::engineering_checkpoint::Roster::new(binding, [a.public_key(), b.public_key()])
            .unwrap();
    provider.driver.checkpoints = Some(
        crate::checkpoint_service::Coordinator::for_test(&provider.directory.0, roster).unwrap(),
    );
    provider
        .driver
        .poll_fixture_admission(&provider.directory.0, &run, binding);
    assert!(provider.driver.fixture.is_some());
    assert!(provider.driver.peers.is_empty());
    assert_eq!(provider.driver.scheduler.status().configured, 1);
}

#[test]
fn live_fixture_admission_authenticates_without_dial_or_peer_file_change() {
    let mut provider = Endpoint::new();
    let mut fixture = Endpoint::new();
    fixture.follow(&provider);
    fixture.driver.listener = None;
    admit_fixture(&mut provider, &fixture);
    provider.append(81);
    until(&mut provider, &mut fixture, |a, b| {
        a.driver.scheduler.status().established == 1 && b.state().height == a.state().height
    });
    assert_eq!(
        provider.state().fingerprint(),
        fixture.state().fingerprint()
    );
    assert!(!fixture.driver.status(false)["mining"].as_bool().unwrap());
    assert!(!provider.directory.0.join("fixture-peers.json").exists());
    assert_eq!(
        provider
            .driver
            .workers
            .values()
            .filter(|w| w.token.is_some())
            .count(),
        1
    );
}

#[test]
fn live_fixture_admission_rejects_mining_hello_before_owner_authentication() {
    let mut provider = Endpoint::new();
    let mut fixture = Endpoint::new();
    fixture.follow(&provider);
    fixture.driver.listener = None;
    fixture.driver.role = Role::Miner;
    admit_fixture(&mut provider, &fixture);
    until(&mut provider, &mut fixture, |a, _| a.driver.failures > 0);
    assert_eq!(provider.driver.connections, 0);
    assert_eq!(provider.driver.scheduler.status().established, 0);
}

fn owner_sync_command<T>(
    endpoint: &mut Endpoint,
    make: impl FnOnce(Answer<T>) -> Command,
) -> Result<T, runtime::Error> {
    let (reply, receive) = mpsc::sync_channel(1);
    let charged = ChargedCommand {
        command: make(reply),
        _reservation: endpoint.driver.budget.reserve(COMMAND_BYTES).unwrap(),
    };
    endpoint
        .driver
        .handle(endpoint.node.as_mut().unwrap(), charged)
        .unwrap();
    receive.recv_timeout(Duration::from_secs(1)).unwrap()
}

fn owner_sync_begin(
    endpoint: &mut Endpoint,
    id: u64,
    base: crate::wire::Snapshot,
    count: u16,
) -> Result<(), runtime::Error> {
    owner_sync_command(endpoint, |reply| Command::Begin {
        id,
        meta: ReplyMeta {
            ancestor: base,
            after: base,
            count,
            more: false,
        },
        reply,
    })
}

fn owner_sync_apply(
    endpoint: &mut Endpoint,
    id: u64,
    base: crate::wire::Snapshot,
    blocks: Vec<crate::wire::Block>,
) -> Result<bool, runtime::Error> {
    let guards = blocks
        .iter()
        .map(|block| {
            endpoint
                .driver
                .budget
                .reserve(block.encoded_len().unwrap() + crate::wire::MAX_ENVELOPE_BYTES + 65536)
                .unwrap()
        })
        .collect();
    owner_sync_command(endpoint, |reply| Command::Apply {
        id,
        batch: Batch {
            ancestor: base,
            after: base,
            blocks,
            more: false,
        },
        guards,
        reply,
    })
}

#[test]
fn stale_sync_metadata_after_owner_advance_retries_before_staging() {
    let (mut owner, _peer, id, _release) = retiring_inbound_pair();
    let old_base = owner.state().tip_snapshot().selector;
    owner_sync_command(&mut owner, |reply| Command::Pull { id, reply }).unwrap();
    owner.append(600_000);
    let advanced = owner.state().fingerprint();
    assert!(matches!(
        owner_sync_begin(&mut owner, id, old_base, 1),
        Err(runtime::Error::Transport(p2p::Error::Unavailable))
    ));
    assert_eq!(owner.state().fingerprint(), advanced);
    assert_eq!(owner.driver.scheduler.status().disabled, 0);
    assert!(!owner.driver.workers[&id].sync_complete);

    // A fresh request can still import a completely validated extension.
    let base = owner.state().tip_snapshot().selector;
    let block = candidate(owner.state(), 800_000);
    let expected = block.id().unwrap();
    owner_sync_command(&mut owner, |reply| Command::Pull { id, reply }).unwrap();
    owner_sync_begin(&mut owner, id, base, 1).unwrap();
    owner_sync_apply(&mut owner, id, base, vec![block]).unwrap();
    assert_eq!(owner.state().height, 2);
    assert_eq!(owner.state().tip, expected);
}

#[test]
fn same_epoch_competing_branch_retains_full_proof_validation() {
    let (mut owner, _peer, id, _release) = retiring_inbound_pair();
    let mut alternative = owner.state().clone();
    let base = alternative.tip_snapshot().selector;
    owner.append(1_000_000);
    let before = owner.state().fingerprint();
    let first = candidate(&alternative, 2_000_000);
    alternative.apply(&first, &TestVerifier).unwrap();
    let second = candidate(&alternative, 3_000_000);
    alternative.apply(&second, &TestVerifier).unwrap();
    let mut invalid = second.clone();
    invalid.transactions[0].proof = vec![2];

    owner_sync_command(&mut owner, |reply| Command::Pull { id, reply }).unwrap();
    owner_sync_begin(&mut owner, id, base, 2).unwrap();
    assert!(matches!(
        owner_sync_apply(&mut owner, id, base, vec![first.clone(), invalid]),
        Err(runtime::Error::Chain(crate::chain::ChainError::Invalid(_)))
    ));
    assert_eq!(owner.state().fingerprint(), before);

    owner_sync_command(&mut owner, |reply| Command::Pull { id, reply }).unwrap();
    owner_sync_begin(&mut owner, id, base, 2).unwrap();
    owner_sync_apply(&mut owner, id, base, vec![first, second]).unwrap();
    assert_eq!(owner.state().fingerprint(), alternative.fingerprint());
}

#[test]
fn synchronization_metadata_without_an_owned_pull_is_retryable() {
    let (mut owner, _peer, id, _release) = retiring_inbound_pair();
    let base = owner.state().tip_snapshot().selector;
    let before = owner.state().fingerprint();
    assert!(matches!(
        owner_sync_begin(&mut owner, id, base, 1),
        Err(runtime::Error::Transport(p2p::Error::Unavailable))
    ));
    assert_eq!(owner.state().fingerprint(), before);
    assert_eq!(owner.driver.scheduler.status().disabled, 0);
}
