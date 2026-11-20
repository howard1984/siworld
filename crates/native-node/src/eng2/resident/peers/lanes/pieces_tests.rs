use super::*;
use std::{os::unix::net::UnixStream, path::PathBuf, thread};
struct Fixture {
    shared: Arc<Shared>,
    genesis: Genesis,
    remote: Hash,
    directory: PathBuf,
    _connection: super::super::Connected,
}
fn fixture(role: p2p::Role, remote_role: p2p::Role, seed: u8) -> Fixture {
    fixture_with_expected(role, remote_role, seed, None)
}
fn fixture_with_expected(
    role: p2p::Role,
    remote_role: p2p::Role,
    seed: u8,
    trusted: Option<p2p::ExpectedPeer>,
) -> Fixture {
    fixture_with_sources(role, remote_role, seed, trusted, &[])
}
fn fixture_with_sources(
    role: p2p::Role,
    remote_role: p2p::Role,
    seed: u8,
    trusted: Option<p2p::ExpectedPeer>,
    additional_seeds: &[u8],
) -> Fixture {
    let state = crate::eng2::snapshot::tests::bootstrap();

    let genesis = Genesis::seal(
        state.chain.config,
        state.governance,
        crate::eng2::genesis::FeeMode::LegacyMiner,
    )
    .unwrap();
    let expected =
        trusted.unwrap_or_else(|| p2p::test_support::expected(genesis.peer_binding(), [seed; 32]));
    let remote = expected.fingerprint();
    let mut entropy = [0; 16];
    getrandom::fill(&mut entropy).unwrap();
    let directory = std::env::temp_dir().join(format!(
        "eng2-piece-adapter-{}",
        crate::local::hex(&entropy)
    ));
    std::fs::create_dir(&directory).unwrap();
    let limits = crate::eng2::snapshot::tests::limits();
    let store = Store::create(
        &directory.join("chain.redb"),
        Genesis::decode(&genesis.encode().unwrap()).unwrap(),
        limits.chain,
    )
    .unwrap();

    let verifier = NativeVerifier::for_genesis(store.engine().genesis()).unwrap();

    let mut driver = Driver::new(store, verifier, limits).unwrap();
    let budget = p2p::Budget::new(MEMORY_BYTES);
    let rules = crate::eng2::selection::HeaderRules {
        network: genesis.config().network,
        genesis: genesis.id(),
        genesis_timestamp: genesis.config().genesis_timestamp,
        genesis_target: genesis.config().genesis_target,
        target_interval: genesis.config().target_interval,
        pow_iterations: genesis.config().pow_iterations,
        max_headers: 128,
    };
    let branches = crate::eng2::branches::BranchStore::create(
        &directory.join("branches.redb"),
        rules,
        crate::eng2::branches::Limits {
            maximum_headers: 128,
            maximum_body_bytes: 64 * 1024 * 1024,
        },
    )
    .unwrap();
    driver
        .enable_reorganization_with_budget(branches, budget.clone())
        .unwrap();
    let mut peers = vec![expected];
    peers.extend(
        additional_seeds
            .iter()
            .map(|&value| p2p::test_support::expected(genesis.peer_binding(), [value; 32])),
    );
    let config = config::Configuration {
        role,
        proof_retention: None,
        listen: None,
        mining: false,
        peers: peers
            .into_iter()
            .map(|expected| config::Destination {
                endpoint: "127.0.0.1:1".parse().unwrap(),
                dial: false,
                checkpoint_reference: false,
                expected,
            })
            .collect(),
        fixed_relay_peers: std::collections::BTreeSet::from([remote]),
        checkpoint_key: None,
        legacy_checkpoint_peers: Default::default(),
        digest: String::new(),
    };

    let headers = Arc::new(header_lane::Hub::new(&driver, &budget, [99; 32]).unwrap());
    driver.observe_headers(headers.clone());
    let network = Arc::new(NetworkStatus::with_pinned_peers(
        config
            .peers
            .iter()
            .map(|peer| (peer.expected.fingerprint(), false)),
    ));
    let connection = network.connected(remote).unwrap();
    network.admit_lane(remote, Lane::Bodies).unwrap();
    let shared = Arc::new(Shared {
        transfers: transfers::Transfers::new(&config, &budget).unwrap(),
        relay: relay::Relay::new(&config, driver.engine().body_policy(), &budget).unwrap(),
        bodies: body_admission::Queue::default(),
        headers,
        owner: Arc::new(Mutex::new(driver)),
        #[cfg(feature = "eng2-rehearsal")]
        isolated_production: Mutex::new(None),
        block_events: Arc::new(block_events::Recorder::new(
            &directory,
            genesis.config().network,
            genesis.id(),
            None,
            "",
            "",
        )),
        cancel: p2p::Cancellation::default(),
        network,
        production: Mutex::new(ProductionStatus::default()),
        checkpoint_observer: Mutex::new(
            crate::eng2::checkpoint_observer::Observer::new(&budget).unwrap(),
        ),
        legacy_checkpoint_peers: Default::default(),
        budget: budget.clone(),
        _pool_charge: budget.reserve(2 * crate::pool::MAX_BYTES).unwrap(),
        operations: None,
        mailbox: Arc::new(CheckpointMailbox::new(budget)),
    });
    assert!(shared.relay.selected(remote, remote_role));

    Fixture {
        shared,
        genesis,
        remote,
        directory,
        _connection: connection,
    }
}

#[test]
fn live_tip_session_can_join_an_offer_transfer_without_an_extra_descriptor() {
    let source = fixture(p2p::Role::Miner, p2p::Role::Validator, 2);
    let receiver = fixture_with_sources(p2p::Role::Validator, p2p::Role::Miner, 1, None, &[3]);
    let header = produced(&source, 25);
    let id = header.id().unwrap();
    let alternate =
        p2p::test_support::expected(receiver.genesis.peer_binding(), [3; 32]).fingerprint();
    let _connection = receiver.shared.network.connected(alternate).unwrap();
    receiver
        .shared
        .network
        .admit_lane(alternate, Lane::Bodies)
        .unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    let mut source_peer = peer(a, &source, p2p::Role::Validator);
    let mut receiver_peer = peer(b, &receiver, p2p::Role::Miner);
    let source_shared = source.shared.clone();
    let worker = thread::spawn(move || {
        assert!(source_peer.probe_propagation(2).unwrap());
        source_peer.finish_round(2).unwrap();
        assert!(offer(&mut source_peer, &source_shared, 3).unwrap());
        source_peer.finish_round(3).unwrap();
        let mut incoming = 1;
        super::super::serve_turn(&mut source_peer, &source_shared, &mut incoming).unwrap();
    });
    let mut incoming = 1;
    super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
    super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
    let (a, b) = UnixStream::pair().unwrap();
    a.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut alternate_peer = Peer::new(
        p2p::Session::from_test_peer_channel(
            a,
            receiver.genesis.peer_binding(),
            receiver.shared.budget.clone(),
            alternate,
            p2p::Role::Miner,
        ),
        &receiver.genesis,
        receiver.shared.headers.body_policy(),
    )
    .unwrap();
    let mut alternate_server = peer(b, &source, p2p::Role::Validator);
    assert!(!pull_batch(&mut alternate_peer, &receiver.shared, 2).unwrap());
    receiver
        .shared
        .headers
        .observe_body_tip(
            alternate,
            alternate_peer.propagation_session_id(),
            header.height,
            id,
        )
        .unwrap();
    assert!(!pull_batch(&mut alternate_peer, &receiver.shared, 2).unwrap());
    let source_shared = source.shared.clone();
    let second = thread::spawn(move || {
        let mut incoming = 1;
        super::super::serve_turn(&mut alternate_server, &source_shared, &mut incoming).unwrap();
        super::super::receive_turn(
            &mut alternate_server,
            &mut incoming,
            |peer, request, message| {
                assert!(matches!(message, crate::eng2::transport::Request::GetTip));
                peer.advertise_tip(request, header.height, id).unwrap();
                Ok(())
            },
        )
        .unwrap();
        super::super::serve_turn(&mut alternate_server, &source_shared, &mut incoming).unwrap();
    });
    assert!(alternate_peer.probe_propagation(2).unwrap());
    alternate_peer.finish_round(2).unwrap();
    super::super::refresh_body_tip(&mut alternate_peer, &receiver.shared.headers, 3).unwrap();
    alternate_peer.finish_round(3).unwrap();
    let stale_session = alternate_peer.propagation_session_id().wrapping_add(1);
    let connected = receiver.shared.network.body_sources().unwrap();
    assert!(
        !receiver
            .shared
            .headers
            .piece_sources(id, alternate, stale_session, &connected)
            .unwrap()
            .contains(&alternate)
    );
    thread::scope(|scope| {
        scope.spawn(|| {
            assert!(pull_batch(&mut receiver_peer, &receiver.shared, 2).unwrap());
            receiver_peer.finish_round(2).unwrap();
        });
        assert!(pull_batch(&mut alternate_peer, &receiver.shared, 4).unwrap());
        alternate_peer.finish_round(4).unwrap();
    });
    worker.join().unwrap();
    second.join().unwrap();
    assert_eq!(
        receiver.shared.budget.body_registry_diagnostic()["window_queries"],
        3
    );
    receiver.shared.transfers.reap(&receiver.shared).unwrap();
    assert_eq!(receiver.shared.transfers.diagnostic()["decoded"], 1);
    assert!(!pull_batch(&mut alternate_peer, &receiver.shared, 5).unwrap());
    receiver.shared.bodies.clear().unwrap();
    drop(alternate_peer);
    drop(receiver_peer);
    drop(source.shared);
    drop(receiver.shared);
    std::fs::remove_dir_all(source.directory).unwrap();
    std::fs::remove_dir_all(receiver.directory).unwrap();
}
fn peer(socket: UnixStream, fixture: &Fixture, role: p2p::Role) -> Peer<UnixStream> {
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    Peer::new(
        p2p::Session::from_test_peer_channel(
            socket,
            fixture.genesis.peer_binding(),
            fixture.shared.budget.clone(),
            fixture.remote,
            role,
        ),
        &fixture.genesis,
        fixture.shared.headers.body_policy(),
    )
    .unwrap()
}
fn assert_body_resources_released(fixture: &Fixture, before: usize, expected_accounts: usize) {
    let (accounts, metadata) = fixture.shared.budget.retained_body_accounting();
    assert_eq!(accounts, expected_accounts);
    assert!(metadata > 0);
    // Failed and retained candidates keep charged account and pin metadata;
    // physical I/O, decoded buffers and queue owners must all have released.
    assert_eq!(
        fixture.shared.budget.available().unwrap() + metadata,
        before
    );
}
fn produced(fixture: &Fixture, tag: u8) -> Header {
    let mut body = crate::eng2::body::tests::body();
    body.network = fixture.genesis.config().network;
    body.height = 1;
    body.profile = fixture.shared.headers.body_policy().profile;
    body.governance.clear();
    body.fund_claims.clear();
    body.issuances.clear();
    body.transactions
        .sort_by_key(|tx| tx.record.statement_id(&body.network));
    body.settlement_proof = vec![tag; 32 * 4096];
    let config = fixture.genesis.config();
    let header = Header {
        network: body.network,
        height: 1,
        parent: fixture.genesis.id(),
        timestamp: config.genesis_timestamp + config.target_interval,
        target: config.genesis_target,
        execution_commitment: [tag; 32],
        body_commitment: body
            .commitment(fixture.shared.headers.body_policy())
            .unwrap(),
        nonce: 0,
    };
    fixture
        .shared
        .headers
        .produced(header.clone(), Arc::new(body))
        .unwrap();
    header
}
#[test]
fn miner_offer_and_service_batch_use_the_real_adapter_and_keep_outer_request() {
    let source = fixture(p2p::Role::Miner, p2p::Role::Validator, 2);
    let receiver = fixture(p2p::Role::Validator, p2p::Role::Miner, 1);
    let header = produced(&source, 4);
    // Independent fixture pins bind different synthetic identities. Supply
    // the exact configured identity and role through the test-only channel.
    let (a, b) = UnixStream::pair().unwrap();
    let mut source_peer = peer(a, &source, p2p::Role::Validator);
    let mut receiver_peer = peer(b, &receiver, p2p::Role::Miner);
    let source_shared = source.shared.clone();
    let receiver_shared = receiver.shared.clone();
    let before = receiver.shared.budget.available().unwrap();
    let worker = thread::spawn(move || {
        assert!(source_peer.probe_propagation(2).unwrap());
        source_peer.finish_round(2).unwrap();
        assert!(offer(&mut source_peer, &source_shared, 3).unwrap());
        source_peer.finish_round(3).unwrap();
        let mut incoming = 1;
        super::super::serve_turn(&mut source_peer, &source_shared, &mut incoming).unwrap();
        assert_eq!(incoming, 2);
    });
    let mut incoming = 1;
    super::super::serve_turn(&mut receiver_peer, &receiver_shared, &mut incoming).unwrap();
    assert_eq!(incoming, 2);
    super::super::serve_turn(&mut receiver_peer, &receiver_shared, &mut incoming).unwrap();
    assert_eq!(incoming, 3);
    assert_eq!(receiver.shared.transfers.diagnostic()["active"], 1);
    assert!(pull_batch(&mut receiver_peer, &receiver_shared, 2).unwrap());
    receiver_peer.finish_round(2).unwrap();
    worker.join().unwrap();
    receiver.shared.transfers.reap(&receiver.shared).unwrap();
    assert_eq!(receiver.shared.transfers.diagnostic()["active"], 0);
    assert_eq!(receiver.shared.transfers.diagnostic()["decoded"], 1);
    assert_eq!(receiver.shared.headers.active_downloads(), 1);
    receiver.shared.bodies.clear().unwrap();
    assert_eq!(receiver.shared.headers.active_downloads(), 0);
    assert_body_resources_released(&receiver, before, 1);
    assert_eq!(header.height, 1);
    drop(receiver_peer);
    drop(receiver_shared);
    drop(source.shared);
    drop(receiver.shared);
    std::fs::remove_dir_all(source.directory).unwrap();
    std::fs::remove_dir_all(receiver.directory).unwrap();
}
#[test]
fn cancelled_candidate_keeps_its_claim_until_the_inflight_adapter_worker_releases() {
    let source = fixture(p2p::Role::Miner, p2p::Role::Validator, 2);
    let receiver = fixture(p2p::Role::Validator, p2p::Role::Miner, 1);
    let header = produced(&source, 5);
    let (a, b) = UnixStream::pair().unwrap();
    let mut source_peer = peer(a, &source, p2p::Role::Validator);
    let mut receiver_peer = peer(b, &receiver, p2p::Role::Miner);
    let source_shared = source.shared.clone();
    let before = receiver.shared.budget.available().unwrap();
    let worker = thread::spawn(move || {
        assert!(source_peer.probe_propagation(2).unwrap());
        source_peer.finish_round(2).unwrap();
        assert!(offer(&mut source_peer, &source_shared, 3).unwrap());
        source_peer.finish_round(3).unwrap();
    });
    let mut incoming = 1;
    super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
    super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
    worker.join().unwrap();
    let (inflight, requests) = receiver
        .shared
        .transfers
        .batch(
            receiver.remote,
            receiver_peer.propagation_session_id(),
            &receiver.shared.headers,
            &receiver.shared.network.body_sources().unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(!requests.is_empty());
    // A qualified replacement source also announces its exact canonical tip.
    receiver
        .shared
        .headers
        .offer(header.clone(), [7; 32])
        .unwrap();
    receiver
        .shared
        .headers
        .observe_body_tip([7; 32], 71, header.height, header.id().unwrap())
        .unwrap();
    receiver.shared.transfers.cancel();
    receiver.shared.transfers.reap(&receiver.shared).unwrap();
    assert_eq!(receiver.shared.transfers.diagnostic()["active"], 1);
    assert!(
        receiver
            .shared
            .headers
            .download_exact([7; 32], header.id().unwrap())
            .unwrap()
            .is_none()
    );
    assert!(inflight.ownership.deadline().check().is_err());
    drop(inflight);
    receiver.shared.transfers.reap(&receiver.shared).unwrap();
    assert_eq!(receiver.shared.transfers.diagnostic()["active"], 0);
    assert_eq!(receiver.shared.transfers.diagnostic()["failed"], 1);
    // This failed Pieces attempt must select whole-body fallback. The test
    // helper download_exact intentionally requests Pieces and remains denied.
    assert!(
        receiver
            .shared
            .headers
            .download_exact([7; 32], header.id().unwrap())
            .unwrap()
            .is_none()
    );
    let replacement = receiver
        .shared
        .headers
        .download_preferred(
            [7; 32],
            p2p::BodyMode::Legacy,
            Some(header.id().unwrap()),
            &Default::default(),
        )
        .unwrap()
        .unwrap();
    drop(replacement);
    assert_eq!(receiver.shared.headers.active_downloads(), 0);
    assert_body_resources_released(&receiver, before, 1);
    drop(receiver_peer);
    drop(source.shared);
    drop(receiver.shared);
    std::fs::remove_dir_all(source.directory).unwrap();
    std::fs::remove_dir_all(receiver.directory).unwrap();
}

struct FaultStream {
    socket: UnixStream,
    armed: Arc<std::sync::atomic::AtomicBool>,
    mode: u8,
    header: Vec<u8>,
    fired: bool,
}
impl std::io::Read for FaultStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(&mut self.socket, bytes)
    }
}
impl std::io::Write for FaultStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.armed.load(std::sync::atomic::Ordering::Acquire) && !self.fired {
            if bytes.starts_with(b"SWPF") {
                self.header = bytes.to_vec();
            }
            if bytes.len() > 38 && bytes[..2] == [0x41, 1] {
                self.fired = true;
                if self.mode == 1 {
                    return Err(std::io::ErrorKind::ConnectionReset.into());
                }
                let mut frame = bytes.to_vec();
                if self.mode == 0 {
                    frame[38] ^= 1;
                }
                self.socket.write_all(&frame)?;
                if self.mode == 2 {
                    self.socket.write_all(&self.header)?;
                    self.socket.write_all(bytes)?;
                }
                return Ok(bytes.len());
            }
        }
        self.socket.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.socket)
    }
}
#[test]
fn corrupt_disconnected_and_duplicate_sources_never_reach_the_admission_queue() {
    for mode in 0..3 {
        let source = fixture(p2p::Role::Miner, p2p::Role::Validator, 2);
        let receiver = fixture(p2p::Role::Validator, p2p::Role::Miner, 1);
        produced(&source, 6);
        let (a, b) = UnixStream::pair().unwrap();
        a.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        a.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let source_stream = FaultStream {
            socket: a,
            armed: armed.clone(),
            mode,
            header: Vec::new(),
            fired: false,
        };
        let mut source_peer = Peer::new(
            p2p::Session::from_test_peer_channel(
                source_stream,
                source.genesis.peer_binding(),
                source.shared.budget.clone(),
                source.remote,
                p2p::Role::Validator,
            ),
            &source.genesis,
            source.shared.headers.body_policy(),
        )
        .unwrap();
        let mut receiver_peer = peer(b, &receiver, p2p::Role::Miner);
        let source_shared = source.shared.clone();
        let before = receiver.shared.budget.available().unwrap();
        let worker = thread::spawn(move || {
            assert!(source_peer.probe_propagation(2).unwrap());
            source_peer.finish_round(2).unwrap();
            assert!(offer(&mut source_peer, &source_shared, 3).unwrap());
            source_peer.finish_round(3).unwrap();
            armed.store(true, std::sync::atomic::Ordering::Release);
            let mut incoming = 1;
            let _ = super::super::serve_turn(&mut source_peer, &source_shared, &mut incoming);
        });
        let mut incoming = 1;
        super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
        super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
        assert!(pull_batch(&mut receiver_peer, &receiver.shared, 2).is_err());
        drop(receiver_peer);
        worker.join().unwrap();
        receiver.shared.transfers.cancel();
        receiver.shared.transfers.reap(&receiver.shared).unwrap();
        assert_eq!(receiver.shared.transfers.diagnostic()["decoded"], 0);
        assert_eq!(receiver.shared.transfers.diagnostic()["active"], 0);
        assert_eq!(receiver.shared.headers.active_downloads(), 0);
        assert_body_resources_released(&receiver, before, 1);
        drop(source.shared);
        drop(receiver.shared);
        std::fs::remove_dir_all(source.directory).unwrap();
        std::fs::remove_dir_all(receiver.directory).unwrap();
    }
}
#[test]
fn fixed_service_refuses_an_offer_from_a_role_outside_its_pinned_miner_policy() {
    let source = fixture(p2p::Role::Miner, p2p::Role::Validator, 2);
    let receiver = fixture(p2p::Role::Validator, p2p::Role::Miner, 1);
    produced(&source, 7);
    let (a, b) = UnixStream::pair().unwrap();
    let mut source_peer = peer(a, &source, p2p::Role::Validator);
    let mut receiver_peer = peer(b, &receiver, p2p::Role::Wallet);
    let source_shared = source.shared.clone();
    let before = receiver.shared.budget.available().unwrap();
    let worker = thread::spawn(move || {
        assert!(source_peer.probe_propagation(2).unwrap());
        source_peer.finish_round(2).unwrap();
        assert!(offer(&mut source_peer, &source_shared, 3).unwrap());
        source_peer.finish_round(3).unwrap();
    });
    let mut incoming = 1;
    super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
    super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
    worker.join().unwrap();
    assert_eq!(receiver.shared.transfers.diagnostic()["active"], 0);
    assert_eq!(receiver.shared.headers.active_downloads(), 0);
    assert_eq!(receiver.shared.budget.available().unwrap(), before);
    drop(receiver_peer);
    drop(source.shared);
    drop(receiver.shared);
    std::fs::remove_dir_all(source.directory).unwrap();
    std::fs::remove_dir_all(receiver.directory).unwrap();
}

struct SlowStream {
    socket: UnixStream,
    blocked: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
    armed: Arc<std::sync::atomic::AtomicBool>,
    fired: bool,
}
impl std::io::Read for SlowStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(&mut self.socket, bytes)
    }
}
impl std::io::Write for SlowStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.armed.load(std::sync::atomic::Ordering::Acquire)
            && !self.fired
            && bytes.len() > 38
            && bytes[..2] == [0x41, 1]
        {
            self.fired = true;
            self.blocked
                .send(())
                .map_err(|_| std::io::ErrorKind::ConnectionReset)?;
            self.release
                .recv_timeout(Duration::from_secs(3))
                .map_err(|_| std::io::ErrorKind::TimedOut)?;
        }
        std::io::Write::write(&mut self.socket, bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.socket)
    }
}
#[test]
fn a_slow_piece_socket_does_not_hold_the_registry_or_another_candidate() {
    let first = fixture(p2p::Role::Miner, p2p::Role::Validator, 2);
    let second = fixture(p2p::Role::Miner, p2p::Role::Validator, 2);
    let receiver = fixture(p2p::Role::Validator, p2p::Role::Miner, 1);
    produced(&first, 8);
    produced(&second, 9);
    let (first_socket, first_receive) = UnixStream::pair().unwrap();
    first_socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    first_socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (blocked_tx, blocked_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let slow = SlowStream {
        socket: first_socket,
        blocked: blocked_tx,
        release: release_rx,
        armed: armed.clone(),
        fired: false,
    };
    let mut first_peer = Peer::new(
        p2p::Session::from_test_peer_channel(
            slow,
            first.genesis.peer_binding(),
            first.shared.budget.clone(),
            first.remote,
            p2p::Role::Validator,
        ),
        &first.genesis,
        first.shared.headers.body_policy(),
    )
    .unwrap();
    let mut first_receiver = peer(first_receive, &receiver, p2p::Role::Miner);
    let (second_socket, second_receive) = UnixStream::pair().unwrap();
    let mut second_peer = peer(second_socket, &second, p2p::Role::Validator);
    let mut second_receiver = peer(second_receive, &receiver, p2p::Role::Miner);
    let before = receiver.shared.budget.available().unwrap();
    let first_shared = first.shared.clone();
    let first_worker = thread::spawn(move || {
        assert!(first_peer.probe_propagation(2).unwrap());
        first_peer.finish_round(2).unwrap();
        assert!(offer(&mut first_peer, &first_shared, 3).unwrap());
        first_peer.finish_round(3).unwrap();
        armed.store(true, std::sync::atomic::Ordering::Release);
        let mut incoming = 1;
        super::super::serve_turn(&mut first_peer, &first_shared, &mut incoming).unwrap();
    });
    let mut incoming = 1;
    super::super::serve_turn(&mut first_receiver, &receiver.shared, &mut incoming).unwrap();
    super::super::serve_turn(&mut first_receiver, &receiver.shared, &mut incoming).unwrap();
    let receiving = receiver.shared.clone();
    let first_pull = thread::spawn(move || {
        assert!(pull_batch(&mut first_receiver, &receiving, 2).unwrap());
        first_receiver.finish_round(2).unwrap();
    });
    blocked_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let second_shared = second.shared.clone();
    let second_worker = thread::spawn(move || {
        assert!(second_peer.probe_propagation(2).unwrap());
        second_peer.finish_round(2).unwrap();
        assert!(offer(&mut second_peer, &second_shared, 3).unwrap());
        second_peer.finish_round(3).unwrap();
        let mut incoming = 1;
        super::super::serve_turn(&mut second_peer, &second_shared, &mut incoming).unwrap();
    });
    let mut incoming = 1;
    super::super::serve_turn(&mut second_receiver, &receiver.shared, &mut incoming).unwrap();
    super::super::serve_turn(&mut second_receiver, &receiver.shared, &mut incoming).unwrap();
    assert!(pull_batch(&mut second_receiver, &receiver.shared, 2).unwrap());
    second_receiver.finish_round(2).unwrap();
    second_worker.join().unwrap();
    receiver.shared.transfers.reap(&receiver.shared).unwrap();
    assert_eq!(receiver.shared.transfers.diagnostic()["decoded"], 1);
    assert_eq!(receiver.shared.transfers.diagnostic()["active"], 1);
    release_tx.send(()).unwrap();
    first_pull.join().unwrap();
    first_worker.join().unwrap();
    receiver.shared.transfers.reap(&receiver.shared).unwrap();
    assert_eq!(receiver.shared.transfers.diagnostic()["decoded"], 2);
    assert_eq!(receiver.shared.transfers.diagnostic()["active"], 0);
    receiver.shared.bodies.clear().unwrap();
    assert_eq!(receiver.shared.headers.active_downloads(), 0);
    assert_body_resources_released(&receiver, before, 2);
    drop(second_receiver);
    drop(first.shared);
    drop(second.shared);
    drop(receiver.shared);
    std::fs::remove_dir_all(first.directory).unwrap();
    std::fs::remove_dir_all(second.directory).unwrap();
    std::fs::remove_dir_all(receiver.directory).unwrap();
}

struct TailGate {
    socket: UnixStream,
    armed: Arc<std::sync::atomic::AtomicBool>,
    from_piece: usize,
    blocked: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
    fired: bool,
}
impl std::io::Read for TailGate {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(&mut self.socket, bytes)
    }
}
impl std::io::Write for TailGate {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.armed.load(std::sync::atomic::Ordering::Acquire)
            && !self.fired
            && bytes.len() > 38
            && bytes[..2] == [0x41, 1]
            && u32::from_le_bytes(bytes[34..38].try_into().unwrap()) as usize >= self.from_piece
        {
            self.fired = true;
            self.blocked
                .send(())
                .map_err(|_| std::io::ErrorKind::ConnectionReset)?;
            self.release
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| std::io::ErrorKind::TimedOut)?;
        }
        std::io::Write::write(&mut self.socket, bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.socket)
    }
}
fn native_body(fixture: &Fixture) -> (Header, crate::wire::Transaction, usize) {
    let path = std::env::var_os("SIWORLD_NATIVE_PIPELINE_TEST_ENVELOPE")
        .expect("public native envelope required");
    let encoded = std::fs::read(path).unwrap();
    assert!(encoded.len() <= crate::wire::MAX_ENVELOPE_BYTES);
    let valid =
        crate::wire::Transaction::decode_envelope(&encoded, &fixture.genesis.config().network)
            .unwrap();
    let mut body = crate::eng2::body::tests::body();
    body.network = fixture.genesis.config().network;
    body.height = 1;
    body.profile = fixture.shared.headers.body_policy().profile;
    body.governance.clear();
    body.fund_claims.clear();
    body.issuances.clear();
    body.fee_output = crate::eng2::execution::legacy_fee_output();
    body.settlement_proof = vec![13; 128 * 1024];
    let snapshot = fixture
        .shared
        .owner
        .lock()
        .unwrap()
        .engine()
        .state()
        .chain()
        .tip_snapshot()
        .selector;
    for transaction in &mut body.transactions {
        transaction.record.snapshot = snapshot;
    }
    body.transactions[0] = valid.clone();
    body.transactions
        .sort_by_key(|tx| tx.record.statement_id(&body.network));
    let policy = fixture.shared.headers.body_policy();
    let length = body.encoded_len(policy).unwrap();
    let settlement_piece = (length - body.settlement_proof.len() + 8)
        .div_ceil(crate::eng2::propagation::authentication::PIECE_BYTES);
    let config = fixture.genesis.config();
    let header = Header {
        network: body.network,
        height: 1,
        parent: fixture.genesis.id(),
        timestamp: config.genesis_timestamp + config.target_interval,
        target: config.genesis_target,
        execution_commitment: [13; 32],
        body_commitment: body.commitment(policy).unwrap(),
        nonce: 0,
    };
    fixture
        .shared
        .headers
        .produced(header.clone(), Arc::new(body))
        .unwrap();
    (header, valid, settlement_piece)
}
#[test]
#[ignore = "owner-operated joint native verification with an explicit public envelope"]
fn joint_native_receipt_precedes_body_completion_and_owner_failure_invalidates_it() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source = fixture(p2p::Role::Miner, p2p::Role::Validator, 2);
    let receiver = fixture(p2p::Role::Validator, p2p::Role::Miner, 1);
    let (header, valid, from_piece) = native_body(&source);
    let (a, b) = UnixStream::pair().unwrap();
    a.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    a.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    let (blocked_tx, blocked_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stream = TailGate {
        socket: a,
        armed: armed.clone(),
        from_piece,
        blocked: blocked_tx,
        release: release_rx,
        fired: false,
    };
    let mut source_peer = Peer::new(
        p2p::Session::from_test_peer_channel(
            stream,
            source.genesis.peer_binding(),
            source.shared.budget.clone(),
            source.remote,
            p2p::Role::Validator,
        ),
        &source.genesis,
        source.shared.headers.body_policy(),
    )
    .unwrap();
    let mut receiver_peer = peer(b, &receiver, p2p::Role::Miner);
    let source_shared = source.shared.clone();
    let before = receiver.shared.budget.available().unwrap();
    let source_worker = thread::spawn(move || {
        assert!(source_peer.probe_propagation(2).unwrap());
        source_peer.finish_round(2).unwrap();
        assert!(offer(&mut source_peer, &source_shared, 3).unwrap());
        source_peer.finish_round(3).unwrap();
        armed.store(true, std::sync::atomic::Ordering::Release);
        let mut incoming = 1;
        super::super::serve_turn(&mut source_peer, &source_shared, &mut incoming).unwrap();
    });
    let mut incoming = 1;
    super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
    super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
    let job = receiver.shared.transfers.test_job(header.id().unwrap());
    let pipeline = job.validation.as_ref().unwrap().clone();
    drop(job);
    let receiving = receiver.shared.clone();
    let receiving_worker = thread::spawn(move || {
        assert!(pull_batch(&mut receiver_peer, &receiving, 2).unwrap());
        receiver_peer.finish_round(2).unwrap();
    });
    blocked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    while pipeline.test_counts().2 == 0 {
        assert!(
            Instant::now() < until,
            "real native receipt did not complete before the body tail"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let job = receiver.shared.transfers.test_job(header.id().unwrap());
    {
        let transfer = job.transfer.lock().unwrap();
        assert!(transfer.verified_bytes() < transfer.body_bytes());
    }
    drop(job);
    assert!(pipeline.test_counts().0 <= 4);
    release_tx.send(()).unwrap();
    receiving_worker.join().unwrap();
    source_worker.join().unwrap();
    let started = Instant::now();
    receiver.shared.transfers.reap(&receiver.shared).unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    let ready = body_admission::test_take(&receiver.shared.bodies);
    let receipts = ready.received.receipts.as_ref().unwrap();
    {
        let owner = receiver.shared.owner.lock().unwrap();
        let engine = owner.engine();
        assert!(receipts.matches_engine(engine, &header));
        let snapshot = engine
            .state()
            .chain()
            .snapshot(valid.record.snapshot)
            .unwrap();
        let proof = crate::state::TransactionProof {
            public: native::codec::PublicTransaction::decode(&valid.record.body).unwrap(),
            context: native::codec::ProofContext::for_snapshot(
                engine.state().network(),
                snapshot.selector.height,
                snapshot.selector.block_id,
            ),
            fee: native::codec::decode_digest(&valid.record.fee_commit).unwrap(),
            root: native::codec::decode_digest(&snapshot.recent_root).unwrap(),
            proof: &valid.proof,
        };
        let ordinal = ready
            .received
            .body
            .transactions
            .iter()
            .position(|tx| tx == &valid)
            .unwrap();
        assert!(receipts.matches(ordinal, &proof));
    }
    // The authentic transaction receipt grants no final state or settlement acceptance.
    let original_head = receiver.shared.owner.lock().unwrap().head().unwrap();
    let error = body_admission::test_admit(&receiver.shared, &ready).unwrap_err();
    assert!(!error.is_empty());
    {
        let owner = receiver.shared.owner.lock().unwrap();
        assert_eq!(owner.head().unwrap().id, original_head.id);
        assert!(!receipts.matches_engine(owner.engine(), &header));
        assert!(owner.capture_verification(&receiver.shared.budget).is_ok());
        assert!(!receipts.matches_engine(owner.engine(), &header));
    }
    assert!(body_admission::test_admit(&receiver.shared, &ready).is_err());
    drop(ready);
    drop(pipeline);
    assert_eq!(receiver.shared.headers.active_downloads(), 0);
    assert_body_resources_released(&receiver, before, 1);
    drop(source.shared);
    drop(receiver.shared);
    std::fs::remove_dir_all(source.directory).unwrap();
    std::fs::remove_dir_all(receiver.directory).unwrap();
}
#[test]
#[ignore = "owner-operated joint native executor saturation check"]
fn joint_native_busy_executor_does_not_block_reap_or_body_admission_queue() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source = fixture(p2p::Role::Miner, p2p::Role::Validator, 2);
    let receiver = fixture(p2p::Role::Validator, p2p::Role::Miner, 1);
    let header = produced(&source, 14);
    let held = crate::verification_executor::acquire_all_for_test();
    let (a, b) = UnixStream::pair().unwrap();
    let mut source_peer = peer(a, &source, p2p::Role::Validator);
    let mut receiver_peer = peer(b, &receiver, p2p::Role::Miner);
    let source_shared = source.shared.clone();
    let before = receiver.shared.budget.available().unwrap();
    let worker = thread::spawn(move || {
        assert!(source_peer.probe_propagation(2).unwrap());
        source_peer.finish_round(2).unwrap();
        assert!(offer(&mut source_peer, &source_shared, 3).unwrap());
        source_peer.finish_round(3).unwrap();
        let mut incoming = 1;
        super::super::serve_turn(&mut source_peer, &source_shared, &mut incoming).unwrap();
    });
    let mut incoming = 1;
    super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
    super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
    let job = receiver.shared.transfers.test_job(header.id().unwrap());
    let pipeline = job.validation.as_ref().unwrap().clone();
    drop(job);
    assert!(pull_batch(&mut receiver_peer, &receiver.shared, 2).unwrap());
    receiver_peer.finish_round(2).unwrap();
    worker.join().unwrap();
    let started = Instant::now();
    receiver.shared.transfers.reap(&receiver.shared).unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(pipeline.test_counts().0, 0);
    assert_eq!(pipeline.test_counts().2, 0);
    let ready = body_admission::test_take(&receiver.shared.bodies);
    assert!(ready.received.receipts.is_some());
    assert_eq!(receiver.shared.transfers.diagnostic()["decoded"], 1);
    drop(held);
    assert!(body_admission::test_admit(&receiver.shared, &ready).is_err());
    assert_eq!(
        receiver.shared.owner.lock().unwrap().head().unwrap().height,
        0
    );
    drop(ready);
    drop(pipeline);
    assert_eq!(receiver.shared.headers.active_downloads(), 0);
    assert_body_resources_released(&receiver, before, 1);
    drop(receiver_peer);
    drop(source.shared);
    drop(receiver.shared);
    std::fs::remove_dir_all(source.directory).unwrap();
    std::fs::remove_dir_all(receiver.directory).unwrap();
}

#[test]
#[ignore = "owner-operated joint native executor saturation check"]
fn queued_body_cannot_publish_after_its_original_scope_closes_while_waiting_for_owner() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source = fixture(p2p::Role::Miner, p2p::Role::Validator, 2);
    let receiver = fixture(p2p::Role::Validator, p2p::Role::Miner, 1);
    let header = produced(&source, 14);
    let held = crate::verification_executor::acquire_all_for_test();
    let (a, b) = UnixStream::pair().unwrap();
    let mut source_peer = peer(a, &source, p2p::Role::Validator);
    let mut receiver_peer = peer(b, &receiver, p2p::Role::Miner);
    let source_shared = source.shared.clone();
    let before = receiver.shared.budget.available().unwrap();
    let worker = thread::spawn(move || {
        assert!(source_peer.probe_propagation(2).unwrap());
        source_peer.finish_round(2).unwrap();
        assert!(offer(&mut source_peer, &source_shared, 3).unwrap());
        source_peer.finish_round(3).unwrap();
        let mut incoming = 1;
        super::super::serve_turn(&mut source_peer, &source_shared, &mut incoming).unwrap();
    });
    let mut incoming = 1;
    super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
    super::super::serve_turn(&mut receiver_peer, &receiver.shared, &mut incoming).unwrap();
    let job = receiver.shared.transfers.test_job(header.id().unwrap());
    let pipeline = job.validation.as_ref().unwrap().clone();
    drop(job);
    assert!(pull_batch(&mut receiver_peer, &receiver.shared, 2).unwrap());
    receiver_peer.finish_round(2).unwrap();
    worker.join().unwrap();
    let started = Instant::now();
    receiver.shared.transfers.reap(&receiver.shared).unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(pipeline.test_counts().0, 0);
    assert_eq!(pipeline.test_counts().2, 0);
    let ready = body_admission::test_take(&receiver.shared.bodies);
    assert!(ready.received.receipts.is_some());
    assert_eq!(receiver.shared.transfers.diagnostic()["decoded"], 1);
    drop(held);
    let scope = receiver.shared.owner.lock().unwrap().body_scope().unwrap();
    let owner_guard = receiver.shared.owner.lock().unwrap();
    std::thread::scope(|threads| {
        let (started, waiting) = std::sync::mpsc::sync_channel(1);
        let shared = &receiver.shared;
        let ready = &ready;
        let task = threads.spawn(move || {
            started.send(()).unwrap();
            body_admission::test_admit(shared, ready)
        });
        waiting.recv_timeout(Duration::from_secs(1)).unwrap();
        scope.close();
        drop(owner_guard);
        assert!(!task.join().unwrap().unwrap());
    });
    assert_eq!(
        receiver.shared.owner.lock().unwrap().head().unwrap().height,
        0
    );
    drop(ready);
    drop(pipeline);
    assert_eq!(receiver.shared.headers.active_downloads(), 0);
    let (accounts, metadata) = receiver.shared.budget.retained_body_accounting();
    assert_eq!(accounts, 1);
    assert!(metadata > 0);
    assert_eq!(
        receiver.shared.budget.available().unwrap() + metadata,
        before
    );
    drop(receiver_peer);
    drop(source.shared);
    drop(receiver.shared);
    std::fs::remove_dir_all(source.directory).unwrap();
    std::fs::remove_dir_all(receiver.directory).unwrap();
}

#[test]
fn header_only_unused_source_spends_no_query_and_qualified_sources_keep_retry_order() {
    let source = fixture(p2p::Role::Miner, p2p::Role::Validator, 2);
    let receiver = fixture(p2p::Role::Validator, p2p::Role::Miner, 1);
    let header = produced(&source, 7);
    let old = [5; 32];
    let unused = [6; 32];
    let connected = std::collections::BTreeSet::from([old, unused]);
    receiver.shared.headers.offer(header.clone(), old).unwrap();
    receiver
        .shared
        .headers
        .observe_body_tip(old, 51, header.height, header.id().unwrap())
        .unwrap();
    let mut original_deadline = None;
    let mut expected_wire = 0;
    for (index, fingerprint) in [old, old, unused].into_iter().enumerate() {
        if index == 1 {
            receiver
                .shared
                .headers
                .offer(header.clone(), unused)
                .unwrap();
            assert!(
                receiver
                    .shared
                    .headers
                    .download_preferred(unused, p2p::BodyMode::Legacy, None, &connected)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                receiver.shared.budget.body_registry_diagnostic()["window_queries"],
                1
            );
        }
        if index == 2 {
            receiver
                .shared
                .headers
                .observe_body_tip(unused, 61, header.height, header.id().unwrap())
                .unwrap();
            assert!(
                receiver
                    .shared
                    .headers
                    .download_preferred(old, p2p::BodyMode::Legacy, None, &connected)
                    .unwrap()
                    .is_none()
            );
        }
        let mut download = receiver
            .shared
            .headers
            .download_preferred(fingerprint, p2p::BodyMode::Legacy, None, &connected)
            .unwrap()
            .unwrap();
        let ownership = download.take_ownership().unwrap();
        let end = ownership.deadline().expires_at();
        if let Some(original) = original_deadline {
            assert_eq!(end, original);
        } else {
            original_deadline = Some(end);
        }
        assert_eq!(ownership.source_ordinal(), Some(index + 1));
        let (a, b) = UnixStream::pair().unwrap();
        a.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut remote = Peer::new(
            p2p::Session::from_test_peer_channel(
                a,
                source.genesis.peer_binding(),
                source.shared.budget.clone(),
                fingerprint,
                p2p::Role::Validator,
            ),
            &source.genesis,
            source.shared.headers.body_policy(),
        )
        .unwrap();
        let mut local = Peer::new(
            p2p::Session::from_test_peer_channel(
                b,
                receiver.genesis.peer_binding(),
                receiver.shared.budget.clone(),
                fingerprint,
                p2p::Role::Miner,
            ),
            &receiver.genesis,
            receiver.shared.headers.body_policy(),
        )
        .unwrap();
        let h = header.clone();
        let body = source
            .shared
            .headers
            .local_body(h.height, h.id().unwrap())
            .unwrap()
            .unwrap();
        let worker = thread::spawn(move || {
            let (request, kind) = remote.receive_request().unwrap();
            assert!(matches!(kind, crate::eng2::transport::Request::Body { .. }));
            if index < 2 {
                remote.send_unavailable(request, h.height).unwrap();
            } else {
                remote.send_body(request, &h, body.body()).unwrap();
            }
        });
        let result = local
            .fetch_body_owned(11, &header, ownership, None)
            .unwrap();
        if index < 2 {
            assert!(result.is_none());
        } else {
            assert!(result.is_some());
        }
        let io = local.application_totals();
        expected_wire += io.sent + io.received;
        drop(result);
        drop(local);
        drop(download);
        worker.join().unwrap();
    }
    assert_eq!(receiver.shared.budget.body_wire_usage().0, expected_wire);
    assert_eq!(receiver.shared.headers.active_downloads(), 0);
    assert_eq!(
        receiver
            .shared
            .owner
            .lock()
            .unwrap()
            .engine()
            .state()
            .height(),
        0
    );
    drop(source.shared);
    drop(receiver.shared);
    std::fs::remove_dir_all(source.directory).unwrap();
    std::fs::remove_dir_all(receiver.directory).unwrap();
}

#[test]
fn native_tls_pull_one_waits_for_exact_tip_then_uses_real_metadata_and_batch() {
    use crate::identity::{NativeIdentity, PeerPin};
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    let state = crate::eng2::snapshot::tests::bootstrap();
    let genesis = Genesis::seal(
        state.chain.config,
        state.governance,
        crate::eng2::genesis::FeeMode::LegacyMiner,
    )
    .unwrap();
    let binding = genesis.peer_binding();
    let mut entropy = [0; 16];
    getrandom::fill(&mut entropy).unwrap();
    let root =
        std::env::temp_dir().join(format!("body-source-tls-{}", crate::local::hex(&entropy)));
    std::fs::create_dir(&root).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let identity = |name: &str| {
        let path = root.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Arc::new(NativeIdentity::initialize(&path.canonicalize().unwrap(), binding).unwrap())
    };
    let source_id = identity("source");
    let receiver_id = identity("receiver");
    let expected = |identity: &NativeIdentity| {
        let descriptor = identity.descriptor().unwrap();
        let pin = PeerPin::from_trusted_descriptor(&descriptor, &binding).unwrap();
        p2p::ExpectedPeer::from_pinned_descriptor(binding, descriptor, pin).unwrap()
    };
    let source_expected = expected(&source_id);
    let receiver_expected = expected(&receiver_id);
    let source = fixture_with_expected(
        p2p::Role::Miner,
        p2p::Role::Validator,
        2,
        Some(receiver_expected.clone()),
    );
    let receiver = fixture_with_expected(
        p2p::Role::Validator,
        p2p::Role::Miner,
        1,
        Some(source_expected.clone()),
    );
    let header = produced(&source, 17);
    receiver
        .shared
        .headers
        .offer(header.clone(), receiver.remote)
        .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    drop(listener);
    let cancellation = p2p::Cancellation::default();
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let guard_cancel = cancellation.clone();
    let guard_done = done.clone();
    let watchdog = thread::spawn(move || {
        for _ in 0..160 {
            if guard_done.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        guard_cancel.cancel();
    });
    let source_shared = source.shared.clone();
    let source_genesis = Genesis::decode(&genesis.encode().unwrap()).unwrap();
    let source_header = header.clone();
    let source_cancel = cancellation.clone();
    let worker = thread::spawn(move || {
        let context = p2p::AdmissionContext::new(
            receiver_expected,
            p2p::ConnectionRole::Responder,
            source_cancel,
        );
        let mut provider =
            p2p::NativeTlsAuthenticator::new(source_id, source_shared.budget.clone());
        let session = p2p::establish_socket(
            server,
            &mut provider,
            &context,
            p2p::Role::Miner,
            source_shared.budget.clone(),
        )
        .unwrap();
        let mut peer = Peer::new(
            session,
            &source_genesis,
            source_shared.headers.body_policy(),
        )
        .unwrap();
        let mut incoming = 1;
        let mut tips = 0;
        for _ in 0..7 {
            let before = peer.application_totals();
            super::super::receive_turn(&mut peer, &mut incoming, |peer, request, message| {
                match message {
                    crate::eng2::transport::Request::Header {
                        height: crate::eng2::transport::propagation::CAPABILITY_HEIGHT,
                    } => peer.send_propagation_capabilities(request).unwrap(),
                    crate::eng2::transport::Request::GetTip => {
                        tips += 1;
                        let tip = if tips <= 2 {
                            (0, source_genesis.id())
                        } else {
                            (source_header.height, source_header.id().unwrap())
                        };
                        peer.advertise_tip(request, tip.0, tip.1).unwrap();
                    }
                    crate::eng2::transport::Request::Propagation(message) => {
                        let received = peer.application_totals().received - before.received;
                        serve(peer, &source_shared, request, message, received).unwrap();
                    }
                    _ => panic!("unexpected body worker request"),
                }
                Ok(())
            })
            .unwrap();
        }
    });
    let context = p2p::AdmissionContext::new(
        source_expected,
        p2p::ConnectionRole::Initiator,
        cancellation.clone(),
    );
    let mut provider =
        p2p::NativeTlsAuthenticator::new(receiver_id, receiver.shared.budget.clone());
    let session = p2p::establish_socket(
        client,
        &mut provider,
        &context,
        p2p::Role::Validator,
        receiver.shared.budget.clone(),
    )
    .unwrap();
    let mut peer = Peer::new(session, &genesis, receiver.shared.headers.body_policy()).unwrap();
    let mut outgoing = 1;
    let mut source_announced = false;
    for turn in 0..7 {
        super::super::pull_one(
            &mut peer,
            &receiver.shared,
            &mut outgoing,
            &mut source_announced,
        )
        .unwrap();
        peer.finish_round(outgoing).unwrap();
        if turn <= 3 {
            assert_eq!(receiver.shared.headers.active_downloads(), 0);
            assert_eq!(receiver.shared.budget.retained_body_accounting().0, 0);
        }
    }
    worker.join().unwrap();
    done.store(true, std::sync::atomic::Ordering::Release);
    watchdog.join().unwrap();
    assert!(!cancellation.is_cancelled());
    receiver.shared.transfers.reap(&receiver.shared).unwrap();
    assert_eq!(receiver.shared.transfers.diagnostic()["decoded"], 1);
    let ready = body_admission::test_take(&receiver.shared.bodies);
    assert_eq!(ready.download.header.id().unwrap(), header.id().unwrap());
    assert_eq!(
        receiver.shared.budget.body_registry_diagnostic()["window_queries"],
        2
    );
    assert_eq!(receiver.shared.headers.tip().unwrap(), (0, genesis.id()));
    assert_eq!(
        receiver.shared.owner.lock().unwrap().head().unwrap().height,
        0
    );
    drop(ready);
    drop(peer);
    drop(source.shared);
    drop(receiver.shared);
    std::fs::remove_dir_all(source.directory).unwrap();
    std::fs::remove_dir_all(receiver.directory).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
