//! Hold the container prover at a barrier; exercise the real service around it.
mod common;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use siworld_circuits::{
    AggregateError, ContainerPublic, FeeOpening, Leaf, MockProver, ProofSystem, ProveError,
    RelationContext, SlotProof, SlotWitness,
};
use siworld_consensus::mine;
use siworld_core::{ContainerProof, DevAccount, Digest, Height, Note, Slot};
use siworld_crypto::{SecretSeed, SpendKey};
use siworld_node::address::encode_address;
use siworld_node::genesis::{AllocationFile, Genesis, GenesisFile, ProofsFile};
use siworld_node::node::Node;
use siworld_node::rpc_auth::{RpcAuth, RpcToken};
use siworld_node::service::{run, Config, RpcConfig};
use siworld_node::DevFundSigner;
use siworld_state::RecentRoots;

#[derive(Default)]
struct BarrierState {
    started: usize,
    released: usize,
    active: usize,
    maximum: usize,
    fail: bool,
    failures: usize,
}
#[derive(Default)]
struct Barrier(Mutex<BarrierState>, Condvar);
impl Barrier {
    fn release(&self, through: usize) {
        self.0.lock().unwrap().released = through;
        self.1.notify_all();
    }
}
struct Observation {
    height: Height,
    paid: bool,
}
struct HeldProver {
    barrier: Arc<Barrier>,
    started: mpsc::Sender<Observation>,
}
impl ProofSystem for HeldProver {
    fn prove_slot(
        &self,
        ctx: &RelationContext,
        w: &SlotWitness,
        blind: Digest,
    ) -> Result<(Slot, SlotProof, FeeOpening), ProveError> {
        ProofSystem::prove_slot(&MockProver, ctx, w, blind)
    }
    fn verify_slot(
        &self,
        anchors: &RecentRoots,
        slot: &Slot,
        proof: &SlotProof,
        fee: &FeeOpening,
    ) -> bool {
        ProofSystem::verify_slot(&MockProver, anchors, slot, proof, fee)
    }
    fn prove_container(
        &self,
        anchors: &RecentRoots,
        height: Height,
        leaves: &[Leaf],
        miner_note: &Note,
        miner_share: u64,
    ) -> Result<ContainerProof, AggregateError> {
        let mut state = self.barrier.0.lock().unwrap();
        state.started += 1;
        state.active += 1;
        state.maximum = state.maximum.max(state.active);
        let call = state.started;
        let _ = self.started.send(Observation {
            height,
            paid: leaves.iter().any(|l| l.fee.fee != 0),
        });
        while state.released < call {
            let (next, timeout) = self
                .barrier
                .1
                .wait_timeout(state, Duration::from_secs(10))
                .unwrap();
            state = next;
            assert!(!timeout.timed_out(), "test did not release the prover");
        }
        state.active -= 1;
        let fail = state.fail;
        state.failures += usize::from(fail);
        drop(state);
        if fail {
            return Err(AggregateError::Prover("injected failure".into()));
        }
        MockProver.prove_container(anchors, height, leaves, miner_note, miner_share)
    }
    fn verify_container(&self, public: &ContainerPublic, proof: &ContainerProof) -> bool {
        ProofSystem::verify_container(&MockProver, public, proof)
    }
}

fn key(byte: u8) -> SpendKey {
    SpendKey::from_digest(Digest([byte; 32]))
}
fn token() -> RpcToken {
    RpcToken::from_hex(&"02".repeat(32)).unwrap()
}
fn socket() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn genesis() -> Genesis {
    Genesis::from_file(&GenesisFile {
        network: "background-proof-test".into(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        block_time: 60,
        pow_iterations: 1,
        target: "ff".repeat(32),
        container_size: 2,
        proofs: ProofsFile::Mock,
        dev_fund: None,
        allocations: vec![AllocationFile {
            owner: siworld_node::hex(&key(1).owner()),
            amount: "100".into(),
        }],
    })
    .unwrap()
}
fn node(genesis: &Genesis, system: Arc<dyn ProofSystem>, byte: u8) -> Node {
    Node::open(
        genesis.clone(),
        key(byte),
        SecretSeed::from_os_rng().unwrap(),
        None,
        system,
    )
    .unwrap()
}

struct Running {
    _journal: common::JournalDir,
    rpc: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    barrier: Arc<Barrier>,
}
impl Running {
    fn call(&self, mut request: Value) -> Result<Value, String> {
        if request["method"] == "send" && request.get("payment_id").is_none() {
            request["payment_id"] = json!(siworld_node::payments::PaymentId::random()
                .unwrap()
                .to_string());
        }
        if request.get("auth").is_none() {
            request["auth"] = json!("02".repeat(32));
        }
        let mut stream = TcpStream::connect_timeout(&self.rpc, Duration::from_secs(1))
            .map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        writeln!(stream, "{request}").map_err(|e| e.to_string())?;
        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&line).map_err(|e| e.to_string())
    }
    fn info(&self) -> Value {
        self.call(json!({"method": "info"}))
            .expect("RPC must respond during proving")
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.barrier.release(usize::MAX);
        self.thread.take().unwrap().join().unwrap();
    }
}
fn start(
    mut node: Node,
    p2p: SocketAddr,
    peers: Vec<SocketAddr>,
    mine: bool,
    barrier: Arc<Barrier>,
) -> Running {
    let journal = common::JournalDir::attach(&mut node);
    let rpc = socket();
    let address = |s: SocketAddr| format!("/ip4/127.0.0.1/tcp/{}", s.port()).parse().unwrap();
    let config = Config {
        worker: None,
        listen: vec![address(p2p)],
        peers: peers.into_iter().map(address).collect(),
        rpc: Some(RpcConfig {
            address: rpc,
            auth: RpcAuth::new(
                RpcToken::from_hex(&"01".repeat(32)).unwrap(),
                Some(token()),
                Some(RpcToken::from_hex(&"03".repeat(32)).unwrap()),
            )
            .unwrap(),
        }),
        mine,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run(node, config, async {
                let _ = stopped.await;
            }))
            .unwrap();
    });
    Running {
        _journal: journal,
        rpc,
        stop: Some(stop),
        thread: Some(thread),
        barrier,
    }
}
fn held(genesis: &Genesis) -> (Node, Arc<Barrier>, mpsc::Receiver<Observation>) {
    let barrier = Arc::new(Barrier::default());
    let (started, observations) = mpsc::channel();
    let system = Arc::new(HeldProver {
        barrier: barrier.clone(),
        started,
    });
    (node(genesis, system, 1), barrier, observations)
}
fn observed(rx: &mpsc::Receiver<Observation>) -> Observation {
    rx.recv_timeout(Duration::from_secs(5))
        .expect("candidate did not start")
}
fn wait_info(running: &Running, predicate: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(info) = running.call(json!({"method": "info"})) {
            if predicate(&info) {
                return info;
            }
        }
        assert!(Instant::now() < deadline, "service did not progress");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "owner-local only: spawns miner"]
fn rpc_and_peer_sync_continue_while_container_proving_is_held() {
    let genesis = genesis();
    let (n, barrier, rx) = held(&genesis);
    let port = socket();
    let a = start(n, port, vec![], true, barrier);
    assert_eq!(observed(&rx).height, 1);
    assert_eq!(a.info()["height"], 0);
    let b = start(
        node(&genesis, Arc::new(MockProver), 2),
        socket(),
        vec![port],
        false,
        Arc::default(),
    );
    wait_info(&a, |i| i["peers"] == 1);
    wait_info(&b, |i| i["peers"] == 1 && i["synced"] == true);
    assert_eq!(a.info()["height"], 0);
}

#[test]
#[ignore = "owner-local only: spawns miner"]
fn same_tip_payment_cancels_old_candidate_and_coalesces_rebuilds() {
    let genesis = genesis();
    let (n, barrier, rx) = held(&genesis);
    let a = start(n, socket(), vec![], true, barrier.clone());
    assert!(!observed(&rx).paid);
    let sent = a
        .call(json!({"method": "send", "to": encode_address(&key(2).address()), "amount": "10"}))
        .unwrap();
    assert_eq!(sent["sent"], "10", "{sent}");
    for _ in 0..5 {
        assert_eq!(a.info()["height"], 0);
    }
    assert_eq!(barrier.0.lock().unwrap().started, 1);
    barrier.release(1);
    let latest = observed(&rx);
    assert_eq!(latest.height, 1);
    assert!(latest.paid);
    assert_eq!(
        a.info()["height"],
        0,
        "stale same-parent candidate was mined"
    );
    assert_eq!(barrier.0.lock().unwrap().maximum, 1);
    barrier.release(2);
    wait_info(&a, |i| {
        i["height"].as_u64().unwrap() >= 1 && i["mempool"] == 0
    });
}

#[test]
#[ignore = "owner-local only: spawns miner"]
fn peer_tip_change_invalidates_in_flight_proof() {
    let genesis = genesis();
    let (n, barrier, rx) = held(&genesis);
    let port = socket();
    let a = start(n, port, vec![], true, barrier.clone());
    assert_eq!(observed(&rx).height, 1);
    let mut peer = node(&genesis, Arc::new(MockProver), 2);
    let mut block = peer.template(genesis.params.genesis_timestamp + 1).unwrap();
    assert!(mine(&mut block.header, 1));
    peer.accept(&block).unwrap();
    let _b = start(peer, socket(), vec![port], false, Arc::default());
    wait_info(&a, |i| i["height"] == 1);
    barrier.release(1);
    assert_eq!(observed(&rx).height, 2);
    assert_eq!(a.info()["tip"], siworld_node::hex(&block.header.hash()));
}

fn funded_node(
    genesis: &Genesis,
    system: Arc<dyn ProofSystem>,
    signer: DevFundSigner,
) -> (Node, common::FundDir) {
    // Construct a genuine 101-block history to mature the first public credit.
    let mut producer = node(genesis, Arc::new(MockProver), 2);
    let mut target = node(genesis, system, 1);
    for height in 1..=101 {
        let mut block = producer
            .template(genesis.params.genesis_timestamp + height)
            .unwrap();
        assert!(mine(&mut block.header, 1));
        producer.accept(&block).unwrap();
        target.accept(&block).unwrap();
    }
    let password = "temporary proving fund test password";
    assert_eq!(
        signer.verifying_keys(),
        DevFundSigner::from_seed(&Digest([8; 32])).verifying_keys()
    );
    let journal = common::FundDir::attach(
        &mut target,
        siworld_node::fund_keys::FundKeystore::seal(&Digest([8; 32]), password).unwrap(),
        password,
    );
    target
        .unlock_fund(
            password,
            &siworld_node::fund_keys::FundGrant {
                version: 2,
                approval_id: siworld_node::fund_payments::PayoutId::random()
                    .unwrap()
                    .to_string(),
                budget: siworld_node::fund_keys::FundBudget {
                    version: 1,
                    id: "ab".repeat(32),
                    direct_sip: "1000000000".into(),
                    lock_sip: "1000000000".into(),
                    total_sip: "2000000000".into(),
                    max_payout_sip: "1000000".into(),
                },
                genesis: siworld_node::hex(&target.genesis.id),
                seconds: 3600,
                direct_sip: "1000000".into(),
                lock_sip: "1000000".into(),
                max_payout_sip: "1000000".into(),
                recipients: vec![encode_address(&key(3).address())],
                approval: None,
            },
        )
        .unwrap();
    (target, journal)
}

#[test]
#[ignore = "owner-local only: spawns miner"]
fn same_tip_payout_invalidates_the_candidate_without_clearing_the_queue() {
    let mut genesis = genesis();
    let signer = DevFundSigner::from_seed(&Digest([8; 32]));
    genesis.params.dev_fund_keys = Some(signer.verifying_keys());
    let barrier = Arc::new(Barrier::default());
    let (started, rx) = mpsc::channel();
    let system = Arc::new(HeldProver {
        barrier: barrier.clone(),
        started,
    });
    let (n, _journal) = funded_node(&genesis, system, signer);
    let a = start(n, socket(), vec![], true, barrier.clone());
    assert_eq!(observed(&rx).height, 102);
    let queued = a
        .call(
            json!({"method": "devfund", "payout_id":"01".repeat(32), "auth": "03".repeat(32), "account": "direct",
        "to": encode_address(&key(3).address()), "amount": "0.0001"}),
        )
        .unwrap();
    assert_eq!(queued["counter"], 0, "{queued}");
    barrier.release(1);
    assert_eq!(observed(&rx).height, 102);
    assert_eq!(a.info()["height"], 101);
    barrier.release(2);
    wait_info(&a, |i| i["dev_fund"]["payouts"] == 1);
}

#[test]
#[ignore = "owner-local only: spawns miner"]
fn failed_background_build_preserves_payment_reservations_and_payouts() {
    let mut genesis = genesis();
    let signer = DevFundSigner::from_seed(&Digest([8; 32]));
    genesis.params.dev_fund_keys = Some(signer.verifying_keys());
    let barrier = Arc::new(Barrier::default());
    barrier.0.lock().unwrap().fail = true;
    let (started, rx) = mpsc::channel();
    let system = Arc::new(HeldProver {
        barrier: barrier.clone(),
        started,
    });
    let (mut n, _journal) = funded_node(&genesis, system, signer);
    n.pay(&key(3).address(), 1_000_000, false).unwrap();
    n.payout(
        siworld_node::fund_payments::PayoutId::random().unwrap(),
        DevAccount::Direct,
        &key(3).address(),
        10_000,
    )
    .unwrap();
    let before = n.balance().unwrap();
    let a = start(n, socket(), vec![], true, barrier.clone());
    assert!(observed(&rx).paid);
    barrier.release(1);
    // Observe the injected failure itself: a due service tick may already have
    // started the next held call before this thread observes an idle prover.
    let deadline = Instant::now() + Duration::from_secs(2);
    while barrier.0.lock().unwrap().failures == 0 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let balance = a.call(json!({"method": "balance"})).unwrap();
    assert_eq!(
        balance["spendable"],
        siworld_node::amount::format_sip(before.spendable)
    );
    assert_eq!(
        balance["pending"],
        siworld_node::amount::format_sip(before.pending)
    );
    assert_eq!(a.info()["mempool"], 1);
    assert_eq!(a.info()["dev_fund"]["payouts"], 0);
    // Wait through the retry tick: the same payment is still selected.
    barrier.0.lock().unwrap().fail = false;
    assert!(observed_with_timeout(&rx, Duration::from_secs(12)).paid);
    assert_eq!(barrier.0.lock().unwrap().maximum, 1);
    barrier.release(2);
    wait_info(&a, |i| i["mempool"] == 0 && i["dev_fund"]["payouts"] == 1);
}

fn observed_with_timeout(rx: &mpsc::Receiver<Observation>, timeout: Duration) -> Observation {
    rx.recv_timeout(timeout).expect("candidate did not start")
}

#[test]
#[ignore = "owner-local only: spawns miner"]
fn tick_does_not_cancel_a_proof_taking_longer_than_the_tick() {
    let genesis = genesis();
    let (n, barrier, rx) = held(&genesis);
    let a = start(n, socket(), vec![], true, barrier.clone());
    observed(&rx);
    // The service tick is 10s; keep this one proof alive across it.
    for _ in 0..11 {
        assert_eq!(a.info()["height"], 0);
        std::thread::sleep(Duration::from_secs(1));
        // Wake the condition variable without releasing the held call.
        barrier.1.notify_all();
    }
    assert_eq!(barrier.0.lock().unwrap().started, 1);
    barrier.release(1);
    wait_info(&a, |i| i["height"] == 1);
}

#[test]
#[ignore = "owner-local only: spawns miner"]
fn shutdown_invalidates_candidate_and_closes_rpc_before_waiting_for_prover() {
    let genesis = genesis();
    let (n, barrier, rx) = held(&genesis);
    let mut a = start(n, socket(), vec![], true, barrier.clone());
    observed(&rx);
    a.stop.take().unwrap().send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while TcpStream::connect(a.rpc).is_ok() {
        assert!(Instant::now() < deadline, "RPC stayed open on shutdown");
        std::thread::sleep(Duration::from_millis(20));
    }
    // The held synchronous proof is still owned, rather than detached.
    assert!(!a.thread.as_ref().unwrap().is_finished());
    barrier.release(1);
    drop(a);
}
