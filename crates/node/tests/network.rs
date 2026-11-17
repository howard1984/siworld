//! Nodes on localhost: one mines, another follows over the network, and a
//! payment sent through the RPC reaches the other node's wallet; a miner with
//! configured peers waits until it has synced.

mod common;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use siworld_circuits::MockProver;
use siworld_core::Digest;
use siworld_crypto::{SecretSeed, SpendKey};
use siworld_node::genesis::{AllocationFile, Genesis, GenesisFile, ProofsFile};
use siworld_node::hex;
use siworld_node::node::Node;
use siworld_node::rpc_auth::{RpcAuth, RpcToken};
use siworld_node::service::{call_authenticated, run, Config, RpcConfig};

fn token(byte: u8) -> RpcToken {
    RpcToken::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
}
fn call(rpc: &str, request: &Value) -> Result<Value, String> {
    let mut request = request.clone();
    if request["method"] == "send" && request.get("payment_id").is_none() {
        request["payment_id"] = json!(siworld_node::payments::PaymentId::random()
            .unwrap()
            .to_string());
    }
    call_authenticated(rpc, &request, &token(2))
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn genesis() -> Genesis {
    genesis_at(now())
}

fn genesis_at(timestamp: u64) -> Genesis {
    Genesis::from_file(&GenesisFile {
        network: "network-test".into(),
        timestamp,
        block_time: 1,
        pow_iterations: 1_000,
        // About 256 nonces per block.
        target: "00".to_string() + &"ff".repeat(31),
        container_size: 4,
        proofs: ProofsFile::Mock,
        dev_fund: None,
        allocations: vec![AllocationFile {
            owner: hex(&SpendKey::from_digest(Digest([1; 32])).owner()),
            amount: "100".into(),
        }],
    })
    .unwrap()
}

struct RunningNode {
    _journal: common::JournalDir,
    rpc: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl std::ops::Deref for RunningNode {
    type Target = str;
    fn deref(&self) -> &str {
        &self.rpc
    }
}
impl Drop for RunningNode {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }
}

/// Every test owns and shuts down its service threads, including after a panic.
fn start(genesis: &Genesis, key: u8, p2p: u16, peers: Vec<u16>, mine: bool) -> RunningNode {
    start_with_backlog(genesis, key, p2p, peers, mine, 0)
}
fn start_with_backlog(
    genesis: &Genesis,
    key: u8,
    p2p: u16,
    peers: Vec<u16>,
    mine: bool,
    backlog: u64,
) -> RunningNode {
    let rpc = format!("127.0.0.1:{}", free_port());
    let config = Config {
        worker: None,
        listen: vec![format!("/ip4/127.0.0.1/tcp/{p2p}").parse().unwrap()],
        peers: peers
            .iter()
            .map(|p| format!("/ip4/127.0.0.1/tcp/{p}").parse().unwrap())
            .collect(),
        rpc: Some(RpcConfig {
            address: rpc.parse().unwrap(),
            auth: RpcAuth::new(token(1), Some(token(2)), Some(token(3))).unwrap(),
        }),
        mine,
    };
    let mut node = Node::open(
        genesis.clone(),
        SpendKey::from_digest(Digest([key; 32])),
        SecretSeed::from_os_rng().unwrap(),
        None,
        Arc::new(MockProver),
    )
    .unwrap();
    // A finite source chain lets the follower drain multiple sync batches. A
    // continuously advancing, nearly free source can outrun a CI runner forever.
    for height in 1..=backlog {
        let mut block = node
            .template(genesis.params.genesis_timestamp + height)
            .unwrap();
        assert!(siworld_consensus::mine(
            &mut block.header,
            node.chain.params.pow_iterations
        ));
        node.accept(&block).unwrap();
    }
    let journal = common::JournalDir::attach(&mut node);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(run(node, config, async {
                let _ = stopped.await;
            }))
            .unwrap();
    });
    let running = RunningNode {
        _journal: journal,
        rpc,
        stop: Some(stop),
        thread: Some(thread),
    };
    wait_for(&running, json!({"method":"info"}), |_| true);
    running
}

/// Calls `method` on `rpc` until `done` holds for the reply.
fn wait_for(rpc: &str, request: Value, done: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Ok(reply) = call(rpc, &request) {
            if done(&reply) {
                return reply;
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting on {request}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "owner-local only: spawns miner"]
fn a_follower_syncs_and_receives_a_payment() {
    let genesis = genesis();
    let (pa, pb) = (free_port(), free_port());
    let a = start(&genesis, 1, pa, vec![], true);
    let b = start(&genesis, 2, pb, vec![pa], false);

    wait_for(&b, json!({"method": "info"}), |r| {
        r["height"].as_u64() >= Some(3) && r["peers"] == 1
    });
    let to = call(&b, &json!({"method": "address"})).unwrap()["address"].clone();
    let sent = call(&a, &json!({"method": "send", "to": to, "amount": "10"})).unwrap();
    assert_eq!(sent["sent"], "10", "{sent}");
    wait_for(&b, json!({"method": "balance"}), |r| r["total"] == "10");

    // b follows a's chain.
    let info_a = call(&a, &json!({"method": "info"})).unwrap();
    wait_for(&b, json!({"method": "info"}), |r| {
        r["height"].as_u64() >= info_a["height"].as_u64()
    });
    assert_eq!(
        call(&b, &json!({"method": "send", "to": "tsi00", "amount": "1"})).unwrap()["error"],
        "invalid address"
    );
}

#[test]
#[ignore = "owner-local only: spawns miner"]
fn a_miner_with_peers_mines_only_once_synced() {
    // Two days behind schedule: ASERT puts the target at the ceiling, so a
    // node mining alone would bury genesis under its own blocks at once.
    let genesis = genesis_at(now() - 2 * 86_400);
    let (pa, pb) = (free_port(), free_port());
    let b = start(&genesis, 2, pb, vec![pa], true);
    std::thread::sleep(Duration::from_secs(2));
    let info = call(&b, &json!({"method": "info"})).unwrap();
    assert_eq!(info["height"], 0, "{info}");
    assert_eq!(info["synced"], false, "{info}");

    let backlog = 200;
    let a = start_with_backlog(&genesis, 1, pa, vec![], false, backlog);
    let source = call(&a, &json!({"method":"info"})).unwrap();
    assert_eq!(source["height"], backlog);
    // b drains the backlog before mining a block on top of a's final height.
    wait_for(&b, json!({"method": "info"}), |r| {
        r["synced"] == true && r["peers"] == 1 && r["height"].as_u64() > Some(backlog)
    });
}
