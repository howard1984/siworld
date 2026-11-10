use super::*;
use crate::{
    eng2::{
        bootstrap::{Chunk, Object, Provider},
        checkpoint_exchange,
        header::Header,
        network::{Owner, Sequence},
        transaction_exchange,
        transport::ChunkRequest,
    },
    identity::PeerPin,
};
use std::{
    net::{Ipv4Addr, TcpListener},
    sync::atomic::{AtomicBool, Ordering},
};

struct Fixture {
    registry: crate::eng2::bootstrap::leases::Registry,
    clock: Instant,
}
impl Fixture {
    fn new(provider: Arc<Provider>) -> Self {
        let clock = Instant::now();
        let mut registry = crate::eng2::bootstrap::leases::Registry::default();
        assert!(registry.publish(provider, clock));
        Self { registry, clock }
    }
}
impl Owner for Fixture {
    fn head(&self) -> Result<(u64, Hash), String> {
        Ok(self.registry.current().map_or((0, [0; 32]), |provider| {
            (provider.manifest().tip_height, provider.manifest().tip_id)
        }))
    }
    fn header(&self, _: u64) -> Result<Option<Header>, String> {
        Ok(None)
    }
    fn block_size(&self, _: u64) -> Result<Option<usize>, String> {
        Ok(None)
    }
    fn block(&self, _: u64) -> Result<(Header, super::super::super::body::Body), String> {
        Err("synthetic transport fixture has no native bodies".into())
    }
    fn accept(&mut self, _: &Header, _: &super::super::super::body::Body) -> Result<(), String> {
        Err("synthetic transport fixture cannot accept blocks".into())
    }
    fn bootstrap_manifest(
        &mut self,
        peer: Hash,
        requested: Option<Hash>,
    ) -> Result<Option<Vec<u8>>, String> {
        self.registry.reconcile(self.clock, |_| true);
        Ok(self
            .registry
            .manifest(peer, requested, self.clock)
            .map(|provider| provider.encoded().to_vec()))
    }
    fn bootstrap_chunk(
        &mut self,
        peer: Hash,
        query: ChunkRequest,
    ) -> Result<Option<Chunk>, String> {
        self.registry.reconcile(self.clock, |_| true);
        let Some(provider) = self.registry.chunk_provider(peer, query.bundle, self.clock) else {
            return Ok(None);
        };
        if query.object != Object::Snapshot || query.offset >= 7 {
            return Ok(None);
        }
        let start = query.offset as usize;
        let end = (start + query.maximum as usize).min(7);
        let bytes = b"fixture"[start..end].to_vec();
        if !self
            .registry
            .charge_chunk(peer, query.bundle, bytes.len(), self.clock)
        {
            return Ok(None);
        }
        Ok(Some(Chunk {
            descriptor: provider.manifest().snapshot,
            bytes,
        }))
    }
}
impl transaction_exchange::Owner for Fixture {
    fn transaction_ids(&self) -> Vec<Hash> {
        Vec::new()
    }
    fn has_transaction(&self, _: &Hash) -> bool {
        true
    }
    fn transaction_packet(&self, _: &Hash) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
    fn submit_transaction(
        &mut self,
        _: Hash,
        _: Hash,
        _: &[u8],
        _: &p2p::Deadline,
    ) -> Result<Hash, String> {
        Err("synthetic transport fixture has no pending state".into())
    }
}
fn directory() -> PathBuf {
    let mut entropy = [0; 16];
    getrandom::fill(&mut entropy).unwrap();
    let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "signed-bootstrap-reconnect-{}",
        crate::local::hex(&entropy)
    ));
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    builder.create(&directory).unwrap();
    directory
}

#[test]
fn hybrid_rollover_reauthenticates_exact_lease_resumes_and_rejects_expired_or_foreign_bundle() {
    let root = directory();
    let (genesis, limits, _) = crate::eng2::bootstrap::tests::framing_fixture();
    let genesis = Arc::new(genesis);
    let client_directory = root.join("client");
    let server_directory = root.join("server");
    let fresh_directory = root.join("fresh");
    for directory in [&client_directory, &server_directory, &fresh_directory] {
        std::fs::create_dir(directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let client_identity =
        Arc::new(NativeIdentity::initialize(&client_directory, genesis.peer_binding()).unwrap());
    let server_identity =
        Arc::new(NativeIdentity::initialize(&server_directory, genesis.peer_binding()).unwrap());
    let fresh_identity =
        Arc::new(NativeIdentity::initialize(&fresh_directory, genesis.peer_binding()).unwrap());
    let descriptor = server_identity.descriptor().unwrap();
    let pin = PeerPin::from_trusted_descriptor(&descriptor, &genesis.peer_binding()).unwrap();
    let expected =
        p2p::ExpectedPeer::from_pinned_descriptor(genesis.peer_binding(), descriptor, pin).unwrap();
    let budget = p2p::Budget::default();
    let body = super::super::super::body::Policy {
        profile: crate::proofs::protocol_profile_fingerprint(),
        max_body_bytes: 1024,
        max_settlement_proof_bytes: 1024,
    };
    let server_connector = Connector::new(
        genesis.clone(),
        server_identity,
        Vec::new(),
        budget.clone(),
        body,
    )
    .unwrap();
    let client_connector = Connector::new(
        genesis.clone(),
        client_identity,
        vec![expected.clone()],
        budget.clone(),
        body,
    )
    .unwrap();
    let fresh_connector = Connector::new(
        genesis.clone(),
        fresh_identity,
        vec![expected.clone()],
        budget.clone(),
        body,
    )
    .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let destination = config::Destination {
        endpoint: listener.local_addr().unwrap(),
        dial: true,
        expected,
    };
    let server_genesis = genesis.clone();
    let stopped = Arc::new(AtomicBool::new(false));
    let stop_server = stopped.clone();
    let server = std::thread::spawn(move || {
        let owner = Arc::new(Mutex::new(Fixture::new(Arc::new(
            crate::eng2::bootstrap::tests::transport_fixture(),
        ))));
        let mut observed = Vec::new();
        for connection in 0..8 {
            if connection == 2 {
                let mut owner = owner.lock().unwrap();
                let now = owner.clock;
                let replacement = Arc::new(crate::eng2::bootstrap::tests::transport_fixture_tag(8));
                assert!(owner.registry.publish(replacement, now));
            }
            if connection == 7 {
                owner.lock().unwrap().clock += Duration::from_secs(7200);
            }
            let started = Instant::now();
            let socket = loop {
                if stop_server.load(Ordering::SeqCst) || started.elapsed() > Duration::from_secs(10)
                {
                    return observed;
                }
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => panic!("synthetic local listener failed"),
                }
            };
            let mut peer = server_connector
                .accept(
                    socket,
                    Instant::now(),
                    p2p::Role::Validator,
                    p2p::Cancellation::default(),
                )
                .unwrap();
            let mut sequence = Sequence::default();
            for round in 0..if connection == 2 || connection == 3 {
                2
            } else {
                1
            } {
                network::respond(&mut peer, &owner, &mut sequence, network::Limits::default())
                    .unwrap();
                if connection == 0 && round == 0 {
                    // Fail after artifact acquisition but before the complete
                    // checkpoint/transaction boundary. This stream is unusable.
                    break;
                }
                checkpoint_exchange::respond(&mut peer, &[], server_genesis.config().network)
                    .unwrap();
                transaction_exchange::respond(&mut peer, &owner).unwrap();
            }
            observed.push(peer.encrypted_stream_bytes());
        }
        observed
    });
    let policy = Policy::decode(&json!({"version":1,"work_floor":"1","max_headers":1000,
        "max_payload_bytes":"2147483648","max_rounds":1000,"max_seconds":60}))
    .unwrap();
    let mut operation = Operation::new(&policy).unwrap();
    let accounting = Arc::new(Mutex::new(Accounting::default()));
    let mut session = Acquisition::new(
        &client_connector,
        &destination,
        &genesis,
        accounting.clone(),
        None,
    );
    session.rotation_bytes = 1;
    let received = session
        .round(&mut operation, |pull| pull.manifest())
        .unwrap()
        .unwrap();
    let manifest = Manifest::decode(&received.bytes, &genesis, limits).unwrap();
    drop(received);
    session.bind(&manifest).unwrap();
    let cache_directory = root.join("quarantine");
    let cache_policy = cache::Policy {
        max_bytes: 1024 * 1024,
        max_chunks_per_object: 8,
        max_body_bytes: 1024,
    };
    let mut cache = cache::Quarantine::create(
        &cache_directory,
        manifest.clone(),
        cache_policy,
        budget.clone(),
    )
    .unwrap();
    for offset in [0, 4] {
        let received = session
            .round(&mut operation, |pull| {
                pull.chunk(ChunkRequest {
                    bundle: manifest.bundle(),
                    object: Object::Snapshot,
                    offset,
                    maximum: 4,
                })
            })
            .unwrap()
            .unwrap();
        cache
            .push(Object::Snapshot, offset, &received.chunk)
            .unwrap();
        drop(received);
        if offset == 0 {
            drop(cache);
            cache = cache::Quarantine::reopen(
                &cache_directory,
                manifest.clone(),
                cache_policy,
                budget.clone(),
            )
            .unwrap();
            assert_eq!(cache.progress(Object::Snapshot).unwrap(), 4);
        }
    }
    assert_eq!(cache.snapshot().unwrap().bytes, b"fixture");
    drop(session);
    let mut wrong = manifest.encode().unwrap();
    wrong[144] ^= 1;
    let end = wrong.len() - 32;
    let changed_bundle = *blake3::hash(&wrong[..end]).as_bytes();
    wrong[end..].copy_from_slice(&changed_bundle);
    let mut changed = Acquisition::new(
        &client_connector,
        &destination,
        &genesis,
        accounting.clone(),
        Some(wrong),
    );
    let mut called = false;
    assert!(
        changed
            .round(&mut operation, |pull| {
                called = true;
                pull.manifest()
            })
            .is_err()
    );
    assert!(!called);
    drop(changed);
    assert_eq!(cache.snapshot().unwrap().bytes, b"fixture");
    assert!(!client_directory.join("chain.redb").exists());
    let mut foreign = Acquisition::new(
        &fresh_connector,
        &destination,
        &genesis,
        accounting.clone(),
        Some(manifest.encode().unwrap()),
    );
    let mut called_foreign = false;
    assert!(
        foreign
            .round(&mut operation, |pull| {
                called_foreign = true;
                pull.manifest()
            })
            .is_err()
    );
    assert!(!called_foreign);
    drop(foreign);
    let mut fresh = Acquisition::new(
        &fresh_connector,
        &destination,
        &genesis,
        accounting.clone(),
        None,
    );
    let current = fresh
        .round(&mut operation, |pull| pull.manifest())
        .unwrap()
        .unwrap();
    let current = Manifest::decode(&current.bytes, &genesis, limits).unwrap();
    assert_ne!(current.bundle(), manifest.bundle());
    assert_eq!(current.tip_id, [8; 32]);
    drop(fresh);
    let mut expired = Acquisition::new(
        &client_connector,
        &destination,
        &genesis,
        accounting.clone(),
        Some(manifest.encode().unwrap()),
    );
    let mut called_after_expiry = false;
    assert!(
        expired
            .round(&mut operation, |pull| {
                called_after_expiry = true;
                pull.manifest()
            })
            .is_err()
    );
    assert!(!called_after_expiry);
    drop(expired);
    assert_eq!(cache.snapshot().unwrap().bytes, b"fixture");
    let counts = accounting.lock().unwrap();
    assert!(!counts.overflow);
    assert_eq!(counts.sessions, 8);
    assert_eq!(operation.connections, 8);
    assert_eq!(
        counts.received,
        counts.retired.iter().map(|v| v.0).sum::<u64>()
    );
    assert_eq!(counts.sent, counts.retired.iter().map(|v| v.1).sum::<u64>());
    assert!(counts.retired.iter().all(|v| v.0 > 0 && v.1 > 0));
    assert!(counts.received > counts.retired.iter().map(|v| v.0).max().unwrap());
    drop(counts);
    stopped.store(true, Ordering::SeqCst);
    assert_eq!(server.join().unwrap().len(), 8);
    drop(cache);
    std::fs::remove_dir_all(root).unwrap();
}
