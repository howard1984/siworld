use super::*;
use crate::eng2::{
    body::Body,
    branches::{BranchStore, Limits as BranchLimits},
    driver::Driver,
    genesis::Genesis,
    header::HEADER_BYTES,
    propagation::{
        authentication::{Descriptor, PIECE_BYTES, encoded_piece},
        pipeline::{DescriptorLedger, Limits},
    },
    selection::{HeaderRules, VerifiedHeaders},
    snapshot::ImportLimits,
    state_components::Limits as StateLimits,
    store::Store,
};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
fn frame(path: &Path, genesis: &Genesis, policy: crate::eng2::body::Policy) -> (Header, Body) {
    let bytes = std::fs::read(path).unwrap();
    let header = Header::decode(&bytes[..HEADER_BYTES], &genesis.config().network).unwrap();
    let body = Body::decode(
        &bytes[HEADER_BYTES..],
        header.network,
        header.height,
        policy,
    )
    .unwrap();
    assert_eq!(body.commitment(policy).unwrap(), header.body_commitment);
    (header, body)
}
#[test]
#[ignore = "owner-operated single real native depth-one switch with public corpus"]
fn joint_native_real_reorganization_invalidates_completed_and_late_candidate_receipts() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source = PathBuf::from(
        std::env::var_os("SIWORLD_JOINT_REORG_CORPUS").expect("verified public corpus required"),
    );
    let destination = PathBuf::from(
        std::env::var_os("SIWORLD_JOINT_REORG_DESTINATION")
            .expect("fresh disposable database clone required"),
    );
    assert!(source.is_absolute() && destination.is_absolute() && !destination.starts_with(&source));
    assert!(destination.join("disposable-fixture").is_file());
    assert!(!destination.join("branches.redb").exists());
    let genesis_bytes = std::fs::read(source.join("genesis.bin")).unwrap();
    let genesis = || Genesis::decode(&genesis_bytes).unwrap();
    let config = genesis().config().clone();
    assert!(config.fixture && config.pow_iterations == 0);
    let imports = ImportLimits {
        chain: StateLimits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        },
        max_snapshot_bytes: 512 * 1024 * 1024,
    };
    let verifier = NativeVerifier::for_genesis(&genesis()).unwrap();
    let database = destination.join("chain.redb");
    let store = if let Some(custody) = std::env::var_os("SIWORLD_JOINT_REORG_IDENTITY_ROOT") {
        let custody = PathBuf::from(custody);
        assert!(custody.is_absolute() && custody != destination && database.is_file());
        assert!(!destination.join("native-peer-identity.secret").exists());
        let identity =
            crate::identity::NativeIdentity::load(&custody, &genesis().peer_binding()).unwrap();
        Store::resume_qualification_copy(&database, genesis(), imports.chain, identity).unwrap()
    } else if database.is_file() {
        // A fresh process authenticates the actual durable head after any I/O
        // failure. No state from the terminated writer is reused or assumed.
        Store::resume_existing(&database, genesis(), imports.chain).unwrap()
    } else {
        let identity =
            crate::identity::NativeIdentity::initialize(&destination, genesis().peer_binding())
                .unwrap();
        let mut store = Store::create(&database, genesis(), imports.chain).unwrap();
        store.enable_authenticated_restart(identity).unwrap();
        store
    };
    let durable_height = store.engine().state().height();
    assert!(durable_height <= 44);
    eprintln!("joint authenticated durable starting height={durable_height}");
    if durable_height > 0 {
        let (expected, _) = frame(
            &source.join(format!("canonical-{durable_height}.bin")),
            &genesis(),
            store.engine().body_policy(),
        );
        assert_eq!(store.header(durable_height).unwrap(), expected);
    }
    let mut owner = Driver::new(store, verifier, imports).unwrap();
    let baseline = Instant::now();
    for height in durable_height + 1..=44 {
        let (header, body) = frame(
            &source.join(format!("canonical-{height}.bin")),
            &genesis(),
            owner.engine().body_policy(),
        );
        owner.accept(&header, &body).unwrap();
        eprintln!("joint authenticated canonical height={height}");
    }
    eprintln!(
        "joint authenticated remaining canonical admission ms={}",
        baseline.elapsed().as_millis()
    );
    let original = owner.header(44).unwrap();
    assert_eq!(owner.head().unwrap().height, 44);
    assert_eq!(owner.head().unwrap().id, original.id().unwrap());
    assert_eq!(owner.engine().genesis().id(), genesis().id());
    assert_eq!(
        crate::local::hex(&crate::proofs::protocol_profile_fingerprint()),
        "3b54f803105ebaf3f6fc55a5dc39dbd055928a2530e38a0197eac5fba43f7717"
    );
    let budget = p2p::Budget::new(1024 * 1024 * 1024);
    let policy = owner.engine().body_policy();
    let (original, mut candidate_body) =
        frame(&source.join("canonical-44.bin"), &genesis(), policy);
    assert_eq!(owner.head().unwrap().id, original.id().unwrap());
    candidate_body.height = 45;
    let bytes = candidate_body.encode(policy).unwrap();
    let candidate = Header {
        network: original.network,
        height: 45,
        parent: original.id().unwrap(),
        timestamp: original.timestamp + config.target_interval,
        target: owner.engine().state().chain().next_target(),
        execution_commitment: [91; 32],
        body_commitment: candidate_body.commitment(policy).unwrap(),
        nonce: 0,
    };
    let capture = owner.capture_verification(&budget).unwrap();
    let pipeline = capture
        .start(
            &candidate,
            &budget,
            &p2p::Deadline::new(Duration::from_secs(180)),
        )
        .unwrap();
    let mut ledger = DescriptorLedger::new(
        candidate.id().unwrap(),
        &[[1; 32]],
        Limits {
            requests: 4,
            wire_bytes: 4 * bytes.len() as u64,
            peer_requests: 1,
            peer_wire_bytes: 4 * bytes.len() as u64,
            parallel: 1,
            lifetime: Duration::from_secs(180),
        },
        Instant::now(),
    )
    .unwrap();
    let attempt = ledger.begin([1; 32], 8192, Instant::now()).unwrap();
    ledger
        .completed(attempt, 1024, true, Instant::now())
        .unwrap();
    let descriptor = Descriptor::build(&bytes, policy.max_body_bytes).unwrap();
    let producer_descriptor = descriptor.clone();
    let (authenticated, first) = descriptor
        .authenticate(
            &candidate,
            encoded_piece(&bytes, 0).unwrap(),
            policy.max_body_bytes,
        )
        .unwrap();
    let (producer, _) = producer_descriptor
        .authenticate(
            &candidate,
            encoded_piece(&bytes, 0).unwrap(),
            policy.max_body_bytes,
        )
        .unwrap();
    let mut transfer = Transfer::new(authenticated, first, ledger, &budget).unwrap();
    let proof_tail =
        (bytes.len() - candidate_body.settlement_proof.len() + 8).div_ceil(PIECE_BYTES);
    for index in 1..proof_tail {
        transfer
            .index_piece(
                producer
                    .verify(index, encoded_piece(&bytes, index).unwrap())
                    .unwrap(),
                Instant::now(),
            )
            .unwrap();
    }
    assert!(transfer.verified_bytes() < transfer.body_bytes());
    pipeline.observe(&transfer).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    while pipeline.test_counts().2 == 0 {
        assert!(
            Instant::now() < until,
            "real native transaction did not produce an early receipt"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let receipts = pipeline.finish(&transfer).unwrap();
    assert!(receipts.slots.iter().any(Option::is_some));
    assert!(receipts.matches_engine(owner.engine(), &candidate));
    let rules = HeaderRules {
        network: config.network,
        genesis: genesis().id(),
        genesis_timestamp: config.genesis_timestamp,
        genesis_target: config.genesis_target,
        target_interval: config.target_interval,
        pow_iterations: config.pow_iterations,
        max_headers: 1000,
    };
    let archive = BranchStore::create(
        &destination.join("branches.redb"),
        rules.clone(),
        BranchLimits {
            maximum_headers: 2000,
            maximum_body_bytes: 2 * 1024 * 1024 * 1024,
        },
    )
    .unwrap();
    owner
        .enable_reorganization_with_budget(archive, budget.clone())
        .unwrap();
    let (fork44, body44) = frame(&source.join("depth1-44.bin"), &genesis(), policy);
    let (fork45, body45) = frame(&source.join("depth1-45.bin"), &genesis(), policy);
    let mut headers = (1..=43)
        .map(|height| owner.header(height).unwrap())
        .collect::<Vec<_>>();
    headers.push(fork44.clone());
    headers.push(fork45.clone());
    owner
        .retain_competing_headers(&VerifiedHeaders::verify(rules, headers).unwrap())
        .unwrap();
    owner.retain_competing_body(&fork44, &body44).unwrap();
    owner.retain_competing_body(&fork45, &body45).unwrap();
    let switch = Instant::now();
    let mut barriers = 0;
    owner
        .reorganization_tick(|ancestor| {
            assert_eq!(ancestor, 43);
            barriers += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(barriers, 1);
    assert_eq!(owner.head().unwrap().height, 43);
    assert!(!owner.activities_allowed());
    assert!(receipts.invalidated.load(Ordering::Acquire));
    assert!(!receipts.matches_engine(owner.engine(), &candidate));
    assert!(pipeline.observe(&transfer).is_err());
    assert!(
        owner
            .accept_observed_with_receipts(&candidate, &candidate_body, None, Some(&receipts))
            .is_err()
    );
    for _ in 0..2 {
        owner
            .reorganization_tick(|_| panic!("restore barrier repeated"))
            .unwrap();
    }
    assert_eq!(owner.head().unwrap().id, fork45.id().unwrap());
    assert!(owner.activities_allowed());
    assert_eq!(owner.last_reorganization().unwrap().depth, 1);
    owner.store().ensure_exportable().unwrap();
    assert!(receipts.invalidated.load(Ordering::Acquire));
    assert!(!receipts.matches_engine(owner.engine(), &candidate));
    assert!(pipeline.observe(&transfer).is_err());
    eprintln!(
        "joint native actual depth-one switch ms={}",
        switch.elapsed().as_millis()
    );
    let until = Instant::now() + Duration::from_secs(5);
    while pipeline.test_counts().0 != 0 {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(receipts);
    drop(pipeline);
    drop(capture);
    drop(transfer);
}
