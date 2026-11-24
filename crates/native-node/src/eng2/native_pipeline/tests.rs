use super::*;
use crate::eng2::{
    genesis::{FeeMode, Genesis},
    snapshot,
};
use native::multi_asset::F;
use p3_field::PrimeCharacteristicRing;
use std::time::Duration;

fn engine() -> Engine {
    let state = snapshot::tests::bootstrap();
    let genesis = Genesis::seal(
        state.chain.config.clone(),
        state.governance.clone(),
        FeeMode::LegacyMiner,
    )
    .unwrap();
    Engine::new(genesis, snapshot::tests::limits().chain).unwrap()
}

fn header(engine: &Engine) -> Header {
    Header {
        network: engine.state().network(),
        height: engine.state().height() + 1,
        parent: engine.state().tip(),
        timestamp: engine.state().chain().timestamp() + 300,
        target: engine.state().chain().next_target(),
        execution_commitment: [31; 32],
        body_commitment: [37; 32],
        nonce: 0,
    }
}

fn decoded_proof<'a>(
    engine: &Engine,
    transaction: &'a crate::wire::Transaction,
) -> TransactionProof<'a> {
    let snapshot = engine
        .state()
        .chain()
        .snapshot(transaction.record.snapshot)
        .unwrap();
    TransactionProof {
        public: PublicTransaction::decode(&transaction.record.body).unwrap(),
        context: ProofContext::for_snapshot(
            engine.state().network(),
            snapshot.selector.height,
            snapshot.selector.block_id,
        ),
        fee: decode_digest(&transaction.record.fee_commit).unwrap(),
        root: decode_digest(&snapshot.recent_root).unwrap(),
        proof: &transaction.proof,
    }
}

#[test]
fn unchanged_native_profile_matches_the_observed_existing_genesis() {
    // Existing SWE2GEN2 protocol profile, fixed independently of this test.
    let expected = "3b54f803105ebaf3f6fc55a5dc39dbd055928a2530e38a0197eac5fba43f7717";
    let actual = crate::proofs::protocol_profile_fingerprint();
    let encoded: String = actual.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(encoded, expected);
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(
        target_os = "linux",
        target_os = "macos",
        all(target_os = "windows", target_env = "msvc")
    )
))]
#[test]
#[ignore = "owner-operated full RandomX dataset and real native proofs; excluded from CI"]
fn randomx_real_block_is_admitted_by_independent_store_and_reopens() {
    use crate::eng2::{
        producer::{self, Search},
        store::Store,
    };
    use std::time::Instant;

    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let path = std::path::PathBuf::from(
        std::env::var_os("SIWORLD_RANDOMX_FIXTURE_DIR").expect("disposable local directory"),
    );
    assert!(path.is_absolute() && path.join("disposable-fixture").is_file());
    let origin = path.join("origin");
    let replica = path.join("replica");
    for directory in [&origin, &replica] {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(directory).unwrap();
    }
    let state = snapshot::tests::bootstrap();
    let prior = state.chain.config.clone();
    let config = crate::state::Config::asert_development(prior.network, 1, [255; 32], 1)
        .unwrap()
        .with_fund_wallets(prior.fund_allocation.unwrap(), prior.fund_verifying_keys)
        .unwrap()
        .with_siworld_randomx()
        .unwrap();
    let bytes = Genesis::seal_with_rule(
        config,
        state.governance,
        FeeMode::LegacyMiner,
        crate::wire::SlotRule::PublicGenesis,
    )
    .unwrap()
    .encode()
    .unwrap();
    let genesis = || Genesis::decode(&bytes).unwrap();
    let limits = snapshot::tests::limits().chain;
    let open = |path: &std::path::Path| {
        let genesis = genesis();
        let identity =
            crate::identity::NativeIdentity::initialize(path, genesis.peer_binding()).unwrap();
        let mut store = Store::create(&path.join("chain.redb"), genesis, limits).unwrap();
        store.enable_authenticated_restart(identity).unwrap();
        store
    };
    let mut producer_store = open(&origin);
    let mut replica_store = open(&replica);
    let prover =
        crate::proofs::NativeProver::for_genesis(producer_store.engine().genesis()).unwrap();
    let verifier = NativeVerifier::for_genesis(replica_store.engine().genesis()).unwrap();
    let settings = crate::producer::MiningSettings {
        mode: crate::wire::RewardMode::Voyager,
        recipient: crate::wallet::WalletKeys::from_seed(
            prior.network,
            zeroize::Zeroizing::new([55; 32]),
            0,
        )
        .unwrap()
        .address(),
    };

    let start = Instant::now();
    let slots = (0..16)
        .map(|_| crate::producer::prepare_padding(producer_store.engine().state().chain(), &prover))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let preparation = Instant::now();
    let engine = producer_store.engine();
    let mut work = producer::prepare(engine, slots, 301, &settings, None, Vec::new())
        .unwrap()
        .prove(&prover)
        .unwrap()
        .prepare_work(engine, &verifier)
        .unwrap();
    let search_start = Instant::now();
    let block = loop {
        assert!(search_start.elapsed() < Duration::from_secs(90));
        match work.search(1).unwrap() {
            Search::Found(block) => break block,
            Search::Pending(next) => {
                assert_eq!(
                    next.next_nonce(),
                    0,
                    "the minimum-work fixture uses one nonce"
                );
                work = next;
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    let body_accepted = Instant::now();
    producer_store
        .append(&block.header, &block.body, &verifier)
        .unwrap();
    let receive = Instant::now();
    let frame = block
        .body
        .encode(producer_store.engine().body_policy())
        .unwrap();
    let decoded = crate::eng2::body::Body::decode(
        &frame,
        block.header.network,
        block.header.height,
        replica_store.engine().body_policy(),
    )
    .unwrap();
    replica_store
        .append(&block.header, &decoded, &verifier)
        .unwrap();
    let acceptance = receive.elapsed();
    drop(replica_store);
    let reopened = Store::resume_existing(&replica.join("chain.redb"), genesis(), limits).unwrap();
    assert_eq!(reopened.engine().state().tip(), block.header.id().unwrap());
    assert_eq!(reopened.header(1).unwrap(), block.header);
    assert_eq!(reopened.engine().state().height(), 1);
    eprintln!(
        "padding_ms={} template_ms={} cold_dataset_and_search_ms={} replica_validation_ms={} body_bytes={}",
        (preparation - start).as_millis(),
        (search_start - preparation).as_millis(),
        (body_accepted - search_start).as_millis(),
        acceptance.as_millis(),
        frame.len(),
    );
}

#[test]
fn exact_receipt_key_rejects_proof_snapshot_fee_root_and_public_mutations() {
    let engine = engine();
    let mut transaction = crate::eng2::body::tests::body().transactions.remove(0);
    transaction.record.snapshot = engine.state().chain().tip_snapshot().selector;
    let proof = decoded_proof(&engine, &transaction);
    let key = proof_key(&proof);
    let mut changed = transaction.clone();
    changed.proof[0] ^= 1;
    assert_ne!(proof_key(&decoded_proof(&engine, &changed)), key);
    let mut changed_proof = decoded_proof(&engine, &transaction);
    changed_proof.context = ProofContext::for_snapshot(engine.state().network(), 1, [99; 32]);
    assert_ne!(proof_key(&changed_proof), key);
    changed_proof = decoded_proof(&engine, &transaction);
    changed_proof.fee[0] += F::ONE;
    assert_ne!(proof_key(&changed_proof), key);
    changed_proof = decoded_proof(&engine, &transaction);
    changed_proof.root[0] += F::ONE;
    assert_ne!(proof_key(&changed_proof), key);
    changed_proof = decoded_proof(&engine, &transaction);
    changed_proof.public.nf[0][0] += F::ONE;
    assert_ne!(proof_key(&changed_proof), key);
}

#[test]
fn parent_header_profile_and_genesis_changes_invalidate_every_receipt() {
    let engine = engine();
    let budget = p2p::Budget::new(16 * 1024 * 1024);
    let capture = Capture::new(
        &engine,
        Arc::new(NativeVerifier::for_genesis(engine.genesis()).unwrap()),
        &budget,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let original = header(&engine);
    let mut receipts = CandidateReceipts {
        binding: capture.binding.clone(),
        block: original.id().unwrap(),
        slots: Vec::new(),
        _metadata: Arc::new(budget.reserve(65_536).unwrap()),
        invalidated: Arc::clone(&capture.invalidated),
    };
    assert!(receipts.matches_engine(&engine, &original));
    let mut changed = original.clone();
    changed.parent[0] ^= 1;
    assert!(!receipts.matches_engine(&engine, &changed));
    changed = original.clone();
    changed.nonce += 1;
    assert!(!receipts.matches_engine(&engine, &changed));
    receipts.binding.profile[0] ^= 1;
    assert!(!receipts.matches_engine(&engine, &original));
    receipts.binding = capture.binding.clone();
    receipts.binding.genesis[0] ^= 1;
    assert!(!receipts.matches_engine(&engine, &original));
    receipts.binding = capture.binding.clone();
    capture.invalidated.store(true, Ordering::Release);
    assert!(!receipts.matches_engine(&engine, &original));
}

#[test]
fn cancelled_candidate_never_starts_or_finishes_a_receipt() {
    let engine = engine();
    let budget = p2p::Budget::new(16 * 1024 * 1024);
    let capture = Capture::new(
        &engine,
        Arc::new(NativeVerifier::for_genesis(engine.genesis()).unwrap()),
        &budget,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let cancellation = p2p::Cancellation::default();
    let deadline = p2p::Deadline::cancellable(Duration::from_secs(5), cancellation.clone());
    let pipeline = capture.start(&header(&engine), &budget, &deadline).unwrap();
    cancellation.cancel();
    assert!(capture.start(&header(&engine), &budget, &deadline).is_err());
    assert!(
        pipeline
            .verify_envelope(&[0; 1], verification_executor::acquire())
            .is_none()
    );
}

#[test]
#[ignore = "owner-operated real native proof verification; excluded from bounded CI"]
fn actual_salted_native_verifier_is_required_before_a_receipt_exists() {
    let engine = engine();
    let budget = p2p::Budget::new(16 * 1024 * 1024);
    let verifier = Arc::new(NativeVerifier::for_genesis(engine.genesis()).unwrap());
    let capture = Capture::new(
        &engine,
        Arc::clone(&verifier),
        &budget,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let fixture =
        std::env::var_os("SIWORLD_NATIVE_PIPELINE_TEST_ENVELOPE").map(std::path::PathBuf::from);
    let generated = std::time::Instant::now();
    let envelope = if let Some(path) = fixture.as_ref().filter(|path| path.is_file()) {
        let metadata = path.metadata().unwrap();
        assert!(metadata.len() <= crate::wire::MAX_ENVELOPE_BYTES as u64);
        std::fs::read(path).unwrap()
    } else {
        let prover = crate::proofs::NativeProver::for_genesis(engine.genesis()).unwrap();
        let padding = crate::producer::prepare_padding(engine.state().chain(), &prover).unwrap();
        let envelope = padding
            .transaction
            .encode_envelope(&engine.state().network())
            .unwrap();
        // Only the public envelope is retained; settlement openings and witness
        // material never enter this optional owner-operated test fixture.
        if let Some(path) = fixture {
            std::fs::write(path, &envelope).unwrap();
        }
        envelope
    };
    let transaction =
        crate::wire::Transaction::decode_envelope(&envelope, &engine.state().network()).unwrap();
    eprintln!(
        "public native fixture preparation ms={}",
        generated.elapsed().as_millis()
    );
    let verified = std::time::Instant::now();
    let deadline = p2p::Deadline::new(Duration::from_secs(180));
    let pipeline = capture.start(&header(&engine), &budget, &deadline).unwrap();
    let receipt = pipeline
        .verify_envelope(&envelope, verification_executor::acquire())
        .unwrap();
    assert_eq!(
        receipt.key,
        proof_key(&decoded_proof(&engine, &transaction))
    );
    let mut corrupt = envelope.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(
        pipeline
            .verify_envelope(&corrupt, verification_executor::acquire())
            .is_none()
    );
    eprintln!(
        "native receipt authenticated envelope bytes={}, valid plus corrupt verification ms={}",
        envelope.len(),
        verified.elapsed().as_millis()
    );
}

#[test]
fn authenticated_slots_start_native_jobs_before_the_remaining_body_arrives() {
    use std::time::Instant;
    let engine = engine();
    let budget = p2p::Budget::new(64 * 1024 * 1024);
    let capture = Capture::new(
        &engine,
        Arc::new(NativeVerifier::for_genesis(engine.genesis()).unwrap()),
        &budget,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let (header, transfer, total_bytes) = partial_transfer(&engine, &budget, false);
    assert!(transfer.verified_bytes() < total_bytes);
    let pipeline = capture
        .start(
            &header,
            &budget,
            &p2p::Deadline::new(Duration::from_secs(180)),
        )
        .unwrap();
    pipeline.observe(&transfer).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let state = pipeline.state.lock().unwrap();
        assert!(state.pending <= 4);
        if state.completed > 0 {
            break;
        }
        assert!(
            Instant::now() < until,
            "authenticated slots did not reach the native verifier"
        );
        let _state = pipeline
            .changed
            .wait_timeout(state, Duration::from_millis(10))
            .unwrap();
    }
    // Synthetic proof bytes were actually rejected. No successful receipt was
    // manufactured merely because the authenticated range and framing matched.
    assert!(
        pipeline
            .state
            .lock()
            .unwrap()
            .receipts
            .iter()
            .all(Option::is_none)
    );
    assert!(transfer.verified_bytes() < total_bytes);
}

fn partial_transfer(
    engine: &Engine,
    budget: &p2p::Budget,
    complete: bool,
) -> (Header, Transfer, usize) {
    use crate::eng2::propagation::{
        authentication::{Descriptor, encoded_piece},
        pipeline::{DescriptorLedger, Limits},
    };
    use std::time::Instant;
    let mut body = crate::eng2::body::tests::body();
    body.network = engine.state().network();
    body.height = engine.state().height() + 1;
    body.profile = engine.body_policy().profile;
    body.governance.clear();
    body.fund_claims.clear();
    body.issuances.clear();
    body.fee_output = crate::eng2::execution::legacy_fee_output();
    body.settlement_proof = vec![7; 128 * 1024];
    for transaction in &mut body.transactions {
        transaction.record.snapshot = engine.state().chain().tip_snapshot().selector;
    }
    body.transactions
        .sort_by_key(|transaction| transaction.record.statement_id(&body.network));
    let policy = engine.body_policy();
    let encoded = body.encode(policy).unwrap();
    let mut header = header(engine);
    header.body_commitment = body.commitment(policy).unwrap();
    let limits = Limits {
        requests: 4,
        wire_bytes: (encoded.len() * 5) as u64,
        peer_requests: 1,
        peer_wire_bytes: (encoded.len() * 5) as u64,
        parallel: 2,
        lifetime: Duration::from_secs(180),
    };
    let mut ledger = DescriptorLedger::new(
        header.id().unwrap(),
        &[[1; 32], [2; 32]],
        limits,
        Instant::now(),
    )
    .unwrap();
    let attempt = ledger.begin([1; 32], 8192, Instant::now()).unwrap();
    ledger
        .completed(attempt, 1024, true, Instant::now())
        .unwrap();
    let descriptor = Descriptor::build(&encoded, policy.max_body_bytes).unwrap();
    let (authenticated, first) = descriptor
        .clone()
        .authenticate(
            &header,
            encoded_piece(&encoded, 0).unwrap(),
            policy.max_body_bytes,
        )
        .unwrap();
    let (producer, _) = descriptor
        .authenticate(
            &header,
            encoded_piece(&encoded, 0).unwrap(),
            policy.max_body_bytes,
        )
        .unwrap();
    let mut transfer = Transfer::new(authenticated, first, ledger, budget).unwrap();
    let indices = if complete {
        (0..producer.piece_count()).collect()
    } else {
        framing::index_pieces(&body, policy).unwrap()
    };
    for index in indices {
        if index != 0 {
            transfer
                .index_piece(
                    producer
                        .verify(index, encoded_piece(&encoded, index).unwrap())
                        .unwrap(),
                    Instant::now(),
                )
                .unwrap();
        }
    }
    (header, transfer, encoded.len())
}

#[test]
fn a_complete_body_does_not_wait_for_all_busy_native_workers_to_freeze_receipts() {
    use std::time::Instant;
    let engine = engine();
    let budget = p2p::Budget::new(64 * 1024 * 1024);
    let capture = Capture::new(
        &engine,
        Arc::new(NativeVerifier::for_genesis(engine.genesis()).unwrap()),
        &budget,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let (header, transfer, total) = partial_transfer(&engine, &budget, true);
    assert_eq!(transfer.verified_bytes(), total);
    let pipeline = capture
        .start(
            &header,
            &budget,
            &p2p::Deadline::new(Duration::from_secs(1)),
        )
        .unwrap();
    // Use one atomic batch reservation: neither this test nor a concurrent
    // final batch may partially reserve four permits and deadlock the other.
    let held = verification_executor::acquire_all_for_test();
    pipeline.observe(&transfer).unwrap();
    let started = Instant::now();
    let receipts = pipeline.finish(&transfer).unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(receipts.slots.iter().all(Option::is_none));
    assert_eq!(pipeline.state.lock().unwrap().pending, 0);
    assert!(pipeline.observe(&transfer).is_err());
    drop(held);
}
