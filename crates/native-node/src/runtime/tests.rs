use super::*;
use crate::fixtures::{TestVerifier, candidate};
use crate::state::{Config, State};
use crate::wire::{Sidecar, Transaction};
use native::codec::encode_digest;
use native::multi_asset::{F, Hasher};
use p3_field::PrimeCharacteristicRing;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "siworld-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn setup(dir: &Directory) -> Node<TestVerifier> {
    let config = Config::development([131; 32], 0).unwrap();
    Node::new(
        Store::open(dir.0.join("chain.redb"), config, &TestVerifier).unwrap(),
        TestVerifier,
    )
}
fn payment(state: &State) -> (Transaction, Sidecar) {
    let mut tx = candidate(state, 300).transactions.remove(0);
    let blind = [F::from_u32(22); 8];
    tx.record.fee_commit = encode_digest(&Hasher::new().fee_commit(100, &blind));
    let sidecar = Sidecar {
        transaction_id: tx.record.statement_id(&state.config.network),
        fee: 100,
        blind: [22; 8],
    };
    (tx, sidecar)
}
#[test]
fn admission_and_canonical_inclusion_share_reservations() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let (tx, sidecar) = payment(node.state());
    let envelope = tx.encode_envelope(&node.state().config.network).unwrap();
    let id = node
        .submit_local(&envelope, Some(&sidecar.encode().unwrap()))
        .unwrap();
    assert_eq!(node.mempool().len(), 1);
    let mut block = candidate(node.state(), 10000);
    block.transactions[0] = tx;
    block
        .transactions
        .sort_by_key(|t| t.record.statement_id(&block.network));
    assert!(matches!(
        node.import_branch(0, &[block], CandidatePolicy::default())
            .unwrap(),
        BranchOutcome::Adopted { .. }
    ));
    assert!(!node.mempool().contains(&id));
    assert_eq!(node.state().height, 1);
}
#[test]
fn rejected_sidecar_and_branch_leave_head_and_pending_unchanged() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let before = node.state().fingerprint();
    let (tx, mut sidecar) = payment(node.state());
    let envelope = tx.encode_envelope(&node.state().config.network).unwrap();
    sidecar.fee += 1;
    assert!(
        node.submit_local(&envelope, Some(&sidecar.encode().unwrap()))
            .is_err()
    );
    assert_eq!(node.mempool().len(), 0);
    assert_eq!(node.state().fingerprint(), before);
    sidecar.fee -= 1;
    node.submit_local(&envelope, Some(&sidecar.encode().unwrap()))
        .unwrap();
    let mut block = candidate(node.state(), 10000);
    block.settlement_proof = vec![2];
    assert!(
        node.import_branch(0, &[block], CandidatePolicy::default())
            .is_err()
    );
    assert_eq!(node.mempool().len(), 1);
    assert_eq!(node.state().fingerprint(), before);
}
#[test]
fn batch_metadata_requires_exact_lengths_counts_and_flags() {
    let snapshot = Snapshot {
        height: 0,
        block_id: [1; 32],
    };
    let good = BatchMeta {
        ancestor: snapshot,
        after: snapshot,
        count: 1,
        more: true,
    };
    let bytes = good.encode();
    assert_eq!(BatchMeta::decode(&bytes).unwrap(), good);
    for mode in 0..3 {
        let mut bad = bytes.to_vec();
        match mode {
            0 => bad.push(0),
            1 => bad[82] = 2,
            _ => bad[80..82].copy_from_slice(&17u16.to_le_bytes()),
        };
        assert!(BatchMeta::decode(&bad).is_err());
    }
}
#[test]
fn missing_requests_reject_duplicates_and_excess() {
    let r = Reference {
        statement: [1; 32],
        proof: [2; 32],
    };
    assert_eq!(
        decode_references(&encode_references(&[r]).unwrap()).unwrap(),
        vec![r]
    );
    assert!(encode_references(&[r, r]).is_err());
    assert!(decode_references(&[0, 0]).is_err());
    let refs: Vec<_> = (0..17u8)
        .map(|n| Reference {
            statement: [n; 32],
            proof: [n + 1; 32],
        })
        .collect();
    assert!(encode_references(&refs).is_err());
}
#[test]
fn gossip_codec_requires_exact_sidecar_and_rejects_trailing_bytes() {
    let dir = Directory::new();
    let node = setup(&dir);
    let (tx, sidecar) = payment(node.state());
    let bytes = encode_gossip(&tx, &sidecar, &node.state().config.network).unwrap();
    let (envelope, opening) = decode_gossip(&bytes).unwrap();
    assert_eq!(opening, &sidecar.encode().unwrap());
    assert_eq!(
        Transaction::decode_envelope(envelope, &node.state().config.network).unwrap(),
        tx
    );
    let mut extra = bytes;
    extra.push(0);
    assert!(decode_gossip(&extra).is_err());
}

// Scripted channels exercise framing and runtime composition. Minting this
// crate-private test capability does not test or provide hybrid authentication.
struct Scripted {
    input: std::io::Cursor<Vec<u8>>,
    output: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    timeout_at_eof: bool,
}
impl Read for Scripted {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self.timeout_at_eof && self.input.position() as usize == self.input.get_ref().len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "scripted deadline",
            ));
        }
        self.input.read(bytes)
    }
}
impl Write for Scripted {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.output.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
type Captured = std::sync::Arc<std::sync::Mutex<Vec<u8>>>;
fn frame(binding: p2p::Binding, kind: u8, request: u64, body: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(p2p::HEADER_BYTES + body.len());
    header.extend_from_slice(b"SWPF");
    header.extend_from_slice(&p2p::VERSION.to_le_bytes());
    header.push(kind);
    header.extend_from_slice(&request.to_le_bytes());
    header.extend_from_slice(&binding.network);
    header.extend_from_slice(&(body.len() as u32).to_le_bytes());
    assert_eq!(header.len(), p2p::HEADER_BYTES);
    header.extend_from_slice(body);
    header
}
fn scripted(
    node: &Node<TestVerifier>,
    peer: Hash,
    packets: Vec<Vec<u8>>,
) -> (Session<Scripted>, Captured) {
    scripted_with_budget(node, peer, packets, node.transport_budget())
}
fn scripted_with_budget(
    node: &Node<TestVerifier>,
    peer: Hash,
    packets: Vec<Vec<u8>>,
    budget: Budget,
) -> (Session<Scripted>, Captured) {
    let binding = node.binding();
    let mut input = p2p::Hello {
        binding,
        role: p2p::Role::Validator,
    }
    .encode()
    .to_vec();
    for packet in packets {
        input.extend(packet);
    }
    let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let channel = Scripted {
        input: std::io::Cursor::new(input),
        output: output.clone(),
        timeout_at_eof: false,
    };
    let admission = p2p::test_support::admission(binding, peer, p2p::ConnectionRole::Initiator);
    let capability = p2p::Authenticated::from_verified_provider(
        channel,
        &admission,
        admission.role(),
        admission.expected_peer().descriptor(),
        p2p::test_support::parameters(),
    )
    .unwrap();
    let session = Session::establish(capability, &admission, p2p::Role::Validator, budget).unwrap();
    (session, output)
}
fn sent(output: &Captured) -> Vec<(u8, u64, Vec<u8>)> {
    let bytes = output.lock().unwrap();
    let mut offset = p2p::HELLO_BYTES;
    let mut frames = Vec::new();
    while offset < bytes.len() {
        let header = &bytes[offset..offset + p2p::HEADER_BYTES];
        assert_eq!(&header[..4], b"SWPF");
        let kind = header[6];
        let request = u64::from_le_bytes(header[7..15].try_into().unwrap());
        let length = u32::from_le_bytes(header[47..51].try_into().unwrap()) as usize;
        offset += p2p::HEADER_BYTES;
        frames.push((kind, request, bytes[offset..offset + length].to_vec()));
        offset += length;
    }
    frames
}
fn full_budget_available(budget: &Budget) -> bool {
    budget.reserve(p2p::CONNECTION_BYTES).is_ok()
}
fn replies(
    node: &Node<TestVerifier>,
    request: u64,
    meta: BatchMeta,
    blocks: &[Block],
) -> Vec<Vec<u8>> {
    let binding = node.binding();
    let mut packets = vec![frame(binding, p2p::SYNC_META, request, &meta.encode())];
    for block in blocks {
        packets.push(frame(
            binding,
            p2p::BLOCK,
            request,
            &block.encode().unwrap(),
        ));
    }
    packets.push(frame(binding, p2p::END_BATCH, request, &[]));
    packets
}

#[test]
fn scripted_gossip_admits_only_a_matching_sidecar_and_exact_compact_recovery_omits_it() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let (transaction, sidecar) = payment(node.state());
    let binding = node.binding();
    let gossip = encode_gossip(&transaction, &sidecar, &binding.network).unwrap();
    let reference = sync::reference(&transaction, &binding.network);
    let requests = vec![
        frame(binding, p2p::TRANSACTION, 71, &gossip),
        frame(
            binding,
            p2p::GET_TRANSACTIONS,
            72,
            &encode_references(&[reference]).unwrap(),
        ),
    ];
    let (mut session, output) = scripted(&node, [41; 32], requests);
    node.serve_once(&mut session).unwrap();
    assert_eq!(node.mempool().len(), 1);
    assert!(sent(&output).is_empty());
    node.serve_once(&mut session).unwrap();
    let responses = sent(&output);
    assert_eq!(responses.len(), 2);
    assert_eq!((responses[0].0, responses[0].1), (p2p::TRANSACTION, 72));
    assert_eq!(
        Transaction::decode_envelope(&responses[0].2, &binding.network).unwrap(),
        transaction
    );
    assert_eq!(
        (responses[1].0, responses[1].1, responses[1].2.len()),
        (p2p::END_BATCH, 72, 0)
    );
    drop(session);
    assert!(full_budget_available(&node.transport_budget()));
}

#[test]
fn serving_a_locator_echoes_the_request_and_streams_valid_bound_blocks() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let first = candidate(node.state(), 10_000);
    node.import_branch(0, std::slice::from_ref(&first), CandidatePolicy::default())
        .unwrap();
    let second = candidate(node.state(), 100_000);
    node.import_branch(1, std::slice::from_ref(&second), CandidatePolicy::default())
        .unwrap();
    let genesis = Snapshot {
        height: 0,
        block_id: node.state().config.genesis_id(),
    };
    let mut request = vec![0];
    request.extend(
        Locator {
            entries: vec![genesis],
        }
        .encode()
        .unwrap(),
    );
    let (mut session, output) = scripted(
        &node,
        [42; 32],
        vec![frame(node.binding(), p2p::GET_BLOCKS, 73, &request)],
    );
    node.serve_once(&mut session).unwrap();
    let responses = sent(&output);
    let meta = BatchMeta::decode(&responses[0].2).unwrap();
    assert_eq!((meta.ancestor, meta.after), (genesis, genesis));
    assert!((1..=2).contains(&meta.count));
    assert_eq!(meta.more, meta.count == 1);
    assert_eq!(responses.len(), usize::from(meta.count) + 2);
    assert!(responses.iter().all(|response| response.1 == 73));
    assert_eq!(responses[0].0, p2p::SYNC_META);
    assert_eq!(responses.last().unwrap().0, p2p::END_BATCH);
    assert!(responses.last().unwrap().2.is_empty());
    for (index, response) in responses[1..responses.len() - 1].iter().enumerate() {
        assert_eq!(response.0, p2p::BLOCK);
        let block = Block::decode(&response.2, &node.state().config.network).unwrap();
        assert_eq!(
            block,
            if index == 0 {
                first.clone()
            } else {
                second.clone()
            }
        );
    }
    drop(session);
    assert!(full_budget_available(&node.transport_budget()));
}

#[test]
fn synchronization_rejects_each_wrong_response_request_without_mutating_or_retaining() {
    for mismatch in 0..4 {
        let dir = Directory::new();
        let mut node = setup(&dir);
        let fingerprint = node.state().fingerprint();
        let base = node.state().tip_snapshot().selector;
        let block = candidate(node.state(), 10_000);
        let meta = BatchMeta {
            ancestor: base,
            after: base,
            count: 1,
            more: false,
        };
        let binding = node.binding();
        let mut packets = replies(&node, 74, meta, &[block]);
        match mismatch {
            0 => packets[0] = frame(binding, p2p::SYNC_META, 75, &meta.encode()),
            1 => packets[1][7..15].copy_from_slice(&75u64.to_le_bytes()),
            2 => packets[2] = frame(binding, p2p::END_BATCH, 75, &[]),
            _ => packets[2] = frame(binding, p2p::END_BATCH, 74, &[1]),
        }
        let (mut session, _) = scripted(&node, [43; 32], packets);
        let mut attempt = SyncAttempt::default();
        assert!(node.synchronize(&mut session, 74, &mut attempt).is_err());
        assert_eq!(node.state().fingerprint(), fingerprint);
        assert!(
            attempt.peer.is_none() && attempt.staging.is_none() && attempt.reservations.is_empty()
        );
        drop(session);
        assert!(full_budget_available(&node.transport_budget()));
    }
}

#[test]
fn a_verified_work_extension_is_adopted_and_all_packet_reservations_are_released() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let base = node.state().tip_snapshot().selector;
    let block = candidate(node.state(), 10_000);
    let expected = block.id().unwrap();
    let meta = BatchMeta {
        ancestor: base,
        after: base,
        count: 1,
        more: false,
    };
    let (mut session, output) = scripted(&node, [44; 32], replies(&node, 76, meta, &[block]));
    let mut attempt = SyncAttempt::default();
    assert!(!node.synchronize(&mut session, 76, &mut attempt).unwrap());
    assert_eq!((node.state().height, node.state().tip), (1, expected));
    assert!(attempt.peer.is_none() && attempt.staging.is_none() && attempt.reservations.is_empty());
    let requests = sent(&output);
    assert_eq!((requests[0].0, requests[0].1), (p2p::GET_BLOCKS, 76));
    assert_eq!(requests.len(), 1);
    drop(session);
    assert!(full_budget_available(&node.transport_budget()));
}

#[test]
fn staged_lower_work_forks_hold_guards_until_adoption_then_release_every_batch() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let mut fork = State::new(node.state().config.clone()).unwrap();
    let base = fork.tip_snapshot().selector;
    for seed in [10_000, 100_000] {
        let block = candidate(node.state(), seed);
        node.import_branch(node.state().height, &[block], CandidatePolicy::default())
            .unwrap();
    }
    let original = node.state().fingerprint();
    let mut attempt = SyncAttempt::default();
    let mut after = base;
    for (index, seed) in [200_000, 300_000, 400_000].into_iter().enumerate() {
        let block = candidate(&fork, seed);
        fork.apply(&block, &TestVerifier).unwrap();
        let meta = BatchMeta {
            ancestor: base,
            after,
            count: 1,
            more: index < 2,
        };
        let request = 80 + index as u64;
        let (mut session, output) =
            scripted(&node, [45; 32], replies(&node, request, meta, &[block]));
        assert_eq!(
            node.synchronize(&mut session, request, &mut attempt)
                .unwrap(),
            index < 2
        );
        let requests = sent(&output);
        assert_eq!(requests.len(), 1);
        if index > 0 {
            assert_eq!(requests[0].2, encode_continue(base, after));
        }
        drop(session);
        if index < 2 {
            assert_eq!(node.state().fingerprint(), original);
            assert_eq!(attempt.reservations.len(), index + 1);
            assert!(!full_budget_available(&node.transport_budget()));
        } else {
            assert_eq!(node.state().fingerprint(), fork.fingerprint());
            assert!(
                attempt.peer.is_none()
                    && attempt.staging.is_none()
                    && attempt.reservations.is_empty()
            );
            assert!(full_budget_available(&node.transport_budget()));
        }
        after = fork.tip_snapshot().selector;
    }
}

#[test]
fn retryable_remote_unavailability_discards_the_staged_attempt_and_its_guards() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let mut fork = State::new(node.state().config.clone()).unwrap();
    let base = fork.tip_snapshot().selector;
    for seed in [10_000, 100_000] {
        let block = candidate(node.state(), seed);
        node.import_branch(node.state().height, &[block], CandidatePolicy::default())
            .unwrap();
    }
    let block = candidate(&fork, 200_000);
    fork.apply(&block, &TestVerifier).unwrap();
    let meta = BatchMeta {
        ancestor: base,
        after: base,
        count: 1,
        more: true,
    };
    let (mut session, _) = scripted(&node, [46; 32], replies(&node, 83, meta, &[block]));
    let mut attempt = SyncAttempt::default();
    node.synchronize(&mut session, 83, &mut attempt).unwrap();
    drop(session);
    assert!(!full_budget_available(&node.transport_budget()));
    let fingerprint = node.state().fingerprint();
    let unavailable = frame(node.binding(), p2p::UNAVAILABLE, 84, &[]);
    let (mut session, _) = scripted(&node, [46; 32], vec![unavailable]);
    assert!(matches!(
        node.synchronize(&mut session, 84, &mut attempt),
        Err(Error::Transport(p2p::Error::Unavailable))
    ));
    assert_eq!(node.state().fingerprint(), fingerprint);
    assert!(attempt.peer.is_none() && attempt.staging.is_none() && attempt.reservations.is_empty());
    drop(session);
    assert!(full_budget_available(&node.transport_budget()));
}

#[test]
fn exact_missing_proof_responses_retain_guards_without_admitting_sidecarless_transactions() {
    let dir = Directory::new();
    let node = setup(&dir);
    let (transaction, _) = payment(node.state());
    let reference = sync::reference(&transaction, &node.state().config.network);
    let envelope = transaction
        .encode_envelope(&node.state().config.network)
        .unwrap();
    for mismatch in 0..3 {
        let binding = node.binding();
        let mut response = transaction.clone();
        if mismatch == 2 {
            response.proof = vec![1, 1];
        }
        let body = if mismatch == 2 {
            response.encode_envelope(&binding.network).unwrap()
        } else {
            envelope.clone()
        };
        let packets = vec![
            frame(
                binding,
                p2p::TRANSACTION,
                if mismatch == 1 { 86 } else { 85 },
                &body,
            ),
            frame(binding, p2p::END_BATCH, 85, &[]),
        ];
        let (mut session, _) = scripted(&node, [47; 32], packets);
        let result = node.fetch_missing(&mut session, 85, &[reference]);
        drop(session);
        if mismatch == 0 {
            let recovered = result.unwrap();
            assert_eq!(recovered.transactions(), std::slice::from_ref(&transaction));
            assert!(!full_budget_available(&node.transport_budget()));
            drop(recovered);
        } else {
            assert!(result.is_err());
        }
        assert_eq!(node.mempool().len(), 0);
        assert!(full_budget_available(&node.transport_budget()));
    }
}

#[test]
fn sessions_with_an_independent_budget_cannot_mutate_the_node() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let (transaction, sidecar) = payment(node.state());
    let bytes = encode_gossip(&transaction, &sidecar, &node.state().config.network).unwrap();
    let packet = frame(node.binding(), p2p::TRANSACTION, 87, &bytes);
    let (mut session, _) = scripted_with_budget(&node, [48; 32], vec![packet], Budget::default());
    assert!(matches!(
        node.serve_once(&mut session),
        Err(Error::Transport(p2p::Error::InvalidProtocol))
    ));
    assert!(node.mempool().is_empty());
    assert!(full_budget_available(&node.transport_budget()));
}

fn pending_compact_block(node: &mut Node<TestVerifier>) -> Block {
    let mut block = candidate(node.state(), 500_000);
    let network = node.state().config.network;
    for (index, transaction) in block.transactions.iter_mut().enumerate() {
        let blind = [F::from_usize(index + 1); 8];
        transaction.record.fee_commit = encode_digest(&Hasher::new().fee_commit(100, &blind));
        let sidecar = Sidecar {
            transaction_id: transaction.record.statement_id(&network),
            fee: 100,
            blind: [index as u32 + 1; 8],
        };
        node.submit_local(
            &transaction.encode_envelope(&network).unwrap(),
            Some(&sidecar.encode().unwrap()),
        )
        .unwrap();
    }
    block
        .transactions
        .sort_by_key(|transaction| transaction.record.statement_id(&network));
    block
}

#[test]
fn compact_adoption_rechecks_proofs_and_releases_all_pending_and_transport_reservations() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let block = pending_compact_block(&mut node);
    let compact = CompactBlock::from_block(&block).unwrap();
    let packet = frame(
        node.binding(),
        p2p::COMPACT_BLOCK,
        88,
        &compact.encode().unwrap(),
    );
    let (mut session, output) = scripted(&node, [49; 32], vec![packet]);
    node.serve_once(&mut session).unwrap();
    assert_eq!(
        (node.state().height, node.state().tip),
        (1, block.id().unwrap())
    );
    assert!(node.mempool().is_empty());
    assert_eq!(
        sent(&output),
        vec![(p2p::END_BATCH, 88, block.id().unwrap().to_vec())]
    );
    drop(session);
    assert!(full_budget_available(&node.transport_budget()));
}

#[test]
fn compact_relay_fetches_every_missing_slot_and_exact_proof_before_atomic_import() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let block = candidate(node.state(), 700_000);
    let compact = CompactBlock::from_block(&block).unwrap();
    let binding = node.binding();
    let request = 100;
    let mut packets = vec![frame(
        binding,
        p2p::COMPACT_BLOCK,
        request,
        &compact.encode().unwrap(),
    )];
    for chunk in block.transactions.chunks(sync::MAX_MISSING) {
        for transaction in chunk {
            packets.push(frame(
                binding,
                p2p::TRANSACTION,
                request,
                &transaction.encode_envelope(&binding.network).unwrap(),
            ));
        }
        packets.push(frame(binding, p2p::END_BATCH, request, &[]));
    }
    let (mut session, output) = scripted(&node, [61; 32], packets);
    node.serve_once(&mut session).unwrap();
    assert_eq!(node.state().tip, block.id().unwrap());
    assert!(
        node.mempool().is_empty(),
        "sidecarless reconstruction must not enter the mempool"
    );
    let sent = sent(&output);
    assert_eq!(
        sent.len(),
        block.transactions.len().div_ceil(sync::MAX_MISSING) + 1
    );
    for (index, chunk) in compact.references.chunks(sync::MAX_MISSING).enumerate() {
        assert_eq!(
            sent[index],
            (
                p2p::GET_TRANSACTIONS,
                request,
                encode_references(chunk).unwrap()
            )
        );
    }
    assert_eq!(
        sent.last().unwrap(),
        &(p2p::END_BATCH, request, block.id().unwrap().to_vec())
    );
    drop(session);
    assert!(full_budget_available(&node.transport_budget()));
}

#[test]
fn compact_recovery_requests_only_missing_exact_references() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let (known, sidecar) = payment(node.state());
    let binding = node.binding();
    node.submit_local(
        &known.encode_envelope(&binding.network).unwrap(),
        Some(&sidecar.encode().unwrap()),
    )
    .unwrap();
    let known_reference = sync::reference(&known, &binding.network);
    let mut block = candidate(node.state(), 750_000);
    block.transactions[0] = known;
    block
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&binding.network));
    let compact = CompactBlock::from_block(&block).unwrap();
    let missing: Vec<_> = block
        .transactions
        .iter()
        .filter(|tx| sync::reference(tx, &binding.network) != known_reference)
        .collect();
    let mut packets = vec![frame(
        binding,
        p2p::COMPACT_BLOCK,
        104,
        &compact.encode().unwrap(),
    )];
    for chunk in missing.chunks(sync::MAX_MISSING) {
        for transaction in chunk {
            packets.push(frame(
                binding,
                p2p::TRANSACTION,
                104,
                &transaction.encode_envelope(&binding.network).unwrap(),
            ));
        }
        packets.push(frame(binding, p2p::END_BATCH, 104, &[]));
    }
    let (mut session, output) = scripted(&node, [66; 32], packets);
    node.serve_once(&mut session).unwrap();
    assert_eq!(node.state().tip, block.id().unwrap());
    let requested: Vec<_> = sent(&output)
        .iter()
        .filter(|frame| frame.0 == p2p::GET_TRANSACTIONS)
        .flat_map(|frame| decode_references(&frame.2).unwrap())
        .collect();
    assert_eq!(requested.len(), 63);
    assert!(!requested.contains(&known_reference));
    drop(session);
    assert!(full_budget_available(&node.transport_budget()));
}

#[test]
fn compact_retry_acknowledges_only_the_exact_previously_accepted_skeleton() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let block = pending_compact_block(&mut node);
    let compact = CompactBlock::from_block(&block).unwrap();
    node.import_branch(0, std::slice::from_ref(&block), CandidatePolicy::default())
        .unwrap();
    let before = node.state().fingerprint();
    let binding = node.binding();
    let (mut session, output) = scripted(
        &node,
        [67; 32],
        vec![frame(
            binding,
            p2p::COMPACT_BLOCK,
            105,
            &compact.encode().unwrap(),
        )],
    );
    node.serve_once(&mut session).unwrap();
    assert_eq!(
        sent(&output),
        vec![(p2p::END_BATCH, 105, compact.expected_id.to_vec())]
    );
    drop(session);
    let mut forged = compact;
    forged.settlement.push(2);
    let (mut session, output) = scripted(
        &node,
        [67; 32],
        vec![frame(
            binding,
            p2p::COMPACT_BLOCK,
            106,
            &forged.encode().unwrap(),
        )],
    );
    assert!(matches!(
        node.serve_once(&mut session),
        Err(Error::Transport(p2p::Error::InvalidProtocol))
    ));
    assert!(sent(&output).is_empty());
    assert_eq!(node.state().fingerprint(), before);
    drop(session);
    assert!(full_budget_available(&node.transport_budget()));
}

#[test]
fn compact_sender_serves_requested_proofs_from_owned_block_after_mempool_pruning() {
    let dir = Directory::new();
    let node = setup(&dir);
    let block = candidate(node.state(), 800_000);
    let compact = CompactBlock::from_block(&block).unwrap();
    let binding = node.binding();
    let request = 101;
    let wanted = &compact.references[..sync::MAX_MISSING];
    let packets = vec![
        frame(
            binding,
            p2p::GET_TRANSACTIONS,
            request,
            &encode_references(wanted).unwrap(),
        ),
        frame(binding, p2p::END_BATCH, request, &compact.expected_id),
    ];
    let (mut session, output) = scripted(&node, [62; 32], packets);
    node.announce_compact(&mut session, request, &block)
        .unwrap();
    let sent = sent(&output);
    assert_eq!(
        sent[0],
        (p2p::COMPACT_BLOCK, request, compact.encode().unwrap())
    );
    for (index, transaction) in block.transactions[..sync::MAX_MISSING].iter().enumerate() {
        assert_eq!(
            sent[index + 1],
            (
                p2p::TRANSACTION,
                request,
                transaction.encode_envelope(&binding.network).unwrap()
            )
        );
    }
    assert_eq!(sent.last().unwrap(), &(p2p::END_BATCH, request, vec![]));
    drop(session);
    assert!(full_budget_available(&node.transport_budget()));
}

#[test]
fn missing_compact_proof_tampering_does_not_change_state_or_keep_buffers() {
    for tamper in 0..3 {
        let dir = Directory::new();
        let mut node = setup(&dir);
        let block = candidate(node.state(), 900_000);
        let compact = CompactBlock::from_block(&block).unwrap();
        let binding = node.binding();
        let before = node.state().fingerprint();
        let mut transaction = block.transactions[0].clone();
        if tamper == 0 {
            transaction.proof.push(2);
        }
        if tamper == 1 {
            transaction.record.snapshot.block_id[0] ^= 1;
        }
        let packets = vec![
            frame(binding, p2p::COMPACT_BLOCK, 102, &compact.encode().unwrap()),
            frame(
                binding,
                p2p::TRANSACTION,
                if tamper == 2 { 103 } else { 102 },
                &transaction.encode_envelope(&binding.network).unwrap(),
            ),
        ];
        let (mut session, _) = scripted(&node, [63; 32], packets);
        assert!(matches!(
            node.serve_once(&mut session),
            Err(Error::Transport(p2p::Error::InvalidProtocol))
        ));
        assert_eq!(node.state().fingerprint(), before);
        assert!(node.mempool().is_empty());
        drop(session);
        assert!(full_budget_available(&node.transport_budget()));
    }
}

fn timeout_session(node: &Node<TestVerifier>, peer: Hash) -> Session<Scripted> {
    let binding = node.binding();
    let input = p2p::Hello {
        binding,
        role: p2p::Role::Validator,
    }
    .encode()
    .to_vec();
    let channel = Scripted {
        input: std::io::Cursor::new(input),
        output: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        timeout_at_eof: true,
    };
    let admission = p2p::test_support::admission(binding, peer, p2p::ConnectionRole::Initiator);
    let capability = p2p::Authenticated::from_verified_provider(
        channel,
        &admission,
        admission.role(),
        admission.expected_peer().descriptor(),
        p2p::test_support::parameters(),
    )
    .unwrap();
    Session::establish(
        capability,
        &admission,
        p2p::Role::Validator,
        node.transport_budget(),
    )
    .unwrap()
}

#[test]
fn compact_transport_timeout_retries_on_fresh_sessions_and_has_a_hard_attempt_cap() {
    let dir = Directory::new();
    let node = setup(&dir);
    let block = candidate(node.state(), 1_000_000);
    let acknowledged = frame(node.binding(), p2p::END_BATCH, 111, &block.id().unwrap());
    let (success, _) = scripted(&node, [64; 32], vec![acknowledged]);
    let mut sessions =
        std::collections::VecDeque::from([timeout_session(&node, [64; 32]), success]);
    let mut connects = 0;
    assert_eq!(
        node.announce_compact_with_retry(&block, 110, 3, || {
            connects += 1;
            Ok(sessions.pop_front().unwrap())
        })
        .unwrap(),
        2
    );
    assert_eq!(connects, 2);
    assert!(full_budget_available(&node.transport_budget()));

    let mut connects = 0;
    assert!(matches!(
        node.announce_compact_with_retry(&block, 120, 3, || {
            connects += 1;
            Ok(timeout_session(&node, [64; 32]))
        }),
        Err(Error::Transport(p2p::Error::Unavailable))
    ));
    assert_eq!(connects, 3);
    assert!(full_budget_available(&node.transport_budget()));
}

#[test]
fn compact_protocol_tampering_never_enters_the_transport_retry_path() {
    let dir = Directory::new();
    let node = setup(&dir);
    let block = candidate(node.state(), 1_100_000);
    let wrong_ack = frame(node.binding(), p2p::END_BATCH, 130, &[5; 32]);
    let (mut session, _) = scripted(&node, [65; 32], vec![wrong_ack]);
    // The sender does not consider a mere END_BATCH sufficient; the receiver
    // must acknowledge the same committed block identity.
    assert!(matches!(
        node.announce_compact(&mut session, 130, &block),
        Err(Error::Transport(p2p::Error::InvalidProtocol))
    ));
    drop(session);
    let mut connects = 0;
    assert!(matches!(
        node.announce_compact_with_retry(&block, 130, 3, || {
            connects += 1;
            let wrong_ack = frame(node.binding(), p2p::END_BATCH, 130, &[5; 32]);
            Ok(scripted(&node, [65; 32], vec![wrong_ack]).0)
        }),
        Err(Error::Transport(p2p::Error::InvalidProtocol))
    ));
    assert_eq!(connects, 1);
    assert!(full_budget_available(&node.transport_budget()));
}

#[test]
fn compact_reconstruction_exhaustion_is_retryable_and_keeps_pending_transactions() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let block = pending_compact_block(&mut node);
    let compact = CompactBlock::from_block(&block).unwrap();
    let fingerprint = node.state().fingerprint();
    node.budget = Budget::new(2 * p2p::HANDSHAKE_BYTES);
    let packet = frame(
        node.binding(),
        p2p::COMPACT_BLOCK,
        89,
        &compact.encode().unwrap(),
    );
    let (mut session, _) = scripted(&node, [50; 32], vec![packet]);
    let pressure = node
        .transport_budget()
        .reserve(p2p::HANDSHAKE_BYTES - 128 * 1024)
        .unwrap();
    assert!(matches!(
        node.serve_once(&mut session),
        Err(Error::Transport(p2p::Error::ResourceExhausted))
    ));
    assert_eq!(node.state().fingerprint(), fingerprint);
    assert_eq!(node.mempool().len(), 64);
    assert!(node.transport_budget().reserve(128 * 1024).is_ok());
    drop(pressure);
    assert_eq!(
        node.transport_budget().available().unwrap(),
        p2p::HANDSHAKE_BYTES
    );
    drop(session);
    assert!(
        node.transport_budget()
            .reserve(2 * p2p::HANDSHAKE_BYTES)
            .is_ok()
    );
}

#[test]
fn outgoing_locator_lookup_exhaustion_precedes_get_blocks_and_preserves_pending() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let block = candidate(node.state(), 10_000);
    node.import_branch(0, &[block], CandidatePolicy::default())
        .unwrap();
    let (transaction, sidecar) = payment(node.state());
    let envelope = transaction
        .encode_envelope(&node.state().config.network)
        .unwrap();
    let pending = node
        .submit_local(&envelope, Some(&sidecar.encode().unwrap()))
        .unwrap();
    let fingerprint = node.state().fingerprint();
    let (mut session, output) = scripted(&node, [51; 32], Vec::new());
    let budget = node.transport_budget();
    let pressure = budget
        .reserve(p2p::CONNECTION_BYTES - p2p::HANDSHAKE_BYTES - 65_536)
        .unwrap();
    let available = budget.available().unwrap();
    let mut attempt = SyncAttempt::default();
    assert!(matches!(
        node.synchronize(&mut session, 90, &mut attempt),
        Err(Error::Transport(p2p::Error::ResourceExhausted))
    ));
    assert!(sent(&output).is_empty());
    assert_eq!(node.state().fingerprint(), fingerprint);
    assert!(node.mempool().contains(&pending));
    assert_eq!(node.mempool().len(), 1);
    assert!(attempt.peer.is_none() && attempt.staging.is_none() && attempt.reservations.is_empty());
    assert_eq!(budget.available().unwrap(), available);
    drop(pressure);
    assert_eq!(
        budget.available().unwrap(),
        p2p::CONNECTION_BYTES - p2p::HANDSHAKE_BYTES
    );
    drop(session);
    assert!(full_budget_available(&budget));
}

#[test]
fn incoming_locator_lookup_exhaustion_is_retryable_and_preserves_pending() {
    let dir = Directory::new();
    let mut node = setup(&dir);
    let block = candidate(node.state(), 10_000);
    node.import_branch(0, &[block], CandidatePolicy::default())
        .unwrap();
    let (transaction, sidecar) = payment(node.state());
    let envelope = transaction
        .encode_envelope(&node.state().config.network)
        .unwrap();
    let pending = node
        .submit_local(&envelope, Some(&sidecar.encode().unwrap()))
        .unwrap();
    let fingerprint = node.state().fingerprint();
    let mut request = vec![0];
    request.extend(Locator::from_store(node.store()).unwrap().encode().unwrap());
    let packet = frame(node.binding(), p2p::GET_BLOCKS, 91, &request);
    let (mut session, output) = scripted(&node, [52; 32], vec![packet]);
    let budget = node.transport_budget();
    let pressure = budget
        .reserve(p2p::CONNECTION_BYTES - p2p::HANDSHAKE_BYTES - 65_536)
        .unwrap();
    let available = budget.available().unwrap();
    assert!(matches!(
        node.serve_once(&mut session),
        Err(Error::Transport(p2p::Error::ResourceExhausted))
    ));
    assert!(sent(&output).is_empty());
    assert_eq!(node.state().fingerprint(), fingerprint);
    assert!(node.mempool().contains(&pending));
    assert_eq!(node.mempool().len(), 1);
    assert_eq!(budget.available().unwrap(), available);
    drop(pressure);
    assert_eq!(
        budget.available().unwrap(),
        p2p::CONNECTION_BYTES - p2p::HANDSHAKE_BYTES
    );
    drop(session);
    assert!(full_budget_available(&budget));
}

#[test]
fn staging_lookup_exhaustion_after_metadata_discards_attempt_and_preserves_pending() {
    struct PressuredResponse {
        channel: Scripted,
        budget: Budget,
        pressure: Option<Reservation>,
    }
    impl Read for PressuredResponse {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            if self.channel.input.position() >= p2p::HELLO_BYTES as u64 && self.pressure.is_none() {
                let retained = self.budget.available().unwrap() - 65_536;
                self.pressure = Some(self.budget.reserve(retained).unwrap());
            }
            self.channel.read(bytes)
        }
    }
    impl Write for PressuredResponse {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.channel.write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.channel.flush()
        }
    }

    let dir = Directory::new();
    let mut node = setup(&dir);
    let block = candidate(node.state(), 10_000);
    node.import_branch(0, &[block], CandidatePolicy::default())
        .unwrap();
    let (transaction, sidecar) = payment(node.state());
    let envelope = transaction
        .encode_envelope(&node.state().config.network)
        .unwrap();
    let pending = node
        .submit_local(&envelope, Some(&sidecar.encode().unwrap()))
        .unwrap();
    let fingerprint = node.state().fingerprint();
    let base = node.state().tip_snapshot().selector;
    let binding = node.binding();
    let meta = BatchMeta {
        ancestor: base,
        after: base,
        count: 0,
        more: false,
    };
    let mut input = p2p::Hello {
        binding,
        role: p2p::Role::Validator,
    }
    .encode()
    .to_vec();
    for packet in replies(&node, 92, meta, &[]) {
        input.extend(packet);
    }
    let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let budget = node.transport_budget();
    let channel = PressuredResponse {
        channel: Scripted {
            input: std::io::Cursor::new(input),
            output: output.clone(),
            timeout_at_eof: false,
        },
        budget: budget.clone(),
        pressure: None,
    };
    let admission = p2p::test_support::admission(binding, [53; 32], p2p::ConnectionRole::Initiator);
    let capability = p2p::Authenticated::from_verified_provider(
        channel,
        &admission,
        admission.role(),
        admission.expected_peer().descriptor(),
        p2p::test_support::parameters(),
    )
    .unwrap();
    let mut session =
        Session::establish(capability, &admission, p2p::Role::Validator, budget.clone()).unwrap();
    let mut attempt = SyncAttempt::default();
    assert!(matches!(
        node.synchronize(&mut session, 92, &mut attempt),
        Err(Error::Transport(p2p::Error::ResourceExhausted))
    ));
    let requests = sent(&output);
    assert_eq!(requests.len(), 1);
    assert_eq!((requests[0].0, requests[0].1), (p2p::GET_BLOCKS, 92));
    assert_eq!(node.state().fingerprint(), fingerprint);
    assert!(node.mempool().contains(&pending));
    assert_eq!(node.mempool().len(), 1);
    assert!(attempt.peer.is_none() && attempt.staging.is_none() && attempt.reservations.is_empty());
    assert_eq!(budget.available().unwrap(), 65_536);
    drop(session);
    assert!(full_budget_available(&budget));
}
