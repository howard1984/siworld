use super::*;
use crate::fixtures::{TestVerifier, candidate};
use crate::state::{Config, State};
#[test]
fn locator_decoder_rejects_duplicates_ascending_heights_and_oversized_counts() {
    let good = Locator {
        entries: vec![
            Snapshot {
                height: 1,
                block_id: [1; 32],
            },
            Snapshot {
                height: 0,
                block_id: [2; 32],
            },
        ],
    };
    assert_eq!(
        Locator::decode(&good.encode().unwrap()).unwrap().entries,
        good.entries
    );
    let mut raw = good.encode().unwrap();
    raw[42..50].copy_from_slice(&1u64.to_le_bytes());
    assert!(Locator::decode(&raw).is_err());
    assert!(Locator::decode(&[255; 2]).is_err());
}
#[test]
fn compact_reconstruction_requires_exact_proof_and_statement_pair() {
    let state = State::new(Config::development([71; 32], 0).unwrap()).unwrap();
    let block = candidate(&state, 2);
    let compact = CompactBlock::from_block(&block).unwrap();
    let resolve = |id: &Reference| {
        block
            .transactions
            .iter()
            .find(|t| t.record.statement_id(&block.network) == id.statement)
            .cloned()
    };
    assert_eq!(compact.reconstruct(resolve).unwrap(), block);
    assert_eq!(
        compact
            .missing(|r| block
                .transactions
                .iter()
                .any(|t| reference(t, &block.network) == *r))
            .len(),
        0
    );
    assert!(compact.reconstruct(|_| None).is_err());
    assert!(
        compact
            .reconstruct(|id| {
                let mut tx = resolve(id)?;
                tx.proof.push(2);
                Some(tx)
            })
            .is_err()
    );
}
#[test]
fn compact_rejects_wrong_body_duplicate_order_and_changed_reward() {
    let state = State::new(Config::development([72; 32], 0).unwrap()).unwrap();
    let block = candidate(&state, 7);
    let c = CompactBlock::from_block(&block).unwrap();
    for mode in 0..4 {
        let mut bad = c.clone();
        match mode {
            0 => bad.references.swap(0, 1),
            1 => bad.references[1] = bad.references[0],
            2 => bad.expected_id[0] ^= 1,
            _ => bad.rewards[0].ciphertext[0] ^= 1,
        };
        assert!(
            bad.reconstruct(|r| block
                .transactions
                .iter()
                .find(|t| reference(t, &block.network) == *r)
                .cloned())
                .is_err()
        );
    }
}
#[test]
fn compact_canonical_codec_roundtrips_and_rejects_trailing_or_overlong_data() {
    let state = State::new(Config::development([73; 32], 0).unwrap()).unwrap();
    let block = candidate(&state, 3);
    let c = CompactBlock::from_block(&block).unwrap();
    let encoded = c.encode().unwrap();
    let decoded = CompactBlock::decode(&encoded, &block.network).unwrap();
    assert_eq!(decoded.expected_id, c.expected_id);
    let mut extra = encoded;
    extra.push(0);
    assert!(CompactBlock::decode(&extra, &block.network).is_err());
    assert!(CompactBlock::decode(&[], &block.network).is_err());
}
#[test]
fn streamed_blocks_match_original_bytes_and_do_not_consume_next_frame() {
    let state = State::new(Config::development([74; 32], 0).unwrap()).unwrap();
    let block = candidate(&state, 9);
    let bytes = block.encode().unwrap();
    let mut streamed = Vec::new();
    block.write_to(&mut streamed).unwrap();
    assert_eq!(streamed, bytes);
    let mut raw = bytes.clone();
    raw.extend_from_slice(b"next");
    let mut input = std::io::Cursor::new(raw);
    let decoded = Block::read_from(&mut input, bytes.len(), &block.network).unwrap();
    assert_eq!(decoded, block);
    assert_eq!(input.position(), bytes.len() as u64);
    assert!(
        Block::read_from(
            &mut std::io::Cursor::new(bytes.clone()),
            bytes.len() + 1,
            &block.network
        )
        .is_err()
    );
    let mut bad = bytes;
    bad[0] ^= 1;
    assert!(Block::read_from(&mut std::io::Cursor::new(&bad), bad.len(), &block.network).is_err());
    let mut verified = state;
    verified.apply(&decoded, &TestVerifier).unwrap();
}

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT_SYNC_DIR: AtomicU64 = AtomicU64::new(0);
struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "siworld-native-sync-{}-{}",
                std::process::id(),
                NEXT_SYNC_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("synthetic sync directory unavailable: {error}"),
            }
        }
    }
    fn db(&self) -> PathBuf {
        self.0.join("chain.redb")
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fill_store(store: &mut Store, count: usize, seed: u32) {
    for index in 0..count {
        let block = candidate(store.state(), seed + index as u32 * 100_000);
        store.append(&block, &TestVerifier).unwrap();
    }
}
fn genesis(store: &Store) -> Snapshot {
    Snapshot {
        height: 0,
        block_id: store.state().config.genesis_id(),
    }
}
const BATCH_BYTES: usize = 640 * 1024 * 1024;

#[test]
fn initial_sync_adopts_each_bounded_batch_with_an_explicit_fresh_base() {
    let source_dir = TestDir::new();
    let target_dir = TestDir::new();
    let config = Config::development([75; 32], 0).unwrap();
    let mut source = Store::open(source_dir.db(), config.clone(), &TestVerifier).unwrap();
    fill_store(&mut source, 3, 1);
    let mut target = Store::open(target_dir.db(), config.clone(), &TestVerifier).unwrap();
    let base = Locator::from_store(&target)
        .unwrap()
        .common_ancestor(&source)
        .unwrap();
    assert_eq!(base, genesis(&source));
    let mut stage = Staging::new(&target, base, CandidatePolicy::default()).unwrap();
    let first = serve_batch(&source, base, base, 1, BATCH_BYTES).unwrap();
    assert!(first.more);
    assert!(matches!(
        stage.accept(&mut target, first, &TestVerifier),
        Ok(BranchOutcome::Adopted { height: 1, .. })
    ));
    let fresh = stage.continuation().unwrap();
    assert_eq!(fresh.height, 1);
    // A successful adoption rebases staging. An old ancestor cannot silently
    // continue the old session against a newly changed accepted state.
    let stale = serve_batch(&source, base, fresh, 1, BATCH_BYTES).unwrap();
    let before = target.state().fingerprint();
    assert!(matches!(
        stage.accept(&mut target, stale, &TestVerifier),
        Err(ChainError::Invalid(_))
    ));
    assert_eq!(target.state().fingerprint(), before);
    while target.state().height < source.state().height {
        let fresh = stage.continuation().unwrap();
        let batch = serve_batch(&source, fresh, fresh, 1, BATCH_BYTES).unwrap();
        assert!(matches!(
            stage.accept(&mut target, batch, &TestVerifier),
            Ok(BranchOutcome::Adopted { .. })
        ));
    }
    assert_eq!(target.state().fingerprint(), source.state().fingerprint());
    let expected = target.state().fingerprint();
    drop(target);
    assert_eq!(
        Store::open_existing(target_dir.db(), config, &TestVerifier)
            .unwrap()
            .state()
            .fingerprint(),
        expected
    );
}

#[test]
fn locator_genesis_and_pinned_continuation_cannot_be_substituted() {
    let first_dir = TestDir::new();
    let fork_dir = TestDir::new();
    let config = Config::development([76; 32], 0).unwrap();
    let mut first = Store::open(first_dir.db(), config.clone(), &TestVerifier).unwrap();
    fill_store(&mut first, 2, 1);
    let mut fork = Store::open(fork_dir.db(), config, &TestVerifier).unwrap();
    fill_store(&mut fork, 2, 1_000_000);
    let base = genesis(&first);
    let pinned = Snapshot {
        height: 1,
        block_id: first.block(1).unwrap().id().unwrap(),
    };
    assert!(serve_batch(&fork, base, pinned, 1, BATCH_BYTES).is_err());
    let mut locator = Locator::from_store(&first).unwrap();
    locator.entries.last_mut().unwrap().block_id[0] ^= 1;
    assert!(locator.common_ancestor(&fork).is_err());
    let mut wrong_base = base;
    wrong_base.block_id[0] ^= 1;
    assert!(Staging::new(&fork, wrong_base, CandidatePolicy::default()).is_err());
    assert!(serve_batch(&first, wrong_base, base, 1, BATCH_BYTES).is_err());
    assert!(serve_batch(&first, base, pinned, 0, BATCH_BYTES).is_err());
    assert!(serve_batch(&first, base, pinned, MAX_BATCH_BLOCKS + 1, BATCH_BYTES).is_err());
    assert!(serve_batch(&first, base, base, 1, MAX_BLOCK_BYTES - 1).is_err());
}

#[test]
fn rejected_candidate_or_budget_never_changes_canonical_or_staged_continuation() {
    let source_dir = TestDir::new();
    let target_dir = TestDir::new();
    let config = Config::development([77; 32], 0).unwrap();
    let mut source = Store::open(source_dir.db(), config.clone(), &TestVerifier).unwrap();
    fill_store(&mut source, 2, 1);
    let mut target = Store::open(target_dir.db(), config.clone(), &TestVerifier).unwrap();
    let base = genesis(&target);
    let original = target.state().fingerprint();
    let mut stage = Staging::new(&target, base, CandidatePolicy::default()).unwrap();
    let mut invalid = serve_batch(&source, base, base, 2, BATCH_BYTES).unwrap();
    invalid.blocks[1].settlement_proof = vec![0];
    assert!(matches!(
        stage.accept(&mut target, invalid, &TestVerifier),
        Err(ChainError::Invalid(_))
    ));
    assert_eq!(stage.continuation().unwrap(), base);
    assert_eq!(target.state().fingerprint(), original);
    assert_eq!(target.detached_count().unwrap(), 0);
    let policy = CandidatePolicy {
        max_blocks: 1,
        ..CandidatePolicy::default()
    };
    let mut bounded = Staging::new(&target, base, policy).unwrap();
    let batch = serve_batch(&source, base, base, 2, BATCH_BYTES).unwrap();
    let error = bounded
        .accept(&mut target, batch, &TestVerifier)
        .unwrap_err();
    assert!(matches!(error, ChainError::ResourceExhausted(_)));
    assert!(!error.is_invalid());
    assert_eq!(bounded.continuation().unwrap(), base);
    assert_eq!(target.state().fingerprint(), original);
    drop(target);
    assert_eq!(
        Store::open_existing(target_dir.db(), config, &TestVerifier)
            .unwrap()
            .state()
            .fingerprint(),
        original
    );
}

#[test]
fn canonical_changes_invalidate_inflight_sync_without_overwriting_new_blocks() {
    let source_dir = TestDir::new();
    let target_dir = TestDir::new();
    let config = Config::development([78; 32], 0).unwrap();
    let mut source = Store::open(source_dir.db(), config.clone(), &TestVerifier).unwrap();
    fill_store(&mut source, 2, 1);
    let mut target = Store::open(target_dir.db(), config, &TestVerifier).unwrap();
    let base = genesis(&target);
    let mut stage = Staging::new(&target, base, CandidatePolicy::default()).unwrap();
    let batch = serve_batch(&source, base, base, 2, BATCH_BYTES).unwrap();
    fill_store(&mut target, 1, 1_000_000);
    let accepted = target.state().fingerprint();
    assert!(matches!(
        stage.accept(&mut target, batch, &TestVerifier),
        Err(ChainError::Local(_))
    ));
    assert_eq!(target.state().fingerprint(), accepted);
    assert_eq!(target.detached_count().unwrap(), 0);
}

#[test]
fn staged_shorter_fork_wins_only_with_greater_verified_work() {
    let source_dir = TestDir::new();
    let target_dir = TestDir::new();
    let config = Config::development([79; 32], 1).unwrap();
    let mut target = Store::open(target_dir.db(), config.clone(), &TestVerifier).unwrap();
    for index in 0..4 {
        let mut block = candidate(target.state(), 1 + index * 100_000);
        block.timestamp = target.state().timestamp() + 14_400;
        block.nonce = 0;
        crate::fixtures::find_test_nonce(&mut block, target.state().config.pow_iterations, true);
        target.append(&block, &TestVerifier).unwrap();
    }
    let mut source = Store::open(source_dir.db(), config, &TestVerifier).unwrap();
    fill_store(&mut source, 3, 10_000_000);
    assert!(source.state().height < target.state().height);
    assert!(source.state().cumulative_work > target.state().cumulative_work);
    let base = genesis(&target);
    let mut stage = Staging::new(&target, base, CandidatePolicy::default()).unwrap();
    let first = serve_batch(&source, base, base, 1, BATCH_BYTES).unwrap();
    assert!(matches!(
        stage.accept(&mut target, first, &TestVerifier),
        Ok(BranchOutcome::Unchanged { .. })
    ));
    assert_eq!(target.state().height, 4);
    let after = stage.continuation().unwrap();
    assert_eq!(after.height, 1);
    let remaining = serve_batch(&source, base, after, 2, BATCH_BYTES).unwrap();
    assert!(matches!(
        stage.accept(&mut target, remaining, &TestVerifier),
        Ok(BranchOutcome::Adopted {
            detached: 4,
            attached: 3,
            height: 3,
            ..
        })
    ));
    assert_eq!(target.state().fingerprint(), source.state().fingerprint());
    assert_eq!(target.detached_count().unwrap(), 4);
}

#[test]
fn compact_missing_requests_never_exceed_the_recovery_batch_limit() {
    let state = State::new(Config::development([80; 32], 0).unwrap()).unwrap();
    let block = candidate(&state, 400);
    let compact = CompactBlock::from_block(&block).unwrap();
    assert_eq!(compact.missing(|_| false).len(), MIN_SLOTS);
    assert_eq!(compact.missing_request(|_| false).len(), MAX_MISSING);
    let available = compact.references[..MIN_SLOTS - 1].to_vec();
    let request = compact.missing_request(|reference| available.contains(reference));
    assert_eq!(request, vec![compact.references[MIN_SLOTS - 1]]);
}
