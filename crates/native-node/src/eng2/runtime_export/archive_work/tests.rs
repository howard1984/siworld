use super::*;
use crate::eng2::{
    genesis::FeeMode,
    runtime_export::tests::Directory,
    snapshot::{
        self,
        tests::{bootstrap, limits, populated},
    },
    state_components::Binding,
};
use native::codec::encode_digest;
use p3_field::PrimeCharacteristicRing;
use std::{
    sync::{Mutex, mpsc},
    time::{Duration, Instant},
};

// Component-validation fixture only. It is not a native block, a checkpoint
// certificate, or evidence of admission to an executed canonical chain.
pub(super) fn fixture(budget: &Budget) -> ArchiveWork {
    let source = bootstrap();
    let genesis = Genesis::seal(
        source.chain.config.clone(),
        source.governance().clone(),
        FeeMode::LegacyMiner,
    )
    .unwrap();
    let initial = genesis.initial_state().unwrap();
    let mut state = populated(&initial);
    for i in 1..=16 {
        let leaf = [native::multi_asset::F::from_u64(i); 12];
        state.chain.tree.append(leaf).unwrap();
        state.chain.leaves.push(leaf);
        assert!(state.chain.commitments.insert(encode_digest(&leaf)));
    }
    let mut roots = native::multi_asset::RecentRoots::new();
    let hasher = native::multi_asset::Hasher::new();
    for (height, tree) in [(0, &initial.chain.tree), (1, &state.chain.tree)] {
        roots.insert(
            &hasher,
            height,
            &tree.root(),
            genesis.fee_mode().base_fee(height).unwrap(),
        );
    }
    let latest = state.chain.snapshots.back_mut().unwrap();
    latest.commitment_root = encode_digest(&state.chain.tree.root());
    latest.recent_root = encode_digest(&roots.tree(&hasher).root());
    let binding = Binding {
        genesis: genesis.id(),
        rules_commitment: genesis.rules_commitment(),
        parent: genesis.id(),
    };
    let mut header = Header {
        network: state.network(),
        height: 1,
        parent: genesis.id(),
        timestamp: 300,
        target: [0xff; 32],
        body_commitment: [6; 32],
        nonce: 0,
        execution_commitment: state.execution_commitment(binding, limits().chain).unwrap(),
    };
    // The snapshot codec represents the current selector as SelfAtHeight,
    // avoiding a circular header-id dependency in the committed components.
    state.chain.tip = header.id().unwrap();
    state.chain.snapshots.back_mut().unwrap().selector.block_id = state.chain.tip;
    header.execution_commitment = state.execution_commitment(binding, limits().chain).unwrap();
    assert_eq!(state.tip(), header.id().unwrap());
    let bytes = snapshot::encode_components(
        &state.canonical_components(binding, limits().chain).unwrap(),
        limits(),
    )
    .unwrap();
    let charge = ArchiveWork::charge(bytes.len()).unwrap();
    let reservation = budget.reserve(charge).unwrap();
    ArchiveWork {
        context: Context {
            network: state.network(),
            genesis: genesis.id(),
            rules: genesis.rules_commitment(),
            anchor: header.clone(),
            authorization: header.clone(),
            roster: state.governance().active_roster().digest(state.network()),
        },
        genesis: genesis.encode().unwrap(),
        archive: bytes,
        base: header,
        suffix: Vec::new(),
        limits: limits(),
        reservation,
    }
}
fn complete(worker: &mut ArchiveWorker) -> Result<ValidatedArchive, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(result) = worker.try_complete()? {
            return Ok(result);
        }
        assert!(
            Instant::now() < deadline,
            "bounded component validation deadline exceeded"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}
#[test]
fn complete_native_reconstruction_preserves_exact_bytes_and_rejects_corrupt_components() {
    let budget = Budget::new(64 * 1024 * 1024);
    let work = fixture(&budget);
    let expected = work.archive.clone();
    let original = budget.available().unwrap();
    let mut worker = ArchiveWorker::default();
    worker.start(work).unwrap();
    let result = complete(&mut worker).unwrap();
    assert_eq!(result.snapshot_bytes(), expected);
    assert_eq!(result.state().chain().tree.count, 16);
    assert_eq!(budget.available().unwrap(), original);
    let dir = Directory::new();
    // A valid component reconstruction alone cannot become a canonical
    // candidate in an unrelated or earlier actual Store.
    assert!(result.check_current(&dir.store()).is_err());
    drop(result);
    assert_eq!(budget.available().unwrap(), 64 * 1024 * 1024);
    let mut corrupt = fixture(&budget);
    let offset = corrupt.archive.len() - 1;
    corrupt.archive[offset] ^= 1;
    worker.start(corrupt).unwrap();
    assert!(complete(&mut worker).is_err());
    assert_eq!(budget.available().unwrap(), 64 * 1024 * 1024);
}
#[test]
fn delayed_full_validation_keeps_actual_owner_projection_available_and_uses_one_slot() {
    let dir = Directory::new();
    let owner = Arc::new(Mutex::new(dir.store()));
    let budget = Budget::new(64 * 1024 * 1024);
    let work = fixture(&budget);
    let second = fixture(&budget);
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let mut worker = ArchiveWorker::default();
    worker
        .start_inner(work, move |_| {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        })
        .unwrap();
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(worker.is_busy());
    assert!(worker.try_complete().unwrap().is_none());
    assert!(worker.start(second).is_err());
    // This uses the real Store/export path while the independent full native
    // validator is delayed; it does not fabricate resident heartbeat evidence.
    for sequence in 1..=3 {
        let store = owner
            .try_lock()
            .expect("archive worker must not own canonical Store");
        assert_eq!(
            super::super::public_projection(&store, sequence, None).unwrap()["height"],
            0
        );
    }
    release_tx.send(()).unwrap();
    let validated = complete(&mut worker).unwrap();
    assert_eq!(validated.state().chain().tree.count, 16);
    drop(validated);
    assert!(!worker.is_busy());
    assert_eq!(budget.available().unwrap(), 64 * 1024 * 1024);
}
#[test]
fn cancellation_and_drop_drain_owned_worker_and_release_shared_budget() {
    for explicit_stop in [true, false] {
        let budget = Budget::new(64 * 1024 * 1024);
        let work = fixture(&budget);
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (exited_tx, exited_rx) = mpsc::sync_channel(1);
        let mut worker = ArchiveWorker::default();
        worker
            .start_inner(work, move |cancelled| {
                started_tx.send(()).unwrap();
                let deadline = Instant::now() + Duration::from_secs(2);
                while !cancelled.load(Ordering::Acquire) {
                    assert!(
                        Instant::now() < deadline,
                        "worker cancellation deadline exceeded"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                exited_tx.send(()).unwrap();
            })
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        if explicit_stop {
            worker.stop().unwrap();
            assert!(!worker.is_busy());
        }
        drop(worker);
        exited_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(budget.available().unwrap(), 64 * 1024 * 1024);
    }
    assert!(ArchiveWork::charge(usize::MAX).is_err());
    assert!(
        Budget::new(1024)
            .reserve(ArchiveWork::charge(1).unwrap())
            .is_err()
    );
}

#[test]
fn retained_archive_releases_workspace_for_the_next_validation() {
    let probe_budget = Budget::new(64 * 1024 * 1024);
    let probe = fixture(&probe_budget);
    let workspace = 64 * 1024 * 1024 - probe_budget.available().unwrap();
    let mut metadata = Vec::with_capacity(8192);
    metadata.resize(4096, 0u8);
    assert!(metadata.capacity() > metadata.len());
    let retained = probe.archive.capacity() + metadata.capacity();
    drop(probe);
    let maximum = workspace + retained;
    let budget = Budget::new(maximum);
    let work = fixture(&budget);
    assert!(budget.reserve(workspace).is_err());
    let validated = work.validate(&AtomicBool::new(false)).unwrap();
    // A completed validation still owns its decoded state and full workspace.
    assert_eq!(budget.available().unwrap(), retained);
    let (snapshot, reservation) = validated.into_snapshot(metadata.capacity()).unwrap();
    assert_eq!(budget.available().unwrap(), maximum - retained);
    // Keeping the previous real encoded snapshot no longer retains its expired
    // validation workspace. A second actual native reconstruction can proceed.
    let next = fixture(&budget);
    let validated = next.validate(&AtomicBool::new(false)).unwrap();
    assert_eq!(validated.snapshot_bytes(), snapshot);
    assert_eq!(budget.available().unwrap(), 0);
    drop(validated);
    assert_eq!(budget.available().unwrap(), maximum - retained);
    assert!(budget.reserve(maximum - retained + 1).is_err());
    assert_eq!(snapshot.capacity() + metadata.capacity(), retained);
    drop((snapshot, metadata, reservation));
    assert_eq!(budget.available().unwrap(), maximum);
}

#[test]
fn retained_archive_failures_release_charges_without_borrowing_live_bytes() {
    let maximum = 64 * 1024 * 1024;
    let budget = Budget::new(maximum);
    let mut work = fixture(&budget);
    let last = work.archive.len() - 1;
    work.archive[last] ^= 1;
    assert!(work.validate(&AtomicBool::new(false)).is_err());
    assert_eq!(budget.available().unwrap(), maximum);
    let validated = fixture(&budget).validate(&AtomicBool::new(false)).unwrap();
    assert!(validated.into_snapshot(usize::MAX).is_err());
    assert_eq!(budget.available().unwrap(), maximum);
    let validated = fixture(&budget).validate(&AtomicBool::new(false)).unwrap();
    assert!(validated.into_snapshot(maximum).is_err());
    assert_eq!(budget.available().unwrap(), maximum);
    let mut metadata = Vec::with_capacity(8192);
    metadata.resize(4096, 0u8);
    assert!(metadata.capacity() > metadata.len());
    let validated = fixture(&budget).validate(&AtomicBool::new(false)).unwrap();
    let (snapshot, mut reservation) = validated.into_snapshot(metadata.capacity()).unwrap();
    let retained = snapshot.capacity() + metadata.capacity();
    assert_eq!(budget.available().unwrap(), maximum - retained);
    assert!(reservation.shrink_to(retained + 1).is_err());
    assert_eq!(budget.available().unwrap(), maximum - retained);
    // Spare allocation capacity remains charged even when it is not payload.
    assert!(budget.reserve(maximum - retained + 1).is_err());
    drop((snapshot, metadata, reservation));
    assert_eq!(budget.available().unwrap(), maximum);
}
