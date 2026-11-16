use super::*;
use crate::eng2::{header::Header, runtime_export::tests::Directory, snapshot::tests::limits};
use std::cell::Cell;

struct Synthetic {
    binding: Binding,
    headers: Vec<Header>,
    height: Cell<u64>,
    receipts: Cell<usize>,
    advance_before_commit: Cell<bool>,
    head_reads: Cell<usize>,
}
impl Synthetic {
    fn new(binding: Binding, count: usize, salt: u64) -> Self {
        let mut parent = binding.genesis();
        let headers = (1..=count)
            .map(|height| {
                let header = Header {
                    network: binding.network(),
                    height: height as u64,
                    parent,
                    timestamp: salt + height as u64,
                    target: [255; 32],
                    execution_commitment: [7; 32],
                    body_commitment: [8; 32],
                    nonce: 0,
                };
                parent = header.id().unwrap();
                header
            })
            .collect();
        Self {
            binding,
            headers,
            height: Cell::new(count as u64),
            receipts: Cell::new(0),
            advance_before_commit: Cell::new(false),
            head_reads: Cell::new(0),
        }
    }
}
impl Source for Synthetic {
    fn head(&self) -> (u64, Hash) {
        let reads = self.head_reads.get();
        self.head_reads.set(reads + 1);
        if self.advance_before_commit.get() && reads == 1 {
            self.advance_before_commit.set(false);
            self.height.set(self.height.get() + 1);
        }
        let h = self.height.get();
        (
            h,
            if h == 0 {
                self.binding.genesis()
            } else {
                self.headers[h as usize - 1].id().unwrap()
            },
        )
    }
    fn header(&self, height: u64) -> Result<Header, String> {
        self.headers
            .get(height as usize - 1)
            .cloned()
            .ok_or("synthetic header unavailable".into())
    }
    fn genesis(&self) -> Result<Vec<u8>, String> {
        Ok(b"synthetic public genesis".to_vec())
    }
    fn receipt(&self, height: u64, _: &p2p::Budget) -> Result<Acquired, String> {
        self.receipts.set(self.receipts.get() + 1);
        let raw = self.header(height)?.encode().unwrap();
        Ok(Acquired {
            native: None,
            synthetic: Some([b"SWE2WLT1".as_slice(), &self.binding.0, &raw, &[0; 17]].concat()),
        })
    }
}
fn binding(store: &Store) -> Binding {
    Binding::new(
        store.engine().state().network(),
        store.engine().genesis().id(),
        store.engine().genesis().rules_commitment(),
        crate::proofs::protocol_profile_fingerprint(),
    )
}
fn head(export: &PublicExport) -> Value {
    serde_json::from_slice(&export.read("wallet-head.json", 2048).unwrap()).unwrap()
}
fn manifest(export: &PublicExport, publisher: &WalletPublisher) -> Manifest {
    let cursor = head(export);
    let name = format!(
        "wallet-generation-{}-{}.bin",
        cursor["height"],
        cursor["tip"].as_str().unwrap()
    );
    Manifest::decode(
        &publisher.binding,
        &export.read(&name, wire::MAX_MANIFEST_BYTES).unwrap(),
    )
    .unwrap()
}
fn finish(
    publisher: &mut WalletPublisher,
    export: &PublicExport,
    source: &Synthetic,
    now: u64,
    budget: &p2p::Budget,
) {
    for _ in 0..=source.height.get() {
        if publisher
            .step(export, source, now, budget)
            .unwrap()
            .published
        {
            return;
        }
    }
    panic!("bounded synthetic backfill did not publish");
}

fn replace_suffix(source: &mut Synthetic, ancestor: usize, salt: u64) {
    let mut parent = if ancestor == 0 {
        source.binding.genesis()
    } else {
        source.headers[ancestor - 1].id().unwrap()
    };
    for header in &mut source.headers[ancestor..] {
        header.parent = parent;
        header.timestamp = salt + header.height;
        parent = header.id().unwrap();
    }
}

fn suffix_depth_reuses_only_the_common_prefix(depth: usize) {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("reorg-depth");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let mut source = Synthetic::new(binding(&store), 300, 300);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1000, &budget);
    let old_head = fs::read(root.join("wallet-head.json")).unwrap();
    let old_manifest = manifest(&export, &publisher);
    let old_name = old_manifest.name();
    let old_bytes = fs::read(root.join(&old_name)).unwrap();
    replace_suffix(&mut source, 300 - depth, 9000);
    publisher.invalidate_advertisement();
    let started = std::time::Instant::now();
    for offset in 1..=depth {
        let progress = publisher.step(&export, &source, 1001, &budget).unwrap();
        assert_eq!(progress.scanned_height, (300 - depth + offset) as u64);
        assert_eq!(progress.published, offset == depth);
        assert_eq!(progress.current, offset == depth);
        if offset < depth {
            assert_eq!(fs::read(root.join("wallet-head.json")).unwrap(), old_head);
        }
    }
    let elapsed = started.elapsed();
    assert_eq!(source.receipts.get(), 300 + depth);
    assert_eq!(fs::read(root.join(old_name)).unwrap(), old_bytes);
    assert_eq!(
        manifest(&export, &publisher).chunks[..2],
        old_manifest.chunks[..2]
    );
    assert_eq!(head(&export)["tip"], crate::local::hex(&source.head().1));
    eprintln!(
        "wallet_reorg_synthetic depth={depth} replacement_receipts={depth} publisher_steps={depth} elapsed_us={}",
        elapsed.as_micros()
    );
}
#[test]
fn reorganization_depth_1_reuses_common_prefix() {
    suffix_depth_reuses_only_the_common_prefix(1);
}
#[test]
fn reorganization_depth_2_reuses_common_prefix() {
    suffix_depth_reuses_only_the_common_prefix(2);
}
#[test]
fn reorganization_depth_7_reuses_common_prefix() {
    suffix_depth_reuses_only_the_common_prefix(7);
}

#[test]
fn reorganization_reuses_common_wallet_prefix_without_reexporting_receipts() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("reorg-prefix");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let mut source = Synthetic::new(binding(&store), 300, 300);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1000, &budget);
    let previous = manifest(&export, &publisher);
    let previous_name = previous.name();
    let previous_bytes = fs::read(root.join(&previous_name)).unwrap();
    let common_path = root.join(previous.chunks[0].name());
    let common_inode = fs::metadata(&common_path).unwrap().ino();
    let common_bytes = fs::read(&common_path).unwrap();
    assert_eq!(source.receipts.get(), 300);
    replace_suffix(&mut source, 299, 9000);
    publisher.invalidate_advertisement();
    let progress = publisher.step(&export, &source, 1001, &budget).unwrap();
    assert_eq!(progress.scanned_height, 300);
    assert!(progress.published && progress.current);
    assert_eq!(source.receipts.get(), 301);
    let current = manifest(&export, &publisher);
    assert_eq!(current.chunks[..2], previous.chunks[..2]);
    assert_eq!(fs::metadata(&common_path).unwrap().ino(), common_inode);
    assert_eq!(fs::read(&common_path).unwrap(), common_bytes);
    assert_eq!(fs::read(root.join(previous_name)).unwrap(), previous_bytes);
}

#[test]
fn reorganization_rewinds_across_immutable_chunk_boundary() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("reorg-chunk");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let mut source = Synthetic::new(binding(&store), 130, 300);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1000, &budget);
    replace_suffix(&mut source, 127, 9000);
    for expected in 128..=130 {
        let progress = publisher.step(&export, &source, 1001, &budget).unwrap();
        assert_eq!(progress.scanned_height, expected);
        assert_eq!(progress.published, expected == 130);
    }
    assert_eq!(source.receipts.get(), 133);
    assert_eq!(head(&export)["tip"], crate::local::hex(&source.head().1));
}

#[test]
fn reorganization_rejects_corrupt_immutable_chunk_before_reusing_prefix() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("reorg-corrupt");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let mut source = Synthetic::new(binding(&store), 130, 300);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1000, &budget);
    let original_cursor = fs::read(root.join("wallet-head.json")).unwrap();
    let chunk = root.join(publisher.full[0].name());
    let mut bytes = fs::read(&chunk).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&chunk, bytes).unwrap();
    replace_suffix(&mut source, 127, 9000);
    assert!(publisher.step(&export, &source, 1001, &budget).is_err());
    assert_eq!(
        fs::read(root.join("wallet-head.json")).unwrap(),
        original_cursor
    );
    assert_eq!(source.receipts.get(), 130);
}

#[test]
fn reorganization_restore_reuses_old_generation_common_prefix() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("reorg-reopen");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let mut source = Synthetic::new(binding(&store), 130, 300);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1000, &budget);
    drop(publisher);
    replace_suffix(&mut source, 127, 9000);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    assert_eq!(publisher.height, 127);
    assert_eq!(source.receipts.get(), 130);
    for _ in 0..3 {
        publisher.step(&export, &source, 1001, &budget).unwrap();
    }
    assert_eq!(head(&export)["tip"], crate::local::hex(&source.head().1));
    assert_eq!(source.receipts.get(), 133);
}

#[test]
fn reorganization_to_shorter_common_prefix_does_not_reexport_receipts() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("reorg-shorter");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let source = Synthetic::new(binding(&store), 130, 300);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1000, &budget);
    source.height.set(127);
    let progress = publisher.step(&export, &source, 1001, &budget).unwrap();
    assert!(progress.published && progress.current);
    assert_eq!(progress.scanned_height, 127);
    assert_eq!(source.receipts.get(), 130);
}
#[test]
fn incremental_backfill_reuses_full_chunks_and_restores_without_receipt_replay() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let source = Synthetic::new(binding(&store), 132, 300);
    source.height.set(130);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    assert!(
        WalletPublisher::restore(
            &export,
            source.binding.clone(),
            &source,
            WalletPolicy::default(),
            &budget
        )
        .is_err()
    );
    for expected in 1..130 {
        let progress = publisher.step(&export, &source, 1000, &budget).unwrap();
        assert_eq!(progress.scanned_height, expected);
        assert!(!progress.published);
        assert!(!root.join("wallet-head.json").exists());
    }
    assert!(
        publisher
            .step(&export, &source, 1000, &budget)
            .unwrap()
            .published
    );
    let first = manifest(&export, &publisher);
    assert_eq!(first.chunks.len(), 2);
    let full_path = root.join(first.chunks[0].name());
    let inode = fs::metadata(&full_path).unwrap().ino();
    let full_bytes = fs::read(&full_path).unwrap();
    let partial = root.join(first.chunks[1].name());
    source.height.set(131);
    finish(&mut publisher, &export, &source, 1001, &budget);
    let next = manifest(&export, &publisher);
    assert_eq!(next.chunks[0], first.chunks[0]);
    assert_ne!(next.chunks[1], first.chunks[1]);
    assert_eq!(fs::metadata(&full_path).unwrap().ino(), inode);
    assert_eq!(fs::read(&full_path).unwrap(), full_bytes);
    assert!(partial.exists());
    assert_eq!(source.receipts.get(), 131);
    drop(publisher);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    assert_eq!(publisher.height, 131);
    assert_eq!(source.receipts.get(), 131);
    finish(&mut publisher, &export, &source, 1061, &budget);
    assert_eq!(head(&export)["published_unix_seconds"], 1061);
    assert_eq!(source.receipts.get(), 131);
    source.height.set(132);
    finish(&mut publisher, &export, &source, 1062, &budget);
    assert_eq!(source.receipts.get(), 132);
}
#[test]
fn catalog_before_head_interruption_and_orphan_restart_preserve_the_committed_head() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let source = Synthetic::new(binding(&store), 3, 300);
    source.height.set(1);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1000, &budget);
    let committed = head(&export);
    source.height.set(2);
    FAIL_BEFORE_HEAD.with(|flag| flag.set(true));
    assert!(publisher.step(&export, &source, 1001, &budget).is_err());
    assert_eq!(head(&export), committed);
    assert_eq!(publisher.catalog.entries.len(), 2);
    assert!(
        publisher
            .catalog
            .entries
            .iter()
            .any(|e| e.height == 1 && e.expires == 1901)
    );
    assert!(
        publisher
            .catalog
            .entries
            .iter()
            .any(|e| e.height == 2 && e.expires == 0)
    );
    drop(publisher);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    assert_eq!(publisher.height, 1);
    finish(&mut publisher, &export, &source, 1002, &budget);
    assert_eq!(head(&export)["height"], 2);
    assert_eq!(publisher.catalog.entries.len(), 2);
    source.height.set(3);
    source.head_reads.set(0);
    source.advance_before_commit.set(false);
    finish(&mut publisher, &export, &source, 1003, &budget);
    assert_eq!(head(&export)["height"], 3);
}
#[test]
fn changed_source_prefix_and_midpublication_head_never_relabel_an_old_generation() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let source = Synthetic::new(binding(&store), 3, 300);
    source.height.set(1);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1000, &budget);
    let committed = head(&export);
    source.height.set(2);
    source.head_reads.set(0);
    source.advance_before_commit.set(true);
    assert!(publisher.step(&export, &source, 1001, &budget).is_err());
    assert_eq!(head(&export), committed);
    finish(&mut publisher, &export, &source, 1002, &budget);
    assert_eq!(head(&export)["height"], 3);
    let replacement = Synthetic::new(source.binding.clone(), 3, 900);
    let old_calls = replacement.receipts.get();
    let progress = publisher
        .step(&export, &replacement, 1003, &budget)
        .unwrap();
    assert_eq!(progress.scanned_height, 1);
    assert!(!progress.published);
    assert!(!progress.current);
    assert_eq!(replacement.receipts.get(), old_calls + 1);
    finish(&mut publisher, &export, &replacement, 1004, &budget);
    assert_eq!(
        head(&export)["tip"],
        crate::local::hex(&replacement.head().1)
    );
}
#[test]
fn advertisement_eviction_preserves_pins_and_expiry_removes_no_artifacts() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let source = Synthetic::new(binding(&store), 5, 300);
    source.height.set(0);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    for h in 1..=4 {
        source.height.set(h);
        finish(&mut publisher, &export, &source, 1000 + h, &budget);
    }
    let before = head(&export);
    source.height.set(5);
    finish(&mut publisher, &export, &source, 1005, &budget);
    assert_ne!(head(&export), before);
    assert_eq!(head(&export)["height"], 5);
    assert_eq!(publisher.retained.entries.len(), 4);
    assert_eq!(publisher.catalog.entries.len(), 4);
    let artifacts: Vec<_> = fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    finish(&mut publisher, &export, &source, 2000, &budget);
    assert_eq!(head(&export)["height"], 5);
    assert_eq!(publisher.catalog.entries.len(), 1);
    assert!(artifacts.iter().all(|p| p.exists()));
}
#[test]
fn budget_corruption_missing_dependencies_and_mutable_write_failure_fail_closed() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let source = Synthetic::new(binding(&store), 2, 300);
    source.height.set(1);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1000, &budget);
    let before = head(&export);
    let old_reserved = publisher.reserved;
    publisher.policy.max_artifact_bytes = old_reserved;
    source.height.set(2);
    assert!(
        publisher
            .step(&export, &source, 1001, &budget)
            .unwrap_err()
            .contains("budget exhausted")
    );
    assert_eq!(publisher.reserved, old_reserved);
    assert_eq!(publisher.height, 1);
    assert_eq!(head(&export), before);
    drop(publisher);
    let first_id = source.headers[0].id().unwrap();
    let receipt = root.join(format!("wallet-1-{}.bin", crate::local::hex(&first_id)));
    let bytes = fs::read(&receipt).unwrap();
    fs::remove_file(&receipt).unwrap();
    assert!(
        WalletPublisher::restore(
            &export,
            source.binding.clone(),
            &source,
            WalletPolicy::default(),
            &budget
        )
        .is_err()
    );
    export
        .write_once(receipt.file_name().unwrap().to_str().unwrap(), &bytes)
        .unwrap();
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    let dependency = manifest(&export, &publisher).chunks[0].name();
    let original = fs::read(root.join(&dependency)).unwrap();
    let mut corrupt = original.clone();
    corrupt[200] ^= 1;
    fs::write(root.join(&dependency), corrupt).unwrap();
    drop(publisher);
    assert!(
        WalletPublisher::restore(
            &export,
            source.binding.clone(),
            &source,
            WalletPolicy::default(),
            &budget
        )
        .is_err()
    );
    fs::write(root.join(&dependency), original).unwrap();
    publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    fs::remove_file(root.join("wallet-head.json")).unwrap();
    std::os::unix::fs::symlink(
        root.join("wallet-genesis.bin"),
        root.join("wallet-head.json"),
    )
    .unwrap();
    assert!(publisher.step(&export, &source, 1002, &budget).is_err());
    assert!(publisher.poisoned);
    assert!(publisher.step(&export, &source, 1003, &budget).is_err());
}

#[test]
fn interruption_before_manifest_and_catalog_never_advances_head_or_catalog() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let source = Synthetic::new(binding(&store), 2, 300);
    source.height.set(1);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1000, &budget);
    let before = head(&export);
    let catalog = export
        .read("wallet-generations.json", CATALOG_BYTES)
        .unwrap();
    source.height.set(2);
    FAIL_BEFORE_MANIFEST.with(|flag| flag.set(true));
    assert!(publisher.step(&export, &source, 1001, &budget).is_err());
    assert_eq!(head(&export), before);
    assert_eq!(
        export
            .read("wallet-generations.json", CATALOG_BYTES)
            .unwrap(),
        catalog
    );
    drop(publisher);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    FAIL_BEFORE_CATALOG.with(|flag| flag.set(true));
    assert!(publisher.step(&export, &source, 1002, &budget).is_err());
    assert_eq!(head(&export), before);
    assert_eq!(
        export
            .read("wallet-generations.json", CATALOG_BYTES)
            .unwrap(),
        catalog
    );
    drop(publisher);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1003, &budget);
    assert_eq!(head(&export)["height"], 2);
}
#[test]
fn failed_immutable_write_keeps_its_durable_charge_across_restart() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("export");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let source = Synthetic::new(binding(&store), 0, 300);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    let original = publisher.reserved;
    FAIL_IMMUTABLE.with(|flag| flag.set(true));
    assert!(
        publisher
            .immutable(&export, "failed.bin", &[0; 4097])
            .is_err()
    );
    let charged = publisher.reserved;
    assert!(charged > original);
    assert!(!root.join("failed.bin").exists());
    let journal: Value =
        serde_json::from_slice(&export.read("wallet-export-budget.json", 2048).unwrap()).unwrap();
    assert_eq!(journal["reserved_bytes"], charged);
    drop(publisher);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    assert!(publisher.reserved >= charged);
    publisher.policy.max_artifact_bytes = publisher.reserved;
    assert!(
        publisher
            .immutable(&export, "another.bin", b"x")
            .unwrap_err()
            .contains("budget exhausted")
    );
    assert!(!root.join("wallet-head.json").exists());
}

// A reader brackets both mutable metadata files. An old generation is history,
// not evidence that the native canonical head has remained unchanged.
fn read_complete_generation(root: &std::path::Path, binding: &Binding) -> Option<(u64, Hash)> {
    let before = fs::read(root.join("wallet-head.json")).unwrap();
    let catalog_before = fs::read(root.join("wallet-generations.json")).unwrap();
    let cursor: Value = serde_json::from_slice(&before).unwrap();
    let height = cursor["height"].as_u64().unwrap();
    let tip = decode_hash(cursor["tip"].as_str().unwrap()).unwrap();
    let catalog = Catalog::decode(binding, &catalog_before).unwrap();
    let entry = catalog
        .entries
        .iter()
        .find(|e| (e.height, e.tip) == (height, tip))
        .unwrap();
    let bytes = fs::read(root.join(format!(
        "wallet-generation-{height}-{}.bin",
        crate::local::hex(&tip)
    )))
    .unwrap();
    assert_eq!(wire::digest(&bytes), entry.digest);
    let manifest = Manifest::decode(binding, &bytes).unwrap();
    assert_eq!((manifest.height, manifest.tip), (height, tip));
    let mut previous = binding.genesis();
    for descriptor in &manifest.chunks {
        let chunk = descriptor
            .decode_chunk(binding, &fs::read(root.join(descriptor.name())).unwrap())
            .unwrap();
        for (index, record) in chunk.records.iter().enumerate() {
            assert_eq!(record.decoded(binding).unwrap().parent, previous);
            let receipt =
                fs::read(root.join(record.receipt_name(chunk.from + index as u64))).unwrap();
            assert_eq!(wire::digest(&receipt), record.receipt_digest);
            previous = record.id;
        }
    }
    assert_eq!(previous, tip);
    let catalog_after = fs::read(root.join("wallet-generations.json")).unwrap();
    let after = fs::read(root.join("wallet-head.json")).unwrap();
    (before == after && catalog_before == catalog_after).then_some((height, tip))
}

fn pause_after_catalog_for_reader(
    signal: &std::sync::mpsc::Sender<()>,
    completed: &std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
) {
    let signal = signal.clone();
    let completed = completed.clone();
    AFTER_CATALOG.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            signal.send(()).unwrap();
            completed
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(3))
                .unwrap();
        }));
    });
}

#[test]
fn paused_publication_remains_readable_to_a_concurrent_reader() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("paused-publication");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let source = Synthetic::new(binding(&store), 4, 300);
    source.height.set(1);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1000, &budget);
    std::thread::scope(|scope| {
        let (send, recv) = std::sync::mpsc::channel();
        let (ack, observed) = std::sync::mpsc::channel();
        let root = &root;
        let binding = source.binding.clone();
        scope.spawn(move || {
            for expected in recv {
                assert_eq!(read_complete_generation(root, &binding), Some(expected));
                ack.send(()).unwrap();
            }
        });
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let overlaps = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (started, ready) = std::sync::mpsc::channel();
        let (read_midpoint, requested) = std::sync::mpsc::channel();
        let (ack_midpoint, completed) = std::sync::mpsc::channel();
        let completed = std::sync::Arc::new(std::sync::Mutex::new(completed));
        let binding = source.binding.clone();
        let done_ref = done.clone();
        let writing_ref = writing.clone();
        let overlaps_ref = overlaps.clone();
        let reader = scope.spawn(move || {
            let mut reads = 0;
            let mut sent = false;
            let mut pending = false;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !done_ref.load(std::sync::atomic::Ordering::Acquire)
                && std::time::Instant::now() < deadline
            {
                pending |= requested.try_recv().is_ok();
                if read_complete_generation(root, &binding).is_some() {
                    if pending {
                        assert!(writing_ref.load(std::sync::atomic::Ordering::Acquire));
                        overlaps_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        ack_midpoint.send(()).unwrap();
                        pending = false;
                    }
                    reads += 1;
                    if writing_ref.load(std::sync::atomic::Ordering::Acquire) {
                        overlaps_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                if reads > 0 && !sent {
                    started.send(()).unwrap();
                    sent = true;
                }
                std::thread::yield_now();
            }
            reads
        });
        ready
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        for next in 2..=4 {
            let committed = source.head();
            export.pause_wallet_head().unwrap();
            publisher.invalidate_advertisement();
            send.send(committed).unwrap();
            observed
                .recv_timeout(std::time::Duration::from_secs(3))
                .unwrap();
            source.height.set(next);
            pause_after_catalog_for_reader(&read_midpoint, &completed);
            writing.store(true, std::sync::atomic::Ordering::Release);
            finish(&mut publisher, &export, &source, 1000 + next, &budget);
            writing.store(false, std::sync::atomic::Ordering::Release);
            send.send(source.head()).unwrap();
            observed
                .recv_timeout(std::time::Duration::from_secs(3))
                .unwrap();
        }
        // Repeated metadata replacement also overlaps the uninterrupted reader
        // without exhausting the finite retained-generation catalog.
        for now in 1005..1021 {
            publisher.invalidate_advertisement();
            pause_after_catalog_for_reader(&read_midpoint, &completed);
            writing.store(true, std::sync::atomic::Ordering::Release);
            finish(&mut publisher, &export, &source, now, &budget);
            writing.store(false, std::sync::atomic::Ordering::Release);
        }
        done.store(true, std::sync::atomic::Ordering::Release);
        assert!(reader.join().unwrap() > 1);
        assert!(overlaps.load(std::sync::atomic::Ordering::Relaxed) > 0);
    });
}

#[test]
fn invalidation_pins_the_committed_generation_past_retention_and_interruption() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("paused-retention");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let source = Synthetic::new(binding(&store), 3, 300);
    source.height.set(1);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1000, &budget);
    let committed = source.head();
    for (height, now) in [(2, 1001), (3, 2002)] {
        publisher.invalidate_advertisement();
        source.height.set(height);
        FAIL_BEFORE_HEAD.with(|flag| flag.set(true));
        assert!(publisher.step(&export, &source, now, &budget).is_err());
        assert_eq!(
            read_complete_generation(&root, &source.binding),
            Some(committed)
        );
    }
    drop(publisher);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    assert_eq!(
        publisher.published.map(|(height, tip, _)| (height, tip)),
        Some(committed)
    );
    finish(&mut publisher, &export, &source, 2003, &budget);
    assert_eq!(
        read_complete_generation(&root, &source.binding),
        Some(source.head())
    );
}

#[test]
fn paused_refresh_failures_preserve_complete_metadata_until_the_head_commits() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("paused-failure");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let source = Synthetic::new(binding(&store), 2, 300);
    source.height.set(1);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1000, &budget);
    let committed = source.head();
    publisher.invalidate_advertisement();
    for fail in [
        &FAIL_BEFORE_MANIFEST,
        &FAIL_BEFORE_CATALOG,
        &FAIL_BEFORE_HEAD,
    ] {
        fail.with(|flag| flag.set(true));
        assert!(publisher.step(&export, &source, 1001, &budget).is_err());
        assert_eq!(
            read_complete_generation(&root, &source.binding),
            Some(committed)
        );
    }
    assert!(
        publisher
            .step(&export, &source, 1001, &budget)
            .unwrap()
            .published
    );
    assert_eq!(head(&export)["published_unix_seconds"], 1001);
}

#[test]
fn rapid_heads_keep_current_publication_and_exact_unexpired_pins() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("retained-index");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let source = Synthetic::new(binding(&store), 8, 300);
    source.height.set(1);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    let mut heads = Vec::new();
    for height in 1..=8 {
        source.height.set(height);
        finish(&mut publisher, &export, &source, 1000 + height, &budget);
        heads.push(source.head());
        assert_eq!(
            read_complete_generation(&root, &source.binding),
            Some(source.head())
        );
        assert!(publisher.catalog.entries.len() <= RETAINED_HEADS);
    }
    assert_eq!(publisher.retained.entries.len(), 7);
    for &(height, tip) in &heads {
        assert_eq!(
            export
                .wallet_generation_manifest(height, tip, 1008)
                .unwrap()
                .height,
            height
        );
    }
    let page = export
        .wallet_generation_header_page(heads[0], 1, 128, 1008, &budget)
        .unwrap();
    assert_eq!(&page.as_ref()[..8], b"SWE2WHP1");
    assert_eq!(
        &page.as_ref()[187..],
        source.headers[0].encode().unwrap().as_slice()
    );
    assert!(
        export
            .wallet_generation_header_page(heads[0], 1, 128, 1902, &budget)
            .is_err()
    );
    assert!(
        export
            .wallet_generation_header_page(heads[0], 0, 128, 1008, &budget)
            .is_err()
    );
    drop(page);
    let before = publisher
        .retained
        .entries
        .iter()
        .map(|e| ((e.height, e.tip), e.expires))
        .collect::<Vec<_>>();
    for now in 1010..1020 {
        publisher.invalidate_advertisement();
        finish(&mut publisher, &export, &source, now, &budget);
    }
    assert_eq!(
        before,
        publisher
            .retained
            .entries
            .iter()
            .map(|e| ((e.height, e.tip), e.expires))
            .collect::<Vec<_>>()
    );
    assert!(
        export
            .wallet_generation_manifest(heads[0].0, heads[0].1, 1902)
            .is_err()
    );
    assert!(
        export
            .wallet_generation_manifest(heads[7].0, heads[7].1, 3000)
            .is_ok()
    );
    drop(publisher);
    let reopened = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    assert_eq!(reopened.retained.entries.len(), 7);
    let path = root.join(format!(
        "wallet-generation-{}-{}.bin",
        heads[0].0,
        crate::local::hex(&heads[0].1)
    ));
    fs::remove_file(path).unwrap();
    assert!(
        export
            .wallet_generation_manifest(heads[0].0, heads[0].1, 1008)
            .is_err()
    );
}
#[test]
fn bounded_retention_exhaustion_and_malformed_records_remain_errors() {
    let dir = Directory::new();
    let store = dir.store();
    let binding = binding(&store);
    let index = RetainedIndex {
        entries: (0..MAX_RETAINED_PINS)
            .map(|i| Entry {
                height: i as u64,
                tip: [i as u8; 32],
                digest: [42; 32],
                expires: 2000,
            })
            .collect(),
    };
    let catalog = Catalog {
        sequence: 1,
        entries: vec![Entry {
            height: 300,
            tip: [43; 32],
            digest: [44; 32],
            expires: 0,
        }],
    };
    assert_eq!(
        catalog
            .staged_advertisement(&index, 301, [45; 32], [46; 32], 1000, Some((300, [43; 32])))
            .unwrap_err(),
        "wallet retained pin index full"
    );
    assert_eq!(index.entries.len(), MAX_RETAINED_PINS);
    let raw = index.encode(&binding).unwrap();
    assert_eq!(
        RetainedIndex::decode(&binding, &raw).unwrap().entries.len(),
        MAX_RETAINED_PINS
    );
    assert!(RetainedIndex::decode(&binding, &raw[..raw.len() - 1]).is_err());
    let mut corrupt = raw.clone();
    corrupt[8] ^= 1;
    assert!(RetainedIndex::decode(&binding, &corrupt).is_err());
    let mut duplicate = index.clone();
    duplicate.entries[1] = duplicate.entries[0].clone();
    assert!(RetainedIndex::decode(&binding, &duplicate.encode(&binding).unwrap()).is_err());
    let index = RetainedIndex {
        entries: vec![Entry {
            height: 300,
            tip: [43; 32],
            digest: [99; 32],
            expires: 2000,
        }],
    };
    assert!(
        catalog
            .staged_advertisement(&index, 301, [45; 32], [46; 32], 1000, Some((300, [43; 32])))
            .is_err()
    );
}
#[test]
fn unchanged_head_refresh_does_not_extend_an_uncommitted_orphan() {
    let old = Entry {
        height: 5,
        tip: [5; 32],
        digest: [6; 32],
        expires: 1500,
    };
    let retained = RetainedIndex {
        entries: vec![old.clone()],
    };
    let catalog = Catalog {
        sequence: 9,
        entries: vec![
            Entry {
                expires: 0,
                ..old.clone()
            },
            Entry {
                height: 4,
                tip: [4; 32],
                digest: [3; 32],
                expires: 1400,
            },
        ],
    };
    let (_, next) = catalog
        .staged_advertisement(&retained, 4, [4; 32], [3; 32], 1200, Some((4, [4; 32])))
        .unwrap();
    assert_eq!(
        next.entries.iter().find(|e| e.height == 5).unwrap().expires,
        1500
    );
}

#[test]
fn interrupted_reactivation_preserves_the_old_unexpired_pin() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("retained-reactivation");
    let export = PublicExport::open(&root, &store, limits()).unwrap();
    let budget = p2p::Budget::new(2 * 1024 * 1024);
    let source = Synthetic::new(binding(&store), 3, 300);
    source.height.set(1);
    let mut publisher = WalletPublisher::restore(
        &export,
        source.binding.clone(),
        &source,
        WalletPolicy::default(),
        &budget,
    )
    .unwrap();
    finish(&mut publisher, &export, &source, 1001, &budget);
    let pin = source.head();
    for height in 2..=3 {
        source.height.set(height);
        finish(&mut publisher, &export, &source, 1000 + height, &budget);
    }
    let committed = source.head();
    publisher.invalidate_advertisement();
    source.height.set(1);
    FAIL_BEFORE_HEAD.with(|flag| flag.set(true));
    assert!(publisher.step(&export, &source, 1004, &budget).is_err());
    assert_eq!(
        read_complete_generation(&root, &source.binding),
        Some(committed)
    );
    assert!(
        export
            .wallet_generation_manifest(pin.0, pin.1, 1004)
            .is_ok()
    );
    assert!(
        export
            .wallet_generation_manifest(committed.0, committed.1, 1004)
            .is_ok()
    );
}
