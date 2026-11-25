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
    assert_eq!(replacement.receipts.get(), old_calls + 1);
    finish(&mut publisher, &export, &replacement, 1004, &budget);
    assert_eq!(
        head(&export)["tip"],
        crate::local::hex(&replacement.head().1)
    );
}
#[test]
fn unexpired_pin_saturation_pauses_exports_and_expiry_removes_no_artifacts() {
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
    assert!(
        publisher
            .step(&export, &source, 1005, &budget)
            .unwrap_err()
            .contains("catalog full")
    );
    assert_eq!(head(&export), before);
    assert_eq!(publisher.catalog.entries.len(), 4);
    let artifacts: Vec<_> = fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    finish(&mut publisher, &export, &source, 2000, &budget);
    assert_eq!(head(&export)["height"], 5);
    assert_eq!(publisher.catalog.entries.len(), 2);
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
