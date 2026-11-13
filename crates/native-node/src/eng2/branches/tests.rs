use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(1);

pub(crate) struct Fixture(pub(crate) std::path::PathBuf);
impl Fixture {
    pub(crate) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "eng2-branches-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub(crate) fn path(&self) -> std::path::PathBuf {
        self.0.join("branches.redb")
    }
    fn store(&self) -> BranchStore {
        BranchStore::create(&self.path(), rules(), limits()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn rules() -> HeaderRules {
    HeaderRules {
        network: [17; 32],
        genesis: [2; 32],
        genesis_timestamp: 1,
        genesis_target: [255; 32],
        target_interval: 300,
        pow_iterations: 0,
        max_headers: 128,
    }
}
fn limits() -> Limits {
    Limits {
        maximum_headers: 128,
        maximum_body_bytes: 16 * 1024 * 1024,
    }
}
fn chain(prefix: &[Header], count: u64, tag: u8) -> VerifiedHeaders {
    let rules = rules();
    let mut headers = prefix.to_vec();
    let mut parent = headers.last().map_or(rules.genesis, |h| h.id().unwrap());
    for height in headers.len() as u64 + 1..=count {
        let h = Header {
            network: rules.network,
            height,
            parent,
            timestamp: 1 + height * 300,
            target: [255; 32],
            execution_commitment: [tag; 32],
            body_commitment: [7; 32],
            nonce: 0,
        };
        assert!(siworld_core::pow::meets_target(
            &siworld_core::pow::pow_hash(&h.pow_seed().unwrap(), 0, 0),
            &h.target
        ));
        parent = h.id().unwrap();
        headers.push(h);
    }
    VerifiedHeaders::verify(rules, headers).unwrap()
}

#[test]
fn durable_arrival_breaks_equal_work_and_duplicates_do_not_reorder() {
    let fixture = Fixture::new();
    let first = chain(&[], 3, 10);
    let second = chain(&[], 3, 11);
    {
        let mut store = fixture.store();
        assert_eq!(store.selection_revision(), 0);
        store.retain_verified_headers(&first).unwrap();
        let first_revision = store.selection_revision();
        assert!(first_revision > 0);
        store.retain_verified_headers(&second).unwrap();
        let changed_revision = store.selection_revision();
        assert!(changed_revision > first_revision);
        store.retain_verified_headers(&first).unwrap();
        assert_eq!(store.selection_revision(), changed_revision);
        assert_eq!(store.best_candidate().unwrap(), Some(first.id(3).unwrap()));
    }
    let mut store = BranchStore::open(&fixture.path(), rules(), limits()).unwrap();
    store.retain_verified_headers(&second).unwrap();
    assert_eq!(store.best_candidate().unwrap(), Some(first.id(3).unwrap()));
    assert_eq!(
        store
            .entry(first.id(3).unwrap())
            .unwrap()
            .unwrap()
            .cumulative_work,
        Work::from(3)
    );
}

#[test]
fn greater_work_and_exact_common_ancestor_are_independently_derived() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let old = chain(&[], 6, 10);
    let new = chain(
        &[
            old.header(1).unwrap().clone(),
            old.header(2).unwrap().clone(),
        ],
        7,
        11,
    );
    store.retain_verified_headers(&old).unwrap();
    store.retain_verified_headers(&new).unwrap();
    let path = store
        .candidate_path(old.id(6).unwrap(), new.id(7).unwrap())
        .unwrap();
    assert_eq!(path.ancestor_height, 2);
    assert_eq!(path.ancestor_id, old.id(2).unwrap());
    assert_eq!(path.ancestor_execution_commitment, Some([10; 32]));
    assert_eq!(path.removed.len(), 4);
    assert_eq!(path.replacement.len(), 5);
    assert_eq!(path.replacement[0], new.id(3).unwrap());
    assert_eq!(path.cumulative_work, Work::from(7));
    assert_eq!(store.best_candidate().unwrap(), Some(new.id(7).unwrap()));
}

#[test]
fn invalid_ancestor_excludes_all_descendants_and_survives_reopen() {
    let fixture = Fixture::new();
    let old = chain(&[], 4, 10);
    let bad = chain(&[], 8, 11);
    {
        let mut store = fixture.store();
        store.retain_verified_headers(&old).unwrap();
        store.retain_verified_headers(&bad).unwrap();
        let before_invalid = store.selection_revision();
        store.mark_invalid(bad.id(2).unwrap()).unwrap();
        let after_invalid = store.selection_revision();
        assert!(after_invalid > before_invalid);
        store.mark_invalid(bad.id(2).unwrap()).unwrap();
        assert_eq!(store.selection_revision(), after_invalid);
        assert_eq!(store.best_candidate().unwrap(), Some(old.id(4).unwrap()));
        assert!(
            store
                .candidate_path(old.id(4).unwrap(), bad.id(8).unwrap())
                .is_err()
        );
    }
    let store = BranchStore::open(&fixture.path(), rules(), limits()).unwrap();
    assert_eq!(store.best_candidate().unwrap(), Some(old.id(4).unwrap()));
}

#[test]
fn bounded_header_batch_failure_is_atomic_and_rules_are_immutable() {
    let fixture = Fixture::new();
    let bound = Limits {
        maximum_headers: 2,
        ..limits()
    };
    let mut store = BranchStore::create(&fixture.path(), rules(), bound).unwrap();
    let path = chain(&[], 3, 10);
    assert!(store.retain_verified_headers(&path).is_err());
    assert!(store.entry(path.id(1).unwrap()).unwrap().is_none());
    drop(store);
    let mut changed = rules();
    changed.pow_iterations = 1;
    assert!(BranchStore::open(&fixture.path(), changed, limits()).is_err());
    assert!(BranchStore::create(&fixture.path(), rules(), limits()).is_err());
}

#[test]
fn retained_body_is_only_framing_qualified_and_preserved_by_identity() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let mut body = crate::eng2::body::tests::body();
    body.height = 1;
    body.fund_claims.clear();
    body.governance.clear();
    let mut h = chain(&[], 1, 10).header(1).unwrap().clone();
    let policy = crate::eng2::body::tests::policy();
    h.body_commitment = body.commitment(policy).unwrap();
    let path = VerifiedHeaders::verify(rules(), vec![h.clone()]).unwrap();
    assert!(store.retain_body(&h, &body, policy).is_err());
    store.retain_verified_headers(&path).unwrap();
    store.retain_body(&h, &body, policy).unwrap();
    let id = h.id().unwrap();
    assert_eq!(
        store.body_size(id).unwrap(),
        Some(body.encoded_len(policy).unwrap())
    );
    assert_eq!(store.body_size([99; 32]).unwrap(), None);
    assert_eq!(
        store.entry(id).unwrap().unwrap().status,
        Status::BodyRetained
    );
    assert_eq!(store.body(id, policy).unwrap(), Some(body.clone()));
    store.retain_body(&h, &body, policy).unwrap();
    body.settlement_proof.push(99);
    assert!(store.retain_body(&h, &body, policy).is_err());
    drop(store);
    let store = BranchStore::open(&fixture.path(), rules(), limits()).unwrap();
    assert_eq!(
        store.entry(id).unwrap().unwrap().status,
        Status::BodyRetained
    );
}

#[test]
fn body_capacity_rejection_keeps_header_and_accounting_unchanged() {
    let fixture = Fixture::new();
    let mut store = BranchStore::create(
        &fixture.path(),
        rules(),
        Limits {
            maximum_body_bytes: 1,
            ..limits()
        },
    )
    .unwrap();
    let mut body = crate::eng2::body::tests::body();
    body.height = 1;
    body.fund_claims.clear();
    body.governance.clear();
    let policy = crate::eng2::body::tests::policy();
    let mut h = chain(&[], 1, 10).header(1).unwrap().clone();
    h.body_commitment = body.commitment(policy).unwrap();
    let path = VerifiedHeaders::verify(rules(), vec![h.clone()]).unwrap();
    store.retain_verified_headers(&path).unwrap();
    assert!(store.retain_body(&h, &body, policy).is_err());
    let id = h.id().unwrap();
    assert!(store.body(id, policy).unwrap().is_none());
    assert_eq!(
        store.entry(id).unwrap().unwrap().status,
        Status::HeaderQualified
    );
}

fn framing_chain(
    prefix: &[(Header, Body)],
    count: u64,
    tag: u8,
) -> (VerifiedHeaders, Vec<(Header, Body)>) {
    let mut blocks = prefix.to_vec();
    let policy = crate::eng2::body::tests::policy();
    let mut parent = blocks
        .last()
        .map_or(rules().genesis, |(header, _)| header.id().unwrap());
    for height in blocks.len() as u64 + 1..=count {
        let mut body = crate::eng2::body::tests::body();
        body.height = height;
        body.fund_claims.clear();
        body.governance.clear();
        let header = Header {
            network: rules().network,
            height,
            parent,
            timestamp: 1 + height * 300,
            target: [255; 32],
            execution_commitment: [tag; 32],
            body_commitment: body.commitment(policy).unwrap(),
            nonce: 0,
        };
        parent = header.id().unwrap();
        blocks.push((header, body));
    }
    let path = VerifiedHeaders::verify(
        rules(),
        blocks.iter().map(|(header, _)| header.clone()).collect(),
    )
    .unwrap();
    (path, blocks)
}

#[test]
fn switch_requires_complete_old_and_new_materials_then_old_replay_survives_reopen() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let policy = crate::eng2::body::tests::policy();
    let (old, old_blocks) = framing_chain(&[], 4, 10);
    let (new, new_blocks) = framing_chain(&old_blocks[..1], 5, 11);
    store.retain_verified_headers(&old).unwrap();
    store.retain_verified_headers(&new).unwrap();
    for (header, body) in &new_blocks {
        store.retain_body(header, body, policy).unwrap();
    }
    // A complete replacement cannot authorize restoring without complete
    // original proofs: those are necessary to recover after native rejection.
    assert!(
        store
            .prepare_switch(old.id(4).unwrap(), new.id(5).unwrap(), policy)
            .is_err()
    );
    for (header, body) in &old_blocks {
        store.retain_body(header, body, policy).unwrap();
    }
    let replay = store
        .prepare_switch(old.id(4).unwrap(), new.id(5).unwrap(), policy)
        .unwrap();
    assert_eq!(
        replay.original.ancestor(),
        (1, old.id(1).unwrap(), Some([10; 32]))
    );
    assert_eq!(replay.original.len(), 3);
    assert_eq!(replay.original.tip().unwrap(), old.id(4).unwrap());
    assert_eq!(replay.replacement.len(), 4);
    assert!(
        store
            .prepare_switch(new.id(5).unwrap(), old.id(4).unwrap(), policy)
            .unwrap_err()
            .contains("preferred")
    );
    assert!(replay.original.encoded_body_bytes() > 0);
    store.mark_invalid(new.id(2).unwrap()).unwrap();
    assert!(store.replay_block(&replay.replacement, 0, policy).is_err());
    drop(store);
    let store = BranchStore::open(&fixture.path(), rules(), limits()).unwrap();
    for (index, expected) in old_blocks[1..].iter().enumerate() {
        let (header, body) = store.replay_block(&replay.original, index, policy).unwrap();
        assert_eq!(header, expected.0);
        assert_eq!(
            body.encode(policy).unwrap(),
            expected.1.encode(policy).unwrap()
        );
        assert_eq!(body.transactions, expected.1.transactions);
        assert_eq!(body.settlement_proof, expected.1.settlement_proof);
    }
    assert!(
        store
            .replay_block(&replay.original, replay.original.len(), policy)
            .is_err()
    );
}

#[test]
fn replay_rechecks_missing_materials_and_rejects_noncontiguous_order() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let policy = crate::eng2::body::tests::policy();
    let (path, blocks) = framing_chain(&[], 3, 10);
    store.retain_verified_headers(&path).unwrap();
    for (header, body) in &blocks {
        store.retain_body(header, body, policy).unwrap();
    }
    let ids = [
        path.id(1).unwrap(),
        path.id(2).unwrap(),
        path.id(3).unwrap(),
    ];
    assert!(
        store
            .replay_plan(rules().genesis, &[ids[1], ids[0]], policy)
            .is_err()
    );
    let plan = store.replay_plan(rules().genesis, &ids, policy).unwrap();
    let transaction = store.database.begin_write().unwrap();
    transaction
        .open_table(BODIES)
        .unwrap()
        .remove(ids[1].as_slice())
        .unwrap();
    transaction.commit().unwrap();
    assert!(store.replay_block(&plan, 1, policy).is_err());
}

#[test]
fn switch_depth_above_twenty_four_is_rejected_before_material_loading() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let old = chain(&[], 25, 10);
    let new = chain(&[], 26, 11);
    store.retain_verified_headers(&old).unwrap();
    store.retain_verified_headers(&new).unwrap();
    let failure = store
        .prepare_switch(
            old.id(25).unwrap(),
            new.id(26).unwrap(),
            crate::eng2::body::tests::policy(),
        )
        .unwrap_err();
    assert!(failure.contains("depth"));
}

#[test]
fn empty_canonical_archive_uses_actual_store_context_without_fabricating_bodies() {
    use crate::eng2::{
        genesis::{FeeMode, Genesis},
        snapshot,
    };
    let fixture = Fixture::new();
    let state = snapshot::tests::bootstrap();
    let genesis = Genesis::seal(
        state.chain().config.clone(),
        state.governance().clone(),
        FeeMode::LegacyMiner,
    )
    .unwrap();
    let config = genesis.config();
    let selected = HeaderRules {
        network: config.network,
        genesis: genesis.id(),
        genesis_timestamp: config.genesis_timestamp,
        genesis_target: config.genesis_target,
        target_interval: config.target_interval,
        pow_iterations: config.pow_iterations,
        max_headers: 128,
    };
    let id = genesis.id();
    let canonical = Store::create(
        &fixture.0.join("canonical.redb"),
        genesis,
        snapshot::tests::limits().chain,
    )
    .unwrap();
    let mut store = BranchStore::create(&fixture.path(), selected, limits()).unwrap();
    let plan = store.archive_canonical_suffix(&canonical, 0).unwrap();
    assert!(plan.is_empty());
    assert_eq!(plan.ancestor(), (0, id, None));
    assert_eq!(plan.tip().unwrap(), id);
    assert_eq!(plan.encoded_body_bytes(), 0);
    assert!(store.archive_canonical_suffix(&canonical, 1).is_err());
}

#[test]
#[ignore = "requires an explicit closed disposable native fixture; never selected by CI"]
fn retain_committed_requires_actual_native_capability_and_preserves_raw_records() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let source = std::path::PathBuf::from(
        std::env::var_os("SIWORLD_REORG_NATIVE_SOURCE").expect("explicit closed source required"),
    );
    assert!(source.is_absolute() && source.join("disposable-fixture").is_file());
    let genesis_bytes = std::fs::read(source.join("genesis.bin")).unwrap();
    let genesis = super::super::genesis::Genesis::decode(&genesis_bytes).unwrap();
    assert!(genesis.config().fixture);
    assert_eq!(genesis.config().pow_iterations, 0);
    assert_eq!(genesis.config().genesis_target, [255; 32]);
    let rules = HeaderRules {
        network: genesis.config().network,
        genesis: genesis.id(),
        genesis_timestamp: genesis.config().genesis_timestamp,
        genesis_target: genesis.config().genesis_target,
        target_interval: genesis.config().target_interval,
        pow_iterations: 0,
        max_headers: 128,
    };
    let fixture = Fixture::new();
    let mut store = BranchStore::create(
        &fixture.path(),
        rules.clone(),
        Limits {
            maximum_headers: 128,
            maximum_body_bytes: 256 * 1024 * 1024,
        },
    )
    .unwrap();
    let mut engine = super::super::execution::Engine::new(
        genesis,
        super::super::state_components::Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        },
    )
    .unwrap();
    let policy = engine.body_policy();
    let table: TableDefinition<u64, &[u8]> = TableDefinition::new("eng2-canonical-blocks-v1");
    let database = redb::ReadOnlyDatabase::open(source.join("chain.redb")).unwrap();
    let transaction = database.begin_read().unwrap();
    let blocks = transaction.open_table(table).unwrap();
    let verifier = crate::proofs::NativeVerifier::new().unwrap();
    let mut previous = None;
    for height in 1..=3u64 {
        let row = blocks.get(height).unwrap().unwrap();
        let bytes = row.value();
        assert!(bytes.len() <= HEADER_BYTES + policy.max_body_bytes);
        let header = Header::decode(&bytes[..HEADER_BYTES], &rules.network).unwrap();
        let body = Body::decode(&bytes[HEADER_BYTES..], rules.network, height, policy).unwrap();
        let committed = engine.apply(&header, &body, &verifier).unwrap();
        if let Some(previous) = previous.as_ref() {
            assert!(
                store
                    .retain_committed(&header, &body, policy, previous)
                    .is_err()
            );
        }
        let mut changed = header.clone();
        changed.execution_commitment[0] ^= 1;
        assert!(
            store
                .retain_committed(&changed, &body, policy, &committed)
                .is_err()
        );
        let mut changed_body = body.clone();
        changed_body.settlement_proof[0] ^= 1;
        assert!(
            store
                .retain_committed(&header, &changed_body, policy, &committed)
                .is_err()
        );
        store
            .retain_committed(&header, &body, policy, &committed)
            .unwrap();
        let entry = store.entry(committed.id()).unwrap().unwrap();
        assert_eq!(entry.status, Status::Executed);
        store
            .retain_committed(&header, &body, policy, &committed)
            .unwrap();
        assert_eq!(
            store.entry(committed.id()).unwrap().unwrap().first_seen,
            entry.first_seen
        );
        assert_eq!(
            store.body(committed.id(), policy).unwrap(),
            Some(body.clone())
        );
        assert_eq!(
            store.body_size(committed.id()).unwrap(),
            Some(body.encoded_len(policy).unwrap())
        );
        let absent = Fixture::new();
        let mut missing = BranchStore::create(
            &absent.path(),
            rules.clone(),
            Limits {
                maximum_headers: 128,
                maximum_body_bytes: 256 * 1024 * 1024,
            },
        )
        .unwrap();
        if height > 1 {
            assert!(
                missing
                    .retain_committed(&header, &body, policy, &committed)
                    .is_err()
            );
        }
        let tiny = Fixture::new();
        let mut limited = BranchStore::create(
            &tiny.path(),
            rules.clone(),
            Limits {
                maximum_headers: 128,
                maximum_body_bytes: 1,
            },
        )
        .unwrap();
        assert!(
            limited
                .retain_committed(&header, &body, policy, &committed)
                .is_err()
        );
        assert!(limited.entry(committed.id()).unwrap().is_none());
        previous = Some(committed);
    }
    drop(store);
    let store = BranchStore::open(
        &fixture.path(),
        rules,
        Limits {
            maximum_headers: 128,
            maximum_body_bytes: 256 * 1024 * 1024,
        },
    )
    .unwrap();
    assert_eq!(
        store.best_candidate().unwrap(),
        previous.as_ref().map(|committed| committed.id())
    );
    println!(
        "retained_native_blocks=3; generated_proofs=0; source_read_only=true; capability_substitution_rejected=true"
    );
}

#[cfg(unix)]
#[test]
#[ignore = "bounded child process for the explicitly invoked branch-store crash test"]
fn branch_store_sigkill_child() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let root = std::path::PathBuf::from(
        std::env::var_os("SIWORLD_BRANCH_CRASH_ROOT").expect("explicit crash root"),
    );
    assert!(root.is_absolute() && root.is_dir());
    let mut store = BranchStore::create(&root.join("branches.redb"), rules(), limits()).unwrap();
    let mut body = crate::eng2::body::tests::body();
    body.height = 1;
    body.governance.clear();
    body.fund_claims.clear();
    let policy = crate::eng2::body::tests::policy();
    let mut first = chain(&[], 1, 10).header(1).unwrap().clone();
    first.body_commitment = body.commitment(policy).unwrap();
    let main = chain(&[first.clone()], 3, 10);
    let competing = chain(&[first.clone()], 3, 20);
    store.retain_verified_headers(&main).unwrap();
    store.retain_verified_headers(&competing).unwrap();
    store.retain_body(&first, &body, policy).unwrap();
    let bad = competing.id(2).unwrap();
    store.mark_invalid(bad).unwrap();
    let value = serde_json::json!({"main":main.id(3).unwrap(),"bad":bad,"body":first.id().unwrap(),
        "main_first":store.entry(main.id(3).unwrap()).unwrap().unwrap().first_seen,
        "bad_first":store.entry(bad).unwrap().unwrap().first_seen,
        "raw":*blake3::hash(&body.encode(policy).unwrap()).as_bytes()});
    let mut file = std::fs::File::create(root.join("ready.json")).unwrap();
    use std::io::Write;
    file.write_all(value.to_string().as_bytes()).unwrap();
    file.sync_all().unwrap();
    loop {
        std::thread::park_timeout(std::time::Duration::from_secs(60));
    }
}
#[cfg(unix)]
#[test]
#[ignore = "owner-operated SIGKILL of a bounded disposable raw-branch fixture; never CI"]
fn branch_store_sigkill_preserves_raw_arrival_and_invalid_marks() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    let root = Fixture::new();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "eng2::branches::tests::branch_store_sigkill_child",
            "--nocapture",
        ])
        .env("SIWORLD_BRANCH_CRASH_ROOT", &root.0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !root.0.join("ready.json").is_file() && std::time::Instant::now() < deadline {
        assert!(
            child.try_wait().unwrap().is_none(),
            "crash fixture exited before committed marker"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    child.kill().unwrap();
    let status = child.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9));
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.0.join("ready.json")).unwrap()).unwrap();
    let hash = |name: &str| -> Hash { serde_json::from_value(value[name].clone()).unwrap() };
    let store = BranchStore::open(&root.path(), rules(), limits()).unwrap();
    assert_eq!(store.best_candidate().unwrap(), Some(hash("main")));
    assert_eq!(
        store.entry(hash("main")).unwrap().unwrap().first_seen,
        value["main_first"].as_u64().unwrap()
    );
    assert_eq!(
        store.entry(hash("bad")).unwrap().unwrap().first_seen,
        value["bad_first"].as_u64().unwrap()
    );
    assert_eq!(
        store.entry(hash("bad")).unwrap().unwrap().status,
        Status::Invalid
    );
    let policy = crate::eng2::body::tests::policy();
    let body = store.body(hash("body"), policy).unwrap().unwrap();
    assert_eq!(
        *blake3::hash(&body.encode(policy).unwrap()).as_bytes(),
        hash("raw")
    );
    println!(
        "sigkill_reopen=true; first_seen_preserved=true; raw_hash_preserved=true; invalid_mark_preserved=true; full_repair_allowed=false"
    );
}
