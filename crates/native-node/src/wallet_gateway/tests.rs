use super::*;
use crate::{
    fixtures::{TestVerifier, candidate},
    state::Config,
    store::Store,
};

fn directory(root: &Path, name: &str, mode: u32) -> PathBuf {
    let path = root.join(name);
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}
fn root() -> PathBuf {
    let mut seed = [0; 8];
    getrandom::fill(&mut seed).unwrap();
    let path = std::env::temp_dir().join(format!("swe-{}", crate::local::hex(&seed)));
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}
fn private_file(path: &Path) {
    let metadata = std::fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
}

fn append_blocks(node: &mut Node<TestVerifier>, count: u32, seed: u32) {
    for at in 0..count {
        let block = candidate(node.state(), seed + at * 100_000);
        node.import_branch(
            node.state().height,
            &[block],
            crate::chain::CandidatePolicy::default(),
        )
        .unwrap();
    }
}

#[test]
fn cold_index_and_queued_public_reads_share_one_bounded_owner_turn() {
    let root = root();
    let config = Config::development([25; 32], 0).unwrap();
    let store = Store::open(root.join("chain.redb"), config, &TestVerifier).unwrap();
    let mut node = Node::new(store, TestVerifier);
    append_blocks(&mut node, 3, 1500);
    let tip = node.state().tip;
    let mut gateway = Gateway::bind(&root.join("s")).unwrap();
    let (send, receive) = mpsc::sync_channel(1);
    gateway.rx = receive;
    for expected in 1..=3 {
        let (reply, response) = mpsc::sync_channel(1);
        send.send(Request {
            kind: 0,
            body: Vec::new(),
            reply,
        })
        .unwrap();
        gateway.poll(&mut node);
        assert_eq!(gateway.ids.len(), expected, "one new identity per turn");
        assert_eq!(gateway.indexed, expected, "one compact record per turn");
        assert!(response.try_recv().unwrap().is_err(), "warming reads wait");
    }
    let status: Value =
        serde_json::from_slice(&gateway.dispatch(&mut node, 0, b"").unwrap()).unwrap();
    assert_eq!(status["height"], 3);
    assert_eq!(status["tip"], crate::local::hex(&tip));
    // A read request must never generate a missing compact record on the owner.
    let missing = gateway
        .cache
        .join(format!("{}.bin", crate::local::hex(&tip)));
    std::fs::remove_file(&missing).unwrap();
    assert!(gateway.dispatch(&mut node, 2, &tip).is_err());
    assert!(!missing.exists());
    drop(gateway);
    drop(node);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cold_export_accepts_queued_submission_without_waiting_for_history() {
    use native::{
        codec::encode_digest,
        multi_asset::{F, Hasher},
    };
    use p3_field::PrimeCharacteristicRing;
    let root = root();
    let public = directory(&root, "public", 0o700);
    let config = Config::development([27; 32], 0).unwrap();
    let store = Store::open(root.join("chain.redb"), config, &TestVerifier).unwrap();
    let mut node = Node::new(store, TestVerifier);
    append_blocks(&mut node, 3, 1500);
    let mut gateway = Gateway::configured(None, Some(&root.join("s")), Some(&public))
        .unwrap()
        .unwrap();
    let mut transaction = candidate(node.state(), 400_000).transactions.remove(0);
    transaction.record.fee_commit =
        encode_digest(&Hasher::new().fee_commit(100, &[F::from_u32(22); 8]));
    let sidecar = crate::wire::Sidecar {
        transaction_id: transaction
            .record
            .statement_id(&node.state().config.network),
        fee: 100,
        blind: [22; 8],
    };
    let mut packet = transaction
        .encode_envelope(&node.state().config.network)
        .unwrap();
    packet.extend(sidecar.encode().unwrap());
    let (send, receive) = mpsc::sync_channel(1);
    gateway.rx = receive;
    let (reply, response) = mpsc::sync_channel(1);
    send.send(Request {
        kind: 3,
        body: packet,
        reply,
    })
    .unwrap();
    gateway.poll(&mut node);
    assert!(response.try_recv().unwrap().is_ok());
    assert_eq!(node.mempool().len(), 1);
    assert_eq!(
        gateway.ids.len(),
        1,
        "submission cannot trigger full backfill"
    );
    assert!(!public.join("chain.json").exists());
    drop(gateway);
    drop(node);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cold_partial_index_reanchors_before_following_a_changed_owner_head() {
    let root = root();
    let public = directory(&root, "public", 0o700);
    let config = Config::development([28; 32], 0).unwrap();
    let store = Store::open(root.join("chain.redb"), config.clone(), &TestVerifier).unwrap();
    let mut node = Node::new(store, TestVerifier);
    append_blocks(&mut node, 3, 1500);
    let mut gateway = Gateway::export_only(&public).unwrap();
    gateway.poll(&mut node);
    let old_first = gateway.ids[0];
    let fork = Store::open(root.join("fork.redb"), config, &TestVerifier).unwrap();
    let mut fork = Node::new(fork, TestVerifier);
    append_blocks(&mut fork, 2, 400_000);
    gateway.poll(&mut fork);
    assert_eq!(gateway.ids.len(), 1);
    assert_ne!(gateway.ids[0], old_first);
    assert_eq!(gateway.ids[0], fork.store().public_block_id(1).unwrap());
    assert_eq!(gateway.indexed, 1);
    assert!(!public.join("chain.json").exists());
    append_blocks(&mut fork, 1, 700_000);
    gateway.poll(&mut fork);
    assert_eq!(gateway.ids.len(), 2);
    assert!(!public.join("chain.json").exists());
    gateway.poll(&mut fork);
    let exported: Value =
        serde_json::from_slice(&std::fs::read(public.join("chain.json")).unwrap()).unwrap();
    assert_eq!(exported["height"], 3);
    assert_eq!(exported["tip"], crate::local::hex(&fork.state().tip));
    assert!(
        public
            .join(format!("{}.bin", crate::local::hex(&old_first)))
            .exists()
    );
    drop(gateway);
    drop(fork);
    drop(node);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cold_export_preserves_complete_head_until_backfill_then_handles_append_and_reorg() {
    let root = root();
    let public = directory(&root, "public", 0o700);
    let config = Config::development([26; 32], 0).unwrap();
    let store = Store::open(root.join("chain.redb"), config.clone(), &TestVerifier).unwrap();
    let mut node = Node::new(store, TestVerifier);
    let mut gateway = Gateway::export_only(&public).unwrap();
    gateway.poll(&mut node);
    let genesis_export = std::fs::read(public.join("chain.json")).unwrap();
    append_blocks(&mut node, 3, 1500);
    for expected in 1..=3 {
        gateway.export.as_mut().unwrap().allow_next();
        gateway.poll(&mut node);
        assert_eq!(gateway.ids.len(), expected);
        if expected < 3 {
            assert_eq!(
                std::fs::read(public.join("chain.json")).unwrap(),
                genesis_export
            );
        }
    }
    let before_reorg = std::fs::read(public.join("chain.json")).unwrap();
    let exported: Value = serde_json::from_slice(&before_reorg).unwrap();
    assert_eq!(exported["height"], 3);
    let old_ids = gateway.ids.clone();
    append_blocks(&mut node, 1, 500_000);
    gateway.export.as_mut().unwrap().allow_next();
    gateway.poll(&mut node);
    assert_eq!(gateway.ids.len(), 4);
    let before_reorg = std::fs::read(public.join("chain.json")).unwrap();

    // Independently verified histories exercise the gateway's owner-head boundary;
    // fork choice is tested separately and is not changed by gateway scheduling.
    let fork = Store::open(root.join("fork.redb"), config.clone(), &TestVerifier).unwrap();
    let mut fork = Node::new(fork, TestVerifier);
    append_blocks(&mut fork, 4, 600_000);
    for expected in 1..=4 {
        gateway.export.as_mut().unwrap().allow_next();
        gateway.poll(&mut fork);
        assert_eq!(gateway.ids.len(), expected);
        if expected < 4 {
            assert_eq!(
                std::fs::read(public.join("chain.json")).unwrap(),
                before_reorg
            );
        }
    }
    let fork_export = std::fs::read(public.join("chain.json")).unwrap();
    let exported: Value = serde_json::from_slice(&fork_export).unwrap();
    assert_eq!(exported["tip"], crate::local::hex(&fork.state().tip));
    for id in old_ids {
        assert!(
            public
                .join(format!("{}.bin", crate::local::hex(&id)))
                .exists()
        );
    }
    let shorter = Store::open(root.join("shorter.redb"), config, &TestVerifier).unwrap();
    let mut shorter = Node::new(shorter, TestVerifier);
    append_blocks(&mut shorter, 2, 1_100_000);
    for expected in 1..=2 {
        gateway.export.as_mut().unwrap().allow_next();
        gateway.poll(&mut shorter);
        assert_eq!(gateway.ids.len(), expected);
        if expected < 2 {
            assert_eq!(
                std::fs::read(public.join("chain.json")).unwrap(),
                fork_export
            );
        }
    }
    let exported: Value =
        serde_json::from_slice(&std::fs::read(public.join("chain.json")).unwrap()).unwrap();
    assert_eq!(exported["height"], 2);
    assert_eq!(exported["tip"], crate::local::hex(&shorter.state().tip));
    for id in exported["ids"].as_array().unwrap() {
        assert!(
            public
                .join(format!("{}.bin", id.as_str().unwrap()))
                .is_file()
        );
    }
    drop(gateway);
    drop(shorter);
    drop(fork);
    drop(node);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn export_defaults_off_and_invalid_configuration_does_not_stop_node() {
    assert!(Gateway::configured(None, None, None).unwrap().is_none());
    let root = root();
    let public = directory(&root, "public", 0o750);
    assert!(
        Gateway::configured(None, None, Some(&public))
            .unwrap()
            .is_none()
    );
    std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = root.join("link");
    std::os::unix::fs::symlink(&public, &link).unwrap();
    assert!(
        Gateway::configured(None, None, Some(&link))
            .unwrap()
            .is_none()
    );
    let socket = root.join("s");
    assert!(
        Gateway::configured(Some(&socket), None, Some(&public))
            .unwrap()
            .is_none()
    );
    assert!(!socket.exists());
    let export = Gateway::configured(None, None, Some(&public))
        .unwrap()
        .unwrap();
    assert!(export.socket.is_none());
    assert!(export.join.is_none());
    assert!(export.rx.try_recv().is_err());
    drop(export);
    assert_eq!(std::fs::read_dir(&public).unwrap().count(), 0);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn file_export_publishes_only_complete_public_snapshots_without_request_capability() {
    let root = root();
    let public = directory(&root, "public", 0o700);
    let config = Config::development([21; 32], 0).unwrap();
    let store = Store::open(root.join("chain.redb"), config, &TestVerifier).unwrap();
    let mut node = Node::new(store, TestVerifier);
    let mut gateway = Gateway::export_only(&public).unwrap();
    for kind in [0, 1, 2, 3, 4, 255] {
        assert!(gateway.dispatch(&mut node, kind, b"").is_err());
    }
    let a = candidate(node.state(), 1500);
    node.import_branch(
        0,
        std::slice::from_ref(&a),
        crate::chain::CandidatePolicy::default(),
    )
    .unwrap();
    let b = candidate(node.state(), 500000);
    node.import_branch(
        1,
        std::slice::from_ref(&b),
        crate::chain::CandidatePolicy::default(),
    )
    .unwrap();
    let accepted_tip = node.state().tip;
    gateway.poll(&mut node);
    assert!(
        !public.join("chain.json").exists(),
        "partial backfill must not publish a head"
    );
    gateway.poll(&mut node);
    let index: Value =
        serde_json::from_slice(&std::fs::read(public.join("chain.json")).unwrap()).unwrap();
    let mut keys: Vec<_> = index
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["genesis", "height", "ids", "network", "tip", "version"]
    );
    assert_eq!(index["height"], 2);
    assert_eq!(index["tip"], crate::local::hex(&accepted_tip));
    for id in index["ids"].as_array().unwrap() {
        let path = public.join(format!("{}.bin", id.as_str().unwrap()));
        let bytes = std::fs::read(&path).unwrap();
        let decoded = crate::compact::CompactBlock::decode(&bytes).unwrap();
        assert_eq!(id.as_str().unwrap(), crate::local::hex(&decoded.id));
        assert_eq!(
            bytes,
            node.store()
                .public_compact_block(decoded.block.height)
                .unwrap()
        );
        assert!(
            decoded
                .block
                .transactions
                .iter()
                .all(|transaction| transaction.proof.is_empty())
        );
        private_file(&path);
    }
    private_file(&public.join("chain.json"));
    assert_eq!(std::fs::read_dir(&public).unwrap().count(), 3);
    assert_eq!(node.state().tip, accepted_tip);
    assert_eq!(node.state().height, 2);
    assert_eq!(node.mempool().len(), 0);
    drop(gateway);
    drop(node);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_export_preserves_last_index_and_node_can_accept_another_block() {
    let root = root();
    let public = directory(&root, "public", 0o700);
    let config = Config::development([23; 32], 0).unwrap();
    let store = Store::open(root.join("chain.redb"), config, &TestVerifier).unwrap();
    let mut node = Node::new(store, TestVerifier);
    let mut gateway = Gateway::export_only(&public).unwrap();
    gateway.poll(&mut node);
    let before = std::fs::read(public.join("chain.json")).unwrap();
    let block = candidate(node.state(), 1500);
    node.import_branch(
        0,
        std::slice::from_ref(&block),
        crate::chain::CandidatePolicy::default(),
    )
    .unwrap();
    // A directory at the immutable file name deterministically makes export fail.
    let blocked = directory(
        &public,
        &format!("{}.bin", crate::local::hex(&block.id().unwrap())),
        0o700,
    );
    let tip = node.state().tip;
    gateway.poll(&mut node);
    assert_eq!(node.state().tip, tip);
    assert_eq!(node.mempool().len(), 0);
    assert_eq!(std::fs::read(public.join("chain.json")).unwrap(), before);
    assert!(gateway.retry_at > Instant::now());
    let log_at = gateway.log_at;
    gateway.poll(&mut node);
    assert_eq!(
        gateway.log_at, log_at,
        "failed export diagnostics are rate limited"
    );
    let next = candidate(node.state(), 500000);
    node.import_branch(
        1,
        std::slice::from_ref(&next),
        crate::chain::CandidatePolicy::default(),
    )
    .unwrap();
    assert_eq!(node.state().tip, next.id().unwrap());
    std::fs::remove_dir(blocked).unwrap();
    gateway.retry_at = Instant::now();
    gateway.export.as_mut().unwrap().allow_next();
    gateway.poll(&mut node);
    gateway.poll(&mut node);
    let after: Value =
        serde_json::from_slice(&std::fs::read(public.join("chain.json")).unwrap()).unwrap();
    assert_eq!(after["height"], 2);
    assert_eq!(after["tip"], crate::local::hex(&node.state().tip));
    private_file(&public.join("chain.json"));
    drop(gateway);
    drop(node);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn atomic_export_replaces_reorganized_index_without_deleting_fork_objects() {
    let root = root();
    let public = directory(&root, "public", 0o700);
    let config = Config::development([22; 32], 0).unwrap();
    let mut export = PublicExport::open(&public).unwrap();
    let old = [3; 32];
    let old_path = public.join(format!("{}.bin", crate::local::hex(&old)));
    std::fs::write(&old_path, b"public fixture").unwrap();
    std::fs::set_permissions(&old_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    export.publish(&config, &[old]).unwrap();
    let before = std::fs::read(public.join("chain.json")).unwrap();
    export.publish(&config, &[[4; 32]]).unwrap();
    assert_eq!(
        std::fs::read(public.join("chain.json")).unwrap(),
        before,
        "publish interval is bounded"
    );
    export.allow_next();
    export.publish(&config, &[[4; 32], [5; 32]]).unwrap();
    let index: Value =
        serde_json::from_slice(&std::fs::read(public.join("chain.json")).unwrap()).unwrap();
    assert_eq!(
        index["ids"],
        json!([crate::local::hex(&[4; 32]), crate::local::hex(&[5; 32])])
    );
    assert!(old_path.exists());
    private_file(&public.join("chain.json"));
    assert_eq!(
        std::fs::read_dir(&public).unwrap().count(),
        2,
        "no temporary snapshots remain"
    );
    std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(PublicExport::open(&public).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn submission_capability_coexists_with_export_without_read_or_admin_operations() {
    let root = root();
    let public = directory(&root, "public", 0o700);
    let config = Config::development([23; 32], 0).unwrap();
    let store = Store::open(root.join("chain.redb"), config, &TestVerifier).unwrap();
    let mut node = Node::new(store, TestVerifier);
    let mut gateway = Gateway::configured(None, Some(&root.join("submit")), Some(&public))
        .unwrap()
        .unwrap();
    for kind in [0, 1, 2, 4, 255] {
        assert!(
            gateway
                .dispatch(&mut node, kind, b"")
                .unwrap_err()
                .contains("Submission-only")
        );
    }
    gateway.poll(&mut node);
    assert!(public.join("chain.json").is_file());
    assert_eq!(
        std::fs::metadata(root.join("submit"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!root.join("compact-public").exists());
    drop(gateway);
    assert!(!root.join("submit").exists());
    drop(node);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn submission_uses_original_admission_and_exact_packet_retry() {
    use native::{
        codec::encode_digest,
        multi_asset::{F, Hasher},
    };
    use p3_field::PrimeCharacteristicRing;
    let root = root();
    let config = Config::development([24; 32], 0).unwrap();
    let store = Store::open(root.join("chain.redb"), config, &TestVerifier).unwrap();
    let mut node = Node::new(store, TestVerifier);
    let before = node.state().tip;
    let mut gateway = Gateway::configured(None, Some(&root.join("submit")), None)
        .unwrap()
        .unwrap();
    let mut tx = candidate(node.state(), 300).transactions.remove(0);
    tx.record.fee_commit = encode_digest(&Hasher::new().fee_commit(100, &[F::from_u32(22); 8]));
    let sidecar = crate::wire::Sidecar {
        transaction_id: tx.record.statement_id(&node.state().config.network),
        fee: 100,
        blind: [22; 8],
    };
    let mut packet = tx.encode_envelope(&node.state().config.network).unwrap();
    packet.extend(sidecar.encode().unwrap());
    let ack = gateway.dispatch(&mut node, 3, &packet).unwrap();
    assert_eq!(gateway.dispatch(&mut node, 3, &packet).unwrap(), ack);
    let value: Value = serde_json::from_slice(&ack).unwrap();
    assert_eq!(
        value,
        json!({"status":"pending", "statement_id": crate::local::hex(&sidecar.transaction_id)})
    );
    *packet.last_mut().unwrap() ^= 1;
    assert!(gateway.dispatch(&mut node, 3, &packet).is_err());
    assert!(gateway.dispatch(&mut node, 3, b"invalid").is_err());
    gateway.poll(&mut node);
    assert_eq!(node.state().tip, before);
    assert_eq!(gateway.indexed, 0);
    assert!(!root.join("compact-public").exists());
    drop(gateway);
    drop(node);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn submission_conflicts_fail_closed_and_export_failure_preserves_submission() {
    let root = root();
    let public = directory(&root, "public", 0o750);
    let socket = root.join("submit");
    assert!(Gateway::configured(Some(&root.join("reference")), Some(&socket), None).is_err());
    assert!(!socket.exists());
    let gateway = Gateway::configured(None, Some(&socket), Some(&public))
        .unwrap()
        .unwrap();
    assert!(gateway.socket.is_some());
    assert!(gateway.export.is_none());
    drop(gateway);
    std::fs::remove_dir_all(root).unwrap();
}
