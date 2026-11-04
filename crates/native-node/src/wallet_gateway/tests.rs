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
