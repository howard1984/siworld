//! Real-time isolated alarm exercise with ephemeral authorities and synthetic history.
//! It cannot read an existing node, connect to a peer, or qualify production pruning.
#[path = "fixtures.rs"]
mod history;
use crate::{
    checkpoint_service::{Coordinator, Exchange},
    engineering_checkpoint::{Certificate, Roster},
    identity::{NativeIdentity, checkpoint_authority::Authority},
    local,
    p2p::Binding,
    runtime::Node,
    state::Config,
    storage_policy::{CheckpointPruning, Role},
    store::Store,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn wall() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| "wall_clock_before_epoch".into())
}
fn save(directory: &Path, value: &Value) -> Result<(), String> {
    let temporary = directory.join("receipt.pending");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| "receipt_create_failed")?;
    file.write_all(value.to_string().as_bytes())
        .map_err(|_| "receipt_write_failed")?;
    file.sync_all().map_err(|_| "receipt_sync_failed")?;
    fs::rename(temporary, directory.join("runtime-receipt.json"))
        .map_err(|_| "receipt_publish_failed".into())
}
fn inventory(node: &Node<history::TestVerifier>) -> Result<String, String> {
    let mut hash = blake3::Hasher::new();
    for height in 1..=96 {
        hash.update(&node.store().block(height)?.encode()?);
    }
    Ok(hash.finalize().to_hex().to_string())
}
fn publish(
    node: &mut Node<history::TestVerifier>,
    coordinator: &mut Coordinator,
    roster: &Roster,
    keys: &[Authority],
    sequence: u64,
    now: u64,
) -> Result<Certificate, String> {
    let candidate = node.store().engineering_checkpoint_candidate(
        roster,
        72,
        sequence,
        now,
        &history::TestVerifier,
    )?;
    let certificate = Certificate {
        statement: candidate.statement().clone(),
        votes: vec![
            node.store()
                .sign_engineering_checkpoint(&keys[0], roster, &candidate)?,
            node.store()
                .sign_engineering_checkpoint(&keys[2], roster, &candidate)?,
        ],
    };
    certificate.authenticate(roster, None, now)?;
    let packet = Exchange {
        certificate: Some(certificate.clone()),
        ..Default::default()
    }
    .encode()?;
    coordinator.receive(node, [0; 32], &packet, now)?;
    let started = Instant::now();
    loop {
        coordinator.poll(node, wall()?)?;
        if node
            .store()
            .latest_engineering_checkpoint()?
            .is_some_and(|c| c.statement == certificate.statement)
        {
            break;
        }
        if started.elapsed() > Duration::from_secs(60) {
            return Err("isolated_certificate_acceptance_timeout".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(certificate)
}
fn exercise(directory: &Path, key_directory: &Path, receipt: &mut Value) -> Result<(), String> {
    let mut network = [0; 32];
    getrandom::fill(&mut network).map_err(|_| "fixture_entropy_failed")?;
    let config = Config::development(network, 0)?;
    if !config.fixture
        || crate::engineering_checkpoint::release_roster(Binding::new(&config))?.is_some()
    {
        return Err("isolated_nonrelease_fixture_required".into());
    }
    local::initialize_config(directory, config.clone())?;
    NativeIdentity::initialize(directory, Binding::new(&config))
        .map_err(|_| "fixture_identity_failed")?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(key_directory)
        .map_err(|_| "temporary_key_root_failed")?;
    let mut keys = Vec::new();
    for index in 0..3 {
        let path = key_directory.join(index.to_string());
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| "temporary_key_directory_failed")?;
        keys.push(
            Authority::initialize(&path, Binding::new(&config))
                .map_err(|_| "temporary_authority_failed")?,
        );
    }
    let roster = Roster::with_transition(
        Binding::new(&config),
        [keys[0].public_key(), keys[1].public_key()],
        keys[2].public_key(),
        1,
    )?;
    let mut store = Store::open(
        directory.join("chain.redb"),
        config.clone(),
        &history::TestVerifier,
    )?;
    for index in 0..96 {
        store.append(
            &history::candidate(store.state(), 100_000 + index * 100_000),
            &history::TestVerifier,
        )?;
    }
    store.configure_storage(Role::Validator)?;
    store.configure_checkpoint_pruning(CheckpointPruning::shortened_for_acceptance(1200)?);
    let mut node = Node::new(store, history::TestVerifier);
    let mut coordinator = Coordinator::isolated_stale_runtime(&config, roster.clone())?;
    let certificate = publish(&mut node, &mut coordinator, &roster, &keys, 1, wall()?)?;
    let started = Instant::now();
    let issued = certificate.statement.issued_unix_seconds;
    let proof_inventory = inventory(&node)?;
    let now = wall()?;
    let fresh = node.isolated_stale_storage_probe(&roster, now, true)?;
    if fresh["pruning_paused"] != false
        || fresh["deleted_proof_blocks"] != 0
        || coordinator.metrics(now)["pruning_paused"] != false
    {
        return Err("fresh_gate_failed".into());
    }
    receipt["status"] = json!("pending_real_1200_seconds");
    receipt["isolation"] = json!({"fixture_network":local::hex(&network),"roster_digest":local::hex(&roster.digest()),
        "authority_count":3,"quorum":2,"signers":[0,2],"production_roster":false,"peer_connections":0,"inbound_listener":false});
    receipt["fresh"] = json!({"observed_unix_seconds":now,"certificate_issued_unix_seconds":issued,
        "certificate_sequence":1,"signature_count":certificate.votes.len(),"coordinator":coordinator.metrics(now),"storage":fresh});
    save(directory, receipt)?;
    println!(
        "{}",
        json!({"status":"real_timer_started","pid":std::process::id(),"issued_unix_seconds":issued})
    );
    loop {
        let now = wall()?;
        let elapsed = started.elapsed().as_secs();
        if elapsed.abs_diff(now.saturating_sub(issued)) > 5 {
            return Err("wall_monotonic_disagreement".into());
        }
        coordinator.poll(&mut node, now)?;
        node.observe_storage_finality(now)?;
        if elapsed >= 1201 && now.checked_sub(issued).is_some_and(|age| age >= 1201) {
            break;
        }
        if elapsed > 1800 {
            return Err("real_runtime_deadline".into());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let now = wall()?;
    let stale = node.isolated_stale_storage_probe(&roster, now, false)?;
    let metrics = coordinator.metrics(now);
    if stale["pruning_paused"] != true
        || stale["reason"] != "checkpoint_stale"
        || stale["deleted_proof_blocks"] != 0
        || metrics["alert"] != "checkpoint_stale"
        || metrics["pruning_paused"] != true
        || inventory(&node)? != proof_inventory
    {
        return Err("stale_pause_or_proof_preservation_failed".into());
    }
    let before_height = node.state().height;
    let block = history::candidate(node.state(), 20_000_000);
    node.import_branch(before_height, &[block], Default::default())
        .map_err(|_| "validation_during_pause_failed")?;
    receipt["stale"] = json!({"observed_unix_seconds":now,"elapsed_monotonic_seconds":started.elapsed().as_secs(),
        "coordinator":metrics,"storage":stale,"protected_proof_inventory_unchanged":true,
        "height_before_validation":before_height,"height_after_validation":node.state().height});
    save(directory, receipt)?;
    let resumed = publish(&mut node, &mut coordinator, &roster, &keys, 2, wall()?)?;
    let now = wall()?;
    let resume = node.isolated_stale_storage_probe(&roster, now, false)?;
    let metrics = coordinator.metrics(now);
    if resume["pruning_paused"] != false
        || resume["deleted_proof_blocks"] != 0
        || metrics["pruning_paused"] != false
        || !metrics["alert"].is_null()
        || inventory(&node)? != proof_inventory
    {
        return Err("resume_or_proof_preservation_failed".into());
    }
    receipt["resume"] = json!({"observed_unix_seconds":now,"elapsed_monotonic_seconds":started.elapsed().as_secs(),
        "certificate_issued_unix_seconds":resumed.statement.issued_unix_seconds,"certificate_sequence":2,
        "signature_count":resumed.votes.len(),"coordinator":metrics,"storage":resume,"protected_proof_inventory_unchanged":true});
    receipt["status"] = json!("state_cycle_passed");
    Ok(())
}
/// The sole argument must not exist. All authority and node material is newly
/// generated below it; no existing chain, credentials or network input is read.
pub fn run(directory: &Path) -> Result<Value, String> {
    if fs::symlink_metadata(directory).is_ok() {
        return Err("absent_isolated_directory_required".into());
    }
    let key_directory = directory.join("temporary-checkpoint-keys");
    let mut receipt = json!({"schema":1,"pid":std::process::id(),"status":"initializing",
        "history":"synthetic_canonical_fixture","proof_verifier":"synthetic_fixture_only",
        "clock":"actual_wall_and_monotonic","checkpoint_max_age_seconds":1200,
        "service_retention_seconds":86400,"production_max_age_seconds":64800,
        "production_publication_seconds":21600,"acceptance_scope":"state_cycle_only",
        "proof_deletion_acceptance":"pending_real_24h_eligible_backlog","production_pruning_qualified":false});
    let result = exercise(directory, &key_directory, &mut receipt);
    let removed = match fs::remove_dir_all(&key_directory) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    };
    let identity = directory.join("native-peer-identity.secret");
    let identity_removed = match fs::remove_file(identity) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    };
    receipt["temporary_checkpoint_keys_deleted"] = json!(removed);
    receipt["temporary_node_key_deleted"] = json!(identity_removed);
    if let Err(error) = &result {
        receipt["status"] = json!("failed");
        receipt["error"] = json!(error);
    }
    if directory.is_dir() {
        save(directory, &receipt)?;
    }
    result?;
    if !removed || !identity_removed {
        return Err("temporary_key_cleanup_failed".into());
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn existing_directory_is_rejected_before_any_contents_are_read() {
        let path =
            std::env::temp_dir().join(format!("siworld-isolated-runtime-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        let marker = path.join("untouched-marker");
        fs::write(&marker, b"preserve").unwrap();
        assert_eq!(
            run(&path).unwrap_err(),
            "absent_isolated_directory_required"
        );
        assert_eq!(fs::read(&marker).unwrap(), b"preserve");
        assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn isolated_coordinator_refuses_a_nonfixture_configuration() {
        let mut config = Config::development([19; 32], 0).unwrap();
        let roster =
            Roster::with_transition(Binding::new(&config), [[1; 1952], [2; 1952]], [3; 1952], 1)
                .unwrap();
        config.fixture = false;
        assert!(Coordinator::isolated_stale_runtime(&config, roster).is_err());
    }
}
