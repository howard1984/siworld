//! Finite offline checkpoint rejection acceptance on a stopped, nonauthority
//! engineering validator. Registration and artifact admission belong to the
//! invoking controller. This module never starts, repairs or advances a node.
use crate::{
    engineering_checkpoint::{Certificate, MAX_CERTIFICATE_BYTES, Roster, SIGNATURE_BYTES},
    local,
    p2p::Binding,
    proofs::NativeVerifier,
    service::{LEASE_FILE, STATUS_FILE},
    state::BlockVerifier,
    storage_policy::Role,
    store::Store,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const JSON_LIMIT: usize = 65_536;
const STABLE_METRICS: &[&str] = &[
    "role",
    "policy_active",
    "service_retention_seconds",
    "checkpoint_publication_interval_seconds",
    "local_proof_blocks",
    "node_storage_limit_bytes",
    "storage_budget_behavior",
    "storage_limit_scope",
    "proof_body_bytes",
    "canonical_proof_body_bytes",
    "protected_historical_proof_blocks",
    "protected_historical_proof_bytes",
    "detached_proof_body_bytes",
    "detached_record_bytes",
    "local_replay_base_height",
    "remote_checkpoint_bootstrap",
    "service_checkpoint_delivery_qualified",
    "latest_checkpoint_height",
    "latest_checkpoint_sequence",
    "last_checkpoint_publication_unix_seconds",
    "retained_proof_blocks",
    "pruned_proof_blocks",
    "history_proof_service",
];

fn sha(bytes: &[u8]) -> String {
    local::hex(&Sha256::digest(bytes))
}

#[derive(PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn identity(meta: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: meta.dev(),
        inode: meta.ino(),
        length: meta.len(),
        modified: (meta.mtime(), meta.mtime_nsec()),
        changed: (meta.ctime(), meta.ctime_nsec()),
    }
}

fn private_regular(path: &Path, max: usize) -> Result<fs::Metadata, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "required_file_unavailable")?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.nlink() != 1
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
        || meta.len() > max as u64
    {
        return Err("private_single_link_regular_file_required".into());
    }
    Ok(meta)
}

fn read_file(path: &Path, max: usize) -> Result<Vec<u8>, String> {
    let before = private_regular(path, max)?;
    let file = local::regular_read(path, true, max).map_err(|_| "checked_file_open_failed")?;
    let opened = file.metadata().map_err(|_| "opened_file_metadata_failed")?;
    if identity(&before) != identity(&opened) {
        return Err("input_changed_while_opening".into());
    }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "checked_file_read_failed")?;
    let after = private_regular(path, max)?;
    if identity(&before) != identity(&after) || bytes.len() as u64 != before.len() {
        return Err("input_changed_while_reading".into());
    }
    Ok(bytes)
}

fn read_json(path: &Path) -> Result<(Vec<u8>, Value), String> {
    let bytes = read_file(path, JSON_LIMIT)?;
    let value = serde_json::from_slice(&bytes).map_err(|_| "invalid_evidence_json")?;
    Ok((bytes, value))
}

fn acquire_existing_lease(directory: &Path) -> Result<fs::File, String> {
    let path = directory.join(LEASE_FILE);
    let before = private_regular(&path, JSON_LIMIT)?;
    // Unlike a resident service, acceptance may never create a missing lease.
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|_| "exclusive_existing_service_lease_unavailable")?;
    let opened = file.metadata().map_err(|_| "lease_metadata_unavailable")?;
    if identity(&before) != identity(&opened)
        || identity(&before) != identity(&private_regular(&path, JSON_LIMIT)?)
    {
        return Err("existing_lease_changed_while_opening".into());
    }
    file.try_lock()
        .map_err(|_| "exclusive_existing_service_lease_unavailable")?;
    if identity(&before) != identity(&private_regular(&path, JSON_LIMIT)?) {
        return Err("existing_lease_changed_while_locking".into());
    }
    Ok(file)
}

fn hex64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn require_no_authority(directory: &Path) -> Result<(), String> {
    // symlink_metadata rejects even a dangling authority link without reading it.
    match fs::symlink_metadata(directory.join("engineering-checkpoint-authority.secret")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("authority_material_forbidden".into()),
    }
}

fn preflight(directory: &Path, expected_run: &str) -> Result<Value, String> {
    if !hex64(expected_run)
        || !directory.is_absolute()
        || directory
            .canonicalize()
            .map_err(|_| "data_directory_unavailable")?
            != directory
    {
        return Err("canonical_directory_and_exact_run_required".into());
    }
    for path in [
        directory.to_path_buf(),
        directory.join("service-runs"),
        directory.join("service-runs").join(expected_run),
    ] {
        let meta = fs::symlink_metadata(path).map_err(|_| "run_directory_unavailable")?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o077 != 0
        {
            return Err("private_real_run_directory_required".into());
        }
    }
    require_no_authority(directory)?;
    private_regular(&directory.join(LEASE_FILE), JSON_LIMIT)?;
    private_regular(&directory.join("chain.redb"), usize::MAX)?;
    private_regular(&directory.join("native-peer-identity.secret"), JSON_LIMIT)?;
    let run_dir = directory.join("service-runs").join(expected_run);
    let (final_bytes, final_value) = read_json(&run_dir.join("final.json"))?;
    let (status_bytes, status) = read_json(&directory.join(STATUS_FILE))?;
    let (_, run) = read_json(&run_dir.join("run.json"))?;
    if final_bytes != status_bytes
        || final_value != status
        || final_value["run_id"] != expected_run
        || final_value["schema_version"] != 1
        || final_value["phase"] != "stopped"
        || final_value["state_available"] != true
        || final_value.get("error_code") != Some(&Value::Null)
        || final_value["pow_attempts"] != 0
        || final_value["storage_metrics"]["role"] != "validator"
    {
        return Err("exact_clean_nonmining_validator_final_required".into());
    }
    if run["schema_version"] != 1 {
        return Err("invalid_run_schema".into());
    }
    for name in [
        "run_id",
        "process_id",
        "network_id",
        "binary_sha256",
        "configuration_sha256",
        "peer_configuration_sha256",
        "started_unix_ms",
    ] {
        if run[name].is_null() || run[name] != final_value[name] {
            return Err("final_run_identity_mismatch".into());
        }
    }
    for name in [
        "network_id",
        "binary_sha256",
        "configuration_sha256",
        "peer_configuration_sha256",
        "tip",
        "state_fingerprint",
    ] {
        if !final_value[name].as_str().is_some_and(hex64) {
            return Err("invalid_final_digest".into());
        }
    }
    if !final_value["height"].as_u64().is_some_and(|h| h > 0)
        || !final_value["cumulative_work"].as_str().is_some_and(|s| {
            s.len() == 128
                && s.as_bytes()
                    .as_chunks::<64>()
                    .0
                    .iter()
                    .all(|c| std::str::from_utf8(c).is_ok_and(hex64))
        })
    {
        return Err("nonempty_final_canonical_head_required".into());
    }
    let config = read_file(&directory.join("engineering-network.bin"), JSON_LIMIT)?;
    let (peer_bytes, peers) = read_json(&directory.join("fixture-peers.json"))?;
    if final_value["configuration_sha256"] != sha(&config)
        || final_value["peer_configuration_sha256"] != sha(&peer_bytes)
        || peers["version"] != 1
        || peers["engineering"] != true
        || peers.get("listen") != Some(&Value::Null)
        || peers["mining"] != false
        || !peers["peers"].as_array().is_some_and(|p| !p.is_empty())
    {
        return Err("original_outbound_nonmining_configuration_required".into());
    }
    Ok(json!({"final":final_value,"final_sha256":sha(&final_bytes),
        "configuration_sha256":sha(&config),"peer_configuration_sha256":sha(&peer_bytes)}))
}

fn invariant(store: &Store) -> Result<Value, String> {
    if store
        .storage_role()
        .map_err(|_| "storage_role_unavailable")?
        != Some(Role::Validator)
    {
        return Err("validator_storage_role_required".into());
    }
    let metadata = store.rejection_acceptance_metadata()?;
    if metadata["local_reward_index_count"] != 0 {
        return Err("nonproducing_fixture_required".into());
    }
    let checked = store
        .verify_local_rewards()
        .map_err(|_| "reward_index_verification_failed")?;
    let current = store
        .latest_engineering_checkpoint()
        .map_err(|_| "accepted_certificate_unavailable")?
        .ok_or("actual_accepted_certificate_required")?;
    let metrics = store
        .storage_metrics()
        .map_err(|_| "storage_metrics_failed")?;
    let mut stable = serde_json::Map::new();
    for field in STABLE_METRICS {
        stable.insert(
            (*field).to_owned(),
            metrics.get(*field).ok_or("storage_metric_missing")?.clone(),
        );
    }
    let binding = Binding::new(&store.state().config);
    Ok(
        json!({"network_id":local::hex(&binding.network),"genesis_id":local::hex(&binding.genesis),
        "verifier_id":local::hex(&binding.verifier),"height":store.state().height,
        "tip":local::hex(&store.state().tip),"state_fingerprint":local::hex(&store.state().fingerprint()),
        "cumulative_work":local::hex(&store.state().cumulative_work.to_big_endian()),
        "accepted_certificate_sha256":sha(&current.encode().map_err(|_| "accepted_certificate_encoding_failed")?),
        "accepted_certificate_height":current.statement.height,
        "accepted_certificate_sequence":current.statement.sequence,
        "metadata":metadata,"storage":stable,"local_reward_receipts_checked":checked}),
    )
}

fn invariant_digest(value: &Value) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|b| sha(&b))
        .map_err(|_| "invariant_encoding_failed".into())
}

struct Case {
    name: &'static str,
    layer: &'static str,
    expected: &'static str,
    bytes: Vec<u8>,
    signature_preserving_sequence_advance: bool,
}

fn cases(current: &Certificate, old: &Certificate) -> Result<Vec<Case>, String> {
    let current_bytes = current
        .encode()
        .map_err(|_| "current_certificate_encoding_failed")?;
    let statement_len = current.statement.encode().len();
    let mut single = current_bytes[..2 + statement_len + 1 + 1 + SIGNATURE_BYTES].to_vec();
    single[2 + statement_len] = 1;
    let mut unknown = current.clone();
    unknown.votes[1].signer = u8::MAX;
    let mut state = current.clone();
    // A changed statement at the existing sequence is equivocation. Advance
    // only the untrusted claim to exercise signature checking after the cursor.
    state.statement.sequence = current
        .statement
        .sequence
        .checked_add(1)
        .ok_or("sequence_exhausted")?;
    state.statement.state_fingerprint[0] ^= 1;
    let mut fork = current.clone();
    fork.statement.sequence = state.statement.sequence;
    fork.statement.block_id[0] ^= 1;
    let encode = |c: &Certificate| c.encode().map_err(|_| "case_encoding_failed".to_owned());
    Ok(vec![
        Case {
            name: "one_signature",
            layer: "production_certificate_decoder",
            expected: "two checkpoint signatures required",
            bytes: single,
            signature_preserving_sequence_advance: false,
        },
        Case {
            name: "unknown_signer",
            layer: "production_store_authentication",
            expected: "both distinct pinned checkpoint signers required in canonical order",
            bytes: encode(&unknown)?,
            signature_preserving_sequence_advance: false,
        },
        Case {
            name: "state_digest_mismatch",
            layer: "production_store_signature_authentication",
            expected: "checkpoint signature invalid",
            bytes: encode(&state)?,
            signature_preserving_sequence_advance: true,
        },
        Case {
            name: "not_on_selected_most_work_chain",
            layer: "production_store_signature_authentication",
            expected: "checkpoint signature invalid",
            bytes: encode(&fork)?,
            signature_preserving_sequence_advance: true,
        },
        Case {
            name: "sequence_regression",
            layer: "production_store_persisted_cursor",
            expected: "checkpoint sequence rollback or equivocation",
            bytes: encode(old)?,
            signature_preserving_sequence_advance: false,
        },
    ])
}

fn exercise(
    store: &mut Store,
    current: &Certificate,
    old: &Certificate,
    roster: &Roster,
    now: u64,
    verifier: &impl BlockVerifier,
) -> Result<(Value, Vec<Value>), String> {
    current
        .authenticate(roster, None, now)
        .map_err(|_| "actual_current_quorum_invalid")?;
    old.authenticate(roster, None, now)
        .map_err(|_| "actual_old_quorum_invalid")?;
    if old.statement.sequence >= current.statement.sequence {
        return Err("genuine_older_sequence_required".into());
    }
    let accepted = store
        .latest_engineering_checkpoint()
        .map_err(|_| "actual_cursor_unavailable")?
        .ok_or("actual_cursor_missing")?;
    if accepted
        .encode()
        .map_err(|_| "actual_cursor_encoding_failed")?
        != current
            .encode()
            .map_err(|_| "current_certificate_encoding_failed")?
    {
        return Err("current_certificate_differs_from_actual_cursor".into());
    }
    let before = invariant(store)?;
    let before_digest = invariant_digest(&before)?;
    let mut results = Vec::new();
    for case in cases(current, old)? {
        let start = Instant::now();
        let rejection = match Certificate::decode(&case.bytes) {
            Err(error) if case.name == "one_signature" => error,
            Err(_) => return Err(format!("{}_unexpected_decode_rejection", case.name)),
            Ok(certificate) if case.name == "one_signature" => {
                let _ = certificate;
                return Err("one_signature_unexpected_decode_acceptance".into());
            }
            Ok(certificate) => {
                match store.accept_engineering_checkpoint(&certificate, roster, now, verifier) {
                    Err(error) => error,
                    Ok(()) => {
                        return Err(format!(
                            "{}_unexpected_acceptance_preserve_fixture",
                            case.name
                        ));
                    }
                }
            }
        };
        if rejection != case.expected {
            return Err(format!("{}_unexpected_rejection_layer", case.name));
        }
        let after = invariant(store)?;
        if after != before {
            return Err(format!(
                "{}_semantic_invariant_changed_preserve_fixture",
                case.name
            ));
        }
        results.push(json!({"case":case.name,"status":"rejected","verification_layer":case.layer,
            "input_origin":if case.name == "sequence_regression" {"unchanged_genuine_older_quorum"} else {"mutated_persisted_current_quorum"},
            "quorum_authenticated_input":case.name == "sequence_regression",
            "rejection_code":case.expected,"input_sha256":sha(&case.bytes),
            "elapsed_monotonic_ms":start.elapsed().as_millis(),
            "before_invariant_sha256":before_digest,"after_invariant_sha256":invariant_digest(&after)?,
            "retained_genuine_signature_bytes":true,
            "untrusted_claim_sequence_advanced":case.signature_preserving_sequence_advance,
            "authenticated_state_or_chain_mismatch_exercised":false,
            "actual_native_chain":true,"live_p2p_injection":false}));
    }
    Ok((before, results))
}

/// The caller must admit the exact registered disposable fixture and artifact
/// before invocation. All mutable Store access is finite and lease protected.
pub fn run(
    directory: &Path,
    expected_run: &str,
    current_file: &Path,
    old_file: &Path,
) -> Result<Value, String> {
    let start = Instant::now();
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "wall_clock_invalid")?
        .as_millis();
    let gate = preflight(directory, expected_run)?;
    let directory_identity =
        fs::symlink_metadata(directory).map_err(|_| "directory_metadata_failed")?;
    let lease_identity = private_regular(&directory.join(LEASE_FILE), JSON_LIMIT)?;
    let _lease = acquire_existing_lease(directory)?;
    if identity(&lease_identity)
        != identity(&private_regular(&directory.join(LEASE_FILE), JSON_LIMIT)?)
        || gate != preflight(directory, expected_run)?
    {
        return Err("admission_changed_during_lease_acquisition".into());
    }
    let current_bytes = read_file(current_file, MAX_CERTIFICATE_BYTES)?;
    let old_bytes = read_file(old_file, MAX_CERTIFICATE_BYTES)?;
    let current =
        Certificate::decode(&current_bytes).map_err(|_| "current_certificate_decode_failed")?;
    let old = Certificate::decode(&old_bytes).map_err(|_| "old_certificate_decode_failed")?;
    let config = local::load(directory).map_err(|_| "native_configuration_invalid")?;
    let binding = Binding::new(&config);
    if gate["final"]["network_id"] != local::hex(&binding.network) {
        return Err("final_network_binding_mismatch".into());
    }
    let roster = crate::engineering_checkpoint::release_roster(binding)
        .map_err(|_| "release_roster_invalid")?
        .ok_or("release_pinned_roster_required")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "wall_clock_invalid")?
        .as_secs();
    let verifier = NativeVerifier::new().map_err(|_| "native_verifier_unavailable")?;
    let mut store =
        Store::check_restart_existing(directory.join("chain.redb"), config.clone(), &verifier)
            .map_err(|_| "exact_restart_open_failed_no_repair_or_tail_advance")?;
    let initial = invariant(&store)?;
    for field in [
        "height",
        "tip",
        "state_fingerprint",
        "cumulative_work",
        "network_id",
    ] {
        if initial[field] != gate["final"][field] {
            return Err("actual_store_differs_from_exact_final".into());
        }
    }
    let (before, results) = exercise(&mut store, &current, &old, &roster, now, &verifier)?;
    drop(store);
    let reopened = Store::check_restart_existing(directory.join("chain.redb"), config, &verifier)
        .map_err(|_| "exact_reopen_failed_preserve_fixture")?;
    let after_reopen = invariant(&reopened)?;
    if before != after_reopen
        || gate != preflight(directory, expected_run)?
        || identity(&lease_identity)
            != identity(&private_regular(&directory.join(LEASE_FILE), JSON_LIMIT)?)
    {
        return Err("reopen_or_admission_invariant_changed_preserve_fixture".into());
    }
    let after_directory =
        fs::symlink_metadata(directory).map_err(|_| "directory_metadata_failed")?;
    if directory_identity.dev() != after_directory.dev()
        || directory_identity.ino() != after_directory.ino()
    {
        return Err("data_directory_replaced_preserve_fixture".into());
    }
    let executable = std::env::current_exe().map_err(|_| "executable_identity_unavailable")?;
    let executable_bytes = fs::read(executable).map_err(|_| "executable_digest_unavailable")?;
    let ended = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "wall_clock_invalid")?
        .as_millis();
    if ended < started {
        return Err("wall_clock_regressed".into());
    }
    Ok(
        json!({"schema":1,"status":"passed","validation_scope":"offline-native-store-rejection",
        "expected_final_run_id":expected_run,"final_sha256":gate["final_sha256"],
        "executable_sha256":sha(&executable_bytes),"started_unix_ms":started,"ended_unix_ms":ended,
        "elapsed_monotonic_ms":start.elapsed().as_millis(),"native_verifier_constructed":true,
        "authenticated_local_restart_checked":true,"proof_replay_checked":false,
        "proof_tail_replay_checked":false,"new_store_created":false,"tail_advanced":false,
        "repair_attempted":false,"primary_service_changed":false,"live_p2p_injection":false,
        "current_certificate_sha256":sha(&current_bytes),"old_certificate_sha256":sha(&old_bytes),
        "old_certificate_authenticated_without_cursor":true,"invariant":before,
        "before_invariant_sha256":invariant_digest(&before)?,
        "after_reopen_invariant_sha256":invariant_digest(&after_reopen)?,"cases":results,
        "deeper_authenticated_state_and_chain_mismatch_scope":"separate synthetic-chain production API tests",
        "cleanup_performed":false}),
    )
}

#[cfg(test)]
mod tests;
