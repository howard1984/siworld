//! Explicit isolated acceptance on the resident owner and authenticated P2P.
//! Ordinary maintenance records finality but never drains the probe backlog.
use super::*;
use crate::{
    checkpoint_service::Coordinator,
    runtime::Node,
    state::BlockVerifier,
    storage_policy::{Role, SERVICE_RETENTION_SECONDS},
};
use std::os::unix::fs::MetadataExt;

const MANIFEST: &str = "checkpoint-stale-acceptance.json";
const RECEIPT: &str = "checkpoint-stale-acceptance-receipt.json";
const AGE_SECONDS: u64 = 1_200;
const ENV: &str = "SIWORLD_CHECKPOINT_STALE_ACCEPTANCE";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Fresh,
    Stale,
    Resume,
    Complete,
    Failed,
}
impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Resume => "resume",
            Self::Complete => "complete",
            Self::Failed => "failed",
        }
    }
    fn next(self) -> Self {
        match self {
            Self::Fresh => Self::Stale,
            Self::Stale => Self::Resume,
            Self::Resume => Self::Complete,
            other => other,
        }
    }
}
fn owned_regular(path: &Path) -> Result<(u64, u64), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "acceptance_public_file_unavailable")?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || !private(&metadata)
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.len() > MAX_JSON_BYTES
    {
        return Err("owned_private_single_link_public_file_required".into());
    }
    Ok((metadata.dev(), metadata.ino()))
}
fn bound_manifest(path: &Path, digest: &str) -> Result<(Value, (u64, u64)), String> {
    let identity = owned_regular(path)?;
    let mut file = checked_file(path, false, MAX_JSON_BYTES)?;
    let meta = file
        .metadata()
        .map_err(|_| "acceptance_manifest_metadata_failed")?;
    if (meta.dev(), meta.ino()) != identity {
        return Err("acceptance_manifest_changed_while_opening".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_JSON_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "acceptance_manifest_read_failed")?;
    if bytes.len() as u64 > MAX_JSON_BYTES
        || !hash_text(digest)
        || local::hex(&Sha256::digest(&bytes)) != digest
        || owned_regular(path)? != identity
    {
        return Err("exact_immutable_acceptance_manifest_required".into());
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| "invalid_acceptance_manifest_json")?;
    Ok((value, identity))
}
fn request_name(phase: &str) -> String {
    format!("checkpoint-stale-probe-{phase}-request.json")
}
fn state_evidence(value: &Value) -> Value {
    json!({"height":value["height"],"tip":value["tip"],
        "state_fingerprint":value["state_fingerprint"],"cumulative_work":value["cumulative_work"],
        "local_reward_index_count":value["local_reward_index_count"]})
}
fn rows(value: &Value) -> Result<&Vec<Value>, String> {
    value["eligible_rows"]
        .as_array()
        .ok_or_else(|| "eligible_proof_evidence_required".into())
}
fn stale_ready(elapsed: u64, fresh_elapsed: u64, wall: u64, issued: u64) -> bool {
    elapsed
        .checked_sub(fresh_elapsed)
        .is_some_and(|age| age > AGE_SECONDS)
        && wall
            .checked_sub(issued)
            .is_some_and(|age| age > AGE_SECONDS)
}

pub(super) struct Acceptance {
    manifest_sha256: String,
    specimen_id: String,
    run_id: String,
    data_identity: (u64, u64),
    manifest_identity: (u64, u64),
    started: Instant,
    phase: Phase,
    fresh_elapsed: u64,
    fresh_issued: u64,
    fresh_sequence: u64,
    reserved: Value,
    fresh_state: Value,
    results: Vec<Value>,
    last_export: Option<Instant>,
}
impl Acceptance {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn load(
        directory: &Path,
        identity: &RunIdentity,
        store: &Store,
        listening: bool,
        mining: bool,
        peer_digest: &str,
        peer_fingerprint: Hash,
    ) -> Result<Option<Self>, String> {
        let digest = match std::env::var(ENV) {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => {
                if store.checkpoint_pruning().max_age_seconds()
                    != crate::engineering_checkpoint::MAX_AGE_SECONDS
                {
                    return Err(
                        "shortened_checkpoint_age_requires_isolated_acceptance_binding".into(),
                    );
                }
                return Ok(None);
            }
            Err(_) => return Err("invalid_acceptance_binding_encoding".into()),
        };
        check_directory(directory)?;
        let meta =
            fs::symlink_metadata(directory).map_err(|_| "acceptance_directory_unavailable")?;
        let manifest_path = directory.join(MANIFEST);
        let (value, manifest_identity) = bound_manifest(&manifest_path, &digest)?;
        if meta.uid() != rustix::process::geteuid().as_raw() {
            return Err("owned_acceptance_directory_required".into());
        }
        let binding = crate::p2p::Binding::new(&store.state().config);
        let valid = value.as_object().is_some_and(|object| object.len() == 14)
            && value["schema"] == 1
            && value["purpose"] == "isolated-real-certificate-stale-probes"
            && value["specimen_id"].as_str().is_some_and(hash_text)
            && value["network_id"] == local::hex(&binding.network)
            && value["genesis_id"] == local::hex(&binding.genesis)
            && value["verifier_id"] == local::hex(&binding.verifier)
            && value["binary_sha256"] == identity.binary_sha256
            && value["configuration_sha256"] == identity.configuration_sha256
            && value["peer_configuration_sha256"] == peer_digest
            && identity.peer_configuration_sha256.as_deref() == Some(peer_digest)
            && value["peer_fingerprint"] == local::hex(&peer_fingerprint)
            && value["directory_device"] == meta.dev()
            && value["directory_inode"] == meta.ino()
            && value["checkpoint_max_age_seconds"] == AGE_SECONDS
            && value["new_registered_specimen"] == true;
        if !valid
            || listening
            || mining
            || store.state().config.fixture
            || store.storage_role()? != Some(Role::Validator)
            || store.checkpoint_pruning().max_age_seconds() != AGE_SECONDS
            || std::env::var_os("SIWORLD_RECOVERY_TRANSPORT_IDENTITY_DIRECTORY").is_some()
            || std::env::var_os("SIWORLD_WALLET_GATEWAY_SOCKET").is_some()
        {
            return Err("isolated_nonmining_outbound_validator_binding_required".into());
        }
        match fs::symlink_metadata(directory.join("engineering-checkpoint-authority.secret")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err("acceptance_authority_material_forbidden".into()),
        }
        if fs::symlink_metadata(directory.join(RECEIPT)).is_ok()
            || ["fresh", "stale", "resume"]
                .iter()
                .any(|phase| fs::symlink_metadata(directory.join(request_name(phase))).is_ok())
        {
            return Err("acceptance_run_must_not_inherit_probe_state".into());
        }
        if store.storage_metrics()?["service_checkpoint_delivery_qualified"] == true {
            return Err("new_unqualified_acceptance_specimen_required".into());
        }
        Ok(Some(Self {
            manifest_sha256: digest,
            specimen_id: value["specimen_id"].as_str().expect("checked").to_owned(),
            run_id: identity.run_id.clone(),
            data_identity: (meta.dev(), meta.ino()),
            manifest_identity,
            started: Instant::now(),
            phase: Phase::Fresh,
            fresh_elapsed: 0,
            fresh_issued: 0,
            fresh_sequence: 0,
            reserved: Value::Null,
            fresh_state: Value::Null,
            results: Vec::new(),
            last_export: None,
        }))
    }
    fn active_binding(&self, directory: &Path) -> Result<(), String> {
        let meta =
            fs::symlink_metadata(directory).map_err(|_| "acceptance_directory_unavailable")?;
        if (meta.dev(), meta.ino()) != self.data_identity
            || bound_manifest(&directory.join(MANIFEST), &self.manifest_sha256)?.1
                != self.manifest_identity
        {
            return Err("acceptance_binding_changed_preserve_specimen".into());
        }
        match fs::symlink_metadata(directory.join("engineering-checkpoint-authority.secret")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            _ => Err("acceptance_authority_material_forbidden".into()),
        }
    }
    fn probe<V: BlockVerifier>(
        &mut self,
        node: &mut Node<V>,
        coordinator: &Coordinator,
        now: u64,
    ) -> Result<Value, String> {
        let elapsed = self.started.elapsed().as_secs();
        let before = node.store().stale_acceptance_rows(now, true)?;
        let metrics = coordinator.metrics(now);
        let certificate = node
            .store()
            .latest_engineering_checkpoint()?
            .ok_or("actual_certificate_required")?;
        let sequence = certificate.statement.sequence;
        let issued = certificate.statement.issued_unix_seconds;
        let positive = self.phase != Phase::Stale;
        match self.phase {
            Phase::Fresh => {
                if elapsed < SERVICE_RETENTION_SECONDS
                    || rows(&before)?.len() < 5
                    || metrics["pruning_paused"] != false
                    || !metrics["alert"].is_null()
                {
                    return Err("fresh_real_24h_eligible_backlog_and_certificate_required".into());
                }
                node.resident_checkpoint_qualify(now)?;
            }
            Phase::Stale => {
                if !stale_ready(elapsed, self.fresh_elapsed, now, self.fresh_issued)
                    || sequence != self.fresh_sequence
                    || metrics["pruning_paused"] != true
                    || metrics["alert"] != "checkpoint_stale"
                    || node.store().storage_metrics()?["expiry_state"] != "checkpoint_stale"
                    || before["height"].as_u64() <= self.fresh_state["height"].as_u64()
                    || !rows(&before)?.contains(&self.reserved)
                {
                    return Err(
                        "real_stale_age_new_validated_head_and_preserved_proof_required".into(),
                    );
                }
            }
            Phase::Resume => {
                if sequence <= self.fresh_sequence
                    || metrics["pruning_paused"] != false
                    || !metrics["alert"].is_null()
                    || !rows(&before)?.contains(&self.reserved)
                {
                    return Err("new_real_certificate_and_reserved_proof_required".into());
                }
            }
            _ => return Err("probe_sequence_complete_or_failed".into()),
        }
        let deleted = node.maintain_storage(now, true)?;
        let after = node.store().stale_acceptance_rows(now, true)?;
        if state_evidence(&before) != state_evidence(&after)
            || (positive && deleted == 0)
            || (!positive && deleted != 0)
            || (!positive && !rows(&after)?.contains(&self.reserved))
        {
            return Err("bounded_probe_or_permanent_state_invariant_failed".into());
        }
        if self.phase == Phase::Fresh {
            self.reserved = rows(&after)?
                .first()
                .cloned()
                .ok_or("fresh_probe_must_preserve_eligible_proof")?;
            self.fresh_state = state_evidence(&after);
            self.fresh_elapsed = elapsed;
            self.fresh_sequence = sequence;
            self.fresh_issued = issued;
        }
        Ok(
            json!({"phase":self.phase.name(),"outcome":"passed","before":before,"after":after,
            "deleted_proof_blocks":deleted,"permanent_state_unchanged":true,"reward_index_unchanged":true,
            "certificate_sha256":local::hex(&Sha256::digest(certificate.encode()?)),
            "certificate_sequence":sequence,"certificate_issued_unix_seconds":issued,
            "coordinator":metrics,"observed_unix_seconds":now,"elapsed_monotonic_seconds":elapsed}),
        )
    }
    /// Invalid requests fail acceptance while ordinary P2P verification continues.
    pub(super) fn poll<V: BlockVerifier>(
        &mut self,
        directory: &Path,
        node: &mut Node<V>,
        coordinator: Option<&Coordinator>,
        now: u64,
    ) {
        let mut export = self
            .last_export
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(30));
        let result = (|| -> Result<(), String> {
            self.active_binding(directory)?;
            if self.started.elapsed() > Duration::from_secs(40 * 60 * 60) {
                return Err("real_acceptance_deadline_preserve_specimen".into());
            }
            if !matches!(self.phase, Phase::Fresh | Phase::Stale | Phase::Resume) {
                return Ok(());
            }
            let path = directory.join(request_name(self.phase.name()));
            if fs::symlink_metadata(&path).is_err() {
                return Ok(());
            }
            owned_regular(&path)?;
            let request = read_json(&path)?;
            if !request.as_object().is_some_and(|object| object.len() == 4)
                || request["schema"] != 1
                || request["run_id"] != self.run_id
                || request["manifest_sha256"] != self.manifest_sha256
                || request["phase"] != self.phase.name()
            {
                return Err("run_bound_probe_request_rejected".into());
            }
            let result = self.probe(node, coordinator.ok_or("real_coordinator_required")?, now)?;
            self.results.push(result);
            self.phase = self.phase.next();
            export = true;
            Ok(())
        })();
        if let Err(error) = result
            && self.phase != Phase::Failed
        {
            self.results
                .push(json!({"phase":self.phase.name(),"outcome":"failed",
                "error":error,"preserve_specimen":true}));
            self.phase = Phase::Failed;
            export = true;
        }
        if export {
            let eligible = node.store().stale_acceptance_rows(now, false).ok();
            let receipt = json!({"schema":1,"run_id":self.run_id,"manifest_sha256":self.manifest_sha256,
                "specimen_id":self.specimen_id,"status":if self.phase==Phase::Complete {"passed"} else if self.phase==Phase::Failed {"failed"} else {"pending"},
                "next_probe":self.phase.name(),"elapsed_monotonic_seconds":self.started.elapsed().as_secs(),
                "observed_unix_seconds":now,"eligible_proof_evidence":eligible,"results":self.results,
                "service_retention_seconds":SERVICE_RETENTION_SECONDS,"checkpoint_max_age_seconds":AGE_SECONDS,
                "production_default_seconds":crate::engineering_checkpoint::MAX_AGE_SECONDS,
                "publication_interval_seconds":crate::engineering_checkpoint::INTERVAL_SECONDS,
                "clock_source":"actual_wall_and_monotonic","transport":"existing_authenticated_outbound_p2p",
                "mining":false,"inbound_listener":false,"authority_secret_loaded":false,
                "ordinary_maintenance_deletion_enabled":false,"cleanup_performed":false});
            if atomic_json(&directory.join(RECEIPT), &receipt).is_ok() {
                self.last_export = Some(Instant::now());
            }
        }
    }
}

/// A once-only request file cannot be overwritten to repeat a pruning probe.
pub fn request(directory: &Path, expected_run: &str, phase: &str) -> Result<(), String> {
    if !["fresh", "stale", "resume"].contains(&phase) || !hash_text(expected_run) {
        return Err("exact_probe_phase_and_run_required".into());
    }
    check_directory(directory)?;
    owned_regular(&directory.join(STATUS_FILE))?;
    owned_regular(&directory.join(RECEIPT))?;
    let status = exported_status(directory)?;
    let receipt = read_json(&directory.join(RECEIPT))?;
    let updated = status["updated_unix_ms"]
        .as_u64()
        .ok_or("fresh_service_status_required")?;
    let now = wall_ms()?;
    if active_run(&status)? != expected_run
        || status["phase"] != "networking"
        || updated > now
        || now.saturating_sub(updated) > 15_000
        || receipt["run_id"] != expected_run
        || receipt["status"] != "pending"
        || receipt["next_probe"] != phase
        || !receipt["manifest_sha256"].as_str().is_some_and(hash_text)
    {
        return Err("fresh_exact_isolated_probe_owner_required".into());
    }
    let value = json!({"schema":1,"run_id":expected_run,"phase":phase,
        "manifest_sha256":receipt["manifest_sha256"]});
    write_once(&directory.join(request_name(phase)), &value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_probe_requires_real_elapsed_and_issue_age() {
        assert!(!stale_ready(1_700, 500, 20_000, 10_000));
        assert!(!stale_ready(1_701, 500, 11_200, 10_000));
        assert!(!stale_ready(499, 500, 11_201, 10_000));
        assert!(!stale_ready(1_701, 500, 11_201, 12_000));
        assert!(stale_ready(1_701, 500, 11_201, 10_000));
    }
    #[test]
    fn probe_order_never_reopens_a_completed_or_failed_phase() {
        assert_eq!(Phase::Fresh.next().name(), "stale");
        assert_eq!(Phase::Stale.next().name(), "resume");
        assert_eq!(Phase::Resume.next().name(), "complete");
        assert_eq!(Phase::Complete.next().name(), "complete");
        assert_eq!(Phase::Failed.next().name(), "failed");
    }
    #[test]
    fn probe_request_requires_exact_live_phase_and_cannot_be_repeated() {
        let path = std::env::temp_dir().join(format!(
            "siworld-stale-probe-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        create_directory(&path).unwrap();
        let run = "a".repeat(64);
        let other = "b".repeat(64);
        let manifest = "c".repeat(64);
        atomic_json(
            &path.join(STATUS_FILE),
            &json!({"run_id":run,"phase":"networking",
            "updated_unix_ms":wall_ms().unwrap()}),
        )
        .unwrap();
        atomic_json(
            &path.join(RECEIPT),
            &json!({"run_id":run,"status":"pending",
            "next_probe":"fresh","manifest_sha256":manifest}),
        )
        .unwrap();
        assert!(request(&path, &other, "fresh").is_err());
        assert!(request(&path, &run, "stale").is_err());
        request(&path, &run, "fresh").unwrap();
        let before = fs::read(path.join(request_name("fresh"))).unwrap();
        assert!(request(&path, &run, "fresh").is_err());
        assert_eq!(fs::read(path.join(request_name("fresh"))).unwrap(), before);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn public_probe_inputs_reject_links_before_opening_contents() {
        let path = std::env::temp_dir().join(format!(
            "siworld-stale-input-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        create_directory(&path).unwrap();
        let original = path.join("public.json");
        write_once(&original, &json!({"schema":1})).unwrap();
        assert!(owned_regular(&original).is_ok());
        let hard = path.join("hard.json");
        fs::hard_link(&original, &hard).unwrap();
        assert!(owned_regular(&original).is_err());
        assert!(owned_regular(&hard).is_err());
        let symbolic = path.join("symbolic.json");
        std::os::unix::fs::symlink(&original, &symbolic).unwrap();
        assert!(owned_regular(&symbolic).is_err());
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn manifest_decode_is_bound_to_the_exact_hashed_file_bytes() {
        let path = std::env::temp_dir().join(format!(
            "siworld-stale-manifest-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        create_directory(&path).unwrap();
        let manifest = path.join(MANIFEST);
        let value = json!({"schema":1,"public_binding":"fixture"});
        write_once(&manifest, &value).unwrap();
        let digest = local::hex(&Sha256::digest(fs::read(&manifest).unwrap()));
        assert_eq!(bound_manifest(&manifest, &digest).unwrap().0, value);
        assert!(bound_manifest(&manifest, &"a".repeat(64)).is_err());
        atomic_json(&manifest, &json!({"schema":1,"public_binding":"changed"})).unwrap();
        assert!(bound_manifest(&manifest, &digest).is_err());
        fs::remove_dir_all(path).unwrap();
    }
}
