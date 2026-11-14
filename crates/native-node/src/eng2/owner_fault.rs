//! One-shot local rendezvous for an explicitly selected owner fault build.
//!
//! This module has no remote control interface and never sends a signal. A
//! retained external owner must kill the parked resident at the selected edge.
use super::genesis::Genesis;
use crate::wire::Hash;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const REQUEST: &str = "owner-fault-request.json";
const MAX_REQUEST_BYTES: usize = 8192;
const PARK_LIMIT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Point {
    RestoreBeforeCommit,
    RestoreAfterCommit,
    RestoreAfterPublish,
    RestoreAfterCapture,
    AppendBeforeCommit,
    AppendAfterCommit,
    AppendAfterPublish,
    AppendAfterCapture,
}
impl Point {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::RestoreBeforeCommit => "restore_before_commit",
            Self::RestoreAfterCommit => "restore_after_commit",
            Self::RestoreAfterPublish => "restore_after_publish",
            Self::RestoreAfterCapture => "restore_after_capture",
            Self::AppendBeforeCommit => "append_before_commit",
            Self::AppendAfterCommit => "append_after_commit",
            Self::AppendAfterPublish => "append_after_publish",
            Self::AppendAfterCapture => "append_after_capture",
        }
    }
    fn is_restore(self) -> bool {
        matches!(
            self,
            Self::RestoreBeforeCommit
                | Self::RestoreAfterCommit
                | Self::RestoreAfterPublish
                | Self::RestoreAfterCapture
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    run_id: String,
    network_id: String,
    genesis_id: String,
    rules_commitment: String,
    proof_profile: String,
    source_commit: String,
    binary_sha256: String,
    old_tip: String,
    candidate: String,
    ancestor_id: String,
    ancestor_height: u64,
    point: Point,
    height: u64,
    marker_name: String,
}

pub(crate) struct Switch {
    pub old_tip: Hash,
    pub candidate: Hash,
    pub ancestor_id: Hash,
    pub ancestor_height: u64,
    pub replacement_height: u64,
}
struct Armed {
    request: Request,
    request_sha256: String,
    marker: PathBuf,
}

/// Owned by one canonical Store, never a process-global hook shared with
/// bootstrap/replay stores. Startup and reorganization wiring are separate.
pub(crate) struct Controller {
    directory: PathBuf,
    parent: PathBuf,
    owner: u32,
    run: String,
    network: String,
    genesis: String,
    rules: String,
    profile: String,
    source: String,
    binary: String,
    consumed: bool,
    armed: Option<Armed>,
}

fn hex(text: &str, width: usize) -> bool {
    text.len() == width
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && text.bytes().any(|b| b != b'0')
}
fn marker_leaf(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text != "."
        && text != ".."
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn parse(bytes: &[u8]) -> Result<Request, String> {
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| "owner fault request schema rejected")?;
    if request.version != 1
        || [
            &request.run_id,
            &request.network_id,
            &request.genesis_id,
            &request.rules_commitment,
            &request.proof_profile,
            &request.binary_sha256,
            &request.old_tip,
            &request.candidate,
            &request.ancestor_id,
        ]
        .into_iter()
        .any(|s| !hex(s, 64))
        || !hex(&request.source_commit, 40)
        || !marker_leaf(&request.marker_name)
    {
        return Err("owner fault request identities rejected".into());
    }
    Ok(request)
}
fn private_directory(path: &Path, owner: Option<u32>) -> Result<u32, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "owner fault directory unavailable")?;
    if path.canonicalize().ok().as_deref() != Some(path)
        || !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.permissions().mode() & 0o077 != 0
        || owner.is_some_and(|uid| meta.uid() != uid)
    {
        return Err("owner fault directory must be canonical, private and same-owner".into());
    }
    Ok(meta.uid())
}
fn create(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "owner fault output must be absent")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "owner fault output durability failed")?;
    File::open(path.parent().ok_or("owner fault output parent missing")?)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| "owner fault parent durability failed".into())
}

impl Controller {
    /// Enabled only by an explicit environment selection in an owner build.
    /// The caller already holds the node's exclusive service lease.
    pub(crate) fn from_environment(
        directory: &Path,
        run: &str,
        genesis: &Genesis,
        binary: &str,
    ) -> Result<Option<Self>, String> {
        match std::env::var("SIWORLD_ENG2_OWNER_FAULT") {
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Ok(value) if value == "1" => (),
            _ => return Err("owner fault selection must be absent or exactly 1".into()),
        }
        if std::env::var_os("GITHUB_ACTIONS").is_some()
            || matches!(std::env::var("CI").as_deref(), Ok("true") | Ok("1"))
            || genesis.config().fixture
            || genesis.config().pow_iterations == 0
            || !hex(run, 64)
            || !hex(binary, 64)
        {
            return Err("owner fault selection requires an explicit nonfixture owner run".into());
        }
        let source = option_env!("SIWORLD_BUILD_COMMIT")
            .filter(|value| hex(value, 40))
            .ok_or("owner fault compiled source declaration required")?;
        if crate::local::hex(&super::genesis_tool::executable_sha256()?) != binary {
            return Err("owner fault executable SHA-256 differs".into());
        }
        let owner = private_directory(directory, None)?;
        let parent = directory
            .parent()
            .ok_or("owner fault sibling directory missing")?;
        private_directory(parent, Some(owner))?;
        Ok(Some(Self {
            directory: directory.into(),
            parent: parent.into(),
            owner,
            run: run.into(),
            network: crate::local::hex(&genesis.config().network),
            genesis: crate::local::hex(&genesis.id()),
            rules: crate::local::hex(&genesis.rules_commitment()),
            profile: crate::local::hex(&crate::proofs::protocol_profile_fingerprint()),
            source: source.into(),
            binary: binary.into(),
            consumed: false,
            armed: None,
        }))
    }

    /// Called after the complete selected branch passed ordinary native
    /// prevalidation and before any restore. Unrelated switches are unarmed.
    pub(crate) fn arm_switch(&mut self, switch: &Switch) -> Result<bool, String> {
        if self.consumed || self.armed.is_some() {
            return Ok(false);
        }
        let path = self.directory.join(REQUEST);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err("owner fault request path unavailable".into()),
            Ok(_) => (),
        }
        let file = crate::local::regular_read(&path, true, MAX_REQUEST_BYTES)?;
        let meta = file
            .metadata()
            .map_err(|_| "owner fault request metadata unavailable")?;
        if meta.uid() != self.owner || meta.nlink() != 1 {
            return Err("owner fault request must be same-owner and single-link".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_REQUEST_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "owner fault request read failed")?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err("owner fault request byte bound".into());
        }
        let request = parse(&bytes)?;
        if request.run_id != self.run
            || request.network_id != self.network
            || request.genesis_id != self.genesis
            || request.rules_commitment != self.rules
            || request.proof_profile != self.profile
            || request.source_commit != self.source
            || request.binary_sha256 != self.binary
        {
            return Err("owner fault request does not bind this actual run".into());
        }
        if request.old_tip != crate::local::hex(&switch.old_tip)
            || request.candidate != crate::local::hex(&switch.candidate)
            || request.ancestor_id != crate::local::hex(&switch.ancestor_id)
            || request.ancestor_height != switch.ancestor_height
        {
            return Ok(false);
        }
        let valid_height = if request.point.is_restore() {
            request.height == switch.ancestor_height
        } else {
            request.height > switch.ancestor_height && request.height <= switch.replacement_height
        };
        if !valid_height {
            return Err("owner fault boundary is outside the selected replacement".into());
        }
        private_directory(&self.directory, Some(self.owner))?;
        private_directory(&self.parent, Some(self.owner))?;
        let marker = self.parent.join(&request.marker_name);
        if marker
            .try_exists()
            .map_err(|_| "owner fault rendezvous path unavailable")?
            || marker.is_symlink()
        {
            return Err("owner fault rendezvous must be absent".into());
        }
        let request_sha256 = crate::local::hex(&Sha256::digest(&bytes));
        create(
            &self
                .directory
                .join(format!("owner-fault-{request_sha256}.claimed")),
            &serde_json::to_vec(&json!({"version":1,"run_id":self.run,
                "request_sha256":request_sha256,"process_id":std::process::id()}))
            .map_err(|_| "owner fault claim encoding failed")?,
        )?;
        self.consumed = true;
        self.armed = Some(Armed {
            request,
            request_sha256,
            marker,
        });
        Ok(true)
    }

    /// At a selected edge, durable rendezvous precedes parking. The caller's
    /// Store must already be unusable, so a missing external kill fails closed.
    pub(crate) fn boundary(&mut self, point: Point, height: u64) -> Result<(), String> {
        let Some(armed) = &self.armed else {
            return Ok(());
        };
        if armed.request.point != point || armed.request.height != height {
            return Ok(());
        }
        let bytes = serde_json::to_vec(
            &json!({"version":1,"scope":"owner-resident-commit-boundary",
            "run_id":self.run,"process_id":std::process::id(),"network_id":self.network,
            "genesis_id":self.genesis,"rules_commitment":self.rules,"proof_profile":self.profile,
            "source_commit":self.source,"source_commit_externally_verified":false,
            "binary_sha256":self.binary,"request_sha256":armed.request_sha256,
            "old_tip":armed.request.old_tip,"candidate":armed.request.candidate,
            "ancestor_id":armed.request.ancestor_id,"ancestor_height":armed.request.ancestor_height,
            "point":point.name(),"height":height,"external_kill_observed":false}),
        )
        .map_err(|_| "owner fault rendezvous encoding failed")?;
        create(&armed.marker, &bytes)?;
        let parked = Instant::now();
        while parked.elapsed() < PARK_LIMIT {
            std::thread::park_timeout(
                PARK_LIMIT
                    .saturating_sub(parked.elapsed())
                    .min(Duration::from_secs(1)),
            );
        }
        Err("owner fault rendezvous expired without an external kill".into())
    }

    /// Successful completion with an armed but unreached request is a failed
    /// fault case, never an invented crash or a successful injection receipt.
    pub(crate) fn complete_switch(&mut self) -> Result<(), String> {
        if self.armed.take().is_some() {
            return Err("owner fault selected boundary was not reached".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> serde_json::Value {
        json!({"version":1,"run_id":"01".repeat(32),"network_id":"02".repeat(32),
            "genesis_id":"03".repeat(32),"rules_commitment":"04".repeat(32),
            "proof_profile":"05".repeat(32),"source_commit":"06".repeat(20),
            "binary_sha256":"07".repeat(32),"old_tip":"08".repeat(32),
            "candidate":"09".repeat(32),"ancestor_id":"0a".repeat(32),
            "ancestor_height":1,"point":"restore_after_commit","height":1,
            "marker_name":"case-001.ready"})
    }
    #[test]
    fn fault_request_rejects_unknown_edges_private_fields_and_path_escape() {
        let original = request();
        assert!(parse(&serde_json::to_vec(&original).unwrap()).is_ok());
        for (field, value) in [
            ("point", json!("after_commit")),
            ("marker_name", json!("../escape")),
            ("height", json!(true)),
            ("source_commit", json!("00".repeat(20))),
            ("secret", json!("excluded")),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        for leaf in [".", "..", "/tmp/marker", "node/marker", ""] {
            assert!(!marker_leaf(leaf));
        }
    }
}
