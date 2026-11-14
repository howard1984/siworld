//! Run-bound local production policy for explicitly isolated native rehearsals.
//! Requests cannot alter validation, peer configuration, custody or chain data.
use super::{genesis::Genesis, resident, store::Store};
use crate::wire::Hash;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::path::Path;

mod io;
#[cfg(test)]
mod tests;

const DIRECTORY: &str = "isolated-production";
const MAX_BYTES: usize = 8192;
const MAX_HEIGHT: u64 = 1_000_000;
const MAX_REVISION: u64 = 1_000_000;
const PURPOSE: &str = "isolated-native-production";
const SELECTION: &str = "SIWORLD_ENG2_ISOLATED_PRODUCTION";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    purpose: String,
    campaign_sha256: String,
    network_id: String,
    genesis_id: String,
    rules_commitment: String,
    proof_profile: String,
    maximum_height: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    manifest_sha256: String,
    run_id: String,
    source_commit: String,
    binary_sha256: String,
    revision: u64,
    expected_height: u64,
    expected_tip: String,
    paused: bool,
    stop_height: u64,
}

fn hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn digest(bytes: &[u8]) -> String {
    crate::local::hex(&Sha256::digest(bytes))
}
fn owner_local() -> Result<(), String> {
    if std::env::var_os("GITHUB_ACTIONS").is_some()
        || matches!(std::env::var("CI").as_deref(), Ok("true") | Ok("1"))
    {
        return Err("isolated production requires owner-local execution".into());
    }
    Ok(())
}
fn eligible(config: &crate::state::Config) -> bool {
    !config.fixture
        && config.pow_iterations == 1
        && config.genesis_target == [0xff; 32]
        && config.work_bits == 0
        && config.target_interval == crate::state::TARGET_INTERVAL
        && config.economics == siworld_core::v1_economics::EconomicsParams::production()
}
fn manifest(bytes: &[u8], genesis: &Genesis) -> Result<Manifest, String> {
    let selected: Manifest = serde_json::from_slice(bytes)
        .map_err(|_| "isolated production manifest schema rejected")?;
    let config = genesis.config();
    if selected.version != 1
        || selected.purpose != PURPOSE
        || !hex(&selected.campaign_sha256, 64)
        || !eligible(config)
        || selected.network_id != crate::local::hex(&config.network)
        || selected.genesis_id != crate::local::hex(&genesis.id())
        || selected.rules_commitment != crate::local::hex(&genesis.rules_commitment())
        || selected.proof_profile
            != crate::local::hex(&crate::proofs::protocol_profile_fingerprint())
        || !(1..=MAX_HEIGHT).contains(&selected.maximum_height)
    {
        return Err("isolated production manifest or minimum-positive-work genesis differs".into());
    }
    Ok(selected)
}
fn request(bytes: &[u8]) -> Result<Request, String> {
    let selected: Request =
        serde_json::from_slice(bytes).map_err(|_| "isolated production request schema rejected")?;
    if selected.version != 1
        || [
            &selected.manifest_sha256,
            &selected.run_id,
            &selected.binary_sha256,
            &selected.expected_tip,
        ]
        .into_iter()
        .any(|value| !hex(value, 64))
        || !hex(&selected.source_commit, 40)
        || !(1..=MAX_REVISION).contains(&selected.revision)
        || selected.expected_height > MAX_HEIGHT
        || selected.stop_height > MAX_HEIGHT
        || (!selected.paused && selected.stop_height <= selected.expected_height)
    {
        return Err("isolated production request identities or height rejected".into());
    }
    Ok(selected)
}
fn name(kind: &str, run: &str, revision: u64) -> String {
    format!("{kind}-{run}-{revision:016}.json")
}

/// Create the durable policy only on an authenticated empty node, under its
/// exclusive service lease. Existing policies and records are never replaced.
pub fn initialize(directory: &Path, source: &Path, pin: &str) -> Result<Value, String> {
    owner_local()?;
    let bytes = io::input(source)?;
    if !hex(pin, 64) || digest(&bytes) != pin {
        return Err("isolated production independent manifest SHA-256 differs".into());
    }
    let _lease = crate::service::Lease::acquire(directory)?;
    let expected = resident::genesis_identifier(directory)?;
    let genesis = resident::load_genesis(directory, &expected)?;
    manifest(&bytes, &genesis)?;
    let store = Store::resume_existing(
        &directory.join("chain.redb"),
        genesis,
        resident::limits().chain,
    )?;
    if store.engine().state().height() != 0 {
        return Err("isolated production initialization requires authenticated empty state".into());
    }
    let files = io::Files::initialize(directory)?;
    files.create("manifest.json", &bytes)?;
    Ok(
        json!({"version":1,"manifest_sha256":pin,"initial_policy":"paused",
        "chain_modified":false,"identity_created":false}),
    )
}

/// Atomically install one immutable, independently pinned request. A successful
/// installation is not runtime acknowledgement; the matching result is required.
pub fn submit(directory: &Path, source: &Path, pin: &str) -> Result<Value, String> {
    owner_local()?;
    let bytes = io::input(source)?;
    if !hex(pin, 64) || digest(&bytes) != pin {
        return Err("isolated production independent request SHA-256 differs".into());
    }
    let selected = request(&bytes)?;
    let files = io::Files::open(directory)?;
    let manifest_bytes = files.required("manifest.json")?;
    if digest(&manifest_bytes) != selected.manifest_sha256 {
        return Err("isolated production submitted manifest differs".into());
    }
    files.create(
        &name("request", &selected.run_id, selected.revision),
        &bytes,
    )?;
    Ok(
        json!({"version":1,"run_id":selected.run_id,"revision":selected.revision,
        "request_sha256":pin,"installed":true,"acknowledged":false}),
    )
}

pub(crate) struct Controller {
    files: io::Files,
    manifest: String,
    maximum: u64,
    run: String,
    source: String,
    binary: String,
    revision: u64,
    paused: bool,
    stop_height: u64,
    request_sha256: Option<String>,
    failed: bool,
}
impl Controller {
    /// Selection is an independent manifest digest. An initialized policy cannot
    /// be bypassed by dropping this selection. Every fresh run starts paused.
    pub(crate) fn from_environment(
        directory: &Path,
        run: &str,
        genesis: &Genesis,
        binary: &str,
    ) -> Result<Option<Self>, String> {
        let pin = match std::env::var(SELECTION) {
            Err(std::env::VarError::NotPresent) => {
                if io::Files::exists(directory)? {
                    return Err(
                        "initialized isolated production requires explicit selection".into(),
                    );
                }
                return Ok(None);
            }
            Ok(pin) if hex(&pin, 64) => pin,
            _ => return Err("isolated production selection must be a manifest SHA-256".into()),
        };
        owner_local()?;
        let source = option_env!("SIWORLD_BUILD_COMMIT")
            .filter(|value| hex(value, 40))
            .ok_or("isolated production compiled source declaration required")?;
        if !hex(run, 64)
            || !hex(binary, 64)
            || crate::local::hex(&super::genesis_tool::executable_sha256()?) != binary
        {
            return Err("isolated production actual run or executable differs".into());
        }
        let files = io::Files::open(directory)?;
        let bytes = files.required("manifest.json")?;
        if digest(&bytes) != pin {
            return Err("isolated production selected manifest differs".into());
        }
        let selected = manifest(&bytes, genesis)?;
        Ok(Some(Self {
            files,
            manifest: pin,
            maximum: selected.maximum_height,
            run: run.into(),
            source: source.into(),
            binary: binary.into(),
            revision: 0,
            paused: true,
            stop_height: 0,
            request_sha256: None,
            failed: false,
        }))
    }

    fn validate(&self, selected: &Request, height: u64, tip: &Hash) -> Result<(), String> {
        if selected.manifest_sha256 != self.manifest
            || selected.run_id != self.run
            || selected.source_commit != self.source
            || selected.binary_sha256 != self.binary
            || selected.revision
                != self
                    .revision
                    .checked_add(1)
                    .ok_or("isolated revision exhausted")?
            || selected.expected_height != height
            || selected.expected_tip != crate::local::hex(tip)
            || selected.stop_height > self.maximum
        {
            return Err("isolated production request context is stale or different".into());
        }
        Ok(())
    }
    /// The caller holds the canonical owner. Processing and acknowledging a new
    /// revision precede every possible local acceptance under that same lock.
    fn poll(&mut self, height: u64, tip: &Hash) -> Result<(bool, u64), String> {
        if digest(&self.files.required("manifest.json")?) != self.manifest {
            return Err("isolated production durable manifest changed".into());
        }
        if let Some(hash) = &self.request_sha256
            && digest(
                &self
                    .files
                    .required(&name("request", &self.run, self.revision))?,
            ) != *hash
        {
            return Err("isolated production applied request changed".into());
        }
        if self.revision < MAX_REVISION {
            let next = self.revision + 1;
            if let Some(bytes) = self.files.read(&name("request", &self.run, next))? {
                let hash = digest(&bytes);
                let selected = request(&bytes).and_then(|selected| {
                    self.validate(&selected, height, tip)?;
                    Ok(selected)
                });
                let selected = match selected {
                    Ok(selected) => selected,
                    Err(error) => {
                        self.files.create(
                            &name("result", &self.run, next),
                            &serde_json::to_vec(&json!({"version":1,"run_id":self.run,
                                "manifest_sha256":self.manifest,"source_commit":self.source,
                                "binary_sha256":self.binary,"revision":next,"request_sha256":hash,
                                "height":height,"tip":crate::local::hex(tip),"status":"rejected",
                                "reason":"invalid_or_stale_request"}))
                            .map_err(|_| "isolated production result encoding failed")?,
                        )?;
                        return Err(error);
                    }
                };
                // Durable acknowledgement is installed before updating memory.
                // Any I/O error terminates this producer; there is no fallback.
                self.files.create(
                    &name("result", &self.run, next),
                    &serde_json::to_vec(&json!({"version":1,"run_id":self.run,
                        "manifest_sha256":self.manifest,"source_commit":self.source,
                        "binary_sha256":self.binary,"revision":next,"request_sha256":hash,
                        "height":height,"tip":crate::local::hex(tip),"paused":selected.paused,
                        "stop_height":selected.stop_height,"status":"applied"}))
                    .map_err(|_| "isolated production result encoding failed")?,
                )?;
                self.revision = next;
                self.paused = selected.paused;
                self.stop_height = selected.stop_height;
                self.request_sha256 = Some(hash);
            }
        }
        Ok((!self.paused && height < self.stop_height, self.revision))
    }
    pub(crate) fn permission(
        &mut self,
        height: u64,
        tip: &Hash,
        expected: Option<u64>,
    ) -> Result<(bool, u64), String> {
        if self.failed {
            return Err("isolated production control remains failed".into());
        }
        match self.poll(height, tip) {
            Ok((allowed, revision)) => Ok((
                allowed && expected.is_none_or(|value| value == revision),
                revision,
            )),
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
    pub(crate) fn status(&self, height: u64) -> Value {
        json!({"version":1,"run_id":self.run,"manifest_sha256":self.manifest,
            "revision":self.revision,"paused":self.paused,"stop_height":self.stop_height,
            "request_sha256":self.request_sha256,"failed":self.failed,
            "production_allowed":!self.failed && !self.paused && height < self.stop_height})
    }
}
