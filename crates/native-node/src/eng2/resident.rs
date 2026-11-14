//! Explicit engineering resident lifecycle with no implicit network migration.
//! Startup loads an existing identity and authenticated committed state only.

use super::{
    driver::Driver, genesis::Genesis, snapshot::ImportLimits, state_components::Limits,
    store::Store,
};
use crate::proofs::NativeProver;
use crate::{identity::NativeIdentity, p2p, proofs::NativeVerifier, service, wire::Hash};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(any(unix, test))]
use std::fs;

mod block_events;
mod bootstrap;
mod config;
pub use bootstrap::bootstrap_signed;
#[cfg(unix)]
mod mailbox;
#[cfg(unix)]
mod operations;
#[cfg(unix)]
pub use operations::{result as operations_result, submit as submit_operations};
pub(crate) mod peers;
mod production;
#[cfg(unix)]
pub(crate) mod submission;
#[cfg(unix)]
pub use mailbox::CheckpointMailbox;
#[cfg(all(test, unix, feature = "eng2-rehearsal"))]
mod public_fixture;
#[cfg(test)]
mod tests;

const MAX_GENESIS_BYTES: usize = 1024 * 1024;
const MEMORY_BYTES: usize = 640 * 1024 * 1024;
const READY_FRESHNESS: Duration = Duration::from_secs(30);

pub fn limits() -> ImportLimits {
    ImportLimits {
        chain: Limits {
            max_leaves: 100_000_000,
            max_nullifiers: 100_000_000,
            max_component_bytes: 256 * 1024 * 1024,
        },
        max_snapshot_bytes: 1024 * 1024 * 1024,
    }
}
pub fn load_genesis(directory: &Path, expected: &str) -> Result<Genesis, String> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("independently checked lowercase genesis identifier required".into());
    }
    let mut bytes = Vec::new();
    crate::local::regular_read(&directory.join("genesis.bin"), true, MAX_GENESIS_BYTES)?
        .read_to_end(&mut bytes)
        .map_err(|_| "explicit genesis read failed")?;
    let genesis = Genesis::decode(&bytes)?;
    if crate::local::hex(&genesis.id()) != expected {
        return Err("explicit genesis differs from independently checked identifier".into());
    }
    Ok(genesis)
}
pub fn genesis_identifier(directory: &Path) -> Result<String, String> {
    let mut bytes = Vec::new();
    crate::local::regular_read(&directory.join("genesis.bin"), true, MAX_GENESIS_BYTES)?
        .read_to_end(&mut bytes)
        .map_err(|_| "explicit public genesis read failed")?;
    Ok(crate::local::hex(&Genesis::decode(&bytes)?.id()))
}
/// Explicit, write-once peer identity creation under an independently pinned
/// genesis. Normal store initialization and resident startup remain load-only.
pub fn initialize_identity(directory: &Path, expected: &str) -> Result<Value, String> {
    // Reject a mismatched public context before acquiring a writable lease.
    let genesis = load_genesis(directory, expected)?;
    let _lease = service::Lease::acquire(directory)?;
    let identity = NativeIdentity::initialize(directory, genesis.peer_binding())
        .map_err(|_| "explicit peer identity creation rejected; existing records preserved")?;
    identity_receipt(&identity)
}
pub fn initialize_store(directory: &Path, expected: &str) -> Result<Value, String> {
    let _lease = service::Lease::acquire(directory)?;
    let genesis = load_genesis(directory, expected)?;
    let identity = NativeIdentity::load(directory, &genesis.peer_binding())
        .map_err(|_| "existing versioned identity required; initialization is separate")?;
    let mut store = Store::create(&directory.join("chain.redb"), genesis, limits().chain)?;
    store.enable_authenticated_restart(identity)?;
    Ok(
        json!({"version":2,"genesis":expected,"height":0,"authenticated_restart":"enabled","identity_created":false}),
    )
}
pub fn qualify_restart(directory: &Path, expected: &str) -> Result<Value, String> {
    let _lease = service::Lease::acquire(directory)?;
    let genesis = load_genesis(directory, expected)?;
    let identity = NativeIdentity::load(directory, &genesis.peer_binding())
        .map_err(|_| "existing versioned identity required")?;
    let mut store = Store::audit_existing(
        &directory.join("chain.redb"),
        genesis,
        limits().chain,
        &NativeVerifier::new()?,
    )?;
    store.enable_authenticated_restart(identity)?;
    Ok(
        json!({"version":2,"genesis":expected,"height":store.engine().state().height(),"explicit_native_audit":"passed","authenticated_restart":"enabled","identity_created":false}),
    )
}
pub fn restart_check(directory: &Path, expected: &str) -> Result<Value, String> {
    let _lease = service::Lease::acquire(directory)?;
    let started = Instant::now();
    let store = Store::resume_existing(
        &directory.join("chain.redb"),
        load_genesis(directory, expected)?,
        limits().chain,
    )?;
    Ok(
        json!({"version":2,"genesis":expected,"height":store.engine().state().height(),"tip":crate::local::hex(&store.engine().state().tip()),"elapsed_ms":started.elapsed().as_millis().to_string(),"historical_proof_replay":false,"authenticated_restart":"passed"}),
    )
}
pub fn public_identity(directory: &Path, expected: &str) -> Result<Value, String> {
    let genesis = load_genesis(directory, expected)?;
    let identity = NativeIdentity::load(directory, &genesis.peer_binding())
        .map_err(|_| "existing versioned identity unavailable")?;
    identity_receipt(&identity)
}
fn identity_receipt(identity: &NativeIdentity) -> Result<Value, String> {
    let descriptor = identity
        .descriptor()
        .map_err(|_| "public identity descriptor unavailable")?;
    Ok(
        json!({"version":crate::identity::VERSION,"fingerprint":crate::local::hex(&descriptor.fingerprint()),"descriptor":crate::local::hex(&descriptor.encode())}),
    )
}
pub fn pin_peer(
    directory: &Path,
    file: &Path,
    fingerprint: &str,
    expected: &str,
) -> Result<(), String> {
    let _lease = service::Lease::acquire(directory)?;
    let genesis = load_genesis(directory, expected)?;
    let mut bytes = Vec::new();
    crate::local::regular_read(file, false, 32768)?
        .read_to_end(&mut bytes)
        .map_err(|_| "public descriptor read failed")?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid public descriptor file")?;
    if value.as_object().is_none_or(|v| v.len() != 3)
        || value["version"] != crate::identity::VERSION
        || value["fingerprint"] != fingerprint
    {
        return Err("public descriptor differs from independently checked fingerprint".into());
    }
    let descriptor = crate::identity::Descriptor::decode(
        &crate::eng2_operations::public_bytes(
            &value["descriptor"],
            crate::identity::DESCRIPTOR_BYTES,
        )?,
        &genesis.peer_binding(),
    )
    .map_err(|_| "public descriptor rejected")?;
    if crate::local::hex(&descriptor.fingerprint()) != fingerprint {
        return Err("public fingerprint differs".into());
    }
    crate::identity::PeerPin::from_trusted_descriptor(&descriptor, &genesis.peer_binding())
        .map_err(|_| "public pin rejected")?
        .persist(directory)
        .map_err(|_| "public pin persistence failed".into())
}
fn unix_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes epoch")?
        .as_millis()
        .try_into()
        .map_err(|_| "system clock exceeds range".into())
}
fn binary_hash() -> Result<String, String> {
    let path = std::env::current_exe().map_err(|_| "running binary unavailable")?;
    let mut file = crate::local::regular_read(&path, false, 256 * 1024 * 1024)?;
    let mut hasher = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let n = file
            .read(&mut bytes)
            .map_err(|_| "running binary hash read failed")?;
        if n == 0 {
            break;
        }
        hasher.update(&bytes[..n]);
    }
    Ok(crate::local::hex(&hasher.finalize()))
}
#[derive(Default)]
struct ProductionStatus {
    phase: &'static str,
    pow_attempts: u64,
    blocks: u64,
    last_pow: Option<Instant>,
    error: Option<&'static str>,
}
struct Shared {
    owner: Arc<Mutex<Driver>>,
    #[cfg(all(unix, feature = "eng2-rehearsal"))]
    isolated_production: Mutex<Option<super::isolated_production::Controller>>,
    block_events: Arc<block_events::Recorder>,
    cancel: p2p::Cancellation,
    network: Arc<peers::NetworkStatus>,
    production: Mutex<ProductionStatus>,
    checkpoint_observer: Mutex<super::checkpoint_observer::Observer>,
    legacy_checkpoint_peers: std::collections::BTreeSet<Hash>,
    budget: p2p::Budget,
    _pool_charge: p2p::Reservation,
    #[cfg(unix)]
    operations: Option<operations::Mailbox>,
    #[cfg(unix)]
    mailbox: Arc<CheckpointMailbox>,
}
struct CancelOnDrop(p2p::Cancellation);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
impl Shared {
    fn checkpoint_conflict(&self) -> Result<bool, String> {
        Ok(self
            .checkpoint_observer
            .lock()
            .map_err(|_| "checkpoint observer lock poisoned")?
            .conflicted())
    }
    fn mining_ready(&self) -> Result<bool, String> {
        let owner = self
            .owner
            .lock()
            .map_err(|_| "resident owner lock poisoned")?;
        let head = owner.head()?;
        Ok(owner.activities_allowed()
            && self.network.ready_at((head.height, head.id))?
            && !self.checkpoint_conflict()?)
    }
    fn phase(&self, phase: &'static str) -> Result<(), String> {
        self.production
            .lock()
            .map_err(|_| "resident status lock poisoned")?
            .phase = phase;
        Ok(())
    }
}
fn export_status(
    directory: &Path,
    run_id: &str,
    shared: &Shared,
    started: Instant,
    sequence: u64,
    mode: (bool, bool),
    export_state: (Option<&str>, Option<bool>, Option<&str>),
) -> Result<(), String> {
    let (checkpoint_error, wallet_export, checkpoint_tick_reason) = export_state;
    let (mining, listening) = mode;
    let owner = shared
        .owner
        .lock()
        .map_err(|_| "resident owner lock poisoned")?;
    let head = match owner.head() {
        Ok(head) => head,
        Err(_) => return export_unavailable_status(directory, run_id, started, sequence),
    };
    let production = shared
        .production
        .lock()
        .map_err(|_| "resident status lock poisoned")?;
    let connections = shared.network.snapshot()?;
    let observer = shared
        .checkpoint_observer
        .lock()
        .map_err(|_| "checkpoint observer lock poisoned")?;
    let conflict = observer.conflicted();
    let ready =
        owner.activities_allowed() && shared.network.ready_at((head.height, head.id))? && !conflict;
    let event = owner.last_reorganization();
    let mut status = json!({
        "schema_version":2,"run_id":run_id,"process_id":std::process::id(),"sequence":sequence,
        "phase":production.phase,"network_id":crate::local::hex(&head.network),"genesis_id":crate::local::hex(&head.genesis),
        "height":head.height,"tip":crate::local::hex(&head.id),"cumulative_work":head.work.to_string(),
        "state_available":true,"ready":ready,"sync_status":if !owner.activities_allowed() { owner.reorganization_status() } else if conflict {"checkpoint_current_quorum_conflict"} else if ready {"caught_up"} else {"waiting_for_current_peer_tip"},
        "connections":connections.connections,"last_completed_round_age_ms":connections.last_round_age_ms,
        "completed_rounds":connections.rounds,"inbound_listener":listening,"mining_enabled":mining,
        "pow_attempts":production.pow_attempts,"mined_blocks":production.blocks,
        "pow_progress_fresh":production.last_pow.is_some_and(|t|t.elapsed()<=READY_FRESHNESS),
        "padding_ready":owner.padding_count(),"padding_bytes":owner.padding_bytes(),
        "error_code":production.error,"updated_unix_ms":unix_ms()?,"elapsed_monotonic_ms":started.elapsed().as_millis().to_string(),
        "historical_proof_replay":false
    });
    status["checkpoint_error"] = json!(checkpoint_error);
    status["checkpoint_tick_reason"] = json!(checkpoint_tick_reason);
    status["checkpoint_archive_error"] = json!(owner.last_archive_error());
    status["reorganization_status"] = json!(owner.reorganization_status());
    status["reorganization_alarm"] = json!(owner.reorganization_alarm());
    status["reorganization_depth"] = json!(event.map(|event| event.depth));
    status["reorganization_ancestor_height"] = json!(event.map(|event| event.ancestor_height));
    status["template_generation"] = json!(owner.template_generation());
    status["wallet_export_enabled"] = json!(wallet_export.is_some());
    status["wallet_export_paused"] = json!(wallet_export);
    status["signed_bootstrap_available"] = json!(owner.bootstrap_available());
    status["checkpoint_observation_error"] = json!(
        observer
            .error()
            .map(super::checkpoint_observer::Error::code)
    );
    status["checkpoint_observed_height"] = json!(observer.observed_height());
    status["checkpoint_conflict"] = json!(conflict);
    #[cfg(all(unix, feature = "eng2-rehearsal"))]
    {
        status["isolated_production_control"] = shared
            .isolated_production
            .lock()
            .map_err(|_| "isolated production control lock poisoned")?
            .as_ref()
            .map(|control| control.status(head.height))
            .unwrap_or(Value::Null);
    }
    status["operations_error"] = json!(operations_error(shared));
    status["native_block_events"] = shared.block_events.diagnostic();
    let (enabled, dropped, error) = owner.accept_observation_diagnostic();
    status["native_accept_observation"] = json!({
        "enabled":enabled,"dropped_events":dropped,
        "error_code":error.map(super::accept_observation::DiagnosticError::code),
        "coverage_established":false,"scope":"ordinary-forward-admission",
    });
    service::atomic_json(&directory.join(service::STATUS_FILE), &status)
}

fn export_unavailable_status(
    directory: &Path,
    run_id: &str,
    started: Instant,
    sequence: u64,
) -> Result<(), String> {
    service::atomic_json(
        &directory.join(service::STATUS_FILE),
        &json!({
            "schema_version":2, "run_id":run_id, "process_id":std::process::id(), "sequence":sequence,
            "phase":"manual_recovery_required", "state_available":false, "ready":false,
            "sync_status":"canonical_state_unavailable", "height":null, "tip":null,
            "reorganization_status":"manual_recovery_required", "reorganization_alarm":"canonical_state_unavailable",
            "wallet_export_paused":true, "signed_bootstrap_available":false,
            "error_code":"canonical_state_unavailable", "updated_unix_ms":unix_ms()?,
            "elapsed_monotonic_ms":started.elapsed().as_millis().to_string(), "historical_proof_replay":false,
        }),
    )
}

#[cfg(unix)]
impl submission::Owner for Mutex<Driver> {
    fn submit(&self, packet: &[u8], deadline: &p2p::Deadline) -> Result<Hash, String> {
        loop {
            deadline
                .check()
                .map_err(|_| "local submission deadline elapsed")?;
            match self.try_lock() {
                Ok(mut owner) => {
                    deadline
                        .check()
                        .map_err(|_| "local submission deadline elapsed")?;
                    return owner.submit_local_transaction(packet, deadline);
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(_) => return Err("resident owner unavailable".into()),
            }
        }
    }
}

fn operations_error(shared: &Shared) -> Option<&'static str> {
    #[cfg(unix)]
    {
        shared.operations.as_ref().map_or(
            Some("local_operations_unavailable"),
            operations::Mailbox::error,
        )
    }
    #[cfg(not(unix))]
    {
        let _ = shared;
        Some("local_operations_unsupported")
    }
}

fn check_windows_configuration(
    windows: bool,
    role: p2p::Role,
    listening: bool,
    signing: bool,
) -> Result<(), String> {
    if windows && (role != p2p::Role::Miner || listening || signing) {
        return Err(
            "Windows resident requires an outbound-only miner without checkpoint signing".into(),
        );
    }
    Ok(())
}
fn check_windows_admission(windows: bool, imported: Option<u64>) -> Result<(), String> {
    if windows && !imported.is_some_and(|height| height > 0) {
        return Err(
            "Windows resident requires a durably imported and authenticated signed checkpoint"
                .into(),
        );
    }
    Ok(())
}

pub fn run(directory: &Path, configuration: &Path, expected: &str) -> Result<(), String> {
    if std::env::var_os("GITHUB_ACTIONS").is_some()
        || matches!(std::env::var("CI").as_deref(), Ok("true") | Ok("1"))
    {
        return Err("native resident execution requires an owner-operated environment".into());
    }
    if !cfg!(any(unix, windows)) {
        return Err(
            "versioned resident checkpoint transport is not available on this platform".into(),
        );
    }
    let _lease = service::Lease::acquire(directory)?;
    let genesis = Arc::new(load_genesis(directory, expected)?);
    let identity = Arc::new(
        NativeIdentity::load(directory, &genesis.peer_binding())
            .map_err(|_| "existing versioned identity unavailable; keys are never regenerated")?,
    );
    let config = config::Configuration::load(directory, configuration, &genesis, &identity)?;
    check_windows_configuration(
        cfg!(windows),
        config.role,
        config.listen.is_some(),
        config.checkpoint_key.is_some(),
    )?;
    let mining = config.mining;
    let listening = config.listen.is_some();
    #[cfg(unix)]
    let bootstrap_service = matches!(config.role, p2p::Role::Bootstrap | p2p::Role::Validator);
    if mining
        && (std::env::var("RAYON_NUM_THREADS").ok().as_deref() != Some("4")
            || std::env::var("SIWORLD_COMPOSITION_HIDING_WORKERS")
                .ok()
                .as_deref()
                != Some("2"))
    {
        return Err("native production requires RAYON_NUM_THREADS=4 and SIWORLD_COMPOSITION_HIDING_WORKERS=2".into());
    }
    let settings = mining
        .then(|| crate::mining::load(directory, genesis.config().network))
        .transpose()?;
    let store = Store::resume_existing(
        &directory.join("chain.redb"),
        Genesis::decode(&genesis.encode()?)?,
        limits().chain,
    )?;
    check_windows_admission(cfg!(windows), store.imported_checkpoint_height())?;
    let budget = p2p::Budget::new(MEMORY_BYTES);
    let mut driver = Driver::new(store, NativeVerifier::new()?, limits())?;
    let header_rules = super::selection::HeaderRules {
        network: genesis.config().network,
        genesis: genesis.id(),
        genesis_timestamp: genesis.config().genesis_timestamp,
        genesis_target: genesis.config().genesis_target,
        target_interval: genesis.config().target_interval,
        pow_iterations: genesis.config().pow_iterations,
        max_headers: 1_000_000,
    };
    let branch_limits = super::branches::Limits {
        maximum_headers: 1_100_000,
        maximum_body_bytes: 64 * 1024 * 1024 * 1024,
    };
    let branch_path = directory.join("branches.redb");
    let branches = if branch_path
        .try_exists()
        .map_err(|_| "branch archive path unavailable")?
    {
        super::branches::BranchStore::open(&branch_path, header_rules, branch_limits)?
    } else {
        super::branches::BranchStore::create(&branch_path, header_rules, branch_limits)?
    };
    driver.enable_reorganization_with_budget(branches, budget.clone())?;
    let running_binary = binary_hash()?;
    let run = service::RunIdentity::new(
        genesis.config().network,
        running_binary.clone(),
        config.digest.clone(),
        unix_ms()?,
    )?;
    #[cfg(all(unix, feature = "eng2-rehearsal"))]
    driver.configure_owner_fault(super::owner_fault::Controller::from_environment(
        directory,
        &run.run_id,
        &genesis,
        &running_binary,
    )?);
    #[cfg(all(unix, feature = "eng2-rehearsal"))]
    let isolated_production = super::isolated_production::Controller::from_environment(
        directory,
        &run.run_id,
        &genesis,
        &running_binary,
    )?;
    #[cfg(all(unix, feature = "eng2-rehearsal"))]
    if isolated_production.is_some() && !mining {
        return Err("isolated production selection requires a miner role".into());
    }
    #[cfg(not(all(unix, feature = "eng2-rehearsal")))]
    if std::env::var_os("SIWORLD_ENG2_ISOLATED_PRODUCTION").is_some()
        || !matches!(std::fs::symlink_metadata(directory.join("isolated-production")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return Err("isolated production control requires a supported rehearsal build".into());
    }
    let event_node = identity
        .descriptor()
        .ok()
        .map(|descriptor| descriptor.fingerprint());
    let block_events = Arc::new(block_events::Recorder::new(
        directory,
        genesis.config().network,
        genesis.id(),
        event_node,
        &run.run_id,
        &running_binary,
    ));
    driver.observe_commits(block_events.clone());
    // The same actual startup inputs initialize both diagnostic bindings.
    // An unavailable sink never changes resident admission or readiness.
    match super::accept_observation::RunIdentity::from_resident(
        genesis.config().network,
        genesis.id(),
        event_node,
        &run.run_id,
        &running_binary,
    ) {
        Some(binding) => {
            if !driver.attach_accept_observer(binding, block_events.clone()) {
                block_events.accept_binding_unavailable();
            }
        }
        None => block_events.accept_binding_unavailable(),
    }
    #[cfg(unix)]
    let operations = operations::Mailbox::open(
        directory,
        &run.run_id,
        genesis.config().network,
        genesis.id(),
    )
    .ok();
    let shared = Arc::new(Shared {
        owner: Arc::new(Mutex::new(driver)),
        #[cfg(all(unix, feature = "eng2-rehearsal"))]
        isolated_production: Mutex::new(isolated_production),
        block_events,
        cancel: p2p::Cancellation::default(),
        network: Arc::new(peers::NetworkStatus::new(
            config.peers.iter().map(|peer| peer.expected.fingerprint()),
        )),
        production: Mutex::new(ProductionStatus {
            phase: "starting",
            ..Default::default()
        }),
        checkpoint_observer: Mutex::new(super::checkpoint_observer::Observer::default()),
        legacy_checkpoint_peers: config.legacy_checkpoint_peers.clone(),
        budget: budget.clone(),
        _pool_charge: budget
            .reserve(2 * crate::pool::MAX_BYTES)
            .map_err(|_| "resident proof queue budget unavailable")?,
        #[cfg(unix)]
        operations,
        #[cfg(unix)]
        mailbox: Arc::new(CheckpointMailbox::new(budget.clone())),
    });
    let _cancel_on_return = CancelOnDrop(shared.cancel.clone());
    service::write_run_receipt(directory, &run)?;
    let started = Instant::now();
    #[cfg(unix)]
    let mut checkpoint_host = {
        let root = directory.join("eng2-public");
        if !root.exists() {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .map_err(|_| "dedicated eng2 export directory creation failed")?;
        }
        let owner = shared
            .owner
            .lock()
            .map_err(|_| "resident owner lock poisoned")?;
        let mut host = super::runtime_export::host::Host::open_resident(
            &root,
            owner.store(),
            limits(),
            config.checkpoint_key.as_deref(),
            &shared.budget,
        )?;
        if !owner.activities_allowed() {
            host.pause_reorganization_exports()?;
            shared.mailbox.publish(&[])?;
        }
        host
    };
    #[cfg(unix)]
    if std::env::var_os("SIWORLD_ENG2_WALLET_EXPORT").is_some_and(|value| value == "1") {
        let owner = shared
            .owner
            .lock()
            .map_err(|_| "resident owner lock poisoned")?;
        // Unavailable wallet exports remain visibly paused while the already
        // authorized checkpoint, peer and validation paths keep running.
        let _ = checkpoint_host.enable_wallet_export(
            owner.store(),
            super::runtime_export::WalletPolicy::default(),
            &shared.budget,
        );
        // Opening the publisher only restores private cursors and its lease;
        // publication waits for both the activity gate and a fresh peer round.
        if !owner.activities_allowed() {
            checkpoint_host.pause_reorganization_exports()?;
        }
    }
    #[cfg(not(unix))]
    if config.checkpoint_key.is_some() {
        return Err("checkpoint signing host is unavailable on this platform".into());
    }
    #[cfg(unix)]
    let submission = std::env::var_os("SIWORLD_ENG2_SUBMIT_SOCKET")
        .map(|path| {
            submission::Socket::bind(Path::new(&path), budget.clone(), shared.owner.clone())
        })
        .transpose()?;
    let network_shared = shared.clone();
    let network = std::thread::Builder::new()
        .name("eng2-network-owner".into())
        .spawn(move || peers::run(config, genesis, identity, network_shared))
        .map_err(|_| "resident network worker creation failed")?;
    let mut producer = match settings {
        Some(settings) => {
            let producer_shared = shared.clone();
            let directory = directory.to_owned();
            Some(
                std::thread::Builder::new()
                    .name("eng2-native-producer".into())
                    .spawn(move || production::run(&directory, settings, producer_shared))
                    .map_err(|_| "resident producer creation failed")?,
            )
        }
        None => None,
    };
    if !mining {
        shared.phase("networking")?;
    }
    let mut sequence = 0u64;
    let mut last_export = Instant::now() - Duration::from_secs(5);
    let mut last_checkpoint = Instant::now() - Duration::from_secs(1);
    #[cfg(unix)]
    let mut checkpoint_error = None;
    #[cfg(not(unix))]
    let checkpoint_error = None;
    #[cfg(unix)]
    let mut checkpoint_tick_reason = None;
    #[cfg(not(unix))]
    let checkpoint_tick_reason = None;
    #[cfg(not(unix))]
    let wallet_export = None;
    let result = (|| {
        while !shared.cancel.is_cancelled() {
            if service::stop_requested(directory, &run.run_id)? {
                break;
            }
            if network.is_finished() {
                return Err("resident network owner exited unexpectedly".into());
            }
            if producer.as_ref().is_some_and(|worker| worker.is_finished()) {
                return Err("resident producer exited unexpectedly".into());
            }
            {
                let mut owner = shared
                    .owner
                    .lock()
                    .map_err(|_| "resident owner lock poisoned")?;
                let _switch_result = owner.reorganization_tick(|ancestor_height| {
                    shared.network.invalidate_head_evidence()?;
                    #[cfg(unix)]
                    {
                        checkpoint_host.pause_reorganization_exports_at(ancestor_height)?;
                        shared.mailbox.publish(&[])?;
                    }
                    #[cfg(not(unix))]
                    let _ = ancestor_height;
                    Ok(())
                });
                if !owner.activities_allowed() {
                    #[cfg(unix)]
                    {
                        checkpoint_host.pause_reorganization_exports()?;
                        shared.mailbox.publish(&[])?;
                    }
                }
            }
            if last_checkpoint.elapsed() >= Duration::from_secs(1) {
                #[cfg(unix)]
                {
                    let mut owner = shared
                        .owner
                        .lock()
                        .map_err(|_| "resident owner lock poisoned")?;
                    if owner.activities_allowed() {
                        let restored = checkpoint_host
                            .reconcile_retained_async(owner.store(), || {
                                owner.capture_checkpoint_headers()
                            });
                        if !matches!(restored, Ok(true)) {
                            // Restoration failure pauses only advertisements and
                            // signing; canonical validation and peers keep running.
                            shared.mailbox.publish(&[])?;
                            checkpoint_error = Some("checkpoint_retained_restoration_unavailable");
                            checkpoint_tick_reason = Some("retained_restoration");
                        } else {
                            let incoming = shared.mailbox.drain()?;
                            let tick = {
                                let observer = shared
                                    .checkpoint_observer
                                    .lock()
                                    .map_err(|_| "checkpoint observer lock poisoned")?;
                                checkpoint_host.tick_resident(
                                    owner.store(),
                                    unix_ms()? / 1000,
                                    &incoming.messages,
                                    &shared.network,
                                    &observer,
                                )
                            };
                            match tick {
                                Ok(tick) => {
                                    shared.mailbox.acknowledge(&incoming)?;
                                    shared.mailbox.publish(&tick.messages())?;
                                    checkpoint_error = None;
                                    checkpoint_tick_reason = None;
                                    if bootstrap_service
                                        && owner
                                            .refresh_bootstrap(
                                                checkpoint_host.latest_checkpoint(),
                                                &shared.budget,
                                            )
                                            .is_err()
                                    {
                                        checkpoint_error = Some("signed_bootstrap_unavailable");
                                    }
                                }
                                Err(_) => {
                                    checkpoint_error =
                                        Some("checkpoint_tick_rejected_or_unavailable");
                                    checkpoint_tick_reason = checkpoint_host
                                        .tick_failure_reason()
                                        .map(super::runtime_export::host::TickFailureReason::code);
                                }
                            }
                            let head = owner.head()?;
                            if shared.network.ready_at((head.height, head.id))? {
                                let _ = checkpoint_host.tick_wallet_export(
                                    owner.store(),
                                    unix_ms()? / 1000,
                                    &shared.budget,
                                );
                            }
                        }
                    }
                }
                last_checkpoint = Instant::now();
            }
            if last_export.elapsed() >= Duration::from_secs(5) {
                sequence = sequence
                    .checked_add(1)
                    .ok_or("resident export sequence exhausted")?;
                export_status(
                    directory,
                    &run.run_id,
                    &shared,
                    started,
                    sequence,
                    (mining, listening),
                    (
                        checkpoint_error,
                        {
                            #[cfg(unix)]
                            {
                                checkpoint_host.wallet_export_state()
                            }
                            #[cfg(not(unix))]
                            {
                                wallet_export
                            }
                        },
                        checkpoint_tick_reason,
                    ),
                )?;
                last_export = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    })();
    shared.phase("stopping")?;
    shared.cancel.cancel();
    #[cfg(unix)]
    let result = result.and(checkpoint_host.stop_preparation());
    #[cfg(unix)]
    drop(submission);
    let network_result = network
        .join()
        .map_err(|_| "resident network worker panicked")?;
    let producer_result = producer
        .take()
        .map(|worker| worker.join().map_err(|_| "resident producer panicked"))
        .transpose()?
        .transpose();
    let result = result.and(network_result).and(producer_result.map(|_| ()));
    shared.block_events.finish();
    shared.phase(if result.is_ok() { "stopped" } else { "error" })?;
    export_status(
        directory,
        &run.run_id,
        &shared,
        started,
        sequence.saturating_add(1),
        (mining, false),
        (
            checkpoint_error,
            {
                #[cfg(unix)]
                {
                    checkpoint_host.wallet_export_state()
                }
                #[cfg(not(unix))]
                {
                    wallet_export
                }
            },
            checkpoint_tick_reason,
        ),
    )?;
    result
}
