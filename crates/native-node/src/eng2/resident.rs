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

mod config;
#[cfg(unix)]
mod mailbox;
#[cfg(unix)]
mod operations;
#[cfg(unix)]
pub use operations::{result as operations_result, submit as submit_operations};
mod peers;
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
    cancel: p2p::Cancellation,
    network: Arc<peers::NetworkStatus>,
    production: Mutex<ProductionStatus>,
    checkpoint_observer: Mutex<super::checkpoint_observer::Observer>,
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
        Ok(self.network.snapshot()?.ready && !self.checkpoint_conflict()?)
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
    checkpoint_error: Option<&str>,
) -> Result<(), String> {
    let (mining, listening) = mode;
    let owner = shared
        .owner
        .lock()
        .map_err(|_| "resident owner lock poisoned")?;
    let head = owner.head()?;
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
    let ready = connections.ready && !conflict;
    service::atomic_json(
        &directory.join(service::STATUS_FILE),
        &json!({
            "schema_version":2,"run_id":run_id,"process_id":std::process::id(),"sequence":sequence,
            "phase":production.phase,"network_id":crate::local::hex(&head.network),"genesis_id":crate::local::hex(&head.genesis),
            "height":head.height,"tip":crate::local::hex(&head.id),"cumulative_work":head.work.to_string(),
            "state_available":true,"ready":ready,"sync_status":if conflict {"checkpoint_current_quorum_conflict"} else if ready {"caught_up"} else {"waiting_for_current_peer_tip"},
            "connections":connections.connections,"last_completed_round_age_ms":connections.last_round_age_ms,
            "completed_rounds":connections.rounds,"inbound_listener":listening,"mining_enabled":mining,
            "pow_attempts":production.pow_attempts,"mined_blocks":production.blocks,
            "pow_progress_fresh":production.last_pow.is_some_and(|t|t.elapsed()<=READY_FRESHNESS),
            "padding_ready":owner.padding_count(),"padding_bytes":owner.padding_bytes(),
            "checkpoint_error":checkpoint_error,"checkpoint_archive_error":owner.last_archive_error(),
            "signed_bootstrap_available":owner.bootstrap_available(),
            "checkpoint_observation_error":observer.error().map(super::checkpoint_observer::Error::code),
            "checkpoint_observed_height":observer.observed_height(),"checkpoint_conflict":conflict,
            "operations_error":operations_error(shared),
            "error_code":production.error,"updated_unix_ms":unix_ms()?,"elapsed_monotonic_ms":started.elapsed().as_millis().to_string(),
            "historical_proof_replay":false
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

pub fn run(directory: &Path, configuration: &Path, expected: &str) -> Result<(), String> {
    if std::env::var_os("GITHUB_ACTIONS").is_some()
        || matches!(std::env::var("CI").as_deref(), Ok("true") | Ok("1"))
    {
        return Err("native resident execution requires an owner-operated environment".into());
    }
    if !cfg!(unix) {
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
    let mining = config.mining;
    let listening = config.listen.is_some();
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
    let driver = Driver::new(store, NativeVerifier::new()?, limits())?;
    let budget = p2p::Budget::new(MEMORY_BYTES);
    let run = service::RunIdentity::new(
        genesis.config().network,
        binary_hash()?,
        config.digest.clone(),
        unix_ms()?,
    )?;
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
        cancel: p2p::Cancellation::default(),
        network: Arc::new(peers::NetworkStatus::default()),
        production: Mutex::new(ProductionStatus {
            phase: "starting",
            ..Default::default()
        }),
        checkpoint_observer: Mutex::new(super::checkpoint_observer::Observer::default()),
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
        super::runtime_export::host::Host::open(
            &root,
            owner.store(),
            limits(),
            config.checkpoint_key.as_deref(),
        )?
    };
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
            if last_checkpoint.elapsed() >= Duration::from_secs(1) {
                #[cfg(unix)]
                {
                    let incoming = shared.mailbox.drain()?;
                    let mut owner = shared
                        .owner
                        .lock()
                        .map_err(|_| "resident owner lock poisoned")?;
                    match checkpoint_host.tick(owner.store(), unix_ms()? / 1000, &incoming.messages)
                    {
                        Ok(tick) => {
                            shared.mailbox.acknowledge(&incoming)?;
                            shared.mailbox.publish(&tick.messages())?;
                            checkpoint_error = None;
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
                            checkpoint_error = Some("checkpoint_tick_rejected_or_unavailable")
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
                    checkpoint_error,
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
    shared.phase(if result.is_ok() { "stopped" } else { "error" })?;
    export_status(
        directory,
        &run.run_id,
        &shared,
        started,
        sequence.saturating_add(1),
        (mining, false),
        checkpoint_error,
    )?;
    result
}
