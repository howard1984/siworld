//! Opt-in composition gate for real resident services, native proofs and wallet
//! recovery. Loopback transport and an easy PoW target do not qualify a public
//! network, production hardware, retention or sustained-load operation.
use super::*;
use crate::producer::MiningSettings;
use crate::state::RewardMode;
use crate::wallet_vault::{PendingWallet, RecoveryWords, UnlockedWallet, WalletVault};
use native::multi_asset::SIP_ASSET_ID;
use std::net::Ipv4Addr;
use zeroize::Zeroizing;

const PASSWORD: &str = "isolated resident composition test passphrase";
const STAGE_LIMIT: Duration = Duration::from_secs(5 * 60);

fn new_run_directory() -> PathBuf {
    let parent = std::env::var_os("SIWORLD_RESIDENT_GENUINE_RUN_ROOT")
        .map_or_else(std::env::temp_dir, PathBuf::from)
        .canonicalize()
        .unwrap();
    let mut suffix = [0; 16];
    getrandom::fill(&mut suffix).unwrap();
    let path = parent.join(format!(
        "resident-native-composition-{}",
        local::hex(&suffix)
    ));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&path).unwrap();
    // Retain the complete private run on success and failure. No Drop cleanup
    // can erase the stores, authenticated receipts or final service exports.
    path
}

fn backed_up_wallet(path: &Path, network: Hash) -> (UnlockedWallet, RecoveryWords) {
    let pending = PendingWallet::generate(network, 0).unwrap();
    let words = pending.recovery_words();
    let parts: Vec<_> = words.expose().split(' ').collect();
    let challenge = pending.backup_challenge();
    let confirmed = pending
        .confirm_backup(challenge.map(|index| parts[index - 1]))
        .unwrap();
    (confirmed.create(path, PASSWORD).unwrap(), words)
}

fn export_identity(path: &Path, identity: &NativeIdentity) -> Descriptor {
    let descriptor = identity.descriptor().unwrap();
    write_once(
        path,
        &json!({
            "version":crate::identity::VERSION,
            "fingerprint":local::hex(&descriptor.fingerprint()),
            "descriptor":local::hex(&descriptor.encode()),
        }),
    )
    .unwrap();
    descriptor
}

fn configure_peer(
    path: &Path,
    listen: SocketAddr,
    mining: bool,
    endpoint: SocketAddr,
    peer: &Descriptor,
) {
    write_once(
        path,
        &json!({
            "version":1,"engineering":true,"listen":listen.to_string(),"mining":mining,
            "peers":[{
                "endpoint":endpoint.to_string(),
                "fingerprint":local::hex(&peer.fingerprint()),
                "descriptor":local::hex(&peer.encode()),
            }],
        }),
    )
    .unwrap();
}

struct ServiceRun {
    directory: PathBuf,
    join: Option<JoinHandle<Result<(), String>>>,
}
impl ServiceRun {
    fn start(directory: &Path, peers: &Path) -> Self {
        let run_directory = directory.to_owned();
        let peer_file = peers.to_owned();
        Self {
            directory: directory.to_owned(),
            join: Some(std::thread::spawn(move || {
                crate::service::run_network(&run_directory, &peer_file)
            })),
        }
    }

    fn status(&self) -> Result<Option<Value>, String> {
        if !self.directory.join(STATUS_FILE).exists() {
            return Ok(None);
        }
        let value = exported_status(&self.directory)?;
        if !value["error_code"].is_null() {
            return Err("resident composition service exported a failure".into());
        }
        Ok(Some(value))
    }

    fn running_status(&self) -> Result<Option<Value>, String> {
        if self.join.as_ref().is_some_and(JoinHandle::is_finished) {
            return Err("resident composition service stopped before its gate".into());
        }
        self.status()
    }

    fn stop(&mut self) -> Result<Value, String> {
        let request_deadline = Instant::now() + Duration::from_secs(20);
        while self.join.as_ref().is_some_and(|join| !join.is_finished()) {
            if request_stop(&self.directory).is_ok() {
                break;
            }
            if Instant::now() >= request_deadline {
                return Err("resident composition graceful-stop request timed out".into());
            }
            std::thread::sleep(POLL);
        }
        if let Some(join) = self.join.take() {
            // A synchronous native proof cannot be preempted safely. Join the
            // one cancelled job; the external gate runner bounds the process.
            join.join()
                .map_err(|_| "resident composition service panicked")??;
        }
        let final_status = self.status()?.ok_or("missing final resident status")?;
        if final_status["phase"] != "stopped" {
            return Err("resident composition did not export a clean final replay".into());
        }
        Ok(final_status)
    }
}
impl Drop for ServiceRun {
    fn drop(&mut self) {
        if self.join.is_some() {
            let _ = self.stop();
            // If startup had not exported a stop-capable run by the bounded
            // request deadline, keep ownership while retrying the stop request
            // and joining rather than silently leaving a resident service.
            if let Some(join) = self.join.take() {
                while !join.is_finished() {
                    let _ = request_stop(&self.directory);
                    std::thread::sleep(POLL);
                }
                let _ = join.join();
            }
        }
    }
}

fn wait_for(mut condition: impl FnMut() -> Result<bool, String>) -> Result<(), String> {
    let deadline = Instant::now() + STAGE_LIMIT;
    while !condition()? {
        if Instant::now() >= deadline {
            return Err("resident native composition stage exceeded five minutes".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn same_head(a: &Value, b: &Value) -> bool {
    ["height", "tip", "state_fingerprint", "cumulative_work"]
        .iter()
        .all(|field| a[*field] == b[*field])
}

fn progress(directory: &Path, stage: &str, start: Instant) {
    atomic_json(
        &directory.join("resident-composition-progress.json"),
        &json!({
            "schema":1,"stage":stage,
            "elapsed_ms":u64::try_from(start.elapsed().as_millis()).unwrap(),
        }),
    )
    .unwrap();
}

#[test]
#[ignore = "opt-in genuine resident miner, hybrid peer synchronization and reward recovery"]
fn genuine_resident_miner_syncs_and_persists_rewards() {
    assert_eq!(
        std::env::var("SIWORLD_RUN_RESIDENT_GENUINE").as_deref(),
        Ok("1"),
        "the genuine resident composition gate requires explicit opt-in"
    );
    assert_eq!(std::env::var("RAYON_NUM_THREADS").as_deref(), Ok("4"));
    assert_eq!(
        std::env::var("SIWORLD_COMPOSITION_HIDING_WORKERS").as_deref(),
        Ok("2")
    );
    let start = Instant::now();
    let directory = new_run_directory();
    let miner_path = directory.join("miner");
    let validator_path = directory.join("validator");
    let config = local::initialize_asert(&miner_path, 1, [0xff; 32], 1).unwrap();
    assert!(!config.fixture);
    assert_eq!(
        config.economics,
        siworld_core::v1_economics::EconomicsParams::production()
    );
    assert_eq!(config.target_interval, 300);
    assert_eq!(config.fund_verifying_keys.len(), 24);
    local::initialize_config(&validator_path, config.clone()).unwrap();
    for path in [&miner_path, &validator_path] {
        let store = Store::open(
            path.join("chain.redb"),
            config.clone(),
            &NativeVerifier::new().unwrap(),
        )
        .unwrap();
        store.require_local_reward_index().unwrap();
        assert_eq!(store.verify_local_rewards().unwrap(), 0);
        assert_eq!(store.state().height, 0);
    }
    let (wallet, words) = backed_up_wallet(&directory.join("wallet"), config.network);
    let settings = MiningSettings {
        mode: RewardMode::Voyager,
        recipient: wallet.keys().unwrap().address(),
    };
    crate::mining::save(&miner_path, config.network, &settings).unwrap();
    let binding = p2p::Binding::new(&config);
    let miner_identity = NativeIdentity::initialize(&miner_path, binding).unwrap();
    let validator_identity = NativeIdentity::initialize(&validator_path, binding).unwrap();
    let miner_export = directory.join("miner-public-identity.json");
    let validator_export = directory.join("validator-public-identity.json");
    let miner_descriptor = export_identity(&miner_export, &miner_identity);
    let validator_descriptor = export_identity(&validator_export, &validator_identity);
    assert_ne!(
        miner_descriptor.fingerprint(),
        validator_descriptor.fingerprint()
    );
    pin_peer(
        &miner_path,
        &validator_export,
        &local::hex(&validator_descriptor.fingerprint()),
    )
    .unwrap();
    pin_peer(
        &validator_path,
        &miner_export,
        &local::hex(&miner_descriptor.fingerprint()),
    )
    .unwrap();
    drop((miner_identity, validator_identity));
    let miner_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let validator_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let miner_address = miner_listener.local_addr().unwrap();
    let validator_address = validator_listener.local_addr().unwrap();
    let miner_peers = directory.join("miner-peers.json");
    let restart_peers = directory.join("miner-restart-peers.json");
    let validator_peers = directory.join("validator-peers.json");
    configure_peer(
        &miner_peers,
        miner_address,
        true,
        validator_address,
        &validator_descriptor,
    );
    configure_peer(
        &restart_peers,
        miner_address,
        false,
        validator_address,
        &validator_descriptor,
    );
    configure_peer(
        &validator_peers,
        validator_address,
        false,
        miner_address,
        &miner_descriptor,
    );
    progress(&directory, "starting-real-services", start);
    drop((miner_listener, validator_listener));
    let mut miner = ServiceRun::start(&miner_path, &miner_peers);
    let mut validator = ServiceRun::start(&validator_path, &validator_peers);
    wait_for(|| {
        let (Some(a), Some(b)) = (miner.running_status()?, validator.running_status()?) else {
            return Ok(false);
        };
        Ok(a["network"]["connected"].as_u64().is_some_and(|n| n >= 1)
            && b["network"]["connected"].as_u64().is_some_and(|n| n >= 1))
    })
    .unwrap();
    progress(&directory, "authenticated-native-production", start);
    wait_for(|| {
        let (Some(a), Some(b)) = (miner.running_status()?, validator.running_status()?) else {
            return Ok(false);
        };
        Ok(a["height"].as_u64().is_some_and(|height| height >= 1) && same_head(&a, &b))
    })
    .unwrap();
    progress(&directory, "stopping-miner-before-final-sync", start);
    let miner_final = miner.stop().unwrap();
    assert!(miner_final["height"].as_u64().unwrap() >= 1);
    // Stop can observe a commit newer than the last exported same-head pair.
    // Only after the producer has joined, restart its existing identity/store
    // without mining so the validator can fetch an immutable final head. This
    // also exercises genuine reconnect and receipt-index recovery on startup.
    progress(&directory, "mining-disabled-restart-and-final-sync", start);
    let mut restarted = ServiceRun::start(&miner_path, &restart_peers);
    wait_for(|| {
        let (Some(a), Some(b)) = (restarted.running_status()?, validator.running_status()?) else {
            return Ok(false);
        };
        Ok(a["run_id"] != miner_final["run_id"]
            && a["phase"] == "networking"
            && a["network"]["connected"].as_u64().is_some_and(|n| n >= 1)
            && same_head(&miner_final, &a)
            && same_head(&miner_final, &b))
    })
    .unwrap();
    let restart_final = restarted.stop().unwrap();
    assert!(same_head(&miner_final, &restart_final));
    let validator_final = validator.stop().unwrap();
    assert!(same_head(&miner_final, &validator_final));
    progress(
        &directory,
        "independent-native-replay-and-wallet-recovery",
        start,
    );
    let verifier = NativeVerifier::new().unwrap();
    let miner_store =
        Store::open_existing(miner_path.join("chain.redb"), config.clone(), &verifier).unwrap();
    let validator_store =
        Store::open_existing(validator_path.join("chain.redb"), config.clone(), &verifier).unwrap();
    assert_eq!(miner_store.state().height, validator_store.state().height);
    assert_eq!(miner_store.state().tip, validator_store.state().tip);
    assert_eq!(
        miner_store.state().fingerprint(),
        validator_store.state().fingerprint()
    );
    assert_eq!(
        miner_final["state_fingerprint"],
        local::hex(&miner_store.state().fingerprint())
    );
    let height = miner_store.state().height;
    assert_eq!(miner_store.verify_local_rewards().unwrap(), height);
    assert_eq!(validator_store.verify_local_rewards().unwrap(), 0);
    let blocks: Vec<_> = (1..=height)
        .map(|number| validator_store.block(number).unwrap())
        .collect();
    assert!(
        blocks
            .iter()
            .all(|block| block.transactions.len() == MIN_READY)
    );
    drop(wallet);
    let recovered_vault = WalletVault::restore(
        &directory.join("wallet-restored"),
        config.network,
        0,
        Zeroizing::new(words.expose().to_owned()),
        PASSWORD,
    )
    .unwrap();
    assert_eq!(
        recovered_vault.keys().unwrap().address(),
        settings.recipient
    );
    let mut recovered = recovered_vault.wallet().unwrap();
    recovered
        .reconcile(config.clone(), &blocks, &verifier)
        .unwrap();
    assert_eq!(
        recovered.head(),
        Some((
            height,
            miner_store.state().tip,
            miner_store.state().fingerprint()
        ))
    );
    assert_eq!(u64::try_from(recovered.receipts().len()).unwrap(), height);
    assert!(recovered.receipts().iter().all(|receipt| {
        receipt.output_index == 3
            && receipt.note().asset_id == SIP_ASSET_ID
            && receipt.note().value > 0
            && receipt.note().unlock_height == receipt.height + config.economics.maturity
    }));
    let first = recovered
        .receipts()
        .iter()
        .find(|receipt| receipt.height == 1)
        .unwrap();
    let initial = State::new(config.clone()).unwrap();
    let expected_reward = initial.reward_allocation(RewardMode::Voyager).unwrap();
    assert_eq!(first.note().value, expected_reward.reward_notes[0].amount);
    atomic_json(
        &directory.join("resident-composition-result.json"),
        &json!({
            "schema":1,"gate":"native-resident-loopback-composition","passed":true,
            "accepted_height":height,"tip":local::hex(&miner_store.state().tip),
            "state_fingerprint":local::hex(&miner_store.state().fingerprint()),
            "slots_per_block":MIN_READY,"native_proof_replay":true,
            "miner_reward_receipts_checked":height,"validator_local_reward_receipts":0,
            "mnemonic_reward_recovery":true,"mining_disabled_restart":true,
            "elapsed_ms":u64::try_from(start.elapsed().as_millis()).unwrap(),
        }),
    )
    .unwrap();
    progress(&directory, "completed", start);
}
