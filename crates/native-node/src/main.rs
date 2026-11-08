//! Disposable native engineering CLI. No retained-network adapter or reset.
use siworld_native_node::{
    audit, local, producer,
    proofs::{NativeProver, NativeVerifier},
    runtime::Node,
    service,
    state::Config,
    store::Store,
};
use std::path::Path;
fn help() {
    println!(
        "siworld-native-node: isolated native V1 engineering network\n\ninit DIRECTORY [WORK_BITS]  Create a cheap development fixture\ninit-service DIRECTORY     Create a new ASERT network with initialization-only calibration\ngenesis-id DIRECTORY       Read the validated public full-rules genesis identifier\nidentity-init DIRECTORY    Explicitly create persistent dual peer identities\nidentity-public DIRECTORY  Export the verified public dual-signed descriptor\nconfigure-miner DIRECTORY MODE ADDRESS_FILE  Select voyager/holder and a backed-up wallet address\nrun DIRECTORY              Run continuous native production; requires four proving workers\nstop DIRECTORY [EXPECTED_RUN_ID]  Request run-bound graceful stop and final verification\nservice-status DIRECTORY   Read the private atomic service export\nstatus DIRECTORY           Show exported service status or independently replay an idle store\ncheck DIRECTORY [--json]   Verify local replay base, retained proofs and reward receipts\nrestart-check DIRECTORY --json  Authenticate exact committed restart state, without proof audit\ncheckpoint-transition-check DIRECTORY --json  Admit existing state before the compiled checkpoint roster cutover\nstorage-role DIRECTORY ROLE  Explicitly select bootstrap|validator|miner|ordinary retention\nstorage-keep-blocks DIRECTORY BLOCKS  Set miner/ordinary proof window (minimum 24)\nstorage-expire DIRECTORY   Apply one bounded offline proof-expiry batch\nstorage-maintain DIRECTORY ROLE BLOCKS  Drain local-role expiry and compact in one verified session\nstorage-maintain-resume DIRECTORY ROLE BLOCKS  Drain local-role expiry from an exact authenticated restart record\nstorage-compact DIRECTORY  Reclaim database pages with the exclusive service lease\ncheckpoint-qualify-service DIRECTORY  Enable service expiry after checkpoint delivery acceptance\naudit DIRECTORY            Independently replay public subsidy and fund-credit counters\nmine DIRECTORY [SLOTS]     Produce and atomically accept one native block (64..576, groups of 16)\n\nRAYON_NUM_THREADS=4 and SIWORLD_COMPOSITION_HIDING_WORKERS=2 are required for run.\nA completed 24-hour observation does not automatically stop the service.\nNo reset, implicit role migration, issuance RPC listener, or public-network activation is provided. Peer listening requires the explicit native-p2p engineering feature."
    );
    #[cfg(feature = "native-p2p")]
    println!(
        "\ninit-peer DIRECTORY GENESIS_DIRECTORY EXPECTED_GENESIS_ID  Initialize a fresh peer from independently checked public ASERT rules\nrun-network DIRECTORY PEER_CONFIG  Listen and reconnect to pinned engineering peers\npeer-pin DIRECTORY DESCRIPTOR_FILE FINGERPRINT  Persist an independently verified public identity pin\npeer-admit-fixture-live DIRECTORY EXPECTED_RUN_ID SPECIMEN_ID DESCRIPTOR_FILE FINGERPRINT  Admit one run-local outbound-only recovery fixture\ncheckpoint-qualify-live DIRECTORY EXPECTED_RUN_ID  Request owner-bound service expiry qualification\ncheckpoint-signing-live DIRECTORY EXPECTED_RUN_ID paused|active  Request run-bound checkpoint signing control\nPublic peer discovery and public-network activation are disabled."
    );
    println!("\n{}", siworld_native_node::wallet_cli::HELP);
    println!(
        "\nengineering-keys CUSTODY_DIRECTORY  Create independent private test custody on an operations host\ninit-engineering-genesis DIRECTORY CUSTODY_DIRECTORY  Seal siworld-eng-1 with production timings and one test fund account"
    );
}
fn cpu_admission() -> Result<(), String> {
    #[cfg(target_arch = "x86_64")]
    if !std::is_x86_feature_detected!("avx2") {
        return Err("AVX2 is required; scalar fallback is disabled".into());
    }
    Ok(())
}
fn config(path: &Path) -> Result<Config, String> {
    local::load(path)
}
fn genesis_identifier(path: &Path) -> Result<String, String> {
    // The public rules are sufficient; do not lease or open the live store.
    Ok(local::hex(&config(path)?.genesis_id()))
}
fn exact(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        Err("unexpected argument".into())
    } else {
        Ok(())
    }
}
fn stop_command(args: &[String]) -> Result<(), String> {
    match args {
        [command, directory] if command == "stop" => service::request_stop(Path::new(directory)),
        [command, directory, expected_run_id] if command == "stop" => {
            service::request_stop_expected(Path::new(directory), expected_run_id)
        }
        _ => Err("expected stop DIRECTORY [EXPECTED_RUN_ID]".into()),
    }
}
fn check_json(args: &[String]) -> Result<bool, String> {
    match args {
        [command, _] if command == "check" => Ok(false),
        [command, _, flag] if command == "check" && flag == "--json" => Ok(true),
        _ => Err("expected check DIRECTORY [--json]".into()),
    }
}
fn restart_check_arguments(args: &[String]) -> Result<(), String> {
    match args {
        [command, _, flag] if command == "restart-check" && flag == "--json" => Ok(()),
        _ => Err("expected restart-check DIRECTORY --json".into()),
    }
}
fn checkpoint_transition_check_arguments(args: &[String]) -> Result<(), String> {
    match args {
        [command, _, flag] if command == "checkpoint-transition-check" && flag == "--json" => {
            Ok(())
        }
        _ => Err("expected checkpoint-transition-check DIRECTORY --json".into()),
    }
}
fn storage_maintain_resume_arguments(
    args: &[String],
) -> Result<siworld_native_node::storage_policy::StartupPolicy, String> {
    let [command, _, role, blocks] = args else {
        return Err("expected storage-maintain-resume DIRECTORY miner|ordinary BLOCKS".into());
    };
    if command != "storage-maintain-resume"
        || blocks.is_empty()
        || !blocks.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("expected storage-maintain-resume DIRECTORY miner|ordinary BLOCKS".into());
    }
    let policy =
        siworld_native_node::storage_policy::StartupPolicy::parse(Some(role), Some(blocks))?
            .ok_or("explicit storage policy required")?;
    if policy.role.serves_historical_proofs() {
        return Err("resume maintenance is limited to miner and ordinary roles".into());
    }
    Ok(policy)
}
#[cfg(feature = "native-p2p")]
fn peer_genesis(source: &Path, expected_genesis: &str) -> Result<Config, String> {
    if expected_genesis.len() != 64
        || !expected_genesis
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("expected an independently checked lowercase genesis identifier".into());
    }
    // Read the immutable public configuration only. Identity seeds, database
    // history, wallet custody, receipts and service records are never copied.
    let config = local::load(source)?;
    if local::hex(&config.genesis_id()) != expected_genesis {
        return Err("genesis configuration differs from the expected genesis identifier".into());
    }
    if config.fixture || config.fund_allocation.is_none() {
        return Err(
            "peer initialization requires ASERT rules and an immutable fund allocation".into(),
        );
    }
    Ok(config)
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    run_arguments(args)
}
fn run_arguments(args: Vec<String>) -> Result<(), String> {
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        help();
        return Ok(());
    }
    cpu_admission()?;
    if matches!(
        args[0].as_str(),
        "wallet-create"
            | "wallet-restore"
            | "wallet-address"
            | "wallet-configure-miner"
            | "wallet-balance"
            | "wallet-pay"
            | "wallet-retry-payment"
            | "wallet-privacy"
    ) {
        return siworld_native_node::wallet_cli::run(&args[0], &args[1..]);
    }
    let maximum_arguments = if cfg!(feature = "native-p2p") && args[0] == "peer-admit-fixture-live"
    {
        6
    } else {
        4
    };
    if args.len() < 2 || args.len() > maximum_arguments {
        return Err("expected command and explicit engineering directory; use --help".into());
    }
    let path = Path::new(&args[1]);
    match args[0].as_str() {
        "engineering-keys" => {
            exact(&args)?;
            let public = siworld_native_node::engineering_genesis::prepare(path)?;
            println!("{public}");
        }
        "init-engineering-genesis" => {
            if args.len() != 3 {
                return Err("expected DIRECTORY CUSTODY_DIRECTORY".into());
            }
            let (timestamp, target, iterations) = service::calibrate()?;
            let config = siworld_native_node::engineering_genesis::initialize(
                path,
                Path::new(&args[2]),
                timestamp,
                target,
                iterations,
            )?;
            println!(
                "{}",
                serde_json::json!({"name": "siworld-eng-1", "genesis_id": local::hex(&config.genesis_id()), "checkpoint_startup": "inactive"})
            );
        }
        "genesis-id" => {
            exact(&args)?;
            println!("{}", genesis_identifier(path)?);
        }
        "storage-role" => {
            if args.len() != 3 {
                return Err(
                    "expected storage-role DIRECTORY bootstrap|validator|miner|ordinary".into(),
                );
            }
            let role = siworld_native_node::storage_policy::Role::parse(&args[2])?;
            let _lease = service::Lease::acquire(path)?;
            let verifier = NativeVerifier::new()?;
            let mut store =
                Store::open_existing(path.join("chain.redb"), config(path)?, &verifier)?;
            store.configure_storage(role)?;
            println!("{}", store.storage_metrics()?);
        }
        "storage-keep-blocks" => {
            if args.len() != 3 {
                return Err("expected storage-keep-blocks DIRECTORY BLOCKS".into());
            }
            let blocks = args[2]
                .parse::<u64>()
                .map_err(|_| "invalid retained proof count")?;
            let _lease = service::Lease::acquire(path)?;
            let verifier = NativeVerifier::new()?;
            let mut store =
                Store::open_existing(path.join("chain.redb"), config(path)?, &verifier)?;
            store.configure_local_proof_blocks(blocks)?;
            println!("{}", store.storage_metrics()?);
        }
        "storage-maintain-resume" => {
            let policy = storage_maintain_resume_arguments(&args)?;
            println!(
                "{}",
                service::storage_maintain_resume_offline(
                    path,
                    policy.role,
                    policy.local_blocks.ok_or("proof window required")?,
                )?
            );
        }
        "storage-maintain" => {
            if args.len() != 4 {
                return Err("expected storage-maintain DIRECTORY miner|ordinary BLOCKS".into());
            }
            let policy = siworld_native_node::storage_policy::StartupPolicy::parse(
                Some(&args[2]),
                Some(&args[3]),
            )?
            .ok_or("explicit storage policy required")?;
            if policy.role.serves_historical_proofs() {
                return Err("offline drain is limited to miner and ordinary roles".into());
            }
            let _lease = service::Lease::acquire(path)?;
            let verifier = NativeVerifier::new()?;
            let mut store =
                Store::open_existing(path.join("chain.redb"), config(path)?, &verifier)?;
            let before = store.storage_metrics()?;
            store.configure_storage(policy.role)?;
            store.configure_local_proof_blocks(
                policy.local_blocks.ok_or("proof window required")?,
            )?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "system clock precedes epoch")?
                .as_secs();
            let mut expired = 0u64;
            loop {
                let count = store.expire_proofs(now, true, &verifier)?;
                expired = expired
                    .checked_add(count)
                    .ok_or("expired proof count overflow")?;
                if count == 0 {
                    break;
                }
            }
            let compacted = store.compact_expired_storage(&verifier)?;
            store.verify_local_rewards()?;
            println!(
                "{}",
                serde_json::json!({"before":before,"after":store.storage_metrics()?,
                "expired_blocks":expired,"compacted":compacted,"reward_replay_verified":true})
            );
        }
        #[cfg(all(feature = "native-p2p", feature = "checkpoint-stale-acceptance", unix))]
        "checkpoint-stale-probe" => {
            if args.len() != 4 {
                return Err(
                    "expected checkpoint-stale-probe DIRECTORY EXPECTED_RUN_ID fresh|stale|resume"
                        .into(),
                );
            }
            service::request_checkpoint_stale_probe(path, &args[2], &args[3])?;
            println!(
                "{}",
                serde_json::json!({"schema":1,"requested":true,"run_id":args[2],"phase":args[3]})
            );
        }
        "storage-expire" | "storage-compact" => {
            exact(&args)?;
            let _lease = service::Lease::acquire(path)?;
            let verifier = NativeVerifier::new()?;
            let mut store =
                Store::open_existing(path.join("chain.redb"), config(path)?, &verifier)?;
            if args[0] == "storage-expire" {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| "system clock precedes epoch")?
                    .as_secs();
                store.expire_proofs(now, true, &verifier)?;
            } else {
                store.compact_expired_storage(&verifier)?;
            }
            println!("{}", store.storage_metrics()?);
        }
        #[cfg(feature = "native-p2p")]
        "peer-admit-fixture-live" => {
            if args.len() != 6 {
                return Err("expected peer-admit-fixture-live DIRECTORY EXPECTED_RUN_ID SPECIMEN_ID DESCRIPTOR_FILE FINGERPRINT".into());
            }
            service::request_fixture_admission(
                path,
                &args[2],
                &args[3],
                Path::new(&args[4]),
                &args[5],
            )?;
            println!(
                "{}",
                serde_json::json!({"fixture_admission_requested":true})
            );
        }
        #[cfg(feature = "native-p2p")]
        "checkpoint-qualify-live" => {
            if args.len() != 3 {
                return Err("expected checkpoint-qualify-live DIRECTORY EXPECTED_RUN_ID".into());
            }
            service::request_checkpoint_qualification(path, &args[2])?;
            println!("{}", serde_json::json!({"qualification_requested":true}));
        }
        #[cfg(feature = "native-p2p")]
        "checkpoint-signing-live" => {
            if args.len() != 4 {
                return Err(
                    "expected checkpoint-signing-live DIRECTORY EXPECTED_RUN_ID paused|active"
                        .into(),
                );
            }
            let paused = match args[3].as_str() {
                "paused" => true,
                "active" => false,
                _ => return Err("expected checkpoint signing state paused or active".into()),
            };
            service::request_checkpoint_signing(path, &args[2], paused)?;
            println!("{}", serde_json::json!({"signing_state_requested":args[3]}));
        }
        "checkpoint-qualify-service" => {
            exact(&args)?;
            let config = config(path)?;
            let roster = siworld_native_node::engineering_checkpoint::release_roster(
                siworld_native_node::p2p::Binding::new(&config),
            )?
            .ok_or("engineering checkpoint authorities are not release-pinned")?;
            let _lease = service::Lease::acquire(path)?;
            let verifier = NativeVerifier::new()?;
            let mut store = Store::open_existing(path.join("chain.redb"), config, &verifier)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "system clock precedes epoch")?
                .as_secs();
            store.qualify_service_checkpoint_delivery(&roster, now)?;
            println!("{}", store.storage_metrics()?);
        }
        "identity-init" | "identity-public" => {
            exact(&args)?;
            let binding = siworld_native_node::p2p::Binding::new(&config(path)?);
            let identity = if args[0] == "identity-init" {
                siworld_native_node::identity::NativeIdentity::initialize(path, binding)
            } else {
                siworld_native_node::identity::NativeIdentity::load(path, &binding)
            }
            .map_err(|_| "native identity initialization or authentication rejected")?;
            if args[0] == "identity-init" && path.join("chain.redb").is_file() {
                let _lease = service::Lease::acquire(path)?;
                let verifier = NativeVerifier::new()?;
                let mut store =
                    Store::open_existing(path.join("chain.redb"), config(path)?, &verifier)?;
                if store.state().height == 0 && store.storage_role()?.is_none() {
                    store.configure_storage(siworld_native_node::storage_policy::Role::Ordinary)?;
                }
            }
            let descriptor = identity
                .descriptor()
                .map_err(|_| "native identity descriptor rejected")?;
            println!(
                "{}",
                serde_json::json!({
                    "version": siworld_native_node::identity::VERSION,
                    "fingerprint": local::hex(&descriptor.fingerprint()),
                    "descriptor": local::hex(&descriptor.encode()),
                })
            );
        }
        "configure-miner" => {
            if args.len() != 4 {
                return Err("expected DIRECTORY voyager|holder ADDRESS_FILE".into());
            }
            let chain = config(path)?;
            let mode = siworld_native_node::state::RewardMode::from_name(&args[2])
                .map_err(|e| e.to_string())?;
            let recipient = siworld_native_node::mining::read_address(Path::new(&args[3]))?;
            siworld_native_node::mining::save(
                path,
                chain.network,
                &producer::MiningSettings { mode, recipient },
            )?;
            println!("mining preference saved for the next block template");
        }
        #[cfg(feature = "native-p2p")]
        "init-peer" => {
            if args.len() != 4 {
                return Err("expected DIRECTORY GENESIS_DIRECTORY EXPECTED_GENESIS_ID".into());
            }
            let public_rules = peer_genesis(Path::new(&args[2]), &args[3])?;
            let config = local::initialize_config(path, public_rules)?;
            let _lease = service::Lease::acquire(path)?;
            let verifier = NativeVerifier::new()?;
            let store = Store::open(path.join("chain.redb"), config, &verifier)?;
            println!(
                "initialized native engineering peer: network={}, height={}, genesis={}",
                local::hex(&store.state().config.network),
                store.state().height,
                local::hex(&store.state().config.genesis_id())
            );
        }
        #[cfg(feature = "native-p2p")]
        "run-network" => {
            if args.len() != 3 {
                return Err("expected DIRECTORY PEER_CONFIG".into());
            }
            service::run_network(path, Path::new(&args[2]))?;
        }
        #[cfg(feature = "native-p2p")]
        "peer-pin" => {
            if args.len() != 4 {
                return Err("expected DIRECTORY DESCRIPTOR_FILE EXPECTED_FINGERPRINT".into());
            }
            service::network::pin_peer(path, Path::new(&args[2]), &args[3])?;
            println!("independently verified peer pin persisted");
        }
        "run" => {
            exact(&args)?;
            service::run(path)?;
        }
        "stop" => {
            stop_command(&args)?;
            println!("graceful stop requested for the exported service run");
        }
        "service-status" => {
            exact(&args)?;
            println!("{}", service::exported_status(path)?);
        }
        "init" | "init-service" => {
            let config = if args[0] == "init-service" {
                exact(&args)?;
                let (timestamp, target, iterations) = service::calibrate()?;
                local::initialize_asert(path, timestamp, target, iterations)?
            } else {
                let bits = args
                    .get(2)
                    .map_or(Ok(0), |x| x.parse::<u8>().map_err(|_| "invalid work bits"))?;
                local::initialize(path, bits)?
            };
            let _lease = service::Lease::acquire(path)?;
            let verifier = NativeVerifier::new()?;
            let store = Store::open(path.join("chain.redb"), config, &verifier)?;
            println!(
                "initialized isolated engineering network: height={}, tip={}",
                store.state().height,
                local::hex(&store.state().tip)
            );
        }
        "restart-check" => {
            restart_check_arguments(&args)?;
            println!("{}", service::restart_check_offline(path)?);
        }
        "checkpoint-transition-check" => {
            checkpoint_transition_check_arguments(&args)?;
            println!("{}", service::checkpoint_transition_check_offline(path)?);
        }
        "status" | "check" | "audit" => {
            if args[0] == "check" {
                let as_json = check_json(&args)?;
                let checked = service::check_offline(path)?;
                if as_json {
                    println!("{checked}");
                } else {
                    println!(
                        "verified engineering state: height={}, tip={}, state={}",
                        checked["height"]
                            .as_u64()
                            .ok_or("checked height unavailable")?,
                        checked["tip"].as_str().ok_or("checked tip unavailable")?,
                        checked["state_fingerprint"]
                            .as_str()
                            .ok_or("checked fingerprint unavailable")?,
                    );
                }
                return Ok(());
            }
            exact(&args)?;
            if args[0] == "status" && path.join(service::STATUS_FILE).exists() {
                println!("{}", service::exported_status(path)?);
                return Ok(());
            }
            let _lease = service::Lease::acquire(path)?;
            let verifier = NativeVerifier::new()?;
            let store = Store::open_existing(path.join("chain.redb"), config(path)?, &verifier)?;
            if args[0] == "audit" {
                let (_, report) = audit::replay_blocks(
                    store.state().config.clone(),
                    (1..=store.state().height).map(|height| store.block(height)),
                    &verifier,
                )?;
                check_audit_head(&report, store.state())?;
                // Heights, subsidy and fund credits are public protocol data.
                // Private fee openings and local wallet receipts are excluded.
                for row in &report.heights {
                    println!(
                        "{}",
                        serde_json::json!({
                            "kind": "height", "height": row.height,
                            "block_id": local::hex(&row.block_id), "subsidy_atoms": row.subsidy,
                            "miner_subsidy_atoms": row.miner_subsidy,
                            "reward_mode": row.mode.name(), "fund_credit_atoms": row.fund_credit,
                            "holder_pool_atoms": row.pool_balance.to_string(),
                            "holder_pool_payout_atoms": row.pool_payout.to_string(), "burn_atoms": row.burn,
                        })
                    );
                }
                println!("{}", audit_summary(&report));
                return Ok(());
            }
            println!(
                "verified engineering state: height={}, tip={}, state={}",
                store.state().height,
                local::hex(&store.state().tip),
                local::hex(&store.state().fingerprint())
            );
        }
        "mine" => {
            let slots = args.get(2).map_or(Ok(64), |x| {
                x.parse::<usize>().map_err(|_| "invalid slot count")
            })?;
            if !(64..=576).contains(&slots) || !slots.is_multiple_of(16) {
                return Err("slot count must be 64..576 in groups of 16".into());
            }
            let _lease = service::Lease::acquire(path)?;
            let verifier = NativeVerifier::new()?;
            let store = Store::open_existing(path.join("chain.redb"), config(path)?, &verifier)?;
            let mut node = Node::new(store, verifier);
            let prover = NativeProver::new()?;
            let settings = siworld_native_node::mining::load(path, node.state().config.network)?;
            let permit = node
                .begin_production()
                .map_err(|_| "production preparation state unavailable")?;
            let produced = producer::produce(node.state(), &prover, slots, &settings)?;
            let prepared = node
                .bind_produced(permit, produced)
                .map_err(|_| "completed production no longer matches the node state")?;
            node.commit_produced(prepared)
                .map_err(|_| "native production receipt or canonical commit rejected")?;
            println!(
                "accepted engineering block: height={}, tip={}",
                node.state().height,
                local::hex(&node.state().tip)
            );
        }
        _ => return Err("unknown command; use --help".into()),
    }
    Ok(())
}
fn check_audit_head(
    report: &audit::AuditReport,
    state: &siworld_native_node::state::State,
) -> Result<(), String> {
    report
        .check_head(state.height, state.tip, state.fingerprint())
        .map_err(|_| "offline issuance audit head differs from verified store".to_owned())
}
fn audit_summary(report: &audit::AuditReport) -> serde_json::Value {
    serde_json::json!({
        "kind": "summary", "scope": "subsidy-pool-burn-signed-fund-spending-and-assets",
        "network": local::hex(&report.network), "height": report.height,
        "tip": local::hex(&report.tip), "state": local::hex(&report.fingerprint),
        "total_subsidy_atoms": report.total_subsidy.to_string(),
        "miner_subsidy_atoms": report.miner_subsidy.to_string(),
        "funds": report.fund_wallets.iter().zip(&report.funds).map(|(identity, fund)| serde_json::json!({
            "account": identity.account, "basis_points": identity.basis_points,
            "team_remainder": identity.team_remainder,
            "ml_dsa_65_verifying_key": local::hex(&identity.verifying_key),
            "entitlement_atoms":fund.entitlement.to_string(),
            "released_atoms":fund.unlocked().expect("audited fund release overflow").to_string(),
            "available_atoms":fund.available().expect("audited fund availability invalid").to_string(),
            "balance_atoms":fund.available().expect("audited fund availability invalid").to_string(),
            "direct_unlocked_atoms":fund.direct_unlocked.to_string(),
            "vesting_unlocked_atoms":fund.vesting_unlocked.to_string(),
            "spent_atoms":fund.spent.to_string(), "spend_count":fund.spend_count,
        })).collect::<Vec<_>>(),
        "holder_pool_atoms":report.holder_pool.to_string(),
        "burned_atoms":report.burned.to_string(),
        "scheduled_locked_subsidy_atoms":report.locked_subsidy.to_string(),
        "scheduled_circulating_atoms":report.scheduled_circulating.to_string(),
        "asset_issuance_supported": report.asset_issuance_supported,
        "issued_assets": report.issued_assets.iter().map(|(id, asset)| serde_json::json!({
            "asset_id":local::hex(id), "height":asset.height,
            "public_supply":asset.public_supply.to_string(), "declaration":local::hex(&asset.declaration),
        })).collect::<Vec<_>>(),
        "fund_spending_supported": report.fund_spending_supported,
        "wallet_reward_recovery_checked": false,
    })
}

fn main() {
    if let Err(error) = run() {
        eprintln!("native engineering operation rejected: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siworld_native_node::state::State;

    fn empty_report() -> (State, audit::AuditReport) {
        let state = State::new(Config::development([71; 32], 0).unwrap()).unwrap();
        let report = audit::AuditReport {
            network: state.config.network,
            height: 0,
            tip: state.tip,
            fingerprint: state.fingerprint(),
            total_subsidy: 0,
            miner_subsidy: 0,
            funds: state.economics.funds().to_vec(),
            fund_wallets: state
                .config
                .fund_verifying_keys
                .iter()
                .enumerate()
                .map(|(index, key)| audit::FundWalletIdentity {
                    account: index as u8,
                    basis_points: 5000,
                    team_remainder: index == 1,
                    verifying_key: *key,
                })
                .collect(),
            holder_pool: 0,
            burned: 0,
            locked_subsidy: 0,
            scheduled_circulating: 0,
            heights: Vec::new(),
            asset_issuance_supported: true,
            issued_assets: Vec::new(),
            fund_spending_supported: true,
        };
        (state, report)
    }
    #[test]
    fn audit_summary_states_its_scope_without_implying_wallet_or_asset_checks() {
        let (_, report) = empty_report();
        let summary = audit_summary(&report);
        assert_eq!(
            summary["scope"],
            "subsidy-pool-burn-signed-fund-spending-and-assets"
        );
        assert_eq!(summary["total_subsidy_atoms"], "0");
        assert_eq!(summary["wallet_reward_recovery_checked"], false);
        assert_eq!(summary["asset_issuance_supported"], true);
        assert_eq!(summary["fund_spending_supported"], true);
        assert_eq!(summary["funds"].as_array().unwrap().len(), 2);
        assert_eq!(summary["funds"][0]["basis_points"], 5000);
        assert_eq!(summary["funds"][0]["released_atoms"], "0");
        assert_eq!(summary["funds"][0]["spent_atoms"], "0");
        assert_eq!(summary["funds"][0]["balance_atoms"], "0");
        assert_eq!(
            summary["funds"][0]["ml_dsa_65_verifying_key"]
                .as_str()
                .unwrap()
                .len(),
            3904
        );
    }
    #[test]
    fn audit_requires_the_exact_verified_height_tip_and_fingerprint() {
        let (state, report) = empty_report();
        check_audit_head(&report, &state).unwrap();
        for field in 0..3 {
            let mut changed = report.clone();
            match field {
                0 => changed.height += 1,
                1 => changed.tip[0] ^= 1,
                _ => changed.fingerprint[0] ^= 1,
            }
            assert_eq!(
                check_audit_head(&changed, &state).unwrap_err(),
                "offline issuance audit head differs from verified store"
            );
        }
    }
}

#[cfg(test)]
mod control_command_tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "siworld-control-command-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn arguments(command: &str, directory: &Path, extra: &[&str]) -> Vec<String> {
        std::iter::once(command.to_owned())
            .chain(std::iter::once(directory.to_str().unwrap().to_owned()))
            .chain(extra.iter().map(|value| (*value).to_owned()))
            .collect()
    }

    #[cfg(feature = "native-p2p")]
    #[test]
    fn fixture_admission_cli_reaches_run_bound_service_validation() {
        let directory = Directory::new();
        let absent = directory.0.join("absent");
        let run_id = "a".repeat(64);
        let fingerprint = "b".repeat(64);
        assert_eq!(
            run_arguments(arguments(
                "peer-admit-fixture-live",
                &absent,
                &[&run_id, "fresh-fixture", "descriptor.json", &fingerprint],
            ))
            .unwrap_err(),
            "service directory unavailable"
        );
        assert!(!absent.exists());
        assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
    }

    #[test]
    fn command_dispatch_rejects_invalid_arity_before_mutation() {
        let directory = Directory::new();
        for command in ["peer-admit-fixture-live", "init", "stop", "unknown-command"] {
            for length in [1, 3, 4, 5, 6, 7] {
                let mut args = arguments(command, &directory.0, &[]);
                args.resize(length, "extra".into());
                let error = run_arguments(args).unwrap_err();
                if command != "peer-admit-fixture-live" && length > 4 {
                    assert_eq!(
                        error,
                        "expected command and explicit engineering directory; use --help"
                    );
                }
                assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 0);
            }
        }
    }

    #[test]
    fn stop_cli_rejects_malformed_mismatched_and_extra_arguments_before_mutation() {
        let directory = Directory::new();
        let run_id = "b".repeat(64);
        let stale = "a".repeat(64);
        let uppercase = "B".repeat(64);
        let status = directory.0.join(service::STATUS_FILE);
        std::fs::write(
            &status,
            serde_json::to_vec(&serde_json::json!({
                "run_id": run_id, "phase": "networking"
            }))
            .unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&status, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        for extra in [
            vec![""],
            vec!["invalid"],
            vec![uppercase.as_str()],
            vec![stale.as_str()],
            vec![run_id.as_str(), "extra"],
        ] {
            assert!(stop_command(&arguments("stop", &directory.0, &extra)).is_err());
            assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 1);
            assert!(!service::stop_requested(&directory.0, &run_id).unwrap());
        }
        assert!(stop_command(&["stop".into()]).is_err());
        stop_command(&arguments("stop", &directory.0, &[&run_id])).unwrap();
        assert!(service::stop_requested(&directory.0, &run_id).unwrap());
    }

    #[test]
    fn check_cli_accepts_only_an_optional_exact_json_flag() {
        let directory = Path::new("unused");
        assert!(!check_json(&arguments("check", directory, &[])).unwrap());
        assert!(check_json(&arguments("check", directory, &["--json"])).unwrap());
        for extra in [
            vec!["json"],
            vec!["--JSON"],
            vec!["--json", "extra"],
            vec!["--json", "--json"],
        ] {
            assert!(check_json(&arguments("check", directory, &extra)).is_err());
        }
        assert!(check_json(&["check".into()]).is_err());
    }

    #[test]
    fn resume_maintenance_cli_requires_exact_local_role_and_window() {
        let directory = Path::new("unused");
        for role in ["miner", "ordinary"] {
            let policy = storage_maintain_resume_arguments(&arguments(
                "storage-maintain-resume",
                directory,
                &[role, "96"],
            ))
            .unwrap();
            assert_eq!(policy.role.name(), role);
            assert_eq!(policy.local_blocks, Some(96));
        }
        for tail in [
            vec![],
            vec!["miner"],
            vec!["miner", "96", "extra"],
            vec!["bootstrap", "96"],
            vec!["validator", "96"],
            vec!["miner", "23"],
            vec!["miner", "NaN"],
            vec!["miner", "+96"],
            vec!["miner", "18446744073709551616"],
        ] {
            assert!(
                storage_maintain_resume_arguments(&arguments(
                    "storage-maintain-resume",
                    directory,
                    &tail
                ))
                .is_err()
            );
        }
        assert!(
            storage_maintain_resume_arguments(&arguments(
                "storage-maintain",
                directory,
                &["miner", "96"]
            ))
            .is_err()
        );
    }

    #[test]
    fn restart_check_cli_requires_the_exact_json_flag() {
        let directory = Path::new("unused");
        assert!(
            restart_check_arguments(&arguments("restart-check", directory, &["--json"])).is_ok()
        );
        for flags in [
            vec![],
            vec!["json"],
            vec!["--JSON"],
            vec!["--json", "extra"],
            vec!["--json", "--json"],
        ] {
            assert!(
                restart_check_arguments(&arguments("restart-check", directory, &flags)).is_err()
            );
        }
        assert!(restart_check_arguments(&["restart-check".into()]).is_err());
        assert!(restart_check_arguments(&arguments("check", directory, &["--json"])).is_err());
    }

    #[test]
    fn checkpoint_transition_check_cli_has_no_network_or_cutover_override() {
        let directory = Path::new("unused");
        assert!(
            checkpoint_transition_check_arguments(&arguments(
                "checkpoint-transition-check",
                directory,
                &["--json"],
            ))
            .is_ok()
        );
        for flags in [
            vec![],
            vec!["json"],
            vec!["--JSON"],
            vec!["--json", "10"],
            vec!["--json", "--json"],
        ] {
            assert!(
                checkpoint_transition_check_arguments(&arguments(
                    "checkpoint-transition-check",
                    directory,
                    &flags,
                ))
                .is_err()
            );
        }
        assert!(
            checkpoint_transition_check_arguments(&arguments(
                "restart-check",
                directory,
                &["--json"]
            ))
            .is_err()
        );
    }
}

#[cfg(test)]
mod peer_initialization_tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "siworld-peer-genesis-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn asert() -> Config {
        let fixture = Config::development([83; 32], 0).unwrap();
        Config::asert_development(fixture.network, 1, [0xff; 32], 1)
            .unwrap()
            .with_fund_wallets(
                fixture.fund_allocation.unwrap(),
                fixture.fund_verifying_keys,
            )
            .unwrap()
    }

    #[test]
    fn genesis_identifier_reads_only_validated_rules_and_binds_rule_changes() {
        let parent = Directory::new();
        let source = parent.0.join("source");
        let original = asert();
        local::initialize_config(&source, original.clone()).unwrap();
        // Runtime sentinels are deliberately unusable as files. Reading the
        // public rules must not acquire a lease, open history or read secrets.
        for name in [
            "chain.redb",
            "native-peer-identity.secret",
            "reward-fixture.secret",
            "service-status.json",
        ] {
            std::fs::create_dir(source.join(name)).unwrap();
        }
        let before = std::fs::read(source.join("engineering-network.bin")).unwrap();
        let identifier = genesis_identifier(&source).unwrap();
        assert_eq!(identifier, local::hex(&original.genesis_id()));
        assert_eq!(identifier.len(), 64);
        assert!(
            identifier
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(
            std::fs::read(source.join("engineering-network.bin")).unwrap(),
            before
        );
        assert_eq!(std::fs::read_dir(&source).unwrap().count(), 5);

        let modified = parent.0.join("modified");
        let mut altered = original.clone();
        altered.pow_iterations += 1;
        local::initialize_config(&modified, altered).unwrap();
        assert_eq!(local::load(&modified).unwrap().network, original.network);
        assert_ne!(genesis_identifier(&modified).unwrap(), identifier);

        let mut malformed = before;
        malformed[0] ^= 1;
        std::fs::write(source.join("engineering-network.bin"), malformed).unwrap();
        assert!(genesis_identifier(&source).is_err());
        let absent = parent.0.join("absent");
        assert!(genesis_identifier(&absent).is_err());
        assert!(!absent.exists());
    }

    #[cfg(feature = "native-p2p")]
    #[test]
    fn peer_genesis_requires_the_exact_explicit_genesis_and_an_asert_fund_registry() {
        let parent = Directory::new();
        let source = parent.0.join("source");
        let original = asert();
        local::initialize_config(&source, original.clone()).unwrap();
        let genesis = local::hex(&original.genesis_id());
        assert_eq!(peer_genesis(&source, &genesis).unwrap(), original);
        for invalid in [
            "".to_owned(),
            "0".repeat(63),
            "f".repeat(64),
            "A".repeat(64),
        ] {
            assert!(peer_genesis(&source, &invalid).is_err());
        }
        let fixture = parent.0.join("fixture");
        local::initialize_config(&fixture, Config::development(original.network, 0).unwrap())
            .unwrap();
        let fixture_id = local::hex(&local::load(&fixture).unwrap().genesis_id());
        assert!(peer_genesis(&fixture, &fixture_id).is_err());
        let unallocated = parent.0.join("unallocated");
        local::initialize_config(
            &unallocated,
            Config::asert_development(original.network, 1, [0xff; 32], 1).unwrap(),
        )
        .unwrap();
        let unallocated_id = local::hex(&local::load(&unallocated).unwrap().genesis_id());
        assert!(peer_genesis(&unallocated, &unallocated_id).is_err());
        let modified = parent.0.join("modified");
        let mut altered = original.clone();
        altered.pow_iterations += 1;
        local::initialize_config(&modified, altered).unwrap();
        assert_eq!(local::load(&modified).unwrap().network, original.network);
        assert!(peer_genesis(&modified, &genesis).is_err());
    }

    #[cfg(feature = "native-p2p")]
    #[test]
    fn same_genesis_provisioning_copies_only_public_rules_and_refuses_existing_destinations() {
        let parent = Directory::new();
        let source = parent.0.join("source");
        let target = parent.0.join("target");
        let original = asert();
        local::initialize_config(&source, original.clone()).unwrap();
        // Synthetic sentinels represent source-owned runtime material. They
        // must never be opened, interpreted or copied by genesis provisioning.
        for name in [
            "chain.redb",
            "native-peer-identity.secret",
            "reward-fixture.secret",
            "service-status.json",
        ] {
            std::fs::write(source.join(name), b"synthetic source-only sentinel").unwrap();
        }
        let config = peer_genesis(&source, &local::hex(&original.genesis_id())).unwrap();
        local::initialize_config(&target, config).unwrap();
        assert_eq!(local::load(&target).unwrap(), original);
        assert_eq!(
            local::load(&target).unwrap().genesis_id(),
            original.genesis_id()
        );
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 1);
        assert!(local::initialize_config(&target, original).is_err());
        for name in [
            "chain.redb",
            "native-peer-identity.secret",
            "reward-fixture.secret",
            "service-status.json",
        ] {
            assert!(!target.join(name).exists());
            assert_eq!(
                std::fs::read(source.join(name)).unwrap(),
                b"synthetic source-only sentinel"
            );
        }
    }
}
