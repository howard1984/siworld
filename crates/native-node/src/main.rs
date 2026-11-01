//! Disposable native engineering CLI. No retained-network adapter or reset.
use siworld_native_node::{
    audit, local, producer,
    proofs::{NativeProver, NativeVerifier},
    service,
    state::Config,
    store::Store,
};
use std::path::Path;
fn help() {
    println!(
        "siworld-native-node: isolated native V1 engineering network\n\ninit DIRECTORY [WORK_BITS]  Create a cheap development fixture\ninit-service DIRECTORY     Create a new ASERT network with initialization-only calibration\nidentity-init DIRECTORY    Explicitly create persistent dual peer identities\nidentity-public DIRECTORY  Export the verified public dual-signed descriptor\nconfigure-miner DIRECTORY MODE ADDRESS_FILE  Select voyager/holder and a backed-up wallet address\nrun DIRECTORY              Run continuous native production; requires four proving workers\nstop DIRECTORY             Request run-bound graceful stop and final verification\nservice-status DIRECTORY   Read the private atomic service export\nstatus DIRECTORY           Show exported service status or independently replay an idle store\ncheck DIRECTORY            Replay every proof and check every local reward receipt\naudit DIRECTORY            Independently replay public subsidy and fund-credit counters\nmine DIRECTORY [SLOTS]     Produce and atomically accept one native block (64..576, groups of 16)\n\nRAYON_NUM_THREADS=4 and SIWORLD_COMPOSITION_HIDING_WORKERS=2 are required for run.\nA completed 24-hour observation does not automatically stop the service.\nNo reset, migration, peer listener, issuance RPC listener, or public-network activation is provided."
    );
    println!("\n{}", siworld_native_node::wallet_cli::HELP);
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
fn exact(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        Err("unexpected argument".into())
    } else {
        Ok(())
    }
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        help();
        return Ok(());
    }
    cpu_admission()?;
    if args.len() < 2 || args.len() > 4 {
        return Err("expected command and explicit engineering directory; use --help".into());
    }
    let path = Path::new(&args[1]);
    match args[0].as_str() {
        "wallet-create" | "wallet-restore" | "wallet-address" | "wallet-configure-miner" => {
            siworld_native_node::wallet_cli::run(&args[0], &args[1..])?;
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
        "run" => {
            exact(&args)?;
            service::run(path)?;
        }
        "stop" => {
            exact(&args)?;
            service::request_stop(path)?;
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
        "status" | "check" | "audit" => {
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
            if args[0] == "check" {
                for height in 1..=store.state().height {
                    let block = store.block(height)?;
                    let id = block.id()?;
                    let secret = local::read_reward(path, &id)?;
                    producer::validate_reward_secret(&block, &secret)?;
                }
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
            let mut store =
                Store::open_existing(path.join("chain.redb"), config(path)?, &verifier)?;
            let prover = NativeProver::new()?;
            let settings = siworld_native_node::mining::load(path, store.state().config.network)?;
            let produced = producer::produce(store.state(), &prover, slots, &settings)?;
            let id = produced.block.id()?;
            producer::validate_reward_secret(&produced.block, &produced.reward_secret)?;
            local::save_reward(path, &id, &produced.reward_secret)?;
            store.append(&produced.block, &verifier)?;
            println!(
                "accepted engineering block: height={}, tip={}",
                store.state().height,
                local::hex(&store.state().tip)
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
