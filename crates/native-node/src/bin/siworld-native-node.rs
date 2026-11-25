//! Explicit owner-operated engineering entry point; no implicit initialization.

use siworld_native_node::{eng2::resident, service};
use std::path::Path;

const HELP: &str = "siworld-eng2-node: explicitly selected engineering network\n\ngenesis-id DIRECTORY\nidentity-init DIRECTORY --expected-genesis ID\nidentity-public DIRECTORY --expected-genesis ID\ninit-store DIRECTORY --expected-genesis ID\nqualify-restart DIRECTORY --expected-genesis ID\nrestart-check DIRECTORY --expected-genesis ID\npeer-pin DIRECTORY DESCRIPTOR_FILE FINGERPRINT --expected-genesis ID\nconfigure-miner DIRECTORY holder|voyager ADDRESS_FILE --expected-genesis ID\nbootstrap-signed DIRECTORY PEER_CONFIG POLICY_FILE --expected-genesis ID\nresume-signed DIRECTORY PEER_CONFIG POLICY_FILE --expected-genesis ID\nrun DIRECTORY PEER_CONFIG --expected-genesis ID\nstatus DIRECTORY\nsubmit-operations DIRECTORY PUBLIC_BUNDLE_FILE RUN_ID PARENT NEXT_HEIGHT --expected-genesis ID\noperations-result DIRECTORY RUN_ID\nstop DIRECTORY EXPECTED_RUN_ID\n\nEvery start loads an existing versioned identity and authenticated committed state.\nOnly identity-init explicitly creates a fresh peer identity. No command regenerates keys, migrates V1 state, changes genesis, or falls back to historical replay.\nSigned bootstrap is outbound-only, requires existing independent service pins and explicit resource/work policy, and never starts mining.\nWindows run requires a durable signed import and no listener or checkpoint signing key.\nqualify-restart is a separate explicit native audit of an existing unqualified store.\nProduction requires RAYON_NUM_THREADS=4 and SIWORLD_COMPOSITION_HIDING_WORKERS=2.\nThe eng2-runtime feature is an owner-operated build and is excluded from CI build features.";

fn run(args: &[String]) -> Result<(), String> {
    let result = match args {
        [] => {
            println!("{HELP}");
            return Ok(());
        }
        [flag] if flag == "--help" || flag == "-h" => {
            println!("{HELP}");
            return Ok(());
        }
        [command, directory] if command == "genesis-id" => {
            println!("{}", resident::genesis_identifier(Path::new(directory))?);
            return Ok(());
        }
        [command, directory] if command == "status" => {
            service::exported_status(Path::new(directory))?
        }
        #[cfg(unix)]
        [command, directory, run] if command == "operations-result" => {
            resident::operations_result(Path::new(directory), run)?
        }
        #[cfg(unix)]
        [
            command,
            directory,
            file,
            run,
            parent,
            height,
            flag,
            expected,
        ] if command == "submit-operations" && flag == "--expected-genesis" => {
            resident::submit_operations(
                Path::new(directory),
                Path::new(file),
                run,
                parent,
                height,
                expected,
            )?
        }
        [command, directory, run] if command == "stop" => {
            service::request_stop_expected(Path::new(directory), run)?;
            return Ok(());
        }
        [command, directory, flag, expected] if flag == "--expected-genesis" => {
            match command.as_str() {
                "identity-init" => resident::initialize_identity(Path::new(directory), expected)?,
                "init-store" => resident::initialize_store(Path::new(directory), expected)?,
                "qualify-restart" => resident::qualify_restart(Path::new(directory), expected)?,
                "restart-check" => resident::restart_check(Path::new(directory), expected)?,
                "identity-public" => resident::public_identity(Path::new(directory), expected)?,
                _ => return Err("unknown explicit engineering operation; use --help".into()),
            }
        }
        [command, directory, configuration, flag, expected]
            if command == "run" && flag == "--expected-genesis" =>
        {
            resident::run(Path::new(directory), Path::new(configuration), expected)?;
            return Ok(());
        }
        [command, directory, configuration, policy, flag, expected]
            if (command == "bootstrap-signed" || command == "resume-signed")
                && flag == "--expected-genesis" =>
        {
            resident::bootstrap_signed(
                Path::new(directory),
                Path::new(configuration),
                Path::new(policy),
                expected,
                command == "resume-signed",
            )?
        }
        [command, directory, file, fingerprint, flag, expected]
            if command == "peer-pin" && flag == "--expected-genesis" =>
        {
            resident::pin_peer(Path::new(directory), Path::new(file), fingerprint, expected)?;
            return Ok(());
        }
        [command, directory, mode, file, flag, expected]
            if command == "configure-miner" && flag == "--expected-genesis" =>
        {
            let _lease = service::Lease::acquire(Path::new(directory))?;
            let genesis = resident::load_genesis(Path::new(directory), expected)?;
            let mode = siworld_native_node::state::RewardMode::from_name(mode)
                .map_err(|e| e.to_string())?;
            let address = siworld_native_node::mining::read_address(Path::new(file))?;
            siworld_native_node::mining::save(
                Path::new(directory),
                genesis.config().network,
                &siworld_native_node::producer::MiningSettings {
                    mode,
                    recipient: address,
                },
            )?;
            return Ok(());
        }
        _ => {
            return Err(
                "explicit command arguments and selected genesis required; use --help".into(),
            );
        }
    };
    println!(
        "{}",
        serde_json::to_string(&result).map_err(|_| "public result encoding failed")?
    );
    Ok(())
}
fn main() {
    if let Err(error) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
