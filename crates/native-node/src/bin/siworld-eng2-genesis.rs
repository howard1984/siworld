//! Offline public-parameter genesis sealing; no custody or network commands.
use siworld_native_node::{
    eng2::genesis_tool::{self, Expected},
    local,
};
use std::{ffi::OsString, path::Path};

const HELP: &str = "siworld-eng2-genesis: offline public parameters only\n\nseal-public CONFIG_RULES.bin GOVERNANCE.bin --expected-config-sha256 C --expected-governance-sha256 G --expected-network N --expected-profile P --expected-fee-recipient-sha256 R --new-genesis NEW_FILE --json\ninspect GENESIS.bin --expected-config-sha256 C --expected-governance-sha256 G --expected-network N --expected-profile P --expected-fee-recipient-sha256 R --json\n\nEvery expected value is mandatory lowercase hexadecimal. Outputs are create-only.\nKnown builtin fixture keys are rejected; arbitrary key provenance is not established.\nNo command generates keys, initializes state, starts a service or submits data.";

fn run(args: &[OsString]) -> Result<serde_json::Value, &'static str> {
    let (config, governance, existing, options) = match args {
        [command, config, governance, rest @ ..] if command == "seal-public" => {
            (Some(config), Some(governance), None, rest)
        }
        [command, genesis, rest @ ..] if command == "inspect" => (None, None, Some(genesis), rest),
        _ => return Err("invalid_arguments"),
    };
    let mut config_digest = None;
    let mut governance_digest = None;
    let mut network = None;
    let mut profile = None;
    let mut recipient = None;
    let mut output = None;
    let mut json = false;
    let mut index = 0;
    while index < options.len() {
        if options[index] == "--json" {
            if json {
                return Err("duplicate_argument");
            }
            json = true;
            index += 1;
            continue;
        }
        let value = options.get(index + 1).ok_or("missing_argument")?;
        if options[index] == "--new-genesis" {
            if output.replace(value).is_some() {
                return Err("duplicate_argument");
            }
        } else {
            let slot = match options[index].to_str() {
                Some("--expected-config-sha256") => &mut config_digest,
                Some("--expected-governance-sha256") => &mut governance_digest,
                Some("--expected-network") => &mut network,
                Some("--expected-profile") => &mut profile,
                Some("--expected-fee-recipient-sha256") => &mut recipient,
                _ => return Err("invalid_arguments"),
            };
            if slot
                .replace(genesis_tool::parse_hash(
                    value.to_str().ok_or("invalid_expected_hex")?,
                )?)
                .is_some()
            {
                return Err("duplicate_argument");
            }
        }
        index += 2;
    }
    if !json {
        return Err("missing_json_flag");
    }
    let expected = Expected {
        config_sha256: config_digest.ok_or("missing_expected_value")?,
        governance_sha256: governance_digest.ok_or("missing_expected_value")?,
        network: network.ok_or("missing_expected_value")?,
        profile: profile.ok_or("missing_expected_value")?,
        fee_recipient_sha256: recipient.ok_or("missing_expected_value")?,
    };
    // Complete executable provenance before creating any output file.
    let binary_sha256 = genesis_tool::executable_sha256()?;
    let mut result = match (config, governance, existing, output) {
        (Some(config), Some(governance), None, Some(output)) => genesis_tool::seal_public(
            Path::new(config),
            Path::new(governance),
            Path::new(output),
            expected,
        )?,
        (None, None, Some(existing), None) => genesis_tool::inspect(Path::new(existing), expected)?,
        _ => return Err("invalid_arguments"),
    };
    result["source"]["executed_binary_sha256"] = local::hex(&binary_sha256).into();
    Ok(result)
}

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if matches!(args.as_slice(), [flag] if flag == "--help" || flag == "-h") {
        println!("{HELP}");
        return;
    }
    match run(&args) {
        Ok(result) => println!("{}", serde_json::json!({"ok":true,"result":result})),
        Err(code) => {
            println!(
                "{}",
                serde_json::json!({"ok":false,"error":code,"chain_state_changed":false,"submitted":false,"network_started":false,"partial_output_may_exist":matches!(code,"output_durability_failed"|"output_directory_durability_failed")})
            );
            std::process::exit(1);
        }
    }
}
