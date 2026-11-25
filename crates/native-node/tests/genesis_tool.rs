use native::{codec::encode_digest, encryption::PaymentAddress, multi_asset::F};
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest, Sha256};
use siworld_native_node::{
    eng2::{
        genesis::Genesis,
        genesis_tool::{self, Expected},
    },
    eng2_governance::GovernanceState,
    issuance::IssuanceConfig,
    state::Config,
};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "siworld-public-genesis-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

// Syntactically valid public bytes only. These keys have no private counterpart
// created by this test and never belong to an actual network or wallet.
fn address(owner: u32, kem_seed: u8) -> PaymentAddress {
    let mut key = [0; 1184];
    key[1152..].fill(kem_seed);
    PaymentAddress::new([F::from_u32(owner); 12], key).unwrap()
}
fn parameters() -> (Config, GovernanceState, Expected) {
    let network = [0x71; 32];
    let fees = address(1, 7);
    let mut config = Config::asert_development(network, 1234, [0x7f; 32], 17)
        .unwrap()
        .with_fund_wallets(
            siworld_core::v1_economics::FundAllocation::new_bps(vec![5000, 5000], 1).unwrap(),
            vec![[0x31; 1952], [0x32; 1952]],
        )
        .unwrap();
    config.issuance = Some(IssuanceConfig {
        fee_owner: encode_digest(&fees.owner()),
        max_metadata_bytes: 256,
        max_per_block: 4,
    });
    let governance = GovernanceState::new(
        network,
        [0x41; 1952],
        [0x42; 1952],
        [[0x43; 1952], [0x44; 1952], [0x45; 1952]],
        fees,
        vec![address(2, 8), address(3, 9)],
    )
    .unwrap();
    let expected = pins(&config, &governance);
    (config, governance, expected)
}
fn pins(config: &Config, governance: &GovernanceState) -> Expected {
    Expected {
        config_sha256: sha(&config.encode_rules()),
        governance_sha256: sha(&governance.canonical_component_bytes().unwrap()),
        network: config.network,
        profile: genesis_tool::compiled_profile(),
        fee_recipient_sha256: sha(&governance.canonical_fee_destination_bytes().unwrap()),
    }
}
fn write_parameters(
    directory: &Directory,
    config: &Config,
    governance: &GovernanceState,
) -> (PathBuf, PathBuf) {
    let c = directory.file("config.bin");
    let g = directory.file("governance.bin");
    fs::write(&c, config.encode_rules()).unwrap();
    fs::write(&g, governance.canonical_component_bytes().unwrap()).unwrap();
    (c, g)
}

#[test]
fn public_genesis_seal_is_reproducible_and_reconstructs_all_eleven_components() {
    let directory = Directory::new();
    let (config, governance, expected) = parameters();
    let (c, g) = write_parameters(&directory, &config, &governance);
    let first = directory.file("first.bin");
    let second = directory.file("second.bin");
    let a = genesis_tool::seal_public(&c, &g, &first, expected).unwrap();
    let b = genesis_tool::seal_public(&c, &g, &second, expected).unwrap();
    assert_eq!(a, b);
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    let mut inspected = genesis_tool::inspect(&first, expected).unwrap();
    inspected["output_created"] = true.into();
    assert_eq!(a, inspected);
    let parts = a["h0"]["components"].as_array().unwrap();
    assert_eq!(parts.len(), 11);
    for (index, part) in parts.iter().enumerate() {
        assert_eq!(part["id"], index + 1);
        assert_eq!(part["component_digest"].as_str().unwrap().len(), 64);
    }
    assert_eq!(parts[1]["execution_bytes"], 58);
    assert_eq!(parts[2]["execution_bytes"], 42);
    assert_ne!(parts[1]["execution_bytes"], parts[1]["snapshot_bytes"]);
    assert_ne!(parts[2]["execution_bytes"], parts[2]["snapshot_bytes"]);
    assert_eq!(a["h0"]["execution_commitment"].as_str().unwrap().len(), 64);
    assert_eq!(a["parameters"]["checkpoint_threshold"], 2);
    assert_eq!(a["source"]["source_commit_verified"], false);
    assert!(genesis_tool::seal_public(&c, &g, &first, expected).is_err());
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    let run = Command::new(env!("CARGO_BIN_EXE_siworld-eng2-genesis"))
        .arg("inspect")
        .arg(&first)
        .args([
            "--expected-config-sha256",
            &siworld_native_node::local::hex(&expected.config_sha256),
            "--expected-governance-sha256",
            &siworld_native_node::local::hex(&expected.governance_sha256),
            "--expected-network",
            &siworld_native_node::local::hex(&expected.network),
            "--expected-profile",
            &siworld_native_node::local::hex(&expected.profile),
            "--expected-fee-recipient-sha256",
            &siworld_native_node::local::hex(&expected.fee_recipient_sha256),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(run.status.success());
    assert!(run.stderr.is_empty());
    let cli: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
    assert_eq!(cli["ok"], true);
    assert_eq!(cli["result"]["h0"], a["h0"]);
    assert_eq!(
        cli["result"]["source"]["executed_binary_sha256"],
        siworld_native_node::local::hex(&sha(&fs::read(env!(
            "CARGO_BIN_EXE_siworld-eng2-genesis"
        ))
        .unwrap()))
    );
}

#[test]
fn public_genesis_rejects_independent_pin_and_complete_recipient_substitution() {
    let directory = Directory::new();
    let (config, governance, expected) = parameters();
    let (c, g) = write_parameters(&directory, &config, &governance);
    for field in 0..5 {
        let mut wrong = expected;
        match field {
            0 => wrong.config_sha256[0] ^= 1,
            1 => wrong.governance_sha256[0] ^= 1,
            2 => wrong.network[0] ^= 1,
            3 => wrong.profile[0] ^= 1,
            _ => wrong.fee_recipient_sha256[0] ^= 1,
        }
        assert!(genesis_tool::seal_public(&c, &g, &directory.file("absent.bin"), wrong).is_err());
        assert!(!directory.file("absent.bin").exists());
    }
    let mut wrong_config = config.clone();
    wrong_config.issuance.as_mut().unwrap().fee_owner = encode_digest(&address(4, 7).owner());
    let updated = pins(&wrong_config, &governance);
    write_parameters(&directory, &wrong_config, &governance);
    assert_eq!(
        genesis_tool::seal_public(&c, &g, &directory.file("absent.bin"), updated),
        Err("fee_recipient_mismatch")
    );
    let different = GovernanceState::new(
        config.network,
        [0x41; 1952],
        [0x42; 1952],
        [[0x43; 1952], [0x44; 1952], [0x45; 1952]],
        address(1, 77),
        vec![address(2, 8), address(3, 9)],
    )
    .unwrap();
    assert_eq!(
        different.active_fee_destination().owner(),
        governance.active_fee_destination().owner()
    );
    let mut updated = pins(&config, &different);
    updated.fee_recipient_sha256 = expected.fee_recipient_sha256;
    write_parameters(&directory, &config, &different);
    assert_eq!(
        genesis_tool::seal_public(&c, &g, &directory.file("absent.bin"), updated),
        Err("fee_recipient_mismatch")
    );
}

#[test]
fn public_genesis_refuses_fixture_zero_work_and_known_builtin_public_keys() {
    let directory = Directory::new();
    let (config, governance, _) = parameters();
    let mut fixture = Config::development(config.network, 0).unwrap();
    fixture.fund_allocation = config.fund_allocation.clone();
    fixture.fund_verifying_keys = config.fund_verifying_keys.clone();
    fixture.issuance = config.issuance.clone();
    let expected = pins(&fixture, &governance);
    let (c, g) = write_parameters(&directory, &fixture, &governance);
    assert_eq!(
        genesis_tool::seal_public(&c, &g, &directory.file("absent.bin"), expected),
        Err("fixture_or_nonproduction_rules")
    );
    let mut no_work = config.clone();
    no_work.pow_iterations = 0;
    let expected = pins(&no_work, &governance);
    write_parameters(&directory, &no_work, &governance);
    assert!(genesis_tool::seal_public(&c, &g, &directory.file("absent.bin"), expected).is_err());
    // Only the already-public built-in fixture derivations are evaluated.
    let mut fixture_keys = Config::development(config.network, 0)
        .unwrap()
        .fund_verifying_keys;
    for value in 1..=5 {
        let mut pair = libcrux_ml_dsa::ml_dsa_65::generate_key_pair([value; 32]);
        fixture_keys.push(*pair.verification_key.as_ref());
        pair.signing_key.as_mut_slice().fill(0);
    }
    fixture_keys.extend(
        Config::asert_development(config.network, 1234, [0x7f; 32], 17)
            .unwrap()
            .with_test_fund_registry()
            .unwrap()
            .fund_verifying_keys,
    );
    for key in fixture_keys {
        let mut rejected = config.clone();
        rejected.fund_verifying_keys[0] = key;
        let expected = pins(&rejected, &governance);
        write_parameters(&directory, &rejected, &governance);
        assert_eq!(
            genesis_tool::seal_public(&c, &g, &directory.file("absent.bin"), expected),
            Err("known_builtin_fixture_key")
        );
    }
    assert!(!directory.file("absent.bin").exists());
}

#[test]
fn public_genesis_files_are_bounded_and_cli_errors_never_echo_inputs() {
    let directory = Directory::new();
    let (config, governance, expected) = parameters();
    let (c, g) = write_parameters(&directory, &config, &governance);
    let output = directory.file("genesis.bin");
    genesis_tool::seal_public(&c, &g, &output, expected).unwrap();
    let bytes = fs::read(&output).unwrap();
    assert!(Genesis::decode(&bytes).is_ok());
    for corrupt in [
        bytes[..bytes.len() - 1].to_vec(),
        [bytes.clone(), vec![0]].concat(),
    ] {
        let bad = directory.file("bad.bin");
        fs::write(&bad, corrupt).unwrap();
        assert!(genesis_tool::inspect(&bad, expected).is_err());
    }
    fs::write(&g, vec![0; genesis_tool::MAX_GOVERNANCE_BYTES + 1]).unwrap();
    assert!(genesis_tool::seal_public(&c, &g, &directory.file("absent.bin"), expected).is_err());
    #[cfg(unix)]
    {
        let link = directory.file("link.bin");
        std::os::unix::fs::symlink(&c, &link).unwrap();
        assert!(
            genesis_tool::seal_public(&link, &g, &directory.file("absent.bin"), expected).is_err()
        );
        std::os::unix::fs::symlink(&output, directory.file("output-link.bin")).unwrap();
        write_parameters(&directory, &config, &governance);
        assert!(
            genesis_tool::seal_public(&c, &g, &directory.file("output-link.bin"), expected)
                .is_err()
        );
        assert_eq!(fs::read(&output).unwrap(), bytes);
    }
    let run = Command::new(env!("CARGO_BIN_EXE_siworld-eng2-genesis"))
        .args([
            "inspect",
            "DO_NOT_ECHO_PRIVATE_MARKER",
            "--expected-network",
            "SECRET_MARKER",
        ])
        .output()
        .unwrap();
    assert!(!run.status.success());
    assert!(run.stderr.is_empty());
    let text = String::from_utf8(run.stdout).unwrap();
    assert!(!text.contains("MARKER"));
    let response: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(response["ok"], false);
    assert_eq!(response["network_started"], false);
    assert!(!directory.file("absent.bin").exists());
}

#[test]
fn public_genesis_cli_requires_each_independent_expected_value() {
    let hash = "11".repeat(32);
    let flags = [
        "--expected-config-sha256",
        "--expected-governance-sha256",
        "--expected-network",
        "--expected-profile",
        "--expected-fee-recipient-sha256",
    ];
    for missing in flags {
        let mut args = vec!["inspect".to_owned(), "unused-public-file.bin".to_owned()];
        for flag in flags {
            if flag != missing {
                args.extend([flag.to_owned(), hash.clone()]);
            }
        }
        args.push("--json".to_owned());
        let run = Command::new(env!("CARGO_BIN_EXE_siworld-eng2-genesis"))
            .args(args)
            .output()
            .unwrap();
        assert!(!run.status.success());
        assert!(run.stderr.is_empty());
        let response: serde_json::Value = serde_json::from_slice(&run.stdout).unwrap();
        assert_eq!(response["error"], "missing_expected_value");
    }
}
