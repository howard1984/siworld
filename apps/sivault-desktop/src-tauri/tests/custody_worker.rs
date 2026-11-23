#![cfg(any(target_os = "macos", all(windows, debug_assertions)))]

use siworld_native_wallet_core::{network, vault::Material};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn worker(operation: &str, path: &Path, inputs: &[&str], prefix: &[u8]) -> serde_json::Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sivault-desktop"));
    command
        .env_remove("SIVAULT_DEV_WALLET")
        .env_remove("SIVAULT_DEV_WALLET_ORIGIN");
    run_worker(command, operation, path, inputs, prefix)
}

fn run_worker(
    command: Command,
    operation: &str,
    path: &Path,
    inputs: &[&str],
    prefix: &[u8],
) -> serde_json::Value {
    let reply = run_worker_reply(command, operation, path, inputs, prefix);
    assert_eq!(reply["status"], "open");
    reply["wallet"].clone()
}

fn run_worker_reply(
    mut command: Command,
    operation: &str,
    path: &Path,
    inputs: &[&str],
    prefix: &[u8],
) -> serde_json::Value {
    let mut child = command
        .args(["--sivault-wallet-worker", operation])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for input in inputs {
            stdin
                .write_all(&u16::try_from(input.len()).unwrap().to_be_bytes())
                .unwrap();
            stdin.write_all(input.as_bytes()).unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let mut result = output.stdout.strip_prefix(prefix).unwrap();
    if operation == "send" && result.first() == Some(&b'T') {
        let length = u16::from_be_bytes(result[1..3].try_into().unwrap()) as usize;
        result = result[3 + length..].strip_prefix(b"D").unwrap();
    } else if operation == "send" {
        result = result.strip_prefix(b"D").unwrap();
    }
    serde_json::from_slice(result).unwrap()
}

#[test]
fn synthetic_custody_over_child_pipes() {
    let network =
        network("06fa3ed71960f2d6add484afba453091a2536e718234df1187f33c0f7dcf5b5d").unwrap();
    let material = Material::generate(network, 0).unwrap();
    let words = material.words();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("fixture.swnvlt");
    let password = "synthetic child pipe fixture";
    let restored = worker("restore", &path, &[&words, password], b"RPD");
    let full = restored["address"].as_str().unwrap();
    let short = restored["short_address"].as_str().unwrap();
    assert!(full.starts_with("sivf1"));
    assert!(short.starts_with("tsi1p"));
    assert_eq!(short.len(), 63);
    assert_eq!(worker("unlock", &path, &[password], b"UD"), restored);
}

#[test]
#[ignore = "requires an owner-controlled loopback development wallet bridge"]
#[cfg(all(feature = "dev-wallet-chain", debug_assertions))]
fn synthetic_reward_from_verified_isolated_receipts() {
    let scope = std::env::var("SIVAULT_DEV_WALLET").expect("isolated wallet scope");
    let endpoint = std::env::var("SIVAULT_DEV_WALLET_ORIGIN").expect("loopback wallet bridge");
    let network = network(scope.split(':').next().unwrap()).unwrap();
    let material = Material {
        network,
        account: 0,
        entropy: [42; 32].into(),
    };
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("synthetic.swnvlt");
    let password = "synthetic reward pipe fixture";
    let mut command = Command::new(env!("CARGO_BIN_EXE_sivault-desktop"));
    command
        .env("SIVAULT_DEV_WALLET", scope)
        .env("SIVAULT_DEV_WALLET_ORIGIN", endpoint);
    let opened = run_worker(
        command,
        "restore",
        &path,
        &[&material.words(), password],
        b"RPD",
    );
    let chain = &opened["chain"];
    assert!(chain["height"].as_u64().is_some_and(|height| height >= 2));
    assert!(
        chain["history"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["kind"] == "mining")
    );
}

#[test]
#[ignore = "broadcasts synthetic payments to an owner-controlled isolated development chain"]
#[cfg(all(feature = "dev-wallet-chain", debug_assertions))]
fn synthetic_short_address_payment() {
    use siworld_native_wallet_core::{
        hex, hex_array,
        identity::Identity,
        recipient::{Descriptor, Network},
    };
    use siworld_native_wallet_engine::state::base_fee;
    let scope = std::env::var("SIVAULT_DEV_WALLET").expect("isolated wallet scope");
    let endpoint = std::env::var("SIVAULT_DEV_WALLET_ORIGIN").expect("loopback wallet bridge");
    let fields: Vec<_> = scope.split(':').collect();
    let network = network(fields[0]).unwrap();
    let genesis = hex_array(fields[1]).unwrap();
    let (sender, receiver) = match fields[2] {
        "a" => (42, 43),
        "b" => (43, 42),
        _ => panic!("expected fixed synthetic fixtures"),
    };
    // No test seed is usable against a distribution or non-development scope.
    assert!(endpoint.starts_with("http://127.0.0.1:"));
    let directory =
        std::env::var_os("SIVAULT_DEV_PAYMENT_TEST_DIR").expect("synthetic fixture directory");
    let directory = Path::new(&directory);
    assert!(directory.is_absolute() && directory.is_dir());
    let path = directory.join(format!("synthetic-{}.swnvlt", fields[2]));
    let password = "synthetic payment pipe fixture";
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sivault-desktop"));
        command
            .env("SIVAULT_DEV_WALLET", &scope)
            .env("SIVAULT_DEV_WALLET_ORIGIN", &endpoint);
        command
    };
    let active = if path.exists() {
        run_worker(command(), "unlock", &path, &[password], b"UD")
    } else {
        let material = Material {
            network,
            account: 0,
            entropy: [sender; 32].into(),
        };
        run_worker(
            command(),
            "restore",
            &path,
            &[&material.words(), password],
            b"RPD",
        )
    };
    let height = active["chain"]["height"]
        .as_u64()
        .expect("wallet did not verify the isolated head");
    assert!(height >= 26);
    let phase = std::env::var("SIVAULT_DEV_PAYMENT_TEST_PHASE");
    if phase.as_deref() == Ok("verify") {
        let payment = &active["chain"]["payment"];
        assert!(
            payment["height"].as_u64().is_some(),
            "payment is not included yet"
        );
        println!("Synthetic payment included in block {}.", payment["height"]);
        return;
    }
    if phase.as_deref() == Ok("retry") {
        let reply = run_worker_reply(command(), "retry_payment", &path, &[password], b"UD");
        assert_eq!(reply["status"], "sent", "{reply}");
        assert_eq!(reply["payment"]["acknowledged"], true);
        return;
    }
    let identity = Identity::derive(&[receiver; 32].into(), network, 0).unwrap();
    let descriptor = Descriptor::new_v2(Network::Testnet, genesis, identity.address()).unwrap();
    let amount = if sender == 42 {
        100_000_000
    } else {
        10_000_000
    };
    let payload = serde_json::json!({
        "address": descriptor.short_address().encode(), "descriptor": hex(descriptor.encode()),
        "amount": amount, "fee": base_fee(height),
    })
    .to_string();
    let reply = run_worker_reply(
        command(),
        "send",
        &path,
        &[&payload, password, "confirmed"],
        b"U",
    );
    assert_eq!(reply["status"], "sent", "{reply}");
    assert_eq!(reply["payment"]["acknowledged"], true);
    assert!(reply["payment"]["height"].is_null());
}
