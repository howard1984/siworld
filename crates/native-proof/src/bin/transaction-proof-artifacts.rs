//! Reproduce the engineering-frozen native V1 security and public-key bundle.
#![recursion_limit = "256"]
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use siworld_native_proof::{
    FriParams,
    common::FEE_BLIND_LEN,
    envelope::{
        FEE_SIDECAR_BYTES, FEE_SIDECAR_SCHEMA, FIXED_ENVELOPE_BYTES,
        FIXED_SETTLEMENT_ENVELOPE_BYTES, MAX_ENVELOPE_BYTES, MAX_SETTLEMENT_ENVELOPE_BYTES,
        NATIVE_ENVELOPE_SCHEMA, SETTLEMENT_ENVELOPE_SCHEMA,
    },
    fee_settlement_air::SettlementProver,
    native_security::{params_json, settlement_report, transaction_report},
    native_verifier::VerifierArtifact,
    transaction::TransactionProver,
};
use std::{collections::BTreeMap, path::Path};

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn profile(artifact: VerifierArtifact, security: Value) -> Value {
    assert_eq!(security["screen"]["passes_selected_model"], true);
    json!({"security":security,"verifier_artifact_hex":hex(&artifact.encode()),
           "verifier_artifact_sha256":hex(&artifact.sha256())})
}
fn bundle(root: &Path) -> Result<Value, String> {
    let p = FriParams::transaction_candidate();
    let mut sources = BTreeMap::new();
    macro_rules! source {
        ($name:literal, $file:literal) => {
            sources.insert(
                $name,
                sha(&std::fs::read(root.join($file)).map_err(|e| e.to_string())?),
            );
        };
    }
    source!(
        "crates/bench-d8/Cargo.toml",
        "crates/native-proof/Cargo.toml"
    );
    source!(
        "crates/bench-d8/Cargo.lock",
        "crates/native-proof/Cargo.lock"
    );
    source!(".cargo/config.toml", ".cargo/config.toml");
    source!("rust-toolchain.toml", "rust-toolchain.toml");
    source!(
        "crates/bench-d8/src/lib.rs",
        "crates/native-proof/src/lib.rs"
    );
    source!(
        "crates/bench-d8/src/common.rs",
        "crates/native-proof/src/common.rs"
    );
    source!(
        "crates/bench-d8/src/air.rs",
        "crates/native-proof/src/air.rs"
    );
    source!(
        "crates/bench-d8/src/trace.rs",
        "crates/native-proof/src/trace.rs"
    );
    source!(
        "crates/bench-d8/src/transaction.rs",
        "crates/native-proof/src/transaction.rs"
    );
    source!(
        "crates/bench-d8/src/codec.rs",
        "crates/native-proof/src/codec.rs"
    );
    source!(
        "crates/bench-d8/src/encryption.rs",
        "crates/native-proof/src/encryption.rs"
    );
    source!(
        "crates/bench-d8/src/envelope.rs",
        "crates/native-proof/src/envelope.rs"
    );
    source!(
        "crates/bench-d8/src/padding_pool.rs",
        "crates/native-proof/src/padding_pool.rs"
    );
    source!(
        "crates/bench-d8/src/snapshots.rs",
        "crates/native-proof/src/snapshots.rs"
    );
    source!(
        "crates/bench-d8/src/proof_codec.rs",
        "crates/native-proof/src/proof_codec.rs"
    );
    source!(
        "crates/bench-d8/src/fee_settlement.rs",
        "crates/native-proof/src/fee_settlement.rs"
    );
    source!(
        "crates/bench-d8/src/fee_settlement_air.rs",
        "crates/native-proof/src/fee_settlement_air.rs"
    );
    source!(
        "crates/bench-d8/src/native_security.rs",
        "crates/native-proof/src/native_security.rs"
    );
    source!(
        "crates/bench-d8/src/native_verifier.rs",
        "crates/native-proof/src/native_verifier.rs"
    );
    source!(
        "crates/bench-d8/src/bin/v1-freeze-artifacts.rs",
        "crates/native-proof/src/bin/transaction-proof-artifacts.rs"
    );
    source!(
        "scripts/check-v1-freeze.py",
        "scripts/ci/check-transaction-proof-profile.py"
    );
    source!(
        "crates/bench-d8/src/bin/native-verifier-bench.rs",
        "crates/native-proof/src/bin/native-verifier-bench.rs"
    );
    source!(
        "crates/bench-d8/src/bin/v1_transaction_scan.rs",
        "crates/native-proof/src/bin/v1_transaction_scan.rs"
    );
    source!(
        "crates/bench-d8/src/bin/fee-settlement-bench.rs",
        "crates/native-proof/src/bin/fee-settlement-bench.rs"
    );
    source!(
        "scripts/measure-native-cgroup.py",
        "scripts/bench/measure-native-cgroup.py"
    );
    source!(
        "scripts/build-d8-checkpoint.py",
        "scripts/bench/build-recursive-proof-benchmark.py"
    );
    source!(
        "scripts/build-prover-release.py",
        "scripts/bench/build-prover-release.py"
    );
    source!(
        "scripts/prover-launcher.rs",
        "scripts/bench/prover-launcher.rs"
    );
    source!(
        ".github/workflows/d8-native-cgroup.yml",
        "scripts/tests/fixtures/source-provenance/recursive-proof-workflow.txt"
    );
    let transaction = TransactionProver::new(p);
    let tx_artifact = VerifierArtifact::transaction(&transaction)?;
    drop(transaction);
    let settlement = SettlementProver::new(576, p);
    let fee_artifact = VerifierArtifact::settlement(&settlement)?;
    Ok(json!({"schema":1,"status":"engineering-frozen",
        "cryptographic_approval":false,"network_activation":false,
        "suite":"KoalaBear-D8-Poseidon2-W24-digest12-random-codeword-hiding",
        "dependency_revision":"d3d15b2b5d1325fb38ebc8979c1cae04b761e71f",
        "parameters":params_json(p),"source_sha256":sources,
        "profiles":{"transaction":profile(tx_artifact,transaction_report(p)?),
                    "settlement":profile(fee_artifact,settlement_report(p)?)},
        "envelope":{"version":1,
            "transaction_schema":NATIVE_ENVELOPE_SCHEMA,"sidecar_schema":FEE_SIDECAR_SCHEMA,
            "settlement_schema":SETTLEMENT_ENVELOPE_SCHEMA,"prefix_bytes":FIXED_ENVELOPE_BYTES,
            "max_bytes":MAX_ENVELOPE_BYTES,"sidecar_bytes":FEE_SIDECAR_BYTES,
            "settlement_prefix_bytes":FIXED_SETTLEMENT_ENVELOPE_BYTES,
            "settlement_max_bytes":MAX_SETTLEMENT_ENVELOPE_BYTES,
            "permanent_transaction_bytes":1830,"fee_blind_field_elements":FEE_BLIND_LEN,
            "transaction_id_excludes_proof_and_sidecar":true},
        "resources":{"max_leaf_proof_bytes":524288,"max_settlement_proof_bytes":524288,
            "proof_decoder_declared_vector_bytes":4194304,
            "verifier_process_memory_bytes":134217728,"verifier_cpu_ms":250,
            "verifier_wall_timeout_ms":2000,"verifier_processes":2,
            "block576_transaction_cpu_ms":144000,"block576_with_settlement_cpu_ms":144250,
            "verified_pool_bytes":536870912,"verified_pool_count":2048,
            "unverified_queue_bytes":67108864,"unverified_queue_count":128,
            "peer_unverified_bytes":2097152,"peer_unverified_count":4,
            "peer_verified_bytes":16777216,"peer_verified_count":64,
            "negative_cache_bytes":1048576,"negative_cache_count":8192,"negative_cache_ttl_seconds":300,
            "abuse_cache_bytes":1048576,"abuse_cache_count":4096,"abuse_cache_ttl_seconds":600,
            "padding_pool_min":64,"padding_pool_max":128,"padding_pool_bytes":68157440,
            "reconstruction_bytes":671088640,"reconstruction_blocks":2,
            "minimum_uplink_bps":25000000,"max_block_slots":576,"block_target_seconds":300,
            "maximum_reorg_depth":24,"proof_retention_seconds_after_finality":2419200},
        "resource_policy":"local-admission-and-process-isolation-not-consensus-validity",
        "limitations":["Independent cryptographic review remains outstanding",
            "Node and wallet integrations and a new engineering-network genesis remain separate work",
            "Hosted repeated-proof workload is not a valid block or a complete state transition"]}))
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let (root, mode, path) = match args.as_slice() {
        [mode, path] => (Path::new("."), mode.as_str(), Path::new(path)),
        [flag, root, mode, path] if flag == "--root" => {
            (Path::new(root), mode.as_str(), Path::new(path))
        }
        _ => {
            return Err(
                "usage: transaction-proof-artifacts [--root ROOT] --output|--check PATH".into(),
            );
        }
    };
    if !matches!(mode, "--output" | "--check") {
        return Err("invalid freeze operation".into());
    }
    let value = bundle(root)?;
    if mode == "--check" {
        let actual: Value =
            serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        if actual != value {
            return Err("frozen native profile differs from source, key or security report".into());
        }
        println!(
            "Frozen native profile, security reports and public verifier artifacts reproduced."
        );
    } else {
        let bytes = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
        std::fs::write(path, [bytes.as_slice(), b"\n"].concat()).map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
