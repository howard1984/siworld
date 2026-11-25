//! Fixed-capacity fee settlement measurements for the private evaluation bundle.
//!
//! Run this binary inside the qualified independent cgroup. One-time AIR/key
//! setup is outside the three timing samples; each capacity is proved three
//! times and verified once per sample.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde_json::json;
use sha2::{Digest, Sha256};
use siworld_native_proof::FriParams;
use siworld_native_proof::common::{self, FEE_BASE, Hasher};
use siworld_native_proof::fee_settlement::{FeeOpening, SettlementSlot};
use siworld_native_proof::fee_settlement_air::{FixedSettlementWitness, SettlementProver};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const CAPACITIES: [usize; 6] = [64, 128, 256, 384, 512, 576];

fn cgroup_dir() -> Option<PathBuf> {
    // cgroup v2 reports the process membership as `0::<relative path>`.
    // Reading the membership avoids accidentally sampling the host/root
    // cgroup when the benchmark is launched in an independent delegated
    // group.  The fallback also supports the root cgroup used by local
    // diagnostics.
    if let Ok(text) = fs::read_to_string("/proc/self/cgroup") {
        for line in text.lines() {
            if let Some(relative) = line.strip_prefix("0::") {
                let path = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
                if path.is_dir() {
                    return Some(path);
                }
            }
        }
    }
    let root = PathBuf::from("/sys/fs/cgroup");
    root.is_dir().then_some(root)
}

fn peak_bytes(cgroup: Option<&Path>) -> (u64, &'static str) {
    if let Some(dir) = cgroup {
        if let Ok(s) = fs::read_to_string(dir.join("memory.peak"))
            && let Ok(v) = s.trim().parse()
        {
            return (v, "cgroup");
        }
        if let Ok(s) = fs::read_to_string(dir.join("memory.current"))
            && let Ok(v) = s.trim().parse()
        {
            return (v, "cgroup-current");
        }
    }
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("VmHWM:")
                && let Some(kib) = value
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
            {
                return (kib.saturating_mul(1024), "vmhwm");
            }
        }
    }
    (0, "unavailable")
}

fn cgroup_value(cgroup: Option<&Path>, name: &str) -> Option<u64> {
    let path = cgroup?.join(name);
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn cgroup_events(cgroup: Option<&Path>) -> serde_json::Value {
    let text = cgroup
        .map(|dir| dir.join("memory.events"))
        .and_then(|path| fs::read_to_string(path).ok())
        .unwrap_or_default();
    let mut out = serde_json::Map::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if let (Some(key), Some(value)) = (fields.next(), fields.next())
            && let Ok(v) = value.parse::<u64>()
        {
            out.insert(key.to_owned(), json!(v));
        }
    }
    serde_json::Value::Object(out)
}
fn sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn digest_hex(digest: &common::Digest) -> String {
    let mut bytes = Vec::with_capacity(digest.len() * 4);
    for element in digest {
        bytes.extend_from_slice(&element.as_canonical_u32().to_le_bytes());
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn witness(capacity: usize) -> FixedSettlementWitness {
    let hasher = Hasher::new();
    let mut slots = Vec::with_capacity(capacity);
    slots.push(SettlementSlot::from_opening(
        &hasher,
        FeeOpening::standard(core::array::from_fn(|i| common::F::from_u32(i as u32 + 1))),
    ));
    for i in 1..capacity {
        let blind = core::array::from_fn(|k| {
            common::F::from_u32(1000 + (i * common::FEE_BLIND_LEN + k) as u32)
        });
        slots.push(SettlementSlot::from_opening(
            &hasher,
            FeeOpening::dummy(blind),
        ));
    }
    FixedSettlementWitness {
        issuance_reward: 100,
        miner_amount: 100 + FEE_BASE,
        block_height: 1000,
        network: [9; 32],
        transaction_list_digest: [11; 32],
        miner_owner: core::array::from_fn(|k| common::F::from_u32(800 + k as u32)),
        miner_rseed: core::array::from_fn(|k| common::F::from_u32(900 + k as u32)),
        slots,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output = args
        .iter()
        .position(|arg| arg == "--output")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "fee-settlement-measurements.json".to_owned());
    let capacities: Vec<usize> = args
        .iter()
        .position(|arg| arg == "--capacity")
        .and_then(|i| args.get(i + 1))
        .map(|value| vec![value.parse().expect("invalid capacity")])
        .unwrap_or_else(|| CAPACITIES.to_vec());
    let requested_trials: usize = args
        .iter()
        .position(|arg| arg == "--trials")
        .map(|i| {
            args.get(i + 1)
                .expect("--trials requires a value")
                .parse()
                .expect("invalid trial count")
        })
        .unwrap_or(3);
    assert!(
        (1..=3).contains(&requested_trials),
        "trial count must be 1..=3"
    );
    let fast = args.iter().any(|arg| arg == "--fast");
    let legacy_candidate = args.iter().any(|arg| arg == "--legacy-candidate");
    let fri_params = if fast {
        FriParams::fast()
    } else if legacy_candidate {
        FriParams::candidate()
    } else {
        FriParams::transaction_candidate()
    };
    let fri_profile = if fast {
        "diagnostic-fast"
    } else if legacy_candidate {
        "legacy-recursive-candidate"
    } else {
        "transaction-candidate-diagnostic"
    };
    let cgroup = cgroup_dir();
    let worker_count = std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .or_else(|| std::thread::available_parallelism().ok().map(usize::from));
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/fee_settlement_air.rs");
    let source_hash = fs::read(&source)
        .map(|b| sha256(&b))
        .unwrap_or_else(|_| "0".repeat(64));
    let binary_hash = std::env::current_exe()
        .ok()
        .and_then(|p| fs::read(p).ok())
        .map(|b| sha256(&b))
        .unwrap_or_else(|| "0".repeat(64));
    let mut records = Vec::new();
    for capacity in &capacities {
        let capacity = *capacity;
        let witness = witness(capacity);
        let input_digests: Vec<String> = witness
            .slots
            .iter()
            .map(|slot| digest_hex(&slot.commitment))
            .collect();
        let prover = SettlementProver::new(capacity, fri_params);
        let constraint_count = prover.air.constraint_count(&witness);
        let key_bytes = postcard::to_allocvec(&prover.vk.commitment)
            .expect("serialize preprocessed verifier commitment");
        let key_hash = sha256(&key_bytes);
        let mut trials = Vec::new();
        for _ in 0..requested_trials {
            let start = Instant::now();
            let (proof, pis) = prover.prove(&witness);
            let generation_ms = start.elapsed().as_millis() as u64;
            let (prover_peak_bytes, prover_peak_source) = peak_bytes(cgroup.as_deref());
            let start = Instant::now();
            prover
                .verify(&proof, &pis)
                .expect("settlement proof verification");
            let verification_ms = start.elapsed().as_millis() as u64;
            let (verifier_peak_bytes, verifier_peak_source) = peak_bytes(cgroup.as_deref());
            trials.push(json!({
                "generation_ms": generation_ms,
                "verification_ms": verification_ms,
                "proof_bytes": postcard::to_allocvec(&proof).expect("serialize proof").len(),
                "prover_peak_bytes": prover_peak_bytes,
                "verifier_peak_bytes": verifier_peak_bytes,
                "prover_peak_source": prover_peak_source,
                "verifier_peak_source": verifier_peak_source,
            }));
        }
        records.push(json!({
            "capacity": capacity,
            "shape": {
                "air_rows": prover.air.height,
                "main_columns": prover.air.main_width(),
                "preprocessed_columns": prover.air.preprocessed_width(),
                "constraint_count": constraint_count,
                "max_constraint_degree": 3,
            },
            "trials": trials,
            "input_digests": input_digests,
            "artifacts": {
                "air_source_sha256": source_hash,
                "verifier_key_sha256": key_hash,
                "binary_sha256": binary_hash,
            },
        }));
    }
    let report = json!({
        "schema": 2,
        "settlement_statement": "confidential-miner-note-v1",
        "suite": "KoalaBear-D8-Poseidon2-W24-digest12",
        "fri_profile": fri_profile,
        "compiler_profile": "release",
        "worker_count": worker_count,
        "commitment_bytes_per_transaction": 48,
        "capacities": capacities,
        "records": records,
        "measurement": {
            "memory_max_bytes": cgroup_value(cgroup.as_deref(), "memory.max"),
            "swap_max_bytes": cgroup_value(cgroup.as_deref(), "memory.swap.max"),
            "memory_events": cgroup_events(cgroup.as_deref()),
            "cgroup_detected": cgroup.is_some(),
            "setup_excluded": true,
        },
    });
    fs::write(
        &output,
        serde_json::to_vec_pretty(&report).expect("encode report"),
    )
    .expect("write report");
}
