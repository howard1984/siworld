//! Measure the native 576-slot settlement relation at its largest fee witness.
//!
//! All slots use the priority fee tier and the Holder reward shape. Fund
//! claims are block-envelope records rather than settlement-AIR inputs; the
//! report therefore records the protocol maximum separately so wire sizing
//! can account for all eight claims without pretending they alter proof bytes.

use p3_field::PrimeCharacteristicRing;
use serde_json::json;
use siworld_multi_asset_experiment::{
    FriParams,
    confidential_fees::{FeeOpening, SettlementSlot},
    multi_asset::{F, FEE_PRIORITY, Hasher, SIP_ASSET_ID},
    settlement::{
        FixedSettlementWitness, HOLDER_UNLOCK_OFFSETS, RewardAllocation, RewardMode,
        RewardNoteWitness, RewardPlan, SettlementProver,
    },
};
use std::{env, fs, path::PathBuf, time::Instant};

const CAPACITY: usize = 576;
const MAX_FUND_CLAIMS: usize = 8;
/// 655,360 B wire cap with the required ten-percent measurement margin.
const SETTLEMENT_ADMISSION_LIMIT: u64 = 589_824;

fn cpu_model() -> Option<String> {
    fs::read_to_string("/proc/cpuinfo")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("model name\t: ").map(str::to_owned))
}

fn validate_full_load(witness: &FixedSettlementWitness) -> Result<(), String> {
    witness
        .check(&Hasher::new())
        .map_err(|error| format!("invalid full-load witness: {error:?}"))?;
    if witness.capacity() != CAPACITY
        || witness.plan.mode != RewardMode::Holder
        || witness.rewards.len() != RewardMode::Holder.note_count()
        || !witness.slots.iter().all(|slot| {
            slot.opening.priority && !slot.opening.dummy && slot.opening.fee == FEE_PRIORITY
        })
    {
        return Err(
            "full-load witness must use 576 priority-fee slots and five Holder rewards".into(),
        );
    }
    Ok(())
}

fn cgroup_dir() -> Option<PathBuf> {
    let text = fs::read_to_string("/proc/self/cgroup").ok()?;
    let relative = text.lines().find_map(|line| line.strip_prefix("0::"))?;
    let path = PathBuf::from("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    path.is_dir().then_some(path)
}

fn memory_peak(path: Option<&PathBuf>) -> Option<u64> {
    let path = path?.join("memory.peak");
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn memory_events(path: Option<&PathBuf>) -> serde_json::Value {
    let Some(path) = path.map(|p| p.join("memory.events")) else {
        return json!({});
    };
    let mut result = serde_json::Map::new();
    if let Ok(text) = fs::read_to_string(path) {
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            if let (Some(name), Some(value)) = (fields.next(), fields.next())
                && let Ok(value) = value.parse::<u64>()
            {
                result.insert(name.to_owned(), json!(value));
            }
        }
    }
    serde_json::Value::Object(result)
}

fn witness() -> FixedSettlementWitness {
    const HEIGHT: u64 = 1_000_000;
    let hasher = Hasher::new();
    let slots = (0..CAPACITY)
        .map(|i| {
            let opening = FeeOpening {
                fee: FEE_PRIORITY,
                blind: core::array::from_fn(|j| F::from_usize(0x10_000 + i * 16 + j)),
                dummy: false,
                priority: true,
            };
            SettlementSlot::from_opening(&hasher, opening)
        })
        .collect::<Vec<_>>();
    let allocations = (0..RewardMode::Holder.note_count())
        .map(|i| RewardAllocation {
            amount: 33_945_245_150u64 / 5 + i as u64,
            unlock_height: HEIGHT
                + if i == 0 {
                    24
                } else {
                    HOLDER_UNLOCK_OFFSETS[i - 1]
                },
        })
        .collect::<Vec<_>>();
    let total_fees = FEE_PRIORITY * CAPACITY as u64;
    let rewards = allocations
        .iter()
        .enumerate()
        .map(|(i, allocation)| RewardNoteWitness {
            asset_id: SIP_ASSET_ID,
            owner: core::array::from_fn(|j| F::from_usize(0x20_000 + i * 32 + j)),
            rseed: core::array::from_fn(|j| F::from_usize(0x30_000 + i * 32 + j)),
            amount: allocation.amount + if i == 0 { total_fees } else { 0 },
        })
        .collect();
    FixedSettlementWitness {
        plan: RewardPlan {
            block_height: HEIGHT,
            mode: RewardMode::Holder,
            allocations,
        },
        network: [9; 32],
        transaction_list_digest: [11; 32],
        rewards,
        slots,
    }
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let output = args
        .iter()
        .position(|arg| arg == "--output")
        .and_then(|index| args.get(index + 1))
        .cloned()
        .unwrap_or_else(|| "settlement-full-load.json".to_owned());
    let trial_count = args
        .iter()
        .position(|arg| arg == "--trials")
        .and_then(|index| args.get(index + 1))
        .map_or(3, |value| {
            value.parse::<usize>().expect("invalid trial count")
        });
    assert!((1..=3).contains(&trial_count), "trial count must be 1..=3");
    assert_eq!(
        env::var("RAYON_NUM_THREADS").as_deref(),
        Ok("4"),
        "full-load measurement requires RAYON_NUM_THREADS=4"
    );
    assert_eq!(p3_maybe_rayon::prelude::current_num_threads(), 4);
    let params = FriParams {
        log_blowup: 8,
        num_queries: 36,
        query_pow_bits: 20,
        commit_pow_bits: 0,
        batch_pow_bits: 20,
        max_log_arity: 1,
    };
    let witness = witness();
    validate_full_load(&witness).expect("full-load witness");
    let started = Instant::now();
    let prover = SettlementProver::new(CAPACITY, params);
    let setup_ns = started.elapsed().as_nanos();
    let cgroup = cgroup_dir();
    let mut trials = Vec::new();
    for trial in 0..trial_count {
        let started = Instant::now();
        let (proof, public) = prover.prove(&witness);
        let generation_ns = started.elapsed().as_nanos();
        let body = postcard::to_allocvec(&proof).expect("proof encoding");
        let started = Instant::now();
        prover.verify(&proof, &public).expect("proof verification");
        let verification_ns = started.elapsed().as_nanos();
        trials.push(json!({
            "trial": trial + 1,
            "proof_body_bytes": body.len(),
            "generation_ns": generation_ns,
            "verification_ns": verification_ns,
            "within_ten_percent_admission_limit": u64::try_from(body.len()).expect("proof body length") <= SETTLEMENT_ADMISSION_LIMIT,
            "memory_peak_bytes": memory_peak(cgroup.as_ref()),
            "memory_events": memory_events(cgroup.as_ref()),
        }));
    }
    let max_proof_body_bytes = trials
        .iter()
        .filter_map(|trial| {
            trial
                .get("proof_body_bytes")
                .and_then(|value| value.as_u64())
        })
        .max()
        .unwrap_or(0);
    let max_generation_ns = trials
        .iter()
        .filter_map(|trial| trial.get("generation_ns").and_then(|value| value.as_u64()))
        .max()
        .unwrap_or(0);
    let max_memory_peak_bytes = trials
        .iter()
        .filter_map(|trial| {
            trial
                .get("memory_peak_bytes")
                .and_then(|value| value.as_u64())
        })
        .max();
    let report = json!({
        "schema": 1,
        "suite": "KoalaBear-D8-Poseidon2-W24-digest12",
        "statement": "native-v1-confidential-miner-note",
        "capacity": 576,
        "cpu_model": cpu_model(),
        "rayon_num_threads": env::var("RAYON_NUM_THREADS").ok(),
        "workers": p3_maybe_rayon::prelude::current_num_threads(),
        "verified": true,
        "setup_ns": setup_ns,
        "fee_tier": "priority",
        "active_fee_slots": 576,
        "reward_note_count": witness.rewards.len(),
        "max_fund_claims": MAX_FUND_CLAIMS,
        "max_proof_body_bytes": max_proof_body_bytes,
        "max_generation_ns": max_generation_ns,
        "max_memory_peak_bytes": max_memory_peak_bytes,
        "settlement_admission_limit_bytes": SETTLEMENT_ADMISSION_LIMIT,
        "within_ten_percent_admission_limit": max_proof_body_bytes <= SETTLEMENT_ADMISSION_LIMIT,
        "parameters": {"log_blowup": 8, "num_queries": 36, "query_pow_bits": 20, "commit_pow_bits": 0, "batch_pow_bits": 20, "max_log_arity": 1},
        "trials": trials,
        "cgroup_detected": cgroup.is_some(),
        "memory_peak_scope": "cumulative peak of the current cgroup, including setup and earlier trials; run one trial per fresh scope for independent peaks",
        "memory_max_bytes": cgroup.as_ref().and_then(|p| fs::read_to_string(p.join("memory.max")).ok()).and_then(|v| v.trim().parse::<u64>().ok()),
        "memory_swap_max_bytes": cgroup.as_ref().and_then(|p| fs::read_to_string(p.join("memory.swap.max")).ok()).and_then(|v| v.trim().parse::<u64>().ok()),
        "max_fund_claims_scope": "block-envelope records; not settlement-AIR inputs",
        "fund_claims_measured": false,
        "fund_claims_code_references": ["crates/native-node/src/wire.rs::MAX_FUND_SPENDS", "crates/native-node/src/state.rs::State::apply", "crates/native-node/src/fund_spend.rs::FundSpend::verify"],
        "reward_plan_scope": "synthetic five-note shape; authenticated consensus reward allocation is checked by the node",
    });
    fs::write(
        output,
        serde_json::to_vec_pretty(&report).expect("report encoding"),
    )
    .expect("report write");
    if max_proof_body_bytes > SETTLEMENT_ADMISSION_LIMIT {
        eprintln!("settlement proof exceeds the 589,824-byte admission measurement limit");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_load_has_exact_capacity_priority_fees_and_all_holder_rewards() {
        let witness = witness();
        validate_full_load(&witness).expect("valid full-load witness");
        assert_eq!(witness.plan.allocations.len(), 5);
        assert_eq!(SETTLEMENT_ADMISSION_LIMIT, 655_360 * 9 / 10);
        assert_eq!(MAX_FUND_CLAIMS, 8);
    }

    #[test]
    fn missing_slot_and_lower_fee_witnesses_cannot_be_reported_as_full_load() {
        let mut missing = witness();
        missing.slots.pop();
        assert!(validate_full_load(&missing).is_err());
        let mut lower_fee = witness();
        lower_fee.slots[0].opening.priority = false;
        assert!(validate_full_load(&lower_fee).is_err());
    }
}
