//! Native V1 engineering chain and network interfaces, separate from the retained node.
#![forbid(unsafe_code)]

pub(crate) mod chain_transition;

#[cfg(all(feature = "checkpoint-rejection-acceptance", unix))]
pub mod checkpoint_rejection_acceptance;
#[cfg(feature = "native-p2p")]
pub(crate) mod checkpoint_service;
#[cfg(all(feature = "native-p2p", feature = "checkpoint-stale-acceptance", unix))]
pub mod checkpoint_stale_runtime;
pub mod eng2;
pub(crate) use eng2::header as wallet_eng2_header;
pub mod eng2_economics;
pub mod eng2_fund;
pub mod eng2_governance;
#[cfg(unix)]
pub mod eng2_materials;
pub mod eng2_operations;
pub mod eng2_settlement;
pub mod eng2_settlement_air;
pub mod engineering_checkpoint;
pub mod engineering_genesis;
pub mod fund_spend;
pub mod issuance;
pub mod local;
pub mod local_payment;
pub mod mining;
pub mod pool;
pub mod producer;
pub mod proof_codec;
pub mod proof_storage;
pub mod proofs;
pub mod service;
pub mod state;
pub(crate) mod storage_budget;
pub mod storage_policy;
pub mod store;
pub mod wire;

pub(crate) fn transaction_proof_results<T: Sync>(
    values: &[T],
    verify: &(impl Fn(&T) -> Result<(), String> + Sync),
) -> Vec<Result<(), String>> {
    use rayon::prelude::*;
    values.par_iter().map(verify).collect()
}

pub mod admission;
pub mod audit;
pub mod chain;
pub mod identity;
pub mod p2p;
pub mod peer_scheduler;
pub mod runtime;
pub mod sync;
pub mod wallet;
pub(crate) mod wallet_balance_view;
pub mod wallet_cli;
pub(crate) mod wallet_crypto;
pub mod wallet_policy;
pub mod wallet_vault;
pub mod web_wallet;

#[cfg(test)]
mod fixtures;

#[cfg(feature = "wallet-light-gateway")]
#[path = "../../native-wallet-engine/src/commitment.rs"]
pub mod commitment;
#[path = "../../native-wallet-engine/src/compact.rs"]
pub mod compact;
#[path = "../../native-wallet-engine/src/ranges.rs"]
pub mod ranges;
#[cfg(all(feature = "wallet-light-gateway", unix))]
pub mod wallet_gateway;

#[cfg(all(unix, feature = "eng2-rehearsal", feature = "eng2-runtime"))]
pub use eng2::wallet_history::codec as eng2_history;
#[cfg(all(unix, feature = "eng2-rehearsal", feature = "eng2-runtime"))]
#[path = "../../native-wallet-engine/src/eng2_light.rs"]
pub mod eng2_light;
#[cfg(all(unix, feature = "eng2-rehearsal", feature = "eng2-runtime"))]
#[path = "../../native-wallet-engine/src/paths.rs"]
pub mod paths;
