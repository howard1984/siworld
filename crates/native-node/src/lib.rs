//! Native V1 engineering chain and network interfaces, separate from the retained node.
#![forbid(unsafe_code)]

#[cfg(all(feature = "checkpoint-rejection-acceptance", unix))]
pub mod checkpoint_rejection_acceptance;
#[cfg(feature = "native-p2p")]
pub(crate) mod checkpoint_service;
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
