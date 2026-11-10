//! Isolated native multi-asset transaction, issuance and settlement proofs.
//! These relations do not activate a retained or public network.
#![allow(clippy::needless_range_loop)]

pub use native_base::{Cfg, FriParams};
pub use native_base::{air, common, fee_settlement, proof_codec};
pub mod codec;
pub mod confidential_fees;
pub mod encryption;
pub mod issuance;
pub mod issuance_air;
pub mod multi_asset;
pub mod multi_asset_air;
pub mod multi_asset_trace;
pub mod multi_asset_transaction;
#[cfg(feature = "security-report")]
pub mod security;
pub mod settlement;

#[cfg(test)]
mod economic_rewards_tests;
