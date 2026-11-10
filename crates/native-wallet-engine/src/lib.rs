//! Browser adapter reusing native formats and frozen proof code.

// The portable adapter shares state validation without requiring a native pool.
pub(crate) fn transaction_proof_results<T: Sync>(
    values: &[T],
    verify: &(impl Fn(&T) -> Result<(), String> + Sync),
) -> Vec<Result<(), String>> {
    values.iter().map(verify).collect()
}

#[path = "../../native-node/src/chain_actions.rs"]
pub(crate) mod chain_transition;

#[path = "../../native-node/src/audit.rs"]
pub mod audit;
#[path = "../../native-node/src/fund_spend.rs"]
pub mod fund_spend;
#[path = "../../native-node/src/issuance.rs"]
pub mod issuance;
#[path = "../../native-node/src/proof_codec.rs"]
pub mod proof_codec;
#[path = "../../native-node/src/proofs.rs"]
pub mod proofs;
#[path = "../../native-node/src/state.rs"]
pub mod state;
#[path = "../../native-node/src/wallet.rs"]
pub mod wallet;
#[path = "../../native-node/src/wallet_crypto.rs"]
pub mod wallet_crypto;
#[path = "../../native-node/src/wallet_policy.rs"]
pub mod wallet_policy;
#[path = "../../native-node/src/wire.rs"]
pub mod wire;
pub mod local {
    pub fn hex(b: &[u8]) -> String {
        b.iter().map(|v| format!("{v:02x}")).collect()
    }
}
pub mod commitment;
pub mod compact;
pub mod history;
pub mod light;
pub mod ranges;

pub mod paths;
