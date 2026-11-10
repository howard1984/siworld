//! Bounded public projections of already accepted chain data.
//! Private fee openings, wallet records and peer metadata never enter this view.
use crate::{compact::CompactBlock, local::hex, state::State, wire::Hash};
use serde_json::{Value, json};
use std::collections::VecDeque;

pub(super) const HEADER_WINDOW: usize = 101;

#[derive(Clone)]
pub(super) struct Header {
    height: u64,
    hash: Hash,
    parent: Hash,
    timestamp: u64,
    target: Hash,
    slots: usize,
    mode: &'static str,
}

#[derive(Default)]
pub(super) struct Headers(VecDeque<Header>);
impl Headers {
    pub(super) fn clear(&mut self) {
        self.0.clear();
    }
    /// Reuse the compact record already authenticated by the index owner.
    pub(super) fn record(&mut self, record: &CompactBlock) {
        let block = &record.block;
        if self.0.back().is_some_and(|last| {
            block.height != last.height.saturating_add(1) || block.parent != last.hash
        }) {
            self.0.clear();
        }
        self.0.push_back(Header {
            height: block.height,
            hash: record.id,
            parent: block.parent,
            timestamp: block.timestamp,
            target: block.target,
            slots: block.transactions.len(),
            mode: block.reward_mode.name(),
        });
        while self.0.len() > HEADER_WINDOW {
            self.0.pop_front();
        }
    }
    pub(super) fn projection(&self, state: &State, checkpoint: Value, published: u64) -> Value {
        let totals = state.economics.totals();
        let blocks = if self
            .0
            .back()
            .is_some_and(|h| h.height == state.height && h.hash == state.tip)
        {
            self.0
                .iter()
                .map(|h| {
                    json!({
                        "height": h.height, "hash": hex(&h.hash), "parent_hash": hex(&h.parent),
                        "timestamp": h.timestamp, "target": hex(&h.target),
                        "slots_including_padding": h.slots, "reward_mode": h.mode,
                        "work": siworld_core::pow::block_work(&h.target).to_string()
                    })
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let funds = state
            .economics
            .funds()
            .iter()
            .enumerate()
            .map(|(index, fund)| {
                json!({"index":index, "entitled_atoms":fund.entitlement.to_string(),
                "released_atoms":fund.unlocked().ok().map(|n|n.to_string()),
                "spent_atoms":fund.spent.to_string()})
            })
            .collect::<Vec<_>>();
        let schedule = state
            .economics
            .locked_schedule()
            .iter()
            .take(64)
            .map(|(height, atoms)| json!({"height":height,"atoms":atoms.to_string()}))
            .collect::<Vec<_>>();
        json!({
            "version":1,"network":hex(&state.config.network),"genesis":hex(&state.config.genesis_id()),
            "height":state.height,"tip":hex(&state.tip),"published_unix_seconds":published,
            "blocks":blocks,
            "economics":{
                "issued_atoms":totals.issued.to_string(),"burned_atoms":totals.burned.to_string(),
                "holder_pool_atoms":totals.holder_pool.to_string(),
                "locked_reward_atoms":totals.locked_subsidy.to_string(),
                "unlock_schedule":schedule,
                "unlock_schedule_complete":state.economics.locked_schedule().len() <= 64,
                "funds":funds,"circulating_estimate_atoms":null
            },
            "checkpoint":checkpoint,
            "governance":{"current_signers":null,"fee_address":null,"fund_addresses":null,"changes":null}
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Config;

    #[test]
    fn aggregate_projection_is_an_explicit_public_allowlist() {
        let state = State::new(Config::development([17; 32], 0).unwrap()).unwrap();
        let view = Headers::default().projection(&state, Value::Null, 1);
        assert_eq!(view["network"], hex(&state.config.network));
        assert_eq!(view["economics"]["issued_atoms"], "0");
        assert!(view["economics"]["circulating_estimate_atoms"].is_null());
        assert!(view["governance"]["changes"].is_null());
        assert_eq!(view["blocks"].as_array().unwrap().len(), 0);
        let fields = view.as_object().unwrap();
        assert_eq!(fields.len(), 10);
        for disallowed in [
            "fees",
            "transactions",
            "addresses",
            "peers",
            "wallet",
            "nullifiers",
            "commitments",
        ] {
            assert!(!fields.contains_key(disallowed));
        }
    }
}
