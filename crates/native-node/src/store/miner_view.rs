//! Private cumulative earned rewards, never a claim about unspent wallet funds.
use super::*;
use serde_json::{Value, json};

impl Store {
    pub fn miner_reward_view(&self) -> Result<Value, String> {
        self.require_local_reward_index()?;
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "reward display database unavailable")?;
        let local = transaction
            .open_table(LOCAL_REWARDS)
            .map_err(|_| "reward display index unavailable")?;
        let canonical = transaction
            .open_table(BLOCKS)
            .map_err(|_| "reward display history unavailable")?;
        let mut accepted = 0u64;
        let mut detached = 0u64;
        let mut mature = 0u128;
        let mut pending = 0u128;
        let mut locked = 0u128;
        let mut unlocks = std::collections::BTreeMap::<u64, u128>::new();
        for row in local
            .iter()
            .map_err(|_| "reward display index unreadable")?
        {
            let (id, record) = row.map_err(|_| "reward display row unreadable")?;
            let id: crate::wire::Hash = id
                .value()
                .try_into()
                .map_err(|_| "reward display identity invalid")?;
            let data = record.value();
            if data.len() != 40 {
                return Err("reward display ownership invalid".into());
            }
            let height = u64::from_le_bytes(data[..8].try_into().expect("checked height"));
            let stored = canonical
                .get(height)
                .map_err(|_| "reward display history unreadable")?;
            let block = stored
                .map(|bytes| {
                    public_record(split_record(bytes.value())?.0, &self.state.config.network)
                })
                .transpose()?;
            let Some((block, _)) = block.filter(|(_, got)| *got == id) else {
                detached = detached
                    .checked_add(1)
                    .ok_or("reward display count overflow")?;
                continue;
            };
            let receipt = self.receipt_owner.read(&id)?;
            if local_receipt_digest(&id, &receipt).as_slice() != &data[8..] {
                return Err("reward display receipt changed".into());
            }
            for (index, (amount, unlock)) in crate::producer::reward_note_amounts(&block, &receipt)?
                .into_iter()
                .enumerate()
            {
                let target = if self.state.height >= unlock {
                    &mut mature
                } else if index == 0 {
                    &mut pending
                } else {
                    &mut locked
                };
                *target = target
                    .checked_add(u128::from(amount))
                    .ok_or("reward display amount overflow")?;
                if self.state.height < unlock {
                    let entry = unlocks.entry(unlock).or_default();
                    *entry = entry
                        .checked_add(u128::from(amount))
                        .ok_or("reward display lock overflow")?;
                }
            }
            accepted = accepted
                .checked_add(1)
                .ok_or("reward display count overflow")?;
        }
        Ok(
            json!({"accepted_blocks":accepted,"detached_blocks":detached,
            "mature_earned_atoms":mature.to_string(),"pending_atoms":pending.to_string(),
            "long_locked_atoms":locked.to_string(),"next_unlock_height":unlocks.keys().next(),
            "scope":"local-produced-main-chain-cumulative-earned-not-wallet-balance"}),
        )
    }
}
