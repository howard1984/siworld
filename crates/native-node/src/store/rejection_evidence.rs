//! Read-only semantic evidence for the explicit offline acceptance target.
use super::*;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

fn feed(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

impl Store {
    /// Digest small committed metadata tables, including the full sealed state,
    /// qualification and receipt index. Proof-body pages and filesystem layout
    /// are intentionally not interpreted as semantic state invariants.
    pub(crate) fn rejection_acceptance_metadata(&self) -> Result<Value, String> {
        let txn = self
            .database
            .begin_read()
            .map_err(|_| "metadata_read_failed")?;
        let present = txn
            .list_tables()
            .map_err(|_| "metadata_schema_failed")?
            .map(|t| t.name().to_owned())
            .collect::<BTreeSet<_>>();
        let mut hash = Sha256::new();
        feed(&mut hash, b"siworld rejection acceptance metadata v1");
        for name in &present {
            feed(&mut hash, name.as_bytes());
        }
        for definition in [
            META,
            retention::STORAGE,
            engineering_checkpoint::ATTESTATIONS,
            resume::RESUME,
        ] {
            feed(&mut hash, definition.name().as_bytes());
            let exists = present.contains(definition.name());
            hash.update([u8::from(exists)]);
            if exists {
                let table = txn
                    .open_table(definition)
                    .map_err(|_| "metadata_table_failed")?;
                hash.update(
                    table
                        .len()
                        .map_err(|_| "metadata_count_failed")?
                        .to_le_bytes(),
                );
                for row in table.iter().map_err(|_| "metadata_iteration_failed")? {
                    let (key, value) = row.map_err(|_| "metadata_row_failed")?;
                    feed(&mut hash, key.value().as_bytes());
                    feed(&mut hash, value.value());
                }
            }
        }
        for definition in [retention::FINALITY, protected_history::PROTECTED] {
            feed(&mut hash, definition.name().as_bytes());
            let exists = present.contains(definition.name());
            hash.update([u8::from(exists)]);
            if exists {
                let table = txn
                    .open_table(definition)
                    .map_err(|_| "metadata_table_failed")?;
                hash.update(
                    table
                        .len()
                        .map_err(|_| "metadata_count_failed")?
                        .to_le_bytes(),
                );
                for row in table.iter().map_err(|_| "metadata_iteration_failed")? {
                    let (key, value) = row.map_err(|_| "metadata_row_failed")?;
                    hash.update(key.value().to_le_bytes());
                    feed(&mut hash, value.value());
                }
            }
        }
        feed(&mut hash, LOCAL_REWARDS.name().as_bytes());
        let table = txn
            .open_table(LOCAL_REWARDS)
            .map_err(|_| "reward_index_required")?;
        let rewards = table.len().map_err(|_| "reward_count_failed")?;
        hash.update(rewards.to_le_bytes());
        for row in table.iter().map_err(|_| "reward_iteration_failed")? {
            let (key, value) = row.map_err(|_| "reward_row_failed")?;
            feed(&mut hash, key.value());
            feed(&mut hash, value.value());
        }
        Ok(
            json!({"metadata_sha256":crate::local::hex(&hash.finalize()),
            "local_reward_index_count":rewards}),
        )
    }
}
