//! Persistent local depth refusal, separate from canonical chain savepoints.
use super::*;
const KEY: &str = "manual-recovery-depth";
const MAGIC: &[u8; 4] = b"SWR1";
const BYTES: usize = 156;
#[derive(Clone, Debug, PartialEq, Eq)]
struct Refusal {
    binding: Hash,
    old_tip: Hash,
    candidate: Hash,
    ancestor: Hash,
    old_height: u64,
    ancestor_height: u64,
    depth: u64,
}
impl Refusal {
    fn valid(&self, rules: &HeaderRules) -> bool {
        self.binding == *blake3::hash(&rules_bytes(rules)).as_bytes()
            && self.old_tip != [0; 32]
            && self.candidate != [0; 32]
            && self.ancestor != [0; 32]
            && self.old_tip != self.candidate
            && self.old_tip != self.ancestor
            && self.candidate != self.ancestor
            && self.depth > 24
            && self.old_height.checked_sub(self.ancestor_height) == Some(self.depth)
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(BYTES);
        bytes.extend_from_slice(MAGIC);
        for hash in [
            &self.binding,
            &self.old_tip,
            &self.candidate,
            &self.ancestor,
        ] {
            bytes.extend_from_slice(hash);
        }
        for height in [self.old_height, self.ancestor_height, self.depth] {
            bytes.extend_from_slice(&height.to_le_bytes());
        }
        bytes
    }
    fn decode(bytes: &[u8], rules: &HeaderRules) -> Result<Self, String> {
        if bytes.len() != BYTES || &bytes[..4] != MAGIC {
            return Err("persistent reorganization refusal schema rejected".into());
        }
        let record = Self {
            binding: bytes[4..36].try_into().unwrap(),
            old_tip: bytes[36..68].try_into().unwrap(),
            candidate: bytes[68..100].try_into().unwrap(),
            ancestor: bytes[100..132].try_into().unwrap(),
            old_height: u64::from_le_bytes(bytes[132..140].try_into().unwrap()),
            ancestor_height: u64::from_le_bytes(bytes[140..148].try_into().unwrap()),
            depth: u64::from_le_bytes(bytes[148..156].try_into().unwrap()),
        };
        if !record.valid(rules) {
            return Err("persistent reorganization refusal context rejected".into());
        }
        Ok(record)
    }
}
impl BranchStore {
    /// A refusal is immutable owner policy, not proof of candidate validity.
    /// Preserve the first record and require explicit recovery into another store.
    pub(crate) fn persist_deep_refusal(
        &mut self,
        old_height: u64,
        old_tip: Hash,
        candidate: Hash,
        path: &CandidatePath,
    ) -> Result<(), String> {
        let record = Refusal {
            binding: *blake3::hash(&rules_bytes(&self.rules)).as_bytes(),
            old_tip,
            candidate,
            ancestor: path.ancestor_id,
            old_height,
            ancestor_height: path.ancestor_height,
            depth: path.removed.len() as u64,
        };
        if !record.valid(&self.rules) {
            return Err("persistent reorganization refusal input rejected".into());
        }
        let bytes = record.encode();
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "persistent reorganization refusal transaction unavailable")?;
        transaction.set_quick_repair(true);
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "persistent reorganization refusal durability unavailable")?;
        {
            let mut meta = transaction
                .open_table(META)
                .map_err(|_| "persistent reorganization refusal metadata unavailable")?;
            let existing = meta
                .get(KEY)
                .map_err(|_| "persistent reorganization refusal read failed")?
                .map(|row| Refusal::decode(row.value(), &self.rules))
                .transpose()?;
            if let Some(existing) = existing {
                return if existing == record {
                    Ok(())
                } else {
                    Err("persistent reorganization refusal already selects another context".into())
                };
            }
            meta.insert(KEY, bytes.as_slice())
                .map_err(|_| "persistent reorganization refusal write failed")?;
        }
        transaction
            .commit()
            .map_err(|_| "persistent reorganization refusal commit failed".into())
    }
    /// Startup must load this before enabling activities. A changed canonical
    /// head, unknown schema or damaged retained path cannot silently clear it.
    pub(crate) fn has_deep_refusal(&self, height: u64, tip: Hash) -> Result<bool, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "persistent reorganization refusal read unavailable")?;
        let meta = transaction
            .open_table(META)
            .map_err(|_| "persistent reorganization refusal metadata unavailable")?;
        let record = meta
            .get(KEY)
            .map_err(|_| "persistent reorganization refusal read failed")?
            .map(|row| Refusal::decode(row.value(), &self.rules))
            .transpose()?;
        let Some(record) = record else {
            return Ok(false);
        };
        if record.old_height != height || record.old_tip != tip {
            return Err("persistent reorganization refusal canonical head differs".into());
        }
        let path = self.candidate_path(tip, record.candidate)?;
        if path.ancestor_id != record.ancestor
            || path.ancestor_height != record.ancestor_height
            || path.removed.len() as u64 != record.depth
        {
            return Err("persistent reorganization refusal retained path differs".into());
        }
        Ok(true)
    }
}
#[cfg(test)]
mod tests;
