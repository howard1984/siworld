//! Codec for state previously verified by this node and sealed by its identity.
//! Never use this local cache decoder to authenticate a peer's checkpoint.
use super::*;
use crate::state::{CanonicalSnapshot, CommitmentTree, SNAPSHOT_WINDOW};
use crate::wire::{DigestBytes, Snapshot};
use native::codec::{decode_digest, encode_digest};
use siworld_core::{pow::Work, v1_economics::EconomicsLedger};
use std::collections::VecDeque;

const MAGIC: &[u8; 8] = b"SWLS0001";
pub(super) const MAX_CHECKPOINT_BYTES: usize = 512 * 1024 * 1024;

fn blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}
fn digests(out: &mut Vec<u8>, values: impl ExactSizeIterator<Item = DigestBytes>) {
    out.extend_from_slice(&(values.len() as u64).to_le_bytes());
    for value in values {
        out.extend_from_slice(&value);
    }
}
pub(super) fn encoded_len(state: &State) -> usize {
    // Fixed fields, six count prefixes, two blob prefixes and final fingerprint.
    let mut bytes = 8usize + 32 + 32 + 8 + 32 + 64 + 6 * 8 + 48 + 2 * 8 + 32;
    for (count, width) in [
        (state.timestamps.len(), 8),
        (state.leaves.len(), 48),
        (state.spent.len(), 48),
        (state.commitments.len(), 48),
        (state.tree.cache_frontier().len(), 48),
        (state.snapshots.len(), 136),
    ] {
        bytes = bytes.saturating_add(count.saturating_mul(width));
    }
    state
        .assets
        .visit_encoding(&mut |part| bytes = bytes.saturating_add(part.len()));
    state
        .economics
        .visit_encoding(&mut |part| bytes = bytes.saturating_add(part.len()));
    bytes
}
pub(super) fn encode(state: &State) -> Result<Vec<u8>, String> {
    if encoded_len(state) > MAX_CHECKPOINT_BYTES {
        return Err("local checkpoint byte budget exceeded".into());
    }
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&state.config.genesis_id());
    bytes.extend_from_slice(&crate::proofs::protocol_profile_fingerprint());
    bytes.extend_from_slice(&state.height.to_le_bytes());
    bytes.extend_from_slice(&state.tip);
    bytes.extend_from_slice(&state.cumulative_work.to_big_endian());
    bytes.extend_from_slice(&(state.timestamps.len() as u64).to_le_bytes());
    for timestamp in &state.timestamps {
        bytes.extend_from_slice(&timestamp.to_le_bytes());
    }
    digests(&mut bytes, state.leaves.iter().map(encode_digest));
    digests(&mut bytes, state.spent.iter().copied());
    digests(&mut bytes, state.commitments.iter().copied());
    digests(&mut bytes, state.tree.cache_frontier().into_iter());
    bytes.extend_from_slice(&encode_digest(&state.tree.root()));
    bytes.extend_from_slice(&(state.snapshots.len() as u64).to_le_bytes());
    for snapshot in &state.snapshots {
        bytes.extend_from_slice(&snapshot.selector.height.to_le_bytes());
        bytes.extend_from_slice(&snapshot.selector.block_id);
        bytes.extend_from_slice(&snapshot.commitment_root);
        bytes.extend_from_slice(&snapshot.recent_root);
    }
    let mut registry = Vec::new();
    state
        .assets
        .visit_encoding(&mut |part| registry.extend_from_slice(part));
    blob(&mut bytes, &registry);
    let mut economics = Vec::new();
    state
        .economics
        .visit_encoding(&mut |part| economics.extend_from_slice(part));
    blob(&mut bytes, &economics);
    bytes.extend_from_slice(&state.fingerprint());
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err("local checkpoint byte budget exceeded".into());
    }
    Ok(bytes)
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let (a, b) = self
            .0
            .split_at_checked(N)
            .ok_or("truncated local checkpoint")?;
        self.0 = b;
        Ok(a.try_into().expect("bounded field"))
    }
    fn number(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn count(&mut self, width: usize) -> Result<usize, String> {
        let count = usize::try_from(self.number()?).map_err(|_| "checkpoint count overflow")?;
        if count > self.0.len() / width {
            return Err("checkpoint count exceeds remaining bytes".into());
        }
        Ok(count)
    }
    fn digests(&mut self) -> Result<Vec<DigestBytes>, String> {
        let count = self.count(48)?;
        (0..count)
            .map(|_| {
                let value = self.array()?;
                let _ = decode_digest(&value).map_err(|_| "noncanonical checkpoint digest")?;
                Ok(value)
            })
            .collect()
    }
    fn blob(&mut self) -> Result<&'a [u8], String> {
        let length = self.count(1)?;
        let (a, b) = self
            .0
            .split_at_checked(length)
            .ok_or("truncated checkpoint blob")?;
        self.0 = b;
        Ok(a)
    }
}
/// Called only after verifying the complete local checkpoint payload seal.
pub(super) fn decode_sealed(bytes: &[u8], config: Config) -> Result<State, String> {
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err("local checkpoint byte budget exceeded".into());
    }
    let mut r = Reader(bytes);
    if &r.array::<8>()? != MAGIC
        || r.array::<32>()? != config.genesis_id()
        || r.array::<32>()? != crate::proofs::protocol_profile_fingerprint()
    {
        return Err("local checkpoint profile mismatch".into());
    }
    let height = r.number()?;
    let tip = r.array()?;
    let cumulative_work = Work::from_big_endian(&r.array::<64>()?);
    let count = r.count(8)?;
    if count == 0 || count > siworld_core::params::MEDIAN_TIME_PAST_WINDOW {
        return Err("local checkpoint timestamp window mismatch".into());
    }
    let timestamps: VecDeque<_> = (0..count).map(|_| r.number()).collect::<Result<_, _>>()?;
    let leaves = r
        .digests()?
        .iter()
        .map(|d| decode_digest(d).map_err(|_| "checkpoint leaf".to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let spent_values = r.digests()?;
    let commitment_values = r.digests()?;
    let spent = spent_values.iter().copied().collect::<BTreeSet<_>>();
    let commitments = commitment_values.iter().copied().collect::<BTreeSet<_>>();
    if spent.len() != spent_values.len()
        || commitments.len() != commitment_values.len()
        || spent_values.windows(2).any(|w| w[0] >= w[1])
        || commitment_values.windows(2).any(|w| w[0] >= w[1])
    {
        return Err("noncanonical local checkpoint sets".into());
    }
    let frontier = r.digests()?;
    let root = r.array()?;
    let tree = CommitmentTree::from_local_cache(leaves.len() as u64, &frontier, root)?;
    let count = r.count(136)?;
    if count == 0 || count > SNAPSHOT_WINDOW {
        return Err("local checkpoint snapshot window mismatch".into());
    }
    let mut snapshots = VecDeque::new();
    for _ in 0..count {
        snapshots.push_back(CanonicalSnapshot {
            selector: Snapshot {
                height: r.number()?,
                block_id: r.array()?,
            },
            commitment_root: r.array()?,
            recent_root: r.array()?,
        });
    }
    if snapshots.back().is_none_or(|s| {
        s.selector
            != (Snapshot {
                height,
                block_id: tip,
            })
            || s.commitment_root != root
    }) || snapshots
        .iter()
        .zip(snapshots.iter().skip(1))
        .any(|(a, b)| a.selector.height.checked_add(1) != Some(b.selector.height))
    {
        return Err("local checkpoint snapshot continuity mismatch".into());
    }
    let assets = crate::issuance::AssetRegistry::from_local_encoding(r.blob()?, height)?;
    let economics = EconomicsLedger::from_authenticated_encoding(
        r.blob()?,
        config.economics.clone(),
        config.fund_allocation.clone(),
    )
    .map_err(|_| "invalid local checkpoint economic cache")?;
    if economics.height() != height {
        return Err("local checkpoint economic height mismatch".into());
    }
    let expected = r.array::<32>()?;
    if !r.0.is_empty() {
        return Err("trailing local checkpoint data".into());
    }
    let state = State {
        config,
        height,
        tip,
        cumulative_work,
        timestamps,
        tree,
        spent,
        commitments,
        leaves,
        snapshots,
        assets,
        economics,
    };
    if state.fingerprint() != expected || encode(&state)? != bytes {
        return Err("local checkpoint state fingerprint mismatch".into());
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_cache_roundtrip_and_next_transition_match_verified_history() {
        let config = Config::development([18; 32], 0).unwrap();
        let mut state = State::new(config.clone()).unwrap();
        for n in 0..3 {
            state
                .apply(
                    &crate::fixtures::candidate(&state, 100_000 * (n + 1)),
                    &crate::fixtures::TestVerifier,
                )
                .unwrap();
        }
        let bytes = encode(&state).unwrap();
        assert_eq!(encoded_len(&state), bytes.len());
        let mut restored = decode_sealed(&bytes, config.clone()).unwrap();
        assert_eq!(restored.fingerprint(), state.fingerprint());
        assert_eq!(restored.leaves, state.leaves);
        let block = crate::fixtures::candidate(&state, 500_000);
        restored
            .apply(&block, &crate::fixtures::TestVerifier)
            .unwrap();
        state.apply(&block, &crate::fixtures::TestVerifier).unwrap();
        assert_eq!(restored.fingerprint(), state.fingerprint());
        assert!(decode_sealed(&bytes[..bytes.len() - 1], config.clone()).is_err());
        let mut bad = bytes;
        bad[88] ^= 1;
        assert!(decode_sealed(&bad, config).is_err());
    }
}
