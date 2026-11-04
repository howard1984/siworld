//! Locally authenticated tree cache; historical ciphertext is never retained.
use crate::{
    commitment::CommitmentBlock,
    state::{CanonicalSnapshot, CommitmentTree, Config, SNAPSHOT_WINDOW, State, base_fee},
    wire::{DigestBytes, Snapshot},
};
use native::{
    codec::{decode_digest, encode_digest},
    multi_asset::{Hasher, RecentRoots},
};
use serde_json::{Value, json};
use siworld_core::pow;
use std::collections::{BTreeSet, VecDeque};

pub struct CommitmentHistory {
    pub state: State,
}
impl CommitmentHistory {
    pub fn new(config: Config) -> Result<Self, String> {
        Ok(Self {
            state: State::new(config)?,
        })
    }
    pub fn append(&mut self, b: &CommitmentBlock) -> Result<(), String> {
        let mut trial = self.state.clone();
        if b.network != trial.config.network
            || b.height != trial.height.checked_add(1).ok_or("Height overflow.")?
            || b.parent != trial.tip
            || b.timestamp <= trial.median_time_past()
        {
            return Err("Historical header chain continuity failed.".into());
        }
        if b.target != trial.next_target()
            || !pow::meets_target(
                &pow::pow_hash(&b.seed, b.nonce, trial.config.pow_iterations),
                &b.target,
            )
        {
            return Err("Historical work or target failed.".into());
        }
        trial.cumulative_work = trial
            .cumulative_work
            .checked_add(pow::block_work(&b.target))
            .ok_or("Work overflow.")?;
        let mut seen = BTreeSet::new();
        for cm in &b.outputs {
            if !seen.insert(*cm) {
                return Err("Duplicate historical output.".into());
            }
            trial
                .tree
                .append(decode_digest(cm).map_err(|_| "Invalid historical commitment field.")?)?;
        }
        trial.height = b.height;
        trial.tip = b.id;
        trial.timestamps.push_back(b.timestamp);
        while trial.timestamps.len() > siworld_core::params::MEDIAN_TIME_PAST_WINDOW {
            trial.timestamps.pop_front();
        }
        // Historical recent-root digests are not wallet verification inputs.
        // Materialize the current digest once when handing state to a scanner.
        trial.snapshots.push_back(CanonicalSnapshot {
            selector: Snapshot {
                height: b.height,
                block_id: b.id,
            },
            commitment_root: encode_digest(&trial.tree.root()),
            recent_root: [0; 48],
        });
        while trial.snapshots.len() > SNAPSHOT_WINDOW {
            trial.snapshots.pop_front();
        }
        self.state = trial;
        Ok(())
    }
    pub fn scanner_state(&self) -> Result<State, String> {
        let mut state = self.state.clone();
        let mut roots = RecentRoots::new();
        let h = Hasher::new();
        for s in &state.snapshots {
            if state.height - s.selector.height < SNAPSHOT_WINDOW as u64 {
                roots.insert(
                    &h,
                    s.selector.height,
                    &decode_digest(&s.commitment_root).map_err(|_| "Invalid cached root.")?,
                    base_fee(s.selector.height),
                );
            }
        }
        state
            .snapshots
            .back_mut()
            .ok_or("Missing cached root window.")?
            .recent_root = encode_digest(&roots.tree(&h).root());
        Ok(state)
    }
    /// Plain public frontier/header context. Persist only inside a wallet-authenticated envelope.
    pub fn cache(&self) -> Result<Vec<u8>, String> {
        let s = &self.state;
        serde_json::to_vec(&json!({"version":1,"network":crate::local::hex(&s.config.network),"genesis":crate::local::hex(&s.config.genesis_id()),
            "height":s.height,"tip":crate::local::hex(&s.tip),"work":crate::local::hex(&s.cumulative_work.to_big_endian()),
            "timestamps":s.timestamps,"count":s.tree.count,"root":crate::local::hex(&encode_digest(&s.tree.root())),
            "frontier":s.tree.cache_frontier().iter().map(|v|crate::local::hex(v)).collect::<Vec<_>>(),
            "snapshots":s.snapshots.iter().map(|v|json!({"height":v.selector.height,"id":crate::local::hex(&v.selector.block_id),"root":crate::local::hex(&v.commitment_root)})).collect::<Vec<_>>()
        })).map_err(|_| "Tree cache encoding failed.".into())
    }
    /// Shape validation does not authenticate a network-supplied snapshot.
    /// This entry point is only for an already authenticated local envelope.
    pub fn open_local(config: Config, bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 2_000_000 {
            return Err("Local tree cache byte limit.".into());
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|_| "Invalid tree cache JSON.")?;
        let mut result = Self::new(config)?;
        let s = &mut result.state;
        let integer = |v: &Value| v.as_u64().ok_or("Invalid tree cache integer.".to_owned());
        if value.as_object().is_none_or(|o| o.len() != 11)
            || value["version"] != 1
            || value["network"] != crate::local::hex(&s.config.network)
            || value["genesis"] != crate::local::hex(&s.config.genesis_id())
        {
            return Err("Local tree cache binding mismatch.".into());
        }
        s.height = integer(&value["height"])?;
        if s.height > 1_000_000 {
            return Err("Local cache height limit.".into());
        }
        s.tip = array::<32>(&value["tip"])?;
        s.cumulative_work = pow::Work::from_big_endian(&array::<64>(&value["work"])?);
        let frontier = value["frontier"]
            .as_array()
            .ok_or("Missing local frontier.")?
            .iter()
            .map(array::<48>)
            .collect::<Result<Vec<DigestBytes>, _>>()?;
        s.tree = CommitmentTree::from_local_cache(
            integer(&value["count"])?,
            &frontier,
            array::<48>(&value["root"])?,
        )?;
        s.timestamps = value["timestamps"]
            .as_array()
            .ok_or("Missing local times.")?
            .iter()
            .map(integer)
            .collect::<Result<VecDeque<_>, _>>()?;
        if s.timestamps.is_empty()
            || s.timestamps.len() > siworld_core::params::MEDIAN_TIME_PAST_WINDOW
        {
            return Err("Local time window limit.".into());
        }
        s.snapshots = value["snapshots"]
            .as_array()
            .ok_or("Missing local roots.")?
            .iter()
            .map(|v| {
                Ok(CanonicalSnapshot {
                    selector: Snapshot {
                        height: integer(&v["height"])?,
                        block_id: array::<32>(&v["id"])?,
                    },
                    commitment_root: array::<48>(&v["root"])?,
                    recent_root: [0; 48],
                })
            })
            .collect::<Result<VecDeque<_>, String>>()?;
        if s.snapshots.is_empty()
            || s.snapshots.len() > SNAPSHOT_WINDOW
            || s.snapshots.len() as u64 != (s.height + 1).min(SNAPSHOT_WINDOW as u64)
        {
            return Err("Local root window limit.".into());
        }
        for (i, v) in s.snapshots.iter().enumerate() {
            if v.selector.height != s.height + 1 - s.snapshots.len() as u64 + i as u64 {
                return Err("Local root window continuity failed.".into());
            }
            let _ = decode_digest(&v.commitment_root).map_err(|_| "Invalid local root field.")?;
        }
        let last = s.snapshots.back().unwrap();
        if last.selector.block_id != s.tip
            || last.commitment_root != encode_digest(&s.tree.root())
            || s.height == 0 && s.tip != s.config.genesis_id()
        {
            return Err("Local cache head mismatch.".into());
        }
        Ok(result)
    }
}
fn array<const N: usize>(value: &Value) -> Result<[u8; N], String> {
    let text = value.as_str().ok_or("Invalid tree cache bytes.")?;
    if text.len() != 2 * N || !text.is_ascii() {
        return Err("Local tree cache byte width.".into());
    }
    let mut bytes = [0; N];
    for (out, chunk) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let d = |b: u8| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err("Invalid tree cache encoding."),
        };
        *out = d(chunk[0])? * 16 + d(chunk[1])?;
    }
    Ok(bytes)
}
