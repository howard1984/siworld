//! Authenticated local restart records, independent of the proof-expiry floor.
//! Only a verified canonical commit may create one. Peer checkpoint authority
//! is never inferred from this local identity seal.
use super::*;
use crate::{
    identity::NativeIdentity,
    p2p::Binding,
    wire::{Hash, RewardRecord},
};
use std::collections::BTreeMap;

pub(super) const RESUME: TableDefinition<&str, &[u8]> =
    TableDefinition::new("local-verified-restart-v1");
const DOMAIN: &str = "siworld atomically verified local restart v1";
const MAGIC: &[u8; 8] = b"SWNR0001";
const MAX_REWARDS: usize = 1_000_000;

#[derive(Clone)]
pub(super) struct Reward {
    pub id: Hash,
    pub height: u64,
    pub digest: Hash,
    pub canonical: bool,
    pub mode: crate::state::RewardMode,
    pub records: Vec<RewardRecord>,
}
impl Reward {
    pub fn validate(&self, store: &Store) -> Result<(), String> {
        let receipt = store.receipt_owner.read(&self.id)?;
        if local_receipt_digest(&self.id, &receipt) != self.digest {
            return Err("restart reward receipt digest mismatch".into());
        }
        crate::producer::validate_reward_material(
            store.state.config.network,
            self.height,
            self.mode,
            &self.records,
            &receipt,
        )
    }
}
pub(super) struct Context {
    identity: NativeIdentity,
    pub rewards: BTreeMap<Hash, Reward>,
    pub maximum_bytes: usize,
}
impl Context {
    pub fn new(path: &Path, config: &Config) -> Result<Option<Self>, String> {
        let directory = std::fs::canonicalize(path.parent().ok_or("restart parent unavailable")?)
            .map_err(|_| "restart identity directory unavailable")?;
        NativeIdentity::load_if_present(&directory, &Binding::new(config))
            .map(|identity| {
                identity.map(|identity| Self {
                    identity,
                    rewards: BTreeMap::new(),
                    maximum_bytes: checkpoint::MAX_CHECKPOINT_BYTES,
                })
            })
            .map_err(|_| "existing restart identity is invalid".into())
    }
    pub fn reward(block: &Block, digest: Hash) -> Result<Reward, String> {
        Ok(Reward {
            id: block.id()?,
            height: block.height,
            digest,
            canonical: true,
            mode: block.reward_mode,
            records: block.rewards.clone(),
        })
    }
    /// A fresh cache is seeded only after the caller completed proof replay and
    /// authenticated every ownership receipt, or verified checkpoint bootstrap.
    pub fn collect_rewards(&mut self, store: &Store) -> Result<(), String> {
        let transaction = store
            .database
            .begin_read()
            .map_err(|_| "restart reward read unavailable")?;
        let canonical = transaction
            .open_table(BLOCKS)
            .map_err(|_| "restart history unavailable")?;
        self.collect_rewards_from(store, &canonical)
    }
    pub fn collect_rewards_from(
        &mut self,
        store: &Store,
        canonical: &impl ReadableTable<u64, &'static [u8]>,
    ) -> Result<(), String> {
        let transaction = store
            .database
            .begin_read()
            .map_err(|_| "restart reward read unavailable")?;
        let rows = transaction
            .open_table(LOCAL_REWARDS)
            .map_err(|_| "restart reward index unavailable")?;
        let detached = transaction.open_table(DETACHED).ok();
        for row in rows.iter().map_err(|_| "restart reward index unreadable")? {
            let (id, row) = row.map_err(|_| "restart reward row unreadable")?;
            let id: Hash = id
                .value()
                .try_into()
                .map_err(|_| "restart reward identity invalid")?;
            if row.value().len() != 40 {
                return Err("restart ownership record invalid".into());
            }
            let height = u64::from_le_bytes(row.value()[..8].try_into().expect("checked height"));
            let digest = row.value()[8..].try_into().expect("checked digest");
            let record = canonical
                .get(height)
                .map_err(|_| "restart history unreadable")?
                .map(|row| public_record(split_record(row.value())?.0, &store.state.config.network))
                .transpose()?;
            let is_canonical = record.as_ref().is_some_and(|(_, got)| got == &id);
            let block = if is_canonical {
                record.expect("checked canonical reward").0
            } else {
                let row = detached
                    .as_ref()
                    .ok_or("restart detached reward table missing")?
                    .get(id.as_slice())
                    .map_err(|_| "restart detached reward unavailable")?
                    .ok_or("restart detached reward missing")?;
                let (block, got) = public_record(
                    split_record(detached_record(row.value())?)?.0,
                    &store.state.config.network,
                )?;
                if got != id {
                    return Err("restart detached reward identity mismatch".into());
                }
                block
            };
            if block.height != height {
                return Err("restart reward height mismatch".into());
            }
            let reward = Reward {
                id,
                height,
                digest,
                canonical: is_canonical,
                mode: block.reward_mode,
                records: block.rewards,
            };
            reward.validate(store)?;
            self.rewards.insert(id, reward);
        }
        Ok(())
    }
    pub fn write(
        &self,
        transaction: &redb::WriteTransaction,
        state: &State,
        rewards: &BTreeMap<Hash, Reward>,
    ) -> Result<bool, String> {
        check_rewards_write(transaction, rewards)?;
        let reward_len = rewards.values().fold(16usize, |bytes, reward| {
            bytes.saturating_add(74).saturating_add(
                reward
                    .records
                    .len()
                    .saturating_mul(crate::wire::REWARD_RECORD_BYTES),
            )
        });
        if checkpoint::encoded_len(state) > self.maximum_bytes
            || reward_len > self.maximum_bytes
            || rewards.len() > MAX_REWARDS
        {
            // Acceleration capacity is never a block-validity rule. Remove
            // only this optional record atomically with the accepted head;
            // a later startup must audit retained proofs instead.
            transaction
                .delete_table(RESUME)
                .map_err(|_| "restart invalidation failed")?;
            return Ok(false);
        }
        let state_bytes = checkpoint::encode(state)?;
        let reward_bytes = encode_rewards(rewards)?;
        let digest = digest(&state.config, &state_bytes, &reward_bytes);
        let seal = self
            .identity
            .seal_local_storage(digest)
            .map_err(|_| "restart state seal failed")?;
        let mut table = transaction
            .open_table(RESUME)
            .map_err(|_| "restart table unavailable")?;
        for (key, bytes) in [
            ("state", state_bytes.as_slice()),
            ("rewards", reward_bytes.as_slice()),
            ("seal", seal.as_slice()),
        ] {
            table
                .insert(key, bytes)
                .map_err(|_| "restart record write failed")?;
        }
        Ok(true)
    }
}
fn digest(config: &Config, state: &[u8], rewards: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key(DOMAIN);
    hasher.update(&configuration(config));
    hasher.update(&(state.len() as u64).to_le_bytes());
    hasher.update(state);
    hasher.update(&(rewards.len() as u64).to_le_bytes());
    hasher.update(rewards);
    *hasher.finalize().as_bytes()
}
fn encode_rewards(rewards: &BTreeMap<Hash, Reward>) -> Result<Vec<u8>, String> {
    if rewards.len() > MAX_REWARDS {
        return Err("restart reward count limit".into());
    }
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&(rewards.len() as u64).to_le_bytes());
    for (id, reward) in rewards {
        if id != &reward.id {
            return Err("restart reward map mismatch".into());
        }
        bytes.extend_from_slice(id);
        bytes.extend_from_slice(&reward.height.to_le_bytes());
        bytes.extend_from_slice(&reward.digest);
        bytes.push(u8::from(reward.canonical));
        bytes.push(reward.mode.to_byte());
        let expected = match reward.mode {
            crate::state::RewardMode::Voyager => 1,
            crate::state::RewardMode::Holder => 5,
        };
        if reward.records.len() != expected {
            return Err("restart reward record count mismatch".into());
        }
        for record in &reward.records {
            bytes.extend_from_slice(&record.commitment);
            bytes.extend_from_slice(&record.ciphertext);
        }
        if bytes.len() > checkpoint::MAX_CHECKPOINT_BYTES {
            return Err("restart rewards byte limit".into());
        }
    }
    Ok(bytes)
}
struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let (field, rest) = self
            .0
            .split_at_checked(N)
            .ok_or("truncated restart reward record")?;
        self.0 = rest;
        Ok(field.try_into().expect("bounded restart field"))
    }
}
fn decode_rewards(bytes: &[u8], height: u64) -> Result<BTreeMap<Hash, Reward>, String> {
    let mut reader = Reader(bytes);
    if &reader.array::<8>()? != MAGIC {
        return Err("unsupported restart reward version".into());
    }
    let count = usize::try_from(u64::from_le_bytes(reader.array()?))
        .map_err(|_| "restart count overflow")?;
    if count > MAX_REWARDS || count > reader.0.len() / (74 + crate::wire::REWARD_RECORD_BYTES) {
        return Err("restart reward count exceeds remaining bytes".into());
    }
    let mut rewards = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let id = reader.array()?;
        if previous.is_some_and(|prior| prior >= id) {
            return Err("restart rewards not canonical".into());
        }
        previous = Some(id);
        let reward_height = u64::from_le_bytes(reader.array()?);
        let digest = reader.array()?;
        let canonical = match reader.array::<1>()? {
            [0] => false,
            [1] => true,
            _ => return Err("restart reward flag invalid".into()),
        };
        let mode = crate::state::RewardMode::from_byte(reader.array::<1>()?[0])
            .map_err(|_| "restart reward mode invalid")?;
        if reward_height == 0 || (canonical && reward_height > height) {
            return Err("restart reward height invalid".into());
        }
        let count = match mode {
            crate::state::RewardMode::Voyager => 1,
            crate::state::RewardMode::Holder => 5,
        };
        let records = (0..count)
            .map(|_| {
                Ok(RewardRecord {
                    commitment: reader.array()?,
                    ciphertext: reader.array()?,
                })
            })
            .collect::<Result<_, String>>()?;
        rewards.insert(
            id,
            Reward {
                id,
                height: reward_height,
                digest,
                canonical,
                mode,
                records,
            },
        );
    }
    if !reader.0.is_empty() || encode_rewards(&rewards)? != bytes {
        return Err("noncanonical restart rewards".into());
    }
    Ok(rewards)
}
pub(super) fn check_rewards(
    database: &impl ReadableDatabase,
    rewards: &BTreeMap<Hash, Reward>,
) -> Result<(), String> {
    let transaction = database
        .begin_read()
        .map_err(|_| "restart reward read unavailable")?;
    check_reward_tables(
        &transaction
            .open_table(META)
            .map_err(|_| "restart metadata unavailable")?,
        &transaction
            .open_table(LOCAL_REWARDS)
            .map_err(|_| "restart reward index unavailable")?,
        rewards,
    )
}
fn check_reward_tables(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
    rows: &impl ReadableTable<&'static [u8], &'static [u8]>,
    rewards: &BTreeMap<Hash, Reward>,
) -> Result<(), String> {
    if local_reward_count(meta)? != rewards.len() as u64
        || rows.len().map_err(|_| "restart reward count unavailable")? != rewards.len() as u64
    {
        return Err("restart reward ownership count mismatch".into());
    }
    for row in rows.iter().map_err(|_| "restart reward index unreadable")? {
        let (id, row) = row.map_err(|_| "restart reward row unreadable")?;
        let id: Hash = id
            .value()
            .try_into()
            .map_err(|_| "restart reward identity invalid")?;
        let reward = rewards.get(&id).ok_or("restart reward witness missing")?;
        let bytes = row.value();
        if bytes.len() != 40
            || bytes[..8] != reward.height.to_le_bytes()
            || bytes[8..] != reward.digest
        {
            return Err("restart reward ownership differs from seal".into());
        }
    }
    Ok(())
}
// redb write transactions implement table reads but not ReadableDatabase.
fn check_rewards_write(
    transaction: &redb::WriteTransaction,
    rewards: &BTreeMap<Hash, Reward>,
) -> Result<(), String> {
    check_reward_tables(
        &transaction
            .open_table(META)
            .map_err(|_| "restart metadata unavailable")?,
        &transaction
            .open_table(LOCAL_REWARDS)
            .map_err(|_| "restart reward index unavailable")?,
        rewards,
    )
}

/// Bind the independently authenticated expiry floor to the accepted branch.
/// Only one canonical record is read; historical prefix audits remain explicit.
pub(super) fn check_floor(
    database: &impl ReadableDatabase,
    state: &State,
    floor: &State,
) -> Result<(), String> {
    if floor.height > state.height {
        return Err("restart record predates expired proof boundary".into());
    }
    if let Some(snapshot) = state
        .snapshots
        .iter()
        .find(|snapshot| snapshot.selector.height == floor.height)
    {
        let anchor = floor.tip_snapshot();
        if snapshot.selector != anchor.selector
            || snapshot.commitment_root != anchor.commitment_root
            || snapshot.recent_root != anchor.recent_root
        {
            return Err("restart expiry floor belongs to a different branch".into());
        }
    }
    if floor.height == 0 {
        if floor.fingerprint() != State::new(state.config.clone())?.fingerprint() {
            return Err("restart genesis expiry floor mismatch".into());
        }
        return Ok(());
    }
    let transaction = database
        .begin_read()
        .map_err(|_| "restart expiry anchor unavailable")?;
    let table = transaction
        .open_table(BLOCKS)
        .map_err(|_| "restart expiry history unavailable")?;
    let row = table
        .get(floor.height)
        .map_err(|_| "restart expiry anchor unreadable")?
        .ok_or("restart expiry anchor missing")?;
    let (bytes, fingerprint) = split_record(row.value())?;
    if public_record(bytes, &state.config.network)?.1 != floor.tip
        || fingerprint != floor.fingerprint()
    {
        return Err("restart expiry canonical anchor mismatch".into());
    }
    Ok(())
}

pub(super) fn load(
    database: &Database,
    path: &Path,
    config: &Config,
) -> Result<Option<(State, Context)>, String> {
    let transaction = database
        .begin_read()
        .map_err(|_| "restart read unavailable")?;
    if !transaction
        .list_tables()
        .map_err(|_| "restart schema unreadable")?
        .any(|table| table.name() == RESUME.name())
    {
        return Ok(None);
    }
    let mut context = Context::new(path, config)?
        .ok_or("restart record requires its existing persistent identity")?;
    let table = transaction
        .open_table(RESUME)
        .map_err(|_| "restart record unavailable")?;
    if table.len().map_err(|_| "restart metadata unreadable")? != 3 {
        return Err("incomplete restart record".into());
    }
    let read = |key| -> Result<Vec<u8>, String> {
        let value = table
            .get(key)
            .map_err(|_| "restart record unreadable")?
            .ok_or("restart record missing")?;
        let maximum = if key == "seal" {
            crate::identity::storage_checkpoint::SEAL_BYTES
        } else {
            checkpoint::MAX_CHECKPOINT_BYTES
        };
        if value.value().len() > maximum || (key == "seal" && value.value().len() != maximum) {
            return Err("restart byte limit".into());
        }
        Ok(value.value().to_vec())
    };
    let state_bytes = read("state")?;
    let rewards = read("rewards")?;
    let seal = read("seal")?;
    context
        .identity
        .descriptor()
        .map_err(|_| "restart identity unavailable")?
        .verify_local_storage(digest(config, &state_bytes, &rewards), &seal)
        .map_err(|_| "restart state seal mismatch")?;
    let state = checkpoint::decode_sealed(&state_bytes, config.clone())?;
    context.rewards = decode_rewards(&rewards, state.height)?;
    check_rewards(database, &context.rewards)?;
    let meta = transaction
        .open_table(META)
        .map_err(|_| "restart head unavailable")?;
    let saved = meta
        .get("head")
        .map_err(|_| "restart head unreadable")?
        .ok_or("restart head missing")?;
    if saved.value().len() != HEAD_BYTES {
        return Err("restart committed head invalid".into());
    }
    let height = u64::from_le_bytes(saved.value()[..8].try_into().expect("checked head"));
    if state.height > height || (state.height == height && saved.value() != head(&state)) {
        return Err("restart state differs from committed head".into());
    }
    if state.height > 0 {
        let blocks = transaction
            .open_table(BLOCKS)
            .map_err(|_| "restart canonical table unavailable")?;
        let row = blocks
            .get(state.height)
            .map_err(|_| "restart anchor unavailable")?
            .ok_or("restart anchor missing")?;
        let (bytes, fingerprint) = split_record(row.value())?;
        let (_, id) = public_record(bytes, &config.network)?;
        if id != state.tip || fingerprint != state.fingerprint() {
            return Err("restart canonical anchor mismatch".into());
        }
    }
    Ok(Some((state, context)))
}
