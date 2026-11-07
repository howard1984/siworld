//! Atomic local proof expiry with a sealed, previously verified replay base.
use super::*;
use crate::{
    compact::CompactBlock,
    engineering_checkpoint::{self as checkpoint_auth, Roster},
    identity::NativeIdentity,
    p2p::Binding,
    storage_policy::{self, FinalityObservation, RecoveryBoundary, Role},
};
use serde_json::{Value, json};

pub(super) const STORAGE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("local-proof-storage-v1");
pub(super) const FINALITY: TableDefinition<u64, &[u8]> =
    TableDefinition::new("local-proof-finality-v1");
/// Bound each owner-loop maintenance transaction independently of chain age.
const MAX_EXPIRE_BLOCKS: u64 = 4;
const MAX_EXPIRE_BYTES: usize = MAX_BLOCK_BYTES;
const DOMAIN: &str = "siworld verified local proof retention v1";

fn initial_prefix(config: &Config) -> crate::wire::Hash {
    blake3::derive_key(DOMAIN, &config.genesis_id())
}
fn next_prefix(previous: crate::wire::Hash, height: u64, compact: &[u8]) -> crate::wire::Hash {
    let mut hash = blake3::Hasher::new_derive_key(DOMAIN);
    hash.update(&previous);
    hash.update(&height.to_le_bytes());
    hash.update(blake3::hash(compact).as_bytes());
    *hash.finalize().as_bytes()
}
fn identity(path: &Path, config: &Config) -> Result<NativeIdentity, String> {
    NativeIdentity::load(
        path.parent().ok_or("storage parent unavailable")?,
        &Binding::new(config),
    )
    .map_err(|_| "existing persistent identity required for local storage checkpoints".into())
}
fn payload(role: Role, prefix: crate::wire::Hash, state: &State) -> Result<Vec<u8>, String> {
    let mut bytes = role.name().as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&prefix);
    bytes.extend(checkpoint::encode(state)?);
    Ok(bytes)
}
fn value(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Vec<u8>, String> {
    let row = table
        .get(key)
        .map_err(|_| "storage metadata unreadable")?
        .ok_or("storage metadata missing")?;
    let maximum = match key {
        "base" => checkpoint::MAX_CHECKPOINT_BYTES,
        "seal" => 3373,
        "role" => 9,
        "prefix" | "qualified_roster" => 32,
        "last_clock" | "local_blocks" => 8,
        _ => 0,
    };
    if row.value().len() > maximum {
        return Err("local storage metadata byte limit".into());
    }
    Ok(row.value().to_vec())
}
pub(super) fn is_enabled(database: &impl ReadableDatabase) -> Result<bool, String> {
    Ok(database
        .begin_read()
        .map_err(|_| "storage schema unreadable")?
        .list_tables()
        .map_err(|_| "storage schema unreadable")?
        .any(|table| table.name() == STORAGE.name()))
}
pub(super) fn stored_role(database: &impl ReadableDatabase) -> Result<Option<Role>, String> {
    if !is_enabled(database)? {
        return Ok(None);
    }
    let txn = database
        .begin_read()
        .map_err(|_| "storage metadata unavailable")?;
    let table = txn
        .open_table(STORAGE)
        .map_err(|_| "storage metadata unavailable")?;
    let name = value(&table, "role")?;
    Ok(Some(Role::parse(
        std::str::from_utf8(&name).map_err(|_| "invalid storage role")?,
    )?))
}
pub(super) fn load_base(
    database: &impl ReadableDatabase,
    config: Config,
    path: &Path,
) -> Result<Option<State>, String> {
    if !is_enabled(database)? {
        return Ok(None);
    }
    let txn = database
        .begin_read()
        .map_err(|_| "storage metadata unreadable")?;
    let table = txn
        .open_table(STORAGE)
        .map_err(|_| "storage metadata unavailable")?;
    let role_bytes = value(&table, "role")?;
    let role = Role::parse(std::str::from_utf8(&role_bytes).map_err(|_| "invalid storage role")?)?;
    let prefix: crate::wire::Hash = value(&table, "prefix")?
        .as_slice()
        .try_into()
        .map_err(|_| "invalid storage prefix")?;
    let bytes = value(&table, "base")?;
    let seal = value(&table, "seal")?;
    let mut message = role.name().as_bytes().to_vec();
    message.push(0);
    message.extend_from_slice(&prefix);
    message.extend_from_slice(&bytes);
    identity(path, &config)?
        .descriptor()
        .map_err(|_| "local storage identity unavailable")?
        .verify_local_storage(blake3::derive_key(DOMAIN, &message), &seal)
        .map_err(|_| "local storage checkpoint seal mismatch")?;
    let base = checkpoint::decode_sealed(&bytes, config.clone())?;
    let blocks = txn
        .open_table(BLOCKS)
        .map_err(|_| "storage canonical table unavailable")?;
    let protected = if txn
        .list_tables()
        .map_err(|_| "protected history schema unavailable")?
        .any(|table| table.name() == super::protected_history::PROTECTED.name())
    {
        Some(
            txn.open_table(super::protected_history::PROTECTED)
                .map_err(|_| "protected history index unavailable")?,
        )
    } else {
        None
    };
    let mut protected_count = 0u64;
    let mut checked = initial_prefix(&config);
    let mut parent = config.genesis_id();
    for height in 1..=base.height {
        let row = blocks
            .get(height)
            .map_err(|_| "storage prefix unavailable")?
            .ok_or("storage prefix missing")?;
        let (bytes, _) = split_record(row.value())?;
        let normalized;
        let record = if bytes.starts_with(b"SWLC0001") {
            if protected
                .as_ref()
                .map(|index| index.get(height))
                .transpose()
                .map_err(|_| "protected history index unreadable")?
                .flatten()
                .is_some()
            {
                return Err("protected history is missing its full proof".into());
            }
            row.value()
        } else {
            let expected = protected
                .as_ref()
                .ok_or("full proof below replay base lacks protected history index")?
                .get(height)
                .map_err(|_| "protected history index unreadable")?
                .ok_or("full proof below replay base lacks protection")?;
            normalized = super::protected_history::authenticate(row.value(), expected.value())?;
            protected_count += 1;
            normalized.as_slice()
        };
        let (bytes, _) = split_record(record)?;
        let compact = CompactBlock::decode(bytes)?;
        if compact.block.height != height || compact.block.parent != parent {
            return Err("local storage public prefix is not canonical".into());
        }
        checked = next_prefix(checked, height, record);
        parent = compact.id;
    }
    if let Some(index) = protected {
        let count = index
            .len()
            .map_err(|_| "protected history count unreadable")?;
        if count > 0 {
            if !role.serves_historical_proofs() || count != protected_count + 1 {
                return Err("protected history differs from the sealed prefix".into());
            }
            let clock = index
                .get(0)
                .map_err(|_| "protected recovery clock unavailable")?
                .ok_or("protected recovery clock missing")?;
            super::protected_history::recovery_clock(clock.value())?;
        }
    }
    if checked != prefix || parent != base.tip {
        return Err("local storage public prefix differs from sealed checkpoint".into());
    }
    Ok(Some(base))
}

fn proof_bytes(block: &Block) -> Result<u64, String> {
    block
        .transactions
        .iter()
        .map(|t| t.proof.len() as u64)
        .chain(block.issuances.iter().map(|i| i.proof.len() as u64))
        .try_fold(block.settlement_proof.len() as u64, |a, b| a.checked_add(b))
        .ok_or_else(|| "proof byte accounting overflow".into())
}
/// Counts file metadata only. Never opens key, wallet, configuration or log data.
fn directory_sizes(directory: &Path) -> Result<(u64, Option<u64>), String> {
    let mut stack = vec![directory.to_owned()];
    let mut entries = 0u64;
    let mut logical = 0u64;
    #[cfg(unix)]
    let mut allocated = 0u64;
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(path).map_err(|_| "storage directory metrics unavailable")? {
            let entry = entry.map_err(|_| "storage directory metrics unavailable")?;
            entries += 1;
            if entries > 65536 {
                return Err("storage directory metric entry budget".into());
            }
            let metadata = match std::fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err("storage directory metrics unavailable".into()),
            };
            if metadata.file_type().is_symlink() {
                return Err("storage directory metrics reject links".into());
            }
            if metadata.is_dir() {
                stack.push(entry.path());
            } else if metadata.is_file() {
                logical = logical
                    .checked_add(metadata.len())
                    .ok_or("storage metric overflow")?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    allocated = allocated
                        .checked_add(metadata.blocks().saturating_mul(512))
                        .ok_or("storage metric overflow")?;
                }
            }
        }
    }
    #[cfg(unix)]
    {
        Ok((logical, Some(allocated)))
    }
    #[cfg(not(unix))]
    {
        Ok((logical, None))
    }
}

pub(super) fn record(txn: &redb::WriteTransaction, block: &Block) -> Result<(), String> {
    if !txn
        .list_tables()
        .map_err(|_| "storage schema unavailable")?
        .any(|table| table.name() == STORAGE.name())
    {
        return Ok(());
    }
    let proof_bytes = proof_bytes(block)?;
    let mut bytes = block.id()?.to_vec();
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&proof_bytes.to_le_bytes());
    txn.open_table(FINALITY)
        .map_err(|_| "storage finality unavailable")?
        .insert(block.height, bytes.as_slice())
        .map_err(|_| "storage accounting write failed")?;
    Ok(())
}
pub(super) fn forget(txn: &redb::WriteTransaction, height: u64) -> Result<(), String> {
    if !txn
        .list_tables()
        .map_err(|_| "storage schema unavailable")?
        .any(|table| table.name() == STORAGE.name())
    {
        return Ok(());
    }
    txn.open_table(FINALITY)
        .map_err(|_| "storage finality unavailable")?
        .remove(height)
        .map_err(|_| "storage accounting removal failed")?;
    Ok(())
}

#[derive(Clone, Copy)]
enum ServiceGate {
    Ready(RecoveryBoundary),
    Paused(&'static str),
}
impl Store {
    fn qualified_checkpoint_roster(&self) -> Result<Option<crate::wire::Hash>, String> {
        if !is_enabled(&self.database)? {
            return Ok(None);
        }
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "checkpoint delivery policy unavailable")?;
        let storage = transaction
            .open_table(STORAGE)
            .map_err(|_| "checkpoint delivery policy unavailable")?;
        storage
            .get("qualified_roster")
            .map_err(|_| "checkpoint delivery policy unreadable")?
            .map(|row| {
                row.value()
                    .try_into()
                    .map_err(|_| "invalid checkpoint delivery qualification".into())
            })
            .transpose()
    }
    fn service_checkpoint_gate(
        &self,
        roster: Option<&Roster>,
        now: u64,
    ) -> Result<ServiceGate, String> {
        let Some(roster) = roster else {
            return Ok(ServiceGate::Paused("checkpoint_delivery_unavailable"));
        };
        if self.qualified_checkpoint_roster()? != Some(roster.digest()) {
            return Ok(ServiceGate::Paused("checkpoint_acceptance_required"));
        }
        let Some(certificate) = self.latest_engineering_checkpoint()? else {
            return Ok(ServiceGate::Paused("checkpoint_unavailable"));
        };
        let authenticated = match certificate.authenticate(roster, None, now) {
            Ok(value) => value,
            Err(_) => return Ok(ServiceGate::Paused("checkpoint_invalid")),
        };
        if !authenticated.pruning_fresh(now) {
            return Ok(ServiceGate::Paused("checkpoint_stale"));
        }
        let statement = &certificate.statement;
        let local_id = match self
            .state
            .snapshots
            .iter()
            .find(|snapshot| snapshot.selector.height == statement.height)
        {
            Some(snapshot) => snapshot.selector.block_id,
            None => match self.canonical_id(statement.height) {
                Ok(id) => id,
                Err(_) => return Ok(ServiceGate::Paused("checkpoint_not_canonical")),
            },
        };
        if statement.binding != Binding::new(&self.state.config)
            || statement.block_id != local_id
            || statement
                .height
                .checked_add(checkpoint_auth::CONFIRMATIONS)
                .is_none_or(|minimum| minimum > self.state.height)
        {
            return Ok(ServiceGate::Paused("checkpoint_not_canonical"));
        }
        Ok(ServiceGate::Ready(RecoveryBoundary {
            height: statement.height,
            sealed_unix_seconds: statement.issued_unix_seconds,
            tail_complete: true,
        }))
    }
    /// Explicit activation after checkpoint delivery and recovery acceptance.
    /// The CLI must use the immutable engineering release roster; a certificate
    /// or peer cannot enable pruning or install replacement authorities.
    pub fn qualify_service_checkpoint_delivery(
        &mut self,
        roster: &Roster,
        now: u64,
    ) -> Result<(), String> {
        if self
            .storage_role()?
            .is_none_or(|role| !role.serves_historical_proofs())
        {
            return Err("checkpoint delivery qualification requires a service storage role".into());
        }
        if roster.binding() != Binding::new(&self.state.config) {
            return Err("checkpoint delivery roster context mismatch".into());
        }
        if !self.state.config.fixture {
            let release = checkpoint_auth::release_roster(Binding::new(&self.state.config))?
                .ok_or("checkpoint release roster is not installed")?;
            if release.digest() != roster.digest() {
                return Err("checkpoint delivery requires the pinned release roster".into());
            }
        }
        let certificate = self
            .latest_engineering_checkpoint()?
            .ok_or("checkpoint delivery requires an accepted certificate")?;
        let authenticated = certificate.authenticate(roster, None, now)?;
        if !authenticated.pruning_fresh(now)
            || self.canonical_id(certificate.statement.height)? != certificate.statement.block_id
            || certificate
                .statement
                .height
                .checked_add(checkpoint_auth::CONFIRMATIONS)
                .is_none_or(|minimum| minimum > self.state.height)
        {
            return Err(
                "checkpoint delivery requires a fresh confirmed canonical checkpoint".into(),
            );
        }
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "checkpoint qualification transaction unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "checkpoint qualification durability unavailable")?;
        transaction
            .open_table(STORAGE)
            .map_err(|_| "checkpoint qualification policy unavailable")?
            .insert("qualified_roster", roster.digest().as_slice())
            .map_err(|_| "checkpoint qualification write failed")?;
        transaction
            .commit()
            .map_err(|_| "checkpoint qualification commit failed".into())
    }
    /// Capacity is an alarm only and never disables validation or storage.
    pub fn storage_ingestion_ready(&self) -> Result<bool, String> {
        Ok(true)
    }
    /// Explicitly migrate local storage policy after this owner has verified the
    /// complete existing history. Existing roles cannot be changed implicitly.
    pub fn configure_storage(&mut self, role: Role) -> Result<(), String> {
        let signer = identity(&self.path, &self.state.config)?;
        if is_enabled(&self.database)? {
            if self.storage_role()? == Some(role) {
                return Ok(());
            }
            if self
                .storage_base
                .as_ref()
                .is_none_or(|base| base.height != 0)
            {
                return Err(
                    "role change after expiry requires proof backfill before explicit migration"
                        .into(),
                );
            }
            // An explicit role selection before expiry preserves all proofs.
            // Restart the service finality-age observations conservatively.
        }
        let genesis = State::new(self.state.config.clone())?;
        let prefix = initial_prefix(&self.state.config);
        let seal = signer
            .seal_local_storage(blake3::derive_key(
                DOMAIN,
                &payload(role, prefix, &genesis)?,
            ))
            .map_err(|_| "local storage checkpoint signing failed")?;
        let mut txn = self
            .database
            .begin_write()
            .map_err(|_| "storage migration unavailable")?;
        txn.set_durability(Durability::Immediate)
            .map_err(|_| "storage durability unavailable")?;
        {
            let mut meta = txn
                .open_table(STORAGE)
                .map_err(|_| "storage metadata initialization failed")?;
            meta.remove("qualified_roster")
                .map_err(|_| "storage qualification reset failed")?;
            for (key, value) in [
                ("role", role.name().as_bytes()),
                ("prefix", prefix.as_slice()),
                ("base", checkpoint::encode(&genesis)?.as_slice()),
                ("seal", seal.as_slice()),
                ("last_clock", &0u64.to_le_bytes()),
            ] {
                meta.insert(key, value)
                    .map_err(|_| "storage metadata initialization failed")?;
            }
        }
        txn.open_table(FINALITY)
            .map_err(|_| "storage finality initialization failed")?;
        for height in 1..=self.state.height {
            let row = txn
                .open_table(BLOCKS)
                .map_err(|_| "storage history unavailable")?
                .get(height)
                .map_err(|_| "storage history unreadable")?
                .ok_or("storage history missing")?
                .value()
                .to_vec();
            let block = Block::decode(split_record(&row)?.0, &self.state.config.network)?;
            record(&txn, &block)?;
        }
        txn.commit()
            .map_err(|_| "storage migration commit failed")?;
        self.storage_base = Some(genesis);
        self.retention_clock_started = false;
        Ok(())
    }

    pub fn local_proof_blocks(&self) -> Result<Option<u64>, String> {
        if self
            .storage_role()?
            .is_none_or(Role::serves_historical_proofs)
        {
            return Ok(None);
        }
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "storage policy read unavailable")?;
        let table = transaction
            .open_table(STORAGE)
            .map_err(|_| "storage policy unavailable")?;
        let row = table
            .get("local_blocks")
            .map_err(|_| "storage policy unreadable")?;
        let blocks = match row {
            Some(row) => u64::from_le_bytes(
                row.value()
                    .try_into()
                    .map_err(|_| "invalid local proof window")?,
            ),
            None => storage_policy::LOCAL_PROOF_BLOCKS,
        };
        if blocks < storage_policy::MIN_LOCAL_PROOF_BLOCKS {
            return Err("local proof window below minimum".into());
        }
        Ok(Some(blocks))
    }
    pub fn configure_local_proof_blocks(&mut self, blocks: u64) -> Result<(), String> {
        if blocks < storage_policy::MIN_LOCAL_PROOF_BLOCKS {
            return Err("local proof retention requires at least 24 blocks".into());
        }
        if self
            .storage_role()?
            .is_none_or(Role::serves_historical_proofs)
        {
            return Err("local proof count requires miner or ordinary role".into());
        }
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| "storage policy write unavailable")?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| "storage policy durability unavailable")?;
        transaction
            .open_table(STORAGE)
            .map_err(|_| "storage policy unavailable")?
            .insert("local_blocks", blocks.to_le_bytes().as_slice())
            .map_err(|_| "storage policy write failed")?;
        transaction
            .commit()
            .map_err(|_| "storage policy commit failed")?;
        Ok(())
    }

    pub fn storage_role(&self) -> Result<Option<Role>, String> {
        stored_role(&self.database)
    }

    pub fn serves_historical_proofs(&self) -> Result<bool, String> {
        Ok(self
            .storage_role()?
            .is_none_or(Role::serves_historical_proofs))
    }

    /// Expire only a contiguous canonical prefix. The new local replay base,
    /// public records and expiry metadata become visible at one durable commit.
    pub fn expire_proofs(
        &mut self,
        now: u64,
        clock_certain: bool,
        verifier: &impl BlockVerifier,
    ) -> Result<u64, String> {
        let roster = checkpoint_auth::release_roster(Binding::new(&self.state.config))?;
        self.expire_proofs_with_roster(now, clock_certain, verifier, roster.as_ref())
    }
    pub(super) fn expire_proofs_with_roster(
        &mut self,
        now: u64,
        clock_certain: bool,
        _verifier: &impl BlockVerifier,
        roster: Option<&Roster>,
    ) -> Result<u64, String> {
        let Some(role) = self.storage_role()? else {
            return Ok(0);
        };
        if !clock_certain {
            return Ok(0);
        }
        // Finality observation continues while delivery is unqualified or
        // checkpoints are stale. Only proof deletion is paused by this gate.
        let service_gate = if role.serves_historical_proofs()
            && (!self.state.config.fixture
                || roster.is_some()
                || self.qualified_checkpoint_roster()?.is_some())
        {
            Some(self.service_checkpoint_gate(roster, now)?)
        } else {
            None
        };
        let can_prune = !matches!(service_gate, Some(ServiceGate::Paused(_)));
        let checkpoint_ceiling = match service_gate {
            Some(ServiceGate::Ready(boundary)) => boundary.height,
            Some(ServiceGate::Paused(_)) => 0,
            None => u64::MAX,
        };
        let local_blocks = self
            .local_proof_blocks()?
            .unwrap_or(storage_policy::LOCAL_PROOF_BLOCKS);
        let signer = identity(&self.path, &self.state.config)?;
        let mut base = self
            .storage_base
            .clone()
            .ok_or("storage checkpoint missing")?;
        let mut txn = self
            .database
            .begin_write()
            .map_err(|_| "storage expiration unavailable")?;
        txn.set_durability(Durability::Immediate)
            .map_err(|_| "storage durability unavailable")?;
        let mut meta = txn
            .open_table(STORAGE)
            .map_err(|_| "storage metadata unavailable")?;
        let last = u64::from_le_bytes(
            value(&meta, "last_clock")?
                .as_slice()
                .try_into()
                .map_err(|_| "invalid storage clock")?,
        );
        // Do not count unobserved downtime or a clock step across restart toward
        // service expiry. In-process callers also enforce a monotonic clock
        // guard. Conservatively extend retention on any backward step.
        let new_session = !self.retention_clock_started;
        let backward = now < last;
        let mut prefix: crate::wire::Hash = value(&meta, "prefix")?
            .as_slice()
            .try_into()
            .map_err(|_| "invalid storage prefix")?;
        let mut finality = txn
            .open_table(FINALITY)
            .map_err(|_| "storage finality unavailable")?;
        let mut blocks = txn
            .open_table(BLOCKS)
            .map_err(|_| "storage history unavailable")?;
        let finalized = chain::finalized_height(self.state.height);
        // Existing records have no trustworthy finality time. Their service
        // window starts at the first observation, never at a block timestamp.
        for height in base.height.saturating_add(1)..=finalized {
            let mut row = finality
                .get(height)
                .map_err(|_| "storage finality unreadable")?
                .ok_or("storage finality missing")?
                .value()
                .to_vec();
            if row.len() != 48 {
                return Err("invalid storage finality record".into());
            }
            let observed = u64::from_le_bytes(row[32..40].try_into().expect("checked row"));
            let rebased = if observed == 0 || backward {
                now.max(1)
            } else if new_session && last > 0 {
                // Preserve only the previously observed, certain-clock age.
                observed.saturating_add(now - last).min(now)
            } else {
                observed
            };
            if rebased != observed {
                row[32..40].copy_from_slice(&rebased.to_le_bytes());
                finality
                    .insert(height, row.as_slice())
                    .map_err(|_| "storage finality write failed")?;
            }
        }
        let old_height = base.height;
        let mut inspected_bytes = 0usize;
        for height in base.height.saturating_add(1)
            ..=finalized
                .min(checkpoint_ceiling)
                .min(base.height.saturating_add(MAX_EXPIRE_BLOCKS))
        {
            let row = finality
                .get(height)
                .map_err(|_| "storage finality unreadable")?
                .ok_or("storage finality missing")?
                .value()
                .to_vec();
            if row.len() != 48 {
                return Err("invalid storage finality record".into());
            }
            let block_id = row[..32]
                .try_into()
                .map_err(|_| "invalid storage identity")?;
            let observed =
                u64::from_le_bytes(row[32..40].try_into().expect("checked finality record"));
            let recovery = Some(match service_gate {
                Some(ServiceGate::Ready(boundary)) => boundary,
                _ => RecoveryBoundary {
                    height,
                    sealed_unix_seconds: now,
                    tail_complete: true,
                },
            });
            if storage_policy::expired_with_local_blocks(
                role,
                height,
                block_id,
                self.state.height,
                Some(FinalityObservation {
                    block_id,
                    observed_unix_seconds: observed,
                }),
                now,
                true,
                recovery,
                local_blocks,
            )
            .is_err()
            {
                break;
            }
            let block_row = blocks
                .get(height)
                .map_err(|_| "storage history unreadable")?
                .ok_or("storage history missing")?;
            let length = block_row
                .value()
                .len()
                .checked_sub(FINGERPRINT_BYTES)
                .ok_or("invalid storage record")?;
            if inspected_bytes
                .checked_add(length)
                .is_none_or(|n| n > MAX_EXPIRE_BYTES)
            {
                break;
            }
            inspected_bytes += length;
            let stored = block_row.value().to_vec();
            drop(block_row);
            let (bytes, fingerprint) = split_record(&stored)?;
            let mut compact = CompactBlock::export_canonical(bytes)?;
            let public = CompactBlock::decode(&compact)?;
            if public.id != block_id {
                return Err("storage finality belongs to another canonical block".into());
            }
            // Store open/append already verified these immutable canonical
            // rows. Authenticate their public effects to the same worked seed
            // and compare every independently saved full-state fingerprint.
            // Repeating STARK verification here would stall owner-loop work.
            super::public_replay::reconstruct_public_effects(&mut base, &public)?;
            if base.fingerprint().as_slice() != fingerprint {
                return Err("storage replay fingerprint mismatch".into());
            }
            compact.extend_from_slice(fingerprint);
            prefix = next_prefix(prefix, height, &compact);
            blocks
                .insert(height, compact.as_slice())
                .map_err(|_| "storage public record write failed")?;
            let mut observed = row;
            observed[40..48].copy_from_slice(&0u64.to_le_bytes());
            finality
                .insert(height, observed.as_slice())
                .map_err(|_| "storage accounting write failed")?;
        }
        let deleted = base.height - old_height;
        drop(blocks);
        drop(finality);
        let protected = super::protected_history::maintain(
            &txn,
            super::protected_history::Maintenance {
                role,
                base_height: base.height,
                tip: self.state.height,
                now,
                last_clock: last,
                new_session,
                backward,
                recovery: match service_gate {
                    Some(ServiceGate::Ready(boundary)) => Some(boundary),
                    _ => None,
                },
                deletion_enabled: can_prune,
                remaining_blocks: MAX_EXPIRE_BLOCKS.saturating_sub(deleted),
                remaining_bytes: MAX_EXPIRE_BYTES.saturating_sub(inspected_bytes),
            },
        )?;
        inspected_bytes = inspected_bytes.saturating_add(protected.inspected_bytes);
        // Detached branches can no longer be selected below this verified base.
        // Preserve their authenticated public fields and local reward evidence.
        if can_prune
            && protected.detached_ready
            && txn
                .list_tables()
                .map_err(|_| "storage schema unavailable")?
                .any(|table| table.name() == DETACHED.name())
        {
            let mut detached = txn
                .open_table(DETACHED)
                .map_err(|_| "detached history unavailable")?;
            let mut replacements = Vec::new();
            for row in detached
                .iter()
                .map_err(|_| "detached history unavailable")?
            {
                let (key, row) = row.map_err(|_| "detached history unavailable")?;
                let (bytes, fingerprint) = split_record(detached_record(row.value())?)?;
                if bytes.starts_with(b"SWLC0001") {
                    continue;
                }
                let block = Block::decode(bytes, &self.state.config.network)?;
                if block.height > base.height {
                    continue;
                }
                if key.value() != block.id()?.as_slice() {
                    return Err("detached storage identity mismatch".into());
                }
                if inspected_bytes
                    .checked_add(bytes.len())
                    .is_none_or(|n| n > MAX_EXPIRE_BYTES)
                    || replacements.len() >= MAX_EXPIRE_BLOCKS as usize
                {
                    break;
                }
                inspected_bytes += bytes.len();
                let mut public = CompactBlock::export_canonical(bytes)?;
                public.extend_from_slice(fingerprint);
                replacements.push((key.value().to_vec(), encode_detached(&public)));
            }
            for (key, value) in replacements {
                detached
                    .insert(key.as_slice(), value.as_slice())
                    .map_err(|_| "detached storage write failed")?;
            }
        }
        if deleted > 0 {
            let encoded = checkpoint::encode(&base)?;
            let seal = signer
                .seal_local_storage(blake3::derive_key(DOMAIN, &payload(role, prefix, &base)?))
                .map_err(|_| "local storage checkpoint signing failed")?;
            meta.insert("base", encoded.as_slice())
                .map_err(|_| "storage checkpoint write failed")?;
            meta.insert("prefix", prefix.as_slice())
                .map_err(|_| "storage prefix write failed")?;
            meta.insert("seal", seal.as_slice())
                .map_err(|_| "storage seal write failed")?;
        }
        meta.insert("last_clock", now.to_le_bytes().as_slice())
            .map_err(|_| "storage clock write failed")?;
        drop(meta);
        txn.commit()
            .map_err(|_| "storage expiration commit failed")?;
        self.retention_clock_started = true;
        self.storage_base = Some(base);
        Ok(deleted.saturating_add(protected.expired))
    }

    pub fn storage_metrics(&self) -> Result<Value, String> {
        let role = self.storage_role()?;
        let mut canonical_proof_bytes = 0u64;
        let mut retained = 0u64;
        let mut pruned = 0u64;
        let mut protected_proof_bytes = 0u64;
        let mut protected_proof_blocks = 0u64;
        let txn = self
            .database
            .begin_read()
            .map_err(|_| "storage metrics unavailable")?;
        if role.is_some() {
            let protected = if txn
                .list_tables()
                .map_err(|_| "protected history metrics unavailable")?
                .any(|table| table.name() == super::protected_history::PROTECTED.name())
            {
                Some(
                    txn.open_table(super::protected_history::PROTECTED)
                        .map_err(|_| "protected history metrics unavailable")?,
                )
            } else {
                None
            };
            let finality = txn
                .open_table(FINALITY)
                .map_err(|_| "storage metrics unavailable")?;
            if finality.len().map_err(|_| "storage metrics unavailable")? != self.state.height {
                return Err("proof accounting count differs from canonical history".into());
            }
            for row in finality.iter().map_err(|_| "storage metrics unreadable")? {
                let (height, row) = row.map_err(|_| "storage metrics unreadable")?;
                if row.value().len() != 48 {
                    return Err("invalid storage metrics row".into());
                }
                let bytes = u64::from_le_bytes(
                    row.value()[40..48].try_into().expect("checked metrics row"),
                );
                canonical_proof_bytes = canonical_proof_bytes
                    .checked_add(bytes)
                    .ok_or("proof metrics overflow")?;
                if height.value() <= self.storage_base.as_ref().map_or(0, |base| base.height) {
                    let marker = protected
                        .as_ref()
                        .map(|index| index.get(height.value()))
                        .transpose()
                        .map_err(|_| "protected history metrics unreadable")?
                        .flatten();
                    if let Some(marker) = marker {
                        if bytes == 0
                            || marker.value().len() != 64
                            || marker.value()[..32] != row.value()[..32]
                        {
                            return Err(
                                "protected proof metrics differ from canonical history".into()
                            );
                        }
                        retained += 1;
                        protected_proof_blocks += 1;
                        protected_proof_bytes = protected_proof_bytes
                            .checked_add(bytes)
                            .ok_or("protected proof metrics overflow")?;
                    } else {
                        if bytes != 0 {
                            return Err("expired proof accounting is nonzero".into());
                        }
                        pruned += 1;
                    }
                } else {
                    retained += 1;
                }
            }
        }
        let mut detached_proof_bytes = 0u64;
        let mut detached_record_bytes = 0u64;
        if txn
            .list_tables()
            .map_err(|_| "storage metrics unavailable")?
            .any(|table| table.name() == DETACHED.name())
        {
            let detached = txn
                .open_table(DETACHED)
                .map_err(|_| "detached metrics unavailable")?;
            for row in detached
                .iter()
                .map_err(|_| "detached metrics unavailable")?
            {
                let (_, row) = row.map_err(|_| "detached metrics unavailable")?;
                detached_record_bytes = detached_record_bytes
                    .checked_add(row.value().len() as u64)
                    .ok_or("storage metrics overflow")?;
                let (bytes, _) = split_record(detached_record(row.value())?)?;
                let (block, _) = public_record(bytes, &self.state.config.network)?;
                detached_proof_bytes = detached_proof_bytes
                    .checked_add(proof_bytes(&block)?)
                    .ok_or("storage metrics overflow")?;
            }
        }
        let latest_checkpoint = self.latest_engineering_checkpoint()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
        let checkpoint_age = latest_checkpoint
            .as_ref()
            .and_then(|c| now.and_then(|now| now.checked_sub(c.statement.issued_unix_seconds)));
        let qualified = self.qualified_checkpoint_roster()?.is_some();
        let release_roster = checkpoint_auth::release_roster(Binding::new(&self.state.config))?;
        let gate = if role.is_some_and(Role::serves_historical_proofs)
            && (!self.state.config.fixture || qualified || release_roster.is_some())
        {
            Some(self.service_checkpoint_gate(release_roster.as_ref(), now.unwrap_or(0))?)
        } else {
            None
        };
        let (directory_logical, directory_allocated) =
            directory_sizes(self.path.parent().ok_or("storage directory missing")?)?;
        let metadata =
            std::fs::metadata(&self.path).map_err(|_| "storage file metadata unavailable")?;
        #[cfg(unix)]
        let allocated = {
            use std::os::unix::fs::MetadataExt;
            Some(metadata.blocks().saturating_mul(512))
        };
        #[cfg(not(unix))]
        let allocated: Option<u64> = None;
        Ok(
            json!({"role":role.map(Role::name),"policy_active":role.is_some(),
            "service_retention_seconds":role.filter(|r| r.serves_historical_proofs()).map(|_| storage_policy::SERVICE_RETENTION_SECONDS),
            "checkpoint_publication_interval_seconds":role.filter(|r| r.serves_historical_proofs()).map(|_| storage_policy::CHECKPOINT_PUBLICATION_SECONDS),
            "local_proof_blocks":self.local_proof_blocks()?,
            "node_storage_limit_bytes":role.filter(|r| r.serves_historical_proofs()).map(|_| crate::storage_budget::NODE_LIMIT_BYTES),
            "database_limit_bytes":Value::Null,
            "ingestion_limit_bytes":Value::Null,
            "auxiliary_limit_bytes":Value::Null,
            "storage_ingestion_paused":false,
            "storage_budget_behavior":"alarm-only",
            "storage_budget_exceeded":crate::storage_budget::budget_exceeded(role,directory_logical),
            "storage_limit_scope":role.filter(|r| r.serves_historical_proofs()).map(|_| "native-owned-logical-file-bytes"),
            "proof_body_bytes":role.map(|_| canonical_proof_bytes.saturating_add(detached_proof_bytes)),
            "canonical_proof_body_bytes":role.map(|_| canonical_proof_bytes),
            "protected_historical_proof_blocks":protected_proof_blocks,
            "protected_historical_proof_bytes":protected_proof_bytes,
            "detached_proof_body_bytes":detached_proof_bytes,"detached_record_bytes":detached_record_bytes,
            "node_directory_logical_bytes":directory_logical,"node_directory_allocated_bytes":directory_allocated,
            "local_replay_base_height":self.storage_base.as_ref().map(|base| base.height),
            "remote_checkpoint_bootstrap":qualified && release_roster.is_some(),
            "service_checkpoint_delivery_qualified":qualified,
            "latest_checkpoint_height":latest_checkpoint.as_ref().map(|c|c.statement.height),
            "latest_checkpoint_sequence":latest_checkpoint.as_ref().map(|c|c.statement.sequence),
            "last_checkpoint_publication_unix_seconds":latest_checkpoint.as_ref().map(|c|c.statement.issued_unix_seconds),
            "checkpoint_age_seconds":checkpoint_age,
            "checkpoint_pruning_paused":matches!(gate, Some(ServiceGate::Paused(_))),
            "expiry_state":match role {
                None => "unconfigured",
                Some(_) if matches!(gate, Some(ServiceGate::Paused(_))) => match gate {
                    Some(ServiceGate::Paused(reason)) => reason, _ => "checkpoint_unavailable",
                },
                Some(_) => "active",
            },"retained_proof_blocks":role.map(|_| retained),
            "pruned_proof_blocks":role.map(|_| pruned),"database_logical_bytes":metadata.len(),
            "database_allocated_bytes":allocated,"history_proof_service":self.serves_historical_proofs()?,
            "scope":"proof-bodies-and-node-directory-file-metadata"}),
        )
    }

    /// Caller holds the exclusive service lease and must not run a producer or
    /// network owner. redb compacts the existing file; no public data is removed.
    pub fn compact_expired_storage(
        &mut self,
        verifier: &impl BlockVerifier,
    ) -> Result<bool, String> {
        if self.storage_role()?.is_none() {
            return Err("proof retention is not configured".into());
        }
        let before = self.state.fingerprint();
        let changed = self
            .database
            .compact()
            .map_err(|_| "local database compaction failed; preserve the store")?;
        let base = load_base(&self.database, self.state.config.clone(), &self.path)?;
        let checked = replay_history(
            &self.database,
            self.state.config.clone(),
            verifier,
            None,
            base,
        )?
        .0;
        if checked.fingerprint() != before {
            return Err("compacted storage state differs; preserve the store".into());
        }
        Ok(changed)
    }
}
