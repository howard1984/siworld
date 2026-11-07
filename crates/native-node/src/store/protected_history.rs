//! Retained local proof bodies below an adopted engineering replay base.
//! The local seal authenticates each row's normalized compact representation;
//! full rows remain available until their independently observed service age.
use super::*;
use crate::{
    compact::CompactBlock,
    storage_policy::{self, FinalityObservation, RecoveryBoundary, Role},
    wire::Hash,
};

pub(super) const PROTECTED: TableDefinition<u64, &[u8]> =
    TableDefinition::new("checkpoint-protected-proofs-v1");
const RECOVERY_CLOCK: u64 = 0;

pub(super) fn normalized_record(record: &[u8]) -> Result<(Vec<u8>, Hash), String> {
    let (bytes, fingerprint) = split_record(record)?;
    let mut compact = if bytes.starts_with(b"SWLC0001") {
        bytes.to_vec()
    } else {
        CompactBlock::export_canonical(bytes)?
    };
    let decoded = CompactBlock::decode(&compact)?;
    compact.extend_from_slice(fingerprint);
    Ok((compact, decoded.id))
}

pub(super) fn marker(normalized: &[u8], id: Hash) -> [u8; 64] {
    let mut marker = [0u8; 64];
    marker[..32].copy_from_slice(&id);
    marker[32..].copy_from_slice(blake3::hash(normalized).as_bytes());
    marker
}

pub(super) fn authenticate(record: &[u8], expected: &[u8]) -> Result<Vec<u8>, String> {
    if expected.len() != 64 || split_record(record)?.0.starts_with(b"SWLC0001") {
        return Err("invalid protected full-proof record".into());
    }
    let (normalized, id) = normalized_record(record)?;
    if marker(&normalized, id) != expected {
        return Err("protected full-proof record differs from accepted history".into());
    }
    Ok(normalized)
}

pub(super) fn recovery_clock(bytes: &[u8]) -> Result<u64, String> {
    let clock = u64::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| "invalid protected recovery clock")?,
    );
    if clock == 0 {
        return Err("invalid protected recovery clock".into());
    }
    Ok(clock)
}

pub(super) struct Maintenance {
    pub role: Role,
    pub base_height: u64,
    pub tip: u64,
    pub now: u64,
    pub last_clock: u64,
    pub new_session: bool,
    pub backward: bool,
    pub recovery: Option<RecoveryBoundary>,
    pub deletion_enabled: bool,
    pub remaining_blocks: u64,
    pub remaining_bytes: usize,
}
impl Maintenance {
    fn observed(&self, previous: u64) -> u64 {
        if previous == 0 || self.backward {
            self.now.max(1)
        } else if self.new_session && self.last_clock > 0 {
            previous
                .saturating_add(self.now - self.last_clock)
                .min(self.now)
        } else {
            previous
        }
    }
}

pub(super) struct Outcome {
    pub expired: u64,
    pub inspected_bytes: usize,
    pub detached_ready: bool,
}

/// The caller commits these changes with its canonical expiry/clock updates.
/// Only normalized proof bodies are removed; permanent records are unchanged.
pub(super) fn maintain(
    transaction: &redb::WriteTransaction,
    policy: Maintenance,
) -> Result<Outcome, String> {
    let mut outcome = Outcome {
        expired: 0,
        inspected_bytes: 0,
        detached_ready: true,
    };
    if !transaction
        .list_tables()
        .map_err(|_| "protected history schema unavailable")?
        .any(|table| table.name() == PROTECTED.name())
    {
        return Ok(outcome);
    }
    let mut protected = transaction
        .open_table(PROTECTED)
        .map_err(|_| "protected history index unavailable")?;
    if protected
        .is_empty()
        .map_err(|_| "protected history index unreadable")?
    {
        return Ok(outcome);
    }
    if !policy.role.serves_historical_proofs() {
        return Err("protected history requires a service storage role".into());
    }
    let previous = protected
        .get(RECOVERY_CLOCK)
        .map_err(|_| "protected recovery clock unavailable")?
        .ok_or("protected recovery clock missing")?;
    let observed = policy.observed(recovery_clock(previous.value())?);
    drop(previous);
    protected
        .insert(RECOVERY_CLOCK, observed.to_le_bytes().as_slice())
        .map_err(|_| "protected recovery clock write failed")?;
    outcome.detached_ready = policy
        .now
        .checked_sub(observed)
        .is_some_and(|age| age >= storage_policy::SERVICE_RETENTION_SECONDS);
    let mut blocks = transaction
        .open_table(BLOCKS)
        .map_err(|_| "protected canonical history unavailable")?;
    let mut finality = transaction
        .open_table(retention::FINALITY)
        .map_err(|_| "protected proof accounting unavailable")?;
    let mut expired = Vec::new();
    for row in protected
        .range(1..)
        .map_err(|_| "protected history iteration unavailable")?
    {
        let (height, expected) = row.map_err(|_| "protected history row unavailable")?;
        let height = height.value();
        if height > policy.base_height || expected.value().len() != 64 {
            return Err("protected history exceeds the sealed replay base".into());
        }
        let mut accounting = finality
            .get(height)
            .map_err(|_| "protected proof accounting unreadable")?
            .ok_or("protected proof accounting missing")?
            .value()
            .to_vec();
        if accounting.len() != 48 || accounting[..32] != expected.value()[..32] {
            return Err("protected proof accounting identity mismatch".into());
        }
        let proof_bytes = u64::from_le_bytes(accounting[40..48].try_into().expect("checked row"));
        if proof_bytes == 0 {
            return Err("protected proof accounting is empty".into());
        }
        let previous = u64::from_le_bytes(accounting[32..40].try_into().expect("checked row"));
        let observed = policy.observed(previous);
        if observed != previous {
            accounting[32..40].copy_from_slice(&observed.to_le_bytes());
            finality
                .insert(height, accounting.as_slice())
                .map_err(|_| "protected finality observation write failed")?;
        }
        let id: Hash = expected.value()[..32].try_into().expect("checked marker");
        if !policy.deletion_enabled
            || expired.len() as u64 >= policy.remaining_blocks
            || storage_policy::expired_with_local_blocks(
                policy.role,
                height,
                id,
                policy.tip,
                Some(FinalityObservation {
                    block_id: id,
                    observed_unix_seconds: observed,
                }),
                policy.now,
                true,
                policy.recovery,
                storage_policy::LOCAL_PROOF_BLOCKS,
            )
            .is_err()
        {
            continue;
        }
        let record = blocks
            .get(height)
            .map_err(|_| "protected full proof unreadable")?
            .ok_or("protected full proof missing")?;
        let length = record
            .value()
            .len()
            .checked_sub(FINGERPRINT_BYTES)
            .ok_or("invalid protected full-proof record")?;
        if outcome
            .inspected_bytes
            .checked_add(length)
            .is_none_or(|bytes| bytes > policy.remaining_bytes)
        {
            continue;
        }
        outcome.inspected_bytes += length;
        let normalized = authenticate(record.value(), expected.value())?;
        drop(record);
        blocks
            .insert(height, normalized.as_slice())
            .map_err(|_| "protected proof expiry write failed")?;
        accounting[40..48].copy_from_slice(&0u64.to_le_bytes());
        finality
            .insert(height, accounting.as_slice())
            .map_err(|_| "protected proof accounting write failed")?;
        expired.push(height);
    }
    outcome.expired = expired.len() as u64;
    for height in expired {
        protected
            .remove(height)
            .map_err(|_| "protected history expiry write failed")?;
    }
    Ok(outcome)
}
