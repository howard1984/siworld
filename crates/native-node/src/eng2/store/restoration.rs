//! Complete authenticated-state reconstruction inside a restored transaction.

use super::*;
use crate::identity::NativeIdentity;
use std::collections::BTreeSet;

pub(super) struct Restored {
    pub engine: Engine,
    pub leaves: Hash,
    pub spends: Hash,
    pub index: Hash,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify(
    transaction: &redb::WriteTransaction,
    genesis: &Genesis,
    limits: Limits,
    identity: &NativeIdentity,
    point: RollbackPoint,
    imported_prefix: u64,
    import_seed: Hash,
) -> Result<Restored, String> {
    if point.height < imported_prefix {
        return Err("rollback ancestor precedes retained imported state".into());
    }
    let meta = transaction
        .open_table(META)
        .map_err(|_| "rollback ancestor metadata unavailable")?;
    let encoded_genesis = genesis.encode()?;
    if meta
        .get("genesis")
        .map_err(|_| "rollback genesis read failed")?
        .as_ref()
        .map(|v| v.value())
        != Some(encoded_genesis.as_slice())
    {
        return Err("rollback ancestor genesis differs".into());
    }
    let mut expected = point.height.to_le_bytes().to_vec();
    expected.extend_from_slice(&point.block_id);
    expected.extend_from_slice(&point.execution_commitment);
    if meta
        .get("head")
        .map_err(|_| "rollback ancestor head read failed")?
        .as_ref()
        .map(|v| v.value())
        != Some(expected.as_slice())
    {
        return Err("rollback ancestor head differs from retained point".into());
    }
    let blocks = transaction
        .open_table(BLOCKS)
        .map_err(|_| "rollback ancestor blocks unavailable")?;
    if blocks
        .len()
        .map_err(|_| "rollback ancestor block count unavailable")?
        != point.height - imported_prefix
    {
        return Err("rollback ancestor retained history count differs".into());
    }
    let index = transaction
        .open_table(INDEX)
        .map_err(|_| "rollback ancestor index unavailable")?;
    if index
        .len()
        .map_err(|_| "rollback ancestor index count unavailable")?
        != point.height
    {
        return Err("rollback ancestor index count differs".into());
    }
    let parent = if point.height == 0 {
        [0; 32]
    } else {
        let row = index
            .get(point.height)
            .map_err(|_| "rollback ancestor header unavailable")?
            .ok_or("rollback ancestor header missing")?;
        let (header, _) = decode_compact(row.value(), genesis.config().network)?;
        if header.height != point.height
            || header
                .id()
                .map_err(|_| "rollback ancestor header identity invalid")?
                != point.block_id
            || header.execution_commitment != point.execution_commitment
        {
            return Err("rollback ancestor point differs from exact header".into());
        }
        header.parent
    };
    let cache = transaction
        .open_table(super::super::restart::CACHE)
        .map_err(|_| "rollback ancestor authenticated image unavailable")?;
    if cache
        .len()
        .map_err(|_| "rollback ancestor image count unavailable")?
        != 5
    {
        return Err("rollback ancestor authenticated image incomplete".into());
    }
    let field = |name: &str, maximum: usize| -> Result<Vec<u8>, String> {
        let value = cache
            .get(name)
            .map_err(|_| "rollback ancestor image read failed")?
            .ok_or("rollback ancestor image field missing")?;
        if value.value().len() > maximum {
            return Err("rollback ancestor image field exceeds bound".into());
        }
        Ok(value.value().to_vec())
    };
    let maximum = limits
        .max_component_bytes
        .checked_mul(6)
        .and_then(|n| n.checked_add(88))
        .ok_or("rollback ancestor image bound overflow")?;
    let bytes = field("state", maximum)?;
    let leaves: Hash = field("leaves", 32)?
        .try_into()
        .map_err(|_| "rollback ancestor leaf digest width")?;
    let spends: Hash = field("spends", 32)?
        .try_into()
        .map_err(|_| "rollback ancestor spend digest width")?;
    let index_digest: Hash = field("index", 32)?
        .try_into()
        .map_err(|_| "rollback ancestor index digest width")?;
    let seal = field("seal", crate::identity::storage_checkpoint::SEAL_BYTES)?;
    identity
        .descriptor()
        .map_err(|_| "rollback ancestor identity unavailable")?
        .verify_local_storage(
            super::super::restart::digest(genesis, &bytes, leaves, spends, index_digest),
            &seal,
        )
        .map_err(|_| "rollback ancestor local seal differs")?;
    if authenticate_header_prefix_seed(
        &index,
        genesis.config().network,
        genesis.id(),
        point.height,
        point.block_id,
        import_seed,
    )? != index_digest
    {
        return Err("rollback ancestor header prefix differs from local seal".into());
    }
    let (leaf_values, leaf_digest) = super::super::restart::read_rows(
        &transaction
            .open_table(super::super::restart::LEAVES)
            .map_err(|_| "rollback ancestor leaves unavailable")?,
        limits.max_leaves,
    )?;
    let (spent_values, spent_digest) = super::super::restart::read_rows(
        &transaction
            .open_table(super::super::restart::SPENDS)
            .map_err(|_| "rollback ancestor spends unavailable")?,
        limits.max_nullifiers,
    )?;
    if leaf_digest != leaves || spent_digest != spends {
        return Err("rollback ancestor permanent rows differ from local seal".into());
    }
    let spent: BTreeSet<_> = spent_values.iter().copied().collect();
    if spent.len() != spent_values.len() {
        return Err("rollback ancestor nullifier duplicate".into());
    }
    let decoded = leaf_values
        .iter()
        .map(|value| {
            native::codec::decode_digest(value)
                .map_err(|_| "rollback ancestor leaf encoding invalid".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (state, root) =
        super::super::restart::restore(genesis, &bytes, decoded, spent, limits, parent)?;
    if state.height() != point.height
        || state.tip() != point.block_id
        || (point.height > 0 && root != point.execution_commitment)
    {
        return Err("rollback ancestor complete state differs from header commitment".into());
    }
    let engine =
        Engine::from_authenticated_local_state(Genesis::decode(&encoded_genesis)?, state, limits)?;
    Ok(Restored {
        engine,
        leaves,
        spends,
        index: index_digest,
    })
}
