//! Shared accepted-state authentication and strictly read-only observation.
use super::*;

pub(super) struct Authenticated {
    pub engine: Engine,
    pub leaves: Hash,
    pub spends: Hash,
    pub index: Hash,
    pub imported_prefix: u64,
    pub import_seed: Hash,
}

/// Read and authenticate exactly the normal restart record. No transaction
/// capable of mutation or rollback maintenance is accepted by this function.
pub(super) fn authenticate(
    txn: &redb::ReadTransaction,
    genesis: Genesis,
    limits: Limits,
    identity: &crate::identity::NativeIdentity,
) -> Result<Authenticated, String> {
    authenticate_inner(txn, genesis, limits, identity, None)
}

fn bounded_history_height(head: &[u8], expected: Option<u64>) -> Result<u64, String> {
    if head.len() != 72 {
        return Err("invalid restart head width".into());
    }
    let height = u64::from_le_bytes(head[..8].try_into().expect("checked restart height"));
    if expected.is_some_and(|expected| !(1..=16_384).contains(&expected) || height != expected) {
        return Err("full history accepted height differs from exact finite budget".into());
    }
    Ok(height)
}

fn authenticate_inner(
    txn: &redb::ReadTransaction,
    genesis: Genesis,
    limits: Limits,
    identity: &crate::identity::NativeIdentity,
    expected_history_height: Option<u64>,
) -> Result<Authenticated, String> {
    let meta = txn
        .open_table(META)
        .map_err(|_| "versioned restart metadata missing")?;
    let encoded = genesis.encode()?;
    if meta
        .get("genesis")
        .map_err(|_| "restart genesis read failed")?
        .as_ref()
        .map(|value| value.value())
        != Some(encoded.as_slice())
    {
        return Err("restart genesis differs from local configuration".into());
    }
    let head_bytes = meta
        .get("head")
        .map_err(|_| "restart head unavailable")?
        .ok_or("restart head missing")?;
    let head_bytes = head_bytes.value();
    // The fixed-width head is the only height-dependent input read before the
    // full-history bound. Do not move this check below index/state traversal.
    let height = bounded_history_height(head_bytes, expected_history_height)?;
    let blocks = txn
        .open_table(BLOCKS)
        .map_err(|_| "restart canonical table missing")?;
    let (imported_prefix, import_seed) = imported::resume_context(txn, height)?;
    if blocks
        .len()
        .map_err(|_| "restart block count unavailable")?
        != height - imported_prefix
    {
        return Err("restart canonical count differs".into());
    }
    let index = txn
        .open_table(INDEX)
        .map_err(|_| "restart compact index missing; explicit audit required")?;
    if index.len().map_err(|_| "restart index count unavailable")? != height {
        return Err("restart compact index count differs".into());
    }
    let parent = if height == 0 {
        [0; 32]
    } else {
        let value = index
            .get(height)
            .map_err(|_| "restart tip unavailable")?
            .ok_or("restart tip missing")?;
        let (header, _) = decode_compact(value.value(), genesis.config().network)?;
        if header.height != height
            || header
                .id()
                .map_err(|_| "restart identity invalid")?
                .as_slice()
                != &head_bytes[8..40]
            || header.execution_commitment.as_slice() != &head_bytes[40..]
        {
            return Err("restart canonical header differs from durable head".into());
        }
        header.parent
    };
    let table = txn
        .open_table(super::super::restart::CACHE)
        .map_err(|_| "authenticated restart record missing; explicit audit required")?;
    if table
        .len()
        .map_err(|_| "restart record count unavailable")?
        != 5
    {
        return Err("incomplete authenticated restart record".into());
    }
    let read = |key: &str, max: usize| -> Result<Vec<u8>, String> {
        let value = table
            .get(key)
            .map_err(|_| "restart field unavailable")?
            .ok_or("restart field missing")?;
        if value.value().len() > max {
            return Err("restart field exceeds bound".into());
        }
        Ok(value.value().to_vec())
    };
    let maximum = limits
        .max_component_bytes
        .checked_mul(6)
        .and_then(|size| size.checked_add(88))
        .ok_or("restart total bound overflow")?;
    let bytes = read("state", maximum)?;
    let leaves: Hash = read("leaves", 32)?
        .try_into()
        .map_err(|_| "restart leaf digest width")?;
    let spends: Hash = read("spends", 32)?
        .try_into()
        .map_err(|_| "restart spend digest width")?;
    let sealed_index: Hash = read("index", 32)?
        .try_into()
        .map_err(|_| "restart compact index digest width")?;
    let seal = read("seal", crate::identity::storage_checkpoint::SEAL_BYTES)?;
    identity
        .descriptor()
        .map_err(|_| "restart descriptor unavailable")?
        .verify_local_storage(
            super::super::restart::digest(&genesis, &bytes, leaves, spends, sealed_index),
            &seal,
        )
        .map_err(|_| "authenticated restart seal mismatch")?;
    let index_digest = authenticate_header_prefix_seed(
        &index,
        genesis.config().network,
        genesis.id(),
        height,
        head_bytes[8..40].try_into().expect("checked restart tip"),
        import_seed,
    )?;
    if index_digest != sealed_index {
        return Err("restart compact index differs from accepted local seal".into());
    }
    let (leaf_values, leaf_digest) = super::super::restart::read_rows(
        &txn.open_table(super::super::restart::LEAVES)
            .map_err(|_| "restart permanent leaves missing")?,
        limits.max_leaves,
    )?;
    let (spent_values, spent_digest) = super::super::restart::read_rows(
        &txn.open_table(super::super::restart::SPENDS)
            .map_err(|_| "restart permanent spends missing")?,
        limits.max_nullifiers,
    )?;
    if leaf_digest != leaves || spent_digest != spends {
        return Err("restart permanent rows differ from accepted local seal".into());
    }
    let spent: std::collections::BTreeSet<_> = spent_values.iter().copied().collect();
    if spent.len() != spent_values.len() {
        return Err("duplicate restart nullifier".into());
    }
    let leaves_decoded = leaf_values
        .iter()
        .map(|value| {
            native::codec::decode_digest(value).map_err(|_| "invalid restart leaf".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (state, root) =
        super::super::restart::restore(&genesis, &bytes, leaves_decoded, spent, limits, parent)?;
    if state.height() != height
        || state.tip().as_slice() != &head_bytes[8..40]
        || (height > 0 && root.as_slice() != &head_bytes[40..])
        || (height == 0 && head_bytes[40..] != [0; 32])
    {
        return Err("authenticated restart state differs from exact durable head".into());
    }
    let engine = Engine::from_authenticated_local_state(genesis, state, limits)?;
    Ok(Authenticated {
        engine,
        leaves,
        spends,
        index: index_digest,
        imported_prefix,
        import_seed,
    })
}

/// An accepted-state observer with no writable database handle. Missing clean
/// allocator state or authentication material is an error, never a repair path.
#[cfg(feature = "eng2-rehearsal")]
pub struct Observation {
    database: redb::ReadOnlyDatabase,
    engine: Engine,
}
#[cfg(feature = "eng2-rehearsal")]
impl Observation {
    pub fn open(path: &Path, genesis: Genesis, limits: Limits) -> Result<Self, String> {
        Self::open_inner(path, genesis, limits, None)
    }
    /// Refuse a different or excessive full-history height immediately after
    /// reading the fixed-width durable head, before authenticating its prefix.
    pub fn open_full_history(
        path: &Path,
        genesis: Genesis,
        limits: Limits,
        height: u64,
    ) -> Result<Self, String> {
        if !(1..=16_384).contains(&height) {
            return Err("full history declared height exceeds finite bound".into());
        }
        Self::open_inner(path, genesis, limits, Some(height))
    }
    fn open_inner(
        path: &Path,
        genesis: Genesis,
        limits: Limits,
        expected_history_height: Option<u64>,
    ) -> Result<Self, String> {
        let directory = path
            .parent()
            .ok_or("observation parent directory missing")?;
        let identity = crate::identity::NativeIdentity::load(directory, &genesis.peer_binding())
            .map_err(|_| "existing observation identity unavailable")?;
        if identity
            .descriptor()
            .map_err(|_| "observation descriptor unavailable")?
            .binding()
            != genesis.peer_binding()
        {
            return Err("observation identity binding differs".into());
        }
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "observation database metadata unavailable")?;
        if !metadata.file_type().is_file()
            || metadata.len() == 0
            || path.canonicalize().ok().as_deref() != Some(path)
        {
            return Err("observation requires an existing canonical regular database".into());
        }
        let database = redb::ReadOnlyDatabase::open(path)
            .map_err(|_| "read-only observation open failed; repair is forbidden")?;
        let transaction = database
            .begin_read()
            .map_err(|_| "observation read transaction unavailable")?;
        let authenticated = authenticate_inner(
            &transaction,
            genesis,
            limits,
            &identity,
            expected_history_height,
        )?;
        drop(transaction);
        Ok(Self {
            database,
            engine: authenticated.engine,
        })
    }
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
    /// Return unchanged complete public frames only; imported or pruned history
    /// cannot satisfy a full-history audit.
    pub fn full_frame_count(&self) -> Result<u64, String> {
        self.database
            .begin_read()
            .map_err(|_| "observation frame transaction unavailable")?
            .open_table(BLOCKS)
            .map_err(|_| "observation full history unavailable")?
            .len()
            .map_err(|_| "observation frame count unavailable".into())
    }
    /// Authenticated compact size for caller allocation reservation, without a body copy.
    pub fn full_frame_size(&self, height: u64) -> Result<usize, String> {
        if height == 0 || height > self.engine.state().height() {
            return Err("observation frame height rejected".into());
        }
        let tx = self
            .database
            .begin_read()
            .map_err(|_| "observation size transaction unavailable")?;
        let table = tx
            .open_table(INDEX)
            .map_err(|_| "observation size index unavailable")?;
        let row = table
            .get(height)
            .map_err(|_| "observation size unavailable")?
            .ok_or("observation size missing")?;
        let (header, size) = decode_compact(row.value(), self.engine.state().network())?;
        if header.height != height || size > self.engine.body_policy().max_body_bytes {
            return Err("observation indexed size rejected".into());
        }
        HEADER_BYTES
            .checked_add(size)
            .ok_or("observation frame size overflow".into())
    }
    pub fn full_frame(&self, height: u64) -> Result<Vec<u8>, String> {
        if height == 0 || height > self.engine.state().height() {
            return Err("observation frame height is not accepted".into());
        }
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "observation frame transaction unavailable")?;
        let index = transaction
            .open_table(INDEX)
            .map_err(|_| "observation compact index unavailable")?;
        let compact = index
            .get(height)
            .map_err(|_| "observation compact header read failed")?
            .ok_or("observation compact header missing")?;
        let (header, body_bytes) = decode_compact(compact.value(), self.engine.state().network())?;
        let table = transaction
            .open_table(BLOCKS)
            .map_err(|_| "observation full history unavailable")?;
        let row = table
            .get(height)
            .map_err(|_| "observation frame read failed")?
            .ok_or("observation complete frame missing")?;
        let frame = row.value();
        let maximum = HEADER_BYTES
            .checked_add(self.engine.body_policy().max_body_bytes)
            .ok_or("observation frame bound overflow")?;
        if header.height != height
            || body_bytes > self.engine.body_policy().max_body_bytes
            || frame.len()
                != HEADER_BYTES
                    .checked_add(body_bytes)
                    .ok_or("observation frame length overflow")?
            || frame.len() < HEADER_BYTES
            || frame.len() > maximum
            || frame[..HEADER_BYTES]
                != header
                    .encode()
                    .map_err(|_| "observation header encoding failed")?
        {
            return Err("observation full frame differs from authenticated header or bound".into());
        }
        Ok(frame.to_vec())
    }
    pub fn header(&self, height: u64) -> Result<Header, String> {
        if height == 0 || height > self.engine.state().height() {
            return Err("observation header height is not accepted".into());
        }
        let transaction = self
            .database
            .begin_read()
            .map_err(|_| "observation header transaction unavailable")?;
        let table = transaction
            .open_table(INDEX)
            .map_err(|_| "observation compact index unavailable")?;
        let value = table
            .get(height)
            .map_err(|_| "observation header lookup failed")?
            .ok_or("observation header missing")?;
        let (header, length) = decode_compact(value.value(), self.engine.state().network())?;
        if header.height != height || length > self.engine.body_policy().max_body_bytes {
            return Err("observation header context or body bound differs".into());
        }
        Ok(header)
    }
}

#[cfg(test)]
mod bounded_history_tests {
    use super::bounded_history_height;
    fn head(height: u64) -> [u8; 72] {
        let mut value = [0; 72];
        value[..8].copy_from_slice(&height.to_le_bytes());
        value
    }
    #[test]
    fn bounded_history_fixed_head_rejects_actual_height_before_prefix_work() {
        assert_eq!(bounded_history_height(&head(97), Some(97)).unwrap(), 97);
        assert_eq!(
            bounded_history_height(&head(16_384), Some(16_384)).unwrap(),
            16_384
        );
        for (actual, declared) in [
            (98, 97),
            (96, 97),
            (16_385, 97),
            (u64::MAX, 97),
            (16_385, 16_385),
            (0, 0),
        ] {
            assert!(bounded_history_height(&head(actual), Some(declared)).is_err());
        }
        assert!(bounded_history_height(&[0; 71], Some(97)).is_err());
        // The existing unbounded authentication entry retains its prior rule.
        assert_eq!(bounded_history_height(&head(16_385), None).unwrap(), 16_385);
    }
}
