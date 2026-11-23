//! Independent full-genesis replay with optional exact checkpoint authentication.
//!
//! This deliberately requires every original prefix body, even before a signed
//! checkpoint. Pruned or missing prefix bodies remain unavailable. No snapshot
//! shortcut, exporter publication, current readiness or original gap is inferred.
use super::*;
use crate::eng2::{
    body::Body,
    certificate::{AuthorizationWitness, Certificate},
    snapshot::{ImportLimits, encode_components},
    state_components::Binding,
};
use std::path::Path;

/// The controller retains original bytes in its bounded immutable archive.
/// A derived wallet generation must never implement this as native originals.
pub trait Archive {
    fn original(&mut self, object: usize, maximum: usize) -> Result<Vec<u8>>;
}
#[derive(Clone)]
pub(super) struct ExecutionMark {
    pub height: u64,
    pub tip: Hash,
    pub snapshot: Hash,
    pub snapshot_bytes: usize,
    pub governance: Hash,
}
impl ExecutionMark {
    pub(super) fn capture(
        engine: &super::super::execution::Engine,
        imports: ImportLimits,
        budget: &Budget,
    ) -> Result<Self> {
        let shape = super::memory::Shape::of(engine.state())?;
        let _work = super::memory::reserve(budget, 0, shape.workspace()?)?;
        Self::capture_reserved(engine, imports, shape)
    }
    pub(super) fn capture_reserved(
        engine: &super::super::execution::Engine,
        mut imports: ImportLimits,
        shape: super::memory::Shape,
    ) -> Result<Self> {
        shape.contains(engine.state())?;
        imports.chain = shape.limits(imports.chain)?;
        imports.max_snapshot_bytes = imports.max_snapshot_bytes.min(shape.components()?);
        let state = engine.state();
        let parent = state
            .chain()
            .snapshots
            .iter()
            .rev()
            .nth(1)
            .map(|s| s.selector.block_id)
            .ok_or(Error::CaptureFailed)?;
        let parts = state
            .canonical_components(
                Binding {
                    genesis: engine.genesis().id(),
                    rules_commitment: engine.genesis().rules_commitment(),
                    parent,
                },
                imports.chain,
            )
            .map_err(|_| Error::CaptureFailed)?;
        let encoded = encode_components(&parts, imports).map_err(|_| Error::CapacityExceeded)?;
        Ok(Self {
            height: state.height(),
            tip: state.tip(),
            snapshot: digest(&encoded),
            snapshot_bytes: encoded.len(),
            governance: digest(&parts[7]),
        })
    }
}

pub struct ReplayReceipt {
    request: Request,
    inventory_digest: Hash,
    closed: Closed,
    final_execution: Hash,
    store: store::Store,
    inventory: Inventory,
    pub(super) marks: Vec<ExecutionMark>,
    _marks: p2p::Reservation,
}
impl ReplayReceipt {
    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn inventory_digest(&self) -> Hash {
        self.inventory_digest
    }
    pub fn transferred_bytes(&self) -> u64 {
        self.closed.bytes
    }
    pub fn final_execution(&self) -> Hash {
        self.final_execution
    }
    /// Independently replayed state, never original exporter publication.
    pub fn replayed_store(&self) -> &store::Store {
        &self.store
    }
    pub fn provenance(&self) -> &'static str {
        "INDEPENDENT_FULL_FRAME_REPLAY_DERIVED_STATE"
    }
}

/// Destination is selected locally by the independent controller. Capture
/// requests have no paths. Store::create refuses an existing database and does
/// not load or create identity keys, restart authority or publication handles.
pub fn replay(
    inventory: &Inventory,
    closed: Closed,
    expected: &Request,
    source: &mut impl Archive,
    destination: &Path,
    imports: ImportLimits,
    canceled: impl Fn() -> bool,
) -> Result<ReplayReceipt> {
    replay_budgeted(
        inventory,
        closed,
        expected,
        source,
        destination,
        imports,
        &Budget::new(super::memory::CACHE_MEMORY),
        canceled,
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn replay_budgeted(
    inventory: &Inventory,
    closed: Closed,
    expected: &Request,
    source: &mut impl Archive,
    destination: &Path,
    imports: ImportLimits,
    mark_budget: &Budget,
    canceled: impl Fn() -> bool,
) -> Result<ReplayReceipt> {
    if &inventory.request != expected
        || expected.prefix.is_some()
        || inventory.digest != inventory_digest(inventory)
        || closed.capture_id != inventory.capture_id
        || closed.inventory_digest != inventory.digest
        || closed.bytes != inventory.total_bytes
    {
        return Err(Error::ContextMismatch);
    }
    let started = Instant::now();
    // A replay has a finite commit deadline; native proof verification is
    // synchronous and cannot be forcibly preempted inside one admitted proof.
    let check = || {
        if canceled() || started.elapsed() > Duration::from_secs(300) {
            Err(Error::CaptureExpired)
        } else {
            Ok(())
        }
    };
    let request = &inventory.request;
    if request.target.height == 0
        || request.target.height > MAX_HEADERS as u64
        || request.target.height > request.limits.headers as u64
        || inventory.total_bytes > request.limits.object_bytes
    {
        return Err(Error::CapacityExceeded);
    }
    if inventory
        .objects
        .iter()
        .try_fold(0u64, |n, o| n.checked_add(o.bytes as u64))
        != Some(inventory.total_bytes)
    {
        return Err(Error::ContextMismatch);
    }
    let count = request.target.height as usize + if request.anchor.height == 0 { 1 } else { 4 };
    if inventory.objects.len() != count {
        return Err(Error::BodyUnavailable);
    }
    let offset = if request.anchor.height == 0 { 1 } else { 4 };
    if request.limits.memory_bytes > super::memory::CACHE_MEMORY {
        return Err(Error::CapacityExceeded);
    }
    let material_bytes = inventory
        .objects
        .iter()
        .take(offset)
        .try_fold(0usize, |n, o| n.checked_add(o.bytes))
        .ok_or(Error::CapacityExceeded)?;
    let material_work = material_bytes
        .checked_mul(3)
        .and_then(|n| n.checked_add(2 * 1024 * 1024))
        .ok_or(Error::CapacityExceeded)?;
    let _materials = super::memory::reserve(mark_budget, 0, material_work)?;
    let mut bytes_read = 0u64;
    let mut read = |i: usize| -> Result<Vec<u8>> {
        check()?;
        let object = inventory.objects.get(i).ok_or(Error::BodyUnavailable)?;
        bytes_read = bytes_read
            .checked_add(object.bytes as u64)
            .filter(|n| *n <= request.limits.object_bytes)
            .ok_or(Error::CapacityExceeded)?;
        let bytes = source.original(i, object.bytes)?;
        if bytes.len() != object.bytes || digest(&bytes) != object.sha256 {
            return Err(Error::CaptureFailed);
        }
        Ok(bytes)
    };
    if inventory.objects[0].kind != Kind::Genesis || inventory.objects[0].bytes > 1024 * 1024 {
        return Err(Error::ContextMismatch);
    }
    let genesis_bytes = read(0)?;
    let genesis = Genesis::decode(&genesis_bytes).map_err(|_| Error::ContextMismatch)?;
    if Context::for_genesis(&genesis) != request.context {
        return Err(Error::ContextMismatch);
    }
    let offset = if request.anchor.height == 0 { 1 } else { 4 };
    let (certificate, witness, snapshot) = if offset == 4 {
        if inventory.objects[1].kind != Kind::Certificate
            || inventory.objects[2].kind != Kind::Witness
            || inventory.objects[3].kind != Kind::Snapshot
            || inventory.objects[1].bytes > super::super::certificate::CERTIFICATE_BYTES
            || inventory.objects[2].bytes > imports.chain.max_component_bytes.saturating_add(4096)
            || inventory.objects[3].bytes > imports.max_snapshot_bytes
        {
            return Err(Error::CapacityExceeded);
        }
        let c = read(1)?;
        let w = read(2)?;
        let s = read(3)?;
        if digest(&c) != request.anchor.certificate
            || digest(&w) != request.anchor.witness
            || digest(&s) != request.anchor.snapshot
        {
            return Err(Error::ContextMismatch);
        }
        (
            Some(
                Certificate::decode(&c, request.context.network)
                    .map_err(|_| Error::CaptureFailed)?,
            ),
            Some(
                AuthorizationWitness::decode(&w, imports.chain.max_component_bytes)
                    .map_err(|_| Error::CaptureFailed)?,
            ),
            Some(s),
        )
    } else {
        if request.anchor != Anchor::genesis(request.context.genesis) {
            return Err(Error::AnchorNotAncestor);
        }
        (None, None, None)
    };
    let c = genesis.config();
    let rules = HeaderRules {
        network: c.network,
        genesis: genesis.id(),
        genesis_timestamp: c.genesis_timestamp,
        genesis_target: c.genesis_target,
        target_interval: c.target_interval,
        asert_half_life: c.asert_half_life(),
        pow_iterations: c.pow_iterations,
        pow_algorithm: c.pow_algorithm(),
        max_headers: request.limits.headers,
    };
    // Only fixed-width original headers are retained here. Whole bodies are
    // reread once for ordinary native admission after complete path validation.
    let policy = super::super::execution::Engine::new(
        Genesis::decode(&genesis_bytes).map_err(|_| Error::ContextMismatch)?,
        imports.chain,
    )
    .map_err(|_| Error::CaptureFailed)?
    .body_policy();
    let mut headers = Vec::with_capacity(request.target.height as usize);
    let mut frame_bytes = 0u64;
    for i in offset..inventory.objects.len() {
        let object = &inventory.objects[i];
        let height = (i - offset + 1) as u64;
        if !matches!(object.kind,Kind::Frame{height:h,..} if h==height)
            || object.bytes < HEADER_BYTES
            || object.bytes - HEADER_BYTES > policy.max_body_bytes
        {
            return Err(Error::BodyUnavailable);
        }
        frame_bytes = frame_bytes
            .checked_add(object.bytes as u64)
            .filter(|n| *n <= request.limits.frame_bytes)
            .ok_or(Error::CapacityExceeded)?;
        let _frame = mark_budget
            .reserve(object.bytes)
            .map_err(|_| Error::CapacityExceeded)?;
        let b = read(i)?;
        let h = Header::decode(&b[..HEADER_BYTES], &request.context.network)
            .map_err(|_| Error::CaptureFailed)?;
        h.verify_body(&b[HEADER_BYTES..], policy.max_body_bytes)
            .map_err(|_| Error::CaptureFailed)?;
        headers.push(h);
    }
    let verified = VerifiedHeaders::verify_bounded(rules, headers, || check().is_ok());
    check()?;
    let verified = verified.map_err(|_| Error::CaptureFailed)?;
    if verified.id(request.target.height).ok() != Some(request.target.tip)
        || verified.height() != request.target.height
        || verified.cumulative_work() != request.target.work
        || verified
            .header(request.target.height)
            .is_none_or(|h| h.execution_commitment != request.target.execution)
    {
        return Err(Error::ContextMismatch);
    }
    if request.anchor.height > request.target.height
        || (offset == 4
            && verified
                .header(request.anchor.height)
                .is_none_or(|h| h.id().ok() != Some(request.anchor.id)))
    {
        return Err(Error::AnchorNotAncestor);
    }
    if let (Some(c), Some(w)) = (&certificate, &witness) {
        let s = &c.statement;
        if s.checkpoint_height != request.anchor.height
            || s.checkpoint_block != request.anchor.id
            || s.authorization_height > request.target.height
            || !super::super::runtime_export::confirmed_checkpoint(
                s.checkpoint_height,
                s.authorization_height,
            )
        {
            return Err(Error::AnchorNotAncestor);
        }
        w.verify_binding(s, &verified, imports.chain.max_component_bytes)
            .map_err(|_| Error::CaptureFailed)?;
    }
    check()?;
    let verifier =
        crate::proofs::NativeVerifier::for_genesis(&genesis).map_err(|_| Error::CaptureFailed)?;
    let mut store = store::Store::create(destination, genesis, imports.chain)
        .map_err(|_| Error::CaptureFailed)?;
    let mark_bytes = (request.target.height as usize)
        .checked_mul(std::mem::size_of::<ExecutionMark>())
        .ok_or(Error::CapacityExceeded)?;
    let marks_charge = mark_budget
        .reserve(mark_bytes)
        .map_err(|_| Error::CapacityExceeded)?;
    let mut marks = Vec::new();
    marks
        .try_reserve_exact(request.target.height as usize)
        .map_err(|_| Error::CapacityExceeded)?;
    let mut authenticated = certificate.is_none();
    let mut snapshot_checked = certificate.is_none();
    for i in offset..inventory.objects.len() {
        check()?;
        let object = &inventory.objects[i];
        let shape = super::memory::Shape::of(store.engine().state())?.advanced(1)?;
        let frame_work = object
            .bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(shape.workspace().ok()?))
            .ok_or(Error::CapacityExceeded)?;
        let frame_charge = mark_budget
            .reserve(frame_work)
            .map_err(|_| Error::CapacityExceeded)?;
        let b = source.original(i, object.bytes)?;
        if b.len() != object.bytes || digest(&b) != object.sha256 {
            return Err(Error::CaptureFailed);
        }
        let height = (i - offset + 1) as u64;
        let header = verified.header(height).ok_or(Error::CaptureFailed)?;
        let body = Body::decode(&b[HEADER_BYTES..], header.network, header.height, policy)
            .map_err(|_| Error::CaptureFailed)?;
        store
            .append(header, &body, &verifier)
            .map_err(|_| Error::CaptureFailed)?;
        check()?;
        shape.contains(store.engine().state())?;
        drop(body);
        drop(b);
        drop(frame_charge);
        marks.push(ExecutionMark::capture(
            store.engine(),
            imports,
            mark_budget,
        )?);
        if let (Some(c), Some(w), Some(s)) = (&certificate, &witness, &snapshot) {
            if height == request.anchor.height {
                let actual = marks.last().ok_or(Error::CaptureFailed)?;
                if actual.snapshot != digest(s) || actual.snapshot_bytes != s.len() {
                    return Err(Error::CaptureFailed);
                }
                snapshot_checked = true;
            }
            if height == c.statement.authorization_height {
                let governance = store.engine().state().governance();
                if marks.last().ok_or(Error::CaptureFailed)?.governance != digest(&w.governance) {
                    return Err(Error::CaptureFailed);
                }
                let roster = governance.active_roster();
                if roster.epoch_sequence != c.statement.roster_sequence
                    || roster.digest(request.context.network) != c.statement.roster_digest
                    || roster.activated_height > height
                {
                    return Err(Error::CaptureFailed);
                }
                c.check_signatures(roster.keys())
                    .map_err(|_| Error::CaptureFailed)?;
                authenticated = true;
            }
        }
    }
    let state = store.engine().state();
    let h = verified
        .header(request.target.height)
        .ok_or(Error::CaptureFailed)?;
    let fingerprint = state
        .execution_commitment(
            Binding {
                genesis: request.context.genesis,
                rules_commitment: request.context.rules,
                parent: h.parent,
            },
            imports.chain,
        )
        .map_err(|_| Error::CaptureFailed)?;
    if !authenticated
        || !snapshot_checked
        || state.tip() != request.target.tip
        || state.chain().cumulative_work != request.target.work
        || fingerprint != request.target.execution
    {
        return Err(Error::CaptureFailed);
    }
    check()?;
    Ok(ReplayReceipt {
        request: request.clone(),
        inventory_digest: inventory.digest,
        closed,
        final_execution: fingerprint,
        store,
        inventory: inventory.clone(),
        marks,
        _marks: marks_charge,
    })
}
