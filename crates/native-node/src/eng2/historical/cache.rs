//! Process-local independently executed prefixes and immutable original files.
//!
//! A serializable Prefix is only a selector. Authority stays in VerifiedPrefix,
//! which has no decoder and cannot be constructed from a native state digest.
use super::*;
use crate::eng2::{
    body::Body,
    execution::Engine,
    snapshot::{ImportLimits, SnapshotState, encode_components},
    state_components::Binding,
};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[derive(Clone, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    mode: u32,
}
fn identity(path: &Path) -> Result<FileIdentity> {
    let m = path
        .symlink_metadata()
        .map_err(|_| Error::BodyUnavailable)?;
    if !m.is_file()
        || m.file_type().is_symlink()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.nlink() != 1
        || m.mode() & 0o777 != 0o600
    {
        return Err(Error::BodyUnavailable);
    }
    Ok(FileIdentity {
        device: m.dev(),
        inode: m.ino(),
        bytes: m.len(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
        mode: m.mode(),
    })
}
struct Pin {
    path: PathBuf,
    identity: FileIdentity,
}
impl Pin {
    fn check(&self) -> Result<()> {
        if identity(&self.path)? != self.identity {
            Err(Error::CaptureFailed)
        } else {
            Ok(())
        }
    }
}

/// Original files retained by the independent controller, never native wallet
/// publication. Files are pinned while their exact bytes are independently read.
/// Subsequent metadata checks reject removal, replacement or writes; this is an
/// owner-local immutable-object discipline, not protection against host root.
pub struct FileArchive {
    inventory: Inventory,
    root: PathBuf,
    pins: Vec<Option<Arc<Pin>>>,
}
impl FileArchive {
    pub fn open(root: &Path, inventory: &Inventory) -> Result<Self> {
        let m = root
            .symlink_metadata()
            .map_err(|_| Error::BodyUnavailable)?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o777 != 0o700
            || inventory.digest != inventory_digest(inventory)
            || inventory.objects.len() > MAX_HEADERS + 4
        {
            return Err(Error::ContextMismatch);
        }
        Ok(Self {
            inventory: inventory.clone(),
            root: root.to_owned(),
            pins: (0..inventory.objects.len()).map(|_| None).collect(),
        })
    }
    fn seal(&self) -> Result<Vec<Arc<Pin>>> {
        let mut pins = Vec::with_capacity(self.pins.len());
        for p in &self.pins {
            let p = p.as_ref().ok_or(Error::BodyUnavailable)?;
            p.check()?;
            pins.push(p.clone());
        }
        Ok(pins)
    }
}
impl Archive for FileArchive {
    fn original(&mut self, object: usize, maximum: usize) -> Result<Vec<u8>> {
        let item = self
            .inventory
            .objects
            .get(object)
            .ok_or(Error::BodyUnavailable)?;
        if item.bytes > maximum {
            return Err(Error::CapacityExceeded);
        }
        let path = self.root.join(format!("object-{object:04}.bin"));
        let before = identity(&path)?;
        if before.bytes != item.bytes as u64 {
            return Err(Error::BodyUnavailable);
        }
        if let Some(pin) = &self.pins[object] {
            pin.check()?;
        }
        let mut file: File =
            crate::local::regular_read(&path, true, maximum).map_err(|_| Error::BodyUnavailable)?;
        let mut bytes = vec![0; item.bytes];
        file.read_exact(&mut bytes)
            .map_err(|_| Error::BodyUnavailable)?;
        if file.read(&mut [0]).map_err(|_| Error::BodyUnavailable)? != 0
            || identity(&path)? != before
            || digest(&bytes) != item.sha256
        {
            return Err(Error::CaptureFailed);
        }
        self.pins[object] = Some(Arc::new(Pin {
            path,
            identity: before,
        }));
        Ok(bytes)
    }
}

/// A certificate checked against original independently executed states.
#[derive(Clone, Serialize)]
pub struct CheckpointReceipt {
    pub height: u64,
    pub block_id: Hash,
    pub certificate_sha256: Hash,
    pub authorization_height: u64,
    pub current: bool,
}

/// Private-construction in-memory execution authority. This grants no original
/// exporter publication, native readiness, signing or service-control authority.
pub struct VerifiedPrefix {
    selector: Prefix,
    context: Context,
    release: Hash,
    executable: Hash,
    genesis: Arc<[u8]>,
    headers: Vec<Header>,
    components: Arc<[u8]>,
    originals: Vec<Arc<Pin>>,
    marks: Vec<super::replay::ExecutionMark>,
    shape: super::memory::Shape,
    checkpoint: Option<CheckpointReceipt>,
    retained_bytes: usize,
    peak_reserved_bytes: usize,
    _reservation: p2p::Reservation,
}
impl VerifiedPrefix {
    pub fn selector(&self) -> &Prefix {
        &self.selector
    }
    pub fn checkpoint(&self) -> Option<&CheckpointReceipt> {
        self.checkpoint.as_ref()
    }
    pub fn allocation_reservation(&self) -> (usize, usize) {
        (self.retained_bytes, self.peak_reserved_bytes)
    }
    pub fn path(&self) -> Result<Vec<Target>> {
        self.check_retained_originals()?;
        let bytes = (self.headers.len() + 1)
            .checked_mul(std::mem::size_of::<Target>())
            .ok_or(Error::CapacityExceeded)?;
        if self
            .retained_bytes
            .checked_add(bytes)
            .is_none_or(|n| n > super::memory::CACHE_MEMORY)
        {
            return Err(Error::CapacityExceeded);
        }
        let mut result = Vec::with_capacity(self.headers.len() + 1);
        let mut work = Work::zero();
        result.push(Target {
            height: 0,
            tip: self.context.genesis,
            work,
            execution: [0; 32],
        });
        for h in &self.headers {
            work = work
                .checked_add(siworld_core::pow::block_work(&h.target))
                .ok_or(Error::CaptureFailed)?;
            result.push(Target {
                height: h.height,
                tip: h.id().map_err(|_| Error::CaptureFailed)?,
                work,
                execution: h.execution_commitment,
            });
        }
        Ok(result)
    }
    pub fn provenance(&self) -> &'static str {
        "INDEPENDENT_NATIVE_PREFIX_AND_SUFFIX_DERIVED_STATE"
    }
    pub fn check_retained_originals(&self) -> Result<()> {
        for p in &self.originals {
            p.check()?;
        }
        Ok(())
    }
    fn metadata_bytes(headers: usize, originals: &[Arc<Pin>]) -> Result<usize> {
        if headers > MAX_HEADERS || originals.len() > 2 * MAX_HEADERS + 16 {
            return Err(Error::CapacityExceeded);
        }
        let pin_bytes = originals
            .iter()
            .try_fold(0usize, |n, p| {
                n.checked_add(
                    std::mem::size_of::<Pin>()
                        + std::mem::size_of::<Arc<Pin>>()
                        + 32
                        + p.path.as_os_str().len(),
                )
            })
            .ok_or(Error::CapacityExceeded)?;
        headers
            .checked_mul(
                std::mem::size_of::<Header>() + std::mem::size_of::<super::replay::ExecutionMark>(),
            )
            .and_then(|n| n.checked_add(pin_bytes))
            .and_then(|n| n.checked_add(1024 * 1024))
            .ok_or(Error::CapacityExceeded)
    }
    /// Authority comes only from ordinary independent execution of all original
    /// prefix bodies. Warm-up ranges remain separate from current observations.
    pub fn from_replay(
        receipt: &ReplayReceipt,
        source: &FileArchive,
        imports: ImportLimits,
        budget: &Budget,
    ) -> Result<Self> {
        if source.inventory != *receipt.inventory() {
            return Err(Error::ContextMismatch);
        }
        let engine = receipt.replayed_store().engine();
        let shape = super::memory::Shape::of(engine.state())?;
        // Reserve before genesis/header/pin/component allocation. The incoming
        // replay Store remains caller-owned; no cache charge is released early.
        let available = budget
            .available()
            .map_err(|_| Error::CapacityExceeded)?
            .min(super::memory::CACHE_MEMORY);
        let charge = super::memory::reserve(budget, 0, available)?;
        let meta_upper = receipt.request().target.height as usize
            * (std::mem::size_of::<Header>() + std::mem::size_of::<super::replay::ExecutionMark>())
            + source.pins.len() * (std::mem::size_of::<Pin>() + 256)
            + 1024 * 1024;
        if shape
            .workspace()?
            .checked_add(meta_upper)
            .is_none_or(|n| n > available)
        {
            return Err(Error::CapacityExceeded);
        }
        let originals = source.seal()?;
        if shape
            .workspace()?
            .checked_add(Self::metadata_bytes(
                receipt.request().target.height as usize,
                &originals,
            )?)
            .is_none_or(|n| n > available)
        {
            return Err(Error::CapacityExceeded);
        }
        let genesis = engine
            .genesis()
            .encode()
            .map_err(|_| Error::CaptureFailed)?;
        let headers = (1..=receipt.request().target.height)
            .map(|h| {
                receipt
                    .replayed_store()
                    .header(h)
                    .map_err(|_| Error::CaptureFailed)
            })
            .collect::<Result<Vec<_>>>()?;
        let marks = receipt.marks.clone();
        let checkpoint = Self::checkpoint_from_archive(
            &headers,
            &marks,
            engine,
            receipt.inventory(),
            source,
            imports,
        )?;
        let mut result = Self::from_engine(
            engine,
            headers,
            originals,
            genesis.into(),
            marks,
            receipt.request(),
            receipt.inventory_digest(),
            imports,
            shape,
            checkpoint,
            charge,
            available,
        )?;
        result
            ._reservation
            .shrink_to(result.retained_bytes)
            .map_err(|_| Error::CapacityExceeded)?;
        Ok(result)
    }
    #[allow(clippy::too_many_arguments)]
    fn from_engine(
        engine: &Engine,
        headers: Vec<Header>,
        originals: Vec<Arc<Pin>>,
        genesis: Arc<[u8]>,
        marks: Vec<super::replay::ExecutionMark>,
        request: &Request,
        origin: Hash,
        mut imports: ImportLimits,
        shape: super::memory::Shape,
        checkpoint: Option<CheckpointReceipt>,
        reservation: p2p::Reservation,
        peak: usize,
    ) -> Result<Self> {
        shape.contains(engine.state())?;
        let meta = Self::metadata_bytes(headers.len(), &originals)?;
        if shape
            .workspace()?
            .checked_add(meta)
            .is_none_or(|n| n > peak)
        {
            return Err(Error::CapacityExceeded);
        }
        imports.chain = shape.limits(imports.chain)?;
        imports.max_snapshot_bytes = imports.max_snapshot_bytes.min(shape.components()?);
        let last = headers.last().ok_or(Error::BodyUnavailable)?;
        let binding = Binding {
            genesis: request.context.genesis,
            rules_commitment: request.context.rules,
            parent: last.parent,
        };
        let state = engine.state();
        if marks.len() != headers.len()
            || state.height() != request.target.height
            || state.tip() != request.target.tip
            || state.chain().cumulative_work != request.target.work
            || state
                .execution_commitment(binding, imports.chain)
                .map_err(|_| Error::CaptureFailed)?
                != request.target.execution
        {
            return Err(Error::ContextMismatch);
        }
        let parts = state
            .canonical_components(binding, imports.chain)
            .map_err(|_| Error::CaptureFailed)?;
        let encoded = encode_components(&parts, imports).map_err(|_| Error::CaptureFailed)?;
        let bytes = encoded
            .len()
            .checked_add(genesis.len())
            .and_then(|n| n.checked_add(meta))
            .ok_or(Error::CapacityExceeded)?;
        if bytes > peak {
            return Err(Error::CapacityExceeded);
        }
        let mut hash = Sha256::new();
        hash.update(b"siworld independently executed prefix v1");
        hash.update(origin);
        hash.update(digest(&encoded));
        for h in [
            request.context.network,
            request.context.genesis,
            request.context.rules,
            request.context.proof_profile,
            request.identity.release,
            request.identity.executable,
            request.target.tip,
            request.target.execution,
        ] {
            hash.update(h);
        }
        hash.update(request.target.height.to_le_bytes());
        hash.update(request.target.work.to_big_endian());
        let components = Arc::from(encoded); // charged while parts/Vec coexist
        drop(parts);
        let result = Self {
            selector: Prefix {
                cache: hash.finalize().into(),
                target: request.target.clone(),
            },
            context: request.context.clone(),
            release: request.identity.release,
            executable: request.identity.executable,
            genesis,
            headers,
            components,
            originals,
            marks,
            shape: super::memory::Shape::of(state)?,
            checkpoint,
            retained_bytes: bytes,
            peak_reserved_bytes: peak,
            _reservation: reservation,
        };
        result.check_retained_originals()?;
        Ok(result)
    }
    fn checkpoint_from_archive(
        headers: &[Header],
        marks: &[super::replay::ExecutionMark],
        engine: &Engine,
        inventory: &Inventory,
        source: &FileArchive,
        imports: ImportLimits,
    ) -> Result<Option<CheckpointReceipt>> {
        let request = &inventory.request;
        if request.anchor.height == 0 {
            return Ok(None);
        }
        use crate::eng2::{
            admission::AdmissionPlan,
            certificate::{AuthorizationWitness, Certificate, CurrentOutcome},
        };
        let read = |i: usize, cap: usize| -> Result<Vec<u8>> {
            let object = inventory.objects.get(i).ok_or(Error::BodyUnavailable)?;
            if object.bytes > cap {
                return Err(Error::CapacityExceeded);
            }
            let pin = source
                .pins
                .get(i)
                .and_then(Option::as_ref)
                .ok_or(Error::BodyUnavailable)?;
            pin.check()?;
            let mut file = crate::local::regular_read(&pin.path, true, cap)
                .map_err(|_| Error::BodyUnavailable)?;
            let mut bytes = vec![0; object.bytes];
            file.read_exact(&mut bytes)
                .map_err(|_| Error::BodyUnavailable)?;
            if file.read(&mut [0]).map_err(|_| Error::BodyUnavailable)? != 0
                || digest(&bytes) != object.sha256
            {
                return Err(Error::CaptureFailed);
            }
            pin.check()?;
            Ok(bytes)
        };
        if inventory
            .objects
            .get(1)
            .is_none_or(|o| o.kind != Kind::Certificate)
            || inventory
                .objects
                .get(2)
                .is_none_or(|o| o.kind != Kind::Witness)
            || inventory
                .objects
                .get(3)
                .is_none_or(|o| o.kind != Kind::Snapshot)
        {
            return Err(Error::BodyUnavailable);
        }
        let certificate_bytes = read(1, crate::eng2::certificate::CERTIFICATE_BYTES)?;
        let witness_bytes = read(2, imports.chain.max_component_bytes.saturating_add(4096))?;
        let snapshot_bytes = read(3, imports.max_snapshot_bytes)?;
        if digest(&certificate_bytes) != request.anchor.certificate
            || digest(&witness_bytes) != request.anchor.witness
            || digest(&snapshot_bytes) != request.anchor.snapshot
        {
            return Err(Error::ContextMismatch);
        }
        let certificate = Certificate::decode(&certificate_bytes, request.context.network)
            .map_err(|_| Error::CaptureFailed)?;
        let witness =
            AuthorizationWitness::decode(&witness_bytes, imports.chain.max_component_bytes)
                .map_err(|_| Error::CaptureFailed)?;
        let statement = &certificate.statement;
        let mark = |height: u64| {
            marks
                .get(
                    height
                        .checked_sub(1)
                        .and_then(|h| usize::try_from(h).ok())
                        .ok_or(Error::AnchorNotAncestor)?,
                )
                .filter(|m| m.height == height)
                .ok_or(Error::AnchorNotAncestor)
        };
        let checkpoint = mark(statement.checkpoint_height)?;
        let authorization = mark(statement.authorization_height)?;
        if statement.checkpoint_height != request.anchor.height
            || statement.checkpoint_block != request.anchor.id
            || checkpoint.tip != statement.checkpoint_block
            || checkpoint.snapshot != digest(&snapshot_bytes)
            || checkpoint.snapshot_bytes != snapshot_bytes.len()
            || authorization.tip != statement.authorization_block
            || authorization.governance != digest(&witness.governance)
            || !crate::eng2::runtime_export::confirmed_checkpoint(
                statement.checkpoint_height,
                statement.authorization_height,
            )
        {
            return Err(Error::AnchorNotAncestor);
        }
        let g = engine.genesis();
        let c = g.config();
        let rules = HeaderRules {
            network: c.network,
            genesis: g.id(),
            genesis_timestamp: c.genesis_timestamp,
            genesis_target: c.genesis_target,
            target_interval: c.target_interval,
            pow_iterations: c.pow_iterations,
            max_headers: request.limits.headers,
        };
        let verified =
            VerifiedHeaders::verify(rules, headers.to_vec()).map_err(|_| Error::CaptureFailed)?;
        let plan = AdmissionPlan::select_signed(&[&verified], Work::one())
            .and_then(|p| {
                p.at_checkpoint(
                    statement.checkpoint_height,
                    statement.checkpoint_height + 1,
                    request.target.height,
                )
            })
            .map_err(|_| Error::AnchorNotAncestor)?;
        let outcome = certificate
            .evaluate_current(
                &witness,
                &plan,
                engine.state().governance(),
                imports.chain.max_component_bytes,
            )
            .map_err(|_| Error::CaptureFailed)?;
        if outcome != CurrentOutcome::Consistent {
            return Err(Error::ContextMismatch);
        }
        Ok(Some(CheckpointReceipt {
            height: statement.checkpoint_height,
            block_id: statement.checkpoint_block,
            certificate_sha256: digest(&certificate_bytes),
            authorization_height: statement.authorization_height,
            current: true,
        }))
    }
    /// Execute only the missing original suffix. A zero-length suffix can bind
    /// new original checkpoint materials to an already independently executed
    /// head. It never turns a native status digest into execution authority.
    #[allow(clippy::too_many_arguments)]
    pub fn extend(
        &self,
        inventory: &Inventory,
        closed: Closed,
        expected: &Request,
        source: &mut FileArchive,
        imports: ImportLimits,
        budget: &Budget,
        canceled: impl Fn() -> bool,
    ) -> Result<Self> {
        let started = Instant::now();
        let check = || {
            if canceled() || started.elapsed() > Duration::from_secs(300) {
                Err(Error::CaptureExpired)
            } else {
                Ok(())
            }
        };
        check()?;
        self.check_retained_originals()?;
        if !self._reservation.covers(budget, self.retained_bytes)
            || inventory.request != *expected
            || source.inventory != *inventory
            || inventory.digest != inventory_digest(inventory)
            || expected.prefix.as_ref() != Some(&self.selector)
            || expected.context != self.context
            || expected.identity.release != self.release
            || expected.identity.executable != self.executable
            || expected.target.height < self.selector.target.height
            || expected.target.height > MAX_HEADERS as u64
            || expected.target.height > expected.limits.headers as u64
            || closed.capture_id != inventory.capture_id
            || closed.inventory_digest != inventory.digest
            || closed.bytes != inventory.total_bytes
        {
            return Err(Error::ContextMismatch);
        }
        let offset = if expected.anchor.height == 0 {
            if expected.anchor != Anchor::genesis(self.context.genesis) {
                return Err(Error::AnchorNotAncestor);
            }
            1
        } else {
            4
        };
        let count = (expected.target.height - self.selector.target.height) as usize;
        if inventory.objects.len() != count + offset
            || inventory.objects[0].kind != Kind::Genesis
            || inventory.total_bytes > expected.limits.object_bytes
            || inventory
                .objects
                .iter()
                .try_fold(0u64, |n, o| n.checked_add(o.bytes as u64))
                != Some(inventory.total_bytes)
        {
            return Err(Error::CapacityExceeded);
        }
        // Old prefix remains charged. Reserve all remaining local workspace
        // before cloning metadata, reconstructing components or reading frames.
        let available = budget
            .available()
            .map_err(|_| Error::CapacityExceeded)?
            .min(super::memory::CACHE_MEMORY.saturating_sub(self.retained_bytes));
        let charge = super::memory::reserve(budget, self.retained_bytes, available)?;
        let meta = self
            .retained_bytes
            .checked_add((count + offset) * 1024)
            .ok_or(Error::CapacityExceeded)?;
        let material_work = inventory
            .objects
            .iter()
            .take(offset)
            .try_fold(0usize, |n, o| n.checked_add(o.bytes))
            .and_then(|n| n.checked_mul(4))
            .ok_or(Error::CapacityExceeded)?;
        let mut working_shape = self.shape;
        let fits = |shape: super::memory::Shape, frame: usize| -> Result<()> {
            let needed = shape
                .workspace()?
                .checked_add(frame.checked_mul(2).ok_or(Error::CapacityExceeded)?)
                .and_then(|n| n.checked_add(meta))
                .and_then(|n| n.checked_add(material_work))
                .ok_or(Error::CapacityExceeded)?;
            if needed > available {
                Err(Error::CapacityExceeded)
            } else {
                Ok(())
            }
        };
        fits(working_shape, 0)?;
        if source.original(0, self.genesis.len())? != self.genesis.as_ref() {
            return Err(Error::ContextMismatch);
        }
        // All checkpoint inputs are validated and retained under this charge.
        for i in 1..offset {
            let o = &inventory.objects[i];
            if o.bytes > available / 4 {
                return Err(Error::CapacityExceeded);
            }
            let _ = source.original(i, o.bytes)?;
        }
        let genesis = Genesis::decode(&self.genesis).map_err(|_| Error::ContextMismatch)?;
        let c = genesis.config();
        let rules = HeaderRules {
            network: c.network,
            genesis: genesis.id(),
            genesis_timestamp: c.genesis_timestamp,
            genesis_target: c.genesis_target,
            target_interval: c.target_interval,
            pow_iterations: c.pow_iterations,
            max_headers: expected.limits.headers,
        };
        let mut local_imports = imports;
        local_imports.chain = working_shape.limits(imports.chain)?;
        let previous = self.headers.last().ok_or(Error::BodyUnavailable)?;
        let state = SnapshotState::from_committed_components(
            &genesis,
            previous,
            &self.components,
            local_imports,
        )
        .map_err(|_| Error::CaptureFailed)?;
        let mut engine = Engine::from_authenticated_local_state(genesis, state, imports.chain)
            .map_err(|_| Error::CaptureFailed)?;
        let policy = engine.body_policy();
        let mut headers = self.headers.clone();
        let mut frames = 0u64;
        for (i, o) in inventory.objects.iter().enumerate().skip(offset) {
            check()?;
            let height = self.selector.target.height + (i - offset + 1) as u64;
            if !matches!(o.kind,Kind::Frame{height:h,..}if h==height)
                || o.bytes < HEADER_BYTES
                || o.bytes - HEADER_BYTES > policy.max_body_bytes
            {
                return Err(Error::BodyUnavailable);
            }
            frames = frames
                .checked_add(o.bytes as u64)
                .filter(|n| *n <= expected.limits.frame_bytes)
                .ok_or(Error::CapacityExceeded)?;
            fits(working_shape, o.bytes)?;
            let bytes = source.original(i, o.bytes)?;
            let h = Header::decode(&bytes[..HEADER_BYTES], &self.context.network)
                .map_err(|_| Error::CaptureFailed)?;
            h.verify_body(&bytes[HEADER_BYTES..], policy.max_body_bytes)
                .map_err(|_| Error::CaptureFailed)?;
            headers.push(h);
        }
        let verified = VerifiedHeaders::verify_bounded(rules, headers.clone(), || check().is_ok())
            .map_err(|_| Error::CaptureFailed)?;
        if verified.id(expected.target.height).ok() != Some(expected.target.tip)
            || verified.cumulative_work() != expected.target.work
            || headers
                .last()
                .is_none_or(|h| h.execution_commitment != expected.target.execution)
        {
            return Err(Error::ContextMismatch);
        }
        let verifier = crate::proofs::NativeVerifier::for_genesis(engine.genesis())
            .map_err(|_| Error::CaptureFailed)?;
        let mut marks = self.marks.clone();
        for (i, o) in inventory.objects.iter().enumerate().skip(offset) {
            check()?;
            let upper = working_shape.advanced(1)?;
            fits(upper, o.bytes)?;
            let bytes = source.original(i, o.bytes)?;
            let h = &headers[self.headers.len() + i - offset];
            let body = Body::decode(&bytes[HEADER_BYTES..], h.network, h.height, policy)
                .map_err(|_| Error::CaptureFailed)?;
            engine
                .apply(h, &body, &verifier)
                .map_err(|_| Error::CaptureFailed)?;
            upper.contains(engine.state())?;
            drop(body);
            drop(bytes);
            working_shape = super::memory::Shape::of(engine.state())?;
            fits(working_shape, 0)?;
            marks.push(super::replay::ExecutionMark::capture_reserved(
                &engine,
                imports,
                working_shape,
            )?);
            check()?;
        }
        let checkpoint =
            Self::checkpoint_from_archive(&headers, &marks, &engine, inventory, source, imports)?;
        let mut originals = self.originals.clone();
        originals.extend(source.seal()?);
        self.check_retained_originals()?;
        let mut result = Self::from_engine(
            &engine,
            headers,
            originals,
            self.genesis.clone(),
            marks,
            expected,
            inventory.digest,
            imports,
            working_shape,
            checkpoint,
            charge,
            available,
        )?;
        drop(verifier);
        drop(engine);
        check()?;
        result
            ._reservation
            .shrink_to(result.retained_bytes)
            .map_err(|_| Error::CapacityExceeded)?;
        Ok(result)
    }
}
