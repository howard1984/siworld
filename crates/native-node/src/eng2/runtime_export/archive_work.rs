//! Immutable checkpoint archive validation without canonical-owner access.
//!
//! A validated archive is not a signing or publication capability. Resident
//! integration must separately acquire its existing readiness and owner guards.
use super::{Header, ImportLimits, SnapshotState, Store};
use crate::eng2::genesis::Genesis;
use crate::{
    p2p::{Budget, Reservation},
    wire::Hash,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;

/// Exact locally accepted context captured with the canonical owner held.
struct Context {
    network: Hash,
    genesis: Hash,
    rules: Hash,
    anchor: Header,
    authorization: Header,
    roster: Hash,
}

/// Immutable bounded input. Only the local Store can construct this input.
/// No Store, signer, network guard or journal is transferred to the worker.
pub struct ArchiveWork {
    context: Context,
    genesis: Vec<u8>,
    archive: Vec<u8>,
    base: Header,
    suffix: Vec<(Header, crate::eng2::body::Body)>,
    limits: ImportLimits,
    reservation: Reservation,
    deferred: Option<(crate::eng2::store::CheckpointArchiveRead, Budget)>,
    input_digest: Hash,
}

/// Private evidence for the exact native-validated archive bytes and captured
/// reconstruction input. It carries no signature or publication authority.
#[cfg(feature = "eng2-runtime")]
#[derive(Clone)]
pub(super) struct NativeArchiveIdentity {
    anchor: Header,
    network: Hash,
    genesis: Hash,
    rules: Hash,
    input: Hash,
    snapshot: Hash,
    snapshot_bytes: usize,
    lineage: Arc<()>,
}
#[cfg(feature = "eng2-runtime")]
impl NativeArchiveIdentity {
    pub(super) fn same_live_validation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.lineage, &other.lineage)
            && self.anchor == other.anchor
            && self.network == other.network
            && self.genesis == other.genesis
            && self.rules == other.rules
            && self.input == other.input
            && self.snapshot == other.snapshot
            && self.snapshot_bytes == other.snapshot_bytes
    }
    pub(super) fn matches(&self, work: &ArchiveWork, snapshot: &[u8]) -> Result<bool, String> {
        Ok(self.anchor == work.context.anchor
            && self.network == work.context.network
            && self.genesis == work.context.genesis
            && self.rules == work.context.rules
            && self.input == work.native_input_identity()?
            && self.snapshot_bytes == snapshot.len()
            && self.snapshot == *blake3::hash(snapshot).as_bytes())
    }
}

/// A complete native reconstruction, still requiring current owner checks.
/// This type cannot be converted directly into a vote or certificate.
pub struct ValidatedArchive {
    context: Context,
    state: SnapshotState,
    archive: Vec<u8>,
    _reservation: Reservation,
    #[cfg(feature = "eng2-runtime")]
    identity: NativeArchiveIdentity,
}
impl ArchiveWork {
    #[cfg(all(test, feature = "eng2-runtime"))]
    pub(crate) fn component_fixture_for_test(budget: &Budget) -> Self {
        tests::fixture(budget)
    }
    #[cfg(all(test, feature = "eng2-runtime"))]
    pub(super) fn component_fixture_with_changed_archive_for_test(budget: &Budget) -> Self {
        let mut work = tests::fixture(budget);
        work.archive[10] ^= 1;
        work
    }
    pub(crate) fn capture_deferred(
        store: &Store,
        anchor: Header,
        read: crate::eng2::store::CheckpointArchiveRead,
        limits: ImportLimits,
        budget: &Budget,
    ) -> Result<Self, String> {
        store.ensure_exportable()?;
        // Reserve bounded immutable context before encoding genesis. No large
        // archive/body bytes are inspected or copied under the canonical owner.
        let reservation = budget
            .reserve(1024 * 1024 + std::mem::size_of::<Self>())
            .map_err(|_| "checkpoint capture context budget unavailable")?;
        let engine = store.engine();
        let genesis = engine.genesis().encode()?;
        if genesis.len() > 1024 * 1024 {
            return Err("checkpoint archive genesis exceeds byte bound".into());
        }
        Ok(Self {
            context: Context {
                network: engine.state().network(),
                genesis: engine.genesis().id(),
                rules: engine.genesis().rules_commitment(),
                anchor: anchor.clone(),
                authorization: store.header(engine.state().height())?,
                roster: engine
                    .state()
                    .governance()
                    .active_roster()
                    .digest(engine.state().network()),
            },
            genesis,
            archive: Vec::new(),
            base: anchor,
            suffix: Vec::new(),
            limits,
            reservation,
            deferred: Some((read, budget.clone())),
            input_digest: [0; 32],
        })
    }
    #[cfg(feature = "eng2-runtime")]
    pub(super) fn from_restore_read(
        read: &crate::eng2::store::CheckpointRestoreRead,
        height: u64,
        limits: ImportLimits,
        budget: &Budget,
    ) -> Result<Self, String> {
        let anchor = read.header(height)?;
        let captured = read.archive(height, limits, budget)?;
        Ok(Self {
            context: Context {
                network: read.network(),
                genesis: read.genesis_id(),
                rules: read.rules(),
                anchor,
                authorization: read
                    .authorization()
                    .ok_or("positive checkpoint authorization missing")?
                    .clone(),
                roster: read.roster(),
            },
            genesis: read.genesis_bytes().to_vec(),
            archive: captured.archive,
            base: captured.base,
            suffix: captured.suffix,
            limits,
            reservation: captured.reservation,
            deferred: None,
            input_digest: captured.input_digest,
        })
    }
    fn native_input_identity(&self) -> Result<Hash, String> {
        let mut hash =
            blake3::Hasher::new_derive_key("siworld eng2 checkpoint native input identity v1");
        hash.update(blake3::hash(&self.genesis).as_bytes());
        hash.update(
            &self
                .context
                .anchor
                .encode()
                .map_err(|_| "checkpoint input anchor invalid")?,
        );
        for bound in [
            self.limits.max_snapshot_bytes,
            self.limits.chain.max_component_bytes,
            self.limits.chain.max_leaves,
            self.limits.chain.max_nullifiers,
        ] {
            hash.update(&(bound as u64).to_le_bytes());
        }
        if self.input_digest == [0; 32] {
            // Test-local component input has no database capture. It still
            // binds its complete snapshot bytes and cannot grant Store access.
            if !self.suffix.is_empty() {
                return Err("checkpoint captured suffix identity missing".into());
            }
            hash.update(
                &self
                    .base
                    .encode()
                    .map_err(|_| "checkpoint input base invalid")?,
            );
            hash.update(blake3::hash(&self.archive).as_bytes());
        } else {
            hash.update(&self.input_digest);
        }
        Ok(*hash.finalize().as_bytes())
    }
    fn charge(bytes: usize) -> Result<usize, String> {
        bytes
            .checked_mul(16)
            .and_then(|n| n.checked_add(8 * 1024 * 1024))
            .ok_or_else(|| "checkpoint archive workspace bound overflow".into())
    }
    pub(crate) fn reserve(
        bytes: usize,
        suffix_bytes: usize,
        budget: &Budget,
    ) -> Result<Reservation, String> {
        let charge = Self::charge(bytes)?
            .checked_add(
                suffix_bytes
                    .checked_mul(4)
                    .ok_or("checkpoint suffix workspace bound overflow")?,
            )
            .ok_or("checkpoint preparation workspace bound overflow")?;
        budget
            .reserve(charge)
            .map_err(|_| "checkpoint archive preparation budget unavailable".into())
    }
    pub(super) fn validate(mut self, cancelled: &AtomicBool) -> Result<ValidatedArchive, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("checkpoint archive preparation cancelled".into());
        }
        if let Some((read, budget)) = self.deferred.take() {
            let captured = read.read(self.context.anchor.height, self.limits, &budget)?;
            self.base = captured.base;
            self.archive = captured.archive;
            self.suffix = captured.suffix;
            self.reservation = captured.reservation;
            self.input_digest = captured.input_digest;
        }
        let _input_identity = self.native_input_identity()?;
        let genesis = Genesis::decode(&self.genesis)?;
        if genesis.id() != self.context.genesis
            || genesis.rules_commitment() != self.context.rules
            || genesis.config().network != self.context.network
        {
            return Err("checkpoint archive immutable context differs".into());
        }
        // This is the unchanged complete native reconstruction, including
        // canonical component bytes, tree membership and execution commitment.
        // Neither a checksum nor claimed descriptors can replace these checks.
        let mut state = SnapshotState::from_committed_components(
            &genesis,
            &self.base,
            &self.archive,
            self.limits,
        )?;
        let archive = if self.suffix.is_empty() {
            self.archive
        } else {
            let mut engine = crate::eng2::execution::Engine::from_authenticated_local_state(
                genesis,
                state,
                self.limits.chain,
            )?;
            let verifier = crate::proofs::NativeVerifier::new()?;
            for (header, body) in self.suffix {
                if cancelled.load(Ordering::Acquire) {
                    return Err("checkpoint archive preparation cancelled".into());
                }
                engine.apply(&header, &body, &verifier)?;
            }
            if engine.state().height() != self.context.anchor.height
                || engine.state().tip()
                    != self
                        .context
                        .anchor
                        .id()
                        .map_err(|_| "invalid captured anchor header")?
            {
                return Err("checkpoint suffix does not reach the captured anchor".into());
            }
            let components = engine.state().canonical_components(
                crate::eng2::state_components::Binding {
                    genesis: self.context.genesis,
                    rules_commitment: self.context.rules,
                    parent: self.context.anchor.parent,
                },
                self.limits.chain,
            )?;
            let bytes = crate::eng2::snapshot::encode_components(&components, self.limits)?;
            state = SnapshotState::from_committed_components(
                engine.genesis(),
                &self.context.anchor,
                &bytes,
                self.limits,
            )?;
            bytes
        };
        if cancelled.load(Ordering::Acquire) {
            return Err("checkpoint archive preparation cancelled".into());
        }
        #[cfg(feature = "eng2-runtime")]
        let identity = NativeArchiveIdentity {
            anchor: self.context.anchor.clone(),
            network: self.context.network,
            genesis: self.context.genesis,
            rules: self.context.rules,
            input: _input_identity,
            snapshot: *blake3::hash(&archive).as_bytes(),
            snapshot_bytes: archive.len(),
            lineage: Arc::new(()),
        };
        Ok(ValidatedArchive {
            context: self.context,
            state,
            archive,
            _reservation: self.reservation,
            #[cfg(feature = "eng2-runtime")]
            identity,
        })
    }
}
impl ValidatedArchive {
    #[cfg(feature = "eng2-runtime")]
    pub(super) fn identity(&self) -> NativeArchiveIdentity {
        self.identity.clone()
    }
    pub(super) fn into_snapshot(
        self,
        retained_metadata_bytes: usize,
    ) -> Result<(Vec<u8>, Reservation), String> {
        let Self {
            archive,
            state,
            _reservation: mut reservation,
            ..
        } = self;
        // Native reconstruction has completed. Release its decoded state before
        // returning workspace, but keep the encoded snapshot and its metadata
        // charged for their complete retained lifetime, including Host::latest.
        drop(state);
        let Some(retained) = archive.capacity().checked_add(retained_metadata_bytes) else {
            drop(archive);
            drop(reservation);
            return Err("checkpoint retained archive byte bound overflow".into());
        };
        if reservation.shrink_to(retained).is_err() {
            drop(archive);
            drop(reservation);
            return Err("checkpoint retained archive exceeds its reservation".into());
        }
        Ok((archive, reservation))
    }
    /// Reacquire the original canonical owner before calling this method.
    /// Normal canonical extension preserves an immutable anchor and captured
    /// authorization header. Reorganization, epoch or immutable-context changes
    /// invalidate it. Live current-head readiness remains a separate host guard.
    pub fn check_current(&self, store: &Store) -> Result<(), String> {
        store.ensure_exportable()?;
        let engine = store.engine();
        let state = engine.state();
        let context = &self.context;
        if state.network() != context.network
            || engine.genesis().id() != context.genesis
            || engine.genesis().rules_commitment() != context.rules
            || state.height() < context.authorization.height
            || store.header(context.anchor.height)? != context.anchor
            || store.header(context.authorization.height)? != context.authorization
            || state.governance().active_roster().digest(state.network()) != context.roster
        {
            return Err("checkpoint archive preparation context is no longer current".into());
        }
        Ok(())
    }
    pub fn state(&self) -> &SnapshotState {
        &self.state
    }
    pub fn snapshot_bytes(&self) -> &[u8] {
        &self.archive
    }
}

/// At most one owned full-validation task and one retained result. Stopping or
/// dropping drains that task; no detached worker can outlive this owner.
enum WorkerResult {
    Archive(Box<ValidatedArchive>),
    #[cfg(all(unix, feature = "eng2-runtime"))]
    Retained(Box<super::retained_work::ValidatedRetained>),
}
#[derive(Default)]
pub struct ArchiveWorker {
    cancelled: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<WorkerResult, String>>>,
    completed: Option<WorkerResult>,
}
impl ArchiveWorker {
    #[cfg(all(test, feature = "eng2-runtime"))]
    pub(crate) fn start_with_test_hook(
        &mut self,
        work: ArchiveWork,
        before: impl FnOnce(&AtomicBool) + Send + 'static,
    ) -> Result<(), String> {
        self.start_inner(work, before)
    }
    pub fn is_busy(&self) -> bool {
        self.worker.is_some() || self.completed.is_some()
    }
    pub fn start(&mut self, work: ArchiveWork) -> Result<(), String> {
        self.start_inner(work, |_| {})
    }
    fn start_inner(
        &mut self,
        work: ArchiveWork,
        before: impl FnOnce(&AtomicBool) + Send + 'static,
    ) -> Result<(), String> {
        self.spawn(move |cancelled| {
            before(cancelled);
            work.validate(cancelled)
                .map(|value| WorkerResult::Archive(Box::new(value)))
        })
    }
    fn spawn(
        &mut self,
        job: impl FnOnce(&AtomicBool) -> Result<WorkerResult, String> + Send + 'static,
    ) -> Result<(), String> {
        if self.is_busy() {
            return Err("checkpoint worker already owns a task or result".into());
        }
        self.cancelled.store(false, Ordering::Release);
        let cancelled = self.cancelled.clone();
        self.worker = Some(
            std::thread::Builder::new()
                .name("eng2-checkpoint-archive".into())
                .spawn(move || job(&cancelled))
                .map_err(|_| "checkpoint archive worker creation failed")?,
        );
        Ok(())
    }
    #[cfg(all(unix, feature = "eng2-runtime"))]
    pub(super) fn start_retained(
        &mut self,
        work: super::retained_work::RetainedWork,
    ) -> Result<(), String> {
        self.spawn(move |cancelled| {
            work.validate(cancelled)
                .map(|value| WorkerResult::Retained(Box::new(value)))
        })
    }
    #[cfg(all(test, unix, feature = "eng2-runtime"))]
    pub(super) fn start_retained_with_test_hook(
        &mut self,
        work: super::retained_work::RetainedWork,
        before: impl FnOnce(&AtomicBool) + Send + 'static,
    ) -> Result<(), String> {
        self.spawn(move |cancelled| {
            before(cancelled);
            work.validate(cancelled)
                .map(|value| WorkerResult::Retained(Box::new(value)))
        })
    }
    fn poll(&mut self) -> Result<(), String> {
        if self.completed.is_some() || !self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            return Ok(());
        }
        self.completed = Some(
            self.worker
                .take()
                .ok_or("checkpoint worker disappeared")?
                .join()
                .map_err(|_| "checkpoint archive worker panicked")??,
        );
        Ok(())
    }
    pub fn try_complete(&mut self) -> Result<Option<ValidatedArchive>, String> {
        self.poll()?;
        match self.completed.take() {
            Some(WorkerResult::Archive(value)) => Ok(Some(*value)),
            #[cfg(all(unix, feature = "eng2-runtime"))]
            Some(value @ WorkerResult::Retained(_)) => {
                self.completed = Some(value);
                Ok(None)
            }
            None => Ok(None),
        }
    }
    #[cfg(all(unix, feature = "eng2-runtime"))]
    pub(super) fn try_complete_retained(
        &mut self,
    ) -> Result<Option<super::retained_work::ValidatedRetained>, String> {
        self.poll()?;
        match self.completed.take() {
            Some(WorkerResult::Retained(value)) => Ok(Some(*value)),
            Some(value @ WorkerResult::Archive(_)) => {
                self.completed = Some(value);
                Ok(None)
            }
            None => Ok(None),
        }
    }
    pub fn cancel(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
    /// Called only after canonical-owner access has ended. Native work is
    /// drained rather than interrupted or detached.
    pub fn stop(&mut self) -> Result<(), String> {
        self.cancel();
        self.completed = None;
        if let Some(worker) = self.worker.take() {
            let _ = worker
                .join()
                .map_err(|_| "checkpoint archive worker panicked")?;
        }
        Ok(())
    }
}
impl Drop for ArchiveWorker {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests;
