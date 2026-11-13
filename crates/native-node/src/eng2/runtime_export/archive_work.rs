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
}

/// A complete native reconstruction, still requiring current owner checks.
/// This type cannot be converted directly into a vote or certificate.
pub struct ValidatedArchive {
    context: Context,
    state: SnapshotState,
    archive: Vec<u8>,
    _reservation: Reservation,
}
impl ArchiveWork {
    #[cfg(all(test, feature = "eng2-runtime"))]
    pub(crate) fn component_fixture_for_test(budget: &Budget) -> Self {
        tests::fixture(budget)
    }
    pub(crate) fn capture(
        store: &Store,
        anchor: Header,
        base: Header,
        bytes: &[u8],
        suffix: Vec<(Header, crate::eng2::body::Body)>,
        reservation: Reservation,
        limits: ImportLimits,
    ) -> Result<Self, String> {
        store.ensure_exportable()?;
        let engine = store.engine();
        let state = engine.state();
        if bytes.len() > limits.max_snapshot_bytes
            || anchor.height == 0
            || anchor.height > state.height()
            || store.header(anchor.height)? != anchor
            || base.height > anchor.height
            || anchor.height - base.height >= super::LEGACY_CHECKPOINT_INTERVAL
            || suffix.len() as u64 != anchor.height - base.height
            || store.header(base.height)? != base
        {
            return Err("checkpoint archive capture exceeds its height or byte bound".into());
        }
        let genesis = engine.genesis().encode()?;
        if genesis.len() > 1024 * 1024 {
            return Err("checkpoint archive genesis exceeds byte bound".into());
        }
        Ok(Self {
            context: Context {
                network: state.network(),
                genesis: engine.genesis().id(),
                rules: engine.genesis().rules_commitment(),
                anchor,
                authorization: store.header(state.height())?,
                roster: state.governance().active_roster().digest(state.network()),
            },
            genesis,
            archive: bytes.to_vec(),
            base,
            suffix,
            limits,
            reservation,
        })
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
    fn validate(self, cancelled: &AtomicBool) -> Result<ValidatedArchive, String> {
        if cancelled.load(Ordering::Acquire) {
            return Err("checkpoint archive preparation cancelled".into());
        }
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
        Ok(ValidatedArchive {
            context: self.context,
            state,
            archive,
            _reservation: self.reservation,
        })
    }
}
impl ValidatedArchive {
    pub(super) fn into_snapshot(self) -> (Vec<u8>, Reservation) {
        (self.archive, self._reservation)
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
#[derive(Default)]
pub struct ArchiveWorker {
    cancelled: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<ValidatedArchive, String>>>,
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
        self.worker.is_some()
    }
    pub fn start(&mut self, work: ArchiveWork) -> Result<(), String> {
        self.start_inner(work, |_| {})
    }
    fn start_inner(
        &mut self,
        work: ArchiveWork,
        before: impl FnOnce(&AtomicBool) + Send + 'static,
    ) -> Result<(), String> {
        if self.worker.is_some() {
            return Err("checkpoint archive preparation is already in flight".into());
        }
        self.cancelled.store(false, Ordering::Release);
        let cancelled = self.cancelled.clone();
        self.worker = Some(
            std::thread::Builder::new()
                .name("eng2-checkpoint-archive".into())
                .spawn(move || {
                    before(&cancelled);
                    work.validate(&cancelled)
                })
                .map_err(|_| "checkpoint archive worker creation failed")?,
        );
        Ok(())
    }
    pub fn try_complete(&mut self) -> Result<Option<ValidatedArchive>, String> {
        if !self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            return Ok(None);
        }
        self.worker
            .take()
            .ok_or("checkpoint archive worker disappeared")?
            .join()
            .map_err(|_| "checkpoint archive worker panicked")?
            .map(Some)
    }
    pub fn cancel(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
    /// Cancellation is checked before and after complete native reconstruction.
    /// An in-progress native check is drained, never abandoned or interrupted.
    pub fn stop(&mut self) -> Result<(), String> {
        self.cancelled.store(true, Ordering::Release);
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
