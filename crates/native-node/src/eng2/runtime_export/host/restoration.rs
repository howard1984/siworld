//! Resident restoration lifecycle on the existing owned archive worker.
use super::super::retained::Restored;
use super::super::retained_work::{PreparedResult, RetainedWork, ValidatedRetained};
use super::*;

impl Host {
    /// Construct an unrestored resident with its shared allocation budget in
    /// place before any retained artifact is read or decoded.
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn open_resident(
        root: &Path,
        store: &Store,
        limits: ImportLimits,
        existing_key: Option<&Path>,
        budget: &crate::p2p::Budget,
    ) -> Result<Self, String> {
        let mut value = Self {
            export: PublicExport::open_unrestored(root, store)?,
            signer: existing_key
                .map(|path| ExistingSigner::load(path, store))
                .transpose()?,
            limits,
            pending: None,
            votes: std::array::from_fn(|_| None),
            journaled_vote: None,
            latest: None,
            last_now: None,
            last_exported: None,
            last_status: None,
            tick_failure: None,
            wallet: None,
            wallet_requested: false,
            wallet_paused: false,
            retired_through: None,
            retained_head: None,
            preparation: None,
            restore_required: true,
            retained_ready: false,
            last_retained_material: None,
        };
        // Startup has no authenticated retained capability to reuse. Existing
        // immutable wallet generations remain, but their mutable head waits.
        value.export.pause_wallet_head()?;
        value.enable_async_preparation(budget)?;
        Ok(value)
    }
    /// Each fresh restoration examines actual artifact contents, including on
    /// an unchanged head. Pending or failed work only pauses checkpoint exports.
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn reconcile_retained_async(
        &mut self,
        store: &Store,
        headers: impl FnOnce() -> Result<Option<crate::eng2::branches::CheckpointHeaders>, String>,
    ) -> Result<bool, String> {
        let result = self.reconcile_retained_step(store, headers);
        if result.is_err() {
            // A real authentication/context failure is different from pending
            // inspection: withdraw old mutable advertisements and invalidate
            // every earlier task, even if the canonical head is unchanged.
            self.pause_reorganization_exports()?;
        }
        result
    }
    #[cfg(feature = "eng2-runtime")]
    fn reconcile_retained_step(
        &mut self,
        store: &Store,
        headers: impl FnOnce() -> Result<Option<crate::eng2::branches::CheckpointHeaders>, String>,
    ) -> Result<bool, String> {
        self.retained_ready = false;
        let restoring = self
            .preparation
            .as_ref()
            .is_some_and(|value| value.retained_request);
        if restoring {
            let preparation = self
                .preparation
                .as_mut()
                .ok_or("checkpoint worker unavailable")?;
            let result = preparation.worker.try_complete_retained();
            if preparation.worker.is_busy() {
                return Ok(false);
            }
            preparation.retained_request = false;
            match result {
                Ok(Some(result)) => {
                    self.install_retained(store, result)?;
                    self.retained_ready = true;
                    return Ok(true);
                }
                Ok(None) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        // Drain a prior archive result without a signing/readiness permit. A
        // completed candidate may coexist with the next restoration task.
        self.advance_preparation(store, None)?;
        let preparation = self
            .preparation
            .as_mut()
            .ok_or("checkpoint worker unavailable")?;
        if preparation.worker.is_busy() {
            return Ok(false);
        }
        let mut work = RetainedWork::capture(
            store,
            headers()?,
            &self.export,
            self.limits,
            &preparation.budget,
            preparation.generation,
            self.retired_through,
            self.latest.as_ref(),
            self.pending.as_ref(),
        )?;
        work.bind_pending_votes(&self.votes, self.journaled_vote.as_ref())?;
        preparation.worker.start_retained(work)?;
        preparation.retained_request = true;
        Ok(false)
    }
    fn validate_retained_prepared(
        store: &Store,
        value: &PreparedResult,
        original: Option<&PreparedCheckpoint>,
        current: bool,
    ) -> Result<(), String> {
        let prepared: &PreparedCheckpoint = match value {
            PreparedResult::Owned(value) => value,
            PreparedResult::Reuse(identity) => {
                let original = original.ok_or("checkpoint live reuse owner disappeared")?;
                if !identity.matches(original) {
                    return Err("checkpoint live reuse ownership changed".into());
                }
                original
            }
        };
        if current {
            prepared.check_current(store)
        } else {
            prepared.check_prefix(store)
        }
    }
    fn install_current_retained_pending(
        &mut self,
        value: PreparedResult,
        head: u64,
        retired: Option<u64>,
    ) -> Result<(), String> {
        // Compare before taking the original live object. Reuse must retain
        // the already collected vote set for this exact same statement.
        let unchanged = self.pending.as_ref().is_some_and(|old| match &value {
            PreparedResult::Owned(candidate) => old.statement == candidate.statement,
            PreparedResult::Reuse(identity) => identity.matches(old),
        });
        let prepared = match value {
            PreparedResult::Owned(value) => *value,
            PreparedResult::Reuse(identity) => {
                let original = self
                    .pending
                    .take()
                    .ok_or("checkpoint reuse owner disappeared")?;
                if !identity.matches(&original) {
                    return Err("checkpoint live reuse ownership changed".into());
                }
                original
            }
        };
        if !retired.is_some_and(|height| prepared.statement.checkpoint_height <= height)
            && !pending_obsolete(
                prepared.statement.checkpoint_height,
                self.export.latest_height(),
                head,
            )
        {
            self.pending = Some(prepared);
            if !unchanged {
                self.votes = std::array::from_fn(|_| None);
            }
        }
        Ok(())
    }
    fn install_retained(&mut self, store: &Store, result: ValidatedRetained) -> Result<(), String> {
        result.revision.check(store)?;
        let preparation = self
            .preparation
            .as_ref()
            .ok_or("checkpoint worker unavailable")?;
        if result.generation != preparation.generation
            || result.material_generation != self.export.material_generation()
            || result.retired_through != self.retired_through
        {
            return Err("checkpoint retained restoration generation changed".into());
        }
        // Preflight every reuse and current-context check before changing any
        // Host object. A late success after cancellation cannot be installed.
        if let Restored::Current(value) = &result.latest {
            Self::validate_retained_prepared(
                store,
                &value.prepared,
                self.latest.as_ref().map(|old| &old.prepared),
                false,
            )?;
        }
        if let Restored::Current(value) = &result.pending {
            Self::validate_retained_prepared(store, value, self.pending.as_ref(), true)?;
        }
        let mut retired = self.retired_through;
        if let Some(height) = result.authenticated_retired_through {
            retired = Some(retired.map_or(height, |old| old.max(height)));
        }
        if let Restored::Retired(height) = &result.latest {
            retired = Some(retired.map_or(*height, |old| old.max(*height)));
        }
        if let Restored::Retired(height) = &result.pending {
            retired = Some(retired.map_or(*height, |old| old.max(*height)));
        }
        if let Restored::Retired(height) = &result.latest {
            self.export.retire_checked_cursor(
                *height,
                result
                    .cursor
                    .as_deref()
                    .ok_or("checkpoint authenticated retired cursor missing")?,
            )?;
        }
        self.latest = match result.latest {
            Restored::Absent | Restored::Retired(_) => {
                self.export.forget_publication();
                None
            }
            Restored::Current(value) => {
                let prepared = match value.prepared {
                    PreparedResult::Owned(value) => *value,
                    PreparedResult::Reuse(_) => {
                        self.latest
                            .take()
                            .ok_or("checkpoint reuse owner disappeared")?
                            .prepared
                    }
                };
                let checkpoint = CertifiedCheckpoint {
                    prepared,
                    certificate: value.certificate,
                    published: value.published,
                };
                self.export.remember_publication(&checkpoint)?;
                Some(checkpoint)
            }
        };
        match result.pending {
            Restored::Absent => (),
            Restored::Retired(_) => {
                self.pending = None;
                self.votes = std::array::from_fn(|_| None);
            }
            Restored::Current(value) => self.install_current_retained_pending(
                value,
                store.engine().state().height(),
                retired,
            )?,
        }
        if let Some(height) = retired
            && self.retired_through != Some(height)
        {
            self.retire_anchor(height)?;
        }
        let material_changed = self.last_retained_material != Some(result.material);
        self.last_retained_material = Some(result.material);
        self.retained_head = Some((
            store.engine().state().height(),
            store.engine().state().tip(),
        ));
        if material_changed {
            self.last_exported = None;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "eng2-runtime"))]
mod tests;
