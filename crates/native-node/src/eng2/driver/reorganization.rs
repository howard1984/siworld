//! Bounded canonical switching through authenticated ancestor restore and append.

use super::*;
use crate::eng2::{
    branches::{BranchStore, SwitchReplay},
    selection::VerifiedHeaders,
    store::{ReplacementBudget, ReplacementFailure, ReplacementReplay},
};
use std::{collections::VecDeque, time::Instant};

struct Active {
    plan: SwitchReplay,
    replay: ReplacementReplay,
    _raw_memory: crate::p2p::Reservation,
}

pub(super) struct Reorganization {
    pub(super) branches: BranchStore,
    pub(super) discovery: crate::eng2::branches::discovery::runtime::Discovery,
    memory: crate::p2p::Budget,
    active: Option<Active>,
    pending_restart: bool,
    cached_candidate: Option<Hash>,
    cached_revision: u64,
    pub(super) stopped: Option<&'static str>,
    recent: VecDeque<Instant>,
    last: Option<SwitchEvent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwitchEvent {
    pub depth: usize,
    pub ancestor_height: u64,
    pub old_tip: Hash,
    pub new_tip: Hash,
    pub frequent: bool,
}

impl Reorganization {
    fn best_candidate(&mut self) -> Result<Option<Hash>, String> {
        let revision = self.branches.selection_revision();
        if revision != self.cached_revision {
            self.cached_candidate = self.branches.best_candidate()?;
            self.cached_revision = revision;
        }
        Ok(self.cached_candidate)
    }
    pub(super) fn paused(&self) -> bool {
        self.active.is_some() || self.stopped.is_some()
    }
}

impl Driver {
    #[cfg(all(unix, feature = "eng2-runtime", feature = "eng2-rehearsal"))]
    pub(crate) fn configure_owner_fault(
        &mut self,
        controller: Option<super::super::owner_fault::Controller>,
    ) {
        self.store.set_owner_fault(controller);
    }
    // Checkpoint archives commit after canonical savepoint capture. A restore
    // or a crash at that boundary can therefore require the current archive
    // to be recreated from the authenticated committed state.
    fn archive_reorganization_boundary(&mut self) -> Result<(), String> {
        let height = self.store.engine().state().height();
        if height > 0 && height.is_multiple_of(crate::eng2::runtime_export::CHECKPOINT_INTERVAL) {
            match self.store.archive_checkpoint_anchor(self.imports) {
                Ok(()) => self.last_archive_error = None,
                Err(error) => {
                    self.last_archive_error = Some(error.clone());
                    return Err(error);
                }
            }
        }
        Ok(())
    }
    /// Seed the accepted header order before any competing header is received.
    /// The raw archive is a separate database, never a canonical savepoint table.
    pub fn enable_reorganization(&mut self, branches: BranchStore) -> Result<(), String> {
        self.enable_reorganization_with_budget(branches, crate::p2p::Budget::new(256 * 1024 * 1024))
    }
    pub fn enable_reorganization_with_budget(
        &mut self,
        mut branches: BranchStore,
        memory: crate::p2p::Budget,
    ) -> Result<(), String> {
        if self.reorganization.is_some() {
            return Err("reorganization archive already configured".into());
        }
        let height = self.store.engine().state().height();
        branches.archive_canonical_suffix(&self.store, height)?;
        self.archive_reorganization_boundary()?;
        let discovery = crate::eng2::branches::discovery::runtime::Discovery::new(
            self.store.engine().state().network(),
            self.store.engine().genesis().id(),
            crate::eng2::branches::discovery::Limits {
                maximum_candidates: 8,
                maximum_peers: 8,
                maximum_requests: 1024,
                maximum_headers: 2048,
                maximum_headers_per_candidate: 256,
                maximum_body_bytes: 4 * 1024 * 1024 * 1024,
                maximum_attempts_per_header: 4,
                candidate_lifetime_ms: 900_000,
                window_ms: 3_600_000,
            },
            crate::eng2::network::discovery_now_ms(),
        )
        .map_err(|error| error.to_string())?;
        let cached_candidate = branches.best_candidate()?;
        let cached_revision = branches.selection_revision();
        let pending_restart = cached_candidate
            .is_some_and(|candidate| candidate != self.store.engine().state().tip());
        self.reorganization = Some(Reorganization {
            branches,
            discovery,
            memory,
            active: None,
            pending_restart,
            cached_candidate,
            cached_revision,
            stopped: None,
            recent: VecDeque::new(),
            last: None,
        });
        Ok(())
    }

    pub fn activities_allowed(&self) -> bool {
        self.store.ensure_exportable().is_ok()
            && self.reorganization.as_ref().is_none_or(|state| {
                state.active.is_none() && state.stopped.is_none() && !state.pending_restart
            })
    }

    pub fn template_generation(&self) -> u64 {
        self.template_generation
    }

    pub fn reorganization_status(&self) -> &'static str {
        match &self.reorganization {
            Some(state) if state.stopped.is_some() => "manual_recovery_required",
            Some(state) if state.active.is_some() => "applying_validated_branch",
            Some(state) if state.pending_restart => "resuming_best_branch",
            Some(_) => "ready",
            None => "unconfigured",
        }
    }

    pub fn reorganization_alarm(&self) -> Option<&'static str> {
        self.reorganization.as_ref().and_then(|state| {
            state.stopped.or_else(|| {
                state.last.and_then(|event| {
                    if event.depth > 6 {
                        Some("reorganization_depth_exceeds_six")
                    } else if event.frequent {
                        Some("reorganization_frequency_exceeds_three_per_hour")
                    } else {
                        None
                    }
                })
            })
        })
    }

    pub fn last_reorganization(&self) -> Option<SwitchEvent> {
        self.reorganization.as_ref().and_then(|state| state.last)
    }

    pub fn retain_competing_headers(&mut self, headers: &VerifiedHeaders) -> Result<(), String> {
        if !self.activities_allowed() {
            return Err("canonical switching pauses competitor admission".into());
        }
        self.reorganization
            .as_mut()
            .ok_or("independent branch archive unavailable")?
            .branches
            .retain_verified_headers(headers)
    }

    pub fn retain_competing_body(&mut self, header: &Header, body: &Body) -> Result<(), String> {
        if !self.activities_allowed() {
            return Err("canonical switching pauses competitor admission".into());
        }
        let policy = self.store.engine().body_policy();
        self.reorganization
            .as_mut()
            .ok_or("independent branch archive unavailable")?
            .branches
            .retain_body(header, body, policy)
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn capture_checkpoint_headers(
        &self,
    ) -> Result<Option<crate::eng2::branches::CheckpointHeaders>, String> {
        self.reorganization
            .as_ref()
            .map(|state| state.branches.capture_checkpoint_headers())
            .transpose()
    }
    pub(super) fn branch_header(&self, id: Hash) -> Result<Option<Header>, String> {
        self.reorganization
            .as_ref()
            .map(|state| state.branches.entry(id))
            .transpose()
            .map(|entry| entry.flatten().map(|entry| entry.header))
    }
    pub(super) fn branch_block_size(&self, id: Hash) -> Result<Option<usize>, String> {
        self.reorganization
            .as_ref()
            .map(|state| state.branches.body_size(id))
            .transpose()
            .map(Option::flatten)
    }
    pub(super) fn branch_block(&self, id: Hash) -> Result<(Header, Body), String> {
        let state = self
            .reorganization
            .as_ref()
            .ok_or("independent branch archive unavailable")?;
        let header = state
            .branches
            .entry(id)?
            .ok_or("retained branch header missing")?
            .header;
        let body = state
            .branches
            .body(id, self.store.engine().body_policy())?
            .ok_or("retained branch body missing")?;
        Ok((header, body))
    }

    /// Called only after the fixed candidate has complete independent materials.
    /// Prevalidation failure leaves the old canonical state untouched.
    fn begin_reorganization(
        &mut self,
        candidate: Hash,
        before_restore: impl FnOnce(u64) -> Result<(), String>,
    ) -> Result<bool, String> {
        let mut state = self
            .reorganization
            .take()
            .ok_or("independent branch archive unavailable")?;
        let result = self.begin_switch_inner(&mut state, candidate, before_restore);
        if result.is_err() && state.stopped.is_none() {
            state.stopped = Some("reorganization_preflight_unavailable");
        }
        self.reorganization = Some(state);
        result
    }

    fn begin_switch_inner(
        &mut self,
        state: &mut Reorganization,
        candidate: Hash,
        before_restore: impl FnOnce(u64) -> Result<(), String>,
    ) -> Result<bool, String> {
        if state.stopped.is_some() || state.active.is_some() {
            return Err("canonical switching is already paused".into());
        }
        let current = self.store.engine().state().tip();
        if candidate == current {
            state.pending_restart = false;
            return Ok(false);
        }
        let path = state.branches.candidate_path(current, candidate)?;
        if path.removed.len() > 24 {
            state.stopped = Some("reorganization_depth_exceeds_twenty_four");
            return Err("reorganization depth exceeds retained window".into());
        }
        let policy = self.store.engine().body_policy();
        let budget = ReplacementBudget {
            max_blocks: 256,
            max_body_bytes: 4 * 1024 * 1024 * 1024,
            max_elapsed: std::time::Duration::from_secs(900),
        };
        if path.replacement.len() > budget.max_blocks {
            state.stopped = Some("reorganization_local_block_budget_deferred");
            return Err("replacement exceeds local block budget".into());
        }
        // Read only persisted lengths before any archive copy, body decode or
        // replay-plan construction. Missing new material remains pending.
        let mut body_bytes = 0u64;
        let mut largest_body = 0usize;
        for id in &path.replacement {
            let Some(bytes) = state.branches.body_size(*id)? else {
                return Ok(false);
            };
            body_bytes = body_bytes
                .checked_add(bytes as u64)
                .ok_or("replay byte budget overflow")?;
            largest_body = largest_body.max(bytes);
        }
        for height in path.ancestor_height + 1..=self.store.engine().state().height() {
            let bytes = self.store.block_size(height)?;
            body_bytes = body_bytes
                .checked_add(bytes as u64)
                .ok_or("replay byte budget overflow")?;
            largest_body = largest_body.max(bytes);
        }
        if body_bytes > budget.max_body_bytes || largest_body > policy.max_body_bytes {
            state.stopped = Some("reorganization_local_byte_budget_deferred");
            return Err("replay materials exceed local byte budget".into());
        }
        // Plans and append load one body at a time. Hold the shared reservation
        // through preflight, prevalidation and every replay transaction. This
        // accounts for encoded/decoded proof-byte scratch, not total process RSS.
        let raw_bytes = largest_body
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(65536))
            .ok_or("replay working byte budget overflow")?;
        let raw_memory = match state.memory.reserve(raw_bytes) {
            Ok(reservation) => reservation,
            Err(_) => {
                state.stopped = Some("reorganization_shared_byte_budget_deferred");
                return Err("replay shared byte budget unavailable".into());
            }
        };
        let prepared = (|| {
            state
                .branches
                .archive_canonical_suffix(&self.store, path.ancestor_height)?;
            state.branches.prepare_switch(current, candidate, policy)
        })();
        let plan = match prepared {
            Ok(plan) => plan,
            Err(error) => {
                state.stopped = Some("reorganization_original_material_or_preflight_failed");
                return Err(error);
            }
        };

        let (height, ancestor, _) = plan.replacement.ancestor();
        let preview = self.store.prevalidate_replacement(
            height,
            ancestor,
            &plan.path.replacement,
            budget,
            &self.verifier,
            |index| {
                state
                    .branches
                    .replay_block(&plan.replacement, index, policy)
            },
        );
        let preview = match preview {
            Ok(preview) => preview,
            Err(ReplacementFailure::Rejected { index, .. }) => {
                let id = *plan
                    .path
                    .replacement
                    .get(index)
                    .ok_or("rejected index missing")?;
                if let Err(error) = state.branches.mark_invalid(id) {
                    state.stopped = Some("reorganization_invalid_mark_unavailable");
                    return Err(error);
                }
                state.pending_restart = state
                    .best_candidate()?
                    .is_some_and(|candidate| candidate != current);
                return Ok(false);
            }
            Err(error) => {
                state.stopped = Some("reorganization_prevalidation_deferred");
                return Err(error.to_string());
            }
        };
        if preview.tip() != candidate || preview.cumulative_work() != plan.path.cumulative_work {
            state.stopped = Some("reorganization_verified_work_or_identity_differs");
            return Err("complete replacement differs from qualified header path".into());
        }
        let generation = match self.template_generation.checked_add(1) {
            Some(value) => value,
            None => {
                state.stopped = Some("reorganization_template_generation_exhausted");
                return Err("template generation exhausted".into());
            }
        };
        if let Err(error) = before_restore(height) {
            state.stopped = Some("reorganization_output_barrier_failed");
            return Err(error);
        }
        self.template_generation = generation;
        self.padding = Pool::new(self.store.engine().state().network());
        // Do not automatically resurrect transactions from the removed suffix.
        self.pending = match pending_pool(self.store.engine().state().network()) {
            Ok(pool) => pool,
            Err(error) => {
                state.stopped = Some("reorganization_pending_pool_unavailable");
                return Err(error);
            }
        };
        #[cfg(all(unix, feature = "eng2-runtime", feature = "eng2-rehearsal"))]
        self.store
            .arm_owner_fault(super::super::owner_fault::Switch {
                old_tip: current,
                candidate,
                ancestor_id: ancestor,
                ancestor_height: height,
                replacement_height: height
                    .checked_add(plan.path.replacement.len() as u64)
                    .ok_or("owner fault replacement height overflow")?,
            })?;
        let replay = match self.store.begin_prevalidated_replacement(preview, |index| {
            state
                .branches
                .replay_block(&plan.replacement, index, policy)
        }) {
            Ok(replay) => replay,
            Err(error) => {
                state.stopped = Some("reorganization_ancestor_restore_failed");
                return Err(error.to_string());
            }
        };
        if let Err(error) = self.archive_reorganization_boundary() {
            state.stopped = Some("reorganization_ancestor_checkpoint_archive_failed");
            return Err(error);
        }
        state.active = Some(Active {
            plan,
            replay,
            _raw_memory: raw_memory,
        });
        Ok(true)
    }

    /// At most one normal append transaction per owner turn. Every intermediate
    /// prefix is committed, authenticated and recoverable through ordinary sync.
    pub fn advance_reorganization(&mut self) -> Result<bool, String> {
        let Some(mut state) = self.reorganization.take() else {
            return Ok(false);
        };
        let result = self.advance_switch_inner(&mut state);
        if result.is_err() && state.stopped.is_none() {
            state.stopped = Some("reorganization_completion_unavailable");
        }
        self.reorganization = Some(state);
        result
    }

    fn advance_switch_inner(&mut self, state: &mut Reorganization) -> Result<bool, String> {
        if state.stopped.is_some() {
            return Ok(false);
        }
        let Some(mut active) = state.active.take() else {
            return Ok(false);
        };
        let result = (|| {
            let index = active.replay.next_index();
            let (header, body) = state.branches.replay_block(
                &active.plan.replacement,
                index,
                self.store.engine().body_policy(),
            )?;
            let committed = self
                .store
                .append_prevalidated(&mut active.replay, &header, &body, &self.verifier)
                .map_err(|error| error.to_string())?;
            state.branches.record_execution(&committed)?;
            self.archive_reorganization_boundary()?;
            Ok::<(), String>(())
        })();
        if let Err(error) = result {
            // Unexpected storage/material/re-execution failures are local. They
            // must not permanently invalidate a branch or release activity gates.
            state.stopped = Some("reorganization_append_or_material_failed");
            state.active = Some(active);
            return Err(error);
        }
        if !active.replay.is_complete() {
            state.active = Some(active);
            return Ok(true);
        }
        if let Err(error) = self.store.ensure_exportable() {
            state.stopped = Some("reorganization_final_authentication_failed");
            state.active = Some(active);
            return Err(error);
        }
        if self.store.engine().state().tip() != active.replay.tip() {
            state.stopped = Some("reorganization_final_state_differs");
            return Err("replacement final identity differs".into());
        }
        #[cfg(all(unix, feature = "eng2-runtime", feature = "eng2-rehearsal"))]
        if let Err(error) = self.store.complete_owner_fault() {
            state.stopped = Some("owner_fault_boundary_not_reached");
            state.active = Some(active);
            return Err(error);
        }
        let now = Instant::now();
        while state
            .recent
            .front()
            .is_some_and(|time| now.duration_since(*time).as_secs() >= 3600)
        {
            state.recent.pop_front();
        }
        state.recent.push_back(now);
        while state.recent.len() > 4 {
            state.recent.pop_front();
        }
        state.last = Some(SwitchEvent {
            depth: active.plan.path.removed.len(),
            ancestor_height: active.plan.path.ancestor_height,
            old_tip: active
                .plan
                .path
                .removed
                .first()
                .copied()
                .unwrap_or(active.plan.path.ancestor_id),
            new_tip: active.replay.tip(),
            frequent: state.recent.len() > 3,
        });
        self.bootstrap
            .reconcile(now, |provider| provider.check_current(&self.store).is_ok());
        self.bootstrap_receipt_height = 0;
        state.pending_restart = state
            .best_candidate()?
            .is_some_and(|candidate| candidate != self.store.engine().state().tip());
        Ok(true)
    }

    /// This inspects only persisted, qualified candidates. Raw discovery and
    /// complete body acquisition remain separately bounded network operations.
    pub fn reorganization_tick(
        &mut self,
        before_restore: impl FnOnce(u64) -> Result<(), String>,
    ) -> Result<(), String> {
        if self
            .reorganization
            .as_ref()
            .is_some_and(|state| state.active.is_some() || state.stopped.is_some())
        {
            self.advance_reorganization()?;
            return Ok(());
        }
        let candidate = match self
            .reorganization
            .as_mut()
            .map(|state| state.best_candidate())
            .transpose()
        {
            Ok(candidate) => candidate.flatten(),
            Err(error) => {
                if let Some(state) = &mut self.reorganization {
                    state.stopped = Some("reorganization_branch_store_unavailable");
                }
                return Err(error);
            }
        };
        if let Some(candidate) = candidate {
            self.begin_reorganization(candidate, before_restore)?;
        }
        Ok(())
    }
}

#[cfg(all(test, unix, feature = "eng2-rehearsal"))]
mod tests;
