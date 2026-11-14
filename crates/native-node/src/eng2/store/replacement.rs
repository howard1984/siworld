//! Full native prevalidation bound to one unchanged canonical store generation.

use super::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// Local work bounds, not consensus validity limits. Expiry is deferred.
/// Elapsed time is checked between loader and verifier calls; this does not
/// interrupt a verifier already running or replace process isolation.
#[derive(Clone, Copy, Debug)]
pub struct ReplacementBudget {
    pub max_blocks: usize,
    pub max_body_bytes: u64,
    pub max_elapsed: Duration,
}

/// A local failure is never enough to persist a consensus-invalid branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplacementFailure {
    Deferred(String),
    /// Only explicit deterministic native rejection reasons use this variant.
    Rejected {
        index: usize,
        reason: String,
    },
}
impl std::fmt::Display for ReplacementFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deferred(reason) => write!(f, "replacement deferred: {reason}"),
            Self::Rejected { index, reason } => {
                write!(f, "replacement block {index} rejected: {reason}")
            }
        }
    }
}
impl std::error::Error for ReplacementFailure {}
fn deferred(reason: impl Into<String>) -> ReplacementFailure {
    ReplacementFailure::Deferred(reason.into())
}
fn native_failure(index: usize, reason: String) -> ReplacementFailure {
    match reason.as_str() {
        "native execution commitment differs from complete checked state"
        | "native transaction proof verification failed"
        | "native settlement proof verification failed" => {
            ReplacementFailure::Rejected { index, reason }
        }
        _ => deferred(reason),
    }
}

#[derive(Clone, Copy)]
struct Material {
    id: Hash,
    body_bytes: usize,
    commitment: Hash,
}

/// Constructed only after every fixed block has passed native execution in a
/// private engine. This authorizes neither fork choice nor a network export.
pub struct PrevalidatedReplacement {
    store: Arc<AtomicU64>,
    revision: u64,
    old_height: u64,
    old_tip: Hash,
    ancestor_height: u64,
    ancestor_id: Hash,
    materials: Vec<Material>,
    budget: ReplacementBudget,
    cumulative_work: siworld_core::pow::Work,
}
impl PrevalidatedReplacement {
    pub fn len(&self) -> usize {
        self.materials.len()
    }
    pub fn is_empty(&self) -> bool {
        self.materials.is_empty()
    }
    pub fn ancestor(&self) -> (u64, Hash) {
        (self.ancestor_height, self.ancestor_id)
    }
    pub fn tip(&self) -> Hash {
        self.materials.last().expect("nonempty verified path").id
    }
    pub fn cumulative_work(&self) -> siworld_core::pow::Work {
        self.cumulative_work
    }
    fn material(
        &self,
        index: usize,
        header: &Header,
        body: &Body,
        policy: super::super::body::Policy,
    ) -> Result<(), ReplacementFailure> {
        let expected = self
            .materials
            .get(index)
            .ok_or_else(|| deferred("replacement index unavailable"))?;
        if header
            .id()
            .map_err(|_| deferred("replacement header encoding changed"))?
            != expected.id
            || body.encoded_len(policy).map_err(deferred)? != expected.body_bytes
            || body.commitment(policy).map_err(deferred)? != expected.commitment
            || header.body_commitment != expected.commitment
        {
            return Err(deferred("prevalidated replacement material changed"));
        }
        Ok(())
    }
}

/// In-process replay ownership. It is intentionally not serializable: a fresh
/// process resumes the already committed valid prefix through ordinary sync.
pub struct ReplacementReplay {
    prepared: PrevalidatedReplacement,
    next: usize,
    revision: u64,
}
impl ReplacementReplay {
    pub fn next_index(&self) -> usize {
        self.next
    }
    pub fn is_complete(&self) -> bool {
        self.next == self.prepared.len()
    }
    pub fn tip(&self) -> Hash {
        self.prepared.tip()
    }
}

fn deadline(started: Instant, budget: ReplacementBudget) -> Result<(), ReplacementFailure> {
    if started.elapsed() >= budget.max_elapsed {
        Err(deferred("replacement local deadline reached"))
    } else {
        Ok(())
    }
}

impl Store {
    /// Abort a savepoint view after reconstructing its complete authenticated
    /// state, then execute all fixed material in memory. The canonical head and
    /// its point registry are unchanged on success, rejection or local expiry.
    /// The caller holds its switch lock while reading a fixed independent plan.
    #[allow(clippy::too_many_arguments)]
    pub fn prevalidate_replacement(
        &self,
        ancestor_height: u64,
        ancestor_id: Hash,
        expected_ids: &[Hash],
        budget: ReplacementBudget,
        verifier: &NativeVerifier,
        mut load: impl FnMut(usize) -> Result<(Header, Body), String>,
    ) -> Result<PrevalidatedReplacement, ReplacementFailure> {
        self.ensure_exportable().map_err(deferred)?;
        if expected_ids.is_empty()
            || expected_ids.len() > budget.max_blocks
            || budget.max_body_bytes == 0
            || budget.max_elapsed.is_zero()
        {
            return Err(deferred("replacement local work budget rejected"));
        }
        let depth = self
            .engine
            .state()
            .height()
            .checked_sub(ancestor_height)
            .ok_or_else(|| deferred("replacement ancestor is above canonical head"))?;
        if depth > 24 {
            return Err(deferred(
                "replacement old-chain depth exceeds transition limit",
            ));
        }
        let started = Instant::now();
        let revision = self.revision.load(Ordering::Acquire);
        let old_height = self.engine.state().height();
        let old_tip = self.engine.state().tip();
        let context = self
            .restart
            .as_ref()
            .ok_or_else(|| deferred("replacement requires authenticated ancestor state"))?;
        let point = rollback::read(&self.database)
            .map_err(deferred)?
            .into_iter()
            .find(|point| point.height == ancestor_height && point.block_id == ancestor_id)
            .ok_or_else(|| deferred("replacement ancestor point unavailable"))?;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|_| deferred("replacement ancestor view unavailable"))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|_| deferred("replacement ancestor view durability unavailable"))?;
        let saved = transaction
            .get_persistent_savepoint(point.savepoint)
            .map_err(|_| deferred("replacement ancestor point changed"))?;
        transaction
            .restore_savepoint(&saved)
            .map_err(|_| deferred("replacement ancestor view restoration failed"))?;
        let mut candidate = restoration::verify(
            &transaction,
            self.engine.genesis(),
            self.engine.limits(),
            &context.identity,
            point,
            self.imported_prefix,
            self.import_seed,
        )
        .map_err(deferred)?
        .engine;
        transaction
            .abort()
            .map_err(|_| deferred("replacement ancestor view abort failed"))?;
        let policy = candidate.body_policy();
        let mut bytes = 0u64;
        let mut materials = Vec::new();
        materials
            .try_reserve_exact(expected_ids.len())
            .map_err(|_| deferred("replacement material index allocation unavailable"))?;
        for (index, expected) in expected_ids.iter().enumerate() {
            deadline(started, budget)?;
            let (header, body) = load(index).map_err(deferred)?;
            let id = header
                .id()
                .map_err(|_| deferred("replacement header identity unavailable"))?;
            if id != *expected {
                return Err(deferred("fixed replacement identity changed"));
            }
            let length = body.encoded_len(policy).map_err(deferred)?;
            bytes = bytes
                .checked_add(
                    u64::try_from(length).map_err(|_| deferred("replacement length overflow"))?,
                )
                .filter(|n| *n <= budget.max_body_bytes)
                .ok_or_else(|| deferred("replacement local byte budget exhausted"))?;
            let commitment = body.commitment(policy).map_err(deferred)?;
            if commitment != header.body_commitment {
                return Err(deferred("fixed replacement body binding changed"));
            }
            deadline(started, budget)?;
            candidate
                .apply(&header, &body, verifier)
                .map_err(|reason| native_failure(index, reason))?;
            deadline(started, budget)?;
            materials.push(Material {
                id,
                body_bytes: length,
                commitment,
            });
        }
        self.ensure_exportable().map_err(deferred)?;
        if self.revision.load(Ordering::Acquire) != revision
            || self.engine.state().height() != old_height
            || self.engine.state().tip() != old_tip
        {
            return Err(deferred(
                "canonical generation changed during replacement prevalidation",
            ));
        }
        Ok(PrevalidatedReplacement {
            store: self.revision.clone(),
            revision,
            old_height,
            old_tip,
            ancestor_height,
            ancestor_id,
            materials,
            budget,
            cumulative_work: candidate.state().chain().cumulative_work,
        })
    }

    /// Recheck every retained byte binding and the canonical generation before
    /// committing the ancestor. No new candidate is substituted after preview.
    pub fn begin_prevalidated_replacement(
        &mut self,
        prepared: PrevalidatedReplacement,
        mut load: impl FnMut(usize) -> Result<(Header, Body), String>,
    ) -> Result<ReplacementReplay, ReplacementFailure> {
        self.check_prevalidated_base(&prepared)?;
        let started = Instant::now();
        let policy = self.engine.body_policy();
        for index in 0..prepared.len() {
            deadline(started, prepared.budget)?;
            let (header, body) = load(index).map_err(deferred)?;
            prepared.material(index, &header, &body, policy)?;
        }
        deadline(started, prepared.budget)?;
        self.check_prevalidated_base(&prepared)?;
        self.restore_ancestor(prepared.ancestor_height, prepared.ancestor_id)
            .map_err(deferred)?;
        Ok(ReplacementReplay {
            prepared,
            next: 0,
            revision: self.revision.load(Ordering::Acquire),
        })
    }

    /// Complete native verification still runs for every durably accepted block.
    /// A failed append consumes no replay position; the owner classifies local
    /// failures separately and preserves its independent original-chain plan.
    pub fn append_prevalidated(
        &mut self,
        replay: &mut ReplacementReplay,
        header: &Header,
        body: &Body,
        verifier: &NativeVerifier,
    ) -> Result<CommittedBlock, ReplacementFailure> {
        self.ensure_exportable().map_err(deferred)?;
        if !Arc::ptr_eq(&self.revision, &replay.prepared.store)
            || self.revision.load(Ordering::Acquire) != replay.revision
        {
            return Err(deferred("replacement replay canonical generation changed"));
        }
        let expected_height = replay
            .prepared
            .ancestor_height
            .checked_add(replay.next as u64)
            .ok_or_else(|| deferred("replacement replay height overflow"))?;
        let expected_parent = if replay.next == 0 {
            replay.prepared.ancestor_id
        } else {
            replay.prepared.materials[replay.next - 1].id
        };
        if self.engine.state().height() != expected_height
            || self.engine.state().tip() != expected_parent
        {
            return Err(deferred("replacement replay prefix changed"));
        }
        replay
            .prepared
            .material(replay.next, header, body, self.engine.body_policy())?;
        // Any unexpected failure during re-execution is conservative deferred.
        // No local I/O or verifier availability error marks a branch invalid.
        let committed = self.append(header, body, verifier).map_err(deferred)?;
        replay.next += 1;
        replay.revision = self.revision.load(Ordering::Acquire);
        Ok(committed)
    }

    fn check_prevalidated_base(
        &self,
        prepared: &PrevalidatedReplacement,
    ) -> Result<(), ReplacementFailure> {
        self.ensure_exportable().map_err(deferred)?;
        if !Arc::ptr_eq(&self.revision, &prepared.store)
            || self.revision.load(Ordering::Acquire) != prepared.revision
            || self.engine.state().height() != prepared.old_height
            || self.engine.state().tip() != prepared.old_tip
        {
            return Err(deferred("prevalidated canonical generation changed"));
        }
        Ok(())
    }
}
