//! One bounded native producer; proving and nonce search hold no owner lock.

use super::super::producer::Search;
fn progress(shared: &Shared, attempts: u64) -> Result<(), String> {
    let mut status = shared
        .production
        .lock()
        .map_err(|_| "resident status lock poisoned")?;
    status.pow_attempts = status
        .pow_attempts
        .checked_add(attempts)
        .ok_or("native work counter exhausted")?;
    status.last_pow = Some(Instant::now());
    Ok(())
}
use super::*;
use crate::producer::MiningSettings;
mod failure;
mod request;
pub(super) use failure::Failure;

fn below_rehearsal_ceiling(
    directory: &Path,
    shared: &Shared,
    required: bool,
) -> Result<bool, String> {
    #[cfg(feature = "eng2-rehearsal")]
    {
        let owner = shared
            .owner
            .lock()
            .map_err(|_| "resident owner lock poisoned")?;
        let ceiling = crate::eng2::rehearsal::partition::production_ceiling(
            directory,
            owner.engine().genesis(),
        )?;
        if required && ceiling.is_none() {
            return Err("partition production budget disappeared".into());
        }
        Ok(ceiling.is_none_or(|maximum| owner.engine().state().height() < maximum))
    }
    #[cfg(not(feature = "eng2-rehearsal"))]
    {
        let _ = (directory, shared, required);
        Ok(true)
    }
}

// Every control poll runs under the same canonical owner used for admission.
// Revisions invalidate work prepared or proved under an earlier local policy.
fn isolated_permission(
    shared: &Shared,
    owner: &Driver,
    expected: Option<u64>,
) -> Result<(bool, u64), String> {
    #[cfg(all(unix, feature = "eng2-rehearsal"))]
    {
        let mut slot = shared
            .isolated_production
            .lock()
            .map_err(|_| "isolated production control lock poisoned")?;
        if let Some(control) = slot.as_mut() {
            return control.permission(
                owner.engine().state().height(),
                &owner.engine().state().tip(),
                expected,
            );
        }
    }
    let _ = (shared, owner, expected);
    Ok((true, 0))
}

// The caller supplies the current production/readiness gates before any
// expensive proving keys or preprocessing are constructed.
fn ready_prover<T>(
    slot: &mut Option<Result<T, String>>,
    ready: bool,
    initialize: impl FnOnce() -> Result<T, String>,
) -> Result<Option<&T>, Failure> {
    if !ready {
        return Ok(None);
    }
    slot.get_or_insert_with(initialize)
        .as_ref()
        .map(Some)
        .map_err(|_| Failure::ProverInit)
}

fn continuous(directory: &Path, settings: &MiningSettings, shared: &Shared) -> Result<(), Failure> {
    let _charge = shared
        .budget
        .reserve(256 * 1024 * 1024)
        .map_err(|_| Failure::Budget)?;
    let mut prover = None;
    #[cfg(feature = "eng2-rehearsal")]
    let ceiling_required = {
        let owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
        crate::eng2::rehearsal::partition::production_ceiling(directory, owner.engine().genesis())
            .map_err(|_| Failure::RehearsalControl)?
            .is_some()
    };
    #[cfg(not(feature = "eng2-rehearsal"))]
    let ceiling_required = false;
    while !shared.cancel.is_cancelled() {
        let below_ceiling = below_rehearsal_ceiling(directory, shared, ceiling_required)
            .map_err(|_| Failure::RehearsalControl)?;
        let (isolated_ready, policy_revision) = {
            let owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
            isolated_permission(shared, &owner, None).map_err(|_| Failure::ProductionControl)?
        };
        let ready = below_ceiling
            && isolated_ready
            && shared.mining_ready().map_err(|_| Failure::Readiness)?;
        let prover = match ready_prover(&mut prover, ready, NativeProver::new)? {
            Some(prover) => prover,
            None => {
                shared
                    .phase(if below_ceiling && isolated_ready {
                        "networking"
                    } else {
                        "rehearsal_paused"
                    })
                    .map_err(|_| Failure::StatusUpdate)?;
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        shared
            .phase("refilling")
            .map_err(|_| Failure::StatusUpdate)?;
        let (generation, task) = {
            let mut owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
            if !owner.activities_allowed()
                || !isolated_permission(shared, &owner, Some(policy_revision))
                    .map_err(|_| Failure::ProductionControl)?
                    .0
            {
                continue;
            }
            let task = if owner.ready_positions() < crate::pool::MIN_READY {
                owner
                    .prepare_padding()
                    .map_err(|_| Failure::PaddingPrepare)?
            } else {
                None
            };
            (owner.template_generation(), task)
        };
        if let Some(task) = task {
            {
                let owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
                if !isolated_permission(shared, &owner, Some(policy_revision))
                    .map_err(|_| Failure::ProductionControl)?
                    .0
                {
                    continue;
                }
            }
            let padding = task.prove(prover).map_err(|_| Failure::PaddingProve)?;
            if shared.cancel.is_cancelled() {
                break;
            }
            let mut owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
            // A long catch-up can expire the witnessed snapshot while a proof
            // runs. Such work is discarded, with no fallback or queue reuse.
            if owner.activities_allowed()
                && isolated_permission(shared, &owner, Some(policy_revision))
                    .map_err(|_| Failure::ProductionControl)?
                    .0
                && owner.template_generation() == generation
                && owner
                    .engine()
                    .state()
                    .chain()
                    .snapshot(padding.transaction.record.snapshot)
                    .is_ok()
            {
                owner
                    .insert_padding(padding)
                    .map_err(|_| Failure::PaddingInsert)?;
            }
            continue;
        }
        if !shared.mining_ready().map_err(|_| Failure::Readiness)? {
            continue;
        }
        shared
            .phase("preparing")
            .map_err(|_| Failure::StatusUpdate)?;
        let (generation, prepared, mut submission) = {
            let mut owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
            if !owner.activities_allowed()
                || owner.ready_positions() < crate::pool::MIN_READY
                || !isolated_permission(shared, &owner, Some(policy_revision))
                    .map_err(|_| Failure::ProductionControl)?
                    .0
            {
                continue;
            }
            let timestamp = (unix_ms().map_err(|_| Failure::PrepareClock)? / 1000).max(
                owner
                    .engine()
                    .state()
                    .chain()
                    .median_time_past()
                    .checked_add(1)
                    .ok_or(Failure::PrepareClock)?,
            );
            let head = owner.head().map_err(|_| Failure::PrepareHead)?;
            let mut submission = request::Request::take(shared, &head);
            let prepared = if let Some((operations, issuances)) = submission.inputs() {
                match owner.prepare_block_with_operations(
                    crate::pool::MIN_READY,
                    timestamp,
                    settings,
                    operations,
                    issuances,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        submission.fail("preparation_rejected");
                        continue;
                    }
                }
            } else {
                owner
                    .prepare_block(crate::pool::MIN_READY, timestamp, settings)
                    .map_err(|_| Failure::PrepareBlock)?
            };
            (owner.template_generation(), prepared, submission)
        };
        {
            let owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
            if !isolated_permission(shared, &owner, Some(policy_revision))
                .map_err(|_| Failure::ProductionControl)?
                .0
            {
                if submission.is_some() {
                    submission.fail("isolated_production_policy_changed");
                }
                continue;
            }
        }
        let proved = match prepared.prove(prover) {
            Ok(proved) => proved,
            Err(_) => {
                if submission.is_some() {
                    submission.fail("proving_rejected");
                    continue;
                }
                return Err(Failure::ProveBlock);
            }
        };
        if shared.cancel.is_cancelled() {
            break;
        }
        let mut work = {
            let owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
            if !owner.activities_allowed()
                || !isolated_permission(shared, &owner, Some(policy_revision))
                    .map_err(|_| Failure::ProductionControl)?
                    .0
                || owner.template_generation() != generation
                || owner.head().map_err(|_| Failure::WorkHead)?.id != proved.parent()
            {
                if submission.is_some() {
                    submission.fail("stale_parent");
                }
                continue;
            }
            match owner.prepare_work(proved) {
                Ok(work) => work,
                Err(_) => {
                    if submission.is_some() {
                        submission.fail("engine_rejected");
                        continue;
                    }
                    return Err(Failure::WorkPrepare);
                }
            }
        };
        shared.phase("mining").map_err(|_| Failure::StatusUpdate)?;
        loop {
            if shared.cancel.is_cancelled()
                || !shared.mining_ready().map_err(|_| Failure::Readiness)?
                || !below_rehearsal_ceiling(directory, shared, ceiling_required)
                    .map_err(|_| Failure::RehearsalControl)?
            {
                break;
            }
            let current_template = {
                let owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
                owner.activities_allowed()
                    && isolated_permission(shared, &owner, Some(policy_revision))
                        .map_err(|_| Failure::ProductionControl)?
                        .0
                    && owner.template_generation() == generation
                    && owner.head().map_err(|_| Failure::WorkHead)?.id == work.parent()
            };
            if !current_template {
                if submission.is_some() {
                    submission.fail("stale_parent");
                }
                break;
            }
            let before = work.next_nonce();
            let searched = work.search(256).map_err(|_| Failure::WorkSearch)?;
            match searched {
                Search::Pending(next) => {
                    let attempts = next.next_nonce() - before;
                    progress(shared, attempts).map_err(|_| Failure::WorkProgress)?;
                    work = next;
                }
                Search::Found(block) => {
                    shared.block_events.produced(&block.header);
                    let attempts = block
                        .header
                        .nonce
                        .checked_sub(before)
                        .and_then(|n| n.checked_add(1))
                        .ok_or(Failure::WorkProgress)?;
                    progress(shared, attempts).map_err(|_| Failure::WorkProgress)?;
                    shared
                        .phase("committing")
                        .map_err(|_| Failure::StatusUpdate)?;
                    let committed = {
                        let mut owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
                        if !isolated_permission(shared, &owner, Some(policy_revision))
                            .map_err(|_| Failure::ProductionControl)?
                            .0
                        {
                            if submission.is_some() {
                                submission.fail("isolated_production_policy_changed");
                            }
                            break;
                        }
                        #[cfg(feature = "eng2-rehearsal")]
                        {
                            let ceiling = crate::eng2::rehearsal::partition::production_ceiling(
                                directory,
                                owner.engine().genesis(),
                            )
                            .map_err(|_| Failure::RehearsalControl)?;
                            if ceiling_required && ceiling.is_none() {
                                return Err(Failure::RehearsalControl);
                            }
                            if ceiling
                                .is_some_and(|maximum| owner.engine().state().height() >= maximum)
                            {
                                if submission.is_some() {
                                    submission.fail("rehearsal_production_paused");
                                }
                                break;
                            }
                        }
                        if shared
                            .checkpoint_conflict()
                            .map_err(|_| Failure::Readiness)?
                        {
                            if submission.is_some() {
                                submission.fail("checkpoint_current_quorum_conflict");
                            }
                            break;
                        }
                        if !owner.activities_allowed()
                            || owner.template_generation() != generation
                            || owner.head().map_err(|_| Failure::CommitHead)?.id
                                != block.header.parent
                        {
                            if submission.is_some() {
                                submission.fail("stale_parent");
                            }
                            break;
                        }
                        match owner.accept(&block.header, &block.body) {
                            Ok(committed) => committed,
                            Err(_) => {
                                if submission.is_some() {
                                    submission.fail("commit_rejected");
                                    break;
                                }
                                return Err(Failure::CommitBlock);
                            }
                        }
                    };
                    if submission.is_some() {
                        let owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
                        submission.committed(&committed, owner.store());
                    }
                    // This receipt is private. A write failure is an explicit
                    // production alarm and never relabels the committed block.
                    crate::local::save_reward(directory, &committed.id(), &block.reward_secret)
                        .map_err(|_| Failure::RewardWrite)?;
                    let mut status = shared
                        .production
                        .lock()
                        .map_err(|_| Failure::StatusUpdate)?;
                    status.blocks = status.blocks.checked_add(1).ok_or(Failure::StatusUpdate)?;
                    break;
                }
            }
        }
    }
    Ok(())
}
pub(super) fn run(
    directory: &Path,
    settings: MiningSettings,
    shared: Arc<Shared>,
) -> Result<(), String> {
    failure::run_once(
        || {
            let workers = rayon::ThreadPoolBuilder::new()
                .num_threads(4)
                .thread_name(|i| format!("eng2-prover-{i}"))
                .build()
                .map_err(|_| Failure::WorkerPool)?;
            workers.install(|| continuous(directory, &settings, &shared))
        },
        |failure| {
            if let Ok(mut status) = shared.production.lock() {
                status.fail(failure);
            }
        },
        || {
            // Keep validating and serving while production is alarmed. No
            // prover retry, credential change or alternate profile is attempted.
            while !shared.cancel.is_cancelled() {
                std::thread::sleep(Duration::from_millis(100));
            }
        },
    )
}

#[cfg(test)]
mod deferred_prover_tests {
    use super::{Failure, ready_prover};
    use std::cell::Cell;

    #[test]
    fn paused_start_and_pause_after_resume_never_initialize_a_prover() {
        let calls = Cell::new(0);
        let mut slot = None;
        let initialize = || {
            calls.set(calls.get() + 1);
            Ok(41u8)
        };
        assert!(
            ready_prover(&mut slot, false, initialize)
                .unwrap()
                .is_none()
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(
            *ready_prover(&mut slot, true, initialize).unwrap().unwrap(),
            41
        );
        assert_eq!(calls.get(), 1);
        assert!(
            ready_prover(&mut slot, false, initialize)
                .unwrap()
                .is_none()
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(
            *ready_prover(&mut slot, true, initialize).unwrap().unwrap(),
            41
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn initialization_failure_propagates_without_a_second_initialization() {
        let calls = Cell::new(0);
        let mut slot: Option<Result<u8, String>> = None;
        let initialize = || {
            calls.set(calls.get() + 1);
            Err("initialization failed".into())
        };
        assert!(
            ready_prover(&mut slot, false, initialize)
                .unwrap()
                .is_none()
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(
            ready_prover(&mut slot, true, initialize).unwrap_err(),
            Failure::ProverInit
        );
        assert_eq!(
            ready_prover(&mut slot, true, initialize).unwrap_err(),
            Failure::ProverInit
        );
        assert_eq!(calls.get(), 1);
    }
}
