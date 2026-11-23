//! One bounded native producer; proving and nonce search hold no owner lock.

use super::super::{driver::PrepareBlockError, producer::Batch};
use crate::pool::FillError;
fn progress(shared: &Shared, attempts: u64) -> Result<(), String> {
    if attempts == 0 {
        return Ok(());
    }
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
mod padding;
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

/// Only an expected shortfall after pruning may return to refill. Other
/// preparation failures indicate a bad configuration, exhausted permanent
/// reservations, or an invariant violation and must not blindly retry.
#[derive(Default)]
struct PreparationRetry {
    head: Option<Hash>,
    attempts: u8,
    required_padding: usize,
}
impl PreparationRetry {
    fn defer(&mut self, head: Hash, error: PrepareBlockError) -> bool {
        const MAX_RETRIES_PER_HEAD: u8 = 3;
        let PrepareBlockError::Padding(FillError::Insufficient { required }) = error else {
            return false;
        };
        if self.head != Some(head) {
            self.head = Some(head);
            self.attempts = 0;
        }
        if self.attempts == MAX_RETRIES_PER_HEAD {
            return false;
        }
        self.attempts += 1;
        self.required_padding = required;
        true
    }

    fn required_padding(&self, head: Hash) -> usize {
        if self.head == Some(head) {
            self.required_padding
        } else {
            0
        }
    }

    fn can_prepare(&self, owner: &Driver, minimum_positions: usize) -> bool {
        self.positions_sufficient(
            owner.engine().state().tip(),
            owner.ready_positions(),
            owner.padding_count(),
            minimum_positions,
        )
    }

    fn positions_sufficient(
        &self,
        head: Hash,
        ready_positions: usize,
        padding_count: usize,
        minimum_positions: usize,
    ) -> bool {
        ready_positions >= minimum_positions && padding_count >= self.required_padding(head)
    }
}

fn continuous(
    directory: &Path,
    settings: &MiningSettings,
    shared: &Shared,
    workers: &Arc<rayon::ThreadPool>,
    search_workers: &rayon::ThreadPool,
    round: &p2p::Cancellation,
) -> Result<(), Failure> {
    let _charge = shared
        .budget
        .reserve(256 * 1024 * 1024)
        .map_err(|_| Failure::Budget)?;
    let proof_genesis = {
        let owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
        let encoded = owner
            .engine()
            .genesis()
            .encode()
            .map_err(|_| Failure::ProverInit)?;
        crate::eng2::genesis::Genesis::decode(&encoded).map_err(|_| Failure::ProverInit)?
    };
    let minimum_positions = proof_genesis.slot_rule().minimum();
    let mut prover = None;
    let mut padding = padding::Pipeline::default();
    let mut preparation_retry = PreparationRetry::default();
    #[cfg(feature = "eng2-rehearsal")]
    let ceiling_required = {
        let owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
        crate::eng2::rehearsal::partition::production_ceiling(directory, owner.engine().genesis())
            .map_err(|_| Failure::RehearsalControl)?
            .is_some()
    };
    #[cfg(not(feature = "eng2-rehearsal"))]
    let ceiling_required = false;
    let cancelled = || shared.cancel.is_cancelled() || round.is_cancelled();
    while !cancelled() {
        let below_ceiling = below_rehearsal_ceiling(directory, shared, ceiling_required)
            .map_err(|_| Failure::RehearsalControl)?;
        let (isolated_ready, policy_revision) = {
            let mut owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
            // Every worker borrowing the preceding candidate has returned.
            // Published candidates have already transferred their reservations.
            owner.discard_unpublished_template();
            isolated_permission(shared, &owner, None).map_err(|_| Failure::ProductionControl)?
        };
        let ready = below_ceiling
            && isolated_ready
            && shared.mining_ready().map_err(|_| Failure::Readiness)?;
        let prover = match ready_prover(&mut prover, ready, || {
            NativeProver::for_genesis(&proof_genesis).map(|prover| Arc::new(Mutex::new(prover)))
        })? {
            Some(prover) => prover,
            None => {
                shared
                    .phase(if shared.headers.error().is_some() {
                        "header_relay_unavailable"
                    } else if shared.headers.waiting() {
                        "awaiting_validated_parent_state"
                    } else if below_ceiling && isolated_ready {
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
        padding.maintain(
            shared,
            round,
            prover,
            workers,
            policy_revision,
            padding::RefillStage::WaitingForPositions(&preparation_retry),
        )?;
        {
            let owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
            if cancelled()
                || !owner.activities_allowed()
                || !preparation_retry.can_prepare(&owner, minimum_positions)
                || !isolated_permission(shared, &owner, Some(policy_revision))
                    .map_err(|_| Failure::ProductionControl)?
                    .0
            {
                drop(owner);
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
        }
        if !shared.mining_ready().map_err(|_| Failure::Readiness)? {
            continue;
        }
        shared
            .phase("preparing")
            .map_err(|_| Failure::StatusUpdate)?;
        let assembly_started = Instant::now();
        let (generation, prepared, mut submission) = {
            let mut owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
            if cancelled()
                || !owner.activities_allowed()
                || !preparation_retry.can_prepare(&owner, minimum_positions)
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
            let (operations, issuances) = submission.inputs().unwrap_or_default();
            let prepared = match owner.prepare_private_template(
                minimum_positions,
                timestamp,
                settings,
                operations,
                issuances,
            ) {
                Ok(prepared) => {
                    preparation_retry = PreparationRetry::default();
                    prepared
                }
                Err(error) if preparation_retry.defer(head.id, error) => {
                    submission.fail("preparation_deferred_padding");
                    drop(owner);
                    shared
                        .production
                        .lock()
                        .map_err(|_| Failure::StatusUpdate)?
                        .prepared_deferred(error);
                    shared
                        .phase("waiting_for_padding")
                        .map_err(|_| Failure::StatusUpdate)?;
                    // Do not wait or generate proofs while holding the owner.
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(error) => {
                    shared
                        .production
                        .lock()
                        .map_err(|_| Failure::StatusUpdate)?
                        .last_preparation_failure = Some(error);
                    if matches!(error, PrepareBlockError::Candidate(_)) && submission.is_some() {
                        submission.fail(error.code());
                        continue;
                    }
                    if submission.is_some() {
                        submission.fail(error.code());
                    }
                    return Err(Failure::PrepareBlock(error));
                }
            };
            (owner.template_generation(), prepared, submission)
        };
        {
            let owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
            if cancelled()
                || !isolated_permission(shared, &owner, Some(policy_revision))
                    .map_err(|_| Failure::ProductionControl)?
                    .0
            {
                if submission.is_some() {
                    submission.fail("isolated_production_policy_changed");
                }
                continue;
            }
        }
        let proof_result = {
            // One prover workspace is shared with background refill. Waiting
            // here never retains the canonical owner or a chain-state borrow.
            let prover = prover.lock().map_err(|_| Failure::ProverInit)?;
            prepared.prove(&prover)
        };
        let proved = match proof_result {
            Ok(proved) => proved,
            Err(_) => {
                if submission.is_some() {
                    submission.fail("proving_rejected");
                    continue;
                }
                return Err(Failure::ProveBlock);
            }
        };
        if cancelled() {
            break;
        }
        let (mut work, header_revision) = {
            let owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
            if cancelled()
                || shared.headers.waiting()
                || !owner.activities_allowed()
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
                Ok(work) => (work, shared.headers.canonical_revision()),
                Err(_) => {
                    if submission.is_some() {
                        submission.fail("engine_rejected");
                        continue;
                    }
                    return Err(Failure::WorkPrepare);
                }
            }
        };
        shared
            .block_events
            .template_ready(work.header(), assembly_started.elapsed());
        shared.phase("mining").map_err(|_| Failure::StatusUpdate)?;
        loop {
            padding.maintain(
                shared,
                round,
                prover,
                workers,
                policy_revision,
                padding::RefillStage::NonceSearch,
            )?;
            if cancelled()
                || !shared.mining_ready().map_err(|_| Failure::Readiness)?
                || !below_rehearsal_ceiling(directory, shared, ceiling_required)
                    .map_err(|_| Failure::RehearsalControl)?
            {
                break;
            }
            let current_template = {
                let owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
                !shared.headers.waiting()
                    && owner.activities_allowed()
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
            let (searched, attempts) = work
                .search_parallel(search_workers, || {
                    cancelled()
                        || shared.headers.waiting()
                        || shared.headers.canonical_revision() != header_revision
                })
                .map_err(|_| Failure::WorkSearch)?;
            progress(shared, attempts).map_err(|_| Failure::WorkProgress)?;
            match searched {
                Batch::Pending(next) => work = next,
                Batch::Warming(next) => {
                    work = next;
                    std::thread::sleep(Duration::from_millis(100));
                }
                Batch::Cancelled => {
                    submission.fail(if cancelled() {
                        "production_interrupted"
                    } else {
                        "stale_parent"
                    });
                    break;
                }
                Batch::Exhausted => return Err(Failure::WorkSearch),
                Batch::Found(block) => {
                    if cancelled() {
                        break;
                    }
                    let super::super::producer::ProducedBlock {
                        header,
                        body,
                        reward_secret,
                    } = block;
                    let body = Arc::new(body);
                    // Diagnostics contain the found header's public identity,
                    // not the proof contents. Keep their I/O outside the owner.
                    shared.block_events.produced(&header);
                    shared
                        .phase("committing")
                        .map_err(|_| Failure::StatusUpdate)?;
                    let committed = {
                        let mut owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
                        if cancelled()
                            || shared.headers.waiting()
                            || !isolated_permission(shared, &owner, Some(policy_revision))
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
                            .checkpoint_blocks_chain(&owner)
                            .map_err(|_| Failure::Readiness)?
                        {
                            if submission.is_some() {
                                submission.fail("checkpoint_current_quorum_conflict");
                            }
                            break;
                        }
                        if !owner.activities_allowed()
                            || owner.template_generation() != generation
                            || owner.head().map_err(|_| Failure::CommitHead)?.id != header.parent
                        {
                            if submission.is_some() {
                                submission.fail("stale_parent");
                            }
                            break;
                        }
                        // Mark the reservation before any publication attempt;
                        // an ambiguous failure must not release this candidate.
                        owner.mark_template_published();
                        shared
                            .headers
                            .produced(header.clone(), body.clone())
                            .map_err(|_| Failure::HeaderPublish)?;
                        match owner.accept(&header, &body) {
                            Ok(committed) => committed,
                            Err(_) => {
                                shared
                                    .headers
                                    .rejected(&header)
                                    .map_err(|_| Failure::HeaderPublish)?;
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
                    crate::local::save_reward(directory, &committed.id(), &reward_secret)
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
    search_threads: usize,
    shared: Arc<Shared>,
) -> Result<(), String> {
    let observer_stop = p2p::Cancellation::default();
    std::thread::scope(|scope| {
        // The watchdog cannot borrow the canonical owner or depend on the
        // status writer, so a stalled producer cannot silence its alarm.
        let _observer = std::thread::Builder::new()
            .name("eng2-pow-watchdog".into())
            .spawn_scoped(scope, || watch_rounds(&shared, &observer_stop))
            .map_err(|_| "resident PoW watchdog creation failed")?;
        let _stop = CancelOnDrop(observer_stop.clone());
        supervise(directory, settings, search_threads, &shared).map_err(|failure| {
            if let Ok(mut status) = shared.production.lock() {
                status.fail(failure);
            }
            // Validation and networking do not depend on recoverable mining.
            while !shared.cancel.is_cancelled() {
                std::thread::sleep(Duration::from_millis(100));
            }
            "native_production_failed".into()
        })
    })
}

fn watch_rounds(shared: &Shared, stop: &p2p::Cancellation) {
    while !shared.cancel.is_cancelled() && !stop.is_cancelled() {
        let (new_alarm, stage, code) = match shared.production.lock() {
            Ok(mut status) => {
                let expected = status.pow_expected && status.phase != "rehearsal_paused";
                let last_pow = status.last_pow;
                (
                    status.pow_watchdog.poll(Instant::now(), expected, last_pow),
                    status.phase,
                    status.failure.map(Failure::code),
                )
            }
            Err(_) => return,
        };
        if new_alarm {
            // Unlike the status projection this is emitted even if the main
            // owner is stalled. Only stable operational codes are logged.
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr().lock(),
                "mining_pow_counter_stalled phase={stage} failure={}",
                code.unwrap_or("none")
            );
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn supervise(
    directory: &Path,
    settings: MiningSettings,
    search_threads: usize,
    shared: &Shared,
) -> Result<(), Failure> {
    let workers = Arc::new(
        rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .thread_name(|i| format!("eng2-prover-{i}"))
            .build()
            .map_err(|_| Failure::WorkerPool)?,
    );
    let search_workers = rayon::ThreadPoolBuilder::new()
        .num_threads(search_threads)
        .stack_size(256 * 1024)
        .thread_name(|i| format!("eng2-pow-{i}"))
        .build()
        .map_err(|_| Failure::SearchPool)?;

    while !shared.cancel.is_cancelled() {
        let round = {
            let mut status = shared
                .production
                .lock()
                .map_err(|_| Failure::StatusUpdate)?;
            status.error = None;
            status.pow_watchdog.begin_round()
        };
        let result = workers.install(|| {
            continuous(
                directory,
                &settings,
                shared,
                &workers,
                &search_workers,
                &round,
            )
        });
        // The foreground template/nonce batch is gone, and Pipeline::drop
        // has joined any refill first. Only then release a private reservation.
        shared
            .owner
            .lock()
            .map_err(|_| Failure::OwnerAccess)?
            .discard_unpublished_template();
        if let Err(failure) = result {
            shared
                .production
                .lock()
                .map_err(|_| Failure::StatusUpdate)?
                .fail(failure);
            if !failure.permits_watchdog_retry() {
                shared
                    .production
                    .lock()
                    .map_err(|_| Failure::StatusUpdate)?
                    .pow_watchdog
                    .finish_round();
                return Err(failure);
            }
            // Let the monotonic no-progress threshold and episode dedupe
            // determine whether the failed native round can be restarted.
            while !shared.cancel.is_cancelled() && !round.is_cancelled() {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        let mut status = shared
            .production
            .lock()
            .map_err(|_| Failure::StatusUpdate)?;
        status.pow_watchdog.finish_round();
        if shared.cancel.is_cancelled() {
            return Ok(());
        }
        if !round.is_cancelled() {
            return result;
        }
        status.pow_watchdog.restarted();
    }
    Ok(())
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

#[cfg(test)]
mod preparation_tests {
    use super::*;

    #[test]
    fn only_pruned_stock_shortfalls_can_defer_and_same_head_retries_are_bounded() {
        let mut recovery = PreparationRetry::default();
        for fatal in [
            PrepareBlockError::Activities,
            PrepareBlockError::Store,
            PrepareBlockError::SlotCount,
            PrepareBlockError::Pending,
            PrepareBlockError::Padding(FillError::PrivateTemplateActive),
            PrepareBlockError::Padding(FillError::ReservationsExhausted),
            PrepareBlockError::Padding(FillError::Network),
        ] {
            assert!(!recovery.defer([1; 32], fatal));
        }
        let shortfall = PrepareBlockError::Padding(FillError::Insufficient { required: 4 });
        for _ in 0..3 {
            assert!(recovery.defer([1; 32], shortfall));
        }
        // Another reported position must not substitute for missing padding.
        assert!(!recovery.positions_sufficient([1; 32], 16, 3, 16));
        assert!(recovery.positions_sufficient([1; 32], 17, 4, 16));
        assert!(recovery.positions_sufficient([2; 32], 16, 3, 16));
        assert!(!recovery.defer([1; 32], shortfall));
        assert!(recovery.defer([2; 32], shortfall));
    }
}
