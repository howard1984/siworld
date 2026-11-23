//! One retained padding task. Proof work shares the existing prover workspace.
//! A completed proof returns through the ordinary independent queue verifier.
use super::*;
use crate::pool::Padding;
use std::thread::JoinHandle;

struct Task<T> {
    worker: Option<JoinHandle<T>>,
}
impl<T> Default for Task<T> {
    fn default() -> Self {
        Self { worker: None }
    }
}
impl<T: Send + 'static> Task<T> {
    fn busy(&self) -> bool {
        self.worker.is_some()
    }
    fn start(&mut self, work: impl FnOnce() -> T + Send + 'static) -> Result<(), Failure> {
        if self.busy() {
            return Err(Failure::PaddingProve);
        }
        self.worker = Some(
            std::thread::Builder::new()
                .name("eng2-padding-refill".into())
                .spawn(work)
                .map_err(|_| Failure::PaddingProve)?,
        );
        Ok(())
    }
    fn poll(&mut self) -> Result<Option<T>, Failure> {
        if !self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            return Ok(None);
        }
        self.worker
            .take()
            .expect("finished padding task")
            .join()
            .map(Some)
            .map_err(|_| Failure::PaddingProve)
    }
}
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        // A proof operation has no interruption API. Preserve ownership until
        // it returns; no prover or witness is detached on cancellation/error.
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum RefillStage<'a> {
    WaitingForPositions(&'a PreparationRetry),
    NonceSearch,
}
fn dispatch_refill(
    positions_sufficient: bool,
    refill: impl FnOnce() -> Result<(), Failure>,
) -> Result<(), Failure> {
    if positions_sufficient {
        return Ok(());
    }
    refill()
}

struct Completed {
    generation: u64,
    policy_revision: u64,
    padding: Padding,
}
#[derive(Default)]
pub(super) struct Pipeline {
    task: Task<Result<Completed, Failure>>,
}
impl Pipeline {
    pub(super) fn maintain(
        &mut self,
        shared: &Shared,
        round: &p2p::Cancellation,
        prover: &Arc<Mutex<NativeProver>>,
        workers: &Arc<rayon::ThreadPool>,
        policy_revision: u64,
        stage: RefillStage<'_>,
    ) -> Result<(), Failure> {
        if let Some(completed) = self.task.poll()? {
            let completed = completed?;
            let mut owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
            if !shared.cancel.is_cancelled()
                && !round.is_cancelled()
                && owner.activities_allowed()
                && owner.template_generation() == completed.generation
                && isolated_permission(shared, &owner, Some(completed.policy_revision))
                    .map_err(|_| Failure::ProductionControl)?
                    .0
                && owner
                    .engine()
                    .state()
                    .chain()
                    .snapshot(completed.padding.transaction.record.snapshot)
                    .is_ok()
            {
                owner
                    .insert_padding(completed.padding)
                    .map_err(|_| Failure::PaddingInsert)?;
            }
        }
        if self.task.busy()
            || shared.cancel.is_cancelled()
            || round.is_cancelled()
            || !shared.mining_ready().map_err(|_| Failure::Readiness)?
        {
            return Ok(());
        }
        let mut owner = shared.owner.lock().map_err(|_| Failure::OwnerAccess)?;
        if round.is_cancelled()
            || !owner.activities_allowed()
            || !isolated_permission(shared, &owner, Some(policy_revision))
                .map_err(|_| Failure::ProductionControl)?
                .0
        {
            return Ok(());
        }
        // Polling above always consumes completed output first. Ready stock
        // gives foreground assembly priority over starting any new proof.
        let minimum = owner.engine().genesis().slot_rule().minimum();
        let positions_sufficient = match stage {
            RefillStage::WaitingForPositions(retry) => retry.can_prepare(&owner, minimum),
            RefillStage::NonceSearch => false,
        };
        dispatch_refill(positions_sufficient, || {
            let generation = owner.template_generation();
            let Some(task) = owner
                .prepare_padding()
                .map_err(|_| Failure::PaddingPrepare)?
            else {
                return Ok(());
            };
            let prover = prover.clone();
            let workers = workers.clone();
            self.task.start(move || {
                workers.install(|| {
                    let prover = prover.lock().map_err(|_| Failure::ProverInit)?;
                    Ok(Completed {
                        generation,
                        policy_revision,
                        padding: task.prove(&prover).map_err(|_| Failure::PaddingProve)?,
                    })
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn one_inflight_task_is_drained_and_its_failure_is_not_retried() {
        let (release, wait) = mpsc::sync_channel(1);
        let mut task = Task::default();
        task.start(move || {
            wait.recv_timeout(Duration::from_secs(1)).unwrap();
            Err::<(), _>(Failure::PaddingProve)
        })
        .unwrap();
        assert!(task.poll().unwrap().is_none());
        assert!(task.start(|| Ok(())).is_err());
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let result = loop {
            if let Some(result) = task.poll().unwrap() {
                break result;
            }
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        };
        assert_eq!(result, Err(Failure::PaddingProve));
        assert!(!task.busy());
        assert!(task.poll().unwrap().is_none());
    }

    #[test]
    fn dropping_pipeline_waits_for_its_owned_task() {
        let (finished, done) = mpsc::sync_channel(1);
        let mut task = Task::default();
        task.start(move || finished.send(()).unwrap()).unwrap();
        drop(task);
        done.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn ready_stock_runs_foreground_before_refill_and_nonce_search_restarts_background_work() {
        let prover = Arc::new(Mutex::new(Vec::new()));
        let mut task = Task::default();
        // This closure would start a competing non-preemptible workspace user.
        dispatch_refill(true, || {
            task.start(|| panic!("ready assembly must not dispatch refill"))
        })
        .unwrap();
        assert!(!task.busy());
        prover.try_lock().unwrap().push("assembly");
        let (entered, receive) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        let background = prover.clone();
        dispatch_refill(false, || {
            task.start(move || {
                let mut guard = background.lock().unwrap();
                guard.push("refill");
                entered.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(1)).unwrap();
            })
        })
        .unwrap();
        receive.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(task.busy());
        assert!(prover.try_lock().is_err());
        release.send(()).unwrap();
        drop(task);
        assert_eq!(*prover.lock().unwrap(), vec!["assembly", "refill"]);
        let mut prepared = false;
        dispatch_refill(false, || {
            prepared = true;
            Ok(())
        })
        .unwrap();
        assert!(prepared);
    }
}
