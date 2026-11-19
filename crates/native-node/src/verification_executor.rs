//! Process-wide native decoder admission shared by early and final verification.
//!
//! A speculative task obtains its permit before starting a thread. Final batch
//! batches obtain their complete capacity before entering the existing Rayon
//! pool. No final OS worker or stack is added. Proof parallelism is unchanged.

use std::sync::{Condvar, Mutex};

const WORKERS: usize = 4;
struct Usage {
    active: usize,
    waiting: usize,
}
static USAGE: Mutex<Usage> = Mutex::new(Usage {
    active: 0,
    waiting: 0,
});
static CHANGED: Condvar = Condvar::new();

pub(crate) struct Permit(usize);

impl Drop for Permit {
    fn drop(&mut self) {
        let mut usage = USAGE.lock().unwrap_or_else(|error| error.into_inner());
        usage.active = usage.active.saturating_sub(self.0);
        CHANGED.notify_all();
    }
}

fn acquire_many(count: usize) -> Permit {
    debug_assert!((1..=WORKERS).contains(&count));
    let mut usage = USAGE.lock().unwrap_or_else(|error| error.into_inner());
    usage.waiting += 1;
    // Acquire a whole final batch atomically. Partial reservations by multiple
    // owners must not each hold one permit while waiting for the other three.
    while usage.active + count > WORKERS {
        usage = CHANGED
            .wait(usage)
            .unwrap_or_else(|error| error.into_inner());
    }
    usage.waiting -= 1;
    usage.active += count;
    Permit(count)
}

#[cfg(all(test, feature = "eng2-runtime"))]
pub(crate) fn acquire_all_for_test() -> Permit {
    acquire_many(WORKERS)
}

pub(crate) fn acquire() -> Permit {
    acquire_many(1)
}

#[cfg(any(feature = "eng2-runtime", test))]
pub(crate) fn try_acquire() -> Option<Permit> {
    let mut usage = USAGE.lock().unwrap_or_else(|error| error.into_inner());
    // Final verification has priority over another speculative envelope. The
    // already-running jobs finish normally; their original deadlines remain.
    if usage.active >= WORKERS || usage.waiting != 0 {
        return None;
    }
    usage.active += 1;
    Some(Permit(1))
}

/// Obtain the complete batch outside Rayon before dispatching to its existing
/// pool. No pool worker blocks on a permit needed by a proof using that pool.
/// Final verification creates no additional OS thread or thread-stack memory.
pub(crate) fn map<T: Sync, R: Send>(values: &[T], operation: &(impl Fn(&T) -> R + Sync)) -> Vec<R> {
    use rayon::prelude::*;
    let mut results = Vec::with_capacity(values.len());
    for batch in values.chunks(WORKERS) {
        let permit = acquire_many(batch.len());
        results.extend(batch.par_iter().map(operation).collect::<Vec<_>>());
        drop(permit);
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn concurrent_final_batches_and_speculative_jobs_never_exceed_four_decoders() {
        let _serial = TEST_SERIAL.lock().unwrap();
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..6 {
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                scope.spawn(move || {
                    map(&[0, 1, 2, 3], &|_| {
                        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(2));
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                });
            }
            for _ in 0..16 {
                if let Some(permit) = try_acquire() {
                    let active = Arc::clone(&active);
                    let peak = Arc::clone(&peak);
                    // The speculative path acquires before creating its worker.
                    scope.spawn(move || {
                        let _permit = permit;
                        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(2));
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            }
        });
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!((1..=WORKERS).contains(&peak.load(Ordering::SeqCst)));
    }

    #[test]
    fn two_final_batches_with_nested_rayon_complete_after_speculative_capacity_is_released() {
        let _serial = TEST_SERIAL.lock().unwrap();
        use std::{
            sync::mpsc,
            time::{Duration, Instant},
        };
        let speculative = acquire();
        let (sender, receiver) = mpsc::channel();
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let sender = sender.clone();
                scope.spawn(move || {
                    let results = map(&[0, 1, 2, 3], &|_| {
                        let (left, right) = rayon::join(|| 7, || 11);
                        left + right
                    });
                    sender.send(results).unwrap();
                });
            }
            let until = Instant::now() + Duration::from_secs(5);
            while USAGE.lock().unwrap().waiting == 0 {
                assert!(
                    Instant::now() < until,
                    "final batch did not request shared capacity"
                );
                std::thread::yield_now();
            }
            assert!(
                try_acquire().is_none(),
                "new speculative work starved a waiting final batch"
            );
            // An in-flight proof can still use the existing Rayon pool while
            // both final batch callers wait outside that pool.
            assert_eq!(rayon::join(|| 3, || 5), (3, 5));
            drop(speculative);
            for _ in 0..2 {
                assert_eq!(
                    receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
                    vec![18; 4]
                );
            }
        });
    }

    // No timing or thread-order assumption: all four permits remain held until
    // the explicit backpressure and release checks have completed.
    #[test]
    fn a_fifth_speculative_or_final_decoder_is_deferred_before_thread_creation() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let held = acquire_many(WORKERS);
        assert!(try_acquire().is_none());
        drop(held);
        let _released = acquire();
    }
}
