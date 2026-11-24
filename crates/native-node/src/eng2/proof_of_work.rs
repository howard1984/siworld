//! Genesis-selected header proof of work, separate from the block identifier.

use super::header::Header;
use crate::wire::Hash;
use siworld_core::pow::{self, Algorithm};

/// Bounds the consensus key lookback for a direct successor. Snapshot selectors
/// belong to the same parent state, including after an authenticated restart.
pub(super) fn epoch_from_state(
    genesis: Hash,
    candidate_height: u64,
    state: &crate::state::State,
) -> Option<Hash> {
    if state.height.checked_add(1) != Some(candidate_height) {
        return None;
    }
    pow::randomx_epoch_key(genesis, candidate_height, |height| {
        let first = state.snapshots.front()?.selector.height;
        let index = usize::try_from(height.checked_sub(first)?).ok()?;
        let selector = &state.snapshots.get(index)?.selector;
        (selector.height == height).then_some(selector.block_id)
    })
}

pub(super) fn verify(
    algorithm: Algorithm,
    iterations: u64,
    header: &Header,
    epoch: impl FnOnce() -> Option<Hash>,
) -> Result<bool, &'static str> {
    let seed = header
        .pow_seed()
        .map_err(|_| "header work input rejected")?;
    let digest = match algorithm {
        Algorithm::SequentialBlake3 => pow::pow_hash(&seed, header.nonce, iterations),
        Algorithm::SiworldRandomX => light_hash(
            epoch().ok_or("RandomX key ancestor unavailable")?,
            seed,
            header.nonce,
        )?,
    };
    Ok(pow::meets_target(&digest, &header.target))
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(
        target_os = "linux",
        target_os = "macos",
        all(target_os = "windows", target_env = "msvc")
    )
))]
pub(super) mod native {
    use super::Hash;
    pub(super) use siworld_randomx_pow::{Cache, Implementation};
    use std::{collections::VecDeque, sync::Mutex};

    // At most two initialized light caches per process (roughly 512 MiB).
    // Keep construction and hashing serialized; a concurrent miss cannot
    // retain an evicted cache or allocate a third cache while a VM uses it.
    const MAX_LIGHT_CACHES: usize = 2;
    static LIGHT: Mutex<VecDeque<(Hash, Cache)>> = Mutex::new(VecDeque::new());

    pub(super) fn light_hash(key: Hash, seed: Hash, nonce: u64) -> Result<Hash, &'static str> {
        let mut entries = LIGHT.lock().map_err(|_| "RandomX light cache poisoned")?;
        let entry = if let Some(position) = entries.iter().position(|(cached, _)| *cached == key) {
            entries
                .remove(position)
                .ok_or("RandomX light cache entry missing")?
        } else {
            if entries.len() >= MAX_LIGHT_CACHES {
                entries.pop_front();
            }
            (key, Cache::new(&key, Implementation::Hardware)?)
        };
        entries.push_back(entry);
        let mut vm = entries
            .back()
            .ok_or("RandomX light cache unavailable")?
            .1
            .vm()?;
        Ok(vm.hash_header(seed, nonce))
    }
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(
        target_os = "linux",
        target_os = "macos",
        all(target_os = "windows", target_env = "msvc")
    )
))]
use native::light_hash;

#[cfg(not(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(
        target_os = "linux",
        target_os = "macos",
        all(target_os = "windows", target_env = "msvc")
    )
)))]
fn light_hash(_: Hash, _: Hash, _: u64) -> Result<Hash, &'static str> {
    Err("RandomX verification unavailable on this target")
}

#[derive(Clone, Copy)]
pub(super) struct MiningKeys {
    current: Hash,
    upcoming: Option<Hash>,
}

impl MiningKeys {
    pub(super) fn for_template(
        genesis: Hash,
        header: &Header,
        parent: &crate::state::State,
    ) -> Result<Self, String> {
        if header.parent != parent.tip {
            return Err("RandomX template parent changed".into());
        }
        let current = epoch_from_state(genesis, header.height, parent)
            .ok_or("RandomX template key ancestor unavailable")?;
        let boundary = parent.height / pow::RANDOMX_KEY_INTERVAL * pow::RANDOMX_KEY_INTERVAL;
        let upcoming = if boundary > pow::randomx_key_height(header.height) {
            let first = parent
                .snapshots
                .front()
                .ok_or("RandomX snapshots unavailable")?
                .selector
                .height;
            let index = usize::try_from(
                boundary
                    .checked_sub(first)
                    .ok_or("RandomX upcoming key too old")?,
            )
            .map_err(|_| "RandomX upcoming key index unavailable")?;
            let selector = parent
                .snapshots
                .get(index)
                .ok_or("RandomX upcoming key missing")?
                .selector;
            if selector.height != boundary {
                return Err("RandomX upcoming key height differs".into());
            }
            let activation = boundary
                .checked_add(pow::RANDOMX_KEY_DELAY)
                .ok_or("RandomX key activation height overflow")?;
            Some(
                pow::randomx_epoch_key(genesis, activation, |_| Some(selector.block_id))
                    .ok_or("RandomX upcoming key invalid")?,
            )
        } else {
            None
        };
        Ok(Self { current, upcoming })
    }
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(
        target_os = "linux",
        target_os = "macos",
        all(target_os = "windows", target_env = "msvc")
    )
))]
mod fast {
    use super::{Hash, MiningKeys};
    pub(super) use siworld_randomx_pow::Dataset;
    use siworld_randomx_pow::{Cache, Implementation};
    use std::{
        panic::{self, UnwindSafe},
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };

    const RETRY_DELAY: Duration = Duration::from_secs(30);
    const MAX_DATASETS: usize = 2;
    type Result<T> = std::result::Result<T, &'static str>;

    enum State<T> {
        Building { job: Arc<Hash>, discard: bool },
        Ready(Arc<T>),
        Failed(Instant),
    }

    struct DatasetCache<T> {
        entries: Vec<(Hash, State<T>)>,
    }

    impl<T> DatasetCache<T> {
        const fn new() -> Self {
            Self {
                entries: Vec::new(),
            }
        }

        fn complete(&mut self, job: &Arc<Hash>, result: Result<T>, now: Instant) {
            let Some(index) = self.entries.iter().position(|(_, state)| {
                matches!(state, State::Building { job: active, .. } if Arc::ptr_eq(active, job))
            }) else {
                return;
            };
            if matches!(self.entries[index].1, State::Building { discard: true, .. }) {
                self.entries.swap_remove(index);
            } else {
                self.entries[index].1 = match result {
                    Ok(dataset) => State::Ready(Arc::new(dataset)),
                    Err(_) => State::Failed(now),
                };
            }
        }

        fn schedule(
            &mut self,
            key: Hash,
            workers: usize,
            now: Instant,
            spawn: impl FnOnce(Arc<Hash>, usize) -> Result<()>,
        ) -> Result<()> {
            if self.entries.len() >= MAX_DATASETS || self.entries.iter().any(|(k, _)| *k == key) {
                return Ok(());
            }
            let job = Arc::new(key);
            self.entries.push((
                key,
                State::Building {
                    job: job.clone(),
                    discard: false,
                },
            ));
            if let Err(error) = spawn(job.clone(), workers) {
                self.complete(&job, Err(error), now);
                return Err(error);
            }
            Ok(())
        }

        fn get(
            &mut self,
            keys: MiningKeys,
            workers: usize,
            now: Instant,
            mut spawn: impl FnMut(Arc<Hash>, usize) -> Result<()>,
        ) -> (Option<Arc<T>>, Option<&'static str>) {
            self.entries.retain_mut(|(key, state)| {
                let wanted = *key == keys.current || Some(*key) == keys.upcoming;
                match state {
                    // Detached fills are not interruptible. Keep their
                    // physical slot charged, but never publish a stale result.
                    State::Building { discard, .. } => {
                        *discard |= !wanted;
                        true
                    }
                    State::Ready(dataset) => wanted || Arc::strong_count(dataset) != 1,
                    State::Failed(when) => {
                        wanted && now.saturating_duration_since(*when) < RETRY_DELAY
                    }
                }
            });
            let workers = workers.clamp(1, 4);
            if let Err(error) = self.schedule(keys.current, workers, now, &mut spawn) {
                return (None, Some(error));
            }
            let Some(dataset) = self.entries.iter().find_map(|(key, state)| match state {
                State::Ready(dataset) if *key == keys.current => Some(dataset.clone()),
                _ => None,
            }) else {
                // A failed current fill still counts as warming during the
                // retry delay, so it does not terminate the producer round.
                return (None, None);
            };
            let error = keys.upcoming.and_then(|next| {
                // Never stop current-key mining because prewarm failed.
                self.schedule(next, 1, now, spawn).err()
            });
            (Some(dataset), error)
        }
    }

    static DATASETS: Mutex<DatasetCache<Dataset>> = Mutex::new(DatasetCache::new());

    fn build<T>(initialize: impl FnOnce() -> Result<T> + UnwindSafe) -> Result<T> {
        panic::catch_unwind(initialize).unwrap_or(Err("RandomX dataset builder panicked"))
    }

    fn report(error: &'static str) {
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr().lock(),
            "randomx_dataset_build_failed: {error}"
        );
    }

    fn spawn(job: Arc<Hash>, workers: usize) -> Result<()> {
        thread::Builder::new()
            .name("randomx-dataset".into())
            .spawn(move || {
                let result = build(|| {
                    Cache::new(&*job, Implementation::Hardware)
                        .and_then(|cache| Dataset::new(&cache, workers))
                });
                let error = result.as_ref().err().copied();
                if let Ok(mut cache) = DATASETS.lock() {
                    cache.complete(&job, result, Instant::now());
                }
                if let Some(error) = error {
                    report(error);
                }
            })
            .map(|_| ())
            .map_err(|_| "RandomX dataset builder thread unavailable")
    }

    pub(super) fn get(keys: MiningKeys, workers: usize) -> Result<Option<Arc<Dataset>>> {
        let (dataset, error) = DATASETS
            .lock()
            .map_err(|_| "RandomX dataset cache poisoned")?
            .get(keys, workers, Instant::now(), spawn);
        if let Some(error) = error {
            report(error);
        }
        Ok(dataset)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn key(byte: u8) -> Hash {
            [byte; 32]
        }

        fn keys(current: u8, upcoming: Option<u8>) -> MiningKeys {
            MiningKeys {
                current: key(current),
                upcoming: upcoming.map(key),
            }
        }

        #[test]
        fn optional_prewarm_spawn_failure_keeps_current_ready_and_retries_after_backoff() {
            let now = Instant::now();
            let mut cache = DatasetCache::new();
            let mut first = None;
            assert_eq!(
                cache.get(keys(1, None), 8, now, |job, workers| {
                    assert_eq!(workers, 4);
                    first = Some(job);
                    Ok(())
                }),
                (None, None)
            );
            cache.complete(&first.unwrap(), Ok(1), now);
            assert_eq!(
                cache.get(keys(1, Some(2)), 8, now, |job, workers| {
                    assert_eq!((*job, workers), (key(2), 1));
                    Err("fixture spawn failure")
                }),
                (Some(Arc::new(1)), Some("fixture spawn failure"))
            );
            assert_eq!(
                cache.get(
                    keys(1, Some(2)),
                    8,
                    now + Duration::from_secs(29),
                    |_, _| { panic!("optional build retried before backoff") }
                ),
                (Some(Arc::new(1)), None)
            );
            let mut next = None;
            assert_eq!(
                cache.get(keys(1, Some(2)), 8, now + RETRY_DELAY, |job, workers| {
                    assert_eq!((*job, workers), (key(2), 1));
                    next = Some(job);
                    Ok(())
                }),
                (Some(Arc::new(1)), None)
            );
            cache.complete(&next.unwrap(), Ok(2), now + RETRY_DELAY);
            assert_eq!(
                cache.get(keys(2, None), 8, now + RETRY_DELAY, |_, _| panic!()),
                (Some(Arc::new(2)), None)
            );
        }

        #[test]
        fn abandoned_builds_keep_their_slots_until_exit_and_cannot_publish() {
            let now = Instant::now();
            let mut cache = DatasetCache::new();
            let mut jobs = Vec::new();
            for current in 1..=4 {
                assert_eq!(
                    cache.get(keys(current, None), 4, now, |job, _| {
                        jobs.push(job);
                        Ok(())
                    }),
                    (None, None)
                );
            }
            assert_eq!(jobs.len(), MAX_DATASETS);
            assert_eq!(cache.entries.len(), MAX_DATASETS);
            // The original key is wanted again. Its already abandoned job
            // remains charged but cannot publish even in this case.
            assert_eq!(
                cache.get(keys(1, None), 4, now, |_, _| panic!()),
                (None, None)
            );
            cache.complete(&jobs[0], Ok(100), now);
            let mut fresh = None;
            assert_eq!(
                cache.get(keys(1, None), 4, now, |job, _| {
                    fresh = Some(job);
                    Ok(())
                }),
                (None, None)
            );
            assert_eq!(cache.entries.len(), MAX_DATASETS);
            // A duplicate completion for the same key cannot steal the slot.
            cache.complete(&jobs[0], Ok(101), now);
            assert_eq!(
                cache.get(keys(1, None), 4, now, |_, _| panic!()),
                (None, None)
            );
            cache.complete(&jobs[1], Ok(200), now);
            cache.complete(&fresh.unwrap(), Ok(1), now);
            assert_eq!(
                cache.get(keys(1, None), 4, now, |_, _| panic!()),
                (Some(Arc::new(1)), None)
            );
            assert_eq!(cache.entries.len(), 1);
        }

        #[test]
        fn borrowed_stale_dataset_keeps_its_slot_until_search_releases_it() {
            let now = Instant::now();
            let mut cache = DatasetCache::new();
            let mut jobs = Vec::new();
            cache.get(keys(1, None), 4, now, |job, _| {
                jobs.push(job);
                Ok(())
            });
            cache.complete(&jobs[0], Ok(1), now);
            let (in_use, _) = cache.get(keys(1, Some(2)), 4, now, |job, _| {
                jobs.push(job);
                Ok(())
            });
            assert!(in_use.is_some());
            assert_eq!(
                cache.get(keys(3, None), 4, now, |_, _| panic!()),
                (None, None)
            );
            drop(in_use);
            assert_eq!(
                cache.get(keys(3, None), 4, now, |job, _| {
                    assert_eq!(*job, key(3));
                    Ok(())
                }),
                (None, None)
            );
            assert_eq!(cache.entries.len(), MAX_DATASETS);
        }

        #[test]
        fn panicking_and_failing_current_builds_retry_without_ending_search() {
            let now = Instant::now();
            let mut cache = DatasetCache::new();
            for (period, result) in [
                build(|| panic!("fixture initialization panic")),
                build(|| Err("fixture allocation failure")),
                build(|| Ok(1)),
            ]
            .into_iter()
            .enumerate()
            {
                let at = now + RETRY_DELAY * period as u32;
                let mut build_job = None;
                assert_eq!(
                    cache.get(keys(1, None), 4, at, |job, _| {
                        build_job = Some(job);
                        Ok(())
                    }),
                    (None, None)
                );
                let expected = result.as_ref().ok().copied().map(Arc::new);
                cache.complete(&build_job.unwrap(), result, at);
                assert_eq!(
                    cache.get(keys(1, None), 4, at + Duration::from_secs(29), |_, _| {
                        panic!("current build retried before backoff")
                    }),
                    (expected, None)
                );
            }
        }
    }
}

#[cfg(not(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(
        target_os = "linux",
        target_os = "macos",
        all(target_os = "windows", target_env = "msvc")
    )
)))]
mod fast {
    use super::{Hash, MiningKeys};
    use std::sync::Arc;
    pub(super) struct Dataset;
    pub(super) struct Vm;
    impl Dataset {
        pub(super) fn vm(&self) -> Result<Vm, &'static str> {
            Err("RandomX fast mode unavailable on this target")
        }
    }
    impl Vm {
        pub(super) fn hash_header(&mut self, _: Hash, _: u64) -> Hash {
            unreachable!("unsupported VM cannot be constructed")
        }
    }
    pub(super) fn get(_: MiningKeys, _: usize) -> Result<Option<Arc<Dataset>>, &'static str> {
        Err("RandomX fast mode unavailable on this target")
    }
}

pub(super) fn fast_dataset(
    keys: MiningKeys,
    workers: usize,
) -> Result<Option<std::sync::Arc<fast::Dataset>>, &'static str> {
    fast::get(keys, workers)
}
