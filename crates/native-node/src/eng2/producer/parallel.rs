//! Resident nonce work. Every lane owns one disjoint range in a bounded batch.
use super::*;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) enum Batch {
    Found(ProducedBlock),
    Pending(Work),
    Warming(Work),
    Cancelled,
    Exhausted,
}

const ATTEMPTS_PER_WORKER: u64 = 256;

fn scan<Hasher: FnMut(u64) -> bool>(
    workers: &rayon::ThreadPool,
    first: u64,
    attempts_per_worker: u64,
    cancelled: impl Fn() -> bool + Sync,
    make_hasher: impl Fn() -> Result<Hasher, &'static str> + Sync,
) -> Result<(u64, Option<u64>), &'static str> {
    let won = AtomicBool::new(false);
    workers.install(|| {
        (0..workers.current_num_threads())
            .into_par_iter()
            .map(|lane| {
                let mut matches = make_hasher()?;
                let mut attempts = 0;
                let start = lane as u128 * u128::from(attempts_per_worker) + u128::from(first);
                for offset in 0..attempts_per_worker {
                    let Ok(nonce) = u64::try_from(start + u128::from(offset)) else {
                        break;
                    };
                    if won.load(Ordering::Relaxed) || cancelled() {
                        break;
                    }
                    attempts += 1;
                    if matches(nonce)
                        && won
                            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                            .is_ok()
                    {
                        return Ok((attempts, Some(nonce)));
                    }
                }
                Ok((attempts, None))
            })
            .try_reduce(
                || (0, None),
                |(a, first), (b, second)| Ok((a + b, first.or(second))),
            )
    })
}

impl Work {
    pub(crate) fn search_parallel(
        mut self,
        workers: &rayon::ThreadPool,
        cancelled: impl Fn() -> bool + Sync,
    ) -> Result<(Batch, u64), String> {
        let seed = self
            .header
            .pow_seed()
            .map_err(|_| "invalid production header")?;
        // Rayon's jobs borrow only the header-derived constant inputs. There
        // is exactly one body, one reward receipt, and one owner of admission.
        let dataset = if let Some(keys) = self.randomx {
            let Some(dataset) =
                super::super::proof_of_work::fast_dataset(keys, workers.current_num_threads())?
            else {
                return Ok((Batch::Warming(self), 0));
            };
            Some(dataset)
        } else {
            None
        };
        let (attempts, found) = scan(
            workers,
            self.header.nonce,
            ATTEMPTS_PER_WORKER,
            &cancelled,
            || {
                let mut vm = dataset.as_ref().map(|dataset| dataset.vm()).transpose()?;
                Ok(move |nonce| {
                    let digest = if let Some(vm) = &mut vm {
                        vm.hash_header(seed, nonce)
                    } else {
                        siworld_core::pow::pow_hash(&seed, nonce, self.pow_iterations)
                    };
                    siworld_core::pow::meets_target(&digest, &self.header.target)
                })
            },
        )?;
        // A cancelled template is never resumed: some ranges may be partial.
        // This also discards a winner that raced a higher-work header.
        let batch_size = ATTEMPTS_PER_WORKER * workers.current_num_threads() as u64;
        let remaining = u128::from(u64::MAX) - u128::from(self.header.nonce) + 1;
        let expected = remaining.min(u128::from(batch_size)) as u64;
        let batch = if cancelled() || (found.is_none() && attempts != expected) {
            Batch::Cancelled
        } else if let Some(nonce) = found {
            self.header.nonce = nonce;
            Batch::Found(ProducedBlock {
                header: self.header,
                body: self.body,
                reward_secret: self.reward_secret,
            })
        } else if let Some(next) = self.header.nonce.checked_add(attempts) {
            self.header.nonce = next;
            Batch::Pending(self)
        } else {
            Batch::Exhausted
        };
        Ok((batch, attempts))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    use super::*;

    fn pool(workers: usize) -> rayon::ThreadPool {
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .unwrap()
    }

    #[test]
    fn native_parallel_search_returns_one_valid_winner_and_leaves_the_body_unchanged() {
        let test_work = || Work {
            header: Header {
                network: [1; 32],
                height: 1,
                parent: [2; 32],
                timestamp: 1,
                target: [255; 32],
                execution_commitment: [3; 32],
                body_commitment: [4; 32],
                nonce: 17,
            },
            body: crate::eng2::body::tests::body(),
            pow_iterations: 0,
            randomx: None,
            reward_secret: Zeroizing::new(Vec::new()),
        };
        let initial_work = test_work();
        let seed = initial_work.header.pow_seed().unwrap();
        let proof = initial_work.body.transactions[0].proof.clone();
        let workers = pool(3);
        let (cancelled, attempts) = test_work().search_parallel(&workers, || true).unwrap();
        assert!(matches!(cancelled, Batch::Cancelled));
        assert_eq!(attempts, 0);
        let (found, attempts) = initial_work.search_parallel(&workers, || false).unwrap();
        let Batch::Found(found) = found else {
            panic!("bounded lowest-difficulty fixture did not produce a result");
        };
        assert!((1..=3 * ATTEMPTS_PER_WORKER).contains(&attempts));
        assert_eq!(found.header.pow_seed().unwrap(), seed);
        assert!(siworld_core::pow::meets_target(
            &siworld_core::pow::pow_hash(&seed, found.header.nonce, 0),
            &found.header.target,
        ));
        assert_eq!(found.body.transactions[0].proof, proof);
    }

    #[test]
    fn all_lanes_are_disjoint_and_exactly_accounted() {
        let workers = pool(4);
        let seen = Mutex::new(BTreeSet::new());
        assert_eq!(
            scan(
                &workers,
                7,
                16,
                || false,
                || Ok(|nonce| {
                    assert!(seen.lock().unwrap().insert(nonce));
                    false
                })
            )
            .unwrap(),
            (64, None)
        );
        assert_eq!(seen.into_inner().unwrap(), (7..71).collect());
    }

    #[test]
    fn cancellation_performs_no_hash_and_the_final_nonce_does_not_wrap() {
        let workers = pool(3);
        assert_eq!(
            scan(&workers, 5, 4, || true, || Ok(|_| panic!("cancelled hash"))).unwrap(),
            (0, None)
        );
        let seen = Mutex::new(BTreeSet::new());
        assert_eq!(
            scan(
                &workers,
                u64::MAX - 3,
                2,
                || false,
                || Ok(|nonce| {
                    assert!(seen.lock().unwrap().insert(nonce));
                    false
                })
            )
            .unwrap(),
            (4, None)
        );
        assert_eq!(
            seen.into_inner().unwrap(),
            (u64::MAX - 3..=u64::MAX).collect()
        );
    }

    #[test]
    fn at_most_one_winner_and_the_counter_includes_in_flight_work() {
        let workers = pool(4);
        let seen = Mutex::new(BTreeSet::new());
        let (attempts, winner) = scan(
            &workers,
            100,
            4,
            || false,
            || {
                Ok(|nonce| {
                    assert!(seen.lock().unwrap().insert(nonce));
                    true
                })
            },
        )
        .unwrap();
        let seen = seen.into_inner().unwrap();
        assert_eq!(attempts, seen.len() as u64);
        assert!(seen.contains(&winner.unwrap()));
        assert!((1..=4).contains(&attempts));
    }
}
