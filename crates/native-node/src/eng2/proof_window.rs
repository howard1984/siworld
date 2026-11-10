//! Bounded independent proof jobs followed by atomic, ordered state execution.
//!
//! Contexts must be resolved against canonical staged dependencies by the
//! caller. This scheduler never creates proof contexts or skips validation.

use crate::wire::Hash;

pub struct BlockProofs<'a, J> {
    pub block_id: Hash,
    pub jobs: &'a [J],
}

#[derive(Clone, Copy)]
pub struct Policy {
    pub workers: usize,
    pub max_blocks: usize,
    pub max_jobs: usize,
    pub max_proof_bytes: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WindowError {
    Bounds,
    Resources,
    Proof {
        block: usize,
        job: usize,
        reason: String,
    },
    Transition {
        block: usize,
        reason: String,
    },
}

pub struct VerifiedWindow<'a, J> {
    blocks: &'a [BlockProofs<'a, J>],
}

pub fn verify<'a, J: Sync>(
    blocks: &'a [BlockProofs<'a, J>],
    policy: Policy,
    proof_bytes: impl Fn(&J) -> usize,
    verify: impl Fn(&J) -> Result<(), String> + Sync,
) -> Result<VerifiedWindow<'a, J>, WindowError> {
    use rayon::prelude::*;
    if !(1..=64).contains(&policy.workers) || blocks.is_empty() || blocks.len() > policy.max_blocks
    {
        return Err(WindowError::Bounds);
    }
    let mut identities = std::collections::BTreeSet::new();
    let mut count = 0usize;
    let mut bytes = 0usize;
    for block in blocks {
        if block.jobs.is_empty() || !identities.insert(block.block_id) {
            return Err(WindowError::Bounds);
        }
        count = count
            .checked_add(block.jobs.len())
            .ok_or(WindowError::Bounds)?;
        if count > policy.max_jobs {
            return Err(WindowError::Bounds);
        }
        for job in block.jobs {
            bytes = bytes
                .checked_add(proof_bytes(job))
                .ok_or(WindowError::Bounds)?;
            if bytes > policy.max_proof_bytes {
                return Err(WindowError::Bounds);
            }
        }
    }
    let mut jobs = Vec::new();
    jobs.try_reserve_exact(count)
        .map_err(|_| WindowError::Resources)?;
    for (block_index, block) in blocks.iter().enumerate() {
        for (job_index, job) in block.jobs.iter().enumerate() {
            jobs.push((block_index, job_index, job));
        }
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(policy.workers)
        .build()
        .map_err(|_| WindowError::Resources)?;
    let results: Vec<_> = pool.install(|| jobs.par_iter().map(|(_, _, job)| verify(job)).collect());
    // Indexed parallel iteration retains input order, independently of the job
    // completion order. Report the first canonical failure, never the fastest.
    for ((block, job, _), result) in jobs.iter().zip(results) {
        result.map_err(|reason| WindowError::Proof {
            block: *block,
            job: *job,
            reason,
        })?;
    }
    Ok(VerifiedWindow { blocks })
}

impl<J> VerifiedWindow<'_, J> {
    /// Apply only to an independently owned state clone. `S::clone` must not
    /// alias mutable transition data, and `apply` must have no external effects.
    /// A durable caller commits this result through its ordinary transaction.
    pub fn execute_atomic<S: Clone>(
        &self,
        state: &mut S,
        mut apply: impl FnMut(&mut S, &BlockProofs<'_, J>) -> Result<(), String>,
    ) -> Result<(), WindowError> {
        let mut staged = state.clone();
        for (block, input) in self.blocks.iter().enumerate() {
            apply(&mut staged, input)
                .map_err(|reason| WindowError::Transition { block, reason })?;
        }
        *state = staged;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn policy() -> Policy {
        Policy {
            workers: 4,
            max_blocks: 4,
            max_jobs: 16,
            max_proof_bytes: 1024,
        }
    }

    #[test]
    fn independently_verifies_every_job_and_applies_state_in_block_order() {
        let first = [1usize, 2];
        let second = [3usize, 4];
        let blocks = [
            BlockProofs {
                block_id: [1; 32],
                jobs: &first,
            },
            BlockProofs {
                block_id: [2; 32],
                jobs: &second,
            },
        ];
        let checked = AtomicUsize::new(0);
        let verified = verify(
            &blocks,
            policy(),
            |_| 1,
            |_| {
                checked.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(checked.load(Ordering::SeqCst), 4);
        let mut state = Vec::new();
        verified
            .execute_atomic(&mut state, |state, block| {
                state.push(block.block_id[0]);
                Ok(())
            })
            .unwrap();
        assert_eq!(state, vec![1, 2]);
    }

    #[test]
    fn invalid_proof_has_canonical_error_and_cannot_mutate_state() {
        let jobs = [0usize, 1, 2, 3];
        let blocks = [BlockProofs {
            block_id: [1; 32],
            jobs: &jobs,
        }];
        let mut state = vec![9];
        let error = verify(
            &blocks,
            policy(),
            |_| 1,
            |job| {
                if *job >= 1 {
                    Err(format!("invalid {job}"))
                } else {
                    Ok(())
                }
            },
        )
        .err()
        .unwrap();
        assert_eq!(
            error,
            WindowError::Proof {
                block: 0,
                job: 1,
                reason: "invalid 1".into()
            }
        );
        assert_eq!(state, vec![9]);
        let verified = verify(&blocks, policy(), |_| 1, |_| Ok(())).unwrap();
        assert_eq!(
            verified.execute_atomic(&mut state, |s, _| {
                s.push(7);
                Err("transition failed".into())
            }),
            Err(WindowError::Transition {
                block: 0,
                reason: "transition failed".into()
            })
        );
        assert_eq!(state, vec![9]);
    }

    #[test]
    fn later_transition_failure_rolls_back_the_whole_uncommitted_window() {
        let jobs = [0usize];
        let blocks = [
            BlockProofs {
                block_id: [1; 32],
                jobs: &jobs,
            },
            BlockProofs {
                block_id: [2; 32],
                jobs: &jobs,
            },
        ];
        let verified = verify(&blocks, policy(), |_| 1, |_| Ok(())).unwrap();
        let mut state = 0;
        let error = verified.execute_atomic(&mut state, |s, block| {
            *s += 1;
            if block.block_id[0] == 2 {
                Err("commitment mismatch".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(
            error,
            Err(WindowError::Transition {
                block: 1,
                reason: "commitment mismatch".into()
            })
        );
        assert_eq!(state, 0);
    }

    #[test]
    fn rejects_all_resource_bounds_before_any_proof_job() {
        let jobs = [0usize, 1];
        let blocks = [BlockProofs {
            block_id: [1; 32],
            jobs: &jobs,
        }];
        let checked = AtomicUsize::new(0);
        for p in [
            Policy {
                workers: 0,
                ..policy()
            },
            Policy {
                workers: 65,
                ..policy()
            },
            Policy {
                max_jobs: 1,
                ..policy()
            },
            Policy {
                max_blocks: 0,
                ..policy()
            },
            Policy {
                max_proof_bytes: 1,
                ..policy()
            },
        ] {
            assert!(matches!(
                verify(
                    &blocks,
                    p,
                    |_| 1,
                    |_| {
                        checked.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                ),
                Err(WindowError::Bounds)
            ));
        }
        assert_eq!(checked.load(Ordering::SeqCst), 0);
        let duplicate = [
            BlockProofs {
                block_id: [1; 32],
                jobs: &jobs,
            },
            BlockProofs {
                block_id: [1; 32],
                jobs: &jobs,
            },
        ];
        assert!(matches!(
            verify(&duplicate, policy(), |_| 1, |_| Ok(())),
            Err(WindowError::Bounds)
        ));
    }
}
