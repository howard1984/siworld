//! Sequential BLAKE3 proof of work, ASERT difficulty and the timestamp rule.
//!
//! Adapted from midstate v5.0.0 (https://github.com/ciphernom/midstate,
//! `core/extension.rs` and `core/state.rs`), Copyright (C) the midstate
//! authors, licensed under GPL-3.0. Changes: the work is seeded by the header
//! instead of a state midstate; ASERT runs in 512-bit arithmetic with the same
//! results; the future-time limit is a relay policy instead of a validity rule.

use primitive_types::U512;
use siworld_core::params::ChainParams;
use siworld_core::{Digest, Header, Height};
use siworld_state::ChainState;

use crate::transition::BlockError;

/// The work for one nonce: `x = BLAKE3(seed ‖ nonce)`, then `iterations` more
/// sequential BLAKE3 hashes of `x`.
pub fn pow_hash(seed: &Digest, nonce: u64, iterations: u64) -> [u8; 32] {
    siworld_core::pow::pow_hash(seed.as_bytes(), nonce, iterations)
}

/// True when the work, read big-endian, is below the target.
pub fn meets_target(work: &[u8; 32], target: &[u8; 32]) -> bool {
    siworld_core::pow::meets_target(work, target)
}

/// ASERT: the target of the block after one at `parent_height` and
/// `parent_timestamp`, anchored at genesis.
pub fn asert_target(
    params: &ChainParams,
    parent_height: Height,
    parent_timestamp: u64,
) -> [u8; 32] {
    siworld_core::pow::asert_target(
        &params.genesis_target,
        params.genesis_timestamp,
        params.target_block_time,
        parent_height,
        parent_timestamp,
    )
}

/// The target the next block's header must carry.
pub fn next_target(state: &ChainState, params: &ChainParams) -> [u8; 32] {
    asert_target(params, state.height, state.timestamp())
}

/// The work a block at `target` adds to its branch: the expected number of
/// nonces tried to meet it, ⌊2^256 / (target + 1)⌋. At most 2^255 (target 1),
/// so a branch's sum fits in 512 bits.
pub fn block_work(target: &[u8; 32]) -> U512 {
    siworld_core::pow::block_work(target)
}

/// Lower bound a new timestamp must exceed: the median of the last
/// MEDIAN_TIME_PAST_WINDOW timestamps, or the tip's while fewer exist.
pub fn median_time_past(state: &ChainState) -> u64 {
    median_of(&state.timestamps)
}

/// `timestamps` are the parent's, oldest first; the last is the parent's own.
fn median_of(timestamps: &[u64]) -> u64 {
    siworld_core::pow::median_time_past(timestamps).expect("genesis records its timestamp")
}

pub fn check_timestamp(state: &ChainState, timestamp: u64) -> Result<(), BlockError> {
    check_timestamp_after(&state.timestamps, timestamp)
}

fn check_timestamp_after(timestamps: &[u64], timestamp: u64) -> Result<(), BlockError> {
    if timestamp > median_of(timestamps) {
        Ok(())
    } else {
        Err(BlockError::BadTimestamp)
    }
}

/// Header checks against the parent state: timestamp, ASERT target, work.
pub fn check_work(
    state: &ChainState,
    params: &ChainParams,
    header: &Header,
) -> Result<(), BlockError> {
    check_work_after(state.height, &state.timestamps, params, header)
}

/// [`check_work`] from only what it reads of the parent: its height and its
/// recent timestamps, oldest first. Lets a node check a side-branch header
/// before rebuilding that branch's state.
pub fn check_work_after(
    parent_height: Height,
    parent_timestamps: &[u64],
    params: &ChainParams,
    header: &Header,
) -> Result<(), BlockError> {
    check_timestamp_after(parent_timestamps, header.timestamp)?;
    let parent_timestamp = *parent_timestamps
        .last()
        .expect("genesis records its timestamp");
    if header.target != asert_target(params, parent_height, parent_timestamp) {
        return Err(BlockError::BadTarget);
    }
    let work = pow_hash(&header.pow_seed(), header.nonce, params.pow_iterations);
    if !meets_target(&work, &header.target) {
        return Err(BlockError::BadPow);
    }
    Ok(())
}

/// Searches nonces upward from the header's nonce until the work meets its
/// target. Returns false only if every remaining nonce fails.
pub fn mine(header: &mut Header, iterations: u64) -> bool {
    loop {
        if let Some(found) = mine_some(header, iterations, u64::MAX) {
            return found;
        }
    }
}

/// [`mine`] for at most `tries` nonces, so a miner can stop when its parent
/// changes. Returns `Some(true)` with the header sealed, `Some(false)` if every
/// remaining nonce fails, or `None` with the header's nonce at the next one
/// to try.
pub fn mine_some(header: &mut Header, iterations: u64, tries: u64) -> Option<bool> {
    let seed = header.pow_seed();
    for _ in 0..tries {
        if meets_target(&pow_hash(&seed, header.nonce, iterations), &header.target) {
            return Some(true);
        }
        match header.nonce.checked_add(1) {
            Some(n) => header.nonce = n,
            None => return Some(false),
        }
    }
    None
}

/// Relay policy, not validity: a block with this timestamp is held until the
/// local clock reaches `timestamp - MAX_FUTURE_BLOCK_TIME`. Validity never
/// reads a clock, so nodes with different clocks agree on every block.
pub fn beyond_future_limit(timestamp: u64, now: u64) -> bool {
    siworld_core::pow::beyond_future_limit(timestamp, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::U256;
    use siworld_core::params::{ASERT_HALF_LIFE, MAX_FUTURE_BLOCK_TIME, MEDIAN_TIME_PAST_WINDOW};

    fn mainnet() -> ChainParams {
        ChainParams {
            genesis_timestamp: 1_700_000_000,
            ..ChainParams::mainnet()
        }
    }

    fn u(t: [u8; 32]) -> U256 {
        U256::from_big_endian(&t)
    }

    /// midstate's `calculate_target`, verbatim apart from parameter passing, as
    /// the reference for [`asert_target`].
    fn midstate_target(p: &ChainParams, height: u64, timestamp: u64) -> [u8; 32] {
        if height == 0 {
            return p.genesis_target;
        }
        let ideal_time = height as i64 * (p.target_block_time as i64);
        let actual_time = (timestamp as i64).saturating_sub(p.genesis_timestamp as i64);
        let drift = actual_time - ideal_time;
        let exponent = drift.saturating_mul(65536) / ASERT_HALF_LIFE;
        let shifts = exponent >> 16;
        let frac = exponent & 0xFFFF;
        let mut factor = 65536i64;
        factor += (frac * 45426) >> 16;
        factor += (frac * frac * 15746) >> 32;
        factor += (frac * frac * frac * 3643) >> 48;
        let mut target = U256::from_big_endian(&p.genesis_target);
        let f = U256::from(factor as u64);
        let base = U256::from(65536u64);
        target = target / base * f + (target % base) * f / base;
        let ceiling = U256::from_big_endian(&[0xff; 32]);
        if shifts > 0 {
            let s = (shifts as usize).min(255);
            let headroom = ceiling >> s;
            target = if target > headroom {
                ceiling
            } else {
                target << s
            };
        } else if shifts < 0 {
            let s = ((-shifts) as usize).min(255);
            target >>= s;
        }
        if target > ceiling {
            target = ceiling
        } else if target.is_zero() {
            target = U256::one()
        }
        target.to_big_endian()
    }

    // ── ASERT (midstate's tests) ──

    #[test]
    fn asert_genesis_target_at_height_zero() {
        let p = mainnet();
        assert_eq!(asert_target(&p, 0, p.genesis_timestamp), p.genesis_target);
        assert_eq!(asert_target(&p, 0, u64::MAX), p.genesis_target);
    }

    #[test]
    fn asert_stable_when_on_schedule() {
        let p = mainnet();
        let t = asert_target(&p, 100, p.genesis_timestamp + 100 * p.target_block_time);
        assert_eq!(t, p.genesis_target);
    }

    #[test]
    fn asert_easier_when_slow_harder_when_fast() {
        let p = mainnet();
        let slow = asert_target(&p, 10, p.genesis_timestamp + 2_000);
        let fast = asert_target(&p, 10, p.genesis_timestamp + 100);
        assert!(u(slow) > u(p.genesis_target));
        assert!(u(fast) < u(p.genesis_target));
    }

    #[test]
    fn asert_halves_after_one_half_life_ahead() {
        let p = mainnet();
        // 240 blocks in no time: drift = −14,400 s, exactly one half-life.
        let t = asert_target(&p, 240, p.genesis_timestamp);
        assert_eq!(u(t), u(p.genesis_target) >> 1);
        // And doubles after one half-life behind.
        let t = asert_target(&p, 1, p.genesis_timestamp + 60 + 14_400);
        assert_eq!(u(t), u(p.genesis_target) << 1);
    }

    #[test]
    fn unset_mainnet_genesis_timestamp_would_open_the_ceiling() {
        // ChainParams::mainnet() leaves the anchor at 0 until launch. Launching
        // with it would put every block decades behind schedule, so from
        // block 2 any hash meets the target.
        let p = ChainParams::mainnet();
        assert_eq!(asert_target(&p, 1, 1_800_000_000), [0xff; 32]);
        let launched = mainnet();
        assert_eq!(
            asert_target(&launched, 1, launched.genesis_timestamp + 60),
            launched.genesis_target
        );
    }

    #[test]
    fn asert_clamps_to_ceiling_and_floor() {
        let p = mainnet();
        assert_eq!(
            asert_target(&p, 1, p.genesis_timestamp + 999_999_999),
            [0xff; 32]
        );
        assert_eq!(asert_target(&p, 1, u64::MAX), [0xff; 32]);
        // A huge negative drift never yields an unreachable zero target.
        let mut one = [0; 32];
        one[31] = 1;
        assert_eq!(asert_target(&p, 10_000_000, p.genesis_timestamp), one);
        assert_eq!(asert_target(&p, u64::MAX, 0), one);
    }

    #[test]
    fn asert_matches_midstate() {
        for p in [mainnet(), ChainParams::devnet()] {
            let g = p.genesis_timestamp;
            for height in [1u64, 2, 10, 239, 240, 241, 1_000, 52_560, 1_000_000] {
                let ideal = g + height * p.target_block_time;
                for ts in [
                    g,
                    g + 1,
                    ideal.saturating_sub(100_000),
                    ideal.saturating_sub(14_400),
                    ideal.saturating_sub(7_777),
                    ideal - 1,
                    ideal,
                    ideal + 1,
                    ideal + 59,
                    ideal + 7_200,
                    ideal + 14_400,
                    ideal + 1_000_000,
                ] {
                    assert_eq!(
                        asert_target(&p, height, ts),
                        midstate_target(&p, height, ts),
                        "height {height} timestamp {ts}"
                    );
                }
            }
        }
    }

    // ── Sequential work ──

    #[test]
    fn work_is_a_hash_chain_over_seed_and_nonce() {
        let seed = Digest([9; 32]);
        let mut first = [0u8; 40];
        first[..32].copy_from_slice(&seed.0);
        first[32..].copy_from_slice(&7u64.to_le_bytes());
        let x0 = *blake3::hash(&first).as_bytes();
        assert_eq!(pow_hash(&seed, 7, 0), x0);
        assert_eq!(pow_hash(&seed, 7, 1), *blake3::hash(&x0).as_bytes());
        let ten = pow_hash(&seed, 7, 10);
        assert_eq!(pow_hash(&seed, 7, 11), *blake3::hash(&ten).as_bytes());
        assert_ne!(pow_hash(&seed, 8, 10), ten);
        assert_ne!(pow_hash(&Digest([8; 32]), 7, 10), ten);
    }

    #[test]
    fn target_comparison_is_big_endian_and_strict() {
        let mut low = [0u8; 32];
        low[31] = 0xff;
        let mut high = [0u8; 32];
        high[0] = 1;
        assert!(meets_target(&low, &high));
        assert!(!meets_target(&high, &low));
        assert!(!meets_target(&high, &high));
        assert!(!meets_target(&[0; 32], &[0; 32]));
    }

    #[test]
    fn mined_header_meets_its_target() {
        let p = ChainParams::devnet();
        let mut h = Header {
            version: 0,
            height: 1,
            parent: Digest::ZERO,
            timestamp: 1,
            target: p.genesis_target,
            nonce: 0,
            state_root: Digest([1; 32]),
            commitment_root: Digest([2; 32]),
            nullifier_root: Digest([3; 32]),
            body_root: Digest([4; 32]),
            container_size: 4,
        };
        assert_eq!(mine_some(&mut h, 1, 4096), Some(true));
        let work = pow_hash(&h.pow_seed(), h.nonce, 1);
        assert!(meets_target(&work, &h.target));
        // Every earlier nonce failed: the search is deterministic.
        for n in 0..h.nonce {
            assert!(!meets_target(&pow_hash(&h.pow_seed(), n, 1), &h.target));
        }
        let mut impossible = h;
        impossible.target = [0; 32];
        impossible.nonce = u64::MAX - 3;
        assert!(!mine(&mut impossible, 1));

        // A search in short runs finds the same nonce.
        let mut parts = h;
        parts.nonce = 0;
        let mut runs = 0;
        let mut found = false;
        for _ in 0..2048 {
            runs += 1;
            if let Some(result) = mine_some(&mut parts, 1, 2) {
                found = result;
                break;
            }
        }
        assert!(found);
        assert_eq!(parts.nonce, h.nonce);
        assert_eq!(runs, h.nonce / 2 + 1);
        impossible.nonce = u64::MAX - 3;
        assert_eq!(mine_some(&mut impossible, 1, 2), None);
        assert_eq!(impossible.nonce, u64::MAX - 1);
        assert_eq!(mine_some(&mut impossible, 1, 5), Some(false));
    }

    // ── Timestamps (midstate's tests) ──

    fn state_with(timestamps: &[u64]) -> ChainState {
        let p = ChainParams::devnet();
        let mut s = ChainState::genesis(&ChainParams {
            genesis_timestamp: timestamps[0],
            ..p
        });
        for &t in &timestamps[1..] {
            s.record_timestamp(t);
        }
        s
    }

    #[test]
    fn timestamp_must_exceed_parent_while_history_is_short() {
        let s = state_with(&[100, 200, 150]);
        assert_eq!(median_time_past(&s), 150);
        assert_eq!(check_timestamp(&s, 150), Err(BlockError::BadTimestamp));
        assert_eq!(check_timestamp(&s, 151), Ok(()));
    }

    #[test]
    fn timestamp_must_exceed_median_of_last_eleven() {
        // Twelve recorded; only the last eleven count: 20..=120, median 70.
        let ts: Vec<u64> = (0..12)
            .map(|i| [1_000, 30, 120, 20, 110, 40, 100, 50, 90, 60, 80, 70][i])
            .collect();
        let s = state_with(&ts);
        assert_eq!(s.timestamps.len(), MEDIAN_TIME_PAST_WINDOW);
        assert_eq!(median_time_past(&s), 70);
        assert_eq!(check_timestamp(&s, 70), Err(BlockError::BadTimestamp));
        // Earlier than the tip is fine once above the median.
        assert_eq!(check_timestamp(&s, 71), Ok(()));
    }

    #[test]
    fn future_limit_is_fifteen_minutes() {
        let now = 1_000_000;
        assert!(!beyond_future_limit(now + 14 * 60, now));
        assert!(!beyond_future_limit(now + MAX_FUTURE_BLOCK_TIME, now));
        assert!(beyond_future_limit(now + MAX_FUTURE_BLOCK_TIME + 1, now));
        assert!(!beyond_future_limit(0, now));
        assert!(beyond_future_limit(
            u64::MAX,
            u64::MAX - MAX_FUTURE_BLOCK_TIME - 1
        ));
        assert!(!beyond_future_limit(u64::MAX, u64::MAX));
    }
}
