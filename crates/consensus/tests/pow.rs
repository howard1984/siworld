//! Block-level PoW rules: the header's target, its work, and its timestamp.

mod common;

use common::*;
use siworld_circuits::MockProver;
use siworld_consensus::{build_block, meets_target, next_target, pow_hash, BlockError, BuildError};
use siworld_core::params::{ChainParams, MEDIAN_TIME_PAST_WINDOW};
use siworld_core::{Block, Digest};
use siworld_state::ChainState;

// Rejection tests need both accepted and rejected work at minimum hash cost.
fn params() -> ChainParams {
    let mut target = [0xff; 32];
    target[0] = 0x7f;
    ChainParams {
        pow_iterations: 2,
        genesis_target: target,
        ..common::params()
    }
}

fn snapshot(state: &ChainState) -> (siworld_core::Roots, Digest, u64, Vec<u64>) {
    (
        state.roots(),
        state.tip,
        state.height,
        state.timestamps.clone(),
    )
}

fn block_at(
    state: &ChainState,
    p: &ChainParams,
    timestamp: u64,
    tag: u64,
) -> Result<Block, BuildError> {
    build_block(
        state,
        &state.anchors,
        p,
        &MockProver,
        &miner(),
        &[],
        &[],
        &block_seed(tag),
        timestamp,
    )
}

#[test]
fn produced_block_carries_the_scheduled_target_and_valid_work() {
    let p = params();
    let (state, _) = genesis(&p, &[]);
    let block = build(&state, &p, &[], 1).unwrap();
    assert_eq!(block.header.target, next_target(&state, &p));
    let work = pow_hash(
        &block.header.pow_seed(),
        block.header.nonce,
        p.pow_iterations,
    );
    assert!(meets_target(&work, &block.header.target));
    chain(&p, state).apply_block(&block).unwrap();
}

#[test]
fn wrong_target_is_rejected_even_with_valid_work_for_it() {
    let p = params();
    let (state, _) = genesis(&p, &[]);
    let mut block = build(&state, &p, &[], 1).unwrap();
    block.header.target = [0xff; 32];
    reseal(&mut block.header, &p);
    let mut node = chain(&p, state);
    let before = snapshot(&node.state);
    assert_eq!(node.apply_block(&block), Err(BlockError::BadTarget));
    assert_eq!(snapshot(&node.state), before);
}

#[test]
fn work_above_target_is_rejected_and_state_is_unchanged() {
    let p = params();
    let (state, _) = genesis(&p, &[]);
    let mut block = build(&state, &p, &[], 1).unwrap();
    let seed = block.header.pow_seed();
    block.header.nonce = (0..4096)
        .find(|&n| !meets_target(&pow_hash(&seed, n, p.pow_iterations), &block.header.target))
        .unwrap();
    let mut node = chain(&p, state);
    let before = snapshot(&node.state);
    assert_eq!(node.apply_block(&block), Err(BlockError::BadPow));
    assert_eq!(snapshot(&node.state), before);
}

#[test]
fn work_is_computed_with_the_chain_iteration_count() {
    // Work found with fewer iterations than the chain uses does not count.
    let p = params();
    let (state, _) = genesis(&p, &[]);
    let mut block = build(&state, &p, &[], 1).unwrap();
    let seed = block.header.pow_seed();
    let cheap = 1;
    block.header.nonce = (0..4096)
        .find(|&n| {
            meets_target(&pow_hash(&seed, n, cheap), &block.header.target)
                && !meets_target(&pow_hash(&seed, n, p.pow_iterations), &block.header.target)
        })
        .unwrap();
    assert_eq!(
        chain(&p, state).apply_block(&block),
        Err(BlockError::BadPow)
    );
}

#[test]
fn timestamp_not_after_parent_is_rejected_by_builder_and_validator() {
    let p = params();
    let (state, _) = genesis(&p, &[]);
    let parent = state.timestamp();
    assert_eq!(
        block_at(&state, &p, parent, 1),
        Err(BuildError::Invalid(BlockError::BadTimestamp))
    );

    let mut block = build(&state, &p, &[], 1).unwrap();
    block.header.timestamp = parent;
    reseal(&mut block.header, &p);
    let mut node = chain(&p, state);
    let before = snapshot(&node.state);
    assert_eq!(node.apply_block(&block), Err(BlockError::BadTimestamp));
    assert_eq!(snapshot(&node.state), before);
}

#[test]
fn timestamp_must_exceed_median_of_last_eleven_blocks() {
    // A tip far ahead of the others does not raise the floor; the median does.
    let p = params();
    let (mut state, _) = genesis(&p, &[]);
    let mut node = chain(&p, state.clone());
    for h in 1..=10u64 {
        let ts = if h == 10 {
            1_000_000
        } else {
            state.timestamp() + 1
        };
        let block = block_at(&state, &p, ts, h).unwrap();
        node.apply_block(&block).unwrap();
        state = node.state.clone();
    }
    assert_eq!(state.timestamps.len(), MEDIAN_TIME_PAST_WINDOW);
    let median = {
        let mut ts = state.timestamps.clone();
        ts.sort_unstable();
        ts[ts.len() / 2]
    };
    assert!(median < state.timestamp());
    assert_eq!(
        block_at(&state, &p, median, 11),
        Err(BuildError::Invalid(BlockError::BadTimestamp))
    );
    // Earlier than the tip but after the median is valid.
    let block = block_at(&state, &p, median + 1, 11).unwrap();
    node.apply_block(&block).unwrap();
}

#[test]
fn applied_blocks_record_at_most_eleven_timestamps() {
    let p = params();
    let (state, _) = genesis(&p, &[]);
    let mut node = chain(&p, state);
    let mut expected = vec![node.state.timestamp()];
    for h in 1..=13u64 {
        let ts = next_timestamp(&node.state, &p);
        let block = block_at(&node.state, &p, ts, h).unwrap();
        node.apply_block(&block).unwrap();
        expected.push(ts);
    }
    let keep = expected.len() - MEDIAN_TIME_PAST_WINDOW;
    assert_eq!(node.state.timestamps, expected[keep..]);
}

#[test]
fn fast_blocks_raise_difficulty_and_slow_blocks_lower_it() {
    let p = ChainParams {
        target_block_time: 60,
        ..params()
    };
    let (state, _) = genesis(&p, &[]);
    let mut node = chain(&p, state);
    let start = next_target(&node.state, &p);

    // Three blocks one second apart against a 60-second schedule.
    let mut prev = start;
    for h in 1..=3u64 {
        let ts = node.state.timestamp() + 1;
        let block = block_at(&node.state, &p, ts, h).unwrap();
        assert_eq!(block.header.target, prev);
        node.apply_block(&block).unwrap();
        let next = next_target(&node.state, &p);
        assert!(next < prev, "target should tighten after a fast block");
        prev = next;
    }

    // One very slow block more than makes up for it.
    let ts = node.state.timestamp() + 10 * 60 * 60;
    let block = block_at(&node.state, &p, ts, 4).unwrap();
    node.apply_block(&block).unwrap();
    assert!(next_target(&node.state, &p) > start);
}
