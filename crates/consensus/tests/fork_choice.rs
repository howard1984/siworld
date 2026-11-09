//! Fork choice: a node follows the valid branch with the most cumulative work
//! (whitepaper §5), not the longest one, and switches branches atomically.

mod common;

use common::*;
use siworld_consensus::{
    asert_target, block_work, meets_target, next_target, pow_hash, BlockError, PendingTx, TipChange,
};
use siworld_core::params::{ChainParams, ATOMS_PER_SIP, MAX_REORG_DEPTH};
use siworld_core::{Block, Digest};
use siworld_crypto::SpendKey;
use siworld_state::ChainState;

// Work-comparison fixtures require a wider margin than the default unit target.
fn params() -> ChainParams {
    let mut target = [0xff; 32];
    target[0] = 0x0f;
    ChainParams {
        pow_iterations: 1,
        genesis_target: target,
        ..common::params()
    }
}

const SIP: u64 = ATOMS_PER_SIP;

fn alice() -> SpendKey {
    key(1)
}

fn bob() -> SpendKey {
    key(2)
}

/// One 1 SIP package for alice at genesis.
fn funded() -> (ChainParams, ChainState, Vec<Owned>) {
    let p = params();
    let (state, owned) = genesis(&p, &[(alice(), SIP, 0)]);
    (p, state, owned)
}

fn spend(state: &ChainState, p: &ChainParams, o: &Owned, tag: u64) -> PendingTx {
    let fee = fee_now(state);
    pay(
        state,
        p,
        [real(state, o), dummy(tag)],
        &bob(),
        [SIP / 2, SIP - SIP / 2 - fee],
        fee,
        tag,
    )
    .expect("valid spend")
}

/// Extends `node`'s own tip with empty blocks on schedule; returns them.
fn extend(
    node: &mut siworld_consensus::Chain<siworld_circuits::MockVerifier>,
    n: u64,
    tag: u64,
) -> Vec<Block> {
    (0..n)
        .map(|i| {
            let block = build(&node.state, &node.params, &[], tag + i).unwrap();
            node.apply_block(&block).unwrap();
            block
        })
        .collect()
}

#[test]
fn block_work_is_the_expected_hashes_for_its_target() {
    let p = ChainParams::devnet();
    // Devnet genesis target 0x0fff…ff: one nonce in 16 succeeds.
    assert_eq!(block_work(&p.genesis_target), 16u64.into());
    assert_eq!(block_work(&[0xff; 32]), 1u64.into());
    let mut hardest = [0; 32];
    hardest[31] = 1;
    assert_eq!(
        block_work(&hardest),
        siworld_consensus::U512::one() << 255usize
    );
}

#[test]
fn equal_work_keeps_the_first_branch_seen() {
    let (p, state, _) = funded();
    let mut a = chain(&p, state.clone());
    let mut b = chain(&p, state);
    let first = extend(&mut a, 1, 1);
    let rival = extend(&mut b, 1, 100);
    assert_ne!(first[0].header.hash(), rival[0].header.hash());

    a.apply_block(&rival[0]).unwrap();
    assert_eq!(a.state.tip, first[0].header.hash());
    assert_eq!(a.tip_work(), b.tip_work());
}

#[test]
fn heavier_branch_replaces_the_tip_and_its_state() {
    let (p, state, owned) = funded();
    let mut a = chain(&p, state.clone());
    let mut b = chain(&p, state.clone());

    // a spends alice's package; b's branch never does.
    let tx = spend(&state, &p, &owned[0], 7);
    let nf = tx.slot.nf[0];
    let h1 = build(&state, &p, &[tx], 1).unwrap();
    a.apply_block(&h1).unwrap();
    assert!(a.state.nullifiers.contains(&nf));

    let rival = extend(&mut b, 2, 100);
    a.apply_block(&rival[0]).unwrap();
    assert_eq!(a.state.tip, h1.header.hash(), "equal work: no switch");
    let roots = a.apply_block(&rival[1]).unwrap();

    assert_eq!(a.state.tip, rival[1].header.hash());
    assert_eq!(a.state.roots(), roots);
    assert_eq!(a.state.roots(), b.state.roots());
    assert_eq!(a.state.height, 2);
    assert_eq!(a.state.timestamps, b.state.timestamps);
    assert_eq!(a.state.prev_anchors_root, b.state.prev_anchors_root);
    assert_eq!(a.tip_work(), b.tip_work());
    // The spend lived only on the abandoned branch, so the package is unspent
    // again and can be spent on the new tip.
    assert!(!a.state.nullifiers.contains(&nf));
    let again = spend(&a.state, &p, &owned[0], 8);
    let next = build(&a.state, &p, &[again], 3).unwrap();
    a.apply_block(&next).unwrap();
    assert!(a.state.nullifiers.contains(&nf));
}

#[test]
fn side_branch_cannot_reuse_a_nullifier_spent_in_its_own_ancestry() {
    let (p, state, owned) = funded();
    let mut a = chain(&p, state.clone());
    let mut b = chain(&p, state.clone());
    extend(&mut a, 3, 1);

    // b's branch spends the package; a second block on it tries again with a
    // spend anchored at genesis, whose root is still in the window.
    let x1 = build(&state, &p, &[spend(&state, &p, &owned[0], 7)], 100).unwrap();
    b.apply_block(&x1).unwrap();
    let again = spend(&state, &p, &owned[0], 8);
    let x2 = build(&b.state, &p, &[], 101).unwrap();
    let mut x2_bad = x2.clone();
    x2_bad.body = build(&state, &p, std::slice::from_ref(&again), 102)
        .unwrap()
        .body;
    x2_bad.header.body_root = x2_bad.body.hash();
    reseal(&mut x2_bad.header, &p);

    a.apply_block(&x1).unwrap();
    let before = (a.state.roots(), a.state.tip, a.tip_work());
    assert_eq!(
        a.apply_block(&x2_bad),
        Err(BlockError::NullifierReused(again.slot.nf[0]))
    );
    assert_eq!((a.state.roots(), a.state.tip, a.tip_work()), before);
    // The honest side block is still accepted afterwards.
    a.apply_block(&x2).unwrap();
}

#[test]
fn invalid_side_block_leaves_the_node_unchanged() {
    let (p, state, _) = funded();
    let mut a = chain(&p, state.clone());
    let mut b = chain(&p, state);
    extend(&mut a, 2, 1);
    let rival = extend(&mut b, 2, 100);

    a.apply_block(&rival[0]).unwrap();
    let before = (a.state.roots(), a.state.tip, a.tip_work());
    let mut bad = rival[1].clone();
    bad.header.state_root = Digest([7; 32]);
    reseal(&mut bad.header, &p);
    assert_eq!(a.apply_block(&bad), Err(BlockError::RootMismatch));
    assert_eq!((a.state.roots(), a.state.tip, a.tip_work()), before);

    let mut no_work = rival[1].clone();
    let seed = no_work.header.pow_seed();
    no_work.header.nonce = (0..4096)
        .find(|n| {
            !meets_target(
                &pow_hash(&seed, *n, p.pow_iterations),
                &no_work.header.target,
            )
        })
        .unwrap();
    assert_eq!(a.apply_block(&no_work), Err(BlockError::BadPow));
    assert_eq!((a.state.roots(), a.state.tip, a.tip_work()), before);
}

#[test]
fn unknown_parents_and_known_blocks_are_rejected() {
    let (p, state, _) = funded();
    let mut a = chain(&p, state.clone());
    let mut b = chain(&p, state);
    let blocks = extend(&mut b, 2, 1);
    assert_eq!(a.apply_block(&blocks[1]), Err(BlockError::BadParent));
    a.apply_block(&blocks[0]).unwrap();
    assert_eq!(a.apply_block(&blocks[0]), Err(BlockError::AlreadyKnown));
    a.apply_block(&blocks[1]).unwrap();
    assert_eq!(a.state.roots(), b.state.roots());
}

/// A far-future timestamp drives ASERT to the target ceiling, so the blocks
/// after it cost one hash each. The attacker's branch is valid and much
/// longer, but every hash buys about one unit of work at any target, so it
/// stays lighter than the honest branch and the node does not follow it.
#[test]
fn future_timestamp_branch_with_more_blocks_but_less_work_loses() {
    let (p, state, _) = funded();
    let mut honest = chain(&p, state.clone());
    let mut attacker = chain(&p, state.clone());
    let blocks = extend(&mut honest, 3, 1);

    let far = state.timestamp() + 1_000_000;
    let mut attack = Vec::new();
    for i in 0..11 {
        let block = build_at(&attacker.state, &p, &[], 100 + i, far + i).unwrap();
        attacker.apply_block(&block).unwrap();
        attack.push(block);
    }
    assert_eq!(next_target(&attacker.state, &p), [0xff; 32]);
    assert!(attacker.state.height > honest.state.height);
    assert!(attacker.tip_work() < honest.tip_work());

    let mut node = chain(&p, state);
    for block in &blocks {
        node.apply_block(block).unwrap();
    }
    for block in &attack {
        node.apply_block(block).unwrap();
    }
    assert_eq!(node.state.tip, blocks[2].header.hash());
    assert_eq!(node.state.height, 3);
    assert_eq!(node.state.roots(), honest.state.roots());

    // Delivered in the other order, the node moves to the honest branch once
    // it outweighs the attack.
    let mut node = chain(&p, honest_genesis(&p));
    for block in &attack {
        node.apply_block(block).unwrap();
    }
    assert_eq!(node.state.tip, attack[10].header.hash());
    for block in &blocks {
        node.apply_block(block).unwrap();
    }
    assert_eq!(node.state.tip, blocks[2].header.hash());
    assert_eq!(node.state.roots(), honest.state.roots());
}

fn honest_genesis(p: &ChainParams) -> ChainState {
    genesis(p, &[(alice(), SIP, 0)]).0
}

/// Devnet parameters with hour-long blocks, so a fork that starts a hundred
/// blocks back is a hundred hours behind ASERT's schedule.
fn hourly() -> ChainParams {
    ChainParams {
        target_block_time: 3600,
        ..params()
    }
}

/// Extends `node` with `n` blocks on schedule; returns the state after each,
/// starting with the state before the first.
fn states(
    node: &mut siworld_consensus::Chain<siworld_circuits::MockVerifier>,
    n: u64,
    tag: u64,
) -> Vec<ChainState> {
    let mut out = vec![node.state.clone()];
    for i in 0..n {
        extend(node, 1, tag + i);
        out.push(node.state.clone());
    }
    out
}

/// ASERT is anchored at genesis, so a branch from far below the tip is far
/// behind schedule: after one block stamped with the current time its target
/// is the ceiling and each further block costs one hash. A node rejects any
/// block whose branch leaves the main chain more than MAX_REORG_DEPTH blocks
/// below the tip, before checking its work, and stores nothing for it.
#[test]
fn fork_deeper_than_max_reorg_depth_is_rejected_before_its_work() {
    let p = hourly();
    let (state, _) = genesis(&p, &[(alice(), SIP, 0)]);
    let mut a = chain(&p, state);
    let at = states(&mut a, MAX_REORG_DEPTH + 5, 1);
    let tip = a.state.height;
    let final_height = tip - MAX_REORG_DEPTH;

    // One block back from the final height, stamped now.
    let deep = &at[final_height as usize - 1];
    let now = a.state.timestamp();
    let first = build_at(deep, &p, &[], 100, now).unwrap();
    // Every block after it would be free.
    assert_eq!(asert_target(&p, deep.height + 1, now), [0xff; 32]);

    let before = (a.state.roots(), a.state.tip, a.tip_work());
    assert_eq!(a.apply_block(&first), Err(BlockError::ReorgTooDeep));
    assert!(!a.contains(&first.header.hash()));
    assert_eq!((a.state.roots(), a.state.tip, a.tip_work()), before);

    // Checked before the target and the work: a header with neither gets
    // the same answer.
    let mut no_work = first.clone();
    no_work.header.target = [0; 32];
    no_work.header.nonce = 1;
    assert_eq!(a.apply_block(&no_work), Err(BlockError::ReorgTooDeep));

    // A fork from the final block itself is within the limit.
    let edge = build_at(&at[final_height as usize], &p, &[], 200, now).unwrap();
    assert_eq!(
        a.accept(&edge).map(|x| x.tip),
        Ok(TipChange::None),
        "a fork exactly MAX_REORG_DEPTH below the tip is allowed"
    );
    assert!(a.contains(&edge.header.hash()));
}

/// A side branch whose fork point falls below the final height can never
/// become the main chain, so the node forgets it and rejects its children.
#[test]
fn side_branch_below_the_final_block_is_forgotten() {
    let (p, state, _) = funded();
    let mut a = chain(&p, state.clone());
    let mut b = chain(&p, state);
    extend(&mut a, 1, 1);
    let side = extend(&mut b, 3, 100);
    a.apply_block(&side[0]).unwrap();
    extend(&mut a, MAX_REORG_DEPTH - 1, 2);
    assert_eq!(a.state.height, MAX_REORG_DEPTH);

    // The fork point, genesis, is still the final block: the branch grows.
    assert_eq!(a.accept(&side[1]).map(|x| x.tip), Ok(TipChange::None));

    // One more main-chain block makes height 1 final; the branch from
    // genesis is gone.
    extend(&mut a, 1, 500);
    assert!(!a.contains(&side[0].header.hash()));
    assert!(!a.contains(&side[1].header.hash()));
    assert_eq!(a.apply_block(&side[2]), Err(BlockError::BadParent));
    assert_eq!(a.apply_block(&side[0]), Err(BlockError::ReorgTooDeep));
}

/// A reorg up to MAX_REORG_DEPTH blocks deep still follows the most work.
#[test]
fn reorg_of_max_depth_follows_the_most_work() {
    let (p, state, _) = funded();
    let mut a = chain(&p, state.clone());
    let mut b = chain(&p, state);
    extend(&mut a, MAX_REORG_DEPTH, 1);
    let rival = extend(&mut b, MAX_REORG_DEPTH + 1, 1_000);
    for block in &rival[..MAX_REORG_DEPTH as usize] {
        assert_eq!(a.accept(block).map(|x| x.tip), Ok(TipChange::None));
    }
    assert_eq!(
        a.accept(&rival[MAX_REORG_DEPTH as usize]).map(|x| x.tip),
        Ok(TipChange::Reorg { fork: 0 })
    );
    assert_eq!(a.state.roots(), b.state.roots());
}
