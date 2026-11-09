//! The counterexample list in docs/testing.md: consensus bugs fixed in midstate v5.0.0,
//! one group of tests per item.

mod common;

use common::*;
use siworld_circuits::{AggregateError, InputWitness, MockProver, RelationError};
use siworld_consensus::{
    assemble_body, check_proof, mine_some, next_target, transition, BlockError, BuildError,
};
use siworld_core::params::ChainParams;
use siworld_core::{Block, ContainerProof, Digest, Header, Nullifier};
use siworld_crypto::SpendKey;
use siworld_state::{ChainState, RecentRoots};

const SIP: u64 = 100_000_000;

fn alice() -> SpendKey {
    key(1)
}

fn bob() -> SpendKey {
    key(2)
}

/// Three 1 SIP packages for alice; the second unlocks only at height 2.
fn funded() -> (ChainParams, ChainState, Vec<Owned>) {
    let p = params();
    let (state, owned) = genesis(
        &p,
        &[(alice(), SIP, 0), (alice(), SIP, 2), (alice(), SIP, 0)],
    );
    (p, state, owned)
}

/// Single-input payment: `o` → bob, paying the standard-tier fee.
fn spend_one(
    state: &ChainState,
    p: &ChainParams,
    o: &Owned,
    tag: u64,
) -> siworld_consensus::PendingTx {
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

/// A block that bypasses transition: its roots are arbitrary. Used only for
/// cases the validator must reject.
fn forced_block(
    state: &ChainState,
    p: &ChainParams,
    txs: &[siworld_consensus::PendingTx],
    tag: u64,
) -> Block {
    let height = state.height + 1;
    let (body, proof) = assemble_body(
        &MockProver,
        &state.anchors,
        p,
        height,
        &miner(),
        txs,
        &[],
        &block_seed(tag),
    )
    .expect("assemble");
    let mut header = Header {
        version: siworld_consensus::BLOCK_VERSION,
        height,
        parent: state.tip,
        timestamp: next_timestamp(state, p),
        target: next_target(state, p),
        nonce: 0,
        state_root: Digest([1; 32]),
        commitment_root: Digest([2; 32]),
        nullifier_root: Digest([3; 32]),
        body_root: body.hash(),
        container_size: p.container_size,
    };
    assert_eq!(mine_some(&mut header, p.pow_iterations, 4096), Some(true));
    Block {
        header,
        body,
        proof,
    }
}

/// A block whose header roots come from `transition` but whose proof, on `acc`,
/// is never passed through `check_proof`. Used only for proofs the validator
/// must reject.
fn unchecked_block(
    state: &ChainState,
    acc: &RecentRoots,
    p: &ChainParams,
    txs: &[siworld_consensus::PendingTx],
    tag: u64,
) -> Block {
    let height = state.height + 1;
    let (body, proof) = assemble_body(
        &MockProver,
        acc,
        p,
        height,
        &miner(),
        txs,
        &[],
        &block_seed(tag),
    )
    .expect("assemble");
    let (_, roots) = transition(state, &body, height, p).expect("valid body");
    let mut header = Header {
        version: siworld_consensus::BLOCK_VERSION,
        height,
        parent: state.tip,
        timestamp: next_timestamp(state, p),
        target: next_target(state, p),
        nonce: 0,
        state_root: roots.state_root,
        commitment_root: roots.commitment_root,
        nullifier_root: roots.nullifier_root,
        body_root: body.hash(),
        container_size: p.container_size,
    };
    assert_eq!(mine_some(&mut header, p.pow_iterations, 4096), Some(true));
    Block {
        header,
        body,
        proof,
    }
}

fn snapshot(state: &ChainState) -> (siworld_core::Roots, Digest, u64, u64, usize) {
    (
        state.roots(),
        state.tip,
        state.height,
        state.commitments.len(),
        state.nullifiers.len(),
    )
}

// ───────────── 1. Non-atomic transaction application ─────────────

#[test]
fn ce1_failed_block_leaves_state_unchanged() {
    let (p, state, owned) = funded();
    let mut node = chain(&p, state.clone());
    let before = snapshot(&node.state);

    // The first slot is valid and the second reuses its nullifier: earlier
    // insertions must not remain.
    let a = spend_one(&state, &p, &owned[0], 10);
    let b = pay(
        &state,
        &p,
        [real(&state, &owned[0]), dummy(11)],
        &bob(),
        [SIP - fee_now(&state), 0],
        fee_now(&state),
        11,
    )
    .unwrap();
    let block = forced_block(&state, &p, &[a.clone(), b], 1);
    assert!(matches!(
        node.apply_block(&block),
        Err(BlockError::NullifierReused(_))
    ));
    assert_eq!(snapshot(&node.state), before);
    assert!(!node.state.nullifiers.contains(&a.slot.nf[1]));
}

#[test]
fn ce1_failure_at_last_step_leaves_state_unchanged() {
    // Depth 3 holds only 8 commitments; a block appends 4×2 + 1 = 9 (its slot
    // outputs and the matured miner package), so the final one fails.
    let p = ChainParams {
        commitment_tree_depth: 3,
        ..params()
    };
    let state = ChainState::genesis(&p);
    let mut node = chain(&p, state.clone());
    let before = snapshot(&node.state);
    let block = forced_block(&state, &p, &[], 1);
    assert_eq!(node.apply_block(&block), Err(BlockError::TreeFull));
    assert_eq!(snapshot(&node.state), before);
    assert_eq!(
        build(&state, &p, &[], 1).unwrap_err(),
        BuildError::Invalid(BlockError::TreeFull)
    );
}

#[test]
fn ce1_root_mismatch_leaves_state_unchanged() {
    let (p, state, owned) = funded();
    let mut node = chain(&p, state.clone());
    let before = snapshot(&node.state);
    let mut block = build(&state, &p, &[spend_one(&state, &p, &owned[0], 10)], 1).unwrap();
    block.header.commitment_root = Digest([9; 32]);
    reseal(&mut block.header, &p);
    assert_eq!(node.apply_block(&block), Err(BlockError::RootMismatch));
    assert_eq!(snapshot(&node.state), before);
}

// ───────────── 2. Block-template and validation paths diverge ─────────────

#[test]
fn ce2_builder_and_validator_agree_over_many_blocks() {
    let (p, state, owned) = funded();
    let mut miner_node = chain(&p, state.clone());
    let mut other_node = chain(&p, state);

    for round in 0..5u64 {
        let s = miner_node.state.clone();
        let txs = match round {
            0 => vec![spend_one(&s, &p, &owned[0], 100)],
            2 => vec![
                spend_one(&s, &p, &owned[1], 200),
                spend_one(&s, &p, &owned[2], 201),
            ],
            _ => vec![],
        };
        let block = build(&s, &p, &txs, round).unwrap();
        let a = miner_node.apply_block(&block).unwrap();
        let b = other_node.apply_block(&block).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.state_root, block.header.state_root);
        assert_eq!(miner_node.state.tip, other_node.state.tip);
        assert_eq!(miner_node.state.roots(), other_node.state.roots());
    }
    assert_eq!(other_node.state.height, 5);
    // Per block: N slots × 2 outputs + 1 matured miner package.
    assert_eq!(
        other_node.state.commitments.len(),
        3 + 5 * (u64::from(p.container_size) * 2 + 1)
    );
    assert_eq!(
        other_node.state.nullifiers.len(),
        5 * p.container_size as usize * 2
    );
}

#[test]
fn ce2_tampered_header_roots_are_rejected() {
    let (p, state, owned) = funded();
    let block = build(&state, &p, &[spend_one(&state, &p, &owned[0], 10)], 1).unwrap();
    let tamper: [fn(&mut Header); 3] = [
        |h| h.state_root.0[0] ^= 1,
        |h| h.commitment_root.0[0] ^= 1,
        |h| h.nullifier_root.0[0] ^= 1,
    ];
    for t in tamper {
        let mut bad = block.clone();
        t(&mut bad.header);
        let mut node = chain(&p, state.clone());
        // The PoW seed covers the roots: give the edited header valid work, so
        // the check reached is the roots against the transition.
        reseal(&mut bad.header, &p);
        assert_eq!(node.apply_block(&bad), Err(BlockError::RootMismatch));
    }
    let mut node = chain(&p, state);
    assert!(node.apply_block(&block).is_ok());
}

#[test]
fn ce2_tampered_body_is_rejected() {
    let (p, state, owned) = funded();
    let block = build(&state, &p, &[spend_one(&state, &p, &owned[0], 10)], 1).unwrap();

    let mut swapped = block.clone();
    swapped.body.slots[0].tag[0] ^= 1;
    let mut node = chain(&p, state.clone());
    assert_eq!(node.apply_block(&swapped), Err(BlockError::BadBodyRoot));

    // Recomputing body_root does not help: ΣE, a public input of the proof, binds every slot byte.
    swapped.header.body_root = swapped.body.hash();
    reseal(&mut swapped.header, &p);
    let ids: Vec<_> = swapped.body.slots.iter().map(|s| s.id()).collect();
    let sorted = ids.windows(2).all(|w| w[0] < w[1]);
    let expected = if sorted {
        BlockError::BadProof
    } else {
        BlockError::NotSorted
    };
    assert_eq!(node.apply_block(&swapped), Err(expected));
}

// ───────────── 3. Batch spends validate only the first input ─────────────

#[test]
fn ce3_second_input_condition_is_checked() {
    let (p, state, owned) = funded();
    let fee = fee_now(&state);
    let outs = [SIP, SIP - fee];
    let err = pay(
        &state,
        &p,
        [real(&state, &owned[0]), real(&state, &owned[1])],
        &bob(),
        outs,
        fee,
        10,
    )
    .unwrap_err();
    assert_eq!(err, RelationError::ConditionNotMet { input: 1 });

    let err = pay(
        &state,
        &p,
        [real(&state, &owned[1]), real(&state, &owned[0])],
        &bob(),
        outs,
        fee,
        10,
    )
    .unwrap_err();
    assert_eq!(err, RelationError::ConditionNotMet { input: 0 });
}

#[test]
fn ce3_condition_passes_once_anchor_reaches_unlock_height() {
    let (p, state, owned) = funded();
    let mut node = chain(&p, state);
    for round in 0..2 {
        let block = build(&node.state, &p, &[], round).unwrap();
        node.apply_block(&block).unwrap();
    }
    let s = node.state.clone();
    let fee = fee_now(&s);
    let tx = pay(
        &s,
        &p,
        [real(&s, &owned[0]), real(&s, &owned[1])],
        &bob(),
        [SIP, SIP - fee],
        fee,
        10,
    )
    .unwrap();
    let block = build(&s, &p, &[tx], 2).unwrap();
    node.apply_block(&block).unwrap();
}

#[test]
fn ce3_second_input_membership_is_checked() {
    let (p, state, owned) = funded();
    let fee = fee_now(&state);
    // A package not in the tree, impersonated using the path of position 0.
    let fake = note_for(&alice(), SIP, 0, 4242);
    let forged = InputWitness::Real {
        note: fake,
        sk: alice(),
        path: state.commitments.path(0).unwrap(),
    };
    let err = pay(
        &state,
        &p,
        [real(&state, &owned[0]), forged],
        &bob(),
        [SIP, SIP - fee],
        fee,
        10,
    )
    .unwrap_err();
    assert_eq!(err, RelationError::NotInTree { input: 1 });
}

#[test]
fn ce3_second_input_spend_key_is_checked() {
    let (p, state, owned) = funded();
    let fee = fee_now(&state);
    let mut stolen = owned[2].clone();
    stolen.sk = bob();
    let err = pay(
        &state,
        &p,
        [real(&state, &owned[0]), real(&state, &stolen)],
        &bob(),
        [SIP, SIP - fee],
        fee,
        10,
    )
    .unwrap_err();
    assert_eq!(err, RelationError::WrongSpendKey { input: 1 });
}

#[test]
fn ce3_second_input_nullifier_is_checked_against_spent_set() {
    let (p, state, owned) = funded();
    let mut node = chain(&p, state.clone());
    let first = spend_one(&state, &p, &owned[2], 10);
    let spent_nf = first.slot.nf[0];
    node.apply_block(&build(&state, &p, &[first], 1).unwrap())
        .unwrap();

    let s = node.state.clone();
    let fee = fee_now(&s);
    let again = pay(
        &s,
        &p,
        [real(&s, &owned[0]), real(&s, &owned[2])],
        &bob(),
        [SIP, SIP - fee],
        fee,
        11,
    )
    .unwrap();
    assert_eq!(again.slot.nf[1], spent_nf);
    assert_eq!(
        build(&s, &p, std::slice::from_ref(&again), 2).unwrap_err(),
        BuildError::Invalid(BlockError::NullifierReused(spent_nf))
    );
    let before = snapshot(&node.state);
    assert_eq!(
        node.apply_block(&forced_block(&s, &p, &[again], 2)),
        Err(BlockError::NullifierReused(spent_nf))
    );
    assert_eq!(snapshot(&node.state), before);
}

#[test]
fn ce3_second_nullifier_is_bound_to_proof() {
    let (p, state, owned) = funded();
    let mut tx = spend_one(&state, &p, &owned[0], 10);
    tx.slot.nf[1] = Nullifier(Digest([7; 32]));
    assert!(matches!(
        assemble_body(
            &MockProver,
            &state.anchors,
            &p,
            1,
            &miner(),
            &[tx],
            &[],
            &block_seed(1)
        ),
        Err(BuildError::Aggregate(
            siworld_circuits::AggregateError::BadSlotProof { .. }
        ))
    ));
}

// ───────────── 4. One-time key / nullifier reuse only logged ─────────────

#[test]
fn ce4_reuse_across_blocks_is_rejected() {
    let (p, state, owned) = funded();
    let mut node = chain(&p, state.clone());
    node.apply_block(&build(&state, &p, &[spend_one(&state, &p, &owned[0], 10)], 1).unwrap())
        .unwrap();

    let s = node.state.clone();
    let again = spend_one(&s, &p, &owned[0], 20);
    let block = forced_block(&s, &p, std::slice::from_ref(&again), 2);
    assert_eq!(
        node.apply_block(&block),
        Err(BlockError::NullifierReused(again.slot.nf[0]))
    );
    assert_eq!(node.state.height, 1);
}

#[test]
fn ce4_reuse_across_slots_in_one_block_is_rejected() {
    let (p, state, owned) = funded();
    let a = spend_one(&state, &p, &owned[0], 10);
    let b = spend_one(&state, &p, &owned[0], 20);
    assert_ne!(a.slot.id(), b.slot.id());
    assert_eq!(a.slot.nf[0], b.slot.nf[0]);
    assert_eq!(
        build(&state, &p, &[a.clone(), b.clone()], 1).unwrap_err(),
        BuildError::Invalid(BlockError::NullifierReused(a.slot.nf[0]))
    );
    let mut node = chain(&p, state.clone());
    assert_eq!(
        node.apply_block(&forced_block(&state, &p, &[a.clone(), b], 1)),
        Err(BlockError::NullifierReused(a.slot.nf[0]))
    );
}

#[test]
fn ce4_reuse_within_one_slot_is_rejected() {
    let (p, state, owned) = funded();
    // Rejected by the proof layer.
    let err = pay(&state, &p, [dummy(5), dummy(5)], &bob(), [0, 0], 0, 10).unwrap_err();
    assert_eq!(err, RelationError::DuplicateNullifier);

    // Even if the proof system lets it through, the consensus layer must reject it.
    // `transition` takes no proof, so this check cannot depend on the proof system.
    let (mut body, proof) = assemble_body(
        &MockProver,
        &state.anchors,
        &p,
        1,
        &miner(),
        &[spend_one(&state, &p, &owned[0], 10)],
        &[],
        &block_seed(1),
    )
    .unwrap();
    body.slots[0].nf[1] = body.slots[0].nf[0];
    let dup = body.slots[0].nf[0];
    body.slots.sort_by_key(|s| s.id());
    assert_eq!(
        transition(&state, &body, 1, &p).unwrap_err(),
        BlockError::NullifierReused(dup)
    );
    // A real verifier does not even accept the proof.
    assert_eq!(
        check_proof(&proof, &state, &body, 1, &MockProver),
        Err(BlockError::BadProof)
    );
}

// ───────────── Other block-structure checks ─────────────

#[test]
fn duplicate_slot_ids_are_rejected_by_strict_order_before_proof_validation() {
    let (p, state, owned) = funded();
    let block = build(&state, &p, &[spend_one(&state, &p, &owned[0], 10)], 1).unwrap();
    let mut duplicate = block.body.clone();
    duplicate.slots[1] = duplicate.slots[0];
    assert_eq!(duplicate.slots[0].id(), duplicate.slots[1].id());
    assert_eq!(
        transition(&state, &duplicate, 1, &p).unwrap_err(),
        BlockError::NotSorted
    );
    assert!(transition(&state, &block.body, 1, &p).is_ok());
}

#[test]
fn wrong_slot_count_unsorted_and_bad_coinbase_are_rejected() {
    let (p, state, owned) = funded();
    let block = build(&state, &p, &[spend_one(&state, &p, &owned[0], 10)], 1).unwrap();

    let mut short = block.body.clone();
    short.slots.pop();
    assert_eq!(
        transition(&state, &short, 1, &p).unwrap_err(),
        BlockError::WrongSlotCount
    );

    let mut unsorted = block.body.clone();
    unsorted.slots.swap(0, 1);
    assert_eq!(
        transition(&state, &unsorted, 1, &p).unwrap_err(),
        BlockError::NotSorted
    );

    let mut greedy = block.body.clone();
    greedy.coinbase.miner_amount += 1;
    assert_eq!(
        transition(&state, &greedy, 1, &p).unwrap_err(),
        BlockError::BadCoinbase
    );

    // The total is right but one atom moved from the development fund to the
    // miner: each of the three amounts is checked, not just their sum.
    let mut skimmed = block.body.clone();
    skimmed.coinbase.dev_direct_amount -= 1;
    skimmed.coinbase.miner_amount += 1;
    assert_eq!(
        transition(&state, &skimmed, 1, &p).unwrap_err(),
        BlockError::BadCoinbase
    );
    let mut skimmed = block.body.clone();
    skimmed.coinbase.dev_lock_amount -= 1;
    skimmed.coinbase.dev_direct_amount += 1;
    assert_eq!(
        transition(&state, &skimmed, 1, &p).unwrap_err(),
        BlockError::BadCoinbase
    );

    assert_eq!(
        transition(&state, &block.body, 2, &p).unwrap_err(),
        BlockError::BadHeight
    );
}

#[test]
fn wrong_parent_is_rejected() {
    let (p, state, _) = funded();
    let mut block = build(&state, &p, &[], 1).unwrap();
    block.header.parent = Digest([4; 32]);
    let mut node = chain(&p, state);
    assert_eq!(node.apply_block(&block), Err(BlockError::BadParent));
}

// ───────────── Proof outside the header; parent's or grandparent's 𝒜 root ─────────────

/// Applies empty blocks on top of `state` and returns every state, genesis first.
fn states_after(p: &ChainParams, state: ChainState, blocks: u64) -> Vec<ChainState> {
    let mut node = chain(p, state);
    let mut out = vec![node.state.clone()];
    for round in 0..blocks {
        let block = build(&node.state, p, &[], 100 + round).unwrap();
        node.apply_block(&block).unwrap();
        out.push(node.state.clone());
    }
    out
}

#[test]
fn header_does_not_commit_to_proof() {
    let (p, state, owned) = funded();
    let block = build(&state, &p, &[spend_one(&state, &p, &owned[0], 10)], 1).unwrap();
    let mut node = chain(&p, state.clone());
    let before = snapshot(&node.state);

    let mut flipped = block.clone();
    flipped.proof.0[0] ^= 1;
    let missing = Block {
        proof: ContainerProof::default(),
        ..block.clone()
    };
    for bad in [flipped, missing] {
        assert_eq!(bad.header.hash(), block.header.hash());
        assert_eq!(bad.body.hash(), block.header.body_root);
        // This copy is rejected, but the header is not: the state is unchanged
        // and the same header with a valid proof is still accepted below.
        assert_eq!(node.apply_block(&bad), Err(BlockError::BadProof));
        assert_eq!(snapshot(&node.state), before);
    }
    node.apply_block(&block).unwrap();
    assert_eq!(node.state.tip, block.header.hash());
}

#[test]
fn proof_on_parent_or_grandparent_root_is_accepted() {
    let (p, state, _) = funded();
    let s = states_after(&p, state, 1);
    let (grandparent, parent) = (&s[0], &s[1]);
    assert_ne!(
        grandparent.anchors.accumulator_root(),
        parent.anchors.accumulator_root()
    );

    let on_parent = build_on(parent, &parent.anchors, &p, &[], 2).unwrap();
    let on_grandparent = build_on(parent, &grandparent.anchors, &p, &[], 2).unwrap();
    // Empty packages do not depend on the anchor, so only the proofs differ:
    // one header, two valid proofs.
    assert_eq!(on_parent.header, on_grandparent.header);
    assert_ne!(on_parent.proof, on_grandparent.proof);

    let mut a = chain(&p, parent.clone());
    let mut b = chain(&p, parent.clone());
    assert_eq!(
        a.apply_block(&on_parent).unwrap(),
        b.apply_block(&on_grandparent).unwrap()
    );
    assert_eq!(a.state.tip, b.state.tip);
}

#[test]
fn proof_on_older_root_is_rejected() {
    let (p, state, _) = funded();
    let s = states_after(&p, state, 2);
    let (great_grandparent, tip) = (&s[0], &s[2]);
    assert_eq!(
        build_on(tip, &great_grandparent.anchors, &p, &[], 3).unwrap_err(),
        BuildError::Invalid(BlockError::BadProof)
    );
    let mut node = chain(&p, tip.clone());
    let before = snapshot(&node.state);
    let block = unchecked_block(tip, &great_grandparent.anchors, &p, &[], 3);
    assert_eq!(node.apply_block(&block), Err(BlockError::BadProof));
    assert_eq!(snapshot(&node.state), before);

    // Block 1 has no grandparent: only genesis's 𝒜 is accepted.
    let genesis = &s[0];
    let mut other = siworld_state::RecentRoots::new(p.anchor_window);
    other.push(Digest([7; 32]), 0);
    assert_eq!(
        build_on(genesis, &other, &p, &[], 1).unwrap_err(),
        BuildError::Invalid(BlockError::BadProof)
    );
}

#[test]
fn slot_anchored_to_parent_needs_parent_root() {
    let (p, state, owned) = funded();
    let s = states_after(&p, state, 1);
    let (grandparent, parent) = (&s[0], &s[1]);
    let tx = spend_one(parent, &p, &owned[0], 10);
    // Until the producer switches to the parent's 𝒜, a slot anchored to the
    // newest block cannot be included.
    assert!(matches!(
        build_on(
            parent,
            &grandparent.anchors,
            &p,
            std::slice::from_ref(&tx),
            2
        ),
        Err(BuildError::Aggregate(AggregateError::AnchorExpired { .. }))
    ));
    build_on(parent, &parent.anchors, &p, &[tx], 2).unwrap();
}

#[test]
fn producer_and_validator_agree_with_either_root() {
    let (p, state, owned) = funded();
    let mut miner_node = chain(&p, state.clone());
    let mut other_node = chain(&p, state);
    let mut prev: Option<ChainState> = None;

    for round in 0..6u64 {
        let s = miner_node.state.clone();
        // Odd rounds prove on the grandparent's 𝒜, with the transaction anchored
        // in the grandparent's window.
        let (acc_state, txs) = match (round % 2, &prev) {
            (1, Some(g)) => {
                let txs = match round {
                    1 => vec![spend_one(g, &p, &owned[0], 100 + round)],
                    3 => vec![spend_one(g, &p, &owned[1], 100 + round)],
                    _ => vec![],
                };
                (g.clone(), txs)
            }
            _ => {
                let txs = match round {
                    2 => vec![spend_one(&s, &p, &owned[2], 100 + round)],
                    _ => vec![],
                };
                (s.clone(), txs)
            }
        };
        let block = build_on(&s, &acc_state.anchors, &p, &txs, round).unwrap();
        let a = miner_node.apply_block(&block).unwrap();
        let b = other_node.apply_block(&block).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.state_root, block.header.state_root);
        assert_eq!(miner_node.state.tip, other_node.state.tip);
        prev = Some(s);
    }
    assert_eq!(other_node.state.height, 6);
    assert_eq!(
        other_node.state.nullifiers.len(),
        6 * p.container_size as usize * 2
    );
}
