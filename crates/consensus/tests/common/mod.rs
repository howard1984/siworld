//! Test helpers: genesis funds, transaction construction, block production.
#![allow(dead_code)]

use siworld_circuits::{
    encrypt_outputs, output_rhos, InputWitness, MockProver, MockVerifier, RelationContext,
    RelationError, SlotWitness,
};
use siworld_consensus::{build_block, BuildError, Chain, Miner, PendingTx};
use siworld_core::issuance::{epoch_of, fee_base};
use siworld_core::params::{ChainParams, DevFundKeys};
use siworld_core::{Block, Condition, DevAccount, Digest, Height, Note, Payout};
use siworld_crypto::{expand, note_commitment, sign_payout, SecretSeed, SigningKey, SpendKey};
use siworld_state::{ChainState, RecentRoots};

pub fn seed(tag: u64) -> Digest {
    expand(&Digest([0x5e; 32]), "test seed", tag)
}

/// The producer's seed for a test block: deterministic, so tests reproduce.
pub fn block_seed(tag: u64) -> SecretSeed {
    SecretSeed::insecure_deterministic(seed(tag))
}

pub fn key(tag: u64) -> SpendKey {
    SpendKey::from_digest(expand(&Digest([0x4b; 32]), "test key", tag))
}

pub fn params() -> ChainParams {
    let mut target = [0xff; 32];
    target[0] = 0x7f; // Minimum-cost fixture supporting both valid and invalid work.
    ChainParams {
        pow_iterations: 1,
        genesis_target: target,
        ..ChainParams::devnet()
    }
}

/// The development fund's test signing key for `account`.
pub fn dev_fund_key(account: DevAccount) -> SigningKey {
    SigningKey::generate(&expand(
        &Digest([0xdf; 32]),
        "dev fund key",
        u64::from(account.to_byte()),
    ))
}

/// Devnet parameters with the test development-fund keys and 60-second
/// blocks, so that the lock releases a payable amount within a test.
pub fn params_with_dev_fund() -> ChainParams {
    ChainParams {
        target_block_time: 60,
        dev_fund_keys: Some(DevFundKeys {
            direct: dev_fund_key(DevAccount::Direct).verifying_key().0,
            lock: dev_fund_key(DevAccount::Lock).verifying_key().0,
        }),
        ..params()
    }
}

/// A signed payout of `amount` from `account` to `to` on the dev-fund test
/// chain, deterministic in `tag`.
pub fn payout(account: DevAccount, counter: u64, amount: u64, to: &SpendKey, tag: u64) -> Payout {
    payout_on(
        &params_with_dev_fund().chain_id,
        account,
        counter,
        amount,
        to,
        tag,
    )
}

/// [`payout`] signed for the chain `chain_id`.
pub fn payout_on(
    chain_id: &Digest,
    account: DevAccount,
    counter: u64,
    amount: u64,
    to: &SpendKey,
    tag: u64,
) -> Payout {
    sign_payout(
        &dev_fund_key(account),
        chain_id,
        account,
        counter,
        amount,
        to.owner(),
        expand(&seed(tag), "payout rseed", 0),
        &expand(&seed(tag), "payout hedge", 0),
    )
}

/// A package held by a wallet and its position in the commitment tree.
#[derive(Clone, Debug)]
pub struct Owned {
    pub sk: SpendKey,
    pub note: Note,
    pub index: u64,
}

pub fn note_for(sk: &SpendKey, value: u64, unlock_height: Height, tag: u64) -> Note {
    Note {
        owner: sk.owner(),
        value,
        cond: Condition { unlock_height },
        rho: expand(&seed(tag), "rho", 0),
        rseed: expand(&seed(tag), "rseed", 0),
    }
}

/// Test genesis: `specs` are (key, amount, unlock_height).
pub fn genesis(
    params: &ChainParams,
    specs: &[(SpendKey, u64, Height)],
) -> (ChainState, Vec<Owned>) {
    let owned: Vec<Owned> = specs
        .iter()
        .enumerate()
        .map(|(i, (sk, value, unlock))| Owned {
            sk: sk.clone(),
            note: note_for(sk, *value, *unlock, 1_000 + i as u64),
            index: i as u64,
        })
        .collect();
    let cms: Vec<_> = owned.iter().map(|o| note_commitment(&o.note)).collect();
    (ChainState::genesis_with_commitments(params, &cms), owned)
}

pub fn real(state: &ChainState, o: &Owned) -> InputWitness {
    InputWitness::Real {
        note: o.note,
        sk: o.sk.clone(),
        path: state
            .commitments
            .path(o.index)
            .expect("owned note is in tree"),
    }
}

pub fn dummy(tag: u64) -> InputWitness {
    InputWitness::Dummy {
        nk: expand(&seed(tag), "nk", 0),
        rho: expand(&seed(tag), "rho in", 0),
    }
}

/// Builds a transaction anchored at the latest root, with both outputs to `to`.
pub fn pay(
    state: &ChainState,
    params: &ChainParams,
    inputs: [InputWitness; 2],
    to: &SpendKey,
    outs: [u64; 2],
    fee: u64,
    tag: u64,
) -> Result<PendingTx, RelationError> {
    let (anchor, _) = state
        .anchors
        .latest()
        .expect("anchor window is never empty");
    let rho = output_rhos(&inputs);
    let out = |j: usize| Note {
        rho: rho[j],
        ..note_for(to, outs[j], 0, tag * 2 + j as u64)
    };
    let outputs = [out(0), out(1)];
    let to = to.address();
    let (ct, view_tags) = encrypt_outputs(
        &outputs,
        [&to, &to],
        [0, 1].map(|j| expand(&seed(tag), "encryption", j)),
    );
    let w = SlotWitness {
        anchor,
        inputs,
        outputs,
        ct,
        tag: view_tags,
        fee,
    };
    let ctx = RelationContext {
        anchors: &state.anchors,
        tree_depth: params.commitment_tree_depth,
    };
    let (slot, proof, fee) = MockProver::prove_slot(&ctx, &w, expand(&seed(tag), "blind", 0))?;
    // Consensus tests hand transactions straight to the producer: no relay,
    // so no anti-spam nonce.
    Ok(PendingTx {
        slot,
        proof,
        fee,
        nonce: 0,
    })
}

/// Standard-tier fee for the next block (epoch chosen by the latest anchor root's height).
pub fn fee_now(state: &ChainState) -> u64 {
    let (_, h) = state
        .anchors
        .latest()
        .expect("anchor window is never empty");
    fee_base(epoch_of(h))
}

pub fn miner_key() -> SpendKey {
    key(999)
}

/// The test miner: its address and a committee key hash unrelated to it.
pub fn miner() -> Miner {
    Miner {
        address: miner_key().address(),
        committee_key: expand(&seed(999), "committee key", 0),
    }
}

/// Builds the next block with a proof on the parent's 𝒜 root.
pub fn build(
    state: &ChainState,
    params: &ChainParams,
    txs: &[PendingTx],
    tag: u64,
) -> Result<Block, BuildError> {
    build_on(state, &state.anchors, params, txs, tag)
}

/// Builds the next block with the given payouts, on the parent's 𝒜 root.
pub fn build_with_payouts(
    state: &ChainState,
    params: &ChainParams,
    txs: &[PendingTx],
    payouts: &[Payout],
    tag: u64,
) -> Result<Block, BuildError> {
    build_block(
        state,
        &state.anchors,
        params,
        &MockProver,
        &miner(),
        txs,
        payouts,
        &block_seed(tag),
        next_timestamp(state, params),
    )
}

/// Builds the next block with a proof on `acc`, the 𝒜 the producer chose.
pub fn build_on(
    state: &ChainState,
    acc: &RecentRoots,
    params: &ChainParams,
    txs: &[PendingTx],
    tag: u64,
) -> Result<Block, BuildError> {
    build_block(
        state,
        acc,
        params,
        &MockProver,
        &miner(),
        txs,
        &[],
        &block_seed(tag),
        next_timestamp(state, params),
    )
}

/// Builds the next block with the given timestamp, on the parent's 𝒜 root.
pub fn build_at(
    state: &ChainState,
    params: &ChainParams,
    txs: &[PendingTx],
    tag: u64,
    timestamp: u64,
) -> Result<Block, BuildError> {
    build_block(
        state,
        &state.anchors,
        params,
        &MockProver,
        &miner(),
        txs,
        &[],
        &block_seed(tag),
        timestamp,
    )
}

/// The next block's timestamp, exactly on schedule, so ASERT keeps the genesis target.
pub fn next_timestamp(state: &ChainState, params: &ChainParams) -> u64 {
    state.timestamp() + params.target_block_time
}

/// Re-mines a header after a test edits it, so the edit reaches the check after PoW.
pub fn reseal(header: &mut siworld_core::Header, params: &ChainParams) {
    header.nonce = 0;
    assert_eq!(
        siworld_consensus::mine_some(header, params.pow_iterations, 4096),
        Some(true)
    );
}

pub fn chain(params: &ChainParams, state: ChainState) -> Chain<MockVerifier> {
    Chain::new(params.clone(), state, MockVerifier)
}
