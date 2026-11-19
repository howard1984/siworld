use crate::state::{BlockVerifier, State};
use crate::wire::{
    Block, DigestBytes, Hash, PUBLIC_BYTES, PublicRecord, REWARD_CIPHERTEXT_BYTES, RewardRecord,
    Transaction,
};
use native::codec::{ProofContext, PublicTransaction, encode_digest};
use native::multi_asset::{Digest, F};
use p3_field::PrimeCharacteristicRing;

pub(crate) struct TestVerifier;
impl BlockVerifier for TestVerifier {
    fn transaction(
        &self,
        _: &PublicTransaction,
        _: &ProofContext,
        _: &Digest,
        _: &Digest,
        proof: &[u8],
    ) -> Result<(), String> {
        if proof == [1] {
            Ok(())
        } else {
            Err("test transaction rejection".into())
        }
    }
    fn settlement(
        &self,
        _: &[Digest],
        _: &native::settlement::RewardPlan,
        _: Hash,
        _: Hash,
        _: &[Digest],
        proof: &[u8],
    ) -> Result<(), String> {
        if proof == [1] {
            Ok(())
        } else {
            Err("test settlement rejection".into())
        }
    }
}
fn felt(value: u32) -> DigestBytes {
    let mut d = [F::ZERO; 12];
    d[0] = F::from_u32(value);
    encode_digest(&d)
}
pub(crate) fn candidate(state: &State, seed: u32) -> Block {
    let snapshot = state.tip_snapshot().selector;
    let mut transactions = Vec::new();
    for i in 0..64u32 {
        let mut body = [0u8; PUBLIC_BYTES];
        for j in 0..5u32 {
            body[j as usize * 48..(j as usize + 1) * 48].copy_from_slice(&felt(seed + i * 5 + j));
        }
        transactions.push(Transaction {
            record: PublicRecord::new(snapshot, body, felt(seed + 10000 + i)).unwrap(),
            proof: vec![1],
        });
    }
    transactions.sort_by_key(|tx| tx.record.statement_id(&state.config.network));
    let mut block = Block {
        network: state.config.network,
        height: state.height + 1,
        parent: state.tip,
        timestamp: state.timestamp() + state.config.target_interval,
        target: state.next_target(),
        nonce: 0,
        transactions,
        reward_mode: crate::state::RewardMode::Voyager,
        rewards: vec![RewardRecord {
            commitment: felt(seed + 20000),
            ciphertext: [0; REWARD_CIPHERTEXT_BYTES],
        }],
        fund_spends: Vec::new(),
        issuances: Vec::new(),
        settlement_proof: vec![1],
    };
    find_test_nonce(&mut block, state.config.pow_iterations, true);
    block
}

/// Search only negligible-difficulty fixture work within two independent limits.
pub(crate) fn find_test_nonce(block: &mut Block, iterations: u64, valid: bool) {
    assert!(
        iterations <= 1_000,
        "fixture PoW iterations exceed the test-only limit"
    );
    let seed = block.pow_seed().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    for _ in 0..65_536 {
        assert!(
            std::time::Instant::now() < deadline,
            "fixture PoW deadline exceeded"
        );
        let accepted = siworld_core::pow::meets_target(
            &siworld_core::pow::pow_hash(&seed, block.nonce, iterations),
            &block.target,
        );
        if accepted == valid {
            return;
        }
        block.nonce = block.nonce.checked_add(1).expect("fixture nonce exhausted");
    }
    panic!("fixture PoW nonce limit exceeded");
}
