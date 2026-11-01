//! Actual ML-DSA-65 claim checks and synthetic maximum-size codec diagnostics.
//!
//! Every key in this test is deterministically generated synthetic test data.
//! Opaque proof and ciphertext fills exercise framing only: no block, note
//! encryption, transaction proof or settlement proof is accepted by this test.

use libcrux_ml_dsa::ml_dsa_65;
use native::codec::{decode_digest, encode_digest};
use native::issuance::{AssetMetadata, IssuanceDeclaration, SignedIssuance, derive_asset_id};
use native::multi_asset::{Digest, F, Hasher, Note, SIP_ASSET_ID};
use native::settlement::{
    RewardMode, RewardPlan, sample_fixed_settlement_witness, settlement_public,
};
use p3_field::PrimeCharacteristicRing;
use serde_json::json;
use siworld_native_node::fund_spend::{
    ENCODED_BYTES, FundSpend, SIGNATURE_BYTES, VERIFYING_KEY_BYTES, canonical_rho,
};
use siworld_native_node::issuance::{
    CIPHERTEXT_BYTES, INITIAL_NOTES, IssuanceRecord, MAX_PROOF_BYTES, MAX_RECORD_BYTES,
    METADATA_CODEC_LIMIT, RECORDS_CODEC_LIMIT, TESTNET_ISSUANCE_FEE_ATOMS,
};
use siworld_native_node::p2p::{Budget, CONNECTION_BYTES, MAX_COMPACT_BYTES};
use siworld_native_node::sync::CompactBlock;
use siworld_native_node::wire::{
    BLOCK_FIXED_BYTES, BLOCK_HEADER_BYTES, Block, Hash, MAX_BLOCK_BYTES, MAX_ENVELOPE_BYTES,
    MAX_FUND_SPENDS, MAX_REWARDS, MAX_SETTLEMENT_PROOF, MAX_SLOTS, MAX_TX_PROOF, PUBLIC_BYTES,
    PublicRecord, REWARD_CIPHERTEXT_BYTES, REWARD_RECORD_BYTES, RewardRecord, Snapshot,
    Transaction, validate_fund_spends,
};
use std::{io::Cursor, time::Instant};

const ACCOUNTS: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 31];

fn digest(seed: usize) -> Digest {
    core::array::from_fn(|index| F::from_usize(seed + index))
}

fn signed_claim(network: Hash, account: u8) -> FundSpend {
    let pair = ml_dsa_65::generate_key_pair([83 + account; 32]);
    let note = Note {
        asset_id: SIP_ASSET_ID,
        owner: digest(1000 + usize::from(account) * 32),
        value: 1,
        unlock_height: 0,
        rho: canonical_rho(network, account, 0),
        rseed: digest(2000 + usize::from(account) * 32),
    };
    let mut spend = FundSpend {
        account,
        counter: 0,
        amount: note.value,
        owner: encode_digest(&note.owner),
        rho: encode_digest(&note.rho),
        rseed: encode_digest(&note.rseed),
        commitment: encode_digest(&Hasher::new().note_cm(&note)),
        ciphertext: [account; REWARD_CIPHERTEXT_BYTES],
        verifying_key: *pair.verification_key.as_ref(),
        signature: [0; SIGNATURE_BYTES],
    };
    spend.signature = *ml_dsa_65::sign(
        &pair.signing_key,
        &spend.message(network),
        b"siworld v0",
        [121 + account; 32],
    )
    .expect("synthetic claim signing")
    .as_ref();
    spend
}

fn verify_claim_bundle(spends: &[FundSpend], network: Hash) {
    assert_eq!(spends.len(), MAX_FUND_SPENDS);
    validate_fund_spends(spends).expect("canonical claim bundle");
    for spend in spends {
        // The keys represent this test's immutable synthetic genesis key table.
        let expected = ml_dsa_65::generate_key_pair([83 + spend.account; 32]);
        let key: &[u8; VERIFYING_KEY_BYTES] = expected.verification_key.as_ref();
        let decoded = FundSpend::decode(&spend.encode()).expect("canonical signed claim");
        assert!(
            decoded == *spend,
            "canonical signed claim changed during decode"
        );
        decoded
            .verify(network, key)
            .expect("actual ML-DSA-65 verification");
    }
}

#[test]
fn eight_actual_signatures_round_trip_and_ninth_duplicate_or_unsorted_claim_is_rejected() {
    let network = [9; 32];
    let spends: Vec<_> = ACCOUNTS
        .into_iter()
        .map(|account| signed_claim(network, account))
        .collect();
    assert_eq!(MAX_FUND_SPENDS, 8);
    assert_eq!(
        spends.iter().map(|s| s.encode().len()).sum::<usize>(),
        54_264
    );
    verify_claim_bundle(&spends, network);

    let mut invalid = spends.clone();
    invalid.insert(7, signed_claim(network, 7));
    assert!(validate_fund_spends(&invalid).is_err());
    invalid = spends.clone();
    invalid[1] = invalid[0].clone();
    assert!(validate_fund_spends(&invalid).is_err());
    invalid = spends.clone();
    invalid.swap(0, 1);
    assert!(validate_fund_spends(&invalid).is_err());
    for spend in &spends {
        let mut corrupt = spend.clone();
        corrupt.signature[0] ^= 1;
        assert!(corrupt.verify(network, &spend.verifying_key).is_err());
        assert!(spend.verify([10; 32], &spend.verifying_key).is_err());
    }
}

fn maximum_issuance_record(network: Hash, sequence: u64) -> IssuanceRecord {
    let pair = ml_dsa_65::generate_key_pair([151; 32]);
    let ciphertexts: Vec<_> = (0..INITIAL_NOTES)
        .map(|index| vec![index as u8; CIPHERTEXT_BYTES])
        .collect();
    let key = *pair.verification_key.as_ref();
    let declaration = IssuanceDeclaration {
        network,
        version: 1,
        issuer_key: key,
        sequence,
        asset_id: derive_asset_id(&network, &key, sequence),
        public_supply: 3,
        metadata: AssetMetadata {
            name: "x".repeat(METADATA_CODEC_LIMIT - 1),
            decimals: 0,
        },
        issuance_fee_atoms: TESTNET_ISSUANCE_FEE_ATOMS,
        note_commitments: (0..INITIAL_NOTES)
            .map(|index| digest(3000 + index * 32))
            .collect(),
        note_ciphertext_digests: ciphertexts
            .iter()
            .map(|c| *blake3::hash(c).as_bytes())
            .collect(),
    };
    let signature = *ml_dsa_65::sign(
        &pair.signing_key,
        &declaration.canonical_bytes(),
        b"siworld asset issuance v1",
        [152; 32],
    )
    .expect("synthetic declaration signing")
    .as_ref();
    let signed = SignedIssuance {
        declaration,
        signature: Some(signature),
    };
    signed
        .verify_signature()
        .expect("actual synthetic issuer signature");
    IssuanceRecord {
        signed,
        ciphertexts,
        // Deliberately opaque codec fill, never passed to an issuance verifier.
        proof: vec![0; MAX_PROOF_BYTES],
        fee_commitment: encode_digest(&digest(4000)),
        fee_rho: encode_digest(&digest(5000)),
    }
}

fn settlement_statement(block: &Block, plan: &RewardPlan) -> Vec<F> {
    let fees: Vec<_> = block
        .transactions
        .iter()
        .map(|tx| decode_digest(&tx.record.fee_commit).expect("canonical fee commitment"))
        .collect();
    let rewards: Vec<_> = block
        .rewards
        .iter()
        .map(|reward| decode_digest(&reward.commitment).expect("canonical reward commitment"))
        .collect();
    assert_eq!(fees.len(), 576);
    settlement_public(&fees, plan, block.network, block.list_digest(), &rewards)
        .expect("fixed-capacity public settlement statement")
}

#[test]
#[ignore = "explicit maximum-size codec diagnostic; performs no proof acceptance"]
fn maximum_opaque_proof_envelope_with_eight_signed_claims_preserves_native_budgets() {
    let started = Instant::now();
    let witness = sample_fixed_settlement_witness(MAX_SLOTS, RewardMode::Holder);
    let network = witness.network;
    let claims_started = Instant::now();
    let spends: Vec<_> = ACCOUNTS
        .into_iter()
        .map(|account| signed_claim(network, account))
        .collect();
    let claim_generation_ns = claims_started.elapsed().as_nanos();
    let claims_started = Instant::now();
    verify_claim_bundle(&spends, network);
    let claim_verification_ns = claims_started.elapsed().as_nanos();
    let claim_bundle_bytes: usize = spends.iter().map(|s| s.encode().len()).sum();
    assert_eq!(claim_bundle_bytes, MAX_FUND_SPENDS * ENCODED_BYTES);

    let mut transactions: Vec<_> = witness
        .slots
        .iter()
        .enumerate()
        .map(|(index, slot)| {
            let mut body = [0; PUBLIC_BYTES];
            body[..48].copy_from_slice(&encode_digest(&digest(10_000 + index * 64)));
            body[48..96].copy_from_slice(&encode_digest(&digest(10_032 + index * 64)));
            Transaction {
                record: PublicRecord::new(
                    Snapshot {
                        height: witness.plan.block_height - 1,
                        block_id: [8; 32],
                    },
                    body,
                    encode_digest(&slot.commitment),
                )
                .expect("synthetic canonical public record"),
                // Deliberately opaque codec fill, never passed to a proof verifier.
                proof: vec![0; MAX_TX_PROOF],
            }
        })
        .collect();
    transactions.sort_by_key(|tx| tx.record.statement_id(&network));
    let mut block = Block {
        network,
        height: witness.plan.block_height,
        parent: [8; 32],
        timestamp: 1,
        target: [0xff; 32],
        nonce: 0,
        transactions,
        reward_mode: siworld_native_node::state::RewardMode::Holder,
        rewards: witness
            .reward_commitments()
            .iter()
            .enumerate()
            .map(|(index, commitment)| RewardRecord {
                commitment: encode_digest(commitment),
                ciphertext: [index as u8; REWARD_CIPHERTEXT_BYTES],
            })
            .collect(),
        fund_spends: Vec::new(),
        issuances: (0..RECORDS_CODEC_LIMIT)
            .map(|i| maximum_issuance_record(network, i as u64))
            .collect(),
        settlement_proof: vec![0; MAX_SETTLEMENT_PROOF],
    };
    let without_claims_len = block
        .encoded_len()
        .expect("canonical block length without claims");
    let without_claims_statement = settlement_statement(&block, &witness.plan);
    let without_claims_pow = block.pow_seed().expect("canonical codec PoW seed");
    block.fund_spends = spends;
    assert_eq!(
        settlement_statement(&block, &witness.plan),
        without_claims_statement
    );
    assert_ne!(
        block.pow_seed().expect("claim-bound PoW seed"),
        without_claims_pow
    );
    assert_eq!(
        block.encoded_len().unwrap() - without_claims_len,
        claim_bundle_bytes
    );
    let expected = BLOCK_FIXED_BYTES
        + (MAX_REWARDS - 1) * REWARD_RECORD_BYTES
        + MAX_FUND_SPENDS * ENCODED_BYTES
        + MAX_SLOTS * (4 + MAX_ENVELOPE_BYTES)
        + MAX_SETTLEMENT_PROOF
        + RECORDS_CODEC_LIMIT * (4 + MAX_RECORD_BYTES - 1);
    assert_eq!(block.encoded_len().unwrap(), expected);
    assert_eq!(expected + RECORDS_CODEC_LIMIT, MAX_BLOCK_BYTES);
    let receive_reservation = expected + MAX_ENVELOPE_BYTES + 65_536;
    let budget = Budget::new(CONNECTION_BYTES);
    let reservation = budget
        .reserve(receive_reservation)
        .expect("maximum receive reservation");
    assert!(
        budget
            .reserve(CONNECTION_BYTES - receive_reservation + 1)
            .is_err()
    );
    drop(reservation);

    let encode_started = Instant::now();
    let mut encoded = block.encode().expect("canonical maximum-size envelope");
    let block_encode_ns = encode_started.elapsed().as_nanos();
    assert_eq!(encoded.len(), expected);
    let decode_started = Instant::now();
    let decoded = Block::decode(&encoded, &network).expect("canonical maximum envelope decode");
    let block_decode_ns = decode_started.elapsed().as_nanos();
    assert!(
        decoded == block,
        "canonical maximum block changed during decode"
    );
    verify_claim_bundle(&decoded.fund_spends, network);
    drop(decoded);
    let decoded = Block::read_from(&mut Cursor::new(&encoded), encoded.len(), &network)
        .expect("bounded maximum-size streaming decode");
    assert!(
        decoded == block,
        "canonical maximum block changed during streaming decode"
    );
    drop(decoded);

    // The count is rejected before transaction/proof allocation in both decoders.
    encoded[BLOCK_HEADER_BYTES - 2] = 9;
    assert!(
        Block::decode(&encoded, &network)
            .expect_err("ninth claim must fail")
            .contains("fund expenditure count limit")
    );
    assert!(
        Block::read_from(&mut Cursor::new(&encoded), encoded.len(), &network)
            .expect_err("ninth streamed claim must fail")
            .to_string()
            .contains("fund expenditure count limit")
    );
    encoded[BLOCK_HEADER_BYTES - 2] = 8;
    drop(encoded);

    let compact = CompactBlock::from_block(&block).expect("maximum compact skeleton");
    let compact_bytes = compact.encode().expect("canonical compact skeleton");
    assert!(compact_bytes.len() <= MAX_COMPACT_BYTES);
    let decoded_compact = CompactBlock::decode(&compact_bytes, &network).expect("compact decode");
    assert!(
        decoded_compact
            .matches_block(&block)
            .expect("full skeleton binding")
    );
    verify_claim_bundle(&decoded_compact.fund_spends, network);
    block.fund_spends.insert(7, signed_claim(network, 7));
    assert!(block.encode().is_err());

    if let Ok(path) = std::env::var("SIWORLD_CLAIM_ENVELOPE_REPORT") {
        let report = json!({
            "schema": 1,
            "scope": "synthetic canonical maximum-size envelope and actual ML-DSA-65 claims",
            "fund_claims_measured": true,
            "claim_signatures_verified": 8,
            "claim_bundle_bytes": claim_bundle_bytes,
            "claim_generation_ns": claim_generation_ns,
            "claim_verification_ns": claim_verification_ns,
            "claim_verification_scope": "synthetic genesis key generation, canonical decoding and native signature checks",
            "wallet_account_limit": 32,
            "maximum_fund_claims_per_block": MAX_FUND_SPENDS,
            "transaction_slots": MAX_SLOTS,
            "reward_records": MAX_REWARDS,
            "issuance_records": RECORDS_CODEC_LIMIT,
            "block_envelope_bytes": expected,
            "maximum_block_bytes": MAX_BLOCK_BYTES,
            "compact_envelope_bytes": compact_bytes.len(),
            "maximum_compact_bytes": MAX_COMPACT_BYTES,
            "logical_receive_reservation_bytes": receive_reservation,
            "logical_connection_budget_bytes": CONNECTION_BYTES,
            "block_encode_ns": block_encode_ns,
            "block_decode_ns": block_decode_ns,
            "diagnostic_wall_ns": started.elapsed().as_nanos(),
            "settlement_statement_unchanged_by_claims": true,
            "pow_seed_binds_claims": true,
            "ninth_claim_rejected": true,
            "opaque_proof_fills": true,
            "transaction_proofs_verified": false,
            "settlement_proof_verified": false,
            "issuance_proofs_verified": false,
            "consensus_state_applied": false,
            "memory_rss_measured": false,
            "acceptance": false,
            "cryptographic_approval": false,
            "network_activation": false,
        });
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&report).expect("public metric encoding"),
        )
        .expect("public metric output");
    }
}
