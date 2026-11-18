//! Owner-local capture regression using actual retained-native transactions.
//! Fee frames and outputs here are syntactic fixtures, never admitted proofs.

use super::super::*;
use crate::eng2::{
    body::{Body, Policy},
    execution::PreparedBlock,
    genesis::FeeMode,
    header::Header,
    snapshot::{
        SnapshotState,
        tests::{binding, bootstrap, limits},
    },
};
use crate::{
    proofs::NativeVerifier,
    wire::{self, RewardRecord, Transaction},
};
use native::{codec::encode_digest, multi_asset::F};
use p3_field::PrimeCharacteristicRing;
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

struct Manifest {
    schema: u32,
    network: String,
    parent: String,
    snapshot_height: u64,
    snapshot_block: String,
    recent_root: String,
    proof_profile: String,
    transactions: Vec<Envelope>,
}

struct Envelope {
    bytes: u64,
    sha256: String,
}

fn manifest(bytes: &[u8]) -> Manifest {
    let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(object.len(), 8);
    let text = |key: &str| object[key].as_str().unwrap().to_owned();
    let transactions = object["transactions"].as_array().unwrap();
    assert_eq!(transactions.len(), wire::MIN_SLOTS);
    Manifest {
        schema: object["schema"].as_u64().unwrap().try_into().unwrap(),
        network: text("network"),
        parent: text("parent"),
        snapshot_height: object["snapshot_height"].as_u64().unwrap(),
        snapshot_block: text("snapshot_block"),
        recent_root: text("recent_root"),
        proof_profile: text("proof_profile"),
        transactions: transactions
            .iter()
            .map(|entry| {
                let entry = entry.as_object().unwrap();
                assert_eq!(entry.len(), 2);
                Envelope {
                    bytes: entry["bytes"].as_u64().unwrap(),
                    sha256: entry["sha256"].as_str().unwrap().to_owned(),
                }
            })
            .collect(),
    }
}

fn bounded_file(path: &Path, maximum: usize) -> Vec<u8> {
    let metadata = fs::symlink_metadata(path).expect("explicit public fixture file required");
    assert!(metadata.file_type().is_file());
    assert!(metadata.len() <= maximum as u64);
    let mut bytes = Vec::new();
    fs::File::open(path)
        .unwrap()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= maximum);
    bytes
}

fn load_transactions(parent: &SnapshotState) -> Vec<Transaction> {
    let directory = PathBuf::from(
        std::env::var_os("SIWORLD_OWNER01_TRANSACTIONS")
            .expect("set the closed public transaction fixture directory"),
    );
    assert!(directory.is_absolute());
    assert_eq!(directory.canonicalize().unwrap(), directory);
    let bytes = bounded_file(&directory.join("manifest.json"), 64 * 1024);
    let pin = std::env::var("SIWORLD_OWNER01_MANIFEST_SHA256")
        .expect("pin the exact reviewed public fixture manifest");
    assert_eq!(pin.len(), 64);
    assert!(
        pin.bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    );
    assert_eq!(crate::local::hex(&Sha256::digest(&bytes)), pin);
    let manifest = manifest(&bytes);
    let snapshot = parent.chain().tip_snapshot();
    assert_eq!(manifest.schema, 1);
    assert_eq!(manifest.network, crate::local::hex(&parent.network()));
    assert_eq!(manifest.parent, crate::local::hex(&parent.tip()));
    assert_eq!(manifest.snapshot_height, snapshot.selector.height);
    assert_eq!(
        manifest.snapshot_block,
        crate::local::hex(&snapshot.selector.block_id)
    );
    assert_eq!(
        manifest.recent_root,
        crate::local::hex(&snapshot.recent_root)
    );
    assert_eq!(
        manifest.proof_profile,
        crate::local::hex(&crate::proofs::protocol_profile_fingerprint())
    );
    assert_eq!(manifest.transactions.len(), wire::MIN_SLOTS);
    let mut transactions = manifest
        .transactions
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            assert!(
                (wire::TX_PREFIX_BYTES as u64 + 1..=wire::MAX_ENVELOPE_BYTES as u64)
                    .contains(&entry.bytes)
            );
            let bytes = bounded_file(
                &directory.join(format!("transaction-{index:04}.bin")),
                wire::MAX_ENVELOPE_BYTES,
            );
            assert_eq!(bytes.len() as u64, entry.bytes);
            assert_eq!(crate::local::hex(&Sha256::digest(&bytes)), entry.sha256);
            let transaction = Transaction::decode_envelope(&bytes, &parent.network()).unwrap();
            assert_eq!(transaction.record.snapshot, snapshot.selector);
            transaction
        })
        .collect::<Vec<_>>();
    transactions.sort_by_key(|tx| tx.record.statement_id(&parent.network()));
    transactions
}

fn policy() -> Policy {
    Policy {
        profile: crate::proofs::protocol_profile_fingerprint(),
        max_body_bytes: wire::MAX_BLOCK_BYTES + wire::REWARD_RECORD_BYTES,
        max_settlement_proof_bytes: MAX_FEE_PROOF_BYTES,
    }
}

fn body(parent: &SnapshotState, transactions: Vec<Transaction>, proof: Vec<u8>) -> Body {
    Body {
        network: parent.network(),
        height: 1,
        profile: policy().profile,
        transactions,
        reward_mode: wire::RewardMode::Voyager,
        rewards: vec![RewardRecord {
            commitment: encode_digest(&[F::from_u32(1_700_001); 12]),
            ciphertext: [90; wire::REWARD_CIPHERTEXT_BYTES],
        }],
        fee_output: RewardRecord {
            commitment: encode_digest(&[F::from_u32(1_700_002); 12]),
            ciphertext: [91; wire::REWARD_CIPHERTEXT_BYTES],
        },
        fund_claims: Vec::new(),
        governance: Vec::new(),
        issuances: Vec::new(),
        settlement_proof: proof,
    }
}

fn header(parent: &SnapshotState, body: &Body) -> Header {
    // One minimum-difficulty nonce; this test performs no work-search loop.
    assert!(parent.chain().config.fixture);
    assert_eq!(parent.chain().config.pow_iterations, 0);
    assert_eq!(parent.chain().next_target(), [255; 32]);
    Header {
        network: parent.network(),
        height: 1,
        parent: parent.tip(),
        timestamp: parent.chain().timestamp() + parent.chain().config.target_interval,
        target: parent.chain().next_target(),
        // No complete settlement or execution transition is asserted here.
        execution_commitment: [41; 32],
        body_commitment: body.commitment(policy()).unwrap(),
        nonce: 0,
    }
}

#[test]
#[ignore = "owner-local: requires 64 genuine retained-native transaction proofs for the exact confidential snapshot"]
fn real_native_capability_captures_only_its_held_body_frame() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    assert!(std::env::var_os("CI").is_none());
    let parent = bootstrap();
    assert_eq!(parent.fee_mode(), FeeMode::ConfidentialDestination);
    assert_eq!(parent.height(), 0);
    let context = binding(&parent, parent.tip());
    let component_binding = binding(&parent, [0; 32]);
    let before = parent
        .canonical_components(component_binding, limits().chain)
        .unwrap();
    let fingerprint = parent.chain().fingerprint();
    let factory = TrustedFactory::from_local_configuration(
        parent.network(),
        ProtocolBinding {
            genesis: context.genesis,
            rules: context.rules_commitment,
            air: complete_fee::source_identity(),
        },
        Identity {
            relation: Relation::CompleteFee,
            profile: [19; 32],
        },
    )
    .unwrap();
    // Deliberately syntactic frames: capture does no fee cryptography/setup.
    let frame_a = v2::encode(factory.identity(), &[1, 2, 3], MAX_FEE_PROOF_BYTES).unwrap();
    let frame_b = v2::encode(factory.identity(), &[4, 5, 6], MAX_FEE_PROOF_BYTES).unwrap();
    let body_a = body(&parent, load_transactions(&parent), frame_a.clone());
    let mut body_b = body_a.clone();
    body_b.settlement_proof = frame_b.clone();
    let header_a = header(&parent, &body_a);
    let header_b = header(&parent, &body_b);
    assert_ne!(header_a.body_commitment, header_b.body_commitment);
    assert!(PreparedBlock::prepare(&parent, &header_a, &body_b, context, policy()).is_err());

    // Actual native verification is the sole constructor of each capability.
    let verifier = NativeVerifier::new().unwrap();
    let mut bad_body = body_a.clone();
    bad_body.transactions[0].proof[0] ^= 1;
    let bad_header = header(&parent, &bad_body);
    assert!(
        PreparedBlock::prepare(&parent, &bad_header, &bad_body, context, policy())
            .unwrap()
            .verify_transactions(&verifier)
            .is_err()
    );
    drop(bad_body);
    let checked_a = NativeCheckedFeeInputs::from_native_checked(
        PreparedBlock::prepare(&parent, &header_a, &body_a, context, policy())
            .unwrap()
            .verify_transactions(&verifier)
            .unwrap(),
    )
    .unwrap();
    let checked_b = NativeCheckedFeeInputs::from_native_checked(
        PreparedBlock::prepare(&parent, &header_b, &body_b, context, policy())
            .unwrap()
            .verify_transactions(&verifier)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        checked_a.canonical_child_statement().unwrap(),
        checked_b.canonical_child_statement().unwrap()
    );
    // These opaque test captures do not claim production owner freshness.
    let request_a = factory
        .prepare(&checked_a, [1; 32], header_a.body_commitment)
        .unwrap();
    let request_b = factory
        .prepare(&checked_b, [2; 32], header_b.body_commitment)
        .unwrap();
    for (request, checked, expected) in [
        (&request_a, &checked_a, frame_a.as_slice()),
        (&request_b, &checked_b, frame_b.as_slice()),
    ] {
        assert!(std::ptr::eq(
            request.proof,
            checked.native_checked().body().settlement_proof.as_slice()
        ));
        assert_eq!(request.proof, expected);
        assert_eq!(request.binding().proof, fee_guard::proof_digest(expected));
        assert_eq!(
            request.binding().statement,
            fee_guard::statement_digest(&checked.canonical_child_statement().unwrap())
        );
    }
    assert_ne!(request_a.binding().proof, request_b.binding().proof);
    assert_eq!(request_a.binding().statement, request_b.binding().statement);
    assert_eq!(
        request_a.binding().canonical_context,
        header_a.body_commitment
    );
    assert_eq!(
        request_b.binding().canonical_context,
        header_b.body_commitment
    );
    assert_eq!(parent.chain().fingerprint(), fingerprint);
    assert_eq!(
        parent
            .canonical_components(component_binding, limits().chain)
            .unwrap(),
        before
    );
}

#[test]
#[ignore = "explicit owner-local generation of the missing 64-transaction confidential-snapshot fixture"]
fn generate_confidential_snapshot_transaction_fixture() {
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    assert!(std::env::var_os("CI").is_none());
    assert_eq!(
        std::env::var("SIWORLD_OWNER01_GENERATE").as_deref(),
        Ok("confidential-snapshot-transactions")
    );
    use native::{
        codec::{ProofContext, PublicTransaction, decode_digest},
        multi_asset::{Hasher, RecentRoots, sample_empty_witness},
        multi_asset_transaction::TransactionProver,
    };
    let directory = PathBuf::from(
        std::env::var_os("SIWORLD_OWNER01_TRANSACTIONS")
            .expect("set a new owner-local fixture output directory"),
    );
    assert!(directory.is_absolute() && !directory.exists());
    let parent = bootstrap();
    assert_eq!(parent.fee_mode(), FeeMode::ConfidentialDestination);
    let snapshot = parent.chain().tip_snapshot();
    let hasher = Hasher::new();
    let mut roots = RecentRoots::new();
    for entry in &parent.chain().snapshots {
        roots.insert(
            &hasher,
            entry.selector.height,
            &decode_digest(&entry.commitment_root).unwrap(),
            parent.fee_mode().base_fee(entry.selector.height).unwrap(),
        );
    }
    let tree = roots.tree(&hasher);
    assert_eq!(encode_digest(&tree.root()), snapshot.recent_root);
    let context = ProofContext::for_snapshot(
        parent.network(),
        snapshot.selector.height,
        snapshot.selector.block_id,
    );
    // The unchanged retained transaction profile only; no settlement setup.
    let prover = TransactionProver::new(native::FriParams {
        log_blowup: 7,
        num_queries: 41,
        query_pow_bits: 20,
        commit_pow_bits: 0,
        batch_pow_bits: 20,
        max_log_arity: 1,
    });
    let verifier = NativeVerifier::new().unwrap();
    fs::create_dir(&directory).unwrap();
    let mut entries = Vec::new();
    for index in 0..wire::MIN_SLOTS {
        let mut witness = sample_empty_witness(0x4f57_4e45_5200 + index as u64);
        witness.slot.anchor = decode_digest(&snapshot.commitment_root).unwrap();
        witness.anchor_height = snapshot.selector.height;
        witness.base_fee = parent
            .fee_mode()
            .base_fee(snapshot.selector.height)
            .unwrap();
        witness.anchor_path = tree.path(snapshot.selector.height);
        for output in &mut witness.slot.outputs {
            output.unlock_height = 0;
        }
        assert!(witness.slot.inputs.iter().all(|input| input.dummy));
        assert_eq!(witness.slot.fee, 0);
        let fields = witness.slot.public_inputs(&hasher);
        // Synthetic ciphertext bytes are committed by the real native proof.
        // This fixture does not test payment encryption or wallet privacy.
        let mut public_bytes = [0; wire::PUBLIC_BYTES];
        for (index, digest) in fields.nf.iter().chain(&fields.cm_out).enumerate() {
            public_bytes[index * 48..(index + 1) * 48].copy_from_slice(&encode_digest(digest));
        }
        let public = PublicTransaction::decode(&public_bytes).unwrap();
        let witness = public.bind_witness(&witness, &context).unwrap();
        witness
            .check_at_snapshot(&hasher, &tree.root(), snapshot.selector.height)
            .unwrap();
        let (proof, generated) = prover.prove_at_snapshot(&witness, snapshot.selector.height);
        assert_eq!(
            generated,
            public.statement(&context, &fields.fee_commit, &tree.root())
        );
        let proof = postcard::to_allocvec(&proof).unwrap();
        verifier
            .verify_transaction(&public, &context, &fields.fee_commit, &tree.root(), &proof)
            .unwrap();
        let transaction = Transaction {
            record: wire::PublicRecord::new(
                snapshot.selector,
                public.encode(),
                encode_digest(&fields.fee_commit),
            )
            .unwrap(),
            proof,
        };
        let bytes = transaction.encode_envelope(&parent.network()).unwrap();
        entries.push(serde_json::json!({
            "bytes": bytes.len(), "sha256": crate::local::hex(&Sha256::digest(&bytes)),
        }));
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(format!("transaction-{index:04}.bin")))
            .unwrap()
            .write_all(&bytes)
            .unwrap();
    }
    let manifest = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": 1,
        "network": crate::local::hex(&parent.network()),
        "parent": crate::local::hex(&parent.tip()),
        "snapshot_height": snapshot.selector.height,
        "snapshot_block": crate::local::hex(&snapshot.selector.block_id),
        "recent_root": crate::local::hex(&snapshot.recent_root),
        "proof_profile": crate::local::hex(&crate::proofs::protocol_profile_fingerprint()),
        "transactions": entries,
    }))
    .unwrap();
    // Completion marker is written only after all 64 independent verifications.
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("manifest.json"))
        .unwrap()
        .write_all(&manifest)
        .unwrap();
}
