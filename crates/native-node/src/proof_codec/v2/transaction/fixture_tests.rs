//! Explicit owner-only generation of one synthetic typed transaction proof.
//! No ledger, network, issuer, paid block or wallet-custody acceptance is implied.
use super::*;
use crate::proof_codec::v2::{backend::TransactionProver, native::NativeProofShape};
use ::native::{
    codec::{ProofContext, encode_digest},
    encryption::{
        EncryptionContext, RecipientViewKey, SenderChangeSecret, decrypt_change, encrypt_change,
        encrypt_payment,
    },
    multi_asset::{Hasher, Note, sample_witness},
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::{fs::OpenOptions, io::Write, path::Path};

fn write_new(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn check_note(actual: &Note, expected: &Note) {
    // Keep plaintext out of assertion diagnostics, including failure paths.
    assert!(
        actual.asset_id == expected.asset_id
            && actual.owner == expected.owner
            && actual.value == expected.value
            && actual.unlock_height == expected.unlock_height
            && actual.rho == expected.rho
            && actual.rseed == expected.rseed
    );
}

#[test]
#[cfg(unix)]
#[ignore = "requires a separately bounded owner-only grant for one V2 proof generation and a fresh output directory"]
fn generate_one_encrypted_typed_transaction_fixture() {
    use std::os::unix::fs::DirBuilderExt;
    assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
    assert_ne!(std::env::var("CI").as_deref(), Ok("true"));
    assert_eq!(
        std::env::var("SIWORLD_V2_TYPED_TRANSACTION_GENERATE").as_deref(),
        Ok("1")
    );
    let output = std::env::var_os("SIWORLD_V2_TYPED_TRANSACTION_OUTPUT")
        .expect("a separately approved absent output directory is required");
    let output = Path::new(&output);
    assert!(output.is_absolute());
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .unwrap();

    // This deterministic witness is synthetic. Fresh encryption keys, coins,
    // nonces and private proof-attempt randomness still use the OS source.
    let witness = sample_witness(0x2941);
    let hasher = Hasher::new();
    let fields = witness.slot.public_inputs(&hasher);
    let notes = core::array::from_fn::<_, 3, _>(|index| {
        witness.slot.output_note(&hasher, &fields.nf, index)
    });
    let network = [9; 32];
    let encryption = EncryptionContext::new(network);
    let recipient = RecipientViewKey::generate(notes[0].owner).unwrap();
    let change_secret = SenderChangeSecret::generate().unwrap();
    let public = PublicTransaction {
        nf: fields.nf,
        cm: fields.cm_out,
        payment: encrypt_payment(&recipient.address(), &notes[0], &encryption).unwrap(),
        change: core::array::from_fn(|index| {
            encrypt_change(&change_secret, &notes[index + 1], &encryption).unwrap()
        }),
    };
    check_note(
        &recipient
            .decrypt_payment(&public.cm[0], &public.payment, &encryption)
            .unwrap(),
        &notes[0],
    );
    for index in 0..2 {
        check_note(
            &decrypt_change(
                &change_secret,
                notes[index + 1].owner,
                &public.cm[index + 1],
                &public.change[index],
                &encryption,
            )
            .unwrap(),
            &notes[index + 1],
        );
    }
    let snapshot_height = witness.anchor_height.checked_add(1).unwrap();
    // These identifiers belong to this isolated fixture, not a selected chain
    // or an authenticated genesis registry. The full source is pinned outside.
    let snapshot_block_id: [u8; 32] =
        Sha256::digest(b"synthetic typed transaction snapshot v1").into();
    let context = ProofContext::for_snapshot(network, snapshot_height, snapshot_block_id);
    let bound = public.bind_witness(&witness, &context).unwrap();
    let root = bound.anchors_root(&hasher);
    let profile = Profile::transaction();
    let binding = ProtocolBinding {
        genesis: Sha256::digest(b"synthetic typed transaction genesis v1").into(),
        rules: Sha256::digest(b"synthetic typed transaction rules v1").into(),
        air: Sha256::digest(include_bytes!(
            "../../../../../bench-multi-asset/src/multi_asset_transaction.rs"
        ))
        .into(),
    };
    let prover = TransactionProver::new(profile).unwrap();
    let key = prover.verification_key().clone();
    let shape = NativeProofShape::from_trusted(
        &prover.air,
        &key,
        prover.public_config(),
        profile,
        Relation::Transaction,
        binding,
        MAX_TRANSACTION_PROOF_BYTES,
    )
    .unwrap();
    let maximum = shape.maximum_frame_bytes().unwrap();
    assert!(maximum <= MAX_TRANSACTION_PROOF_BYTES);
    let (proof, statement) = prover.prove_at_snapshot(&bound, snapshot_height).unwrap();
    assert_eq!(
        statement,
        public.statement(&context, &fields.fee_commit, &root)
    );
    let frame = shape.encode(&proof).unwrap();
    let expected = shape.identity();
    drop(proof);
    drop(prover);
    drop(bound);
    drop(witness);
    drop(recipient);
    drop(change_secret);
    let verifier =
        FixedTransactionVerifier::from_trusted(network, profile, binding, key.clone(), expected)
            .unwrap();
    let prepared = TransactionProof {
        public: public.clone(),
        context,
        fee: fields.fee_commit,
        root,
        proof: &frame,
    };
    assert_eq!(verifier.verify_prepared(&prepared), Ok(()));
    let encoded_public = public.encode();
    assert_eq!(PublicTransaction::decode(&encoded_public).unwrap(), public);
    let parameters = profile.params();
    let fixture = json!({
        "network":network,"genesis":binding.genesis,"rules":binding.rules,"air":binding.air,
        "expected_identity":expected.profile,
        "fri_parameters":[parameters.log_blowup,parameters.num_queries,parameters.query_pow_bits,
            parameters.commit_pow_bits,parameters.batch_pow_bits,parameters.max_log_arity],
        "key_width":key.width,"key_degree_bits":key.degree_bits,
        "key_commitment":postcard::to_allocvec(&key.commitment).unwrap(),
        "public_transaction":encoded_public.as_slice(),
        "fee_commitment":encode_digest(&fields.fee_commit).as_slice(),
        "recent_roots_root":encode_digest(&root).as_slice(),
        "snapshot_height":snapshot_height,"snapshot_block_id":snapshot_block_id,
        "proof_frame":frame,
    });
    let encoded = serde_json::to_vec(&fixture).unwrap();
    assert!(encoded.len() <= 4 * 1024 * 1024);
    // Only public bytes are persisted. The consumer must obtain and pin the
    // final fixture independently before its separate verification-only run.
    write_new(&output.join("fixture.json"), &encoded);
    let receipt = serde_json::to_vec(&json!({
        "version":1,"scope":"synthetic-encrypted-typed-v2-transaction-proof-only",
        "fixture_bytes":encoded.len(),"fixture_sha256":crate::local::hex(&Sha256::digest(&encoded)),
        "maximum_frame_bytes":maximum,"actual_typed_verification":true,
        "three_output_ciphertexts_locally_decrypted":true,
        "canonical_snapshot_membership_verified":false,"network_registered":false,
        "fee_payment_verified":false,"block_verified":false,"privacy_qualified":false,
    }))
    .unwrap();
    write_new(&output.join("receipt.json"), &receipt);
    std::fs::File::open(output).unwrap().sync_all().unwrap();
}
