//! Independent native-verification diagnostics with offline synthetic fixtures.
//!
//! Fixture creation is a separate command and process. Verification never
//! constructs preprocessing prover data or generates proofs. Repeating a
//! fixture measures cryptographic work only, not stateful block acceptance.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use siworld_native_proof::{
    FriParams,
    codec::{ProofContext, PublicTransaction},
    common::{self, F, FEE_BASE, Hasher, acc_witnesses, sample_slot},
    encryption::{
        EncryptionContext, OutputPairCiphertexts, RecipientViewKey, SenderChangeSecret,
        check_output_pair_before_broadcast, encrypt_change, encrypt_payment_with_opening,
    },
    envelope::{NativeEnvelope, SettlementEnvelope, SettlementEnvelopeContext},
    fee_settlement::{FeeOpening, SettlementSlot},
    fee_settlement_air::{FixedSettlementWitness, SettlementProver},
    native_verifier::{SettlementVerifier, TransactionVerifier, VerifierArtifact},
    proof_codec::ProofShape,
    snapshots::SnapshotId,
    transaction::TransactionProver,
};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

const SUITE: &str = "KoalaBear-D8-Poseidon2-W24-digest12";
const NETWORK: [u8; 32] = [9; 32];
const SNAPSHOT: SnapshotId = SnapshotId {
    height: 1000,
    block_id: [10; 32],
};

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}
fn unhex(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err("invalid trusted SHA-256 value".into());
    }
    let mut result = [0; 32];
    for (i, part) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        result[i] = u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap();
    }
    Ok(result)
}
fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    fs::File::open(path)
        .map_err(|_| "fixture file unavailable")?
        .take((maximum + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|_| "fixture read failed")?;
    if data.len() > maximum {
        return Err("fixture exceeds fixed input bound".into());
    }
    Ok(data)
}
fn write_new(path: &Path, data: &[u8]) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "refusing to overwrite fixture or report")?
        .write_all(data)
        .map_err(|_| "fixture write failed".into())
}
fn json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(value).map_err(|_| "JSON encoding failed".into())
}
fn field_bytes(public: &[F]) -> Vec<u8> {
    public
        .iter()
        .flat_map(|value| value.as_canonical_u32().to_le_bytes())
        .collect()
}
fn fields(bytes: &[u8], length: usize) -> Result<Vec<F>, String> {
    if bytes.len() != length * 4 {
        return Err("public statement length mismatch".into());
    }
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| {
            let n = u32::from_le_bytes(*word);
            if n >= F::ORDER_U32 {
                Err("noncanonical public statement field".into())
            } else {
                Ok(F::from_u32(n))
            }
        })
        .collect()
}
fn params_json() -> Value {
    let p = FriParams::transaction_candidate();
    json!({"log_blowup":p.log_blowup,"num_queries":p.num_queries,
        "query_pow_bits":p.query_pow_bits,"batch_pow_bits":p.batch_pow_bits,
        "commit_pow_bits":p.commit_pow_bits,"max_log_arity":p.max_log_arity})
}

fn prepare(directory: &Path) -> Result<(), String> {
    fs::create_dir(directory).map_err(|_| "fixture directory must be new")?;
    let p = FriParams::transaction_candidate();
    let mut witness = acc_witnesses(vec![sample_slot(61, false)], SNAPSHOT.height, FEE_BASE, 62)
        .0
        .remove(0);
    let hasher = Hasher::new();
    let inputs = witness.slot.public_inputs(&hasher);
    let notes = [
        witness.slot.output_note(&hasher, &inputs.nf, 0),
        witness.slot.output_note(&hasher, &inputs.nf, 1),
    ];
    let recipient =
        RecipientViewKey::generate(notes[0].owner).map_err(|_| "payment fixture key failed")?;
    let sender = SenderChangeSecret::generate().map_err(|_| "change fixture key failed")?;
    let encryption = EncryptionContext::new(NETWORK);
    let (payment, opening) =
        encrypt_payment_with_opening(&recipient.address(), &notes[0], &encryption)
            .map_err(|_| "payment fixture encryption failed")?;
    let change = encrypt_change(&sender, &notes[1], &encryption)
        .map_err(|_| "change fixture encryption failed")?;
    let pair = check_output_pair_before_broadcast(
        OutputPairCiphertexts {
            commitments: inputs.cm_out,
            payment,
            change,
        },
        &notes,
        &recipient.address(),
        &opening,
        &sender,
        &encryption,
    )
    .map_err(|_| "fixture output check failed")?;
    let public = PublicTransaction {
        nf: inputs.nf,
        cm: *pair.commitments(),
        payment: pair.payment().clone(),
        change: pair.change().clone(),
    };
    let context = ProofContext::for_snapshot(NETWORK, SNAPSHOT.height, SNAPSHOT.block_id);
    witness = public
        .bind_witness(&witness, &context)
        .map_err(|_| "fixture witness binding failed")?;
    let root = witness.anchors_root(&hasher);
    let prover = TransactionProver::new(p);
    let (proof, statement) = prover.prove(&witness);
    prover.verify(&proof, &statement)?;
    let proof = postcard::to_allocvec(&proof).map_err(|_| "fixture proof encoding failed")?;
    let shape = ProofShape::from_trusted(&prover.air, &prover.vk, &prover.cfg)
        .map_err(|e| e.to_string())?;
    let envelope =
        NativeEnvelope::from_parts(NETWORK, SNAPSHOT, public, inputs.fee_commit, &proof, &shape)
            .map_err(|e| format!("fixture envelope: {e:?}"))?
            .encode(&shape)
            .map_err(|e| format!("fixture envelope: {e:?}"))?;
    let key = VerifierArtifact::transaction(&prover)?;
    let transaction = json!({"vk_sha256":hex(&key.sha256()),"envelope_sha256":hex(&sha(&envelope)),"root_sha256":hex(&sha(&field_bytes(&root)))});
    write_new(&directory.join("transaction.vk"), &key.encode())?;
    write_new(&directory.join("transaction.envelope"), &envelope)?;
    write_new(&directory.join("transaction.root"), &field_bytes(&root))?;
    drop(prover);
    let slots = (0..576)
        .map(|i| {
            let blind = core::array::from_fn(|k| {
                F::from_u32(1000 + (i * common::FEE_BLIND_LEN + k) as u32)
            });
            SettlementSlot::from_opening(
                &hasher,
                if i == 0 {
                    FeeOpening::standard(blind)
                } else {
                    FeeOpening::dummy(blind)
                },
            )
        })
        .collect();
    let transaction_ids: Vec<[u8; 32]> = (0u64..576).map(|i| sha(&i.to_le_bytes())).collect();
    let miner_owner = core::array::from_fn(|i| F::from_u32(800 + i as u32));
    let miner_rseed = core::array::from_fn(|i| F::from_u32(900 + i as u32));
    let miner_amount = 100 + FEE_BASE;
    let miner_commitment =
        hasher.miner_note_cm(miner_amount, SNAPSHOT.height, &miner_owner, &miner_rseed);
    let context = SettlementEnvelopeContext::from_transactions(
        NETWORK,
        SNAPSHOT.height,
        &transaction_ids,
        miner_commitment,
    )
    .map_err(|_| "settlement fixture context failed")?;
    let witness = FixedSettlementWitness {
        issuance_reward: 100,
        miner_amount,
        block_height: SNAPSHOT.height,
        network: NETWORK,
        transaction_list_digest: context.transaction_list_digest,
        miner_owner,
        miner_rseed,
        slots,
    };
    let prover = SettlementProver::new(576, p);
    let (proof, statement) = prover.prove(&witness);
    prover.verify(&proof, &statement)?;
    let proof = postcard::to_allocvec(&proof).map_err(|_| "settlement fixture encoding failed")?;
    let commitments: Vec<_> = witness.slots.iter().map(|slot| slot.commitment).collect();
    let reconstructed = context
        .public_inputs(&commitments, 100)
        .map_err(|_| "settlement fixture statement reconstruction failed")?;
    if reconstructed != statement {
        return Err("settlement fixture statement mismatch".into());
    }
    let shape = ProofShape::from_trusted(&prover.air, &prover.vk, &prover.cfg)
        .map_err(|e| e.to_string())?;
    let envelope = SettlementEnvelope::from_parts(context, &proof, &shape)
        .map_err(|_| "settlement fixture envelope failed")?
        .encode(&shape)
        .map_err(|_| "settlement fixture envelope encoding failed")?;
    let commitment_bytes: Vec<u8> = commitments
        .iter()
        .flat_map(|value| field_bytes(value))
        .collect();
    let transaction_id_bytes: Vec<u8> = transaction_ids.into_iter().flatten().collect();
    let key = VerifierArtifact::settlement(&prover)?;
    let settlement = json!({"vk_sha256":hex(&key.sha256()),"envelope_sha256":hex(&sha(&envelope)),
        "commitments_sha256":hex(&sha(&commitment_bytes)),"transaction_ids_sha256":hex(&sha(&transaction_id_bytes)),
        "miner_note_commitment":miner_commitment.map(|value| value.as_canonical_u32()),
        "issuance_reward":100,"statement":"confidential-miner-note-v1"});
    write_new(&directory.join("settlement.vk"), &key.encode())?;
    write_new(&directory.join("settlement.envelope"), &envelope)?;
    write_new(&directory.join("settlement.commitments"), &commitment_bytes)?;
    write_new(
        &directory.join("settlement.transaction-ids"),
        &transaction_id_bytes,
    )?;
    write_new(
        &directory.join("manifest.json"),
        &json_bytes(&json!({"schema":1,"suite":SUITE,
        "parameters":params_json(),"network":NETWORK,"snapshot":{"height":SNAPSHOT.height,"block_id":SNAPSHOT.block_id},
        "transaction":transaction,"settlement":settlement,"synthetic_fixtures":true}))?,
    )?;
    Ok(())
}

fn authenticated_file(
    directory: &Path,
    manifest: &Value,
    key: &str,
    filename: &str,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let bytes = read_bounded(&directory.join(filename), maximum)?;
    let expected = unhex(manifest[key].as_str().ok_or("missing fixture identity")?)?;
    if sha(&bytes) != expected {
        return Err("trusted fixture identity mismatch".into());
    }
    Ok(bytes)
}

fn verify(
    directory: &Path,
    manifest_sha: [u8; 32],
    kind: &str,
    output: &Path,
) -> Result<(), String> {
    if std::env::var("RAYON_NUM_THREADS").as_deref() != Ok("1")
        || p3_maybe_rayon::prelude::current_num_threads() != 1
    {
        return Err("independent verifier requires exactly one worker".into());
    }
    let start = Instant::now();
    let manifest = read_bounded(&directory.join("manifest.json"), 16384)?;
    if sha(&manifest) != manifest_sha {
        return Err("fixture manifest authentication failed".into());
    }
    let manifest: Value =
        serde_json::from_slice(&manifest).map_err(|_| "invalid fixture manifest")?;
    if manifest["schema"] != 1
        || manifest["suite"] != SUITE
        || manifest["parameters"] != params_json()
        || manifest["network"] != json!(NETWORK)
        || manifest["snapshot"]["height"] != SNAPSHOT.height
        || manifest["snapshot"]["block_id"] != json!(SNAPSHOT.block_id)
    {
        return Err("fixture context or parameters mismatch".into());
    }
    let calls = if kind == "block576" { 576 } else { 1 };
    let mut durations = Vec::with_capacity(calls);
    let (loading_ns, proof_body_bytes) = if kind == "transaction" || kind == "block576" {
        let metadata = &manifest["transaction"];
        let key = authenticated_file(directory, metadata, "vk_sha256", "transaction.vk", 8192)?;
        let verifier = TransactionVerifier::load(
            &key,
            unhex(metadata["vk_sha256"].as_str().ok_or("missing key hash")?)?,
        )?;
        let envelope = authenticated_file(
            directory,
            metadata,
            "envelope_sha256",
            "transaction.envelope",
            526187,
        )?;
        let root = authenticated_file(directory, metadata, "root_sha256", "transaction.root", 48)?;
        let root: common::Digest = fields(&root, 12)?
            .try_into()
            .map_err(|_| "invalid root length")?;
        let loading_ns = start.elapsed().as_nanos();
        let mut proof_bytes = 0;
        for _ in 0..calls {
            let started = Instant::now();
            let transaction = NativeEnvelope::decode(&envelope, &NETWORK, &verifier.shape)
                .map_err(|e| format!("envelope decode: {e:?}"))?;
            if transaction.snapshot_id() != SNAPSHOT {
                return Err("untrusted snapshot selection".into());
            }
            let statement = transaction.transaction().statement(
                &transaction.context(),
                transaction.fee_commit(),
                &root,
            );
            verifier.verify_bytes(transaction.proof_body(), &statement)?;
            durations.push(started.elapsed().as_nanos() as u64);
            proof_bytes = transaction.proof_body().len();
        }
        (loading_ns, proof_bytes)
    } else if kind == "settlement" {
        let metadata = &manifest["settlement"];
        let key = authenticated_file(directory, metadata, "vk_sha256", "settlement.vk", 8192)?;
        let verifier = SettlementVerifier::load(
            &key,
            unhex(metadata["vk_sha256"].as_str().ok_or("missing key hash")?)?,
        )?;
        let envelope = authenticated_file(
            directory,
            metadata,
            "envelope_sha256",
            "settlement.envelope",
            524447,
        )?;
        let commitment_bytes = authenticated_file(
            directory,
            metadata,
            "commitments_sha256",
            "settlement.commitments",
            576 * 48,
        )?;
        let commitment_fields = fields(&commitment_bytes, 576 * 12)?;
        let commitments: Vec<common::Digest> = commitment_fields.as_chunks::<12>().0.to_vec();
        let ids = authenticated_file(
            directory,
            metadata,
            "transaction_ids_sha256",
            "settlement.transaction-ids",
            576 * 32,
        )?;
        if ids.len() != 576 * 32 {
            return Err("settlement transaction identity length mismatch".into());
        }
        let ids: Vec<[u8; 32]> = ids.as_chunks::<32>().0.to_vec();
        let commitment = metadata["miner_note_commitment"]
            .as_array()
            .ok_or("missing trusted miner commitment")?;
        if commitment.len() != 12
            || metadata["issuance_reward"] != 100
            || metadata["statement"] != "confidential-miner-note-v1"
        {
            return Err("invalid trusted settlement context".into());
        }
        let mut miner_commitment = [F::ZERO; 12];
        for (destination, value) in miner_commitment.iter_mut().zip(commitment) {
            let value = value
                .as_u64()
                .filter(|value| *value < F::ORDER_U32 as u64)
                .ok_or("noncanonical trusted miner commitment")?;
            *destination = F::from_u32(value as u32);
        }
        let context = SettlementEnvelopeContext::from_transactions(
            NETWORK,
            SNAPSHOT.height,
            &ids,
            miner_commitment,
        )
        .map_err(|_| "invalid trusted settlement context")?;
        let loading_ns = start.elapsed().as_nanos();
        let started = Instant::now();
        let decoded = SettlementEnvelope::decode(&envelope, &context, &verifier.shape)
            .map_err(|_| "settlement envelope validation failed")?;
        let public = context
            .public_inputs(&commitments, 100)
            .map_err(|_| "settlement statement reconstruction failed")?;
        verifier.verify_bytes(decoded.proof_body(), &public)?;
        durations.push(started.elapsed().as_nanos() as u64);
        (loading_ns, decoded.proof_body().len())
    } else {
        return Err("unknown verifier workload".into());
    };
    let total: u64 = durations.iter().sum();
    durations.sort_unstable();
    let report = json!({"schema":1,"suite":SUITE,"parameters":params_json(),"kind":kind,
        "verification_only":true,"workers":1,"setup_performed":false,"generation_calls":0,
        "verification_calls":calls,"unique_proof_count":1,"stateful_block_validation":false,
        "workload_description":if calls==576 {"576 independent cryptographic checks of one repeated proof; repeated nullifiers are not a valid block"} else {"one independent native proof verification"},
        "wire_codec":if kind=="settlement" {"SWST-v1"} else {"SWTX-v1"},
        "statement_reconstructed":true,"verified":true,"loading_ns":loading_ns,"verification_ns":total,"proof_body_bytes":proof_body_bytes,
        "per_proof_wall_min_ns":durations[0],"per_proof_wall_median_ns":durations[durations.len()/2],
        "per_proof_wall_max_ns":durations[durations.len()-1]});
    write_new(output, &json_bytes(&report)?)
}

fn run() -> Result<(), String> {
    let mut values = BTreeMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(name) = args.next() {
        if ![
            "--prepare-fixtures",
            "--kind",
            "--fixtures",
            "--fixture-manifest-sha256",
            "--output",
        ]
        .contains(&name.as_str())
            || values.contains_key(&name)
        {
            return Err("unknown or duplicate argument".into());
        }
        values.insert(name, args.next().ok_or("missing argument value")?);
    }
    if let Some(directory) = values.get("--prepare-fixtures") {
        if values.len() != 1 {
            return Err("fixture preparation must run as a separate command".into());
        }
        return prepare(&PathBuf::from(directory));
    }
    if values.len() != 4 {
        return Err("verifier needs workload, fixtures, trusted manifest hash and output".into());
    }
    verify(
        &PathBuf::from(
            values
                .get("--fixtures")
                .ok_or("missing fixture directory")?,
        ),
        unhex(
            values
                .get("--fixture-manifest-sha256")
                .ok_or("missing trusted fixture manifest hash")?,
        )?,
        values.get("--kind").ok_or("missing workload")?,
        &PathBuf::from(values.get("--output").ok_or("missing output")?),
    )
}
fn main() {
    if let Err(error) = run() {
        eprintln!("native verifier diagnostic failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_hashes_have_one_canonical_text_representation() {
        let value = sha(b"public verifier fixture");
        let encoded = hex(&value);
        assert_eq!(unhex(&encoded).unwrap(), value);
        for invalid in [
            encoded.to_uppercase(),
            format!("{encoded}00"),
            "zz".repeat(32),
        ] {
            assert!(unhex(&invalid).is_err());
        }
    }

    #[test]
    fn public_statement_fields_reject_lengths_and_noncanonical_aliases() {
        let values = [F::ZERO, F::ONE, F::from_u32(F::ORDER_U32 - 1)];
        let encoded = field_bytes(&values);
        assert_eq!(fields(&encoded, 3).unwrap(), values);
        assert!(fields(&encoded[..encoded.len() - 1], 3).is_err());
        let mut invalid = encoded;
        invalid[..4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
        assert!(fields(&invalid, 3).is_err());
    }
}
