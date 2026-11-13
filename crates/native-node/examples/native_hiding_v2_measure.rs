//! Manual, offline measurements of actual native hiding V2 proofs.
//!
//! This example is excluded from workflows and never joins a network. It emits
//! public proofs, public verification metadata and sanitized timing records.
//! The retained settlement fixture does not specify eng-2 fee economics.
use native::{
    issuance::{
        AssetMetadata, ISSUER_KEY_BYTES, ISSUER_SIGNATURE_BYTES, IssuanceDeclaration,
        IssuancePolicy, SignedIssuance, sample_issuance,
    },
    multi_asset::{AssetId, DCT_BYTES, Digest, F, Hasher, sample_witness},
    multi_asset_transaction::statement_for,
    settlement::{
        RewardAllocation, RewardMode, RewardPlan, sample_fixed_settlement_witness,
        settlement_public,
    },
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_uni_stark::PreprocessedVerifierKey;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use siworld_native_node::proof_codec::v2::backend::{
    Config, IssuanceProver, IssuanceVerifier, Profile, SettlementProver, SettlementVerifier,
    TransactionProver, TransactionVerifier,
};
use siworld_native_node::proof_codec::v2::{ProtocolBinding, Relation, native::NativeProofShape};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::Instant,
};

type Result<T> = std::result::Result<T, String>;
const MANIFEST_LIMIT: usize = 1_048_576;
const RETAINED_NATIVE_FRAME_LIMIT: usize = 655_360;
const THREADS: usize = 4;
const SNAPSHOT_HEIGHT: u64 = 12_289;
const SETTLEMENT_CAPACITY: usize = 576;
const ISSUANCE_NOTES: usize = 3;

#[derive(Clone, Copy)]
enum Family {
    Transaction,
    Settlement,
    Issuance,
}
impl Family {
    fn parse(name: &str) -> Result<Self> {
        match name {
            "transaction" => Ok(Self::Transaction),
            "settlement576" => Ok(Self::Settlement),
            "issuance3" => Ok(Self::Issuance),
            _ => Err("expected transaction, settlement576 or issuance3".into()),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Transaction => "transaction",
            Self::Settlement => "settlement576",
            Self::Issuance => "issuance3",
        }
    }
    fn relation(self) -> Relation {
        match self {
            Self::Transaction => Relation::Transaction,
            Self::Settlement => Relation::Settlement,
            Self::Issuance => Relation::Issuance,
        }
    }
    fn profile(self) -> Profile {
        match self {
            Self::Transaction => Profile::transaction(),
            Self::Settlement => Profile::settlement(),
            Self::Issuance => Profile::issuance(),
        }
    }
    fn limit(self) -> usize {
        if matches!(self, Self::Issuance) {
            524_288
        } else {
            RETAINED_NATIVE_FRAME_LIMIT
        }
    }
    fn binding(self) -> ProtocolBinding {
        let mut air = Sha256::new();
        air.update(b"offline native hiding V2 measurement AIR source closure v1");
        air.update(self.name().as_bytes());
        for source in [
            include_bytes!("../../bench-d8/src/lib.rs").as_slice(),
            include_bytes!("../../bench-d8/src/air.rs").as_slice(),
            include_bytes!("../../bench-d8/src/common.rs").as_slice(),
            include_bytes!("../../bench-d8/src/fee_settlement.rs").as_slice(),
            include_bytes!("../../bench-multi-asset/src/multi_asset.rs").as_slice(),
            include_bytes!("../../bench-multi-asset/src/multi_asset_air.rs").as_slice(),
            include_bytes!("../../bench-multi-asset/src/multi_asset_transaction.rs").as_slice(),
            include_bytes!("../../bench-multi-asset/src/settlement.rs").as_slice(),
            include_bytes!("../../bench-multi-asset/src/issuance_air.rs").as_slice(),
            include_bytes!("../../bench-multi-asset/src/issuance.rs").as_slice(),
            include_bytes!("../../bench-multi-asset/src/confidential_fees.rs").as_slice(),
        ] {
            air.update((source.len() as u64).to_le_bytes());
            air.update(source);
        }
        ProtocolBinding {
            genesis: sha(b"offline synthetic native hiding V2 fixture genesis v1"),
            rules: sha(b"offline native hiding V2 measurement rules v1;settlement576;issuance3"),
            air: air.finalize().into(),
        }
    }
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str, maximum: usize) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.len() > maximum.saturating_mul(2) {
        return Err("invalid public byte encoding length".into());
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |b| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err("noncanonical public hex encoding".to_string()),
            };
            Ok(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect()
}
fn number(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| "invalid public integer".into())
}
fn string(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| "invalid public string".into())
}
fn array(value: &Value, expected: usize) -> Result<&[Value]> {
    let values = value.as_array().ok_or("invalid public array")?;
    if values.len() != expected {
        return Err("public array length mismatch".into());
    }
    Ok(values)
}
fn bytes<const N: usize>(value: &Value) -> Result<[u8; N]> {
    unhex(string(value)?, N)?
        .try_into()
        .map_err(|_| "public byte length mismatch".into())
}
fn digest(value: &Value) -> Result<Digest> {
    let mut result = [F::ZERO; 12];
    for (slot, value) in result.iter_mut().zip(array(value, 12)?) {
        let integer = u32::try_from(number(value)?).map_err(|_| "public field overflow")?;
        let field = F::from_u32(integer);
        if field.as_canonical_u32() != integer {
            return Err("noncanonical public field".into());
        }
        *slot = field;
    }
    Ok(result)
}
fn digests<const N: usize>(value: &Value) -> Result<[Digest; N]> {
    array(value, N)?
        .iter()
        .map(digest)
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| "public digest count mismatch".into())
}
fn public_digest(digest: &Digest) -> Vec<u32> {
    digest
        .iter()
        .map(|field| field.as_canonical_u32())
        .collect()
}
fn public_digests(digests: &[Digest]) -> Vec<Vec<u32>> {
    digests.iter().map(public_digest).collect()
}
fn phase<T>(
    family: Family,
    name: &str,
    times: &mut BTreeMap<String, u64>,
    work: impl FnOnce() -> Result<T>,
) -> Result<T> {
    eprintln!(
        "{}",
        json!({"event":"phase_start","relation":family.name(),"phase":name})
    );
    let start = Instant::now();
    let result = work();
    let micros = u64::try_from(start.elapsed().as_micros()).map_err(|_| "duration overflow")?;
    times.insert(name.into(), micros);
    eprintln!(
        "{}",
        json!({"event":"phase_end","relation":family.name(),"phase":name,"wall_microseconds":micros,"passed":result.is_ok()})
    );
    result
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "cannot create measurement artifact")?;
    file.write_all(bytes)
        .map_err(|_| "cannot write measurement artifact")?;
    file.sync_all()
        .map_err(|_| "cannot persist measurement artifact".to_string())
}
fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let length = fs::metadata(path)
        .map_err(|_| "measurement artifact unavailable")?
        .len();
    if length == 0 || length > maximum as u64 {
        return Err("measurement artifact length rejected".into());
    }
    let mut data = Vec::new();
    fs::File::open(path)
        .map_err(|_| "cannot open measurement artifact")?
        .take(maximum as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "cannot read measurement artifact")?;
    if data.len() > maximum {
        return Err("measurement artifact grew beyond bound".into());
    }
    Ok(data)
}
fn key_json(key: &PreprocessedVerifierKey<Config>) -> Result<Value> {
    let commitment =
        postcard::to_allocvec(&key.commitment).map_err(|_| "public key encoding failed")?;
    Ok(json!({"width":key.width,"degree_bits":key.degree_bits,"commitment":hex(&commitment)}))
}
fn read_key(value: &Value) -> Result<PreprocessedVerifierKey<Config>> {
    let commitment = unhex(string(&value["commitment"])?, 4096)?;
    let (commitment, tail) =
        postcard::take_from_bytes(&commitment).map_err(|_| "public key decoding failed")?;
    if !tail.is_empty() {
        return Err("public key trailing bytes rejected".into());
    }
    Ok(PreprocessedVerifierKey {
        width: usize::try_from(number(&value["width"])?)
            .map_err(|_| "public key width overflow")?,
        degree_bits: usize::try_from(number(&value["degree_bits"])?)
            .map_err(|_| "public key degree overflow")?,
        commitment,
    })
}
fn transaction_context() -> (native::multi_asset::AccWitness, Value) {
    let witness = sample_witness(0x2941);
    let hasher = Hasher::new();
    let inputs = witness.slot.public_inputs(&hasher);
    let context = json!({
        "nullifiers":public_digests(&inputs.nf),"commitments":public_digests(&inputs.cm_out),
        "ciphertext_digest":hex(&witness.d_ct),"fee_commitment":public_digest(&inputs.fee_commit),
        "recent_roots_root":public_digest(&witness.anchors_root(&hasher)),"snapshot_height":SNAPSHOT_HEIGHT,
    });
    (witness, context)
}
fn transaction_public(context: &Value) -> Result<Vec<F>> {
    let ciphertext: [u8; DCT_BYTES] = bytes(&context["ciphertext_digest"])?;
    Ok(statement_for(
        &digests(&context["nullifiers"])?,
        &digests(&context["commitments"])?,
        &ciphertext,
        &digest(&context["fee_commitment"])?,
        &digest(&context["recent_roots_root"])?,
        number(&context["snapshot_height"])?,
    ))
}
fn settlement_context(witness: &native::settlement::FixedSettlementWitness) -> Value {
    json!({"fees":public_digests(&witness.slots.iter().map(|slot|slot.commitment).collect::<Vec<_>>()),
        "height":witness.plan.block_height,"mode":witness.plan.mode as u8,
        "allocations":witness.plan.allocations.iter().map(|a|json!({"amount":a.amount,"unlock_height":a.unlock_height})).collect::<Vec<_>>(),
        "network":hex(&witness.network),"list_digest":hex(&witness.transaction_list_digest),
        "reward_commitments":public_digests(&witness.reward_commitments())})
}
fn settlement_statement(context: &Value) -> Result<Vec<F>> {
    if number(&context["mode"])? != 1 {
        return Err("expected Holder fixture".into());
    }
    let allocations = array(&context["allocations"], 5)?
        .iter()
        .map(|a| {
            Ok(RewardAllocation {
                amount: number(&a["amount"])?,
                unlock_height: number(&a["unlock_height"])?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let fees = array(&context["fees"], SETTLEMENT_CAPACITY)?
        .iter()
        .map(digest)
        .collect::<Result<Vec<_>>>()?;
    settlement_public(
        &fees,
        &RewardPlan {
            block_height: number(&context["height"])?,
            mode: RewardMode::Holder,
            allocations,
        },
        bytes(&context["network"])?,
        bytes(&context["list_digest"])?,
        &digests::<5>(&context["reward_commitments"])?,
    )
}
fn issuance_context(
    signed: &SignedIssuance,
    ciphertexts: &[Vec<u8>],
    policy: IssuancePolicy,
) -> Result<Value> {
    let declaration = &signed.declaration;
    Ok(
        json!({"network":hex(&declaration.network),"version":declaration.version,
        "issuer_key":hex(&declaration.issuer_key),"sequence":declaration.sequence,"asset_id":hex(&declaration.asset_id.0),
        "supply":declaration.public_supply,"name":declaration.metadata.name,"decimals":declaration.metadata.decimals,
        "fee_atoms":declaration.issuance_fee_atoms,"commitments":public_digests(&declaration.note_commitments),
        "ciphertext_digests":declaration.note_ciphertext_digests.iter().map(|d|hex(d)).collect::<Vec<_>>(),
        "signature":hex(signed.signature.as_ref().ok_or("fixture signature unavailable")?),
        "ciphertexts":ciphertexts.iter().map(|ciphertext|hex(ciphertext)).collect::<Vec<_>>(),
        "policy":{"max_notes":policy.max_notes,"metadata_limit":policy.max_metadata_bytes,
            "ciphertext_limit":policy.max_ciphertext_bytes_per_note,"fee_atoms":policy.required_fee_atoms}}),
    )
}
fn issuance_statement(context: &Value) -> Result<(SignedIssuance, Vec<Vec<u8>>, IssuancePolicy)> {
    let policy = &context["policy"];
    if number(&policy["max_notes"])? != ISSUANCE_NOTES as u64
        || number(&policy["metadata_limit"])? != 256
        || number(&policy["ciphertext_limit"])? != 4096
        || number(&policy["fee_atoms"])? != 123
    {
        return Err("issuance fixture policy mismatch".into());
    }
    let name = string(&context["name"])?;
    if name.len() > 256 {
        return Err("fixture metadata too large".into());
    }
    let declaration = IssuanceDeclaration {
        network: bytes(&context["network"])?,
        version: u32::try_from(number(&context["version"])?).map_err(|_| "version overflow")?,
        issuer_key: bytes::<ISSUER_KEY_BYTES>(&context["issuer_key"])?,
        sequence: number(&context["sequence"])?,
        asset_id: AssetId(bytes(&context["asset_id"])?),
        public_supply: number(&context["supply"])?,
        metadata: AssetMetadata {
            name: name.into(),
            decimals: u8::try_from(number(&context["decimals"])?)
                .map_err(|_| "decimals overflow")?,
        },
        issuance_fee_atoms: number(&context["fee_atoms"])?,
        note_commitments: digests::<ISSUANCE_NOTES>(&context["commitments"])?.to_vec(),
        note_ciphertext_digests: array(&context["ciphertext_digests"], ISSUANCE_NOTES)?
            .iter()
            .map(bytes)
            .collect::<Result<Vec<_>>>()?,
    };
    let ciphertexts = array(&context["ciphertexts"], ISSUANCE_NOTES)?
        .iter()
        .map(|value| unhex(string(value)?, 4096))
        .collect::<Result<Vec<_>>>()?;
    Ok((
        SignedIssuance {
            declaration,
            signature: Some(bytes::<ISSUER_SIGNATURE_BYTES>(&context["signature"])?),
        },
        ciphertexts,
        IssuancePolicy {
            max_notes: ISSUANCE_NOTES,
            max_metadata_bytes: 256,
            max_ciphertext_bytes_per_note: 4096,
            required_fee_atoms: 123,
        },
    ))
}

fn finish(
    family: Family,
    output: &Path,
    context: Value,
    key: Value,
    frame: &[u8],
    maximum: usize,
    times: BTreeMap<String, u64>,
) -> Result<()> {
    let binding = family.binding();
    let manifest = json!({"schema":1,"relation":family.name(),"threads":THREADS,"profile":hex(&family.profile().id()),
        "binding":{"genesis":hex(&binding.genesis),"rules":hex(&binding.rules),"air":hex(&binding.air)},
        "key":key,"public_context":context,"proof_sha256":hex(&sha(frame)),"proof_bytes":frame.len(),
        "frame_limit":family.limit(),"maximum_frame_bytes":maximum,"source_commit":option_env!("SIWORLD_SOURCE_COMMIT")});
    let encoded = serde_json::to_vec_pretty(&manifest).map_err(|_| "manifest encoding failed")?;
    write_new(&output.join("proof.frame"), frame)?;
    write_new(&output.join("public-manifest.json"), &encoded)?;
    let report = json!({"status":"actual_native_v2_roundtrip_passed","relation":family.name(),"threads":THREADS,
        "proof_bytes":frame.len(),"maximum_frame_bytes":maximum,"frame_limit":family.limit(),
        "public_manifest_sha256":hex(&sha(&encoded)),"proof_sha256":hex(&sha(frame)),"phase_wall_microseconds":times,
        "peak_rss_bytes":null,"cpu_microseconds":null,"network_activation":false,"complete_fee_qualified":false});
    write_new(
        &output.join("measurement.json"),
        &serde_json::to_vec_pretty(&report).map_err(|_| "report encoding failed")?,
    )?;
    println!("{report}");
    Ok(())
}
fn measure(family: Family, output: &Path) -> Result<()> {
    fs::create_dir(output).map_err(|_| "use a new dedicated measurement directory")?;
    let profile = family.profile();
    let binding = family.binding();
    let mut times = BTreeMap::new();
    match family {
        Family::Transaction => {
            let (witness, context) =
                phase(family, "fixture", &mut times, || Ok(transaction_context()))?;
            let public = transaction_public(&context)?;
            let prover = phase(family, "public_setup", &mut times, || {
                TransactionProver::new(profile)
            })?;
            let verifier =
                TransactionVerifier::from_trusted_key(profile, prover.verification_key().clone());
            let shape = NativeProofShape::from_trusted(
                &verifier.air,
                verifier.verification_key(),
                verifier.public_config(),
                profile,
                family.relation(),
                binding,
                family.limit(),
            )
            .map_err(|_| "trusted shape rejected")?;
            let maximum = shape
                .maximum_frame_bytes()
                .map_err(|_| "frame accounting failed")?;
            let (proof, returned) = phase(family, "prove", &mut times, || {
                prover.prove_at_snapshot(&witness, SNAPSHOT_HEIGHT)
            })?;
            if returned != public {
                return Err("transaction statement reconstruction mismatch".into());
            }
            let frame = phase(family, "encode", &mut times, || {
                shape
                    .encode(&proof)
                    .map_err(|_| "frame encoding failed".into())
            })?;
            drop(proof);
            drop(witness);
            drop(prover);
            let decoded = phase(family, "decode", &mut times, || {
                shape
                    .decode(&frame)
                    .map_err(|_| "frame decoding failed".into())
            })?;
            phase(family, "independent_verify", &mut times, || {
                verifier.verify(&decoded, &public)
            })?;
            finish(
                family,
                output,
                context,
                key_json(verifier.verification_key())?,
                &frame,
                maximum,
                times,
            )
        }
        Family::Settlement => {
            let witness = phase(family, "fixture", &mut times, || {
                Ok(sample_fixed_settlement_witness(
                    SETTLEMENT_CAPACITY,
                    RewardMode::Holder,
                ))
            })?;
            let context = settlement_context(&witness);
            let public = settlement_statement(&context)?;
            let prover = phase(family, "public_setup", &mut times, || {
                SettlementProver::new(SETTLEMENT_CAPACITY, profile)
            })?;
            let verifier = SettlementVerifier::from_trusted_key(
                SETTLEMENT_CAPACITY,
                profile,
                prover.verification_key().clone(),
            );
            let shape = NativeProofShape::from_trusted(
                &verifier.air,
                verifier.verification_key(),
                verifier.public_config(),
                profile,
                family.relation(),
                binding,
                family.limit(),
            )
            .map_err(|_| "trusted shape rejected")?;
            let maximum = shape
                .maximum_frame_bytes()
                .map_err(|_| "frame accounting failed")?;
            let (proof, returned) = phase(family, "prove", &mut times, || prover.prove(&witness))?;
            if returned != public {
                return Err("settlement statement reconstruction mismatch".into());
            }
            let frame = phase(family, "encode", &mut times, || {
                shape
                    .encode(&proof)
                    .map_err(|_| "frame encoding failed".into())
            })?;
            drop(proof);
            drop(witness);
            drop(prover);
            let decoded = phase(family, "decode", &mut times, || {
                shape
                    .decode(&frame)
                    .map_err(|_| "frame decoding failed".into())
            })?;
            phase(family, "independent_verify", &mut times, || {
                verifier.verify(&decoded, &public)
            })?;
            finish(
                family,
                output,
                context,
                key_json(verifier.verification_key())?,
                &frame,
                maximum,
                times,
            )
        }
        Family::Issuance => {
            let (signed, witness, policy) = phase(family, "fixture", &mut times, || {
                Ok(sample_issuance(ISSUANCE_NOTES))
            })?;
            let context = issuance_context(&signed, &witness.ciphertexts, policy)?;
            let (rebuilt, ciphertexts, policy) = issuance_statement(&context)?;
            let public = rebuilt.declaration.public_inputs();
            let prover = phase(family, "public_setup", &mut times, || {
                IssuanceProver::new(ISSUANCE_NOTES, profile)
            })?;
            let verifier = IssuanceVerifier::from_trusted_key(
                ISSUANCE_NOTES,
                profile,
                prover.verification_key().clone(),
            );
            let shape = NativeProofShape::from_trusted(
                &verifier.air,
                verifier.verification_key(),
                verifier.public_config(),
                profile,
                family.relation(),
                binding,
                family.limit(),
            )
            .map_err(|_| "trusted shape rejected")?;
            let maximum = shape
                .maximum_frame_bytes()
                .map_err(|_| "frame accounting failed")?;
            let (proof, returned) = phase(family, "prove", &mut times, || {
                prover
                    .prove(&witness)
                    .map_err(|_| "issuance proving failed".into())
            })?;
            if returned != public {
                return Err("issuance statement reconstruction mismatch".into());
            }
            let frame = phase(family, "encode", &mut times, || {
                shape
                    .encode(&proof)
                    .map_err(|_| "frame encoding failed".into())
            })?;
            drop(proof);
            drop(witness);
            drop(prover);
            let decoded = phase(family, "decode", &mut times, || {
                shape
                    .decode(&frame)
                    .map_err(|_| "frame decoding failed".into())
            })?;
            phase(family, "independent_verify", &mut times, || {
                verifier
                    .verify(&decoded, &public)
                    .map_err(|_| "issuance verification failed".into())
            })?;
            let expected = rebuilt.declaration.binding();
            phase(family, "signed_issuance_verify", &mut times, || {
                verifier
                    .verify_signed(
                        &rebuilt,
                        &decoded,
                        &rebuilt.declaration.network,
                        rebuilt.declaration.version,
                        policy,
                        &ciphertexts,
                        |binding, fee| *binding == expected && fee == 123,
                    )
                    .map(|_| ())
                    .map_err(|_| "signed issuance fixture rejected".into())
            })?;
            finish(
                family,
                output,
                context,
                key_json(verifier.verification_key())?,
                &frame,
                maximum,
                times,
            )
        }
    }
}
fn verify(input: &Path, trusted_hash: &str, iterations: usize) -> Result<()> {
    if !(1..=100).contains(&iterations) {
        return Err("verification iterations must be 1..=100".into());
    }
    let manifest = read_bounded(&input.join("public-manifest.json"), MANIFEST_LIMIT)?;
    let expected: [u8; 32] = unhex(trusted_hash, 32)?
        .try_into()
        .map_err(|_| "invalid trusted manifest hash")?;
    if sha(&manifest) != expected {
        return Err("trusted manifest hash mismatch".into());
    }
    let manifest: Value = serde_json::from_slice(&manifest).map_err(|_| "invalid manifest JSON")?;
    if number(&manifest["schema"])? != 1 {
        return Err("unsupported manifest schema".into());
    }
    let family = Family::parse(string(&manifest["relation"])?)?;
    let profile = family.profile();
    let binding = family.binding();
    if bytes::<32>(&manifest["profile"])? != profile.id()
        || bytes::<32>(&manifest["binding"]["genesis"])? != binding.genesis
        || bytes::<32>(&manifest["binding"]["rules"])? != binding.rules
        || bytes::<32>(&manifest["binding"]["air"])? != binding.air
        || number(&manifest["frame_limit"])? != family.limit() as u64
    {
        return Err("trusted measurement profile mismatch".into());
    }
    let frame = read_bounded(&input.join("proof.frame"), family.limit())?;
    if bytes::<32>(&manifest["proof_sha256"])? != sha(&frame)
        || number(&manifest["proof_bytes"])? != frame.len() as u64
    {
        return Err("public proof binding mismatch".into());
    }
    let key = read_key(&manifest["key"])?;
    let context = &manifest["public_context"];
    let mut times = BTreeMap::new();
    macro_rules! verify_body {
        ($verifier:expr,$public:expr) => {{
            let verifier = $verifier;
            let public = $public;
            let shape = NativeProofShape::from_trusted(
                &verifier.air,
                verifier.verification_key(),
                verifier.public_config(),
                profile,
                family.relation(),
                binding,
                family.limit(),
            )
            .map_err(|_| "trusted shape rejected")?;
            let proof = phase(family, "decode", &mut times, || {
                shape
                    .decode(&frame)
                    .map_err(|_| "frame decoding failed".into())
            })?;
            for iteration in 0..iterations {
                phase(family, &format!("verify_{iteration}"), &mut times, || {
                    verifier
                        .verify(&proof, &public)
                        .map_err(|_| "independent verification failed".into())
                })?;
            }
        }};
    }
    match family {
        Family::Transaction => verify_body!(
            TransactionVerifier::from_trusted_key(profile, key),
            transaction_public(context)?
        ),
        Family::Settlement => verify_body!(
            SettlementVerifier::from_trusted_key(SETTLEMENT_CAPACITY, profile, key),
            settlement_statement(context)?
        ),
        Family::Issuance => {
            let (signed, _, _) = issuance_statement(context)?;
            verify_body!(
                IssuanceVerifier::from_trusted_key(ISSUANCE_NOTES, profile, key),
                signed.declaration.public_inputs()
            );
        }
    }
    println!(
        "{}",
        json!({"status":"public_fixture_verification_passed","relation":family.name(),"threads":THREADS,
        "iterations":iterations,"phase_wall_microseconds":times,"cpu_microseconds":null,"peak_rss_bytes":null})
    );
    Ok(())
}
fn run() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(THREADS)
        .build()
        .map_err(|_| "cannot create bounded proving pool")?;
    match arguments.as_slice() {
        [command,family,output] if command=="measure"=>pool.install(||measure(Family::parse(family)?,Path::new(output))),
        [command,input,hash,count] if command=="verify"=>pool.install(||verify(Path::new(input),hash,count.parse().map_err(|_|"invalid iteration count")?)),
        _=>Err("usage: native_hiding_v2_measure measure FAMILY NEW_DIRECTORY | verify DIRECTORY TRUSTED_MANIFEST_SHA256 ITERATIONS".into()),
    }
}
fn main() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("{{\"status\":\"measurement_panicked\",\"details_suppressed\":true}}");
    }));
    if let Err(error) = run() {
        eprintln!("{}", json!({"status":"measurement_failed","error":error}));
        std::process::exit(1);
    }
}
