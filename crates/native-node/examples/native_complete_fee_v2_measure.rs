//! Manual offline CompleteFee measurements with a synthetic 576-slot statement.
//! This example is excluded from workflows and never joins a network. A fresh
//! verifier reconstructs only public data and accepts no peer-selected key.
use native::{
    encryption::{PaymentAddress, PaymentCiphertext},
    multi_asset::{Digest, F, Hasher, Note, SIP_ASSET_ID},
    settlement::{RewardAllocation, RewardMode, RewardPlan},
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use siworld_native_node::proof_codec::v2::{
    FRAME_BYTES, MAX_FEE_PROOF_BYTES, ProtocolBinding,
    complete_fee::{
        self as fee, FeeLocalSumWitness, FeeSchedule, LegacyFeeOpening, LegacyPrivateSettlement,
        LegacySettlementSlot, SettlementPolicy, Statement, StatementInputs,
    },
    receive::read_fee_frame,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::Instant,
};
type Result<T> = std::result::Result<T, String>;
const MANIFEST_LIMIT: u64 = 1_048_576;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn bytes<const N: usize>(value: &Value) -> Result<[u8; N]> {
    let text = value.as_str().ok_or("expected hex string")?;
    if text.len() != 2 * N || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid fixed hex".into());
    }
    let mut result = [0; N];
    for (out, pair) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let digit = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b.to_ascii_lowercase() - b'a' + 10
            }
        };
        *out = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(result)
}
fn number(v: &Value) -> Result<u64> {
    v.as_u64().ok_or_else(|| "expected unsigned integer".into())
}
fn digest(v: &Value) -> Result<Digest> {
    let values = v
        .as_array()
        .filter(|x| x.len() == 12)
        .ok_or("expected digest12")?;
    let mut result = [F::ZERO; 12];
    for (out, value) in result.iter_mut().zip(values) {
        let raw = u32::try_from(number(value)?).map_err(|_| "field overflow")?;
        if raw >= F::ORDER_U32 {
            return Err("noncanonical field".into());
        }
        *out = F::from_u32(raw);
    }
    Ok(result)
}
fn digests(v: &Value, count: usize) -> Result<Vec<Digest>> {
    v.as_array()
        .filter(|values| values.len() == count)
        .ok_or("digest count")?
        .iter()
        .map(digest)
        .collect()
}
fn public_digest(d: &Digest) -> Vec<u32> {
    d.iter().map(F::as_canonical_u32).collect()
}
fn binding() -> ProtocolBinding {
    ProtocolBinding {
        genesis: [31; 32],
        rules: [37; 32],
        air: fee::source_identity(),
    }
}
fn fixture() -> (FeeLocalSumWitness, PaymentAddress) {
    let h = Hasher::new();
    let pair = libcrux_ml_kem::mlkem768::portable::generate_key_pair([3; 64]);
    let owner = [F::from_u8(7); 12];
    let address = PaymentAddress::new(owner, *pair.public_key().as_slice()).unwrap();
    let policy = SettlementPolicy {
        plan: RewardPlan {
            block_height: 17,
            mode: RewardMode::Voyager,
            allocations: vec![RewardAllocation {
                amount: 41,
                unlock_height: 17,
            }],
        },
        fee_owner: owner,
        fees: FeeSchedule::from_previous_standard(100).unwrap(),
        max_slots: fee::CAPACITY,
    };
    let slots: Vec<_> = (0..fee::CAPACITY)
        .map(|i| {
            let amount = [0, 10, 40][i % 3];
            let blind = [F::from_usize(i + 1); 8];
            LegacySettlementSlot {
                commitment: fee::legacy_fee_commit(&h, amount, &blind),
                opening: LegacyFeeOpening { fee: amount, blind },
            }
        })
        .collect();
    let total = slots.iter().map(|s| s.opening.fee).sum();
    let note = |value, unlock_height, owner, rho, rseed| Note {
        value,
        unlock_height,
        owner,
        rho,
        rseed,
        asset_id: SIP_ASSET_ID,
    };
    let reward = note(
        41,
        17,
        [F::from_u8(9); 12],
        h.reward_rho(17, 0),
        [F::from_u8(83); 12],
    );
    let fee_note = note(total, 0, owner, [F::from_u8(87); 12], [F::from_u8(89); 12]);
    (
        FeeLocalSumWitness {
            policy,
            network: [31; 32],
            transaction_list_digest: [47; 32],
            fee_destination_digest: fee::fee_destination_digest(&address),
            settlement: LegacyPrivateSettlement {
                rewards: vec![reward],
                fee_note,
                slots,
            },
        },
        address,
    )
}
fn public_manifest(
    w: &FeeLocalSumWitness,
    address: &PaymentAddress,
    c: &PaymentCiphertext,
) -> Value {
    let h = Hasher::new();
    json!({"format":"siworld-local-complete-fee-v2-public-1","genesis":hex(&binding().genesis),
        "rules":hex(&binding().rules),"air":hex(&binding().air),"network":hex(&w.network),
        "ordered_transaction_digest":hex(&w.transaction_list_digest),"previous_standard":100,
        "height":w.policy.plan.block_height,"reward_mode":0,
        "allocations":w.policy.plan.allocations.iter().map(|a|json!({"amount":a.amount,"unlock_height":a.unlock_height})).collect::<Vec<_>>(),
        "owner":public_digest(&address.owner()),"encapsulation_key":hex(address.encapsulation_key()),
        "fee_commitments":w.settlement.slots.iter().map(|s|public_digest(&s.commitment)).collect::<Vec<_>>(),
        "reward_commitments":w.settlement.rewards.iter().map(|n|public_digest(&h.note_cm(n))).collect::<Vec<_>>(),
        "fee_commitment":public_digest(&h.note_cm(&w.settlement.fee_note)),
        "ciphertext":{"kem":hex(&c.kem_ciphertext),"body":hex(&c.body),"tag":hex(&c.tag),"view_tag":c.view_tag}})
}
fn statement(v: &Value) -> Result<Statement> {
    if v["format"] != "siworld-local-complete-fee-v2-public-1" {
        return Err("unsupported public manifest".into());
    }
    let binding = ProtocolBinding {
        genesis: bytes(&v["genesis"])?,
        rules: bytes(&v["rules"])?,
        air: bytes(&v["air"])?,
    };
    let mode = match number(&v["reward_mode"])? {
        0 => RewardMode::Voyager,
        1 => RewardMode::Holder,
        _ => return Err("reward mode".into()),
    };
    let allocations = v["allocations"]
        .as_array()
        .filter(|a| a.len() == mode.note_count())
        .ok_or("reward allocations")?
        .iter()
        .map(|a| {
            Ok(RewardAllocation {
                amount: number(&a["amount"])?,
                unlock_height: number(&a["unlock_height"])?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let owner = digest(&v["owner"])?;
    let policy = SettlementPolicy {
        plan: RewardPlan {
            block_height: number(&v["height"])?,
            mode,
            allocations,
        },
        fee_owner: owner,
        fees: FeeSchedule::from_previous_standard(number(&v["previous_standard"])?)?,
        max_slots: fee::CAPACITY,
    };
    let address =
        PaymentAddress::new(owner, bytes(&v["encapsulation_key"])?).map_err(|e| e.to_string())?;
    let fees = digests(&v["fee_commitments"], fee::CAPACITY)?;
    let rewards = digests(&v["reward_commitments"], mode.note_count())?;
    let c = &v["ciphertext"];
    let ciphertext = PaymentCiphertext {
        kem_ciphertext: bytes(&c["kem"])?,
        body: bytes(&c["body"])?,
        tag: bytes(&c["tag"])?,
        view_tag: u8::try_from(number(&c["view_tag"])?).map_err(|_| "view tag")?,
    };
    Statement::from_authenticated(
        StatementInputs {
            policy: &policy,
            network: bytes(&v["network"])?,
            transaction_list_digest: bytes(&v["ordered_transaction_digest"])?,
            address: &address,
            fee_commitments: &fees,
            reward_commitments: &rewards,
            fee_commitment: digest(&v["fee_commitment"])?,
            ciphertext: &ciphertext,
        },
        binding,
    )
    .map_err(|e| format!("statement: {e:?}"))
}
fn write_new(p: &Path, bytes: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| e.to_string())
}
fn run() -> Result<()> {
    if std::env::var("RAYON_NUM_THREADS").as_deref() != Ok("4")
        || std::env::var("SIWORLD_COMPOSITION_HIDING_WORKERS").as_deref() != Ok("2")
    {
        return Err(
            "expected external four-thread and two-composition-worker configuration".into(),
        );
    }
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 3 {
        return Err(
            "expected prove DIRECTORY or verify DIRECTORY PUBLIC_SHA256 FRAME_SHA256".into(),
        );
    }
    let directory = Path::new(&args[2]);
    match args[1].as_str() {
        "prove" if args.len() == 3 => {
            fs::create_dir(directory).map_err(|e| e.to_string())?;
            let (w, address) = fixture();
            let context = native::encryption::EncryptionContext::new(w.network);
            let (ciphertext, opening) = native::encryption::encrypt_payment_with_opening(
                &address,
                &w.settlement.fee_note,
                &context,
            )
            .map_err(|e| e.to_string())?;
            let coins = *opening.expose_encapsulation_coins();
            let public = serde_json::to_vec_pretty(&public_manifest(&w, &address, &ciphertext))
                .map_err(|e| e.to_string())?;
            let started = Instant::now();
            let frame =
                fee::prove(&w, &address, coins, binding()).map_err(|e| format!("prove: {e:?}"))?;
            let elapsed = started.elapsed().as_secs_f64();
            write_new(&directory.join("public.json"), &public)?;
            write_new(&directory.join("proof.frame"), &frame)?;
            println!(
                "{}",
                json!({"relation":"CompleteFee","synthetic_only":true,"complete_frame_bytes":frame.len(),"public_sha256":sha(&public),"frame_sha256":sha(&frame),"prove_seconds":elapsed})
            );
        }
        "verify" if args.len() == 5 => {
            let mut public = Vec::new();
            File::open(directory.join("public.json"))
                .map_err(|e| e.to_string())?
                .take(MANIFEST_LIMIT + 1)
                .read_to_end(&mut public)
                .map_err(|e| e.to_string())?;
            if public.len() as u64 > MANIFEST_LIMIT || sha(&public) != args[3] {
                return Err("public manifest length or hash".into());
            }
            let v: Value = serde_json::from_slice(&public).map_err(|e| e.to_string())?;
            let mut file = File::open(directory.join("proof.frame")).map_err(|e| e.to_string())?;
            let declared = file.metadata().map_err(|e| e.to_string())?.len();
            if !((FRAME_BYTES as u64 + 1)..=MAX_FEE_PROOF_BYTES as u64).contains(&declared) {
                return Err("excessive complete frame".into());
            }
            let started = Instant::now();
            let verifier = statement(&v)?
                .verifier()
                .map_err(|e| format!("verifier setup: {e:?}"))?;
            let setup = started.elapsed().as_secs_f64();
            let frame = read_fee_frame(&mut file, declared, verifier.shape().identity())
                .map_err(|e| format!("receive: {e:?}"))?;
            if sha(&frame) != args[4] {
                return Err("frame hash".into());
            }
            let started = Instant::now();
            verifier
                .verify(&frame)
                .map_err(|e| format!("verify: {e:?}"))?;
            println!(
                "{}",
                json!({"relation":"CompleteFee","synthetic_only":true,"complete_frame_bytes":frame.len(),"structural_complete_frame_upper_bound":verifier.shape().maximum_complete_frame_bytes(),"public_sha256":sha(&public),"frame_sha256":sha(&frame),"setup_seconds":setup,"verify_seconds":started.elapsed().as_secs_f64()})
            );
        }
        _ => return Err("unsupported arguments".into()),
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
