//! Explicit offline rehearsal using real native proofs and independent replay.
//! Synthetic wallet and governance custody is confined to one new private directory.

use super::{
    execution::Engine,
    genesis::{FeeMode, Genesis},
    state_components::Limits,
    store::Store,
};
use crate::{
    eng2_governance::{
        self, Action, ActionKind, Authorization, GovernanceState, IssuanceFeeParameters,
        SignedAction, SignerRole,
    },
    eng2_operations::{self, PendingOperations},
    pool::Padding,
    producer::{MiningSettings, prepare_padding},
    proofs::{NativeProver, NativeVerifier},
    state::Config,
    wallet::issuance::{ISSUER_SIGNATURE_CONTEXT, InitialOutput, IssuanceRequest},
    wallet::{FeeTier, Wallet, WalletKeys},
    wire::{Block, Hash, MIN_SLOTS, RewardMode, Transaction},
};
use native::{
    codec::encode_digest,
    confidential_fees::FeeOpening,
    multi_asset::{F, SIP_ASSET_ID},
};
use p3_field::PrimeCharacteristicRing;
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
    time::Instant,
};
use zeroize::{Zeroize, Zeroizing};

mod continuation;
pub mod partition;
pub use continuation::{check_continuation, continue_run};

const PAYMENT_HEIGHT: u64 = 26;
const CONSOLIDATION_HEIGHT: u64 = 27;
const ISSUANCE_HEIGHT: u64 = 28;

fn private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "new private rehearsal file unavailable")?;
    file.write_all(bytes)
        .map_err(|_| "private rehearsal write failed")?;
    file.sync_all()
        .map_err(|_| "private rehearsal durability failed".into())
}
fn derive(seed: &[u8], label: &'static str) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(label, seed))
}
fn genesis(seed: &[u8], network: Hash) -> Result<Genesis, String> {
    let mut config = Config::development(network, 0)?.with_test_fund_registry()?;
    let key = |domain| {
        *libcrux_ml_dsa::ml_dsa_65::generate_key_pair(*derive(seed, domain))
            .verification_key
            .as_ref()
    };
    let address = |index| {
        WalletKeys::from_seed(
            network,
            derive(seed, "siworld eng2 rehearsal payment v1"),
            index,
        )
        .map(|keys| keys.address())
    };
    config.issuance = Some(crate::issuance::IssuanceConfig {
        fee_owner: encode_digest(&address(2)?.owner()),
        max_metadata_bytes: 256,
        max_per_block: 4,
    });
    let governance = GovernanceState::new_with_issuance_fee(
        network,
        key("siworld eng2 rehearsal founder v1"),
        key("siworld eng2 rehearsal revocation v1"),
        [
            key("siworld eng2 rehearsal certificate one v1"),
            key("siworld eng2 rehearsal certificate two v1"),
            key("siworld eng2 rehearsal certificate three v1"),
        ],
        address(2)?,
        (3..27).map(address).collect::<Result<Vec<_>, _>>()?,
        IssuanceFeeParameters::default(),
    )?;
    Genesis::seal(config, governance, FeeMode::LegacyMiner)
}

fn operations(
    seed: &[u8],
    engine: &Engine,
    height: u64,
) -> Result<Option<PendingOperations>, String> {
    let network = engine.state().network();
    let mut governance = Vec::new();
    let mut fund_claims = Vec::new();
    if height <= 2 {
        let (kind, role, domain) = if height == 1 {
            (
                ActionKind::ProposeIssuanceFee {
                    amount_atoms: 4_000_000_000,
                },
                SignerRole::Founder,
                "siworld eng2 rehearsal founder v1",
            )
        } else {
            (
                ActionKind::CancelIssuanceFee {
                    proposal_sequence: 1,
                },
                SignerRole::Revocation,
                "siworld eng2 rehearsal revocation v1",
            )
        };
        let action = Action {
            network,
            sequence: height,
            kind,
        };
        let mut pair = libcrux_ml_dsa::ml_dsa_65::generate_key_pair(*derive(seed, domain));
        let signature = libcrux_ml_dsa::ml_dsa_65::sign(
            &pair.signing_key,
            &action.signing_bytes(role)?,
            eng2_governance::SIGNATURE_CONTEXT,
            *derive(seed, "siworld eng2 rehearsal governance signature v1"),
        )
        .map_err(|_| "rehearsal governance signing failed")?;
        pair.signing_key.as_mut_slice().zeroize();
        let signed = SignedAction {
            action,
            signatures: vec![Authorization {
                role,
                signature: *signature.as_ref(),
            }],
        };
        governance.push(eng2_operations::hex(&signed.encode()?));
    }
    if height == PAYMENT_HEIGHT {
        let config = &engine.state().chain().config;
        let authority = config.fund_verifying_keys[0];
        let address = engine.state().governance().active_fund_destination(0)?;
        let mut address_bytes = encode_digest(&address.owner()).to_vec();
        address_bytes.extend_from_slice(address.encapsulation_key());
        let request = serde_json::to_vec(&json!({"operation":"claim-prepare","network":eng2_operations::hex(&network),"height":height.to_string(),"member":0,"amount_atoms":"1","counter":"0","destination_hex":eng2_operations::hex(&address_bytes),"authority_hex":eng2_operations::hex(&authority),"rseed_hex":eng2_operations::hex(&encode_digest(&[F::from_u32(9);12]))})).map_err(|_| "claim request encoding failed")?;
        let prepared = eng2_operations::execute(&request)?;
        let signing_request = serde_json::to_vec(&json!({"operation":"claim-sign","claim_hex":prepared["claim_hex"],"confirmed_digest":prepared["review_digest"]})).map_err(|_| "claim signing request encoding failed")?;
        let executable = std::env::current_exe()
            .map_err(|_| "rehearsal executable unavailable")?
            .with_file_name(format!(
                "siworld-eng2-operations{}",
                std::env::consts::EXE_SUFFIX
            ));
        let mut child = std::process::Command::new(executable)
            .arg("--sign-claim-pipe")
            .arg(eng2_operations::hex(&network))
            .arg(eng2_operations::hex(&authority))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| "private-pipe operation signer unavailable")?;
        {
            let mut pipe = child
                .stdin
                .take()
                .ok_or("private signer pipe unavailable")?;
            pipe.write_all(&(signing_request.len() as u32).to_be_bytes())
                .map_err(|_| "public signing frame write failed")?;
            pipe.write_all(&signing_request)
                .map_err(|_| "public signing frame write failed")?;
            let fund_seed = Zeroizing::new(blake3::derive_key(
                "siworld disposable twenty-four-wallet fund fixture v1",
                &0u32.to_le_bytes(),
            ));
            pipe.write_all(&32u32.to_be_bytes())
                .map_err(|_| "private signing frame write failed")?;
            pipe.write_all(fund_seed.as_ref())
                .map_err(|_| "private signing frame write failed")?;
        }
        let output = child
            .wait_with_output()
            .map_err(|_| "private-pipe signing failed")?;
        if !output.status.success() || output.stdout.len() > eng2_operations::MAX_INPUT_BYTES {
            return Err("private-pipe operation signing rejected".into());
        }
        let signed: Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| "private-pipe operation response malformed")?;
        if signed["ok"] != true || signed["result"]["signature_verified"] != true {
            return Err("private-pipe operation signature not verified".into());
        }
        fund_claims.push(signed["result"]["claim_hex"].clone());
    }
    if governance.is_empty() && fund_claims.is_empty() {
        return Ok(None);
    }
    let bytes = serde_json::to_vec(&json!({"version":1,"network":eng2_operations::hex(&network),"height":height.to_string(),"fund_claims":fund_claims,"governance":governance})).map_err(|_| "pending operation bundle encoding failed")?;
    Ok(Some(PendingOperations::decode(&bytes, network, height)?))
}
/// Public-data-only wallet projection after actual native admission. The
/// authenticated eng2 identity is passed separately; V1 IDs are never derived.
fn wallet_projection(header: &super::header::Header, body: &super::body::Body) -> Block {
    Block {
        network: header.network,
        height: header.height,
        parent: header.parent,
        timestamp: header.timestamp,
        target: header.target,
        nonce: header.nonce,
        transactions: body
            .transactions
            .iter()
            .map(|tx| Transaction {
                record: tx.record.clone(),
                proof: Vec::new(),
            })
            .collect(),
        reward_mode: body.reward_mode,
        rewards: body.rewards.clone(),
        fund_spends: body
            .fund_claims
            .iter()
            .map(|claim| claim.spend.clone())
            .collect(),
        issuances: body.issuances.clone(),
        settlement_proof: Vec::new(),
    }
}

/// Runs only in a newly created directory and never joins or modifies a node.
/// A partial run reports transfer/fund gates pending rather than faking maturity.
pub fn run(directory: &Path, blocks: u64, mode: FeeMode) -> Result<Value, String> {
    if mode != FeeMode::LegacyMiner || !(1..=96).contains(&blocks) {
        return Err("rehearsal requires explicit legacy mode and 1 through 96 blocks".into());
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(directory)
        .map_err(|_| "rehearsal directory must be new and absent")?;
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| "rehearsal entropy unavailable")?;
    private_write(&directory.join("rehearsal.seed"), seed.as_ref())?;
    let network = blake3::derive_key("siworld eng2 offline rehearsal network v1", seed.as_ref());
    let genesis = genesis(seed.as_ref(), network)?;
    let genesis_bytes = genesis.encode()?;
    private_write(&directory.join("genesis.bin"), &genesis_bytes)?;
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    let path = directory.join("chain.redb");
    let verifier = NativeVerifier::for_genesis(&genesis)?;
    let store = Store::create(&path, genesis, limits)?;
    execute(directory, blocks, seed, genesis_bytes, store, verifier, 0)
}

#[allow(clippy::too_many_arguments)]
fn execute(
    directory: &Path,
    blocks: u64,
    seed: Zeroizing<[u8; 32]>,
    genesis_bytes: Vec<u8>,
    mut store: Store,
    verifier: NativeVerifier,
    prefix: u64,
) -> Result<Value, String> {
    let network = store.engine().state().network();
    let path = directory.join("chain.redb");
    let limits = store.engine().limits();
    let mut miner = Wallet::from_seed(
        network,
        derive(seed.as_ref(), "siworld eng2 rehearsal payment v1"),
        0,
    )?;
    let mut recipient = Wallet::from_seed(
        network,
        derive(seed.as_ref(), "siworld eng2 rehearsal payment v1"),
        1,
    )?;
    let mut fund_wallet = Wallet::from_seed(
        network,
        derive(seed.as_ref(), "siworld eng2 rehearsal payment v1"),
        3,
    )?;
    let settings = MiningSettings {
        mode: RewardMode::Voyager,
        recipient: miner.address(),
    };
    let mut fee_wallet = Wallet::from_seed(
        network,
        derive(seed.as_ref(), "siworld eng2 rehearsal payment v1"),
        2,
    )?;
    let started = Instant::now();
    let mut timings = Vec::new();
    let mut transferred = false;
    let mut last_root = [0; 32];
    let mut governance_records = 0u64;
    let mut fund_claimed = false;
    let mut issued_asset = None;
    let mut issuance_paid = false;
    if prefix > 0 {
        if prefix != 24 || store.engine().state().height() != prefix {
            return Err("continuation requires the exact audited 24-block prefix".into());
        }
        for height in 1..=prefix {
            let (header, body) = store.block(height)?;
            let id = header
                .id()
                .map_err(|_| "invalid accepted continuation identity")?;
            let projection = wallet_projection(&header, &body);
            for wallet in [
                &mut miner,
                &mut recipient,
                &mut fund_wallet,
                &mut fee_wallet,
            ] {
                wallet.scan_light_data(
                    store.engine().state().chain(),
                    std::slice::from_ref(&projection),
                    &[id],
                    true,
                )?;
            }
            governance_records += body.governance.len() as u64;
            last_root = header.execution_commitment;
            let mut bytes = Vec::new();
            crate::local::regular_read(
                &directory.join(format!("block-{height}.json")),
                true,
                65536,
            )?
            .read_to_end(&mut bytes)
            .map_err(|_| "continuation receipt read failed")?;
            let receipt: Value =
                serde_json::from_slice(&bytes).map_err(|_| "invalid continuation receipt")?;
            if receipt["height"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                != Some(height)
                || receipt["block_id"] != crate::local::hex(&id)
                || receipt["execution_commitment"] != crate::local::hex(&last_root)
                || receipt["native_verified"] != true
                || receipt["durable_committed"] != true
            {
                return Err("continuation receipt differs from audited actual header".into());
            }
            timings.push(receipt);
        }
        if governance_records != 2
            || store.engine().state().governance().sequence() != 2
            || store
                .engine()
                .state()
                .governance()
                .pending_issuance_fee()
                .is_some()
            || store.engine().state().governance().issuance_fee_atoms() != 5_000_000_000
        {
            return Err("continuation governance differs from cancelled actual proposal".into());
        }
    }
    let prover = NativeProver::for_genesis(store.engine().genesis())?;
    for height in prefix + 1..=blocks {
        let block_started = Instant::now();
        let state = store.engine().state().chain();
        let mut positions = Vec::with_capacity(MIN_SLOTS);
        let mut issuances = Vec::new();
        if !transferred && height >= PAYMENT_HEIGHT {
            let note = miner
                .receipts()
                .iter()
                .find(|note| {
                    !note.spent
                        && note.note().asset_id == SIP_ASSET_ID
                        && note.note().value > 200_000_000
                        && note.note().unlock_height <= state.height
                })
                .ok_or("mature actual miner note is unavailable")?;
            let payment = miner
                .prepare_transfer(
                    state,
                    [Some(note.commitment), None],
                    &recipient.address(),
                    SIP_ASSET_ID,
                    100_000_000,
                    FeeTier::Standard,
                    state.timestamp(),
                )?
                .prove(&prover)?;
            payment
                .sidecar
                .check_opening(&payment.transaction.record, &network)?;
            positions.push(Padding {
                transaction: payment.transaction,
                opening: FeeOpening {
                    fee: payment.sidecar.fee,
                    blind: payment.sidecar.blind.map(native::multi_asset::F::from_u32),
                    dummy: false,
                    priority: false,
                },
            });
            transferred = true;
        }
        if height == CONSOLIDATION_HEIGHT || height == ISSUANCE_HEIGHT {
            let mut notes: Vec<_> = miner
                .receipts()
                .iter()
                .filter(|note| {
                    !note.spent
                        && note.note().asset_id == SIP_ASSET_ID
                        && note.note().value > 0
                        && note.note().unlock_height <= state.height
                })
                .collect();
            notes.sort_unstable_by_key(|note| std::cmp::Reverse(note.note().value));
            if notes.len() < 2 {
                return Err("two actual mature miner notes are unavailable".into());
            }
            let selected = [Some(notes[0].commitment), Some(notes[1].commitment)];
            let payment = if height == CONSOLIDATION_HEIGHT {
                let value = notes[0]
                    .note()
                    .value
                    .checked_add(notes[1].note().value)
                    .and_then(|value| value.checked_sub(crate::state::base_fee(state.height)))
                    .ok_or("actual consolidation value overflow")?;
                miner
                    .prepare_transfer(
                        state,
                        selected,
                        &miner.address(),
                        SIP_ASSET_ID,
                        value,
                        FeeTier::Standard,
                        state.timestamp(),
                    )?
                    .prove(&prover)?
            } else {
                if store.engine().state().governance().issuance_fee_atoms() != 5_000_000_000 {
                    return Err("cancelled issuance proposal changed the active price".into());
                }
                let mut issuer = libcrux_ml_dsa::ml_dsa_65::generate_key_pair(*derive(
                    seed.as_ref(),
                    "siworld eng2 rehearsal issuer v1",
                ));
                let prepared = miner.prepare_issuance(
                    &state.config,
                    IssuanceRequest {
                        issuer_key: *issuer.verification_key.as_ref(),
                        sequence: 1,
                        public_supply: 300,
                        metadata: native::issuance::AssetMetadata {
                            name: "Rehearsal asset".into(),
                            decimals: 0,
                        },
                        outputs: std::array::from_fn(|_| InitialOutput {
                            recipient: recipient.address(),
                            amount: 100,
                        }),
                    },
                )?;
                let fee = miner.prepare_issuance_fee(
                    state,
                    selected,
                    store.engine().state().governance().active_fee_destination(),
                    prepared.declaration(),
                    FeeTier::Standard,
                    state.timestamp(),
                )?;
                let receipt = fee.receipt().clone();
                let signature = libcrux_ml_dsa::ml_dsa_65::sign(
                    &issuer.signing_key,
                    &prepared.signature_message(),
                    ISSUER_SIGNATURE_CONTEXT,
                    *derive(seed.as_ref(), "siworld eng2 rehearsal issuer signature v1"),
                )
                .map_err(|_| "rehearsal issuer signing failed")?;
                issuer.signing_key.as_mut_slice().zeroize();
                let signed = prepared.attach_signature(*signature.as_ref())?;
                let issued =
                    signed.prove_for_genesis(&prover, &receipt, store.engine().genesis())?;
                issued_asset = Some(issued.record.signed.declaration.asset_id);
                issuances.push(issued.record);
                fee.into_transfer().prove(&prover)?
            };
            payment
                .sidecar
                .check_opening(&payment.transaction.record, &network)?;
            positions.push(Padding {
                transaction: payment.transaction,
                opening: FeeOpening {
                    fee: payment.sidecar.fee,
                    blind: payment.sidecar.blind.map(F::from_u32),
                    dummy: false,
                    priority: false,
                },
            });
        }
        while positions.len() < MIN_SLOTS {
            positions.push(prepare_padding(state, &prover)?);
        }
        let timestamp = state
            .timestamp()
            .checked_add(300)
            .ok_or("rehearsal timestamp overflow")?;
        let operations = operations(seed.as_ref(), store.engine(), height)?;
        let produced = super::producer::assemble_with_operations(
            store.engine(),
            &prover,
            &verifier,
            positions,
            timestamp,
            &settings,
            10_000_000,
            operations,
            issuances,
        )?;
        let accepted = store.append(&produced.header, &produced.body, &verifier)?;
        // Everything below occurs after the durable block transaction succeeds.
        if let Some(bytes) = eng2_operations::records::committed_governance_records(&accepted)? {
            private_write(&directory.join(format!("governance-{height}.json")), &bytes)?;
            governance_records += accepted.inclusions().len() as u64;
        }
        let projection = wallet_projection(&produced.header, &produced.body);
        miner.scan_light_data(
            store.engine().state().chain(),
            std::slice::from_ref(&projection),
            &[accepted.id()],
            true,
        )?;
        fund_wallet.scan_light_data(
            store.engine().state().chain(),
            std::slice::from_ref(&projection),
            &[accepted.id()],
            true,
        )?;
        fee_wallet.scan_light_data(
            store.engine().state().chain(),
            std::slice::from_ref(&projection),
            &[accepted.id()],
            true,
        )?;
        recipient.scan_light_data(
            store.engine().state().chain(),
            &[projection],
            &[accepted.id()],
            true,
        )?;
        last_root = accepted.execution_commitment();
        if height == PAYMENT_HEIGHT {
            if store.engine().state().fund().balance(0)?.spent != 1
                || fund_wallet
                    .balances(height + 1)?
                    .get(&SIP_ASSET_ID)
                    .copied()
                    .unwrap_or(0)
                    != 1
            {
                return Err("actual fund debit or recovered fund-wallet balance differs".into());
            }
            fund_claimed = true;
        }
        if height == ISSUANCE_HEIGHT {
            let asset = issued_asset.ok_or("actual issued asset is unavailable")?;
            if fee_wallet
                .balances(height + 1)?
                .get(&SIP_ASSET_ID)
                .copied()
                .unwrap_or(0)
                != 5_000_000_000
                || recipient
                    .balances(height + 1)?
                    .get(&asset)
                    .copied()
                    .unwrap_or(0)
                    != 300
            {
                return Err(
                    "actual issuance destination payment or minted wallet balance differs".into(),
                );
            }
            issuance_paid = true;
        }
        let progress = json!({"version":1,"height":height.to_string(),"block_id":crate::local::hex(&accepted.id()),"execution_commitment":crate::local::hex(&last_root),"native_verified":true,"durable_committed":true,"elapsed_ms":block_started.elapsed().as_millis().to_string()});
        let progress_bytes =
            serde_json::to_vec(&progress).map_err(|_| "rehearsal progress encoding failed")?;
        private_write(
            &directory.join(format!("block-{height}.json")),
            &progress_bytes,
        )?;
        timings.push(progress);
    }
    if transferred
        && recipient
            .balances(blocks + 1)?
            .get(&SIP_ASSET_ID)
            .copied()
            .unwrap_or(0)
            != 100_000_000
    {
        return Err("actual recipient wallet transfer balance differs".into());
    }
    let final_id = store.engine().state().tip();
    let mut independent = Engine::new(Genesis::decode(&genesis_bytes)?, limits)?;
    let mut checked = 0u64;
    for height in 1..=blocks {
        let (header, body) = store.block(height)?;
        let accepted = independent.apply(&header, &body, &verifier)?;
        if accepted.id() != header.id().map_err(|_| "independent header invalid")?
            || accepted.execution_commitment() != header.execution_commitment
        {
            return Err("independent per-block native execution differs".into());
        }
        checked += 1;
    }
    if independent.state().tip() != final_id || independent.state().height() != blocks {
        return Err("independent native replay head differs".into());
    }
    drop(store);
    let audit = Store::audit_existing(&path, Genesis::decode(&genesis_bytes)?, limits, &verifier)?;
    if audit.engine().state().tip() != final_id {
        return Err("durable reopened native audit differs".into());
    }
    let report = json!({
        "version":1,"scope":"offline-native-rehearsal","fee_mode":"legacy-miner",
        "genesis_id":crate::local::hex(&audit.engine().genesis().id()),
        "native_proof_blocks":blocks.to_string(),"independently_checked_execution_commitments":checked.to_string(),
        "durable_reopen_audit":"passed","production_fast_restart":"not_qualified_by_this_rehearsal",
        "reused_native_proof_blocks":prefix.to_string(),"new_native_proof_blocks":(blocks-prefix).to_string(),
        "wallet_transfer":if transferred { "passed" } else { "pending_maturity" },
        "wallet_transfer_atoms":if transferred { Some("100000000") } else { None },
        "fund_claim":if fund_claimed {"passed_private_pipe_native_commit"} else {"pending_26_real_proof_blocks"},
        "unified_governance_records":governance_records.to_string(),
        "issuance_and_dedicated_fee_payment":if issuance_paid {"passed_50_SIP_and_300_asset_atoms"} else {"pending_28_real_proof_blocks"},
        "tip":crate::local::hex(&final_id),"execution_commitment":crate::local::hex(&last_root),
        "database_bytes":std::fs::metadata(path).map_err(|_| "rehearsal database metadata unavailable")?.len().to_string(),
        "elapsed_ms":started.elapsed().as_millis().to_string(),"blocks":timings,
    });
    private_write(
        &directory.join("result.json"),
        &serde_json::to_vec(&report).map_err(|_| "rehearsal result encoding failed")?,
    )?;
    Ok(report)
}
