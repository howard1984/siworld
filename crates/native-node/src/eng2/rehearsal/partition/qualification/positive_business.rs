//! Owner-operated positive business frames on an existing isolated native store.
//! Custody, the stopped-node lease and a hard process resource guard are caller
//! responsibilities. This module never imports keys, opens a Store or joins peers.
use super::Context;
use crate::{
    eng2::{
        body::Body, execution::Engine, genesis::FeeMode, state_components::Binding, store::Store,
    },
    eng2_governance::canonical_address,
    eng2_operations::{self, PendingOperations},
    proofs::{NativeProver, NativeVerifier},
    state::State,
    wallet::{
        FeeTier, PreparedTransfer, Wallet, WalletPayment,
        issuance::{InitialOutput, IssuanceRequest, WalletIssuance},
    },
    wire::DigestBytes,
};
use native::{
    codec::{PublicTransaction, encode_digest},
    encryption::{EncryptionContext, PaymentAddress},
    multi_asset::{AssetId, F, Hasher, Note, SIP_ASSET_ID},
};
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};
use zeroize::Zeroize;

pub mod custody_caller;
mod native_business;
mod prefix;
const MAX_PLAN: usize = 128 * 1024;
const MAX_STEPS: usize = 4;
const ROLES: [&str; 5] = [
    "payer",
    "recipient",
    "fee_destination",
    "fund_destination",
    "reward",
];

pub struct Actors<'a> {
    pub payer: &'a mut Wallet,
    pub recipient: &'a mut Wallet,
    pub fee_destination: &'a mut Wallet,
    pub fund_destination: &'a mut Wallet,
    pub reward: &'a mut Wallet,
}
impl Actors<'_> {
    fn wallets(&self) -> [&Wallet; 5] {
        [
            &*self.payer,
            &*self.recipient,
            &*self.fee_destination,
            &*self.fund_destination,
            &*self.reward,
        ]
    }
    fn require_fresh(&self, expected: &[WalletExpectation]) -> Result<(), String> {
        if self
            .wallets()
            .into_iter()
            .zip(expected)
            .any(|(wallet, expected)| {
                wallet.head().is_some()
                    || !wallet.receipts().is_empty()
                    || crate::local::hex(&canonical_address(&wallet.address())) != expected.address
            })
        {
            return Err(
                "business requires dedicated empty real-custody wallet scanner views".into(),
            );
        }
        Ok(())
    }
    fn require_head(&self, state: &State) -> Result<(), String> {
        let expected = Some((state.height, state.tip, state.fingerprint()));
        if self
            .wallets()
            .into_iter()
            .any(|wallet| wallet.head() != expected)
        {
            return Err("business wallet scanner and exact accepted head differ".into());
        }
        Ok(())
    }
    fn scan(
        &mut self,
        state: &State,
        header: &crate::eng2::header::Header,
        body: &Body,
        append: bool,
    ) -> Result<(), String> {
        let projection = crate::eng2::rehearsal::wallet_projection(header, body);
        let id = header.id().map_err(|_| "business wallet header invalid")?;
        for wallet in [
            &mut *self.payer,
            &mut *self.recipient,
            &mut *self.fee_destination,
            &mut *self.fund_destination,
            &mut *self.reward,
        ] {
            wallet.scan_light_data(state, std::slice::from_ref(&projection), &[id], append)?;
        }
        Ok(())
    }
}

/// Implementations must state whether openings are durable or memory-only and
/// must check the external hard resource guard before every phase. The concrete
/// caller journals proved payments but retains other openings only in memory.
/// Callback success is not an independent custody or recovery receipt.
pub trait Custody {
    fn before_phase(&mut self, phase: &str) -> Result<(), String>;
    /// Reserve these exact real inputs and protect the original opening before proof.
    /// This may be erased memory retention; it does not imply crash recovery.
    /// Never write plaintext openings to evidence files.
    fn protect_prepared_payment(
        &mut self,
        kind: &str,
        recipient: &PaymentAddress,
        payment: &PreparedTransfer,
    ) -> Result<(), String>;
    fn protect_payment(
        &mut self,
        kind: &str,
        recipient: &PaymentAddress,
        payment: &WalletPayment,
    ) -> Result<(), String>;
    fn protect_issuance(
        &mut self,
        recipient: &PaymentAddress,
        issuance: &WalletIssuance,
    ) -> Result<(), String>;
    fn protect_reward(
        &mut self,
        block: &crate::eng2::producer::ProducedBlock,
    ) -> Result<(), String>;
    /// Sign these exact bytes with the independently held issuer key and
    /// wallet::issuance::ISSUER_SIGNATURE_CONTEXT.
    fn sign_issuance(
        &mut self,
        message: &[u8],
    ) -> Result<[u8; native::issuance::ISSUER_SIGNATURE_BYTES], String>;
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Balance {
    asset: String,
    received_notes: u64,
    spent_notes: u64,
    unspent_notes: u64,
    received_atoms: String,
    spent_atoms: String,
    unspent_atoms: String,
    available_atoms: String,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WalletExpectation {
    role: String,
    address: String,
    balances: Vec<Balance>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicInput {
    path: String,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issuance {
    issuer_key: String,
    sequence: u64,
    name: String,
    decimals: u8,
    amounts: [u64; crate::issuance::INITIAL_NOTES],
    expected_asset_id: String,
}
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Standard,
    Priority,
    Consolidation,
    Issuance,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Priority => "priority",
            Self::Consolidation => "consolidation",
            Self::Issuance => "issuance",
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedInput {
    commitment: String,
    nullifier: String,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExpectedOperation {
    kind: String,
    identity: String,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExpectedFundCounter {
    member: u8,
    spent_atoms: String,
    spend_count: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    kind: Kind,
    amount: u64,
    max_note_value: u64,
    issuance: Option<Issuance>,
    operations: Option<PublicInput>,
    inputs: [Option<ExpectedInput>; 2],
    expected_operations: Vec<ExpectedOperation>,
    expected_fund_counters: Vec<ExpectedFundCounter>,
    expected_governance_sequence: u64,
    expected_wallets: Vec<WalletExpectation>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    campaign_id: String,
    isolated_directory: String,
    start_height: u64,
    start_tip: String,
    deadline_seconds: u64,
    max_nonce_attempts: u64,
    max_output_bytes: u64,
    external_resource_manifest_sha256: String,
    history_budget: PublicInput,
    expected_before: Vec<WalletExpectation>,
    steps: Vec<Step>,
}
fn hex(text: &str, bytes: usize) -> bool {
    text.len() == 2 * bytes
        && text
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn decimal(text: &str) -> bool {
    !text.is_empty()
        && (text == "0" || !text.starts_with('0'))
        && text.bytes().all(|v| v.is_ascii_digit())
        && text.parse::<u128>().is_ok()
}
fn expected_shape(wallets: &[WalletExpectation]) -> bool {
    wallets.len() == ROLES.len()
        && wallets.iter().zip(ROLES).all(|(wallet, role)| {
            wallet.role == role
                && hex(&wallet.address, 48 + 1184)
                && wallet.balances.len() <= 64
                && wallet.balances.iter().all(|b| {
                    hex(&b.asset, 32)
                        && [
                            &b.received_atoms,
                            &b.spent_atoms,
                            &b.unspent_atoms,
                            &b.available_atoms,
                        ]
                        .into_iter()
                        .all(|v| decimal(v))
                })
                && wallet
                    .balances
                    .windows(2)
                    .all(|pair| pair[0].asset < pair[1].asset)
        })
        && wallets.iter().enumerate().all(|(index, wallet)| {
            wallets[..index]
                .iter()
                .all(|other| wallet.address != other.address)
        })
}
fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    crate::local::regular_read(path, true, maximum)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "business private input read failed")?;
    if bytes.len() > maximum {
        return Err("business private input byte bound".into());
    }
    Ok(bytes)
}
fn private_directory(path: &Path) -> Result<u32, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "business isolated directory missing")?;
    if path.canonicalize().ok().as_deref() != Some(path)
        || !meta.is_dir()
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err("business directory must be canonical and private".into());
    }
    Ok(meta.uid())
}
struct Output {
    directory: PathBuf,
    used: u64,
    maximum: u64,
}
impl Output {
    fn create(path: &Path, owner: u32, maximum: u64) -> Result<Self, String> {
        let parent = path.parent().ok_or("business output parent missing")?;
        if !path.is_absolute() || private_directory(parent)? != owner {
            return Err("business output requires a private same-owner parent".into());
        }
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| "business output must be absent")?;
        if private_directory(path)? != owner {
            return Err("business output owner differs".into());
        }
        Ok(Self {
            directory: path.into(),
            used: 0,
            maximum,
        })
    }
    fn write(&mut self, name: &str, bytes: &[u8]) -> Result<(), String> {
        let next = self
            .used
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or("business output byte budget exhausted")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.directory.join(name))
            .map_err(|_| "business output must be new")?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "business output durability failed")?;
        fs::File::open(&self.directory)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| "business output directory durability failed")?;
        self.used = next;
        Ok(())
    }
    fn json(&mut self, name: &str, value: &Value) -> Result<(), String> {
        self.write(
            name,
            &serde_json::to_vec(value).map_err(|_| "business output encoding failed")?,
        )
    }
}
#[derive(Default)]
struct Totals {
    received: u64,
    spent: u64,
    unspent: u64,
    received_atoms: u128,
    spent_atoms: u128,
    unspent_atoms: u128,
    available_atoms: u128,
}
fn wallets(actors: &Actors<'_>, spend_height: u64) -> Result<Vec<WalletExpectation>, String> {
    actors
        .wallets()
        .into_iter()
        .zip(ROLES)
        .map(|(wallet, role)| {
            let mut sums: BTreeMap<AssetId, Totals> = BTreeMap::new();
            for receipt in wallet.receipts().iter().filter(|r| r.note().value > 0) {
                let entry = sums.entry(receipt.note().asset_id).or_default();
                let amount = u128::from(receipt.note().value);
                entry.received += 1;
                entry.received_atoms = entry
                    .received_atoms
                    .checked_add(amount)
                    .ok_or("business receipt total overflow")?;
                if receipt.spent {
                    entry.spent += 1;
                    entry.spent_atoms = entry
                        .spent_atoms
                        .checked_add(amount)
                        .ok_or("business receipt total overflow")?;
                } else {
                    entry.unspent += 1;
                    entry.unspent_atoms = entry
                        .unspent_atoms
                        .checked_add(amount)
                        .ok_or("business receipt total overflow")?;
                    if receipt.note().unlock_height <= spend_height {
                        entry.available_atoms = entry
                            .available_atoms
                            .checked_add(amount)
                            .ok_or("business receipt total overflow")?;
                    }
                }
            }
            if sums.len() > 64 {
                return Err("business wallet asset count bound".into());
            }
            let available = wallet.balances(spend_height)?;
            if sums.iter().any(|(asset, totals)| {
                available.get(asset).copied().unwrap_or(0) != totals.available_atoms
            }) || available.keys().any(|asset| !sums.contains_key(asset))
            {
                return Err(
                    "business private receipt totals differ from wallet balance API".into(),
                );
            }
            let balances = sums
                .into_iter()
                .map(|(asset, t)| Balance {
                    asset: crate::local::hex(&asset.0),
                    received_notes: t.received,
                    spent_notes: t.spent,
                    unspent_notes: t.unspent,
                    received_atoms: t.received_atoms.to_string(),
                    spent_atoms: t.spent_atoms.to_string(),
                    unspent_atoms: t.unspent_atoms.to_string(),
                    available_atoms: t.available_atoms.to_string(),
                })
                .collect();
            Ok(WalletExpectation {
                role: role.into(),
                address: crate::local::hex(&canonical_address(&wallet.address())),
                balances,
            })
        })
        .collect()
}
fn selected(
    step: &Step,
    wallet: &Wallet,
    state: &State,
) -> Result<[Option<DigestBytes>; 2], String> {
    let mut result = [None; 2];
    for (slot, input) in step.inputs.iter().enumerate() {
        if let Some(input) = input {
            let commitment: DigestBytes =
                eng2_operations::public_bytes(&Value::String(input.commitment.clone()), 48)?
                    .try_into()
                    .map_err(|_| "business input commitment width")?;
            let receipt = wallet
                .receipts()
                .iter()
                .find(|r| r.commitment == commitment)
                .ok_or("business independently pinned original input missing")?;
            if receipt.spent
                || receipt.note().asset_id != SIP_ASSET_ID
                || receipt.note().value == 0
                || receipt.note().unlock_height > state.height
                || state.spent.contains(&receipt.nullifier)
                || crate::local::hex(&receipt.nullifier) != input.nullifier
            {
                return Err(
                    "business original input or independent real-nullifier expectation differs"
                        .into(),
                );
            }
            result[slot] = Some(commitment);
        }
    }
    Ok(result)
}
fn erase_note(note: &mut Note) {
    note.owner.fill(F::ZERO);
    note.asset_id.0.zeroize();
    note.value.zeroize();
    note.unlock_height.zeroize();
    note.rho.fill(F::ZERO);
    note.rseed.fill(F::ZERO);
}
fn check_prepared_payment(
    prepared: &PreparedTransfer,
    step: &Step,
    state: &State,
    recipient: &PaymentAddress,
    tier: FeeTier,
) -> Result<(), String> {
    let witness = &prepared.witness().slot;
    let expected_fee = crate::state::base_fee(state.height)
        .checked_mul(if tier == FeeTier::Priority { 4 } else { 1 })
        .ok_or("business expected fee overflow")?;
    if prepared.record().snapshot.height != state.height
        || witness.fee != expected_fee
        || witness.fee_is_priority != (tier == FeeTier::Priority)
        || witness.outputs[0].asset_id != SIP_ASSET_ID
        || witness.outputs[0].value != step.amount
        || witness.outputs[0].owner != recipient.owner()
        || witness.outputs[0].unlock_height != 0
    {
        return Err(
            "business prepared payment differs from independent amount, destination or fee tier"
                .into(),
        );
    }
    let hasher = Hasher::new();
    for (slot, expected) in step.inputs.iter().enumerate() {
        let input = &witness.inputs[slot];
        if let Some(expected) = expected {
            let mut note = input.note(&hasher);
            let commitment = crate::local::hex(&encode_digest(&hasher.note_cm(&note)));
            erase_note(&mut note);
            if input.dummy
                || input.value == 0
                || commitment != expected.commitment
                || crate::local::hex(&encode_digest(&prepared.public().nf[slot]))
                    != expected.nullifier
            {
                return Err(
                    "business prepared real inputs differ from independent commitments/nullifiers"
                        .into(),
                );
            }
        } else if !input.dummy || input.value != 0 {
            return Err("business planned dummy input differs".into());
        }
    }
    let mut recovered = prepared
        .payment_opening()
        .verify_payment(
            recipient,
            &prepared.public().cm[0],
            &prepared.public().payment,
            &EncryptionContext::new(state.config.network),
        )
        .map_err(|_| "business opening does not bind full expected payment address")?;
    let valid = hasher.note_cm(&recovered) == prepared.public().cm[0]
        && recovered.value == step.amount
        && recovered.asset_id == SIP_ASSET_ID
        && recovered.owner == recipient.owner()
        && recovered.unlock_height == 0;
    erase_note(&mut recovered);
    if !valid {
        return Err("business original opening and expected payment differ".into());
    }
    Ok(())
}
fn external_operations(
    claims: &[crate::eng2::fund_claim::PublicFundClaim],
    actions: &[crate::eng2_governance::SignedAction],
) -> Result<Vec<ExpectedOperation>, String> {
    let mut result = Vec::new();
    for claim in claims {
        result.push(ExpectedOperation {
            kind: "fund_claim_sha256".into(),
            identity: crate::local::hex(&Sha256::digest(claim.encode())),
        });
    }
    for action in actions {
        result.push(ExpectedOperation {
            kind: "governance_action_sha256".into(),
            identity: crate::local::hex(&Sha256::digest(action.encode()?)),
        });
    }
    Ok(result)
}
fn fund_counters(
    store: &Store,
    expected: &[ExpectedFundCounter],
) -> Result<Vec<ExpectedFundCounter>, String> {
    expected
        .iter()
        .map(|e| {
            let b = store.engine().state().fund().balance(e.member)?;
            Ok(ExpectedFundCounter {
                member: e.member,
                spent_atoms: b.spent.to_string(),
                spend_count: b.spend_count,
            })
        })
        .collect()
}
fn gate(
    started: Instant,
    plan: &Plan,
    custody: &mut impl Custody,
    phase: &str,
) -> Result<(), String> {
    if started.elapsed().as_secs() >= plan.deadline_seconds {
        return Err("business cooperative deadline exhausted".into());
    }
    custody.before_phase(phase)
}
fn frame(store: &Store, height: u64) -> Result<Vec<u8>, String> {
    let (header, body) = store.block(height)?;
    let mut bytes = header
        .encode()
        .map_err(|_| "business header encoding failed")?
        .to_vec();
    bytes.extend_from_slice(&body.encode(store.engine().body_policy())?);
    Ok(bytes)
}
fn operation_ids(body: &Body) -> Result<Vec<Value>, String> {
    let mut result = Vec::new();
    for claim in &body.fund_claims {
        result.push(json!({"height":body.height,"operation":{"kind":"fund_claim_sha256","identity":crate::local::hex(&Sha256::digest(claim.encode()))},"amount_atoms":claim.spend.amount.to_string(),"counter":claim.spend.counter}));
    }
    for action in &body.governance {
        result.push(json!({"height":body.height,"operation":{"kind":"governance_action_sha256","identity":crate::local::hex(&Sha256::digest(action.encode()?))}}));
    }
    for issuance in &body.issuances {
        result.push(json!({"height":body.height,"operation":{"kind":"issuance_declaration","identity":crate::local::hex(&issuance.signed.declaration.binding())}}));
    }
    Ok(result)
}

fn frozen_policy(
    store: &Store,
    actors: &Actors<'_>,
) -> Result<crate::eng2_governance::GovernanceState, String> {
    let state = store.engine().state().chain();
    let mut frozen_policy = store.engine().state().governance().clone();
    frozen_policy.apply_block(
        state
            .height
            .checked_add(1)
            .ok_or("business next height overflow")?,
        &[],
    )?;
    let configured = state
        .config
        .issuance
        .as_ref()
        .ok_or("business issuance policy missing")?;
    if frozen_policy.issuance_fee_atoms() != crate::issuance::TESTNET_ISSUANCE_FEE_ATOMS
        || encode_digest(&frozen_policy.active_fee_destination().owner()) != configured.fee_owner
        || canonical_address(frozen_policy.active_fee_destination())
            != canonical_address(store.engine().state().governance().active_fee_destination())
        || canonical_address(frozen_policy.active_fee_destination())
            != canonical_address(&actors.fee_destination.address())
    {
        return Err("business wallet API does not support the activated issuance policy; accepted prefix retained".into());
    }
    Ok(frozen_policy)
}
fn preflight_issuance(spec: &Issuance, state: &State) -> Result<u64, String> {
    let policy = state
        .config
        .issuance
        .as_ref()
        .ok_or("business issuance policy missing")?;
    if spec.name.is_empty()
        || spec.name.len() > 255
        || spec
            .name
            .len()
            .checked_add(1)
            .is_none_or(|n| n > usize::from(policy.max_metadata_bytes))
        || !hex(&spec.issuer_key, native::issuance::ISSUER_KEY_BYTES)
        || spec.amounts.contains(&0)
        || !hex(&spec.expected_asset_id, 32)
    {
        return Err("business issuance input bound".into());
    }
    let key: [u8; native::issuance::ISSUER_KEY_BYTES] = eng2_operations::public_bytes(
        &Value::String(spec.issuer_key.clone()),
        native::issuance::ISSUER_KEY_BYTES,
    )?
    .try_into()
    .map_err(|_| "business issuer key width")?;
    if crate::local::hex(
        &native::issuance::derive_asset_id(&state.config.network, &key, spec.sequence).0,
    ) != spec.expected_asset_id
    {
        return Err("business independent issuance asset expectation differs".into());
    }
    spec.amounts.iter().try_fold(0u64, |sum, amount| {
        sum.checked_add(*amount)
            .ok_or_else(|| "business issuance amount overflow".into())
    })
}

/// The caller must already hold the exclusive service lease for this exact
/// isolated Store and preserve any pre-open evidence before constructing it.
/// There is no implicit resume, metadata maintenance, repair or database copy.
/// Explicit production append is the only intended canonical mutation here.
#[allow(clippy::too_many_arguments)]
pub fn generate(
    store: &mut Store,
    isolated_directory: &Path,
    output_directory: &Path,
    plan_path: &Path,
    plan_pin: &str,
    binding: (&Path, &str),
    actors: &mut Actors<'_>,
    custody: &mut impl Custody,
) -> Result<Value, String> {
    if std::env::var_os("CI").is_some() || std::env::var_os("GITHUB_ACTIONS").is_some() {
        return Err("positive business material requires owner-local execution".into());
    }
    let context = Context::load(binding.0, binding.1)?;
    let encoded_plan = read(plan_path, MAX_PLAN)?;
    context.check_manifest_pin(&encoded_plan, plan_pin)?;
    let plan: Plan =
        serde_json::from_slice(&encoded_plan).map_err(|_| "business plan schema rejected")?;
    let sequence = [
        Kind::Standard,
        Kind::Priority,
        Kind::Consolidation,
        Kind::Issuance,
    ];
    let mut original_commitments = BTreeSet::new();
    let mut original_nullifiers = BTreeSet::new();
    if plan.version != 3
        || !hex(&plan.campaign_id, 32)
        || !hex(&plan.start_tip, 32)
        || !hex(&plan.external_resource_manifest_sha256, 32)
        || plan.isolated_directory
            != isolated_directory
                .to_str()
                .ok_or("business path encoding rejected")?
        || !(1..=super::full_history::MAX_HISTORY_HEIGHT - MAX_STEPS as u64)
            .contains(&plan.start_height)
        || !(1..=3600).contains(&plan.deadline_seconds)
        || !(1..=1_000_000).contains(&plan.max_nonce_attempts)
        || !(1_048_576..=17_179_869_184).contains(&plan.max_output_bytes)
        || !expected_shape(&plan.expected_before)
        || plan.steps.len() != MAX_STEPS
        || plan.steps.iter().zip(sequence).any(|(step, kind)| {
            step.kind != kind
                || !expected_shape(&step.expected_wallets)
                || step
                    .expected_wallets
                    .iter()
                    .zip(&plan.expected_before)
                    .any(|(after, before)| after.address != before.address)
                || (kind == Kind::Issuance) != step.issuance.is_some()
                || step.amount == 0
                || (kind == Kind::Issuance
                    && step.amount != crate::issuance::TESTNET_ISSUANCE_FEE_ATOMS)
                || (kind == Kind::Consolidation
                    && (step.max_note_value == 0 || step.inputs.iter().any(Option::is_none)))
                || (kind != Kind::Consolidation && step.max_note_value != 0)
                || step.inputs.iter().all(Option::is_none)
                || step.inputs.iter().flatten().any(|i| {
                    !hex(&i.commitment, 48)
                        || !hex(&i.nullifier, 48)
                        || !original_commitments.insert(i.commitment.clone())
                        || !original_nullifiers.insert(i.nullifier.clone())
                })
                || step.expected_operations.len()
                    > crate::wire::MAX_FUND_SPENDS + crate::eng2_governance::MAX_ACTIONS_PER_BLOCK
                || step.expected_operations.iter().any(|o| {
                    !matches!(
                        o.kind.as_str(),
                        "fund_claim_sha256" | "governance_action_sha256"
                    ) || !hex(&o.identity, 32)
                })
                || step.expected_fund_counters.len() > crate::eng2_governance::MAX_FUND_MEMBERS
                || step.expected_fund_counters.iter().any(|c| {
                    !decimal(&c.spent_atoms)
                        || usize::from(c.member) >= crate::eng2_governance::MAX_FUND_MEMBERS
                })
                || step
                    .expected_fund_counters
                    .windows(2)
                    .any(|w| w[0].member >= w[1].member)
        })
    {
        return Err("business plan context or bounded campaign rejected".into());
    }
    store.ensure_exportable()?;
    actors.require_fresh(&plan.expected_before)?;
    context.check_genesis(store.engine().genesis())?;
    if store.engine().genesis().fee_mode() != FeeMode::LegacyMiner
        || store.engine().state().height() != plan.start_height
        || crate::local::hex(&store.engine().state().tip()) != plan.start_tip
    {
        return Err("business plan differs from the actual legacy parent".into());
    }
    frozen_policy(store, actors)?;
    for step in &plan.steps {
        if let Some(spec) = &step.issuance {
            preflight_issuance(spec, store.engine().state().chain())?;
        }
    }
    let owner = private_directory(isolated_directory)?;
    if output_directory.starts_with(isolated_directory)
        || isolated_directory.starts_with(output_directory)
    {
        return Err("business output and isolated node must be separate".into());
    }
    let started = Instant::now();
    gate(
        started,
        &plan,
        custody,
        "before_complete_original_prefix_preflight",
    )?;
    let prefix =
        prefix::FrozenPrefix::prepare(&context, store, &plan, output_directory, started, custody)?;
    gate(started, &plan, custody, "before_public_input_preflight")?;
    let mut operations = Vec::with_capacity(MAX_STEPS);
    let mut signed_fund = false;
    let mut signed_governance = false;
    for (index, step) in plan.steps.iter().enumerate() {
        let mut fund_members = Vec::new();
        let mut claims = Vec::new();
        let mut actions = Vec::new();
        let decoded = if let Some(input) = &step.operations {
            if input.path.len() > 2048 || !hex(&input.sha256, 32) {
                return Err("business operations input bound".into());
            }
            let bytes = read(Path::new(&input.path), eng2_operations::MAX_INPUT_BYTES)?;
            context.check_manifest_pin(&bytes, &input.sha256)?;
            let value: Value =
                serde_json::from_slice(&bytes).map_err(|_| "business operations JSON rejected")?;
            let parsed = PendingOperations::decode(
                &bytes,
                store.engine().state().network(),
                plan.start_height + index as u64 + 1,
            )?;
            for entry in value["fund_claims"]
                .as_array()
                .ok_or("business fund list missing")?
            {
                let claim = crate::eng2::fund_claim::PublicFundClaim::decode(
                    &eng2_operations::public_bytes(entry, crate::eng2::fund_claim::ENCODED_BYTES)?,
                )?;
                if claim.spend.amount == 0
                    || claim.spend.owner
                        != encode_digest(&actors.fund_destination.address().owner())
                {
                    return Err(
                        "business fund claim must be positive and bind the fund actor owner".into(),
                    );
                }
                fund_members.push(claim.spend.account);
                signed_fund = true;
                claims.push(claim);
            }
            for entry in value["governance"]
                .as_array()
                .ok_or("business governance list missing")?
            {
                actions.push(crate::eng2_governance::SignedAction::decode(
                    &eng2_operations::public_bytes(entry, 16384)?,
                )?);
            }
            signed_governance |= !value["governance"]
                .as_array()
                .ok_or("business governance list missing")?
                .is_empty();
            Some(parsed)
        } else {
            None
        };
        if external_operations(&claims, &actions)? != step.expected_operations {
            return Err(
                "business signed input operations differ from independent identity expectations"
                    .into(),
            );
        }
        if fund_members
            != step
                .expected_fund_counters
                .iter()
                .map(|c| c.member)
                .collect::<Vec<_>>()
        {
            return Err("business fund counter expectations must cover exact claim members".into());
        }
        operations.push((decoded, fund_members));
    }
    if !signed_fund || !signed_governance {
        return Err("business campaign requires explicit signed fund and governance inputs".into());
    }
    let mut output = Output::create(output_directory, owner, plan.max_output_bytes)?;
    output.write("plan.json", &encoded_plan)?;
    output.write("history-budget.json", prefix.budget_bytes())?;
    output.write("genesis.bin", &store.engine().genesis().encode()?)?;
    output.json("intent.json", &json!({"version":1,"scope":"private-owner-positive-native-business","qualification":context.receipt(),"plan_sha256":plan_pin,"campaign_id":plan.campaign_id,"external_resource_manifest_sha256":plan.external_resource_manifest_sha256,"external_resource_guard_independently_verified":false,"new_blocks":MAX_STEPS,"canonical_append_authorized_by_caller":true,"completed":false,"g1_passed":false,"g2_passed":false}))?;
    gate(started, &plan, custody, "before_native_verifier_setup")?;
    let verifier = NativeVerifier::for_genesis(store.engine().genesis())?;
    let mut reference = Engine::new(
        crate::eng2::genesis::Genesis::decode(&store.engine().genesis().encode()?)?,
        store.engine().limits(),
    )?;
    for height in 1..=plan.start_height {
        gate(started, &plan, custody, "before_original_prefix_verify")?;
        let _frame_charge = prefix.before_frame(store, height)?;
        let (header, body) = store.block(height)?;
        let mut encoded = header
            .encode()
            .map_err(|_| "business original header encoding failed")?
            .to_vec();
        encoded.extend_from_slice(&body.encode(store.engine().body_policy())?);
        prefix.check_frame(&header, encoded.len())?;
        reference.apply(&header, &body, &verifier)?;
        actors.scan(reference.state().chain(), &header, &body, height != 1)?;
        output.write(&format!("block-{height:04}.frame"), &encoded)?;
    }
    let (parent_header, _) = store.block(plan.start_height)?;
    let parent_binding = Binding {
        genesis: store.engine().genesis().id(),
        rules_commitment: store.engine().genesis().rules_commitment(),
        parent: parent_header.parent,
    };
    if reference.state().tip() != store.engine().state().tip()
        || store
            .engine()
            .state()
            .canonical_components(parent_binding, store.engine().limits())?
            != reference
                .state()
                .canonical_components(parent_binding, reference.limits())?
    {
        return Err("business original prefix and all11 actual state components differ".into());
    }
    prefix.check_head(store)?;
    prefix.check_input_unchanged()?;
    output.json("original-prefix.json", &prefix.receipt())?;
    actors.require_head(store.engine().state().chain())?;
    for step in &plan.steps {
        selected(step, actors.payer, store.engine().state().chain())?;
    }
    let before = wallets(actors, plan.start_height)?;
    if before != plan.expected_before {
        return Err(
            "business original wallet scan differs from independently pinned expectations".into(),
        );
    }
    output.json("wallet-before.json", &json!({"height":plan.start_height,"tip":plan.start_tip,"expected":plan.expected_before,"observed":before,"local_wallet_scan_performed":true,"independent_s4_scan_performed":false}))?;
    frozen_policy(store, actors)?;
    gate(started, &plan, custody, "before_native_prover_setup")?;
    let prover = NativeProver::for_genesis(store.engine().genesis())?;
    let mut records = Vec::new();
    for (index, (step, (pending, fund_members))) in plan.steps.iter().zip(operations).enumerate() {
        gate(started, &plan, custody, "before_positive_business_proof")?;
        store.ensure_exportable()?;
        let state = store.engine().state().chain();
        actors.require_head(state)?;
        let selected = selected(step, actors.payer, state)?;
        let expected_recipient = match step.kind {
            Kind::Consolidation => actors.payer.address(),
            Kind::Issuance => actors.fee_destination.address(),
            _ => actors.recipient.address(),
        };
        let tier = if step.kind == Kind::Priority {
            FeeTier::Priority
        } else {
            FeeTier::Standard
        };
        let frozen = frozen_policy(store, actors)?;
        for member in fund_members {
            if canonical_address(frozen.active_fund_destination(member)?)
                != canonical_address(&actors.fund_destination.address())
            {
                return Err("business fund claim differs from full actor destination; accepted prefix retained".into());
            }
        }
        let now = state.timestamp();
        let mut issuances = Vec::new();
        let custody_cell = RefCell::new(&mut *custody);
        let payment = match step.kind {
            Kind::Standard | Kind::Priority => native_business::prove_payment(
                actors.payer,
                state,
                selected,
                &actors.recipient.address(),
                SIP_ASSET_ID,
                step.amount,
                tier,
                now,
                &prover,
                |prepared| {
                    check_prepared_payment(prepared, step, state, &expected_recipient, tier)?;
                    custody_cell.borrow_mut().protect_prepared_payment(
                        step.kind.name(),
                        &expected_recipient,
                        prepared,
                    )?;
                    gate(
                        started,
                        &plan,
                        &mut **custody_cell.borrow_mut(),
                        "before_native_business_transaction_proof",
                    )
                },
            )?,
            Kind::Consolidation => native_business::prove_small_sip_consolidation(
                actors.payer,
                state,
                step.max_note_value,
                tier,
                now,
                &prover,
                |prepared| {
                    check_prepared_payment(prepared, step, state, &expected_recipient, tier)?;
                    custody_cell.borrow_mut().protect_prepared_payment(
                        step.kind.name(),
                        &expected_recipient,
                        prepared,
                    )?;
                    gate(
                        started,
                        &plan,
                        &mut **custody_cell.borrow_mut(),
                        "before_native_business_transaction_proof",
                    )
                },
            )?
            .ok_or("business requires two genuine eligible consolidation notes")?,
            Kind::Issuance => {
                let spec = step
                    .issuance
                    .as_ref()
                    .ok_or("business issuance specification missing")?;
                let public_supply = preflight_issuance(spec, state)?;
                let issuer_key = eng2_operations::public_bytes(
                    &Value::String(spec.issuer_key.clone()),
                    native::issuance::ISSUER_KEY_BYTES,
                )?
                .try_into()
                .map_err(|_| "business issuer key width")?;
                let request = IssuanceRequest {
                    issuer_key,
                    sequence: spec.sequence,
                    public_supply,
                    metadata: native::issuance::AssetMetadata {
                        name: spec.name.clone(),
                        decimals: spec.decimals,
                    },
                    outputs: std::array::from_fn(|slot| InitialOutput {
                        recipient: actors.recipient.address(),
                        amount: spec.amounts[slot],
                    }),
                };
                let (issuance, payment) = native_business::prove_paid_issuance(
                    actors.payer,
                    state,
                    selected,
                    store.engine().state().governance().active_fee_destination(),
                    request,
                    tier,
                    now,
                    |message| custody_cell.borrow_mut().sign_issuance(message),
                    store.engine().genesis(),
                    &prover,
                    |prepared| {
                        check_prepared_payment(prepared, step, state, &expected_recipient, tier)?;
                        custody_cell.borrow_mut().protect_prepared_payment(
                            step.kind.name(),
                            &expected_recipient,
                            prepared,
                        )?;
                        gate(
                            started,
                            &plan,
                            &mut **custody_cell.borrow_mut(),
                            "before_native_business_transaction_proof",
                        )
                    },
                    |phase| gate(started, &plan, &mut **custody_cell.borrow_mut(), phase),
                )?;
                if crate::local::hex(&issuance.record.signed.declaration.asset_id.0)
                    != spec.expected_asset_id
                {
                    return Err(
                        "business produced issuance asset differs from independent expectation"
                            .into(),
                    );
                }
                issuances.push(issuance);
                payment
            }
        };
        let statement = payment
            .transaction
            .record
            .statement_id(&state.config.network);
        let public = PublicTransaction::decode(&payment.transaction.record.body)
            .map_err(|_| "business public transaction decode failed")?;
        let nullifiers: Vec<_> = public
            .nf
            .into_iter()
            .map(|nf| crate::local::hex(&encode_digest(&nf)))
            .collect();
        let timestamp = state
            .timestamp()
            .checked_add(300)
            .ok_or("business timestamp overflow")?;
        gate(
            started,
            &plan,
            &mut **custody_cell.borrow_mut(),
            "before_explicit_canonical_append",
        )?;
        let produced = native_business::append_business_block(
            store,
            &prover,
            &verifier,
            native_business::BusinessInputs {
                payments: vec![(payment, tier)],
                issuances,
                operations: pending,
            },
            timestamp,
            &crate::producer::MiningSettings {
                mode: crate::wire::RewardMode::Voyager,
                recipient: actors.reward.address(),
            },
            plan.max_nonce_attempts,
            |payment| {
                custody_cell.borrow_mut().protect_payment(
                    step.kind.name(),
                    &expected_recipient,
                    payment,
                )
            },
            |issuance| {
                custody_cell
                    .borrow_mut()
                    .protect_issuance(&actors.recipient.address(), issuance)
            },
            |block| custody_cell.borrow_mut().protect_reward(block),
            |phase| gate(started, &plan, &mut **custody_cell.borrow_mut(), phase),
        )?;
        store.ensure_exportable()?;
        let height = plan.start_height + index as u64 + 1;
        let (header, body) = store.block(height)?;
        if produced.committed.id()
            != header
                .id()
                .map_err(|_| "business committed header invalid")?
            || produced.transactions != [statement]
            || produced.frame != frame(store, height)?
        {
            return Err("business appended frame differs from committed material".into());
        }
        gate(
            started,
            &plan,
            &mut **custody_cell.borrow_mut(),
            "before_new_frame_independent_verification",
        )?;
        reference.apply(&header, &body, &verifier)?;
        actors.scan(reference.state().chain(), &header, &body, true)?;
        actors.require_head(store.engine().state().chain())?;
        let observed = wallets(actors, height)?;
        output.write(&format!("block-{height:04}.frame"), &produced.frame)?;
        let fund_post_counters: Vec<_> = body.fund_claims.iter().map(|claim| {
            let balance = store.engine().state().fund().balance(claim.spend.account)?;
            Ok(json!({"member":claim.spend.account,"entitlement":balance.entitlement.to_string(),"direct_unlocked":balance.direct_unlocked.to_string(),"vesting_unlocked":balance.vesting_unlocked.to_string(),"spent":balance.spent.to_string(),"spend_count":balance.spend_count}))
        }).collect::<Result<Vec<Value>, String>>()?;
        for (slot, expected) in step.inputs.iter().enumerate() {
            if let Some(expected) = expected {
                let nf: DigestBytes =
                    eng2_operations::public_bytes(&Value::String(expected.nullifier.clone()), 48)?
                        .try_into()
                        .map_err(|_| "business real nullifier width")?;
                if crate::local::hex(&encode_digest(&public.nf[slot])) != expected.nullifier
                    || !store.engine().state().chain().spent.contains(&nf)
                {
                    return Err(
                        "business real nullifier differs or is absent after canonical append"
                            .into(),
                    );
                }
            }
        }
        let actual_external_operations = external_operations(&body.fund_claims, &body.governance)?;
        let actual_fund_counters = fund_counters(store, &step.expected_fund_counters)?;
        let expectations_equal = actual_external_operations == step.expected_operations
            && actual_fund_counters == step.expected_fund_counters
            && store.engine().state().governance().sequence() == step.expected_governance_sequence;
        let operations = operation_ids(&body)?;
        let record = json!({"height":height,"id":crate::local::hex(&produced.committed.id()),"kind":step.kind.name(),"transaction_statement":crate::local::hex(&statement),"transaction_nullifiers":nullifiers,"expected_real_nullifiers":step.inputs.iter().map(|i| i.as_ref().map(|i|i.nullifier.as_str())).collect::<Vec<_>>(),"dummy_nullifiers_independently_preknown":false,"expected_external_operations":step.expected_operations,"expected_fund_counters":step.expected_fund_counters,"expected_governance_sequence":step.expected_governance_sequence,"operation_counter_sequence_expectations_equal":expectations_equal,"issuance_declarations":produced.issuances.into_iter().map(|id| crate::local::hex(&id)).collect::<Vec<_>>(),"included_operations":operations,"fund_post_counters":fund_post_counters,"governance_sequence":store.engine().state().governance().sequence(),"active_issuance_fee_atoms":store.engine().state().governance().issuance_fee_atoms(),"frame_sha256":crate::local::hex(&Sha256::digest(&produced.frame)),"frame_bytes":produced.frame.len(),"wallet_balance_spend_height":height,"wallet_expected":step.expected_wallets,"wallet_observed":observed,"wallet_expectations_equal_local_scan":observed == step.expected_wallets,"independent_s4_scan_performed":false,"full_business_acceptance_passed":false});
        output.json(&format!("business-{height:04}.json"), &record)?;
        if !expectations_equal {
            return Err(
                "business operation/counter/sequence expectations differ; accepted prefix retained"
                    .into(),
            );
        }
        if observed != step.expected_wallets {
            return Err("business wallet scan differs from independently pinned expectations; accepted prefix retained".into());
        }
        records.push(record);
    }
    let final_height = store.engine().state().height();
    let (header, _) = store.block(final_height)?;
    let state_binding = Binding {
        genesis: store.engine().genesis().id(),
        rules_commitment: store.engine().genesis().rules_commitment(),
        parent: header.parent,
    };
    if store
        .engine()
        .state()
        .canonical_components(state_binding, store.engine().limits())?
        != reference
            .state()
            .canonical_components(state_binding, reference.limits())?
    {
        return Err(
            "business final actual components differ from independent native replay".into(),
        );
    }
    prefix.check_input_unchanged()?;
    if read(plan_path, MAX_PLAN)? != encoded_plan {
        return Err("business pinned plan changed during generation".into());
    }
    gate(started, &plan, custody, "before_positive_business_closeout")?;
    let result = json!({"version":1,"scope":"private-owner-positive-native-business","qualification":context.receipt(),"campaign_id":plan.campaign_id,"plan_sha256":plan_pin,"new_blocks":MAX_STEPS,"final_height":final_height,"final_tip":crate::local::hex(&store.engine().state().tip()),"native_verified_and_explicitly_appended":true,"all11_actual_component_bytes_equal_independent_native_replay":true,"business":records,"original_history":prefix.receipt(),"wallet_material_private":true,"dedicated_wallet_scanner_memory_mutated":true,"custody_implementation_independently_verified":false,"expectation_author_independently_verified":false,"independent_s4_scan_performed":false,"independent_p5_audit_manifest_produced":false,"complete_fee_activated":false,"full_business_acceptance_passed":false,"g1_passed":false,"g2_passed":false,"elapsed_ms":started.elapsed().as_millis().to_string()});
    output.json("completed.json", &result)?;
    Ok(
        json!({"version":1,"scope":"private-owner-positive-native-business","campaign_id":plan.campaign_id,"plan_sha256":plan_pin,"new_blocks":MAX_STEPS,"final_height":final_height,"private_result_written":true,"dedicated_wallet_scanner_memory_mutated":true,"custody_implementation_independently_verified":false,"expectation_author_independently_verified":false,"native_verified_and_explicitly_appended":true,"all11_actual_component_bytes_equal_independent_native_replay":true,"independent_s4_scan_performed":false,"independent_p5_audit_manifest_produced":false,"complete_fee_activated":false,"full_business_acceptance_passed":false,"g1_passed":false,"g2_passed":false}),
    )
}
