//! Bounded owner-local executable custody, business and independent scan chain.
use super::Context;
use crate::{
    eng2::{genesis::Genesis, store::Store},
    eng2_governance::{canonical_address, decode_address},
    eng2_materials::issuer::{IssuerExpectation, IssuerSigner, prepare_isolated_issuer},
    wallet_vault::{
        WalletVault,
        rehearsal::{ActorRole, RehearsalBinding},
    },
    wire::Hash,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Instant,
};
mod business;
mod passwords;
mod resources;
mod scan;
use resources::{Guard, ResourcePlan};
const ROLES: [ActorRole; 5] = [
    ActorRole::Payer,
    ActorRole::Recipient,
    ActorRole::FeeDestination,
    ActorRole::FundDestination,
    ActorRole::Reward,
];
const NAMES: [&str; 5] = [
    "payer",
    "recipient",
    "fee_destination",
    "fund_destination",
    "reward",
];
type Result<T> = std::result::Result<T, String>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    role: String,
    directory: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    height: u64,
    tip: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    action: String,
    source_commit: String,
    binary_sha256: String,
    initialization: Input,
    prerequisites: Input,
    actors: [Actor; 5],
    issuer_directory: PathBuf,
    excluded_roots: Vec<PathBuf>,
    resources: ResourcePlan,
    initial_receipt: Option<Input>,
    genesis: Option<Input>,
    qualification: Option<Input>,
    business: Option<Input>,
    expectations: Option<Input>,
    head: Option<Head>,
    node_directory: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prerequisites {
    version: u32,
    parameters: Value,
    reward_role: String,
}
#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct CustodySet {
    version: u32,
    initialization_sha256: String,
    prerequisites_sha256: String,
    addresses: [String; 5],
    issuer_key: String,
    genesis_id: String,
    genesis_sha256: String,
}
fn hash(text: &str) -> Result<Hash> {
    crate::eng2::genesis_tool::parse_hash(text).map_err(|_| "custody_public_hash_rejected".into())
}
fn sha(bytes: &[u8]) -> String {
    crate::local::hex(&Sha256::digest(bytes))
}
fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    if !path.is_absolute() || path.canonicalize().ok().as_deref() != Some(path) {
        return Err("custody_public_path_rejected".into());
    }
    let f = fs::File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| "custody_public_input_unavailable")?,
    );
    let m = f
        .metadata()
        .map_err(|_| "custody_public_input_unavailable")?;
    if !m.is_file()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o022 != 0
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > maximum as u64
    {
        return Err("custody_public_input_rejected".into());
    }
    let mut b = Vec::new();
    f.take((maximum + 1) as u64)
        .read_to_end(&mut b)
        .map_err(|_| "custody_public_input_unavailable")?;
    if b.is_empty() || b.len() > maximum {
        return Err("custody_public_input_rejected".into());
    }
    Ok(b)
}
fn load(input: &Input, maximum: usize) -> Result<Vec<u8>> {
    let b = read(&input.path, maximum)?;
    if sha(&b) != input.sha256 {
        return Err("custody_public_pin_changed".into());
    }
    Ok(b)
}
fn canonical_private(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(|_| "custody_directory_unavailable")?;
    if path.canonicalize().ok().as_deref() != Some(path)
        || !m.is_dir()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o7777 != 0o700
    {
        return Err("custody_directory_rejected".into());
    }
    Ok(())
}
fn overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
struct Output {
    path: PathBuf,
    used: u64,
}
impl Output {
    fn create(path: &Path) -> Result<Self> {
        Self::create_with_parent_sync(path, |parent| {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| "custody_output_parent_durability_failed".into())
        })
    }
    fn create_with_parent_sync(
        path: &Path,
        sync_parent: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<Self> {
        crate::wallet_vault::rehearsal::new_private_path(path)?;
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|_| "custody_output_requires_new_directory")?;
        // A failed parent synchronization preserves the new empty directory.
        sync_parent(path.parent().ok_or("custody_output_parent_required")?)?;
        Ok(Self {
            path: path.into(),
            used: 0,
        })
    }
    fn write(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        self.used = self
            .used
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= 64 * 1024 * 1024)
            .ok_or("custody_output_budget_exhausted")?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.path.join(name))
            .map_err(|_| "custody_output_unavailable")?;
        f.write_all(bytes)
            .and_then(|_| f.sync_all())
            .map_err(|_| "custody_output_durability_failed")?;
        fs::File::open(&self.path)
            .and_then(|d| d.sync_all())
            .map_err(|_| "custody_output_durability_failed".into())
    }
    fn json(&mut self, name: &str, value: &impl Serialize) -> Result<()> {
        let b = serde_json::to_vec(value).map_err(|_| "custody_output_encoding_failed")?;
        self.write(name, &b)
    }
}
fn address(text: &str) -> Result<native::encryption::PaymentAddress> {
    let b: [u8; 1232] = crate::eng2_operations::public_bytes(&json!(text), 1232)?
        .try_into()
        .map_err(|_| "custody_address_width_rejected")?;
    decode_address(&b)
}
fn authority(text: &str) -> Result<[u8; 1952]> {
    crate::eng2_operations::public_bytes(&json!(text), 1952)?
        .try_into()
        .map_err(|_| "custody_issuer_width_rejected".into())
}
fn resolve(prerequisites: &Prerequisites, addresses: &[String; 5]) -> Result<Genesis> {
    if prerequisites.version != 1 || prerequisites.reward_role != "reward" {
        return Err("custody_prerequisites_rejected".into());
    }
    let mut p = prerequisites.parameters.clone();
    if p["fee_destination"] != "$actor:fee_destination" {
        return Err("custody_fee_placeholder_rejected".into());
    }
    p["fee_destination"] = json!(addresses[2]);
    let members = p["fund"]["members"]
        .as_array_mut()
        .ok_or("custody_fund_placeholder_rejected")?;
    if members.is_empty() || members.len() > 32 {
        return Err("custody_fund_placeholder_rejected".into());
    }
    for member in members {
        if member["destination"] != "$actor:fund_destination" {
            return Err("custody_fund_placeholder_rejected".into());
        }
        member["destination"] = json!(addresses[3]);
    }
    crate::eng2::genesis_tool::reconstruct(&p)
        .map_err(|_| "custody_genesis_projection_rejected".into())
}
fn set(
    binding: &RehearsalBinding,
    plan: &Plan,
    prerequisites: &Prerequisites,
    addresses: [String; 5],
    issuer_key: String,
) -> Result<CustodySet> {
    let unique: std::collections::BTreeSet<_> = addresses.iter().collect();
    if unique.len() != 5 {
        return Err("custody_actor_addresses_overlap".into());
    }
    let genesis = resolve(prerequisites, &addresses)?;
    if genesis.config().network != binding.network() {
        return Err("custody_projected_network_differs".into());
    }
    let bytes = genesis.encode()?;
    Ok(CustodySet {
        version: 1,
        initialization_sha256: plan.initialization.sha256.clone(),
        prerequisites_sha256: plan.prerequisites.sha256.clone(),
        addresses,
        issuer_key,
        genesis_id: crate::local::hex(&genesis.id()),
        genesis_sha256: sha(&bytes),
    })
}
fn existing(
    plan: &Plan,
    binding: &RehearsalBinding,
    prerequisites: &Prerequisites,
    passwords: &passwords::Passwords,
    guard: &Guard<'_>,
) -> Result<CustodySet> {
    let input = plan
        .initial_receipt
        .as_ref()
        .ok_or("custody_initial_receipt_required")?;
    let expected: CustodySet = serde_json::from_slice(&load(input, 32768)?)
        .map_err(|_| "custody_initial_receipt_rejected")?;
    let mut addresses = Vec::with_capacity(5);
    for (i, spec) in plan.actors.iter().enumerate() {
        guard.check()?;
        let vault = WalletVault::open_isolated_rehearsal(
            &spec.directory,
            &passwords.0[i],
            binding,
            ROLES[i],
        )?;
        addresses.push(crate::local::hex(&canonical_address(
            &vault.wallet()?.address(),
        )));
    }
    let key = authority(&expected.issuer_key)?;
    let _issuer = IssuerSigner::open(&plan.issuer_directory, binding, key)?;
    let actual = set(
        binding,
        plan,
        prerequisites,
        addresses
            .try_into()
            .map_err(|_| "custody_actor_count_rejected")?,
        expected.issuer_key.clone(),
    )?;
    if actual != expected {
        return Err("custody_actual_identity_set_differs".into());
    }
    Ok(actual)
}
fn genesis(plan: &Plan, prerequisites: &Prerequisites, custody: &CustodySet) -> Result<Genesis> {
    let input = plan.genesis.as_ref().ok_or("custody_genesis_required")?;
    let bytes = load(input, 1024 * 1024)?;
    let actual = Genesis::decode(&bytes)?;
    let expected = resolve(prerequisites, &custody.addresses)?;
    if actual.encode()? != expected.encode()? || sha(&bytes) != custody.genesis_sha256 {
        return Err("custody_sealed_genesis_projection_differs".into());
    }
    Ok(actual)
}
fn validate_paths(plan: &Plan, output: &Path, initialize: bool) -> Result<()> {
    if !output.starts_with(&plan.resources.run_root)
        || plan.excluded_roots.is_empty()
        || plan.excluded_roots.len() > 32
    {
        return Err("custody_path_scope_rejected".into());
    }
    let mut roots = vec![output.to_path_buf()];
    for (i, a) in plan.actors.iter().enumerate() {
        if a.role != NAMES[i] {
            return Err("custody_role_order_rejected".into());
        }
        roots.push(a.directory.clone());
    }
    roots.push(plan.issuer_directory.clone());
    for (i, path) in roots.iter().enumerate() {
        if !path.starts_with(&plan.resources.run_root)
            || roots[..i].iter().any(|p| overlap(p, path))
        {
            return Err("custody_path_overlap".into());
        }
        if initialize || i == 0 {
            crate::wallet_vault::rehearsal::new_private_path(path)?;
        } else {
            canonical_private(path)?;
        }
    }
    if let Some(node) = &plan.node_directory {
        canonical_private(node)?;
        if !node.starts_with(&plan.resources.run_root) || roots.iter().any(|p| overlap(p, node)) {
            return Err("custody_node_path_overlap".into());
        }
    }
    if let Some(node) = &plan.node_directory {
        roots.push(node.clone());
    }
    for excluded in &plan.excluded_roots {
        let actual = excluded
            .canonicalize()
            .map_err(|_| "custody_excluded_root_unavailable")?;
        if actual != *excluded || roots.iter().any(|p| overlap(p, excluded)) {
            return Err("custody_excluded_root_overlap".into());
        }
    }
    Ok(())
}
fn frozen_inputs(plan: &Plan) -> Result<Vec<(&Input, Vec<u8>)>> {
    let inputs = [
        (&plan.initial_receipt, 32768),
        (&plan.genesis, 1024 * 1024),
        (&plan.qualification, 8192),
        (&plan.business, 128 * 1024),
        (&plan.expectations, 16 * 1024 * 1024),
    ];
    let mut frozen = Vec::new();
    for (input, maximum) in inputs {
        if let Some(input) = input {
            frozen.push((input, load(input, maximum)?));
        }
    }
    Ok(frozen)
}
fn execute(action: &str, plan_path: &Path, pin: &str, output: &Path) -> Result<Value> {
    if std::env::var_os("GITHUB_ACTIONS").is_some() || std::env::var("CI").as_deref() == Ok("true")
    {
        return Err("custody_owner_environment_required".into());
    }
    let encoded = load(
        &Input {
            path: plan_path.into(),
            sha256: pin.into(),
        },
        128 * 1024,
    )?;
    let plan: Plan =
        serde_json::from_slice(&encoded).map_err(|_| "custody_plan_schema_rejected")?;
    if plan.version != 1
        || plan.action != action
        || option_env!("SIWORLD_BUILD_COMMIT") != Some(plan.source_commit.as_str())
        || crate::local::hex(
            &crate::eng2::genesis_tool::executable_sha256()
                .map_err(|_| "custody_executable_unavailable")?,
        ) != plan.binary_sha256
    {
        return Err("custody_source_binary_binding_rejected".into());
    }
    let parameters = load(&plan.initialization, 4096)?;
    let binding = RehearsalBinding::decode(&parameters, hash(&plan.initialization.sha256)?)?;
    let prerequisite_bytes = load(&plan.prerequisites, 262144)?;
    if binding.receipt()["genesis_parameters_sha256"].as_str()
        != Some(sha(&prerequisite_bytes).as_str())
    {
        return Err("custody_prerequisite_pin_differs".into());
    }
    let prerequisites: Prerequisites = serde_json::from_slice(&prerequisite_bytes)
        .map_err(|_| "custody_prerequisite_schema_rejected")?;
    // Check every existing genesis serializer/policy before drawing any identity entropy.
    let dummy = format!("01000000{}", "00".repeat(1228));
    let projected = resolve(&prerequisites, &std::array::from_fn(|_| dummy.clone()))?;
    if projected.config().network != binding.network() {
        return Err("custody_prerequisite_network_differs".into());
    }
    let initialize = action == "init";
    if !matches!(action, "init" | "open" | "business" | "scan")
        || initialize
            && (plan.initial_receipt.is_some()
                || plan.genesis.is_some()
                || plan.business.is_some()
                || plan.qualification.is_some()
                || plan.expectations.is_some()
                || plan.head.is_some()
                || plan.node_directory.is_some())
        || action == "open"
            && (plan.genesis.is_some()
                || plan.business.is_some()
                || plan.qualification.is_some()
                || plan.expectations.is_some()
                || plan.head.is_some()
                || plan.node_directory.is_some())
    {
        return Err("custody_action_plan_rejected".into());
    }
    validate_paths(&plan, output, initialize)?;
    let guard = Guard::new(&plan.resources)?;
    let frozen = frozen_inputs(&plan)?;
    guard.check()?;
    let passwords = passwords::read()?;
    guard.check()?;
    let mut out = Output::create(output)?;
    out.write("plan.json", &encoded)?;
    let result = if initialize {
        let mut addresses = Vec::new();
        for (i, spec) in plan.actors.iter().enumerate() {
            guard.check()?;
            let vault = WalletVault::create_isolated_rehearsal(
                &spec.directory,
                &passwords.0[i],
                &binding,
                ROLES[i],
            )?;
            let r = WalletVault::isolated_rehearsal_receipt(&vault, &binding, ROLES[i])?;
            addresses.push(
                r["address_hex"]
                    .as_str()
                    .ok_or("custody_actor_receipt_rejected")?
                    .to_owned(),
            );
            out.json(&format!("actor-{}.json", NAMES[i]), &r)?;
        }
        guard.check()?;
        let issuer = prepare_isolated_issuer(&plan.issuer_directory, &binding)?;
        out.json("issuer.json", &issuer)?;
        let public: Value =
            serde_json::from_slice(&read(&plan.issuer_directory.join("public.json"), 8192)?)
                .map_err(|_| "custody_issuer_public_rejected")?;
        let actual = set(
            &binding,
            &plan,
            &prerequisites,
            addresses
                .try_into()
                .map_err(|_| "custody_actor_count_rejected")?,
            public["public_key_hex"]
                .as_str()
                .ok_or("custody_issuer_public_rejected")?
                .to_owned(),
        )?;
        // Read back every actual vault again before issuing the complete set receipt.
        for (i, a) in plan.actors.iter().enumerate() {
            guard.check()?;
            let _ = WalletVault::open_isolated_rehearsal(
                &a.directory,
                &passwords.0[i],
                &binding,
                ROLES[i],
            )?;
        }
        let _ = IssuerSigner::open(
            &plan.issuer_directory,
            &binding,
            authority(&actual.issuer_key)?,
        )?;
        out.json("custody.json", &actual)?;
        json!({"operation":"init","custody_set_sha256":sha(&serde_json::to_vec(&actual).map_err(|_|"custody_output_encoding_failed")?),"operational_business_passed":false})
    } else {
        let custody = existing(&plan, &binding, &prerequisites, &passwords, &guard)?;
        match action {
            "open" => {
                out.json("custody.json", &custody)?;
                json!({"operation":"open","authenticated_custody_reopened":true})
            }
            "business" => business::run(
                &plan,
                &binding,
                &prerequisites,
                &custody,
                &passwords,
                &guard,
                &mut out,
            )?,
            "scan" => scan::run(
                &plan,
                &prerequisites,
                &custody,
                &passwords,
                &guard,
                &mut out,
            )?,
            _ => return Err("custody_action_rejected".into()),
        }
    };
    guard.check()?;
    if read(plan_path, 128 * 1024)? != encoded
        || load(&plan.initialization, 4096)? != parameters
        || load(&plan.prerequisites, 262144)? != prerequisite_bytes
    {
        return Err("custody_frozen_input_changed".into());
    }
    for (input, bytes) in frozen {
        if load(input, bytes.len())? != bytes {
            return Err("custody_frozen_input_changed".into());
        }
        guard.check()?;
    }
    out.json("completed.json", &result)?;
    // Completion requires both this retained receipt and a successful exit.
    guard.check()?;
    Ok(
        json!({"version":1,"operation":action,"completed_receipt_sha256":sha(&serde_json::to_vec(&result).map_err(|_|"custody_output_encoding_failed")?),"g1_passed":false,"g2_passed":false}),
    )
}
/// Errors deliberately hide all implementation/parser/custody contents.
pub fn run(action: &str, plan: &Path, pin: &str, output: &Path) -> Result<Value> {
    execute(action, plan, pin, output)
        .map_err(|_| "custody_operation_failed; retained records preserved".into())
}
#[cfg(test)]
mod tests;
