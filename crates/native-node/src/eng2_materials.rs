//! Fresh engineering-only public material preparation and post-genesis binding.
//! No network client, existing wallet import or production custody claim.
use crate::{eng2::genesis::Genesis, eng2_governance::canonical_address, wallet::WalletKeys};
use libcrux_ml_dsa::ml_dsa_65;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};
mod signing;
mod storage;
pub use signing::{SigningPins, sign_operation};
#[cfg(test)]
mod tests;

const MAGIC: &[u8; 8] = b"SW2MAT01";
const PENDING_BYTES: usize = 8 + 32 + 1 + 1 + 32 + 32;
const PENDING_CONTEXT: &str = "siworld eng2 pending material record v1";
const BOUND_CONTEXT: &str = "siworld eng2 checkpoint test signer record v1";
type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    Checkpoint = 0,
    Founder = 1,
    Revocation = 2,
    FundClaim = 3,
    FeeWallet = 4,
    FundWallet = 5,
    MinerWallet = 6,
}
impl Purpose {
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "checkpoint" => Ok(Self::Checkpoint),
            "founder" => Ok(Self::Founder),
            "revocation" => Ok(Self::Revocation),
            "fund-claim" => Ok(Self::FundClaim),
            "fee-wallet" => Ok(Self::FeeWallet),
            "fund-wallet" => Ok(Self::FundWallet),
            "miner-wallet" => Ok(Self::MinerWallet),
            _ => Err("unknown engineering material purpose".into()),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Checkpoint => "checkpoint",
            Self::Founder => "founder",
            Self::Revocation => "revocation",
            Self::FundClaim => "fund-claim",
            Self::FeeWallet => "fee-wallet",
            Self::FundWallet => "fund-wallet",
            Self::MinerWallet => "miner-wallet",
        }
    }
    fn check(self, index: u8) -> Result<()> {
        let valid = match self {
            Self::Checkpoint => index < 3,
            Self::FundClaim | Self::FundWallet => index < 32,
            _ => index == 0,
        };
        if valid {
            Ok(())
        } else {
            Err("engineering material index is invalid".into())
        }
    }
    fn wallet(self) -> bool {
        matches!(self, Self::FeeWallet | Self::FundWallet | Self::MinerWallet)
    }
}
fn sha(bytes: &[u8]) -> String {
    crate::local::hex(&Sha256::digest(bytes))
}
fn public_parameters(
    network: [u8; 32],
    purpose: Purpose,
    index: u8,
    seed: Zeroizing<[u8; 32]>,
) -> Result<(Vec<u8>, String)> {
    let (algorithm, public) = if purpose.wallet() {
        let address = WalletKeys::from_seed(network, seed, 0)?.address();
        (
            "native-payment-address",
            canonical_address(&address).to_vec(),
        )
    } else {
        let mut pair = ml_dsa_65::generate_key_pair(*seed);
        let public = pair.verification_key.as_ref().to_vec();
        pair.signing_key.as_mut_slice().zeroize();
        ("ML-DSA-65", public)
    };
    let fingerprint = sha(&public);
    let mut value = json!({"version":1,"scope":"eng2-only","network":crate::local::hex(&network),"purpose":purpose.name(),"index":index,"algorithm":algorithm});
    value[if purpose.wallet() {
        "address_hex"
    } else {
        "public_key_hex"
    }] = Value::String(crate::local::hex(&public));
    if purpose.wallet() {
        value["account"] = json!(0);
    }
    let bytes = serde_json::to_vec(&value).map_err(|_| "public material encoding failed")?;
    Ok((bytes, fingerprint))
}
fn receipt(
    network: [u8; 32],
    purpose: Purpose,
    index: u8,
    public: &[u8],
    identity: &str,
    operation: &str,
) -> Value {
    json!({"version":1,"scope":"eng2-only","operation":operation,"network":crate::local::hex(&network),"purpose":purpose.name(),"index":index,"public_parameters_sha256":sha(public),"public_identity_sha256":identity,"private_directory_mode":"0700","private_file_mode":"0600","write_once":true,"source":{"package_version":env!("CARGO_PKG_VERSION"),"commit":option_env!("SIWORLD_BUILD_COMMIT"),"module_sha256":sha(include_bytes!("eng2_materials.rs")),"storage_sha256":sha(include_bytes!("eng2_materials/storage.rs")),"signing_sha256":sha(include_bytes!("eng2_materials/signing.rs")),"cli_sha256":sha(include_bytes!("bin/siworld-eng2-materials.rs"))}})
}
/// Create a new independent seed. The custody directory must not exist and must
/// be outside every Git checkout. Only public hashes are returned.
pub fn prepare(directory: &Path, network: [u8; 32], purpose: Purpose, index: u8) -> Result<Value> {
    purpose.check(index)?;
    if network == [0; 32] {
        return Err("nonzero engineering network is required".into());
    }
    prepare_with_entropy(directory, network, purpose, index, |seed| {
        getrandom::fill(seed).map_err(|_| "OS randomness unavailable".into())
    })
}
fn prepare_with_entropy(
    directory: &Path,
    network: [u8; 32],
    purpose: Purpose,
    index: u8,
    fill: impl FnOnce(&mut [u8; 32]) -> Result<()>,
) -> Result<Value> {
    purpose.check(index)?;
    if network == [0; 32] {
        return Err("nonzero engineering network is required".into());
    }
    let mut seed = Zeroizing::new([0; 32]);
    fill(&mut seed)?;
    prepare_seed(directory, network, purpose, index, seed)
}
fn prepare_seed(
    directory: &Path,
    network: [u8; 32],
    purpose: Purpose,
    index: u8,
    seed: Zeroizing<[u8; 32]>,
) -> Result<Value> {
    purpose.check(index)?;
    if network == [0; 32] {
        return Err("nonzero engineering network is required".into());
    }
    let (public, fingerprint) = public_parameters(network, purpose, index, Zeroizing::new(*seed))?;
    let mut pending = Zeroizing::new(Vec::with_capacity(PENDING_BYTES));
    pending.extend_from_slice(MAGIC);
    pending.extend_from_slice(&network);
    pending.push(purpose as u8);
    pending.push(index);
    pending.extend_from_slice(seed.as_ref());
    let checksum = blake3::derive_key(PENDING_CONTEXT, &pending);
    pending.extend_from_slice(&checksum);
    let custody = storage::Directory::create(directory)?;
    custody.write_once("pending.secret", &pending)?;
    custody.write_once("public.json", &public)?;
    if *custody.read("pending.secret", PENDING_BYTES)? != *pending
        || *custody.read("public.json", public.len())? != public
    {
        return Err("engineering material readback failed".into());
    }
    Ok(receipt(
        network,
        purpose,
        index,
        &public,
        &fingerprint,
        "prepare",
    ))
}
/// Bind an existing checkpoint seed after the public genesis was independently
/// sealed. This creates the exact current runtime record without changing it.
pub fn bind_checkpoint(
    directory: &Path,
    genesis_path: &Path,
    expected_id: [u8; 32],
    expected_sha256: [u8; 32],
) -> Result<Value> {
    if expected_id == [0; 32] || expected_sha256 == [0; 32] {
        return Err("independent genesis pins are required".into());
    }
    let bytes = storage::read_public(genesis_path, 262_144)?;
    if Sha256::digest(&bytes).as_slice() != expected_sha256 {
        return Err("sealed genesis digest differs".into());
    }
    // The current genesis prefix is magic8/mode1/profile32 followed by
    // Config::encode_rules; fixture is its fixed byte33. Reject it before
    // Config::decode_rules can invoke development fixture constructors.
    if bytes.len() < 41 + crate::state::CONFIG_RULE_BYTES
        || &bytes[..8] != b"SWE2GEN1"
        || bytes[8] != crate::eng2::genesis::FeeMode::LegacyMiner as u8
        || bytes[41 + 33] != 0
    {
        return Err("nonfixture LegacyMiner genesis is required".into());
    }
    let genesis = Genesis::decode(&bytes)?;
    if genesis.config().fixture
        || genesis.config().pow_iterations == 0
        || genesis.config().economics != siworld_core::v1_economics::EconomicsParams::production()
    {
        return Err("production economic and work parameters are required".into());
    }
    if genesis.id() != expected_id {
        return Err("sealed genesis identity differs".into());
    }
    let custody = storage::Directory::open(directory)?;
    let pending = custody.read("pending.secret", PENDING_BYTES)?;
    if &pending[..8] != MAGIC
        || pending[8..40] != genesis.config().network
        || pending[40] != Purpose::Checkpoint as u8
        || pending[41] >= 3
        || pending[74..] != blake3::derive_key(PENDING_CONTEXT, &pending[..74])
    {
        return Err("checkpoint preparation context differs".into());
    }
    let index = pending[41];
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(&pending[42..74]).map_err(|_| "pending seed width invalid")?,
    );
    let (public, fingerprint) = public_parameters(
        genesis.config().network,
        Purpose::Checkpoint,
        index,
        Zeroizing::new(*seed),
    )?;
    if *custody.read("public.json", public.len())? != public {
        return Err("prepared public parameters differ".into());
    }
    let mut pair = ml_dsa_65::generate_key_pair(*seed);
    let matches = genesis.initial_governance().active_roster().keys()[usize::from(index)]
        == *pair.verification_key.as_ref();
    pair.signing_key.as_mut_slice().zeroize();
    if !matches {
        return Err("checkpoint public key is not in the selected genesis slot".into());
    }
    let mut bound = Zeroizing::new(Vec::with_capacity(169));
    bound.extend_from_slice(b"SW2KEY01");
    for value in [
        genesis.config().network,
        genesis.id(),
        genesis.rules_commitment(),
    ] {
        bound.extend_from_slice(&value);
    }
    bound.push(index);
    bound.extend_from_slice(seed.as_ref());
    let checksum = blake3::derive_key(BOUND_CONTEXT, &bound);
    bound.extend_from_slice(&checksum);
    custody.write_once("checkpoint-bound.secret", &bound)?;
    if *custody.read("checkpoint-bound.secret", 169)? != *bound {
        return Err("bound checkpoint readback failed".into());
    }
    let mut result = receipt(
        genesis.config().network,
        Purpose::Checkpoint,
        index,
        &public,
        &fingerprint,
        "bind-checkpoint",
    );
    result["genesis"] = json!(crate::local::hex(&genesis.id()));
    result["genesis_sha256"] = json!(crate::local::hex(&expected_sha256));
    result["rules_commitment"] = json!(crate::local::hex(&genesis.rules_commitment()));
    result["pending_preserved"] = json!(true);
    result["runtime_record_bytes"] = json!(169);
    Ok(result)
}
