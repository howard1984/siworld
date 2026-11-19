//! Offline sealing and reconstruction of explicitly pinned public parameters.
use super::{
    commitment::{self, COMPONENTS, Component, ComponentId},
    genesis::{FeeMode, Genesis},
    state_components::{Binding, Limits},
};
use crate::{eng2_governance::GovernanceState, state::Config, wire::Hash};
use native::codec::encode_digest;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

mod parameters;
pub use parameters::encode_public;
#[cfg(all(unix, feature = "eng2-rehearsal", feature = "eng2-runtime"))]
pub(crate) use parameters::reconstruct;

pub const MAX_GOVERNANCE_BYTES: usize = 131_072;
const MAX_GENESIS_BYTES: usize = 41 + crate::state::CONFIG_RULE_BYTES + 4 + MAX_GOVERNANCE_BYTES;
const H0_LIMITS: Limits = Limits {
    max_leaves: 1,
    max_nullifiers: 1,
    max_component_bytes: 262_144,
};
type Result<T> = std::result::Result<T, &'static str>;

// SHA-256 of ML-DSA-65 public keys from existing deterministic fixtures only:
// repeated seed bytes 1..=5 and 83/84, then the public 24-member registry
// derivation in Config::with_test_fund_registry, in member order 0..=23.
// This finite list does not establish arbitrary external key provenance.
const KNOWN_FIXTURE_KEYS: [&str; 31] = [
    "83ee80fcbcaf4872ed023e55cb10d7a2b4f1336a182115ea9c000f7449a7a9b0",
    "fda6ad37a2ab2ae563455cc73b3d263e13fc889914d975127dfbb3a07f274a1d",
    "663f26006bbbbd9243cf4881dd06a740d22487719c2f371c3bbeef6e86b7a5e8",
    "d94ac2152ca366e9430504623536219ac1517f2fe614d3b53e96a1a57cc4733c",
    "db0229df233110413da2c2031249e0a28300b68245b20668e723d11c127acb51",
    "0d51acbafe8ff6af001fa2b2c856e2b7ede340bda90e6581ba196b350c854637",
    "177a770d7eb1c89730577d2e343723ed644c8c78dddc7b092ff3786ac201b464",
    "e04ceadb948a0d3f6b5142f417b63026a9c730d95c608af11dd84324d2dbfa08",
    "2062070736ef5d511dae9da987e63cf1f964beb053dfba085ac04717ec958250",
    "c2feeb51af259f9120692027c867ec8c8815eb19e76ca87566d0b59970938ef3",
    "9ddb8cf5565af847d121a9056e50b8215d3aa19aa7c817b68830b488b4d214d3",
    "234778c2b9693cef4db09910723a4825aea44191ea283af738f926fe73d74e98",
    "1a798b0846b6b15415c84e397af641f7c875c2c45a37dc7544dd76e6a461d7b5",
    "72dfd7057aeddae94023bfe1a5cde18c6748eb6d39bb60c6ddc8617889f0bcc2",
    "7b26b23bc8d757d27b8f2b9995fe431b056abee3b82d9c7090711f42226b7c1a",
    "cdd0aa82bba0626f5289ff16639a9e0e21a93f03656d099cbf76cbe14eb29a1a",
    "f13ab005f42c5cdc07a517823d2cd9f84ea3d0ef1c8d20f41702e5f299c3b227",
    "00ce749b896fac9b4c34fdbb9bfb656751b955a2dacb6c0a1df8751393b9141a",
    "73e38f08c993c083ff4d76292c3dc5e5871f574842b6a917549103a56356b72f",
    "5c583f7936f1ad9deea9235d30f248c59fb4ffaec3b58827f8fff6766ba1fa2c",
    "b3ab0f63da1ab9596d7f0ce837ce0f0695adb612f25b89db7c8aa7e2612b0d78",
    "000d1ce482bb93169308ba5351f000cd8f2873eccfdb6177243d6f24a81e5d23",
    "c994879a67f8b004ef70dfc5284fc44d505a25a4335addea9ea0c7def02fca8b",
    "465a07783336148e9e7c2f4810b3642152713ee52d3b9083231ef8bdecb1898e",
    "410aef51b0aff23b7279a928dcc1275e5dcc6f88e4f8e2728c63121e7584abf2",
    "b2d99c5a35454188ca3e71aff3a80535e5be5ef36d62d4aac1cfd79d052c032d",
    "ade56a3d4d2d147065607ef54c369116182cde7d43ba8ea9342c02fb13fa78eb",
    "c5b904726dd0f9407a2b6b139bfd37b674e4ead475a9f35b3ce8edbee41967c8",
    "00b092368c7f6f5fa3a827325ab1e28ce13bc5c6fa0e60baf3c14e214d45c973",
    "397b55b47cc4d791d4805d354fecd3e8a5138f9d6eeb64bb007796b3a00b1cb8",
    "5bf597d05418d050fb02832d052977981947ad5b3ff7b1d9162024410d58a039",
];

/// Independent public pins; none may be inferred from the input being checked.
#[derive(Clone, Copy)]
pub struct Expected {
    pub config_sha256: Hash,
    pub governance_sha256: Hash,
    pub network: Hash,
    pub profile: Hash,
    pub fee_recipient_sha256: Hash,
}

/// Compiled proof-profile identity, to compare with an independently pinned value.
pub fn compiled_profile() -> Hash {
    crate::proofs::protocol_profile_fingerprint()
}

pub fn parse_hash(text: &str) -> Result<Hash> {
    if text.len() != 64 {
        return Err("invalid_expected_hex");
    }
    let mut hash = [0; 32];
    for (out, pair) in hash.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let digit = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        *out = digit(pair[0])
            .zip(digit(pair[1]))
            .map(|(a, b)| a * 16 + b)
            .ok_or("invalid_expected_hex")?;
    }
    Ok(hash)
}
fn digest(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    crate::local::hex(bytes)
}

fn public_read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags, open};
        File::from(
            open(
                path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| "public_file_unavailable")?,
        )
    };
    #[cfg(not(unix))]
    let file =
        crate::local::regular_read(path, false, maximum).map_err(|_| "public_file_unavailable")?;
    let meta = file.metadata().map_err(|_| "public_file_unavailable")?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > maximum as u64 {
        return Err("public_file_bound");
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "public_file_unavailable")?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("public_file_bound");
    }
    Ok(bytes)
}

// The canonical config places fixture immediately after network and work bits.
// Reject it before the shared decoder can invoke development fixture helpers.
fn decode_nonfixture_config(bytes: &[u8]) -> Result<Config> {
    if bytes.len() != crate::state::CONFIG_RULE_BYTES {
        return Err("invalid_config");
    }
    if bytes[33] != 0 {
        return Err("fixture_or_nonproduction_rules");
    }
    Config::decode_rules(bytes).map_err(|_| "invalid_config")
}

fn guard(genesis: &Genesis, expected: Expected) -> Result<()> {
    let config = genesis.config();
    let governance = genesis.initial_governance();
    if expected.network == [0; 32]
        || config.network != expected.network
        || expected.profile != crate::proofs::protocol_profile_fingerprint()
        || genesis.fee_mode() != FeeMode::LegacyMiner
    {
        return Err("public_context_mismatch");
    }
    config.validate().map_err(|_| "invalid_config")?;
    if config.fixture
        || config.work_bits != 0
        || config.genesis_timestamp == 0
        || config.genesis_target == [0; 32]
        || config.target_interval != crate::state::TARGET_INTERVAL
        || !(1..=crate::state::MAX_POW_ITERATIONS).contains(&config.pow_iterations)
        || config.economics != siworld_core::v1_economics::EconomicsParams::production()
    {
        return Err("fixture_or_nonproduction_rules");
    }
    let governance_bytes = governance
        .canonical_component_bytes()
        .map_err(|_| "invalid_governance")?;
    if digest(&config.encode_rules()) != expected.config_sha256
        || digest(&governance_bytes) != expected.governance_sha256
    {
        return Err("public_parameter_digest_mismatch");
    }
    let issuance = config.issuance.as_ref().ok_or("issuance_config_required")?;
    let destination = governance
        .canonical_fee_destination_bytes()
        .map_err(|_| "invalid_fee_recipient")?;
    if issuance.fee_owner != encode_digest(&governance.active_fee_destination().owner())
        || digest(&destination) != expected.fee_recipient_sha256
    {
        return Err("fee_recipient_mismatch");
    }
    let (founder, revocation) = governance.active_owner_keys();
    for key in config
        .fund_verifying_keys
        .iter()
        .chain([founder, revocation])
        .chain(governance.active_roster().keys().iter())
    {
        if KNOWN_FIXTURE_KEYS.contains(&hex(&digest(key)).as_str()) {
            return Err("known_builtin_fixture_key");
        }
    }
    Ok(())
}

fn component_name(id: ComponentId) -> &'static str {
    match id {
        ComponentId::ChainContext => "chain_context",
        ComponentId::CommitmentTree => "commitment_tree",
        ComponentId::Nullifiers => "nullifiers",
        ComponentId::RecentRoots => "recent_roots",
        ComponentId::HolderPool => "holder_pool",
        ComponentId::DevelopmentFund => "development_fund",
        ComponentId::FeeDestination => "fee_destination",
        ComponentId::Governance => "governance",
        ComponentId::IssuanceAndBurn => "issuance_and_burn",
        ComponentId::LockedRewards => "locked_rewards",
        ComponentId::AssetRegistry => "asset_registry",
    }
}
fn report(genesis: &Genesis, bytes: &[u8], expected: Expected) -> Result<Value> {
    guard(genesis, expected)?;
    let state = genesis
        .initial_state()
        .map_err(|_| "h0_reconstruction_failed")?;
    let binding = Binding {
        genesis: genesis.id(),
        rules_commitment: genesis.rules_commitment(),
        parent: [0; 32],
    };
    let parts = state
        .canonical_components(binding, H0_LIMITS)
        .map_err(|_| "h0_reconstruction_failed")?;
    // Snapshot import bytes carry full vectors. The existing execution kernel
    // commits tree and nullifier state through its compact canonical encodings.
    let mut execution_parts = parts.clone();
    execution_parts[1] =
        super::state_components::tree_execution_encoding(&state.chain().tree).to_vec();
    execution_parts[2] = super::nullifiers::NullifierSet::rebuild(&state.chain().spent)
        .map_err(|_| "h0_reconstruction_failed")?
        .execution_encoding()
        .to_vec();
    let components = COMPONENTS
        .into_iter()
        .zip(&execution_parts)
        .map(|(id, bytes)| {
            Component::from_local_encoding(id, bytes, H0_LIMITS.max_component_bytes)
                .map_err(|_| "h0_component_failed")
        })
        .collect::<Result<Vec<_>>>()?;
    let root = state
        .execution_commitment(binding, H0_LIMITS)
        .map_err(|_| "h0_reconstruction_failed")?;
    if commitment::aggregate(state.network(), 0, [0; 32], &components)
        .map_err(|_| "h0_aggregate_failed")?
        != root
    {
        return Err("h0_aggregate_mismatch");
    }
    let rows: Vec<_> = components
        .iter()
        .zip(&parts)
        .map(|(component, snapshot)| {
            let descriptor = component.descriptor();
            json!({"id":descriptor.id() as u16,"name":component_name(descriptor.id()),
            "execution_bytes":descriptor.encoded_len(),"snapshot_bytes":snapshot.len(),
            "snapshot_sha256":hex(&digest(snapshot)),"component_digest":hex(&descriptor.digest())})
        })
        .collect();
    let config = genesis.config();
    let governance = genesis.initial_governance();
    let allocation = config
        .fund_allocation
        .as_ref()
        .ok_or("fund_allocation_required")?;
    let members: Vec<_> = config.fund_verifying_keys.iter().zip(allocation.basis_points())
        .enumerate().map(|(index,(key, share))| {
            let destination = governance.active_fund_destination(index as u8).map_err(|_| "invalid_fund_member")?;
            Ok(json!({"member":index,"basis_points":share,"authority_sha256":hex(&digest(key)),
                "destination_sha256":hex(&digest(&crate::eng2_governance::canonical_address(destination)))}))
        }).collect::<Result<Vec<_>>>()?;
    let (founder, revocation) = governance.active_owner_keys();
    let roster: Vec<_> = governance
        .active_roster()
        .keys()
        .iter()
        .enumerate()
        .map(|(slot, key)| json!({"slot":slot,"public_key_sha256":hex(&digest(key))}))
        .collect();
    let issuance = config.issuance.as_ref().ok_or("issuance_config_required")?;
    Ok(
        json!({"version":1,"network":hex(&config.network),"genesis_id":hex(&genesis.id()),
        "rules_commitment":hex(&genesis.rules_commitment()),
        "proof_profile":hex(&crate::proofs::protocol_profile_fingerprint()),
        "peer_verifier":hex(&genesis.peer_binding().verifier),"fee_mode":"legacy-miner",
        "genesis_bytes":bytes.len(),"genesis_sha256":hex(&digest(bytes)),
        "source":{"config_rules_sha256":hex(&expected.config_sha256),"governance_component_sha256":hex(&expected.governance_sha256),"source_commit_verified":false},
        "parameters":{"fixture":false,"work_bits":config.work_bits,
            "genesis_timestamp":config.genesis_timestamp.to_string(),"genesis_target":hex(&config.genesis_target),
            "target_interval_seconds":config.target_interval.to_string(),"pow_iterations":config.pow_iterations.to_string(),
            "economic_rule_version":siworld_core::v1_economics::ECONOMICS_RULE_VERSION,"economic_timing":"production",
            "fund_team_index":allocation.team_index(),"fund_members":members,
            "founder_public_key_sha256":hex(&digest(founder)),"revocation_public_key_sha256":hex(&digest(revocation)),
            "checkpoint_threshold":crate::eng2_governance::ActiveRoster::THRESHOLD,"checkpoint_slots":roster,
            "issuance":{"fee_owner":hex(&issuance.fee_owner),"recipient_sha256":hex(&expected.fee_recipient_sha256),
                "fee_owner_matches":true,"initial_fee_atoms":governance.issuance_fee_atoms().to_string(),
                "max_metadata_bytes":issuance.max_metadata_bytes,"max_per_block":issuance.max_per_block}},
        "h0":{"height":0,"tip":hex(&state.tip()),"parent":hex(&[0;32]),"components":rows,"execution_commitment":hex(&root)},
        "fixture_key_check":{"known_builtin_fingerprints":KNOWN_FIXTURE_KEYS.len(),"arbitrary_key_provenance_verified":false},
        "chain_state_changed":false,"submitted":false,"network_started":false}),
    )
}

/// Create one absent public genesis file after all public preflight checks pass.
pub fn seal_public(
    config_path: &Path,
    governance_path: &Path,
    output: &Path,
    expected: Expected,
) -> Result<Value> {
    let config_bytes = public_read(config_path, crate::state::CONFIG_RULE_BYTES)?;
    let governance_bytes = public_read(governance_path, MAX_GOVERNANCE_BYTES)?;
    let config = decode_nonfixture_config(&config_bytes)?;
    let governance = GovernanceState::decode_component(&governance_bytes, expected.network)
        .map_err(|_| "invalid_governance")?;
    let genesis =
        Genesis::seal(config, governance, FeeMode::LegacyMiner).map_err(|_| "invalid_genesis")?;
    let bytes = genesis.encode().map_err(|_| "invalid_genesis")?;
    let decoded = Genesis::decode(&bytes).map_err(|_| "invalid_genesis")?;
    if decoded.encode().map_err(|_| "invalid_genesis")? != bytes {
        return Err("noncanonical_genesis");
    }
    let mut result = report(&decoded, &bytes, expected)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|_| "new_output_required")?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "output_durability_failed")?;
    #[cfg(unix)]
    File::open(
        output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .and_then(|parent| parent.sync_all())
    .map_err(|_| "output_directory_durability_failed")?;
    result["output_created"] = true.into();
    Ok(result)
}

/// Reconstruct an existing public genesis against independent public pins.
pub fn inspect(path: &Path, expected: Expected) -> Result<Value> {
    let bytes = public_read(path, MAX_GENESIS_BYTES)?;
    let config_start = 8 + 1 + 32;
    let config_end = config_start + crate::state::CONFIG_RULE_BYTES;
    decode_nonfixture_config(
        bytes
            .get(config_start..config_end)
            .ok_or("invalid_genesis")?,
    )?;
    let genesis = Genesis::decode(&bytes).map_err(|_| "invalid_genesis")?;
    let mut result = report(&genesis, &bytes, expected)?;
    result["output_created"] = false.into();
    Ok(result)
}

/// Hash the currently executing tool, without accepting a caller source claim.
pub fn executable_sha256() -> Result<Hash> {
    let path = std::env::current_exe().map_err(|_| "executable_unavailable")?;
    let mut file = File::open(path).map_err(|_| "executable_unavailable")?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65_536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "executable_unavailable")?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}
