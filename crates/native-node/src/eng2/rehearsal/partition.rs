//! Synthetic custody and bounded production controls for loopback partitions.
//! Network orchestration remains external; these operations never start a node.
use super::*;
#[cfg(unix)]
mod actual_state;
mod audit;
#[cfg(unix)]
mod corpus;
#[cfg(unix)]
mod driver_case;
#[cfg(unix)]
pub use driver_case::driver_case;
mod replay;
pub use audit::audit;
pub use replay::replay_prefix;

const MARKER: &str = "reorg-production-ceiling.json";
const PURPOSE: &str = "isolated-native-reorganization";
const MAX_HEIGHT: u64 = 96;

fn owner_local() -> Result<(), String> {
    if std::env::var_os("GITHUB_ACTIONS").is_some()
        || matches!(std::env::var("CI").as_deref(), Ok("true") | Ok("1"))
    {
        return Err("partition rehearsal requires owner-local execution".into());
    }
    Ok(())
}
fn create_private(directory: &Path) -> Result<(), String> {
    if !directory.is_absolute()
        || directory
            .parent()
            .and_then(|p| p.canonicalize().ok())
            .as_deref()
            != directory.parent()
    {
        return Err("new canonical absolute rehearsal directory required".into());
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(directory)
        .map_err(|_| "rehearsal directory must be absent".into())
}
fn bounded_bytes(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    crate::local::regular_read(path, true, maximum)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "bounded partition record read failed")?;
    if bytes.len() > maximum {
        return Err("partition record exceeds byte limit".into());
    }
    Ok(bytes)
}
fn ceiling_value(genesis: &Genesis, maximum_height: u64) -> Result<Value, String> {
    if !genesis.config().fixture
        || genesis.config().genesis_target != [0xff; 32]
        || genesis.config().pow_iterations != 0
        || maximum_height > MAX_HEIGHT
    {
        return Err(
            "partition production requires a bounded minimum-difficulty synthetic genesis".into(),
        );
    }
    Ok(
        json!({"version":1,"purpose":PURPOSE,"genesis_id":crate::local::hex(&genesis.id()),
        "maximum_height":maximum_height}),
    )
}
fn decode_ceiling(value: &Value, genesis: &Genesis) -> Result<u64, String> {
    if value.as_object().map(|v| v.len()) != Some(4)
        || value["version"] != 1
        || value["purpose"] != PURPOSE
        || value["genesis_id"] != crate::local::hex(&genesis.id())
    {
        return Err("partition production marker context differs".into());
    }
    let height = value["maximum_height"]
        .as_u64()
        .ok_or("invalid partition production height")?;
    ceiling_value(genesis, height)?;
    Ok(height)
}

/// Missing marker leaves the ordinary resident policy unchanged. An invalid
/// marker fails closed. This function exists only in the rehearsal build.
pub fn production_ceiling(directory: &Path, genesis: &Genesis) -> Result<Option<u64>, String> {
    let path = directory.join(MARKER);
    match path.try_exists() {
        Ok(false) => return Ok(None),
        Err(_) => return Err("partition production marker unavailable".into()),
        Ok(true) => {}
    }
    owner_local()?;
    let value = serde_json::from_slice(&bounded_bytes(&path, 4096)?)
        .map_err(|_| "invalid partition production marker")?;
    decode_ceiling(&value, genesis).map(Some)
}

/// Create a new synthetic campaign. The seed remains owner-private; the output
/// contains only public genesis identifiers and no usable custody material.
pub fn initialize(directory: &Path) -> Result<Value, String> {
    owner_local()?;
    create_private(directory)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| "partition entropy unavailable")?;
    let network = blake3::derive_key("siworld eng2 offline rehearsal network v1", seed.as_ref());
    let selected = genesis(seed.as_ref(), network)?;
    ceiling_value(&selected, 0)?;
    private_write(&directory.join("rehearsal.seed"), seed.as_ref())?;
    private_write(&directory.join("genesis.bin"), &selected.encode()?)?;
    Ok(
        json!({"scope":PURPOSE,"genesis_id":crate::local::hex(&selected.id()),
        "network_id":crate::local::hex(&network),"maximum_production_height":MAX_HEIGHT,
        "nodes_started":false,"custody_printed":false}),
    )
}

/// Initialize one fresh node beneath the synthetic campaign, with independently
/// generated peer identity, authenticated empty store and distinct reward address.
pub fn initialize_node(campaign: &Path, directory: &Path, index: u32) -> Result<Value, String> {
    owner_local()?;
    if campaign.canonicalize().ok().as_deref() != Some(campaign)
        || directory.parent() != Some(campaign)
        || index >= 64
    {
        return Err("node must be a fresh direct child of its synthetic campaign".into());
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    crate::local::regular_read(&campaign.join("rehearsal.seed"), true, 32)?
        .read_exact(seed.as_mut())
        .map_err(|_| "partition seed width differs")?;
    let network = blake3::derive_key("siworld eng2 offline rehearsal network v1", seed.as_ref());
    let selected = genesis(seed.as_ref(), network)?;
    let encoded = bounded_bytes(&campaign.join("genesis.bin"), 1024 * 1024)?;
    if selected.encode()? != encoded {
        return Err("partition synthetic custody and genesis differ".into());
    }
    create_private(directory)?;
    private_write(&directory.join("genesis.bin"), &encoded)?;
    let identity = crate::identity::NativeIdentity::initialize(directory, selected.peer_binding())
        .map_err(|_| "new partition peer identity unavailable")?;
    let descriptor = identity
        .descriptor()
        .map_err(|_| "partition descriptor unavailable")?;
    let limit = ceiling_value(&selected, 0)?;
    let settings = MiningSettings {
        mode: RewardMode::Voyager,
        recipient: WalletKeys::from_seed(
            network,
            derive(seed.as_ref(), "siworld eng2 rehearsal partition reward v1"),
            index,
        )?
        .address(),
    };
    let mut store = Store::create(
        &directory.join("chain.redb"),
        selected,
        Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        },
    )?;
    store.enable_authenticated_restart(identity)?;
    crate::mining::save(directory, network, &settings)?;
    crate::service::atomic_json(&directory.join(MARKER), &limit)?;
    Ok(
        json!({"scope":PURPOSE,"genesis_id":limit["genesis_id"],"network_id":crate::local::hex(&network),
        "descriptor":crate::local::hex(&descriptor.encode()),"fingerprint":crate::local::hex(&descriptor.fingerprint()),
        "height":0,"production_ceiling":0,"node_started":false,"custody_printed":false}),
    )
}

/// Change only the synthetic node's local height budget; this neither mines nor
/// alters a block, chain state, identity, proof profile or consensus parameter.
pub fn set_production_ceiling(directory: &Path, height: u64) -> Result<Value, String> {
    owner_local()?;
    let encoded = bounded_bytes(&directory.join("genesis.bin"), 1024 * 1024)?;
    let selected = Genesis::decode(&encoded)?;
    if production_ceiling(directory, &selected)?.is_none() {
        return Err("existing partition production marker required".into());
    }
    let value = ceiling_value(&selected, height)?;
    crate::service::atomic_json(&directory.join(MARKER), &value)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_marker_binds_synthetic_genesis_and_bounded_integer_height() {
        let selected = genesis(&[42; 32], [23; 32]).unwrap();
        for h in [0, 1, 25, 26, 96] {
            assert_eq!(
                decode_ceiling(&ceiling_value(&selected, h).unwrap(), &selected).unwrap(),
                h
            );
        }
        assert!(ceiling_value(&selected, 97).is_err());
        let mut value = ceiling_value(&selected, 25).unwrap();
        value["genesis_id"] = json!("00".repeat(32));
        assert!(decode_ceiling(&value, &selected).is_err());
        value = ceiling_value(&selected, 25).unwrap();
        value["maximum_height"] = json!(-1);
        assert!(decode_ceiling(&value, &selected).is_err());
        value["maximum_height"] = json!(1.5);
        assert!(decode_ceiling(&value, &selected).is_err());
        value = ceiling_value(&selected, 25).unwrap();
        value["extra"] = json!(true);
        assert!(decode_ceiling(&value, &selected).is_err());
    }
}
