//! Encode bounded public inputs with the existing genesis serializers.
use super::*;
use crate::eng2_governance::{self, IssuanceFeeParameters};
use siworld_core::v1_economics::FundAllocation;

const MAX_INPUT_BYTES: usize = 262_144;

fn fields(value: &Value, names: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("invalid_public_parameters")?;
    if object.len() != names.len() || names.iter().any(|name| !object.contains_key(*name)) {
        return Err("unexpected_public_parameter_field");
    }
    Ok(())
}
fn public_bytes<const N: usize>(value: &Value) -> Result<[u8; N]> {
    let text = value.as_str().ok_or("invalid_public_hex")?;
    if text.len() != N * 2 {
        return Err("invalid_public_hex");
    }
    let mut bytes = [0; N];
    for (out, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let digit = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        *out = digit(pair[0])
            .zip(digit(pair[1]))
            .map(|(a, b)| a * 16 + b)
            .ok_or("invalid_public_hex")?;
    }
    Ok(bytes)
}
fn address(value: &Value) -> Result<native::encryption::PaymentAddress> {
    eng2_governance::decode_address(&public_bytes::<1232>(value)?)
        .map_err(|_| "invalid_public_address")
}
fn parameters(value: &Value) -> Result<(Config, GovernanceState, Expected)> {
    fields(
        value,
        &[
            "version",
            "network",
            "proof_profile",
            "fixture",
            "work_bits",
            "genesis_timestamp",
            "genesis_target",
            "pow_iterations",
            "target_interval",
            "economics",
            "fee_mode",
            "checkpoint_threshold",
            "checkpoint_public_keys",
            "founder_public_key",
            "revocation_public_key",
            "fee_destination",
            "fund",
            "issuance",
        ],
    )?;
    if value["version"] != 1
        || value["fixture"] != false
        || value["work_bits"] != 0
        || value["genesis_target"] != "ff".repeat(32)
        || value["pow_iterations"] != 1
        || value["target_interval"] != 300
        || value["economics"] != "production"
        || value["fee_mode"] != "legacy-miner"
        || value["checkpoint_threshold"] != 2
    {
        return Err("unsupported_public_parameter_rules");
    }
    let network = public_bytes::<32>(&value["network"])?;
    let profile = public_bytes::<32>(&value["proof_profile"])?;
    let timestamp = value["genesis_timestamp"]
        .as_str()
        .ok_or("invalid_public_timestamp")?;
    let time: u64 = timestamp.parse().map_err(|_| "invalid_public_timestamp")?;
    if time == 0 || timestamp != time.to_string() {
        return Err("invalid_public_timestamp");
    }
    let keys = value["checkpoint_public_keys"]
        .as_array()
        .filter(|keys| keys.len() == 3)
        .ok_or("invalid_public_roster")?;
    let roster = [
        public_bytes::<1952>(&keys[0])?,
        public_bytes::<1952>(&keys[1])?,
        public_bytes::<1952>(&keys[2])?,
    ];
    let fund = &value["fund"];
    fields(fund, &["team_index", "members"])?;
    let team = fund["team_index"]
        .as_u64()
        .and_then(|x| usize::try_from(x).ok())
        .ok_or("invalid_public_allocation")?;
    let members = fund["members"]
        .as_array()
        .filter(|members| !members.is_empty() && members.len() <= 32)
        .ok_or("invalid_public_allocation")?;
    let mut shares = Vec::with_capacity(members.len());
    let mut authorities = Vec::with_capacity(members.len());
    let mut destinations = Vec::with_capacity(members.len());
    for member in members {
        fields(member, &["basis_points", "public_key", "destination"])?;
        shares.push(
            member["basis_points"]
                .as_u64()
                .and_then(|x| u16::try_from(x).ok())
                .ok_or("invalid_public_allocation")?,
        );
        authorities.push(public_bytes::<1952>(&member["public_key"])?);
        destinations.push(address(&member["destination"])?);
    }
    let fee_destination = address(&value["fee_destination"])?;
    let mut config = Config::asert_development(network, time, [0xff; 32], 1)
        .map_err(|_| "invalid_config")?
        .with_fund_wallets(
            FundAllocation::new_bps(shares, team).map_err(|_| "invalid_public_allocation")?,
            authorities,
        )
        .map_err(|_| "invalid_config")?;
    let issuance = &value["issuance"];
    fields(issuance, &["max_metadata_bytes", "max_per_block"])?;
    config.issuance = Some(crate::issuance::IssuanceConfig {
        fee_owner: encode_digest(&fee_destination.owner()),
        max_metadata_bytes: issuance["max_metadata_bytes"]
            .as_u64()
            .and_then(|x| u16::try_from(x).ok())
            .ok_or("invalid_public_issuance")?,
        max_per_block: issuance["max_per_block"]
            .as_u64()
            .and_then(|x| u8::try_from(x).ok())
            .ok_or("invalid_public_issuance")?,
    });
    let governance = GovernanceState::new_with_issuance_fee(
        network,
        public_bytes::<1952>(&value["founder_public_key"])?,
        public_bytes::<1952>(&value["revocation_public_key"])?,
        roster,
        fee_destination,
        destinations,
        IssuanceFeeParameters::default(),
    )
    .map_err(|_| "invalid_governance")?;
    let governance_bytes = governance
        .canonical_component_bytes()
        .map_err(|_| "invalid_governance")?;
    let expected = Expected {
        config_sha256: digest(&config.encode_rules()),
        governance_sha256: digest(&governance_bytes),
        network,
        profile,
        fee_recipient_sha256: digest(
            &governance
                .canonical_fee_destination_bytes()
                .map_err(|_| "invalid_fee_recipient")?,
        ),
    };
    let genesis = Genesis::seal(config.clone(), governance.clone(), FeeMode::LegacyMiner)
        .map_err(|_| "invalid_genesis")?;
    guard(&genesis, expected)?;
    Ok((config, governance, expected))
}

/// Encode public parameters in an absent directory after all checks complete.
/// This does not generate keys, write a genesis, or initialize a node.
pub fn encode_public(input: &Path, output: &Path, expected_input: Hash) -> Result<Value> {
    let bytes = public_read(input, MAX_INPUT_BYTES)?;
    if digest(&bytes) != expected_input {
        return Err("public_input_digest_mismatch");
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid_public_parameters")?;
    let (config, governance, expected) = parameters(&value)?;
    let config_bytes = config.encode_rules();
    let governance_bytes = governance
        .canonical_component_bytes()
        .map_err(|_| "invalid_governance")?;
    // Exercise the same decoders used by seal-public before publishing inputs.
    let genesis = Genesis::seal(
        decode_nonfixture_config(&config_bytes)?,
        GovernanceState::decode_component(&governance_bytes, expected.network)
            .map_err(|_| "invalid_governance")?,
        FeeMode::LegacyMiner,
    )
    .map_err(|_| "invalid_genesis")?;
    let encoded = genesis.encode().map_err(|_| "invalid_genesis")?;
    let decoded = Genesis::decode(&encoded).map_err(|_| "invalid_genesis")?;
    if decoded.encode().map_err(|_| "invalid_genesis")? != encoded {
        return Err("noncanonical_genesis");
    }
    let mut result = report(&decoded, &encoded, expected)?;
    std::fs::create_dir(output).map_err(|_| "new_output_required")?;
    for (name, body) in [
        ("config-rules.bin", config_bytes.as_slice()),
        ("governance.bin", governance_bytes.as_slice()),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join(name))
            .map_err(|_| "output_durability_failed")?;
        file.write_all(body)
            .and_then(|_| file.sync_all())
            .map_err(|_| "output_durability_failed")?;
    }
    #[cfg(unix)]
    for directory in [
        output,
        output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    ] {
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| "output_directory_durability_failed")?;
    }
    result["public_input_sha256"] = hex(&expected_input).into();
    result["parameter_files_created"] = true.into();
    result["genesis_file_created"] = false.into();
    result["source"]["parameter_hashes_computed_from_public_input"] = true.into();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        // Public synthetic encodings only; no signing or wallet seed is derived.
        let destination = format!("01000000{}", "00".repeat(1228));
        json!({"version":1,"network":"01".repeat(32),"proof_profile":hex(&compiled_profile()),
            "fixture":false,"work_bits":0,"genesis_timestamp":"1","genesis_target":"ff".repeat(32),
            "pow_iterations":1,"target_interval":300,"economics":"production","fee_mode":"legacy-miner",
            "checkpoint_threshold":2,"checkpoint_public_keys":["0b".repeat(1952),"0c".repeat(1952),"0d".repeat(1952)],
            "founder_public_key":"0e".repeat(1952),"revocation_public_key":"0f".repeat(1952),
            "fee_destination":destination.clone(),"fund":{"team_index":0,"members":[
                {"basis_points":10000,"public_key":"10".repeat(1952),"destination":destination}]},
            "issuance":{"max_metadata_bytes":256,"max_per_block":4}})
    }
    #[test]
    fn public_parameters_preserve_existing_canonical_serializers() {
        let (config, governance, expected) = parameters(&input()).unwrap();
        let config_bytes = config.encode_rules();
        let gov_bytes = governance.canonical_component_bytes().unwrap();
        assert_eq!(Config::decode_rules(&config_bytes).unwrap(), config);
        assert_eq!(
            GovernanceState::decode_component(&gov_bytes, expected.network).unwrap(),
            governance
        );
        assert_eq!(expected.config_sha256, digest(&config_bytes));
        assert_eq!(expected.governance_sha256, digest(&gov_bytes));
    }
    #[test]
    fn public_parameters_reject_private_fields_and_rule_substitution() {
        for (field, replacement) in [
            ("seed", json!("private")),
            ("fixture", json!(true)),
            ("pow_iterations", json!(0)),
            ("target_interval", json!(1)),
            ("checkpoint_threshold", json!(1)),
            ("genesis_timestamp", json!("01")),
            ("proof_profile", json!("00".repeat(32))),
            (
                "checkpoint_public_keys",
                json!(["0b".repeat(1952), "0b".repeat(1952), "0b".repeat(1952)]),
            ),
        ] {
            let mut value = input();
            value[field] = replacement;
            assert!(parameters(&value).is_err(), "accepted {field}");
        }
        let mut value = input();
        value["fund"]["members"][0]["basis_points"] = json!(9999);
        assert!(parameters(&value).is_err());
        value = input();
        value["fund"]["members"][0]["private_key"] = json!("private");
        assert!(parameters(&value).is_err());
    }
    #[test]
    fn encoding_checks_input_pin_bounds_and_create_only_outputs() {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "siworld-public-parameters-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("input.json");
        let output = root.join("parameters");
        let bytes = serde_json::to_vec(&input()).unwrap();
        std::fs::write(&source, &bytes).unwrap();
        assert_eq!(
            encode_public(&source, &output, [0; 32]).unwrap_err(),
            "public_input_digest_mismatch"
        );
        assert!(!output.exists());
        let receipt = encode_public(&source, &output, digest(&bytes)).unwrap();
        let config = std::fs::read(output.join("config-rules.bin")).unwrap();
        let governance = std::fs::read(output.join("governance.bin")).unwrap();
        assert_eq!(
            receipt["source"]["config_rules_sha256"],
            hex(&digest(&config))
        );
        assert_eq!(
            receipt["source"]["governance_component_sha256"],
            hex(&digest(&governance))
        );
        assert_eq!(
            encode_public(&source, &output, digest(&bytes)).unwrap_err(),
            "new_output_required"
        );
        assert_eq!(
            std::fs::read(output.join("config-rules.bin")).unwrap(),
            config
        );
        assert_eq!(
            std::fs::read(output.join("governance.bin")).unwrap(),
            governance
        );
        std::fs::write(&source, vec![b' '; MAX_INPUT_BYTES + 1]).unwrap();
        let second = root.join("second");
        assert_eq!(
            encode_public(&source, &second, [0; 32]).unwrap_err(),
            "public_file_bound"
        );
        assert!(!second.exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
