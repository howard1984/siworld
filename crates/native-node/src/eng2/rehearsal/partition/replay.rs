//! Bounded replay of unchanged exported native frames into an empty node.
//! This prepares local state; peer discovery and branch healing remain external.
use super::*;
use crate::eng2::{body::Body, header::Header};
use sha2::{Digest as _, Sha256};

const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
const REPLAY_DEADLINE_SECONDS: u64 = 900;

pub(super) fn manifest_records<'a>(
    manifest: &'a Value,
    selected: &Genesis,
    height: u64,
) -> Result<&'a [Value], String> {
    manifest_records_inner(manifest, selected, height, None)
}

pub(super) fn manifest_records_inner<'a>(
    manifest: &'a Value,
    selected: &Genesis,
    height: u64,
    qualification: Option<&super::qualification::Context>,
) -> Result<&'a [Value], String> {
    let scope = if let Some(context) = qualification {
        context.check_genesis(selected)?;
        context.check_manifest(manifest)?;
        super::qualification::AUDIT_SCOPE
    } else {
        "read-only-synthetic-native-partition-audit"
    };
    let source_height = manifest["height"]
        .as_u64()
        .ok_or("replay source height missing")?;
    if height == 0
        || height > MAX_HEIGHT
        || source_height < height
        || source_height > MAX_HEIGHT
        || manifest["schema"] != 1
        || manifest["scope"] != scope
        || manifest["genesis_id"] != crate::local::hex(&selected.id())
        || manifest["network_id"] != crate::local::hex(&selected.config().network)
        || manifest["rules_commitment"] != crate::local::hex(&selected.rules_commitment())
        || manifest["proof_profile"]
            != crate::local::hex(&crate::proofs::protocol_profile_fingerprint())
        || manifest["independent_native_replay"] != true
        || manifest["durable_head_verified"] != true
    {
        return Err("replay source context, profile or height differs".into());
    }
    let records = manifest["blocks"]
        .as_array()
        .ok_or("replay source records missing")?;
    if records.len() != source_height as usize {
        return Err("replay source record count differs".into());
    }
    for (offset, record) in records.iter().enumerate() {
        let current = offset as u64 + 1;
        if record["height"] != current
            || record["frame"] != format!("block-{current:04}.frame")
            || record["frame_bytes"].as_u64().is_none()
            || [
                "id",
                "parent",
                "execution_commitment",
                "cumulative_work",
                "frame_sha256",
            ]
            .into_iter()
            .any(|field| {
                record[field].as_str().is_none_or(|value| {
                    value.len() != if field == "cumulative_work" { 128 } else { 64 }
                        || !value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
            })
        {
            return Err("replay source record framing differs".into());
        }
    }
    Ok(&records[..height as usize])
}

pub(super) fn read_frame(
    source: &Path,
    record: &Value,
    selected: &Genesis,
    policy: crate::eng2::body::Policy,
) -> Result<(Header, Body), String> {
    let height = record["height"]
        .as_u64()
        .ok_or("replay frame height missing")?;
    let maximum = crate::eng2::header::HEADER_BYTES
        .checked_add(policy.max_body_bytes)
        .ok_or("replay frame bound overflow")?;
    let declared = record["frame_bytes"]
        .as_u64()
        .ok_or("replay frame byte count missing")?;
    if declared < crate::eng2::header::HEADER_BYTES as u64 || declared > maximum as u64 {
        return Err("replay declared frame exceeds bound".into());
    }
    let bytes = bounded_bytes(&source.join(format!("block-{height:04}.frame")), maximum)?;
    if bytes.len() as u64 != declared
        || record["frame_sha256"] != crate::local::hex(&Sha256::digest(&bytes))
    {
        return Err("replay frame size or digest differs".into());
    }
    let (head, body) = bytes.split_at(crate::eng2::header::HEADER_BYTES);
    let header = Header::decode(head, &selected.config().network)
        .map_err(|_| "replay native header rejected")?;
    let body = Body::decode(body, selected.config().network, height, policy)?;
    if header.height != height
        || record["id"]
            != crate::local::hex(&header.id().map_err(|_| "replay native block id rejected")?)
        || record["parent"] != crate::local::hex(&header.parent)
        || record["execution_commitment"] != crate::local::hex(&header.execution_commitment)
    {
        return Err("replay native frame identity differs".into());
    }
    Ok((header, body))
}

/// The destination must already have its own identity and authenticated empty
/// store. Every source block is independently verified before the first append,
/// then read and verified again by normal Store::append. No proof is generated.
/// A source change during append can leave only a normally committed valid prefix.
pub fn replay_prefix(source: &Path, directory: &Path, height: u64) -> Result<Value, String> {
    replay_prefix_inner(source, directory, height, None)
}

pub(super) fn replay_prefix_inner(
    source: &Path,
    directory: &Path,
    height: u64,
    qualification: Option<(&super::qualification::Context, &str)>,
) -> Result<Value, String> {
    owner_local()?;
    if source.canonicalize().ok().as_deref() != Some(source)
        || directory.canonicalize().ok().as_deref() != Some(directory)
        || source.starts_with(directory)
        || directory.starts_with(source)
    {
        return Err("separate canonical replay source and node directories required".into());
    }
    let encoded = bounded_bytes(&source.join("genesis.bin"), 1024 * 1024)?;
    let selected = Genesis::decode(&encoded)?;
    if let Some((context, _)) = qualification {
        context.check_genesis(&selected)?;
    } else {
        ceiling_value(&selected, 0)?;
        if production_ceiling(directory, &selected)? != Some(0) {
            return Err("replay destination production must be paused".into());
        }
    }
    if bounded_bytes(&directory.join("genesis.bin"), 1024 * 1024)? != encoded {
        return Err("replay destination genesis or paused production differs".into());
    }
    let manifest_bytes = bounded_bytes(&source.join("manifest.json"), MAX_MANIFEST_BYTES)?;
    let manifest: Value =
        serde_json::from_slice(&manifest_bytes).map_err(|_| "replay source manifest rejected")?;
    let records = if let Some((context, pin)) = qualification {
        context.check_manifest_pin(&manifest_bytes, pin)?;
        manifest_records_inner(&manifest, &selected, height, Some(context))?
    } else {
        manifest_records(&manifest, &selected, height)?
    };
    let _lease = crate::service::Lease::acquire(directory)?;
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    let database = directory.join("chain.redb");
    let mut store = Store::resume_existing(&database, Genesis::decode(&encoded)?, limits)?;
    if store.engine().state().height() != 0 {
        return Err("replay destination must have an authenticated empty store".into());
    }
    let started = Instant::now();
    let verifier = NativeVerifier::for_genesis(store.engine().genesis())?;
    let mut preflight = Engine::new(Genesis::decode(&encoded)?, limits)?;
    for record in records {
        if started.elapsed().as_secs() >= REPLAY_DEADLINE_SECONDS {
            return Err("native prefix replay deadline".into());
        }
        let (header, body) = read_frame(source, record, &selected, preflight.body_policy())?;
        preflight.apply(&header, &body, &verifier)?;
        if qualification.is_some() {
            super::actual_state::observe(&preflight, &preflight, &header, record)?;
        }
        if record["cumulative_work"]
            != crate::local::hex(&preflight.state().chain().cumulative_work.to_big_endian())
        {
            return Err("replay cumulative work differs".into());
        }
    }
    let expected_tip = preflight.state().tip();
    drop(preflight);
    let mut reference = qualification
        .map(|_| Engine::new(Genesis::decode(&encoded)?, limits))
        .transpose()?;
    for record in records {
        if started.elapsed().as_secs() >= REPLAY_DEADLINE_SECONDS {
            return Err("native prefix replay deadline".into());
        }
        let (header, body) = read_frame(source, record, &selected, store.engine().body_policy())?;
        store.append(&header, &body, &verifier)?;
        if let Some(reference) = reference.as_mut() {
            reference.apply(&header, &body, &verifier)?;
            super::actual_state::observe(store.engine(), reference, &header, record)?;
        }
    }
    if store.engine().state().height() != height || store.engine().state().tip() != expected_tip {
        return Err("native prefix replay committed head differs".into());
    }
    drop(store);
    let reopened = Store::resume_existing(&database, Genesis::decode(&encoded)?, limits)?;
    if reopened.engine().state().height() != height
        || reopened.engine().state().tip() != expected_tip
    {
        return Err("native prefix replay authenticated reopen differs".into());
    }
    if let Some(reference) = &reference {
        let record = records.last().ok_or("qualification replay prefix empty")?;
        let (header, _) = read_frame(source, record, &selected, reopened.engine().body_policy())?;
        super::actual_state::observe(reopened.engine(), reference, &header, record)?;
        if bounded_bytes(&source.join("genesis.bin"), 1024 * 1024)? != encoded
            || bounded_bytes(&source.join("manifest.json"), MAX_MANIFEST_BYTES)? != manifest_bytes
        {
            return Err("qualification source context changed during replay".into());
        }
        for record in records {
            if started.elapsed().as_secs() >= REPLAY_DEADLINE_SECONDS {
                return Err("native prefix replay deadline".into());
            }
            read_frame(source, record, &selected, reopened.engine().body_policy())?;
        }
    }
    let scope = if qualification.is_some() {
        "owner-nonfixture-native-prefix-replay"
    } else {
        "synthetic-native-prefix-replay"
    };
    let mut result = json!({"scope":scope,"height":height,
        "tip":crate::local::hex(&expected_tip),
        "source_manifest_sha256":crate::local::hex(&Sha256::digest(&manifest_bytes)),
        "native_preflight":true,"ordinary_store_append":true,"authenticated_reopen":true,
        "source_frames_changed":false,"proofs_generated":false,"nodes_started":false,
        "peer_heal_tested":false,"g1_passed":false,"g2_passed":false,
        "elapsed_ms":started.elapsed().as_millis().to_string()});
    if let Some((context, _)) = qualification {
        result["qualification"] = context.receipt();
        result["actual_eleven_component_bytes_equal_native_reference"] = json!(true);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(selected: &Genesis) -> Value {
        json!({"schema":1,"scope":"read-only-synthetic-native-partition-audit",
            "height":1,"genesis_id":crate::local::hex(&selected.id()),
            "network_id":crate::local::hex(&selected.config().network),
            "rules_commitment":crate::local::hex(&selected.rules_commitment()),
            "proof_profile":crate::local::hex(&crate::proofs::protocol_profile_fingerprint()),
            "independent_native_replay":true,"durable_head_verified":true,
            "blocks":[{"height":1,"frame":"block-0001.frame","frame_bytes":200,
            "id":"00".repeat(32),"parent":"00".repeat(32),
            "execution_commitment":"00".repeat(32),"cumulative_work":"00".repeat(64),
            "frame_sha256":"00".repeat(32)}]})
    }

    #[test]
    fn prefix_manifest_rejects_profile_bounds_paths_and_incomplete_records() {
        let selected = genesis(&[42; 32], [23; 32]).unwrap();
        let original = manifest(&selected);
        assert_eq!(manifest_records(&original, &selected, 1).unwrap().len(), 1);
        let mut narrow_work = original.clone();
        narrow_work["blocks"][0]["cumulative_work"] = json!("00".repeat(32));
        assert!(manifest_records(&narrow_work, &selected, 1).is_err());
        for height in [0, 2, 97, u64::MAX] {
            assert!(manifest_records(&original, &selected, height).is_err());
        }
        for field in [
            "genesis_id",
            "network_id",
            "rules_commitment",
            "proof_profile",
        ] {
            let mut changed = original.clone();
            changed[field] = json!("00".repeat(32));
            assert!(manifest_records(&changed, &selected, 1).is_err());
        }
        let mut changed = original.clone();
        changed["blocks"][0]["frame"] = json!("../block-0001.frame");
        assert!(manifest_records(&changed, &selected, 1).is_err());
        let mut changed = original.clone();
        changed["blocks"][0]["frame_sha256"] = json!("AB".repeat(32));
        assert!(manifest_records(&changed, &selected, 1).is_err());
        let mut changed = original;
        changed["blocks"] = json!([]);
        assert!(manifest_records(&changed, &selected, 1).is_err());
    }

    #[test]
    fn frame_replay_rejects_declared_oversize_truncation_digest_and_invalid_header() {
        let selected = genesis(&[42; 32], [23; 32]).unwrap();
        let engine = Engine::new(
            Genesis::decode(&selected.encode().unwrap()).unwrap(),
            Limits {
                max_leaves: 1_000_000,
                max_nullifiers: 1_000_000,
                max_component_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap();
        let policy = engine.body_policy();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let source = std::env::temp_dir().join(format!(
            "siworld-native-frame-replay-{}-{unique}",
            std::process::id()
        ));
        let source = source
            .parent()
            .unwrap()
            .canonicalize()
            .unwrap()
            .join(source.file_name().unwrap());
        create_private(&source).unwrap();
        let mut record = manifest(&selected)["blocks"][0].clone();
        record["frame_bytes"] =
            json!(policy.max_body_bytes + crate::eng2::header::HEADER_BYTES + 1);
        assert!(
            read_frame(&source, &record, &selected, policy)
                .unwrap_err()
                .contains("declared")
        );

        let bytes = vec![0; crate::eng2::header::HEADER_BYTES];
        private_write(&source.join("block-0001.frame"), &bytes).unwrap();
        record["frame_bytes"] = json!(bytes.len() + 1);
        assert!(
            read_frame(&source, &record, &selected, policy)
                .unwrap_err()
                .contains("size or digest")
        );
        record["frame_bytes"] = json!(bytes.len());
        assert!(
            read_frame(&source, &record, &selected, policy)
                .unwrap_err()
                .contains("size or digest")
        );
        record["frame_sha256"] = json!(crate::local::hex(&Sha256::digest(&bytes)));
        assert!(
            read_frame(&source, &record, &selected, policy)
                .unwrap_err()
                .contains("header rejected")
        );
        assert_eq!(engine.state().height(), 0);
        std::fs::remove_dir_all(source).unwrap();
    }
}
