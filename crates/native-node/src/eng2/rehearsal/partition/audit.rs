//! Read-only native replay and public frame export for a stopped synthetic node.
use super::*;
use redb::{ReadableDatabase, ReadableTableMetadata, TableDefinition};
use sha2::{Digest as _, Sha256};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("eng2-canonical-meta-v1");
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("eng2-canonical-blocks-v1");
const COMPONENTS: [&str; 11] = [
    "context",
    "tree",
    "nullifiers",
    "roots",
    "holder_pool",
    "development_fund",
    "fee_destination",
    "governance",
    "issuance_and_burn",
    "locked_rewards",
    "assets",
];

/// Acquire the normal service lease, then replay a read-only database snapshot.
/// Only a new output directory is written; source blocks and indexes are intact.
pub fn audit(directory: &Path, output: &Path) -> Result<Value, String> {
    owner_local()?;
    let _lease = crate::service::Lease::acquire(directory)?;
    let encoded = bounded_bytes(&directory.join("genesis.bin"), 1024 * 1024)?;
    let selected = Genesis::decode(&encoded)?;
    if production_ceiling(directory, &selected)?.is_none() {
        return Err("partition audit requires its synthetic node marker".into());
    }
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    let mut engine = Engine::new(selected, limits)?;
    let database = redb::ReadOnlyDatabase::open(directory.join("chain.redb"))
        .map_err(|_| "stopped partition database unavailable for read-only audit")?;
    let transaction = database
        .begin_read()
        .map_err(|_| "partition snapshot unavailable")?;
    let metadata = transaction
        .open_table(META)
        .map_err(|_| "partition metadata unavailable")?;
    if metadata
        .get("genesis")
        .map_err(|_| "partition genesis unavailable")?
        .as_ref()
        .map(|v| v.value())
        != Some(encoded.as_slice())
    {
        return Err("partition database genesis differs".into());
    }
    let durable = metadata
        .get("head")
        .map_err(|_| "partition head unavailable")?
        .ok_or("partition durable head missing")?
        .value()
        .to_vec();
    if durable.len() != 72 {
        return Err("partition head width differs".into());
    }
    let height = u64::from_le_bytes(
        durable[..8]
            .try_into()
            .map_err(|_| "partition height width")?,
    );
    if height > MAX_HEIGHT {
        return Err("partition replay exceeds height budget".into());
    }
    let blocks = transaction
        .open_table(BLOCKS)
        .map_err(|_| "partition block table unavailable")?;
    if blocks
        .len()
        .map_err(|_| "partition block count unavailable")?
        != height
    {
        return Err("partition source must retain every native proof block".into());
    }
    create_private(output)?;
    private_write(&output.join("genesis.bin"), &encoded)?;
    let verifier = NativeVerifier::new()?;
    let mut records = Vec::new();
    let started = Instant::now();
    let mut commitment = [0u8; 32];
    let mut components = Value::Null;
    for h in 1..=height {
        if started.elapsed().as_secs() >= 900 {
            return Err("partition native replay deadline".into());
        }
        let row = blocks
            .get(h)
            .map_err(|_| "partition block read failed")?
            .ok_or("partition native proof block missing")?;
        let bytes = row.value();
        let header_bytes = super::super::super::header::HEADER_BYTES;
        if bytes.len() < header_bytes
            || bytes.len() > header_bytes + engine.body_policy().max_body_bytes
        {
            return Err("partition native frame exceeds canonical bound".into());
        }
        let header = super::super::super::header::Header::decode(
            &bytes[..header_bytes],
            &engine.state().network(),
        )
        .map_err(|_| "partition native header invalid")?;
        let body = super::super::super::body::Body::decode(
            &bytes[header_bytes..],
            engine.state().network(),
            h,
            engine.body_policy(),
        )?;
        let accepted = engine.apply(&header, &body, &verifier)?;
        commitment = accepted.execution_commitment();
        if commitment != header.execution_commitment
            || accepted.id() != header.id().map_err(|_| "partition block id invalid")?
        {
            return Err("partition replay execution or identity differs".into());
        }
        let binding = super::super::super::state_components::Binding {
            genesis: engine.genesis().id(),
            rules_commitment: engine.genesis().rules_commitment(),
            parent: header.parent,
        };
        let parts = engine.state().canonical_components(binding, limits)?;
        components=Value::Object(COMPONENTS.into_iter().zip(parts).map(|(name,part)|
            (name.to_owned(),json!({"bytes":part.len(),"blake3":crate::local::hex(blake3::hash(&part).as_bytes())}))).collect());
        let frame_name = format!("block-{h:04}.frame");
        private_write(&output.join(&frame_name), bytes)?;
        records.push(json!({"height":h,"id":crate::local::hex(&accepted.id()),"parent":crate::local::hex(&header.parent),
            "execution_commitment":crate::local::hex(&commitment),"cumulative_work":crate::local::hex(&engine.state().chain().cumulative_work.to_big_endian()),
            "frame":frame_name,"frame_bytes":bytes.len(),"frame_sha256":crate::local::hex(&Sha256::digest(bytes)),
            "components":components}));
    }
    let mut expected = engine.state().height().to_le_bytes().to_vec();
    expected.extend_from_slice(&engine.state().tip());
    expected.extend_from_slice(&commitment);
    if expected != durable {
        return Err("partition durable head differs from independent complete replay".into());
    }
    let result = json!({"schema":1,"scope":"read-only-synthetic-native-partition-audit","genesis_id":crate::local::hex(&engine.genesis().id()),
        "network_id":crate::local::hex(&engine.state().network()),"rules_commitment":crate::local::hex(&engine.genesis().rules_commitment()),
        "proof_profile":crate::local::hex(&crate::proofs::protocol_profile_fingerprint()),"height":height,"tip":crate::local::hex(&engine.state().tip()),
        "independent_native_replay":true,"durable_head_verified":true,"source_block_bytes_changed":false,
        "final_components":components,"blocks":records,"elapsed_ms":started.elapsed().as_millis().to_string(),
        "wallet_scanned":false,"g1_passed":false,"g2_passed":false});
    private_write(
        &output.join("manifest.json"),
        &serde_json::to_vec_pretty(&result).map_err(|_| "partition manifest encoding failed")?,
    )?;
    Ok(result)
}
