//! Bounded, complete genesis-to-head history in independently pinned pages.
//! No page is a trusted state checkpoint; replay always begins at genesis.
use super::super::{actual_state, bounded_bytes, create_private};
use super::{AUDIT_SCOPE, Context};
use crate::{
    eng2::{
        body::Body,
        execution::Engine,
        genesis::Genesis,
        header::{HEADER_BYTES, Header},
        state_components::{Binding, Limits},
        store::Observation,
    },
    proofs::NativeVerifier,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{path::Path, time::Instant};

pub(super) const MAX_HISTORY_HEIGHT: u64 = 16_384;
pub(super) const MAX_INDEX_BYTES: usize = 256 * 1024;
const PAGE_RECORDS: u64 = 96;
const MAX_PAGE_BYTES: usize = 1024 * 1024;
const MAX_RECORD_BYTES: usize = 8192;
const MAX_FRAME_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_DATABASE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_DEADLINE_SECONDS: u64 = 3600;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Budget {
    version: u32,
    pub height: u64,
    maximum_frame_bytes: u64,
    deadline_seconds: u64,
}
impl Budget {
    pub(super) fn load(context: &Context, input: (&Path, &str)) -> Result<(Self, Vec<u8>), String> {
        let bytes = bounded_bytes(input.0, 4096)?;
        context.check_manifest_pin(&bytes, input.1)?;
        let budget: Self =
            serde_json::from_slice(&bytes).map_err(|_| "full history budget schema rejected")?;
        budget.validate()?;
        Ok((budget, bytes))
    }
    fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || !(1..=MAX_HISTORY_HEIGHT).contains(&self.height)
            || self.maximum_frame_bytes < self.height * HEADER_BYTES as u64
            || self.maximum_frame_bytes > MAX_FRAME_BYTES
            || !(1..=MAX_DEADLINE_SECONDS).contains(&self.deadline_seconds)
        {
            return Err("full history explicit budget exceeds finite bounds".into());
        }
        Ok(())
    }
    pub(super) fn tick(&self, started: Instant) -> Result<(), String> {
        if started.elapsed().as_secs() >= self.deadline_seconds {
            return Err("full history total deadline".into());
        }
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Page {
    file: String,
    first_height: u64,
    last_height: u64,
    bytes: usize,
    sha256: String,
    frame_bytes: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PageRecords {
    first_height: u64,
    last_height: u64,
    blocks: Vec<Value>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Index {
    schema: u32,
    scope: String,
    genesis_id: String,
    network_id: String,
    rules_commitment: String,
    proof_profile: String,
    qualification: Value,
    height: u64,
    tip: String,
    budget_sha256: String,
    total_frame_bytes: u64,
    independent_native_replay: bool,
    durable_head_verified: bool,
    authenticated_read_only_opens: u32,
    final_components: Value,
    pages: Vec<Page>,
}
pub(super) struct Source {
    index: Index,
    budget: Budget,
}
fn hex(value: &Value, bytes: usize) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == bytes * 2
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn record_valid(record: &Value, height: u64) -> bool {
    record.as_object().is_some_and(|o| o.len() == 9)
        && record["height"] == height
        && record["frame"] == format!("block-{height:04}.frame")
        && record["frame_bytes"]
            .as_u64()
            .is_some_and(|n| n >= HEADER_BYTES as u64 && n <= MAX_FRAME_BYTES)
        && ["id", "parent", "execution_commitment", "frame_sha256"]
            .into_iter()
            .all(|k| hex(&record[k], 32))
        && hex(&record["cumulative_work"], 64)
        && record["components"]
            .as_object()
            .is_some_and(|o| o.len() == 11)
}
fn page_layout(pages: &[Page], height: u64, total_frame_bytes: u64) -> Result<(), String> {
    let mut next = 1;
    let mut total = 0u64;
    for (offset, page) in pages.iter().enumerate() {
        if page.file != format!("records-{offset:06}.json")
            || page.first_height != next
            || page.last_height != (next + PAGE_RECORDS - 1).min(height)
            || page.bytes == 0
            || page.bytes > MAX_PAGE_BYTES
            || !hex(&json!(page.sha256), 32)
        {
            return Err("full history page coverage or framing rejected".into());
        }
        total = total
            .checked_add(page.frame_bytes)
            .ok_or("full history page byte overflow")?;
        next = page.last_height + 1;
    }
    if next != height + 1 || total != total_frame_bytes {
        return Err("full history page total differs".into());
    }
    Ok(())
}
impl Source {
    pub(super) fn open(
        manifest: &Value,
        selected: &Genesis,
        context: &Context,
        budget: Budget,
        budget_pin: &str,
    ) -> Result<Self, String> {
        context.check_genesis(selected)?;
        context.check_manifest(manifest)?;
        let index: Index = serde_json::from_value(manifest.clone())
            .map_err(|_| "full history index schema rejected")?;
        if index.schema != 2
            || index.scope != AUDIT_SCOPE
            || index.height != budget.height
            || index.genesis_id != crate::local::hex(&selected.id())
            || index.network_id != crate::local::hex(&selected.config().network)
            || index.rules_commitment != crate::local::hex(&selected.rules_commitment())
            || index.proof_profile
                != crate::local::hex(&crate::proofs::protocol_profile_fingerprint())
            || index.budget_sha256 != budget_pin
            || !hex(&json!(index.tip), 32)
            || !index.independent_native_replay
            || !index.durable_head_verified
            || index.authenticated_read_only_opens != 2
            || index.total_frame_bytes > budget.maximum_frame_bytes
            || index.pages.len() as u64 != index.height.div_ceil(PAGE_RECORDS)
        {
            return Err("full history index context or coverage rejected".into());
        }
        page_layout(&index.pages, index.height, index.total_frame_bytes)?;
        Ok(Self { index, budget })
    }
    pub(super) fn walk(
        &self,
        directory: &Path,
        started: Instant,
        mut visit: impl FnMut(&Value) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut next = 1;
        let mut total = 0u64;
        for page in &self.index.pages {
            self.budget.tick(started)?;
            let bytes = bounded_bytes(&directory.join(&page.file), MAX_PAGE_BYTES)?;
            if bytes.len() != page.bytes
                || crate::local::hex(&Sha256::digest(&bytes)) != page.sha256
            {
                return Err("full history pinned page changed".into());
            }
            let values: PageRecords =
                serde_json::from_slice(&bytes).map_err(|_| "full history page schema rejected")?;
            if values.first_height != page.first_height
                || values.last_height != page.last_height
                || values.blocks.len() as u64 != page.last_height - page.first_height + 1
            {
                return Err("full history page count differs".into());
            }
            let mut page_bytes = 0u64;
            for record in &values.blocks {
                self.budget.tick(started)?;
                if !record_valid(record, next)
                    || serde_json::to_vec(record)
                        .map_err(|_| "full history record encoding failed")?
                        .len()
                        > MAX_RECORD_BYTES
                {
                    return Err("full history sequential record rejected".into());
                }
                page_bytes = page_bytes
                    .checked_add(
                        record["frame_bytes"]
                            .as_u64()
                            .ok_or("full history frame length absent")?,
                    )
                    .ok_or("full history frame byte overflow")?;
                total = total
                    .checked_add(
                        record["frame_bytes"]
                            .as_u64()
                            .ok_or("full history frame length absent")?,
                    )
                    .ok_or("full history total byte overflow")?;
                if total > self.budget.maximum_frame_bytes {
                    return Err("full history frame byte budget exceeded".into());
                }
                if next == self.index.height
                    && (record["id"] != self.index.tip
                        || record["components"] != self.index.final_components)
                {
                    return Err("full history final record differs from index".into());
                }
                visit(record)?;
                next += 1;
            }
            if page_bytes != page.frame_bytes {
                return Err("full history page frame byte sum differs".into());
            }
        }
        if next != self.index.height + 1 || total != self.index.total_frame_bytes {
            return Err("full history exact complete prefix missing".into());
        }
        self.budget.tick(started)
    }
}
fn limits() -> Limits {
    Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    }
}
fn database_bound(directory: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(directory.join("chain.redb"))
        .map_err(|_| "full history database metadata unavailable")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_DATABASE_BYTES {
        return Err("full history database exceeds finite input bound".into());
    }
    Ok(())
}
pub(super) fn check_database(directory: &Path) -> Result<(), String> {
    database_bound(directory)
}
fn write_page(
    output: &Path,
    records: &mut Vec<Value>,
    pages: &mut Vec<Page>,
) -> Result<(), String> {
    let first = records
        .first()
        .and_then(|r| r["height"].as_u64())
        .ok_or("full history page empty")?;
    let last = records
        .last()
        .and_then(|r| r["height"].as_u64())
        .ok_or("full history page empty")?;
    let frame_bytes = records
        .iter()
        .try_fold(0u64, |sum, r| sum.checked_add(r["frame_bytes"].as_u64()?))
        .ok_or("full history page byte overflow")?;
    let bytes = serde_json::to_vec(&PageRecords {
        first_height: first,
        last_height: last,
        blocks: std::mem::take(records),
    })
    .map_err(|_| "full history page encoding failed")?;
    if bytes.len() > MAX_PAGE_BYTES {
        return Err("full history page exceeds byte budget".into());
    }
    let file = format!("records-{:06}.json", pages.len());
    super::super::super::private_write(&output.join(&file), &bytes)?;
    pages.push(Page {
        file,
        first_height: first,
        last_height: last,
        bytes: bytes.len(),
        sha256: crate::local::hex(&Sha256::digest(&bytes)),
        frame_bytes,
    });
    Ok(())
}

/// Export every original frame from an authenticated stopped owner. A manifest
/// is published only after complete replay and a second authenticated read-only
/// open. Partial output remains incomplete and is never a passing manifest.
pub fn export(
    directory: &Path,
    output: &Path,
    budget_input: (&Path, &str),
    binding: (&Path, &str),
) -> Result<Value, String> {
    let started = Instant::now();
    let context = Context::load(binding.0, binding.1)?;
    let (budget, budget_bytes) = Budget::load(&context, budget_input)?;
    super::source_path(directory)?;
    if output.starts_with(directory) || directory.starts_with(output) {
        return Err("full history source and output must be separate".into());
    }
    let _lease = crate::service::Lease::acquire(directory)?;
    database_bound(directory)?;
    let encoded = bounded_bytes(&directory.join("genesis.bin"), 1024 * 1024)?;
    let selected = Genesis::decode(&encoded)?;
    context.check_genesis(&selected)?;
    budget.tick(started)?;
    let store = Observation::open_full_history(
        &directory.join("chain.redb"),
        Genesis::decode(&encoded)?,
        limits(),
        budget.height,
    )?;
    if store.engine().state().height() != budget.height
        || store.full_frame_count()? != budget.height
    {
        return Err("full history requires exact declared height and every original frame".into());
    }
    create_private(output)?;
    super::super::super::private_write(&output.join("genesis.bin"), &encoded)?;
    let verifier = NativeVerifier::for_genesis(&selected)?;
    let mut reference = Engine::new(selected, limits())?;
    let mut records = Vec::with_capacity(PAGE_RECORDS as usize);
    let mut pages = Vec::new();
    let mut total = 0u64;
    let mut final_pair = None;
    for height in 1..=budget.height {
        budget.tick(started)?;
        let bytes = store.full_frame(height)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or("full history frame bytes overflow")?;
        if total > budget.maximum_frame_bytes {
            return Err("full history frame byte budget exceeded".into());
        }
        let header = Header::decode(&bytes[..HEADER_BYTES], &reference.state().network())
            .map_err(|_| "full history header rejected")?;
        let body = Body::decode(
            &bytes[HEADER_BYTES..],
            reference.state().network(),
            height,
            reference.body_policy(),
        )?;
        reference.apply(&header, &body, &verifier)?;
        let components = reference.state().canonical_components(
            Binding {
                genesis: reference.genesis().id(),
                rules_commitment: reference.genesis().rules_commitment(),
                parent: header.parent,
            },
            limits(),
        )?;
        let components = Value::Object(actual_state::COMPONENTS.into_iter().zip(components).map(|(name, part)|
            (name.to_owned(), json!({"bytes":part.len(),"blake3":crate::local::hex(blake3::hash(&part).as_bytes())}))).collect());
        let record = json!({"height":height,"id":crate::local::hex(&reference.state().tip()),"parent":crate::local::hex(&header.parent),
            "execution_commitment":crate::local::hex(&header.execution_commitment),"cumulative_work":crate::local::hex(&reference.state().chain().cumulative_work.to_big_endian()),
            "frame":format!("block-{height:04}.frame"),"frame_bytes":bytes.len(),"frame_sha256":crate::local::hex(&Sha256::digest(&bytes)),"components":components});
        actual_state::observe(&reference, &reference, &header, &record)?;
        if serde_json::to_vec(&record)
            .map_err(|_| "full history record encoding failed")?
            .len()
            > MAX_RECORD_BYTES
        {
            return Err("full history record exceeds byte budget".into());
        }
        super::super::super::private_write(
            &output.join(format!("block-{height:04}.frame")),
            &bytes,
        )?;
        records.push(record.clone());
        if records.len() as u64 == PAGE_RECORDS {
            write_page(output, &mut records, &mut pages)?;
        }
        final_pair = Some((header, record));
    }
    if !records.is_empty() {
        write_page(output, &mut records, &mut pages)?;
    }
    let (header, record) = final_pair.ok_or("full history final record absent")?;
    actual_state::observe(store.engine(), &reference, &header, &record)?;
    drop(store);
    budget.tick(started)?;
    let reopened = Observation::open_full_history(
        &directory.join("chain.redb"),
        Genesis::decode(&encoded)?,
        limits(),
        budget.height,
    )?;
    actual_state::observe(reopened.engine(), &reference, &header, &record)?;
    if reopened.full_frame_count()? != budget.height
        || bounded_bytes(&directory.join("genesis.bin"), 1024 * 1024)? != encoded
        || bounded_bytes(budget_input.0, 4096)? != budget_bytes
    {
        return Err("full history pinned inputs changed".into());
    }
    budget.tick(started)?;
    let result = serde_json::to_value(Index {
        schema: 2,
        scope: AUDIT_SCOPE.into(),
        genesis_id: crate::local::hex(&reference.genesis().id()),
        network_id: crate::local::hex(&reference.state().network()),
        rules_commitment: crate::local::hex(&reference.genesis().rules_commitment()),
        proof_profile: crate::local::hex(&crate::proofs::protocol_profile_fingerprint()),
        qualification: context.receipt(),
        height: budget.height,
        tip: crate::local::hex(&reference.state().tip()),
        budget_sha256: budget_input.1.into(),
        total_frame_bytes: total,
        independent_native_replay: true,
        durable_head_verified: true,
        authenticated_read_only_opens: 2,
        final_components: record["components"].clone(),
        pages,
    })
    .map_err(|_| "full history index encoding failed")?;
    let bytes = serde_json::to_vec(&result).map_err(|_| "full history index encoding failed")?;
    if bytes.len() > MAX_INDEX_BYTES {
        return Err("full history index exceeds byte budget".into());
    }
    super::super::super::private_write(&output.join("manifest.json"), &bytes)?;
    Ok(
        json!({"scope":"owner-nonfixture-complete-history-export","height":budget.height,
        "source_manifest_sha256":crate::local::hex(&Sha256::digest(&bytes)),"complete_from_genesis":true,
        "authenticated_read_only_opens":2,"actual_eleven_component_bytes_equal_native_reference":true,
        "proofs_generated":false,"nodes_started":false,"g1_passed":false,"g2_passed":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn page(offset: usize, first: u64, last: u64) -> Page {
        Page {
            file: format!("records-{offset:06}.json"),
            first_height: first,
            last_height: last,
            bytes: 256,
            sha256: "01".repeat(32),
            frame_bytes: last - first + 1,
        }
    }
    #[test]
    fn complete_history_pages_reject_missing_or_shifted_genesis_prefix() {
        let mut pages = vec![page(0, 1, 96), page(1, 97, 97)];
        assert!(page_layout(&pages, 97, 97).is_ok());
        pages[0].first_height = 2;
        assert!(page_layout(&pages, 97, 97).is_err());
        pages[0].first_height = 1;
        pages[1].first_height = 96;
        assert!(page_layout(&pages, 97, 97).is_err());
        pages[1].first_height = 97;
        pages[1].file = "../records-000001.json".into();
        assert!(page_layout(&pages, 97, 97).is_err());
        assert!(page_layout(&pages[..1], 97, 96).is_err());
    }
    #[test]
    fn complete_history_budget_remains_finite_beyond_short_case_limit() {
        let mut budget = Budget {
            version: 1,
            height: 97,
            maximum_frame_bytes: 1024 * 1024,
            deadline_seconds: 900,
        };
        assert!(budget.validate().is_ok());
        budget.height = MAX_HISTORY_HEIGHT + 1;
        assert!(budget.validate().is_err());
        budget.height = 97;
        budget.maximum_frame_bytes = MAX_FRAME_BYTES + 1;
        assert!(budget.validate().is_err());
        budget.maximum_frame_bytes = 1024 * 1024;
        budget.deadline_seconds = MAX_DEADLINE_SECONDS + 1;
        assert!(budget.validate().is_err());
        assert!(serde_json::from_str::<Budget>(r#"{"version":1,"height":97,"maximum_frame_bytes":1048576,"deadline_seconds":900,"repair":true}"#).is_err());
        assert!(serde_json::from_str::<Budget>(r#"{"version":1,"version":1,"height":97,"maximum_frame_bytes":1048576,"deadline_seconds":900}"#).is_err());
    }
}
