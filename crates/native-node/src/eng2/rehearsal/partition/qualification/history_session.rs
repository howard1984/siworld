//! Owner-only, in-process complete native replay with explicit segment budgets.
//! Segments retain one genesis-initialized Engine. No receipt or saved boundary
//! can initialize, resume or stand in for any part of native execution.
use super::super::{actual_state, bounded_bytes, create_private};
use super::{Context, full_history, persisted_state::SessionAssertions};
use crate::{
    eng2::{
        body::Body,
        execution::Engine,
        genesis::Genesis,
        header::{HEADER_BYTES, Header},
        snapshot::{ImportLimits, SnapshotState, encode_components},
        state_components::{Binding, Limits},
        store::Observation,
    },
    proofs::NativeVerifier,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{path::Path, time::Instant};

mod resources;
use resources::RunGuard;
#[cfg(test)]
mod tests;

const GIB: u64 = 1024 * 1024 * 1024;
const MAX_SEGMENT_BYTES: u64 = 16 * GIB;
const MAX_RUN_BYTES: u64 = 64 * GIB;
const MIN_DISK_FREE: u64 = 128 * GIB;
const MAX_SEGMENTS: usize = 256;
const MAX_PAGE_BYTES: usize = 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_BOUNDARY_BYTES: usize = GIB as usize;
const MAX_RUN_ENTRIES: u64 = 200_000;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Budget {
    version: u32,
    height: u64,
    maximum_total_frame_bytes: u64,
    maximum_segment_frame_bytes: u64,
    maximum_segment_blocks: u64,
    maximum_segments: usize,
    deadline_seconds: u64,
    segment_deadline_seconds: u64,
    maximum_output_bytes: u64,
    maximum_run_logical_bytes: u64,
    maximum_run_entries: u64,
    minimum_disk_free_bytes: u64,
}
impl Budget {
    fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || !(1..=full_history::MAX_HISTORY_HEIGHT).contains(&self.height)
            || self.maximum_total_frame_bytes < self.height * HEADER_BYTES as u64
            || self.maximum_total_frame_bytes > MAX_RUN_BYTES
            || self.maximum_total_frame_bytes > self.maximum_run_logical_bytes
            || !(HEADER_BYTES as u64..=MAX_SEGMENT_BYTES)
                .contains(&self.maximum_segment_frame_bytes)
            || self.maximum_segment_frame_bytes > self.maximum_total_frame_bytes
            || !(1..=96).contains(&self.maximum_segment_blocks)
            || !(1..=MAX_SEGMENTS).contains(&self.maximum_segments)
            || !(1..=3600).contains(&self.deadline_seconds)
            || !(1..=self.deadline_seconds).contains(&self.segment_deadline_seconds)
            || !(1..=MAX_SEGMENT_BYTES).contains(&self.maximum_output_bytes)
            || !(1..=MAX_RUN_BYTES).contains(&self.maximum_run_logical_bytes)
            || self.maximum_output_bytes > self.maximum_run_logical_bytes
            || self.maximum_segment_blocks * (self.maximum_segments as u64) < self.height
            || !(1..=MAX_RUN_ENTRIES).contains(&self.maximum_run_entries)
            || self.minimum_disk_free_bytes < MIN_DISK_FREE
        {
            return Err("history session explicit budget exceeds finite bounds".into());
        }
        Ok(())
    }
    fn tick(&self, started: Instant, segment: Option<Instant>) -> Result<(), String> {
        if started.elapsed().as_secs() >= self.deadline_seconds
            || segment.is_some_and(|at| at.elapsed().as_secs() >= self.segment_deadline_seconds)
        {
            return Err("history session deadline exceeded".into());
        }
        Ok(())
    }
}
#[derive(Clone, Serialize)]
struct FrozenFrame {
    height: u64,
    header: Vec<u8>,
    frame_bytes: u64,
    frame_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Range {
    first: u64,
    last: u64,
    frame_bytes: u64,
}
fn ranges(frames: &[FrozenFrame], budget: Budget) -> Result<Vec<Range>, String> {
    let mut result = Vec::new();
    let mut current: Option<Range> = None;
    let mut total = 0u64;
    for (offset, frame) in frames.iter().enumerate() {
        if frame.height != offset as u64 + 1
            || frame.header.len() != HEADER_BYTES
            || frame.frame_bytes < HEADER_BYTES as u64
            || frame.frame_bytes > budget.maximum_segment_frame_bytes
        {
            return Err("history session frame coverage or segment bound rejected".into());
        }
        total = total
            .checked_add(frame.frame_bytes)
            .ok_or("session total byte overflow")?;
        if total > budget.maximum_total_frame_bytes {
            return Err("history session complete prefix byte budget exceeded".into());
        }
        if current.as_ref().is_some_and(|range| {
            range.last - range.first + 1 == budget.maximum_segment_blocks
                || range.frame_bytes > budget.maximum_segment_frame_bytes - frame.frame_bytes
        }) {
            result.push(current.take().ok_or("session segment missing")?);
        }
        if let Some(range) = current.as_mut() {
            range.last = frame.height;
            range.frame_bytes += frame.frame_bytes;
        } else {
            current = Some(Range {
                first: frame.height,
                last: frame.height,
                frame_bytes: frame.frame_bytes,
            });
        }
        if result.len() >= budget.maximum_segments {
            return Err("history session segment count exceeded".into());
        }
    }
    if let Some(range) = current {
        result.push(range);
    }
    if frames.len() as u64 != budget.height
        || result.is_empty()
        || result.len() > budget.maximum_segments
    {
        return Err("history session requires the complete declared genesis prefix".into());
    }
    Ok(result)
}
fn limits() -> Limits {
    Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    }
}
fn binding(engine: &Engine, header: &Header) -> Binding {
    Binding {
        genesis: engine.genesis().id(),
        rules_commitment: engine.genesis().rules_commitment(),
        parent: header.parent,
    }
}
fn record(engine: &Engine, header: &Header, frame: &FrozenFrame) -> Result<Value, String> {
    let parts = engine
        .state()
        .canonical_components(binding(engine, header), limits())?;
    let components = Value::Object(actual_state::COMPONENTS.into_iter().zip(parts).map(|(name, part)|
        (name.to_owned(), json!({"bytes":part.len(),"blake3":crate::local::hex(blake3::hash(&part).as_bytes())}))).collect());
    Ok(
        json!({"height":header.height,"id":crate::local::hex(&engine.state().tip()),
        "parent":crate::local::hex(&header.parent),"execution_commitment":crate::local::hex(&header.execution_commitment),
        "cumulative_work":crate::local::hex(&engine.state().chain().cumulative_work.to_big_endian()),
        "frame":format!("block-{:04}.frame",header.height),"frame_bytes":frame.frame_bytes,
        "frame_sha256":frame.frame_sha256,"components":components}),
    )
}
fn check_frame(bytes: &[u8], frozen: &FrozenFrame, network: &[u8; 32]) -> Result<Header, String> {
    if bytes.len() as u64 != frozen.frame_bytes
        || bytes.get(..HEADER_BYTES) != Some(frozen.header.as_slice())
        || crate::local::hex(&Sha256::digest(bytes)) != frozen.frame_sha256
    {
        return Err("history session frozen original frame changed".into());
    }
    let header = Header::decode(&frozen.header, network).map_err(|_| "session header rejected")?;
    if header.height != frozen.height {
        return Err("session original header height differs".into());
    }
    Ok(header)
}
struct Output<'a> {
    directory: &'a Path,
    guard: RunGuard<'a>,
    bytes: u64,
    pins: Vec<Value>,
}
impl Output<'_> {
    fn write(&mut self, name: &str, bytes: &[u8], maximum: usize) -> Result<String, String> {
        if bytes.len() > maximum {
            return Err("session output record exceeds byte bound".into());
        }
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or("session output byte overflow")?;
        if next > self.guard.budget.maximum_output_bytes {
            return Err("session output budget exceeded".into());
        }
        self.guard.check(bytes.len() as u64)?;
        super::super::super::private_write(&self.directory.join(name), bytes)?;
        self.bytes = next;
        let sha = crate::local::hex(&Sha256::digest(bytes));
        self.pins
            .push(json!({"file":name,"bytes":bytes.len(),"sha256":sha}));
        self.guard.check(0)?;
        Ok(sha)
    }
    fn json(&mut self, name: &str, value: &Value, maximum: usize) -> Result<String, String> {
        let bytes = serde_json::to_vec(value).map_err(|_| "session JSON encoding failed")?;
        self.write(name, &bytes, maximum)
    }
    fn complete(&self, result: &Value) -> Result<String, String> {
        // The completion manifest is the final write. Every retained output and
        // execution check has completed before its write-ahead resource check.
        let bytes = serde_json::to_vec(result).map_err(|_| "session manifest encoding failed")?;
        if bytes.len() > MAX_MANIFEST_BYTES
            || self
                .bytes
                .checked_add(bytes.len() as u64)
                .is_none_or(|total| total > self.guard.budget.maximum_output_bytes)
        {
            return Err("session completion manifest exceeds output budget".into());
        }
        self.guard.check(bytes.len() as u64)?;
        super::super::super::private_write(&self.directory.join("manifest.json"), &bytes)?;
        Ok(crate::local::hex(&Sha256::digest(&bytes)))
    }
    fn verify(&self) -> Result<(), String> {
        for pin in &self.pins {
            self.guard.budget.tick(self.guard.started, None)?;
            let name = pin["file"]
                .as_str()
                .ok_or("session output pin name absent")?;
            let length = pin["bytes"]
                .as_u64()
                .ok_or("session output pin length absent")? as usize;
            let bytes = bounded_bytes(&self.directory.join(name), length)?;
            if bytes.len() != length || crate::local::hex(&Sha256::digest(&bytes)) != pin["sha256"]
            {
                return Err("history session retained output changed".into());
            }
        }
        self.guard.check(0)
    }
}
fn boundary(engine: &Engine, header: &Header) -> Result<Vec<u8>, String> {
    let parts = engine
        .state()
        .canonical_components(binding(engine, header), limits())?;
    let bounds = ImportLimits {
        chain: limits(),
        max_snapshot_bytes: MAX_BOUNDARY_BYTES,
    };
    let bytes = encode_components(&parts, bounds)?;
    let reconstructed =
        SnapshotState::from_committed_components(engine.genesis(), header, &bytes, bounds)?;
    let check = Engine::from_authenticated_local_state(
        Genesis::decode(&engine.genesis().encode()?)?,
        reconstructed,
        limits(),
    )?;
    if check
        .state()
        .canonical_components(binding(engine, header), limits())?
        != parts
        || check.state().chain().cumulative_work != engine.state().chain().cumulative_work
        || check.state().height() != engine.state().height()
        || check.state().tip() != engine.state().tip()
    {
        return Err("session full boundary round trip differs".into());
    }
    // The live reference is never replaced by reconstructed or file-loaded state.
    Ok(bytes)
}

/// Run one fresh, read-only audit from genesis through the exact accepted head.
/// The separately named interface requires an explicit total and segment plan;
/// it does not modify the existing full-history export's 16-GiB policy.
/// Partial output is retained on failure. No resume/import/receipt input exists.
pub fn audit(
    directory: &Path,
    run_root: &Path,
    output: &Path,
    budget_input: (&Path, &str),
    expectations_input: (&Path, &str),
    binding_input: (&Path, &str),
) -> Result<Value, String> {
    let started = Instant::now();
    let context = Context::load(binding_input.0, binding_input.1)?;
    let budget_bytes = bounded_bytes(budget_input.0, 4096)?;
    context.check_manifest_pin(&budget_bytes, budget_input.1)?;
    let budget: Budget =
        serde_json::from_slice(&budget_bytes).map_err(|_| "session budget schema rejected")?;
    budget.validate()?;
    let expectations_bytes = bounded_bytes(expectations_input.0, 128 * 1024)?;
    context.check_manifest_pin(&expectations_bytes, expectations_input.1)?;
    let mut assertions = SessionAssertions::load(&expectations_bytes, budget.height)?;
    super::source_path(directory)?;
    super::source_path(run_root)?;
    if directory == run_root
        || !directory.starts_with(run_root)
        || !output.starts_with(run_root)
        || output == run_root
        || output.starts_with(directory)
        || directory.starts_with(output)
    {
        return Err("session requires disjoint node/output under one complete run root".into());
    }
    let guard = RunGuard::new(run_root, budget, started)?;
    guard.check(0)?;
    let _lease = crate::service::Lease::acquire(directory)?;
    full_history::check_database(directory)?;
    let encoded = bounded_bytes(&directory.join("genesis.bin"), 1024 * 1024)?;
    let selected = Genesis::decode(&encoded)?;
    context.check_genesis(&selected)?;
    let store = Observation::open_full_history(
        &directory.join("chain.redb"),
        Genesis::decode(&encoded)?,
        limits(),
        budget.height,
    )?;
    if store.engine().state().height() != budget.height
        || store.full_frame_count()? != budget.height
    {
        return Err("session requires exact authenticated height and all original frames".into());
    }
    let expected_tip = store.engine().state().tip();
    // Reserve the new directory entry before creating the output generation.
    guard.check(1)?;
    create_private(output)?;
    let mut output = Output {
        directory: output,
        guard,
        bytes: 0,
        pins: Vec::new(),
    };
    output.write("genesis.bin", &encoded, 1024 * 1024)?;
    let mut frames = Vec::with_capacity(budget.height as usize);
    let mut total = 0u64;
    // Freeze original bytes before any proof execution. Never infer validation
    // from this metadata or accept it as a separately supplied execution receipt.
    for height in 1..=budget.height {
        budget.tick(started, None)?;
        output.guard.disk(0)?;
        let bytes = store.full_frame(height)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or("session original byte overflow")?;
        if total > budget.maximum_total_frame_bytes
            || bytes.len() as u64 > budget.maximum_segment_frame_bytes
        {
            return Err("session original history exceeds explicit byte plan".into());
        }
        frames.push(FrozenFrame {
            height,
            header: bytes[..HEADER_BYTES].to_vec(),
            frame_bytes: bytes.len() as u64,
            frame_sha256: crate::local::hex(&Sha256::digest(&bytes)),
        });
    }
    let segments = ranges(&frames, budget)?;
    let mut metadata_pages = Vec::new();
    for (index, chunk) in frames.chunks(96).enumerate() {
        let name = format!("frozen-{index:06}.json");
        let hash = output.json(&name, &json!({"frames":chunk}), MAX_PAGE_BYTES)?;
        metadata_pages.push(json!({"file":name,"sha256":hash,"first":chunk[0].height,"last":chunk[chunk.len()-1].height}));
    }
    let source_root = output.json("frozen-metadata.json", &json!({"version":1,"qualification":context.receipt(),
        "height":budget.height,"tip":crate::local::hex(&expected_tip),"budget_sha256":budget_input.1,
        "total_frame_bytes":total,"pages":metadata_pages,"segments":segments,"native_execution_performed":false}), MAX_MANIFEST_BYTES)?;
    let verifier = NativeVerifier::for_genesis(&selected)?;
    let mut reference = Engine::new(selected, limits())?;
    let genesis_parts = reference.state().canonical_components(
        Binding {
            genesis: reference.genesis().id(),
            rules_commitment: reference.genesis().rules_commitment(),
            parent: [0; 32],
        },
        limits(),
    )?;
    let genesis_state = encode_components(
        &genesis_parts,
        ImportLimits {
            chain: limits(),
            max_snapshot_bytes: MAX_BOUNDARY_BYTES,
        },
    )?;
    output.write("state-genesis.bin", &genesis_state, MAX_BOUNDARY_BYTES)?;
    drop(genesis_state);
    drop(genesis_parts);
    let mut final_pair = None;
    let mut previous = source_root.clone();
    let mut receipts = Vec::new();
    for (index, range) in segments.iter().enumerate() {
        let segment_started = Instant::now();
        output.guard.check(0)?;
        if reference.state().height() + 1 != range.first {
            return Err("session execution range gap".into());
        }
        let mut records = Vec::new();
        for frame in &frames[(range.first - 1) as usize..range.last as usize] {
            budget.tick(started, Some(segment_started))?;
            output.guard.disk(0)?;
            let bytes = store.full_frame(frame.height)?;
            let header = check_frame(&bytes, frame, &reference.state().network())?;
            let body = Body::decode(
                &bytes[HEADER_BYTES..],
                reference.state().network(),
                frame.height,
                reference.body_policy(),
            )?;
            reference.apply(&header, &body, &verifier)?;
            assertions.observe(&body)?;
            let record = record(&reference, &header, frame)?;
            actual_state::observe(&reference, &reference, &header, &record)?;
            records.push(record.clone());
            final_pair = Some((header, record));
        }
        for frame in &frames[(range.first - 1) as usize..range.last as usize] {
            budget.tick(started, Some(segment_started))?;
            output.guard.disk(0)?;
            check_frame(
                &store.full_frame(frame.height)?,
                frame,
                &reference.state().network(),
            )?;
        }
        let (header, last) = final_pair
            .as_ref()
            .ok_or("session segment produced no state")?;
        let snapshot = boundary(&reference, header)?;
        let state_name = format!("state-{index:06}.bin");
        let state_hash = output.write(&state_name, &snapshot, MAX_BOUNDARY_BYTES)?;
        let records_name = format!("native-{index:06}.json");
        let records_hash =
            output.json(&records_name, &json!({"blocks":records}), MAX_PAGE_BYTES)?;
        let receipt_name = format!("segment-{index:06}.json");
        let receipt_hash = output.json(&receipt_name, &json!({"version":1,"range":range,
            "source_metadata_sha256":source_root,"previous_record_sha256":previous,
            "state_file":state_name,"state_sha256":state_hash,"header":header.encode().map_err(|_| "session boundary header encoding failed")?.to_vec(),
            "actual_reference_state":last,"native_records_file":records_name,"native_records_sha256":records_hash,
            "assertions":assertions.progress(),"native_verifier_calls_completed_in_this_process":true,
            "saved_record_is_execution_proof":false,"boundary_imported_to_continue":false}), MAX_PAGE_BYTES)?;
        receipts.push(json!({"file":receipt_name,"sha256":receipt_hash}));
        previous = receipt_hash;
        budget.tick(started, Some(segment_started))?;
    }
    let (header, last) = final_pair.ok_or("session final state absent")?;
    if reference.state().height() != budget.height || reference.state().tip() != expected_tip {
        return Err("session final native head differs from original accepted head".into());
    }
    actual_state::observe(store.engine(), &reference, &header, &last)?;
    let _ = assertions.finish(store.engine(), &reference)?;
    drop(store);
    let reopened = Observation::open_full_history(
        &directory.join("chain.redb"),
        Genesis::decode(&encoded)?,
        limits(),
        budget.height,
    )?;
    if reopened.full_frame_count()? != budget.height {
        return Err("session reopened full history count differs".into());
    }
    let actual = actual_state::observe(reopened.engine(), &reference, &header, &last)?;
    let business = assertions.finish(reopened.engine(), &reference)?;
    // A final whole-prefix pass detects changes after an earlier segment ended.
    for range in &segments {
        let segment_started = Instant::now();
        output.guard.check(0)?;
        for frame in &frames[(range.first - 1) as usize..range.last as usize] {
            budget.tick(started, Some(segment_started))?;
            output.guard.disk(0)?;
            check_frame(
                &reopened.full_frame(frame.height)?,
                frame,
                &reference.state().network(),
            )?;
        }
    }
    if bounded_bytes(&directory.join("genesis.bin"), 1024 * 1024)? != encoded
        || bounded_bytes(budget_input.0, 4096)? != budget_bytes
        || bounded_bytes(expectations_input.0, 128 * 1024)? != expectations_bytes
    {
        return Err("session pinned inputs changed".into());
    }
    let _ = Context::load(binding_input.0, binding_input.1)?;
    output.verify()?;
    budget.tick(started, None)?;
    let result = json!({"version":1,"scope":"owner-nonfixture-complete-native-history-session",
        "qualification":context.receipt(),"budget_sha256":budget_input.1,"expectations_sha256":expectations_input.1,
        "source_metadata_sha256":source_root,"height":budget.height,"tip":crate::local::hex(&expected_tip),
        "total_original_frame_bytes":total,"segments":receipts,"files":output.pins,
        "entire_prefix_natively_executed_from_genesis_in_this_process":true,"reference_resumed_or_imported":false,
        "saved_records_are_execution_proofs":false,"authenticated_read_only_opens":2,
        "actual_eleven_component_bytes_equal_native_reference":true,"actual_state":actual,"business_assertions":business,
        "all_original_frames_rechecked_after_authenticated_reopen":true,
        "proofs_generated":false,"nodes_started":false,"database_changed":false,
        "wallet_scan_performed":false,"wallet_balances_verified":false,"g1_passed":false,"g2_passed":false});
    let manifest = output.complete(&result)?;
    Ok(
        json!({"scope":"owner-nonfixture-complete-native-history-session","manifest_sha256":manifest,
        "height":budget.height,"total_original_frame_bytes":total,"native_complete_from_genesis":true,
        "saved_records_are_execution_proofs":false,"g1_passed":false,"g2_passed":false}),
    )
}
