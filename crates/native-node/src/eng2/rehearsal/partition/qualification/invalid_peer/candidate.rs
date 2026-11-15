//! Owner-local generation and inspection of a distinct invalid branch candidate.
//! Accepted source frames and canonical databases are never edited.
use super::super::full_history;
use super::*;
use crate::eng2::{
    body::{Body, Policy},
    branches::{self, Status},
    rehearsal::partition::{self, actual_state::observe, replay},
    selection::{HeaderRules, VerifiedHeaders},
    state_components::Limits,
    store::{ReplacementBudget, ReplacementFailure, Store},
};
use crate::proofs::NativeVerifier;
use sha2::{Digest as _, Sha256};
use std::time::Duration;

const MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const REASON: &str = "native execution commitment differs from complete checked state";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    directory: String,
    manifest_sha256: String,
    height: u64,
    budget: String,
    budget_sha256: String,
    audit_binding: String,
    audit_binding_sha256: String,
}

fn input_context(bytes: &[u8], pin: &str, helper: &Context) -> Result<Context, String> {
    helper.check_manifest_pin(bytes, pin)?;
    let binding = super::super::parse(bytes)?;
    if binding.network_id != helper.binding.network_id
        || binding.genesis_id != helper.binding.genesis_id
        || binding.rules_commitment != helper.binding.rules_commitment
        || binding.proof_profile != helper.binding.proof_profile
    {
        return Err("negative candidate input audit protocol differs from helper".into());
    }
    // This context validates only pinned historical input declarations.
    // Context::load independently validates the running helper.
    Ok(Context {
        binding,
        binding_sha256: pin.into(),
    })
}

/// An input audit's provenance is distinct from this tool's executable binding.
/// It is authenticated by independent pins, never by pretending this executable
/// was compiled from the historical auditor's source commit.
struct History {
    directory: std::path::PathBuf,
    genesis: Vec<u8>,
    manifest: Vec<u8>,
    budget: Vec<u8>,
    audit_binding: Vec<u8>,
    pages: full_history::Source,
    records: Vec<Value>,
    provenance: Value,
}
impl History {
    fn open(s: &Source, helper: &Context, started: Instant) -> Result<Self, String> {
        let directory = Path::new(&s.directory);
        super::super::source_path(directory)?;
        let audit_binding = read(Path::new(&s.audit_binding), 8192)?;
        let input = input_context(&audit_binding, &s.audit_binding_sha256, helper)?;
        let genesis = read(&directory.join("genesis.bin"), 1024 * 1024)?;
        let selected = Genesis::decode(&genesis)?;
        input.check_genesis(&selected)?;
        helper.check_genesis(&selected)?;
        let manifest = read(
            &directory.join("manifest.json"),
            full_history::MAX_INDEX_BYTES,
        )?;
        helper.check_manifest_pin(&manifest, &s.manifest_sha256)?;
        let value: Value = serde_json::from_slice(&manifest)
            .map_err(|_| "negative candidate input manifest schema")?;
        if value["qualification"]["binary_sha256"] != input.binding.binary_sha256
            || value["qualification"]["binding_sha256"] != input.binding_sha256
        {
            return Err("negative candidate input auditor binding differs".into());
        }
        let (budget, budget_bytes) =
            full_history::Budget::load(&input, (Path::new(&s.budget), &s.budget_sha256))?;
        if budget.height != s.height {
            return Err("negative candidate input height differs".into());
        }
        let pages =
            full_history::Source::open(&value, &selected, &input, budget, &s.budget_sha256)?;
        let mut records = Vec::new();
        pages.walk(directory, started, |record| {
            records.push(record.clone());
            Ok(())
        })?;
        Ok(Self {
            directory: directory.into(),
            genesis,
            manifest,
            budget: budget_bytes,
            audit_binding,
            pages,
            records,
            provenance: input.receipt(),
        })
    }
    fn record(&self, height: u64) -> Result<&Value, String> {
        height
            .checked_sub(1)
            .and_then(|i| self.records.get(i as usize))
            .ok_or_else(|| "negative candidate source height unavailable".into())
    }
    fn read(&self, height: u64, policy: Policy) -> Result<(Header, Body), String> {
        replay::read_frame(
            &self.directory,
            self.record(height)?,
            &Genesis::decode(&self.genesis)?,
            policy,
        )
    }
    fn headers(&self, height: u64, policy: Policy) -> Result<Vec<Header>, String> {
        (1..=height)
            .map(|h| self.read(h, policy).map(|(header, _)| header))
            .collect()
    }
    fn unchanged(&self, s: &Source, policy: Policy, started: Instant) -> Result<(), String> {
        if read(&self.directory.join("genesis.bin"), 1024 * 1024)? != self.genesis
            || read(
                &self.directory.join("manifest.json"),
                full_history::MAX_INDEX_BYTES,
            )? != self.manifest
            || read(Path::new(&s.budget), 4096)? != self.budget
            || read(Path::new(&s.audit_binding), 8192)? != self.audit_binding
        {
            return Err("negative candidate input context changed".into());
        }
        let mut count = 0;
        self.pages.walk(&self.directory, started, |record| {
            if self.records.get(count) != Some(record) {
                return Err("negative candidate input records changed".into());
            }
            count += 1;
            self.read(count as u64, policy)?;
            Ok(())
        })?;
        if count != self.records.len() {
            return Err("negative candidate input record count changed".into());
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    canonical: Source,
    competing: Source,
    receiver_height: u64,
    ancestor_height: u64,
    ancestor_id: String,
    maximum_nonce_attempts: u64,
    maximum_elapsed_seconds: u64,
    maximum_body_bytes: u64,
}

fn parse_plan(bytes: &[u8]) -> Result<Plan, String> {
    let p: Plan = serde_json::from_slice(bytes).map_err(|_| "negative branch plan schema")?;
    if p.version != 1
        || p.ancestor_height == 0
        || p.receiver_height
            .checked_sub(p.ancestor_height)
            .is_none_or(|d| !(1..=24).contains(&d))
        || p.canonical.height < p.receiver_height
        || p.competing.height <= p.receiver_height
        || p.canonical.height > 96
        || p.competing.height > 96
        || !(1..=1_000_000).contains(&p.maximum_nonce_attempts)
        || !(1..=900).contains(&p.maximum_elapsed_seconds)
        || !(1..=MAX_BYTES).contains(&p.maximum_body_bytes)
        || hash(&p.ancestor_id).is_err()
        || [&p.canonical, &p.competing].into_iter().any(|s| {
            [&s.directory, &s.budget, &s.audit_binding]
                .into_iter()
                .any(|v| v.is_empty() || v.len() > 2048)
                || [
                    &s.manifest_sha256,
                    &s.budget_sha256,
                    &s.audit_binding_sha256,
                ]
                .into_iter()
                .any(|v| hash(v).is_err())
        })
        || p.canonical.directory == p.competing.directory
    {
        return Err("negative branch plan context".into());
    }
    Ok(p)
}

fn rules(selected: &Genesis) -> HeaderRules {
    let c = selected.config();
    HeaderRules {
        network: c.network,
        genesis: selected.id(),
        genesis_timestamp: c.genesis_timestamp,
        genesis_target: c.genesis_target,
        target_interval: c.target_interval,
        pow_iterations: c.pow_iterations,
        max_headers: 96,
    }
}

fn distinct_header(original: &Header) -> Header {
    let mut header = original.clone();
    header.execution_commitment[0] ^= 1;
    header.nonce = 0;
    header
}

fn time(started: Instant, seconds: u64) -> Result<(), String> {
    if started.elapsed() >= Duration::from_secs(seconds) {
        Err("negative branch owner deadline reached".into())
    } else {
        Ok(())
    }
}

fn reject_exact(
    result: Result<crate::eng2::store::PrevalidatedReplacement, ReplacementFailure>,
    index: usize,
) -> Result<(), String> {
    match result {
        Err(ReplacementFailure::Rejected {
            index: actual,
            reason,
        }) if actual == index && reason == REASON => Ok(()),
        Err(other) => Err(format!(
            "negative candidate did not reach exact native rejection: {other}"
        )),
        Ok(_) => Err("negative candidate unexpectedly passed native prevalidation".into()),
    }
}

fn existing_lease(directory: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let parent =
        std::fs::symlink_metadata(directory).map_err(|_| "inspection directory unavailable")?;
    if !parent.is_dir() || parent.permissions().mode() & 0o077 != 0 {
        return Err("inspection requires an existing private node directory".into());
    }
    let path = directory.join(crate::service::LEASE_FILE);
    let before =
        std::fs::symlink_metadata(&path).map_err(|_| "existing inspection lease missing")?;
    if !before.file_type().is_file()
        || before.permissions().mode() & 0o077 != 0
        || before.len() > 65536
    {
        return Err("existing inspection lease shape or permissions differ".into());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)
        .map_err(|_| "existing inspection lease unavailable")?;
    let opened = file
        .metadata()
        .map_err(|_| "existing inspection lease metadata unavailable")?;
    let after =
        std::fs::symlink_metadata(&path).map_err(|_| "existing inspection lease changed")?;
    if !opened.is_file()
        || !after.file_type().is_file()
        || opened.permissions().mode() & 0o077 != 0
        || opened.len() > 65536
        || before.dev() != opened.dev()
        || before.ino() != opened.ino()
        || opened.dev() != after.dev()
        || opened.ino() != after.ino()
    {
        return Err("existing inspection lease identity or permissions differ".into());
    }
    file.try_lock()
        .map_err(|_| "another service or operation holds the engineering lease")?;
    Ok(file)
}

/// Build a new header over a separately pinned valid native body. The original
/// terminal frame remains intact and the new nonce binds the changed header.
/// This runs only when explicitly invoked on an owner-operated machine.
pub fn generate(
    plan_path: &Path,
    plan_pin: &str,
    output: &Path,
    binding: &Path,
    binding_pin: &str,
) -> Result<Value, String> {
    let context = Context::load(binding, binding_pin)?;
    let bytes = read(plan_path, 16 * 1024)?;
    context.check_manifest_pin(&bytes, plan_pin)?;
    let p = parse_plan(&bytes)?;
    let started = Instant::now();
    let a_path = Path::new(&p.canonical.directory);
    let b_path = Path::new(&p.competing.directory);
    if [a_path, b_path]
        .into_iter()
        .any(|s| output.starts_with(s) || s.starts_with(output))
    {
        return Err("negative candidate output must be separate from both source corpora".into());
    }
    let a = History::open(&p.canonical, &context, started)?;
    let b = History::open(&p.competing, &context, started)?;
    if a.genesis != b.genesis {
        return Err("negative candidate source genesis differs".into());
    }
    let selected = Genesis::decode(&a.genesis)?;
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    let engine = Engine::new(Genesis::decode(&a.genesis)?, limits)?;
    let policy = engine.body_policy();
    a.unchanged(&p.canonical, policy, started)?;
    b.unchanged(&p.competing, policy, started)?;
    let old_headers =
        VerifiedHeaders::verify(rules(&selected), a.headers(p.receiver_height, policy)?)
            .map_err(|_| "negative candidate canonical headers rejected")?;
    let original_headers = b.headers(p.receiver_height + 1, policy)?;
    let positive = VerifiedHeaders::verify(rules(&selected), original_headers.clone())
        .map_err(|_| "negative candidate control headers rejected")?;
    let ancestor = hash(&p.ancestor_id)?;
    for h in 1..=p.ancestor_height {
        if old_headers.id(h).ok() != positive.id(h).ok() {
            return Err("negative candidate common prefix differs".into());
        }
    }
    if old_headers.id(p.ancestor_height).ok() != Some(ancestor)
        || old_headers.id(p.ancestor_height + 1).ok() == positive.id(p.ancestor_height + 1).ok()
        || positive.cumulative_work() <= old_headers.cumulative_work()
        || positive
            .work_at(p.receiver_height)
            .map_err(|_| "negative candidate prefix work unavailable")?
            > old_headers.cumulative_work()
    {
        return Err("negative candidate ancestor, divergence or work differs".into());
    }
    let terminal_height = p.receiver_height + 1;
    let (original, body) = b.read(terminal_height, policy)?;
    if body.commitment(policy)? != original.body_commitment {
        return Err("negative candidate control body binding differs".into());
    }
    let mut original_frame = original
        .encode()
        .map_err(|_| "negative candidate original header encoding")?
        .to_vec();
    body.write_to(&mut original_frame, policy)
        .map_err(|_| "negative candidate original body encoding")?;
    if b.record(terminal_height)?["frame_sha256"]
        != crate::local::hex(&Sha256::digest(&original_frame))
        || b.record(terminal_height)?["frame_bytes"] != original_frame.len()
    {
        return Err("negative candidate original frame roundtrip differs".into());
    }
    time(started, p.maximum_elapsed_seconds)?;
    partition::create_private(output)?;
    let scratch = output.join("preflight");
    partition::create_private(&scratch)?;
    super::super::super::super::private_write(&scratch.join("genesis.bin"), &a.genesis)?;
    let identity = NativeIdentity::initialize(&scratch, selected.peer_binding())
        .map_err(|_| "negative candidate preflight identity unavailable")?;
    let mut store = Store::create(
        &scratch.join("chain.redb"),
        Genesis::decode(&a.genesis)?,
        limits,
    )?;
    store.enable_authenticated_restart(identity)?;
    let verifier = NativeVerifier::for_genesis(&selected)?;
    for height in 1..=p.receiver_height {
        time(started, p.maximum_elapsed_seconds)?;
        let (header, body) = a.read(height, policy)?;
        store.append(&header, &body, &verifier)?;
    }
    let (old_tip, _) = a.read(p.receiver_height, policy)?;
    let before = observe(
        store.engine(),
        store.engine(),
        &old_tip,
        a.record(p.receiver_height)?,
    )?;
    let count = (terminal_height - p.ancestor_height) as usize;
    let budget = ReplacementBudget {
        max_blocks: count,
        max_body_bytes: p.maximum_body_bytes,
        max_elapsed: Duration::from_secs(p.maximum_elapsed_seconds),
    };
    let positive_ids: Vec<_> = (p.ancestor_height + 1..=terminal_height)
        .map(|h| {
            positive
                .id(h)
                .map_err(|_| "negative candidate control identity")
        })
        .collect::<Result<_, _>>()?;
    // The original complete replacement must pass actual native execution,
    // including the unchanged terminal proof body, before deriving a negative.
    let verified = store
        .prevalidate_replacement(
            p.ancestor_height,
            ancestor,
            &positive_ids,
            budget,
            &verifier,
            |i| {
                time(started, p.maximum_elapsed_seconds)?;
                b.read(p.ancestor_height + i as u64 + 1, policy)
            },
        )
        .map_err(|e| format!("negative candidate valid control failed: {e}"))?;
    if verified.tip() != original.id().map_err(|_| "control terminal identity")?
        || verified.cumulative_work() != positive.cumulative_work()
    {
        return Err("negative candidate control result differs".into());
    }
    drop(verified);
    let mut candidate = distinct_header(&original);
    let seed = candidate
        .pow_seed()
        .map_err(|_| "negative candidate PoW seed")?;
    let mut attempts = 0u64;
    loop {
        time(started, p.maximum_elapsed_seconds)?;
        if attempts >= p.maximum_nonce_attempts {
            return Err("negative candidate bounded nonce search exhausted".into());
        }
        attempts += 1;
        if siworld_core::pow::meets_target(
            &siworld_core::pow::pow_hash(&seed, candidate.nonce, selected.config().pow_iterations),
            &candidate.target,
        ) {
            break;
        }
        candidate.nonce = candidate
            .nonce
            .checked_add(1)
            .ok_or("negative candidate nonce exhausted")?;
    }
    let mut negative_headers = original_headers;
    *negative_headers
        .last_mut()
        .ok_or("negative candidate terminal unavailable")? = candidate.clone();
    let negative = VerifiedHeaders::verify(rules(&selected), negative_headers)
        .map_err(|_| "negative candidate complete fresh header path rejected")?;
    let candidate_id = candidate.id().map_err(|_| "negative candidate identity")?;
    if negative.cumulative_work() <= old_headers.cumulative_work()
        || candidate_id == original.id().map_err(|_| "control candidate identity")?
    {
        return Err("negative candidate distinct identity or greater work differs".into());
    }
    let mut ids = positive_ids;
    *ids.last_mut()
        .ok_or("negative candidate identities empty")? = candidate_id;
    reject_exact(
        store.prevalidate_replacement(p.ancestor_height, ancestor, &ids, budget, &verifier, |i| {
            time(started, p.maximum_elapsed_seconds)?;
            if i + 1 == count {
                Ok((candidate.clone(), body.clone()))
            } else {
                b.read(p.ancestor_height + i as u64 + 1, policy)
            }
        }),
        count - 1,
    )?;
    store.ensure_exportable()?;
    let after = observe(
        store.engine(),
        store.engine(),
        &old_tip,
        a.record(p.receiver_height)?,
    )?;
    if before != after {
        return Err("negative candidate preflight changed canonical state".into());
    }
    a.unchanged(&p.canonical, policy, started)?;
    b.unchanged(&p.competing, policy, started)?;
    time(started, p.maximum_elapsed_seconds)?;
    let mut frame = candidate
        .encode()
        .map_err(|_| "negative candidate frame header")?
        .to_vec();
    frame.extend_from_slice(&original_frame[HEADER_BYTES..]);
    let frame_sha256 = crate::local::hex(&Sha256::digest(&frame));
    super::super::super::super::private_write(&output.join("candidate.frame"), &frame)?;
    let mut branch_frames = Vec::new();
    let mut total_frame_bytes = 0u64;
    for height in p.ancestor_height + 1..terminal_height {
        let record = b.record(height)?;
        let bytes = record["frame_bytes"]
            .as_u64()
            .ok_or("negative candidate frame byte count")?;
        total_frame_bytes = total_frame_bytes
            .checked_add(bytes)
            .ok_or("negative candidate frame total overflow")?;
        branch_frames.push(json!({"path":b.directory.join(format!("block-{height:04}.frame")),"sha256":record["frame_sha256"],"bytes":bytes}));
    }
    total_frame_bytes = total_frame_bytes
        .checked_add(frame.len() as u64)
        .filter(|n| *n <= MAX_BYTES)
        .ok_or("negative candidate transmitted frame budget exceeded")?;
    branch_frames.push(
        json!({"path":output.join("candidate.frame"),"sha256":frame_sha256,"bytes":frame.len()}),
    );
    let result = json!({"schema":1,"scope":"owner-generated-invalid-execution-candidate", "qualification":context.receipt(),
        "plan_sha256":plan_pin,"canonical_manifest_sha256":p.canonical.manifest_sha256,"competing_manifest_sha256":p.competing.manifest_sha256,
        "canonical_input_audit":a.provenance,"competing_input_audit":b.provenance,
        "historical_input_executable_externally_verified":false,
        "receiver_height":p.receiver_height,"receiver_tip":before["id"],"ancestor_height":p.ancestor_height,"ancestor_id":p.ancestor_id,
        "candidate_height":terminal_height,"candidate_tip":crate::local::hex(&candidate_id),"candidate_frame":"candidate.frame","candidate_frame_sha256":frame_sha256,"candidate_frame_bytes":frame.len(),
        "branch_frames":branch_frames,"total_frame_bytes":total_frame_bytes,
        "original_terminal":b.record(terminal_height)?,"body_commitment":crate::local::hex(&candidate.body_commitment),"body_sha256":crate::local::hex(&Sha256::digest(&frame[HEADER_BYTES..])),
        "candidate_work":crate::local::hex(&negative.cumulative_work().to_big_endian()),"nonce_attempts":attempts,
        "valid_control_native_prevalidation_passed":true,"negative_prevalidation":{"variant":"Rejected","index":count-1,"reason":REASON},
        "preflight_before":before,"preflight_after":after,"eleven_preflight_components_unchanged":true,
        "source_frames_changed":false,"source_databases_opened":false,"proofs_generated":false,"input_kind":"negative_input",
        "receiver_rejection_proven":false,"receiver_unchanged_state_proven":false,"g1_passed":false,"g2_passed":false});
    super::super::super::super::private_write(
        &output.join("manifest.json"),
        &serde_json::to_vec_pretty(&result).map_err(|_| "negative candidate receipt encoding")?,
    )?;
    Ok(result)
}

/// Inspect only an exact durable branch entry under the stopped service lease.
/// Pair this with independent before/after canonical component audits.
pub fn inspect(
    directory: &Path,
    id: &str,
    binding: &Path,
    binding_pin: &str,
) -> Result<Value, String> {
    let context = Context::load(binding, binding_pin)?;
    super::super::source_path(directory)?;
    let id = hash(id)?;
    let _lease = existing_lease(directory)?;
    let selected = Genesis::decode(&read(&directory.join("genesis.bin"), 1024 * 1024)?)?;
    context.check_genesis(&selected)?;
    let engine = Engine::new(
        selected,
        Limits {
            max_leaves: 1_000_000,
            max_nullifiers: 1_000_000,
            max_component_bytes: 64 * 1024 * 1024,
        },
    )?;
    let result = branches::observation::inspect(
        &directory.join("branches.redb"),
        &rules(engine.genesis()),
        id,
        engine.body_policy(),
    )?;
    let mut receipt = json!({"schema":1,"scope":"read-only-exact-retained-branch-entry","qualification":context.receipt(),"candidate_id":crate::local::hex(&id),
        "found":false,"database_open_mode":"read-only","canonical_state_checked":false,"native_rejection_reason_recorded":false,"g1_passed":false,"g2_passed":false});
    if let Some(observed) = result {
        let header = observed.entry.header;
        receipt["found"] = json!(true);
        receipt["entry"] = json!({"height":header.height,"parent":crate::local::hex(&header.parent),
            "header_hex":crate::local::hex(&header.encode().map_err(|_| "observed branch header encoding")?),
            "execution_commitment":crate::local::hex(&header.execution_commitment),"body_commitment":crate::local::hex(&header.body_commitment),
            "cumulative_work":crate::local::hex(&observed.entry.cumulative_work.to_big_endian()),"first_seen":observed.entry.first_seen,
            "status":match observed.entry.status { Status::HeaderQualified=>"HeaderQualified",Status::BodyRetained=>"BodyRetained",Status::Executed=>"Executed",Status::Invalid=>"Invalid" },
            "body_bytes":observed.body_bytes,"body_sha256":observed.body_sha256.map(|v| crate::local::hex(&v))});
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Value {
        json!({"version":1,
            "canonical":{"directory":"/canonical","manifest_sha256":"01".repeat(32),"height":26,"budget":"/canonical-budget","budget_sha256":"05".repeat(32),"audit_binding":"/canonical-binding","audit_binding_sha256":"06".repeat(32)},
            "competing":{"directory":"/competing","manifest_sha256":"02".repeat(32),"height":27,"budget":"/competing-budget","budget_sha256":"07".repeat(32),"audit_binding":"/competing-binding","audit_binding_sha256":"08".repeat(32)},
            "receiver_height":8,"ancestor_height":1,"ancestor_id":"03".repeat(32),
            "maximum_nonce_attempts":100,"maximum_elapsed_seconds":120,"maximum_body_bytes":1048576})
    }

    #[test]
    fn negative_candidate_preserves_historical_source_without_changing_protocol() {
        let mut value = json!({"version":1,"network_id":"01".repeat(32),"genesis_id":"02".repeat(32),"rules_commitment":"03".repeat(32),"proof_profile":"04".repeat(32),"source_commit":"05".repeat(20),"binary_sha256":"06".repeat(32)});
        let helper = Context {
            binding: super::super::super::parse(&serde_json::to_vec(&value).unwrap()).unwrap(),
            binding_sha256: "07".repeat(32),
        };
        value["source_commit"] = json!("08".repeat(20));
        value["binary_sha256"] = json!("09".repeat(32));
        let bytes = serde_json::to_vec(&value).unwrap();
        let pin = crate::local::hex(&Sha256::digest(&bytes));
        let original = input_context(&bytes, &pin, &helper).unwrap();
        assert_eq!(original.receipt()["source_commit"], value["source_commit"]);
        assert_eq!(original.receipt()["binary_sha256"], value["binary_sha256"]);
        assert_ne!(
            original.receipt()["source_commit"],
            helper.receipt()["source_commit"]
        );
        assert!(input_context(&bytes, &"10".repeat(32), &helper).is_err());
        for field in [
            "network_id",
            "genesis_id",
            "rules_commitment",
            "proof_profile",
        ] {
            let mut changed = value.clone();
            changed[field] = json!("11".repeat(32));
            let bytes = serde_json::to_vec(&changed).unwrap();
            let pin = crate::local::hex(&Sha256::digest(&bytes));
            assert!(input_context(&bytes, &pin, &helper).is_err(), "{field}");
        }
    }

    #[test]
    fn negative_candidate_plan_bounds_exact_work_and_rejects_unknown_fields() {
        assert!(parse_plan(&serde_json::to_vec(&plan()).unwrap()).is_ok());
        for (field, value) in [
            ("maximum_nonce_attempts", json!(0)),
            ("maximum_nonce_attempts", json!(1_000_001)),
            ("maximum_elapsed_seconds", json!(901)),
            ("maximum_body_bytes", json!(0)),
            ("ancestor_height", json!(0)),
            ("receiver_height", json!(26)),
            ("source_commit_override", json!("04".repeat(20))),
        ] {
            let mut p = plan();
            p[field] = value;
            assert!(
                parse_plan(&serde_json::to_vec(&p).unwrap()).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn negative_candidate_header_has_new_identity_and_preserves_source() {
        let original = Header {
            network: [1; 32],
            height: 9,
            parent: [2; 32],
            timestamp: 2701,
            target: [255; 32],
            execution_commitment: [3; 32],
            body_commitment: [4; 32],
            nonce: 17,
        };
        let original_bytes = original.encode().unwrap();
        let changed = distinct_header(&original);
        assert_eq!(original.encode().unwrap(), original_bytes);
        assert_ne!(original.id().unwrap(), changed.id().unwrap());
        assert_ne!(original.pow_seed().unwrap(), changed.pow_seed().unwrap());
        assert_ne!(original.execution_commitment, changed.execution_commitment);
        assert_eq!(changed.body_commitment, original.body_commitment);
        assert_eq!(changed.parent, original.parent);
        assert_eq!(changed.height, original.height);
        assert_eq!(changed.target, original.target);
        assert_eq!(changed.timestamp, original.timestamp);
        assert_eq!(changed.nonce, 0);
    }

    #[test]
    fn negative_candidate_requires_the_exact_native_rejected_edge() {
        assert!(
            reject_exact(
                Err(ReplacementFailure::Rejected {
                    index: 2,
                    reason: REASON.into()
                }),
                2
            )
            .is_ok()
        );
        assert!(reject_exact(Err(ReplacementFailure::Deferred(REASON.into())), 2).is_err());
        assert!(
            reject_exact(
                Err(ReplacementFailure::Rejected {
                    index: 1,
                    reason: REASON.into()
                }),
                2
            )
            .is_err()
        );
        assert!(
            reject_exact(
                Err(ReplacementFailure::Rejected {
                    index: 2,
                    reason: "native transaction proof verification failed".into()
                }),
                2
            )
            .is_err()
        );
    }

    #[test]
    fn negative_candidate_inspection_never_creates_or_changes_the_service_lease() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let fixture = crate::eng2::branches::tests::Fixture::new();
        std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = fixture.0.join(crate::service::LEASE_FILE);
        assert!(existing_lease(&fixture.0).is_err());
        assert!(!path.exists());
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let first = existing_lease(&fixture.0).unwrap();
        assert!(existing_lease(&fixture.0).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), Vec::<u8>::new());
        drop(first);
        drop(existing_lease(&fixture.0).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), Vec::<u8>::new());
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(fixture.0.join("missing-target"), &path).unwrap();
        assert!(existing_lease(&fixture.0).is_err());
        assert!(!fixture.0.join("missing-target").exists());
    }
}
