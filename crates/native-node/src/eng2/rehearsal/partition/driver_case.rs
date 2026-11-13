//! Owner-only normal Driver switching of unchanged complete native frames.
use super::*;
use super::{actual_state::observe, corpus::Corpus};
use crate::eng2::{
    branches::{self, BranchStore},
    driver::Driver,
    header::Header,
    selection::{HeaderRules, VerifiedHeaders},
    snapshot::ImportLimits,
};
use std::cell::Cell;

fn check_time(start: Instant) -> Result<(), String> {
    if start.elapsed().as_secs() >= 900 {
        return Err("owner Driver case deadline exceeded".into());
    }
    Ok(())
}
fn save_observation(
    directory: &Path,
    name: &str,
    actual: &Engine,
    reference: &Engine,
    header: &Header,
    record: &Value,
) -> Result<(), String> {
    private_write(
        &directory.join(format!("{name}.json")),
        &serde_json::to_vec_pretty(&observe(actual, reference, header, record)?)
            .map_err(|_| "actual state observation encoding failed")?,
    )
}

/// A manifest pin must come from completed independent corpus acceptance.
/// This command never starts a resident, creates a proof, or alters a source.
pub fn driver_case(
    source_a: &Path,
    pin_a: &str,
    source_b: &Path,
    pin_b: &str,
    directory: &Path,
    depth: u64,
) -> Result<Value, String> {
    owner_local()?;
    if ![1, 6, 7, 23, 24, 25].contains(&depth)
        || source_a == source_b
        || directory.starts_with(source_a)
        || directory.starts_with(source_b)
        || source_a.starts_with(directory)
        || source_b.starts_with(directory)
    {
        return Err("separate public corpora, fresh destination and exact depth required".into());
    }
    let started = Instant::now();
    let a = Corpus::open(source_a, pin_a, 26)?;
    let b = Corpus::open(source_b, pin_b, 27)?;
    if a.genesis != b.genesis
        || a.record(1)? != b.record(1)?
        || a.record(2)?["id"] == b.record(2)?["id"]
    {
        return Err("audited corpora must share H1 and diverge at H2".into());
    }
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    let mut reference = Engine::new(Genesis::decode(&a.genesis)?, limits)?;
    let policy = reference.body_policy();
    a.unchanged(policy)?;
    b.unchanged(policy)?;
    let selected = reference.genesis();
    let config = selected.config();
    let rules = HeaderRules {
        network: config.network,
        genesis: selected.id(),
        genesis_timestamp: config.genesis_timestamp,
        genesis_target: config.genesis_target,
        target_interval: config.target_interval,
        pow_iterations: config.pow_iterations,
        max_headers: 96,
    };
    let old_height = depth + 1;
    let new_height = depth + 2;
    let old_headers = VerifiedHeaders::verify(rules.clone(), a.headers(old_height, policy)?)
        .map_err(|_| "old complete native header prefix rejected")?;
    let new_headers = VerifiedHeaders::verify(rules.clone(), b.headers(new_height, policy)?)
        .map_err(|_| "replacement complete native header prefix rejected")?;
    if new_headers.cumulative_work() <= old_headers.cumulative_work() {
        return Err("replacement must have independently verified greater Work512".into());
    }
    check_time(started)?;
    // No private campaign seed, wallet, old database or identity is copied.
    create_private(directory)?;
    let _lease = crate::service::Lease::acquire(directory)?;
    private_write(&directory.join("genesis.bin"), &a.genesis)?;
    let marker = ceiling_value(reference.genesis(), 0)?;
    private_write(
        &directory.join(MARKER),
        &serde_json::to_vec(&marker).map_err(|_| "paused production marker encoding failed")?,
    )?;
    let observations = directory.join("observations");
    create_private(&observations)?;
    private_write(
        &directory.join("case-start.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema":1,"depth":depth,"old_height":old_height,"replacement_height":new_height,
            "manifest_a_sha256":pin_a,"manifest_b_sha256":pin_b,
            "binary_sha256":crate::local::hex(&crate::eng2::genesis_tool::executable_sha256()?),
            "genesis_id":crate::local::hex(&reference.genesis().id()),
            "proof_profile":crate::local::hex(&crate::proofs::protocol_profile_fingerprint()),
            "production_ceiling":0,"nodes_started":false,"proofs_generated":false
        }))
        .map_err(|_| "Driver case start receipt encoding failed")?,
    )?;
    let identity =
        crate::identity::NativeIdentity::initialize(directory, reference.genesis().peer_binding())
            .map_err(|_| "fresh case identity creation failed")?;
    let path = directory.join("chain.redb");
    let mut store = Store::create(&path, Genesis::decode(&a.genesis)?, limits)?;
    store.enable_authenticated_restart(identity)?;
    let mut driver = Driver::new(
        store,
        NativeVerifier::new()?,
        ImportLimits {
            chain: limits,
            max_snapshot_bytes: 256 * 1024 * 1024,
        },
    )?;
    driver.enable_reorganization(BranchStore::create(
        &directory.join("branches.redb"),
        rules,
        branches::Limits {
            maximum_headers: 256,
            maximum_body_bytes: 2 * 1024 * 1024 * 1024,
        },
    )?)?;
    let verifier = NativeVerifier::new()?;
    // A is admitted through the ordinary canonical path, never a restored DB copy.
    for h in 1..=old_height {
        check_time(started)?;
        let (header, body) = a.read(h, policy)?;
        reference.apply(&header, &body, &verifier)?;
        driver.accept(&header, &body)?;
        driver.store().ensure_exportable()?;
        save_observation(
            &observations,
            &format!("a-{h:04}"),
            driver.engine(),
            &reference,
            &header,
            a.record(h)?,
        )?;
    }
    let old_tip = driver.engine().state().tip();
    let generation = driver.template_generation();
    driver.retain_competing_headers(&new_headers)?;
    for h in 2..=new_height {
        check_time(started)?;
        let (header, body) = b.read(h, policy)?;
        driver.retain_competing_body(&header, &body)?;
    }
    #[cfg(all(test, unix, feature = "eng2-rehearsal"))]
    crate::eng2::store::arm_full_frame_crash_boundary();
    let barrier_calls = Cell::new(0);
    let switched = driver.reorganization_tick(|height| {
        if height != 1 {
            return Err("Driver selected a different ancestor".into());
        }
        barrier_calls.set(barrier_calls.get() + 1);
        Ok(())
    });
    if depth == 25 {
        if switched.is_ok()
            || barrier_calls.get() != 0
            || driver.activities_allowed()
            || driver.template_generation() != generation
            || driver.reorganization_status() != "manual_recovery_required"
            || driver.reorganization_alarm() != Some("reorganization_depth_exceeds_twenty_four")
        {
            return Err(
                "depth25 did not refuse before restore with owner activities paused".into(),
            );
        }
        let (header, _) = a.read(old_height, policy)?;
        driver.store().ensure_exportable()?;
        save_observation(
            &observations,
            "depth25-refused",
            driver.engine(),
            &reference,
            &header,
            a.record(old_height)?,
        )?;
    } else {
        switched?;
        if barrier_calls.get() != 1
            || driver.activities_allowed()
            || driver.template_generation() != generation + 1
            || driver.reorganization_status() != "applying_validated_branch"
        {
            return Err("Driver restore or owner activity barrier differs".into());
        }
        reference = Engine::new(Genesis::decode(&b.genesis)?, limits)?;
        let (header, body) = b.read(1, policy)?;
        reference.apply(&header, &body, &verifier)?;
        driver.store().ensure_exportable()?;
        save_observation(
            &observations,
            "b-0001-restored",
            driver.engine(),
            &reference,
            &header,
            b.record(1)?,
        )?;
        for h in 2..=new_height {
            check_time(started)?;
            if driver.activities_allowed() {
                return Err("owner activities resumed before final append".into());
            }
            driver.reorganization_tick(|_| Err("restore barrier repeated during append".into()))?;
            let (header, body) = b.read(h, policy)?;
            reference.apply(&header, &body, &verifier)?;
            driver.store().ensure_exportable()?;
            save_observation(
                &observations,
                &format!("b-{h:04}-appended"),
                driver.engine(),
                &reference,
                &header,
                b.record(h)?,
            )?;
        }
        let event = driver
            .last_reorganization()
            .ok_or("completed switch event missing")?;
        let alarm = if depth > 6 {
            Some("reorganization_depth_exceeds_six")
        } else {
            None
        };
        if !driver.activities_allowed()
            || driver.reorganization_status() != "ready"
            || driver.reorganization_alarm() != alarm
            || event.depth as u64 != depth
            || event.ancestor_height != 1
            || event.old_tip != old_tip
            || event.new_tip != reference.state().tip()
        {
            return Err("completed Driver switch event, pause state or alarm differs".into());
        }
    }
    // A real authenticated reopen, after releasing the only mutable DB owner.
    drop(driver);
    let reopened = Store::resume_existing(&path, Genesis::decode(&a.genesis)?, limits)?;
    let (corpus, height) = if depth == 25 {
        (&a, old_height)
    } else {
        (&b, new_height)
    };
    let (header, _) = corpus.read(height, policy)?;
    reopened.ensure_exportable()?;
    save_observation(
        &observations,
        "final-authenticated-reopen",
        reopened.engine(),
        &reference,
        &header,
        corpus.record(height)?,
    )?;
    drop(reopened);
    a.unchanged(policy)?;
    b.unchanged(policy)?;
    check_time(started)?;
    let receipt = json!({"schema":1,"scope":"owner-native-full-frame-driver-case",
        "depth":depth,"old_height":old_height,"replacement_height":new_height,
        "common_ancestor":1,"normal_switch_completed":depth <= 24,"depth25_refused":depth == 25,
        "actual_state_observed_after_every_restore_and_append":depth <= 24,
        "actual_eleven_component_bytes_equal_native_reference":true,
        "pinned_audit_oracle_matched":true,"final_authenticated_reopen":true,
        "replacement_native_execution_checked":depth <= 24,
        "intermediate_authenticated_reopen":false,"source_frames_unchanged":true,
        "proofs_generated":false,"mining_started":false,"peer_heal_tested":false,
        "crash_tested":false,"wallet_scanned":false,"checkpoint_authority_tested":false,
        "g1_passed":false,"g2_passed":false,"elapsed_ms":started.elapsed().as_millis().to_string()});
    private_write(
        &directory.join("case-complete.json"),
        &serde_json::to_vec_pretty(&receipt).map_err(|_| "Driver case receipt encoding failed")?,
    )?;
    Ok(receipt)
}

#[cfg(all(test, unix, feature = "eng2-rehearsal"))]
mod crash_cases;
