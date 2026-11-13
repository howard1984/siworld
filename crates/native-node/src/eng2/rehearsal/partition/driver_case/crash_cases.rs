//! Explicit ignored entrypoints for one owned full-frame kill and its recovery.
use super::*;
use std::path::PathBuf;

struct Input {
    source_a: PathBuf,
    pin_a: String,
    source_b: PathBuf,
    pin_b: String,
    directory: PathBuf,
    depth: u64,
    point: String,
    height: u64,
    marker: PathBuf,
    binary: String,
}
fn value(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("explicit full-frame test parameter required: {name}"))
}
impl Input {
    fn load() -> Result<Self, String> {
        owner_local()?;
        let input = Self {
            source_a: value("SIWORLD_FULL_FRAME_SOURCE_A")?.into(),
            pin_a: value("SIWORLD_FULL_FRAME_MANIFEST_A_SHA256")?,
            source_b: value("SIWORLD_FULL_FRAME_SOURCE_B")?.into(),
            pin_b: value("SIWORLD_FULL_FRAME_MANIFEST_B_SHA256")?,
            directory: value("SIWORLD_FULL_FRAME_DIRECTORY")?.into(),
            depth: value("SIWORLD_FULL_FRAME_DEPTH")?
                .parse()
                .map_err(|_| "invalid full-frame depth")?,
            point: value("SIWORLD_REORG_CRASH_POINT")?,
            height: value("SIWORLD_REORG_CRASH_HEIGHT")?
                .parse()
                .map_err(|_| "invalid crash height")?,
            marker: value("SIWORLD_REORG_CRASH_MARKER")?.into(),
            binary: value("SIWORLD_FULL_FRAME_BINARY_SHA256")?,
        };
        if ![1, 6, 7, 23, 24].contains(&input.depth)
            || crate::local::hex(&crate::eng2::genesis_tool::executable_sha256()?) != input.binary
            || !input.marker.is_absolute()
            || input
                .marker
                .parent()
                .and_then(|p| p.canonicalize().ok())
                .as_deref()
                != input.marker.parent()
            || input.marker.starts_with(&input.directory)
            || input.marker.starts_with(&input.source_a)
            || input.marker.starts_with(&input.source_b)
        {
            return Err(
                "explicit binary, canonical sibling marker and supported crash depth required"
                    .into(),
            );
        }
        input.expected_prefix()?;
        Ok(input)
    }
    fn expected_prefix(&self) -> Result<(bool, u64), String> {
        let after = ["after_commit", "after_publish", "after_capture"];
        if self.height == 1 {
            if self.point == "restore_before_commit" {
                return Ok((true, self.depth + 1));
            }
            if after
                .iter()
                .any(|suffix| self.point == format!("restore_{suffix}"))
            {
                return Ok((false, 1));
            }
        }
        if (2..=self.depth + 2).contains(&self.height) {
            if self.point == "append_before_commit" {
                return Ok((false, self.height - 1));
            }
            if after
                .iter()
                .any(|suffix| self.point == format!("append_{suffix}"))
            {
                return Ok((false, self.height));
            }
        }
        Err("named crash boundary does not select a replacement commit edge".into())
    }
    fn binding(&self) -> Value {
        json!({"schema":1,"scope":"owner-full-frame-named-crash",
            "source_a":self.source_a,"manifest_a_sha256":self.pin_a,
            "source_b":self.source_b,"manifest_b_sha256":self.pin_b,
            "directory":self.directory,"depth":self.depth,"point":self.point,
            "height":self.height,"marker":self.marker,"binary_sha256":self.binary})
    }
    fn binding_path(&self) -> PathBuf {
        self.marker.with_extension("child-binding.json")
    }
}

#[test]
#[ignore = "explicit owner-local complete corpus, absent case and externally owned SIGKILL"]
fn full_frame_driver_crash_child() {
    run_crash_child().unwrap();
    panic!("full-frame child completed without reaching its named SIGKILL boundary");
}
fn run_crash_child() -> Result<(), String> {
    let input = Input::load()?;
    if value("SIWORLD_REORG_CRASH_CHILD")? != "1"
        || value("SIWORLD_REORG_CRASH_FULL_FRAME")? != "1"
        || input.directory.exists()
        || input.marker.exists()
    {
        return Err("new explicitly armed full-frame child and absent case/marker required".into());
    }
    private_write(
        &input.binding_path(),
        &serde_json::to_vec_pretty(&input.binding())
            .map_err(|_| "full-frame child binding encoding failed")?,
    )?;
    let _ = driver_case(
        &input.source_a,
        &input.pin_a,
        &input.source_b,
        &input.pin_b,
        &input.directory,
        input.depth,
    )?;
    Ok(())
}

fn advance_reference(
    reference: &mut Engine,
    corpus: &Corpus,
    height: u64,
    verifier: &NativeVerifier,
) -> Result<(), String> {
    if reference.state().height() > height {
        return Err("native recovery reference moved backwards".into());
    }
    for h in reference.state().height() + 1..=height {
        let (header, body) = corpus.read(h, reference.body_policy())?;
        reference.apply(&header, &body, verifier)?;
        // Validate the independently executed oracle at every prefix as well.
        let _ = observe(reference, reference, &header, corpus.record(h)?)?;
    }
    Ok(())
}
fn observe_store(
    store: &Store,
    reference: &Engine,
    corpus: &Corpus,
    headers: &VerifiedHeaders,
    height: u64,
    output: &Path,
    name: &str,
) -> Result<(), String> {
    store.ensure_exportable()?;
    if store.engine().state().height() != height {
        return Err("authenticated recovery height differs".into());
    }
    for h in 1..=height {
        let expected = headers
            .header(h)
            .ok_or("qualified recovery header missing")?;
        if store
            .header(h)?
            .encode()
            .map_err(|_| "actual recovery header encoding rejected")?
            != expected
                .encode()
                .map_err(|_| "qualified recovery header encoding rejected")?
        {
            return Err("authenticated recovery full header prefix differs".into());
        }
    }
    save_observation(
        output,
        name,
        store.engine(),
        reference,
        headers
            .header(height)
            .ok_or("recovery tip header missing")?,
        corpus.record(height)?,
    )
}

#[test]
#[ignore = "explicit owner-local killed full-frame case; authenticates and resumes only that case"]
fn full_frame_driver_resume() {
    resume_case().unwrap();
}
fn resume_case() -> Result<(), String> {
    let input = Input::load()?;
    if std::env::var("SIWORLD_REORG_CRASH_CHILD").as_deref() == Ok("1") {
        return Err("recovery must not inherit an armed crash-child environment".into());
    }
    if input.directory.canonicalize().ok().as_deref() != Some(input.directory.as_path())
        || input.directory.starts_with(&input.source_a)
        || input.directory.starts_with(&input.source_b)
        || input.source_a.starts_with(&input.directory)
        || input.source_b.starts_with(&input.directory)
        || input.directory.join("case-complete.json").exists()
    {
        return Err("separate existing incomplete owned full-frame case required".into());
    }
    let binding: Value = serde_json::from_slice(&bounded_bytes(&input.binding_path(), 32 * 1024)?)
        .map_err(|_| "full-frame child binding unavailable")?;
    if binding != input.binding()
        || bounded_bytes(&input.marker, 4096)?
            != format!("{}:{}\n", input.point, input.height).as_bytes()
    {
        return Err("exact full-frame child and named marker binding required".into());
    }
    let a = Corpus::open(&input.source_a, &input.pin_a, 26)?;
    let b = Corpus::open(&input.source_b, &input.pin_b, 27)?;
    if a.genesis != b.genesis
        || a.record(1)? != b.record(1)?
        || a.record(2)?["id"] == b.record(2)?["id"]
        || bounded_bytes(&input.directory.join("genesis.bin"), 1024 * 1024)? != a.genesis
    {
        return Err("recovery corpora or case genesis differ".into());
    }
    let start: Value = serde_json::from_slice(&bounded_bytes(
        &input.directory.join("case-start.json"),
        32 * 1024,
    )?)
    .map_err(|_| "case start receipt unavailable")?;
    if start["manifest_a_sha256"] != input.pin_a
        || start["manifest_b_sha256"] != input.pin_b
        || start["binary_sha256"] != input.binary
        || start["depth"] != input.depth
        || start["old_height"] != input.depth + 1
        || start["replacement_height"] != input.depth + 2
        || start["production_ceiling"] != 0
    {
        return Err("case start receipt does not bind this full-frame invocation".into());
    }
    let selected = Genesis::decode(&a.genesis)?;
    if production_ceiling(&input.directory, &selected)? != Some(0) {
        return Err("crash case production ceiling must remain zero".into());
    }
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
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
    let mut reference_b = Engine::new(Genesis::decode(&b.genesis)?, limits)?;
    let policy = reference_b.body_policy();
    a.unchanged(policy)?;
    b.unchanged(policy)?;
    let headers_a = VerifiedHeaders::verify(rules.clone(), a.headers(input.depth + 1, policy)?)
        .map_err(|_| "recovery A header path rejected")?;
    let headers_b = VerifiedHeaders::verify(rules.clone(), b.headers(input.depth + 2, policy)?)
        .map_err(|_| "recovery B header path rejected")?;
    if headers_b.cumulative_work() <= headers_a.cumulative_work() {
        return Err("recovery B Work512 must exceed A".into());
    }
    let _lease = crate::service::Lease::acquire(&input.directory)?;
    let output = input.directory.join("recovery-observations");
    create_private(&output)?;
    let started = Instant::now();
    let path = input.directory.join("chain.redb");
    let store = Store::resume_existing(&path, Genesis::decode(&a.genesis)?, limits)?;
    let verifier = NativeVerifier::new()?;
    let (old_branch, expected_height) = input.expected_prefix()?;
    if old_branch {
        let mut reference_a = Engine::new(Genesis::decode(&a.genesis)?, limits)?;
        advance_reference(&mut reference_a, &a, expected_height, &verifier)?;
        observe_store(
            &store,
            &reference_a,
            &a,
            &headers_a,
            expected_height,
            &output,
            "initial-authenticated-A",
        )?;
    } else {
        advance_reference(&mut reference_b, &b, expected_height, &verifier)?;
        observe_store(
            &store,
            &reference_b,
            &b,
            &headers_b,
            expected_height,
            &output,
            "initial-authenticated-B",
        )?;
    }
    // Observe the exact committed crash prefix before rebuilding any owner/archive.
    let mut driver = Driver::new(
        store,
        NativeVerifier::new()?,
        ImportLimits {
            chain: limits,
            max_snapshot_bytes: 256 * 1024 * 1024,
        },
    )?;
    driver.enable_reorganization(BranchStore::open(
        &input.directory.join("branches.redb"),
        rules,
        branches::Limits {
            maximum_headers: 256,
            maximum_body_bytes: 1024 * 1024 * 1024,
        },
    )?)?;
    let target_height = input.depth + 2;
    let target = headers_b
        .id(target_height)
        .map_err(|_| "recovery target header missing")?;
    for turn in 0..=target_height + 1 {
        check_time(started)?;
        if driver.engine().state().tip() == target && driver.activities_allowed() {
            break;
        }
        driver.reorganization_tick(|_| Ok(()))?;
        let height = driver.engine().state().height();
        if height == 0
            || height > target_height
            || driver.engine().state().tip()
                != headers_b
                    .id(height)
                    .map_err(|_| "recovery prefix missing")?
        {
            return Err("ordinary recovery did not produce the retained B prefix".into());
        }
        advance_reference(&mut reference_b, &b, height, &verifier)?;
        observe_store(
            driver.store(),
            &reference_b,
            &b,
            &headers_b,
            height,
            &output,
            &format!("turn-{turn:04}-B-{height:04}"),
        )?;
    }
    if driver.engine().state().tip() != target
        || !driver.activities_allowed()
        || driver.reorganization_status() != "ready"
    {
        return Err("ordinary retained-best recovery did not finish within the turn bound".into());
    }
    advance_reference(&mut reference_b, &b, target_height, &verifier)?;
    drop(driver);
    let reopened = Store::resume_existing(&path, Genesis::decode(&b.genesis)?, limits)?;
    observe_store(
        &reopened,
        &reference_b,
        &b,
        &headers_b,
        target_height,
        &output,
        "final-authenticated-B",
    )?;
    drop(reopened);
    a.unchanged(policy)?;
    b.unchanged(policy)?;
    check_time(started)?;
    private_write(
        &output.join("recovery-complete.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema":1,"binding":input.binding(),"expected_initial_old_branch":old_branch,
            "expected_initial_height":expected_height,"final_height":target_height,
            "actual_eleven_component_bytes_equal_native_oracle":true,
            "full_header_prefix_equal":true,"initial_and_final_authenticated_reopen":true,
            "ordinary_retained_best_driver_recovery":true,"source_frames_unchanged":true,
            "proofs_generated":false,"mining_started":false,"g1_passed":false,"g2_passed":false
        }))
        .map_err(|_| "full-frame recovery receipt encoding failed")?,
    )?;
    Ok(())
}
