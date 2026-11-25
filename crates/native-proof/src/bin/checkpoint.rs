//! Isolated D8/W24 resident-process checkpoint. Synthetic fixtures only.
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use p3_air::BaseAir;
use p3_circuit_prover::TablePacking;
use p3_field::{Field, PackedValue};
use p3_recursion::{
    ProveNextLayerParams,
    artifact::{ArtifactLimits, PortableArtifactExport},
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use siworld_native_proof::{
    FriParams, SlotProver,
    agg::{
        AccAggregation, Child, Input, MinerNote, anchor_leaf, compose_acc,
        fanin::EightLeafAggregation, node_digest, root_statement,
    },
    common::{F, FEE_BASE, MINER_SHARE, Rng, acc_witnesses, sample_slot},
    security,
};

const SUITE: &str = "KoalaBear-D8-Poseidon2-W24-digest12";

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn read(path: &Path) -> Result<Value, String> {
    serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
fn output(value: Value) {
    println!("{value}");
    std::io::stdout().flush().expect("flush phase evidence");
}
#[cfg(target_os = "linux")]
fn monotonic_ns() -> u64 {
    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: i32, time: *mut Timespec) -> i32;
    }
    let mut time = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    assert_eq!(unsafe { clock_gettime(1, &mut time) }, 0);
    u64::try_from(time.seconds).unwrap() * 1_000_000_000 + u64::try_from(time.nanoseconds).unwrap()
}
#[cfg(not(target_os = "linux"))]
fn monotonic_ns() -> u64 {
    panic!("checkpoint requires Linux CLOCK_MONOTONIC")
}

fn memory() -> u64 {
    let membership = std::fs::read_to_string("/proc/self/cgroup").expect("cgroup membership");
    let path = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("unified cgroup");
    std::fs::read_to_string(
        Path::new("/sys/fs/cgroup")
            .join(path.trim_start_matches('/'))
            .join("memory.current"),
    )
    .expect("owned memory.current")
    .trim()
    .parse()
    .expect("memory bytes")
}
fn measured<T>(name: &str, phases: &mut Vec<Value>, run: impl FnOnce() -> T) -> T {
    let first = monotonic_ns();
    let before = memory();
    output(
        json!({"event":"d8_phase_start", "phase":name, "start_ns":first, "memory_start":before}),
    );
    let result = run();
    let last = monotonic_ns();
    let after = memory();
    let row = json!({"phase":name, "start_ns":first, "end_ns":last, "memory_start":before, "memory_end":after, "wall_ns":last-first});
    output(json!({"event":"d8_phase_end", "measurement":row}));
    phases.push(row);
    result
}
fn bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    postcard::to_allocvec(value).map_err(|e| e.to_string())
}
fn freeze(directory: &Path, name: &str, data: &[u8]) -> Result<Value, String> {
    let path = directory.join(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    file.write_all(data)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(json!({"path":name,"sha256":sha(data)}))
}
fn save_json(directory: &Path, name: &str, data: &Value) -> Result<Value, String> {
    freeze(
        directory,
        name,
        &serde_json::to_vec_pretty(data).map_err(|e| e.to_string())?,
    )
}
fn params(value: &Value) -> Result<FriParams, String> {
    let n = |key| {
        value[key]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| format!("invalid parameter {key}"))
    };
    Ok(FriParams {
        log_blowup: n("log_blowup")?,
        num_queries: n("queries")?,
        query_pow_bits: n("query_grinding")?,
        commit_pow_bits: n("commit_grinding")?,
        batch_pow_bits: n("batch_grinding")?,
        max_log_arity: n("max_log_arity")?,
    })
}
fn fold(rows: &[Vec<F>]) -> Vec<F> {
    rows[1..]
        .iter()
        .fold(rows[0].clone(), |a, b| compose_acc(&a, b))
}
fn geometry(value: &Value, leaf: bool) -> Value {
    let r = &value["report"];
    let tables = if leaf {
        vec![
            json!({"height":value["base_trace_rows"],"main_columns":value["main_width"],"preprocessed_columns":value["preprocessed_width"]}),
        ]
    } else {
        value["tables"].as_array().expect("tables").iter().map(|t|json!({"height":t["base_trace_rows"],"main_columns":t["main_width"],"preprocessed_columns":t["preprocessed_width"]})).collect()
    };
    json!({"status":"actual-extracted","tables":tables,"constraints":r["shape"]["num_constraints"],"max_degree":r["shape"]["max_constraint_degree"],"quotient_chunks":r["shape"]["num_quotient_chunks"],"batched_openings":r["shape"]["num_batched_functions"],"lookup_dimensions":[r["shape"]["lookup_denominators_per_row"],r["shape"]["max_lookup_message_width"]]})
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let mut values = BTreeMap::new();
    while let Some(key) = arguments.next() {
        values.insert(key, arguments.next().ok_or("missing argument")?);
    }
    let bootstrap_path = PathBuf::from(
        values
            .get("--checkpoint-bootstrap")
            .ok_or("missing bootstrap")?,
    );
    let expected_sha = values
        .get("--checkpoint-bootstrap-sha256")
        .ok_or("missing bootstrap checksum")?;
    let control = PathBuf::from(
        values
            .get("--checkpoint-control-dir")
            .ok_or("missing control directory")?,
    );
    let bootstrap_bytes = std::fs::read(&bootstrap_path).map_err(|e| e.to_string())?;
    if sha(&bootstrap_bytes) != *expected_sha {
        return Err("bootstrap checksum mismatch".into());
    }
    let mut manifest: Value =
        serde_json::from_slice(&bootstrap_bytes).map_err(|e| e.to_string())?;
    let directory = bootstrap_path.parent().ok_or("bootstrap parent")?;
    if manifest["suite"] != SUITE {
        return Err("D8/W24/digest12 required".into());
    }
    let entry = &manifest["files"]["leaf_input_fixture"];
    let relative = entry["path"].as_str().ok_or("fixture path missing")?;
    if Path::new(relative).is_absolute()
        || Path::new(relative)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("fixture path must stay in bundle".into());
    }
    let fixture = std::fs::read(directory.join(relative)).map_err(|e| e.to_string())?;
    if Some(sha(&fixture).as_str()) != entry["sha256"].as_str() {
        return Err("fixture checksum mismatch".into());
    }
    let fixture: Value = serde_json::from_slice(&fixture).map_err(|e| e.to_string())?;
    if fixture
        != json!({"generator":"siworld-d8-synthetic-v1","first_seed":100,"slots":16,"anchor_height":1000,"base_fee":678904,"anchor_rng_seed":21,"dummy":false})
    {
        return Err("unsupported synthetic fixture descriptor".into());
    }
    let leaf_fri = params(&manifest["parameters"]["leaf"])?;
    let merge_fri = params(&manifest["parameters"]["merge8"])?;
    let root_fri = params(&manifest["parameters"]["root"])?;
    let execution =
        json!({"slots":16,"jobs":1,"native_workers":2,"rayon_threads":2,"hiding_workers":2});
    let runtime = json!({"packing_width":<<F as Field>::Packing as PackedValue>::WIDTH,"compiled_avx2":cfg!(target_feature="avx2"),"compiled_avx512f":cfg!(target_feature="avx512f"),"global_rayon_threads":p3_maybe_rayon::prelude::current_num_threads(),"rayon_num_threads":std::env::var("RAYON_NUM_THREADS").ok(),"composition_hiding_workers":std::env::var("SIWORLD_COMPOSITION_HIDING_WORKERS").ok()});
    if runtime["compiled_avx2"] != true
        || runtime["packing_width"] != 8
        || runtime["global_rayon_threads"] != 2
        || std::env::var("SIWORLD_COMPOSITION_HIDING_WORKERS").as_deref() != Ok("2")
    {
        return Err("fixed v3/two-worker checkpoint configuration required".into());
    }
    let mut setup = Vec::new();
    let first = monotonic_ns();
    let first_memory = memory();
    let prover = measured("prepare_leaf", &mut setup, || {
        Arc::new(SlotProver::new_acc(leaf_fri))
    });
    let slots = (0..16).map(|i| sample_slot(100 + i, false)).collect();
    let (witnesses, _) = acc_witnesses(slots, 1000, FEE_BASE, 21);
    let sample = measured("bootstrap_leaf", &mut setup, || {
        prover.prove_acc(&witnesses[0])
    });
    prover.verify(&sample.0, &sample.1)?;
    let input = Input::Uni(&sample.0, &sample.1, &witnesses[0].anchor_path);
    let layer = ProveNextLayerParams {
        table_packing: TablePacking::new(4, 4)
            .with_min_trace_height((4 * (16 + merge_fri.num_queries as usize)).next_power_of_two()),
        ..Default::default()
    };
    let batch = measured("prepare_merge8", &mut setup, || {
        EightLeafAggregation::new(prover.clone(), input, &merge_fri.config(), &layer)
    })?;
    let sample_full = anchor_leaf(&sample.1, &witnesses[0].anchor_path);
    let sample_statement = fold(&vec![sample_full; 8]);
    let sample_merge = measured("bootstrap_merge8", &mut setup, || batch.prove(&[input; 8]))?;
    let verifier = batch.verifier();
    verifier
        .verify(&sample_merge, &node_digest(&sample_statement))
        .map_err(|e| format!("{e:?}"))?;
    let root = measured("prepare_root", &mut setup, || {
        AccAggregation::new(
            Child::Batch(verifier),
            Input::Batch(&sample_merge, &sample_statement),
            &root_fri.config(),
            &layer,
            true,
        )
    })?;
    let leaf_report = security::leaf(&prover, leaf_fri);
    let merge_report = security::recursive(&batch.verifier(), merge_fri)?;
    let root_report = security::recursive(&root.verifier(), root_fri)?;
    let shapes = json!({"suite":SUITE,"layers":{"leaf":geometry(&leaf_report,true),"merge8":geometry(&merge_report,false),"root":geometry(&root_report,false)}});
    let mut reports = security::checkpoint_reports(&leaf_report, &merge_report, &root_report)?;
    let files = manifest["files"]
        .as_object_mut()
        .ok_or("bootstrap files missing")?;
    files.insert(
        "actual_shapes".into(),
        save_json(directory, "actual-shapes.json", &shapes)?,
    );
    reports["actual_shapes_sha256"] = files["actual_shapes"]["sha256"].clone();
    reports["configuration_sha256"] = files["configuration"]["sha256"].clone();
    files.insert(
        "security_report".into(),
        save_json(directory, "actual-security.json", &reports)?,
    );
    let preprocessing = prover
        .air
        .preprocessed_trace()
        .ok_or("missing leaf preprocessing")?;
    files.insert(
        "leaf_artifact".into(),
        freeze(
            directory,
            "leaf-air.bin",
            &bytes(&(preprocessing.width, &preprocessing.values))?,
        )?,
    );
    files.insert(
        "leaf_verifying_key".into(),
        freeze(
            directory,
            "leaf-key.bin",
            &bytes(&(
                prover.vk.degree_bits,
                prover.vk.width,
                &prover.vk.commitment,
            ))?,
        )?,
    );
    let merge_artifact = batch
        .verifier()
        .encode_verifier_artifact(ArtifactLimits::default())
        .map_err(|e| format!("{e:?}"))?;
    files.insert(
        "merge8_artifact".into(),
        freeze(directory, "merge8-verifier.bin", &merge_artifact)?,
    );
    files.insert(
        "merge8_verifying_key".into(),
        json!({"path":"merge8-verifier.bin","sha256":sha(&merge_artifact)}),
    );
    let root_artifact = root
        .verifier()
        .encode_verifier_artifact(ArtifactLimits::default())
        .map_err(|e| format!("{e:?}"))?;
    files.insert(
        "root_artifact".into(),
        freeze(directory, "root-verifier.bin", &root_artifact)?,
    );
    files.insert(
        "root_verifying_key".into(),
        json!({"path":"root-verifier.bin","sha256":sha(&root_artifact)}),
    );
    // The synthetic fixture and its generator seed are frozen by bootstrap before launch.
    files.insert(
        "merge_input_proofs".into(),
        freeze(
            directory,
            "bootstrap-proofs.bin",
            &bytes(&(&sample.0, &sample.1, &sample_merge))?,
        )?,
    );
    let last = monotonic_ns();
    let last_memory = memory();
    let startup = json!({"phase":"startup","start_ns":first,"end_ns":last,"memory_start":first_memory,"memory_end":last_memory,"wall_ns":last-first});
    drop(sample_merge);
    drop(sample);
    manifest["checkpoint_mode"] = json!("n16-full");
    manifest["stage"] = json!("prepared");
    manifest["execution"] = execution.clone();
    let final_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    let final_sha = sha(&final_bytes);
    freeze(directory, "frozen-manifest.json", &final_bytes)?;
    let ready_start = monotonic_ns();
    let ready_memory = memory();
    let ready_end = monotonic_ns();
    let resident = json!({"phase":"ready_resident","start_ns":ready_start,"end_ns":ready_end,"memory_start":ready_memory,"memory_end":memory(),"wall_ns":ready_end-ready_start});
    let ready = json!({"manifest_path":directory.join("frozen-manifest.json"),"manifest_sha256":final_sha,"resident_setup_complete":true,"prepared_layers":["leaf","merge8","root"],"setup_phases":[startup,resident],"setup_detail":setup});
    let temporary = control.join("setup-ready.tmp");
    std::fs::write(
        &temporary,
        serde_json::to_vec_pretty(&ready).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    std::fs::rename(temporary, control.join("setup-ready.json")).map_err(|e| e.to_string())?;
    let grant = control.join("grant.json");
    while !grant.exists() {
        if control.join("cancel.json").exists() {
            return Err("controller canceled checkpoint".into());
        }
        if monotonic_ns() - ready_start > 120_000_000_000 {
            return Err("controller grant timed out".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let grant = read(&grant)?;
    if grant["manifest_sha256"] != final_sha || grant["allowed_trials"] != 3 {
        return Err("invalid controller grant".into());
    }
    let note = MinerNote {
        height: 1234,
        share: MINER_SHARE,
        owner: Rng::new(9).digest(),
        rseed: Rng::new(10).digest(),
    };
    for trial in 1..=3 {
        if control.join("cancel.json").exists() {
            return Err("controller canceled checkpoint".into());
        }
        let mut phases = Vec::new();
        let timed_start_ns = monotonic_ns();
        let leaves = measured("leaf16", &mut phases, || {
            witnesses
                .iter()
                .map(|w| prover.prove_acc(w))
                .collect::<Vec<_>>()
        });
        let inputs = (0..16)
            .map(|i| Input::Uni(&leaves[i].0, &leaves[i].1, &witnesses[i].anchor_path))
            .collect::<Vec<_>>();
        let full = (0..16)
            .map(|i| anchor_leaf(&leaves[i].1, &witnesses[i].anchor_path))
            .collect::<Vec<_>>();
        let statements = [fold(&full[..8]), fold(&full[8..])];
        let left = measured("merge1", &mut phases, || batch.prove(&inputs[..8]))?;
        let right = measured("merge2", &mut phases, || batch.prove(&inputs[8..]))?;
        let (proof, root_bytes, root_output_ready_ns) = measured("root", &mut phases, || {
            let proof = root.prove(
                Input::Batch(&left, &statements[0]),
                Input::Batch(&right, &statements[1]),
                Some(&note),
            )?;
            // Canonical export performs its own proof check. It is part of
            // artifact production, before the separately timed verification.
            let encoded = root
                .verifier()
                .encode_proof_artifact(&proof, ArtifactLimits::default())
                .map_err(|e| format!("{e:?}"))?;
            Ok::<_, String>((proof, encoded, monotonic_ns()))
        })?;
        let timed_end_ns = monotonic_ns();
        measured("verification", &mut phases, || {
            root.verifier().verify(
                &proof,
                &root_statement(&statements[0], &statements[1], &note),
            )
        })
        .map_err(|e| format!("{e:?}"))?;
        let retained = json!({"leaves":leaves.iter().map(|(p,s)|bytes(&(p,s)).map(|b|b.len())).collect::<Result<Vec<_>,_>>()?.iter().sum::<usize>(),"merge1":bytes(&left)?.len(),"merge2":bytes(&right)?.len(),"root":root_bytes.len(),"basis":"leaf/merge serialized sizes are diagnostics; root is the retained canonical artifact; excludes allocator footprint"});
        output(
            json!({"event":"d8_checkpoint_trial","trial":trial,"checkpoint_mode":"n16-full","suite":SUITE,"manifest_sha256":final_sha,"verified":true,"fresh_hiding_randomness":true,"parameters":manifest["parameters"],"execution":execution,"runtime":runtime,"leaf_proofs_at_merge_start":16,"batch_grinding_verified_paths":["native","recursive","prepared"],"timed_start_ns":timed_start_ns,"timed_end_ns":timed_end_ns,"canonical_root_output":{"encoding":"plonky3-canonical-artifact","completed_ns":root_output_ready_ns,"bytes":root_bytes.len()},"phases":phases,"retained_serialized_bytes":retained}),
        );
        drop(root_bytes);
    }
    let mut teardown = Vec::new();
    measured("teardown", &mut teardown, || {
        drop(root);
        drop(batch);
        drop(prover);
    });
    output(
        json!({"event":"d8_checkpoint_complete","teardown_phase":teardown[0],"manifest_sha256":final_sha,"trials":3}),
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        output(json!({"event":"d8_checkpoint_failure","error":error}));
        std::process::exit(2);
    }
}
