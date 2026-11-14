use super::*;
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
};
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> Self {
        let mut entropy = [0; 16];
        getrandom::fill(&mut entropy).unwrap();
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "siworld-isolated-control-{}",
            crate::local::hex(&entropy)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn controller(directory: &Path) -> Controller {
    let files = io::Files::initialize(directory).unwrap();
    let bytes = b"{}";
    files.create("manifest.json", bytes).unwrap();
    Controller {
        files,
        manifest: digest(bytes),
        maximum: 100_000,
        run: "01".repeat(32),
        source: "02".repeat(20),
        binary: "03".repeat(32),
        revision: 0,
        paused: true,
        stop_height: 0,
        request_sha256: None,
        failed: false,
    }
}
fn command(control: &Controller, height: u64, tip: &Hash, stop: u64, paused: bool) -> Value {
    json!({"version":1,"manifest_sha256":control.manifest,"run_id":control.run,
        "source_commit":control.source,"binary_sha256":control.binary,
        "revision":control.revision+1,"expected_height":height,
        "expected_tip":crate::local::hex(tip),"paused":paused,"stop_height":stop})
}
fn install(control: &Controller, value: &Value) {
    control
        .files
        .create(
            &name("request", &control.run, value["revision"].as_u64().unwrap()),
            &serde_json::to_vec(value).unwrap(),
        )
        .unwrap();
}
#[test]
fn pause_resume_revisions_and_exact_height_do_not_reuse_old_permission() {
    let temp = Temporary::new();
    let mut control = controller(&temp.0);
    let tip = [9; 32];
    assert_eq!(control.poll(600, &tip).unwrap(), (false, 0));
    install(&control, &command(&control, 600, &tip, 625, false));
    assert_eq!(control.poll(600, &tip).unwrap(), (true, 1));
    assert_eq!(control.poll(624, &tip).unwrap(), (true, 1));
    assert_eq!(control.poll(625, &tip).unwrap(), (false, 1));
    assert_eq!(control.poll(626, &tip).unwrap(), (false, 1));
    install(&control, &command(&control, 625, &tip, 625, true));
    assert_eq!(control.poll(625, &tip).unwrap(), (false, 2));
    install(&control, &command(&control, 625, &tip, 650, false));
    let (allowed, revision) = control.poll(625, &tip).unwrap();
    assert!(allowed);
    assert_ne!(revision, 1);
    assert_eq!(control.permission(625, &tip, Some(1)).unwrap(), (false, 3));
    assert_eq!(control.permission(625, &tip, Some(2)).unwrap(), (false, 3));
    assert_eq!(control.permission(625, &tip, Some(3)).unwrap(), (true, 3));
    let receipt: Value = serde_json::from_slice(
        &control
            .files
            .required(&name("result", &control.run, 2))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["status"], "applied");
    assert_eq!(receipt["paused"], true);
    assert_eq!(receipt["height"], 625);
    assert_eq!(receipt["revision"], 2);
}
#[test]
fn invalid_run_build_revision_manifest_and_bounds_are_rejected_without_enabling() {
    for field in [
        "run_id",
        "source_commit",
        "binary_sha256",
        "revision",
        "manifest_sha256",
        "stop_height",
    ] {
        let temp = Temporary::new();
        let mut control = controller(&temp.0);
        let tip = [9; 32];
        let mut value = command(&control, 25, &tip, 50, false);
        value[field] = match field {
            "expected_height" => json!(24),
            "revision" => json!(2),
            "stop_height" => json!(100_001),
            "source_commit" => json!("04".repeat(20)),
            _ => json!("04".repeat(32)),
        };
        // Put the malformed revision at the next expected immutable name.
        control
            .files
            .create(
                &name("request", &control.run, 1),
                &serde_json::to_vec(&value).unwrap(),
            )
            .unwrap();
        assert!(control.permission(25, &tip, None).is_err(), "{field}");
        assert!(control.failed);
        assert_eq!(control.status(25)["production_allowed"], false);
        assert!(control.permission(25, &tip, None).is_err());
        assert_eq!(control.revision, 0);
        assert!(control.paused);
        let receipt: Value = serde_json::from_slice(
            &control
                .files
                .required(&name("result", &control.run, 1))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["status"], "rejected");
    }
}
#[test]
fn applied_request_or_manifest_removal_and_replacement_fail_closed() {
    for target in ["request", "manifest", "directory"] {
        let temp = Temporary::new();
        let mut control = controller(&temp.0);
        let tip = [9; 32];
        install(&control, &command(&control, 1, &tip, 25, false));
        assert_eq!(control.poll(1, &tip).unwrap(), (true, 1));
        let root = temp.0.join(DIRECTORY);
        match target {
            "request" => fs::remove_file(root.join(name("request", &control.run, 1))).unwrap(),
            "manifest" => fs::write(root.join("manifest.json"), b"[]").unwrap(),
            _ => {
                fs::rename(&root, temp.0.join("retained")).unwrap();
                fs::DirBuilder::new().mode(0o700).create(root).unwrap();
            }
        }
        assert!(control.permission(1, &tip, None).is_err(), "{target}");
        assert!(control.failed);
        assert_eq!(control.status(1)["production_allowed"], false);
    }
}
#[test]
fn immutable_records_reject_overwrite_symlink_hardlink_modes_and_oversize() {
    let temp = Temporary::new();
    let files = io::Files::initialize(&temp.0).unwrap();
    files.create("original", b"{}").unwrap();
    assert!(files.create("original", b"[]").is_err());
    assert_eq!(files.required("original").unwrap(), b"{}");
    let root = temp.0.join(DIRECTORY);
    std::os::unix::fs::symlink(root.join("original"), root.join("link")).unwrap();
    assert!(files.read("link").is_err());
    fs::hard_link(root.join("original"), root.join("hard")).unwrap();
    assert!(files.read("original").is_err());
    fs::remove_file(root.join("hard")).unwrap();
    fs::set_permissions(root.join("original"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(files.read("original").is_err());
    assert!(
        files
            .create("oversized", &vec![b'x'; MAX_BYTES + 1])
            .is_err()
    );
    assert!(!root.join("oversized").exists());
}
#[test]
fn request_schema_rejects_unknown_fields_path_text_and_ambiguous_numbers() {
    let temp = Temporary::new();
    let control = controller(&temp.0);
    let original = command(&control, 25, &[9; 32], 50, false);
    assert!(request(&serde_json::to_vec(&original).unwrap()).is_ok());
    for (field, value) in [
        ("extra", json!(true)),
        ("revision", json!(-1)),
        ("revision", json!(1.5)),
        ("run_id", json!("../escape")),
        ("paused", json!("false")),
        ("stop_height", json!(25)),
    ] {
        let mut altered = original.clone();
        altered[field] = value;
        assert!(
            request(&serde_json::to_vec(&altered).unwrap()).is_err(),
            "{field}"
        );
    }
}
#[test]
fn only_nonfixture_minimum_positive_work_genesis_is_eligible() {
    let mut config = crate::state::Config::asert_development([8; 32], 1, [0xff; 32], 1).unwrap();
    assert!(eligible(&config));
    config.pow_iterations = 64;
    assert!(!eligible(&config));
    config.pow_iterations = 0;
    assert!(!eligible(&config));
    config.pow_iterations = 1;
    config.genesis_target[0] = 0xfe;
    assert!(!eligible(&config));
    assert!(!eligible(
        &crate::state::Config::development([8; 32], 0).unwrap()
    ));
}

#[test]
fn acknowledgement_write_failure_latches_failed_without_advancing_revision() {
    let temp = Temporary::new();
    let mut control = controller(&temp.0);
    let tip = [9; 32];
    install(&control, &command(&control, 25, &tip, 50, false));
    let result_name = name("result", &control.run, 1);
    control.files.create(&result_name, b"{}").unwrap();
    assert!(control.permission(25, &tip, None).is_err());
    assert!(control.failed);
    assert!(control.paused);
    assert_eq!(control.revision, 0);
    assert!(control.request_sha256.is_none());
    assert_eq!(control.status(25)["production_allowed"], false);
    assert_eq!(control.files.required(&result_name).unwrap(), b"{}");
    assert!(control.permission(25, &tip, Some(0)).is_err());
}

#[test]
fn authenticated_head_compare_failure_consumes_once_pauses_and_requires_a_new_revision() {
    for (height, tip, paused) in [
        (26, [9; 32], false),
        (25, [8; 32], false),
        (26, [9; 32], true),
    ] {
        let temp = Temporary::new();
        let mut control = controller(&temp.0);
        install(&control, &command(&control, 25, &[9; 32], 50, false));
        assert_eq!(control.permission(25, &[9; 32], None).unwrap(), (true, 1));
        let old_stop = control.stop_height;
        install(&control, &command(&control, 25, &[9; 32], 60, paused));
        assert_eq!(
            control.permission(height, &tip, Some(1)).unwrap(),
            (false, 2)
        );
        assert!(!control.failed);
        assert!(control.paused);
        assert!(control.stop_height <= old_stop);
        let status = control.status(height);
        assert_eq!(status["production_allowed"], false);
        let result = name("result", &control.run, 2);
        let receipt = control.files.required(&result).unwrap();
        let rejected: Value = serde_json::from_slice(&receipt).unwrap();
        assert_eq!(rejected["status"], "rejected");
        assert_eq!(rejected["reason"], "head_compare_failed");
        assert_eq!(rejected["paused"], true);
        assert_eq!(rejected["stop_height"], control.stop_height);
        for _ in 0..3 {
            assert_eq!(
                control.permission(height, &tip, Some(2)).unwrap(),
                (false, 2)
            );
            assert_eq!(control.files.required(&result).unwrap(), receipt);
        }
        install(&control, &command(&control, height, &tip, 70, false));
        assert_eq!(
            control.permission(height, &tip, Some(1)).unwrap(),
            (false, 3)
        );
        assert_eq!(
            control.permission(height, &tip, Some(2)).unwrap(),
            (false, 3)
        );
        assert_eq!(
            control.permission(height, &tip, Some(3)).unwrap(),
            (true, 3)
        );
    }
}

#[test]
fn head_mismatch_does_not_hide_invalid_context_or_bounds() {
    for (field, value) in [
        ("source_commit", json!("04".repeat(20))),
        ("manifest_sha256", json!("04".repeat(32))),
        ("run_id", json!("04".repeat(32))),
        ("binary_sha256", json!("04".repeat(32))),
        ("revision", json!(2)),
        ("stop_height", json!(100_001)),
        ("expected_height", json!(100_001)),
    ] {
        let temp = Temporary::new();
        let mut control = controller(&temp.0);
        let mut selected = command(&control, 24, &[8; 32], 50, true);
        selected[field] = value;
        control
            .files
            .create(
                &name("request", &control.run, 1),
                &serde_json::to_vec(&selected).unwrap(),
            )
            .unwrap();
        assert!(control.permission(25, &[9; 32], None).is_err(), "{field}");
        assert!(control.failed);
        assert_eq!(control.revision, 0);
        assert_eq!(control.status(25)["production_allowed"], false);
    }
}

#[test]
fn rejected_head_request_and_manifest_are_still_immutable() {
    for target in ["request", "manifest"] {
        let temp = Temporary::new();
        let mut control = controller(&temp.0);
        install(&control, &command(&control, 24, &[8; 32], 50, false));
        assert_eq!(control.permission(25, &[9; 32], None).unwrap(), (false, 1));
        let path = if target == "request" {
            name("request", &control.run, 1)
        } else {
            "manifest.json".into()
        };
        fs::write(temp.0.join(DIRECTORY).join(path), b"[]").unwrap();
        assert!(control.permission(25, &[9; 32], None).is_err());
        assert!(control.failed);
    }
}

#[test]
fn rejected_head_receipt_io_failure_is_fatal_without_consuming_revision() {
    let temp = Temporary::new();
    let mut control = controller(&temp.0);
    install(&control, &command(&control, 24, &[8; 32], 50, false));
    control
        .files
        .create(&name("result", &control.run, 1), b"{}")
        .unwrap();
    assert!(control.permission(25, &[9; 32], None).is_err());
    assert!(control.failed);
    assert_eq!(control.revision, 0);
    assert!(control.request_sha256.is_none());
    assert!(control.paused);
}
