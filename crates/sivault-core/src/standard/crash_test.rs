use super::*;
use std::{
    env,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const ROOT: &str = "SIVAULT_CRASH_TEST_ROOT";
const PHASE: &str = "SIVAULT_CRASH_TEST_PHASE";
const PASSWORD: &str = "synthetic interrupted commit fixture";
const PAYLOAD: &[u8] = b"Synthetic file for interrupted publication.\n";

pub(super) fn pause(phase: &str) {
    if env::var(PHASE).as_deref() == Ok(phase) {
        let root = PathBuf::from(env::var_os(ROOT).unwrap());
        fs::write(root.join("ready"), phase).unwrap();
        loop {
            thread::park();
        }
    }
}

#[test]
fn import_child() {
    let Some(root) = env::var_os(ROOT).map(PathBuf::from) else {
        return;
    };
    let mut safe = Safe::open(root.join("safe"), PASSWORD, false).unwrap();
    safe.import_file(root.join("sample.txt"), None).unwrap();
    panic!("child missed its publication checkpoint");
}

#[test]
fn process_kill_preserves_a_complete_generation() {
    if mutation_supported().is_err() {
        return;
    }
    for phase in ["before", "after"] {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path();
        let path = root.join("safe");
        drop(Safe::create(&path, PASSWORD).unwrap());
        fs::write(root.join("sample.txt"), PAYLOAD).unwrap();
        let mut child = Command::new(env::current_exe().unwrap())
            .args(["--exact", "standard::crash_test::import_child"])
            .env(ROOT, root)
            .env(PHASE, phase)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        let reached = loop {
            if fs::read(root.join("ready")).as_deref().ok() == Some(phase.as_bytes()) {
                break true;
            }
            if child.try_wait().unwrap().is_some() || Instant::now() >= deadline {
                break false;
            }
            thread::sleep(Duration::from_millis(10));
        };
        if reached {
            child.kill().unwrap();
        } else {
            let _ = child.kill();
        }
        assert!(!child.wait().unwrap().success());
        assert!(reached, "child did not reach {phase} publication");
        let safe = Safe::open(&path, PASSWORD, true).unwrap();
        if phase == "before" {
            assert!(safe.entries().is_empty());
        } else {
            let [entry] = safe.entries() else {
                panic!("published file is not visible");
            };
            let output = root.join("export.txt");
            safe.export_file(&entry.id, &output).unwrap();
            assert_eq!(fs::read(output).unwrap(), PAYLOAD);
        }
    }
}
