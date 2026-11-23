#![cfg(all(
    feature = "desktop-e2e",
    debug_assertions,
    any(target_os = "macos", windows)
))]

use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

struct Instance {
    process: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Instance {
    fn start(role: &str, data: &Path) -> Self {
        let mut process = Command::new(env!("CARGO_BIN_EXE_sivault-desktop"))
            .args(["--sivault-controlled-test", role])
            .arg(data)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = process.stdin.take().unwrap();
        let output = BufReader::new(process.stdout.take().unwrap());
        Self {
            process,
            input,
            output,
        }
    }

    fn receive(&mut self) -> String {
        let mut reply = String::new();
        assert_ne!(
            self.output.read_line(&mut reply).unwrap(),
            0,
            "child closed its response stream"
        );
        reply.trim().into()
    }

    fn request(&mut self, operation: &str, expected: &str) {
        writeln!(self.input, "{operation}").unwrap();
        self.input.flush().unwrap();
        assert_eq!(self.receive(), expected, "{operation}");
    }

    fn stop(mut self) {
        writeln!(self.input, "stop").unwrap();
        self.input.flush().unwrap();
        assert!(self.process.wait().unwrap().success());
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

#[test]
fn two_native_desktop_processes_restart_refill_and_revoke() {
    let releaser_data = tempfile::tempdir().unwrap();
    let owner_data = tempfile::tempdir().unwrap();
    let mut releaser = Instance::start("releaser", releaser_data.path());
    let peer = releaser.receive();
    assert!(peer.starts_with("127.0.0.1:"));
    let mut owner = Instance::start("owner", owner_data.path());
    owner.request(&format!("create {peer}"), "ok");
    owner.stop();
    releaser.stop();
    let mut releaser = Instance::start("releaser", releaser_data.path());
    assert_eq!(
        releaser.receive(),
        peer,
        "port and key must survive restart"
    );
    let mut owner = Instance::start("owner", owner_data.path());
    owner.request("open", "ok");
    owner.request("wrong", "denied");
    owner.request("open", "denied");
    owner.request("refill", "ok");
    owner.request("open", "ok");
    owner.request("revoke", "ok");
    assert!(
        !releaser_data
            .path()
            .join("releaser-slot/material-v1")
            .exists()
    );
    owner.request("open", "denied");
    releaser.stop();
    owner.stop();
}
