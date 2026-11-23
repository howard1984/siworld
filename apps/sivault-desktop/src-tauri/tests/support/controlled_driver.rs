//! Debug-only native process entry for the desktop controlled-safe integration test.
use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
};

use sivault_core::owner::OwnerIdentity;
use sivault_releaser::administration::Change;
use siworld_native_wallet_core::vault::Material;

use crate::{
    controlled,
    releaser::{LocalPeer, ReleaserState},
};

const SAFE_PASSWORD: &str = "synthetic controlled safe password";
const REL_STORAGE: &str = "synthetic releaser storage password";

fn identity() -> OwnerIdentity {
    let fixture = Material {
        entropy: [91; 32].into(),
        network: [92; 32],
        account: 0,
    };
    let restored = Material::restore([92; 32], 0, fixture.words()).unwrap();
    OwnerIdentity::derive(&restored.entropy)
}

pub fn dispatch() -> bool {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--sivault-controlled-test")) {
        return false;
    }
    let role = args.next().unwrap().into_string().unwrap();
    let directory = PathBuf::from(args.next().unwrap());
    assert!(directory.is_absolute() && directory.is_dir());
    let owner = identity();
    let stdin = io::stdin().lock();
    let mut out = io::stdout().lock();
    if role == "releaser" {
        let state = ReleaserState::default();
        match state.start_test_service(directory, REL_STORAGE, owner.identifier()) {
            Ok(peer) => writeln!(out, "{peer}").unwrap(),
            Err(_) => {
                writeln!(out, "unavailable").unwrap();
                return true;
            }
        }
        out.flush().unwrap();
        let _ = stdin.lines().next();
        state.stop(true);
    } else {
        assert_eq!(role, "owner");
        let path = directory.join("synthetic.sivault");
        for line in stdin.lines() {
            let line = line.unwrap();
            let parts: Vec<_> = line.split_ascii_whitespace().collect();
            let result = match parts.as_slice() {
                ["create", address, identifier] => LocalPeer::parse(address, identifier)
                    .and_then(|peer| controlled::create(&path, SAFE_PASSWORD, &peer, 2, &owner))
                    .map(drop),
                ["open"] => controlled::open(&path, SAFE_PASSWORD, true).map(drop),
                ["wrong"] => controlled::open(&path, "wrong synthetic password", true).map(drop),
                ["refill"] => controlled::manage(
                    &path,
                    &owner,
                    Change::Refill {
                        current: 2,
                        additional: 1,
                    },
                ),
                ["revoke"] => controlled::manage(&path, &owner, Change::Revoke),
                ["stop"] => break,
                _ => panic!("unexpected fixture operation"),
            };
            if let Err(error) = &result {
                eprintln!("{error:?}");
            }
            writeln!(out, "{}", if result.is_ok() { "ok" } else { "denied" }).unwrap();
            out.flush().unwrap();
        }
    }
    true
}
