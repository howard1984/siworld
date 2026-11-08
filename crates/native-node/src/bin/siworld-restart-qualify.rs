//! Exact-head legacy restart qualification from pinned checkpoint evidence.
use siworld_native_node::{
    engineering_checkpoint::{self, Certificate},
    local,
    p2p::Binding,
    proofs::NativeVerifier,
    service::Lease,
    store::{
        Store,
        checkpoint_bootstrap::{BootstrapLimits, CheckpointBootstrap},
    },
};
use std::{
    fs,
    io::Read,
    path::Path,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

fn bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "qualification input unavailable")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum as u64 {
        return Err("qualification input is not a bounded regular file".into());
    }
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .map_err(|_| "qualification input unavailable")?
    };
    #[cfg(windows)]
    let mut file = siworld_miner_platform::read_private(path, false)?;
    #[cfg(not(any(unix, windows)))]
    return Err("qualification inputs require a supported file identity boundary".into());
    let opened = file
        .metadata()
        .map_err(|_| "qualification input identity unavailable")?;
    if !opened.is_file() || opened.len() > maximum as u64 {
        return Err("qualification input file limit".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err("qualification input identity changed".into());
        }
    }
    let mut bytes = Vec::with_capacity(opened.len().min(maximum as u64) as usize);
    file.by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "qualification input unreadable")?;
    if bytes.len() > maximum || bytes.len() as u64 != opened.len() {
        return Err("qualification input byte limit".into());
    }
    let after = fs::symlink_metadata(path).map_err(|_| "qualification input identity changed")?;
    if !after.is_file() || after.file_type().is_symlink() || after.len() != opened.len() {
        return Err("qualification input changed".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if after.dev() != opened.dev() || after.ino() != opened.ino() {
            return Err("qualification input identity changed".into());
        }
    }
    #[cfg(windows)]
    if siworld_miner_platform::file_identity(&file)?
        != siworld_miner_platform::file_identity(&siworld_miner_platform::read_private(
            path, false,
        )?)?
    {
        return Err("qualification input identity changed".into());
    }
    Ok(bytes)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn qualification_inputs_reject_links_and_oversized_files() {
        let directory =
            std::env::temp_dir().join(format!("siworld-qualify-input-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let input = directory.join("input.bin");
        fs::write(&input, [1, 2, 3, 4]).unwrap();
        assert_eq!(bounded_file(&input, 4).unwrap(), [1, 2, 3, 4]);
        assert!(bounded_file(&input, 3).is_err());
        let link = directory.join("link.bin");
        std::os::unix::fs::symlink(&input, &link).unwrap();
        assert!(bounded_file(&link, 4).is_err());
        assert!(bounded_file(&directory, 4).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
fn run() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let profile = args.first().is_some_and(|value| value == "--profile");
    if profile {
        args.remove(0);
    }
    if args.len() != 3 {
        return Err(
            "expected [--profile] DIRECTORY CERTIFICATE_FILE PERMANENT_RECORD_DIRECTORY".into(),
        );
    }
    let directory =
        fs::canonicalize(Path::new(&args[0])).map_err(|_| "existing node directory unavailable")?;
    let config = local::load(&directory)?;
    let roster = engineering_checkpoint::release_roster(Binding::new(&config))?
        .ok_or("engineering checkpoint authorities are not release-pinned")?;
    let certificate = Certificate::decode(&bounded_file(
        Path::new(&args[1]),
        engineering_checkpoint::MAX_CERTIFICATE_BYTES,
    )?)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes epoch")?
        .as_secs();
    let records = Path::new(&args[2]);
    let start = Instant::now();
    if profile {
        let mut session = CheckpointBootstrap::begin(
            &directory.join("restart-profile-stage.redb"),
            config,
            certificate.clone(),
            roster,
            None,
            now,
            siworld_core::pow::Work::zero(),
            BootstrapLimits::default(),
        )?;
        for height in 1..=certificate.statement.height {
            session.push_permanent(&bounded_file(
                &records.join(format!("{height}.bin")),
                siworld_native_node::ranges::MAX_COMPACT + 48,
            )?)?;
        }
        let mut metrics = session.verified_prefix_metrics()?;
        metrics["prefix_reconstruction_ms"] = serde_json::json!(start.elapsed().as_millis());
        metrics["mode"] = serde_json::json!("profile-only-no-adoption");
        println!("{metrics}");
        return Ok(());
    }
    let _lease = Lease::acquire(&directory)?;
    let mut result = Store::qualify_restart_existing(
        &directory.join("chain.redb"),
        config,
        certificate,
        roster,
        now,
        &directory.join("restart-qualification-stage.redb"),
        |height| {
            bounded_file(
                &records.join(format!("{height}.bin")),
                siworld_native_node::ranges::MAX_COMPACT + 48,
            )
        },
        &NativeVerifier::new()?,
    )?;
    result["elapsed_ms"] = serde_json::json!(start.elapsed().as_millis());
    println!("{result}");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
