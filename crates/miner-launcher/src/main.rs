//! Generic x86-64 entry point. Never execute proof code before admission.
#![forbid(unsafe_code)]
#[cfg(all(
    target_arch = "x86_64",
    any(
        target_feature = "avx",
        target_feature = "avx2",
        target_feature = "bmi1",
        target_feature = "bmi2",
        target_feature = "f16c",
        target_feature = "fma",
        target_feature = "lzcnt",
        all(not(windows), target_feature = "sse3"),
        target_feature = "sse4.1",
        target_feature = "sse4.2",
        target_feature = "popcnt",
        target_feature = "movbe",
        target_feature = "ssse3",
        all(not(windows), target_feature = "cmpxchg16b"),
        target_feature = "lahfsahf",
        target_feature = "xsave"
    )
))]
compile_error!("Build the miner launcher with -C target-cpu=x86-64");
#[cfg(any(windows, test))]
use sha2::{Digest, Sha256};
use std::ffi::OsString;
#[cfg(any(windows, test))]
use std::io::Read;
#[cfg(any(windows, test))]
use std::path::Path;
#[derive(Clone, Copy, Debug)]
struct Feature {
    name: &'static str,
    supported: bool,
}

#[cfg(target_arch = "x86_64")]
fn cpu_features() -> Vec<Feature> {
    // The standard-library AVX detector checks OSXSAVE and XCR0 as well as
    // CPUID. Detecting an advertised AVX2 bit alone would not qualify the OS.
    // LAHF/SAHF has no standard feature-detection macro. CPUID is always
    // available on x86-64 and is a safe intrinsic on the pinned toolchain.
    let extended_max = std::arch::x86_64::__cpuid(0x8000_0000).eax;
    let lahf_sahf =
        extended_max >= 0x8000_0001 && std::arch::x86_64::__cpuid(0x8000_0001).ecx & 1 != 0;
    macro_rules! feature {
        ($name:tt) => {
            Feature {
                name: $name,
                supported: std::is_x86_feature_detected!($name),
            }
        };
    }
    vec![
        feature!("avx2"),
        feature!("avx"),
        feature!("bmi1"),
        feature!("bmi2"),
        feature!("f16c"),
        feature!("fma"),
        feature!("lzcnt"),
        feature!("movbe"),
        feature!("xsave"),
        feature!("sse3"),
        feature!("ssse3"),
        feature!("sse4.1"),
        feature!("sse4.2"),
        feature!("popcnt"),
        feature!("cmpxchg16b"),
        Feature {
            name: "lahf_sahf",
            supported: lahf_sahf,
        },
    ]
}

#[cfg(not(target_arch = "x86_64"))]
fn cpu_features() -> Vec<Feature> {
    vec![Feature {
        name: "x86_64",
        supported: false,
    }]
}

fn missing_features(features: &[Feature]) -> Vec<&'static str> {
    features
        .iter()
        .filter(|feature| !feature.supported)
        .map(|feature| feature.name)
        .collect()
}

fn rejection_message(missing: &[&str]) -> String {
    format!(
        "Cannot start proof process: x86-64-v3 CPU and OS support (including AVX2) are required; missing: {}. Scalar fallback is disabled.",
        missing.join(", ")
    )
}

#[cfg(any(windows, test))]
fn check_digest(path: &Path, expected: &str) -> Result<(), String> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("Worker SHA-256 is not pinned by this build".into());
    }
    let mut file = std::fs::File::open(path).map_err(|_| "Packaged worker unavailable")?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let n = file
            .read(&mut bytes)
            .map_err(|_| "Packaged worker unreadable")?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    let actual = format!("{:x}", hash.finalize());
    if actual != expected {
        return Err("Worker SHA-256 mismatch; do not run this package".into());
    }
    Ok(())
}
fn run() -> Result<i32, String> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.as_slice() == [OsString::from("--help")] || args.as_slice() == [OsString::from("-h")] {
        print!("{}", include_str!("../../miner-cli/help.txt"));
        return Ok(0);
    }
    let missing = missing_features(&cpu_features());
    if !missing.is_empty() {
        return Err(rejection_message(&missing));
    }
    if args.as_slice() == [OsString::from("--check-cpu")] {
        println!("CPU admission passed: x86-64-v3");
        return Ok(0);
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        Err("This package runs natively on Windows 10/11 x86_64".into())
    }
    #[cfg(windows)]
    {
        siworld_miner_platform::check_memory(siworld_miner_platform::visible_memory()?)?;
        if std::thread::available_parallelism()
            .map_err(|_| "CPU count unavailable")?
            .get()
            < 4
        {
            return Err("At least 4 logical CPUs are required".into());
        }
        if args.as_slice() == [OsString::from("--check-hardware")] {
            println!("Hardware admission passed");
            return Ok(0);
        }
        if args.first().is_some_and(|a| a == "--worker") {
            return Err("Internal worker mode cannot be launched directly".into());
        }
        let exe = std::env::current_exe().map_err(|_| "Package path unavailable")?;
        let worker = exe
            .parent()
            .ok_or("Package root unavailable")?
            .join("libexec/siworld-miner-worker.exe");
        check_digest(&worker, option_env!("SIWORLD_WORKER_SHA256").unwrap_or(""))?;
        siworld_miner_platform::install_stop_handler()?;
        let status = std::process::Command::new(worker)
            .args(args)
            .status()
            .map_err(|_| "Native worker could not start")?;
        Ok(status.code().unwrap_or(126))
    }
}
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(78);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_each_cpu_capability_is_rejected() {
        let complete = cpu_features()
            .into_iter()
            .map(|mut f| {
                f.supported = true;
                f
            })
            .collect::<Vec<_>>();
        for i in 0..complete.len() {
            let mut f = complete.clone();
            f[i].supported = false;
            assert_eq!(missing_features(&f), vec![complete[i].name]);
        }
    }
    #[test]
    fn worker_digest_rejects_missing_pin_or_changed_binary() {
        let path = std::env::temp_dir().join(format!("siworld-launcher-{}", std::process::id()));
        std::fs::write(&path, b"synthetic worker").unwrap();
        assert!(check_digest(&path, "").is_err());
        let expected = format!("{:x}", Sha256::digest(b"synthetic worker"));
        check_digest(&path, &expected).unwrap();
        std::fs::write(&path, b"modified worker").unwrap();
        assert!(check_digest(&path, &expected).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
