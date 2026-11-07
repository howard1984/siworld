//! Baseline bootstrap for x86-64-v3 proof executables.
//!
//! Build directly with `rustc -C target-cpu=x86-64`, independently of the
//! workspace target flags. Only this bootstrap runs before CPU qualification.
//! The optimized executable is installed at `../libexec/<bootstrap-name>` relative to the bootstrap directory.

#![forbid(unsafe_code)]

#[cfg(all(
    target_arch = "x86_64",
    any(
        target_feature = "avx",
        target_feature = "avx2",
        target_feature = "bmi1",
        target_feature = "bmi2",
        target_feature = "cmpxchg16b",
        target_feature = "f16c",
        target_feature = "fma",
        target_feature = "lahfsahf",
        target_feature = "lzcnt",
        target_feature = "movbe",
        target_feature = "popcnt",
        target_feature = "sse3",
        target_feature = "ssse3",
        target_feature = "sse4.1",
        target_feature = "sse4.2",
        target_feature = "xsave"
    )
))]
compile_error!(
    "The proof bootstrap must use the generic x86-64 baseline, not x86-64-v3 or native CPU flags"
);

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

const CPU_UNSUPPORTED: i32 = 78;
const LAUNCH_FAILURE: i32 = 126;
const EXECUTABLES: &[&str] = &["siworld-native-node", "siworld-checkpoint-key"];

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

fn worker_path(executable: &Path) -> Result<PathBuf, &'static str> {
    let filename = executable
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or("Cannot determine proof bootstrap name")?;
    let name = filename.strip_suffix(".exe").unwrap_or(filename);
    if !EXECUTABLES.contains(&name) {
        return Err("Unrecognized proof bootstrap name");
    }
    let directory = executable
        .parent()
        .ok_or("Cannot determine proof bootstrap directory")?;
    Ok(directory.join("..").join("libexec").join(filename))
}

fn print_cpu_metadata(features: &[Feature], missing: &[&str]) {
    let values = features
        .iter()
        .map(|feature| format!("\"{}\":{}", feature.name, feature.supported))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "{{\"required_baseline\":\"x86-64-v3\",\"supported\":{},\"scalar_fallback\":false,\"features\":{{{values}}}}}",
        missing.is_empty()
    );
}

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let features = cpu_features();
    let missing = missing_features(&features);
    let check_only = args.len() == 1 && args[0] == OsStr::new("--check-cpu");
    if check_only {
        print_cpu_metadata(&features, &missing);
    }
    if !missing.is_empty() {
        eprintln!("{}", rejection_message(&missing));
        std::process::exit(CPU_UNSUPPORTED);
    }
    if check_only {
        return;
    }
    let worker = std::env::current_exe()
        .map_err(|_| "Cannot resolve proof bootstrap executable")
        .and_then(|path| worker_path(&path));
    let worker = match worker {
        Ok(worker) => worker,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(LAUNCH_FAILURE);
        }
    };
    let mut command = std::process::Command::new(worker);
    command.args(args);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = command.exec();
        eprintln!("Cannot execute optimized proof worker: {error}");
        std::process::exit(LAUNCH_FAILURE);
    }
    #[cfg(not(unix))]
    {
        match command.status() {
            Ok(status) => std::process::exit(status.code().unwrap_or(LAUNCH_FAILURE)),
            Err(error) => {
                eprintln!("Cannot execute optimized proof worker: {error}");
                std::process::exit(LAUNCH_FAILURE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEATURES: &[&str] = &[
        "avx2",
        "avx",
        "bmi1",
        "bmi2",
        "f16c",
        "fma",
        "lzcnt",
        "movbe",
        "xsave",
        "sse3",
        "ssse3",
        "sse4.1",
        "sse4.2",
        "popcnt",
        "cmpxchg16b",
        "lahf_sahf",
    ];

    fn supported_features() -> Vec<Feature> {
        FEATURES
            .iter()
            .map(|name| Feature {
                name,
                supported: true,
            })
            .collect()
    }

    #[test]
    fn accepts_complete_v3_capabilities() {
        assert!(missing_features(&supported_features()).is_empty());
    }

    #[test]
    fn rejects_each_missing_v3_feature() {
        for (index, name) in FEATURES.iter().enumerate() {
            let mut features = supported_features();
            features[index].supported = false;
            assert_eq!(missing_features(&features), vec![*name]);
        }
    }

    #[test]
    fn avx2_without_os_avx_support_is_rejected() {
        let mut features = supported_features();
        features
            .iter_mut()
            .find(|feature| feature.name == "avx")
            .unwrap()
            .supported = false;
        assert_eq!(missing_features(&features), vec!["avx"]);
    }

    #[test]
    fn reports_all_missing_features_without_fallback() {
        let message = rejection_message(&["avx2", "bmi2"]);
        assert!(message.contains("including AVX2"));
        assert!(message.contains("missing: avx2, bmi2"));
        assert!(message.contains("Scalar fallback is disabled"));
    }

    #[test]
    fn installed_entrypoints_resolve_only_packaged_workers() {
        for name in EXECUTABLES {
            let executable = Path::new("package/bin").join(name);
            assert_eq!(
                worker_path(&executable).unwrap(),
                Path::new("package/bin/../libexec").join(name)
            );
        }
    }

    #[test]
    fn windows_entrypoint_preserves_executable_suffix() {
        assert_eq!(
            worker_path(Path::new("package/bin/siworld-native-node.exe")).unwrap(),
            Path::new("package/bin/../libexec/siworld-native-node.exe")
        );
    }

    #[test]
    fn rejects_unknown_launcher_and_path_injection() {
        for name in ["other", "..", "libexec", "composition-bench-worker"] {
            assert!(worker_path(&Path::new("package").join(name)).is_err());
        }
    }
}
