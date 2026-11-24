use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create private CMake input directory");
    for entry in fs::read_dir(source).expect("list vendored RandomX") {
        let entry = entry.expect("read vendored RandomX entry");
        let kind = entry.file_type().expect("read RandomX entry type");
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            assert!(kind.is_file(), "unexpected vendored RandomX entry");
            fs::copy(entry.path(), target).expect("copy vendored RandomX file");
        }
    }
}

fn main() {
    println!("cargo::rerun-if-changed=vendor/randomx");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    let source = out.join("randomx-src");
    copy_tree(Path::new("vendor/randomx"), &source);
    let os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo target OS");
    let toolchain = env::var("CARGO_CFG_TARGET_ENV").expect("Cargo target toolchain");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo target architecture");
    assert!(
        matches!(arch.as_str(), "x86_64" | "aarch64"),
        "unsupported RandomX architecture"
    );
    assert!(
        matches!(
            (os.as_str(), toolchain.as_str()),
            ("macos" | "linux", _) | ("windows", "msvc")
        ),
        "unsupported RandomX target"
    );
    let dst = cmake::Config::new(&source)
        .define("ARCH_ID", &arch)
        .define("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
        .define("BUILD_SHARED_LIBS", "OFF")
        .profile("Release")
        .build_target("randomx")
        .build();
    let build = dst.join("build");
    let libname = if toolchain == "msvc" {
        "randomx.lib"
    } else {
        "librandomx.a"
    };
    let directory = [build.join("Release"), build]
        .into_iter()
        .find(|dir| dir.join(libname).is_file())
        .expect("RandomX static archive not found");
    println!("cargo::rustc-link-search=native={}", directory.display());
    println!("cargo::rustc-link-lib=static=randomx");
    if os == "macos" {
        println!("cargo::rustc-link-lib=c++");
    } else if os == "linux" {
        println!("cargo::rustc-link-lib=stdc++");
    } else if toolchain == "msvc" {
        println!("cargo::rustc-link-lib=advapi32");
    }
}
