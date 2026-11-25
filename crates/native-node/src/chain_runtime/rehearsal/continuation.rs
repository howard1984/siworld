//! Explicit continuation of an internally generated, failed rehearsal fixture.
//! The original directory is never opened for writes and no custody is exported.

use super::*;

const PREFIX: u64 = 24;
const FINAL: u64 = 28;

fn files() -> Vec<String> {
    ["genesis.bin", "chain.redb", "rehearsal.seed"]
        .into_iter()
        .map(str::to_owned)
        .chain((1..=PREFIX).map(|h| format!("block-{h}.json")))
        .chain((1..=2).map(|h| format!("governance-{h}.json")))
        .collect()
}
fn validate(source: &Path, destination: &Path) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), String> {
    if !source.is_absolute()
        || !destination.is_absolute()
        || source
            .canonicalize()
            .map_err(|_| "rehearsal source unavailable")?
            != source
        || destination.exists()
        || destination.symlink_metadata().is_ok()
        || source == destination
    {
        return Err(
            "continuation requires an existing canonical source and new absolute copy".into(),
        );
    }
    let metadata = source
        .symlink_metadata()
        .map_err(|_| "rehearsal source unavailable")?;
    if !metadata.file_type().is_dir() {
        return Err("continuation source is not a private directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("continuation requires an owner-private rehearsal directory".into());
        }
    }
    if source.join("result.json").symlink_metadata().is_ok()
        || source.join("block-25.json").symlink_metadata().is_ok()
    {
        return Err("continuation accepts only the failed 24-block rehearsal prefix".into());
    }
    let custody = bound_custody(source)?;
    for name in files() {
        let maximum = if name == "chain.redb" {
            16 * 1024 * 1024 * 1024
        } else {
            1024 * 1024
        };
        let file = crate::local::regular_read(&source.join(name), true, maximum)?;
        if file
            .metadata()
            .map_err(|_| "rehearsal source metadata unavailable")?
            .len()
            == 0
        {
            return Err("empty continuation fixture file".into());
        }
    }
    Ok(custody)
}
fn bound_custody(directory: &Path) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), String> {
    let mut seed = Zeroizing::new([0; 32]);
    crate::local::regular_read(&directory.join("rehearsal.seed"), true, 32)?
        .read_exact(seed.as_mut())
        .map_err(|_| "synthetic rehearsal custody width differs")?;
    let network = blake3::derive_key("siworld eng2 offline rehearsal network v1", seed.as_ref());
    let mut encoded = Vec::new();
    crate::local::regular_read(&directory.join("genesis.bin"), true, 1024 * 1024)?
        .read_to_end(&mut encoded)
        .map_err(|_| "public rehearsal genesis read failed")?;
    if genesis(seed.as_ref(), network)?.encode()? != encoded {
        return Err("custody is not bound to this internally generated synthetic rehearsal".into());
    }
    Ok((seed, encoded))
}

pub fn check_continuation(source: &Path, destination: &Path) -> Result<Value, String> {
    let (_seed, encoded) = validate(source, destination)?;
    Ok(json!({"scope":"synthetic-rehearsal-continuation-preflight",
        "synthetic_custody_genesis_binding":"passed", "genesis_id":crate::local::hex(&Genesis::decode(&encoded)?.id()),
        "source_prefix":"24", "target_height":"28", "copied_files":files(),
        "native_prefix_audit":"required_on_copy", "proof_generation":false,
        "source_modified":false, "custody_printed":false}))
}

pub fn continue_run(source: &Path, destination: &Path) -> Result<Value, String> {
    let (seed, encoded) = validate(source, destination)?;
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(destination)
        .map_err(|_| "new continuation directory unavailable")?;
    for name in files() {
        let maximum = if name == "chain.redb" {
            16 * 1024 * 1024 * 1024
        } else {
            1024 * 1024
        };
        let mut input = crate::local::regular_read(&source.join(&name), true, maximum)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(destination.join(&name))
            .map_err(|_| "private continuation copy unavailable")?;
        std::io::copy(&mut input, &mut output).map_err(|_| "private continuation copy failed")?;
        output
            .sync_all()
            .map_err(|_| "private continuation copy durability failed")?;
    }
    let (copied_seed, copied_genesis) = bound_custody(destination)?;
    if copied_seed.as_ref() != seed.as_ref() || copied_genesis != encoded {
        return Err("copied rehearsal custody or genesis changed during freeze".into());
    }
    let limits = Limits {
        max_leaves: 1_000_000,
        max_nullifiers: 1_000_000,
        max_component_bytes: 64 * 1024 * 1024,
    };
    let verifier = NativeVerifier::new()?;
    let store = Store::audit_existing(
        &destination.join("chain.redb"),
        Genesis::decode(&encoded)?,
        limits,
        &verifier,
    )?;
    if store.engine().state().height() != PREFIX {
        return Err("native-audited continuation prefix differs from 24 blocks".into());
    }
    private_write(
        &destination.join("continuation-prefix.json"),
        &serde_json::to_vec(&json!({
            "scope":"copied-synthetic-rehearsal", "native_prefix_audit":"passed", "height":"24",
            "tip":crate::local::hex(&store.engine().state().tip()), "reused_native_proofs":"24",
            "source_modified":false, "custody_exported":false
        }))
        .map_err(|_| "continuation receipt encoding failed")?,
    )?;
    execute(destination, FINAL, seed, encoded, store, verifier, PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuation_rejects_unrelated_custody_and_existing_destinations_without_proving() {
        let source = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("eng2-continuation-{}", std::process::id()));
        let destination = source.join("copy");
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&source).unwrap();
        private_write(&source.join("rehearsal.seed"), &[1; 32]).unwrap();
        let network = blake3::derive_key("siworld eng2 offline rehearsal network v1", &[2; 32]);
        private_write(
            &source.join("genesis.bin"),
            &genesis(&[2; 32], network).unwrap().encode().unwrap(),
        )
        .unwrap();
        assert!(
            check_continuation(&source, &destination)
                .err()
                .unwrap()
                .contains("internally generated synthetic rehearsal")
        );
        assert!(!destination.exists());
        std::fs::create_dir(&destination).unwrap();
        assert!(check_continuation(&source, &destination).is_err());
        std::fs::remove_dir_all(source).unwrap();
    }
}
