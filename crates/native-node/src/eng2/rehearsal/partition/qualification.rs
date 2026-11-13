//! Explicit source-bound qualification of unchanged nonfixture native history.
use super::*;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

pub(super) const AUDIT_SCOPE: &str = "read-only-owner-nonfixture-native-audit";
const MAX_BINDING_BYTES: usize = 8192;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    version: u32,
    network_id: String,
    genesis_id: String,
    rules_commitment: String,
    proof_profile: String,
    source_commit: String,
    binary_sha256: String,
}

pub(super) struct Context {
    binding: Binding,
    binding_sha256: String,
}

fn lower_hex(text: &str, bytes: usize) -> bool {
    text.len() == bytes * 2
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && text.bytes().any(|b| b != b'0')
}

fn parse(bytes: &[u8]) -> Result<Binding, String> {
    let binding: Binding =
        serde_json::from_slice(bytes).map_err(|_| "qualification binding schema rejected")?;
    if binding.version != 1
        || [
            &binding.network_id,
            &binding.genesis_id,
            &binding.rules_commitment,
            &binding.proof_profile,
            &binding.binary_sha256,
        ]
        .into_iter()
        .any(|value| !lower_hex(value, 32))
        || !lower_hex(&binding.source_commit, 20)
    {
        return Err("qualification binding identities rejected".into());
    }
    Ok(binding)
}

impl Context {
    pub(super) fn load(path: &Path, pin: &str) -> Result<Self, String> {
        owner_local()?;
        let bytes = bounded_bytes(path, MAX_BINDING_BYTES)?;
        if !lower_hex(pin, 32) || crate::local::hex(&Sha256::digest(&bytes)) != pin {
            return Err("independent qualification binding SHA-256 differs".into());
        }
        let binding = parse(&bytes)?;
        // A declaration is a binding, not independent build provenance. The
        // owner must separately verify the source archive and build manifest.
        if option_env!("SIWORLD_BUILD_COMMIT") != Some(binding.source_commit.as_str()) {
            return Err("compiled source declaration absent or different".into());
        }
        if crate::local::hex(&crate::eng2::genesis_tool::executable_sha256()?)
            != binding.binary_sha256
        {
            return Err("qualification executable SHA-256 differs".into());
        }
        if crate::local::hex(&crate::proofs::protocol_profile_fingerprint())
            != binding.proof_profile
        {
            return Err("qualification compiled proof profile differs".into());
        }
        Ok(Self {
            binding,
            binding_sha256: pin.into(),
        })
    }

    pub(super) fn check_genesis(&self, selected: &Genesis) -> Result<(), String> {
        if selected.config().fixture
            || selected.config().pow_iterations == 0
            || crate::local::hex(&selected.config().network) != self.binding.network_id
            || crate::local::hex(&selected.id()) != self.binding.genesis_id
            || crate::local::hex(&selected.rules_commitment()) != self.binding.rules_commitment
        {
            return Err("qualification requires the pinned nonfixture native genesis".into());
        }
        Ok(())
    }

    pub(super) fn check_manifest_pin(&self, bytes: &[u8], pin: &str) -> Result<(), String> {
        if !lower_hex(pin, 32) || crate::local::hex(&Sha256::digest(bytes)) != pin {
            return Err("qualification source manifest SHA-256 differs".into());
        }
        Ok(())
    }

    pub(super) fn check_manifest(&self, manifest: &Value) -> Result<(), String> {
        let source = &manifest["qualification"];
        if manifest["scope"] != AUDIT_SCOPE
            || source["network_id"] != self.binding.network_id
            || source["genesis_id"] != self.binding.genesis_id
            || source["rules_commitment"] != self.binding.rules_commitment
            || source["proof_profile"] != self.binding.proof_profile
            || source["source_commit"] != self.binding.source_commit
            || source["source_commit_origin"] != "compile-time-declaration"
            || source["source_commit_externally_verified"] != false
            || !source["binary_sha256"]
                .as_str()
                .is_some_and(|s| lower_hex(s, 32))
            || !source["binding_sha256"]
                .as_str()
                .is_some_and(|s| lower_hex(s, 32))
        {
            return Err("qualification manifest source binding differs".into());
        }
        // Executables built from the same source may differ (audit CLI versus
        // a test harness). The independently pinned manifest retains the audit
        // executable; this invocation independently pins its own executable.
        Ok(())
    }

    pub(super) fn receipt(&self) -> Value {
        json!({"source_commit":self.binding.source_commit,
            "source_commit_origin":"compile-time-declaration",
            "source_commit_externally_verified":false,
            "binary_sha256":self.binding.binary_sha256,
            "binding_sha256":self.binding_sha256,
            "network_id":self.binding.network_id,"genesis_id":self.binding.genesis_id,
            "rules_commitment":self.binding.rules_commitment,"proof_profile":self.binding.proof_profile})
    }
}

fn source_path(source: &Path) -> Result<(), String> {
    if source.canonicalize().ok().as_deref() != Some(source) {
        return Err("qualification source must be a canonical absolute directory".into());
    }
    Ok(())
}

/// Read-only full native history audit under the stopped source's service lease.
/// This does not authenticate its accepted-state seal or modify the source DB.
pub fn audit(directory: &Path, output: &Path, binding: &Path, pin: &str) -> Result<Value, String> {
    let context = Context::load(binding, pin)?;
    source_path(directory)?;
    super::audit::audit_inner(directory, output, Some(&context))
}

/// Populate an authenticated empty stopped node by ordinary verified append.
/// No resident starts and no synthetic production marker is created or accepted.
pub fn replay_prefix(
    source: &Path,
    source_pin: &str,
    directory: &Path,
    height: u64,
    binding: &Path,
    pin: &str,
) -> Result<Value, String> {
    let context = Context::load(binding, pin)?;
    source_path(source)?;
    source_path(directory)?;
    super::replay::replay_prefix_inner(source, directory, height, Some((&context, source_pin)))
}

/// Switch authentic full-frame prefixes through the ordinary Driver/Store path.
/// This offline case proves neither peer healing nor a live resident crash.
#[cfg(unix)]
pub fn driver_case(
    sources: (&Path, &str, &Path, &str),
    directory: &Path,
    depth: u64,
    binding: &Path,
    pin: &str,
) -> Result<Value, String> {
    let context = Context::load(binding, pin)?;
    super::driver_case::driver_case_inner(sources, directory, depth, Some(&context))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value() -> Value {
        json!({"version":1,"network_id":"01".repeat(32),"genesis_id":"02".repeat(32),
            "rules_commitment":"03".repeat(32),"proof_profile":"04".repeat(32),
            "source_commit":"05".repeat(20),"binary_sha256":"06".repeat(32)})
    }
    fn context() -> Context {
        Context {
            binding: parse(&serde_json::to_vec(&value()).unwrap()).unwrap(),
            binding_sha256: "07".repeat(32),
        }
    }

    #[test]
    fn qualification_binding_rejects_unknown_duplicate_and_noncanonical_identities() {
        let original = value();
        assert!(parse(&serde_json::to_vec(&original).unwrap()).is_ok());
        for (field, replacement) in [
            ("version", json!(true)),
            ("version", json!(1.0)),
            ("network_id", json!("00".repeat(32))),
            ("binary_sha256", json!("AB".repeat(32))),
            ("source_commit", json!("05".repeat(32))),
        ] {
            let mut changed = original.clone();
            changed[field] = replacement;
            assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut private = original.clone();
        private["secret"] = json!("excluded");
        assert!(parse(&serde_json::to_vec(&private).unwrap()).is_err());
        let duplicate = format!(
            "{{\"version\":1,{}",
            &serde_json::to_string(&original).unwrap()[1..]
        );
        assert!(parse(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn qualification_manifest_keeps_source_and_independent_artifact_bindings() {
        let context = context();
        let mut manifest = json!({"scope":AUDIT_SCOPE,"qualification":context.receipt()});
        assert!(context.check_manifest(&manifest).is_ok());
        // A distinct same-source audit executable is permitted only as a
        // recorded identity within an independently SHA-pinned source manifest.
        manifest["qualification"]["binary_sha256"] = json!("08".repeat(32));
        assert!(context.check_manifest(&manifest).is_ok());
        manifest["qualification"]["source_commit"] = json!("09".repeat(20));
        assert!(context.check_manifest(&manifest).is_err());
        let mut synthetic = json!({"scope":"read-only-synthetic-native-partition-audit",
            "qualification":context.receipt()});
        assert!(context.check_manifest(&synthetic).is_err());
        synthetic["scope"] = json!(AUDIT_SCOPE);
        synthetic["qualification"]["binding_sha256"] = json!("00".repeat(32));
        assert!(context.check_manifest(&synthetic).is_err());
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let pin = crate::local::hex(&Sha256::digest(&bytes));
        assert!(context.check_manifest_pin(&bytes, &pin).is_ok());
        assert!(
            context
                .check_manifest_pin(&bytes, &"01".repeat(32))
                .is_err()
        );
    }
}
