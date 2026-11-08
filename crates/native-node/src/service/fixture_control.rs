//! Owner-authorized, run-local admission for one checkpoint recovery fixture.
//! Public descriptors are checked in full before existing pinned transport is
//! used. No endpoint, listener, durable pin or checkpoint authority is created.
use super::*;
use crate::identity::{Descriptor, PeerPin};
use crate::p2p::{Binding, ExpectedPeer, Role};

const REQUEST: &str = "checkpoint-fixture-admission-request.json";
const RECEIPT: &str = "checkpoint-fixture-admission-receipt.json";
const STATUS: &str = "checkpoint-fixture-admission-status.json";
const KIND: &str = "checkpoint-recovery";
const REQUEST_AGE_MS: u64 = 60_000;

#[derive(Clone)]
pub(super) struct FixtureAdmission {
    expected: ExpectedPeer,
    specimen: String,
    descriptor_sha256: String,
}
impl FixtureAdmission {
    pub(super) fn expected(&self, fingerprint: Hash) -> Option<ExpectedPeer> {
        (self.expected.fingerprint() == fingerprint).then(|| self.expected.clone())
    }
    pub(super) fn permits_role(&self, fingerprint: Hash, role: Role) -> bool {
        self.expected.fingerprint() == fingerprint && role == Role::Validator
    }
    pub(super) fn status(&self) -> Value {
        json!({"fixture_kind":KIND,"specimen_id":self.specimen,
            "fingerprint":local::hex(&self.expected.fingerprint()),
            "descriptor_sha256":self.descriptor_sha256,"dial":false,
            "required_remote_role":"validator","run_local":true})
    }
}

fn specimen_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
fn decode_hex(value: &str, length: usize) -> Result<Vec<u8>, String> {
    if value.len() != 2 * length {
        return Err("invalid public fixture record length".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            Some((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "invalid public fixture record encoding".into())
}
fn verified_public(value: &Value, binding: Binding) -> Result<ExpectedPeer, String> {
    if !value.as_object().is_some_and(|object| object.len() == 3)
        || value["version"] != crate::identity::VERSION
    {
        return Err("complete public fixture identity required".into());
    }
    let fingerprint = decode_hex(
        value["fingerprint"]
            .as_str()
            .ok_or("fixture fingerprint required")?,
        32,
    )?;
    let bytes = decode_hex(
        value["descriptor"]
            .as_str()
            .ok_or("fixture descriptor required")?,
        crate::identity::DESCRIPTOR_BYTES,
    )?;
    // Descriptor decoding checks the network, genesis and verifier binding and
    // both Ed25519 and ML-DSA possession signatures. Its self-signature is not
    // a trust source: only this checked, owner-only request grants admission.
    let descriptor = Descriptor::decode(&bytes, &binding)
        .map_err(|_| "public fixture descriptor verification rejected")?;
    if descriptor.encode().as_slice() != bytes || descriptor.fingerprint().as_slice() != fingerprint
    {
        return Err("public fixture fingerprint mismatch".into());
    }
    let pin = PeerPin::from_trusted_descriptor(&descriptor, &binding)
        .map_err(|_| "public fixture pin rejected")?;
    ExpectedPeer::from_pinned_descriptor(binding, descriptor, pin)
        .map_err(|_| "public fixture identity mismatch".into())
}
fn fresh_run(directory: &Path, expected_run_id: &str) -> Result<(), String> {
    if !hash_text(expected_run_id) {
        return Err("complete provider run identity required".into());
    }
    check_directory(directory)?;
    let status = exported_status(directory)?;
    let now = wall_ms()?;
    let updated = status["updated_unix_ms"]
        .as_u64()
        .ok_or("provider time unavailable")?;
    if active_run(&status)? != expected_run_id
        || status["phase"] != "networking"
        || updated > now.saturating_add(1000)
        || now.saturating_sub(updated) > 15_000
    {
        return Err("fresh networking status for the selected provider run required".into());
    }
    Ok(())
}

/// The operator must independently verify the complete public fingerprint.
/// This operation neither opens a store nor reads or exports identity secrets.
pub fn request_fixture_admission(
    directory: &Path,
    expected_run_id: &str,
    specimen: &str,
    descriptor_file: &Path,
    fingerprint: &str,
) -> Result<(), String> {
    fresh_run(directory, expected_run_id)?;
    if !specimen_id(specimen) || !hash_text(fingerprint) {
        return Err("registered specimen and complete checked fingerprint required".into());
    }
    let mut bytes = Vec::new();
    local::regular_read(descriptor_file, false, 32_768)?
        .take(32_769)
        .read_to_end(&mut bytes)
        .map_err(|_| "public fixture identity unavailable")?;
    if bytes.len() > 32_768 {
        return Err("public fixture identity byte limit".into());
    }
    let public: Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid public fixture identity")?;
    if public["fingerprint"] != fingerprint {
        return Err("public fixture and independently checked fingerprint differ".into());
    }
    let binding = Binding::new(&local::load(directory)?);
    let expected = verified_public(&public, binding)?;
    let digest = local::hex(&Sha256::digest(expected.descriptor().encode()));
    // A write-once intent cannot silently replace a pending admission. An
    // uncertain command is reconciled from the owner receipt and live status.
    write_once(
        &directory.join(REQUEST),
        &json!({"schema":1,"run_id":expected_run_id,"fixture_kind":KIND,
            "specimen_id":specimen,"public":public,"descriptor_sha256":digest,
            "mining":false,"inbound_listening":false,"coordinator_authority":false,
            "created_unix_ms":wall_ms()?}),
    )
}

fn decode_request(
    value: &Value,
    binding: Binding,
    local_id: Hash,
    run_id: &str,
    now: u64,
) -> Result<FixtureAdmission, String> {
    let created = value["created_unix_ms"]
        .as_u64()
        .ok_or("fixture request time required")?;
    if !value.as_object().is_some_and(|object| object.len() == 10)
        || value["schema"] != 1
        || value["run_id"] != run_id
        || value["fixture_kind"] != KIND
        || value["mining"] != false
        || value["inbound_listening"] != false
        || value["coordinator_authority"] != false
        || created > now.saturating_add(1000)
        || now.saturating_sub(created) > REQUEST_AGE_MS
    {
        return Err("run-bound public fixture request rejected".into());
    }
    let specimen = value["specimen_id"]
        .as_str()
        .filter(|v| specimen_id(v))
        .ok_or("registered fixture specimen required")?;
    let expected = verified_public(&value["public"], binding)?;
    let digest = local::hex(&Sha256::digest(expected.descriptor().encode()));
    if expected.fingerprint() == local_id || value["descriptor_sha256"] != digest {
        return Err("public fixture descriptor binding rejected".into());
    }
    Ok(FixtureAdmission {
        expected,
        specimen: specimen.into(),
        descriptor_sha256: digest,
    })
}

/// Only the canonical owner calls the installation closure. Existing pins,
/// workers and scheduler generations remain unchanged. Admission is held only
/// in this Driver run; request or receipt files are never loaded on restart.
pub(super) fn poll(
    directory: &Path,
    run_id: &str,
    binding: Binding,
    local_id: Hash,
    eligible_provider: bool,
    slot: &mut Option<FixtureAdmission>,
    mut install: impl FnMut(&ExpectedPeer) -> Result<(), String>,
) {
    let path = directory.join(REQUEST);
    if !path.exists() {
        publish_status(directory, run_id, eligible_provider, slot.as_ref());
        return;
    }
    let mut admitted = Value::Null;
    let result = (|| -> Result<&'static str, String> {
        let value = read_json(&path)?;
        // Only a checked, owned private regular file can be consumed. Rejected
        // requests and receipt failures must not interrupt chain validation.
        fs::remove_file(&path).map_err(|_| "fixture request consumption failed")?;
        let request = decode_request(&value, binding, local_id, run_id, wall_ms()?)?;
        if !eligible_provider {
            return Ok("provider_unavailable");
        }
        if let Some(previous) = slot {
            return Ok(if previous.status() == request.status() {
                admitted = previous.status();
                "already_admitted"
            } else {
                "slot_occupied"
            });
        }
        install(&request.expected)?;
        admitted = request.status();
        *slot = Some(request);
        Ok("admitted")
    })();
    let outcome = result.unwrap_or("request_rejected");
    let _ = atomic_json(
        &directory.join(RECEIPT),
        &json!({"schema":1,"run_id":run_id,"outcome":outcome,"admission":admitted,
            "updated_unix_ms":wall_ms().ok()}),
    );
    publish_status(directory, run_id, eligible_provider, slot.as_ref());
}

fn publish_status(directory: &Path, run_id: &str, eligible: bool, slot: Option<&FixtureAdmission>) {
    // Keep the established service/network status schema unchanged. This
    // independent observation binds the ephemeral owner slot to its live run.
    let _ = atomic_json(
        &directory.join(STATUS),
        &json!({"schema":1,"run_id":run_id,
        "eligible_provider":eligible,"admission":slot.map(FixtureAdmission::status),
        "updated_unix_ms":wall_ms().ok()}),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NativeIdentity;
    use crate::state::Config;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "siworld-fixture-admission-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            local::initialize_config(&path, config()).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn config() -> Config {
        Config::development([211; 32], 0).unwrap()
    }
    fn public(directory: &Path, binding: Binding) -> Value {
        let identity = NativeIdentity::initialize(directory, binding).unwrap();
        let descriptor = identity.descriptor().unwrap();
        json!({"version":1,"fingerprint":local::hex(&descriptor.fingerprint()),
            "descriptor":local::hex(&descriptor.encode())})
    }
    fn request(public: &Value, run: &str, now: u64) -> Value {
        let expected = verified_public(public, Binding::new(&config())).unwrap();
        json!({"schema":1,"run_id":run,"fixture_kind":KIND,
            "specimen_id":"recovery-test","public":public,
            "descriptor_sha256":local::hex(&Sha256::digest(expected.descriptor().encode())),
            "mining":false,"inbound_listening":false,"coordinator_authority":false,
            "created_unix_ms":now})
    }
    #[test]
    fn full_dual_descriptor_binding_is_required() {
        let fixture = Directory::new();
        let binding = Binding::new(&config());
        let original = public(&fixture.0, binding);
        let mut value = original.clone();
        value["fingerprint"] = Value::String("a".repeat(64));
        assert!(verified_public(&value, binding).is_err());
        for offset in [0, 6, 102, 134, 2086, crate::identity::DESCRIPTOR_BYTES - 1] {
            let mut value = original.clone();
            let mut bytes = decode_hex(
                value["descriptor"].as_str().unwrap(),
                crate::identity::DESCRIPTOR_BYTES,
            )
            .unwrap();
            bytes[offset] ^= 1;
            value["descriptor"] = Value::String(local::hex(&bytes));
            assert!(verified_public(&value, binding).is_err(), "offset {offset}");
        }
        let wrong = Binding::new(&Config::development([212; 32], 0).unwrap());
        assert!(verified_public(&original, wrong).is_err());
        let mut value = original.clone();
        value["descriptor"] = Value::String(value["descriptor"].as_str().unwrap().to_uppercase());
        assert!(verified_public(&value, binding).is_err());
        let mut value = original;
        value["extra"] = true.into();
        assert!(verified_public(&value, binding).is_err());
    }
    #[test]
    fn old_runs_times_roles_and_ambiguous_requests_are_rejected() {
        let fixture = Directory::new();
        let binding = Binding::new(&config());
        let p = public(&fixture.0, binding);
        let run = "a".repeat(64);
        let now = 100_000;
        let base = request(&p, &run, now);
        assert!(decode_request(&base, binding, [1; 32], &run, now).is_ok());
        for (field, changed) in [
            ("run_id", json!("b".repeat(64))),
            ("fixture_kind", json!("peer")),
            ("mining", json!(true)),
            ("inbound_listening", json!(true)),
            ("coordinator_authority", json!(true)),
            ("created_unix_ms", json!(now - 60_001)),
            ("created_unix_ms", json!(now + 1001)),
            ("specimen_id", json!("../escape")),
            ("descriptor_sha256", json!("0".repeat(64))),
            ("extra", json!(1)),
        ] {
            let mut value = base.clone();
            value[field] = changed;
            assert!(
                decode_request(&value, binding, [1; 32], &run, now).is_err(),
                "{field}"
            );
        }
        let expected = verified_public(&p, binding).unwrap();
        assert!(decode_request(&base, binding, expected.fingerprint(), &run, now).is_err());
    }
    #[test]
    fn one_run_local_slot_is_idempotent_and_never_replaced() {
        let provider = Directory::new();
        let fixture = Directory::new();
        let binding = Binding::new(&config());
        let p = public(&fixture.0, binding);
        let run = "a".repeat(64);
        let mut slot = None;
        let mut installs = 0;
        for expected_outcome in ["admitted", "already_admitted", "slot_occupied"] {
            let mut value = request(&p, &run, wall_ms().unwrap());
            if expected_outcome == "slot_occupied" {
                value["specimen_id"] = json!("other-test");
            }
            write_once(&provider.0.join(REQUEST), &value).unwrap();
            poll(&provider.0, &run, binding, [1; 32], true, &mut slot, |_| {
                installs += 1;
                Ok(())
            });
            let result = read_json(&provider.0.join(RECEIPT)).unwrap();
            assert_eq!(result["outcome"], expected_outcome);
            assert!(!provider.0.join(REQUEST).exists());
        }
        assert_eq!(installs, 1);
        let admitted = slot.unwrap();
        let fingerprint = verified_public(&p, binding).unwrap().fingerprint();
        assert!(admitted.expected(fingerprint).is_some());
        assert!(admitted.expected([2; 32]).is_none());
        assert!(admitted.permits_role(fingerprint, Role::Validator));
        assert!(!admitted.permits_role(fingerprint, Role::Miner));
        assert!(
            !provider
                .0
                .join(format!("peer-{}.pin", local::hex(&fingerprint)))
                .exists()
        );
        assert!(!provider.0.join("native-peer-identity.secret").exists());
    }
    #[test]
    fn rejected_requests_and_resource_failure_do_not_install_or_abort() {
        let provider = Directory::new();
        let fixture = Directory::new();
        let binding = Binding::new(&config());
        let p = public(&fixture.0, binding);
        let run = "a".repeat(64);
        let mut slot = None;
        for (eligible, wrong_run, expected_outcome) in [
            (false, false, "provider_unavailable"),
            (true, true, "request_rejected"),
            (true, false, "request_rejected"),
        ] {
            let value = request(
                &p,
                if wrong_run { "wrong-run" } else { &run },
                wall_ms().unwrap(),
            );
            write_once(&provider.0.join(REQUEST), &value).unwrap();
            poll(
                &provider.0,
                &run,
                binding,
                [1; 32],
                eligible,
                &mut slot,
                |_| Err("capacity".into()),
            );
            assert!(slot.is_none());
            assert_eq!(
                read_json(&provider.0.join(RECEIPT)).unwrap()["outcome"],
                expected_outcome
            );
        }
    }
    #[test]
    fn writer_requires_fresh_selected_run_and_independent_fingerprint() {
        let provider = Directory::new();
        let fixture = Directory::new();
        let binding = Binding::new(&config());
        let p = public(&fixture.0, binding);
        let run = "a".repeat(64);
        let public_file = fixture.0.join("public.json");
        atomic_json(&public_file, &p).unwrap();
        let fingerprint = p["fingerprint"].as_str().unwrap();
        for (phase, updated, selected) in [
            ("starting", wall_ms().unwrap(), run.clone()),
            ("networking", 1, run.clone()),
            ("networking", wall_ms().unwrap(), "b".repeat(64)),
        ] {
            atomic_json(
                &provider.0.join(STATUS_FILE),
                &json!({"run_id":run,"phase":phase,"updated_unix_ms":updated}),
            )
            .unwrap();
            assert!(
                request_fixture_admission(
                    &provider.0,
                    &selected,
                    "recovery-test",
                    &public_file,
                    fingerprint
                )
                .is_err()
            );
            assert!(!provider.0.join(REQUEST).exists());
        }
        atomic_json(
            &provider.0.join(STATUS_FILE),
            &json!({"run_id":run,"phase":"networking","updated_unix_ms":wall_ms().unwrap()}),
        )
        .unwrap();
        assert!(
            request_fixture_admission(
                &provider.0,
                &run,
                "recovery-test",
                &public_file,
                &"0".repeat(64)
            )
            .is_err()
        );
        request_fixture_admission(
            &provider.0,
            &run,
            "recovery-test",
            &public_file,
            fingerprint,
        )
        .unwrap();
        assert!(
            request_fixture_admission(
                &provider.0,
                &run,
                "recovery-test",
                &public_file,
                fingerprint
            )
            .is_err()
        );
    }
    #[test]
    fn scheduler_admission_preserves_existing_attempt_and_capacity() {
        use crate::p2p::Budget;
        use crate::peer_scheduler::{Direction, Error, Failure, MAX_PEERS, Scheduler};
        let mut scheduler = Scheduler::new([1; 32], &[[2; 32]], Budget::default(), 0).unwrap();
        let established = scheduler
            .begin([2; 32], Direction::Outbound, 1)
            .unwrap()
            .token;
        scheduler.authenticated(established, 2).unwrap();
        scheduler.admit_fixture([3; 32], 3).unwrap();
        assert_eq!(scheduler.status().configured, 2);
        assert_eq!(scheduler.status().established, 1);
        assert_eq!(
            scheduler.admit_fixture([3; 32], 4),
            Err(Error::InvalidIdentity)
        );
        scheduler
            .closed(established, Failure::Unavailable, 5)
            .unwrap();
        assert_eq!(scheduler.status().established, 0);
        let mut exhausted = Scheduler::new([1; 32], &[], Budget::new(0), 0).unwrap();
        assert_eq!(exhausted.admit_fixture([2; 32], 1), Err(Error::Capacity));
        assert_eq!(exhausted.status().configured, 0);
        let peers = (2..MAX_PEERS + 2)
            .map(|i| [i as u8; 32])
            .collect::<Vec<_>>();
        let mut full = Scheduler::new([1; 32], &peers, Budget::default(), 0).unwrap();
        assert_eq!(full.admit_fixture([99; 32], 1), Err(Error::Capacity));
        assert_eq!(full.status().configured, MAX_PEERS);
    }
    #[cfg(unix)]
    #[test]
    fn symlink_or_shared_requests_cannot_install_a_fixture() {
        use std::os::unix::{fs::PermissionsExt, fs::symlink};
        let provider = Directory::new();
        let fixture = Directory::new();
        let binding = Binding::new(&config());
        let p = public(&fixture.0, binding);
        let run = "a".repeat(64);
        let external = fixture.0.join("request.json");
        write_once(&external, &request(&p, &run, wall_ms().unwrap())).unwrap();
        symlink(&external, provider.0.join(REQUEST)).unwrap();
        let mut slot = None;
        poll(&provider.0, &run, binding, [1; 32], true, &mut slot, |_| {
            panic!("untrusted request installed")
        });
        assert!(slot.is_none());
        assert!(external.exists());
        assert!(provider.0.join(REQUEST).is_symlink());
        fs::remove_file(provider.0.join(REQUEST)).unwrap();
        write_once(
            &provider.0.join(REQUEST),
            &request(&p, &run, wall_ms().unwrap()),
        )
        .unwrap();
        fs::set_permissions(provider.0.join(REQUEST), fs::Permissions::from_mode(0o644)).unwrap();
        poll(&provider.0, &run, binding, [1; 32], true, &mut slot, |_| {
            panic!("shared request installed")
        });
        assert!(slot.is_none());
        assert!(provider.0.join(REQUEST).exists());
    }
}
