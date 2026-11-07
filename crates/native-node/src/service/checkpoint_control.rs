//! Explicit, run-bound local activation after checkpoint recovery acceptance.
//! Network claims cannot create this owner-only operator request.
use super::*;
use crate::{runtime::Node, state::BlockVerifier};

const REQUEST: &str = "checkpoint-qualification-request.json";
const RECEIPT: &str = "checkpoint-qualification-receipt.json";
const SIGNING_REQUEST: &str = "checkpoint-signing-request.json";
const SIGNING_RECEIPT: &str = "checkpoint-signing-receipt.json";

pub fn request_checkpoint_qualification(
    directory: &Path,
    expected_run_id: &str,
) -> Result<(), String> {
    require_live_run(directory, expected_run_id)?;
    atomic_json(
        &directory.join(REQUEST),
        &json!({"schema":1,"run_id":expected_run_id}),
    )
}

fn require_live_run(directory: &Path, expected_run_id: &str) -> Result<(), String> {
    if !hash_text(expected_run_id) {
        return Err("expected a complete service run identity".into());
    }
    check_directory(directory)?;
    let status = exported_status(directory)?;
    let now = wall_ms()?;
    let updated = status["updated_unix_ms"]
        .as_u64()
        .ok_or("service observation time unavailable")?;
    if active_run(&status)? != expected_run_id
        || status["phase"] != "networking"
        || updated > now.saturating_add(1000)
        || now.saturating_sub(updated) > 15_000
    {
        return Err("fresh networking status for the expected run is required".into());
    }
    Ok(())
}

pub fn request_checkpoint_signing(
    directory: &Path,
    expected_run_id: &str,
    paused: bool,
) -> Result<(), String> {
    require_live_run(directory, expected_run_id)?;
    atomic_json(
        &directory.join(SIGNING_REQUEST),
        &json!({"schema":1,"run_id":expected_run_id,"signing_state":if paused {"paused"} else {"active"}}),
    )
}

/// Only the canonical owner changes signing intent. Rejected local requests
/// cannot stop validation, and a new run never loads intent from an old receipt.
pub(super) fn poll_signing(
    directory: &Path,
    run_id: &str,
    mut coordinator: Option<&mut crate::checkpoint_service::Coordinator>,
) {
    let path = directory.join(SIGNING_REQUEST);
    if !path.exists() {
        return;
    }
    let result = (|| -> Result<&'static str, String> {
        let value = read_json(&path)?;
        let paused = match value["signing_state"].as_str() {
            Some("paused") => Some(true),
            Some("active") => Some(false),
            _ => None,
        };
        let valid = value.as_object().is_some_and(|object| {
            object.len() == 3 && value["schema"] == 1 && value["run_id"] == run_id
        });
        fs::remove_file(&path).map_err(|_| "checkpoint signing request consumption failed")?;
        let Some(paused) = paused.filter(|_| valid) else {
            return Ok("request_rejected");
        };
        let Some(coordinator) = &mut coordinator else {
            return Ok("authority_unavailable");
        };
        if coordinator.set_signing_paused(paused).is_err() {
            return Ok("authority_unavailable");
        }
        Ok(if paused { "paused" } else { "active" })
    })();
    let outcome = result.unwrap_or("request_unavailable");
    let _ = atomic_json(
        &directory.join(SIGNING_RECEIPT),
        &json!({"schema":1,"run_id":run_id,"outcome":outcome,
            "signing_paused":coordinator.as_ref().map(|c| c.signing_paused()),
            "updated_unix_ms":wall_ms().ok()}),
    );
}

/// Malformed or rejected requests cannot interrupt canonical validation.
pub(super) fn poll<V: BlockVerifier>(directory: &Path, run_id: &str, node: &mut Node<V>) {
    let path = directory.join(REQUEST);
    if !path.exists() {
        return;
    }
    let result = (|| -> Result<&'static str, String> {
        let value = read_json(&path)?;
        let valid = value.as_object().is_some_and(|object| {
            object.len() == 2 && value["schema"] == 1 && value["run_id"] == run_id
        });
        // Consume only a checked private regular request, never a secret or
        // configuration file. A new run cannot inherit a previous run's intent.
        fs::remove_file(&path).map_err(|_| "checkpoint request consumption failed")?;
        if !valid {
            return Ok("request_rejected");
        }
        let now = wall_ms()? / 1000;
        Ok(if node.resident_checkpoint_qualify(now).is_ok() {
            "qualified"
        } else {
            "qualification_rejected"
        })
    })();
    let outcome = result.unwrap_or("request_unavailable");
    let _ = atomic_json(
        &directory.join(RECEIPT),
        &json!({"schema":1,"run_id":run_id,"outcome":outcome,
            "qualified":outcome=="qualified","updated_unix_ms":wall_ms().ok()}),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "siworld-checkpoint-control-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            create_directory(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn explicit_request_requires_the_selected_fresh_networking_run() {
        let directory = Directory::new();
        let run = "a".repeat(64);
        let status = directory.0.join(STATUS_FILE);
        for (selected, phase, updated) in [
            ("b".repeat(64), "networking", wall_ms().unwrap()),
            (run.clone(), "starting", wall_ms().unwrap()),
            (run.clone(), "networking", 1),
        ] {
            atomic_json(
                &status,
                &json!({"run_id":run,"phase":phase,"updated_unix_ms":updated}),
            )
            .unwrap();
            assert!(request_checkpoint_qualification(&directory.0, &selected).is_err());
            assert!(!directory.0.join(REQUEST).exists());
        }
        atomic_json(
            &status,
            &json!({"run_id":run,"phase":"networking","updated_unix_ms":wall_ms().unwrap()}),
        )
        .unwrap();
        request_checkpoint_qualification(&directory.0, &run).unwrap();
        assert_eq!(
            read_json(&directory.0.join(REQUEST)).unwrap()["run_id"],
            run
        );
    }

    #[test]
    fn old_or_unqualified_requests_never_replace_state_or_stop_validation() {
        let parent = Directory::new();
        let directory = parent.0.join("network");
        let config = local::initialize(&directory, 0).unwrap();
        let store = Store::open(
            directory.join("chain.redb"),
            config,
            &crate::fixtures::TestVerifier,
        )
        .unwrap();
        let fingerprint = store.state().fingerprint();
        let mut node = Node::new(store, crate::fixtures::TestVerifier);
        let run = "a".repeat(64);
        for (request_run, outcome) in [
            ("b".repeat(64), "request_rejected"),
            (run.clone(), "qualification_rejected"),
        ] {
            atomic_json(
                &directory.join(REQUEST),
                &json!({"schema":1,"run_id":request_run}),
            )
            .unwrap();
            poll(&directory, &run, &mut node);
            assert!(!directory.join(REQUEST).exists());
            let receipt = read_json(&directory.join(RECEIPT)).unwrap();
            assert_eq!(receipt["outcome"], outcome);
            assert_eq!(receipt["qualified"], false);
            assert_eq!(node.state().fingerprint(), fingerprint);
            assert_eq!(
                node.store().storage_metrics().unwrap()["policy_active"],
                false
            );
        }
    }

    #[test]
    fn signing_requests_are_run_bound_and_do_not_survive_restart() {
        use crate::{
            checkpoint_service::Coordinator, engineering_checkpoint::Roster,
            identity::checkpoint_authority::Authority, p2p::Binding,
        };
        let parent = Directory::new();
        let directory = parent.0.join("network");
        let second = parent.0.join("second-authority");
        let config = local::initialize(&directory, 0).unwrap();
        create_directory(&second).unwrap();
        let directory = directory.canonicalize().unwrap();
        let second = second.canonicalize().unwrap();
        let binding = Binding::new(&config);
        let a = Authority::initialize(&directory, binding).unwrap();
        let b = Authority::initialize(&second, binding).unwrap();
        let roster = Roster::new(binding, [a.public_key(), b.public_key()]).unwrap();
        let mut coordinator = Coordinator::for_test_signer(&directory, roster.clone(), a).unwrap();
        let run = "a".repeat(64);
        atomic_json(
            &directory.join(STATUS_FILE),
            &json!({"run_id":run,"phase":"networking","updated_unix_ms":wall_ms().unwrap()}),
        )
        .unwrap();
        assert!(request_checkpoint_signing(&directory, &"b".repeat(64), true).is_err());
        assert!(!directory.join(SIGNING_REQUEST).exists());
        for paused in [true, false, true] {
            request_checkpoint_signing(&directory, &run, paused).unwrap();
            poll_signing(&directory, &run, Some(&mut coordinator));
            assert!(!directory.join(SIGNING_REQUEST).exists());
            assert_eq!(coordinator.signing_paused(), paused);
            let receipt = read_json(&directory.join(SIGNING_RECEIPT)).unwrap();
            assert_eq!(receipt["run_id"], run);
            assert_eq!(receipt["signing_paused"], paused);
            assert_eq!(receipt["outcome"], if paused { "paused" } else { "active" });
        }
        drop(coordinator);
        let authority = Authority::load(&directory, binding).unwrap();
        let mut restarted = Coordinator::for_test_signer(&directory, roster, authority).unwrap();
        assert!(!restarted.signing_paused());
        // A pending old-run request cannot carry pause intent into the restart.
        request_checkpoint_signing(&directory, &run, true).unwrap();
        let next_run = "b".repeat(64);
        poll_signing(&directory, &next_run, Some(&mut restarted));
        assert!(!restarted.signing_paused());
        let receipt = read_json(&directory.join(SIGNING_RECEIPT)).unwrap();
        assert_eq!(receipt["run_id"], next_run);
        assert_eq!(receipt["outcome"], "request_rejected");
        assert_eq!(receipt["signing_paused"], false);
    }
}
