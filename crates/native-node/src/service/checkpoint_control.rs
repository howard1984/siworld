//! Explicit, run-bound local activation after checkpoint recovery acceptance.
//! Network claims cannot create this owner-only operator request.
use super::*;
use crate::{runtime::Node, state::BlockVerifier};

const REQUEST: &str = "checkpoint-qualification-request.json";
const RECEIPT: &str = "checkpoint-qualification-receipt.json";

pub fn request_checkpoint_qualification(
    directory: &Path,
    expected_run_id: &str,
) -> Result<(), String> {
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
    atomic_json(
        &directory.join(REQUEST),
        &json!({"schema":1,"run_id":expected_run_id}),
    )
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
}
