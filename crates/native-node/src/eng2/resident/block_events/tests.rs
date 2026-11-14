use super::*;
use std::sync::atomic::AtomicU64;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "native-block-events-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        #[cfg(windows)]
        siworld_miner_platform::Directory::create(&path).unwrap();
        #[cfg(not(windows))]
        {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&path).unwrap();
        }
        Self(path)
    }
    fn recorder(&self) -> Recorder {
        Recorder::new(
            &self.0,
            [1; 32],
            [2; 32],
            Some([3; 32]),
            &"4".repeat(64),
            &"5".repeat(64),
        )
    }
    fn records(&self) -> Vec<Value> {
        let mut records = Vec::new();
        for index in 0..SEGMENTS {
            if let Ok(bytes) = fs::read(path(&self.0, index)) {
                for line in bytes
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                {
                    records.push(serde_json::from_slice(line).unwrap());
                }
            }
        }
        records
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn event_types_keep_fixed_process_bindings_and_distinct_sequences() {
    let directory = Directory::new();
    let recorder = directory.recorder();
    recorder.record(Kind::Produced, 7, Some([6; 32]), Some(123), "10".into());
    recorder.record(Kind::Accepted, 7, Some([6; 32]), Some(124), "20".into());
    recorder.finish();
    let records = directory.records();
    assert_eq!(records.len(), 4);
    assert_eq!(records[0]["kind"], "native-event-stream-start");
    assert_eq!(records[1]["kind"], "native-block-produced");
    assert_eq!(records[2]["kind"], "native-block-durably-accepted");
    assert_eq!(records[1]["sequence"], 1);
    assert_eq!(records[2]["sequence"], 2);
    assert_ne!(
        records[1]["deduplication_key"],
        records[2]["deduplication_key"]
    );
    for event in &records[1..3] {
        assert_eq!(event["node_id"], "03".repeat(32));
        assert_eq!(event["run_id"], "4".repeat(64));
        assert_eq!(event["binary_sha256"], "5".repeat(64));
        assert_eq!(event["source_commit_externally_verified"], false);
        assert!(serde_json::to_vec(event).unwrap().len() < RECORD_BYTES);
        let keys = event.as_object().unwrap();
        assert!(keys.keys().all(|key| {
            [
                "version",
                "record",
                "event_source",
                "kind",
                "network_id",
                "genesis_id",
                "source_commit",
                "source_commit_origin",
                "source_commit_externally_verified",
                "binary_sha256",
                "node_id",
                "run_id",
                "sequence",
                "block_id",
                "height",
                "event_unix_ms",
                "elapsed_monotonic_ns",
                "clock_offset_ms",
                "clock_uncertainty_ms",
                "clock_calibration_measured",
                "deduplication_key",
                "produced_unix_ms",
                "accepted_unix_ms",
            ]
            .contains(&key.as_str())
        }));
    }
    assert_eq!(records[3]["kind"], "native-event-stream-end");
    assert_eq!(records[3]["event_attempts"], 2);
    assert_eq!(records[3]["written_events"], 2);
    assert_eq!(records[3]["dropped_events"], 0);
    assert_eq!(recorder.diagnostic()["stream_end_written"], true);
    assert_eq!(recorder.diagnostic()["coverage_established"], false);
}

#[test]
fn segment_rotation_has_fixed_file_and_byte_limits() {
    let directory = Directory::new();
    let mut ring = Ring::open(&directory.0, 128).unwrap();
    for _ in 0..32 {
        ring.append(b"{\"sample\":\"bounded synthetic transport-free record\"}\n")
            .unwrap();
    }
    assert!(ring.rollovers > SEGMENTS as u64);
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), SEGMENTS);
    for index in 0..SEGMENTS {
        assert!(fs::metadata(path(&directory.0, index)).unwrap().len() <= 128);
    }
}

#[test]
fn changed_file_disables_recording_and_preserves_loss_counters() {
    let directory = Directory::new();
    let recorder = directory.recorder();
    recorder
        .state
        .lock()
        .unwrap()
        .log
        .as_ref()
        .unwrap()
        .file
        .set_len(1)
        .unwrap();
    recorder.record(Kind::Accepted, 1, Some([6; 32]), Some(123), "1".into());
    recorder.record(Kind::Accepted, 2, Some([7; 32]), Some(124), "2".into());
    recorder.finish();
    let diagnostic = recorder.diagnostic();
    assert_eq!(diagnostic["enabled"], false);
    assert_eq!(diagnostic["error_code"], "native_event_log_changed");
    assert_eq!(diagnostic["event_attempts"], 2);
    assert_eq!(diagnostic["written_events"], 0);
    assert_eq!(diagnostic["dropped_events"], 2);
    assert_eq!(diagnostic["stream_end_written"], false);
    assert_eq!(fs::metadata(path(&directory.0, 0)).unwrap().len(), 1);
}

#[test]
fn oversized_previous_log_is_rejected_without_truncation() {
    let directory = Directory::new();
    let file = open_slot(&directory.0, 0, true).unwrap();
    file.set_len(SEGMENT_BYTES + 1).unwrap();
    drop(file);
    let recorder = directory.recorder();
    assert_eq!(
        recorder.diagnostic()["error_code"],
        "native_event_existing_log_rejected"
    );
    assert_eq!(
        fs::metadata(path(&directory.0, 0)).unwrap().len(),
        SEGMENT_BYTES + 1
    );
    assert_eq!(recorder.diagnostic()["stream_start_written"], false);
}

#[test]
fn new_run_uses_a_fresh_slot_after_an_interrupted_record() {
    let directory = Directory::new();
    let mut file = open_slot(&directory.0, 0, true).unwrap();
    file.write_all(b"{\"interrupted\":").unwrap();
    drop(file);
    let recorder = directory.recorder();
    recorder.finish();
    assert_eq!(
        fs::read(path(&directory.0, 0)).unwrap(),
        b"{\"interrupted\":"
    );
    let bytes = fs::read(path(&directory.0, 1)).unwrap();
    let markers: Vec<Value> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(markers.len(), 2);
    assert_eq!(markers[1]["event_attempts"], 0);
    assert_eq!(recorder.diagnostic()["stream_end_written"], true);
}

#[test]
fn mismatched_header_context_cannot_be_recorded_as_acceptance() {
    let directory = Directory::new();
    let recorder = directory.recorder();
    let header = Header {
        network: [9; 32],
        height: 1,
        parent: [0; 32],
        timestamp: 1,
        target: [1; 32],
        execution_commitment: [2; 32],
        body_commitment: [3; 32],
        nonce: 0,
    };
    recorder.committed(&header);
    assert_eq!(recorder.diagnostic()["written_events"], 0);
    assert_eq!(recorder.diagnostic()["dropped_events"], 1);
    assert_eq!(
        recorder.diagnostic()["error_code"],
        "native_event_header_unavailable"
    );
}

#[test]
fn unknown_clock_and_duplicate_logical_keys_remain_explicit() {
    let directory = Directory::new();
    let recorder = directory.recorder();
    recorder.record(Kind::Accepted, 1, Some([6; 32]), None, "1".into());
    recorder.record(Kind::Accepted, 1, Some([6; 32]), None, "2".into());
    let records = directory.records();
    assert!(records[1]["accepted_unix_ms"].is_null());
    assert!(records[1]["clock_offset_ms"].is_null());
    assert!(records[1]["clock_uncertainty_ms"].is_null());
    assert_eq!(records[1]["clock_calibration_measured"], false);
    assert_eq!(
        records[1]["deduplication_key"],
        records[2]["deduplication_key"]
    );
    assert_ne!(records[1]["sequence"], records[2]["sequence"]);
    assert_eq!(recorder.diagnostic()["stream_end_written"], false);
}

#[test]
fn missing_runtime_identity_leaves_observation_unavailable() {
    let directory = Directory::new();
    let recorder = Recorder::new(
        &directory.0,
        [1; 32],
        [2; 32],
        None,
        &"4".repeat(64),
        &"5".repeat(64),
    );
    assert_eq!(recorder.diagnostic()["enabled"], false);
    assert_eq!(
        recorder.diagnostic()["error_code"],
        "native_event_binding_unavailable"
    );
    assert_eq!(recorder.diagnostic()["stream_start_written"], false);
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
}
