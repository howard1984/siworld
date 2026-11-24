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

#[test]
fn optional_header_and_template_events_do_not_claim_body_acceptance_or_measured_clock_error() {
    let directory = Directory::new();
    let recorder = directory.recorder();
    let header = Header {
        network: [1; 32],
        height: 1,
        parent: [2; 32],
        timestamp: 1,
        target: [255; 32],
        execution_commitment: [3; 32],
        body_commitment: [4; 32],
        nonce: 0,
    };
    recorder.header_qualified(&header);
    recorder.header_forwarded(&header);
    recorder.template_ready(&header, std::time::Duration::from_micros(123));
    recorder.finish();
    let records = directory.records();
    assert_eq!(records.len(), 5);
    assert_eq!(records[1]["kind"], "native-header-qualified");
    assert_eq!(records[2]["kind"], "native-header-forwarded");
    let template = &records[3];
    assert_eq!(template["assembly_excluding_pow_us"], 123);
    assert_eq!(template["parent_id"], "02".repeat(32));
    assert_eq!(template["body_commitment"], "04".repeat(32));
    assert_eq!(template["template_header_id_is_mined_block_id"], false);
    for event in &records[1..4] {
        assert!(event["accepted_unix_ms"].is_null());
        assert_eq!(event["clock_calibration_measured"], false);
        assert!(serde_json::to_vec(event).unwrap().len() < RECORD_BYTES);
    }
}

#[test]
fn optional_body_attempts_retain_actual_edges_and_failure_without_claiming_acceptance() {
    let directory = Directory::new();
    let recorder = directory.recorder();
    let header = Header {
        network: [1; 32],
        height: 9,
        parent: [2; 32],
        timestamp: 1,
        target: [255; 32],
        execution_commitment: [3; 32],
        body_commitment: [4; 32],
        nonce: 7,
    };
    let start = recorder.started + std::time::Duration::from_nanos(10);
    for (attempt, outcome) in [(1, 1), (2, 3)] {
        recorder.body_fetch(
            [8; 32],
            &header,
            Some(FetchTiming {
                connection: 5,
                attempt,
                height: header.height,
                block: header.id().unwrap(),
                bytes: 1000,
                received_bytes: if outcome == 1 { 1000 } else { 100 },
                start: Some(start),
                body_start: Some(start + std::time::Duration::from_nanos(5)),
                chunks_end: (outcome == 1).then_some(start + std::time::Duration::from_nanos(10)),
                decoded: (outcome == 1).then_some(start + std::time::Duration::from_nanos(15)),
                end: Some(start + std::time::Duration::from_nanos(20)),
                outcome,
                transport_error: if outcome == 1 { 0 } else { 2 },
            }),
            0,
        );
    }
    recorder.finish();
    let records = directory.records();
    assert_eq!(records.len(), 4);
    for event in &records[1..3] {
        assert_eq!(event["kind"], "native-body-fetch-observed");
        assert_eq!(event["peer_id"], "08".repeat(32));
        assert_eq!(event["block_id"], crate::local::hex(&header.id().unwrap()));
        assert_eq!(event["fetch_timing"]["start"], "10");
        assert_eq!(event["fetch_timing"]["body_start"], "15");
        assert_eq!(event["fetch_timing"]["ordinal_available"], true);
        assert_eq!(event["native_acceptance_implied"], false);
        assert!(event["accepted_unix_ms"].is_null());
        assert_eq!(event["clock_calibration_measured"], false);
        assert!(serde_json::to_vec(event).unwrap().len() < RECORD_BYTES);
    }
    assert_eq!(records[1]["fetch_timing"]["chunks_end"], "20");
    assert_eq!(records[1]["fetch_timing"]["decoded"], "25");
    assert!(records[2]["fetch_timing"]["chunks_end"].is_null());
    assert!(records[2]["fetch_timing"]["decoded"].is_null());
    assert_eq!(records[2]["fetch_timing"]["transport_error"], "unavailable");
    assert_ne!(
        records[1]["deduplication_key"],
        records[2]["deduplication_key"]
    );
    assert_eq!(recorder.diagnostic()["dropped_events"], 0);
}

#[test]
fn direct_push_keeps_independent_destination_receipts_without_claiming_acceptance() {
    let directory = Directory::new();
    let recorder = directory.recorder();
    for (peer, outcome, sent) in [
        ([7; 32], "body_sent", 10_000_100),
        ([8; 32], "credit_declined", 128),
        ([9; 32], "interrupted", 65_536),
    ] {
        recorder.record(
            Kind::DirectPush {
                peer,
                outcome,
                body_bytes: 10_000_000,
                sent_application_bytes: sent,
            },
            42,
            Some([6; 32]),
            Some(123),
            "10".into(),
        );
    }
    let records = directory.records();
    let receipt_keys: std::collections::BTreeSet<_> = records[1..]
        .iter()
        .map(|event| {
            assert_eq!(event["native_acceptance_implied"], false);
            assert_eq!(event["declared_body_bytes"], 10_000_000);
            event["deduplication_key"].to_string()
        })
        .collect();
    assert_eq!(receipt_keys.len(), 3);
    assert_eq!(records[1]["outcome"], "body_sent");
    assert_eq!(records[2]["sent_application_bytes"], 128);
    assert_eq!(records[3]["outcome"], "interrupted");
}

#[test]
fn piece_source_failure_and_completion_preserve_counters_under_the_original_record_cap() {
    use crate::eng2::propagation::pipeline::SourceBytes;
    let directory = Directory::new();
    let mut recorder = directory.recorder();
    recorder.binding.source = Some("a".repeat(40));
    recorder.state.lock().unwrap().sequence = u64::MAX - 3;
    let edge = recorder.started + std::time::Duration::from_secs(3600);
    let timing = FetchTiming {
        attempt: u64::MAX,
        start: Some(edge),
        body_start: Some(edge),
        chunks_end: Some(edge),
        decoded: Some(edge),
        end: Some(edge),
        ..Default::default()
    };
    let source = SourceBytes {
        peer: [255; 32],
        requested: u64::MAX,
        queries: u64::MAX,
        received: u64::MAX,
        authenticated_body_bytes: u64::MAX,
        sent: u64::MAX,
        reserved_wire: u64::MAX,
        bad_pieces: u64::MAX,
        failures: u64::MAX,
    };
    for outcome in ["incomplete_or_cancelled", "authenticated_body_decoded"] {
        recorder.record(
            Kind::PieceSource {
                source,
                timing,
                outcome,
            },
            u64::MAX,
            Some([255; 32]),
            Some(u64::MAX),
            u128::MAX.to_string(),
        );
    }
    let records = directory.records();
    assert_eq!(records.len(), 3, "{:?}", recorder.diagnostic());
    assert_ne!(
        records[1]["deduplication_key"],
        records[2]["deduplication_key"]
    );
    for record in &records[1..] {
        assert!(serde_json::to_vec(record).unwrap().len() < RECORD_BYTES);
        assert_eq!(
            record["source_counters"]["received_application_bytes"],
            u64::MAX
        );
        assert_eq!(record["source_counters"]["queries"], u64::MAX);
        assert_eq!(record["source_counters"]["unique_body_bytes"], u64::MAX);
        assert_eq!(record["native_acceptance_implied"], false);
        assert_eq!(record["transfer_times_ns"]["body"], "3600000000000");
        assert!(
            !record
                .as_object()
                .unwrap()
                .keys()
                .any(|key| key.contains("endpoint") || key.contains("transaction"))
        );
    }
    assert_eq!(recorder.diagnostic()["dropped_events"], 0);
}
