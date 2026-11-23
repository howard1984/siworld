use super::*;

fn budget(height: u64) -> Budget {
    Budget {
        version: 1,
        height,
        maximum_total_frame_bytes: 32 * GIB,
        maximum_segment_frame_bytes: 4 * GIB,
        maximum_segment_blocks: 96,
        maximum_segments: 256,
        deadline_seconds: 3600,
        segment_deadline_seconds: 900,
        maximum_output_bytes: GIB,
        maximum_run_logical_bytes: 64 * GIB,
        maximum_run_entries: 200_000,
        minimum_disk_free_bytes: 128 * GIB,
    }
}
fn frames(count: u64, bytes: u64) -> Vec<FrozenFrame> {
    (1..=count)
        .map(|height| FrozenFrame {
            height,
            header: vec![0; HEADER_BYTES],
            frame_bytes: bytes,
            frame_sha256: "00".repeat(32),
        })
        .collect()
}
#[test]
fn segment_plan_covers_genesis_prefix_without_using_a_nonzero_anchor() {
    let mut input = frames(97, HEADER_BYTES as u64);
    let plan = ranges(&input, budget(97)).unwrap();
    assert_eq!(
        plan,
        vec![
            Range {
                first: 1,
                last: 96,
                frame_bytes: 96 * HEADER_BYTES as u64
            },
            Range {
                first: 97,
                last: 97,
                frame_bytes: HEADER_BYTES as u64
            }
        ]
    );
    input.remove(0);
    assert!(ranges(&input, budget(96)).is_err());
    let mut input = frames(97, HEADER_BYTES as u64);
    input.swap(94, 95);
    assert!(ranges(&input, budget(97)).is_err());
    input = frames(97, HEADER_BYTES as u64);
    input[96].height = 96;
    assert!(ranges(&input, budget(97)).is_err());
    assert!(ranges(&input[..96], budget(97)).is_err());
}
#[test]
fn explicit_new_session_segments_logical_over_sixteen_gib_without_changing_old_policy() {
    // Logical lengths only: no corresponding body buffers, files or work exist.
    let input = frames(9, 2 * GIB);
    let plan = ranges(&input, budget(9)).unwrap();
    assert_eq!(plan.len(), 5);
    assert!(plan.iter().all(|range| range.frame_bytes <= 4 * GIB));
    assert_eq!(
        plan.iter().map(|range| range.frame_bytes).sum::<u64>(),
        18 * GIB
    );
    let mut limited = budget(9);
    limited.maximum_total_frame_bytes = 16 * GIB;
    assert!(ranges(&input, limited).is_err());
    limited = budget(9);
    limited.maximum_segments = 4;
    assert!(ranges(&input, limited).is_err());
    assert!(ranges(&frames(1, 4 * GIB + 1), budget(1)).is_err());
}
#[test]
fn session_budget_rejects_unbounded_or_ambiguous_requests() {
    let good = budget(97);
    good.validate().unwrap();
    for change in 0..11 {
        let mut bad = good;
        match change {
            0 => bad.height = 16_385,
            1 => bad.maximum_total_frame_bytes = 64 * GIB + 1,
            2 => bad.maximum_segment_frame_bytes = 16 * GIB + 1,
            3 => bad.maximum_segment_blocks = 97,
            4 => bad.maximum_segments = 257,
            5 => bad.deadline_seconds = 3601,
            6 => bad.segment_deadline_seconds = 3601,
            7 => bad.maximum_output_bytes = 16 * GIB + 1,
            8 => bad.maximum_run_logical_bytes = 64 * GIB + 1,
            9 => bad.minimum_disk_free_bytes = 128 * GIB - 1,
            _ => bad.maximum_run_entries = 200_001,
        }
        assert!(bad.validate().is_err());
    }
    let mut value = serde_json::to_value(good).unwrap();
    value["trusted_checkpoint"] = json!("unsupported");
    assert!(serde_json::from_value::<Budget>(value).is_err());
    let raw = serde_json::to_string(&good).unwrap();
    let duplicate = raw.replacen("{", "{\"height\":97,", 1);
    assert!(serde_json::from_str::<Budget>(&duplicate).is_err());
}
#[test]
fn frozen_bytes_bind_header_length_and_digest_before_decoding() {
    let bytes = vec![0; HEADER_BYTES];
    let frozen = FrozenFrame {
        height: 1,
        header: bytes.clone(),
        frame_bytes: bytes.len() as u64,
        frame_sha256: crate::local::hex(&Sha256::digest(&bytes)),
    };
    let mut changed = frozen.clone();
    changed.frame_bytes += 1;
    assert!(check_frame(&bytes, &changed, &[1; 32]).is_err());
    changed = frozen.clone();
    changed.frame_sha256 = "01".repeat(32);
    assert!(check_frame(&bytes, &changed, &[1; 32]).is_err());
    changed = frozen;
    changed.header[0] = 1;
    assert!(check_frame(&bytes, &changed, &[1; 32]).is_err());
}

#[test]
fn complete_boundary_round_trip_rejects_corruption_in_each_of_eleven_components() {
    use crate::eng2::{
        genesis::FeeMode,
        snapshot::tests::{bootstrap, populated},
    };
    // Component codec fixture only. It is not an executed native block and
    // cannot initialize the production audit, which always calls Engine::new.
    let old = bootstrap();
    let genesis = Genesis::seal(
        old.chain.config.clone(),
        old.governance().clone(),
        FeeMode::LegacyMiner,
    )
    .unwrap();
    let mut state = populated(&genesis.initial_state().unwrap());
    let context = Binding {
        genesis: genesis.id(),
        rules_commitment: genesis.rules_commitment(),
        parent: genesis.id(),
    };
    let mut header = Header {
        network: state.network(),
        height: 1,
        parent: genesis.id(),
        timestamp: 300,
        target: [0xff; 32],
        execution_commitment: state.execution_commitment(context, limits()).unwrap(),
        body_commitment: [6; 32],
        nonce: 0,
    };
    state.chain.tip = header.id().unwrap();
    state.chain.snapshots.back_mut().unwrap().selector.block_id = state.chain.tip;
    header.execution_commitment = state.execution_commitment(context, limits()).unwrap();
    let engine = Engine::from_authenticated_local_state(genesis, state, limits()).unwrap();
    let expected = engine
        .state()
        .canonical_components(context, limits())
        .unwrap();
    let bytes = boundary(&engine, &header).unwrap();
    let bounds = ImportLimits {
        chain: limits(),
        max_snapshot_bytes: MAX_BOUNDARY_BYTES,
    };
    let restored =
        SnapshotState::from_committed_components(engine.genesis(), &header, &bytes, bounds)
            .unwrap();
    assert_eq!(
        restored.canonical_components(context, limits()).unwrap(),
        expected
    );
    for changed_component in 0..11 {
        let mut changed = expected.clone();
        let part = &mut changed[changed_component];
        let last = part.len() - 1;
        part[last] ^= 1;
        let bytes = encode_components(&changed, bounds).unwrap();
        assert!(
            SnapshotState::from_committed_components(engine.genesis(), &header, &bytes, bounds)
                .is_err()
        );
    }
    let mut changed = header;
    changed.parent[0] ^= 1;
    assert!(
        SnapshotState::from_committed_components(engine.genesis(), &changed, &bytes, bounds)
            .is_err()
    );
}
