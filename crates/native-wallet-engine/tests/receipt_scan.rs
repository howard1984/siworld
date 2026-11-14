//! Bounded disposable tests. Native proof/state qualification is never implied.
#![cfg(feature = "receipt-scan-synthetic")]
use siworld_native_wallet_engine::{
    eng2_history::{Context, HEADER_BYTES, ReceiptBlock},
    receipt_scan::{
        Limits,
        accounting::Totals,
        history::FrozenEng2History,
        origin::{self, OriginKind},
        scan,
        synthetic::{self, Branch, Fault, SECOND_ASSET, ZERO_ASSET},
    },
};
use std::time::Duration;

#[test]
fn complete_receipts_match_independent_case_constants() {
    for branch in [
        Branch::Original,
        Branch::Replacement,
        Branch::ConflictReplacement,
    ] {
        let case = synthetic::reorg_case(branch, 3).unwrap();
        let report = scan(&case.history, &case.custody, 3, &Limits::default()).unwrap();
        report.matches(&case.expected).unwrap();
        assert_eq!(report.height(), 3);
        assert_eq!(report.owned_notes(), 4);
        assert!(!report.native_consensus_qualified());
        assert!(!report.real_custody_used());
    }
}
#[test]
fn fresh_replacement_removes_orphans_restores_spends_and_origins() {
    let a = synthetic::reorg_case(Branch::Original, 3).unwrap();
    let b = synthetic::reorg_case(Branch::Replacement, 3).unwrap();
    let original = scan(&a.history, &a.custody, 3, &Limits::default()).unwrap();
    let replacement = scan(&b.history, &b.custody, 3, &Limits::default()).unwrap();
    original.matches(&a.expected).unwrap();
    replacement.matches(&b.expected).unwrap();
    for (commitment, expected) in &b.expected.notes {
        assert!(replacement.origin(commitment) == Some(&expected.origin));
    }
    let mut stale = a.expected.clone();
    stale.history_manifest = b.history.manifest_sha256();
    assert!(replacement.matches(&stale).is_err());
    // The moved note retains its commitment, but its complete origin changes.
    let mut moved_count = 0;
    for (commitment, expected) in &a.expected.notes {
        if let Some(next) = b.expected.notes.get(commitment) {
            if expected.origin != next.origin {
                moved_count += 1;
            }
        }
    }
    assert_eq!(moved_count, 1);
}
#[test]
fn maturity_uses_committed_unlock_and_explicit_spend_height() {
    for height in [1, 2, 3] {
        let case = synthetic::padding_prefix(height).unwrap();
        scan(&case.history, &case.custody, height, &Limits::default())
            .unwrap()
            .matches(&case.expected)
            .unwrap();
    }
    for branch in [
        Branch::Original,
        Branch::Replacement,
        Branch::ConflictReplacement,
    ] {
        let case = synthetic::reorg_case(branch, 4).unwrap();
        scan(&case.history, &case.custody, 4, &Limits::default())
            .unwrap()
            .matches(&case.expected)
            .unwrap();
    }
}
#[test]
fn corrupted_or_incomplete_prefixes_and_snapshot_pins_reject() {
    let case = synthetic::reorg_case(Branch::Original, 3).unwrap();
    for fault in [
        Fault::MissingFirst,
        Fault::MissingMiddle,
        Fault::MissingLast,
        Fault::Reordered,
        Fault::DuplicateHeight,
        Fault::TailMismatch,
        Fault::Context,
        Fault::Profile,
        Fault::ReceiptCorrupt,
        Fault::SnapshotPinChange,
    ] {
        let altered = synthetic::with_fault(&case.history, fault);
        assert!(scan(&altered, &case.custody, 3, &Limits::default()).is_err());
    }
}
#[test]
fn byte_height_note_nullifier_and_deadline_limits_fail_closed() {
    let case = synthetic::reorg_case(Branch::Original, 3).unwrap();
    let bytes = (0..case.history.frame_count())
        .map(|i| case.history.frame(i).unwrap().1.len() as u64)
        .sum();
    let exact = Limits {
        max_blocks: 3,
        max_receipt_bytes: bytes,
        max_owned_notes: 4,
        max_nullifiers: 384,
        ..Limits::default()
    };
    scan(&case.history, &case.custody, 3, &exact)
        .unwrap()
        .matches(&case.expected)
        .unwrap();
    let mut limits = vec![exact.clone(); 5];
    limits[0].max_blocks = 2;
    limits[1].max_receipt_bytes = bytes - 1;
    limits[2].max_owned_notes = 3;
    limits[3].max_nullifiers = 383;
    limits[4].max_elapsed = Duration::ZERO;
    for limit in limits {
        assert!(scan(&case.history, &case.custody, 3, &limit).is_err());
    }
}
#[test]
fn checked_amount_and_count_overflows_preserve_the_prior_total() {
    let mut amount = Totals {
        received_atoms: u128::MAX,
        spent_atoms: u128::MAX,
        ..Totals::default()
    };
    let before = amount.clone();
    assert!(amount.add(1, true, true).is_err());
    assert!(amount == before);
    let mut count = Totals {
        received_notes: u64::MAX,
        spent_notes: u64::MAX,
        ..Totals::default()
    };
    let before = count.clone();
    assert!(count.add(1, true, true).is_err());
    assert!(count == before);
}
#[test]
fn exact_assets_include_zero_rows_and_reject_missing_or_extra_amounts() {
    let case = synthetic::reorg_case(Branch::Replacement, 3).unwrap();
    let report = scan(&case.history, &case.custody, 3, &Limits::default()).unwrap();
    report.matches(&case.expected).unwrap();
    let mut missing = case.expected.clone();
    missing.balances.remove(&SECOND_ASSET);
    assert!(report.matches(&missing).is_err());
    let mut extra = case.expected.clone();
    extra
        .balances
        .get_mut(&ZERO_ASSET)
        .unwrap()
        .add(1, false, true)
        .unwrap();
    assert!(report.matches(&extra).is_err());
}
#[test]
fn complete_origins_distinguish_repeated_category_positions() {
    let case = synthetic::reorg_case(Branch::Original, 3).unwrap();
    let context = Context::from_genesis(case.history.genesis(), case.history.genesis_id()).unwrap();
    let (header, receipt) = case.history.frame(0).unwrap();
    let header: [u8; HEADER_BYTES] = header.try_into().unwrap();
    let receipt = ReceiptBlock::decode(&context, &header, receipt).unwrap();
    let origins = origin::output_origins(&receipt).unwrap();
    let first_outputs = origins
        .iter()
        .filter(|o| matches!(o.kind, OriginKind::Transaction { output: 0, .. }))
        .collect::<Vec<_>>();
    assert_eq!(first_outputs.len(), 64);
    for (i, left) in first_outputs.iter().enumerate() {
        for right in &first_outputs[i + 1..] {
            assert!(left.kind != right.kind);
        }
    }
}
#[test]
#[ignore = "explicit owner-controlled resource qualification of a complete65-block prefix"]
fn complete_prefix_exceeds_sixty_four_blocks() {
    let case = synthetic::padding_prefix(65).unwrap();
    let limits = Limits {
        max_elapsed: Duration::from_secs(300),
        ..Limits::default()
    };
    synthetic::authenticate_header_pages(&case.history).unwrap();
    scan(&case.history, &case.custody, 65, &limits)
        .unwrap()
        .matches(&case.expected)
        .unwrap();
}
#[test]
#[ignore = "explicit owner-controlled resource qualification across128-header pages"]
fn complete_prefix_crosses_header_page_boundary() {
    let case = synthetic::padding_prefix(129).unwrap();
    let limits = Limits {
        max_elapsed: Duration::from_secs(300),
        ..Limits::default()
    };
    synthetic::authenticate_header_pages(&case.history).unwrap();
    scan(&case.history, &case.custody, 129, &limits)
        .unwrap()
        .matches(&case.expected)
        .unwrap();
}
