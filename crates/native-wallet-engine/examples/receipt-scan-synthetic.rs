//! Explicit disposable self-check only. No file, seed or custody path is read.
use siworld_native_wallet_engine::receipt_scan::{
    Limits, scan,
    synthetic::{Branch, reorg_case},
};
use std::process::ExitCode;
fn opaque(text: &str) -> bool {
    (8..=96).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
fn run() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 || args[0] != "--synthetic-only" || !opaque(&args[1]) {
        eprintln!("usage: receipt-scan-synthetic --synthetic-only OPAQUE_EVIDENCE_REFERENCE");
        return ExitCode::from(2);
    }
    let matched = [
        Branch::Original,
        Branch::Replacement,
        Branch::ConflictReplacement,
    ]
    .into_iter()
    .all(|branch| {
        let Ok(case) = reorg_case(branch, 3) else {
            return false;
        };
        let Ok(report) = scan(&case.history, &case.custody, 3, &Limits::default()) else {
            return false;
        };
        !report.native_consensus_qualified()
            && !report.real_custody_used()
            && report.matches(&case.expected).is_ok()
    });
    let status = if matched {
        "SYNTHETIC_MATCHED"
    } else {
        "INCOMPLETE"
    };
    println!(
        "{}",
        serde_json::json!({"status":status,"evidence_ref":args[1]})
    );
    if matched {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
fn main() -> ExitCode {
    run()
}
