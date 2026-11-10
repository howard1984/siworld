use super::super::{archive, body, snapshot};
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
struct Temp(std::path::PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "eng2-isolated-sync-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn source_policy() -> archive::Policy {
    archive::Policy {
        max_active_transfers: 2,
        max_lease_seconds: 3600,
        max_chunk_bytes: 1024,
        max_snapshot_bytes: 32 * 1024 * 1024,
    }
}
fn policy() -> Policy {
    Policy {
        import: snapshot::tests::limits(),
        body: body::tests::policy(),
        max_download_bytes: 64 * 1024 * 1024,
        max_chunk_bytes: 1024,
        max_chunks_per_object: 4096,
    }
}

#[test]
fn source_selected_transfer_resumes_in_one_isolated_directory_and_waits_for_native_verification() {
    let temp = Temp::new();
    let (context, anchor, plan, limits, body) = archive::tests::body_fixture();
    let bootstrap = snapshot::tests::bootstrap();
    let live_before = bootstrap.chain.fingerprint();
    let source_path = temp.0.join("source.redb");
    let mut source = Archive::create(&source_path, context, source_policy()).unwrap();
    let stored_anchor = source.store_anchor(&anchor, &plan, limits).unwrap();
    source.store_tail_body(&plan, &body, policy().body).unwrap();
    let transfer = source
        .begin_transfer(stored_anchor, &plan, [7; 32], 100, 60)
        .unwrap();
    let directory = temp.0.join("stage");
    let mut session = Session::create(
        &directory,
        &plan,
        &bootstrap,
        context.rules_commitment,
        policy(),
        stored_anchor,
    )
    .unwrap();
    let chunk = source.read_chunk(&transfer, [7; 32], 0, 1024, 120).unwrap();
    session.push_anchor_chunk(0, &chunk).unwrap();
    assert_eq!(session.progress().unwrap().downloaded_bytes, 1024);
    assert!(session.anchor().is_none());
    drop(session);
    drop(source);
    let source = Archive::open_existing(&source_path, context, source_policy()).unwrap();
    let mut session = Session::open_existing(
        &directory,
        &plan,
        &bootstrap,
        context.rules_commitment,
        policy(),
    )
    .unwrap();
    session
        .pull_anchor(&source, &transfer, [7; 32], 120)
        .unwrap();
    assert_eq!(session.anchor().unwrap().pin(), anchor.pin());
    assert_eq!(session.progress().unwrap().phase, Phase::AcquiringTail);
    session
        .pull_body(&source, &transfer, [7; 32], 1, 120)
        .unwrap();
    assert_eq!(session.read_body(1).unwrap(), body);
    // This archive fixture deliberately carries synthetic governance signatures.
    // Authenticated framing cannot promote those into execution authority.
    assert!(
        matches!(session.prepare_anchor_successor(&body), Err(reason) if reason == "governance ML-DSA-65 signature invalid")
    );
    assert_eq!(
        session.progress().unwrap(),
        Progress {
            phase: Phase::AwaitingNativeVerification,
            anchor_bytes: stored_anchor.bytes,
            downloaded_bytes: stored_anchor.bytes + body.encoded_len(policy().body).unwrap() as u64,
            completed_bodies: vec![1]
        }
    );
    assert_eq!(bootstrap.chain.fingerprint(), live_before);
    drop(session);
    let session = Session::open_existing(
        &directory,
        &plan,
        &bootstrap,
        context.rules_commitment,
        policy(),
    )
    .unwrap();
    assert_eq!(
        session.progress().unwrap().phase,
        Phase::AwaitingNativeVerification
    );
    assert_eq!(session.read_body(1).unwrap(), body);
    assert_eq!(bootstrap.chain.fingerprint(), live_before);
}

#[test]
fn disconnect_and_invalid_final_chunks_leave_durable_progress_and_parent_unchanged() {
    let temp = Temp::new();
    let (context, anchor, plan, limits, body) = archive::tests::body_fixture();
    let bootstrap = snapshot::tests::bootstrap();
    let before = bootstrap.chain.fingerprint();
    let mut source =
        Archive::create(&temp.0.join("source.redb"), context, source_policy()).unwrap();
    let stored = source.store_anchor(&anchor, &plan, limits).unwrap();
    let body_descriptor = source.store_tail_body(&plan, &body, policy().body).unwrap();
    let transfer = source
        .begin_transfer(stored, &plan, [7; 32], 100, 60)
        .unwrap();
    let directory = temp.0.join("stage");
    let mut session = Session::create(
        &directory,
        &plan,
        &bootstrap,
        context.rules_commitment,
        policy(),
        stored,
    )
    .unwrap();
    let raw = source.load_anchor(stored).unwrap();
    for chunk in raw[..raw.len() - 1].chunks(1024) {
        let offset = session.progress().unwrap().anchor_bytes;
        session.push_anchor_chunk(offset, chunk).unwrap();
    }
    let progress = session.progress().unwrap();
    assert!(
        session
            .pull_anchor(&source, &transfer, [7; 32], 161)
            .is_err()
    );
    assert_eq!(session.progress().unwrap(), progress);
    assert!(
        session
            .push_anchor_chunk(progress.anchor_bytes, &[raw[raw.len() - 1] ^ 1])
            .is_err()
    );
    assert_eq!(session.progress().unwrap(), progress);
    assert!(session.anchor().is_none());
    session
        .push_anchor_chunk(progress.anchor_bytes, &raw[raw.len() - 1..])
        .unwrap();
    session.begin_body(body_descriptor).unwrap();
    let raw = body.encode(policy().body).unwrap();
    let mut offset = 0;
    for chunk in raw[..raw.len() - 1].chunks(1024) {
        session.push_body_chunk(1, offset, chunk).unwrap();
        offset += chunk.len() as u64;
    }
    let progress = session.progress().unwrap();
    assert!(
        session
            .push_body_chunk(1, offset, &[raw[raw.len() - 1] ^ 1])
            .is_err()
    );
    assert_eq!(session.progress().unwrap(), progress);
    assert!(session.read_body(1).is_err());
    assert!(session.prepare_anchor_successor(&body).is_err());
    session
        .push_body_chunk(1, offset, &raw[raw.len() - 1..])
        .unwrap();
    assert_eq!(session.read_body(1).unwrap(), body);
    assert_eq!(bootstrap.chain.fingerprint(), before);
}

#[test]
fn restart_rejects_wrong_context_and_corrupted_complete_data_without_reinitializing() {
    let temp = Temp::new();
    let (context, anchor, plan, limits, body) = archive::tests::body_fixture();
    let bootstrap = snapshot::tests::bootstrap();
    let before = bootstrap.chain.fingerprint();
    let mut source =
        Archive::create(&temp.0.join("source.redb"), context, source_policy()).unwrap();
    let stored = source.store_anchor(&anchor, &plan, limits).unwrap();
    source.store_tail_body(&plan, &body, policy().body).unwrap();
    let transfer = source
        .begin_transfer(stored, &plan, [7; 32], 100, 60)
        .unwrap();
    let directory = temp.0.join("stage");
    let mut session = Session::create(
        &directory,
        &plan,
        &bootstrap,
        context.rules_commitment,
        policy(),
        stored,
    )
    .unwrap();
    session
        .pull_anchor(&source, &transfer, [7; 32], 120)
        .unwrap();
    session
        .pull_body(&source, &transfer, [7; 32], 1, 120)
        .unwrap();
    drop(session);
    let mut other_rules = context.rules_commitment;
    other_rules[0] ^= 1;
    assert!(Session::open_existing(&directory, &plan, &bootstrap, other_rules, policy()).is_err());
    let altered = Policy {
        body: body::Policy {
            profile: [99; 32],
            ..policy().body
        },
        ..policy()
    };
    assert!(
        Session::open_existing(
            &directory,
            &plan,
            &bootstrap,
            context.rules_commitment,
            altered
        )
        .is_err()
    );
    let session = Session::open_existing(
        &directory,
        &plan,
        &bootstrap,
        context.rules_commitment,
        policy(),
    )
    .unwrap();
    let transaction = session.database.begin_write().unwrap();
    let mut damaged = body.encode(policy().body).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    transaction
        .open_table(RAW)
        .unwrap()
        .insert(1, damaged.as_slice())
        .unwrap();
    transaction.commit().unwrap();
    assert!(session.read_body(1).is_err());
    drop(session);
    assert!(
        Session::open_existing(
            &directory,
            &plan,
            &bootstrap,
            context.rules_commitment,
            policy()
        )
        .is_err()
    );
    let database = open_database(&directory, false).unwrap();
    let transaction = database.begin_read().unwrap();
    assert_eq!(
        transaction
            .open_table(RAW)
            .unwrap()
            .get(1)
            .unwrap()
            .unwrap()
            .value(),
        damaged
    );
    assert_eq!(bootstrap.chain.fingerprint(), before);
}

#[test]
fn download_budget_chunk_count_and_creation_boundaries_preserve_existing_data() {
    let temp = Temp::new();
    let (context, anchor, plan, limits, body) = archive::tests::body_fixture();
    let bootstrap = snapshot::tests::bootstrap();
    let mut source =
        Archive::create(&temp.0.join("source.redb"), context, source_policy()).unwrap();
    let stored = source.store_anchor(&anchor, &plan, limits).unwrap();
    let body_descriptor = source.store_tail_body(&plan, &body, policy().body).unwrap();
    let transfer = source
        .begin_transfer(stored, &plan, [7; 32], 100, 60)
        .unwrap();
    let too_small = Policy {
        max_chunks_per_object: 1,
        ..policy()
    };
    let rejected_path = temp.0.join("rejected");
    assert!(
        Session::create(
            &rejected_path,
            &plan,
            &bootstrap,
            context.rules_commitment,
            too_small,
            stored
        )
        .is_err()
    );
    assert!(!rejected_path.exists());

    let limited = Policy {
        max_download_bytes: stored.bytes + body_descriptor.bytes - 1,
        ..policy()
    };
    let directory = temp.0.join("budget");
    let mut session = Session::create(
        &directory,
        &plan,
        &bootstrap,
        context.rules_commitment,
        limited,
        stored,
    )
    .unwrap();
    session
        .pull_anchor(&source, &transfer, [7; 32], 120)
        .unwrap();
    let progress = session.progress().unwrap();
    assert!(session.begin_body(body_descriptor).is_err());
    assert_eq!(session.progress().unwrap(), progress);
    drop(session);

    let fragment_limit = Policy {
        max_chunks_per_object: stored.bytes.div_ceil(1024) as usize,
        ..policy()
    };
    let directory = temp.0.join("fragments");
    let mut session = Session::create(
        &directory,
        &plan,
        &bootstrap,
        context.rules_commitment,
        fragment_limit,
        stored,
    )
    .unwrap();
    for offset in 0..fragment_limit.max_chunks_per_object as u64 {
        session.push_anchor_chunk(offset, &[0]).unwrap();
    }
    let progress = session.progress().unwrap();
    assert!(
        session
            .push_anchor_chunk(progress.anchor_bytes, &[0])
            .is_err()
    );
    assert_eq!(session.progress().unwrap(), progress);
    drop(session);
    let session = Session::open_existing(
        &directory,
        &plan,
        &bootstrap,
        context.rules_commitment,
        fragment_limit,
    )
    .unwrap();
    assert_eq!(session.progress().unwrap(), progress);
    drop(session);

    let directory = temp.0.join("empty");
    create_directory(&directory).unwrap();
    std::fs::write(directory.join(FILE), []).unwrap();
    assert!(
        Session::open_existing(
            &directory,
            &plan,
            &bootstrap,
            context.rules_commitment,
            policy()
        )
        .is_err()
    );
    assert_eq!(std::fs::metadata(directory.join(FILE)).unwrap().len(), 0);
    assert!(
        Session::create(
            &directory,
            &plan,
            &bootstrap,
            context.rules_commitment,
            policy(),
            stored
        )
        .is_err()
    );
    assert_eq!(std::fs::metadata(directory.join(FILE)).unwrap().len(), 0);
}
