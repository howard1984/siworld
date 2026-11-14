use super::*;
use crate::eng2::{branches::tests::Fixture, selection::VerifiedHeaders};
fn rules() -> HeaderRules {
    HeaderRules {
        network: [17; 32],
        genesis: [2; 32],
        genesis_timestamp: 1,
        genesis_target: [255; 32],
        target_interval: 300,
        pow_iterations: 0,
        max_headers: 128,
    }
}
fn limits() -> Limits {
    Limits {
        maximum_headers: 128,
        maximum_body_bytes: 16 * 1024 * 1024,
    }
}
fn chain(prefix: &[Header], height: u64, tag: u8) -> VerifiedHeaders {
    let rules = rules();
    let mut headers = prefix.to_vec();
    let mut parent = headers
        .last()
        .map_or(rules.genesis, |head| head.id().unwrap());
    // Fixed finite minimum-difficulty header fixtures; no nonce search or body proof.
    for height in headers.len() as u64 + 1..=height {
        let header = Header {
            network: rules.network,
            height,
            parent,
            timestamp: 1 + height * 300,
            target: [255; 32],
            execution_commitment: [tag; 32],
            body_commitment: [7; 32],
            nonce: 0,
        };
        parent = header.id().unwrap();
        headers.push(header);
    }
    VerifiedHeaders::verify(rules, headers).unwrap()
}
fn prepared() -> (
    Fixture,
    BranchStore,
    VerifiedHeaders,
    VerifiedHeaders,
    CandidatePath,
) {
    let fixture = Fixture::new();
    let mut store = BranchStore::create(&fixture.path(), rules(), limits()).unwrap();
    let old = chain(&[], 26, 10);
    let new = chain(&[old.header(1).unwrap().clone()], 27, 11);
    store.retain_verified_headers(&old).unwrap();
    store.retain_verified_headers(&new).unwrap();
    let path = store
        .candidate_path(old.id(26).unwrap(), new.id(27).unwrap())
        .unwrap();
    assert_eq!(path.removed.len(), 25);
    (fixture, store, old, new, path)
}
fn raw_write(store: &BranchStore, bytes: &[u8]) {
    let mut transaction = store.database.begin_write().unwrap();
    transaction.set_durability(Durability::Immediate).unwrap();
    {
        transaction
            .open_table(META)
            .unwrap()
            .insert(KEY, bytes)
            .unwrap();
    }
    transaction.commit().unwrap();
}
fn raw_read(store: &BranchStore) -> Vec<u8> {
    let transaction = store.database.begin_read().unwrap();
    let table = transaction.open_table(META).unwrap();
    table.get(KEY).unwrap().unwrap().value().to_vec()
}
#[test]
fn refusal_survives_reopen_without_reordering_headers_or_replacing_first_context() {
    let (fixture, mut store, old, new, path) = prepared();
    let old_tip = old.id(26).unwrap();
    let candidate = new.id(27).unwrap();
    let best = store.best_candidate().unwrap();
    let revision = store.selection_revision();
    assert!(!store.has_deep_refusal(26, old_tip).unwrap());
    store
        .persist_deep_refusal(26, old_tip, candidate, &path)
        .unwrap();
    let original = raw_read(&store);
    store
        .persist_deep_refusal(26, old_tip, candidate, &path)
        .unwrap();
    assert_eq!(raw_read(&store), original);
    assert_eq!(store.best_candidate().unwrap(), best);
    assert_eq!(store.selection_revision(), revision);
    assert!(
        store
            .persist_deep_refusal(27, old_tip, candidate, &path)
            .is_err()
    );
    assert_eq!(raw_read(&store), original);
    drop(store);
    let reopened = BranchStore::open(&fixture.path(), rules(), limits()).unwrap();
    assert!(reopened.has_deep_refusal(26, old_tip).unwrap());
    assert!(reopened.has_deep_refusal(27, candidate).is_err());
    assert!(reopened.has_deep_refusal(25, old_tip).is_err());
    assert_eq!(raw_read(&reopened), original);
}
#[test]
fn unknown_truncated_corrupt_and_wrong_context_records_survive_as_failures() {
    for mode in 0..7 {
        let (fixture, mut store, old, new, path) = prepared();
        let old_tip = old.id(26).unwrap();
        let candidate = new.id(27).unwrap();
        store
            .persist_deep_refusal(26, old_tip, candidate, &path)
            .unwrap();
        let mut bytes = raw_read(&store);
        match mode {
            0 => bytes[3] = b'2',
            1 => {
                bytes.pop();
            }
            2 => bytes.push(0),
            3 => bytes[4] ^= 1,
            4 => bytes[36] ^= 1,
            5 => bytes[68] ^= 1,
            _ => bytes[148] = 24,
        }
        raw_write(&store, &bytes);
        assert!(store.has_deep_refusal(26, old_tip).is_err(), "{mode}");
        assert!(
            store
                .persist_deep_refusal(26, old_tip, candidate, &path)
                .is_err(),
            "{mode}"
        );
        assert_eq!(raw_read(&store), bytes);
        drop(store);
        let reopened = BranchStore::open(&fixture.path(), rules(), limits()).unwrap();
        assert!(reopened.has_deep_refusal(26, old_tip).is_err(), "{mode}");
        assert_eq!(raw_read(&reopened), bytes);
    }
}
#[test]
fn missing_retained_candidate_cannot_clear_persisted_refusal() {
    let (_fixture, mut store, old, new, path) = prepared();
    let old_tip = old.id(26).unwrap();
    let candidate = new.id(27).unwrap();
    store
        .persist_deep_refusal(26, old_tip, candidate, &path)
        .unwrap();
    let original = raw_read(&store);
    let mut transaction = store.database.begin_write().unwrap();
    transaction.set_durability(Durability::Immediate).unwrap();
    {
        transaction
            .open_table(HEADERS)
            .unwrap()
            .remove(candidate.as_slice())
            .unwrap();
    }
    transaction.commit().unwrap();
    assert!(store.has_deep_refusal(26, old_tip).is_err());
    assert_eq!(raw_read(&store), original);
}
