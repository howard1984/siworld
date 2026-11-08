use super::*;
use crate::{
    engineering_checkpoint::{CONTEXT, Certificate, INTERVAL_SECONDS, Statement, Vote},
    identity::{NativeIdentity, checkpoint_authority::Authority},
    p2p::Binding,
};
use libcrux_ml_dsa::ml_dsa_65;
use std::sync::atomic::{AtomicU64, Ordering};

fn check_with_roster(directory: &Path, roster: &Roster, now: u64) -> Result<Value, String> {
    check_inner(directory, roster, now, || Ok(now))
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "siworld-transition-admission-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        create_directory(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _parent: Directory,
    directory: PathBuf,
    roster: Roster,
    legacy: Roster,
    authority: Authority,
    other: Authority,
}
impl Fixture {
    fn new() -> Self {
        let parent = Directory::new();
        let directory = parent.0.join("network");
        let config = local::initialize(&directory, 0).unwrap();
        let directory = directory.canonicalize().unwrap();
        let binding = Binding::new(&config);
        NativeIdentity::initialize(&directory, binding).unwrap();
        let authority = Authority::initialize(&directory, binding).unwrap();
        let other_dir = parent.0.join("other");
        create_directory(&other_dir).unwrap();
        let other = Authority::initialize(&other_dir, binding).unwrap();
        let keys = [authority.public_key(), other.public_key()];
        let third = *ml_dsa_65::generate_key_pair([109; 32])
            .verification_key
            .as_ref();
        let roster = Roster::with_transition(binding, keys, third, 10).unwrap();
        let legacy = Roster::new(binding, keys).unwrap();
        let verifier = crate::fixtures::TestVerifier;
        let store = Store::open(directory.join("chain.redb"), config, &verifier).unwrap();
        drop(store);
        Self {
            _parent: parent,
            directory,
            roster,
            legacy,
            authority,
            other,
        }
    }
    fn history(&self) {
        let verifier = crate::fixtures::TestVerifier;
        let mut store = Store::open_existing(
            self.directory.join("chain.redb"),
            local::load(&self.directory).unwrap(),
            &verifier,
        )
        .unwrap();
        while store.state().height < 96 {
            let block = crate::fixtures::candidate(
                store.state(),
                1_000_000 + store.state().height as u32 * 10_000,
            );
            store.append(&block, &verifier).unwrap();
        }
    }
    fn accepted(&self, sequence: u64) {
        self.history();
        let verifier = crate::fixtures::TestVerifier;
        let mut store = Store::open_existing(
            self.directory.join("chain.redb"),
            local::load(&self.directory).unwrap(),
            &verifier,
        )
        .unwrap();
        let candidate = store
            .engineering_checkpoint_candidate(
                &self.legacy,
                72,
                sequence,
                INTERVAL_SECONDS,
                &verifier,
            )
            .unwrap();
        let certificate = Certificate {
            statement: candidate.statement().clone(),
            votes: vec![
                store
                    .sign_engineering_checkpoint(&self.authority, &self.legacy, &candidate)
                    .unwrap(),
                store
                    .sign_engineering_checkpoint(&self.other, &self.legacy, &candidate)
                    .unwrap(),
            ],
        };
        store
            .accept_engineering_checkpoint(&certificate, &self.legacy, INTERVAL_SECONDS, &verifier)
            .unwrap();
    }
    fn statement(&self, sequence: u64) -> Statement {
        self.history();
        let verifier = crate::fixtures::TestVerifier;
        let store = Store::open_existing(
            self.directory.join("chain.redb"),
            local::load(&self.directory).unwrap(),
            &verifier,
        )
        .unwrap();
        store
            .engineering_checkpoint_candidate(
                &self.legacy,
                72,
                sequence,
                INTERVAL_SECONDS,
                &verifier,
            )
            .unwrap()
            .statement()
            .clone()
    }
    fn unassembled(&self, sequence: u64) {
        self.history();
        let verifier = crate::fixtures::TestVerifier;
        let store = Store::open_existing(
            self.directory.join("chain.redb"),
            local::load(&self.directory).unwrap(),
            &verifier,
        )
        .unwrap();
        let candidate = store
            .engineering_checkpoint_candidate(
                &self.legacy,
                72,
                sequence,
                INTERVAL_SECONDS,
                &verifier,
            )
            .unwrap();
        store
            .sign_engineering_checkpoint(&self.authority, &self.legacy, &candidate)
            .unwrap();
    }
    fn journal(&self, sequence: u64, change: impl FnOnce(&mut Statement, &mut Vote)) {
        let mut statement = self.statement(sequence);
        let pair = ml_dsa_65::generate_key_pair([71; 32]);
        let mut vote = Vote {
            signer: 0,
            signature: *ml_dsa_65::sign(&pair.signing_key, &statement.encode(), CONTEXT, [73; 32])
                .unwrap()
                .as_ref(),
        };
        change(&mut statement, &mut vote);
        let mut bytes = statement.encode();
        bytes.push(vote.signer);
        bytes.extend_from_slice(&vote.signature);
        let path = self
            .directory
            .join(format!("engineering-checkpoint-vote-{sequence:020}.bin"));
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    fn logical_snapshot(&self) -> [u8; 32] {
        use redb::{ReadableDatabase, ReadableTable, TableDefinition, TableHandle};
        let database = redb::ReadOnlyDatabase::open(self.directory.join("chain.redb")).unwrap();
        let transaction = database.begin_read().unwrap();
        let mut names = transaction
            .list_tables()
            .unwrap()
            .map(|t| t.name().to_owned())
            .collect::<Vec<_>>();
        names.sort();
        let mut hash = blake3::Hasher::new();
        for name in &names {
            hash.update(name.as_bytes());
        }
        for name in [
            "native-store-meta-v2",
            "local-verified-restart-v1",
            "engineering-checkpoint-attestations-v1",
        ] {
            if names.iter().any(|n| n == name) {
                let table = transaction
                    .open_table(TableDefinition::<&str, &[u8]>::new(name))
                    .unwrap();
                for row in table.iter().unwrap() {
                    let (key, value) = row.unwrap();
                    hash.update(key.value().as_bytes());
                    hash.update(blake3::hash(value.value()).as_bytes());
                }
            }
        }
        for row in transaction
            .open_table(TableDefinition::<u64, &[u8]>::new("canonical-blocks-v2"))
            .unwrap()
            .iter()
            .unwrap()
        {
            let (key, value) = row.unwrap();
            hash.update(&key.value().to_le_bytes());
            hash.update(blake3::hash(value.value()).as_bytes());
        }
        for name in ["local-production-receipts-v1", "detached-blocks-v1"] {
            if names.iter().any(|n| n == name) {
                for row in transaction
                    .open_table(TableDefinition::<&[u8], &[u8]>::new(name))
                    .unwrap()
                    .iter()
                    .unwrap()
                {
                    let (key, value) = row.unwrap();
                    hash.update(key.value());
                    hash.update(blake3::hash(value.value()).as_bytes());
                }
            }
        }
        let mut journals = std::fs::read_dir(&self.directory)
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.unwrap();
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("engineering-checkpoint-vote")
                    .then_some(entry.path())
            })
            .collect::<Vec<_>>();
        journals.sort();
        for path in journals {
            hash.update(path.file_name().unwrap().as_encoded_bytes());
            hash.update(blake3::hash(&std::fs::read(path).unwrap()).as_bytes());
        }
        *hash.finalize().as_bytes()
    }
    fn preserved(&self, call: impl FnOnce() -> Result<Value, String>) -> Result<Value, String> {
        let before = self.logical_snapshot();
        let result = call();
        assert_eq!(self.logical_snapshot(), before);
        result
    }
}

#[test]
fn transition_admission_proves_actual_absence_without_replay_or_logical_store_writes() {
    let f = Fixture::new();
    let result = f
        .preserved(|| check_with_roster(&f.directory, &f.roster, INTERVAL_SECONDS))
        .unwrap();
    assert_eq!(result["checkpoint_transition_admission_checked"], true);
    assert_eq!(result["transition_first_sequence"], 10);
    assert!(result["accepted_checkpoint"].is_null());
    assert_eq!(result["authenticated_checkpoint_absence"], true);
    assert_eq!(result["authority_journal_count"], 0);
    assert!(result["maximum_authority_journal_sequence"].is_null());
    assert_eq!(result["height"], 0);
    assert_eq!(result["proof_replay_checked"], false);
    assert_eq!(result["proof_tail_replay_checked"], false);
}

#[test]
fn transition_admission_authenticates_actual_certificate_and_all_durable_votes() {
    let f = Fixture::new();
    f.accepted(1);
    f.unassembled(9);
    let result = f
        .preserved(|| check_with_roster(&f.directory, &f.roster, INTERVAL_SECONDS))
        .unwrap();
    assert_eq!(result["accepted_checkpoint"]["sequence"], 1);
    assert_eq!(result["accepted_checkpoint"]["height"], 72);
    assert_eq!(result["authenticated_checkpoint_absence"], false);
    assert_eq!(result["authority_journal_count"], 2);
    assert_eq!(result["maximum_authority_journal_sequence"], 9);
    assert!(
        f.preserved(|| check_with_roster(&f.directory, &f.roster, INTERVAL_SECONDS - 1))
            .is_err()
    );
}

#[test]
fn transition_admission_refuses_actual_old_roster_state_at_or_beyond_cutover() {
    let f = Fixture::new();
    for sequence in [10, 11, u64::MAX] {
        f.accepted(sequence);
        assert!(
            f.preserved(|| check_with_roster(&f.directory, &f.roster, INTERVAL_SECONDS))
                .is_err()
        );
    }
}

#[test]
fn transition_admission_rejects_unassembled_invalid_and_misnamed_vote_journals() {
    let f = Fixture::new();
    // A validly persisted unassembled vote already binds its sequence.
    f.unassembled(10);
    assert!(
        f.preserved(|| check_with_roster(&f.directory, &f.roster, INTERVAL_SECONDS))
            .is_err()
    );
    std::fs::remove_file(
        f.directory
            .join("engineering-checkpoint-vote-00000000000000000010.bin"),
    )
    .unwrap();
    f.journal(2, |_, _| {});
    assert!(
        f.preserved(|| check_with_roster(&f.directory, &f.roster, INTERVAL_SECONDS))
            .is_err()
    );
    std::fs::remove_file(
        f.directory
            .join("engineering-checkpoint-vote-00000000000000000002.bin"),
    )
    .unwrap();
    f.journal(3, |statement, _| statement.sequence = 4);
    assert!(
        f.preserved(|| check_with_roster(&f.directory, &f.roster, INTERVAL_SECONDS))
            .is_err()
    );
}

#[test]
fn transition_admission_requires_idle_exact_restart_and_a_future_compiled_transition() {
    let f = Fixture::new();
    assert!(
        f.preserved(|| checkpoint_transition_check_offline(&f.directory))
            .is_err()
    );
    assert!(
        f.preserved(|| check_with_roster(&f.directory, &f.legacy, INTERVAL_SECONDS))
            .is_err()
    );
    assert!(
        f.preserved(|| check_with_roster(&f.directory, &f.roster, 10 * INTERVAL_SECONDS))
            .is_err()
    );
    assert!(
        f.preserved(
            || check_inner(&f.directory, &f.roster, INTERVAL_SECONDS, || Ok(
                10 * INTERVAL_SECONDS
            ))
        )
        .is_err()
    );
    assert!(
        f.preserved(
            || check_inner(&f.directory, &f.roster, INTERVAL_SECONDS, || Ok(
                INTERVAL_SECONDS - 1
            ))
        )
        .is_err()
    );
    let lease = Lease::acquire(&f.directory).unwrap();
    assert!(
        check_with_roster(&f.directory, &f.roster, INTERVAL_SECONDS)
            .unwrap_err()
            .contains("holds the engineering lease")
    );
    drop(lease);
    std::fs::remove_file(f.directory.join("native-peer-identity.secret")).unwrap();
    assert!(
        f.preserved(|| check_with_roster(&f.directory, &f.roster, INTERVAL_SECONDS))
            .is_err()
    );
}

#[test]
fn transition_admission_rejects_malformed_and_signature_corrupted_persisted_certificates() {
    use redb::{ReadableDatabase, TableDefinition};
    const TABLE: TableDefinition<&str, &[u8]> =
        TableDefinition::new("engineering-checkpoint-attestations-v1");
    let f = Fixture::new();
    f.accepted(1);
    let path = f.directory.join("chain.redb");
    let original = {
        let database = redb::Database::open(&path).unwrap();
        let tx = database.begin_read().unwrap();
        tx.open_table(TABLE)
            .unwrap()
            .get("accepted")
            .unwrap()
            .unwrap()
            .value()
            .to_vec()
    };
    let mut corrupted = original.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    for bytes in [b"invalid".to_vec(), corrupted] {
        {
            let database = redb::Database::open(&path).unwrap();
            let tx = database.begin_write().unwrap();
            tx.open_table(TABLE)
                .unwrap()
                .insert("accepted", bytes.as_slice())
                .unwrap();
            tx.commit().unwrap();
        }
        assert!(
            f.preserved(|| check_with_roster(&f.directory, &f.roster, INTERVAL_SECONDS))
                .is_err()
        );
    }
}

#[test]
fn transition_admission_rejects_a_valid_vote_conflicting_with_actual_accepted_state() {
    let f = Fixture::new();
    f.accepted(1);
    std::fs::remove_file(
        f.directory
            .join("engineering-checkpoint-vote-00000000000000000001.bin"),
    )
    .unwrap();
    let verifier = crate::fixtures::TestVerifier;
    let store = Store::open_existing(
        f.directory.join("chain.redb"),
        local::load(&f.directory).unwrap(),
        &verifier,
    )
    .unwrap();
    let candidate = store
        .engineering_checkpoint_candidate(&f.legacy, 72, 1, INTERVAL_SECONDS + 1, &verifier)
        .unwrap();
    // Deliberately bypass the Store cursor guard to model a conflicting public
    // journal already present in an untrusted local inventory.
    f.authority.sign(&candidate, &f.legacy).unwrap();
    drop(store);
    let error = f
        .preserved(|| check_with_roster(&f.directory, &f.roster, INTERVAL_SECONDS + 1))
        .unwrap_err();
    assert!(error.contains("conflicts with the accepted statement"));
}
