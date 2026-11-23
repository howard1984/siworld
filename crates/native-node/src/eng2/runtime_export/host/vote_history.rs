//! Signer custody outside the canonical store and its recoverable exports.
//!
//! The operator must never restore the high-water journal from a backup or
//! clone an active signer. A separate journal detects restoration of vote
//! history even when a restore retains its inode. This does not defend
//! against simultaneous rollback of both custody files.

use super::*;
use crate::eng2::certificate::{SIGNATURE_BYTES, STATEMENT_BYTES};
use std::{
    fs::{File, symlink_metadata},
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
};

const HEADER_BYTES: usize = 56;
const RECORD_BYTES: usize = STATEMENT_BYTES + 1 + SIGNATURE_BYTES;
const VOTE_MAGIC: &[u8; 8] = b"SW2VOTE1";
const GUARD_MAGIC: &[u8; 8] = b"SW2HIGH1";
const ABSTAIN: &str = "checkpoint signer custody unavailable; abstaining";

pub(super) struct History {
    votes: Journal,
    guard: Journal,
}

struct Journal {
    path: PathBuf,
    file: File,
    header: [u8; HEADER_BYTES],
    end: u64,
    healthy: bool,
}

fn owner_directory(path: &Path) -> Result<(), String> {
    let metadata = symlink_metadata(path).map_err(|_| ABSTAIN)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(ABSTAIN.into());
    }
    Ok(())
}

fn location(key: &Path, export: &Path, suffix: &str) -> Result<PathBuf, String> {
    let parent = key.parent().ok_or(ABSTAIN)?;
    owner_directory(parent)?;
    let parent = parent.canonicalize().map_err(|_| ABSTAIN)?;
    let data = export
        .parent()
        .ok_or(ABSTAIN)?
        .canonicalize()
        .map_err(|_| ABSTAIN)?;
    if parent.starts_with(&data) {
        return Err("checkpoint signer custody must be outside the node data directory".into());
    }
    let mut name = key.file_name().ok_or(ABSTAIN)?.to_os_string();
    name.push(suffix);
    Ok(parent.join(name))
}

fn open_file(path: &Path, create: bool) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true).append(true).mode(0o600).custom_flags(
        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK)
            .bits() as i32,
    );
    if create {
        options.create_new(true);
    }
    let file = options.open(path).map_err(|_| ABSTAIN)?;
    let metadata = file.metadata().map_err(|_| ABSTAIN)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ABSTAIN.into());
    }
    file.try_lock().map_err(|_| ABSTAIN)?;
    Ok(file)
}

fn binding(
    file: &File,
    signer: &ExistingSigner,
    magic: &[u8; 8],
) -> Result<[u8; HEADER_BYTES], String> {
    let metadata = file.metadata().map_err(|_| ABSTAIN)?;
    let mut hash = blake3::Hasher::new_derive_key("siworld eng2 signer vote custody v1");
    hash.update(&signer.network);
    hash.update(&signer.genesis);
    hash.update(&signer.rules);
    hash.update(&[signer.slot]);
    hash.update(&signer.public);

    let mut bytes = [0; HEADER_BYTES];
    bytes[..8].copy_from_slice(magic);
    bytes[8..40].copy_from_slice(hash.finalize().as_bytes());
    bytes[40..48].copy_from_slice(&metadata.dev().to_le_bytes());
    bytes[48..56].copy_from_slice(&metadata.ino().to_le_bytes());
    Ok(bytes)
}

impl Journal {
    fn initialize(path: &Path, signer: &ExistingSigner, magic: &[u8; 8]) -> Result<(), String> {
        let mut file = open_file(path, true)?;
        let header = binding(&file, signer, magic)?;
        file.write_all(&header)
            .and_then(|_| file.sync_all())
            .map_err(|_| ABSTAIN)?;
        crate::store::sync_parent(path)
    }

    fn open(path: PathBuf, signer: &ExistingSigner, magic: &[u8; 8]) -> Result<Self, String> {
        let file = open_file(&path, false)?;
        let end = file.metadata().map_err(|_| ABSTAIN)?.len();
        let header = binding(&file, signer, magic)?;
        let mut this = Self {
            path,
            file,
            header,
            end,
            healthy: true,
        };
        this.last(signer)?;
        Ok(this)
    }

    fn last(&mut self, signer: &ExistingSigner) -> Result<Option<(Statement, Vote)>, String> {
        let file = self.file.metadata().map_err(|_| ABSTAIN)?;
        let path = symlink_metadata(&self.path).map_err(|_| ABSTAIN)?;
        if !self.healthy
            || !path.is_file()
            || path.ino() != file.ino()
            || path.dev() != file.dev()
            || path.nlink() != 1
            || path.permissions().mode() & 0o777 != 0o600
            || path.uid() != rustix::process::geteuid().as_raw()
            || file.len() != self.end
        {
            return Err(ABSTAIN.into());
        }
        let entries = self.end.checked_sub(HEADER_BYTES as u64).ok_or(ABSTAIN)?;
        if entries % RECORD_BYTES as u64 != 0 {
            return Err(ABSTAIN.into());
        }
        let mut header = [0; HEADER_BYTES];
        self.file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.read_exact(&mut header))
            .map_err(|_| ABSTAIN)?;
        if header != self.header {
            return Err(ABSTAIN.into());
        }
        if entries == 0 {
            return Ok(None);
        }
        let mut record = [0; RECORD_BYTES];
        self.file
            .seek(SeekFrom::End(-(RECORD_BYTES as i64)))
            .and_then(|_| self.file.read_exact(&mut record))
            .map_err(|_| ABSTAIN)?;
        let statement =
            Statement::decode(&record[..STATEMENT_BYTES], signer.network).map_err(|_| ABSTAIN)?;
        let vote = Vote {
            slot: record[STATEMENT_BYTES],
            signature: record[STATEMENT_BYTES + 1..]
                .try_into()
                .expect("fixed vote record"),
        };
        if vote.slot != signer.slot {
            return Err(ABSTAIN.into());
        }
        ml_dsa_65::verify(
            &super::super::MLDSA65VerificationKey::new(signer.public),
            &record[..STATEMENT_BYTES],
            Statement::signing_context(),
            &super::super::MLDSA65Signature::new(vote.signature),
        )
        .map_err(|_| ABSTAIN)?;
        Ok(Some((statement, vote)))
    }

    fn persist(&mut self, statement: &Statement, vote: &Vote) -> Result<(), String> {
        let statement = statement.encode().map_err(|_| ABSTAIN)?;
        let mut record = [0; RECORD_BYTES];
        record[..STATEMENT_BYTES].copy_from_slice(&statement);
        record[STATEMENT_BYTES] = vote.slot;
        record[STATEMENT_BYTES + 1..].copy_from_slice(&vote.signature);
        let new_end = self.end.checked_add(RECORD_BYTES as u64).ok_or(ABSTAIN)?;
        // An ambiguous write disables this handle.
        self.healthy = false;
        self.file
            .write_all(&record)
            .and_then(|_| self.file.sync_all())
            .map_err(|_| ABSTAIN)?;
        self.end = new_end;
        self.healthy = true;
        Ok(())
    }
}

impl History {
    /// Initial provisioning only. The key must never have signed for this
    /// genesis. Neither an existing journal nor partial initialization is reset.
    pub(super) fn initialize(
        key: &Path,
        export: &Path,
        signer: &ExistingSigner,
    ) -> Result<(), String> {
        let votes = location(key, export, ".votes")?;
        let guard = location(key, export, ".vote-high-water")?;
        for path in [&votes, &guard] {
            match symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(ABSTAIN.into()),
            }
        }
        Journal::initialize(&guard, signer, GUARD_MAGIC)?;
        Journal::initialize(&votes, signer, VOTE_MAGIC)
    }

    pub(super) fn open(key: &Path, export: &Path, signer: &ExistingSigner) -> Result<Self, String> {
        // Every caller acquires the two nonblocking locks in the same order.
        let guard = Journal::open(
            location(key, export, ".vote-high-water")?,
            signer,
            GUARD_MAGIC,
        )?;
        let votes = Journal::open(location(key, export, ".votes")?, signer, VOTE_MAGIC)?;
        Ok(Self { votes, guard })
    }

    pub(super) fn sign(
        &mut self,
        signer: &ExistingSigner,
        store: &Store,
        prepared: &PreparedCheckpoint,
        random: [u8; 32],
    ) -> Result<Option<Vote>, String> {
        prepared.check_current(store)?;
        let statement = prepared.statement();
        let floor = store.finalized_checkpoint()?.map(|certificate| {
            let statement = certificate.statement;
            (statement.checkpoint_height, statement.checkpoint_block)
        });
        let last = self.votes.last(signer)?;
        let high_water = self.guard.last(signer)?;
        let action = authorize(
            statement,
            floor,
            last.as_ref(),
            high_water.as_ref(),
            |height| {
                store
                    .header(height)?
                    .id()
                    .map_err(|_| "checkpoint signing ancestor identity unavailable".into())
            },
        )?;
        match action {
            Action::Abstain => Ok(None),
            Action::Resend => {
                let (_, vote) = last.ok_or(ABSTAIN)?;
                prepared.verify_vote(&vote)?;
                Ok(Some(vote))
            }
            Action::Sign => {
                let vote = prepared.sign(store, signer.slot, &signer.key, random)?;
                self.persist(statement, &vote)?;
                Ok(Some(vote))
            }
        }
    }

    fn persist(&mut self, statement: &Statement, vote: &Vote) -> Result<(), String> {
        // The guard must be durable first. A crash after this write and before
        // persisting the ordinary history looks like a restore; it cannot
        // lower the upper bound. Neither failure can release a vote.
        self.guard.persist(statement, vote)?;
        self.votes.persist(statement, vote)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Abstain,
    Resend,
    Sign,
}

fn authorize(
    candidate: &Statement,
    floor: Option<(u64, Hash)>,
    previous: Option<&(Statement, Vote)>,
    high_water: Option<&(Statement, Vote)>,
    header_id: impl Fn(u64) -> Result<Hash, String>,
) -> Result<Action, String> {
    if let Some((height, id)) = floor
        && (candidate.checkpoint_height <= height || header_id(height)? != id)
    {
        return Ok(Action::Abstain);
    }
    let highest_possible = high_water.map_or(0, |(statement, _)| statement.checkpoint_height);
    // The guard is written first. Finding a later vote in the ordinary journal
    // means the guard is unreliable. Never resume from it.
    if previous.is_some_and(|(statement, _)| {
        high_water.is_none() || statement.checkpoint_height > highest_possible
    }) {
        return Err(ABSTAIN.into());
    }
    let floor_height = floor.map_or(0, |(height, _)| height);
    if previous != high_water || floor_height > highest_possible {
        // A gap in custody cannot be inferred from observed peer heights or
        // from the old vote history. Wait for a locally accepted certificate
        // 24 blocks beyond the separately retained upper bound.
        return Ok(
            if floor_height
                .checked_sub(highest_possible)
                .is_some_and(|gap| gap >= super::super::CHECKPOINT_CONFIRMATIONS)
            {
                Action::Sign
            } else {
                Action::Abstain
            },
        );
    }
    let previous = previous.map(|(statement, _)| statement);
    let Some(previous) = previous else {
        return Ok(Action::Sign);
    };
    match candidate.checkpoint_height.cmp(&previous.checkpoint_height) {
        std::cmp::Ordering::Less => Ok(Action::Abstain),
        std::cmp::Ordering::Equal => Ok(if candidate == previous {
            Action::Resend
        } else {
            Action::Abstain
        }),
        std::cmp::Ordering::Greater => Ok(
            if header_id(previous.checkpoint_height)? == previous.checkpoint_block {
                Action::Sign
            } else {
                Action::Abstain
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eng2::runtime_export::tests::Directory;

    fn statement(network: Hash, height: u64, id: u8) -> Statement {
        Statement {
            network,
            checkpoint_height: height,
            checkpoint_block: [id; 32],
            authorization_height: height + 24,
            authorization_block: [8; 32],
            roster_sequence: 0,
            roster_digest: [9; 32],
        }
    }

    fn pair(statement: Statement) -> (Statement, Vote) {
        (
            statement,
            Vote {
                slot: 0,
                signature: [0; SIGNATURE_BYTES],
            },
        )
    }

    #[test]
    fn missing_custody_disables_voting_but_not_keyless_slot_zero_coordination() {
        use crate::eng2::{
            genesis::{FeeMode, Genesis},
            snapshot::tests::{bootstrap, limits},
        };
        use crate::wire::SlotRule;

        let files = Directory::new();
        let state = bootstrap();
        let genesis = Genesis::seal_with_rule(
            state.chain.config.clone().with_one_hour_asert().unwrap(),
            state.governance().clone(),
            FeeMode::LegacyMiner,
            SlotRule::PublicGenesis,
        )
        .unwrap();
        let store = Store::create(&files.0.join("chain.redb"), genesis, limits().chain).unwrap();
        let keys = Directory::new();
        let key_dir = keys.private("keys");
        let export = files.private("export");
        for (slot, seed) in [(0, 3), (1, 4)] {
            let key = key_dir.join(format!("signer-{slot}.bin"));
            super::super::tests::key_fixture(&key, &store, slot, seed);
            let signer = ExistingSigner::load_for_host(&key, &export, &store).unwrap();
            assert!(!signer.can_sign(&store));
            assert_eq!(signer.can_propose(&store), slot == 0);
        }
    }

    #[test]
    fn next_vote_must_extend_own_unpublished_vote_and_accepted_floor() {
        let first = pair(statement([1; 32], 36, 2));
        let next = statement([1; 32], 48, 3);
        let fork = pair(statement([1; 32], 36, 5));
        let matching = |height| match height {
            12 => Ok([4; 32]),
            36 => Ok([2; 32]),
            _ => Err("unexpected query".into()),
        };
        assert_eq!(
            authorize(
                &next,
                Some((12, [4; 32])),
                Some(&first),
                Some(&first),
                matching
            )
            .unwrap(),
            Action::Sign
        );
        assert_eq!(
            authorize(
                &next,
                Some((12, [6; 32])),
                Some(&first),
                Some(&first),
                matching
            )
            .unwrap(),
            Action::Abstain
        );
        assert_eq!(
            authorize(
                &next,
                Some((12, [4; 32])),
                Some(&fork),
                Some(&fork),
                matching
            )
            .unwrap(),
            Action::Abstain
        );
        assert_eq!(
            authorize(&fork.0, None, Some(&first), Some(&first), matching).unwrap(),
            Action::Abstain
        );
        assert_eq!(
            authorize(&first.0, None, Some(&first), Some(&first), matching).unwrap(),
            Action::Resend
        );
    }

    #[test]
    fn signer_older_than_floor_waits_for_two_certificate_intervals() {
        let known_last = pair(statement([1; 32], 12, 2));
        let candidate = statement([1; 32], 60, 3);
        let header = |_| Ok([4; 32]);
        for (height, expected) in [(35, Action::Abstain), (36, Action::Sign)] {
            assert_eq!(
                authorize(
                    &candidate,
                    Some((height, [4; 32])),
                    Some(&known_last),
                    Some(&known_last),
                    header
                )
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn a_rollback_gap_needs_a_valid_floor_twenty_four_blocks_above_the_guard() {
        let stale = pair(statement([1; 32], 12, 2));
        let guard = pair(statement([1; 32], 36, 3));
        let candidate = statement([1; 32], 72, 4);
        let header = |_| Ok([5; 32]);
        for (floor, expected) in [
            (None, Action::Abstain),
            (Some((48, [5; 32])), Action::Abstain),
            (Some((59, [5; 32])), Action::Abstain),
            (Some((60, [6; 32])), Action::Abstain),
            (Some((60, [5; 32])), Action::Sign),
            (Some((72, [5; 32])), Action::Abstain),
        ] {
            for history in [None, Some(&stale)] {
                assert_eq!(
                    authorize(&candidate, floor, history, Some(&guard), header).unwrap(),
                    expected,
                );
            }
        }
        assert!(
            authorize(
                &candidate,
                Some((60, [5; 32])),
                Some(&guard),
                Some(&stale),
                header
            )
            .is_err()
        );
        assert!(authorize(&candidate, Some((60, [5; 32])), Some(&guard), None, header).is_err());
    }

    #[test]
    fn exact_private_vote_survives_reopen_but_torn_or_copied_record_abstains() {
        let signer_directory = Directory::new();
        let key = signer_directory.private("keys").join("signer.bin");
        let data_directory = Directory::new();
        let export = data_directory.private("export");
        let store = data_directory.store();
        super::super::tests::key_fixture(&key, &store, 0, 3);
        let signer = ExistingSigner::load(&key, &store).unwrap();

        assert!(History::open(&key, &export, &signer).is_err());
        History::initialize(&key, &export, &signer).unwrap();
        assert!(History::initialize(&key, &export, &signer).is_err());
        let mut history = History::open(&key, &export, &signer).unwrap();
        assert!(History::open(&key, &export, &signer).is_err());
        assert!(history.votes.last(&signer).unwrap().is_none());
        assert!(history.guard.last(&signer).unwrap().is_none());

        let first = statement(signer.network, 12, 2);
        let signature = ml_dsa_65::sign(
            &signer.key,
            &first.encode().unwrap(),
            Statement::signing_context(),
            [4; 32],
        )
        .unwrap();
        let vote = Vote {
            slot: signer.slot,
            signature: *signature.as_ref(),
        };
        history.persist(&first, &vote).unwrap();
        drop(history);
        let mut history = History::open(&key, &export, &signer).unwrap();
        let expected = Some((first, vote));
        assert_eq!(history.votes.last(&signer).unwrap(), expected);
        assert_eq!(history.guard.last(&signer).unwrap(), expected);
        let path = history.votes.path.clone();
        let guard_path = history.guard.path.clone();
        let inode = history.votes.file.metadata().unwrap().ino();
        drop(history);

        // Simulate an in-place restore to the empty initial journal. Its
        // identity is unchanged; the separate guard is the only evidence of
        // the previously persisted vote. A surviving guard-only write from a
        // crash between the two fsyncs has the same observable state.
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(HEADER_BYTES as u64)
            .unwrap();
        let mut history = History::open(&key, &export, &signer).unwrap();
        assert_eq!(history.votes.file.metadata().unwrap().ino(), inode);
        let stale = history.votes.last(&signer).unwrap();
        let bound = history.guard.last(&signer).unwrap();
        assert!(stale.is_none());
        assert_eq!(bound, expected);
        let next = statement(signer.network, 24, 9);
        assert_eq!(
            authorize(&next, None, stale.as_ref(), bound.as_ref(), |_| panic!(
                "unexpected ancestor"
            ))
            .unwrap(),
            Action::Abstain,
        );
        let restored = path.with_extension("restored");
        std::fs::copy(&path, &restored).unwrap();
        std::fs::rename(&restored, &path).unwrap();
        assert!(history.votes.last(&signer).is_err());
        drop(history);
        assert!(History::open(&key, &export, &signer).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(History::initialize(&key, &export, &signer).is_err());
        Journal::initialize(&path, &signer, VOTE_MAGIC).unwrap();
        open_file(&guard_path, false)
            .unwrap()
            .write_all(&[0])
            .unwrap();
        assert!(History::open(&key, &export, &signer).is_err());
        std::fs::remove_file(&guard_path).unwrap();
        assert!(History::initialize(&key, &export, &signer).is_err());
        assert!(History::open(&key, &export, &signer).is_err());
    }
}
