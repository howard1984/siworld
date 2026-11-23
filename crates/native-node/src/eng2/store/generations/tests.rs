//! Storage-layer regressions using fixed canonical history views. These test
//! redb durability and the native identity seal, not block admission.

use super::*;
use crate::eng2::certificate::{Statement, Vote};
use libcrux_ml_dsa::ml_dsa_65;
use std::{
    fs::DirBuilder,
    io::Write,
    os::unix::{fs::DirBuilderExt, process::ExitStatusExt},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const BINDING: Binding = Binding {
    network: [17; 32],
    genesis: [18; 32],
    verifier: [19; 32],
};
const CHILD_DIRECTORY: &str = "SIWORLD_GENERATION_TEST_CHILD_DIRECTORY";
const CHILD_BOUNDARY: &str = "SIWORLD_GENERATION_TEST_CHILD_BOUNDARY";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut id = [0; 16];
        getrandom::fill(&mut id).unwrap();
        let path = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("siworld-generation-{}", crate::local::hex(&id)));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// Deterministic test chains share their first N blocks. Later blocks carry a
// branch label. Work is independent of block count to catch height comparisons.
struct Fixture {
    generation: Generation,
    path_id: FileId,
    height: u64,
    common: u64,
    branch: u8,
    work: u64,
}
impl Fixture {
    fn create(
        directory: &Path,
        generation: Generation,
        height: u64,
        common: u64,
        branch: u8,
        work: u64,
    ) -> Self {
        let path = generation.path(directory);
        let (mut file, _) = checked_file(&path, true).unwrap();
        file.write_all(b"fixed generation fixture\n").unwrap();
        Self::read(directory, generation, height, common, branch, work)
    }
    fn read(
        directory: &Path,
        generation: Generation,
        height: u64,
        common: u64,
        branch: u8,
        work: u64,
    ) -> Self {
        let path = generation.path(directory);
        assert_eq!(std::fs::read(&path).unwrap(), b"fixed generation fixture\n");
        Self {
            generation,
            path_id: path_file_id(&path).unwrap(),
            height,
            common,
            branch,
            work,
        }
    }
}
impl ChainView for Fixture {
    fn generation(&self) -> Generation {
        self.generation
    }
    fn binding(&self) -> Binding {
        BINDING
    }
    fn matches_path(&self, path: &Path) -> Result<bool> {
        Ok(path_file_id(path)? == self.path_id)
    }
    fn head(&self) -> Result<Head> {
        Ok(Head {
            height: self.height,
            id: self.block(self.height)?.unwrap(),
            work: Work::from(self.work),
        })
    }
    fn block(&self, height: u64) -> Result<Option<Hash>> {
        if height > self.height {
            return Ok(None);
        }
        if height == 0 {
            return Ok(Some(BINDING.genesis));
        }
        let mut input = [0; 9];
        input[..8].copy_from_slice(&height.to_le_bytes());
        input[8] = if height <= self.common {
            0
        } else {
            self.branch
        };
        Ok(Some(blake3::derive_key(
            "siworld fixed generation test block",
            &input,
        )))
    }
}

fn certificate(view: &Fixture, height: u64, slots: [u8; 2]) -> Certificate {
    let authorization_height = height + 24;
    let pairs = [1, 2, 3].map(|slot| ml_dsa_65::generate_key_pair([slot; 32]));
    let keys = pairs.each_ref().map(|pair| *pair.verification_key.as_ref());
    let statement = Statement {
        network: BINDING.network,
        checkpoint_height: height,
        checkpoint_block: view.block(height).unwrap().unwrap(),
        authorization_height,
        authorization_block: view.block(authorization_height).unwrap().unwrap(),
        roster_sequence: 0,
        roster_digest: [31; 32],
    };
    let encoded = statement.encode().unwrap();
    let votes = slots.map(|slot| Vote {
        slot,
        signature: *ml_dsa_65::sign(
            &pairs[usize::from(slot)].signing_key,
            &encoded,
            Statement::signing_context(),
            [42; 32],
        )
        .unwrap()
        .as_ref(),
    });
    let certificate = Certificate { statement, votes };
    certificate.check_signatures(&keys).unwrap();
    certificate
}

fn initialized(directory: &Path) -> (NativeIdentity, GenerationControl, Fixture) {
    let identity = NativeIdentity::initialize(directory, BINDING).unwrap();
    let mut initial = Fixture::create(directory, Generation::initial(), 0, 24, 1, 0);
    let mut control = GenerationControl::create_with(directory, &identity, &initial).unwrap();
    initial.height = 48;
    initial.work = 480;
    let expected = control.current().unwrap().clone();
    assert!(
        control
            .advance_verified_floor(
                &identity,
                &expected,
                &initial,
                certificate(&initial, 12, [0, 1])
            )
            .unwrap()
    );
    (identity, control, initial)
}

fn reopen(
    directory: &Path,
    identity: &NativeIdentity,
    view: &Fixture,
) -> Result<GenerationControl> {
    GenerationControl::open_with(directory, identity, |record, binding| {
        verify(record, binding, directory, view)?;
        Ok(())
    })
    .map(|(control, ())| control)
}

#[test]
fn imported_head_and_floor_are_published_together() {
    let dir = Scratch::new();
    let owner = NativeIdentity::initialize(dir.path(), BINDING).unwrap();
    let chain = Fixture::create(dir.path(), Generation::initial(), 48, 24, 1, 480);
    let certificate = certificate(&chain, 12, [0, 1]);
    let mut wrong = certificate.clone();
    wrong.statement.authorization_block = [34; 32];
    assert!(matches!(
        GenerationControl::create_record(dir.path(), &owner, &chain, Some(wrong)),
        Err(Error::Invalid(
            "import authorization differs from selected history"
        ))
    ));
    GenerationControl::ensure_new(dir.path()).unwrap();
    let control =
        GenerationControl::create_record(dir.path(), &owner, &chain, Some(certificate.clone()))
            .unwrap();
    drop(control);
    assert!(GenerationControl::ensure_new(dir.path()).is_err());
    let reopened = reopen(dir.path(), &owner, &chain).unwrap();
    let record = reopened.current().unwrap();
    assert_eq!(record.floor(), Some(&certificate));
    assert_eq!(record.published_head(), chain.head().unwrap());
}

#[test]
fn native_genesis_can_reopen_but_a_different_open_store_cannot_claim_its_path() {
    // Debug native state initialization can exceed the test harness stack.
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(native_genesis_store_binding)
        .unwrap()
        .join()
        .unwrap();
}

fn native_genesis_store_binding() {
    use crate::eng2::{
        genesis::{FeeMode, Genesis},
        state_components::Limits,
    };

    let dir = Scratch::new();
    let fixture = crate::eng2::snapshot::tests::bootstrap();
    let genesis = || {
        Genesis::seal(
            fixture.chain.config.clone(),
            fixture.governance.clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap()
    };
    let binding = genesis().peer_binding();
    let identity = NativeIdentity::initialize(dir.path(), binding).unwrap();
    let load_identity = || NativeIdentity::load(dir.path(), &binding).unwrap();
    let limits = Limits {
        max_leaves: 4096,
        max_nullifiers: 4096,
        max_component_bytes: 1024 * 1024,
    };
    let initial = Generation::initial();
    let selected_path = initial.path(dir.path());
    let wrong_path = dir.path().join("unselected.redb");
    let mut selected = Store::create(&selected_path, genesis(), limits).unwrap();
    let mut wrong = Store::create(&wrong_path, genesis(), limits).unwrap();
    selected
        .enable_authenticated_restart(load_identity())
        .unwrap();
    wrong.enable_authenticated_restart(load_identity()).unwrap();
    assert!(matches!(
        GenerationControl::create(
            dir.path(),
            &identity,
            &StoreView::new(initial, &wrong).unwrap()
        ),
        Err(Error::Invalid(
            "open generation does not match its selected file"
        ))
    ));
    let control = GenerationControl::create(
        dir.path(),
        &identity,
        &StoreView::new(initial, &selected).unwrap(),
    )
    .unwrap();
    drop(control);
    drop(selected);
    drop(wrong);

    assert!(matches!(
        GenerationControl::open_existing(dir.path(), &identity, |_| Store::resume_existing(
            &wrong_path,
            genesis(),
            limits
        )),
        Err(Error::Invalid(
            "open generation does not match its selected file"
        ))
    ));
    let (reopened, chain) = GenerationControl::open_existing(dir.path(), &identity, |path| {
        Store::resume_existing(path, genesis(), limits)
    })
    .unwrap();
    assert_eq!(reopened.current().unwrap().generation(), initial);
    assert_eq!(
        reopened.current().unwrap().published_head().id,
        chain.engine().genesis().id()
    );
}

#[test]
fn generation_publication_rechecks_current_work_and_floor() {
    let dir = Scratch::new();
    let (identity, mut control, initial) = initialized(dir.path());
    let stale = control.current().unwrap().clone();
    let newer = certificate(&initial, 24, [1, 2]);
    assert!(
        control
            .advance_verified_floor(&identity, &stale, &initial, newer.clone())
            .unwrap()
    );
    let expected = control.current().unwrap().clone();
    assert_eq!(expected.floor(), Some(&newer));

    assert!(
        !control
            .advance_verified_floor(
                &identity,
                &expected,
                &initial,
                certificate(&initial, 24, [0, 2])
            )
            .unwrap()
    );
    assert_eq!(control.current().unwrap().floor(), Some(&newer));
    let low = Fixture::create(
        dir.path(),
        expected.generation().successor([35; 32]).unwrap(),
        80,
        24,
        3,
        480,
    );
    assert_eq!(
        control.publish_with(&identity, &stale, &initial, &low, |_| Ok(())),
        Err(Error::Stale)
    );
    assert_eq!(
        control.publish_with(&identity, &expected, &initial, &low, |_| Ok(())),
        Err(Error::NotGreaterWork)
    );

    let conflicts = Fixture::create(
        dir.path(),
        expected.generation().successor([36; 32]).unwrap(),
        80,
        23,
        3,
        800,
    );
    assert!(matches!(
        control.publish_with(&identity, &expected, &initial, &conflicts, |_| Ok(())),
        Err(Error::Invalid(
            "selected generation does not contain the accepted checkpoint"
        ))
    ));

    let candidate = Fixture::create(
        dir.path(),
        expected.generation().successor([37; 32]).unwrap(),
        36,
        24,
        3,
        720,
    );
    control
        .publish_with(&identity, &expected, &initial, &candidate, |_| Ok(()))
        .unwrap();
    let selected = control.current().unwrap().clone();
    assert_eq!(selected.generation(), candidate.generation);
    assert_eq!(selected.published_head(), candidate.head().unwrap());
    assert_eq!(selected.floor(), Some(&newer));
    drop(control);
    assert_eq!(
        reopen(dir.path(), &identity, &candidate)
            .unwrap()
            .current()
            .unwrap(),
        &selected
    );
}

#[test]
fn generation_paths_must_name_the_authenticated_open_files() {
    let dir = Scratch::new();
    let (identity, mut control, initial) = initialized(dir.path());
    let expected = control.current().unwrap().clone();
    let generation = expected.generation().successor([35; 32]).unwrap();
    let candidate = Fixture::create(dir.path(), generation, 80, 12, 3, 800);

    let path = generation.path(dir.path());
    std::fs::rename(&path, dir.path().join("previous")).unwrap();
    let other = Fixture::create(dir.path(), generation, 80, 12, 3, 800);
    assert!(matches!(
        control.publish_with(&identity, &expected, &initial, &candidate, |_| Ok(())),
        Err(Error::Invalid(
            "open generation does not match its selected file"
        ))
    ));

    let path = dir.path().join(CONTROL_FILE);
    std::fs::rename(&path, dir.path().join("previous-control")).unwrap();
    checked_file(&path, true).unwrap();
    assert!(matches!(
        control.publish_with(&identity, &expected, &initial, &other, |_| Ok(())),
        Err(Error::Invalid("generation control file identity changed"))
    ));
}

#[test]
fn stale_missing_corrupt_or_wrong_identity_is_not_recovered_by_guessing() {
    let dir = Scratch::new();
    let (identity, mut control, initial) = initialized(dir.path());
    let initial_record = control.current().unwrap().clone();
    let candidate = Fixture::create(
        dir.path(),
        initial_record.generation().successor([33; 32]).unwrap(),
        48,
        12,
        3,
        600,
    );
    control
        .publish_with(&identity, &initial_record, &initial, &candidate, |_| Ok(()))
        .unwrap();
    let expected = control.current().unwrap().clone();
    control
        .advance_verified_floor(
            &identity,
            &expected,
            &candidate,
            certificate(&candidate, 24, [0, 2]),
        )
        .unwrap();
    drop(control);

    let another = Scratch::new();
    let wrong = NativeIdentity::initialize(another.path(), BINDING).unwrap();
    assert!(matches!(
        reopen(dir.path(), &wrong, &candidate),
        Err(Error::Invalid("generation control seal rejected"))
    ));
    assert!(reopen(dir.path(), &identity, &initial).is_err());

    let mut stale = Fixture {
        height: 23,
        work: 410,
        ..candidate
    };
    assert!(reopen(dir.path(), &identity, &stale).is_err());

    // Reconstruct another authenticated view with a later head that preserves
    // the publication pin but no longer has the newer accepted checkpoint.
    let floor_dir = Scratch::new();
    let (floor_identity, mut floor_control, mut floor_view) = initialized(floor_dir.path());
    let before = floor_control.current().unwrap().clone();
    let newer = certificate(&floor_view, 24, [0, 2]);
    floor_control
        .advance_verified_floor(&floor_identity, &before, &floor_view, newer)
        .unwrap();
    drop(floor_control);
    floor_view.common = 23;
    floor_view.branch = 5;
    assert!(matches!(
        reopen(floor_dir.path(), &floor_identity, &floor_view),
        Err(Error::Invalid(
            "selected generation does not contain the accepted checkpoint"
        ))
    ));

    let candidate_path = stale.generation.path(dir.path());
    std::fs::rename(&candidate_path, dir.path().join("moved-generation")).unwrap();
    assert!(reopen(dir.path(), &identity, &stale).is_err());
    std::fs::rename(dir.path().join("moved-generation"), candidate_path).unwrap();
    stale.height = 48;
    stale.work = 600;
    let path = dir.path().join(CONTROL_FILE);
    std::fs::rename(&path, dir.path().join("moved-control")).unwrap();
    assert!(reopen(dir.path(), &identity, &stale).is_err());
    assert!(!path.exists());
    std::fs::rename(dir.path().join("moved-control"), &path).unwrap();
    let (database, _) = control_database(dir.path(), false).unwrap();
    let mut transaction = database.begin_write().unwrap();
    immediate(&mut transaction).unwrap();
    {
        let mut table = transaction.open_table(TABLE).unwrap();
        let mut row = table.get(KEY).unwrap().unwrap().value().to_vec();
        *row.last_mut().unwrap() ^= 1;
        table.insert(KEY, row.as_slice()).unwrap();
    }
    transaction.commit().unwrap();
    drop(database);
    assert!(matches!(
        reopen(dir.path(), &identity, &stale),
        Err(Error::Invalid("generation control seal rejected"))
    ));
}

#[test]
fn crash_child() {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
        return;
    };
    let directory = PathBuf::from(directory);
    let killed_at = match std::env::var(CHILD_BOUNDARY).unwrap().as_str() {
        "before" => CommitBoundary::BeforeCommit,
        "after" => CommitBoundary::AfterCommit,
        _ => panic!("invalid fixture boundary"),
    };
    let identity = NativeIdentity::load(&directory, &BINDING).unwrap();
    let initial = Fixture::read(&directory, Generation::initial(), 48, 24, 1, 480);
    let generation = initial.generation.successor([3; 32]).unwrap();
    let candidate = Fixture::read(&directory, generation, 70, 12, 3, 700);
    let mut control = reopen(&directory, &identity, &initial).unwrap();
    let expected = control.current().unwrap().clone();
    control
        .publish_with(&identity, &expected, &initial, &candidate, |point| {
            if point == killed_at {
                std::fs::write(directory.join("at-boundary"), b"ready").unwrap();
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        })
        .unwrap();
    panic!("fixture did not stop at the configured durability boundary");
}

#[test]
fn process_kill_reopens_only_the_complete_selected_generation() {
    for point in ["before", "after"] {
        let dir = Scratch::new();
        let (identity, control, initial) = initialized(dir.path());
        let expected = control.current().unwrap().clone();
        drop(control);
        let next = expected.generation().successor([3; 32]).unwrap();
        let candidate = Fixture::create(dir.path(), next, 70, 12, 3, 700);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "eng2::store::generations::tests::crash_child",
                "--nocapture",
            ])
            .env(CHILD_DIRECTORY, dir.path())
            .env(CHILD_BOUNDARY, point)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !dir.path().join("at-boundary").exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "fixture stopped before {point}"
            );
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("fixture timed out at {point}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(9));

        let selected = if point == "before" {
            &initial
        } else {
            &candidate
        };
        let control = reopen(dir.path(), &identity, selected).unwrap();
        let record = control.current().unwrap();
        assert_eq!(record.generation(), selected.generation());
        assert_eq!(record.floor(), expected.floor());
        if point == "before" {
            assert_eq!(record, &expected);
        } else {
            assert_eq!(record.published_head(), candidate.head().unwrap());
        }
    }
}
