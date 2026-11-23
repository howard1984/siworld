//! Replay an eligible branch away from the selected chain. Only a completed
//! and sealed generation can cross the owner's canonical publication barrier.

use super::*;
use crate::eng2::{
    branches::{CandidatePath, ShadowBranch},
    genesis::Genesis,
    store::{
        generations::{Generation, Record},
        shadow_prefix::ShadowPrefix,
    },
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const LIVE_DISK_HEADROOM: u64 = 20 * 1024 * 1024 * 1024;
const RETRY_AFTER: Duration = Duration::from_secs(60);
const PARKED_LIFETIME: Duration = Duration::from_secs(300);
const ACTIVE_IDLE_LIMIT: Duration = Duration::from_secs(300);
const MAX_DEFERRED: usize = 64;
const SCAN_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Default)]
pub(super) struct Scheduler {
    active: Option<Job>,
    parked: Option<Parked>,
    deferred: VecDeque<(Hash, Instant)>,
    scanned: Option<Instant>,
    empty_scan: Option<ScanKey>,
    alarm: Option<&'static str>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ScanKey {
    revision: u64,
    tip: Hash,
    fence: Option<(u64, Hash)>,
}

impl Scheduler {
    pub(super) fn active(&self) -> bool {
        self.active.is_some()
    }

    pub(super) fn alarm(&self) -> Option<&'static str> {
        self.alarm
    }

    fn defer(&mut self, id: Hash, now: Instant) {
        self.deferred
            .retain(|(other, expiry)| *other != id && *expiry > now);
        if self.deferred.len() >= MAX_DEFERRED {
            self.deferred.pop_front();
        }
        self.deferred.push_back((id, now + RETRY_AFTER));
        self.empty_scan = None;
        self.alarm = Some("reorganization_shadow_replay_deferred");
    }
}

struct Job {
    candidate: Hash,
    expected: Record,
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<ReplayOutcome, String>>>,
    progress: Arc<Mutex<Instant>>,
    park_expires: Option<Instant>,
}

struct Parked {
    replay: Box<Replay>,
    expected: Record,
    retry_at: Instant,
    expires: Instant,
}

impl Drop for Job {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.cancel.store(true, Ordering::Release);
            let _ = thread.join();
        }
    }
}

impl Job {
    fn spawn(
        candidate: Hash,
        expected: Record,
        cancel: Arc<AtomicBool>,
        progress: Arc<Mutex<Instant>>,
        park_expires: Option<Instant>,
        work: impl FnOnce() -> Result<ReplayOutcome, String> + Send + 'static,
    ) -> Result<Self, String> {
        let thread = std::thread::Builder::new()
            .name("eng2-shadow-replay".into())
            .spawn(work)
            .map_err(|_| "shadow replay worker unavailable")?;
        Ok(Self {
            candidate,
            expected,
            cancel,
            thread: Some(thread),
            progress,
            park_expires,
        })
    }
}

struct Scratch {
    path: PathBuf,
    store: Option<Store>,
    preserve: bool,
}

impl Scratch {
    fn store(&self) -> &Store {
        self.store.as_ref().expect("open shadow store")
    }

    fn store_mut(&mut self) -> &mut Store {
        self.store.as_mut().expect("open shadow store")
    }

    fn disk_room(&self, next: usize) -> Result<(), String> {
        let disk = rustix::fs::statvfs(&self.path).map_err(|_| "shadow disk probe unavailable")?;
        let available = (disk.f_bavail as u128) * (disk.f_frsize as u128);
        let metadata =
            std::fs::symlink_metadata(&self.path).map_err(|_| "shadow database unavailable")?;
        let estimate = (next as u128) * 4 + 64 * 1024 * 1024;
        if u128::from(metadata.len()) + estimate > u128::from(MAX_FILE_BYTES) {
            return Err("shadow database exceeds file budget".into());
        }
        if available < u128::from(LIVE_DISK_HEADROOM) + estimate {
            return Err("shadow disk budget deferred".into());
        }
        Ok(())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.preserve
            && self
                .store
                .as_ref()
                .is_some_and(|store| store.matches_owner_path(&self.path) == Ok(true))
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

struct Ready {
    scratch: Scratch,
    prefix: ShadowPrefix,
    generation: Generation,
    candidate: Hash,
    _memory: Vec<crate::p2p::Reservation>,
}

struct Inputs {
    prefix: ShadowPrefix,
    archive: ShadowBranch,
    path: CandidatePath,
    candidate: Hash,
    generation: Generation,
    target: PathBuf,
    genesis: Vec<u8>,
    limits: super::super::ImportLimits,
    memory: crate::p2p::Budget,
    verifier: Arc<NativeVerifier>,
    cancel: Arc<AtomicBool>,
    progress: Arc<Mutex<Instant>>,
}

struct Replay {
    inputs: Inputs,
    scratch: Scratch,
    retained: Vec<crate::p2p::Reservation>,
    initialized: bool,
    replacement_done: usize,
}

enum ReplayOutcome {
    Ready(Box<Ready>),
    Deferred(Box<Replay>),
}

fn checkpoint_archive(store: &Store, limits: super::super::ImportLimits) -> Result<(), String> {
    if store
        .engine()
        .state()
        .height()
        .is_multiple_of(crate::eng2::runtime_export::CHECKPOINT_INTERVAL)
    {
        store.archive_checkpoint_anchor(limits)?;
    }
    Ok(())
}

impl Replay {
    fn new(inputs: Inputs) -> Result<Self, String> {
        inputs.checkpoint_progress()?;
        let store = Store::create(
            &inputs.target,
            Genesis::decode(&inputs.genesis)?,
            inputs.limits.chain,
        )?;
        Ok(Self {
            scratch: Scratch {
                path: inputs.target.clone(),
                store: Some(store),
                preserve: false,
            },
            inputs,
            retained: Vec::new(),
            initialized: false,
            replacement_done: 0,
        })
    }

    fn execute(&mut self, header: Header, body: Body) -> Result<(), String> {
        let policy = self.scratch.store().engine().body_policy();
        let nonproof = body
            .transactions
            .iter()
            .try_fold(body.settlement_proof.len(), |n, tx| {
                n.checked_add(tx.proof.len())
            })
            .and_then(|proof_bytes| body.encoded_len(policy).ok()?.checked_sub(proof_bytes))
            .ok_or("shadow state growth accounting failed")?;
        // Account for state growth and allocation overhead across the full
        // replay. The transient proof buffers are separately charged per row.
        let growth = nonproof
            .checked_mul(16)
            .ok_or("shadow state byte accounting overflow")?;
        let reservation = self
            .inputs
            .memory
            .reserve(growth)
            .map_err(|_| "shadow state memory deferred")?;
        self.scratch
            .store_mut()
            .append(&header, &body, &self.inputs.verifier)?;
        self.retained.push(reservation);
        checkpoint_archive(self.scratch.store(), self.inputs.limits)
    }

    fn advance(&mut self) -> Result<(), String> {
        if !self.initialized {
            loop {
                self.inputs.checkpoint_progress()?;
                let bytes = self.inputs.prefix.next_bytes()?;
                self.scratch.disk_room(bytes)?;
                if !self
                    .inputs
                    .prefix
                    .copy_next(self.scratch.store(), &self.inputs.memory)?
                {
                    break;
                }
            }
            self.scratch
                .disk_room(self.inputs.prefix.snapshot_bytes()?)?;
            self.retained.push(
                self.inputs
                    .prefix
                    .start_replay(self.scratch.store_mut(), &self.inputs.memory)?,
            );
            self.initialized = true;
        }
        while self.scratch.store().engine().state().height() < self.inputs.path.ancestor_height {
            self.inputs.checkpoint_progress()?;
            let height = self.scratch.store().engine().state().height() + 1;
            let bytes = self.inputs.prefix.canonical_size(height)?;
            let _scratch = block_budget(&self.inputs.memory, bytes)?;
            self.scratch.disk_room(bytes)?;
            let (header, body) = self
                .inputs
                .prefix
                .canonical_block(self.scratch.store(), height)?;
            self.execute(header, body)?;
        }
        if self.replacement_done == 0
            && self.scratch.store().engine().state().tip() != self.inputs.path.ancestor_id
        {
            return Err("shadow replay ancestor differs".into());
        }
        while let Some(&id) = self.inputs.path.replacement.get(self.replacement_done) {
            self.inputs.checkpoint_progress()?;
            let bytes = self.inputs.archive.size(id)?;
            let _scratch = block_budget(&self.inputs.memory, bytes)?;
            self.scratch.disk_room(bytes)?;
            let (header, body) = self
                .inputs
                .archive
                .block(id, self.scratch.store().engine().body_policy())?;
            self.execute(header, body)?;
            self.replacement_done += 1;
        }
        self.inputs.checkpoint_progress()?;
        let state = self.scratch.store().engine().state();
        if state.tip() != self.inputs.candidate
            || state.chain().cumulative_work != self.inputs.path.cumulative_work
        {
            return Err("shadow verified work or tip differs".into());
        }
        Ok(())
    }

    fn run(mut self) -> Result<ReplayOutcome, String> {
        match self.advance() {
            Ok(()) => Ok(ReplayOutcome::Ready(Box::new(Ready {
                scratch: self.scratch,
                prefix: self.inputs.prefix,
                generation: self.inputs.generation,
                candidate: self.inputs.candidate,
                _memory: self.retained,
            }))),
            Err(error) if resumable_budget_error(&error) => {
                Ok(ReplayOutcome::Deferred(Box::new(self)))
            }
            Err(error) => Err(error),
        }
    }
}

impl Inputs {
    fn checkpoint_progress(&self) -> Result<(), String> {
        let mut progress = self
            .progress
            .lock()
            .map_err(|_| "shadow progress unavailable")?;
        let now = Instant::now();
        check_liveness(&self.cancel, *progress, now)?;
        *progress = now;
        Ok(())
    }
}

fn check_liveness(cancel: &AtomicBool, progress: Instant, now: Instant) -> Result<(), String> {
    if now.saturating_duration_since(progress) >= ACTIVE_IDLE_LIMIT {
        return Err("shadow replay progress expired".into());
    }
    if cancel.load(Ordering::Acquire) {
        return Err("shadow replay canceled".into());
    }
    Ok(())
}

fn resumable_budget_error(error: &str) -> bool {
    // Only waits before a write are resumable. Verification, archive and
    // storage errors discard the candidate rather than retrying a commit.
    matches!(
        error,
        "shadow disk budget deferred"
            | "shadow prefix shared byte budget deferred"
            | "shadow checkpoint prefix memory deferred"
            | "shadow state memory deferred"
            | "shadow proof memory deferred"
    )
}

fn block_budget(
    memory: &crate::p2p::Budget,
    bytes: usize,
) -> Result<crate::p2p::Reservation, String> {
    let charge = bytes
        .checked_mul(4)
        .and_then(|value| value.checked_add(64 * 1024))
        .ok_or("shadow proof byte bound overflow")?;
    memory
        .reserve(charge)
        .map_err(|_| "shadow proof memory deferred".into())
}

fn owner_identity(
    directory: &Path,
    store: &Store,
) -> Result<crate::identity::NativeIdentity, String> {
    crate::identity::NativeIdentity::load(directory, &store.engine().genesis().peer_binding())
        .map_err(|_| "existing shadow sealing identity unavailable".into())
}

impl Driver {
    pub(super) fn shadow_tick(
        &mut self,
        state: &mut Reorganization,
        before_publish: impl FnOnce(u64) -> Result<(), String>,
    ) -> Result<(), String> {
        let now = Instant::now();
        if let Some(job) = &state.shadow.active {
            let idle = job
                .progress
                .lock()
                .map(|progress| now.saturating_duration_since(*progress) >= ACTIVE_IDLE_LIMIT)
                .unwrap_or(true);
            if idle || self.store.generation_record()? != job.expected {
                job.cancel.store(true, Ordering::Release);
            }
            if !job.thread.as_ref().is_some_and(JoinHandle::is_finished) {
                return Ok(());
            }
            let mut job = state.shadow.active.take().expect("active replay");
            let ready = job.thread.take().expect("active replay thread").join();
            match ready {
                Ok(Ok(ReplayOutcome::Ready(ready))) if !job.cancel.load(Ordering::Acquire) => {
                    if self.install_shadow(state, &job.expected, *ready, before_publish)? {
                        state.shadow.parked = None;
                        state.shadow.alarm = None;
                        return Ok(());
                    }
                }
                Ok(Ok(ReplayOutcome::Deferred(replay)))
                    if state.shadow.parked.is_none()
                        && job
                            .park_expires
                            .is_none_or(|expiry| now + RETRY_AFTER < expiry)
                        && self.store.generation_record()? == job.expected =>
                {
                    state.shadow.parked = Some(Parked {
                        replay,
                        expected: job.expected.clone(),
                        retry_at: now + RETRY_AFTER,
                        expires: job.park_expires.unwrap_or(now + PARKED_LIFETIME),
                    });
                }
                _ => {}
            }
            state.shadow.defer(job.candidate, now);
            return Ok(());
        }
        if let Some(parked) = &state.shadow.parked {
            if parked.expires <= now || self.store.generation_record()? != parked.expected {
                state.shadow.parked = None;
            } else if parked.retry_at <= now {
                let parked = state.shadow.parked.take().expect("parked replay");
                let candidate = parked.replay.inputs.candidate;
                let cancel = parked.replay.inputs.cancel.clone();
                let progress = parked.replay.inputs.progress.clone();
                *progress.lock().map_err(|_| "shadow progress unavailable")? = now;
                state.shadow.active = Some(Job::spawn(
                    candidate,
                    parked.expected,
                    cancel,
                    progress,
                    Some(parked.expires),
                    move || (*parked.replay).run(),
                )?);
                return Ok(());
            }
        }
        if state
            .shadow
            .scanned
            .is_some_and(|last| now.duration_since(last) < SCAN_INTERVAL)
        {
            return Ok(());
        }
        state.shadow.scanned = Some(now);
        let deferred_count = state.shadow.deferred.len();
        state.shadow.deferred.retain(|(_, expiry)| *expiry > now);
        let fence = checkpoint_fence(&self.store);
        let scan_key = ScanKey {
            revision: state.branches.selection_revision(),
            tip: self.store.engine().state().tip(),
            fence,
        };
        if deferred_count == state.shadow.deferred.len()
            && state.shadow.empty_scan == Some(scan_key)
        {
            return Ok(());
        }
        state.shadow.empty_scan = None;
        state.best_candidate(&self.store)?;
        let candidate =
            state
                .branches
                .select_shadow_candidate(&self.store, fence, &state.memory, |id| {
                    state.shadow.deferred.iter().any(|(other, _)| *other == id)
                        || state
                            .shadow
                            .parked
                            .as_ref()
                            .is_some_and(|job| job.replay.inputs.candidate == id)
                });
        let Some(candidate) = (match candidate {
            Ok(candidate) => candidate,
            Err(error) => {
                state.shadow.alarm = Some("reorganization_shadow_candidate_scan_deferred");
                return Err(error);
            }
        }) else {
            if state.shadow.alarm == Some("reorganization_shadow_candidate_scan_deferred") {
                state.shadow.alarm = None;
            }
            state.shadow.empty_scan = Some(scan_key);
            return Ok(());
        };
        let expected = self.store.generation_record()?;
        let path = state
            .branches
            .candidate_path(self.store.engine().state().tip(), candidate)?;
        if fence.is_some_and(|(height, id)| {
            path.ancestor_height < height
                || (path.ancestor_height == height && path.ancestor_id != id)
        }) {
            state.cached_checkpoint_conflict = Some(candidate);
            return Ok(());
        }
        if let Some(warning) = ForkDepthWarning::from_path(&path, now) {
            state.depth_warning = Some(warning);
        }
        let prefix = match self
            .store
            .capture_shadow_prefix(expected.clone(), self.imports)
        {
            Ok(prefix) => prefix,
            Err(_) => {
                state.shadow.defer(candidate, now);
                return Ok(());
            }
        };
        let mut id = [0; 32];
        getrandom::fill(&mut id).map_err(|_| "shadow generation entropy unavailable")?;
        let generation = expected.generation().successor(id)?;
        let target = generation.path(self.store.generation_directory()?);
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Mutex::new(now));
        let inputs = Inputs {
            prefix,
            archive: state.branches.capture_shadow_branch()?,
            path,
            candidate,
            generation,
            target,
            genesis: self.store.engine().genesis().encode()?,
            limits: self.imports,
            memory: state.memory.clone(),
            verifier: self.verifier.clone(),
            cancel: cancel.clone(),
            progress: progress.clone(),
        };
        state.shadow.active = Some(Job::spawn(
            candidate,
            expected,
            cancel,
            progress,
            None,
            move || Replay::new(inputs)?.run(),
        )?);
        Ok(())
    }

    fn install_shadow(
        &mut self,
        state: &mut Reorganization,
        expected: &Record,
        mut ready: Ready,
        before_publish: impl FnOnce(u64) -> Result<(), String>,
    ) -> Result<bool, String> {
        let current = self.store.engine().state();
        if &self.store.generation_record()? != expected
            || ready
                .scratch
                .store()
                .engine()
                .state()
                .chain()
                .cumulative_work
                <= current.chain().cumulative_work
        {
            return Ok(false);
        }
        let tip = current.tip();
        let Ok(path) = state.branches.candidate_path(tip, ready.candidate) else {
            return Ok(false);
        };
        if path.ancestor_height < ready.prefix.height() {
            return Ok(false);
        }
        let template = self
            .template_generation
            .checked_add(1)
            .ok_or("template generation exhausted")?;
        let pending = pending_pool(current.network())?;
        let identity = owner_identity(self.store.generation_directory()?, &self.store)?;
        ready.scratch.disk_room(0)?;
        self.store
            .seal_shadow_prefix(&ready.prefix, ready.scratch.store_mut(), identity)?;
        before_publish(path.ancestor_height)?;
        if let Err(error) = self.store.publish_shadow_generation(
            expected,
            ready.generation,
            &mut ready.scratch.store,
        ) {
            ready.scratch.preserve = self.store.ensure_exportable().is_err();
            return Err(error);
        }
        self.invalidate_verification();
        self.template_generation = template;
        self.padding = Pool::new(self.store.engine().state().network());
        self.pending = pending;
        let now = Instant::now();
        state
            .recent
            .retain(|time| now.saturating_duration_since(*time) < Duration::from_secs(3600));
        state.recent.push_back(now);
        if state.recent.len() > 4 {
            state.recent.pop_front();
        }
        state.last = Some(SwitchEvent {
            depth: path.removed.len(),
            ancestor_height: path.ancestor_height,
            old_tip: tip,
            new_tip: ready.candidate,
            frequent: state.recent.len() > 3,
        });
        self.bootstrap = crate::eng2::bootstrap::leases::Registry::default();
        self.bootstrap_receipt_height = 0;
        state.invalidate_progress();
        state.cached_revision = 0;
        state.pending_restart = false;
        self.last_archive_error = None;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eng2::{header::HEADER_BYTES, selection::HeaderRules};
    use redb::{ReadableDatabase, TableDefinition};

    #[test]
    fn shadow_replay_idle_timeout_and_cancellation_prevent_more_work() {
        let start = Instant::now();
        let deadline = start + ACTIVE_IDLE_LIMIT;
        let cancel = AtomicBool::new(false);
        assert_eq!(check_liveness(&cancel, start, start), Ok(()));
        assert_eq!(
            check_liveness(&cancel, start, deadline),
            Err("shadow replay progress expired".into())
        );
        cancel.store(true, Ordering::Release);
        assert_eq!(
            check_liveness(&cancel, start, start),
            Err("shadow replay canceled".into())
        );
    }

    #[test]
    #[ignore = "owner-local qualification with an existing closed native RandomX block"]
    fn resumes_a_native_candidate_after_shared_memory_is_released() {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        assert!(std::env::var_os("GITHUB_ACTIONS").is_none());
        let source = PathBuf::from(
            std::env::var_os("SIWORLD_ENG2_NATIVE_FIXTURE").expect("closed fixture directory"),
        );
        assert_eq!(source.canonicalize().unwrap(), source);
        let bytes = std::fs::read(source.join("genesis.bin")).unwrap();
        let genesis = || Genesis::decode(&bytes).unwrap();
        assert!(genesis().checkpoint_fork_choice());
        let mut entropy = [0; 16];
        getrandom::fill(&mut entropy).unwrap();
        let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "eng2-shadow-resume-{}",
            crate::local::hex(&entropy)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let limits = crate::eng2::resident::limits();
        let identity = || {
            crate::identity::NativeIdentity::load(&directory, &genesis().peer_binding()).unwrap()
        };
        let owner =
            crate::identity::NativeIdentity::initialize(&directory, genesis().peer_binding())
                .unwrap();
        let mut canonical =
            Store::initialize_selected(&directory, genesis(), limits.chain, owner).unwrap();
        let (header, body) = {
            let db = redb::ReadOnlyDatabase::open(source.join("chain.redb")).unwrap();
            let txn = db.begin_read().unwrap();
            let table = txn
                .open_table(TableDefinition::<u64, &[u8]>::new(
                    "eng2-canonical-blocks-v1",
                ))
                .unwrap();
            let row = table.get(1).unwrap().unwrap();
            let raw = row.value();
            let network = genesis().config().network;
            let header = Header::decode(&raw[..HEADER_BYTES], &network).unwrap();
            let body = Body::decode(
                &raw[HEADER_BYTES..],
                network,
                1,
                canonical.engine().body_policy(),
            )
            .unwrap();
            (header, body)
        };
        let config = canonical.engine().genesis().config();
        let rules = HeaderRules {
            network: config.network,
            genesis: canonical.engine().genesis().id(),
            genesis_timestamp: config.genesis_timestamp,
            genesis_target: config.genesis_target,
            target_interval: config.target_interval,
            asert_half_life: config.asert_half_life(),
            pow_algorithm: config.pow_algorithm(),
            pow_iterations: config.pow_iterations,
            max_headers: 8,
        };
        let mut branches = BranchStore::create(
            &directory.join("branches.redb"),
            rules.clone(),
            crate::eng2::branches::Limits {
                maximum_headers: 8,
                maximum_body_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap();
        let qualified = VerifiedHeaders::verify(rules, vec![header.clone()]).unwrap();
        branches.retain_verified_headers(&qualified).unwrap();
        branches
            .retain_body(&header, &body, canonical.engine().body_policy())
            .unwrap();
        let candidate = header.id().unwrap();
        let path = branches
            .candidate_path(canonical.engine().state().tip(), candidate)
            .unwrap();
        let expected = canonical.generation_record().unwrap();
        let generation = expected.generation().successor([7; 32]).unwrap();
        let target = generation.path(&directory);
        let memory = crate::p2p::Budget::new(256 * 1024 * 1024);
        let hold = memory.reserve(250 * 1024 * 1024).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Mutex::new(Instant::now()));
        let inputs = Inputs {
            prefix: canonical
                .capture_shadow_prefix(expected.clone(), limits)
                .unwrap(),
            archive: branches.capture_shadow_branch().unwrap(),
            path,
            candidate,
            generation,
            target: target.clone(),
            genesis: bytes.clone(),
            limits,
            memory,
            verifier: Arc::new(NativeVerifier::for_genesis(canonical.engine().genesis()).unwrap()),
            cancel: cancel.clone(),
            progress: progress.clone(),
        };
        let mut first = Job::spawn(
            candidate,
            expected.clone(),
            cancel.clone(),
            progress.clone(),
            None,
            move || Replay::new(inputs)?.run(),
        )
        .unwrap();
        let ReplayOutcome::Deferred(parked) = first.thread.take().unwrap().join().unwrap().unwrap()
        else {
            panic!("resource pressure must defer before native append");
        };
        drop(first);
        assert!(parked.initialized);
        assert_eq!(parked.scratch.store().engine().state().height(), 0);
        assert_eq!(canonical.engine().state().height(), 0);
        let inode = std::fs::symlink_metadata(&target).unwrap().ino();
        drop(hold);
        let mut resumed = Job::spawn(
            candidate,
            expected.clone(),
            cancel,
            progress,
            Some(Instant::now() + PARKED_LIFETIME),
            move || (*parked).run(),
        )
        .unwrap();
        let ReplayOutcome::Ready(mut ready) =
            resumed.thread.take().unwrap().join().unwrap().unwrap()
        else {
            panic!("released memory must allow native replay");
        };
        assert_eq!(std::fs::symlink_metadata(&target).unwrap().ino(), inode);
        canonical
            .seal_shadow_prefix(&ready.prefix, ready.scratch.store_mut(), identity())
            .unwrap();
        canonical
            .publish_shadow_generation(&expected, generation, &mut ready.scratch.store)
            .unwrap();
        drop(ready);
        drop(canonical);
        let reopened = Store::resume_selected(&directory, genesis(), limits.chain).unwrap();
        assert_eq!(reopened.engine().state().tip(), candidate);
        assert_eq!(reopened.header(1).unwrap(), header);
        drop(reopened);
        drop(branches);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
