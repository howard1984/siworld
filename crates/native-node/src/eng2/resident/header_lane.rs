//! Header-only ownership is independent of synchronous native body verification.
use super::*;
use crate::eng2::{
    body::{Body, Policy},
    header::Header,
    selection::HeaderRules,
};
use siworld_core::pow::{self, Work};
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

const MAX_HEADERS: usize = 128;
const MAX_DOWNLOADS: usize = 4;
const MAX_ATTEMPTS: usize = 4;
const RETENTION: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct Context {
    height: u64,
    id: Hash,
    work: Work,
    times: VecDeque<u64>,
}
#[derive(Clone)]
struct Entry {
    header: Header,
    context: Context,
    source: Hash,
    first: Instant,
    sequence: u64,
    sent: std::collections::BTreeSet<Hash>,
    attempts: std::collections::BTreeSet<Hash>,
    downloads: BTreeMap<Hash, DownloadState>,
    complete: bool,
    body: Option<Arc<LocalBody>>,
}
struct Inner {
    canonical: Context,
    anchors: BTreeMap<Hash, Context>,
    entries: VecDeque<Entry>,
    sequence: u64,
    rate_start: Instant,
    offers: usize,
}
pub(crate) struct LocalBody {
    header: Header,
    body: Arc<Body>,
    length: usize,
    _charge: p2p::Reservation,
}
impl LocalBody {
    pub(crate) fn header(&self) -> &Header {
        &self.header
    }
    pub(crate) fn body(&self) -> &Body {
        &self.body
    }
    pub(crate) fn length(&self) -> usize {
        self.length
    }
}
pub(crate) struct Hub {
    local: Hash,
    policy: Policy,
    budget: p2p::Budget,
    local_deferred: AtomicU64,
    active_downloads: AtomicUsize,
    rules: HeaderRules,
    inner: Mutex<Inner>,
    waiting: AtomicBool,
    failed: AtomicBool,
    _charge: p2p::Reservation,
}
#[derive(Clone)]
struct DownloadState {
    cancel: p2p::Cancellation,
    deadline: p2p::Deadline,
    progress: Arc<DownloadProgress>,
}
struct DownloadProgress {
    attempt_index: usize,
    started: Instant,
    state: Mutex<ProgressState>,
}
struct ProgressState {
    received_bytes: u64,
    total_bytes: u64,
    last_progress: Option<Instant>,
    phase: &'static str,
}
impl DownloadProgress {
    fn new(attempt_index: usize) -> Self {
        Self {
            attempt_index,
            started: Instant::now(),
            state: Mutex::new(ProgressState {
                received_bytes: 0,
                total_bytes: 0,
                last_progress: None,
                phase: "waiting_for_body",
            }),
        }
    }
    fn received(&self, bytes: usize, total: usize) {
        if let Ok(mut state) = self.state.lock() {
            let bytes = bytes as u64;
            let total = total as u64;
            if bytes > state.received_bytes && bytes <= total {
                state.received_bytes = bytes;
                state.total_bytes = total;
                state.last_progress = Some(Instant::now());
                state.phase = "receiving_body";
            }
        }
    }
    fn decoded(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.last_progress = Some(Instant::now());
            state.phase = "decoded_awaiting_admission";
        }
    }
    fn diagnostic(&self, now: Instant) -> serde_json::Value {
        let Ok(state) = self.state.lock() else {
            return json!({"phase":"unavailable"});
        };
        json!({
            "attempt_index":self.attempt_index,
            "phase":state.phase,
            "attempt_age_ms":now.saturating_duration_since(self.started).as_millis(),
            "received_bytes":state.received_bytes,
            "total_bytes":state.total_bytes,
            "last_progress_age_ms":state.last_progress.map(|at| now.saturating_duration_since(at).as_millis()),
        })
    }
}
pub(crate) struct Download {
    pub header: Header,
    pub cancel: p2p::Cancellation,
    pub deadline: p2p::Deadline,
    progress: Arc<DownloadProgress>,
    peer: Hash,
    hub: Arc<Hub>,
}
impl Download {
    pub(crate) fn received(&self, bytes: usize, total: usize) {
        self.progress.received(bytes, total);
    }
    pub(crate) fn decoded(&self) {
        self.progress.decoded();
    }
}
impl Drop for Download {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.hub.inner.lock() {
            for entry in &mut inner.entries {
                if entry.header == self.header {
                    entry.downloads.remove(&self.peer);
                }
            }
        }
        // The lease outlives an expired/evicted cache entry and may still own a
        // decoded queue job or synchronous native admission.
        self.hub.active_downloads.fetch_sub(1, Ordering::AcqRel);
    }
}
impl Hub {
    pub(crate) fn new(owner: &Driver, budget: &p2p::Budget, local: Hash) -> Result<Self, String> {
        if local == [0; 32] {
            return Err("local header identity unavailable".into());
        }
        let config = owner.engine().genesis().config();
        let rules = HeaderRules {
            network: config.network,
            genesis: owner.engine().genesis().id(),
            genesis_timestamp: config.genesis_timestamp,
            genesis_target: config.genesis_target,
            target_interval: config.target_interval,
            pow_iterations: config.pow_iterations,
            max_headers: 1_000_000,
        };
        let genesis = Context {
            height: 0,
            id: rules.genesis,
            work: Work::zero(),
            times: VecDeque::from([rules.genesis_timestamp]),
        };
        let now = Instant::now();
        let hub = Self {
            local,
            policy: owner.engine().body_policy(),
            budget: budget.clone(),
            local_deferred: AtomicU64::new(0),
            active_downloads: AtomicUsize::new(0),
            rules,
            inner: Mutex::new(Inner {
                canonical: genesis,
                anchors: BTreeMap::new(),
                entries: VecDeque::new(),
                sequence: 0,
                rate_start: now,
                offers: 0,
            }),
            waiting: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            _charge: budget
                .reserve(512 * 1024)
                .map_err(|_| "header lane cache budget unavailable")?,
        };
        hub.committed(owner)?;
        Ok(hub)
    }
    pub(crate) fn error(&self) -> Option<&'static str> {
        self.failed
            .load(Ordering::Acquire)
            .then_some("header_context_update_failed")
    }
    fn ensure_available(&self) -> Result<(), String> {
        self.error().map_or(Ok(()), |error| Err(error.into()))
    }
    /// Canonical admission has already succeeded. A diagnostic cache failure
    /// disables optional paths but cannot change that committed result.
    pub(crate) fn after_commit(&self, update: impl FnOnce() -> Result<(), String>) {
        if update().is_err() {
            self.failed.store(true, Ordering::Release);
            self.waiting.store(true, Ordering::Release);
            if let Ok(mut inner) = self.inner.lock() {
                for entry in &inner.entries {
                    for download in entry.downloads.values() {
                        download.cancel.cancel();
                    }
                }
                inner.entries.clear();
            }
        }
    }
    // Only accepted canonical Store records seed work/timestamp contexts. There
    // is no remote/context constructor and no speculative canonical head.
    pub(crate) fn committed(&self, owner: &Driver) -> Result<(), String> {
        self.ensure_available()?;
        let head = owner.head()?;
        let mut contexts = Vec::new();
        let mut work = head.work;
        for height in (head.height.saturating_sub(24)..=head.height).rev() {
            let mut times = VecDeque::new();
            for at in height.saturating_sub(10)..=height {
                times.push_back(if at == 0 {
                    self.rules.genesis_timestamp
                } else {
                    owner.header(at)?.timestamp
                });
            }
            let header = if height == 0 {
                None
            } else {
                Some(owner.header(height)?)
            };
            let id = header
                .as_ref()
                .map(Header::id)
                .transpose()
                .map_err(|_| "canonical header identity rejected")?
                .unwrap_or(self.rules.genesis);
            contexts.push(Context {
                height,
                id,
                work,
                times,
            });
            if let Some(header) = header {
                work = work
                    .checked_sub(pow::block_work(&header.target))
                    .ok_or("canonical header work underflow")?;
            }
        }
        let canonical = contexts
            .first()
            .ok_or("canonical header context missing")?
            .clone();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        inner.canonical = canonical.clone();
        inner.anchors = contexts.into_iter().map(|c| (c.id, c)).collect();
        if head.height > 0 {
            let header = owner.header(head.height)?;
            if !inner.entries.iter().any(|e| e.context.id == canonical.id) {
                if inner.entries.len() >= MAX_HEADERS
                    && let Some(evicted) = inner.entries.pop_front()
                {
                    for download in evicted.downloads.values() {
                        download.cancel.cancel();
                    }
                }
                inner.sequence = inner
                    .sequence
                    .checked_add(1)
                    .ok_or("header sequence exhausted")?;
                let sequence = inner.sequence;
                inner.entries.push_back(Entry {
                    header,
                    context: canonical,
                    source: [0; 32],
                    first: Instant::now(),
                    sequence,
                    sent: Default::default(),
                    attempts: Default::default(),
                    downloads: Default::default(),
                    complete: true,
                    body: None,
                });
            }
        }
        for entry in &mut inner.entries {
            if entry.context.id == head.id {
                entry.complete = true;
                entry.body = None;
                for download in entry.downloads.values() {
                    download.cancel.cancel();
                }
            }
        }
        self.reconcile(&mut inner, Instant::now());
        Ok(())
    }
    fn reconcile(&self, inner: &mut Inner, now: Instant) {
        inner.entries.retain(|entry| {
            let mut active = false;
            for download in entry.downloads.values() {
                if download.deadline.check_at(now).is_ok() {
                    active = true;
                } else {
                    download.cancel.cancel();
                }
            }
            // A cache sweep cannot shorten an existing transfer's fixed budget.
            // Expired leases still own their slots until their consumers drop.
            now.saturating_duration_since(entry.first) < RETENTION || active
        });
        self.waiting.store(
            inner.entries.iter().any(|entry| {
                entry.source != self.local && entry.context.work > inner.canonical.work
            }),
            Ordering::Release,
        );
    }
    pub(crate) fn tip(&self) -> Result<(u64, Hash), String> {
        self.ensure_available()?;
        let inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        Ok((inner.canonical.height, inner.canonical.id))
    }
    pub(crate) fn waiting(&self) -> bool {
        self.failed.load(Ordering::Acquire) || self.waiting.load(Ordering::Acquire)
    }
    pub(crate) fn sync_progress(&self) -> serde_json::Value {
        if self.failed.load(Ordering::Acquire) {
            return serde_json::Value::Null;
        }
        let Ok(inner) = self.inner.lock() else {
            return serde_json::Value::Null;
        };
        let now = Instant::now();
        let Some(entry) = inner
            .entries
            .iter()
            .filter(|entry| {
                entry.source != self.local
                    && !entry.complete
                    && entry.context.work > inner.canonical.work
            })
            .max_by_key(|entry| (entry.context.work, entry.context.height))
        else {
            return serde_json::Value::Null;
        };
        let downloads: Vec<_> = entry
            .downloads
            .values()
            .take(2)
            .map(|download| {
                let mut value = download.progress.diagnostic(now);
                value["active"] = json!(download.deadline.check_at(now).is_ok());
                value
            })
            .collect();
        json!({
            "scope":"validated_header_body",
            "candidate_height":entry.context.height,
            "candidate_id":crate::local::hex(&entry.context.id),
            "candidate_sequence":entry.sequence,
            "candidate_work":entry.context.work.to_string(),
            "candidate_age_ms":now.saturating_duration_since(entry.first).as_millis(),
            "canonical_height":inner.canonical.height,
            "canonical_id":crate::local::hex(&inner.canonical.id),
            "canonical_work":inner.canonical.work.to_string(),
            "lag_blocks":entry.context.height.checked_sub(inner.canonical.height),
            "downloads":downloads,
        })
    }
    pub(crate) fn tick(&self) -> Result<(), String> {
        if self.failed.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        self.reconcile(&mut inner, Instant::now());
        Ok(())
    }
    pub(crate) fn active_downloads(&self) -> usize {
        self.active_downloads.load(Ordering::Acquire)
    }
    pub(crate) fn local_deferred(&self) -> u64 {
        self.local_deferred.load(Ordering::Relaxed)
    }
    /// Only the local producer calls this after its owner-side controls and
    /// fully verified candidate preparation. This grants no canonical state.
    pub(crate) fn produced(&self, header: Header, body: Arc<Body>) -> Result<(), String> {
        if body.network != header.network
            || body.height != header.height
            || body.commitment(self.policy)? != header.body_commitment
        {
            return Err("local body binding rejected".into());
        }
        let length = body.encoded_len(self.policy)?;
        let bytes = length
            .checked_mul(3)
            .and_then(|n| n.checked_add(65_536))
            .ok_or("local body byte accounting overflow")?;
        let charge = match self.budget.reserve(bytes) {
            Ok(charge) => charge,
            Err(p2p::Error::ResourceExhausted) => {
                self.local_deferred.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Err(_) => return Err("local body cache budget unavailable".into()),
        };
        let cached = Arc::new(LocalBody {
            header: header.clone(),
            body,
            length,
            _charge: charge,
        });
        if !self.offer_inner(header, self.local, Some(cached))? {
            self.local_deferred.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
    pub(crate) fn local_body(
        &self,
        height: u64,
        id: Hash,
    ) -> Result<Option<Arc<LocalBody>>, String> {
        self.ensure_available()?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        self.reconcile(&mut inner, Instant::now());
        Ok(inner
            .entries
            .iter()
            .find(|entry| entry.context.id == id && entry.header.height == height)
            .and_then(|entry| entry.body.clone()))
    }
    pub(crate) fn offer(&self, header: Header, peer: Hash) -> Result<bool, String> {
        self.offer_inner(header, peer, None)
    }
    fn offer_inner(
        &self,
        header: Header,
        peer: Hash,
        body: Option<Arc<LocalBody>>,
    ) -> Result<bool, String> {
        self.ensure_available()?;
        let now = Instant::now();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        self.reconcile(&mut inner, now);
        if header.network != self.rules.network
            || header.height == 0
            || header.height > self.rules.max_headers as u64
            || peer == [0; 32]
        {
            return Err("header lane context rejected".into());
        }
        let id = header.id().map_err(|_| "header identity rejected")?;
        if inner.entries.iter().any(|e| e.context.id == id) {
            return Ok(false);
        }
        if now.saturating_duration_since(inner.rate_start) >= Duration::from_secs(1) {
            inner.rate_start = now;
            inner.offers = 0;
        }
        if inner.offers >= 32 || inner.entries.len() >= MAX_HEADERS {
            return Ok(false);
        }
        // Charge attempts before hashing; malformed offers cannot bypass the
        // global qualification CPU bound by failing their final PoW check.
        inner.offers += 1;
        let parent = inner.anchors.get(&header.parent).cloned().or_else(|| {
            inner
                .entries
                .iter()
                .find(|e| e.context.id == header.parent)
                .map(|e| e.context.clone())
        });
        let Some(parent) = parent else {
            return Ok(false);
        };
        let times: Vec<_> = parent.times.iter().copied().collect();
        if parent.height.checked_add(1) != Some(header.height)
            || header.timestamp
                <= pow::median_time_past(&times).ok_or("header timestamp context unavailable")?
        {
            return Err("header linkage or timestamp rejected".into());
        }
        let target = pow::asert_target(
            &self.rules.genesis_target,
            self.rules.genesis_timestamp,
            self.rules.target_interval,
            parent.height,
            *parent
                .times
                .back()
                .ok_or("header parent time unavailable")?,
        );
        if header.target != target {
            return Err("header target rejected".into());
        }
        let seed = header.pow_seed().map_err(|_| "header seed rejected")?;
        if !pow::meets_target(
            &pow::pow_hash(&seed, header.nonce, self.rules.pow_iterations),
            &target,
        ) {
            return Err("header proof of work rejected".into());
        }
        let work = parent
            .work
            .checked_add(pow::block_work(&target))
            .ok_or("header work overflow")?;
        let mut times = parent.times;
        times.push_back(header.timestamp);
        while times.len() > 11 {
            times.pop_front();
        }
        inner.sequence = inner
            .sequence
            .checked_add(1)
            .ok_or("header sequence exhausted")?;
        let sequence = inner.sequence;
        let context = Context {
            height: header.height,
            id,
            work,
            times,
        };
        inner.entries.push_back(Entry {
            header,
            context,
            source: peer,
            first: now,
            sequence,
            sent: Default::default(),
            attempts: Default::default(),
            downloads: Default::default(),
            complete: body.is_some(),
            body,
        });
        self.reconcile(&mut inner, now);
        Ok(true)
    }
    pub(crate) fn outgoing(&self, peer: Hash) -> Result<Vec<Header>, String> {
        self.ensure_available()?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        self.reconcile(&mut inner, Instant::now());
        let floor = inner.canonical.work;
        Ok(inner
            .entries
            .iter_mut()
            .filter(|e| e.context.work >= floor && e.source != peer && !e.sent.contains(&peer))
            .take(8)
            .map(|e| {
                e.sent.insert(peer);
                e.header.clone()
            })
            .collect())
    }
    pub(crate) fn download(self: &Arc<Self>, peer: Hash) -> Result<Option<Download>, String> {
        self.ensure_available()?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        self.reconcile(&mut inner, Instant::now());
        if self.active_downloads.load(Ordering::Acquire) >= MAX_DOWNLOADS {
            return Ok(None);
        }
        let floor = inner.canonical.work;
        let mut needed = std::collections::BTreeSet::new();
        let mut pending: Vec<_> = inner
            .entries
            .iter()
            .filter(|entry| entry.context.work >= floor)
            .map(|entry| entry.context.id)
            .collect();
        while let Some(id) = pending.pop() {
            if !needed.insert(id) {
                continue;
            }
            if let Some(entry) = inner.entries.iter().find(|entry| entry.context.id == id) {
                pending.push(entry.header.parent);
            }
        }
        let next = inner
            .entries
            .iter_mut()
            .filter(|e| {
                !e.complete
                    && needed.contains(&e.context.id)
                    && e.downloads.len() < 2
                    && e.attempts.len() < MAX_ATTEMPTS
                    && !e.attempts.contains(&peer)
            })
            .min_by_key(|e| (e.header.height, e.sequence));
        let Some(entry) = next else {
            return Ok(None);
        };
        let cancel = p2p::Cancellation::default();
        let deadline =
            p2p::Deadline::cancellable(crate::eng2::transport::BODY_FETCH_TIMEOUT, cancel.clone());
        let progress = Arc::new(DownloadProgress::new(entry.attempts.len() + 1));
        entry.attempts.insert(peer);
        entry.downloads.insert(
            peer,
            DownloadState {
                cancel: cancel.clone(),
                deadline: deadline.clone(),
                progress: progress.clone(),
            },
        );
        self.active_downloads.fetch_add(1, Ordering::AcqRel);
        Ok(Some(Download {
            header: entry.header.clone(),
            cancel,
            deadline,
            progress,
            peer,
            hub: self.clone(),
        }))
    }
    pub(crate) fn path(&self, header: &Header) -> Result<Vec<Header>, String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        let mut path = vec![header.clone()];
        let mut parent = header.parent;
        while let Some(entry) = inner
            .entries
            .iter()
            .find(|entry| entry.context.id == parent)
        {
            if path.len() >= MAX_HEADERS {
                return Err("header cache path capacity exceeded".into());
            }
            path.push(entry.header.clone());
            parent = entry.header.parent;
        }
        path.reverse();
        Ok(path)
    }
    pub(crate) fn completed(&self, header: &Header) -> Result<(), String> {
        if self.failed.load(Ordering::Acquire) {
            return Ok(());
        }
        let id = header.id().map_err(|_| "body header identity rejected")?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        for entry in &mut inner.entries {
            if entry.context.id == id {
                entry.complete = true;
                entry.body = None;
                for download in entry.downloads.values() {
                    download.cancel.cancel();
                }
            }
        }
        self.reconcile(&mut inner, Instant::now());
        Ok(())
    }
    pub(crate) fn rejected(&self, header: &Header) -> Result<(), String> {
        if self.failed.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut rejected = std::collections::BTreeSet::from([header
            .id()
            .map_err(|_| "rejected header identity unavailable")?]);
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        loop {
            let before = rejected.len();
            for entry in &inner.entries {
                if rejected.contains(&entry.header.parent) {
                    rejected.insert(entry.context.id);
                }
            }
            if rejected.len() == before {
                break;
            }
        }
        inner.entries.retain(|entry| {
            if rejected.contains(&entry.context.id) {
                for download in entry.downloads.values() {
                    download.cancel.cancel();
                }
                false
            } else {
                true
            }
        });
        self.reconcile(&mut inner, Instant::now());
        Ok(())
    }
    pub(crate) fn disconnected(&self, peer: Hash) {
        if let Ok(mut inner) = self.inner.lock() {
            for entry in &mut inner.entries {
                entry.sent.remove(&peer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hub() -> Arc<Hub> {
        let rules = HeaderRules {
            network: [1; 32],
            genesis: [2; 32],
            genesis_timestamp: 1,
            genesis_target: [255; 32],
            target_interval: 300,
            pow_iterations: 0,
            max_headers: 128,
        };
        let context = Context {
            height: 0,
            id: rules.genesis,
            work: Work::zero(),
            times: VecDeque::from([1]),
        };
        Arc::new(Hub {
            local: [99; 32],
            policy: Policy {
                profile: crate::proofs::protocol_profile_fingerprint(),
                max_body_bytes: 4 * 1024 * 1024,
                max_settlement_proof_bytes: 3 * 1024 * 1024,
            },
            budget: p2p::Budget::new(32 * 1024 * 1024),
            local_deferred: AtomicU64::new(0),
            active_downloads: AtomicUsize::new(0),
            rules,
            inner: Mutex::new(Inner {
                canonical: context.clone(),
                anchors: BTreeMap::from([(context.id, context)]),
                entries: VecDeque::new(),
                sequence: 0,
                rate_start: Instant::now(),
                offers: 0,
            }),
            waiting: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            _charge: p2p::Budget::new(1024 * 1024).reserve(512 * 1024).unwrap(),
        })
    }
    fn header(parent: Hash, height: u64, tag: u8) -> Header {
        Header {
            network: [1; 32],
            height,
            parent,
            timestamp: 1 + height * 300,
            target: [255; 32],
            execution_commitment: [tag; 32],
            body_commitment: [tag; 32],
            nonce: 0,
        }
    }
    #[test]
    fn qualified_header_pauses_work_without_creating_state_and_raw_completion_cannot_resume_it() {
        let hub = hub();
        let first = header([2; 32], 1, 3);
        let mut wrong = first.clone();
        wrong.parent = [9; 32];
        assert!(!hub.offer(wrong, [4; 32]).unwrap());
        let mut wrong = first.clone();
        wrong.target = [254; 32];
        assert!(hub.offer(wrong, [4; 32]).is_err());
        assert!(hub.offer(first.clone(), [4; 32]).unwrap());
        assert!(hub.waiting());
        assert_eq!(hub.tip().unwrap(), (0, [2; 32]));
        assert!(hub.outgoing([4; 32]).unwrap().is_empty());
        assert_eq!(hub.outgoing([5; 32]).unwrap(), vec![first.clone()]);
        assert!(hub.outgoing([5; 32]).unwrap().is_empty());
        hub.completed(&first).unwrap();
        assert!(hub.waiting());
        assert_eq!(hub.tip().unwrap(), (0, [2; 32]));
        let child = header(first.id().unwrap(), 2, 6);
        hub.offer(child, [4; 32]).unwrap();
        hub.rejected(&first).unwrap();
        assert!(!hub.waiting());
        assert!(hub.outgoing([6; 32]).unwrap().is_empty());
    }
    #[test]
    fn sync_progress_requires_a_qualified_higher_work_header_and_actual_body_progress() {
        let hub = hub();
        assert!(hub.sync_progress().is_null());
        let first = header([2; 32], 1, 3);
        let id = first.id().unwrap();
        assert!(hub.offer(first.clone(), [8; 32]).unwrap());
        let before = hub.sync_progress();
        assert_eq!(before["candidate_height"], 1);
        assert_eq!(before["candidate_id"], crate::local::hex(&id));
        assert_eq!(before["lag_blocks"], 1);
        assert_eq!(before["downloads"].as_array().unwrap().len(), 0);

        let download = hub.download([7; 32]).unwrap().unwrap();
        let pending = hub.sync_progress();
        assert_eq!(pending["downloads"][0]["phase"], "waiting_for_body");
        assert_eq!(pending["downloads"][0]["attempt_index"], 1);
        assert_eq!(pending["downloads"][0]["active"], true);
        assert!(pending["downloads"][0]["last_progress_age_ms"].is_null());
        download.received(1024, 2048);
        let partial = hub.sync_progress();
        assert_eq!(partial["downloads"][0]["received_bytes"], 1024);
        assert_eq!(partial["downloads"][0]["total_bytes"], 2048);
        assert_eq!(partial["downloads"][0]["phase"], "receiving_body");
        assert!(partial["downloads"][0]["last_progress_age_ms"].is_number());
        download.received(512, 2048);
        assert_eq!(hub.sync_progress()["downloads"][0]["received_bytes"], 1024);
        download.decoded();
        assert_eq!(
            hub.sync_progress()["downloads"][0]["phase"],
            "decoded_awaiting_admission"
        );
        hub.completed(&first).unwrap();
        assert!(hub.sync_progress().is_null());
    }
    #[test]
    fn diagnostic_does_not_refresh_progress_or_reuse_a_failed_attempt_identity() {
        let hub = hub();
        let first = header([2; 32], 1, 3);
        hub.offer(first, [8; 32]).unwrap();
        let download = hub.download([7; 32]).unwrap().unwrap();
        download.received(1024, 2048);
        let old = Instant::now() - Duration::from_secs(60);
        download.progress.state.lock().unwrap().last_progress = Some(old);
        download.received(1024, 2048);
        download.received(512, 2048);
        let value = hub.sync_progress();
        assert!(
            value["downloads"][0]["last_progress_age_ms"]
                .as_u64()
                .unwrap()
                >= 60_000
        );
        assert_eq!(
            download.progress.state.lock().unwrap().last_progress,
            Some(old)
        );
        download.cancel.cancel();
        assert_eq!(hub.sync_progress()["downloads"][0]["active"], false);
        drop(download);
        let replacement = hub.download([6; 32]).unwrap().unwrap();
        let value = hub.sync_progress();
        assert_eq!(value["downloads"][0]["attempt_index"], 2);
        assert_eq!(value["downloads"][0]["received_bytes"], 0);
        assert!(value["downloads"][0]["last_progress_age_ms"].is_null());
        drop(replacement);
    }
    #[test]
    fn multi_peer_download_caps_cancellation_and_retained_ownership_are_enforced() {
        let hub = hub();
        let first = header([2; 32], 1, 3);
        let second = header(first.id().unwrap(), 2, 4);
        hub.offer(first.clone(), [8; 32]).unwrap();
        hub.offer(second, [8; 32]).unwrap();
        let one = hub.download([1; 32]).unwrap().unwrap();
        let two = hub.download([2; 32]).unwrap().unwrap();
        assert_eq!(one.header, first);
        assert_eq!(two.header, first);
        let three = hub.download([3; 32]).unwrap().unwrap();
        let four = hub.download([4; 32]).unwrap().unwrap();
        assert!(hub.download([5; 32]).unwrap().is_none());
        hub.completed(&first).unwrap();
        assert!(one.cancel.is_cancelled());
        assert!(two.cancel.is_cancelled());
        assert!(!three.cancel.is_cancelled());
        drop(one);
        drop(two);
        drop(three);
        drop(four);
        let inner = hub.inner.lock().unwrap();
        assert!(inner.entries.iter().all(|entry| entry.downloads.is_empty()));
    }
    #[test]
    fn cached_contexts_match_full_verification_across_median_windows_and_qualified_fork_prefixes() {
        let hub = hub();
        let mut headers = Vec::new();
        let mut parent = [2; 32];
        for height in 1..=25 {
            let header = header(parent, height, 3);
            parent = header.id().unwrap();
            assert!(hub.offer(header.clone(), [8; 32]).unwrap());
            headers.push(header);
        }
        let verified =
            crate::eng2::selection::VerifiedHeaders::verify(hub.rules.clone(), headers.clone())
                .unwrap();
        {
            let mut inner = hub.inner.lock().unwrap();
            for entry in &mut inner.entries {
                assert_eq!(
                    entry.context.work,
                    verified.work_at(entry.header.height).unwrap()
                );
                assert_eq!(
                    entry.context.times,
                    verified.timestamp_window(entry.header.height).unwrap()
                );
                entry.complete = true;
            }
            inner.canonical = inner
                .entries
                .iter()
                .find(|entry| entry.header.height == 20)
                .unwrap()
                .context
                .clone();
        }
        let mut parent = headers[16].id().unwrap();
        for height in 18..=21 {
            let fork = header(parent, height, 4);
            parent = fork.id().unwrap();
            assert!(hub.offer(fork, [7; 32]).unwrap());
        }
        assert!(hub.waiting());
        assert!(
            hub.outgoing([6; 32])
                .unwrap()
                .iter()
                .all(|header| header.height >= 20)
        );
        assert_eq!(hub.download([5; 32]).unwrap().unwrap().header.height, 18);
    }
    #[test]
    fn local_publication_serves_one_immutable_body_without_advancing_state_and_keeps_its_charge_until_last_reader()
     {
        let hub = hub();
        let mut body = crate::eng2::body::tests::body();
        body.network = hub.rules.network;
        body.height = 1;
        body.profile = hub.policy.profile;
        body.governance.clear();
        body.fund_claims.clear();
        body.transactions
            .sort_by_key(|tx| tx.record.statement_id(&body.network));
        let mut header = header([2; 32], 1, 3);
        header.body_commitment = body.commitment(hub.policy).unwrap();
        let id = header.id().unwrap();
        let body = Arc::new(body);
        let available = hub.budget.available().unwrap();
        hub.produced(header.clone(), body.clone()).unwrap();
        assert!(!hub.waiting());
        assert_eq!(hub.tip().unwrap(), (0, [2; 32]));
        assert!(hub.download([5; 32]).unwrap().is_none());
        let cached = hub.local_body(1, id).unwrap().unwrap();
        assert!(Arc::ptr_eq(&cached.body, &body));
        assert!(hub.local_body(2, id).unwrap().is_none());
        assert_eq!(hub.outgoing([5; 32]).unwrap(), vec![header.clone()]);
        let charged = hub.budget.available().unwrap();
        assert!(charged < available);
        hub.rejected(&header).unwrap();
        assert!(hub.local_body(1, id).unwrap().is_none());
        assert_eq!(hub.budget.available().unwrap(), charged);
        drop(cached);
        assert_eq!(hub.budget.available().unwrap(), available);
    }
    #[test]
    fn active_download_survives_cache_retention_but_not_its_fixed_body_budget() {
        let hub = hub();
        let first = header([2; 32], 1, 3);
        hub.offer(first, [8; 32]).unwrap();
        let download = hub.download([1; 32]).unwrap().unwrap();
        let now = Instant::now();
        {
            let mut inner = hub.inner.lock().unwrap();
            hub.reconcile(&mut inner, now + RETENTION + Duration::from_secs(1));
            assert_eq!(inner.entries.len(), 1);
            assert!(!download.cancel.is_cancelled());
            hub.reconcile(&mut inner, now + Duration::from_secs(179));
            assert_eq!(inner.entries.len(), 1);
            assert!(!download.cancel.is_cancelled());
            hub.reconcile(&mut inner, now + crate::eng2::transport::BODY_FETCH_TIMEOUT);
            assert!(inner.entries.is_empty());
        }
        assert!(download.cancel.is_cancelled());
        assert!(download.deadline.check().is_err());
        assert_eq!(hub.active_downloads(), 1);
        drop(download);
        assert_eq!(hub.active_downloads(), 0);
    }
    #[test]
    fn idle_retention_and_failed_download_peer_attempt_cap_remain_bounded() {
        let hub = hub();
        let first = header([2; 32], 1, 3);
        hub.offer(first, [8; 32]).unwrap();
        for peer in 1..=MAX_ATTEMPTS {
            let download = hub.download([peer as u8; 32]).unwrap().unwrap();
            drop(download);
            assert!(hub.download([peer as u8; 32]).unwrap().is_none());
        }
        assert_eq!(hub.active_downloads(), 0);
        assert!(hub.download([9; 32]).unwrap().is_none());
        let mut inner = hub.inner.lock().unwrap();
        assert_eq!(inner.entries[0].attempts.len(), MAX_ATTEMPTS);
        let expires = inner.entries[0].first + RETENTION;
        hub.reconcile(&mut inner, expires - Duration::from_nanos(1));
        assert_eq!(inner.entries.len(), 1);
        hub.reconcile(&mut inner, expires);
        assert!(inner.entries.is_empty());
    }
    #[test]
    fn expired_headers_do_not_release_slots_owned_by_queued_or_active_bodies() {
        let hub = hub();
        let first = header([2; 32], 1, 3);
        let second = header(first.id().unwrap(), 2, 3);
        hub.offer(first.clone(), [8; 32]).unwrap();
        hub.offer(second, [8; 32]).unwrap();
        let mut leases = Vec::new();
        for peer in 1..=4 {
            leases.push(hub.download([peer; 32]).unwrap().unwrap());
        }
        {
            let mut inner = hub.inner.lock().unwrap();
            hub.reconcile(
                &mut inner,
                Instant::now() + crate::eng2::transport::BODY_FETCH_TIMEOUT,
            );
        }
        assert!(leases.iter().all(|lease| lease.cancel.is_cancelled()));
        assert!(hub.inner.lock().unwrap().entries.is_empty());
        let replacement = header([2; 32], 1, 4);
        hub.offer(replacement.clone(), [9; 32]).unwrap();
        assert!(hub.download([5; 32]).unwrap().is_none());
        drop(leases.pop());
        let next = hub.download([5; 32]).unwrap().unwrap();
        assert_eq!(next.header, replacement);
        assert!(hub.download([6; 32]).unwrap().is_none());
        drop(next);
        drop(leases);
        assert_eq!(hub.active_downloads.load(Ordering::Acquire), 0);
        assert!(hub.download([6; 32]).unwrap().is_some());
    }
    #[test]
    fn postcommit_cache_failure_disables_optional_paths_and_preserves_owned_downloads() {
        let hub = hub();
        let header = header([2; 32], 1, 3);
        hub.offer(header.clone(), [8; 32]).unwrap();
        let download = hub.download([5; 32]).unwrap().unwrap();
        let mut calls = 0;
        // This update has no error-return channel to reverse a prior native
        // commitment. Its distinct diagnostic pauses only optional work/mining.
        hub.after_commit(|| {
            calls += 1;
            Err("synthetic cache update failure".into())
        });
        assert_eq!(calls, 1);
        assert_eq!(hub.error(), Some("header_context_update_failed"));
        assert!(hub.waiting());
        assert!(download.cancel.is_cancelled());
        assert_eq!(hub.active_downloads(), 1);
        assert!(hub.tip().is_err());
        assert!(hub.outgoing([6; 32]).is_err());
        assert!(hub.download([6; 32]).is_err());
        assert!(hub.offer(header, [6; 32]).is_err());
        assert!(hub.tick().is_ok());
        assert!(hub.waiting());
        drop(download);
        assert_eq!(hub.active_downloads(), 0);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = hub.inner.lock().unwrap();
            panic!("synthetic disabled cache lock failure");
        }));
        assert!(poisoned.is_err());
        // Late optional completions cannot turn the disabled cache into a
        // failed admission-worker result or stop ordinary synchronization.
        let late = self::header([2; 32], 1, 4);
        assert!(hub.completed(&late).is_ok());
        assert!(hub.rejected(&late).is_ok());
        assert!(hub.tick().is_ok());
    }
}
