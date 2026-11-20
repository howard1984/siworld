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
fn cache_charge() -> usize {
    512 * 1024 + MAX_HEADERS * std::mem::size_of::<Entry>()
}
const MAX_DOWNLOADS: usize = 4;
const MAX_BODY_SOURCE_HINTS: usize = 8;
#[cfg(test)]
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
    relay_sent: std::collections::BTreeSet<Hash>,
    offered_sources: [Option<Hash>; 8],
    downloads: BTreeMap<Hash, DownloadState>,
    authorization: Option<p2p::BodyAuthorization>,
    complete: bool,
    body: Option<Arc<LocalBody>>,
}
struct Inner {
    progress_owner: Option<super::progress_runs::OwnerContext>,
    progress_epoch: u64,
    canonical: Context,
    anchors: BTreeMap<Hash, Context>,
    entries: VecDeque<Entry>,
    sequence: u64,
    rate_start: Instant,
    offers: usize,
    body_tips: BTreeMap<Hash, BodyTip>,
}
struct BodyTip {
    session: u64,
    height: u64,
    id: Hash,
    pieces: bool,
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
    binding: p2p::Binding,
    progress_runs: super::progress_runs::Recorder,
    local: Hash,
    policy: Policy,
    budget: p2p::Budget,
    body_scope: p2p::BodyScope,
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
struct ProgressObservation {
    hub: Arc<Hub>,
    candidate: super::progress_runs::Candidate,
    deadline: p2p::Deadline,
}
impl ProgressObservation {
    fn received(&self, bytes: usize, total: usize) {
        let token = self.hub.progress_runs.token(self.candidate.clone());
        if self.deadline.check().is_ok() && !self.hub.failed.load(Ordering::Acquire) {
            if let Some(token) = token {
                self.hub.progress_runs.received(token, bytes, total);
            }
        } else {
            self.hub
                .progress_runs
                .end(self.candidate.id, self.candidate.attempt_index);
        }
    }
}
impl Drop for ProgressObservation {
    fn drop(&mut self) {
        self.hub
            .progress_runs
            .end(self.candidate.id, self.candidate.attempt_index);
    }
}
pub(crate) struct Download {
    ownership: Option<p2p::BodyClaim>,
    candidate: super::progress_runs::Candidate,
    pub header: Header,
    pub cancel: p2p::Cancellation,
    pub deadline: p2p::Deadline,
    progress: Arc<DownloadProgress>,
    peer: Hash,
    hub: Arc<Hub>,
}
impl Download {
    pub(crate) fn ownership(&self) -> Result<&p2p::BodyClaim, String> {
        self.ownership
            .as_ref()
            .ok_or_else(|| "body acquisition ownership already transferred".into())
    }

    pub(crate) fn take_ownership(&mut self) -> Result<p2p::BodyClaim, String> {
        self.ownership
            .take()
            .ok_or_else(|| "body acquisition ownership already transferred".into())
    }

    pub(crate) fn received(&self, bytes: usize, total: usize) {
        let token = self.hub.progress_runs.token(self.candidate.clone());
        self.progress.received(bytes, total);
        if self.deadline.check().is_ok() && !self.hub.failed.load(Ordering::Acquire) {
            if let Some(token) = token {
                self.hub.progress_runs.received(token, bytes, total);
            }
        } else {
            self.hub
                .progress_runs
                .end(self.candidate.id, self.candidate.attempt_index);
        }
    }
    pub(crate) fn decoded(&self) {
        self.progress.decoded();
        self.hub
            .progress_runs
            .end(self.candidate.id, self.candidate.attempt_index);
    }
}
impl Drop for Download {
    fn drop(&mut self) {
        self.hub
            .progress_runs
            .end(self.candidate.id, self.candidate.attempt_index);
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
            binding: owner.engine().genesis().peer_binding(),
            progress_runs: super::progress_runs::Recorder::default(),
            local,
            policy: owner.engine().body_policy(),
            budget: budget.clone(),
            body_scope: owner.body_scope()?,
            local_deferred: AtomicU64::new(0),
            active_downloads: AtomicUsize::new(0),
            rules,
            inner: Mutex::new(Inner {
                progress_owner: None,
                progress_epoch: 0,
                canonical: genesis,
                anchors: BTreeMap::new(),
                entries: VecDeque::new(),
                sequence: 0,
                rate_start: now,
                offers: 0,
                body_tips: BTreeMap::new(),
            }),
            waiting: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            _charge: budget
                .reserve(cache_charge())
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
            self.invalidate_progress_context();
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
        self.invalidate_progress_context();
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
        let head_changed = inner.canonical.id != canonical.id;
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
                    relay_sent: Default::default(),
                    offered_sources: Default::default(),
                    downloads: Default::default(),
                    authorization: None,
                    complete: true,
                    body: None,
                });
            }
        }
        Self::canonical_body_available(
            &mut inner,
            head.id,
            self.local,
            head_changed,
            Instant::now(),
        );
        self.reconcile(&mut inner, Instant::now());
        Ok(())
    }
    fn canonical_body_available(
        inner: &mut Inner,
        id: Hash,
        local: Hash,
        head_changed: bool,
        now: Instant,
    ) {
        for entry in &mut inner.entries {
            if entry.context.id == id {
                if head_changed {
                    entry.first = now;
                    entry.sent.clear();
                }
                entry.complete = true;
                if entry.source != local {
                    entry.body = None;
                }
                for download in entry.downloads.values() {
                    download.cancel.cancel();
                }
            }
        }
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
    /// The canonical owner calls this immediately after its state transition.
    /// Status export only reads history and never changes event eligibility.
    pub(crate) fn publish_progress_context(&self, eligible: bool) {
        self.set_progress_context(eligible, false);
    }
    /// Call before a canonical switch, recovery, or owner error transition.
    pub(crate) fn invalidate_progress_context(&self) {
        self.set_progress_context(false, true);
    }
    fn set_progress_context(&self, eligible: bool, force: bool) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        let mut context = super::progress_runs::OwnerContext {
            state_epoch: inner.progress_epoch,
            canonical_height: inner.canonical.height,
            canonical_id: inner.canonical.id,
            canonical_work: inner.canonical.work,
            eligible: eligible && !self.failed.load(Ordering::Acquire),
        };
        if !force && inner.progress_owner.as_ref() == Some(&context) {
            return;
        }
        let Some(epoch) = inner.progress_epoch.checked_add(1) else {
            return;
        };
        context.state_epoch = epoch;
        inner.progress_epoch = epoch;
        inner.progress_owner = Some(context.clone());
        self.progress_runs.publish(context);
    }
    pub(crate) fn observe_body(
        self: &Arc<Self>,
        header: &Header,
        peer: Hash,
        claim: &p2p::BodyClaim,
    ) -> Option<super::super::network::BodyProgress> {
        let observation = self.body_observation(header, peer, claim)?;
        Some(Box::new(move |bytes, total| {
            observation.received(bytes, total)
        }))
    }
    fn body_observation(
        self: &Arc<Self>,
        header: &Header,
        peer: Hash,
        claim: &p2p::BodyClaim,
    ) -> Option<ProgressObservation> {
        self.offer(header.clone(), peer).ok()?;
        let id = header.id().ok()?;
        let attempt_index = claim.source_ordinal()?;
        let inner = self.inner.lock().ok()?;
        let entry = inner.entries.iter().find(|e| e.context.id == id)?;
        Some(ProgressObservation {
            hub: self.clone(),
            candidate: super::progress_runs::Candidate {
                id,
                sequence: entry.sequence,
                height: entry.context.height,
                work: entry.context.work,
                attempt_index,
            },
            deadline: claim.deadline().clone(),
        })
    }
    pub(crate) fn sync_progress_runs(&self) -> serde_json::Value {
        self.progress_runs.snapshot()
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
    pub(crate) fn accepted_body(&self, header: &Header) -> Result<(), String> {
        if header.network != self.binding.network {
            return Err("accepted body context differs".into());
        }
        self.budget
            .accepted_body(
                self.binding,
                header.height,
                header.id().map_err(|_| "accepted body identity rejected")?,
            )
            .map_err(|_| "accepted body retirement unavailable")?;
        Ok(())
    }
    pub(crate) fn body_policy(&self) -> Policy {
        self.policy
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
    pub(crate) fn relay_body(
        &self,
        peer: Hash,
    ) -> Result<Option<(Arc<LocalBody>, p2p::Deadline)>, String> {
        self.ensure_available()?;
        let inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        Ok(inner
            .entries
            .iter()
            .filter(|e| e.source == self.local && !e.relay_sent.contains(&peer))
            .filter_map(|e| {
                e.body.as_ref().map(|body| {
                    (
                        body.clone(),
                        p2p::Deadline::from_started(
                            e.first,
                            crate::eng2::transport::BODY_FETCH_TIMEOUT,
                            p2p::Cancellation::default(),
                        ),
                    )
                })
            })
            .find(|(_, deadline)| deadline.check().is_ok()))
    }
    pub(crate) fn relay_offered(&self, header: &Header, peer: Hash) -> Result<(), String> {
        let id = header.id().map_err(|_| "relay header identity rejected")?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        if let Some(entry) = inner.entries.iter_mut().find(|e| e.context.id == id) {
            entry.relay_sent.insert(peer);
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
        if let Some(entry) = inner.entries.iter_mut().find(|e| e.context.id == id) {
            if !entry.offered_sources.contains(&Some(peer))
                && let Some(slot) = entry.offered_sources.iter_mut().find(|s| s.is_none())
            {
                *slot = Some(peer);
            }
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
            relay_sent: Default::default(),
            offered_sources: std::array::from_fn(|i| (i == 0).then_some(peer)),
            downloads: Default::default(),
            authorization: None,
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
    #[cfg(test)]
    pub(crate) fn download(self: &Arc<Self>, peer: Hash) -> Result<Option<Download>, String> {
        self.download_mode(peer, p2p::BodyMode::Legacy)
    }
    #[cfg(test)]
    pub(crate) fn download_mode(
        self: &Arc<Self>,
        peer: Hash,
        mode: p2p::BodyMode,
    ) -> Result<Option<Download>, String> {
        self.download_selected(peer, mode, None, &Default::default(), false, None)
    }
    #[cfg(test)]
    pub(crate) fn download_exact(
        self: &Arc<Self>,
        peer: Hash,
        id: Hash,
    ) -> Result<Option<Download>, String> {
        self.download_selected(
            peer,
            p2p::BodyMode::Pieces,
            Some(id),
            &Default::default(),
            false,
            None,
        )
    }
    pub(crate) fn download_preferred(
        self: &Arc<Self>,
        peer: Hash,
        mode: p2p::BodyMode,
        target: Option<Hash>,
        connected: &std::collections::BTreeSet<Hash>,
    ) -> Result<Option<Download>, String> {
        self.download_selected(peer, mode, target, connected, true, None)
    }
    #[cfg(test)]
    fn download_unqualified(
        self: &Arc<Self>,
        peer: Hash,
        mode: p2p::BodyMode,
        target: Option<Hash>,
        connected: &std::collections::BTreeSet<Hash>,
    ) -> Result<Option<Download>, String> {
        self.download_selected(peer, mode, target, connected, false, None)
    }
    pub(crate) fn download_offered(
        self: &Arc<Self>,
        offer: &crate::eng2::transport::propagation::Offer,
        connected: &std::collections::BTreeSet<Hash>,
    ) -> Result<Option<Download>, String> {
        if offer.binding() != self.binding {
            return Err("body offer binding differs".into());
        }
        let id = offer
            .header()
            .id()
            .map_err(|_| "body offer identity rejected")?;
        self.download_selected(
            offer.peer(),
            p2p::BodyMode::Pieces,
            Some(id),
            connected,
            true,
            Some((offer.peer(), id)),
        )
    }
    #[cfg(test)]
    pub(crate) fn observe_body_tip(
        &self,
        peer: Hash,
        session: u64,
        height: u64,
        id: Hash,
    ) -> Result<(), String> {
        self.observe_body_lane_tip(peer, session, height, id, false)
    }

    pub(super) fn observe_body_lane_tip(
        &self,
        peer: Hash,
        session: u64,
        height: u64,
        id: Hash,
        pieces: bool,
    ) -> Result<(), String> {
        self.ensure_available()?;
        if peer == [0; 32]
            || session == 0
            || height > self.rules.max_headers as u64
            || (height == 0 && id != self.binding.genesis)
        {
            return Err("body source announcement rejected".into());
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        if !inner.body_tips.contains_key(&peer) && inner.body_tips.len() == MAX_BODY_SOURCE_HINTS {
            // An idle or unqualified tip cannot crowd out a known candidate's
            // holder. The fixed source-hint capacity is not expanded.
            if let Some(stale) = inner.body_tips.iter().find_map(|(source, tip)| {
                (!inner.entries.iter().any(|e| {
                    !e.complete && e.header.height == tip.height && e.context.id == tip.id
                }))
                .then_some(*source)
            }) {
                inner.body_tips.remove(&stale);
            }
        }
        if inner.body_tips.contains_key(&peer) || inner.body_tips.len() < MAX_BODY_SOURCE_HINTS {
            inner.body_tips.insert(
                peer,
                BodyTip {
                    session,
                    height,
                    id,
                    pieces,
                },
            );
        }
        Ok(())
    }
    pub(crate) fn forget_body_tip(&self, peer: Hash, session: u64) {
        if let Ok(mut inner) = self.inner.lock()
            && inner
                .body_tips
                .get(&peer)
                .is_some_and(|tip| tip.session == session)
        {
            inner.body_tips.remove(&peer);
        }
    }
    pub(super) fn piece_sources(
        &self,
        id: Hash,
        peer: Hash,
        session: u64,
        connected: &std::collections::BTreeSet<Hash>,
    ) -> Result<std::collections::BTreeSet<Hash>, String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| "header cache lock poisoned")?;
        let Some(entry) = inner
            .entries
            .iter()
            .find(|entry| entry.context.id == id && !entry.complete)
        else {
            return Ok(Default::default());
        };
        Ok(connected
            .iter()
            .copied()
            .filter(|source| {
                inner
                    .body_tips
                    .get(source)
                    .is_some_and(|tip| tip.pieces && (*source != peer || tip.session == session))
                    && Self::source_can_serve(&inner, *source, entry, None)
            })
            .collect())
    }
    fn source_can_serve(
        inner: &Inner,
        peer: Hash,
        target: &Entry,
        offer: Option<(Hash, Hash)>,
    ) -> bool {
        if offer == Some((peer, target.context.id)) {
            return true;
        }
        let Some(&BodyTip {
            mut height, mut id, ..
        }) = inner.body_tips.get(&peer)
        else {
            return false;
        };
        // Height alone is never sufficient: follow only qualified exact hashes
        // and parent links on the peer's announced canonical branch.
        for _ in 0..MAX_HEADERS {
            if height < target.header.height {
                return false;
            }
            let Some(entry) = inner
                .entries
                .iter()
                .find(|e| e.context.id == id && e.header.height == height)
            else {
                return false;
            };
            if id == target.context.id {
                return true;
            }
            id = entry.header.parent;
            let Some(parent_height) = height.checked_sub(1) else {
                return false;
            };
            height = parent_height;
        }
        false
    }
    fn download_selected(
        self: &Arc<Self>,
        peer: Hash,
        mode: p2p::BodyMode,
        target: Option<Hash>,
        connected: &std::collections::BTreeSet<Hash>,
        announced_only: bool,
        offer: Option<(Hash, Hash)>,
    ) -> Result<Option<Download>, String> {
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
        // A busy exact body does not block independent candidates. Failed
        // claims consume neither a peer attempt nor a download slot.
        let mut eligible: Vec<_> = inner
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                target.is_none_or(|id| id == e.context.id)
                    && !e.complete
                    && (if announced_only {
                        Self::source_can_serve(&inner, peer, e, offer)
                    } else {
                        e.offered_sources.contains(&Some(peer))
                    })
                    && needed.contains(&e.context.id)
            })
            .map(|(index, e)| (e.header.height, e.sequence, index))
            .collect();
        eligible.sort_unstable();
        let mut selected = None;
        for (_, _, index) in eligible {
            let alternatives: Vec<_> = if announced_only {
                inner
                    .body_tips
                    .keys()
                    .copied()
                    .filter(|p| connected.contains(p))
                    .filter(|p| Self::source_can_serve(&inner, *p, &inner.entries[index], offer))
                    .collect()
            } else {
                inner.entries[index]
                    .offered_sources
                    .iter()
                    .flatten()
                    .copied()
                    .filter(|p| connected.contains(p))
                    .collect()
            };
            let entry = &mut inner.entries[index];
            let cancel = p2p::Cancellation::default();
            let deadline = p2p::Deadline::cancellable(
                crate::eng2::transport::BODY_FETCH_TIMEOUT,
                cancel.clone(),
            );
            if entry.authorization.is_none() {
                match self.budget.authorize_body(
                    &self.body_scope,
                    self.binding,
                    entry.header.height,
                    entry.context.id,
                    &deadline,
                ) {
                    Ok(authorization) => entry.authorization = Some(authorization),
                    Err(
                        p2p::BodyClaimError::Capacity
                        | p2p::BodyClaimError::Expired
                        | p2p::BodyClaimError::QueryLimit,
                    ) => continue,
                    Err(_) => return Err("body owner authorization unavailable".into()),
                }
            }
            let authorization = entry
                .authorization
                .as_ref()
                .ok_or("body authorization missing")?;
            match self
                .budget
                .claim_body_preferred(authorization, peer, mode, alternatives)
            {
                Ok(claim) => {
                    selected = Some((index, claim.cancellation(), claim));
                    break;
                }
                Err(p2p::BodyClaimError::Expired) => {
                    // Release the cached pin only after the old lease is no
                    // longer useful. The shared registry owns retry timing.
                    entry.authorization = None;
                    continue;
                }
                Err(
                    p2p::BodyClaimError::Busy
                    | p2p::BodyClaimError::Capacity
                    | p2p::BodyClaimError::SourceUsed
                    | p2p::BodyClaimError::PreferUnused
                    | p2p::BodyClaimError::QueryLimit,
                ) => continue,
                Err(_) => return Err("node body ownership unavailable".into()),
            }
        }
        let Some((index, cancel, ownership)) = selected else {
            return Ok(None);
        };
        let entry = &mut inner.entries[index];
        let deadline = ownership.deadline().clone();
        let source_ordinal = ownership
            .source_ordinal()
            .ok_or("body source ordinal unavailable")?;
        let progress = Arc::new(DownloadProgress::new(source_ordinal));
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
            ownership: Some(ownership),
            candidate: super::progress_runs::Candidate {
                id: entry.context.id,
                sequence: entry.sequence,
                height: entry.context.height,
                work: entry.context.work,
                attempt_index: progress.attempt_index,
            },
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
                if entry.source != self.local {
                    entry.body = None;
                }
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
    fn checkpoint_progress_candidate() -> super::super::progress_runs::Candidate {
        super::super::progress_runs::Candidate {
            id: [3; 32],
            sequence: 1,
            height: 1,
            work: siworld_core::pow::block_work(&[255; 32]),
            attempt_index: 1,
        }
    }
    fn checkpoint_progress_event(hub: &Hub, bytes: usize, now: u64) {
        let token = hub
            .progress_runs
            .token(checkpoint_progress_candidate())
            .unwrap();
        hub.progress_runs.received_test_at(token, bytes, now);
    }
    #[test]
    fn checkpoint_progress_pending_preserves_actual_run_without_extending_it() {
        use super::super::progress_checkpoint::State;
        let hub = hub();
        let mut checkpoint = State::default();
        checkpoint.publish(&hub, true, None);
        checkpoint_progress_event(&hub, 10, 100);
        checkpoint_progress_event(&hub, 20, 200);
        let before = hub.sync_progress_runs();
        checkpoint.restoration(&hub, false);
        checkpoint.publish(&hub, true, Some("checkpoint_retained_restoration_pending"));
        assert_eq!(hub.sync_progress_runs(), before);
        checkpoint_progress_event(&hub, 30, 300);
        checkpoint.restoration(&hub, false);
        checkpoint.publish(&hub, true, Some("checkpoint_retained_restoration_pending"));
        checkpoint_progress_event(&hub, 40, 400);
        let after = hub.sync_progress_runs();
        assert_eq!(after["runs"].as_array().unwrap().len(), 1);
        assert_eq!(after["runs"][0]["id"], before["runs"][0]["id"]);
        assert_eq!(
            after["runs"][0]["state_epoch"],
            before["runs"][0]["state_epoch"]
        );
        assert_eq!(after["runs"][0]["start_ns"], "100");
        assert_eq!(after["runs"][0]["end_ns"], "400");
        assert_eq!(hub.sync_progress_runs(), after);
        // Repeated byte counts and a gap beyond five seconds still cannot extend a run.
        checkpoint_progress_event(&hub, 40, 500);
        assert_eq!(hub.sync_progress_runs(), after);
        checkpoint_progress_event(&hub, 50, 5_000_000_401);
        assert_eq!(hub.sync_progress_runs(), after);
        checkpoint_progress_event(&hub, 60, 5_000_000_501);
        assert_eq!(
            hub.sync_progress_runs()["runs"].as_array().unwrap().len(),
            2
        );
    }
    #[test]
    fn checkpoint_progress_failure_pending_cannot_reopen_until_successful_tick() {
        use super::super::progress_checkpoint::State;
        for error in [
            "checkpoint_retained_restoration_failed",
            "checkpoint_tick_rejected_or_unavailable",
            "signed_bootstrap_unavailable",
        ] {
            let hub = hub();
            let mut checkpoint = State::default();
            checkpoint.publish(&hub, true, None);
            checkpoint_progress_event(&hub, 10, 100);
            checkpoint_progress_event(&hub, 20, 200);
            let stale = hub
                .progress_runs
                .token(checkpoint_progress_candidate())
                .unwrap();
            if error == "checkpoint_retained_restoration_failed" {
                checkpoint.restoration(&hub, true);
            } else {
                checkpoint.failed(&hub);
            }
            checkpoint.publish(&hub, true, Some(error));
            for _ in 0..2 {
                checkpoint.restoration(&hub, false);
                checkpoint.publish(&hub, true, Some("checkpoint_retained_restoration_pending"));
                assert!(
                    hub.progress_runs
                        .token(checkpoint_progress_candidate())
                        .is_none()
                );
            }
            // Even clearing the presentation string is not a successful tick.
            checkpoint.publish(&hub, true, None);
            assert!(
                hub.progress_runs
                    .token(checkpoint_progress_candidate())
                    .is_none()
            );
            let stopped = hub.sync_progress_runs();
            hub.progress_runs.received_test_at(stale, 30, 300);
            assert_eq!(hub.sync_progress_runs(), stopped);
            checkpoint.recovered();
            checkpoint.publish(&hub, true, None);
            checkpoint_progress_event(&hub, 40, 400);
            checkpoint_progress_event(&hub, 50, 500);
            let after = hub.sync_progress_runs();
            assert_eq!(after["runs"].as_array().unwrap().len(), 2);
            assert_ne!(
                after["runs"][0]["state_epoch"],
                after["runs"][1]["state_epoch"]
            );
            assert_eq!(after["runs"][1]["start_ns"], "400");
        }
    }
    #[test]
    fn checkpoint_progress_pending_cannot_override_owner_guards_or_hard_errors() {
        use super::super::progress_checkpoint::State;
        for error in [
            None,
            Some("checkpoint_retained_restoration_pending"),
            Some("checkpoint_current_quorum_conflict"),
            Some("checkpoint_observer_unavailable"),
        ] {
            let hub = hub();
            let mut checkpoint = State::default();
            checkpoint.publish(&hub, true, None);
            checkpoint_progress_event(&hub, 10, 100);
            checkpoint_progress_event(&hub, 20, 200);
            let old = hub.sync_progress_runs();
            let stale = hub
                .progress_runs
                .token(checkpoint_progress_candidate())
                .unwrap();
            // These publications represent the unchanged owner/archive/reorg/observer gates.
            checkpoint.publish(&hub, false, error);
            checkpoint.restoration(&hub, false);
            checkpoint.publish(&hub, false, Some("checkpoint_retained_restoration_pending"));
            assert!(
                hub.progress_runs
                    .token(checkpoint_progress_candidate())
                    .is_none()
            );
            hub.progress_runs.received_test_at(stale, 30, 300);
            assert_eq!(hub.sync_progress_runs(), old);
            // Recovery cannot override an owner/observer/reorganization guard.
            checkpoint.recovered();
            checkpoint.publish(&hub, false, None);
            assert!(
                hub.progress_runs
                    .token(checkpoint_progress_candidate())
                    .is_none()
            );
            checkpoint.publish(&hub, true, Some("unrecognized_error"));
            assert!(
                hub.progress_runs
                    .token(checkpoint_progress_candidate())
                    .is_none()
            );
        }
    }

    use super::*;
    impl Hub {
        pub(super) fn advertise_test_source(&self, peer: Hash) {
            let headers: Vec<_> = self
                .inner
                .lock()
                .unwrap()
                .entries
                .iter()
                .map(|entry| entry.header.clone())
                .collect();
            for header in headers {
                self.offer(header, peer).unwrap();
            }
        }
        pub(super) fn advertised_download(
            self: &Arc<Self>,
            peer: Hash,
        ) -> Result<Option<Download>, String> {
            self.advertise_test_source(peer);
            self.download(peer)
        }
        pub(super) fn advertised_download_mode(
            self: &Arc<Self>,
            peer: Hash,
            mode: p2p::BodyMode,
        ) -> Result<Option<Download>, String> {
            self.advertise_test_source(peer);
            self.download_mode(peer, mode)
        }
    }
    pub(super) fn hub() -> Arc<Hub> {
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
        let budget = p2p::Budget::new(32 * 1024 * 1024);
        let body_scope = budget
            .resident_body_scope(1, Instant::now() + Duration::from_secs(3600))
            .unwrap();
        Arc::new(Hub {
            binding: p2p::Binding {
                network: rules.network,
                genesis: rules.genesis,
                verifier: [0; 32],
            },
            progress_runs: super::super::progress_runs::Recorder::default(),
            local: [99; 32],
            policy: Policy {
                profile: crate::proofs::protocol_profile_fingerprint(),
                max_body_bytes: 4 * 1024 * 1024,
                max_settlement_proof_bytes: 3 * 1024 * 1024,
            },
            budget,
            body_scope,
            local_deferred: AtomicU64::new(0),
            active_downloads: AtomicUsize::new(0),
            rules,
            inner: Mutex::new(Inner {
                progress_owner: None,
                progress_epoch: 0,
                canonical: context.clone(),
                anchors: BTreeMap::from([(context.id, context)]),
                entries: VecDeque::new(),
                sequence: 0,
                rate_start: Instant::now(),
                offers: 0,
                body_tips: BTreeMap::new(),
            }),
            waiting: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            _charge: p2p::Budget::new(1024 * 1024)
                .reserve(cache_charge())
                .unwrap(),
        })
    }
    pub(super) fn header(parent: Hash, height: u64, tag: u8) -> Header {
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
    fn legacy_discovery_and_optional_progress_keep_candidate_source_ordinals_after_many_claims() {
        let hub = hub();
        // Burn only unrelated claims. Their process-wide generations must not
        // become this candidate's public source-attempt index.
        for tag in 10..18 {
            let claim = hub
                .budget
                .claim_body(
                    hub.binding,
                    1,
                    [tag; 32],
                    [7; 32],
                    p2p::BodyMode::Legacy,
                    &p2p::Deadline::new(Duration::from_secs(180)),
                )
                .unwrap();
            claim.begin_query([7; 32]).unwrap();
            drop(claim);
            hub.budget.accepted_body(hub.binding, 1, [tag; 32]).unwrap();
        }
        let header = header([2; 32], 1, 3);
        let claim = hub
            .budget
            .claim_body(
                hub.binding,
                1,
                header.id().unwrap(),
                [7; 32],
                p2p::BodyMode::Legacy,
                &p2p::Deadline::new(Duration::from_secs(180)),
            )
            .unwrap();
        assert!(claim.progress_attempt().unwrap() > 4);
        let observation = hub.body_observation(&header, [7; 32], &claim).unwrap();
        assert_eq!(observation.candidate.attempt_index, 1);
        claim.begin_query([7; 32]).unwrap();
        let ordinary = hub.observe_body(&header, [7; 32], &claim).unwrap();
        ordinary(1, 10);
        drop(ordinary);
        let discovery = hub.observe_body(&header, [7; 32], &claim).unwrap();
        discovery(2, 10);
        drop(discovery);
        drop(observation);
        drop(claim);
        let download = hub.advertised_download([6; 32]).unwrap().unwrap();
        assert_eq!(download.candidate.attempt_index, 2);
        download.ownership().unwrap().begin_query([6; 32]).unwrap();
        assert_eq!(download.ownership().unwrap().source_ordinal(), Some(2));
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

        let download = hub.advertised_download([7; 32]).unwrap().unwrap();
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
        let download = hub.advertised_download([7; 32]).unwrap().unwrap();
        download.ownership().unwrap().begin_query([7; 32]).unwrap();
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
        let replacement = hub.advertised_download([6; 32]).unwrap().unwrap();
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
        hub.offer(first.clone(), [8; 32]).unwrap();
        let mut parent = first.id().unwrap();
        for height in 2..=5 {
            let next = header(parent, height, 4);
            parent = next.id().unwrap();
            hub.offer(next, [8; 32]).unwrap();
        }
        let one = hub.advertised_download([1; 32]).unwrap().unwrap();
        let two = hub.advertised_download([2; 32]).unwrap().unwrap();
        assert_eq!(one.header, first);
        assert_eq!(two.header.height, 2);
        let three = hub.advertised_download([3; 32]).unwrap().unwrap();
        let four = hub.advertised_download([4; 32]).unwrap().unwrap();
        assert_eq!(three.header.height, 3);
        assert_eq!(four.header.height, 4);
        assert!(hub.advertised_download([5; 32]).unwrap().is_none());
        assert!(
            hub.inner
                .lock()
                .unwrap()
                .entries
                .iter()
                .all(|e| e.downloads.len() <= 1)
        );
        hub.completed(&first).unwrap();
        assert!(one.cancel.is_cancelled());
        assert!(!two.cancel.is_cancelled());
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
        assert_eq!(
            hub.advertised_download([5; 32])
                .unwrap()
                .unwrap()
                .header
                .height,
            18
        );
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
        assert!(hub.advertised_download([5; 32]).unwrap().is_none());
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
        let download = hub.advertised_download([1; 32]).unwrap().unwrap();
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
    fn actual_hub_legacy_and_pieces_downloads_share_one_exact_account() {
        let hub = hub();
        let first = header([2; 32], 1, 3);
        hub.offer(first.clone(), [8; 32]).unwrap();
        let pieces = hub
            .advertised_download_mode([5; 32], p2p::BodyMode::Pieces)
            .unwrap()
            .unwrap();
        let first_deadline = pieces.deadline.expires_at();
        pieces.ownership().unwrap().begin_query([5; 32]).unwrap();
        assert!(
            hub.advertised_download_mode([6; 32], p2p::BodyMode::Legacy)
                .unwrap()
                .is_none()
        );
        drop(pieces);
        let retry = hub
            .advertised_download_mode([5; 32], p2p::BodyMode::Legacy)
            .unwrap()
            .unwrap();
        assert_eq!(retry.deadline.expires_at(), first_deadline);
        assert_eq!(retry.ownership().unwrap().source_ordinal(), Some(2));
        drop(retry);
        let legacy = hub
            .advertised_download_mode([6; 32], p2p::BodyMode::Legacy)
            .unwrap()
            .unwrap();
        assert_eq!(legacy.deadline.expires_at(), first_deadline);
        for _ in 0..3 {
            legacy.ownership().unwrap().begin_query([6; 32]).unwrap();
        }
        assert!(legacy.ownership().unwrap().begin_query([6; 32]).is_err());
        drop(legacy);
        assert!(
            hub.advertised_download_mode([7; 32], p2p::BodyMode::Pieces)
                .unwrap()
                .is_none()
        );
        assert_eq!(hub.budget.retained_body_accounting().0, 1);
        assert_eq!(hub.active_downloads(), 0);
    }
    #[test]
    fn idle_retention_and_failed_download_peer_attempt_cap_remain_bounded() {
        let hub = hub();
        let first = header([2; 32], 1, 3);
        hub.offer(first, [8; 32]).unwrap();
        for peer in 1..=MAX_ATTEMPTS {
            let download = hub.advertised_download([peer as u8; 32]).unwrap().unwrap();
            download
                .ownership()
                .unwrap()
                .begin_query([peer as u8; 32])
                .unwrap();
            drop(download);
        }
        assert_eq!(hub.active_downloads(), 0);
        assert!(hub.advertised_download([9; 32]).unwrap().is_none());
        let mut inner = hub.inner.lock().unwrap();
        assert_eq!(inner.entries[0].offered_sources.iter().flatten().count(), 6);
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
        hub.offer(first.clone(), [8; 32]).unwrap();
        let mut parent = first.id().unwrap();
        for height in 2..=4 {
            let next = header(parent, height, 3);
            parent = next.id().unwrap();
            hub.offer(next, [8; 32]).unwrap();
        }
        let mut leases = Vec::new();
        for peer in 1..=4 {
            leases.push(hub.advertised_download([peer; 32]).unwrap().unwrap());
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
        assert!(hub.advertised_download([5; 32]).unwrap().is_none());
        drop(leases.pop());
        let next = hub.advertised_download([5; 32]).unwrap().unwrap();
        assert_eq!(next.header, replacement);
        assert!(hub.advertised_download([6; 32]).unwrap().is_none());
        drop(next);
        drop(leases);
        assert_eq!(hub.active_downloads.load(Ordering::Acquire), 0);
        assert!(hub.advertised_download([6; 32]).unwrap().is_some());
    }
    #[test]
    fn postcommit_cache_failure_disables_optional_paths_and_preserves_owned_downloads() {
        let hub = hub();
        let header = header([2; 32], 1, 3);
        hub.offer(header.clone(), [8; 32]).unwrap();
        let download = hub.advertised_download([5; 32]).unwrap().unwrap();
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

#[cfg(test)]
mod retry_cache_regressions {
    use super::*;
    #[test]
    fn cached_expired_authorization_releases_pin_and_reopens_the_same_body() {
        let hub = super::tests::hub();
        let header = super::tests::header([2; 32], 1, 3);
        hub.offer(header, [5; 32]).unwrap();
        let first = hub.advertised_download([5; 32]).unwrap().unwrap();
        first.ownership().unwrap().begin_query([5; 32]).unwrap();
        drop(first);
        // Age the registry, leaving the real cache pin and request path intact.
        hub.budget.age_test_body_accounts(Duration::from_secs(196));
        assert!(hub.advertised_download([5; 32]).unwrap().is_none());
        let next = hub.advertised_download([5; 32]).unwrap();
        assert!(
            next.is_some(),
            "the cache must release its expired authorization pin"
        );
        let next = next.unwrap();
        next.ownership().unwrap().begin_query([5; 32]).unwrap();
        assert_eq!(hub.budget.retained_body_accounting().0, 1);
        assert_eq!(next.ownership().unwrap().source_ordinal(), Some(1));
    }

    #[test]
    fn cached_failed_source_retries_after_unused_connected_offerer() {
        let hub = super::tests::hub();
        let h = super::tests::header([2; 32], 1, 3);
        hub.offer(h.clone(), [5; 32]).unwrap();
        let one = hub.advertised_download([5; 32]).unwrap().unwrap();
        let deadline = one.deadline.expires_at();
        one.ownership().unwrap().begin_query([5; 32]).unwrap();
        drop(one);
        hub.offer(h.clone(), [6; 32]).unwrap();
        let connected = std::collections::BTreeSet::from([[5; 32], [6; 32]]);
        assert!(
            hub.download_unqualified([5; 32], p2p::BodyMode::Legacy, None, &connected)
                .unwrap()
                .is_none()
        );
        let two = hub
            .download_unqualified([6; 32], p2p::BodyMode::Pieces, None, &connected)
            .unwrap()
            .unwrap();
        assert_eq!(two.deadline.expires_at(), deadline);
        assert_eq!(two.ownership().unwrap().source_ordinal(), Some(2));
        two.ownership().unwrap().begin_query([6; 32]).unwrap();
        drop(two);
        let three = hub
            .download_unqualified([5; 32], p2p::BodyMode::Legacy, None, &connected)
            .unwrap()
            .unwrap();
        assert_eq!(three.ownership().unwrap().source_ordinal(), Some(3));
        three.ownership().unwrap().begin_query([5; 32]).unwrap();
        drop(three);
        // Evict only the cache, then reoffer the identical body as on reconnect.
        hub.inner.lock().unwrap().entries.front_mut().unwrap().first -=
            RETENTION + Duration::from_secs(1);
        hub.offer(h, [5; 32]).unwrap();
        let four = hub.advertised_download([5; 32]).unwrap().unwrap();
        assert_eq!(four.deadline.expires_at(), deadline);
        assert_eq!(four.ownership().unwrap().source_ordinal(), Some(4));
        four.ownership().unwrap().begin_query([5; 32]).unwrap();
        drop(four);
        assert!(hub.advertised_download([6; 32]).unwrap().is_none());
        assert_eq!(hub.budget.retained_body_accounting().0, 1);
    }
}

#[cfg(test)]
mod source_selection_regressions {
    use super::*;
    #[test]
    fn body_download_requires_an_authenticated_advertiser_for_the_exact_header() {
        let hub = super::tests::hub();
        let header = super::tests::header([2; 32], 1, 3);
        hub.offer(header, [5; 32]).unwrap();
        let connected = std::collections::BTreeSet::from([[5; 32], [6; 32]]);
        assert!(
            hub.download_unqualified([6; 32], p2p::BodyMode::Legacy, None, &connected)
                .unwrap()
                .is_none()
        );
        assert_eq!(hub.budget.retained_body_accounting().0, 0);
        assert!(
            hub.download_unqualified([5; 32], p2p::BodyMode::Legacy, None, &connected)
                .unwrap()
                .is_some()
        );
    }

    fn hub_fetch_after_unavailable_replies(unavailable_count: u64) -> bool {
        use crate::eng2::transport::{Peer, binding, tests as wire};
        let g = wire::genesis();
        let (mut body, mut header) = wire::body_header(&g);
        // Match this scheduler fixture's known height-zero parent. No state admission is requested.
        body.height = 1;
        header.height = 1;
        header.body_commitment = body.commitment(wire::policy()).unwrap();
        let bound = binding(&g);
        let mut owned = Arc::try_unwrap(super::tests::hub()).ok().unwrap();
        owned.binding = bound;
        owned.rules.network = bound.network;
        owned.rules.genesis = bound.genesis;
        {
            let inner = owned.inner.get_mut().unwrap();
            inner.canonical.id = bound.genesis;
            inner.anchors = BTreeMap::from([(bound.genesis, inner.canonical.clone())]);
        }
        let hub = Arc::new(owned);
        let peer_id = [9; 32];
        assert!(hub.offer(header.clone(), peer_id).unwrap());
        assert_eq!(hub.budget.retained_body_accounting().0, 0);
        let bytes = wire::wire_after_unavailable(&g, &body, &header, unavailable_count);
        let mut client = Peer::new(
            wire::session(bytes, bound, hub.budget.clone()),
            &g,
            wire::policy(),
        )
        .unwrap();
        let connected = std::collections::BTreeSet::from([peer_id]);
        let before = Instant::now();
        let mut deadline = None;
        for request in 1..=unavailable_count {
            let mut download = hub
                .download_unqualified(peer_id, p2p::BodyMode::Legacy, None, &connected)
                .unwrap()
                .unwrap();
            if let Some(first) = deadline {
                assert_eq!(download.deadline.expires_at(), first);
            } else {
                deadline = Some(download.deadline.expires_at());
            }
            let claim = download.take_ownership().unwrap();
            assert!(
                client
                    .fetch_body_owned(request, &header, claim, None)
                    .unwrap()
                    .is_none()
            );
            let (timing, _) = client.take_fetch_observation();
            assert_eq!(timing.unwrap().outcome, 2);
            drop(download);
            assert_eq!(hub.active_downloads(), 0);
        }
        assert!(before.elapsed() < Duration::from_secs(3));
        assert_eq!(hub.budget.retained_body_accounting().0, 1);
        // An existing header is retained, but its duplicate offer reports no insertion.
        assert!(!hub.offer(header.clone(), peer_id).unwrap());
        assert_eq!(
            hub.inner.lock().unwrap().entries[0].context.id,
            header.id().unwrap()
        );
        let Some(mut download) = hub
            .download_unqualified(peer_id, p2p::BodyMode::Legacy, None, &connected)
            .unwrap()
        else {
            let auth = hub.inner.lock().unwrap().entries[0]
                .authorization
                .as_ref()
                .unwrap()
                .clone();
            assert!(matches!(
                hub.budget
                    .claim_body_authorized(&auth, peer_id, p2p::BodyMode::Legacy),
                Err(p2p::BodyClaimError::QueryLimit)
            ));
            return false;
        };
        assert_eq!(Some(download.deadline.expires_at()), deadline);
        let body = client
            .fetch_body_owned(
                unavailable_count + 1,
                &header,
                download.take_ownership().unwrap(),
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            body.body.commitment(wire::policy()).unwrap(),
            header.body_commitment
        );
        assert!(before.elapsed() < Duration::from_secs(3));
        true
    }
    #[test]
    fn three_unavailable_replies_leave_one_query_for_the_body() {
        assert!(hub_fetch_after_unavailable_replies(3));
    }
    fn metadata_failure_then_legacy_fetch(legacy_unavailable: u64, reopen: bool) -> bool {
        use crate::eng2::transport::{Peer, binding, tests as wire};
        let g = wire::genesis();
        let (mut body, mut header) = wire::body_header(&g);
        // Match this scheduler fixture's known height-zero parent. No state admission is requested.
        body.height = 1;
        header.height = 1;
        header.body_commitment = body.commitment(wire::policy()).unwrap();
        let bound = binding(&g);
        let mut owned = Arc::try_unwrap(super::tests::hub()).ok().unwrap();
        owned.binding = bound;
        owned.rules.network = bound.network;
        owned.rules.genesis = bound.genesis;
        {
            let inner = owned.inner.get_mut().unwrap();
            inner.canonical.id = bound.genesis;
            inner.anchors = BTreeMap::from([(bound.genesis, inner.canonical.clone())]);
        }
        let hub = Arc::new(owned);
        use crate::eng2::propagation::pipeline::{DescriptorLedger, Limits};
        let peer_id = [9; 32];
        assert!(hub.offer(header.clone(), peer_id).unwrap());
        let connected = std::collections::BTreeSet::from([peer_id]);
        let started = Instant::now();
        let metadata_download = hub
            .download_unqualified(peer_id, p2p::BodyMode::Pieces, None, &connected)
            .unwrap()
            .unwrap();
        let original_deadline = metadata_download.deadline.expires_at();
        assert_eq!(
            metadata_download.ownership().unwrap().source_ordinal(),
            Some(1)
        );
        let mut ledger = DescriptorLedger::new(
            header.id().unwrap(),
            &[peer_id],
            Limits {
                requests: 4,
                wire_bytes: crate::eng2::transport::propagation::maximum_wire(
                    wire::policy().max_body_bytes,
                )
                .unwrap(),
                peer_requests: 1,
                peer_wire_bytes: crate::eng2::transport::propagation::maximum_wire(
                    wire::policy().max_body_bytes,
                )
                .unwrap(),
                parallel: 1,
                lifetime: original_deadline.duration_since(Instant::now()),
            },
            Instant::now(),
        )
        .unwrap();
        // The sender uses the real nine-byte UNAVAILABLE response. The trailing
        // body is never read on this failed metadata connection.
        let bytes = wire::wire_after_unavailable(&g, &body, &header, 1);
        let mut metadata_peer = Peer::new(
            wire::session(bytes, bound, hub.budget.clone()),
            &g,
            wire::policy(),
        )
        .unwrap();
        assert!(matches!(
            metadata_peer.fetch_propagation_metadata_at(
                1,
                &header,
                &mut ledger,
                metadata_download.ownership().unwrap()
            ),
            Err(p2p::Error::InvalidProtocol)
        ));
        let after_metadata = hub.budget.body_registry_diagnostic();
        assert_eq!(after_metadata["queries"], 1);
        assert_eq!(after_metadata["window_queries"], 1);
        let account = after_metadata["account"].as_u64().unwrap();
        drop(metadata_peer);
        drop(ledger);
        drop(metadata_download);
        assert_eq!(hub.active_downloads(), 0);
        // A new peer instance models the failed optional body lane reconnect;
        // it retains exactly the same node budget, binding and peer identity.
        let bytes = wire::wire_after_unavailable(&g, &body, &header, legacy_unavailable);
        let mut client = Peer::new(
            wire::session(bytes, bound, hub.budget.clone()),
            &g,
            wire::policy(),
        )
        .unwrap();
        for request in 1..=legacy_unavailable {
            let mut download = hub
                .download_unqualified(peer_id, p2p::BodyMode::Legacy, None, &connected)
                .unwrap()
                .unwrap();
            assert_eq!(download.deadline.expires_at(), original_deadline);
            assert_eq!(
                download.ownership().unwrap().source_ordinal(),
                Some((request + 1) as usize)
            );
            assert!(
                client
                    .fetch_body_owned(request, &header, download.take_ownership().unwrap(), None)
                    .unwrap()
                    .is_none()
            );
            let (timing, _) = client.take_fetch_observation();
            assert_eq!(timing.as_ref().unwrap().outcome, 2);
            assert_eq!(timing.as_ref().unwrap().received_bytes, 0);
            drop(download);
        }
        assert!(!hub.offer(header.clone(), peer_id).unwrap());
        let mut next = hub
            .download_unqualified(peer_id, p2p::BodyMode::Legacy, None, &connected)
            .unwrap();
        if next.is_none() {
            {
                let auth = hub.inner.lock().unwrap().entries[0]
                    .authorization
                    .as_ref()
                    .unwrap()
                    .clone();
                assert!(matches!(
                    hub.budget
                        .claim_body_authorized(&auth, peer_id, p2p::BodyMode::Legacy),
                    Err(p2p::BodyClaimError::QueryLimit)
                ));
            }
            let blocked = hub.budget.body_registry_diagnostic();
            assert_eq!(blocked["queries"], 4);
            assert_eq!(blocked["window_queries"], 4);
            assert_eq!(blocked["account"].as_u64(), Some(account));

            if !reopen {
                return false;
            }
            // Simulate elapsed account age through the existing test hook. No
            // wall-clock wait, quota refund, new scope or window rollover occurs.
            hub.budget.age_test_body_accounts(Duration::from_secs(181));
            assert!(
                hub.download_unqualified(peer_id, p2p::BodyMode::Legacy, None, &connected)
                    .unwrap()
                    .is_none()
            );
            assert!(hub.inner.lock().unwrap().entries[0].authorization.is_none());
            // Expiration alone must not skip the original first-reopen backoff.
            assert!(
                hub.download_unqualified(peer_id, p2p::BodyMode::Legacy, None, &connected)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(hub.budget.body_registry_diagnostic()["code"], "expired");
            let wire_before = hub.budget.body_wire_usage();
            hub.budget.age_test_body_accounts(Duration::from_secs(15));
            next = hub
                .download_unqualified(peer_id, p2p::BodyMode::Legacy, None, &connected)
                .unwrap();
            assert!(next.is_some());
            let reopened = hub.budget.body_registry_diagnostic();
            assert!(reopened["account"].as_u64().unwrap() > account);
            assert_eq!(reopened["queries"], 0);
            assert_eq!(reopened["window_queries"], 4);
            assert_eq!(hub.budget.body_wire_usage(), wire_before);
        }
        let mut next = next.unwrap();
        let received = client
            .fetch_body_owned(
                legacy_unavailable + 1,
                &header,
                next.take_ownership().unwrap(),
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            received.body.commitment(wire::policy()).unwrap(),
            header.body_commitment
        );
        let final_state = hub.budget.body_registry_diagnostic();
        assert_eq!(final_state["window_queries"], legacy_unavailable + 2);
        if reopen {
            assert_eq!(final_state["queries"], 1);
        } else {
            assert_eq!(next.deadline.expires_at(), original_deadline);
        }

        assert!(started.elapsed() < Duration::from_secs(3));
        true
    }
    #[test]
    fn metadata_and_two_unavailable_replies_preserve_the_last_body_query() {
        assert!(metadata_failure_then_legacy_fetch(2, false));
    }
    #[test]
    fn expired_metadata_account_reopens_after_backoff_without_refund() {
        assert!(metadata_failure_then_legacy_fetch(3, true));
    }
}

#[cfg(test)]
mod body_source_regressions {
    use super::*;
    #[test]
    fn forwarded_header_without_body_announcement_cannot_claim() {
        let hub = super::tests::hub();
        let header = super::tests::header([2; 32], 1, 3);
        assert!(hub.offer(header, [5; 32]).unwrap());
        let connected = std::collections::BTreeSet::from([[5; 32]]);
        assert!(
            hub.download_preferred([5; 32], p2p::BodyMode::Legacy, None, &connected)
                .unwrap()
                .is_none(),
            "a forwarded header is not a body availability announcement"
        );
        assert_eq!(hub.budget.retained_body_accounting().0, 0);
        assert_eq!(hub.active_downloads(), 0);
    }

    fn available(hub: &Arc<Hub>, peer: Hash, header: &Header) -> Option<Download> {
        let connected = std::collections::BTreeSet::from([peer]);
        hub.download_preferred(
            peer,
            p2p::BodyMode::Legacy,
            Some(header.id().unwrap()),
            &connected,
        )
        .unwrap()
    }
    #[test]
    fn exact_tip_and_known_ancestor_path_qualify_without_admitting_state() {
        let hub = super::tests::hub();
        let one = super::tests::header([2; 32], 1, 3);
        let two = super::tests::header(one.id().unwrap(), 2, 4);
        hub.offer(one.clone(), [5; 32]).unwrap();
        hub.offer(two.clone(), [5; 32]).unwrap();
        hub.observe_body_tip([6; 32], 61, 2, two.id().unwrap())
            .unwrap();
        let first = available(&hub, [6; 32], &one).unwrap();
        assert_eq!(first.header.id().unwrap(), one.id().unwrap());
        let deadline = first.deadline.expires_at();
        first.ownership().unwrap().begin_query([6; 32]).unwrap();
        drop(first);
        hub.observe_body_tip([6; 32], 61, 2, two.id().unwrap())
            .unwrap();
        let retry = available(&hub, [6; 32], &one).unwrap();
        assert_eq!(retry.deadline.expires_at(), deadline);
        assert_eq!(hub.tip().unwrap(), (0, [2; 32]));
        assert!(hub.waiting());
        assert!(!hub.inner.lock().unwrap().entries[0].complete);
    }
    #[test]
    fn height_alone_wrong_branch_and_unknown_tip_cannot_qualify() {
        let hub = super::tests::hub();
        let one = super::tests::header([2; 32], 1, 3);
        let other = super::tests::header([2; 32], 1, 4);
        hub.offer(one.clone(), [5; 32]).unwrap();
        hub.offer(other.clone(), [6; 32]).unwrap();
        for (height, id) in [
            (1, other.id().unwrap()),
            (2, [7; 32]),
            (2, one.id().unwrap()),
        ] {
            hub.observe_body_tip([5; 32], 51, height, id).unwrap();
            assert!(available(&hub, [5; 32], &one).is_none());
        }
        assert_eq!(hub.budget.retained_body_accounting().0, 0);
    }
    #[test]
    fn tip_withdrawal_disconnect_and_old_session_drop_do_not_renew_account() {
        let hub = super::tests::hub();
        let one = super::tests::header([2; 32], 1, 3);
        hub.offer(one.clone(), [5; 32]).unwrap();
        hub.observe_body_tip([5; 32], 51, 1, one.id().unwrap())
            .unwrap();
        let first = available(&hub, [5; 32], &one).unwrap();
        let expiry = first.deadline.expires_at();
        first.ownership().unwrap().begin_query([5; 32]).unwrap();
        drop(first);
        hub.observe_body_tip([5; 32], 51, 0, [2; 32]).unwrap();
        assert!(available(&hub, [5; 32], &one).is_none());
        hub.observe_body_tip([5; 32], 52, 1, one.id().unwrap())
            .unwrap();
        hub.forget_body_tip([5; 32], 51);
        let next = available(&hub, [5; 32], &one).unwrap();
        assert_eq!(next.deadline.expires_at(), expiry);
        next.ownership().unwrap().begin_query([5; 32]).unwrap();
        drop(next);
        hub.forget_body_tip([5; 32], 52);
        assert!(available(&hub, [5; 32], &one).is_none());
        assert_eq!(hub.budget.body_registry_diagnostic()["window_queries"], 2);
    }
    #[test]
    fn source_reorganization_changes_only_eligible_exact_branch() {
        let hub = super::tests::hub();
        let one = super::tests::header([2; 32], 1, 3);
        let other = super::tests::header([2; 32], 1, 4);
        hub.offer(one.clone(), [5; 32]).unwrap();
        hub.offer(other.clone(), [5; 32]).unwrap();
        hub.observe_body_tip([5; 32], 51, 1, one.id().unwrap())
            .unwrap();
        let download = available(&hub, [5; 32], &one).unwrap();
        download.ownership().unwrap().begin_query([5; 32]).unwrap();
        drop(download);
        assert!(available(&hub, [5; 32], &other).is_none());
        hub.observe_body_tip([5; 32], 51, 1, other.id().unwrap())
            .unwrap();
        assert!(available(&hub, [5; 32], &one).is_none());
        assert!(available(&hub, [5; 32], &other).is_some());
        assert_eq!(hub.tip().unwrap(), (0, [2; 32]));
    }
    #[test]
    fn full_forwarder_slots_cannot_exclude_actual_announced_holder() {
        let hub = super::tests::hub();
        let one = super::tests::header([2; 32], 1, 3);
        for value in 1..=8 {
            hub.offer(one.clone(), [value; 32]).unwrap();
            hub.observe_body_tip([value; 32], value as u64, 0, [2; 32])
                .unwrap();
        }
        assert_eq!(
            hub.inner.lock().unwrap().entries[0]
                .offered_sources
                .iter()
                .flatten()
                .count(),
            8
        );
        hub.observe_body_tip([9; 32], 91, 1, one.id().unwrap())
            .unwrap();
        assert!(available(&hub, [9; 32], &one).is_some());
        assert_eq!(hub.inner.lock().unwrap().body_tips.len(), 8);
    }
    fn wire_fixture() -> (crate::eng2::genesis::Genesis, Body, Header, Arc<Hub>) {
        use crate::eng2::transport::{binding, tests as wire};
        let g = wire::genesis();
        let (mut body, mut header) = wire::body_header(&g);
        body.height = 1;
        header.height = 1;
        header.body_commitment = body.commitment(wire::policy()).unwrap();
        let bound = binding(&g);
        let mut owned = Arc::try_unwrap(super::tests::hub()).ok().unwrap();
        owned.binding = bound;
        owned.rules.network = bound.network;
        owned.rules.genesis = bound.genesis;
        {
            let inner = owned.inner.get_mut().unwrap();
            inner.canonical.id = bound.genesis;
            inner.anchors = BTreeMap::from([(bound.genesis, inner.canonical.clone())]);
        }
        (g, body, header, Arc::new(owned))
    }
    #[test]
    fn actual_tip_frame_allows_immediate_real_body_fetch() {
        use crate::eng2::transport::{Peer, binding, tests as wire};
        let (g, body, header, hub) = wire_fixture();
        hub.offer(header.clone(), [5; 32]).unwrap();
        let bytes = wire::tip_wire(&g, header.height, header.id().unwrap());
        let mut peer = Peer::new(
            wire::session(bytes, binding(&g), hub.budget.clone()),
            &g,
            wire::policy(),
        )
        .unwrap();
        let (height, id) = peer.fetch_tip(77).unwrap();
        hub.observe_body_tip(peer.peer(), peer.propagation_session_id(), height, id)
            .unwrap();
        let bytes = wire::wire_after_unavailable(&g, &body, &header, 0);
        let mut body_peer = Peer::new(
            wire::session(bytes, binding(&g), hub.budget.clone()),
            &g,
            wire::policy(),
        )
        .unwrap();
        let mut download = available(&hub, body_peer.peer(), &header).unwrap();
        let received = body_peer
            .fetch_body_owned(1, &header, download.take_ownership().unwrap(), None)
            .unwrap()
            .unwrap();
        assert_eq!(
            received.body.commitment(wire::policy()).unwrap(),
            header.body_commitment
        );
        assert_eq!(hub.budget.body_registry_diagnostic()["window_queries"], 1);
        assert_eq!(hub.tip().unwrap(), (0, binding(&g).genesis));
    }
    #[test]
    fn repeated_lying_tip_does_not_refund_query_bytes_or_deadline() {
        use crate::eng2::transport::{Peer, binding, tests as wire};
        let (g, body, header, hub) = wire_fixture();
        hub.offer(header.clone(), [9; 32]).unwrap();
        let bytes = wire::wire_after_unavailable(&g, &body, &header, 4);
        let mut client = Peer::new(
            wire::session(bytes, binding(&g), hub.budget.clone()),
            &g,
            wire::policy(),
        )
        .unwrap();
        let mut expiry = None;
        let mut charged = 0;
        for request in 1..=4 {
            hub.observe_body_tip(
                client.peer(),
                client.propagation_session_id(),
                1,
                header.id().unwrap(),
            )
            .unwrap();
            let mut download = available(&hub, client.peer(), &header).unwrap();
            if let Some(first) = expiry {
                assert_eq!(download.deadline.expires_at(), first);
            } else {
                expiry = Some(download.deadline.expires_at());
            }
            assert!(
                client
                    .fetch_body_owned(request, &header, download.take_ownership().unwrap(), None)
                    .unwrap()
                    .is_none()
            );
            let used = hub.budget.body_wire_usage().0;
            assert!(used > charged);
            charged = used;
            drop(download);
            hub.forget_body_tip(client.peer(), client.propagation_session_id());
            assert!(available(&hub, client.peer(), &header).is_none());
        }
        hub.observe_body_tip(
            client.peer(),
            client.propagation_session_id(),
            1,
            header.id().unwrap(),
        )
        .unwrap();
        assert!(available(&hub, client.peer(), &header).is_none());
        let state = hub.budget.body_registry_diagnostic();
        assert_eq!(state["code"], "query_limit");
        assert_eq!(state["queries"], 4);
        assert_eq!(state["window_queries"], 4);
        assert_eq!(hub.budget.body_wire_usage().0, charged);
        assert_eq!(hub.tip().unwrap(), (0, binding(&g).genesis));
    }
    #[test]
    fn source_qualification_preserves_four_active_download_limit() {
        let hub = super::tests::hub();
        let mut held = Vec::new();
        for value in 1..=5 {
            let header = super::tests::header([2; 32], 1, value);
            hub.offer(header.clone(), [value; 32]).unwrap();
            hub.observe_body_tip([value; 32], value as u64, 1, header.id().unwrap())
                .unwrap();
            let download = available(&hub, [value; 32], &header);
            if value <= 4 {
                held.push(download.unwrap());
            } else {
                assert!(download.is_none());
            }
        }
        assert_eq!(hub.active_downloads(), 4);
        drop(held);
        assert_eq!(hub.active_downloads(), 0);
    }

    #[test]
    fn parsed_explicit_offer_qualifies_only_its_exact_known_header() {
        use crate::eng2::transport::tests as wire;
        let (g, body, header, hub) = wire_fixture();
        hub.offer(header.clone(), [5; 32]).unwrap();
        let offer = wire::authenticated_offer(&g, &header, &body);
        hub.offer(header.clone(), offer.peer()).unwrap();
        assert!(available(&hub, offer.peer(), &header).is_none());
        let connected = std::collections::BTreeSet::from([offer.peer()]);
        let download = hub.download_offered(&offer, &connected).unwrap().unwrap();
        assert_eq!(download.header.id().unwrap(), header.id().unwrap());
        assert_eq!(download.ownership().unwrap().source_ordinal(), Some(1));
        assert!(hub.inner.lock().unwrap().body_tips.is_empty());
        assert_eq!(hub.tip().unwrap(), (0, hub.binding.genesis));
        drop(download);
        let mut unknown = header.clone();
        unknown.parent = [71; 32];
        let offer = wire::authenticated_offer(&g, &unknown, &body);
        assert!(!hub.offer(unknown.clone(), offer.peer()).unwrap());
        assert!(hub.download_offered(&offer, &connected).unwrap().is_none());
        assert_eq!(hub.active_downloads(), 0);
        assert_eq!(hub.budget.retained_body_accounting().0, 1);
    }

    #[test]
    fn cache_expiry_requires_requalified_header_after_late_holder_tip() {
        let hub = super::tests::hub();
        let one = super::tests::header([2; 32], 1, 3);
        hub.offer(one.clone(), [5; 32]).unwrap();
        assert!(available(&hub, [5; 32], &one).is_none());
        assert_eq!(hub.active_downloads(), 0);
        assert_eq!(hub.budget.retained_body_accounting().0, 0);
        // Simulate a 100-second body wait, exceeding the unmodified 30-second
        // header cache retention. There is no live download to extend it.
        hub.inner.lock().unwrap().entries[0].first -= Duration::from_secs(100);
        hub.tick().unwrap();
        assert!(hub.inner.lock().unwrap().entries.is_empty());
        hub.observe_body_tip([6; 32], 61, 1, one.id().unwrap())
            .unwrap();
        assert!(
            available(&hub, [6; 32], &one).is_none(),
            "a hash-only tip cannot recreate a qualified header"
        );
        assert_eq!(hub.budget.retained_body_accounting().0, 0);
        // A fresh authenticated header with its known parent restores the
        // optional path. This does not prove discovery republishes it in time.
        assert!(hub.offer(one.clone(), [6; 32]).unwrap());
        assert!(available(&hub, [6; 32], &one).is_some());
    }

    #[test]
    fn late_canonical_body_republishes_after_receiver_cache_expiry() {
        let source = super::tests::hub();
        let receiver = super::tests::hub();
        let header = super::tests::header([2; 32], 1, 3);
        source.offer(header.clone(), [7; 32]).unwrap();
        let outgoing = source.outgoing([6; 32]).unwrap();
        assert_eq!(outgoing.len(), 1);
        receiver.offer(outgoing[0].clone(), [5; 32]).unwrap();
        receiver.inner.lock().unwrap().entries[0].first -= Duration::from_secs(100);
        receiver.tick().unwrap();
        assert!(receiver.inner.lock().unwrap().entries.is_empty());
        {
            let mut inner = source.inner.lock().unwrap();
            // This is the exact publication helper called only after Driver's
            // authenticated canonical Store head has changed. The fixture
            // models that event; no native proof admission is claimed here.
            inner.entries[0].first -= Duration::from_secs(100);
            inner.canonical = inner.entries[0].context.clone();
            Hub::canonical_body_available(
                &mut inner,
                header.id().unwrap(),
                source.local,
                true,
                Instant::now(),
            );
        }
        let announced = source.tip().unwrap();
        receiver
            .observe_body_tip([5; 32], 51, announced.0, announced.1)
            .unwrap();
        assert!(available(&receiver, [5; 32], &header).is_none());
        let fresh = source.outgoing([6; 32]).unwrap();
        assert_eq!(
            fresh.len(),
            1,
            "a newly canonical body must republish its exact header after an earlier speculative announcement"
        );
        assert!(receiver.offer(fresh[0].clone(), [5; 32]).unwrap());
        assert!(available(&receiver, [5; 32], &header).is_some());
        assert_eq!(RETENTION, Duration::from_secs(30));
        assert!(source.outgoing([6; 32]).unwrap().is_empty());
    }

    #[test]
    fn same_head_notifications_do_not_renew_cache_claim_or_progress() {
        let hub = super::tests::hub();
        let header = super::tests::header([2; 32], 1, 3);
        hub.offer(header.clone(), [5; 32]).unwrap();
        hub.observe_body_tip([5; 32], 51, 1, header.id().unwrap())
            .unwrap();
        let download = available(&hub, [5; 32], &header).unwrap();
        let deadline = download.deadline.expires_at();
        download.ownership().unwrap().begin_query([5; 32]).unwrap();
        {
            let mut inner = hub.inner.lock().unwrap();
            inner.canonical = inner.entries[0].context.clone();
            Hub::canonical_body_available(
                &mut inner,
                header.id().unwrap(),
                hub.local,
                true,
                Instant::now(),
            );
        }
        assert_eq!(hub.outgoing([6; 32]).unwrap().len(), 1);
        let first = hub.inner.lock().unwrap().entries[0].first;
        let state = hub.budget.body_registry_diagnostic();
        let progress = hub.sync_progress_runs();
        {
            let mut inner = hub.inner.lock().unwrap();
            Hub::canonical_body_available(
                &mut inner,
                header.id().unwrap(),
                hub.local,
                false,
                Instant::now() + Duration::from_secs(100),
            );
        }
        assert_eq!(hub.inner.lock().unwrap().entries[0].first, first);
        assert!(hub.outgoing([6; 32]).unwrap().is_empty());
        assert_eq!(download.deadline.expires_at(), deadline);
        let after = hub.budget.body_registry_diagnostic();
        for field in [
            "scope",
            "sequence",
            "phase",
            "code",
            "height",
            "account",
            "generation",
            "queries",
            "window_queries",
            "terminal",
            "wire_charged_bytes",
            "wire_reserved_bytes",
            "wire_maximum_bytes",
        ] {
            assert_eq!(after[field], state[field], "changed invariant: {field}");
        }
        assert_eq!(hub.sync_progress_runs(), progress);
        assert_eq!(RETENTION, Duration::from_secs(30));
    }
}
