//! Exact-body accounting shared by owner-authorized transport acquisitions.
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
pub(super) const CAPACITY: usize = 32;
const BOOK_CAPACITY: usize = 2048;
const WINDOW_QUERIES: u64 = 1024;
pub(super) const HANDOFF_DELAY: Duration = Duration::from_secs(30);
pub(super) fn record_charge() -> usize {
    16 * std::mem::size_of::<(Key, Entry)>() + 512
}
pub(super) fn pin_charge() -> usize {
    std::mem::size_of::<Pin>() + 64
}
pub(super) fn scope_charge() -> usize {
    std::mem::size_of::<ScopeState>() + 64
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Legacy,
    Pieces,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Key {
    pub context: [[u8; 32]; 3],
    pub height: u64,
    pub id: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimError {
    Busy,
    Expired,
    Capacity,
    SourceUsed,
    QueryLimit,
    Unavailable,
}
#[derive(Debug)]
struct Owner {
    scope: u64,
    generation: u64,
    source: [u8; 32],
    mode: Mode,
    started: Instant,
    decoded: bool,
    bytes: u64,
    total: u64,
    last_progress: Option<Instant>,
    cancel: Arc<AtomicBool>,
}
#[derive(Debug)]
struct Source {
    peer: [u8; 32],
    generation: u64,
}
#[derive(Debug)]
struct Entry {
    account: u64,
    epoch: u64,
    origin: Weak<ScopeState>,
    origin_bootstrap: bool,
    origin_scope: u64,
    pins: usize,
    first: Instant,
    expires: Instant,
    owner: Option<Owner>,
    terminal: bool,
    ever_issued: bool,
    sources: [Option<Source>; 4],
    queries: u8,
    _charge: Option<super::BodyBookCharge>,
}
#[derive(Debug)]
struct Window {
    identity: u64,
    expires: Instant,
    queries: u64,
    maximum_queries: u64,
}
#[derive(Debug)]
struct Inner {
    entries: BTreeMap<Key, Entry>,
    generation: u64,
    account: u64,
    scope: u64,
    active: usize,
    unwindowed_queries: u64,
    maximum_entries: usize,
    resident: Option<Window>,
}
#[derive(Debug)]
pub(super) struct Registry(Mutex<Inner>);
impl Default for Registry {
    fn default() -> Self {
        Self(Mutex::new(Inner {
            entries: BTreeMap::new(),
            generation: 0,
            account: 0,
            scope: 0,
            active: 0,
            unwindowed_queries: 0,
            maximum_entries: BOOK_CAPACITY,
            resident: None,
        }))
    }
}
#[derive(Debug)]
struct ScopeState {
    registry: Arc<Registry>,
    id: u64,
    bootstrap: bool,
    deadline: Instant,
    closed: AtomicBool,
    _charge: Option<super::BodyBookCharge>,
}
/// Minted only by the original resident window owner or selected bootstrap operation.
#[derive(Clone, Debug)]
pub(crate) struct Scope(Arc<ScopeState>);
impl Scope {
    pub(crate) fn close(&self) {
        self.0.closed.store(true, Ordering::Release);
        let inner = self
            .0
            .registry
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for entry in inner.entries.values() {
            if let Some(owner) = entry
                .owner
                .as_ref()
                .filter(|owner| owner.scope == self.0.id)
            {
                owner.cancel.store(true, Ordering::Release);
            }
        }
    }
    pub(super) fn matches(&self, registry: &Arc<Registry>) -> bool {
        Arc::ptr_eq(&self.0.registry, registry)
    }
}
#[derive(Debug)]
struct Pin {
    registry: Arc<Registry>,
    key: Key,
    account: u64,
    scope: Scope,
    _charge: Option<super::BodyBookCharge>,
}
impl Drop for Pin {
    fn drop(&mut self) {
        let mut inner = self.registry.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = inner
            .entries
            .get_mut(&self.key)
            .filter(|e| e.account == self.account)
        {
            entry.pins = entry.pins.saturating_sub(1);
        }
        if inner.entries.get(&self.key).is_some_and(|entry| {
            entry.account == self.account
                && entry.pins == 0
                && entry.owner.is_none()
                && entry.queries == 0
                && !entry.ever_issued
                && !entry.terminal
        }) {
            inner.entries.remove(&self.key);
        }
    }
}
/// A pin joins the existing exact account; it never creates a new query budget.
#[derive(Clone, Debug)]
pub struct Authorization {
    pin: Arc<Pin>,
}
impl Authorization {
    pub(super) fn matches(&self, key: Key, registry: &Arc<Registry>) -> bool {
        self.pin.key == key && Arc::ptr_eq(&self.pin.registry, registry)
    }
}
impl Registry {
    #[cfg(test)]
    pub(super) fn retained_accounting(&self) -> (usize, usize) {
        let inner = self.0.lock().unwrap();
        let bytes = inner
            .entries
            .values()
            .map(|entry| {
                entry
                    ._charge
                    .as_ref()
                    .map_or(0, |charge| charge.bytes + entry.pins * pin_charge())
            })
            .sum();
        (inner.entries.len(), bytes)
    }
    #[cfg(test)]
    pub(super) fn resident_scope(
        self: &Arc<Self>,
        identity: u64,
        now: Instant,
        expires: Instant,
    ) -> Result<Scope, ClaimError> {
        self.resident_scope_charged(identity, now, expires, None)
    }
    pub(super) fn resident_scope_charged(
        self: &Arc<Self>,
        identity: u64,
        now: Instant,
        expires: Instant,
        charge: Option<super::BodyBookCharge>,
    ) -> Result<Scope, ClaimError> {
        let mut inner = self.0.lock().map_err(|_| ClaimError::Unavailable)?;
        if now >= expires || identity == 0 {
            return Err(ClaimError::Expired);
        }
        match &inner.resident {
            Some(window) if window.identity != identity => return Err(ClaimError::Unavailable),
            Some(_) => (),
            None => {
                inner.resident = Some(Window {
                    identity,
                    expires,
                    queries: inner.unwindowed_queries,
                    maximum_queries: WINDOW_QUERIES,
                })
            }
        }
        inner.scope = inner.scope.checked_add(1).ok_or(ClaimError::Unavailable)?;
        Ok(Scope(Arc::new(ScopeState {
            registry: self.clone(),
            id: inner.scope,
            bootstrap: false,
            deadline: expires,
            closed: AtomicBool::new(false),
            _charge: charge,
        })))
    }
    #[cfg(test)]
    pub(super) fn bootstrap_scope(
        self: &Arc<Self>,
        now: Instant,
        expires: Instant,
    ) -> Result<Scope, ClaimError> {
        self.bootstrap_scope_charged(now, expires, None)
    }
    pub(super) fn bootstrap_scope_charged(
        self: &Arc<Self>,
        now: Instant,
        expires: Instant,
        charge: Option<super::BodyBookCharge>,
    ) -> Result<Scope, ClaimError> {
        if now >= expires {
            return Err(ClaimError::Expired);
        }
        let mut inner = self.0.lock().map_err(|_| ClaimError::Unavailable)?;
        inner.scope = inner.scope.checked_add(1).ok_or(ClaimError::Unavailable)?;
        Ok(Scope(Arc::new(ScopeState {
            registry: self.clone(),
            id: inner.scope,
            bootstrap: true,
            deadline: expires,
            closed: AtomicBool::new(false),
            _charge: charge,
        })))
    }
    pub(super) fn restrict_limits(
        self: &Arc<Self>,
        scope: &Scope,
        maximum_entries: usize,
        maximum_queries: u64,
    ) -> Result<(), ClaimError> {
        if !scope.matches(self) || scope.0.bootstrap || maximum_entries == 0 || maximum_queries == 0
        {
            return Err(ClaimError::Unavailable);
        }
        let mut inner = self.0.lock().map_err(|_| ClaimError::Unavailable)?;
        inner.maximum_entries = inner.maximum_entries.min(maximum_entries);
        let window = inner.resident.as_mut().ok_or(ClaimError::Unavailable)?;
        window.maximum_queries = window.maximum_queries.min(maximum_queries);
        Ok(())
    }
    /// Only a successful original Ledger renewal supplies these identities.
    pub(super) fn advance_window(
        &self,
        old: u64,
        new: u64,
        now: Instant,
        expires: Instant,
    ) -> Result<(), ClaimError> {
        let mut inner = self.0.lock().map_err(|_| ClaimError::Unavailable)?;
        let window = inner.resident.as_mut().ok_or(ClaimError::Unavailable)?;
        if window.identity != old || new == old || new == 0 || expires <= now {
            return Err(ClaimError::Unavailable);
        }
        let maximum_queries = window.maximum_queries;
        *window = Window {
            identity: new,
            expires,
            queries: 0,
            maximum_queries,
        };
        inner.unwindowed_queries = 0;
        inner
            .entries
            .retain(|_, entry| entry.owner.is_some() || entry.pins != 0 || now < entry.expires);
        Ok(())
    }
    pub(super) fn authorize(
        self: &Arc<Self>,
        scope: &Scope,
        key: Key,
        now: Instant,
        expires: Instant,
        charges: Option<(super::BodyBookCharge, super::BodyBookCharge)>,
    ) -> Result<Authorization, ClaimError> {
        let (record_charge, pin_charge) = match charges {
            Some((record, pin)) => (Some(record), Some(pin)),
            None => (None, None),
        };
        if !scope.matches(self) || scope.0.closed.load(Ordering::Acquire) {
            return Err(ClaimError::Unavailable);
        }
        let mut inner = self.0.lock().map_err(|_| ClaimError::Unavailable)?;
        if scope.0.closed.load(Ordering::Acquire) {
            return Err(ClaimError::Unavailable);
        }
        let (epoch, scope_end) = if scope.0.bootstrap {
            (
                inner.resident.as_ref().map_or(0, |w| w.identity),
                scope.0.deadline,
            )
        } else {
            let w = inner.resident.as_ref().ok_or(ClaimError::Unavailable)?;
            if now >= w.expires {
                return Err(ClaimError::Expired);
            }
            (w.identity, expires)
        };
        let end = expires.min(scope_end);
        if now >= end {
            return Err(ClaimError::Expired);
        }
        let replace = inner.entries.get(&key).is_some_and(|e| {
            e.owner.is_none()
                && e.pins == 0
                && now >= e.expires
                && (e.epoch != epoch
                    || (scope.0.bootstrap
                        && e.origin_bootstrap
                        && e.origin_scope != scope.0.id
                        && e.origin
                            .upgrade()
                            .is_none_or(|s| s.closed.load(Ordering::Acquire))))
        });
        if replace {
            inner.entries.remove(&key);
        }
        if !inner.entries.contains_key(&key) {
            if !scope.0.bootstrap
                && expires.saturating_duration_since(now)
                    > crate::eng2::transport::BODY_FETCH_TIMEOUT
            {
                return Err(ClaimError::Expired);
            }
            if inner.entries.len() >= inner.maximum_entries {
                return Err(ClaimError::Capacity);
            }
            inner.account = inner
                .account
                .checked_add(1)
                .ok_or(ClaimError::Unavailable)?;
            let account = inner.account;
            inner.entries.insert(
                key,
                Entry {
                    account,
                    epoch,
                    origin: Arc::downgrade(&scope.0),
                    origin_bootstrap: scope.0.bootstrap,
                    origin_scope: scope.0.id,
                    pins: 0,
                    first: now,
                    expires: end,
                    owner: None,
                    terminal: false,
                    ever_issued: false,
                    sources: std::array::from_fn(|_| None),
                    queries: 0,
                    _charge: record_charge,
                },
            );
        }
        let entry = inner.entries.get_mut(&key).ok_or(ClaimError::Unavailable)?;
        entry.expires = entry.expires.min(end);
        if entry.terminal || now >= entry.expires {
            return Err(ClaimError::Expired);
        }
        entry.pins = entry.pins.checked_add(1).ok_or(ClaimError::Capacity)?;
        Ok(Authorization {
            pin: Arc::new(Pin {
                registry: self.clone(),
                key,
                account: entry.account,
                scope: scope.clone(),
                _charge: pin_charge,
            }),
        })
    }
    pub(super) fn claim_authorized(
        self: &Arc<Self>,
        authorization: &Authorization,
        source: [u8; 32],
        mode: Mode,
        now: Instant,
    ) -> Result<Lease, ClaimError> {
        let pin = &authorization.pin;
        if !Arc::ptr_eq(self, &pin.registry) || pin.scope.0.closed.load(Ordering::Acquire) {
            return Err(ClaimError::Unavailable);
        }
        let mut inner = self.0.lock().map_err(|_| ClaimError::Unavailable)?;
        if pin.scope.0.closed.load(Ordering::Acquire) {
            return Err(ClaimError::Unavailable);
        }
        let entry = inner
            .entries
            .get_mut(&pin.key)
            .filter(|e| e.account == pin.account)
            .ok_or(ClaimError::Unavailable)?;
        if entry.terminal || now >= entry.expires {
            if let Some(owner) = &entry.owner {
                owner.cancel.store(true, Ordering::Release);
            }
            return Err(ClaimError::Expired);
        }
        if entry.owner.is_none() && entry.sources.iter().flatten().any(|s| s.peer == source) {
            return Err(ClaimError::SourceUsed);
        }
        if entry.queries >= 4 {
            return Err(ClaimError::QueryLimit);
        }
        if let Some(owner) = &entry.owner {
            let elapsed = now.saturating_duration_since(owner.started);
            let stalled = now
                .saturating_duration_since(owner.last_progress.unwrap_or(owner.started))
                >= HANDOFF_DELAY;
            let remaining = entry.expires.saturating_duration_since(now);
            let infeasible = owner.total > owner.bytes
                && owner.bytes > 0
                && u128::from(owner.total - owner.bytes).saturating_mul(elapsed.as_nanos())
                    > u128::from(owner.bytes).saturating_mul(remaining.as_nanos());
            if !owner.decoded
                && (owner.source != source || owner.mode != mode)
                && elapsed >= HANDOFF_DELAY
                && (stalled || infeasible)
            {
                owner.cancel.store(true, Ordering::Release);
            }
            return Err(ClaimError::Busy);
        }
        if inner.active >= CAPACITY {
            return Err(ClaimError::Capacity);
        }
        inner.generation = inner
            .generation
            .checked_add(1)
            .ok_or(ClaimError::Unavailable)?;
        let generation = inner.generation;
        inner.active += 1;
        let cancel = Arc::new(AtomicBool::new(false));
        let entry = inner
            .entries
            .get_mut(&pin.key)
            .ok_or(ClaimError::Unavailable)?;
        entry.ever_issued = true;
        entry.owner = Some(Owner {
            scope: pin.scope.0.id,
            generation,
            source,
            mode,
            started: now,
            decoded: false,
            bytes: 0,
            total: 0,
            last_progress: None,
            cancel: cancel.clone(),
        });
        Ok(Lease {
            registry: self.clone(),
            key: pin.key,
            account: pin.account,
            generation,
            first: entry.first,
            expires: entry.expires,
            cancel,
            complete: AtomicBool::new(false),
            _authorization: authorization.clone(),
        })
    }
    #[cfg(any(feature = "eng2-runtime", test))]
    pub(super) fn accepted(&self, key: Key) -> Result<bool, ClaimError> {
        let mut inner = self.0.lock().map_err(|_| ClaimError::Unavailable)?;
        let Some(entry) = inner.entries.get_mut(&key) else {
            return Ok(false);
        };
        entry.terminal = true;
        if let Some(owner) = &entry.owner {
            owner.cancel.store(true, Ordering::Release);
        }
        Ok(true)
    }
    #[cfg(test)]
    pub(super) fn claim(
        self: &Arc<Self>,
        key: Key,
        source: [u8; 32],
        mode: Mode,
        now: Instant,
        expires: Instant,
    ) -> Result<Lease, ClaimError> {
        let scope = self.resident_scope(1, now, now + Duration::from_secs(3600))?;
        let auth = self.authorize(&scope, key, now, expires, None)?;
        self.claim_authorized(&auth, source, mode, now)
    }
}
#[derive(Debug)]
pub(super) struct Lease {
    registry: Arc<Registry>,
    key: Key,
    account: u64,
    generation: u64,
    pub first: Instant,
    pub expires: Instant,
    pub cancel: Arc<AtomicBool>,
    complete: AtomicBool,
    _authorization: Authorization,
}
impl Lease {
    #[cfg(any(feature = "eng2-runtime", test))]
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
    #[cfg(any(test, feature = "eng2-runtime"))]
    pub(super) fn source_ordinal(&self) -> Option<usize> {
        let inner = self.registry.0.lock().ok()?;
        let entry = inner
            .entries
            .get(&self.key)
            .filter(|e| e.account == self.account)?;
        let owner = entry.owner.as_ref()?;
        if entry.terminal
            || owner.generation != self.generation
            || owner.decoded
            || self.cancel.load(Ordering::Acquire)
            || self
                ._authorization
                .pin
                .scope
                .0
                .closed
                .load(Ordering::Acquire)
        {
            return None;
        }
        if let Some(index) = entry.sources.iter().position(|s| {
            s.as_ref()
                .is_some_and(|s| s.peer == owner.source && s.generation == self.generation)
        }) {
            return Some(index + 1);
        }
        entry
            .sources
            .iter()
            .position(Option::is_none)
            .map(|i| i + 1)
    }
    /// Scheduling information only; begin_query remains the query authority.
    pub(super) fn can_query(&self, peer: [u8; 32], reserve: u8, now: Instant) -> bool {
        if reserve == 0 || self.check_active(now).is_err() {
            return false;
        }
        let Ok(inner) = self.registry.0.lock() else {
            return false;
        };
        let Some(entry) = inner
            .entries
            .get(&self.key)
            .filter(|e| e.account == self.account)
        else {
            return false;
        };
        let (used, maximum) = inner
            .resident
            .as_ref()
            .map_or((inner.unwindowed_queries, WINDOW_QUERIES), |window| {
                (window.queries, window.maximum_queries)
            });
        entry.queries.checked_add(reserve).is_some_and(|n| n <= 4)
            && used
                .checked_add(u64::from(reserve))
                .is_some_and(|n| n <= maximum)
            && !entry
                .sources
                .iter()
                .flatten()
                .any(|s| s.peer == peer && s.generation != self.generation)
    }

    pub(super) fn begin_query(&self, peer: [u8; 32], now: Instant) -> Result<(), ClaimError> {
        let mut inner = self
            .registry
            .0
            .lock()
            .map_err(|_| ClaimError::Unavailable)?;
        let (queries, maximum_queries) = inner
            .resident
            .as_ref()
            .map_or((inner.unwindowed_queries, WINDOW_QUERIES), |window| {
                (window.queries, window.maximum_queries)
            });
        if queries >= maximum_queries {
            return Err(ClaimError::QueryLimit);
        }
        let entry = inner
            .entries
            .get_mut(&self.key)
            .filter(|e| e.account == self.account)
            .ok_or(ClaimError::Unavailable)?;
        let owner = entry.owner.as_ref().ok_or(ClaimError::Unavailable)?;
        if owner.generation != self.generation || owner.decoded {
            return Err(ClaimError::Unavailable);
        }
        if entry.terminal
            || now >= entry.expires
            || self.cancel.load(Ordering::Acquire)
            || self
                ._authorization
                .pin
                .scope
                .0
                .closed
                .load(Ordering::Acquire)
        {
            return Err(ClaimError::Expired);
        }
        if entry.queries >= 4 {
            return Err(ClaimError::QueryLimit);
        }
        if let Some(source) = entry.sources.iter().flatten().find(|s| s.peer == peer) {
            if source.generation != self.generation {
                return Err(ClaimError::SourceUsed);
            }
        } else {
            *entry
                .sources
                .iter_mut()
                .find(|s| s.is_none())
                .ok_or(ClaimError::Capacity)? = Some(Source {
                peer,
                generation: self.generation,
            });
        }
        entry.queries += 1;
        if let Some(window) = &mut inner.resident {
            window.queries += 1;
        } else {
            inner.unwindowed_queries += 1;
        }
        Ok(())
    }
    pub(super) fn matches(&self, key: Key, registry: &Arc<Registry>) -> bool {
        self.key == key && Arc::ptr_eq(&self.registry, registry)
    }
    pub(super) fn check_active(&self, now: Instant) -> Result<(), ClaimError> {
        if now >= self.expires
            || self.cancel.load(Ordering::Acquire)
            || self
                ._authorization
                .pin
                .scope
                .0
                .closed
                .load(Ordering::Acquire)
        {
            return Err(ClaimError::Expired);
        }
        let inner = self
            .registry
            .0
            .lock()
            .map_err(|_| ClaimError::Unavailable)?;
        let entry = inner
            .entries
            .get(&self.key)
            .filter(|entry| entry.account == self.account)
            .ok_or(ClaimError::Unavailable)?;
        if entry.terminal
            || now >= entry.expires
            || entry
                .owner
                .as_ref()
                .is_none_or(|owner| owner.generation != self.generation)
        {
            return Err(ClaimError::Unavailable);
        }
        Ok(())
    }
    pub(super) fn received(&self, bytes: u64, total: u64, now: Instant) -> Result<(), ClaimError> {
        if now >= self.expires
            || self.cancel.load(Ordering::Acquire)
            || self
                ._authorization
                .pin
                .scope
                .0
                .closed
                .load(Ordering::Acquire)
        {
            return Err(ClaimError::Expired);
        }
        let mut inner = self
            .registry
            .0
            .lock()
            .map_err(|_| ClaimError::Unavailable)?;
        let entry = inner
            .entries
            .get_mut(&self.key)
            .filter(|entry| entry.account == self.account)
            .ok_or(ClaimError::Unavailable)?;
        if entry.terminal || now >= entry.expires {
            return Err(ClaimError::Expired);
        }
        let owner = entry.owner.as_mut().ok_or(ClaimError::Unavailable)?;
        if owner.generation != self.generation
            || owner.decoded
            || bytes > total
            || total == 0
            || (owner.total != 0 && owner.total != total)
            || now < owner.started
            || owner.last_progress.is_some_and(|last| now < last)
        {
            return Err(ClaimError::Unavailable);
        }
        if bytes > owner.bytes {
            owner.bytes = bytes;
            owner.total = total;
            owner.last_progress = Some(now);
        }
        Ok(())
    }
    pub(super) fn decoded(&self, now: Instant) -> Result<(), ClaimError> {
        let mut inner = self
            .registry
            .0
            .lock()
            .map_err(|_| ClaimError::Unavailable)?;
        let entry = inner
            .entries
            .get_mut(&self.key)
            .filter(|e| e.account == self.account)
            .ok_or(ClaimError::Unavailable)?;
        let owner = entry.owner.as_mut().ok_or(ClaimError::Unavailable)?;
        if owner.generation != self.generation
            || entry.terminal
            || self.cancel.load(Ordering::Acquire)
            || now >= entry.expires
            || self
                ._authorization
                .pin
                .scope
                .0
                .closed
                .load(Ordering::Acquire)
        {
            return Err(ClaimError::Expired);
        }
        owner.decoded = true;
        Ok(())
    }
    pub(super) fn complete(&self) {
        self.complete.store(true, Ordering::Release);
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut inner = self.registry.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = inner.entries.get_mut(&self.key).filter(|e| {
            e.account == self.account
                && e.owner
                    .as_ref()
                    .is_some_and(|o| o.generation == self.generation)
        }) {
            entry.terminal |= self.complete.load(Ordering::Acquire);
            entry.owner = None;
            inner.active = inner.active.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(n: u8) -> Key {
        Key {
            context: [[1; 32], [2; 32], [3; 32]],
            height: 10,
            id: [n; 32],
        }
    }
    fn claim(
        r: &Arc<Registry>,
        k: Key,
        source: u8,
        now: Instant,
        end: Instant,
    ) -> Result<Lease, ClaimError> {
        r.claim(k, [source; 32], Mode::Legacy, now, end)
    }
    #[test]
    fn failed_sources_and_fallback_share_four_actual_queries_without_refund() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + Duration::from_secs(180);
        let first = claim(&r, key(1), 1, n, end).unwrap();
        first.begin_query([1; 32], n).unwrap();
        drop(first);
        assert_eq!(
            r.claim(key(1), [1; 32], Mode::Pieces, n, end).unwrap_err(),
            ClaimError::SourceUsed
        );
        let pieces = r.claim(key(1), [2; 32], Mode::Pieces, n, end).unwrap();
        pieces.begin_query([2; 32], n).unwrap();
        pieces.begin_query([2; 32], n).unwrap();
        pieces.begin_query([3; 32], n).unwrap();
        assert_eq!(pieces.begin_query([4; 32], n), Err(ClaimError::QueryLimit));
        drop(pieces);
        assert_eq!(
            claim(&r, key(1), 4, n, end).unwrap_err(),
            ClaimError::QueryLimit
        );
    }
    #[test]
    fn unissued_claims_and_busy_contenders_do_not_consume_source_or_query_allowance() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + Duration::from_secs(180);
        let first = claim(&r, key(1), 1, n, end).unwrap();
        drop(first);
        let second = claim(&r, key(1), 1, n, end).unwrap();
        assert_eq!(claim(&r, key(1), 2, n, end).unwrap_err(), ClaimError::Busy);
        for _ in 0..4 {
            second.begin_query([1; 32], n).unwrap();
        }
        assert_eq!(second.begin_query([1; 32], n), Err(ClaimError::QueryLimit));
    }
    #[test]
    fn source_ordinals_are_candidate_local_and_reads_never_spend_query_tickets() {
        let r = Arc::new(Registry::default());
        let now = Instant::now();
        let end = now + Duration::from_secs(180);
        for candidate in 0..8 {
            let lease = r
                .claim(key(candidate), [1; 32], Mode::Legacy, now, end)
                .unwrap();
            assert_eq!(lease.generation(), u64::from(candidate) + 1);
            for _ in 0..8 {
                assert_eq!(lease.source_ordinal(), Some(1));
            }
            {
                let inner = r.0.lock().unwrap();
                let entry = inner.entries.get(&lease.key).unwrap();
                assert_eq!(entry.queries, 0);
                assert_eq!(entry.sources.iter().flatten().count(), 0);
            }
            lease.begin_query([1; 32], now).unwrap();
            assert_eq!(lease.source_ordinal(), Some(1));
            drop(lease);
            r.accepted(key(candidate)).unwrap();
        }
        let candidate = key(10);
        for ordinal in 1..=4 {
            let source = [ordinal as u8; 32];
            let lease = r.claim(candidate, source, Mode::Legacy, now, end).unwrap();
            assert!(lease.generation() > 4);
            assert_eq!(lease.source_ordinal(), Some(ordinal));
            lease.begin_query(source, now).unwrap();
            assert_eq!(lease.source_ordinal(), Some(ordinal));
            drop(lease);
        }
        assert_eq!(
            r.claim(candidate, [5; 32], Mode::Legacy, now, end)
                .unwrap_err(),
            ClaimError::QueryLimit
        );
    }

    #[test]
    fn owner_acceptance_retires_only_the_exact_terminal_after_actual_io_release() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + Duration::from_secs(180);
        let old = claim(&r, key(1), 1, n, end).unwrap();
        old.begin_query([1; 32], n).unwrap();
        assert!(r.accepted(key(1)).unwrap());
        assert_eq!(
            claim(&r, key(1), 2, n, end).unwrap_err(),
            ClaimError::Expired
        );
        assert!(old.cancel.load(Ordering::Acquire));
        let other = claim(&r, key(2), 1, n, end).unwrap();
        drop(other);
        assert!(!r.accepted(key(3)).unwrap());
        drop(old);
        assert_eq!(
            claim(&r, key(1), 2, n, end).unwrap_err(),
            ClaimError::Expired
        );
    }
    #[test]
    fn failed_expired_accounts_do_not_retain_io_capacity() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + Duration::from_secs(1);
        for id in 0..CAPACITY {
            let lease = claim(&r, key(id as u8), 1, n, end).unwrap();
            lease.begin_query([1; 32], n).unwrap();
            drop(lease);
        }
        assert!(claim(&r, key(100), 1, end, end + HANDOFF_DELAY).is_ok());
        assert!(r.accepted(key(0)).unwrap());
        assert_eq!(
            claim(&r, key(1), 1, end, end + HANDOFF_DELAY).unwrap_err(),
            ClaimError::Expired
        );
    }
    #[test]
    fn simultaneous_sources_have_one_owner() {
        use std::sync::{Barrier, atomic::AtomicUsize};
        let r = Arc::new(Registry::default());
        let now = Instant::now();
        let start = Arc::new(Barrier::new(16));
        let held = Arc::new(Barrier::new(16));
        let winners = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for source in 0..16 {
                let (r, start, held, winners) =
                    (r.clone(), start.clone(), held.clone(), winners.clone());
                scope.spawn(move || {
                    start.wait();
                    let lease = claim(&r, key(1), source, now, now + Duration::from_secs(180));
                    if lease.is_ok() {
                        winners.fetch_add(1, Ordering::SeqCst);
                    }
                    held.wait();
                    drop(lease);
                });
            }
        });
        assert_eq!(winners.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn healthy_five_megabit_body_finishes_despite_contenders_every_second() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + Duration::from_secs(180);
        let owner = claim(&r, key(1), 1, n, end).unwrap();
        for second in 1..=64 {
            let now = n + Duration::from_secs(second);
            owner.received(second * 625_000, 40_000_000, now).unwrap();
            assert_eq!(
                claim(&r, key(1), 2, now, end).unwrap_err(),
                ClaimError::Busy
            );
            assert!(
                !owner.cancel.load(Ordering::Acquire),
                "healthy transfer cancelled at {second}"
            );
        }
        owner.decoded(n + Duration::from_secs(64)).unwrap();
        owner.complete();
        drop(owner);
    }
    #[test]
    fn progressing_but_infeasible_source_can_yield_within_original_budget() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + Duration::from_secs(180);
        let owner = claim(&r, key(1), 1, n, end).unwrap();
        for second in 1..=30 {
            owner
                .received(
                    second * 100_000,
                    40_000_000,
                    n + Duration::from_secs(second),
                )
                .unwrap();
        }
        assert_eq!(
            claim(&r, key(1), 2, n + HANDOFF_DELAY, end).unwrap_err(),
            ClaimError::Busy
        );
        assert!(owner.cancel.load(Ordering::Acquire));
        drop(owner);
        let next = claim(&r, key(1), 2, n + HANDOFF_DELAY, end + HANDOFF_DELAY).unwrap();
        assert_eq!(next.expires, end);
    }
    #[test]
    fn stalled_source_handoff_requires_actual_release_and_keeps_original_deadline() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + Duration::from_secs(180);
        let first = claim(&r, key(1), 1, n, end).unwrap();
        assert_eq!(
            claim(&r, key(1), 2, n + Duration::from_secs(29), end).unwrap_err(),
            ClaimError::Busy
        );
        assert!(!first.cancel.load(Ordering::Acquire));
        assert_eq!(
            claim(
                &r,
                key(1),
                2,
                n + HANDOFF_DELAY,
                end + Duration::from_secs(100)
            )
            .unwrap_err(),
            ClaimError::Busy
        );
        assert!(first.cancel.load(Ordering::Acquire));
        assert_eq!(
            claim(&r, key(1), 2, n + Duration::from_secs(31), end).unwrap_err(),
            ClaimError::Busy
        );
        drop(first);
        let replacement = claim(
            &r,
            key(1),
            2,
            n + Duration::from_secs(31),
            end + Duration::from_secs(100),
        )
        .unwrap();
        assert_eq!(replacement.expires, end);
        assert_eq!(replacement.first, n);
        drop(replacement);
        assert_eq!(
            claim(&r, key(1), 3, end, end + Duration::from_secs(180)).unwrap_err(),
            ClaimError::Expired
        );
    }
    #[test]
    fn decoded_admission_cannot_be_preempted_or_released_by_complete_until_drop() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + Duration::from_secs(180);
        let first = claim(&r, key(1), 1, n, end).unwrap();
        first.decoded(n).unwrap();
        first.complete();
        assert_eq!(
            claim(&r, key(1), 2, n + HANDOFF_DELAY, end).unwrap_err(),
            ClaimError::Busy
        );
        assert!(!first.cancel.load(Ordering::Acquire));
        drop(first);
        assert_eq!(
            claim(&r, key(1), 2, n + HANDOFF_DELAY, end).unwrap_err(),
            ClaimError::Expired
        );
    }
    #[test]
    fn mode_fallback_shares_ownership_and_deadline() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + Duration::from_secs(180);
        let pieces = r.claim(key(1), [1; 32], Mode::Pieces, n, end).unwrap();
        assert_eq!(
            claim(&r, key(1), 1, n + HANDOFF_DELAY, end).unwrap_err(),
            ClaimError::Busy
        );
        assert!(pieces.cancel.load(Ordering::Acquire));
        drop(pieces);
        let legacy = claim(&r, key(1), 1, n + HANDOFF_DELAY, end + HANDOFF_DELAY).unwrap();
        assert_eq!(legacy.expires, end);
    }
    #[test]
    fn cancelled_decode_is_not_admitted() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + Duration::from_secs(180);
        let first = claim(&r, key(1), 1, n, end).unwrap();
        let _ = claim(&r, key(1), 2, n + HANDOFF_DELAY, end);
        assert_eq!(first.decoded(n + HANDOFF_DELAY), Err(ClaimError::Expired));
    }
    #[test]
    fn exact_hash_context_and_node_instance_do_not_share() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + HANDOFF_DELAY;
        let original = key(1);
        let lease = claim(&r, original, 1, n, end).unwrap();
        assert!(lease.matches(original, &r));
        for part in 0..5 {
            let mut other = original;
            match part {
                0..=2 => other.context[part][0] ^= 1,
                3 => other.height += 1,
                _ => other.id[0] ^= 1,
            }
            assert!(claim(&r, other, 1, n, end).is_ok());
            assert!(!lease.matches(other, &r));
        }
        assert!(!lease.matches(original, &Arc::new(Registry::default())));
    }
    #[test]
    fn capacity_does_not_evict_expired_or_live_lifecycles_implicitly() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + HANDOFF_DELAY;
        let leases: Vec<_> = (0..CAPACITY)
            .map(|id| claim(&r, key(id as u8), 1, n, end).unwrap())
            .collect();
        assert_eq!(
            claim(&r, key(100), 1, n, end).unwrap_err(),
            ClaimError::Capacity
        );
        assert_eq!(r.0.lock().unwrap().active, CAPACITY);
        drop(leases);
        assert_eq!(r.0.lock().unwrap().active, 0);
        assert!(claim(&r, key(100), 1, end, end + HANDOFF_DELAY).is_ok());
        assert_eq!(
            claim(&r, key(0), 2, end, end + HANDOFF_DELAY).unwrap_err(),
            ClaimError::Expired
        );
    }
    #[test]
    fn disconnect_or_panic_releases_but_does_not_renew_deadline() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + HANDOFF_DELAY;
        let inner = r.clone();
        assert!(
            std::panic::catch_unwind(move || {
                let _lease = claim(&inner, key(1), 1, n, end).unwrap();
                panic!("disconnected source");
            })
            .is_err()
        );
        let next = claim(&r, key(1), 2, n, end + HANDOFF_DELAY).unwrap();
        assert_eq!(next.expires, end);
    }
    #[test]
    fn a_hundred_distinct_failed_sources_release_io_without_refunding_exact_accounts() {
        let r = Arc::new(Registry::default());
        let now = Instant::now();
        let end = now + Duration::from_secs(180);
        for id in 0..100 {
            let lease =
                claim(&r, key(id), 1, now, end).expect("ended failure retained an I/O slot");
            lease.begin_query([1; 32], now).unwrap();
            drop(lease);
        }
        assert_eq!(r.0.lock().unwrap().active, 0);
        assert_eq!(r.0.lock().unwrap().entries.len(), 100);
        assert_eq!(
            claim(&r, key(0), 1, now, end).unwrap_err(),
            ClaimError::SourceUsed
        );
        assert!(claim(&r, key(200), 1, now, end).is_ok());
    }
    #[test]
    fn bootstrap_pin_and_resident_window_share_one_exact_deadline_and_four_queries() {
        let r = Arc::new(Registry::default());
        let now = Instant::now();
        let resident = r
            .resident_scope(1, now, now + Duration::from_secs(3600))
            .unwrap();
        let late = now + Duration::from_secs(3590);
        let original = late + Duration::from_secs(180);
        let old = r
            .authorize(&resident, key(1), late, original, None)
            .unwrap();
        let first = r
            .claim_authorized(&old, [1; 32], Mode::Legacy, late)
            .unwrap();
        first.begin_query([1; 32], late).unwrap();
        let bootstrap = r
            .bootstrap_scope(late, now + Duration::from_secs(7200))
            .unwrap();
        let retained = r
            .authorize(
                &bootstrap,
                key(1),
                late,
                late + Duration::from_secs(600),
                None,
            )
            .unwrap();
        assert!(Arc::ptr_eq(&old.pin.registry, &retained.pin.registry));
        assert_eq!(old.pin.account, retained.pin.account);
        r.advance_window(
            1,
            2,
            now + Duration::from_secs(3600),
            now + Duration::from_secs(7200),
        )
        .unwrap();
        assert_eq!(
            r.claim_authorized(
                &retained,
                [2; 32],
                Mode::Pieces,
                now + Duration::from_secs(3601)
            )
            .unwrap_err(),
            ClaimError::Busy
        );
        drop(first);
        let second = r
            .claim_authorized(
                &retained,
                [2; 32],
                Mode::Pieces,
                now + Duration::from_secs(3601),
            )
            .unwrap();
        assert_eq!(second.first, late);
        assert_eq!(second.expires, original);
        second
            .begin_query([2; 32], now + Duration::from_secs(3601))
            .unwrap();
        second
            .begin_query([3; 32], now + Duration::from_secs(3601))
            .unwrap();
        second
            .begin_query([4; 32], now + Duration::from_secs(3601))
            .unwrap();
        assert_eq!(
            second.begin_query([4; 32], now + Duration::from_secs(3601)),
            Err(ClaimError::QueryLimit)
        );
        drop(second);
        drop(old);
        assert_eq!(
            r.authorize(
                &resident,
                key(1),
                original + Duration::from_secs(1),
                original + Duration::from_secs(180),
                None
            )
            .unwrap_err(),
            ClaimError::Expired
        );
        drop(retained);
        let fresh = r
            .authorize(
                &resident,
                key(1),
                original + Duration::from_secs(1),
                original + Duration::from_secs(180),
                None,
            )
            .unwrap();
        assert!(
            r.claim_authorized(
                &fresh,
                [1; 32],
                Mode::Legacy,
                original + Duration::from_secs(1)
            )
            .is_ok()
        );
    }
    #[test]
    fn stale_authorization_cannot_release_or_query_a_new_account_after_owner_rollover() {
        let r = Arc::new(Registry::default());
        let now = Instant::now();
        let scope = r
            .resident_scope(1, now, now + Duration::from_secs(3600))
            .unwrap();
        let auth = r
            .authorize(&scope, key(1), now, now + Duration::from_secs(180), None)
            .unwrap();
        let old_id = auth.pin.account;
        // Keep a dead authorization Arc to exercise an old callback without an owner pin.
        let stale = auth.clone();
        let old = r
            .claim_authorized(&auth, [1; 32], Mode::Legacy, now)
            .unwrap();
        old.begin_query([1; 32], now).unwrap();
        drop(old);
        // A live candidate pin prevents retirement, even without socket I/O.
        r.advance_window(
            1,
            2,
            now + Duration::from_secs(3600),
            now + Duration::from_secs(7200),
        )
        .unwrap();
        assert_eq!(
            r.authorize(
                &scope,
                key(1),
                now + Duration::from_secs(3601),
                now + Duration::from_secs(3781),
                None
            )
            .unwrap_err(),
            ClaimError::Expired
        );
        drop(stale);
        drop(auth);
        let replacement = r
            .authorize(
                &scope,
                key(1),
                now + Duration::from_secs(3601),
                now + Duration::from_secs(3781),
                None,
            )
            .unwrap();
        assert_ne!(replacement.pin.account, old_id);
        let current = r
            .claim_authorized(
                &replacement,
                [2; 32],
                Mode::Legacy,
                now + Duration::from_secs(3601),
            )
            .unwrap();
        assert_eq!(r.0.lock().unwrap().active, 1);
        current
            .begin_query([2; 32], now + Duration::from_secs(3601))
            .unwrap();
        drop(current);
        assert_eq!(r.0.lock().unwrap().active, 0);
    }
    #[test]
    fn closing_original_operation_rejects_partial_stream_without_releasing_owner() {
        let r = Arc::new(Registry::default());
        let now = Instant::now();
        let end = now + Duration::from_secs(180);
        let bootstrap = r.bootstrap_scope(now, end).unwrap();
        let auth = r.authorize(&bootstrap, key(1), now, end, None).unwrap();
        let old = r
            .claim_authorized(&auth, [1; 32], Mode::Legacy, now)
            .unwrap();
        old.begin_query([1; 32], now).unwrap();
        old.received(1, 10, now).unwrap();
        bootstrap.close();
        assert!(old.cancel.load(Ordering::Acquire));
        assert_eq!(old.received(10, 10, now), Err(ClaimError::Expired));
        assert_eq!(old.decoded(now), Err(ClaimError::Expired));
        assert_eq!(old.check_active(now), Err(ClaimError::Expired));
        assert_eq!(old.source_ordinal(), None);
        let resident = r
            .resident_scope(1, now, now + Duration::from_secs(3600))
            .unwrap();
        let next = r.authorize(&resident, key(1), now, end, None).unwrap();
        assert_eq!(
            r.claim_authorized(&next, [2; 32], Mode::Pieces, now)
                .unwrap_err(),
            ClaimError::Busy
        );
        assert_eq!(r.0.lock().unwrap().active, 1);
        drop(old);
        let next = r
            .claim_authorized(&next, [2; 32], Mode::Pieces, now)
            .unwrap();
        assert_eq!(next.first, now);
        assert_eq!(next.expires, end);
        drop(next);
    }
    #[test]
    fn resident_deadlines_cannot_exceed_original_transport_limit_or_reset_same_window() {
        let r = Arc::new(Registry::default());
        let now = Instant::now();
        let window_end = now + Duration::from_secs(3600);
        let scope = r.resident_scope(1, now, window_end).unwrap();
        let late = window_end - Duration::from_secs(10);
        assert_eq!(
            r.authorize(
                &scope,
                key(1),
                late,
                late + crate::eng2::transport::BODY_FETCH_TIMEOUT + Duration::from_nanos(1),
                None
            )
            .unwrap_err(),
            ClaimError::Expired
        );
        let auth = r
            .authorize(
                &scope,
                key(1),
                late,
                late + crate::eng2::transport::BODY_FETCH_TIMEOUT,
                None,
            )
            .unwrap();
        let original = r
            .claim_authorized(&auth, [1; 32], Mode::Legacy, late)
            .unwrap();
        assert_eq!(
            original.expires,
            late + crate::eng2::transport::BODY_FETCH_TIMEOUT
        );
        let _same = r
            .resident_scope(1, now, window_end + Duration::from_secs(3600))
            .unwrap();
        assert_eq!(
            r.0.lock().unwrap().resident.as_ref().unwrap().expires,
            window_end
        );
        assert_eq!(
            r.authorize(
                &scope,
                key(2),
                window_end,
                window_end + Duration::from_secs(1),
                None
            )
            .unwrap_err(),
            ClaimError::Expired
        );
    }
    #[test]
    fn shorter_original_operation_expires_an_already_decoded_shared_owner() {
        let r = Arc::new(Registry::default());
        let now = Instant::now();
        let scope = r
            .resident_scope(1, now, now + Duration::from_secs(3600))
            .unwrap();
        let auth = r
            .authorize(
                &scope,
                key(1),
                now,
                now + crate::eng2::transport::BODY_FETCH_TIMEOUT,
                None,
            )
            .unwrap();
        let old = r
            .claim_authorized(&auth, [1; 32], Mode::Legacy, now)
            .unwrap();
        old.begin_query([1; 32], now).unwrap();
        old.decoded(now).unwrap();
        let shorter = r
            .bootstrap_scope(now + Duration::from_secs(1), now + Duration::from_secs(10))
            .unwrap();
        let pin = r
            .authorize(
                &shorter,
                key(1),
                now + Duration::from_secs(1),
                now + Duration::from_secs(10),
                None,
            )
            .unwrap();
        let late = now + Duration::from_secs(11);
        assert!(old.check_active(late).is_err());
        assert!(old.received(1, 10, late).is_err());
        assert_eq!(
            r.claim_authorized(&pin, [2; 32], Mode::Pieces, late)
                .unwrap_err(),
            ClaimError::Expired
        );
        assert_eq!(r.0.lock().unwrap().active, 1);
        drop(old);
        assert_eq!(r.0.lock().unwrap().active, 0);
    }
    #[test]
    fn cold_bootstrap_queries_reach_the_global_cap_without_a_resident_window_or_reconnect_reset() {
        let registry = Arc::new(Registry::default());
        let now = Instant::now();
        let end = now + crate::eng2::transport::BODY_FETCH_TIMEOUT;
        let operation = registry.bootstrap_scope(now, end).unwrap();
        for height in 1..=WINDOW_QUERIES {
            let mut candidate = key(1);
            candidate.height = height;
            let pin = registry
                .authorize(&operation, candidate, now, end, None)
                .unwrap();
            let lease = registry
                .claim_authorized(&pin, [1; 32], Mode::Legacy, now)
                .unwrap();
            lease.begin_query([1; 32], now).unwrap();
            drop(lease);
        }
        let reconnect = registry.bootstrap_scope(now, end).unwrap();
        let mut candidate = key(1);
        candidate.height = WINDOW_QUERIES + 1;
        let pin = registry
            .authorize(&reconnect, candidate, now, end, None)
            .unwrap();
        let lease = registry
            .claim_authorized(&pin, [2; 32], Mode::Pieces, now)
            .unwrap();
        assert_eq!(lease.begin_query([2; 32], now), Err(ClaimError::QueryLimit));
        drop(lease);
        let state = registry.0.lock().unwrap();
        assert!(state.resident.is_none());
        assert_eq!(state.unwindowed_queries, WINDOW_QUERIES);
        assert_eq!(state.active, 0);
    }

    #[test]
    fn first_original_discovery_window_inherits_cold_queries_until_its_lawful_renewal() {
        use super::super::{Binding, Budget, Deadline};
        use crate::eng2::branches::discovery::runtime::{Discovery, resident_limits};
        let budget = Budget::new(1024 * 1024);
        let binding = Binding {
            network: [1; 32],
            genesis: [2; 32],
            verifier: [3; 32],
        };
        let end = Instant::now() + crate::eng2::transport::BODY_FETCH_TIMEOUT;
        let original = budget.bootstrap_body_scope(end).unwrap();
        for height in 1..=3 {
            let pin = budget
                .authorize_body(
                    &original,
                    binding,
                    height,
                    [4; 32],
                    &Deadline::new(crate::eng2::transport::BODY_FETCH_TIMEOUT),
                )
                .unwrap();
            let lease = budget
                .claim_body_authorized(&pin, [5; 32], Mode::Legacy)
                .unwrap();
            lease.begin_query([5; 32]).unwrap();
            drop(lease);
        }
        let mut limits = resident_limits();
        limits.maximum_requests = 3;
        let mut discovery =
            Discovery::new(binding.network, binding.genesis, limits, 0, budget.clone()).unwrap();
        let pin = budget
            .authorize_body(
                &original,
                binding,
                4,
                [4; 32],
                &Deadline::new(crate::eng2::transport::BODY_FETCH_TIMEOUT),
            )
            .unwrap();
        let lease = budget
            .claim_body_authorized(&pin, [6; 32], Mode::Pieces)
            .unwrap();
        assert!(lease.begin_query([6; 32]).is_err());
        drop(lease);
        assert_eq!(
            budget
                .0
                .bodies
                .0
                .lock()
                .unwrap()
                .resident
                .as_ref()
                .unwrap()
                .queries,
            3
        );
        discovery.renew_body_window(limits.window_ms - 1).unwrap();
        assert_eq!(
            budget
                .0
                .bodies
                .0
                .lock()
                .unwrap()
                .resident
                .as_ref()
                .unwrap()
                .queries,
            3
        );
        discovery.renew_body_window(limits.window_ms).unwrap();
        let lease = budget
            .claim_body_authorized(&pin, [6; 32], Mode::Pieces)
            .unwrap();
        lease.begin_query([6; 32]).unwrap();
        assert_eq!(
            budget
                .0
                .bodies
                .0
                .lock()
                .unwrap()
                .resident
                .as_ref()
                .unwrap()
                .queries,
            1
        );
        drop(lease);
    }
    #[test]
    fn record_and_arc_memory_are_reserved_before_the_first_tree_insertion() {
        use super::super::{Binding, Budget, Deadline};
        let budget = Budget::new(scope_charge() + record_charge() - 1);
        let scope = budget
            .resident_body_scope(7, Instant::now() + Duration::from_secs(3600))
            .unwrap();
        let binding = Binding {
            network: [1; 32],
            genesis: [2; 32],
            verifier: [3; 32],
        };
        assert_eq!(budget.0.usage.lock().unwrap().bytes, scope_charge());
        assert_eq!(
            budget
                .authorize_body(
                    &scope,
                    binding,
                    1,
                    [4; 32],
                    &Deadline::new(Duration::from_secs(180))
                )
                .unwrap_err(),
            ClaimError::Capacity
        );
        assert!(budget.0.bodies.0.lock().unwrap().entries.is_empty());
        assert_eq!(budget.0.usage.lock().unwrap().bytes, scope_charge());
        drop(scope);
        assert_eq!(budget.0.usage.lock().unwrap().bytes, 0);
    }
    #[test]
    fn accounted_metadata_returns_after_lawful_terminal_retirement_without_budget_cycles() {
        use super::super::{Binding, Budget, Deadline};
        let budget =
            Budget::new(2 * record_charge() + 2 * pin_charge() + 2 * scope_charge() + 4096);
        let weak = Arc::downgrade(&budget.0);
        let now = Instant::now();
        let scope = budget
            .resident_body_scope(11, now + Duration::from_secs(3600))
            .unwrap();
        let binding = Binding {
            network: [1; 32],
            genesis: [2; 32],
            verifier: [3; 32],
        };
        let authorization = budget
            .authorize_body(
                &scope,
                binding,
                1,
                [4; 32],
                &Deadline::new(Duration::from_secs(180)),
            )
            .unwrap();
        let lease = budget
            .claim_body_authorized(&authorization, [5; 32], Mode::Legacy)
            .unwrap();
        lease.begin_query([5; 32]).unwrap();
        drop(lease);
        drop(authorization);
        assert_eq!(
            budget.0.usage.lock().unwrap().bytes,
            scope_charge() + record_charge()
        );
        budget
            .0
            .bodies
            .advance_window(
                11,
                12,
                now + Duration::from_secs(3600),
                now + Duration::from_secs(7200),
            )
            .unwrap();
        assert_eq!(budget.0.usage.lock().unwrap().bytes, scope_charge());
        drop(scope);
        assert_eq!(budget.0.usage.lock().unwrap().bytes, 0);
        drop(budget);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn source_confirmation_planning_retains_prior_generation_sources_and_queries() {
        let r = Arc::new(Registry::default());
        let n = Instant::now();
        let end = n + Duration::from_secs(3);
        let prior = claim(&r, key(1), 1, n, end).unwrap();
        prior.begin_query([1; 32], n).unwrap();
        drop(prior);
        let owner = r.claim(key(1), [2; 32], Mode::Pieces, n, end).unwrap();
        assert!(!owner.can_query([1; 32], 1, n));
        assert!(owner.can_query([3; 32], 3, n));
        owner.begin_query([2; 32], n).unwrap();
        assert!(!owner.can_query([3; 32], 3, n));
        assert!(owner.can_query([2; 32], 1, n));
        assert_eq!(owner.begin_query([1; 32], n), Err(ClaimError::SourceUsed));
        owner.begin_query([2; 32], n).unwrap();
        owner.begin_query([3; 32], n).unwrap();
        assert!(!owner.can_query([4; 32], 1, n));
        assert_eq!(owner.begin_query([4; 32], n), Err(ClaimError::QueryLimit));
        assert_eq!(owner.expires, end);
        assert!(!owner.can_query([2; 32], 1, end));
    }
}
