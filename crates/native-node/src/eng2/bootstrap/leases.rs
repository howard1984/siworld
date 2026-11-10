//! Bounded owner-local promises for immutable signed bootstrap offers.
//! Peer identity comes from authentication; time is sampled by the owner.
use super::Provider;
use crate::wire::Hash;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};

const MIB: usize = 1024 * 1024;
#[derive(Clone, Copy)]
struct Bounds {
    lifetime: Duration,
    peers: usize,
    records: usize,
    per_peer: usize,
    offers: usize,
    snapshot: usize,
    published_snapshots: usize,
    preparing_snapshots: usize,
    operations: u64,
    artifact_bytes: u64,
}
impl Default for Bounds {
    fn default() -> Self {
        Self {
            lifetime: Duration::from_secs(7200),
            peers: 32,
            records: 64,
            per_peer: 2,
            offers: 3,
            snapshot: 64 * MIB,
            published_snapshots: 192 * MIB,
            preparing_snapshots: 256 * MIB,
            operations: 1_048_576,
            artifact_bytes: 256 * 1024 * 1024 * 1024,
        }
    }
}
struct Lease {
    deadline: Instant,
    operations: u64,
    artifact_bytes: u64,
    exhausted: bool,
}
impl Lease {
    fn unexpired(&self, now: Instant) -> bool {
        now < self.deadline
    }
}

/// Conservative full-body ranges generated only by the canonical owner.
/// This capability does not authorize deletion or change chain acceptance.
pub struct BodyPins {
    ranges: Vec<(u64, u64)>,
}
impl BodyPins {
    pub fn protects(&self, height: u64) -> bool {
        self.ranges
            .iter()
            .any(|(first, last)| (*first..=*last).contains(&height))
    }
}

#[derive(Default)]
pub(crate) struct Registry {
    bounds: Bounds,
    current: Option<Hash>,
    offers: BTreeMap<Hash, Arc<Provider>>,
    // Expired/exhausted entries remain tombstones until their offer is removed.
    leases: BTreeMap<(Hash, Hash), Lease>,
}
impl Registry {
    pub(crate) fn current(&self) -> Option<&Arc<Provider>> {
        self.current.and_then(|bundle| self.offers.get(&bundle))
    }
    fn has_unexpired(&self, bundle: Hash, now: Instant) -> bool {
        self.leases
            .iter()
            .any(|((_, leased), lease)| *leased == bundle && lease.unexpired(now))
    }
    /// Called under the owner lock before lookup, publication or pin derivation.
    /// Failed canonical/roster checks discard the offer and its lease records.
    pub(crate) fn reconcile(&mut self, now: Instant, mut valid: impl FnMut(&Provider) -> bool) {
        let remove: Vec<_> = self
            .offers
            .iter()
            .filter_map(|(bundle, provider)| {
                (!valid(provider)
                    || (self.current != Some(*bundle) && !self.has_unexpired(*bundle, now)))
                .then_some(*bundle)
            })
            .collect();
        for bundle in remove {
            self.offers.remove(&bundle);
        }
        if self
            .current
            .is_some_and(|bundle| !self.offers.contains_key(&bundle))
        {
            self.current = None;
        }
        self.leases
            .retain(|(_, bundle), _| self.offers.contains_key(bundle));
    }
    /// Reserve capacity before capturing a replacement. Existing valid offers
    /// remain visible when capacity or checkpoint preparation is unavailable.
    pub(crate) fn preparation_allowed(&self, snapshot_bytes: usize, now: Instant) -> bool {
        if snapshot_bytes == 0 || snapshot_bytes > self.bounds.snapshot {
            return false;
        }
        let mut preparing = snapshot_bytes;
        let mut published = snapshot_bytes;
        let mut offers = 1usize;
        for (bundle, provider) in &self.offers {
            let Some(next) = preparing.checked_add(provider.snapshot.len()) else {
                return false;
            };
            preparing = next;
            if self.has_unexpired(*bundle, now) {
                let Some(next) = published.checked_add(provider.snapshot.len()) else {
                    return false;
                };
                published = next;
                offers += 1;
            }
        }
        offers <= self.bounds.offers
            && published <= self.bounds.published_snapshots
            && preparing <= self.bounds.preparing_snapshots
    }
    pub(crate) fn publish(&mut self, provider: Arc<Provider>, now: Instant) -> bool {
        let bundle = provider.manifest().bundle();
        if self.current == Some(bundle) {
            return true;
        }
        if self.offers.contains_key(&bundle)
            || !self.preparation_allowed(provider.snapshot.len(), now)
        {
            return false;
        }
        self.offers.insert(bundle, provider);
        self.current = Some(bundle);
        self.reconcile(now, |_| true);
        true
    }
    fn allow(
        &mut self,
        peer: Hash,
        bundle: Hash,
        now: Instant,
        bytes: u64,
        operation: bool,
    ) -> bool {
        let Some(lease) = self.leases.get_mut(&(peer, bundle)) else {
            return false;
        };
        if !lease.unexpired(now) || lease.exhausted {
            return false;
        }
        let operations = lease.operations.checked_add(u64::from(operation));
        let artifact_bytes = lease.artifact_bytes.checked_add(bytes);
        match (operations, artifact_bytes) {
            (Some(operations), Some(artifact_bytes))
                if operations <= self.bounds.operations
                    && artifact_bytes <= self.bounds.artifact_bytes =>
            {
                lease.operations = operations;
                lease.artifact_bytes = artifact_bytes;
                true
            }
            _ => {
                lease.exhausted = true;
                false
            }
        }
    }
    fn start_current(&mut self, peer: Hash, bundle: Hash, now: Instant) -> Option<()> {
        if self.leases.contains_key(&(peer, bundle)) {
            return Some(());
        }
        let peers: BTreeSet<_> = self.leases.keys().map(|(peer, _)| *peer).collect();
        if self.leases.len() >= self.bounds.records
            || (!peers.contains(&peer) && peers.len() >= self.bounds.peers)
            || self
                .leases
                .keys()
                .filter(|(owner, _)| *owner == peer)
                .count()
                >= self.bounds.per_peer
        {
            return None;
        }
        let deadline = now.checked_add(self.bounds.lifetime)?;
        self.leases.insert(
            (peer, bundle),
            Lease {
                deadline,
                operations: 0,
                artifact_bytes: 0,
                exhausted: false,
            },
        );
        Some(())
    }
    /// Only a fresh request for current may create a lease. An exact request
    /// must already own that bundle, including when it is still current.
    pub(crate) fn manifest(
        &mut self,
        peer: Hash,
        requested: Option<Hash>,
        now: Instant,
    ) -> Option<Arc<Provider>> {
        let bundle = match requested {
            Some(bundle) => bundle,
            None => {
                let bundle = self.current?;
                self.start_current(peer, bundle, now)?;
                bundle
            }
        };
        let provider = self.offers.get(&bundle)?.clone();
        if !self.allow(peer, bundle, now, provider.encoded().len() as u64, true) {
            return None;
        }
        Some(provider)
    }
    pub(crate) fn chunk_provider(
        &mut self,
        peer: Hash,
        bundle: Hash,
        now: Instant,
    ) -> Option<Arc<Provider>> {
        let provider = self.offers.get(&bundle)?.clone();
        self.allow(peer, bundle, now, 0, true).then_some(provider)
    }
    pub(crate) fn charge_chunk(
        &mut self,
        peer: Hash,
        bundle: Hash,
        bytes: usize,
        now: Instant,
    ) -> bool {
        let Ok(bytes) = u64::try_from(bytes) else {
            return false;
        };
        self.allow(peer, bundle, now, bytes, false)
    }
    pub(crate) fn body_pins(&self, now: Instant) -> BodyPins {
        let ranges = self
            .offers
            .iter()
            .filter(|(bundle, _)| {
                self.current == Some(**bundle) || self.has_unexpired(**bundle, now)
            })
            .map(|(_, provider)| {
                (
                    provider.manifest().checkpoint_height() + 1,
                    provider.manifest().tip_height,
                )
            })
            .collect();
        BodyPins { ranges }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn provider(tag: u8) -> Arc<Provider> {
        let (_, _, manifest) = super::super::tests::framing_fixture();
        let encoded = manifest.encode().unwrap();
        let mut provider = Provider {
            manifest,
            encoded,
            snapshot: b"fixture".to_vec(),
            _reservation: crate::p2p::Budget::default().reserve(1024 * 1024).unwrap(),
        };
        provider.manifest.tip_id = [tag; 32];
        provider.manifest.certificate.statement.authorization_block = [tag; 32];
        provider.manifest.bundle = *blake3::hash(&provider.manifest.prefix().unwrap()).as_bytes();
        provider.encoded = provider.manifest.encode().unwrap();
        Arc::new(provider)
    }
    #[test]
    fn rollover_preserves_exact_peer_bundle_and_preparation_keeps_current() {
        let now = Instant::now();
        let (a, b) = (provider(7), provider(8));
        let mut registry = Registry::default();
        assert!(registry.publish(a.clone(), now));
        assert!(registry.manifest([1; 32], None, now).is_some());
        assert!(registry.current().is_some());
        assert!(!registry.preparation_allowed(65 * MIB, now));
        assert_eq!(
            registry.current().unwrap().manifest().bundle(),
            a.manifest().bundle()
        );
        assert!(registry.publish(b.clone(), now));
        assert_eq!(
            registry
                .manifest([1; 32], Some(a.manifest().bundle()), now)
                .unwrap()
                .encoded(),
            a.encoded()
        );
        assert_eq!(
            registry.manifest([2; 32], None, now).unwrap().encoded(),
            b.encoded()
        );
        assert!(
            registry
                .manifest([2; 32], Some(a.manifest().bundle()), now)
                .is_none()
        );
        assert!(registry.manifest([1; 32], Some([0; 32]), now).is_none());
        assert!(
            registry
                .chunk_provider([2; 32], a.manifest().bundle(), now)
                .is_none()
        );
        assert!(registry.body_pins(now).protects(73));
        assert!(!registry.body_pins(now).protects(72));
    }
    #[test]
    fn expiry_exhaustion_and_reconnection_cannot_renew_deadline() {
        let now = Instant::now();
        let a = provider(7);
        let bundle = a.manifest().bundle();
        let mut registry = Registry::default();
        assert!(registry.publish(a, now));
        assert!(registry.manifest([1; 32], None, now).is_some());
        let deadline = registry.leases[&([1; 32], bundle)].deadline;
        assert!(
            registry
                .manifest([1; 32], Some(bundle), now + Duration::from_secs(7199))
                .is_some()
        );
        assert_eq!(registry.leases[&([1; 32], bundle)].deadline, deadline);
        assert!(registry.manifest([1; 32], Some(bundle), deadline).is_none());
        assert!(registry.manifest([1; 32], None, deadline).is_none());
        assert_eq!(registry.leases[&([1; 32], bundle)].deadline, deadline);
        registry.bounds.operations = 1;
        assert!(registry.manifest([2; 32], None, now).is_some());
        assert!(registry.chunk_provider([2; 32], bundle, now).is_none());
        assert!(registry.manifest([2; 32], None, now).is_none());
        assert_eq!(
            registry.leases[&([2; 32], bundle)].deadline,
            now + Duration::from_secs(7200)
        );
    }
    #[test]
    fn retired_expiry_releases_only_registry_derived_tail_pins_and_tombstones() {
        let now = Instant::now();
        let mut registry = Registry::default();
        let a = provider(7);
        let bundle = a.manifest().bundle();
        assert!(registry.publish(a, now));
        assert!(registry.manifest([1; 32], None, now).is_some());
        let mut b = Arc::try_unwrap(provider(8)).ok().unwrap();
        b.manifest.certificate.statement.checkpoint_height = 144;
        b.manifest.certificate.statement.authorization_height = 168;
        b.manifest.tip_height = 168;
        b.manifest.bundle = *blake3::hash(&b.manifest.prefix().unwrap()).as_bytes();
        b.encoded = b.manifest.encode().unwrap();
        assert!(registry.publish(Arc::new(b), now));
        assert!(registry.body_pins(now).protects(73));
        let after = now + Duration::from_secs(7200);
        registry.reconcile(after, |_| true);
        assert!(!registry.body_pins(after).protects(73));
        assert!(registry.body_pins(after).protects(145));
        assert!(!registry.offers.contains_key(&bundle));
        assert!(!registry.leases.contains_key(&([1; 32], bundle)));
        assert!(registry.manifest([1; 32], Some(bundle), after).is_none());
    }
    #[test]
    fn capacity_bytes_and_canonical_or_signer_invalidation_fail_closed() {
        let now = Instant::now();
        let mut registry = Registry::default();
        registry.bounds.peers = 1;
        registry.bounds.records = 2;
        registry.bounds.per_peer = 1;
        let a = provider(7);
        let bundle = a.manifest().bundle();
        assert!(registry.publish(a, now));
        assert!(registry.manifest([1; 32], None, now).is_some());
        assert!(registry.manifest([2; 32], None, now).is_none());
        assert!(registry.publish(provider(8), now));
        assert!(registry.manifest([1; 32], None, now).is_none());
        registry.bounds.artifact_bytes = 0;
        assert!(!registry.charge_chunk([1; 32], bundle, 1, now));
        assert!(registry.chunk_provider([1; 32], bundle, now).is_none());
        registry.reconcile(now, |_| false);
        assert!(registry.current().is_none());
        assert!(registry.offers.is_empty());
        assert!(registry.leases.is_empty());
        assert!(!registry.body_pins(now).protects(73));
    }
    #[test]
    fn leased_offer_and_snapshot_caps_defer_publication_without_losing_current() {
        let now = Instant::now();
        let mut registry = Registry::default();
        for (peer, tag) in [(1, 7), (2, 8), (3, 9)] {
            assert!(registry.publish(provider(tag), now));
            assert!(registry.manifest([peer; 32], None, now).is_some());
        }
        assert_eq!(registry.offers.len(), 3);
        let before = registry.current().unwrap().manifest().bundle();
        assert!(!registry.publish(provider(10), now));
        assert_eq!(registry.current().unwrap().manifest().bundle(), before);
        registry.bounds.offers = 4;
        registry.bounds.preparing_snapshots = 7;
        assert!(!registry.preparation_allowed(7, now));
        registry.bounds.preparing_snapshots = 256 * MIB;
        registry.bounds.published_snapshots = 7;
        assert!(!registry.preparation_allowed(7, now));
        assert_eq!(registry.current().unwrap().manifest().bundle(), before);
    }
    #[test]
    fn independent_peer_record_and_per_peer_caps_include_nonrenewing_tombstones() {
        let now = Instant::now();
        let mut registry = Registry::default();
        let (a, b, c) = (provider(7), provider(8), provider(9));
        let a_bundle = a.manifest().bundle();
        assert!(registry.publish(a, now));
        for peer in 0..32 {
            assert!(registry.manifest([peer; 32], None, now).is_some());
        }
        assert!(registry.manifest([32; 32], None, now).is_none());
        assert!(registry.publish(b, now));
        for peer in 0..32 {
            assert!(registry.manifest([peer; 32], None, now).is_some());
        }
        assert_eq!(registry.leases.len(), 64);
        assert!(registry.publish(c, now));
        assert!(registry.manifest([0; 32], None, now).is_none());
        registry.bounds.per_peer = 3;
        assert!(registry.manifest([0; 32], None, now).is_none());
        registry.bounds.records = 65;
        assert!(registry.manifest([0; 32], None, now).is_some());
        let expiry = now + Duration::from_secs(7200);
        registry.reconcile(expiry, |_| true);
        // The current-offer tombstone survives; a repeated fresh request must
        // not restart its two-hour promise after expiration.
        assert!(registry.manifest([0; 32], None, expiry).is_none());
        assert!(registry.manifest([0; 32], Some(a_bundle), expiry).is_none());
        assert_eq!(registry.leases.len(), 1);
        assert!(registry.manifest([1; 32], None, expiry).is_some());
    }
}
