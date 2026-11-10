//! Bounded admission of received native transactions and private fee openings.
//!
//! The state transition remains authoritative. This pool verifies the frozen
//! transaction relation and reserves every pending input and output; it does
//! not reinterpret a proved fee using the current snapshot's fee schedule.
//! Peer identifiers are opaque bounded values, never connection addresses.

use crate::pool::Padding;
use crate::state::{BlockVerifier, State};
use crate::wire::{
    DigestBytes, Hash, MAX_ENVELOPE_BYTES, MAX_SLOTS, SIDECAR_BYTES, Sidecar, TX_PREFIX_BYTES,
    Transaction, borrowed_envelope,
};
use native::codec::{ProofContext, PublicTransaction, decode_digest, encode_digest};
use native::confidential_fees::FeeOpening;
use native::multi_asset::{Digest, F};
use p3_field::PrimeCharacteristicRing;
use std::collections::{BTreeMap, BTreeSet};

/// An authenticated transport maps a connection to one fixed-size opaque ID.
/// This type deliberately carries neither an address nor a display name.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerId(pub Hash);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub bytes: usize,
    pub entries: usize,
    pub peer_bytes: usize,
    pub peer_entries: usize,
    pub peers: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 512 * 1024 * 1024,
            entries: 2048,
            peer_bytes: 16 * 1024 * 1024,
            peer_entries: 64,
            peers: 4096,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), AdmissionError> {
        let maximum = Self::default();
        if self.bytes == 0
            || self.bytes > maximum.bytes
            || self.entries == 0
            || self.entries > maximum.entries
            || self.peer_bytes == 0
            || self.peer_bytes > maximum.peer_bytes
            || self.peer_entries == 0
            || self.peer_entries > maximum.peer_entries
            || self.peers == 0
            || self.peers > maximum.peers
        {
            return Err(AdmissionError::Unavailable(ResourceReason::Configuration));
        }
        Ok(())
    }
}

/// Only a completed cryptographic rejection establishes an invalid proof.
/// A worker timeout, sandbox limit, or failed worker is retryable unavailability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationError {
    Invalid,
    Unavailable,
}

pub trait AdmissionVerifier {
    fn verify(
        &self,
        public: &PublicTransaction,
        context: &ProofContext,
        fee: &Digest,
        root: &Digest,
        proof: &[u8],
    ) -> Result<(), VerificationError>;
    /// Check local admission availability immediately before the first pool
    /// mutation. This hook cannot change the proof validity result.
    fn check_commit(&self) -> Result<(), VerificationError> {
        Ok(())
    }
}

/// The in-process block verifier has no worker resource-result interface.
/// An isolated worker instead implements AdmissionVerifier directly so its
/// resource failures cannot be converted into invalid-proof verdicts.
impl<V: BlockVerifier> AdmissionVerifier for V {
    fn verify(
        &self,
        public: &PublicTransaction,
        context: &ProofContext,
        fee: &Digest,
        root: &Digest,
        proof: &[u8],
    ) -> Result<(), VerificationError> {
        self.transaction(public, context, fee, root, proof)
            .map_err(|_| VerificationError::Invalid)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidReason {
    Envelope,
    MissingSidecar,
    Sidecar,
    Snapshot,
    Duplicate,
    CanonicalConflict,
    PendingConflict,
    Proof,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceReason {
    Configuration,
    GlobalBudget,
    PeerBudget,
    Verifier,
    Selection,
}

/// Admission failures are local policy results, not block-invalidity verdicts.
/// Error values contain no fee, nullifier, transaction classification or peer ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Invalid(InvalidReason),
    Unavailable(ResourceReason),
}
impl core::fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "native transaction admission: {self:?}")
    }
}
impl std::error::Error for AdmissionError {}

struct Entry {
    transaction: Transaction,
    sidecar: Sidecar,
    peer: PeerId,
    inputs: [DigestBytes; 2],
    outputs: [DigestBytes; 3],
    bytes: usize,
}
#[derive(Default)]
struct PeerUsage {
    bytes: usize,
    entries: usize,
}

// Large records are boxed so tree nodes retain bounded small map values.
// Conservative per-entry allowance covers tree nodes, reservation indices and
// one peer-map entry, in addition to the owned struct and wire payload. This
// is a bounded ledger, not a process RSS or allocator charged-memory claim.
const ENTRY_INDEX_ALLOWANCE: usize = 4096;
fn entry_bytes(envelope_bytes: usize) -> Option<usize> {
    envelope_bytes
        .checked_add(SIDECAR_BYTES)
        .and_then(|n| n.checked_add(core::mem::size_of::<Entry>()))
        .and_then(|n| n.checked_add(ENTRY_INDEX_ALLOWANCE))
}

pub struct Mempool {
    network: Hash,
    limits: Limits,
    entries: BTreeMap<Hash, Box<Entry>>,
    inputs: BTreeSet<DigestBytes>,
    outputs: BTreeSet<DigestBytes>,
    peers: BTreeMap<PeerId, PeerUsage>,
    bytes: usize,
}
impl Mempool {
    pub fn new(network: Hash) -> Self {
        Self::with_limits(network, Limits::default()).expect("default admission limits")
    }
    /// Local callers may tighten the selected policy, never silently raise it.
    pub fn with_limits(network: Hash, limits: Limits) -> Result<Self, AdmissionError> {
        limits.validate()?;
        Ok(Self {
            network,
            limits,
            entries: BTreeMap::new(),
            inputs: BTreeSet::new(),
            outputs: BTreeSet::new(),
            peers: BTreeMap::new(),
            bytes: 0,
        })
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
    pub fn contains(&self, id: &Hash) -> bool {
        self.entries.contains_key(id)
    }
    pub fn ids(&self) -> Vec<Hash> {
        self.entries.keys().copied().collect()
    }
    /// Compact reconstruction borrows a verified object without another copy.
    pub fn transaction(&self, id: &Hash) -> Option<&Transaction> {
        self.entries.get(id).map(|entry| &entry.transaction)
    }
    /// Private production/relay access only. Never serialize this into a block.
    pub fn sidecar(&self, id: &Hash) -> Option<&Sidecar> {
        self.entries.get(id).map(|entry| &entry.sidecar)
    }
    fn check_network(&self, state: &State) -> Result<(), AdmissionError> {
        if self.network != state.config.network {
            return Err(AdmissionError::Unavailable(ResourceReason::Configuration));
        }
        Ok(())
    }
    fn check_budget(&self, peer: PeerId, bytes: usize) -> Result<(), AdmissionError> {
        if self
            .bytes
            .checked_add(bytes)
            .is_none_or(|n| n > self.limits.bytes)
            || self.entries.len() >= self.limits.entries
        {
            return Err(AdmissionError::Unavailable(ResourceReason::GlobalBudget));
        }
        let usage = self.peers.get(&peer);
        if usage.is_none() && self.peers.len() >= self.limits.peers {
            return Err(AdmissionError::Unavailable(ResourceReason::PeerBudget));
        }
        let peer_bytes = usage.map_or(0, |usage| usage.bytes);
        let peer_entries = usage.map_or(0, |usage| usage.entries);
        if peer_bytes
            .checked_add(bytes)
            .is_none_or(|n| n > self.limits.peer_bytes)
            || peer_entries >= self.limits.peer_entries
        {
            return Err(AdmissionError::Unavailable(ResourceReason::PeerBudget));
        }
        Ok(())
    }
    fn check_conflicts(
        &self,
        state: &State,
        id: &Hash,
        inputs: &[DigestBytes; 2],
        outputs: &[DigestBytes; 3],
    ) -> Result<(), AdmissionError> {
        if inputs[0] == inputs[1]
            || outputs[0] == outputs[1]
            || outputs[0] == outputs[2]
            || outputs[1] == outputs[2]
            || inputs.iter().any(|nf| state.spent.contains(nf))
            || outputs.iter().any(|cm| state.commitments.contains(cm))
        {
            return Err(AdmissionError::Invalid(InvalidReason::CanonicalConflict));
        }
        if self.entries.contains_key(id) {
            return Err(AdmissionError::Invalid(InvalidReason::Duplicate));
        }
        if inputs.iter().any(|nf| self.inputs.contains(nf))
            || outputs.iter().any(|cm| self.outputs.contains(cm))
        {
            return Err(AdmissionError::Invalid(InvalidReason::PendingConflict));
        }
        Ok(())
    }
    /// Inspect canonical borrowed framing and reserve the full ledger cost
    /// before copying or decoding a proof. No reservation or peer entry is
    /// retained on failure. The mutable receiver serializes pending admission;
    /// the immutable state reference prevents a canonical update mid-check.
    ///
    /// A transport must separately bound ingress, queue residence and verifier
    /// execution. This method is the verified-pool boundary, not a worker
    /// sandbox. Prune after each canonical update before accepting more work.
    pub fn submit_encoded(
        &mut self,
        state: &State,
        peer: PeerId,
        envelope: &[u8],
        sidecar: Option<&[u8]>,
        verifier: &impl AdmissionVerifier,
    ) -> Result<Hash, AdmissionError> {
        self.check_network(state)?;
        if !(TX_PREFIX_BYTES + 1..=MAX_ENVELOPE_BYTES).contains(&envelope.len()) {
            return Err(AdmissionError::Invalid(InvalidReason::Envelope));
        }
        let bytes = entry_bytes(envelope.len())
            .ok_or(AdmissionError::Unavailable(ResourceReason::GlobalBudget))?;
        // There is no yield or reentrant mutation between this reservation
        // preflight and insertion. Failed parsing/verification changes nothing.
        self.check_budget(peer, bytes)?;
        let (record, proof) = borrowed_envelope(envelope, &self.network)
            .map_err(|_| AdmissionError::Invalid(InvalidReason::Envelope))?;
        let snapshot = state
            .snapshot(record.snapshot)
            .map_err(|_| AdmissionError::Invalid(InvalidReason::Snapshot))?;
        let root = decode_digest(&snapshot.recent_root)
            .map_err(|_| AdmissionError::Unavailable(ResourceReason::Configuration))?;
        let sidecar = sidecar.ok_or(AdmissionError::Invalid(InvalidReason::MissingSidecar))?;
        let sidecar = Sidecar::decode(sidecar)
            .map_err(|_| AdmissionError::Invalid(InvalidReason::Sidecar))?;
        sidecar
            .check_opening(&record, &self.network)
            .map_err(|_| AdmissionError::Invalid(InvalidReason::Sidecar))?;
        let id = record.statement_id(&self.network);
        let public = PublicTransaction::decode(&record.body)
            .map_err(|_| AdmissionError::Invalid(InvalidReason::Envelope))?;
        let inputs = public.nf.map(|nf| encode_digest(&nf));
        let outputs = public.cm.map(|cm| encode_digest(&cm));
        self.check_conflicts(state, &id, &inputs, &outputs)?;
        let fee = decode_digest(&record.fee_commit)
            .map_err(|_| AdmissionError::Invalid(InvalidReason::Envelope))?;
        let context = ProofContext::for_snapshot(
            self.network,
            record.snapshot.height,
            record.snapshot.block_id,
        );
        verifier
            .verify(&public, &context, &fee, &root, proof)
            .map_err(|error| match error {
                VerificationError::Invalid => AdmissionError::Invalid(InvalidReason::Proof),
                VerificationError::Unavailable => {
                    AdmissionError::Unavailable(ResourceReason::Verifier)
                }
            })?;
        // The complete envelope is borrowed until successful verification.
        // A boxed slice discards any upstream Vec capacity before retention.
        let proof = proof.to_vec().into_boxed_slice().into_vec();
        verifier
            .check_commit()
            .map_err(|_| AdmissionError::Unavailable(ResourceReason::Verifier))?;
        self.inputs.extend(inputs);
        self.outputs.extend(outputs);
        let usage = self.peers.entry(peer).or_default();
        usage.bytes += bytes;
        usage.entries += 1;
        self.bytes += bytes;
        self.entries.insert(
            id,
            Box::new(Entry {
                transaction: Transaction { record, proof },
                sidecar,
                peer,
                inputs,
                outputs,
                bytes,
            }),
        );
        Ok(id)
    }
    /// Remove one entry and every associated byte/identity reservation exactly
    /// once. Used after inclusion or explicit local eviction.
    pub fn remove(&mut self, id: &Hash) -> bool {
        let Some(entry) = self.entries.remove(id) else {
            return false;
        };
        for input in entry.inputs {
            self.inputs.remove(&input);
        }
        for output in entry.outputs {
            self.outputs.remove(&output);
        }
        self.bytes -= entry.bytes;
        let usage = self
            .peers
            .get_mut(&entry.peer)
            .expect("owned admission peer ledger");
        usage.bytes -= entry.bytes;
        usage.entries -= 1;
        if usage.entries == 0 {
            self.peers.remove(&entry.peer);
        }
        true
    }
    /// Expiry, removed fork snapshots and confirmed conflicts invalidate an
    /// entry without re-verifying its immutable proof. Re-admission from an
    /// orphaned block still requires the matching private sidecar.
    pub fn prune(&mut self, state: &State) -> Result<usize, AdmissionError> {
        self.check_network(state)?;
        let removed: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                (state.snapshot(entry.transaction.record.snapshot).is_err()
                    || entry.inputs.iter().any(|nf| state.spent.contains(nf))
                    || entry
                        .outputs
                        .iter()
                        .any(|cm| state.commitments.contains(cm)))
                .then_some(*id)
            })
            .collect();
        for id in &removed {
            self.remove(id);
        }
        Ok(removed.len())
    }
    /// Copy at most one block's positions for production, prioritizing private
    /// fee amounts with statement identity as a deterministic tie breaker.
    /// Originals and reservations remain until canonical inclusion/eviction,
    /// so a failed candidate cannot release conflicts or lose fee openings.
    pub fn select(
        &mut self,
        state: &State,
        maximum: usize,
    ) -> Result<Vec<Padding>, AdmissionError> {
        if maximum > MAX_SLOTS {
            return Err(AdmissionError::Unavailable(ResourceReason::Selection));
        }
        self.prune(state)?;
        let mut ids: Vec<_> = self.entries.keys().copied().collect();
        ids.sort_unstable_by_key(|id| (core::cmp::Reverse(self.entries[id].sidecar.fee), *id));
        ids.truncate(maximum);
        Ok(ids
            .iter()
            .map(|id| {
                let entry = &self.entries[id];
                let mut transaction = entry.transaction.clone();
                transaction.proof = transaction.proof.into_boxed_slice().into_vec();
                Padding {
                    transaction,
                    opening: FeeOpening {
                        fee: entry.sidecar.fee,
                        blind: entry.sidecar.blind.map(F::from_u32),
                        // These legacy reference-model flags do not enter the
                        // fixed settlement relation. Never infer classification.
                        dummy: false,
                        priority: false,
                    },
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests;
