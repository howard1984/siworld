//! Bounded private queue of independently verified pre-generated positions.
//! Entries move into one candidate only; no queue metadata is exported.
use crate::state::{BlockVerifier, State};
use crate::wire::{
    DigestBytes, GROUP, Hash, MAX_SLOTS, MAX_TX_PROOF, MIN_SLOTS, SIDECAR_BYTES, TX_PREFIX_BYTES,
    Transaction,
};
use native::codec::{ProofContext, PublicTransaction, decode_digest, encode_digest};
use native::confidential_fees::FeeOpening;
use native::multi_asset::{Digest, Hasher};
use std::collections::{BTreeMap, BTreeSet};

pub const MIN_READY: usize = 64;
pub const MAX_ENTRIES: usize = 128;
pub const MAX_BYTES: usize = 65 * 1024 * 1024;
const MAX_CONSUMED: usize = 1024;
const RESERVATION_BYTES: usize = 32 + 5 * 48 + 256;

/// Move-only private proof and its settlement opening.
pub struct Padding {
    pub(crate) transaction: Transaction,
    pub(crate) opening: FeeOpening,
}
struct Reserved {
    value: Padding,
    inputs: [DigestBytes; 2],
    outputs: [DigestBytes; 3],
    bytes: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FillError {
    Limit,
    Network,
    Insufficient { required: usize },
    ReservationsExhausted,
    PrivateTemplateActive,
}
impl FillError {
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::Limit => "candidate padding shortfall exceeds 576",
            Self::Network => "private queue network mismatch",
            Self::Insufficient { .. } => "private queue not ready",
            Self::ReservationsExhausted => "consumed reservation limit reached",
            Self::PrivateTemplateActive => "previous private template is still owned",
        }
    }
}

struct Consumed {
    inputs: [DigestBytes; 2],
    outputs: [DigestBytes; 3],
}
pub struct Pool {
    network: Hash,
    entries: BTreeMap<Hash, Reserved>,
    inputs: BTreeSet<DigestBytes>,
    outputs: BTreeSet<DigestBytes>,
    consumed: BTreeMap<Hash, Consumed>,
    // Only one resident producer owns a private candidate at a time. These
    // identify reservations that have never crossed the publication edge.
    private_template: Vec<Hash>,
    bytes: usize,
}
impl Pool {
    pub fn new(network: Hash) -> Self {
        Self {
            network,
            entries: BTreeMap::new(),
            inputs: BTreeSet::new(),
            outputs: BTreeSet::new(),
            consumed: BTreeMap::new(),
            private_template: Vec::new(),
            bytes: 0,
        }
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
    pub fn ready(&self) -> bool {
        self.len() >= MIN_READY
    }
    /// Reserve enough room for a maximum-sized next proof before starting work.
    pub fn can_grow(&self) -> bool {
        let maximum = TX_PREFIX_BYTES
            + MAX_TX_PROOF
            + SIDECAR_BYTES
            + RESERVATION_BYTES
            + std::mem::size_of::<Reserved>();
        self.len() < MAX_ENTRIES
            && self
                .bytes
                .checked_add(maximum)
                .is_some_and(|n| n <= MAX_BYTES)
    }
    fn network(&self, state: &State) -> Result<(), String> {
        if self.network != state.config.network {
            return Err("private queue network mismatch".into());
        }
        Ok(())
    }
    fn public(state: &State, value: &Padding) -> Result<(PublicTransaction, Digest), String> {
        let tx = &value.transaction;
        tx.record.validate()?;
        if tx.proof.is_empty() || tx.proof.len() > MAX_TX_PROOF {
            return Err("private queue proof byte limit".into());
        }
        let snapshot = state.snapshot(tx.record.snapshot)?;
        let root =
            decode_digest(&snapshot.recent_root).map_err(|_| "invalid canonical recent root")?;
        let public = PublicTransaction::decode(&tx.record.body)
            .map_err(|_| "invalid private queue public fields")?;
        let inputs = public.nf.map(|nf| encode_digest(&nf));
        let outputs = public.cm.map(|cm| encode_digest(&cm));
        if inputs[0] == inputs[1]
            || outputs.iter().collect::<BTreeSet<_>>().len() != outputs.len()
            || inputs.iter().any(|nf| state.spent.contains(nf))
            || outputs.iter().any(|cm| state.commitments.contains(cm))
        {
            return Err("private queue canonical-state conflict".into());
        }
        if value.opening.fee != 0
            || !value.opening.dummy
            || value.opening.priority
            || encode_digest(&Hasher::new().fee_commit(value.opening.fee, &value.opening.blind))
                != tx.record.fee_commit
        {
            return Err("private queue fee opening mismatch".into());
        }
        Ok((public, root))
    }
    /// Verify through the independent block verifier before reserving any input,
    /// output, identity or byte budget. A rejected insertion leaves the queue unchanged.
    pub fn insert(
        &mut self,
        state: &State,
        mut value: Padding,
        verifier: &impl BlockVerifier,
    ) -> Result<(), String> {
        self.network(state)?;
        let (public, root) = Self::public(state, &value)?;
        // Serialization may leave a growing Vec with capacity above its wire
        // length. Normalize before retention so reserved capacity is bounded.
        value.transaction.proof = value.transaction.proof.into_boxed_slice().into_vec();
        let id = value.transaction.record.statement_id(&self.network);
        let inputs = public.nf.map(|nf| encode_digest(&nf));
        let outputs = public.cm.map(|cm| encode_digest(&cm));
        let bytes = TX_PREFIX_BYTES
            .checked_add(value.transaction.proof.capacity())
            .and_then(|n| {
                n.checked_add(SIDECAR_BYTES + RESERVATION_BYTES + std::mem::size_of::<Reserved>())
            })
            .ok_or("private queue byte accounting overflow")?;
        if self.entries.len() >= MAX_ENTRIES
            || self.bytes.checked_add(bytes).is_none_or(|n| n > MAX_BYTES)
        {
            return Err("private queue capacity limit".into());
        }
        if self.entries.contains_key(&id)
            || self.consumed.contains_key(&id)
            || inputs.iter().any(|nf| {
                self.inputs.contains(nf) || self.consumed.values().any(|c| c.inputs.contains(nf))
            })
            || outputs.iter().any(|cm| {
                self.outputs.contains(cm) || self.consumed.values().any(|c| c.outputs.contains(cm))
            })
        {
            return Err("private queue reservation conflict".into());
        }
        let selector = value.transaction.record.snapshot;
        let context = ProofContext::for_snapshot(self.network, selector.height, selector.block_id);
        let fee = decode_digest(&value.transaction.record.fee_commit)
            .map_err(|_| "invalid private fee commitment")?;
        verifier.transaction(&public, &context, &fee, &root, &value.transaction.proof)?;
        self.inputs.extend(inputs);
        self.outputs.extend(outputs);
        self.bytes += bytes;
        self.entries.insert(
            id,
            Reserved {
                value,
                inputs,
                outputs,
                bytes,
            },
        );
        Ok(())
    }
    pub fn prune(&mut self, state: &State) -> Result<usize, String> {
        self.network(state)?;
        let removed: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| Self::public(state, &entry.value).is_err().then_some(*id))
            .collect();
        for id in &removed {
            let entry = self
                .entries
                .remove(id)
                .expect("selected private queue entry");
            for nf in entry.inputs {
                self.inputs.remove(&nf);
            }
            for cm in entry.outputs {
                self.outputs.remove(&cm);
            }
            self.bytes -= entry.bytes;
        }
        // Accepted canonical spends absorb their tombstones. Publication
        // retains uncommitted entries even if a snapshot later expires.
        self.consumed
            .retain(|_, entry| !entry.inputs.iter().all(|nf| state.spent.contains(nf)));
        Ok(removed.len())
    }
    pub fn take(&mut self, state: &State, count: usize) -> Result<Vec<Padding>, String> {
        if !(MIN_SLOTS..=MAX_SLOTS).contains(&count) || !count.is_multiple_of(GROUP) {
            return Err("candidate positions must be 64 through 576 in groups of 16".into());
        }
        self.take_reserved(state, count, false)
            .map_err(|error| error.message().into())
    }
    /// Fill an exact shortfall; a shortfall may be any count, including zero.
    /// Ordinary callers retain every consumed reservation. Resident private
    /// templates may release only their unpublished reservations.
    pub(crate) fn take_for_fill(
        &mut self,
        state: &State,
        count: usize,
    ) -> Result<Vec<Padding>, String> {
        self.take_reserved(state, count, false)
            .map_err(|error| error.message().into())
    }

    pub(crate) fn take_for_fill_with_visibility(
        &mut self,
        state: &State,
        count: usize,
        private: bool,
    ) -> Result<Vec<Padding>, FillError> {
        self.take_reserved(state, count, private)
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn discard_unpublished_template(&mut self) {
        for id in self.private_template.drain(..) {
            // Only reservation metadata is released. Proofs and witnesses
            // left the queue when selected and are never returned to it.
            self.consumed.remove(&id);
        }
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn mark_template_published(&mut self) {
        // An attempted or ambiguous publication is treated as disclosed.
        self.private_template.clear();
    }

    fn take_reserved(
        &mut self,
        state: &State,
        count: usize,
        private: bool,
    ) -> Result<Vec<Padding>, FillError> {
        if count > MAX_SLOTS {
            return Err(FillError::Limit);
        }
        if private && !self.private_template.is_empty() {
            return Err(FillError::PrivateTemplateActive);
        }
        self.prune(state).map_err(|_| FillError::Network)?;
        if self.entries.len() < count {
            return Err(FillError::Insufficient { required: count });
        }
        if self
            .consumed
            .len()
            .checked_add(count)
            .is_none_or(|n| n > MAX_CONSUMED)
        {
            return Err(FillError::ReservationsExhausted);
        }
        let ids: Vec<_> = self.entries.keys().take(count).copied().collect();
        if private {
            self.private_template.extend(&ids);
        }
        let mut selected = Vec::with_capacity(count);
        for id in ids {
            let entry = self
                .entries
                .remove(&id)
                .expect("selected private queue entry");
            for nf in entry.inputs {
                self.inputs.remove(&nf);
            }
            for cm in entry.outputs {
                self.outputs.remove(&cm);
            }
            self.bytes -= entry.bytes;
            self.consumed.insert(
                id,
                Consumed {
                    inputs: entry.inputs,
                    outputs: entry.outputs,
                },
            );
            selected.push(entry.value);
        }
        Ok(selected)
    }
}
#[cfg(test)]
mod tests;
