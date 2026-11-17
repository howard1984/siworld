//! Candidate-scoped early native verification of authenticated transaction slots.
//!
//! Receipts only avoid repeating an identical cryptographic check. Canonical
//! snapshot membership, nullifiers, outputs, governance, fees, settlement,
//! complete state execution and durable publication remain the normal owner path.

use super::{
    execution::Engine,
    header::Header,
    propagation::{
        framing::{self, Slot},
        pipeline::Transfer,
    },
};
use crate::{
    p2p,
    proofs::NativeVerifier,
    state::TransactionProof,
    verification_executor,
    wire::{DigestBytes, Hash},
};
use native::codec::{ProofContext, PublicTransaction, decode_digest, encode_digest};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};

const STACK_BYTES: usize = 2 * 1024 * 1024;
const TASK_OVERHEAD_BYTES: usize = 64 * 1024;
const MAX_PENDING: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Context,
    Framing,
    Deadline,
    Resources,
}

#[derive(Clone, PartialEq, Eq)]
struct Binding {
    network: Hash,
    genesis: Hash,
    rules: Hash,
    profile: Hash,
    parent: Hash,
    height: u64,
}

/// Captured under the mutable owner, then used without holding its lock.
#[derive(Clone)]
pub(crate) struct Capture {
    binding: Binding,
    roots: Arc<Vec<((u64, Hash), DigestBytes)>>,
    _roots_charge: Arc<p2p::Reservation>,
    verifier: Arc<NativeVerifier>,
    policy: super::body::Policy,
    invalidated: Arc<AtomicBool>,
}

impl Capture {
    pub(crate) fn new(
        engine: &Engine,
        verifier: Arc<NativeVerifier>,
        budget: &p2p::Budget,
        invalidated: Arc<AtomicBool>,
    ) -> Result<Self, Error> {
        if !verifier.authenticates(engine.genesis()) {
            return Err(Error::Context);
        }
        let state = engine.state();
        let count = state.chain().snapshots.len();
        let charge = count
            .checked_mul(256)
            .and_then(|value| value.checked_add(1024))
            .ok_or(Error::Resources)?;
        let roots_charge = budget.reserve(charge).map_err(|_| Error::Resources)?;
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(count)
            .map_err(|_| Error::Resources)?;
        roots.extend(state.chain().snapshots.iter().map(|snapshot| {
            (
                (snapshot.selector.height, snapshot.selector.block_id),
                snapshot.recent_root,
            )
        }));
        Ok(Self {
            binding: Binding {
                network: state.network(),
                genesis: engine.genesis().id(),
                rules: engine.genesis().rules_commitment(),
                profile: engine.body_policy().profile,
                parent: state.tip(),
                height: state.height().checked_add(1).ok_or(Error::Context)?,
            },
            roots: Arc::new(roots),
            _roots_charge: Arc::new(roots_charge),
            verifier,
            policy: engine.body_policy(),
            invalidated,
        })
    }

    fn root(&self, selector: (u64, Hash)) -> Option<&DigestBytes> {
        self.roots
            .iter()
            .rev()
            .find(|(key, _)| *key == selector)
            .map(|(_, root)| root)
    }

    pub(crate) fn start(
        &self,
        header: &Header,
        budget: &p2p::Budget,
        deadline: &p2p::Deadline,
    ) -> Result<Arc<Pipeline>, Error> {
        if header.network != self.binding.network
            || header.parent != self.binding.parent
            || header.height != self.binding.height
        {
            return Err(Error::Context);
        }
        if self.invalidated.load(Ordering::Acquire) {
            return Err(Error::Context);
        }
        deadline.check().map_err(|_| Error::Deadline)?;
        Ok(Arc::new(Pipeline {
            capture: self.clone(),
            header: header.clone(),
            id: header.id().map_err(|_| Error::Context)?,
            budget: budget.clone(),
            deadline: deadline.clone(),
            _metadata: Arc::new(budget.reserve(65_536).map_err(|_| Error::Resources)?),
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            closed: AtomicBool::new(false),
        }))
    }
}

#[derive(Default)]
struct State {
    slots: Option<usize>,
    layout: Vec<Slot>,
    submitted: Vec<bool>,
    receipts: Vec<Option<Receipt>>,
    pending: usize,
    completed: usize,
}

pub(crate) struct Pipeline {
    capture: Capture,
    header: Header,
    id: Hash,
    budget: p2p::Budget,
    deadline: p2p::Deadline,
    state: Mutex<State>,
    changed: Condvar,
    closed: AtomicBool,
    _metadata: Arc<p2p::Reservation>,
}

/// This token cannot be constructed from a caller-supplied success flag.
struct Receipt {
    key: Hash,
}

pub(crate) struct CandidateReceipts {
    binding: Binding,
    block: Hash,
    slots: Vec<Option<Receipt>>,
    _metadata: Arc<p2p::Reservation>,
    invalidated: Arc<AtomicBool>,
}

impl CandidateReceipts {
    pub(crate) fn matches_engine(&self, engine: &Engine, header: &Header) -> bool {
        let state = engine.state();
        !self.invalidated.load(Ordering::Acquire)
            && self.binding
                == (Binding {
                    network: state.network(),
                    genesis: engine.genesis().id(),
                    rules: engine.genesis().rules_commitment(),
                    profile: engine.body_policy().profile,
                    parent: state.tip(),
                    height: state.height().checked_add(1).unwrap_or(0),
                })
            && header.network == self.binding.network
            && header.parent == self.binding.parent
            && header.height == self.binding.height
            && header.id().ok() == Some(self.block)
    }

    pub(crate) fn matches(&self, ordinal: usize, proof: &TransactionProof<'_>) -> bool {
        self.slots
            .get(ordinal)
            .and_then(Option::as_ref)
            .is_some_and(|receipt| receipt.key == proof_key(proof))
    }
}

fn proof_key(proof: &TransactionProof<'_>) -> Hash {
    let mut hasher =
        blake3::Hasher::new_derive_key("siworld exact native transaction verification receipt v1");
    hasher.update(&proof.context.network);
    hasher.update(&proof.context.version().to_le_bytes());
    match proof.context.snapshot() {
        Some((height, id)) => {
            hasher.update(&[1]);
            hasher.update(&height.to_le_bytes());
            hasher.update(&id);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&proof.public.encode());
    hasher.update(&encode_digest(&proof.fee));
    hasher.update(&encode_digest(&proof.root));
    hasher.update(&(proof.proof.len() as u64).to_le_bytes());
    hasher.update(proof.proof);
    *hasher.finalize().as_bytes()
}

impl Pipeline {
    #[cfg(test)]
    pub(crate) fn test_counts(&self) -> (usize, usize, usize) {
        let state = self.state.lock().unwrap();
        (
            state.pending,
            state.completed,
            state
                .receipts
                .iter()
                .filter(|receipt| receipt.is_some())
                .count(),
        )
    }
    /// Nonblocking observer. Only immutable authenticated envelope bytes are
    /// copied. A busy shared verifier returns backpressure before any spawn.
    pub(crate) fn observe(self: &Arc<Self>, transfer: &Transfer) -> Result<(), Error> {
        if self.capture.invalidated.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            return Err(Error::Context);
        }
        self.deadline.check().map_err(|_| Error::Deadline)?;
        let mut state = self.state.lock().map_err(|_| Error::Resources)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Context);
        }
        if state.slots.is_none() {
            let layout = match framing::inspect(transfer, &self.header, self.capture.policy) {
                Ok(layout) => layout,
                Err(framing::Error::NeedPiece(_)) => return Ok(()),
                Err(_) => return Err(Error::Framing),
            };
            let metadata = layout
                .slots
                .len()
                .checked_mul(
                    std::mem::size_of::<Slot>() + std::mem::size_of::<Option<Receipt>>() + 1,
                )
                .and_then(|value| value.checked_add(std::mem::size_of::<State>()))
                .ok_or(Error::Resources)?;
            if metadata > 65_536 {
                return Err(Error::Resources);
            }
            state.slots = Some(layout.slots.len());
            state.submitted.resize(layout.slots.len(), false);
            state.receipts.resize_with(layout.slots.len(), || None);
            state.layout = layout.slots;
        }
        if transfer.block() != self.id {
            return Err(Error::Context);
        }
        for index in 0..state.layout.len() {
            let slot = state.layout[index].clone();
            if state.pending >= MAX_PENDING {
                break;
            }
            let ordinal = slot.ordinal();
            if state.submitted[ordinal] {
                continue;
            }
            let envelope = match slot.envelope(transfer) {
                Ok(bytes) => bytes,
                Err(framing::Error::NeedPiece(_)) => continue,
                Err(_) => return Err(Error::Framing),
            };
            // Malformed transaction statements remain an ordinary final native
            // rejection; no invalid body can obtain a successful receipt.
            let (record, _) =
                match crate::wire::borrowed_envelope(envelope, &self.capture.binding.network) {
                    Ok(value) => value,
                    Err(_) => {
                        state.submitted[ordinal] = true;
                        state.completed += 1;
                        continue;
                    }
                };
            if self
                .capture
                .root((record.snapshot.height, record.snapshot.block_id))
                .is_none()
            {
                state.submitted[ordinal] = true;
                state.completed += 1;
                continue;
            }
            let Some(permit) = verification_executor::try_acquire() else {
                break;
            };
            let charge = envelope
                .len()
                .checked_add(STACK_BYTES)
                .and_then(|value| value.checked_add(TASK_OVERHEAD_BYTES))
                .ok_or(Error::Resources)?;
            let reservation = self.budget.reserve(charge).map_err(|_| Error::Resources)?;
            let mut copied = Vec::new();
            copied
                .try_reserve_exact(envelope.len())
                .map_err(|_| Error::Resources)?;
            copied.extend_from_slice(envelope);
            let pipeline = Arc::clone(self);
            state.submitted[ordinal] = true;
            state.pending += 1;
            let spawned = std::thread::Builder::new()
                .name("native-slot-verification".into())
                .stack_size(STACK_BYTES)
                .spawn(move || {
                    let _reservation = reservation;
                    let receipt = pipeline.verify(slot, &copied, permit);
                    if let Ok(mut state) = pipeline.state.lock() {
                        state.pending = state.pending.saturating_sub(1);
                        state.completed += 1;
                        if pipeline.deadline.check().is_ok()
                            && !pipeline.capture.invalidated.load(Ordering::Acquire)
                            && !pipeline.closed.load(Ordering::Acquire)
                        {
                            state.receipts[ordinal] = receipt;
                        }
                        pipeline.changed.notify_all();
                    }
                });
            if spawned.is_err() {
                // A failed spawn drops its captured permit and reservation.
                state.pending -= 1;
                state.submitted[ordinal] = false;
                return Err(Error::Resources);
            }
        }
        Ok(())
    }

    fn verify(
        &self,
        slot: Slot,
        envelope: &[u8],
        permit: verification_executor::Permit,
    ) -> Option<Receipt> {
        if slot.block() != self.id || self.deadline.check().is_err() {
            return None;
        }
        self.verify_envelope(envelope, permit)
    }

    fn verify_envelope(
        &self,
        envelope: &[u8],
        permit: verification_executor::Permit,
    ) -> Option<Receipt> {
        if self.deadline.check().is_err()
            || self.capture.invalidated.load(Ordering::Acquire)
            || self.closed.load(Ordering::Acquire)
        {
            return None;
        }
        let (record, proof) =
            crate::wire::borrowed_envelope(envelope, &self.capture.binding.network).ok()?;
        let root = decode_digest(
            self.capture
                .root((record.snapshot.height, record.snapshot.block_id))?,
        )
        .ok()?;
        let public = PublicTransaction::decode(&record.body).ok()?;
        let fee = decode_digest(&record.fee_commit).ok()?;
        let context = ProofContext::for_snapshot(
            self.capture.binding.network,
            record.snapshot.height,
            record.snapshot.block_id,
        );
        let _permit = permit;
        self.capture
            .verifier
            .verify_transaction(&public, &context, &fee, &root, proof)
            .ok()?;
        if self.deadline.check().is_err()
            || self.capture.invalidated.load(Ordering::Acquire)
            || self.closed.load(Ordering::Acquire)
        {
            return None;
        }
        Some(Receipt {
            key: proof_key(&TransactionProof {
                public,
                context,
                fee,
                root,
                proof,
            }),
        })
    }

    /// Freeze only completed early receipts. This method never waits for a
    /// verifier permit, starts another job or blocks the body lane on proofs.
    /// Missing receipts retain the ordinary complete final verification path.
    pub(crate) fn finish(
        self: &Arc<Self>,
        transfer: &Transfer,
    ) -> Result<CandidateReceipts, Error> {
        self.deadline.check().map_err(|_| Error::Deadline)?;
        if transfer.block() != self.id || self.capture.invalidated.load(Ordering::Acquire) {
            return Err(Error::Context);
        }
        self.closed.store(true, Ordering::Release);
        let mut state = self.state.lock().map_err(|_| Error::Resources)?;
        Ok(CandidateReceipts {
            binding: self.capture.binding.clone(),
            block: self.id,
            slots: std::mem::take(&mut state.receipts),
            _metadata: Arc::clone(&self._metadata),
            invalidated: Arc::clone(&self.capture.invalidated),
        })
    }
}

#[cfg(test)]
mod tests;

/// Synthetic control-flow receipts for final-gate regression tests only.
/// Production receipts have no constructor other than actual native success.
#[cfg(test)]
pub(crate) fn final_gate_test_receipts(
    engine: &Engine,
    header: &Header,
    body: &super::body::Body,
) -> CandidateReceipts {
    let budget = p2p::Budget::new(65_536);
    let slots = body
        .transactions
        .iter()
        .map(|transaction| {
            let snapshot = engine
                .state()
                .chain()
                .snapshot(transaction.record.snapshot)
                .unwrap();
            Some(Receipt {
                key: proof_key(&TransactionProof {
                    public: PublicTransaction::decode(&transaction.record.body).unwrap(),
                    context: ProofContext::for_snapshot(
                        body.network,
                        snapshot.selector.height,
                        snapshot.selector.block_id,
                    ),
                    fee: decode_digest(&transaction.record.fee_commit).unwrap(),
                    root: decode_digest(&snapshot.recent_root).unwrap(),
                    proof: &transaction.proof,
                }),
            })
        })
        .collect();
    CandidateReceipts {
        binding: Binding {
            network: engine.state().network(),
            genesis: engine.genesis().id(),
            rules: engine.genesis().rules_commitment(),
            profile: engine.body_policy().profile,
            parent: engine.state().tip(),
            height: engine.state().height() + 1,
        },
        block: header.id().unwrap(),
        slots,
        _metadata: Arc::new(budget.reserve(65_536).unwrap()),
        invalidated: Arc::new(AtomicBool::new(false)),
    }
}

#[cfg(all(test, unix, feature = "eng2-rehearsal"))]
mod joint_reorganization_tests;
