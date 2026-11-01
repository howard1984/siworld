//! Native admission, verified-work synchronization and production composition.
//! This module never starts a listener or supplies an authentication provider.
use crate::admission::{AdmissionError, Mempool, PeerId};
use crate::chain::{BranchOutcome, CandidatePolicy, ChainError};
use crate::p2p::{self, Budget, Packet, Reservation, Session};
use crate::pool::Pool;
use crate::producer::{self, ProducedBlock};
use crate::proofs::NativeProver;
use crate::state::{BlockVerifier, State};
use crate::store::Store;
use crate::sync::{self, Batch, CompactBlock, Locator, Reference, Staging};
use crate::wire::{
    Block, GROUP, Hash, MAX_BLOCK_BYTES, MAX_ENVELOPE_BYTES, MAX_SLOTS, MIN_SLOTS, SIDECAR_BYTES,
    Sidecar, Snapshot, TX_PREFIX_BYTES, Transaction,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

// A canonical ID lookup currently decodes one complete stored proof block.
#[cfg(feature = "native-p2p")]
pub(crate) mod resident;

const BLOCK_LOOKUP_BYTES: usize = MAX_BLOCK_BYTES + 65_536;
fn transaction_has_output(tx: &Transaction, commitment: &crate::wire::DigestBytes) -> bool {
    native::codec::PublicTransaction::decode(&tx.record.body).is_ok_and(|p| {
        p.cm.iter()
            .any(|c| native::codec::encode_digest(c) == *commitment)
    })
}
/// A transport timeout or explicit temporary refusal can be retried only on
/// a fresh authenticated session. Protocol mismatches are never retried.
pub const MAX_COMPACT_RELAY_ATTEMPTS: u8 = 3;
const COMPACT_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug)]
pub enum Error {
    Transport(p2p::Error),
    Admission(AdmissionError),
    Chain(ChainError),
    Local(String),
}
impl From<p2p::Error> for Error {
    fn from(e: p2p::Error) -> Self {
        Self::Transport(e)
    }
}
impl From<AdmissionError> for Error {
    fn from(e: AdmissionError) -> Self {
        Self::Admission(e)
    }
}
impl From<ChainError> for Error {
    fn from(e: ChainError) -> Self {
        Self::Chain(e)
    }
}
impl From<String> for Error {
    fn from(e: String) -> Self {
        Self::Local(e)
    }
}
fn invalid() -> Error {
    Error::Transport(p2p::Error::InvalidProtocol)
}

/// A move-only authorization for work prepared from one canonical node state.
/// Capture this before handing a state snapshot to a worker. It grants no proof
/// or consensus bypass and cannot be used after adoption or owner restart.
pub struct ProductionPermit {
    owner: Arc<()>,
    generation: u64,
    fingerprint: Hash,
}

/// A move-only production result bound to one node and its preparation state.
/// Mining may change the nonce and timestamp; the common transition still checks
/// every resulting field and proof when the candidate is committed.
pub struct PreparedBlock {
    produced: ProducedBlock,
    owner: Arc<()>,
    generation: u64,
    fingerprint: Hash,
}
impl PreparedBlock {
    pub fn block(&self) -> &Block {
        &self.produced.block
    }
    pub fn block_mut(&mut self) -> &mut Block {
        &mut self.produced.block
    }
}

pub struct Node<V> {
    store: Store,
    verifier: V,
    mempool: Mempool,
    padding: Pool,
    budget: Budget,
    pending_issuances: std::collections::BTreeMap<Hash, crate::issuance::IssuanceRecord>,
    production_owner: Arc<()>,
    production_generation: u64,
}
impl<V: BlockVerifier> Node<V> {
    pub fn new(store: Store, verifier: V) -> Self {
        let network = store.state().config.network;
        Self {
            store,
            verifier,
            mempool: Mempool::new(network),
            padding: Pool::new(network),
            budget: Budget::default(),
            pending_issuances: std::collections::BTreeMap::new(),
            production_owner: Arc::new(()),
            production_generation: 0,
        }
    }
    pub fn state(&self) -> &State {
        self.store.state()
    }
    pub fn store(&self) -> &Store {
        &self.store
    }
    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }
    /// Supply clones of this one budget to every node session.
    pub fn transport_budget(&self) -> Budget {
        self.budget.clone()
    }
    pub fn binding(&self) -> p2p::Binding {
        p2p::Binding::new(&self.state().config)
    }
    /// Trusted local wallet ingress has the same verification and bounded quota
    /// as one remote identity. It does not infer a local bypass for proofs.
    pub fn submit_local(
        &mut self,
        envelope: &[u8],
        sidecar: Option<&[u8]>,
    ) -> Result<Hash, AdmissionError> {
        let peer = PeerId(blake3::derive_key(
            "siworld native local admission identity v1",
            &self.state().config.network,
        ));
        self.mempool
            .submit_encoded(self.store.state(), peer, envelope, sidecar, &self.verifier)
    }
    /// Bounded local RPC ingress. The caller must authenticate/authorize the
    /// local wallet before dispatch; this function does not open a listener.
    pub fn dispatch_issuance_rpc(&mut self, request: &[u8]) -> Result<Vec<u8>, Error> {
        let maximum = crate::issuance::MAX_RECORD_BYTES
            .checked_mul(2)
            .and_then(|n| n.checked_add(128))
            .ok_or_else(invalid)?;
        if request.len() > maximum {
            return Err(invalid());
        }
        let value: serde_json::Value = serde_json::from_slice(request).map_err(|_| invalid())?;
        let object = value.as_object().ok_or_else(invalid)?;
        if object.len() != 2 || value["method"] != "submitissuance" {
            return Err(invalid());
        }
        let text = value["record"].as_str().ok_or_else(invalid)?;
        if text.len() > crate::issuance::MAX_RECORD_BYTES * 2 || !text.len().is_multiple_of(2) {
            return Err(invalid());
        }
        let digit = |value: u8| match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        };
        let bytes: Vec<u8> = text
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| Some((digit(p[0])? << 4) | digit(p[1])?))
            .collect::<Option<_>>()
            .ok_or_else(invalid)?;
        let id = self.submit_issuance(&bytes)?;
        serde_json::to_vec(
            &serde_json::json!({"accepted":true,"declaration":crate::local::hex(&id)}),
        )
        .map_err(|_| invalid())
    }
    pub fn pending_issuance_count(&self) -> usize {
        self.pending_issuances.len()
    }
    /// A signed declaration is queued only after independent issuance proof
    /// validation and discovery of its fee output in canonical history or an
    /// admitted transaction selected for the same block.
    pub fn submit_issuance(&mut self, bytes: &[u8]) -> Result<Hash, Error> {
        let record = crate::issuance::IssuanceRecord::decode(bytes)?;
        record.validate(&self.state().config)?;
        let id = record.signed.declaration.binding();
        if let Some(pending) = self.pending_issuances.get(&id) {
            return if pending == &record {
                Ok(id)
            } else {
                Err(Error::Local("conflicting issuance retry".into()))
            };
        }
        self.state()
            .height
            .checked_add(1)
            .ok_or_else(|| Error::Local("issuance height exhausted".into()))?;
        let policy = self.state().config.issuance.as_ref().ok_or_else(invalid)?;
        if self.pending_issuances.len() >= usize::from(policy.max_per_block) {
            return Err(p2p::Error::ResourceExhausted.into());
        }
        let has_fee = self.state().commitments.contains(&record.fee_commitment)
            || self.mempool.ids().iter().any(|id| {
                self.mempool
                    .transaction(id)
                    .is_some_and(|tx| transaction_has_output(tx, &record.fee_commitment))
            });
        if !has_fee {
            return Err(Error::Local(
                "issuance fee output is not in canonical history or an admitted transaction".into(),
            ));
        }
        self.state().assets.check_available(&record)?;
        let declaration = &record.signed.declaration;
        for pending in self.pending_issuances.values() {
            let prior = &pending.signed.declaration;
            if prior.asset_id == declaration.asset_id
                || (prior.issuer_key == declaration.issuer_key
                    && prior.sequence == declaration.sequence)
                || pending.fee_commitment == record.fee_commitment
            {
                return Err(Error::Local("issuance reservation conflicts".into()));
            }
        }
        for commitment in &record.signed.declaration.note_commitments {
            let cm = native::codec::encode_digest(commitment);
            if self.state().commitments.contains(&cm)
                || self
                    .pending_issuances
                    .values()
                    .any(|p| p.signed.declaration.note_commitments.contains(commitment))
            {
                return Err(Error::Local("issuance output is already reserved".into()));
            }
        }
        self.verifier.issuance(&record)?;
        let id = record.signed.declaration.binding();
        self.pending_issuances.insert(id, record);
        Ok(id)
    }
    fn reconcile_pools(&mut self) -> Result<(), Error> {
        self.mempool.prune(self.store.state())?;
        self.padding.prune(self.store.state())?;
        let state = self.store.state();
        let mempool = &self.mempool;
        self.pending_issuances.retain(|_, r| {
            state.assets.check_available(r).is_ok()
                && (state.commitments.contains(&r.fee_commitment)
                    || mempool.ids().iter().any(|id| {
                        mempool
                            .transaction(id)
                            .is_some_and(|tx| transaction_has_output(tx, &r.fee_commitment))
                    }))
        });
        Ok(())
    }
    pub fn import_branch(
        &mut self,
        ancestor: u64,
        blocks: &[Block],
        policy: CandidatePolicy,
    ) -> Result<BranchOutcome, Error> {
        let next_generation = self
            .production_generation
            .checked_add(1)
            .ok_or_else(|| Error::Local("production generation exhausted".into()))?;
        let result = self
            .store
            .consider_branch(ancestor, blocks, policy, &self.verifier)?;
        if matches!(result, BranchOutcome::Adopted { .. }) {
            self.production_generation = next_generation;
            self.reconcile_pools()?;
        }
        Ok(result)
    }
    /// Reserve the identity of the current canonical state before asynchronous
    /// proof generation or work search. The node remains the sole store owner.
    pub fn begin_production(&self) -> Result<ProductionPermit, Error> {
        self.production_generation
            .checked_add(1)
            .ok_or_else(|| Error::Local("production generation exhausted".into()))?;
        Ok(ProductionPermit {
            owner: Arc::clone(&self.production_owner),
            generation: self.production_generation,
            fingerprint: self.state().fingerprint(),
        })
    }
    /// Bind completed worker output only to the state for which work began.
    /// The returned move-only result still requires the common verified commit.
    pub fn bind_produced(
        &self,
        permit: ProductionPermit,
        produced: ProducedBlock,
    ) -> Result<PreparedBlock, Error> {
        if !Arc::ptr_eq(&self.production_owner, &permit.owner)
            || permit.generation != self.production_generation
            || permit.fingerprint != self.state().fingerprint()
            || produced.block.network != self.state().config.network
            || produced.block.parent != self.state().tip
            || self.state().height.checked_add(1) != Some(produced.block.height)
        {
            return Err(Error::Local("stale or foreign production result".into()));
        }
        Ok(PreparedBlock {
            produced,
            owner: permit.owner,
            generation: permit.generation,
            fingerprint: permit.fingerprint,
        })
    }
    /// Preserve the authenticated recovery receipt before the durable common
    /// state transition. Receipt storage is bound to this store's opened parent
    /// directory and database identity; callers cannot redirect it elsewhere.
    /// An append failure preserves the receipt as evidence and leaves the head
    /// unchanged. An identical durable receipt can be reused after interrupted
    /// append; partial or conflicting evidence is never overwritten. Neither
    /// this method nor a preparation token bypasses proofs.
    pub fn commit_produced(&mut self, prepared: PreparedBlock) -> Result<Hash, Error> {
        if !Arc::ptr_eq(&self.production_owner, &prepared.owner)
            || prepared.generation != self.production_generation
            || prepared.fingerprint != self.state().fingerprint()
            || prepared.produced.block.parent != self.state().tip
            || self.state().height.checked_add(1) != Some(prepared.produced.block.height)
        {
            return Err(Error::Local("stale or foreign production result".into()));
        }
        let next_generation = self
            .production_generation
            .checked_add(1)
            .ok_or_else(|| Error::Local("production generation exhausted".into()))?;
        let produced = prepared.produced;
        producer::validate_reward_secret(&produced.block, &produced.reward_secret)?;
        let id = produced.block.id()?;
        self.store
            .save_reward_receipt(&id, &produced.reward_secret)?;
        self.store
            .append_produced(&produced.block, &produced.reward_secret, &self.verifier)?;
        self.production_generation = next_generation;
        self.reconcile_pools()?;
        Ok(id)
    }
    /// Select already verified pending inputs for an off-thread producer.
    /// Private fee openings stay in this local work item; originals remain
    /// reserved until canonical inclusion and stale work never removes them.
    pub fn select_pending(&mut self, slots: usize) -> Result<Vec<crate::pool::Padding>, Error> {
        if !(MIN_SLOTS..=MAX_SLOTS).contains(&slots) || !slots.is_multiple_of(GROUP) {
            return Err(invalid());
        }
        self.reconcile_pools()?;
        self.mempool
            .select(self.store.state(), slots)
            .map_err(Into::into)
    }

    pub fn precompute_one(&mut self, prover: &NativeProver) -> Result<(), Error> {
        self.padding.prune(self.store.state())?;
        if !self.padding.can_grow() {
            return Err(Error::Transport(p2p::Error::ResourceExhausted));
        }
        let value = producer::prepare_padding(self.store.state(), prover)?;
        self.padding
            .insert(self.store.state(), value, &self.verifier)?;
        Ok(())
    }
    /// Real pending entries remain reserved until canonical inclusion. A failed
    /// candidate can consume padding reservations but never deletes wallet work.
    /// Commit with `commit_produced` after the work search completes. The recovery
    /// receipt remains private inside the move-only preparation result.
    pub fn prepare_block(
        &mut self,
        prover: &NativeProver,
        slots: usize,
        timestamp: u64,
        settings: &producer::MiningSettings,
    ) -> Result<PreparedBlock, Error> {
        if !(MIN_SLOTS..=MAX_SLOTS).contains(&slots) || !slots.is_multiple_of(GROUP) {
            return Err(invalid());
        }
        self.reconcile_pools()?;
        let permit = self.begin_production()?;
        let mut values = self.mempool.select(self.store.state(), slots)?;
        let remaining = slots - values.len();
        values.extend(self.padding.take_for_fill(self.store.state(), remaining)?);
        let mut produced =
            producer::assemble(self.store.state(), prover, values, timestamp, settings)?;
        produced.block.issuances = self
            .pending_issuances
            .values()
            .filter(|r| {
                self.store.state().commitments.contains(&r.fee_commitment)
                    || produced
                        .block
                        .transactions
                        .iter()
                        .any(|tx| transaction_has_output(tx, &r.fee_commitment))
            })
            .cloned()
            .collect();
        produced.block.validate_shape()?;
        self.bind_produced(permit, produced)
    }
    fn session<S>(&self, session: &Session<S>) -> Result<(), Error>
    where
        S: Read + Write,
    {
        if !session.shares_budget(&self.budget) || session.binding() != self.binding() {
            return Err(invalid());
        }
        Ok(())
    }
    /// Serve one authenticated request. Framing or I/O errors require dropping
    /// the session. Branch announcements are fully verified or request retry.
    pub fn serve_once<S: Read + Write>(&mut self, session: &mut Session<S>) -> Result<(), Error> {
        self.session(session)?;
        match session.receive()? {
            Packet::Control {
                kind,
                request,
                body,
                reservation,
            } => {
                let _guard = reservation;
                match kind {
                    p2p::GET_BLOCKS => {
                        // Locator resolution also decodes stored proof blocks.
                        // Reserve before any lookup, including ancestor matching.
                        // Leave bounded control-frame space while streaming replies.
                        let allowance = self
                            .budget
                            .available()?
                            .saturating_sub(p2p::MAX_CONTROL_BYTES + 65536);
                        if allowance < BLOCK_LOOKUP_BYTES {
                            return Err(p2p::Error::ResourceExhausted.into());
                        }
                        let batch_reservation = self.budget.reserve(allowance)?;
                        let (ancestor, after) = decode_request(&body, &self.store)?;
                        let batch = match sync::serve_batch(
                            &self.store,
                            ancestor,
                            after,
                            sync::MAX_BATCH_BLOCKS,
                            allowance.saturating_sub(65536),
                        ) {
                            Ok(b) => b,
                            Err(_) => {
                                session.send_control(p2p::UNAVAILABLE, request, &[])?;
                                return Ok(());
                            }
                        };
                        let meta = BatchMeta {
                            ancestor,
                            after,
                            count: batch.blocks.len() as u16,
                            more: batch.more,
                        };
                        session.send_control(p2p::SYNC_META, request, &meta.encode())?;
                        for block in &batch.blocks {
                            session.send_reserved_block(request, block, &batch_reservation)?;
                        }
                        session.send_control(p2p::END_BATCH, request, &[])?;
                    }
                    p2p::TRANSACTION => {
                        let (envelope, sidecar) = decode_gossip(&body)?;
                        self.mempool.submit_encoded(
                            self.store.state(),
                            PeerId(session.peer()),
                            envelope,
                            Some(sidecar),
                            &self.verifier,
                        )?;
                    }
                    p2p::GET_TRANSACTIONS => {
                        let references = decode_references(&body)?;
                        for r in references {
                            let Some(tx) = self.mempool.transaction(&r.statement).filter(|tx| {
                                sync::reference(tx, &self.state().config.network) == r
                            }) else {
                                session.send_control(p2p::UNAVAILABLE, request, &[])?;
                                return Ok(());
                            };
                            let _copy_guard = self.budget.reserve(MAX_ENVELOPE_BYTES + 64)?;
                            let envelope = tx.encode_envelope(&self.state().config.network)?;
                            session.send_control(p2p::TRANSACTION, request, &envelope)?;
                        }
                        session.send_control(p2p::END_BATCH, request, &[])?;
                    }
                    p2p::COMPACT_BLOCK => {
                        let _compact_copy = self.budget.reserve(
                            body.len()
                                .checked_add(65536)
                                .ok_or(p2p::Error::ResourceExhausted)?,
                        )?;
                        let compact = CompactBlock::decode(&body, &self.state().config.network)
                            .map_err(|_| invalid())?;
                        // Public references arrive first. Resolve exact local
                        // proof bytes, request every missing batch, reconstruct
                        // the committed block and only then run its common
                        // state transition. No fee opening is requested here.
                        self.receive_compact(session, request, compact)?;
                    }
                    _ => return Err(invalid()),
                }
                Ok(())
            }
            Packet::Block {
                block, reservation, ..
            } => {
                let _guard = reservation;
                self.import_extension(&block)
            }
        }
    }
    fn import_extension(&mut self, block: &Block) -> Result<(), Error> {
        if block.parent != self.state().tip {
            return Err(Error::Transport(p2p::Error::Unavailable));
        }
        self.import_branch(
            self.state().height,
            std::slice::from_ref(block),
            CandidatePolicy::default(),
        )?;
        Ok(())
    }

    fn receive_compact<S: Read + Write>(
        &mut self,
        session: &mut Session<S>,
        request: u64,
        compact: CompactBlock,
    ) -> Result<(), Error> {
        if compact.expected_id == self.state().tip {
            // A lost acknowledgement is safe to retry only when every byte of
            // the skeleton matches the accepted block. An attacker cannot get
            // an acknowledgement merely by copying the known tip identity.
            let _lookup = self.budget.reserve(BLOCK_LOOKUP_BYTES)?;
            let accepted = self.store.block(self.state().height)?;
            if !compact.matches_block(&accepted).map_err(|_| invalid())? {
                return Err(invalid());
            }
            session.send_control(p2p::END_BATCH, request, &compact.expected_id)?;
            return Ok(());
        }
        if compact.parent != self.state().tip
            || self.state().height.checked_add(1) != Some(compact.height)
        {
            session.send_control(p2p::UNAVAILABLE, request, &[])?;
            return Ok(());
        }
        // Account separately for local proof copies and recovered envelopes.
        // Recovered transactions are moved into the block, not copied into a
        // second full-block buffer. Each guard survives through import.
        let structural_bytes = compact.issuances.iter().try_fold(
            compact.settlement.len().saturating_add(65_536),
            |total, issuance| {
                total
                    .checked_add(issuance.encoded_len()?)
                    .ok_or_else(|| "compact owned-byte overflow".to_owned())
            },
        )?;
        let local_bytes = compact
            .references
            .iter()
            .try_fold(structural_bytes, |total, r| {
                let extra = self
                    .mempool
                    .transaction(&r.statement)
                    .filter(|tx| sync::reference(tx, &compact.network) == *r)
                    .map_or(0, |tx| TX_PREFIX_BYTES + tx.proof.len() + 64);
                total
                    .checked_add(extra)
                    .ok_or(p2p::Error::ResourceExhausted)
            })?;
        let _local = self.budget.reserve(local_bytes)?;
        let mut transactions = BTreeMap::new();
        for r in &compact.references {
            if let Some(transaction) = self
                .mempool
                .transaction(&r.statement)
                .filter(|tx| sync::reference(tx, &compact.network) == *r)
            {
                transactions.insert(r.statement, transaction.clone());
            }
        }
        let mut recovered_guards = Vec::new();
        let deadline = p2p::Deadline::new(COMPACT_EXCHANGE_TIMEOUT);
        loop {
            let missing = compact.missing_request(|r| transactions.contains_key(&r.statement));
            if missing.is_empty() {
                break;
            }
            let recovered = self.fetch_missing_before(session, request, &missing, &deadline)?;
            for transaction in recovered.transactions {
                let statement = transaction.record.statement_id(&compact.network);
                if transactions.insert(statement, transaction).is_some() {
                    return Err(invalid());
                }
            }
            recovered_guards.extend(recovered._reservations);
        }
        let block = compact
            .reconstruct(|r| transactions.remove(&r.statement))
            .map_err(|_| invalid())?;
        self.import_extension(&block)?;
        session.send_control(p2p::END_BATCH, request, &compact.expected_id)?;
        // Guards include every recovered proof until validation, persistence
        // and the acknowledgement finish. They then release together.
        drop(recovered_guards);
        Ok(())
    }

    /// Announces only a compact skeleton, then answers bounded requests for
    /// the missing public statements and exact proof bytes. The owned block
    /// supplies dummy and confirmed transactions even after pool pruning.
    /// A successful return requires the receiver's committed block identity.
    pub fn announce_compact<S: Read + Write>(
        &self,
        session: &mut Session<S>,
        request: u64,
        block: &Block,
    ) -> Result<(), Error> {
        self.session(session)?;
        if block.network != self.state().config.network {
            return Err(invalid());
        }
        let _compact_guard = self.budget.reserve(p2p::MAX_COMPACT_BYTES * 2 + 65_536)?;
        let compact = CompactBlock::from_block(block)?;
        let encoded = compact.encode()?;
        session.send_control(p2p::COMPACT_BLOCK, request, &encoded)?;
        let mut requested = BTreeSet::new();
        let deadline = p2p::Deadline::new(COMPACT_EXCHANGE_TIMEOUT);
        // At most one request per transaction plus its acknowledgement. A
        // peer cannot prolong the exchange with repeated or unrelated IDs.
        for _ in 0..=compact.references.len() {
            match session.receive_before(&deadline)? {
                Packet::Control {
                    kind: p2p::GET_TRANSACTIONS,
                    request: r,
                    body,
                    reservation,
                } if r == request => {
                    let _request_guard = reservation;
                    let references = decode_references(&body)?;
                    for reference in references {
                        if !requested.insert(reference.statement) {
                            return Err(invalid());
                        }
                        let Some(transaction) = block
                            .transactions
                            .iter()
                            .find(|tx| sync::reference(tx, &block.network) == reference)
                        else {
                            return Err(invalid());
                        };
                        let _copy_guard = self.budget.reserve(MAX_ENVELOPE_BYTES + 64)?;
                        let envelope = transaction.encode_envelope(&block.network)?;
                        session.send_control(p2p::TRANSACTION, request, &envelope)?;
                    }
                    session.send_control(p2p::END_BATCH, request, &[])?;
                }
                Packet::Control {
                    kind: p2p::END_BATCH,
                    request: r,
                    body,
                    ..
                } if r == request && body == compact.expected_id => return Ok(()),
                Packet::Control {
                    kind: p2p::UNAVAILABLE,
                    request: r,
                    body,
                    ..
                } if r == request && body.is_empty() => {
                    return Err(p2p::Error::Unavailable.into());
                }
                _ => return Err(invalid()),
            }
        }
        Err(invalid())
    }

    /// Bounded retry composition for a caller that owns connection policy and
    /// the reviewed authentication provider. A failed session is dropped before
    /// invoking the factory again. No listener, fallback transport or automatic
    /// peer selection is introduced by this API.
    pub fn announce_compact_with_retry<S: Read + Write>(
        &self,
        block: &Block,
        first_request: u64,
        attempts: u8,
        mut connect: impl FnMut() -> Result<Session<S>, Error>,
    ) -> Result<u8, Error> {
        if attempts == 0 || attempts > MAX_COMPACT_RELAY_ATTEMPTS {
            return Err(invalid());
        }
        for index in 0..attempts {
            let request = first_request
                .checked_add(u64::from(index))
                .ok_or_else(invalid)?;
            let result = match connect() {
                Ok(mut session) => self.announce_compact(&mut session, request, block),
                Err(error) => Err(error),
            };
            match result {
                Ok(()) => return Ok(index + 1),
                Err(Error::Transport(p2p::Error::Unavailable)) if index + 1 < attempts => {}
                Err(error) => return Err(error),
            }
        }
        Err(p2p::Error::Unavailable.into())
    }
    /// Pull one bounded batch. Advertised work never enters fork choice.
    /// Failure discards this attempt's uncommitted branch and reservations.
    /// A false result exhausts this peer's response; it does not establish that
    /// the local node has the globally strongest chain or a trusted checkpoint.
    pub fn synchronize<S: Read + Write>(
        &mut self,
        session: &mut Session<S>,
        request: u64,
        attempt: &mut SyncAttempt,
    ) -> Result<bool, Error> {
        let result = self.synchronize_inner(session, request, attempt);
        if result.is_err() {
            attempt.clear();
        }
        result
    }
    fn synchronize_inner<S: Read + Write>(
        &mut self,
        session: &mut Session<S>,
        request: u64,
        attempt: &mut SyncAttempt,
    ) -> Result<bool, Error> {
        self.session(session)?;
        if attempt.peer.is_some_and(|peer| peer != session.peer()) {
            return Err(invalid());
        }
        attempt.peer = Some(session.peer());
        let body = if let Some(staging) = &attempt.staging {
            encode_continue(staging.base(), staging.continuation()?)
        } else {
            let _lookup_guard = self.budget.reserve(BLOCK_LOOKUP_BYTES)?;
            let mut b = vec![0];
            b.extend(Locator::from_store(&self.store)?.encode()?);
            b
        };
        session.send_control(p2p::GET_BLOCKS, request, &body)?;
        let meta = match session.receive()? {
            Packet::Control {
                kind: p2p::SYNC_META,
                request: r,
                body,
                ..
            } if r == request => BatchMeta::decode(&body)?,
            Packet::Control {
                kind: p2p::UNAVAILABLE,
                request: r,
                ..
            } if r == request => return Err(p2p::Error::Unavailable.into()),
            _ => return Err(invalid()),
        };
        if attempt.staging.is_none() {
            if meta.after != meta.ancestor {
                return Err(invalid());
            }
            let _lookup_guard = self.budget.reserve(BLOCK_LOOKUP_BYTES)?;
            attempt.staging = Some(Staging::new(
                &self.store,
                meta.ancestor,
                CandidatePolicy::default(),
            )?);
        }
        let staging = attempt.staging.as_ref().expect("initialized staging");
        if (meta.ancestor, meta.after) != (staging.base(), staging.continuation()?) {
            return Err(invalid());
        }
        let mut blocks = Vec::with_capacity(usize::from(meta.count));
        let mut guards = Vec::with_capacity(usize::from(meta.count));
        for _ in 0..meta.count {
            match session.receive()? {
                Packet::Block {
                    request: r,
                    block,
                    reservation,
                } if r == request => {
                    blocks.push(*block);
                    guards.push(reservation);
                }
                _ => return Err(invalid()),
            }
        }
        match session.receive()? {
            Packet::Control {
                kind: p2p::END_BATCH,
                request: r,
                body,
                ..
            } if r == request && body.is_empty() => {}
            _ => return Err(invalid()),
        }
        if blocks.is_empty() {
            if meta.more {
                return Err(invalid());
            }
            attempt.clear();
            return Ok(false);
        }
        let next_generation = self
            .production_generation
            .checked_add(1)
            .ok_or_else(|| Error::Local("production generation exhausted".into()))?;
        let result = attempt
            .staging
            .as_mut()
            .expect("initialized staging")
            .accept(
                &mut self.store,
                Batch {
                    ancestor: meta.ancestor,
                    after: meta.after,
                    blocks,
                    more: meta.more,
                },
                &self.verifier,
            )?;
        if matches!(result, BranchOutcome::Adopted { .. }) {
            self.production_generation = next_generation;
            attempt.reservations.clear();
            self.reconcile_pools()?;
        } else {
            attempt.reservations.extend(guards);
        }
        if !meta.more {
            attempt.clear();
        }
        Ok(meta.more)
    }
    /// Exact-proof compact recovery; returned envelopes omit private fee openings
    /// and must never be admitted as gossip without a separately checked sidecar.
    pub fn fetch_missing<S: Read + Write>(
        &self,
        session: &mut Session<S>,
        request: u64,
        references: &[Reference],
    ) -> Result<Recovered, Error> {
        self.fetch_missing_before(
            session,
            request,
            references,
            &p2p::Deadline::new(COMPACT_EXCHANGE_TIMEOUT),
        )
    }
    fn fetch_missing_before<S: Read + Write>(
        &self,
        session: &mut Session<S>,
        request: u64,
        references: &[Reference],
        deadline: &p2p::Deadline,
    ) -> Result<Recovered, Error> {
        self.session(session)?;
        let body = encode_references(references)?;
        session.send_control(p2p::GET_TRANSACTIONS, request, &body)?;
        let mut transactions = Vec::with_capacity(references.len());
        let mut reservations = Vec::with_capacity(references.len());
        for expected in references {
            match session.receive_before(deadline)? {
                Packet::Control {
                    kind: p2p::TRANSACTION,
                    request: r,
                    body,
                    reservation,
                } if r == request => {
                    // The original packet guard covers body. Reserve the decoded
                    // proof copy before it coexists with that original buffer.
                    let _body_guard = reservation;
                    let retained = self.budget.reserve(
                        body.len()
                            .checked_add(64)
                            .ok_or(p2p::Error::ResourceExhausted)?,
                    )?;
                    let tx = Transaction::decode_envelope(&body, &self.state().config.network)
                        .map_err(|_| invalid())?;
                    if sync::reference(&tx, &self.state().config.network) != *expected {
                        return Err(invalid());
                    }
                    drop(body);
                    transactions.push(tx);
                    reservations.push(retained);
                }
                Packet::Control {
                    kind: p2p::UNAVAILABLE,
                    request: r,
                    ..
                } if r == request => return Err(p2p::Error::Unavailable.into()),
                _ => return Err(invalid()),
            }
        }
        match session.receive_before(deadline)? {
            Packet::Control {
                kind: p2p::END_BATCH,
                request: r,
                body,
                ..
            } if r == request && body.is_empty() => {}
            _ => return Err(invalid()),
        }
        Ok(Recovered {
            transactions,
            _reservations: reservations,
        })
    }
}
#[derive(Default)]
pub struct SyncAttempt {
    peer: Option<Hash>,
    staging: Option<Staging>,
    reservations: Vec<Reservation>,
}
impl SyncAttempt {
    pub fn clear(&mut self) {
        self.peer = None;
        self.staging = None;
        self.reservations.clear();
    }
}
pub struct Recovered {
    transactions: Vec<Transaction>,
    _reservations: Vec<Reservation>,
}
impl Recovered {
    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BatchMeta {
    ancestor: Snapshot,
    after: Snapshot,
    count: u16,
    more: bool,
}
fn put_snapshot(out: &mut Vec<u8>, s: Snapshot) {
    out.extend_from_slice(&s.height.to_le_bytes());
    out.extend_from_slice(&s.block_id);
}
fn snapshot(bytes: &[u8]) -> Snapshot {
    Snapshot {
        height: u64::from_le_bytes(bytes[..8].try_into().expect("bounded snapshot")),
        block_id: bytes[8..40].try_into().expect("bounded ID"),
    }
}
impl BatchMeta {
    fn encode(self) -> [u8; 83] {
        let mut out = Vec::with_capacity(83);
        put_snapshot(&mut out, self.ancestor);
        put_snapshot(&mut out, self.after);
        out.extend_from_slice(&self.count.to_le_bytes());
        out.push(u8::from(self.more));
        out.try_into().expect("fixed metadata")
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 83 || bytes[82] > 1 {
            return Err(invalid());
        }
        let count = u16::from_le_bytes(bytes[80..82].try_into().expect("fixed count"));
        if usize::from(count) > sync::MAX_BATCH_BLOCKS {
            return Err(invalid());
        }
        Ok(Self {
            ancestor: snapshot(&bytes[..40]),
            after: snapshot(&bytes[40..80]),
            count,
            more: bytes[82] == 1,
        })
    }
}
fn encode_continue(base: Snapshot, after: Snapshot) -> Vec<u8> {
    let mut out = vec![1];
    put_snapshot(&mut out, base);
    put_snapshot(&mut out, after);
    out
}
fn decode_request(bytes: &[u8], store: &Store) -> Result<(Snapshot, Snapshot), Error> {
    match bytes.first() {
        Some(0) => {
            let locator = Locator::decode(&bytes[1..]).map_err(|_| invalid())?;
            let base = locator.common_ancestor(store).map_err(|_| invalid())?;
            Ok((base, base))
        }
        Some(1) if bytes.len() == 81 => Ok((snapshot(&bytes[1..41]), snapshot(&bytes[41..81]))),
        _ => Err(invalid()),
    }
}
pub fn encode_gossip(
    tx: &Transaction,
    sidecar: &Sidecar,
    network: &Hash,
) -> Result<Vec<u8>, String> {
    if sidecar.transaction_id != tx.record.statement_id(network) {
        return Err("gossip sidecar identity mismatch".into());
    }
    let envelope = tx.encode_envelope(network)?;
    let mut out = Vec::with_capacity(4 + envelope.len() + SIDECAR_BYTES);
    out.extend_from_slice(&(envelope.len() as u32).to_le_bytes());
    out.extend(envelope);
    out.extend(sidecar.encode()?);
    Ok(out)
}
fn decode_gossip(bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if bytes.len() < 4 + SIDECAR_BYTES {
        return Err(invalid());
    }
    let n = u32::from_le_bytes(bytes[..4].try_into().expect("fixed length")) as usize;
    if n > MAX_ENVELOPE_BYTES || bytes.len() != 4 + n + SIDECAR_BYTES {
        return Err(invalid());
    }
    Ok((&bytes[4..4 + n], &bytes[4 + n..]))
}
fn encode_references(values: &[Reference]) -> Result<Vec<u8>, Error> {
    if values.is_empty()
        || values.len() > sync::MAX_MISSING
        || values
            .iter()
            .map(|r| r.statement)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != values.len()
    {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(2 + 64 * values.len());
    bytes.extend_from_slice(&(values.len() as u16).to_le_bytes());
    for r in values {
        bytes.extend_from_slice(&r.statement);
        bytes.extend_from_slice(&r.proof);
    }
    Ok(bytes)
}
fn decode_references(bytes: &[u8]) -> Result<Vec<Reference>, Error> {
    if bytes.len() < 2 {
        return Err(invalid());
    }
    let n = u16::from_le_bytes(bytes[..2].try_into().expect("fixed count")) as usize;
    if n == 0 || n > sync::MAX_MISSING || bytes.len() != 2 + 64 * n {
        return Err(invalid());
    }
    let values: Vec<_> = bytes[2..]
        .as_chunks::<64>()
        .0
        .iter()
        .map(|r| Reference {
            statement: r[..32].try_into().expect("fixed statement"),
            proof: r[32..].try_into().expect("fixed proof"),
        })
        .collect();
    encode_references(&values)?;
    Ok(values)
}
#[cfg(all(test, unix))]
mod production_tests;
#[cfg(test)]
mod tests;
