//! Pure consensus-owner synchronization operations for the resident driver.
//!
//! The owner returns bounded values to transport workers. It never reads or
//! writes a socket, and no worker receives access to the canonical store.
use super::*;

/// One reply fits within a fresh channel's conservative 512 MiB directional
/// wire allowance, including TLS record overhead and admission metadata. The
/// driver reauthenticates before a cycle whose remaining allowance is smaller.
const RESIDENT_BATCH_BYTES: usize = 480 * 1024 * 1024;

/// A maximum 576-slot block owns its decoded proofs while validation builds a
/// second encoded durable record. This local candidate allowance includes both
/// representations; it does not enlarge peer framing, the 640 MiB transport
/// budget or the 480 MiB reply cap, and it is not a process RSS limit.
fn resident_candidate_policy() -> CandidatePolicy {
    CandidatePolicy {
        max_bytes: 1024 * 1024 * 1024,
        ..Default::default()
    }
}

pub(crate) enum OwnedCheckpointData {
    Empty,
    Permanent {
        body: Vec<u8>,
        reservation: Reservation,
    },
    Tail {
        block: Box<Block>,
        reservation: Reservation,
    },
}
pub(crate) struct OwnedSyncReply {
    pub(crate) batch: Batch,
    pub(crate) reservation: Reservation,
}

pub(crate) struct ProductionInputs {
    pub(crate) permit: ProductionPermit,
    pub(crate) positions: Vec<crate::pool::Padding>,
    pub(crate) issuances: Vec<crate::issuance::IssuanceRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReplyMeta {
    pub(crate) ancestor: Snapshot,
    pub(crate) after: Snapshot,
    pub(crate) count: u16,
    pub(crate) more: bool,
}
impl ReplyMeta {
    pub(crate) fn encode(self) -> [u8; 83] {
        BatchMeta {
            ancestor: self.ancestor,
            after: self.after,
            count: self.count,
            more: self.more,
        }
        .encode()
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value = BatchMeta::decode(bytes)?;
        Ok(Self {
            ancestor: value.ancestor,
            after: value.after,
            count: value.count,
            more: value.more,
        })
    }
}

pub(crate) struct OwnedRelay {
    pub(crate) statement: Hash,
    pub(crate) body: Vec<u8>,
    pub(crate) _reservation: Reservation,
}

impl<V: BlockVerifier> Node<V> {
    pub(crate) fn resident_checkpoint_qualify(&mut self, now: u64) -> Result<(), String> {
        let roster =
            crate::engineering_checkpoint::release_roster(p2p::Binding::new(&self.state().config))?
                .ok_or("engineering checkpoint roster unavailable")?;
        self.store.qualify_service_checkpoint_delivery(&roster, now)
    }

    pub(crate) fn resident_serve_checkpoint(
        &self,
        body: &[u8],
    ) -> Result<OwnedCheckpointData, Error> {
        let Some(request) =
            crate::checkpoint_service::Request::decode(body).map_err(|_| invalid())?
        else {
            return Ok(OwnedCheckpointData::Empty);
        };
        if !self.store.serves_historical_proofs()? {
            return Err(p2p::Error::Unavailable.into());
        }
        let certificate = self
            .store
            .latest_engineering_checkpoint()?
            .ok_or(p2p::Error::Unavailable)?;
        if certificate.statement.digest() != request.certificate
            || request.permanent != (request.height <= certificate.statement.height)
            || request.height > self.state().height
        {
            return Err(p2p::Error::Unavailable.into());
        }
        let reservation = self.budget.reserve(BLOCK_LOOKUP_BYTES)?;
        if request.permanent {
            Ok(OwnedCheckpointData::Permanent {
                body: self.store.public_compact_block(request.height)?,
                reservation,
            })
        } else {
            Ok(OwnedCheckpointData::Tail {
                block: Box::new(self.store.block(request.height)?),
                reservation,
            })
        }
    }

    pub(crate) fn resident_checkpoint_push_tail(
        &self,
        session: &mut crate::store::checkpoint_bootstrap::CheckpointBootstrap,
        block: &Block,
    ) -> Result<(), String> {
        session.push_tail(block, &self.verifier)
    }
    pub(crate) fn resident_adopt_checkpoint(
        &mut self,
        verified: crate::store::checkpoint_bootstrap::VerifiedBootstrap,
        now: u64,
    ) -> Result<u64, String> {
        let generation = self
            .production_generation
            .checked_add(1)
            .ok_or("production generation exhausted")?;
        let bytes = self.store.adopt_engineering_bootstrap(verified, now)?;
        self.production_generation = generation;
        self.reconcile_pools()
            .map_err(|_| "checkpoint adopted pool reconciliation unavailable")?;
        Ok(bytes)
    }

    pub(crate) fn resident_accept_checkpoint(
        &mut self,
        certificate: &crate::engineering_checkpoint::Certificate,
        roster: &crate::engineering_checkpoint::Roster,
        now: u64,
        candidate: &crate::store::engineering_checkpoint::LocalCandidate,
    ) -> Result<(), String> {
        self.store
            .accept_engineering_checkpoint_cached(certificate, roster, now, candidate)
    }

    /// Return one already verified packet. Per-connection acknowledgements are
    /// bounded by the current pool and are reset after reauthentication.
    pub(crate) fn resident_relay_next(
        &self,
        acknowledged: &mut std::collections::BTreeSet<Hash>,
    ) -> Result<Option<OwnedRelay>, Error> {
        acknowledged.retain(|id| self.mempool.contains(id));
        let Some(id) = self
            .mempool
            .ids()
            .into_iter()
            .find(|id| !acknowledged.contains(id))
        else {
            return Ok(None);
        };
        // Includes serialization temporaries and the owned outgoing packet.
        let reservation = self.budget.reserve(3 * p2p::MAX_CONTROL_BYTES)?;
        let tx = self.mempool.transaction(&id).ok_or_else(invalid)?;
        let sidecar = self.mempool.sidecar(&id).ok_or_else(invalid)?;
        let body =
            encode_gossip(tx, sidecar, &self.state().config.network).map_err(Error::Local)?;
        Ok(Some(OwnedRelay {
            statement: id,
            body,
            _reservation: reservation,
        }))
    }

    /// Exact duplicates require no second proof verification. Different proof
    /// or sidecar bytes never inherit an existing statement's verification.
    pub(crate) fn resident_admit_relay(&mut self, peer: Hash, body: &[u8]) -> Result<Hash, Error> {
        let (envelope, sidecar) = decode_gossip(body)?;
        let (record, _) = crate::wire::borrowed_envelope(envelope, &self.state().config.network)
            .map_err(|_| invalid())?;
        let id = record.statement_id(&self.state().config.network);
        if let Some(known) = self.mempool.transaction(&id) {
            let _comparison = self.budget.reserve(2 * p2p::MAX_CONTROL_BYTES)?;
            if known
                .encode_envelope(&self.state().config.network)
                .map_err(Error::Local)?
                != envelope
                || self
                    .mempool
                    .sidecar(&id)
                    .ok_or_else(invalid)?
                    .encode()
                    .map_err(Error::Local)?
                    != sidecar
            {
                return Err(invalid());
            }
            return Ok(id);
        }
        if self.state().snapshot(record.snapshot).is_err() {
            return Err(p2p::Error::Unavailable.into());
        }
        let public =
            native::codec::PublicTransaction::decode(&record.body).map_err(|_| invalid())?;
        if public.nf.iter().any(|nf| {
            self.state()
                .spent
                .contains(&native::codec::encode_digest(nf))
        }) {
            return Err(p2p::Error::Unavailable.into());
        }
        self.mempool
            .submit_encoded(
                self.store.state(),
                PeerId(peer),
                envelope,
                Some(sidecar),
                &self.verifier,
            )
            .map_err(Into::into)
    }

    /// Detect a retired worker authorization even when canonical state later
    /// returns to the same fingerprint. Stale completion is normal local work
    /// cancellation, not a reason to stop the resident networking service.
    pub(crate) fn resident_permit_is_current(&self, permit: &ProductionPermit) -> bool {
        Arc::ptr_eq(&self.production_owner, &permit.owner)
            && self.production_generation == permit.generation
            && self.state().fingerprint() == permit.fingerprint
    }

    pub(crate) fn resident_prepared_is_current(&self, prepared: &PreparedBlock) -> bool {
        Arc::ptr_eq(&self.production_owner, &prepared.owner)
            && self.production_generation == prepared.generation
            && self.state().fingerprint() == prepared.fingerprint
            && self.state().tip == prepared.produced.block.parent
            && self.state().height.checked_add(1) == Some(prepared.produced.block.height)
    }

    pub(crate) fn resident_padding_ready(&self) -> bool {
        self.padding.ready()
    }
    pub(crate) fn resident_padding_can_grow(&self) -> bool {
        self.padding.can_grow()
    }

    /// Transfer only bounded, already verified entries into one producer job.
    /// The worker receives no store, verifier or node ownership. Wallet entries
    /// stay reserved until a subsequently accepted canonical block consumes them.
    pub(crate) fn resident_production_inputs(
        &mut self,
        slots: usize,
    ) -> Result<ProductionInputs, Error> {
        if !(MIN_SLOTS..=MAX_SLOTS).contains(&slots) || !slots.is_multiple_of(GROUP) {
            return Err(invalid());
        }
        self.reconcile_pools()?;
        let permit = self.begin_production()?;
        let mut positions = self.mempool.select(self.store.state(), slots)?;
        let remaining = slots - positions.len();
        positions.extend(self.padding.take_for_fill(self.store.state(), remaining)?);
        let issuances = self
            .pending_issuances
            .values()
            .filter(|record| {
                self.store
                    .state()
                    .commitments
                    .contains(&record.fee_commitment)
                    || positions.iter().any(|position| {
                        transaction_has_output(&position.transaction, &record.fee_commitment)
                    })
            })
            .cloned()
            .collect();
        Ok(ProductionInputs {
            permit,
            positions,
            issuances,
        })
    }

    /// Recheck a completed background proof against the current canonical
    /// snapshots and reservations. An obsolete generation is discarded by the
    /// driver before entering this independently verified insertion path.
    pub(crate) fn resident_insert_padding(
        &mut self,
        value: crate::pool::Padding,
    ) -> Result<(), Error> {
        self.padding.prune(self.store.state())?;
        self.padding
            .insert(self.store.state(), value, &self.verifier)?;
        Ok(())
    }

    /// Resolve canonical ancestry before the transport allocates incoming proof
    /// blocks. A maximum received block and a second maximum lookup allocation
    /// need not coexist in the shared transport budget.
    pub(crate) fn resident_begin_batch(
        &self,
        peer: Hash,
        attempt: &mut SyncAttempt,
        meta: &ReplyMeta,
    ) -> Result<(), Error> {
        let result = (|| {
            if attempt.peer.is_some_and(|current| current != peer)
                || usize::from(meta.count) > sync::MAX_BATCH_BLOCKS
                || (meta.count == 0 && meta.more)
            {
                return Err(invalid());
            }
            attempt.peer = Some(peer);
            if attempt.staging.is_none() {
                if meta.count == 0 {
                    return self.resident_validate_empty_reply(
                        meta.ancestor,
                        meta.after,
                        meta.more,
                    );
                }
                if meta.after != meta.ancestor {
                    return Err(invalid());
                }
                let _lookup_guard = self.budget.reserve(BLOCK_LOOKUP_BYTES)?;
                attempt.staging = Some(Staging::new(
                    &self.store,
                    meta.ancestor,
                    resident_candidate_policy(),
                )?);
            }
            let staging = attempt.staging.as_ref().expect("initialized staging");
            if (meta.ancestor, meta.after) != (staging.base(), staging.continuation()?) {
                return Err(invalid());
            }
            Ok(())
        })();
        if result.is_err() {
            attempt.clear();
        }
        result
    }

    /// An older canonical peer can return an empty reply without proposing a
    /// fork. Validate its anchor without applying branch finality restrictions.
    fn resident_validate_empty_reply(
        &self,
        ancestor: Snapshot,
        after: Snapshot,
        more: bool,
    ) -> Result<(), Error> {
        if ancestor != after || more || ancestor.height > self.state().height {
            return Err(invalid());
        }
        let canonical = if ancestor.height == 0 {
            self.state().config.genesis_id()
        } else {
            let _lookup_guard = self.budget.reserve(BLOCK_LOOKUP_BYTES)?;
            self.store.block(ancestor.height)?.id()?
        };
        if canonical != ancestor.block_id {
            return Err(invalid());
        }
        Ok(())
    }

    /// The driver retains its small command-envelope reservation while the
    /// returned request waits in a worker queue. Locator lookups additionally
    /// reserve a maximum decoded block before touching canonical history.
    pub(crate) fn resident_sync_request(
        &self,
        peer: Hash,
        attempt: &SyncAttempt,
    ) -> Result<Vec<u8>, Error> {
        if attempt.peer.is_some_and(|current| current != peer) {
            return Err(invalid());
        }
        if let Some(staging) = &attempt.staging {
            return Ok(encode_continue(staging.base(), staging.continuation()?));
        }
        let _lookup_guard = self.budget.reserve(BLOCK_LOOKUP_BYTES)?;
        let mut body = vec![0];
        body.extend(Locator::from_store(&self.store)?.encode()?);
        Ok(body)
    }

    /// All batch blocks and vector allocations remain covered by this one
    /// reservation until the worker finishes transmitting or drops the reply.
    pub(crate) fn resident_serve_sync(&self, body: &[u8]) -> Result<OwnedSyncReply, Error> {
        if body.len() > 1 + 2 + 40 * sync::MAX_LOCATORS {
            return Err(invalid());
        }
        let allowance = self
            .budget
            .available()?
            .saturating_sub(p2p::MAX_CONTROL_BYTES + 65536)
            .min(RESIDENT_BATCH_BYTES + 65536);
        if allowance < BLOCK_LOOKUP_BYTES {
            return Err(p2p::Error::ResourceExhausted.into());
        }
        let reservation = self.budget.reserve(allowance)?;
        let (ancestor, after) = decode_request(body, &self.store)?;
        let batch = sync::serve_batch(
            &self.store,
            ancestor,
            after,
            sync::MAX_BATCH_BLOCKS,
            allowance.saturating_sub(65536),
        )
        .map_err(|_| Error::Transport(p2p::Error::Unavailable))?;
        Ok(OwnedSyncReply { batch, reservation })
    }

    /// Frame reservations accompany every decoded block across the owner
    /// channel. Neither a response hint nor a disconnected worker can supply
    /// fork-choice authority. Any failure discards the entire staged attempt.
    pub(crate) fn resident_accept_batch(
        &mut self,
        peer: Hash,
        attempt: &mut SyncAttempt,
        batch: Batch,
        guards: Vec<Reservation>,
    ) -> Result<bool, Error> {
        let result = self.resident_accept_batch_inner(peer, attempt, batch, guards);
        if result.is_err() {
            attempt.clear();
        }
        result
    }

    fn resident_accept_batch_inner(
        &mut self,
        peer: Hash,
        attempt: &mut SyncAttempt,
        batch: Batch,
        guards: Vec<Reservation>,
    ) -> Result<bool, Error> {
        if attempt.peer.is_some_and(|current| current != peer)
            || batch.blocks.len() > sync::MAX_BATCH_BLOCKS
            || guards.len() != batch.blocks.len()
        {
            return Err(invalid());
        }
        if attempt.staging.is_none() && batch.blocks.is_empty() {
            self.resident_validate_empty_reply(batch.ancestor, batch.after, batch.more)?;
            attempt.clear();
            return Ok(false);
        }
        for (block, guard) in batch.blocks.iter().zip(&guards) {
            let required = block
                .encoded_len()?
                .checked_add(MAX_ENVELOPE_BYTES + 65536)
                .ok_or(p2p::Error::ResourceExhausted)?;
            if !guard.covers(&self.budget, required) {
                return Err(invalid());
            }
        }
        let vectors = batch
            .blocks
            .capacity()
            .checked_mul(std::mem::size_of::<Block>())
            .and_then(|bytes| {
                guards
                    .capacity()
                    .checked_mul(std::mem::size_of::<Reservation>())
                    .and_then(|extra| bytes.checked_add(extra))
            })
            .and_then(|bytes| bytes.checked_add(65536))
            .ok_or(p2p::Error::ResourceExhausted)?;
        let vector_guard = self.budget.reserve(vectors)?;
        attempt.peer = Some(peer);
        if attempt.staging.is_none() {
            if batch.after != batch.ancestor {
                return Err(invalid());
            }
            let _lookup_guard = self.budget.reserve(BLOCK_LOOKUP_BYTES)?;
            attempt.staging = Some(Staging::new(
                &self.store,
                batch.ancestor,
                resident_candidate_policy(),
            )?);
        }
        let staging = attempt.staging.as_ref().expect("initialized staging");
        if (batch.ancestor, batch.after) != (staging.base(), staging.continuation()?) {
            return Err(invalid());
        }
        if batch.blocks.is_empty() {
            if batch.more {
                return Err(invalid());
            }
            attempt.clear();
            return Ok(false);
        }
        let more = batch.more;
        let next_generation = self
            .production_generation
            .checked_add(1)
            .ok_or_else(|| Error::Local("production generation exhausted".into()))?;
        let outcome = attempt
            .staging
            .as_mut()
            .expect("initialized staging")
            .accept(&mut self.store, batch, &self.verifier)?;
        if matches!(outcome, BranchOutcome::Adopted { .. }) {
            self.production_generation = next_generation;
            attempt.reservations.clear();
            self.reconcile_pools()?;
        } else {
            attempt.reservations.extend(guards);
            attempt.reservations.push(vector_guard);
        }
        if !more {
            attempt.clear();
        }
        Ok(more)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{TestVerifier, candidate};
    use crate::state::Config;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "siworld-resident-sync-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn setup(directory: &Directory) -> Node<TestVerifier> {
        let config = Config::development([203; 32], 0).unwrap();
        Node::new(
            Store::open(directory.0.join("chain.redb"), config, &TestVerifier).unwrap(),
            TestVerifier,
        )
    }
    fn guards<V: BlockVerifier>(node: &Node<V>, blocks: &[Block]) -> Vec<Reservation> {
        blocks
            .iter()
            .map(|block| {
                node.budget
                    .reserve(block.encoded_len().unwrap() + MAX_ENVELOPE_BYTES + 65536)
                    .unwrap()
            })
            .collect()
    }
    fn append(node: &mut Node<TestVerifier>, seed: u32) {
        let block = candidate(node.state(), seed);
        node.import_branch(node.state().height, &[block], CandidatePolicy::default())
            .unwrap();
    }

    fn padding(state: &State, seed: u32) -> crate::pool::Padding {
        use native::confidential_fees::FeeOpening;
        use native::multi_asset::{F, Hasher};
        use p3_field::PrimeCharacteristicRing;
        let mut transaction = candidate(state, seed).transactions.remove(0);
        let opening = FeeOpening::dummy([F::ZERO; native::multi_asset::FEE_BLIND_LEN]);
        transaction.record.fee_commit =
            native::codec::encode_digest(&Hasher::new().fee_commit(opening.fee, &opening.blind));
        crate::pool::Padding {
            transaction,
            opening,
        }
    }

    #[cfg(unix)]
    #[test]
    fn off_thread_inputs_move_only_a_complete_verified_candidate_and_pin_its_owner() {
        let directory = Directory::new();
        let mut node = setup(&directory);
        let fingerprint = node.state().fingerprint();
        let mut expected = std::collections::BTreeSet::new();
        for index in 0..MIN_SLOTS {
            let value = padding(node.state(), 100_000 + index as u32 * 1_000);
            expected.insert(
                value
                    .transaction
                    .record
                    .statement_id(&node.state().config.network),
            );
            node.resident_insert_padding(value).unwrap();
        }
        assert!(node.resident_padding_ready());
        let inputs = node.resident_production_inputs(MIN_SLOTS).unwrap();
        assert_eq!(inputs.positions.len(), MIN_SLOTS);
        assert!(inputs.issuances.is_empty());
        assert_eq!(node.padding.len(), 0);
        assert_eq!(node.state().fingerprint(), fingerprint);
        let actual = inputs
            .positions
            .iter()
            .map(|value| {
                value
                    .transaction
                    .record
                    .statement_id(&node.state().config.network)
            })
            .collect();
        assert_eq!(expected, actual);
        // A second worker cannot reuse the private queue entries. A late result
        // from the first snapshot cannot become a new canonical production.
        assert!(node.resident_production_inputs(MIN_SLOTS).is_err());
        let produced = crate::producer::production_fixture(node.state(), 300_000);
        append(&mut node, 400_000);
        assert!(node.bind_produced(inputs.permit, produced).is_err());
    }

    #[test]
    fn background_padding_is_independently_verified_before_entering_the_live_queue() {
        let directory = Directory::new();
        let mut node = setup(&directory);
        let fingerprint = node.state().fingerprint();
        let mut invalid = padding(node.state(), 500_000);
        invalid.transaction.proof[0] = 2;
        assert!(node.resident_insert_padding(invalid).is_err());
        assert_eq!(node.padding.len(), 0);
        assert_eq!(node.state().fingerprint(), fingerprint);
        let value = padding(node.state(), 600_000);
        node.resident_insert_padding(value).unwrap();
        assert_eq!(node.padding.len(), 1);
        assert_eq!(node.state().fingerprint(), fingerprint);
    }

    #[cfg(unix)]
    #[test]
    fn retired_worker_generation_is_stale_even_when_the_state_fingerprint_is_identical() {
        let directory = Directory::new();
        let mut node = setup(&directory);
        let foreign_directory = Directory::new();
        let foreign = setup(&foreign_directory);
        let fingerprint = node.state().fingerprint();
        assert_eq!(foreign.state().fingerprint(), fingerprint);
        let permit = node.begin_production().unwrap();
        let prepared = node
            .bind_produced(
                node.begin_production().unwrap(),
                crate::producer::production_fixture(node.state(), 700_000),
            )
            .unwrap();
        assert!(node.resident_permit_is_current(&permit));
        assert!(node.resident_prepared_is_current(&prepared));
        assert!(!foreign.resident_permit_is_current(&permit));
        assert!(!foreign.resident_prepared_is_current(&prepared));
        node.production_generation += 1;
        assert_eq!(node.state().fingerprint(), fingerprint);
        assert!(!node.resident_permit_is_current(&permit));
        assert!(!node.resident_prepared_is_current(&prepared));
        assert_eq!(node.state().height, 0);
    }

    #[test]
    fn metadata_reuses_the_existing_exact_wire_encoding() {
        let base = Snapshot {
            height: 0,
            block_id: [1; 32],
        };
        let value = ReplyMeta {
            ancestor: base,
            after: base,
            count: 1,
            more: true,
        };
        assert_eq!(ReplyMeta::decode(&value.encode()).unwrap(), value);
        let mut extra = value.encode().to_vec();
        extra.push(0);
        assert!(ReplyMeta::decode(&extra).is_err());
        let mut flag = value.encode();
        flag[82] = 2;
        assert!(ReplyMeta::decode(&flag).is_err());
    }

    #[test]
    fn empty_older_peer_reply_preserves_a_finalized_local_prefix() {
        let directory = Directory::new();
        let mut node = setup(&directory);
        for n in 0..26 {
            append(&mut node, 4_000_000 + n * 1_000);
        }
        let before = node.state().fingerprint();
        let generation = node.production_generation;
        let available = node.budget.available().unwrap();
        let base = Snapshot {
            height: 0,
            block_id: node.state().config.genesis_id(),
        };
        let mut attempt = SyncAttempt::default();
        node.resident_begin_batch(
            [7; 32],
            &mut attempt,
            &ReplyMeta {
                ancestor: base,
                after: base,
                count: 0,
                more: false,
            },
        )
        .unwrap();
        assert!(attempt.staging.is_none());
        assert!(
            !node
                .resident_accept_batch(
                    [7; 32],
                    &mut attempt,
                    Batch {
                        ancestor: base,
                        after: base,
                        blocks: Vec::new(),
                        more: false
                    },
                    Vec::new(),
                )
                .unwrap()
        );
        assert_eq!(node.state().fingerprint(), before);
        assert_eq!(node.production_generation, generation);
        assert_eq!(node.budget.available().unwrap(), available);
        assert!(attempt.peer.is_none() && attempt.staging.is_none());
        // A nonempty branch still cannot replace the finalized local prefix.
        assert!(
            node.resident_begin_batch(
                [7; 32],
                &mut attempt,
                &ReplyMeta {
                    ancestor: base,
                    after: base,
                    count: 1,
                    more: false
                },
            )
            .is_err()
        );
        let bad = Snapshot {
            block_id: [99; 32],
            ..base
        };
        assert!(
            node.resident_begin_batch(
                [7; 32],
                &mut attempt,
                &ReplyMeta {
                    ancestor: bad,
                    after: bad,
                    count: 0,
                    more: false
                },
            )
            .is_err()
        );
        assert!(
            node.resident_accept_batch(
                [7; 32],
                &mut attempt,
                Batch {
                    ancestor: bad,
                    after: bad,
                    blocks: Vec::new(),
                    more: false
                },
                Vec::new(),
            )
            .is_err()
        );
        assert_eq!(node.state().fingerprint(), before);
    }

    #[test]
    fn owner_serves_and_accepts_a_verified_extension_without_socket_ownership() {
        let source_directory = Directory::new();
        let target_directory = Directory::new();
        let mut source = setup(&source_directory);
        let mut target = setup(&target_directory);
        append(&mut source, 10_000);
        let mut attempt = SyncAttempt::default();
        let body = target.resident_sync_request([7; 32], &attempt).unwrap();
        let reply = source.resident_serve_sync(&body).unwrap();
        target
            .resident_begin_batch(
                [7; 32],
                &mut attempt,
                &ReplyMeta {
                    ancestor: reply.batch.ancestor,
                    after: reply.batch.after,
                    count: reply.batch.blocks.len() as u16,
                    more: reply.batch.more,
                },
            )
            .unwrap();
        let incoming = guards(&target, &reply.batch.blocks);
        let generation = target.production_generation;
        assert!(
            !target
                .resident_accept_batch([7; 32], &mut attempt, reply.batch, incoming)
                .unwrap()
        );
        assert_eq!(target.state().fingerprint(), source.state().fingerprint());
        assert_eq!(target.production_generation, generation + 1);
        assert!(attempt.staging.is_none() && attempt.peer.is_none());
    }

    #[test]
    fn invalid_initial_continuation_and_missing_guards_leave_state_unchanged() {
        for missing_guard in [false, true] {
            let directory = Directory::new();
            let mut node = setup(&directory);
            let before = node.state().fingerprint();
            let block = candidate(node.state(), 20_000);
            let base = Snapshot {
                height: 0,
                block_id: node.state().tip,
            };
            let incoming = if missing_guard {
                Vec::new()
            } else {
                guards(&node, std::slice::from_ref(&block))
            };
            let mut after = base;
            if !missing_guard {
                after.height = 1;
            }
            let batch = Batch {
                ancestor: base,
                after,
                blocks: vec![block],
                more: false,
            };
            let mut attempt = SyncAttempt::default();
            assert!(
                node.resident_accept_batch([8; 32], &mut attempt, batch, incoming)
                    .is_err()
            );
            assert_eq!(node.state().fingerprint(), before);
            assert!(attempt.peer.is_none() && attempt.staging.is_none());
        }
    }

    #[test]
    fn foreign_or_undersized_frame_reservations_cannot_enter_owner_staging() {
        for foreign in [false, true] {
            let directory = Directory::new();
            let mut node = setup(&directory);
            let block = candidate(node.state(), 25_000);
            let required = block.encoded_len().unwrap() + MAX_ENVELOPE_BYTES + 65536;
            let guard = if foreign {
                Budget::default().reserve(required).unwrap()
            } else {
                node.budget.reserve(required - 1).unwrap()
            };
            let base = Snapshot {
                height: 0,
                block_id: node.state().tip,
            };
            let before = node.state().fingerprint();
            assert!(
                node.resident_accept_batch(
                    [8; 32],
                    &mut SyncAttempt::default(),
                    Batch {
                        ancestor: base,
                        after: base,
                        blocks: vec![block],
                        more: false,
                    },
                    vec![guard],
                )
                .is_err()
            );
            assert_eq!(node.state().fingerprint(), before);
        }
    }

    #[test]
    fn stale_staging_and_wrong_peer_cannot_change_the_canonical_head() {
        let directory = Directory::new();
        let mut node = setup(&directory);
        append(&mut node, 30_000);
        append(&mut node, 40_000);
        let base = Snapshot {
            height: 0,
            block_id: node.state().config.genesis_id(),
        };
        let genesis = State::new(node.state().config.clone()).unwrap();
        let first = candidate(&genesis, 50_000);
        let mut fork = genesis;
        fork.apply(&first, &TestVerifier).unwrap();
        let second = candidate(&fork, 60_000);
        let first_id = first.id().unwrap();
        let incoming = guards(&node, std::slice::from_ref(&first));
        let mut attempt = SyncAttempt::default();
        node.resident_accept_batch(
            [9; 32],
            &mut attempt,
            Batch {
                ancestor: base,
                after: base,
                blocks: vec![first],
                more: true,
            },
            incoming,
        )
        .unwrap();
        assert!(node.resident_sync_request([10; 32], &attempt).is_err());
        append(&mut node, 70_000);
        let before = node.state().fingerprint();
        let incoming = guards(&node, std::slice::from_ref(&second));
        assert!(
            node.resident_accept_batch(
                [9; 32],
                &mut attempt,
                Batch {
                    ancestor: base,
                    after: Snapshot {
                        height: 1,
                        block_id: first_id,
                    },
                    blocks: vec![second],
                    more: false,
                },
                incoming,
            )
            .is_err()
        );
        assert_eq!(node.state().fingerprint(), before);
        assert!(attempt.peer.is_none() && attempt.staging.is_none());
    }

    #[test]
    fn an_empty_response_cannot_claim_a_continuation() {
        let directory = Directory::new();
        let mut node = setup(&directory);
        let base = Snapshot {
            height: 0,
            block_id: node.state().tip,
        };
        let mut attempt = SyncAttempt::default();
        let before = node.state().fingerprint();
        assert!(
            node.resident_accept_batch(
                [11; 32],
                &mut attempt,
                Batch {
                    ancestor: base,
                    after: base,
                    blocks: Vec::new(),
                    more: true,
                },
                Vec::new(),
            )
            .is_err()
        );
        assert_eq!(node.state().fingerprint(), before);
    }

    #[test]
    fn metadata_ancestry_is_checked_before_incoming_block_reservations() {
        let directory = Directory::new();
        let node = setup(&directory);
        let available = node.budget.available().unwrap();
        let base = Snapshot {
            height: 0,
            block_id: node.state().tip,
        };
        let mut attempt = SyncAttempt::default();
        node.resident_begin_batch(
            [12; 32],
            &mut attempt,
            &ReplyMeta {
                ancestor: base,
                after: base,
                count: 1,
                more: false,
            },
        )
        .unwrap();
        assert_eq!(node.budget.available().unwrap(), available);
        let incoming = node.budget.reserve(BLOCK_LOOKUP_BYTES).unwrap();
        assert!(node.budget.reserve(BLOCK_LOOKUP_BYTES).is_err());
        assert!(attempt.staging.is_some());
        drop(incoming);
        let mut bad = ReplyMeta {
            ancestor: base,
            after: base,
            count: 1,
            more: false,
        };
        bad.after.height = 1;
        assert!(
            node.resident_begin_batch([12; 32], &mut attempt, &bad)
                .is_err()
        );
        assert!(attempt.peer.is_none() && attempt.staging.is_none());
    }

    #[test]
    fn maximum_576_slot_proof_envelopes_import_and_replay_with_the_resident_allowance() {
        // This exercises actual framing, memory admission, database promotion
        // and replay. Proof bytes are deliberately synthetic and establish no
        // transaction/settlement soundness or prover performance evidence.
        use native::codec::{ProofContext, PublicTransaction};
        use native::multi_asset::Digest;
        struct MaximumEnvelopeVerifier;
        impl BlockVerifier for MaximumEnvelopeVerifier {
            fn transaction(
                &self,
                _: &PublicTransaction,
                _: &ProofContext,
                _: &Digest,
                _: &Digest,
                proof: &[u8],
            ) -> Result<(), String> {
                if proof.len() == crate::wire::MAX_TX_PROOF && proof.iter().all(|byte| *byte == 1) {
                    Ok(())
                } else {
                    Err("invalid synthetic maximum transaction envelope".into())
                }
            }
            fn settlement(
                &self,
                _: &[Digest],
                _: &native::settlement::RewardPlan,
                _: Hash,
                _: Hash,
                _: &[Digest],
                proof: &[u8],
            ) -> Result<(), String> {
                if proof.len() == crate::wire::MAX_SETTLEMENT_PROOF
                    && proof.iter().all(|byte| *byte == 1)
                {
                    Ok(())
                } else {
                    Err("invalid synthetic maximum settlement envelope".into())
                }
            }
        }
        let directory = Directory::new();
        let config = Config::development([211; 32], 0).unwrap();
        let mut node = Node::new(
            Store::open(
                directory.0.join("chain.redb"),
                config.clone(),
                &MaximumEnvelopeVerifier,
            )
            .unwrap(),
            MaximumEnvelopeVerifier,
        );
        let peer = [41; 32];
        let base = node.state().tip_snapshot().selector;
        let mut block = candidate(node.state(), 800_000);
        let mut transactions = Vec::with_capacity(MAX_SLOTS);
        for group in 0..(MAX_SLOTS / MIN_SLOTS) {
            let fixture = candidate(node.state(), 800_000 + group as u32 * 1_000);
            for mut transaction in fixture.transactions {
                transaction.proof = vec![1; crate::wire::MAX_TX_PROOF];
                transactions.push(transaction);
            }
        }
        transactions.sort_unstable_by_key(|tx| tx.record.statement_id(&config.network));
        block.transactions = transactions;
        block.settlement_proof = vec![1; crate::wire::MAX_SETTLEMENT_PROOF];
        let seed = block.pow_seed().unwrap();
        block.nonce = 0;
        while !siworld_core::pow::meets_target(
            &siworld_core::pow::pow_hash(&seed, block.nonce, config.pow_iterations),
            &block.target,
        ) {
            block.nonce += 1;
        }
        let bytes = block.encoded_len().unwrap();
        assert!(bytes >= MAX_SLOTS * crate::wire::MAX_TX_PROOF + crate::wire::MAX_SETTLEMENT_PROOF);
        assert!(bytes <= MAX_BLOCK_BYTES);
        assert!(matches!(
            crate::chain::candidate_budget(
                std::slice::from_ref(&block),
                CandidatePolicy::default()
            ),
            Err(ChainError::ResourceExhausted(_))
        ));
        let mut attempt = SyncAttempt::default();
        node.resident_begin_batch(
            peer,
            &mut attempt,
            &ReplyMeta {
                ancestor: base,
                after: base,
                count: 1,
                more: false,
            },
        )
        .unwrap();
        let available = node.transport_budget().available().unwrap();
        let incoming = guards(&node, std::slice::from_ref(&block));
        let expected_tip = block.id().unwrap();
        assert!(
            !node
                .resident_accept_batch(
                    peer,
                    &mut attempt,
                    Batch {
                        ancestor: base,
                        after: base,
                        blocks: vec![block],
                        more: false,
                    },
                    incoming
                )
                .unwrap()
        );
        assert_eq!(node.transport_budget().available().unwrap(), available);
        assert_eq!(node.state().height, 1);
        assert_eq!(node.state().tip, expected_tip);
        let fingerprint = node.state().fingerprint();
        drop(node);
        let reopened = Store::open_existing(
            directory.0.join("chain.redb"),
            config,
            &MaximumEnvelopeVerifier,
        )
        .unwrap();
        assert_eq!(reopened.state().height, 1);
        assert_eq!(reopened.state().tip, expected_tip);
        assert_eq!(reopened.state().fingerprint(), fingerprint);
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;
    use crate::fixtures::{TestVerifier, candidate};
    use native::codec::encode_digest;
    use native::multi_asset::{F, Hasher};
    use p3_field::PrimeCharacteristicRing;
    #[test]
    fn relay_deduplicates_exact_packets_but_rejects_altered_proof_and_sidecar() {
        let path = std::env::temp_dir().join(format!("siworld-relay-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let config = crate::state::Config::development([203; 32], 0).unwrap();
        let store = Store::open(path.join("chain.redb"), config.clone(), &TestVerifier).unwrap();
        let mut node = Node::new(store, TestVerifier);
        let mut tx = candidate(node.state(), 940_000).transactions.remove(0);
        tx.record.fee_commit = encode_digest(&Hasher::new().fee_commit(100, &[F::from_u32(34); 8]));
        let sidecar = Sidecar {
            transaction_id: tx.record.statement_id(&config.network),
            fee: 100,
            blind: [34; 8],
        };
        let packet = encode_gossip(&tx, &sidecar, &config.network).unwrap();
        let before = node.state().fingerprint();
        assert_eq!(
            node.resident_admit_relay([4; 32], &packet).unwrap(),
            sidecar.transaction_id
        );
        assert_eq!(
            node.resident_admit_relay([5; 32], &packet).unwrap(),
            sidecar.transaction_id
        );
        assert_eq!(node.mempool().len(), 1);
        let mut altered = packet.clone();
        altered[4 + TX_PREFIX_BYTES] ^= 1;
        assert!(node.resident_admit_relay([5; 32], &altered).is_err());
        let mut altered = packet.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(node.resident_admit_relay([5; 32], &altered).is_err());
        assert_eq!(node.state().fingerprint(), before);
        let mut seen = std::collections::BTreeSet::new();
        let outbound = node.resident_relay_next(&mut seen).unwrap().unwrap();
        assert_eq!(outbound.statement, sidecar.transaction_id);
        assert_eq!(outbound.body, packet);
        seen.insert(outbound.statement);
        assert!(node.resident_relay_next(&mut seen).unwrap().is_none());
        drop(outbound);
        drop(node);
        std::fs::remove_dir_all(path).unwrap();
    }
}
