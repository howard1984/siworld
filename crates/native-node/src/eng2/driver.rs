//! Single mutable owner for versioned durable admission and local production.
//! Socket reads, actual proving and nonce search run outside this owner.

use super::{
    body::Body,
    execution::{CommittedBlock, Engine},
    header::Header,
    producer::{self, PreparedBlock, ProvedBlock, Work},
    snapshot::ImportLimits,
    store::Store,
};
use crate::{
    admission::{Mempool, PeerId},
    pool::{Padding, Pool},
    producer::{MiningSettings, PreparedPadding, prepare_padding_witness},
    proofs::NativeVerifier,
    wire::Hash,
};

#[cfg(feature = "eng2-runtime")]
mod history;
mod reorganization;
pub use reorganization::SwitchEvent;

fn pending_pool(network: Hash) -> Result<Mempool, String> {
    Mempool::with_limits(
        network,
        crate::admission::Limits {
            bytes: crate::pool::MAX_BYTES,
            entries: 128,
            peer_bytes: 8 * 1024 * 1024,
            peer_entries: 16,
            peers: 128,
        },
    )
    .map_err(|_| "pending admission limits rejected".into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub network: Hash,
    pub genesis: Hash,
    pub height: u64,
    pub id: Hash,
    pub work: siworld_core::pow::Work,
}

/// Native verification is synchronous, so this is a commit deadline rather
/// than CPU preemption. Late verification never inserts into the pending pool.
struct TimedAdmission<'a, V> {
    verifier: &'a V,
    deadline: &'a crate::p2p::Deadline,
}
impl<V: crate::admission::AdmissionVerifier> crate::admission::AdmissionVerifier
    for TimedAdmission<'_, V>
{
    fn verify(
        &self,
        public: &native::codec::PublicTransaction,
        context: &native::codec::ProofContext,
        fee: &native::multi_asset::Digest,
        root: &native::multi_asset::Digest,
        proof: &[u8],
    ) -> Result<(), crate::admission::VerificationError> {
        self.deadline
            .check()
            .map_err(|_| crate::admission::VerificationError::Unavailable)?;
        self.verifier.verify(public, context, fee, root, proof)?;
        self.deadline
            .check()
            .map_err(|_| crate::admission::VerificationError::Unavailable)
    }
    fn check_commit(&self) -> Result<(), crate::admission::VerificationError> {
        self.verifier.check_commit()?;
        self.deadline
            .check()
            .map_err(|_| crate::admission::VerificationError::Unavailable)
    }
}
fn transaction_identity(packet: &[u8], network: &Hash) -> Result<(Hash, usize), String> {
    let prefix: [u8; 4] = packet
        .get(..4)
        .ok_or("pending transaction framing rejected")?
        .try_into()
        .expect("checked prefix");
    let length = u32::from_le_bytes(prefix) as usize;
    if length > crate::wire::MAX_ENVELOPE_BYTES
        || packet.len() != 4 + length + crate::wire::SIDECAR_BYTES
    {
        return Err("pending transaction framing rejected".into());
    }
    let id = crate::wire::borrowed_envelope(&packet[4..4 + length], network)
        .map_err(|_| "pending transaction envelope rejected")?
        .0
        .statement_id(network);
    Ok((id, length))
}

pub struct Driver {
    #[cfg(feature = "eng2-runtime")]
    historical_active: std::sync::Arc<std::sync::atomic::AtomicBool>,
    store: Store,
    verifier: std::sync::Arc<NativeVerifier>,
    #[cfg(feature = "eng2-runtime")]
    verification_invalidated: std::sync::Arc<std::sync::atomic::AtomicBool>,
    padding: Pool,
    pending: Mempool,
    imports: ImportLimits,
    last_archive_error: Option<String>,
    bootstrap: super::bootstrap::leases::Registry,
    bootstrap_receipt_height: u64,
    reorganization: Option<reorganization::Reorganization>,
    forward_discovery: Option<super::branches::discovery::runtime::Discovery>,
    template_generation: u64,
    #[cfg(feature = "eng2-runtime")]
    header_hub: Option<std::sync::Arc<super::resident::header_lane::Hub>>,
    #[cfg(feature = "eng2-runtime")]
    accept_observation: super::accept_observation::Observation,
}
impl Driver {
    /// The caller explicitly creates or resumes the store and loads only the
    /// verification keys. This constructor never creates identity credentials.
    pub fn new(
        store: Store,
        verifier: NativeVerifier,
        imports: ImportLimits,
    ) -> Result<Self, String> {
        store.ensure_exportable()?;
        if !verifier.authenticates(store.engine().genesis()) {
            return Err("driver verifier differs from sealed salted genesis".into());
        }
        Ok(Self {
            #[cfg(feature = "eng2-runtime")]
            historical_active: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            padding: Pool::new(store.engine().state().network()),
            pending: pending_pool(store.engine().state().network())?,
            store,
            verifier: std::sync::Arc::new(verifier),
            #[cfg(feature = "eng2-runtime")]
            verification_invalidated: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
            imports,
            last_archive_error: None,
            bootstrap: super::bootstrap::leases::Registry::default(),
            bootstrap_receipt_height: 0,
            reorganization: None,
            forward_discovery: None,
            template_generation: 0,
            #[cfg(feature = "eng2-runtime")]
            header_hub: None,
            #[cfg(feature = "eng2-runtime")]
            accept_observation: super::accept_observation::Observation::default(),
        })
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn observe_headers(
        &mut self,
        hub: std::sync::Arc<super::resident::header_lane::Hub>,
    ) {
        if let Some(state) = &mut self.reorganization {
            state.progress_hub = Some(std::sync::Arc::downgrade(&hub));
        }
        self.header_hub = Some(hub);
    }
    fn ensure_activities_allowed(&self) -> Result<(), String> {
        if self.activities_allowed() {
            Ok(())
        } else {
            Err("canonical switching pauses owner activities".into())
        }
    }
    pub fn store(&self) -> &Store {
        &self.store
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn observe_commits(
        &mut self,
        observer: std::sync::Arc<dyn super::store::CommitObserver>,
    ) {
        self.store.observe_commits(observer);
    }
    /// Explicit service-role maintenance. At most one missing permanent receipt
    /// is materialized per tick; this preserves bodies and all accepted state.
    pub fn refresh_bootstrap(
        &mut self,
        certified: Option<&super::runtime_export::CertifiedCheckpoint>,
        budget: &crate::p2p::Budget,
    ) -> Result<(), String> {
        self.ensure_activities_allowed()?;
        let now = std::time::Instant::now();
        self.bootstrap
            .reconcile(now, |provider| provider.check_current(&self.store).is_ok());
        let Some(certified) = certified else {
            return Ok(());
        };
        if self
            .bootstrap
            .current()
            .is_some_and(|provider| provider.manifest().certificate == *certified.certificate())
        {
            return Ok(());
        }
        certified.check_current(&self.store)?;
        let anchor = certified.certificate().statement.checkpoint_height;
        if self.bootstrap_receipt_height < anchor {
            let height = self.bootstrap_receipt_height + 1;
            if self.store.permanent_receipt_descriptor(height)?.is_none() {
                self.store.materialize_permanent_receipt(height, budget)?;
            }
            self.bootstrap_receipt_height = height;
            if height < anchor {
                return Ok(());
            }
        }
        if !self
            .bootstrap
            .preparation_allowed(certified.snapshot_bytes().len(), now)
        {
            return Ok(());
        }
        let provider =
            super::bootstrap::Provider::capture(&self.store, certified, self.imports, budget)?;
        // Capacity was checked under this same owner lock. Publication replaces
        // current atomically; old valid leased offers remain exact-addressable.
        if !self.bootstrap.publish(std::sync::Arc::new(provider), now) {
            return Err("bootstrap publication capacity changed under owner lock".into());
        }
        Ok(())
    }
    pub fn bootstrap_available(&self) -> bool {
        self.activities_allowed()
            && self
                .bootstrap
                .current()
                .is_some_and(|provider| provider.check_current(&self.store).is_ok())
    }
    /// Derive conservative proof-body retention from this owner's registry.
    /// No public constructor accepts remote ranges; deletion is not enabled.
    pub fn bootstrap_body_pins(&mut self) -> super::bootstrap::BodyPins {
        let now = std::time::Instant::now();
        self.bootstrap
            .reconcile(now, |provider| provider.check_current(&self.store).is_ok());
        self.bootstrap.body_pins(now)
    }
    #[cfg(feature = "eng2-runtime")]
    fn invalidate_verification(&mut self) {
        self.verification_invalidated
            .store(true, std::sync::atomic::Ordering::Release);
        self.verification_invalidated =
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn capture_verification(
        &self,
        budget: &crate::p2p::Budget,
    ) -> Result<super::native_pipeline::Capture, super::native_pipeline::Error> {
        self.check_forward_admission()
            .map_err(|_| super::native_pipeline::Error::Context)?;
        super::native_pipeline::Capture::new(
            self.store.engine(),
            std::sync::Arc::clone(&self.verifier),
            budget,
            std::sync::Arc::clone(&self.verification_invalidated),
        )
    }
    pub fn engine(&self) -> &Engine {
        self.store.engine()
    }
    pub fn head(&self) -> Result<Head, String> {
        self.store.ensure_exportable()?;
        let engine = self.store.engine();
        Ok(Head {
            network: engine.state().network(),
            genesis: engine.genesis().id(),
            height: engine.state().height(),
            id: engine.state().tip(),
            work: engine.state().chain().cumulative_work,
        })
    }
    /// Exact retained header resolution for retiring obsolete checkpoint
    /// advertisements. This does not grant canonical or signing authority.
    pub fn retained_header(&self, height: u64, id: Hash) -> Result<Option<Header>, String> {
        let header = Driver::branch_header(self, id)?;
        if header
            .as_ref()
            .is_some_and(|header| header.height != height)
        {
            return Err("retained authorization header height differs".into());
        }
        Ok(header)
    }
    pub fn header(&self, height: u64) -> Result<Header, String> {
        self.store.header(height)
    }
    pub fn block_size(&self, height: u64) -> Result<usize, String> {
        self.store.block_size(height)
    }
    pub fn block(&self, height: u64) -> Result<(Header, Body), String> {
        self.store.block(height)
    }

    /// Return only after the exact native block is durably committed. Archive
    /// failures are independently observable and do not undo accepted history.
    pub fn accept(&mut self, header: &Header, body: &Body) -> Result<CommittedBlock, String> {
        #[cfg(feature = "eng2-runtime")]
        {
            self.accept_observed(header, body, None)
        }
        #[cfg(not(feature = "eng2-runtime"))]
        {
            self.check_forward_admission()?;
            let committed = match self.store.append(header, body, self.verifier.as_ref()) {
                Ok(committed) => committed,
                Err(original) => return Err(self.after_append_error(original)),
            };
            self.finish_accepted(header, body, committed)
        }
    }
    fn check_forward_admission(&self) -> Result<(), String> {
        // A preferred header without its body still permits ordinary forward sync.
        if self
            .reorganization
            .as_ref()
            .is_some_and(|state| state.paused())
        {
            return Err("canonical switching pauses forward admission".into());
        }
        self.store.ensure_exportable()
    }
    fn after_append_error(&mut self, original: String) -> String {
        #[cfg(feature = "eng2-runtime")]
        self.invalidate_verification();
        if self.store.ensure_exportable().is_err()
            && let Some(state) = &mut self.reorganization
        {
            state.stop("reorganization_canonical_store_unavailable");
        }
        original
    }
    #[cfg(feature = "eng2-runtime")]
    pub(super) fn accept_observed(
        &mut self,
        header: &Header,
        body: &Body,
        frame: Option<super::accept_observation::FrameIdentity>,
    ) -> Result<CommittedBlock, String> {
        self.accept_observed_with_receipts(header, body, frame, None)
    }
    #[cfg(feature = "eng2-runtime")]
    pub(super) fn accept_observed_with_receipts(
        &mut self,
        header: &Header,
        body: &Body,
        frame: Option<super::accept_observation::FrameIdentity>,
        receipts: Option<&super::native_pipeline::CandidateReceipts>,
    ) -> Result<CommittedBlock, String> {
        self.check_forward_admission()?;
        #[cfg(feature = "eng2-runtime")]
        if let Some(hub) = &self.header_hub {
            hub.invalidate_progress_context();
        }
        let attempt = frame.and_then(|frame| self.accept_observation.begin(header, Some(frame)));
        let mut timing = super::accept_observation::ValidationTiming::default();
        let committed = match self.store.append_diagnosed_with_receipts(
            header,
            body,
            self.verifier.as_ref(),
            &mut timing,
            receipts,
        ) {
            Ok(committed) => committed,
            Err(failure) => {
                // Observe this actual typed rejection before returning the same
                // original error and retaining the original availability handling.
                self.accept_observation.rejected(attempt.as_ref(), &failure);
                let outcome =
                    if failure.commit() == super::accept_observation::CommitKnowledge::NotReached {
                        2
                    } else {
                        3
                    };
                self.accept_observation
                    .completed(attempt.as_ref(), timing, outcome);
                return Err(self.after_append_error(failure.into_original()));
            }
        };
        let result = self.finish_accepted(header, body, committed);
        self.accept_observation.completed(
            attempt.as_ref(),
            timing,
            if result.is_ok() { 1 } else { 4 },
        );
        result
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn accept_timing_json(&self, origin: std::time::Instant) -> serde_json::Value {
        self.accept_observation.timing_json(origin)
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn attach_accept_observer(
        &mut self,
        run: super::accept_observation::RunIdentity,
        observer: std::sync::Arc<dyn super::accept_observation::Observer>,
    ) -> bool {
        self.accept_observation.attach(run, observer)
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn accept_observation_diagnostic(
        &self,
    ) -> (
        bool,
        u64,
        Option<super::accept_observation::DiagnosticError>,
    ) {
        let (dropped, error) = self.accept_observation.diagnostic();
        (self.accept_observation.enabled(), dropped, error)
    }
    fn finish_accepted(
        &mut self,
        header: &Header,
        body: &Body,
        committed: CommittedBlock,
    ) -> Result<CommittedBlock, String> {
        #[cfg(feature = "eng2-runtime")]
        self.invalidate_verification();
        if let Some(state) = &mut self.reorganization
            && let Err(error) = state.branches.retain_committed(
                header,
                body,
                self.store.engine().body_policy(),
                &committed,
            )
        {
            // Canonical commit already succeeded. Preserve that fact and
            // stop production instead of reporting the block uncommitted.
            state.stop("reorganization_committed_archive_failed");
            self.last_archive_error = Some(error);
        }
        // The pool is created for this immutable network, so pruning cannot
        // fail its context check after a successful append.
        self.pending
            .prune(self.store.engine().state().chain())
            .expect("owner pending network is immutable");
        self.padding
            .prune(self.store.engine().state().chain())
            .expect("owner padding network is immutable");
        if committed
            .height()
            .is_multiple_of(crate::eng2::runtime_export::CHECKPOINT_INTERVAL)
        {
            self.last_archive_error = self.store.archive_checkpoint_anchor(self.imports).err();
        }
        self.bootstrap
            .reconcile(std::time::Instant::now(), |provider| {
                provider.check_current(&self.store).is_ok()
            });
        #[cfg(feature = "eng2-runtime")]
        if let Some(hub) = &self.header_hub {
            hub.after_commit(|| {
                hub.accepted_body(header)?;
                hub.committed(self)
            });
        }
        Ok(committed)
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn body_scope(&self) -> Result<crate::p2p::BodyScope, String> {
        self.reorganization
            .as_ref()
            .map(|s| s.discovery.body_scope())
            .ok_or("body lifecycle owner unavailable".into())
    }
    pub fn last_archive_error(&self) -> Option<&str> {
        self.last_archive_error.as_deref()
    }
    /// Pending wallet work is independently verified and retained until its
    /// inputs become canonical. No fee sidecar is exported in public status.
    pub fn ready_positions(&self) -> usize {
        self.padding.len().saturating_add(self.pending.len())
    }
    pub fn transaction_ids(&self) -> Vec<Hash> {
        self.pending.ids()
    }
    pub fn has_transaction(&self, id: &Hash) -> bool {
        self.pending.contains(id)
    }
    pub fn transaction_packet(&self, id: &Hash) -> Result<Option<Vec<u8>>, String> {
        match (self.pending.transaction(id), self.pending.sidecar(id)) {
            (Some(transaction), Some(sidecar)) => crate::runtime::encode_gossip(
                transaction,
                sidecar,
                &self.store.engine().state().network(),
            )
            .map(Some),
            (None, None) => Ok(None),
            _ => Err("pending transaction sidecar unavailable".into()),
        }
    }
    pub fn submit_transaction(
        &mut self,
        peer: Hash,
        expected: Hash,
        packet: &[u8],
    ) -> Result<Hash, String> {
        self.submit_transaction_before(
            peer,
            expected,
            packet,
            &crate::p2p::Deadline::new(std::time::Duration::from_secs(10)),
        )
    }
    fn submit_transaction_before(
        &mut self,
        peer: Hash,
        expected: Hash,
        packet: &[u8],
        deadline: &crate::p2p::Deadline,
    ) -> Result<Hash, String> {
        self.ensure_activities_allowed()?;
        deadline
            .check()
            .map_err(|_| "pending transaction deadline elapsed")?;
        self.store.ensure_exportable()?;
        let network = self.store.engine().state().network();
        let (id, length) = transaction_identity(packet, &network)?;
        let envelope = &packet[4..4 + length];
        if id != expected {
            return Err("pending transaction identity differs".into());
        }
        if self.pending.contains(&id) {
            let existing = zeroize::Zeroizing::new(
                self.transaction_packet(&id)?
                    .ok_or("pending packet unavailable")?,
            );
            deadline
                .check()
                .map_err(|_| "pending transaction deadline elapsed")?;
            return if existing.as_slice() == packet {
                Ok(id)
            } else {
                Err("pending retry differs from admitted packet".into())
            };
        }
        self.pending
            .submit_encoded(
                self.store.engine().state().chain(),
                PeerId(peer),
                envelope,
                Some(&packet[4 + length..]),
                &TimedAdmission {
                    verifier: self.verifier.as_ref(),
                    deadline,
                },
            )
            .map_err(|_| "pending transaction admission rejected".into())
    }
    #[cfg(all(unix, feature = "eng2-runtime"))]
    pub(crate) fn submit_local_transaction(
        &mut self,
        packet: &[u8],
        deadline: &crate::p2p::Deadline,
    ) -> Result<Hash, String> {
        deadline
            .check()
            .map_err(|_| "pending transaction deadline elapsed")?;
        let network = self.store.engine().state().network();
        let (id, _) = transaction_identity(packet, &network)?;
        let peer = blake3::derive_key(
            "siworld eng2 owner local submission v1",
            &self.store.engine().genesis().id(),
        );
        self.submit_transaction_before(peer, id, packet, deadline)
    }
    pub fn padding_count(&self) -> usize {
        self.padding.len()
    }
    pub fn padding_bytes(&self) -> usize {
        self.padding.bytes()
    }

    /// A single bounded producer worker calls this, proves outside its owner
    /// lock, then returns the completed padding for independent admission.
    pub fn prepare_padding(&mut self) -> Result<Option<PreparedPadding>, String> {
        self.ensure_activities_allowed()?;
        self.store.ensure_exportable()?;
        self.padding.prune(self.store.engine().state().chain())?;
        if !self.padding.can_grow() {
            return Ok(None);
        }
        prepare_padding_witness(self.store.engine().state().chain()).map(Some)
    }
    pub fn insert_padding(&mut self, padding: Padding) -> Result<(), String> {
        self.ensure_activities_allowed()?;
        self.store.ensure_exportable()?;
        self.padding.insert(
            self.store.engine().state().chain(),
            padding,
            self.verifier.as_ref(),
        )
    }
    pub fn prepare_block(
        &mut self,
        count: usize,
        timestamp: u64,
        settings: &MiningSettings,
    ) -> Result<PreparedBlock, String> {
        self.prepare_block_with_operations(count, timestamp, settings, None, Vec::new())
    }
    pub fn prepare_block_with_operations(
        &mut self,
        count: usize,
        timestamp: u64,
        settings: &MiningSettings,
        operations: Option<crate::eng2_operations::PendingOperations>,
        issuances: Vec<crate::issuance::IssuanceRecord>,
    ) -> Result<PreparedBlock, String> {
        self.ensure_activities_allowed()?;
        self.store.ensure_exportable()?;
        if !(crate::wire::MIN_SLOTS..=crate::wire::MAX_SLOTS).contains(&count)
            || !count.is_multiple_of(crate::wire::GROUP)
        {
            return Err("production position count rejected".into());
        }
        let state = self.store.engine().state().chain();
        self.padding.prune(state)?;
        let mut positions = self
            .pending
            .select(state, count)
            .map_err(|_| "pending transaction selection rejected")?;
        positions.extend(self.padding.take_for_fill(state, count - positions.len())?);
        producer::prepare(
            self.store.engine(),
            positions,
            timestamp,
            settings,
            operations,
            issuances,
        )
    }
    pub fn prepare_work(&self, proved: ProvedBlock) -> Result<Work, String> {
        self.ensure_activities_allowed()?;
        self.store.ensure_exportable()?;
        proved.prepare_work(self.store.engine(), self.verifier.as_ref())
    }
}

impl super::network::Owner for Driver {
    fn authorize_body(
        &mut self,
        header: &Header,
        budget: &crate::p2p::Budget,
        peer_binding: crate::p2p::Binding,
        expires: std::time::Instant,
    ) -> Result<Option<crate::p2p::BodyAuthorization>, String> {
        use siworld_core::pow;
        self.store.ensure_exportable()?;
        let binding = self.store.engine().genesis().peer_binding();
        if peer_binding != binding || header.network != binding.network || header.height == 0 {
            return Err("body authorization immutable context differs".into());
        }
        let id = header.id().map_err(|_| "body identity rejected")?;
        let state = self.store.engine().state();
        if header.height <= state.height()
            && self
                .store
                .header(header.height)?
                .id()
                .map_err(|_| "canonical identity unavailable")?
                == id
        {
            return Ok(None);
        }
        if state.height().checked_add(1) != Some(header.height)
            || header.parent != state.tip()
            || header.timestamp <= state.chain().median_time_past()
            || header.target != state.chain().next_target()
            || !pow::meets_target(
                &pow::pow_hash(
                    &header.pow_seed().map_err(|_| "body header seed rejected")?,
                    header.nonce,
                    self.store.engine().genesis().config().pow_iterations,
                ),
                &header.target,
            )
        {
            return Err("body forward header qualification rejected".into());
        }
        let now_ms = super::network::discovery_now_ms();
        let discovery = if let Some(reorganization) = &mut self.reorganization {
            if reorganization
                .branches
                .entry(id)?
                .is_some_and(|entry| entry.status == super::branches::Status::Invalid)
            {
                return Err("body header is durably invalid".into());
            }
            &mut reorganization.discovery
        } else {
            if self.forward_discovery.is_none() {
                self.forward_discovery = Some(
                    super::branches::discovery::runtime::Discovery::new(
                        binding.network,
                        binding.genesis,
                        super::branches::discovery::runtime::resident_limits(),
                        now_ms,
                        budget.clone(),
                    )
                    .map_err(|e| e.to_string())?,
                );
            }
            self.forward_discovery
                .as_mut()
                .ok_or("forward body owner unavailable")?
        };
        discovery.renew_body_window(now_ms)?;
        let now = std::time::Instant::now();
        let deadline = crate::p2p::Deadline::from_started(
            now,
            expires.saturating_duration_since(now),
            crate::p2p::Cancellation::default(),
        );
        match budget.authorize_body(
            &discovery.body_scope(),
            binding,
            header.height,
            id,
            &deadline,
        ) {
            Ok(authorization) => Ok(Some(authorization)),
            Err(
                crate::p2p::BodyClaimError::Capacity
                | crate::p2p::BodyClaimError::Expired
                | crate::p2p::BodyClaimError::QueryLimit,
            ) => Ok(None),
            Err(_) => Err("body owner authorization unavailable".into()),
        }
    }
    fn exact_exchange_enabled(&self) -> bool {
        self.reorganization.is_some()
    }
    fn branch_discovery_next(
        &mut self,
        remote: (u64, Hash),
        peer: Hash,
        now_ms: u64,
    ) -> Result<super::network::DiscoveryAction, String> {
        let state = self
            .reorganization
            .as_mut()
            .ok_or("independent branch archive unavailable")?;
        if state.paused() {
            return Ok(super::network::DiscoveryAction::Deferred);
        }
        state
            .discovery
            .next(&mut state.branches, &self.store, remote, peer, now_ms)
    }
    fn branch_discovery_received(
        &mut self,
        request: super::branches::discovery::HeaderRequest,
        header: Option<Header>,
        now_ms: u64,
    ) -> Result<(), String> {
        let state = self
            .reorganization
            .as_mut()
            .ok_or("independent branch archive unavailable")?;
        state.discovery.received(request, header, now_ms)
    }
    fn checkpoint_headers_next(
        &mut self,
        remote: (u64, Hash),
        peer: Hash,
        now_ms: u64,
    ) -> Result<super::network::DiscoveryAction, String> {
        let state = self
            .reorganization
            .as_mut()
            .ok_or("independent branch archive unavailable")?;
        if state.paused() {
            return Ok(super::network::DiscoveryAction::Deferred);
        }
        state
            .discovery
            .next_headers(&mut state.branches, &self.store, remote, peer, now_ms)
    }
    fn branch_discovery_deferred(
        &mut self,
        request: super::branches::discovery::HeaderRequest,
        now_ms: u64,
    ) -> Result<(), String> {
        let state = self
            .reorganization
            .as_mut()
            .ok_or("independent branch archive unavailable")?;
        state.discovery.deferred(request, now_ms)
    }
    fn branch_discovery_body(
        &mut self,
        request: super::branches::discovery::HeaderRequest,
        header: &Header,
        body: &Body,
        now_ms: u64,
    ) -> Result<(), String> {
        let policy = self.store.engine().body_policy();
        let state = self
            .reorganization
            .as_mut()
            .ok_or("independent branch archive unavailable")?;
        state
            .discovery
            .body(&mut state.branches, request, header, body, policy, now_ms)
    }
    fn branch_header(&self, id: Hash) -> Result<Option<Header>, String> {
        Driver::branch_header(self, id)
    }
    fn branch_block_size(&self, id: Hash) -> Result<Option<usize>, String> {
        Driver::branch_block_size(self, id)
    }
    fn branch_block(&self, id: Hash) -> Result<(Header, Body), String> {
        Driver::branch_block(self, id)
    }
    fn bootstrap_manifest(
        &mut self,
        authenticated_peer: Hash,
        requested_bundle: Option<Hash>,
    ) -> Result<Option<Vec<u8>>, String> {
        self.ensure_activities_allowed()?;
        let now = std::time::Instant::now();
        self.bootstrap
            .reconcile(now, |provider| provider.check_current(&self.store).is_ok());
        Ok(self
            .bootstrap
            .manifest(authenticated_peer, requested_bundle, now)
            .map(|provider| provider.encoded().to_vec()))
    }
    fn bootstrap_chunk(
        &mut self,
        authenticated_peer: Hash,
        query: super::transport::ChunkRequest,
    ) -> Result<Option<super::bootstrap::Chunk>, String> {
        self.ensure_activities_allowed()?;
        let now = std::time::Instant::now();
        self.bootstrap
            .reconcile(now, |provider| provider.check_current(&self.store).is_ok());
        let Some(provider) = self
            .bootstrap
            .chunk_provider(authenticated_peer, query.bundle, now)
        else {
            return Ok(None);
        };
        let chunk = provider.chunk(
            &self.store,
            query.bundle,
            query.object,
            query.offset,
            query.maximum as usize,
        )?;
        match chunk {
            Some(chunk)
                if self.bootstrap.charge_chunk(
                    authenticated_peer,
                    query.bundle,
                    chunk.bytes.len(),
                    now,
                ) =>
            {
                Ok(Some(chunk))
            }
            _ => Ok(None),
        }
    }
    fn head(&self) -> Result<(u64, Hash), String> {
        let head = Driver::head(self)?;
        Ok((head.height, head.id))
    }
    fn header(&self, height: u64) -> Result<Option<Header>, String> {
        let head = Driver::head(self)?;
        if height == 0 || height > head.height {
            return Ok(None);
        }
        Driver::header(self, height).map(Some)
    }
    fn block_size(&self, height: u64) -> Result<Option<usize>, String> {
        let head = Driver::head(self)?;
        if height == 0 || height > head.height {
            return Ok(None);
        }
        Driver::block_size(self, height).map(Some)
    }
    fn block(&self, height: u64) -> Result<(Header, Body), String> {
        Driver::block(self, height)
    }
    fn accept(&mut self, header: &Header, body: &Body) -> Result<(), String> {
        Driver::accept(self, header, body).map(|_| ())
    }
    #[cfg(feature = "eng2-runtime")]
    fn body_progress(
        &self,
        header: &Header,
        peer: Hash,
        claim: &crate::p2p::BodyClaim,
    ) -> Result<Option<super::network::BodyProgress>, String> {
        Ok(self
            .header_hub
            .as_ref()
            .and_then(|hub| hub.observe_body(header, peer, claim)))
    }
    #[cfg(feature = "eng2-runtime")]
    fn accept_received(
        &mut self,
        header: &Header,
        received: &super::transport::ReceivedBody,
    ) -> Result<(), String> {
        self.accept_observed_with_receipts(
            header,
            &received.body,
            received.observation,
            received.receipts.as_ref(),
        )
        .map(|_| ())
    }
}

#[cfg(feature = "eng2-runtime")]
impl super::transaction_exchange::Owner for Driver {
    fn transaction_ids(&self) -> Vec<Hash> {
        Driver::transaction_ids(self)
    }
    fn has_transaction(&self, id: &Hash) -> bool {
        Driver::has_transaction(self, id)
    }
    fn transaction_packet(&self, id: &Hash) -> Result<Option<Vec<u8>>, String> {
        Driver::transaction_packet(self, id)
    }
    fn submit_transaction(
        &mut self,
        peer: Hash,
        expected: Hash,
        packet: &[u8],
        deadline: &crate::p2p::Deadline,
    ) -> Result<Hash, String> {
        self.submit_transaction_before(peer, expected, packet, deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn late_verification_or_final_commit_never_inserts_pending_work() {
        use crate::admission::{AdmissionVerifier, VerificationError};
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };
        struct Late {
            clock: Arc<AtomicU64>,
            after_verify: bool,
        }
        impl AdmissionVerifier for Late {
            fn verify(
                &self,
                _: &native::codec::PublicTransaction,
                _: &native::codec::ProofContext,
                _: &native::multi_asset::Digest,
                _: &native::multi_asset::Digest,
                _: &[u8],
            ) -> Result<(), VerificationError> {
                if self.after_verify {
                    self.clock.store(20_000, Ordering::Relaxed);
                }
                Ok(())
            }
            fn check_commit(&self) -> Result<(), VerificationError> {
                if !self.after_verify {
                    self.clock.store(20_000, Ordering::Relaxed);
                }
                Ok(())
            }
        }
        let state = super::super::snapshot::tests::bootstrap().chain;
        let mut transaction = crate::fixtures::candidate(&state, 2_500_000)
            .transactions
            .remove(0);
        transaction.record.fee_commit = native::codec::encode_digest(
            &native::multi_asset::Hasher::new()
                .fee_commit(0, &[native::multi_asset::F::default(); 8]),
        );
        let id = transaction.record.statement_id(&state.config.network);
        let sidecar = crate::wire::Sidecar {
            transaction_id: id,
            fee: 0,
            blind: [0; 8],
        }
        .encode()
        .unwrap();
        let envelope = transaction.encode_envelope(&state.config.network).unwrap();
        for after_verify in [true, false] {
            let clock = Arc::new(AtomicU64::new(0));
            let deadline =
                crate::p2p::Deadline::test_clock(std::time::Duration::from_secs(10), clock.clone());
            let late = Late {
                clock: clock.clone(),
                after_verify,
            };
            let mut pool = Mempool::new(state.config.network);
            assert!(
                pool.submit_encoded(
                    &state,
                    PeerId([7; 32]),
                    &envelope,
                    Some(&sidecar),
                    &TimedAdmission {
                        verifier: &late,
                        deadline: &deadline
                    }
                )
                .is_err()
            );
            assert_eq!(clock.load(Ordering::Relaxed), 20_000);
            assert!(pool.is_empty());
            assert_eq!(pool.bytes(), 0);
            assert_eq!(pool.peer_count(), 0);
        }
    }
    #[test]
    fn actual_driver_authorization_keeps_failed_accounts_without_exhausting_io_slots() {
        let initial = super::super::snapshot::tests::bootstrap();
        let genesis = super::super::genesis::Genesis::seal(
            initial.chain.config.clone(),
            initial.governance.clone(),
            super::super::genesis::FeeMode::LegacyMiner,
        )
        .unwrap();
        let imports = ImportLimits {
            chain: super::super::state_components::Limits {
                max_leaves: 10_000,
                max_nullifiers: 10_000,
                max_component_bytes: 16 * 1024 * 1024,
            },
            max_snapshot_bytes: 32 * 1024 * 1024,
        };
        let directory =
            std::env::temp_dir().join(format!("driver-body-authority-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let store = Store::create(&directory.join("chain.redb"), genesis, imports.chain).unwrap();
        let verifier = NativeVerifier::for_genesis(store.engine().genesis()).unwrap();
        let mut owner = Driver::new(store, verifier, imports).unwrap();
        let budget = crate::p2p::Budget::new(64 * 1024 * 1024);
        let binding = owner.engine().genesis().peer_binding();
        let mut header = super::super::header::Header {
            network: binding.network,
            height: 1,
            parent: binding.genesis,
            timestamp: owner.engine().genesis().config().genesis_timestamp + 300,
            target: owner.engine().state().chain().next_target(),
            execution_commitment: [3; 32],
            body_commitment: [4; 32],
            nonce: 0,
        };
        for tag in 1u8..=100 {
            header.execution_commitment = [tag; 32];
            let auth = super::super::network::Owner::authorize_body(
                &mut owner,
                &header,
                &budget,
                binding,
                std::time::Instant::now() + std::time::Duration::from_secs(180),
            )
            .unwrap()
            .unwrap();
            let session = crate::p2p::Session::from_test_channel(
                std::io::Cursor::new(Vec::<u8>::new()),
                binding,
                budget.clone(),
            );
            let mut peer = super::super::transport::Peer::new(
                session,
                owner.engine().genesis(),
                owner.engine().body_policy(),
            )
            .unwrap();
            let lease = peer
                .claim_body_authorized(&header, &auth, crate::p2p::BodyMode::Legacy)
                .unwrap();
            // The actual ordinary transport writes a request and observes a disconnected
            // response, releasing physical ownership without completing its account.
            assert!(
                peer.fetch_body_owned(u64::from(tag), &header, lease, None)
                    .is_err()
            );
            assert_eq!(
                budget
                    .claim_body_authorized(&auth, [9; 32], crate::p2p::BodyMode::Pieces)
                    .unwrap_err(),
                crate::p2p::BodyClaimError::SourceUsed
            );
        }
        #[cfg(unix)]
        {
            let mut body = super::super::body::tests::body();
            body.network = binding.network;
            body.height = 1;
            body.profile = owner.engine().body_policy().profile;
            body.governance.clear();
            body.fund_claims.clear();
            body.transactions
                .sort_by_key(|transaction| transaction.record.statement_id(&body.network));
            header.execution_commitment = [201; 32];
            header.body_commitment = body.commitment(owner.engine().body_policy()).unwrap();
            let auth = super::super::network::Owner::authorize_body(
                &mut owner,
                &header,
                &budget,
                binding,
                std::time::Instant::now() + super::super::transport::BODY_FETCH_TIMEOUT,
            )
            .unwrap()
            .unwrap();
            let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
            a.set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut receiver = super::super::transport::Peer::new(
                crate::p2p::Session::from_test_channel(a, binding, budget.clone()),
                owner.engine().genesis(),
                owner.engine().body_policy(),
            )
            .unwrap();
            let mut sender = super::super::transport::Peer::new(
                crate::p2p::Session::from_test_channel(b, binding, budget.clone()),
                owner.engine().genesis(),
                owner.engine().body_policy(),
            )
            .unwrap();
            let expected = body.clone();
            let sent_header = header.clone();
            let worker = std::thread::spawn(move || {
                let (request, _) = sender.receive_request().unwrap();
                sender.send_body(request, &sent_header, &body).unwrap();
            });
            let lease = receiver
                .claim_body_authorized(&header, &auth, crate::p2p::BodyMode::Legacy)
                .unwrap();
            let received = receiver
                .fetch_body_owned(101, &header, lease, None)
                .unwrap()
                .unwrap();
            assert_eq!(received.body, expected);
            drop(received);
            worker.join().unwrap();
        }
        assert_eq!(owner.engine().state().height(), 0);
        let mut wrong = binding;
        wrong.genesis = [9; 32];
        assert!(
            super::super::network::Owner::authorize_body(
                &mut owner,
                &header,
                &budget,
                wrong,
                std::time::Instant::now() + std::time::Duration::from_secs(180)
            )
            .is_err()
        );
        drop(owner);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn resident_owner_rejects_synthetic_native_proofs_without_publication() {
        let initial = super::super::snapshot::tests::bootstrap();
        let genesis = super::super::genesis::Genesis::seal(
            initial.chain.config.clone(),
            initial.governance.clone(),
            super::super::genesis::FeeMode::LegacyMiner,
        )
        .unwrap();
        let imports = ImportLimits {
            chain: super::super::state_components::Limits {
                max_leaves: 10_000,
                max_nullifiers: 10_000,
                max_component_bytes: 16 * 1024 * 1024,
            },
            max_snapshot_bytes: 32 * 1024 * 1024,
        };
        let directory = std::env::temp_dir().join(format!("eng2-driver-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("chain.redb");
        let store = Store::create(&path, genesis, imports.chain).unwrap();
        let verifier = NativeVerifier::for_genesis(store.engine().genesis()).unwrap();
        let mut owner = Driver::new(store, verifier, imports).unwrap();
        let head = owner.head().unwrap();
        assert_eq!(head.height, 0);
        assert!(
            super::super::network::Owner::header(&owner, 1)
                .unwrap()
                .is_none()
        );
        assert!(
            super::super::network::Owner::block_size(&owner, 1)
                .unwrap()
                .is_none()
        );
        let mut pending = crate::fixtures::candidate(owner.engine().state().chain(), 2_500_000)
            .transactions
            .remove(0);
        pending.record.fee_commit = native::codec::encode_digest(
            &native::multi_asset::Hasher::new()
                .fee_commit(0, &[native::multi_asset::F::default(); 8]),
        );
        let pending_id = pending.record.statement_id(&head.network);
        let packet = crate::runtime::encode_gossip(
            &pending,
            &crate::wire::Sidecar {
                transaction_id: pending_id,
                fee: 0,
                blind: [0; 8],
            },
            &head.network,
        )
        .unwrap();
        assert!(
            owner
                .submit_transaction([7; 32], [8; 32], &packet)
                .unwrap_err()
                .contains("identity differs")
        );
        assert!(
            owner
                .submit_transaction([7; 32], pending_id, &packet)
                .is_err()
        );
        assert!(owner.transaction_ids().is_empty());
        assert_eq!(owner.head().unwrap(), head);
        // Seed only this retry-policy test through an explicit mock verifier.
        // The real Driver admission above rejected the same synthetic proof.
        struct Accepted;
        impl crate::admission::AdmissionVerifier for Accepted {
            fn verify(
                &self,
                _: &native::codec::PublicTransaction,
                _: &native::codec::ProofContext,
                _: &native::multi_asset::Digest,
                _: &native::multi_asset::Digest,
                _: &[u8],
            ) -> Result<(), crate::admission::VerificationError> {
                Ok(())
            }
        }
        let envelope_length = u32::from_le_bytes(packet[..4].try_into().unwrap()) as usize;
        owner
            .pending
            .submit_encoded(
                owner.store.engine().state().chain(),
                PeerId([7; 32]),
                &packet[4..4 + envelope_length],
                Some(&packet[4 + envelope_length..]),
                &Accepted,
            )
            .unwrap();
        assert_eq!(
            owner
                .submit_transaction([7; 32], pending_id, &packet)
                .unwrap(),
            pending_id
        );
        let mut different = packet.clone();
        different[4 + envelope_length - 1] ^= 1;
        assert!(
            owner
                .submit_transaction([7; 32], pending_id, &different)
                .unwrap_err()
                .contains("retry differs")
        );
        assert_eq!(owner.transaction_ids(), vec![pending_id]);
        assert_eq!(owner.head().unwrap(), head);
        owner.pending.remove(&pending_id);
        let old = crate::fixtures::candidate(owner.engine().state().chain(), 2_500_000);
        let body = Body {
            network: old.network,
            height: old.height,
            profile: owner.engine().body_policy().profile,
            transactions: old.transactions,
            reward_mode: old.reward_mode,
            rewards: old.rewards,
            fee_output: super::super::execution::legacy_fee_output(),
            fund_claims: Vec::new(),
            governance: Vec::new(),
            issuances: Vec::new(),
            settlement_proof: vec![1],
        };
        let header = Header {
            network: body.network,
            height: body.height,
            parent: head.id,
            timestamp: old.timestamp,
            target: old.target,
            execution_commitment: [3; 32],
            body_commitment: body.commitment(owner.engine().body_policy()).unwrap(),
            nonce: 0,
        };
        assert!(owner.accept(&header, &body).is_err());
        assert_eq!(owner.head().unwrap(), head);
        assert_eq!(owner.padding_count(), 0);
        assert!(owner.last_archive_error().is_none());
        assert!(owner.block(1).is_err());
        drop(owner);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
