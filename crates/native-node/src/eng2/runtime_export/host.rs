//! Explicitly constructed, bounded checkpoint coordination for a resident driver.
//! No listener, key generation or service installation occurs. Archive work
//! requires explicit resident opt-in and remains owned by this host.
use super::*;
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

const KEY_MAGIC: &[u8; 8] = b"SW2KEY01";
const KEY_BYTES: usize = 8 + 96 + 1 + 32 + 32;
pub use crate::eng2::checkpoint_wire::{
    Incoming, MAX_CHECKPOINT_PACKET_BYTES, MAX_MESSAGES_PER_TICK, Proposal,
};

/// Existing synthetic engineering-network key only. This loader has no write
/// or initialization method, and deliberately does not accept any V1 key file.
pub struct ExistingSigner {
    network: Hash,
    genesis: Hash,
    rules: Hash,
    slot: u8,
    public: [u8; super::super::certificate::VERIFYING_KEY_BYTES],
    key: MLDSA65SigningKey,
}
impl Drop for ExistingSigner {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}
impl std::fmt::Debug for ExistingSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExistingCheckpointSigner(REDACTED)")
    }
}
impl ExistingSigner {
    pub fn load(path: &Path, store: &Store) -> Result<Self, String> {
        store.ensure_exportable()?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NONBLOCK)
                    .bits() as i32,
            )
            .open(path)
            .map_err(|_| "existing eng2 test signer unavailable")?;
        let metadata = file
            .metadata()
            .map_err(|_| "eng2 signer metadata unavailable")?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.len() != KEY_BYTES as u64
        {
            return Err("eng2 signer requires an exact owner-only regular record".into());
        }
        let mut bytes = Zeroizing::new([0u8; KEY_BYTES]);
        file.read_exact(bytes.as_mut())
            .map_err(|_| "eng2 signer read failed")?;
        let mut trailing = [0u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| "eng2 signer trailing read failed")?
            != 0
        {
            return Err("eng2 signer record length changed".into());
        }
        let engine = store.engine();
        let network = engine.state().network();
        let genesis = engine.genesis().id();
        let rules = engine.genesis().rules_commitment();
        if &bytes[..8] != KEY_MAGIC
            || bytes[8..40] != network
            || bytes[40..72] != genesis
            || bytes[72..104] != rules
            || bytes[137..]
                != blake3::derive_key(
                    "siworld eng2 checkpoint test signer record v1",
                    &bytes[..137],
                )
        {
            return Err(
                "eng2 signer record is malformed or belongs to another immutable context".into(),
            );
        }
        let slot = bytes[104];
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(&bytes[105..137]).map_err(|_| "eng2 signer seed width invalid")?,
        );
        let pair = ml_dsa_65::generate_key_pair(*seed);
        let value = Self {
            network,
            genesis,
            rules,
            slot,
            public: *pair.verification_key.as_ref(),
            key: pair.signing_key,
        };
        value.check_current(store)?;
        Ok(value)
    }
    pub fn slot(&self) -> u8 {
        self.slot
    }
    pub fn public_key(&self) -> &[u8; super::super::certificate::VERIFYING_KEY_BYTES] {
        &self.public
    }
    fn check_current(&self, store: &Store) -> Result<(), String> {
        store.ensure_exportable()?;
        let engine = store.engine();
        self.check_authorization(
            engine.state().network(),
            engine.genesis().id(),
            engine.genesis().rules_commitment(),
            engine.state().governance().active_roster(),
        )
    }
    fn check_authorization(
        &self,
        network: Hash,
        genesis: Hash,
        rules: Hash,
        roster: &ActiveRoster,
    ) -> Result<(), String> {
        if network != self.network
            || genesis != self.genesis
            || rules != self.rules
            || roster.keys().get(usize::from(self.slot)) != Some(&self.public)
        {
            return Err("eng2 signer is not authorized in the current local roster".into());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alarm {
    Unavailable,
    Stale,
    SignerNotCurrent,
    WaitingForPeerHead,
    CurrentQuorumConflict,
}
impl Alarm {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "checkpoint_unavailable",
            Self::Stale => "checkpoint_stale",
            Self::SignerNotCurrent => "checkpoint_signer_not_current",
            Self::WaitingForPeerHead => "checkpoint_signing_waiting_for_current_peer_tip",
            Self::CurrentQuorumConflict => "checkpoint_current_quorum_conflict",
        }
    }
}
/// Fixed diagnostic origins for a failed tick. No error text or input is exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TickFailureReason {
    Context,
    InputBounds,
    Preparation,
    Proposal,
    Vote,
    VoteWithoutCandidate,
    Certificate,
    CertificatePreparationPending,
    CandidatePreparation,
    VoteSigning,
    CertificatePublication,
    StatusPublication,
    CurrentProjection,
}
impl TickFailureReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::Context => "context",
            Self::InputBounds => "input_bounds",
            Self::Preparation => "preparation",
            Self::Proposal => "proposal",
            Self::Vote => "vote",
            Self::VoteWithoutCandidate => "vote_without_candidate",
            Self::Certificate => "certificate",
            Self::CertificatePreparationPending => "certificate_preparation_pending",
            Self::CandidatePreparation => "candidate_preparation",
            Self::VoteSigning => "vote_signing",
            Self::CertificatePublication => "certificate_publication",
            Self::StatusPublication => "status_publication",
            Self::CurrentProjection => "current_projection",
        }
    }
}
// Only the resident entry point can construct the production readiness gate.
// Public observation never accepts an asserted boolean or a caller-made permit.
struct SigningGuard<'a> {
    #[cfg(feature = "eng2-runtime")]
    _network: crate::eng2::resident::peers::CheckpointReady<'a>,
    #[cfg(not(feature = "eng2-runtime"))]
    _marker: std::marker::PhantomData<&'a ()>,
}
trait SigningReadiness {
    fn guard(&self, store: &Store) -> Result<SigningGuard<'_>, Alarm>;
    fn alarm(&self, store: &Store) -> Option<Alarm> {
        self.guard(store).err()
    }
}
fn with_signing_readiness<T>(
    store: &Store,
    readiness: Option<&dyn SigningReadiness>,
    action: impl FnOnce() -> Result<T, String>,
) -> Result<Option<T>, String> {
    let Some(gate) = readiness else {
        return Ok(None);
    };
    let Ok(_guard) = gate.guard(store) else {
        return Ok(None);
    };
    action().map(Some)
}
#[cfg(feature = "eng2-runtime")]
struct ResidentSigningReadiness<'a> {
    head: (Hash, Hash, Hash, u64, Hash, Hash),
    network: &'a crate::eng2::resident::peers::NetworkStatus,
    observer: &'a crate::eng2::checkpoint_observer::Observer,
}
#[cfg(feature = "eng2-runtime")]
impl ResidentSigningReadiness<'_> {
    fn head(store: &Store) -> Result<(Hash, Hash, Hash, u64, Hash, Hash), String> {
        store.ensure_exportable()?;
        let engine = store.engine();
        let state = engine.state();
        Ok((
            state.network(),
            engine.genesis().id(),
            engine.genesis().rules_commitment(),
            state.height(),
            state.tip(),
            state.governance().active_roster().digest(state.network()),
        ))
    }
}
#[cfg(feature = "eng2-runtime")]
impl SigningReadiness for ResidentSigningReadiness<'_> {
    fn guard(&self, store: &Store) -> Result<SigningGuard<'_>, Alarm> {
        if Self::head(store).ok().as_ref() != Some(&self.head) {
            return Err(Alarm::Unavailable);
        }
        if self.observer.conflicted() {
            return Err(Alarm::CurrentQuorumConflict);
        }
        let guard = self
            .network
            .checkpoint_ready((self.head.3, self.head.4))
            .map_err(|_| Alarm::WaitingForPeerHead)?;
        Ok(SigningGuard { _network: guard })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub height: u64,
    pub checkpoint_height: Option<u64>,
    pub published: Option<u64>,
    pub pending_height: Option<u64>,
    pub pruning_paused: bool,
    pub alarm: Option<Alarm>,
    pub signer_slot: Option<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicCertificate {
    pub certificate: Certificate,
    pub witness: AuthorizationWitness,
}
pub struct Tick {
    pub status: Status,
    pub proposal: Option<Proposal>,
    pub vote: Option<Vote>,
    pub certificate: Option<PublicCertificate>,
    pub newly_published: bool,
    pub exported_current: bool,
}
/// Exactly one tick is called by the existing canonical-state owner. Incoming
/// candidates are claims, never an authority to replace or mutate chain state.
pub struct Host {
    export: PublicExport,
    signer: Option<ExistingSigner>,
    limits: ImportLimits,
    pending: Option<PreparedCheckpoint>,
    votes: [Option<Vote>; 3],
    latest: Option<CertifiedCheckpoint>,
    last_now: Option<u64>,
    last_exported: Option<(u64, Hash, Option<u64>)>,
    last_status: Option<Status>,
    tick_failure: Option<TickFailureReason>,
    wallet: Option<WalletPublisher>,
    wallet_requested: bool,
    wallet_paused: bool,
    retired_through: Option<u64>,
    retained_head: Option<(u64, Hash)>,
    preparation: Option<ResidentPreparation>,
}
struct ResidentPreparation {
    budget: crate::p2p::Budget,
    worker: archive_work::ArchiveWorker,
    request: Option<Proposal>,
    completed: Option<PreparedCheckpoint>,
    certificate_only: bool,
    generation: u64,
    request_generation: u64,
}
impl ResidentPreparation {
    /// Invalidate without joining: the caller may own the canonical Store.
    /// Keep an in-flight request until its exact owned result is drained.
    fn invalidate(&mut self) -> Result<(), String> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or("checkpoint preparation generation exhausted")?;
        self.worker.cancel();
        self.completed = None;
        if !self.worker.is_busy() {
            self.request = None;
            self.request_generation = self.generation;
            self.certificate_only = false;
        }
        Ok(())
    }
}
impl Host {
    /// The failed operation's bounded origin; the original Result is unchanged.
    pub fn tick_failure_reason(&self) -> Option<TickFailureReason> {
        self.tick_failure
    }
    /// The accepted, durably published capability only; pending proposals and
    /// votes cannot be exposed as signed bootstrap state.
    pub fn latest_checkpoint(&self) -> Option<&CertifiedCheckpoint> {
        self.latest.as_ref()
    }
    /// Explicit opt-in only. `existing_key=None` creates a nonsigning observer;
    /// a missing or invalid requested key is rejected rather than initialized.
    pub fn open(
        root: &Path,
        store: &Store,
        limits: ImportLimits,
        existing_key: Option<&Path>,
    ) -> Result<Self, String> {
        let export = PublicExport::open(root, store, limits)?;
        let signer = existing_key
            .map(|path| ExistingSigner::load(path, store))
            .transpose()?;
        let latest = export.restore_latest(store, limits)?;
        let pending = export.resume_candidate(store, limits)?.filter(|candidate| {
            !super::pending_obsolete(
                candidate.statement().checkpoint_height,
                export.latest_height(),
                store.engine().state().height(),
            )
        });
        Ok(Self {
            export,
            signer,
            limits,
            pending,
            votes: std::array::from_fn(|_| None),
            latest,
            last_now: None,
            last_exported: None,
            last_status: None,
            tick_failure: None,
            wallet: None,
            wallet_requested: false,
            wallet_paused: false,
            retired_through: None,
            retained_head: None,
            preparation: None,
        })
    }
    /// Open retained local publications without granting an obsolete
    /// authorization signing or publication authority. Corruption, missing old
    /// headers and invalid signatures remain errors. The strict `open` is unchanged.
    pub fn open_retained(
        root: &Path,
        store: &Store,
        limits: ImportLimits,
        existing_key: Option<&Path>,
        retained: impl FnMut(u64, Hash) -> Result<Option<Header>, String>,
    ) -> Result<Self, String> {
        let export = PublicExport::open_unrestored(root, store)?;
        let signer = existing_key
            .map(|path| ExistingSigner::load(path, store))
            .transpose()?;
        let mut value = Self {
            export,
            signer,
            limits,
            pending: None,
            votes: std::array::from_fn(|_| None),
            latest: None,
            last_now: None,
            last_exported: None,
            last_status: None,
            tick_failure: None,
            wallet: None,
            wallet_requested: false,
            wallet_paused: false,
            retired_through: None,
            retained_head: None,
            preparation: None,
        };
        value.reconcile_retained(store, retained)?;
        Ok(value)
    }
    fn retire_anchor(&mut self, height: u64) -> Result<(), String> {
        self.retired_through = Some(self.retired_through.map_or(height, |old| old.max(height)));
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| self.anchor_retired(pending.statement.checkpoint_height))
        {
            self.pending = None;
            self.votes = std::array::from_fn(|_| None);
        }
        if let Some(preparation) = &mut self.preparation {
            preparation.invalidate()?;
        }
        Ok(())
    }
    fn anchor_retired(&self, height: u64) -> bool {
        self.retired_through
            .is_some_and(|retired| height <= retired)
    }
    /// Call under the canonical owner lock after a transition or on retained
    /// startup, before a signing/publication tick. Immutable evidence is never
    /// deleted; only fully validated obsolete mutable advertisements are retired.
    pub fn reconcile_retained(
        &mut self,
        store: &Store,
        mut retained: impl FnMut(u64, Hash) -> Result<Option<Header>, String>,
    ) -> Result<(), String> {
        use super::retained::Restored;
        store.ensure_exportable()?;
        let head = (
            store.engine().state().height(),
            store.engine().state().tip(),
        );
        if self.retained_head == Some(head) {
            return Ok(());
        }
        match self
            .export
            .restore_latest_retained(store, self.limits, &mut retained)?
        {
            Restored::Absent => {
                self.latest = None;
            }
            Restored::Current(checkpoint) => {
                self.export.remember_publication(&checkpoint)?;
                self.latest = Some(checkpoint);
            }
            Restored::Retired(height) => {
                self.export.remove_retired_checkpoint_cursor(height)?;
                self.latest = None;
                self.last_exported = None;
                self.retire_anchor(height)?;
            }
        }
        match self
            .export
            .resume_candidate_retained(store, self.limits, &mut retained)?
        {
            Restored::Absent => (),
            Restored::Current(candidate) => {
                if !self.anchor_retired(candidate.statement.checkpoint_height)
                    && !super::pending_obsolete(
                        candidate.statement.checkpoint_height,
                        self.export.latest_height(),
                        store.engine().state().height(),
                    )
                {
                    let unchanged = self
                        .pending
                        .as_ref()
                        .is_some_and(|old| old.statement == candidate.statement);
                    self.pending = Some(candidate);
                    if !unchanged {
                        self.votes = std::array::from_fn(|_| None);
                    }
                }
            }
            Restored::Retired(height) => self.retire_anchor(height)?,
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|candidate| self.anchor_retired(candidate.statement.checkpoint_height))
        {
            self.pending = None;
            self.votes = std::array::from_fn(|_| None);
        }
        self.retained_head = Some(head);
        Ok(())
    }
    /// The barrier runs before ancestor restoration. Authorizations at or below
    /// the ancestor retain their original valid advertisement and publication
    /// time. Later authorizations are withdrawn and cannot be signed again at
    /// the same anchor, including after a failed restore followed by restart.
    pub fn pause_reorganization_exports_at(&mut self, ancestor_height: u64) -> Result<(), String> {
        // Capture unsigned work before invalidation drops its completed buffer.
        let preparation_anchor = self.preparation.as_ref().and_then(|preparation| {
            preparation
                .request
                .as_ref()
                .map(|request| &request.statement)
                .into_iter()
                .chain(preparation.completed.as_ref().map(|value| &value.statement))
                .filter(|statement| statement.authorization_height > ancestor_height)
                .map(|statement| statement.checkpoint_height)
                .max()
        });
        self.pause_reorganization_exports()?;
        self.retained_head = None;
        if let Some(height) = preparation_anchor {
            self.retire_anchor(height)?;
        }
        if let Some(checkpoint) = &self.latest
            && checkpoint.prepared.authorization.height > ancestor_height
        {
            self.export.withdraw_checkpoint(checkpoint)?;
            let height = checkpoint.certificate.statement.checkpoint_height;
            self.latest = None;
            self.last_exported = None;
            self.retire_anchor(height)?;
        }
        if let Some(pending) = &self.pending
            && pending.authorization.height > ancestor_height
        {
            self.retire_anchor(pending.statement.checkpoint_height)?;
        }
        Ok(())
    }
    /// Explicit wallet opt-in, independent of checkpoint signing and admission.
    /// An opening failure pauses only this export; no new Store is opened.
    pub fn enable_wallet_export(
        &mut self,
        store: &Store,
        policy: WalletPolicy,
        budget: &crate::p2p::Budget,
    ) -> Result<(), String> {
        if self.wallet_requested {
            return Err("wallet export was already requested".into());
        }
        self.wallet_requested = true;
        self.wallet_paused = true;
        self.wallet = Some(WalletPublisher::open(&self.export, store, policy, budget)?);
        self.wallet_paused = false;
        Ok(())
    }
    /// Called under the canonical owner lock before restoring any savepoint.
    /// Signer journals remain untouched; the resident skips signing ticks until
    /// switching finishes and authenticated readiness has been re-established.
    pub fn pause_reorganization_exports(&mut self) -> Result<(), String> {
        if let Some(preparation) = &mut self.preparation {
            preparation.invalidate()?;
        }
        self.export.pause_wallet_head()?;
        if let Some(wallet) = &mut self.wallet {
            wallet.invalidate_advertisement();
        }
        self.wallet_paused = self.wallet_requested;
        Ok(())
    }
    pub fn wallet_export_state(&self) -> Option<bool> {
        self.wallet_requested.then_some(self.wallet_paused)
    }
    /// Enable one keyless archive-preparation worker using the resident's
    /// existing shared budget. The canonical Store is never moved to it.
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn enable_async_preparation(
        &mut self,
        budget: &crate::p2p::Budget,
    ) -> Result<(), String> {
        if self.preparation.is_some() {
            return Err("checkpoint preparation was already enabled".into());
        }
        self.preparation = Some(ResidentPreparation {
            budget: budget.clone(),
            worker: archive_work::ArchiveWorker::default(),
            request: None,
            completed: None,
            certificate_only: false,
            generation: 0,
            request_generation: 0,
        });
        Ok(())
    }
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn stop_preparation(&mut self) -> Result<(), String> {
        if let Some(mut preparation) = self.preparation.take() {
            preparation.completed = None;
            preparation.request = None;
            preparation.worker.stop()?;
        }
        Ok(())
    }
    fn advance_preparation(
        &mut self,
        store: &Store,
        readiness: Option<&dyn SigningReadiness>,
    ) -> Result<(), String> {
        let retired_through = self.retired_through;
        let Some(preparation) = &mut self.preparation else {
            return Ok(());
        };
        let result = preparation.worker.try_complete();
        if preparation.request_generation != preparation.generation {
            // A cancelled obsolete task may return either cancellation or a
            // complete result. Neither can regain authority after the barrier.
            if !preparation.worker.is_busy() {
                preparation.request = None;
                preparation.completed = None;
                preparation.request_generation = preparation.generation;
                preparation.certificate_only = false;
            }
            drop(result);
            return Ok(());
        }
        if let Some(archive) = result? {
            let request = preparation
                .request
                .take()
                .ok_or("checkpoint preparation request missing")?;
            if retired_through.is_some_and(|height| request.statement.checkpoint_height <= height) {
                return Ok(());
            }
            // Canonical extension is allowed. Replaced anchor/authorization
            // headers, epoch or immutable context invalidate the result.
            if archive.check_current(store).is_ok() {
                preparation.completed = Some(PreparedCheckpoint::from_validated_archive(
                    store,
                    archive,
                    request.statement,
                    request.witness,
                    self.limits,
                )?);
            }
        }
        if let Some(completed) = &preparation.completed {
            if retired_through.is_some_and(|height| completed.statement.checkpoint_height <= height)
                || completed.check_current(store).is_err()
                || pending_obsolete(
                    completed.statement.checkpoint_height,
                    self.export.latest_height(),
                    store.engine().state().height(),
                )
            {
                preparation.completed = None;
                return Ok(());
            }
            if preparation.certificate_only {
                return Ok(());
            }
            if let Some(pending) = &self.pending {
                if pending.statement != completed.statement || pending.witness != completed.witness
                {
                    // A durable pending candidate retains priority over an
                    // unsigned completed task. Do not block incoming quorum
                    // certificates behind work that is no longer needed.
                    preparation.completed = None;
                    return Ok(());
                }
                preparation.completed = None;
                return Ok(());
            }
            if with_signing_readiness(store, readiness, || {
                self.export.retain_prepared(store, completed, self.limits)
            })?
            .is_some()
            {
                self.pending = preparation.completed.take();
            }
        }
        Ok(())
    }
    fn start_local_preparation(
        &mut self,
        store: &Store,
        readiness: Option<&dyn SigningReadiness>,
    ) -> Result<(), String> {
        let retired_through = self.retired_through;
        let preparation = self
            .preparation
            .as_mut()
            .ok_or("checkpoint preparation unavailable")?;
        if preparation.worker.is_busy() || preparation.completed.is_some() {
            return Ok(());
        }
        if let Some((request, work)) = with_signing_readiness(store, readiness, || {
            let (statement, witness) = PreparedCheckpoint::current_proposal(store, self.limits)?
                .ok_or("eligible checkpoint disappeared")?;
            if retired_through.is_some_and(|height| statement.checkpoint_height <= height) {
                return Err("checkpoint preparation anchor is retired".into());
            }
            let work = store.capture_checkpoint_archive(
                statement.checkpoint_height,
                self.limits,
                &preparation.budget,
            )?;
            Ok((Proposal { statement, witness }, work))
        })? {
            preparation.worker.start(work)?;
            preparation.request = Some(request);
            preparation.request_generation = preparation.generation;
            preparation.certificate_only = false;
        }
        Ok(())
    }
    fn schedule_peer_preparation(
        &mut self,
        store: &Store,
        proposal: &Proposal,
        certificate_only: bool,
    ) -> Result<(), String> {
        if self.anchor_retired(proposal.statement.checkpoint_height) {
            return Err("checkpoint preparation anchor is retired".into());
        }
        let preparation = self
            .preparation
            .as_mut()
            .ok_or("checkpoint preparation unavailable")?;
        PreparedCheckpoint::proposal_context(
            store,
            &proposal.statement,
            &proposal.witness,
            self.limits,
        )?;
        if let Some(completed) = &preparation.completed {
            if completed.statement != proposal.statement || completed.witness != proposal.witness {
                if !certificate_only {
                    return Err("checkpoint preparation conflicts with completed candidate".into());
                }
                preparation.completed = None;
            } else {
                return Ok(());
            }
        }
        if preparation.worker.is_busy() {
            if preparation.request.as_ref() != Some(proposal) {
                if certificate_only {
                    preparation.invalidate()?;
                }
                return Err("checkpoint preparation already owns another candidate".into());
            }
            return Ok(());
        }
        let work = store.capture_checkpoint_archive(
            proposal.statement.checkpoint_height,
            self.limits,
            &preparation.budget,
        )?;
        preparation.worker.start(work)?;
        preparation.request = Some(proposal.clone());
        preparation.request_generation = preparation.generation;
        preparation.certificate_only = certificate_only;
        Ok(())
    }
    fn completed_certificate_preparation(
        &mut self,
        store: &Store,
        proposal: &Proposal,
        certificate: &Certificate,
    ) -> Result<Option<PreparedCheckpoint>, String> {
        if self.anchor_retired(proposal.statement.checkpoint_height) {
            return Err("checkpoint certificate anchor is retired".into());
        }
        if let Some(pending) = &self.pending
            && pending.statement == proposal.statement
            && pending.witness == proposal.witness
        {
            pending.check_current(store)?;
            certificate
                .check_signatures(pending.roster.keys())
                .map_err(|_| "checkpoint certificate signatures invalid")?;
            return Ok(self.pending.take());
        }
        if let Some(preparation) = &mut self.preparation
            && let Some(completed) = &preparation.completed
            && completed.statement == proposal.statement
            && completed.witness == proposal.witness
        {
            completed.check_current(store)?;
            certificate
                .check_signatures(completed.roster.keys())
                .map_err(|_| "checkpoint certificate signatures invalid")?;
            return Ok(preparation.completed.take());
        }
        Ok(None)
    }
    /// The existing resident owner calls one step with its shared budget.
    /// Failure cannot stop checkpoint coordination or canonical validation.
    pub fn tick_wallet_export(
        &mut self,
        store: &Store,
        now: u64,
        budget: &crate::p2p::Budget,
    ) -> Result<Option<WalletProgress>, String> {
        if !self.wallet_requested {
            return Ok(None);
        }
        let result = self
            .wallet
            .as_mut()
            .ok_or_else(|| "wallet publisher unavailable".to_string())
            .and_then(|publisher| publisher.tick(&self.export, store, now, budget));
        self.wallet_paused = result.is_err();
        result.map(Some)
    }
    /// Observe public messages and publish accepted data without creating a new
    /// proposal or signature. An existing key alone grants no network readiness.
    pub fn tick(&mut self, store: &Store, now: u64, incoming: &[Incoming]) -> Result<Tick, String> {
        self.tick_inner(store, now, incoming, None)
    }
    /// Called while the resident owns the canonical Store lock and observer
    /// guard, in owner -> observer -> network order. Readiness is checked again
    /// at each new proposal/signature; no reusable permit escapes this call.
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn tick_resident(
        &mut self,
        store: &Store,
        now: u64,
        incoming: &[Incoming],
        network: &crate::eng2::resident::peers::NetworkStatus,
        observer: &crate::eng2::checkpoint_observer::Observer,
    ) -> Result<Tick, String> {
        self.tick_failure = Some(TickFailureReason::Context);
        let readiness = ResidentSigningReadiness {
            head: ResidentSigningReadiness::head(store)?,
            network,
            observer,
        };
        self.tick_inner(store, now, incoming, Some(&readiness))
    }
    /// Work is bounded to at most three messages, one local vote, one certificate
    /// and one current projection. Cadence migration may verify a bounded
    /// retained native suffix in an isolated engine. The driver archives each
    /// positive 12-block boundary after durable append.
    fn tick_inner(
        &mut self,
        store: &Store,
        now: u64,
        incoming: &[Incoming],
        readiness: Option<&dyn SigningReadiness>,
    ) -> Result<Tick, String> {
        self.tick_failure = Some(TickFailureReason::Context);
        let result = self.tick_step(store, now, incoming, readiness);
        if result.is_ok() {
            self.tick_failure = None;
        }
        result
    }
    fn tick_step(
        &mut self,
        store: &Store,
        now: u64,
        incoming: &[Incoming],
        readiness: Option<&dyn SigningReadiness>,
    ) -> Result<Tick, String> {
        store.ensure_exportable()?;
        self.tick_failure = Some(TickFailureReason::InputBounds);
        if incoming.len() > MAX_MESSAGES_PER_TICK
            || now >= (1u64 << 53)
            || self.last_now.is_some_and(|last| now < last)
        {
            return Err(
                "eng2 checkpoint tick exceeds message/time bounds or regresses its clock".into(),
            );
        }
        if incoming
            .iter()
            .filter(|item| matches!(item, Incoming::Proposal(_)))
            .count()
            > 1
            || incoming
                .iter()
                .filter(|item| matches!(item, Incoming::Certified { .. }))
                .count()
                > 1
        {
            return Err(
                "eng2 checkpoint tick accepts at most one proposal and one certificate".into(),
            );
        }
        // Reject variable witness sizes before cloning or reconstructing a state.
        for item in incoming {
            let witness = match item {
                Incoming::Proposal(p) => Some(&p.witness),
                Incoming::Certified { witness, .. } => Some(witness),
                _ => None,
            };
            if let Some(witness) = witness {
                witness
                    .encode(
                        self.limits
                            .chain
                            .max_component_bytes
                            .min(crate::eng2::checkpoint_wire::MAX_GOVERNANCE_BYTES),
                    )
                    .map_err(|_| "eng2 incoming checkpoint witness exceeds bounds")?;
            }
        }
        self.last_now = Some(now);
        let state = store.engine().state();
        if self.pending.as_ref().is_some_and(|p| {
            p.check_current(store).is_err()
                || super::pending_obsolete(
                    p.statement().checkpoint_height,
                    self.export.latest_height(),
                    state.height(),
                )
        }) {
            self.pending = None;
            self.votes = std::array::from_fn(|_| None);
        }
        let mut newly_published = false;
        self.tick_failure = Some(TickFailureReason::Preparation);
        self.advance_preparation(store, readiness)?;
        for item in incoming {
            let height = match item {
                Incoming::Proposal(proposal) => proposal.statement.checkpoint_height,
                Incoming::Vote { statement, .. } => statement.checkpoint_height,
                Incoming::Certified { certificate, .. } => certificate.statement.checkpoint_height,
            };
            if self.anchor_retired(height) {
                continue;
            }
            match item {
                Incoming::Proposal(proposal) => {
                    self.tick_failure = Some(TickFailureReason::Proposal);
                    if super::pending_obsolete(
                        proposal.statement.checkpoint_height,
                        self.export.latest_height(),
                        state.height(),
                    ) {
                        continue;
                    }
                    self.accept_proposal(store, proposal)?;
                }
                Incoming::Vote { statement, vote } => {
                    self.tick_failure = Some(TickFailureReason::Vote);
                    if super::pending_obsolete(
                        statement.checkpoint_height,
                        self.export.latest_height(),
                        state.height(),
                    ) {
                        continue;
                    }
                    if self.pending.is_none() {
                        self.tick_failure = Some(TickFailureReason::VoteWithoutCandidate);
                    }
                    let pending = self
                        .pending
                        .as_ref()
                        .ok_or("checkpoint vote has no independently matched candidate")?;
                    if pending.statement() != statement {
                        return Err(
                            "checkpoint vote differs from the durable pending statement".into()
                        );
                    }
                    pending.verify_vote(vote)?;
                    let slot = usize::from(vote.slot);
                    if self.votes[slot]
                        .as_ref()
                        .is_some_and(|previous| previous != vote.as_ref())
                    {
                        return Err(
                            "another signature already occupies this checkpoint signer slot".into(),
                        );
                    }
                    self.votes[slot] = Some((**vote).clone());
                }
                Incoming::Certified {
                    certificate,
                    witness,
                } => {
                    self.tick_failure = Some(TickFailureReason::Certificate);
                    if let Some(latest) = &self.latest
                        && latest.certificate.statement == certificate.statement
                    {
                        if latest.prepared.witness != *witness {
                            return Err("known checkpoint certificate witness differs".into());
                        }
                        certificate
                            .check_signatures(latest.prepared.roster.keys())
                            .map_err(|_| "known checkpoint certificate signatures invalid")?;
                        // Another valid two-slot subset authenticates the same
                        // statement, but must never refresh publication time.
                        continue;
                    }
                    if self
                        .export
                        .latest_height()
                        .is_some_and(|height| certificate.statement.checkpoint_height < height)
                    {
                        // Retired certificates cannot replace a newer local
                        // publication or block its next coordination step.
                        continue;
                    }
                    if self.export.latest_height() != Some(certificate.statement.checkpoint_height)
                        && eligible_checkpoint(state.height())
                            != Some(certificate.statement.checkpoint_height)
                    {
                        return Err(
                            "new checkpoint certificate does not match the current eligible anchor"
                                .into(),
                        );
                    }
                    let prepared = if self.preparation.is_some() {
                        let proposal = Proposal {
                            statement: certificate.statement.clone(),
                            witness: witness.clone(),
                        };
                        let (_, _, roster) = PreparedCheckpoint::proposal_context(
                            store,
                            &proposal.statement,
                            &proposal.witness,
                            self.limits,
                        )?;
                        certificate
                            .check_signatures(roster.keys())
                            .map_err(|_| "checkpoint certificate signatures invalid")?;
                        match self.completed_certificate_preparation(
                            store,
                            &proposal,
                            certificate,
                        )? {
                            Some(prepared) => prepared,
                            None => {
                                self.schedule_peer_preparation(store, &proposal, true)?;
                                // Failed input remains eligible for peer replay
                                // while the owned keyless worker runs.
                                self.tick_failure =
                                    Some(TickFailureReason::CertificatePreparationPending);
                                return Err("checkpoint certificate preparation is pending".into());
                            }
                        }
                    } else {
                        PreparedCheckpoint::from_proposal(
                            store,
                            certificate.statement.clone(),
                            witness.clone(),
                            self.limits,
                        )?
                    };
                    // Publication time is a local observation, never authenticated
                    // by a peer's unsigned wall-clock metadata.
                    self.tick_failure = Some(TickFailureReason::CertificatePublication);
                    if self.anchor_retired(prepared.statement.checkpoint_height) {
                        return Err("checkpoint certificate anchor is retired".into());
                    }
                    prepared.check_current(store)?;
                    let certified = prepared.certify(store, certificate.votes.clone(), now)?;
                    if self
                        .export
                        .publish_checkpoint(store, &certified, self.limits)?
                    {
                        self.latest = Some(certified);
                        newly_published = true;
                        self.pending = None;
                        self.votes = std::array::from_fn(|_| None);
                    }
                }
            }
        }
        self.tick_failure = Some(TickFailureReason::CandidatePreparation);
        let current_signer = self
            .signer
            .as_ref()
            .is_some_and(|signer| signer.check_current(store).is_ok());
        let due = self.export.publication_due(now, state.height())?;
        // Slot zero is the sole local proposer. Other signers wait for its exact
        // independently checked proposal, avoiding competing authorization heads.
        if self.pending.is_none()
            && due
            && eligible_checkpoint(state.height())
                .is_some_and(|height| !self.anchor_retired(height))
            && current_signer
            && self.signer.as_ref().is_some_and(|s| s.slot == 0)
        {
            if self.preparation.is_some() {
                self.start_local_preparation(store, readiness)?;
            } else {
                self.pending = with_signing_readiness(store, readiness, || {
                    self.export.prepare_checkpoint(store, self.limits)
                })?
                .flatten();
            }
        }
        self.tick_failure = Some(TickFailureReason::VoteSigning);
        if let Some(pending) = &self.pending
            && !self.anchor_retired(pending.statement.checkpoint_height)
            && current_signer
            && self
                .export
                .latest_height()
                .is_none_or(|height| pending.statement.checkpoint_height > height)
        {
            pending.check_current(store)?;
            let signer = self
                .signer
                .as_ref()
                .ok_or("checkpoint signer disappeared")?;
            let slot = usize::from(signer.slot);
            if self.votes[slot].is_none() {
                self.votes[slot] = with_signing_readiness(store, readiness, || {
                    let mut random = Zeroizing::new([0; 32]);
                    getrandom::fill(random.as_mut())
                        .map_err(|_| "checkpoint signing entropy unavailable")?;
                    self.export.sign_vote(
                        store,
                        pending,
                        signer.slot,
                        &signer.key,
                        *random,
                        self.limits,
                    )
                })?;
            }
        }
        let available = self
            .votes
            .iter()
            .flatten()
            .take(2)
            .cloned()
            .collect::<Vec<_>>();
        self.tick_failure = Some(TickFailureReason::CertificatePublication);
        if available.len() == 2
            && self
                .pending
                .as_ref()
                .is_some_and(|pending| !self.anchor_retired(pending.statement.checkpoint_height))
            && due
        {
            let prepared = self
                .pending
                .take()
                .ok_or("checkpoint candidate disappeared")?;
            prepared.check_current(store)?;
            let certified = prepared.certify(
                store,
                available
                    .try_into()
                    .map_err(|_| "checkpoint quorum cardinality differs")?,
                now,
            )?;
            if self
                .export
                .publish_checkpoint(store, &certified, self.limits)?
            {
                self.latest = Some(certified);
                newly_published = true;
            }
            self.votes = std::array::from_fn(|_| None);
        }
        self.tick_failure = Some(TickFailureReason::StatusPublication);
        let paused = self.export.pruning_paused(now)?;
        let signing_alarm = self.signer.as_ref().and_then(|_| {
            readiness.map_or(Some(Alarm::WaitingForPeerHead), |gate| gate.alarm(store))
        });
        let alarm = if self.signer.is_some() && !current_signer {
            Some(Alarm::SignerNotCurrent)
        } else if signing_alarm == Some(Alarm::CurrentQuorumConflict) {
            signing_alarm
        } else if self.export.latest_height().is_none() {
            Some(Alarm::Unavailable)
        } else if signing_alarm.is_some() {
            signing_alarm
        } else if paused {
            Some(Alarm::Stale)
        } else {
            None
        };
        let status = Status {
            height: state.height(),
            checkpoint_height: self.export.latest_height(),
            published: self.export.last_publication(),
            pending_height: self.pending.as_ref().map(|p| p.statement.checkpoint_height),
            pruning_paused: paused,
            alarm,
            signer_slot: self.signer.as_ref().map(|s| s.slot),
        };
        if self.last_status.as_ref() != Some(&status) {
            let bytes=serde_json::to_vec(&json!({"version":2,"network":crate::local::hex(&state.network()),"genesis":crate::local::hex(&store.engine().genesis().id()),"height":state.height(),"observed_unix_seconds":now,
                "checkpoint_height":status.checkpoint_height,"published_unix_seconds":status.published,"pending_height":status.pending_height,"pruning_paused":status.pruning_paused,"alarm":status.alarm.map(Alarm::code),"signer_slot":status.signer_slot})).map_err(|_|"checkpoint status encoding failed")?;
            self.export.write_status(&bytes)?;
            self.last_status = Some(status.clone());
        }
        self.tick_failure = Some(TickFailureReason::CurrentProjection);
        let export_head = (state.height(), state.tip(), self.export.latest_height());
        let exported_current = self.last_exported != Some(export_head);
        if exported_current {
            self.export
                .publish_current(store, now, self.latest.as_ref())?;
            self.last_exported = Some(export_head);
        }
        let proposal = self.pending.as_ref().map(|p| Proposal {
            statement: p.statement.clone(),
            witness: p.witness.clone(),
        });
        let vote = self
            .signer
            .as_ref()
            .and_then(|s| self.votes[usize::from(s.slot)].clone());
        Ok(Tick {
            status,
            proposal,
            vote,
            certificate: self.latest.as_ref().map(|c| PublicCertificate {
                certificate: c.certificate.clone(),
                witness: c.prepared.witness.clone(),
            }),
            newly_published,
            exported_current,
        })
    }
    fn accept_proposal(&mut self, store: &Store, proposal: &Proposal) -> Result<(), String> {
        if eligible_checkpoint(store.engine().state().height())
            != Some(proposal.statement.checkpoint_height)
        {
            return Err("checkpoint proposal does not match the current eligible anchor".into());
        }
        if self
            .export
            .latest_height()
            .is_some_and(|height| proposal.statement.checkpoint_height <= height)
        {
            return Err("checkpoint proposal does not advance the published anchor".into());
        }
        if let Some(pending) = &self.pending {
            if pending.statement() != &proposal.statement || pending.witness() != &proposal.witness
            {
                return Err(
                    "checkpoint proposal conflicts with the durable pending candidate".into(),
                );
            }
            return pending.check_current(store);
        }
        if self.preparation.is_some() {
            self.schedule_peer_preparation(store, proposal, false)?;
        } else {
            self.pending = Some(self.export.accept_proposal(
                store,
                proposal.statement.clone(),
                proposal.witness.clone(),
                self.limits,
            )?);
        }
        self.votes = std::array::from_fn(|_| None);
        Ok(())
    }
}
#[cfg(all(test, feature = "eng2-runtime"))]
mod preparation_tests;
#[cfg(all(test, feature = "eng2-runtime"))]
mod readiness_tests;
#[cfg(test)]
mod tests;

mod codec;
