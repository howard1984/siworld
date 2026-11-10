//! Explicitly constructed, bounded checkpoint coordination for a resident driver.
//! No listener, background thread, key generation or service installation occurs.
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
    wallet: Option<WalletPublisher>,
    wallet_requested: bool,
    wallet_paused: bool,
}
impl Host {
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
        let pending = export.resume_candidate(store, limits)?;
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
            wallet: None,
            wallet_requested: false,
            wallet_paused: false,
        })
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
    pub fn wallet_export_state(&self) -> Option<bool> {
        self.wallet_requested.then_some(self.wallet_paused)
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
        let readiness = ResidentSigningReadiness {
            head: ResidentSigningReadiness::head(store)?,
            network,
            observer,
        };
        self.tick_inner(store, now, incoming, Some(&readiness))
    }
    /// Work is bounded to at most three messages, one local vote, one certificate
    /// and one current projection. No waiting, mining or proof replay occurs.
    /// The driver archives every positive 72-block boundary after durable append.
    fn tick_inner(
        &mut self,
        store: &Store,
        now: u64,
        incoming: &[Incoming],
        readiness: Option<&dyn SigningReadiness>,
    ) -> Result<Tick, String> {
        store.ensure_exportable()?;
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
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.check_current(store).is_err())
        {
            self.pending = None;
            self.votes = std::array::from_fn(|_| None);
        }
        let mut newly_published = false;
        for item in incoming {
            match item {
                Incoming::Proposal(proposal) => self.accept_proposal(store, proposal)?,
                Incoming::Vote { statement, vote } => {
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
                    if self.export.latest_height() != Some(certificate.statement.checkpoint_height)
                        && eligible_checkpoint(state.height())
                            != Some(certificate.statement.checkpoint_height)
                    {
                        return Err(
                            "new checkpoint certificate does not match the current eligible anchor"
                                .into(),
                        );
                    }
                    let prepared = PreparedCheckpoint::from_proposal(
                        store,
                        certificate.statement.clone(),
                        witness.clone(),
                        self.limits,
                    )?;
                    // Publication time is a local observation, never authenticated
                    // by a peer's unsigned wall-clock metadata.
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
        let current_signer = self
            .signer
            .as_ref()
            .is_some_and(|signer| signer.check_current(store).is_ok());
        let due = self.export.publication_due(now, state.height())?;
        // Slot zero is the sole local proposer. Other signers wait for its exact
        // independently checked proposal, avoiding competing authorization heads.
        if self.pending.is_none()
            && due
            && current_signer
            && self.signer.as_ref().is_some_and(|s| s.slot == 0)
        {
            self.pending = with_signing_readiness(store, readiness, || {
                self.export.prepare_checkpoint(store, self.limits)
            })?
            .flatten();
        }
        if let Some(pending) = &self.pending
            && current_signer
            && self
                .export
                .latest_height()
                .is_none_or(|height| pending.statement.checkpoint_height > height)
        {
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
        if available.len() == 2 && self.pending.is_some() && due {
            let prepared = self
                .pending
                .take()
                .ok_or("checkpoint candidate disappeared")?;
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
        self.pending = Some(self.export.accept_proposal(
            store,
            proposal.statement.clone(),
            proposal.witness.clone(),
            self.limits,
        )?);
        self.votes = std::array::from_fn(|_| None);
        Ok(())
    }
}
#[cfg(all(test, feature = "eng2-runtime"))]
mod readiness_tests;
#[cfg(test)]
mod tests;

mod codec;
