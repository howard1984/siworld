//! Engineering checkpoint coordination on the canonical-state owner. Remote
//! bytes supply claims only; votes require an independent immutable local build.
use crate::{
    engineering_checkpoint::{self as auth, Certificate, Roster, Statement, Vote},
    identity::checkpoint_authority::Authority,
    p2p::Binding,
    runtime::Node,
    state::BlockVerifier,
    store::engineering_checkpoint::LocalCandidate,
};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

pub const MAX_EXCHANGE_BYTES: usize = crate::p2p::MAX_CHECKPOINT_EXCHANGE_BYTES;
mod bootstrap;
#[cfg(feature = "native-p2p")]
use bootstrap::Catchup;
pub(crate) use bootstrap::{Goal, Request};
const MAGIC: &[u8; 8] = b"SWCEX001";

#[derive(Clone)]
pub(crate) struct Proposal {
    pub(crate) statement: Statement,
    pub(crate) vote: Vote,
}
impl Proposal {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.statement.encode();
        bytes.push(self.vote.signer);
        bytes.extend_from_slice(&self.vote.signature);
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        let length = bytes
            .len()
            .checked_sub(1 + auth::SIGNATURE_BYTES)
            .ok_or("checkpoint proposal truncated")?;
        let statement = Statement::decode(&bytes[..length])?;
        let signer = bytes[length];
        if signer != 0 {
            return Err("checkpoint proposal requires the pinned leader".into());
        }
        Ok(Self {
            statement,
            vote: Vote {
                signer,
                signature: bytes[length + 1..]
                    .try_into()
                    .map_err(|_| "checkpoint proposal signature shape")?,
            },
        })
    }
}
#[derive(Default)]
pub(crate) struct Exchange {
    pub(crate) proposal: Option<Proposal>,
    pub(crate) certificate: Option<Certificate>,
    pub(crate) goal: Option<Goal>,
}
impl Exchange {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, String> {
        let proposal = self
            .proposal
            .as_ref()
            .map(Proposal::encode)
            .unwrap_or_default();
        let certificate = self
            .certificate
            .as_ref()
            .map(Certificate::encode)
            .transpose()?
            .unwrap_or_default();
        let mut bytes = MAGIC.to_vec();
        for body in [
            proposal,
            certificate,
            self.goal.as_ref().map(Goal::encode).unwrap_or_default(),
        ] {
            let length = u16::try_from(body.len()).map_err(|_| "checkpoint exchange length")?;
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(&body);
        }
        if bytes.len() > MAX_EXCHANGE_BYTES {
            return Err("checkpoint exchange resource limit".into());
        }
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_EXCHANGE_BYTES || bytes.len() < 14 || &bytes[..8] != MAGIC {
            return Err("checkpoint exchange format or resource limit".into());
        }
        let mut position = 8;
        let mut field = || -> Result<&[u8], String> {
            let length = bytes
                .get(position..position + 2)
                .ok_or("checkpoint exchange truncated")?;
            position += 2;
            let end = position
                .checked_add(u16::from_le_bytes(length.try_into().unwrap()) as usize)
                .ok_or("checkpoint exchange length")?;
            let value = bytes
                .get(position..end)
                .ok_or("checkpoint exchange truncated")?;
            position = end;
            Ok(value)
        };
        let proposal = field()?;
        let certificate = field()?;
        let goal = field()?;
        let value = Self {
            proposal: (!proposal.is_empty())
                .then(|| Proposal::decode(proposal))
                .transpose()?,
            certificate: (!certificate.is_empty())
                .then(|| Certificate::decode(certificate))
                .transpose()?,
            goal: (!goal.is_empty()).then(|| Goal::decode(goal)).transpose()?,
        };
        if position != bytes.len() {
            return Err("checkpoint exchange trailing bytes".into());
        }
        Ok(value)
    }
}
struct Build {
    height: u64,
    cancel: Arc<AtomicBool>,
    worker: JoinHandle<Result<LocalCandidate, String>>,
}
/// Running state must independently match an attestation before acceptance.
/// Fresh or stale-node bootstrap remains quarantined until its authenticated
/// permanent prefix and full proof tail can be adopted atomically. A running
/// state mismatch raises an urgent signal while ordinary validation continues.
pub(crate) struct Coordinator {
    roster: Roster,
    authority: Option<Authority>,
    signer: Option<u8>,
    proposal: Option<Proposal>,
    incoming: Option<Proposal>,
    pending: Option<Certificate>,
    accepted: Option<Certificate>,
    cached: Option<LocalCandidate>,
    build: Option<Build>,
    failed_build_height: Option<u64>,
    directory: std::path::PathBuf,
    local_head: Option<Goal>,
    remote_goal: Option<Goal>,
    remote_goal_owner: Option<crate::wire::Hash>,
    download_owner: Option<crate::wire::Hash>,
    #[cfg(feature = "native-p2p")]
    catchup: Option<Catchup>,
    signing_paused: bool,
    pub(crate) alert: Option<&'static str>,
}
#[cfg(feature = "native-p2p")]
impl Coordinator {
    pub(crate) fn load(directory: &Path, binding: Binding) -> Result<Option<Self>, String> {
        let Some(roster) = auth::release_roster(binding)? else {
            return Ok(None);
        };
        let authority = if directory
            .join("engineering-checkpoint-authority.secret")
            .try_exists()
            .map_err(|_| "checkpoint authority metadata unavailable")?
        {
            Some(
                Authority::load(directory, binding)
                    .map_err(|_| "checkpoint authority unavailable")?,
            )
        } else {
            None
        };
        let mut value = Self::new(roster, authority)?;
        value.directory = directory.to_owned();
        Ok(Some(value))
    }
    fn new(roster: Roster, authority: Option<Authority>) -> Result<Self, String> {
        let signer = authority
            .as_ref()
            .map(|value| roster.index(&value.public_key()))
            .transpose()?;
        Ok(Self {
            roster,
            authority,
            signer,
            proposal: None,
            incoming: None,
            pending: None,
            accepted: None,
            cached: None,
            build: None,
            failed_build_height: None,
            directory: std::path::PathBuf::new(),
            local_head: None,
            remote_goal: None,
            remote_goal_owner: None,
            download_owner: None,
            catchup: None,
            signing_paused: false,
            alert: None,
        })
    }
    #[cfg(test)]
    pub(crate) fn for_test(directory: &Path, roster: Roster) -> Result<Self, String> {
        let mut value = Self::new(roster, None)?;
        value.directory = directory.to_owned();
        Ok(value)
    }
    #[cfg(test)]
    pub(crate) fn for_test_signer(
        directory: &Path,
        roster: Roster,
        authority: Authority,
    ) -> Result<Self, String> {
        let mut value = Self::new(roster, Some(authority))?;
        value.directory = directory.to_owned();
        Ok(value)
    }
    pub(crate) fn outbound(&self) -> Result<Vec<u8>, String> {
        Exchange {
            proposal: if self.signing_paused {
                None
            } else {
                self.proposal.clone()
            },
            certificate: self.accepted.clone(),
            goal: self.local_head.clone(),
        }
        .encode()
    }
    pub(crate) fn signing_paused(&self) -> bool {
        self.signing_paused
    }
    /// Operator intent is scoped to this process run. No key, persisted vote,
    /// accepted certificate or ordinary validation state is changed.
    pub(crate) fn set_signing_paused(&mut self, paused: bool) -> Result<(), String> {
        if self.signer.is_none() {
            return Err("checkpoint signing requires a local authority".into());
        }
        self.signing_paused = paused;
        if paused {
            self.proposal = None;
            self.incoming = None;
        }
        Ok(())
    }
    pub(crate) fn receive<V: BlockVerifier>(
        &mut self,
        node: &Node<V>,
        peer: crate::wire::Hash,
        bytes: &[u8],
        now: u64,
    ) -> Result<(), String> {
        let packet = Exchange::decode(bytes)?;
        // Invalid signatures cannot leave a persistent, unauthenticated goal
        // behind when the owning transport is rejected.
        if let Some(certificate) = &packet.certificate {
            certificate.authenticate(&self.roster, None, now)?;
        }
        if let Some(proposal) = &packet.proposal {
            self.roster
                .verify_vote(&proposal.statement, &proposal.vote)?;
        }
        if let Some(certificate) = packet.certificate {
            // A peer may advertise its previous publication while learning a
            // newer one. Authenticate it before ignoring that advertisement;
            // importing a checkpoint still enforces the persisted cursor.
            certificate.authenticate(&self.roster, None, now)?;
            let cursor = node.store().checkpoint_cursor()?;
            let superseded = cursor.is_some_and(|known| {
                certificate.statement.sequence < known.sequence
                    || certificate.statement.height < known.height
            });
            if !superseded {
                certificate.authenticate(&self.roster, cursor, now)?;
                if self.pending.as_ref().is_some_and(|known| {
                    certificate.statement.sequence == known.statement.sequence
                        && certificate.statement != known.statement
                }) {
                    self.alert = Some("checkpoint_quorum_equivocation");
                    return Err("checkpoint quorum equivocation".into());
                }
                let newer =
                    self.accepted.as_ref().is_none_or(|known| {
                        certificate.statement.sequence > known.statement.sequence
                    }) && self.pending.as_ref().is_none_or(|known| {
                        certificate.statement.sequence > known.statement.sequence
                    });
                if newer {
                    if self.catchup.as_ref().is_some_and(|download| {
                        download.certificate.statement.digest() != certificate.statement.digest()
                    }) {
                        self.catchup = None;
                        self.download_owner = None;
                    }
                    self.pending = Some(certificate);
                }
            }
        }
        if let Some(proposal) = packet.proposal {
            self.roster
                .verify_vote(&proposal.statement, &proposal.vote)?;
            // A signed one-vote proposal authenticates neither a checkpoint nor
            // pruning. Only a current scheduled proposal may be countersigned.
            if proposal.statement.issued_unix_seconds <= now
                && proposal.statement.issued_unix_seconds / auth::INTERVAL_SECONDS
                    == now / auth::INTERVAL_SECONDS
                && proposal.statement.sequence == now / auth::INTERVAL_SECONDS
                && node
                    .store()
                    .checkpoint_cursor()?
                    .is_none_or(|cursor| proposal.statement.sequence > cursor.sequence)
            {
                if self.incoming.as_ref().is_some_and(|known| {
                    known.statement.sequence == proposal.statement.sequence
                        && known.statement != proposal.statement
                }) {
                    self.alert = Some("checkpoint_leader_equivocation");
                } else {
                    self.incoming = Some(proposal);
                }
            }
        }
        if let Some(goal) = packet.goal
            && goal.height <= 1_000_000
            && (self.remote_goal_owner == Some(peer)
                || self
                    .remote_goal
                    .as_ref()
                    .is_none_or(|before| goal.work > before.work))
        {
            self.remote_goal = Some(goal);
            self.remote_goal_owner = Some(peer);
        }
        Ok(())
    }
    fn matching_candidate(&self, statement: &Statement) -> Option<LocalCandidate> {
        self.cached
            .as_ref()
            .filter(|candidate| candidate.statement().height == statement.height)
            .map(|candidate| candidate.reissued(statement.sequence, statement.issued_unix_seconds))
    }
    fn request_build<V: BlockVerifier>(
        &mut self,
        node: &Node<V>,
        height: u64,
        sequence: u64,
        issued: u64,
    ) -> Result<(), String> {
        if self
            .cached
            .as_ref()
            .is_some_and(|candidate| candidate.statement().height == height)
            || self.build.is_some()
            || self.failed_build_height == Some(height)
            || height
                .checked_add(auth::CONFIRMATIONS)
                .is_none_or(|required| required > node.state().height)
        {
            return Ok(());
        }
        let snapshot =
            node.store()
                .engineering_checkpoint_snapshot(&self.roster, height, sequence, issued)?;
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let worker = std::thread::Builder::new()
            .name("checkpoint-local-summary".into())
            .stack_size(2 * 1024 * 1024)
            .spawn(move || snapshot.finish(Some(&flag)))
            .map_err(|_| "checkpoint local summary worker unavailable")?;
        self.build = Some(Build {
            height,
            cancel,
            worker,
        });
        Ok(())
    }
    #[cfg(feature = "native-p2p")]
    pub(crate) fn poll<V: BlockVerifier>(
        &mut self,
        node: &mut Node<V>,
        now: u64,
    ) -> Result<(), String> {
        self.local_head = Some(Goal::local(node));
        if self.accepted.is_none() {
            self.accepted = node.store().latest_engineering_checkpoint()?;
        }
        if self.catchup.as_ref().is_some_and(|download| {
            now.checked_sub(download.certificate.statement.issued_unix_seconds)
                .is_none_or(|age| age > auth::MAX_AGE_SECONDS)
        }) {
            self.catchup = None;
            self.download_owner = None;
        }
        if let (Some(download), Some(goal)) = (&mut self.catchup, &self.remote_goal)
            && !download.advance_goal(goal)?
        {
            self.catchup = None;
            self.download_owner = None;
        }
        if self.catchup.is_none()
            && !self.directory.as_os_str().is_empty()
            && let (Some(certificate), Some(goal)) = (&self.pending, &self.remote_goal)
        {
            let keep = node
                .store()
                .local_proof_blocks()?
                .unwrap_or(crate::storage_policy::LOCAL_PROOF_BLOCKS);
            let local = node.state().height;
            let role = node
                .store()
                .storage_role()?
                .unwrap_or(crate::storage_policy::Role::Ordinary);
            let stale = local == 0
                || (role.serves_historical_proofs() && local <= certificate.statement.height)
                || (!role.serves_historical_proofs()
                    && local
                        .checked_add(keep)
                        .is_some_and(|minimum| certificate.statement.height >= minimum));
            let fresh = now
                .checked_sub(certificate.statement.issued_unix_seconds)
                .is_some_and(|age| age <= auth::MAX_AGE_SECONDS);
            if stale
                && fresh
                && goal.work > node.state().cumulative_work.to_big_endian()
                && certificate
                    .statement
                    .height
                    .checked_add(auth::CONFIRMATIONS)
                    .is_some_and(|n| goal.height >= n)
            {
                self.catchup = Some(Catchup::begin(
                    &self.directory,
                    node.state().config.clone(),
                    certificate.clone(),
                    self.roster.clone(),
                    node.store().checkpoint_cursor()?,
                    now,
                    node.state().cumulative_work,
                    goal.clone(),
                )?);
            }
        }
        if self.catchup.is_some() {
            return Ok(());
        }
        // A cached height alone cannot identify a candidate after a reorg.
        // Stale local computation is discarded, never countersigned.
        if let Some(candidate) = &self.cached
            && (candidate.statement().height > node.state().height
                || node.store().canonical_id(candidate.statement().height)?
                    != candidate.statement().block_id)
        {
            self.cached = None;
            self.failed_build_height = None;
        }
        if self
            .build
            .as_ref()
            .is_some_and(|build| build.worker.is_finished())
        {
            let build = self.build.take().expect("completed build");
            let height = build.height;
            // Move the handle without implementing a custom Drop on the owner.
            let Build { worker, cancel, .. } = build;
            let result = worker
                .join()
                .map_err(|_| "checkpoint summary worker panicked")?;
            drop(cancel);
            match result {
                Ok(candidate) => {
                    if candidate.statement().height <= node.state().height
                        && node.store().canonical_id(candidate.statement().height)?
                            == candidate.statement().block_id
                    {
                        self.cached = Some(candidate);
                    }
                    self.failed_build_height = None;
                }
                Err(_) => {
                    self.alert = Some("checkpoint_local_summary_failed");
                    self.failed_build_height = Some(height);
                }
            }
        }
        if let Some(certificate) = &self.pending {
            let statement = certificate.statement.clone();
            if statement
                .height
                .checked_add(auth::CONFIRMATIONS)
                .is_some_and(|n| n <= node.state().height)
            {
                if node.store().canonical_id(statement.height)? != statement.block_id {
                    self.alert = Some("checkpoint_local_chain_mismatch");
                    self.pending = None;
                } else if let Some(candidate) = self.matching_candidate(&statement) {
                    if candidate.statement() != &statement {
                        self.alert = Some("checkpoint_local_state_mismatch");
                        self.pending = None;
                    } else {
                        let certificate = self.pending.take().expect("matched certificate");
                        node.resident_accept_checkpoint(
                            &certificate,
                            &self.roster,
                            now,
                            &candidate,
                        )?;
                        self.accepted = Some(certificate);
                        self.proposal = None;
                    }
                } else {
                    self.request_build(
                        node,
                        statement.height,
                        statement.sequence,
                        statement.issued_unix_seconds,
                    )?;
                }
            }
        }
        if !self.signing_paused
            && self.signer == Some(1)
            && let Some(proposal) = &self.incoming
        {
            let statement = proposal.statement.clone();
            if statement.issued_unix_seconds / auth::INTERVAL_SECONDS
                != now / auth::INTERVAL_SECONDS
            {
                self.incoming = None;
            } else if statement
                .height
                .checked_add(auth::CONFIRMATIONS)
                .is_some_and(|n| n <= node.state().height)
            {
                if node.store().canonical_id(statement.height)? != statement.block_id {
                    self.alert = Some("checkpoint_local_chain_mismatch");
                    self.incoming = None;
                } else if let Some(candidate) = self.matching_candidate(&statement) {
                    if candidate.statement() != &statement {
                        self.alert = Some("checkpoint_local_state_mismatch");
                        self.incoming = None;
                    } else {
                        let vote = node.store().sign_engineering_checkpoint(
                            self.authority.as_ref().expect("signer"),
                            &self.roster,
                            &candidate,
                        )?;
                        let certificate = Certificate {
                            statement,
                            votes: vec![proposal.vote.clone(), vote],
                        };
                        node.resident_accept_checkpoint(
                            &certificate,
                            &self.roster,
                            now,
                            &candidate,
                        )?;
                        self.accepted = Some(certificate);
                        self.incoming = None;
                    }
                } else {
                    self.request_build(
                        node,
                        statement.height,
                        statement.sequence,
                        statement.issued_unix_seconds,
                    )?;
                }
            }
        }
        if !self.signing_paused && self.signer == Some(0) {
            let sequence = now / auth::INTERVAL_SECONDS;
            if sequence > 0
                && self
                    .accepted
                    .as_ref()
                    .is_none_or(|value| value.statement.sequence < sequence)
            {
                if self
                    .proposal
                    .as_ref()
                    .is_none_or(|proposal| proposal.statement.sequence != sequence)
                {
                    self.proposal = self
                        .authority
                        .as_ref()
                        .expect("signer")
                        .saved_vote(sequence)?
                        .map(|(statement, vote)| Proposal { statement, vote });
                }
                if self.proposal.is_none()
                    && let Some(height) = auth::scheduled_height(node.state().height)
                {
                    let issued = sequence * auth::INTERVAL_SECONDS;
                    let cached = self
                        .cached
                        .as_ref()
                        .filter(|candidate| candidate.statement().height == height)
                        .map(|candidate| candidate.reissued(sequence, issued));
                    if let Some(candidate) = cached {
                        let vote = node.store().sign_engineering_checkpoint(
                            self.authority.as_ref().expect("signer"),
                            &self.roster,
                            &candidate,
                        )?;
                        self.proposal = Some(Proposal {
                            statement: candidate.statement().clone(),
                            vote,
                        });
                    } else {
                        self.request_build(node, height, sequence, issued)?;
                    }
                }
            }
        }
        Ok(())
    }
    pub(crate) fn download_request(&mut self, peer: crate::wire::Hash) -> Vec<u8> {
        if self.catchup.is_none() || self.download_owner.is_some_and(|owner| owner != peer) {
            return vec![0];
        }
        self.download_owner = Some(peer);
        self.catchup
            .as_ref()
            .and_then(Catchup::request)
            .map_or_else(|| vec![0], |request| request.encode().to_vec())
    }
    pub(crate) fn release_download_peer(&mut self, peer: crate::wire::Hash) {
        if self.download_owner == Some(peer) {
            self.download_owner = None;
        }
        if self.remote_goal_owner == Some(peer) {
            self.remote_goal = None;
            self.remote_goal_owner = None;
        }
    }
    pub(crate) fn push_permanent<V: BlockVerifier>(
        &mut self,
        node: &mut Node<V>,
        peer: crate::wire::Hash,
        bytes: &[u8],
        now: u64,
    ) -> Result<(), String> {
        if self.download_owner != Some(peer) {
            return Err("checkpoint data peer has no download ownership".into());
        }
        let result = self
            .catchup
            .as_mut()
            .ok_or("checkpoint session is not active")?
            .push_permanent(bytes);
        self.finish_download(node, result, now)
    }
    pub(crate) fn push_tail<V: BlockVerifier>(
        &mut self,
        node: &mut Node<V>,
        peer: crate::wire::Hash,
        block: &crate::wire::Block,
        now: u64,
    ) -> Result<(), String> {
        if self.download_owner != Some(peer) {
            return Err("checkpoint data peer has no download ownership".into());
        }
        let result = self
            .catchup
            .as_mut()
            .ok_or("checkpoint session is not active")?
            .push_tail(node, block);
        self.finish_download(node, result, now)
    }
    fn finish_download<V: BlockVerifier>(
        &mut self,
        node: &mut Node<V>,
        result: Result<(), String>,
        now: u64,
    ) -> Result<(), String> {
        if result.is_err() {
            self.catchup = None;
            self.download_owner = None;
            self.alert = Some("checkpoint_download_rejected");
            return result;
        }
        if self.catchup.as_ref().is_some_and(Catchup::ready) {
            let mut download = self.catchup.take().expect("completed catchup");
            self.download_owner = None;
            match download.adopt(node, now) {
                Ok(downloaded_bytes) => {
                    let receipt = download.completion_receipt(node, now, downloaded_bytes);
                    self.accepted = Some(download.certificate);
                    self.pending = None;
                    self.local_head = Some(Goal::local(node));
                    // Canonical adoption already succeeded. An export failure
                    // records an operator alert without blaming the data peer
                    // or undoing the fully verified transition.
                    if crate::service::atomic_json(
                        &self.directory.join("checkpoint-recovery-receipt.json"),
                        &receipt,
                    )
                    .is_err()
                    {
                        self.alert = Some("checkpoint_recovery_receipt_unavailable");
                    }
                }
                Err(error) => {
                    self.alert = Some("checkpoint_adoption_rejected");
                    return Err(error);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn catchup_metrics(&self) -> Option<serde_json::Value> {
        self.catchup.as_ref().map(Catchup::metrics)
    }
    pub(crate) fn is_catching_up(&self) -> bool {
        self.catchup.is_some()
    }
    pub(crate) fn metrics(&self, now: u64) -> serde_json::Value {
        let age = self
            .accepted
            .as_ref()
            .and_then(|c| now.checked_sub(c.statement.issued_unix_seconds));
        serde_json::json!({"enabled":true,"authority":self.signer.is_some(),"signing_paused":self.signing_paused,
            "summary_building":self.build.is_some(),"catchup":self.catchup.as_ref().map(Catchup::metrics),"latest_height":self.accepted.as_ref().map(|c|c.statement.height),
            "latest_sequence":self.accepted.as_ref().map(|c|c.statement.sequence),"age_seconds":age,
            "pruning_paused":age.is_none_or(|age|age>auth::MAX_AGE_SECONDS),
            "alert":self.alert.or_else(|| age.is_none_or(|age|age>auth::MAX_AGE_SECONDS).then_some("checkpoint_stale"))})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exchange_is_bounded_and_rejects_trailing_or_partial_fields() {
        let encoded = Exchange::default().encode().unwrap();
        assert!(Exchange::decode(&encoded).is_ok());
        assert!(Exchange::decode(&[encoded.as_slice(), &[0]].concat()).is_err());
        assert!(Exchange::decode(&encoded[..encoded.len() - 1]).is_err());
        assert!(Exchange::decode(&vec![0; MAX_EXCHANGE_BYTES + 1]).is_err());
        let mut bad = encoded;
        bad[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(Exchange::decode(&bad).is_err());
    }
}

impl Drop for Coordinator {
    fn drop(&mut self) {
        if let Some(build) = self.build.take() {
            build.cancel.store(true, Ordering::Relaxed);
            let _ = build.worker.join();
        }
    }
}

#[cfg(all(test, feature = "native-p2p", unix))]
mod coordination_tests {
    use super::*;
    use crate::{
        fixtures::{TestVerifier, candidate},
        local,
        state::Config,
        store::Store,
    };
    use std::{
        path::PathBuf,
        sync::atomic::AtomicU64,
        time::{Duration, Instant},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new(config: &Config) -> Self {
            let path = std::env::temp_dir().join(format!(
                "siworld-checkpoint-coordinator-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            local::initialize_config(&path, config.clone()).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn settle(
        coordinator: &mut Coordinator,
        node: &mut Node<TestVerifier>,
        now: u64,
        ready: impl Fn(&Coordinator) -> bool,
    ) {
        let started = Instant::now();
        loop {
            coordinator.poll(node, now).unwrap();
            if ready(coordinator) {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(180),
                "coordinator did not finish: {:?}",
                coordinator.metrics(now)
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    #[test]
    fn independent_countersigning_publication_restart_and_stale_resume() {
        let config = Config::development([223; 32], 0).unwrap();
        let da = Directory::new(&config);
        let db = Directory::new(&config);
        let binding = Binding::new(&config);
        let a = Authority::initialize(&da.0, binding).unwrap();
        let b = Authority::initialize(&db.0, binding).unwrap();
        let roster = Roster::new(binding, [a.public_key(), b.public_key()]).unwrap();
        let mut sa = Store::open(da.0.join("chain.redb"), config.clone(), &TestVerifier).unwrap();
        let mut sb = Store::open(db.0.join("chain.redb"), config.clone(), &TestVerifier).unwrap();
        for index in 0..96 {
            let block = candidate(sa.state(), 900_000_000 + index * 100_000);
            sa.append(&block, &TestVerifier).unwrap();
            sb.append(&block, &TestVerifier).unwrap();
        }
        let mut na = Node::new(sa, TestVerifier);
        let mut nb = Node::new(sb, TestVerifier);
        let before = na.state().fingerprint();
        let mut ca = Coordinator::new(roster.clone(), Some(a)).unwrap();
        let mut cb = Coordinator::new(roster.clone(), Some(b)).unwrap();
        ca.set_signing_paused(true).unwrap();
        ca.poll(&mut na, 21_600).unwrap();
        assert!(ca.proposal.is_none());
        assert!(ca.build.is_none());
        assert!(
            ca.authority
                .as_ref()
                .unwrap()
                .saved_vote(1)
                .unwrap()
                .is_none()
        );
        assert_eq!(ca.metrics(21_600)["signing_paused"], true);
        ca.set_signing_paused(false).unwrap();
        settle(&mut ca, &mut na, 21_600, |c| c.proposal.is_some());
        let first = ca.proposal.as_ref().unwrap().statement.digest();
        ca.set_signing_paused(true).unwrap();
        assert!(
            Exchange::decode(&ca.outbound().unwrap())
                .unwrap()
                .proposal
                .is_none()
        );
        drop(ca);
        let a = Authority::load(&da.0, binding).unwrap();
        let mut ca = Coordinator::new(roster.clone(), Some(a)).unwrap();
        assert!(!ca.signing_paused());
        ca.poll(&mut na, 21_605).unwrap();
        assert_eq!(ca.proposal.as_ref().unwrap().statement.digest(), first);
        cb.receive(&nb, [1; 32], &ca.outbound().unwrap(), 21_605)
            .unwrap();
        // A one-vote proposal is never persisted as a valid checkpoint.
        assert!(
            nb.store()
                .latest_engineering_checkpoint()
                .unwrap()
                .is_none()
        );
        settle(&mut cb, &mut nb, 21_605, |c| c.accepted.is_some());
        ca.receive(&na, [2; 32], &cb.outbound().unwrap(), 21_605)
            .unwrap();
        settle(&mut ca, &mut na, 21_605, |c| c.accepted.is_some());
        let certificate = ca.accepted.as_ref().unwrap();
        let first_certificate = certificate.clone();
        certificate.authenticate(&roster, None, 21_605).unwrap();
        assert_eq!(certificate.statement.height, 72);
        assert_eq!(before, na.state().fingerprint());
        assert_eq!(before, nb.state().fingerprint());
        assert_eq!(
            ca.metrics(21_600 + auth::MAX_AGE_SECONDS + 1)["pruning_paused"],
            true
        );
        // A new valid publication automatically clears stale pruning status.
        settle(&mut ca, &mut na, 108_000, |c| {
            c.proposal
                .as_ref()
                .is_some_and(|p| p.statement.sequence == 5)
        });
        cb.receive(&nb, [1; 32], &ca.outbound().unwrap(), 108_000)
            .unwrap();
        settle(&mut cb, &mut nb, 108_000, |c| {
            c.accepted
                .as_ref()
                .is_some_and(|p| p.statement.sequence == 5)
        });
        assert_eq!(cb.metrics(108_000)["pruning_paused"], false);
        ca.set_signing_paused(true).unwrap();
        // A valid superseded advertisement must not disconnect a peer during
        // the normal publication transition or roll back accepted state.
        let old = Exchange {
            certificate: Some(first_certificate),
            ..Default::default()
        }
        .encode()
        .unwrap();
        cb.receive(&nb, [1; 32], &old, 108_001).unwrap();
        assert_eq!(cb.accepted.as_ref().unwrap().statement.sequence, 5);
        assert!(cb.pending.is_none());
        ca.receive(&na, [2; 32], &cb.outbound().unwrap(), 108_001)
            .unwrap();
        settle(&mut ca, &mut na, 108_001, |c| {
            c.accepted
                .as_ref()
                .is_some_and(|p| p.statement.sequence == 5)
        });
        assert_eq!(before, na.state().fingerprint());
        assert!(ca.signing_paused());
        let mut bad = ca.outbound().unwrap();
        bad[20] ^= 1;
        assert!(cb.receive(&nb, [1; 32], &bad, 108_000).is_err());

        // Incoming hints cannot survive failed authentication, peer ownership
        // release, publication rollover or checkpoint expiry as a hidden work
        // floor for a fresh node.
        let dc = Directory::new(&config);
        let sc = Store::open(dc.0.join("chain.redb"), config, &TestVerifier).unwrap();
        let mut nc = Node::new(sc, TestVerifier);
        let mut cc = Coordinator::for_test(&dc.0, roster).unwrap();
        cc.receive(&nc, [1; 32], &ca.outbound().unwrap(), 108_001)
            .unwrap();
        cc.poll(&mut nc, 108_001).unwrap();
        assert!(cc.catchup.is_some());
        assert_eq!(cc.remote_goal_owner, Some([1; 32]));
        let initial_goal = cc.remote_goal.clone().unwrap();
        let mut invalid = ca.accepted.clone().unwrap();
        invalid.votes[0].signature[0] ^= 1;
        let forged = Exchange {
            certificate: Some(invalid),
            goal: Some(Goal {
                height: 1_000_000,
                id: [99; 32],
                work: [u8::MAX; 64],
            }),
            ..Default::default()
        }
        .encode()
        .unwrap();
        assert!(cc.receive(&nc, [2; 32], &forged, 108_001).is_err());
        assert_eq!(cc.remote_goal, Some(initial_goal.clone()));
        assert_eq!(cc.remote_goal_owner, Some([1; 32]));
        assert_ne!(cc.download_request([1; 32]), [0]);
        cc.release_download_peer([2; 32]);
        assert_eq!(cc.download_owner, Some([1; 32]));
        cc.release_download_peer([1; 32]);
        assert!(cc.remote_goal.is_none());
        assert!(cc.remote_goal_owner.is_none());
        assert!(cc.download_owner.is_none());
        // A normal reconnect preserves staged work. A changed goal cannot
        // lower the live adoption requirement or retarget existing state.
        let download = cc.catchup.as_mut().unwrap();
        assert!(download.advance_goal(&initial_goal).unwrap());
        let mut extension = initial_goal.clone();
        extension.height += 1;
        extension.work[0] = 1;
        extension.id[0] ^= 1;
        assert!(download.advance_goal(&extension).unwrap());
        let mut stronger_fork = extension.clone();
        stronger_fork.work[0] = 2;
        assert!(!download.advance_goal(&stronger_fork).unwrap());
        assert!(!download.advance_goal(&initial_goal).unwrap());
        cc.receive(&nc, [1; 32], &ca.outbound().unwrap(), 108_001)
            .unwrap();
        cc.poll(&mut nc, 108_001).unwrap();
        assert!(cc.catchup.is_some());

        let expired = 108_000 + auth::MAX_AGE_SECONDS + 1;
        cc.poll(&mut nc, expired).unwrap();
        assert!(cc.catchup.is_none());
        assert!(cc.download_owner.is_none());
        // The same staged session can be replaced by the next six-hour
        // publication without retaining the old certificate or data owner.
        cc.poll(&mut nc, 129_600).unwrap();
        assert!(cc.catchup.is_some());
        assert_ne!(cc.download_request([1; 32]), [0]);
        ca.set_signing_paused(false).unwrap();
        settle(&mut ca, &mut na, 129_600, |c| {
            c.proposal
                .as_ref()
                .is_some_and(|p| p.statement.sequence == 6)
        });
        cb.receive(&nb, [1; 32], &ca.outbound().unwrap(), 129_600)
            .unwrap();
        cb.set_signing_paused(true).unwrap();
        // A proposal received during the pause may be validated and queued but
        // cannot generate a countersignature or fresh quorum.
        cb.receive(&nb, [1; 32], &ca.outbound().unwrap(), 129_600)
            .unwrap();
        cb.poll(&mut nb, 129_600).unwrap();
        assert_eq!(cb.accepted.as_ref().unwrap().statement.sequence, 5);
        assert!(
            cb.authority
                .as_ref()
                .unwrap()
                .saved_vote(6)
                .unwrap()
                .is_none()
        );
        let next = candidate(na.state(), 920_000_000);
        na.import_branch(96, std::slice::from_ref(&next), Default::default())
            .unwrap();
        nb.import_branch(96, &[next], Default::default()).unwrap();
        assert_eq!(na.state().height, 97);
        assert_eq!(na.state().fingerprint(), nb.state().fingerprint());
        cb.set_signing_paused(false).unwrap();
        settle(&mut cb, &mut nb, 129_600, |c| {
            c.accepted
                .as_ref()
                .is_some_and(|p| p.statement.sequence == 6)
        });
        cc.receive(&nc, [2; 32], &cb.outbound().unwrap(), 129_600)
            .unwrap();
        assert!(cc.catchup.is_none());
        assert!(cc.download_owner.is_none());
        cc.poll(&mut nc, 129_600).unwrap();
        assert_eq!(
            cc.catchup.as_ref().unwrap().certificate.statement.sequence,
            6
        );
    }
}
