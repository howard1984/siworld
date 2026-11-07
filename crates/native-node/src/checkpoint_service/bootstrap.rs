//! One bounded, quarantined checkpoint download. No staged state is usable by
//! the live node until quorum, permanent summary and the complete goal tail pass.
use super::*;
use crate::{
    state::Config,
    store::checkpoint_bootstrap::{BootstrapLimits, CheckpointBootstrap},
    wire::{Block, Hash},
};
use siworld_core::pow::Work;
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Goal {
    pub(crate) height: u64,
    pub(crate) id: Hash,
    pub(crate) work: [u8; 64],
}
impl Goal {
    pub(crate) fn local<V: BlockVerifier>(node: &Node<V>) -> Self {
        Self {
            height: node.state().height,
            id: node.state().tip,
            work: node.state().cumulative_work.to_big_endian(),
        }
    }
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = self.height.to_le_bytes().to_vec();
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(&self.work);
        bytes
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 104 {
            return Err("checkpoint goal shape".into());
        }
        Ok(Self {
            height: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            id: bytes[8..40].try_into().unwrap(),
            work: bytes[40..].try_into().unwrap(),
        })
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Request {
    pub(crate) permanent: bool,
    pub(crate) certificate: Hash,
    pub(crate) height: u64,
}
impl Request {
    pub(crate) fn encode(self) -> [u8; 41] {
        let mut bytes = [0; 41];
        bytes[0] = if self.permanent { 1 } else { 2 };
        bytes[1..33].copy_from_slice(&self.certificate);
        bytes[33..].copy_from_slice(&self.height.to_le_bytes());
        bytes
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Option<Self>, String> {
        if bytes == [0] {
            return Ok(None);
        }
        if bytes.len() != 41 || !matches!(bytes[0], 1 | 2) {
            return Err("checkpoint data request shape".into());
        }
        let height = u64::from_le_bytes(bytes[33..].try_into().unwrap());
        if height == 0 {
            return Err("checkpoint data height invalid".into());
        }
        Ok(Some(Self {
            permanent: bytes[0] == 1,
            certificate: bytes[1..33].try_into().unwrap(),
            height,
        }))
    }
}
#[cfg(feature = "native-p2p")]
pub(crate) struct Catchup {
    pub(crate) certificate: Certificate,
    goal: Goal,
    session: Option<CheckpointBootstrap>,
    started: Instant,
    started_unix_seconds: u64,
}
#[cfg(feature = "native-p2p")]
impl Catchup {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin(
        directory: &Path,
        config: Config,
        certificate: Certificate,
        roster: Roster,
        previous: Option<auth::Cursor>,
        now: u64,
        minimum_work: Work,
        goal: Goal,
    ) -> Result<Self, String> {
        let limits = BootstrapLimits::default();
        if goal.height > limits.max_height
            || goal.height.saturating_sub(certificate.statement.height) > limits.max_tail_blocks
            || certificate
                .statement
                .height
                .checked_add(auth::CONFIRMATIONS)
                .is_none_or(|minimum| goal.height < minimum)
            || Work::from_big_endian(&goal.work) <= minimum_work
        {
            return Err("checkpoint goal resource or work limit".into());
        }
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| "checkpoint staging entropy unavailable")?;
        let path = directory.join(format!(
            "checkpoint-catchup-{}.redb",
            crate::local::hex(&nonce)
        ));
        let session = CheckpointBootstrap::begin(
            &path,
            config,
            certificate.clone(),
            roster,
            previous,
            now,
            minimum_work,
            limits,
        )?;
        Ok(Self {
            certificate,
            goal,
            session: Some(session),
            started: Instant::now(),
            started_unix_seconds: now,
        })
    }
    /// Continue toward newly advertised greater work only by fully verifying
    /// its additional tail. A stronger equal/lower-height fork needs a fresh
    /// quarantined reconstruction; it cannot retarget staged state in place.
    pub(crate) fn advance_goal(&mut self, goal: &Goal) -> Result<bool, String> {
        if goal == &self.goal {
            return Ok(true);
        }
        // An unverified work advertisement must not survive replacement by a
        // later peer and become an immutable adoption floor. Reconstructing
        // discards only quarantine; live state still requires greater work.
        if goal.work <= self.goal.work {
            return Ok(false);
        }
        let limits = BootstrapLimits::default();
        if goal.height > limits.max_height
            || goal
                .height
                .saturating_sub(self.certificate.statement.height)
                > limits.max_tail_blocks
        {
            return Err("checkpoint advanced goal resource limit".into());
        }
        if goal.height <= self.goal.height {
            return Ok(false);
        }
        self.goal = goal.clone();
        Ok(true)
    }
    pub(crate) fn request(&self) -> Option<Request> {
        let height = self.session.as_ref()?.progress().0.checked_add(1)?;
        (height <= self.goal.height).then_some(Request {
            permanent: height <= self.certificate.statement.height,
            certificate: self.certificate.statement.digest(),
            height,
        })
    }
    pub(crate) fn push_permanent(&mut self, bytes: &[u8]) -> Result<(), String> {
        if !self.request().is_some_and(|request| request.permanent) {
            return Err("checkpoint permanent data is out of phase".into());
        }
        self.session
            .as_mut()
            .ok_or("checkpoint session unavailable")?
            .push_permanent(bytes)
    }
    pub(crate) fn push_tail<V: BlockVerifier>(
        &mut self,
        node: &Node<V>,
        block: &Block,
    ) -> Result<(), String> {
        if !self
            .request()
            .is_some_and(|request| !request.permanent && request.height == block.height)
        {
            return Err("checkpoint proof data is out of phase".into());
        }
        node.resident_checkpoint_push_tail(
            self.session
                .as_mut()
                .ok_or("checkpoint session unavailable")?,
            block,
        )
    }
    pub(crate) fn ready(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| s.progress().0 == self.goal.height)
    }
    pub(crate) fn adopt<V: BlockVerifier>(
        &mut self,
        node: &mut Node<V>,
        now: u64,
    ) -> Result<u64, String> {
        let session = self
            .session
            .take()
            .ok_or("checkpoint session unavailable")?;
        if session.progress().0 != self.goal.height
            || session.staged_state().tip != self.goal.id
            || session.staged_state().cumulative_work.to_big_endian() != self.goal.work
        {
            return Err("urgent checkpoint tail does not match the greatest observed goal".into());
        }
        let verified = session.finish()?;
        node.resident_adopt_checkpoint(verified, now)
    }
    pub(crate) fn metrics(&self) -> serde_json::Value {
        let (height, checkpoint, downloaded) = self.session.as_ref().map_or(
            (self.goal.height, self.certificate.statement.height, 0),
            |s| s.progress(),
        );
        let elapsed = self.started.elapsed().as_secs();
        let remaining = self.goal.height.saturating_sub(height);
        let eta = (height > 0).then(|| elapsed.saturating_mul(remaining) / height);
        serde_json::json!({"phase":"checkpoint_catchup","height":height,"checkpoint_height":checkpoint,
            "goal_height":self.goal.height,"downloaded_bytes":downloaded,"elapsed_seconds":elapsed,"eta_seconds":eta})
    }
    pub(crate) fn completion_receipt<V: BlockVerifier>(
        &self,
        node: &Node<V>,
        completed_unix_seconds: u64,
        downloaded_bytes: u64,
    ) -> serde_json::Value {
        let elapsed: u64 = self
            .started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let state = node.state();
        serde_json::json!({"schema_version":1,"phase":"completed",
            "started_unix_seconds":self.started_unix_seconds,"completed_unix_seconds":completed_unix_seconds,
            "elapsed_monotonic_ms":elapsed,"downloaded_bytes":downloaded_bytes,
            "checkpoint_height":self.certificate.statement.height,"checkpoint_sequence":self.certificate.statement.sequence,
            "final_height":state.height,"final_tip":crate::local::hex(&state.tip),
            "final_state_fingerprint":crate::local::hex(&state.fingerprint()),
            "final_cumulative_work":crate::local::hex(&state.cumulative_work.to_big_endian())})
    }
}
