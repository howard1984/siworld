//! Bounded nonsigning observations against an independently accepted Store.
//! Observations grant no import, publication, readiness or state-adoption authority.
use super::{
    certificate::{AuthorizationWitness, Statement, Vote},
    checkpoint_wire::{Incoming, MAX_GOVERNANCE_BYTES},
    commitment::{self, Component, ComponentId},
    header::Header,
    runtime_export::eligible_checkpoint,
    store::Store,
};
use crate::{
    eng2_governance::{ActiveRoster, GovernanceState},
    wire::Hash,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    /// The local accepted prefix or historical signer keys are not available.
    Unavailable,
    /// The supplied data fails an independently checkable binding or signature.
    Rejected,
    /// A valid current quorum contradicts the independently selected prefix.
    Conflict,
}
impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "checkpoint_observation_unavailable",
            Self::Rejected => "checkpoint_observation_rejected",
            Self::Conflict => "checkpoint_current_quorum_conflict",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Proposal,
    Vote,
    CurrentCertificate(u64),
    Historical,
}
#[derive(Default)]
pub(crate) struct Observer {
    last_now: Option<u64>,
    observed_height: Option<u64>,
    conflict: bool,
    error: Option<Error>,
}
trait View {
    fn height(&self) -> u64;
    fn governance(&self) -> &GovernanceState;
    fn header(&self, height: u64) -> Result<Header, Error>;
}
struct Accepted<'a>(&'a Store);
impl View for Accepted<'_> {
    fn height(&self) -> u64 {
        self.0.engine().state().height()
    }
    fn governance(&self) -> &GovernanceState {
        self.0.engine().state().governance()
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.0.header(height).map_err(|_| Error::Unavailable)
    }
}
impl Observer {
    pub fn conflicted(&self) -> bool {
        self.conflict
    }
    pub fn observed_height(&self) -> Option<u64> {
        self.observed_height
    }
    pub fn error(&self) -> Option<Error> {
        self.error
    }
    /// The caller holds the canonical owner lock and the decoded packet charge.
    /// No checkpoint key, archive scan, vote creation or outgoing queue is used.
    pub fn observe(
        &mut self,
        store: &Store,
        now: u64,
        incoming: &Incoming,
    ) -> Result<Outcome, Error> {
        if self.conflict {
            return Err(Error::Conflict);
        }
        if store.ensure_exportable().is_err() {
            self.error = Some(Error::Unavailable);
            return Err(Error::Unavailable);
        }
        self.check(&Accepted(store), now, incoming)
    }
    fn check(&mut self, view: &impl View, now: u64, incoming: &Incoming) -> Result<Outcome, Error> {
        if self.conflict {
            return Err(Error::Conflict);
        }
        let result = if now >= 1u64 << 53
            || self.last_now.is_some_and(|last| now < last)
            || incoming.encode(MAX_GOVERNANCE_BYTES).is_err()
        {
            Err(Error::Rejected)
        } else {
            self.last_now = Some(now);
            evaluate(view, incoming)
        };
        match result {
            Ok(outcome) => {
                if let Outcome::CurrentCertificate(height) = outcome {
                    self.observed_height = Some(self.observed_height.unwrap_or(0).max(height));
                }
                self.error = None;
            }
            Err(error) => {
                self.error = Some(error);
                if error == Error::Conflict {
                    self.conflict = true;
                }
            }
        }
        result
    }
}
fn headers(view: &impl View, statement: &Statement) -> Result<(Header, Hash), Error> {
    let current = view.governance();
    if current.height() != view.height()
        || statement.network != current.network()
        || statement.encode().is_err()
        || eligible_checkpoint(statement.authorization_height) != Some(statement.checkpoint_height)
    {
        return Err(Error::Rejected);
    }
    if statement.authorization_height > view.height() {
        return Err(Error::Unavailable);
    }
    let authorization = view.header(statement.authorization_height)?;
    let anchor = view.header(statement.checkpoint_height)?;
    if authorization.network != statement.network
        || anchor.network != statement.network
        || authorization.height != statement.authorization_height
        || anchor.height != statement.checkpoint_height
    {
        return Err(Error::Rejected);
    }
    Ok((authorization, anchor.id().map_err(|_| Error::Rejected)?))
}
fn authority(
    view: &impl View,
    statement: &Statement,
    header: &Header,
    witness: &AuthorizationWitness,
) -> Result<ActiveRoster, Error> {
    witness
        .encode(MAX_GOVERNANCE_BYTES)
        .map_err(|_| Error::Rejected)?;
    let component = Component::from_local_encoding(
        ComponentId::Governance,
        &witness.governance,
        MAX_GOVERNANCE_BYTES,
    )
    .map_err(|_| Error::Rejected)?;
    if witness.descriptors[7] != component.descriptor()
        || commitment::aggregate_descriptors(
            header.network,
            header.height,
            header.parent,
            &witness.descriptors,
        )
        .map_err(|_| Error::Rejected)?
            != header.execution_commitment
    {
        return Err(Error::Rejected);
    }
    let governance = GovernanceState::decode_component(&witness.governance, statement.network)
        .map_err(|_| Error::Rejected)?;
    let roster = governance.active_roster();
    let current = view.governance().active_roster();
    if governance.height() != header.height
        || roster.activated_height > header.height
        || roster.epoch_sequence != statement.roster_sequence
        || roster.digest(statement.network) != statement.roster_digest
        || roster.epoch_sequence > current.epoch_sequence
        || (roster.epoch_sequence == current.epoch_sequence
            && roster.digest(statement.network) != current.digest(statement.network))
    {
        return Err(Error::Rejected);
    }
    Ok(roster.clone())
}
fn verify_vote(view: &impl View, statement: &Statement, vote: &Vote) -> Result<(), Error> {
    use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65Signature, MLDSA65VerificationKey};
    let roster = view.governance().active_roster();
    if statement.roster_sequence < roster.epoch_sequence {
        return Err(Error::Unavailable);
    }
    if statement.roster_sequence != roster.epoch_sequence
        || statement.roster_digest != roster.digest(statement.network)
        || roster.activated_height > statement.authorization_height
    {
        return Err(Error::Rejected);
    }
    let key = roster
        .keys()
        .get(usize::from(vote.slot))
        .ok_or(Error::Rejected)?;
    ml_dsa_65::verify(
        &MLDSA65VerificationKey::new(*key),
        &statement.encode().map_err(|_| Error::Rejected)?,
        Statement::signing_context(),
        &MLDSA65Signature::new(vote.signature),
    )
    .map_err(|_| Error::Rejected)
}
fn evaluate(view: &impl View, incoming: &Incoming) -> Result<Outcome, Error> {
    match incoming {
        Incoming::Proposal(proposal) => {
            let (header, selected) = headers(view, &proposal.statement)?;
            let roster = authority(view, &proposal.statement, &header, &proposal.witness)?;
            if header.id().map_err(|_| Error::Rejected)? != proposal.statement.authorization_block
                || selected != proposal.statement.checkpoint_block
            {
                return Err(Error::Rejected);
            }
            if roster.epoch_sequence < view.governance().active_roster().epoch_sequence {
                return Ok(Outcome::Historical);
            }
            Ok(Outcome::Proposal)
        }
        Incoming::Vote { statement, vote } => {
            let (header, selected) = headers(view, statement)?;
            if header.id().map_err(|_| Error::Rejected)? != statement.authorization_block
                || selected != statement.checkpoint_block
            {
                return Err(Error::Rejected);
            }
            verify_vote(view, statement, vote)?;
            Ok(Outcome::Vote)
        }
        Incoming::Certified {
            certificate,
            witness,
        } => {
            let statement = &certificate.statement;
            let current = view.governance().active_roster();
            let is_current = statement.roster_sequence == current.epoch_sequence;
            if is_current {
                // Independent executed keys establish the current authority.
                // A foreign authorization witness cannot excuse a valid current
                // quorum contradicting either selected prefix identity.
                if statement.roster_digest != current.digest(statement.network)
                    || current.activated_height > statement.authorization_height
                {
                    return Err(Error::Rejected);
                }
                certificate
                    .check_signatures(current.keys())
                    .map_err(|_| Error::Rejected)?;
            }
            let (header, selected) = headers(view, statement)?;
            let matches_authorization =
                header.id().map_err(|_| Error::Rejected)? == statement.authorization_block;
            if is_current && (!matches_authorization || selected != statement.checkpoint_block) {
                return Err(Error::Conflict);
            }
            if !matches_authorization {
                return Err(Error::Rejected);
            }
            let roster = authority(view, statement, &header, witness)?;
            if !is_current {
                certificate
                    .check_signatures(roster.keys())
                    .map_err(|_| Error::Rejected)?;
            }
            if roster.epoch_sequence < current.epoch_sequence {
                return Ok(Outcome::Historical);
            }
            Ok(Outcome::CurrentCertificate(
                certificate.statement.checkpoint_height,
            ))
        }
    }
}

#[cfg(test)]
mod tests;
