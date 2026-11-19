//! Bounded nonsigning observations against an independently accepted Store.
//! Observations grant no import, publication, readiness or state-adoption authority.
use super::{
    certificate::{AuthorizationWitness, Certificate, Statement, Vote},
    checkpoint_wire::{Incoming, MAX_GOVERNANCE_BYTES},
    commitment::{self, Component, ComponentId},
    header::Header,
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
    /// A current quorum shares the anchor but awaits canonical authorization.
    PendingAuthorization,
    /// Evidence cannot be preserved without losing a previously seen quorum.
    EvidenceUnavailable,
}
impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "checkpoint_observation_unavailable",
            Self::Rejected => "checkpoint_observation_rejected",
            Self::Conflict => "checkpoint_current_quorum_conflict",
            Self::PendingAuthorization => "checkpoint_authorization_pending",
            Self::EvidenceUnavailable => "checkpoint_observation_evidence_unavailable",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Proposal,
    Vote,
    CurrentCertificate(u64),
    Historical,
    PendingAuthorization,
    ObsoleteAuthorization,
}
const MAX_PENDING_AUTHORIZATIONS: usize = 8;
struct RetainedObservation {
    certificate: Certificate,
    obsolete: bool,
    witness: Option<AuthorizationWitness>,
    _witness_charge: Option<crate::p2p::Reservation>,
}
#[derive(Default)]
pub(crate) struct Observer {
    #[cfg(feature = "eng2-runtime")]
    progress_hub: Option<std::sync::Weak<super::resident::header_lane::Hub>>,
    last_now: Option<u64>,
    observed_height: Option<u64>,
    hard: Option<Error>,
    pending: Vec<RetainedObservation>,
    next_retained: usize,
    retired_anchor: Option<(u64, Hash)>,
    retired_anchor_unavailable: bool,
    _evidence_charge: Option<crate::p2p::Reservation>,
    budget: Option<crate::p2p::Budget>,
    #[cfg(unix)]
    evidence: Option<super::runtime_export::PublicExport>,
    #[cfg(all(test, unix))]
    synthetic_evidence: Vec<Certificate>,
    error: Option<Error>,
}
trait View {
    fn height(&self) -> u64;
    fn governance(&self) -> &GovernanceState;
    fn header(&self, height: u64) -> Result<Header, Error>;
    fn retained_header(&self, _height: u64, _id: Hash) -> Result<Option<Header>, Error> {
        Ok(None)
    }
}
struct Accepted<'a> {
    store: &'a Store,
    retained: &'a dyn Fn(u64, Hash) -> Result<Option<Header>, Error>,
}
impl View for Accepted<'_> {
    fn height(&self) -> u64 {
        self.store.engine().state().height()
    }
    fn governance(&self) -> &GovernanceState {
        self.store.engine().state().governance()
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.store.header(height).map_err(|_| Error::Unavailable)
    }
    fn retained_header(&self, height: u64, id: Hash) -> Result<Option<Header>, Error> {
        (self.retained)(height, id)
    }
}
impl Observer {
    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn observe_progress(
        &mut self,
        hub: &std::sync::Arc<super::resident::header_lane::Hub>,
    ) {
        self.progress_hub = Some(std::sync::Arc::downgrade(hub));
    }
    fn restrict_progress(&self) {
        #[cfg(feature = "eng2-runtime")]
        if let Some(hub) = self
            .progress_hub
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            hub.invalidate_progress_context();
        }
    }

    pub fn new(budget: &crate::p2p::Budget) -> Result<Self, String> {
        let charge = budget
            .reserve(MAX_PENDING_AUTHORIZATIONS * std::mem::size_of::<RetainedObservation>())
            .map_err(|_| "checkpoint observation evidence budget unavailable")?;
        let mut observer = Self::default();
        observer
            .pending
            .try_reserve_exact(MAX_PENDING_AUTHORIZATIONS)
            .map_err(|_| "checkpoint observation evidence allocation failed")?;
        observer._evidence_charge = Some(charge);
        observer.budget = Some(budget.clone());
        Ok(observer)
    }
    #[cfg(unix)]
    pub fn open_evidence(&mut self, root: &std::path::Path, store: &Store) -> Result<(), String> {
        if self.evidence.is_some() || !self.pending.is_empty() || self.observed_height.is_some() {
            return Err("checkpoint observation evidence already active".into());
        }
        let evidence = super::runtime_export::PublicExport::open_observation_evidence(root, store)?;
        if let Some(certificate) = evidence.observed_retirement()? {
            let roster = store.engine().state().governance().active_roster();
            if certificate.statement.roster_sequence == roster.epoch_sequence {
                if certificate.statement.roster_digest
                    != roster.digest(certificate.statement.network)
                    || roster.activated_height > certificate.statement.authorization_height
                {
                    return Err("checkpoint observation retirement roster differs".into());
                }
                certificate
                    .check_signatures(roster.keys())
                    .map_err(|_| "checkpoint observation retirement signatures invalid")?;
            }
            // Historical journal context restores a restriction only. It does
            // not establish current authorization or permit a new signature.
            self.retired_anchor = Some((
                certificate.statement.checkpoint_height,
                certificate.statement.checkpoint_block,
            ));
        }
        self.evidence = Some(evidence);
        self.reconcile_view(&Accepted {
            store,
            retained: &|_, _| Ok(None),
        });
        Ok(())
    }
    pub fn conflicted(&self) -> bool {
        self.hard.is_some()
            || self.retired_anchor_unavailable
            || self.pending.iter().any(|saved| !saved.obsolete)
    }
    pub fn observed_height(&self) -> Option<u64> {
        self.observed_height
    }
    pub fn error(&self) -> Option<Error> {
        self.error
    }
    pub fn gate_reason(&self) -> Option<Error> {
        self.hard
            .or_else(|| {
                self.retired_anchor_unavailable
                    .then_some(Error::Unavailable)
            })
            .or_else(|| {
                self.pending
                    .iter()
                    .any(|saved| !saved.obsolete)
                    .then_some(Error::PendingAuthorization)
            })
    }
    pub fn retained_target(&mut self) -> Option<(u64, Hash)> {
        for _ in 0..self.pending.len() {
            let index = self.next_retained % self.pending.len();
            self.next_retained = index + 1;
            let saved = &self.pending[index];
            if !saved.obsolete {
                let statement = &saved.certificate.statement;
                return Some((
                    statement.authorization_height,
                    statement.authorization_block,
                ));
            }
        }
        None
    }
    /// The caller holds the canonical owner lock and the decoded packet charge.
    /// No checkpoint key, archive scan, vote creation or outgoing queue is used.
    pub fn observe(
        &mut self,
        store: &Store,
        now: u64,
        incoming: &Incoming,
        retained: &impl Fn(u64, Hash) -> Result<Option<Header>, Error>,
    ) -> Result<Outcome, Error> {
        if let Some(error) = self.hard {
            return Err(error);
        }
        if store.ensure_exportable().is_err() {
            self.restrict_progress();
            self.error = Some(Error::Unavailable);
            return Err(Error::Unavailable);
        }
        let view = Accepted { store, retained };
        self.reconcile_view(&view);
        self.check(&view, now, incoming)
    }
    /// Called only under the canonical owner lock after an allowed transition.
    /// Matching identities alone never clear pending evidence or grant readiness.
    pub fn reconcile(
        &mut self,
        store: &Store,
        retained: &impl Fn(u64, Hash) -> Result<Option<Header>, Error>,
    ) {
        if store.ensure_exportable().is_ok() {
            let view = Accepted { store, retained };
            self.reconcile_authenticated_view(&view);
        }
    }
    fn reconcile_authenticated_view(&mut self, view: &impl View) {
        self.reconcile_view(view);
        if self.hard.is_some() {
            return;
        }
        #[cfg(unix)]
        for index in 0..self.pending.len() {
            let saved = &self.pending[index];
            if !saved.obsolete
                && let Some(witness) = &saved.witness
                && obsolete_authorization(view, &saved.certificate.statement, witness) == Ok(true)
                && current_quorum(view, &saved.certificate) == Ok(true)
            {
                let certificate = saved.certificate.clone();
                if let Err(error) = self.watch_retired(view, &certificate) {
                    self.restrict_progress();
                    self.error = Some(error);
                    if matches!(error, Error::Conflict | Error::EvidenceUnavailable) {
                        self.restrict_progress();
                        self.hard = Some(error);
                    }
                    return;
                }
                self.pending[index].obsolete = true;
            }
        }
        self.pending.retain(|saved| !saved.obsolete);
        self.error = self.gate_reason();
    }
    fn reconcile_view(&mut self, view: &impl View) {
        self.retired_anchor_unavailable = false;
        if let Some((height, anchor)) = self.retired_anchor {
            if height > view.height() {
                self.restrict_progress();
                self.retired_anchor_unavailable = true;
            } else {
                match view
                    .header(height)
                    .and_then(|header| header.id().map_err(|_| Error::Rejected))
                {
                    Ok(id) if id != anchor => {
                        self.restrict_progress();
                        self.hard = Some(Error::Conflict);
                        self.error = self.hard;
                        return;
                    }
                    Err(_) => {
                        self.restrict_progress();
                        self.retired_anchor_unavailable = true;
                    }
                    Ok(_) => (),
                }
            }
        }
        for saved in &self.pending {
            let certificate = &saved.certificate;
            if let Ok((_, selected)) = headers(view, &certificate.statement)
                && selected != certificate.statement.checkpoint_block
            {
                self.restrict_progress();
                self.hard = Some(Error::Conflict);
                self.error = self.hard;
                break;
            }
        }
    }
    fn watch_retired(&mut self, view: &impl View, certificate: &Certificate) -> Result<(), Error> {
        let statement = &certificate.statement;
        if view
            .header(statement.checkpoint_height)?
            .id()
            .map_err(|_| Error::Rejected)?
            != statement.checkpoint_block
        {
            return Err(Error::Conflict);
        }
        if let Some((height, anchor)) = self.retired_anchor {
            if height > view.height() {
                return Err(Error::Unavailable);
            }
            if view.header(height)?.id().map_err(|_| Error::Rejected)? != anchor {
                return Err(Error::Conflict);
            }
        }
        #[cfg(unix)]
        if let Some(evidence) = &self.evidence {
            self.retired_anchor = Some(
                evidence
                    .record_observed_retirement(certificate)
                    .map_err(|_| Error::EvidenceUnavailable)?,
            );
            return Ok(());
        }
        if self
            .retired_anchor
            .is_none_or(|(height, _)| height < statement.checkpoint_height)
        {
            self.retired_anchor = Some((statement.checkpoint_height, statement.checkpoint_block));
        }
        Ok(())
    }
    #[cfg(unix)]
    fn preserve_quorum(
        &mut self,
        certificate: &Certificate,
        keys: &[[u8; super::certificate::VERIFYING_KEY_BYTES]; 3],
    ) -> Result<(), Error> {
        #[cfg(unix)]
        if let Some(evidence) = &self.evidence {
            return match evidence.record_observed_quorum(certificate, keys) {
                Ok(false) => Ok(()),
                Ok(true) => Err(Error::Conflict),
                Err(_) => Err(Error::EvidenceUnavailable),
            };
        }
        #[cfg(test)]
        {
            let _ = keys;
            if let Some(saved) = self.synthetic_evidence.iter().find(|saved| {
                saved.statement.network == certificate.statement.network
                    && saved.statement.roster_sequence == certificate.statement.roster_sequence
                    && saved.statement.checkpoint_height == certificate.statement.checkpoint_height
            }) {
                return if saved.statement == certificate.statement {
                    Ok(())
                } else {
                    Err(Error::Conflict)
                };
            }
            self.synthetic_evidence.push(certificate.clone());
            Ok(())
        }
        #[cfg(not(test))]
        {
            let _ = keys;
            Err(Error::EvidenceUnavailable)
        }
    }
    fn check(&mut self, view: &impl View, now: u64, incoming: &Incoming) -> Result<Outcome, Error> {
        if let Some(error) = self.hard {
            return Err(error);
        }
        let result = if now >= 1u64 << 53
            || self.last_now.is_some_and(|last| now < last)
            || incoming.encode(MAX_GOVERNANCE_BYTES).is_err()
        {
            Err(Error::Rejected)
        } else {
            self.last_now = Some(now);
            (|| {
                let current = match incoming {
                    Incoming::Certified { certificate, .. } => current_quorum(view, certificate)?,
                    _ => false,
                };
                if current && let Incoming::Certified { certificate, .. } = incoming {
                    // Validate the network and readable confirmed prefix before
                    // admitting durable signature evidence; witnesses grant no authority.
                    headers(view, &certificate.statement)?;
                    #[cfg(unix)]
                    self.preserve_quorum(certificate, view.governance().active_roster().keys())?;
                }
                let result = evaluate(view, incoming, current);
                if result == Ok(Outcome::Historical)
                    && let Incoming::Certified {
                        certificate,
                        witness,
                    } = incoming
                {
                    let (header, selected) = headers(view, &certificate.statement)?;
                    if selected != certificate.statement.checkpoint_block {
                        return Err(Error::Rejected);
                    }
                    let roster = authority(view, &certificate.statement, &header, witness)?;
                    #[cfg(unix)]
                    self.preserve_quorum(certificate, roster.keys())?;
                    #[cfg(not(unix))]
                    let _ = roster;
                }
                if result == Ok(Outcome::ObsoleteAuthorization) {
                    let Incoming::Certified { certificate, .. } = incoming else {
                        unreachable!()
                    };
                    self.watch_retired(view, certificate)?;
                    let statement = &certificate.statement;
                    self.pending
                        .retain(|saved| saved.certificate.statement != *statement);
                    return result;
                }
                if result == Err(Error::PendingAuthorization) {
                    self.restrict_progress();
                    let Incoming::Certified {
                        certificate,
                        witness,
                    } = incoming
                    else {
                        unreachable!()
                    };
                    if self.pending.iter().any(|saved| {
                        saved.certificate.statement == certificate.statement
                            && saved.witness.as_ref() == Some(witness)
                    }) {
                        return Ok(Outcome::PendingAuthorization);
                    }
                    let (saved_witness, witness_charge) = {
                        let charge = self
                            .budget
                            .as_ref()
                            .map(|budget| budget.reserve(witness.governance.len()))
                            .transpose()
                            .map_err(|_| Error::EvidenceUnavailable)?;
                        let mut governance = Vec::new();
                        governance
                            .try_reserve_exact(witness.governance.len())
                            .map_err(|_| Error::EvidenceUnavailable)?;
                        governance.extend_from_slice(&witness.governance);
                        (
                            Some(AuthorizationWitness {
                                descriptors: witness.descriptors,
                                governance,
                            }),
                            charge,
                        )
                    };
                    if let Some(saved) = self
                        .pending
                        .iter_mut()
                        .find(|saved| saved.certificate.statement == certificate.statement)
                    {
                        saved.obsolete = false;
                        saved.witness = saved_witness;
                        saved._witness_charge = witness_charge;
                    } else {
                        if self.pending.len() == MAX_PENDING_AUTHORIZATIONS {
                            return Err(Error::EvidenceUnavailable);
                        }
                        self.pending.push(RetainedObservation {
                            certificate: (**certificate).clone(),
                            obsolete: false,
                            witness: saved_witness,
                            _witness_charge: witness_charge,
                        });
                    }
                    return Ok(Outcome::PendingAuthorization);
                }
                if matches!(
                    result,
                    Ok(Outcome::CurrentCertificate(_) | Outcome::Historical)
                ) && let Incoming::Certified { certificate, .. } = incoming
                {
                    self.pending
                        .retain(|saved| saved.certificate.statement != certificate.statement);
                }
                result
            })()
        };
        match result {
            Ok(outcome) => {
                if let Outcome::CurrentCertificate(height) = outcome {
                    self.observed_height = Some(self.observed_height.unwrap_or(0).max(height));
                }
                self.error = self.gate_reason();
            }
            Err(error) => {
                self.restrict_progress();
                self.error = Some(error);
                if matches!(error, Error::Conflict | Error::EvidenceUnavailable) {
                    self.restrict_progress();
                    self.hard = Some(error);
                }
            }
        }
        result
    }
}
fn current_quorum(view: &impl View, certificate: &Certificate) -> Result<bool, Error> {
    let statement = &certificate.statement;
    let current = view.governance().active_roster();
    if statement.roster_sequence != current.epoch_sequence {
        return Ok(false);
    }
    if statement.roster_digest != current.digest(statement.network)
        || current.activated_height > statement.authorization_height
    {
        return Err(Error::Rejected);
    }
    certificate
        .check_signatures(current.keys())
        .map_err(|_| Error::Rejected)?;
    Ok(true)
}
fn headers(view: &impl View, statement: &Statement) -> Result<(Header, Hash), Error> {
    let current = view.governance();
    if current.height() != view.height()
        || statement.network != current.network()
        || statement.encode().is_err()
        || !super::runtime_export::confirmed_checkpoint(
            statement.checkpoint_height,
            statement.authorization_height,
        )
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
fn evaluate(
    view: &impl View,
    incoming: &Incoming,
    verified_current: bool,
) -> Result<Outcome, Error> {
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
            if is_current && !verified_current {
                return Err(Error::Rejected);
            }
            let (header, selected) = headers(view, statement)?;
            let matches_authorization =
                header.id().map_err(|_| Error::Rejected)? == statement.authorization_block;
            if is_current && selected != statement.checkpoint_block {
                return Err(Error::Conflict);
            }
            if is_current && !matches_authorization {
                #[cfg(unix)]
                if obsolete_authorization(view, statement, witness)? {
                    return Ok(Outcome::ObsoleteAuthorization);
                }
                // Durable public observation evidence is currently available
                // on Unix. Other platforms retain the previous refusal policy.
                return Err(if cfg!(unix) {
                    Error::PendingAuthorization
                } else {
                    Error::Conflict
                });
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

#[cfg(unix)]
fn obsolete_authorization(
    view: &impl View,
    statement: &Statement,
    witness: &AuthorizationWitness,
) -> Result<bool, Error> {
    let (_, anchor) = headers(view, statement)?;
    if anchor != statement.checkpoint_block {
        return Err(Error::Conflict);
    }
    let saved = super::runtime_export::retained_authorization(
        statement.network,
        view.height(),
        statement,
        |height| view.header(height).map_err(|error| error.code().into()),
        &mut |height, id| {
            view.retained_header(height, id)
                .map_err(|error| error.code().into())
        },
    );
    let Ok((saved, false)) = saved else {
        return Ok(false);
    };
    // Current-quorum signatures are checked independently of this witness.
    // Binding to the exact old header establishes obsolescence only.
    authority(view, statement, &saved, witness)?;
    Ok(true)
}

#[cfg(test)]
pub(crate) mod tests;
