//! Synthetic header views test observation policy, not native execution or import.
use super::*;
use crate::eng2::{certificate::Certificate, checkpoint_wire::Proposal, commitment::COMPONENTS};
use crate::eng2_governance::{
    Action, ActionKind, Authorization, SIGNATURE_CONTEXT, SignedAction, SignerRole, SlotReplacement,
};
use libcrux_ml_dsa::ml_dsa_65;
use std::collections::BTreeMap;

struct Synthetic {
    governance: GovernanceState,
    headers: BTreeMap<u64, Header>,
    statement: Statement,
    witness: AuthorizationWitness,
}
impl View for Synthetic {
    fn height(&self) -> u64 {
        self.governance.height()
    }
    fn governance(&self) -> &GovernanceState {
        &self.governance
    }
    fn header(&self, height: u64) -> Result<Header, Error> {
        self.headers.get(&height).cloned().ok_or(Error::Unavailable)
    }
}
fn fixture() -> Synthetic {
    fixture_at(72)
}
fn fixture_at(checkpoint: u64) -> Synthetic {
    let authorization_height = checkpoint + 24;
    let mut governance = crate::eng2::snapshot::tests::bootstrap()
        .governance()
        .clone();
    for height in 1..=authorization_height {
        governance.apply_block(height, &[]).unwrap();
    }
    let network = governance.network();
    let encoded = governance.canonical_component_bytes().unwrap();
    let witness = AuthorizationWitness {
        governance: encoded.clone(),
        descriptors: COMPONENTS.map(|id| {
            Component::from_local_encoding(
                id,
                if id == ComponentId::Governance {
                    &encoded
                } else {
                    b"synthetic public component"
                },
                MAX_GOVERNANCE_BYTES,
            )
            .unwrap()
            .descriptor()
        }),
    };
    let anchor = Header {
        network,
        height: checkpoint,
        parent: [7; 32],
        timestamp: 21600,
        target: [255; 32],
        execution_commitment: [8; 32],
        body_commitment: [9; 32],
        nonce: 0,
    };
    let authorization = Header {
        network,
        height: authorization_height,
        parent: [10; 32],
        timestamp: 28800,
        target: [255; 32],
        execution_commitment: commitment::aggregate_descriptors(
            network,
            authorization_height,
            [10; 32],
            &witness.descriptors,
        )
        .unwrap(),
        body_commitment: [11; 32],
        nonce: 0,
    };
    let roster = governance.active_roster();
    let statement = Statement {
        network,
        checkpoint_height: checkpoint,
        checkpoint_block: anchor.id().unwrap(),
        authorization_height,
        authorization_block: authorization.id().unwrap(),
        roster_sequence: roster.epoch_sequence,
        roster_digest: roster.digest(network),
    };
    Synthetic {
        governance,
        headers: BTreeMap::from([(checkpoint, anchor), (authorization_height, authorization)]),
        statement,
        witness,
    }
}
fn vote(statement: &Statement, slot: u8, seed: u8) -> Vote {
    Vote {
        slot,
        signature: *ml_dsa_65::sign(
            &ml_dsa_65::generate_key_pair([seed; 32]).signing_key,
            &statement.encode().unwrap(),
            Statement::signing_context(),
            [42; 32],
        )
        .unwrap()
        .as_ref(),
    }
}
fn certified(fixture: &Synthetic, statement: Statement) -> Incoming {
    Incoming::Certified {
        certificate: Box::new(Certificate {
            votes: [vote(&statement, 0, 3), vote(&statement, 1, 4)],
            statement,
        }),
        witness: fixture.witness.clone(),
    }
}
#[test]
fn proposals_votes_and_current_certificate_are_checked_without_changing_the_view() {
    let fixture = fixture();
    let before = fixture.governance.canonical_component_bytes().unwrap();
    let mut observer = Observer::default();
    let proposal = Incoming::Proposal(Proposal {
        statement: fixture.statement.clone(),
        witness: fixture.witness.clone(),
    });
    assert_eq!(
        observer.check(&fixture, 1, &proposal),
        Ok(Outcome::Proposal)
    );
    assert_eq!(observer.observed_height(), None);
    let packet = Incoming::Vote {
        statement: fixture.statement.clone(),
        vote: Box::new(vote(&fixture.statement, 0, 3)),
    };
    assert_eq!(observer.check(&fixture, 2, &packet), Ok(Outcome::Vote));
    assert_eq!(observer.observed_height(), None);
    assert_eq!(
        observer.check(&fixture, 3, &certified(&fixture, fixture.statement.clone())),
        Ok(Outcome::CurrentCertificate(72))
    );
    assert_eq!(observer.observed_height(), Some(72));
    assert!(!observer.conflicted());
    assert_eq!(
        before,
        fixture.governance.canonical_component_bytes().unwrap()
    );
}
#[test]
fn only_a_valid_current_quorum_can_latch_a_selected_prefix_conflict() {
    let fixture = fixture();
    let mut statement = fixture.statement.clone();
    statement.checkpoint_block[0] ^= 1;
    let packet = certified(&fixture, statement.clone());
    if let Incoming::Certified { certificate, .. } = &packet {
        certificate
            .check_signatures(fixture.governance.active_roster().keys())
            .unwrap();
    }
    let mut observer = Observer::default();
    let proposal = Incoming::Proposal(Proposal {
        statement: statement.clone(),
        witness: fixture.witness.clone(),
    });
    assert_eq!(observer.check(&fixture, 1, &proposal), Err(Error::Rejected));
    assert!(!observer.conflicted());
    let one_vote = Incoming::Vote {
        statement: statement.clone(),
        vote: Box::new(vote(&statement, 0, 3)),
    };
    assert_eq!(observer.check(&fixture, 2, &one_vote), Err(Error::Rejected));
    assert!(!observer.conflicted());
    assert_eq!(observer.check(&fixture, 3, &packet), Err(Error::Conflict));
    assert!(observer.conflicted());
    assert_eq!(observer.error(), Some(Error::Conflict));
    assert_eq!(
        observer.check(&fixture, 4, &certified(&fixture, fixture.statement.clone())),
        Err(Error::Conflict)
    );
    assert_eq!(observer.observed_height(), None);
}
#[test]
fn unknown_history_and_invalid_signatures_are_not_quorum_conflicts() {
    let fixture = fixture();
    let mut observer = Observer::default();
    let mut future = fixture.statement.clone();
    future.authorization_height = 97;
    future.authorization_block = [12; 32];
    assert_eq!(
        observer.check(&fixture, 1, &certified(&fixture, future)),
        Err(Error::Unavailable)
    );
    assert!(!observer.conflicted());
    let mut packet = certified(&fixture, fixture.statement.clone());
    if let Incoming::Certified { certificate, .. } = &mut packet {
        certificate.votes[0].signature[0] ^= 1;
    }
    assert_eq!(observer.check(&fixture, 2, &packet), Err(Error::Rejected));
    assert!(!observer.conflicted());
    let mut packet = certified(&fixture, fixture.statement.clone());
    if let Incoming::Certified { witness, .. } = &mut packet {
        witness.governance[0] ^= 1;
    }
    assert_eq!(observer.check(&fixture, 3, &packet), Err(Error::Rejected));
    assert_eq!(observer.observed_height(), None);
    assert_ne!(Error::Unavailable.code(), Error::Conflict.code());
}
#[test]
fn lawful_roster_rotation_keeps_old_certificates_historical_without_refreshing_observation() {
    let mut fixture = fixture();
    let old = certified(&fixture, fixture.statement.clone());
    rotate_roster(&mut fixture);
    assert_eq!(fixture.governance.active_roster().epoch_sequence, 1);
    let mut observer = Observer::default();
    assert_eq!(observer.check(&fixture, 1, &old), Ok(Outcome::Historical));
    let proposal = Incoming::Proposal(Proposal {
        statement: fixture.statement.clone(),
        witness: fixture.witness.clone(),
    });
    assert_eq!(
        observer.check(&fixture, 2, &proposal),
        Ok(Outcome::Historical)
    );
    assert_eq!(observer.observed_height(), None);
    assert!(!observer.conflicted());
}

#[cfg(unix)]
#[test]
fn current_quorum_for_competing_authorization_waits_without_trusting_its_witness() {
    let fixture = fixture();
    let mut statement = fixture.statement.clone();
    statement.authorization_block[0] ^= 1;
    let mut packet = certified(&fixture, statement);
    if let Incoming::Certified { witness, .. } = &mut packet {
        // This witness cannot bind to the competing header, which is absent.
        // Conflict authority comes only from independently current quorum keys.
        witness.governance[0] ^= 1;
    }
    let mut bad_signatures = packet.clone();
    if let Incoming::Certified { certificate, .. } = &mut bad_signatures {
        certificate.votes[1].signature[0] ^= 1;
    }
    let mut observer = Observer::default();
    assert_eq!(
        observer.check(&fixture, 1, &bad_signatures),
        Err(Error::Rejected)
    );
    assert!(!observer.conflicted());
    assert_eq!(
        observer.check(&fixture, 2, &packet),
        Ok(Outcome::PendingAuthorization)
    );
    assert!(observer.conflicted());
    assert_eq!(observer.error(), Some(Error::PendingAuthorization));
    assert_eq!(observer.observed_height(), None);
}

// Construct the latched state through actual synthetic quorum verification.
// This helper is compiled only with the unit-test module.
pub(crate) fn synthetic_current_conflict() -> Observer {
    let fixture = fixture();
    let mut statement = fixture.statement.clone();
    statement.checkpoint_block[0] ^= 1;
    let mut observer = Observer::default();
    assert_eq!(
        observer.check(&fixture, 1, &certified(&fixture, statement)),
        Err(Error::Conflict)
    );
    observer
}

#[test]
fn current_quorum_verification_does_not_depend_on_publisher_cadence() {
    for checkpoint in [1, 11, 13, 71, 73] {
        let fixture = fixture_at(checkpoint);
        let packet = certified(&fixture, fixture.statement.clone());
        assert_eq!(
            Observer::default().check(&fixture, 1, &packet),
            Ok(Outcome::CurrentCertificate(checkpoint))
        );
        let mut insufficient = fixture.statement.clone();
        insufficient.checkpoint_height += 1;
        let packet = certified(&fixture, insufficient);
        assert_eq!(
            Observer::default().check(&fixture, 1, &packet),
            Err(Error::Rejected)
        );
    }
}

#[cfg(unix)]
#[test]
fn canonical_adoption_requires_fresh_full_witness_before_same_observer_recovers() {
    let mut fixture = fixture_at(12);
    let original = fixture.headers[&36].clone();
    let packet = certified(&fixture, fixture.statement.clone());
    fixture.headers.get_mut(&36).unwrap().nonce ^= 1;
    let mut broken = packet.clone();
    if let Incoming::Certified { witness, .. } = &mut broken {
        witness.governance[0] ^= 1;
    }
    let mut observer = Observer::default();
    assert_eq!(
        observer.check(&fixture, 1, &broken),
        Ok(Outcome::PendingAuthorization)
    );
    assert!(observer.conflicted());
    assert_eq!(observer.pending.len(), 1);
    // Repeated pending evidence must not allocate another retained certificate.
    assert_eq!(
        observer.check(&fixture, 2, &broken),
        Ok(Outcome::PendingAuthorization)
    );
    assert_eq!(observer.pending.len(), 1);
    fixture.headers.insert(36, original);
    observer.reconcile_view(&fixture);
    assert!(observer.conflicted());
    assert_eq!(observer.observed_height(), None);
    assert_eq!(observer.check(&fixture, 3, &broken), Err(Error::Rejected));
    assert!(observer.conflicted());
    assert_eq!(
        observer.check(&fixture, 4, &packet),
        Ok(Outcome::CurrentCertificate(12))
    );
    assert!(!observer.conflicted());
    assert_eq!(observer.error(), None);
    assert_eq!(observer.observed_height(), Some(12));
    assert!(observer.pending.is_empty());
}

#[cfg(unix)]
#[test]
fn a_second_valid_statement_for_an_accepted_anchor_is_permanent_conflict() {
    let mut fixture = fixture_at(12);
    let first = certified(&fixture, fixture.statement.clone());
    let mut observer = Observer::default();
    assert_eq!(
        observer.check(&fixture, 1, &first),
        Ok(Outcome::CurrentCertificate(12))
    );
    fixture.headers.get_mut(&36).unwrap().nonce ^= 1;
    let mut other = fixture.statement.clone();
    other.authorization_block = fixture.headers[&36].id().unwrap();
    let second = certified(&fixture, other);
    assert_eq!(observer.check(&fixture, 2, &second), Err(Error::Conflict));
    assert!(observer.conflicted());
    assert_eq!(observer.pending.len(), 0);
    assert_eq!(observer.check(&fixture, 3, &first), Err(Error::Conflict));
}

#[cfg(unix)]
#[test]
fn missing_authorization_and_anchor_changes_cannot_clear_pending() {
    let mut fixture = fixture_at(12);
    let packet = certified(&fixture, fixture.statement.clone());
    fixture.headers.get_mut(&36).unwrap().nonce ^= 1;
    let mut observer = Observer::default();
    assert_eq!(
        observer.check(&fixture, 1, &packet),
        Ok(Outcome::PendingAuthorization)
    );
    let auth = fixture.headers.remove(&36).unwrap();
    observer.reconcile_view(&fixture);
    assert!(observer.conflicted());
    assert_eq!(
        observer.check(&fixture, 2, &packet),
        Err(Error::Unavailable)
    );
    fixture.headers.insert(36, auth);
    fixture.headers.get_mut(&12).unwrap().nonce ^= 1;
    observer.reconcile_view(&fixture);
    assert_eq!(observer.check(&fixture, 3, &packet), Err(Error::Conflict));
}

#[cfg(unix)]
#[test]
fn pending_capacity_is_fail_closed_and_evidence_budget_is_reserved() {
    let bytes = MAX_PENDING_AUTHORIZATIONS * std::mem::size_of::<Certificate>();
    assert!(Observer::new(&crate::p2p::Budget::new(bytes - 1)).is_err());
    let budget = crate::p2p::Budget::new(bytes);
    let mut observer = Observer::new(&budget).unwrap();
    assert!(budget.reserve(1).is_err());
    for checkpoint in 1..=MAX_PENDING_AUTHORIZATIONS as u64 + 1 {
        let mut fixture = fixture_at(checkpoint);
        let packet = certified(&fixture, fixture.statement.clone());
        fixture.headers.get_mut(&(checkpoint + 24)).unwrap().nonce ^= 1;
        let result = observer.check(&fixture, checkpoint, &packet);
        if checkpoint <= MAX_PENDING_AUTHORIZATIONS as u64 {
            assert_eq!(result, Ok(Outcome::PendingAuthorization));
        } else {
            assert_eq!(result, Err(Error::EvidenceUnavailable));
        }
    }
    assert_eq!(observer.pending.len(), MAX_PENDING_AUTHORIZATIONS);
    assert!(observer.conflicted());
    drop(observer);
    assert!(budget.reserve(bytes).is_ok());
}

fn rotate_roster(fixture: &mut Synthetic) {
    let action = Action {
        network: fixture.governance.network(),
        sequence: 1,
        kind: ActionKind::ReplaceCheckpointSigners {
            replacements: [6, 7, 8]
                .into_iter()
                .enumerate()
                .map(|(slot, seed)| SlotReplacement {
                    slot: slot as u8,
                    key: *ml_dsa_65::generate_key_pair([seed; 32])
                        .verification_key
                        .as_ref(),
                })
                .collect(),
        },
    };
    let signatures = [(SignerRole::Founder, 1), (SignerRole::Revocation, 2)]
        .into_iter()
        .map(|(role, seed)| Authorization {
            role,
            signature: *ml_dsa_65::sign(
                &ml_dsa_65::generate_key_pair([seed; 32]).signing_key,
                &action.signing_bytes(role).unwrap(),
                SIGNATURE_CONTEXT,
                [43; 32],
            )
            .unwrap()
            .as_ref(),
        })
        .collect();
    let signed = SignedAction { action, signatures };
    for height in 97..=124 {
        fixture
            .governance
            .apply_block(
                height,
                if height == 100 {
                    std::slice::from_ref(&signed)
                } else {
                    &[]
                },
            )
            .unwrap();
    }
}

#[cfg(unix)]
#[test]
fn roster_rotation_alone_never_clears_pending_but_verified_history_can() {
    let mut fixture = fixture();
    let selected = fixture.headers[&96].clone();
    let packet = certified(&fixture, fixture.statement.clone());
    fixture.headers.get_mut(&96).unwrap().nonce ^= 1;
    let mut observer = Observer::default();
    assert_eq!(
        observer.check(&fixture, 1, &packet),
        Ok(Outcome::PendingAuthorization)
    );
    rotate_roster(&mut fixture);
    observer.reconcile_view(&fixture);
    assert!(observer.conflicted());
    fixture.headers.insert(96, selected);
    observer.reconcile_view(&fixture);
    assert!(observer.conflicted());
    let mut broken = packet.clone();
    if let Incoming::Certified { witness, .. } = &mut broken {
        witness.governance[0] ^= 1;
    }
    assert_eq!(observer.check(&fixture, 2, &broken), Err(Error::Rejected));
    assert!(observer.conflicted());
    assert_eq!(
        observer.check(&fixture, 3, &packet),
        Ok(Outcome::Historical)
    );
    assert!(!observer.conflicted());
    assert_eq!(observer.observed_height(), None);
}

#[cfg(unix)]
pub(crate) fn synthetic_pending_authorization() -> Observer {
    let mut fixture = fixture_at(12);
    let packet = certified(&fixture, fixture.statement.clone());
    fixture.headers.get_mut(&36).unwrap().nonce ^= 1;
    let mut observer = Observer::default();
    assert_eq!(
        observer.check(&fixture, 1, &packet),
        Ok(Outcome::PendingAuthorization)
    );
    observer
}
