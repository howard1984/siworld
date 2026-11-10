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
    let mut governance = crate::eng2::snapshot::tests::bootstrap()
        .governance()
        .clone();
    for height in 1..=96 {
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
        height: 72,
        parent: [7; 32],
        timestamp: 21600,
        target: [255; 32],
        execution_commitment: [8; 32],
        body_commitment: [9; 32],
        nonce: 0,
    };
    let authorization = Header {
        network,
        height: 96,
        parent: [10; 32],
        timestamp: 28800,
        target: [255; 32],
        execution_commitment: commitment::aggregate_descriptors(
            network,
            96,
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
        checkpoint_height: 72,
        checkpoint_block: anchor.id().unwrap(),
        authorization_height: 96,
        authorization_block: authorization.id().unwrap(),
        roster_sequence: roster.epoch_sequence,
        roster_digest: roster.digest(network),
    };
    Synthetic {
        governance,
        headers: BTreeMap::from([(72, anchor), (96, authorization)]),
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
    assert_eq!(fixture.governance.active_roster().epoch_sequence, 1);
    let mut observer = Observer::default();
    assert_eq!(observer.check(&fixture, 1, &old), Ok(Outcome::Historical));
    assert_eq!(observer.observed_height(), None);
    assert!(!observer.conflicted());
}
