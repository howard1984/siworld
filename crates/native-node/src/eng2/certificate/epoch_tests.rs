use super::*;
use crate::eng2::{
    admission::AdmissionPlan,
    commitment::{self, COMPONENTS, Component, ComponentId},
    header::Header,
    selection::{HeaderRules, SourceObservation, VerifiedHeaders},
};
use crate::eng2_governance::{
    Action, ActionKind, Authorization, GovernanceState, SIGNATURE_CONTEXT, SignedAction,
    SignerRole, SlotReplacement,
};
use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65KeyPair};
use siworld_core::pow::Work;
use std::net::IpAddr;

const LIMIT: usize = 131_072;
struct Fixture {
    plan: AdmissionPlan,
    states: Vec<GovernanceState>,
    witnesses: Vec<AuthorizationWitness>,
    old: [MLDSA65KeyPair; 3],
    new: [MLDSA65KeyPair; 3],
}
fn pair(seed: u8) -> MLDSA65KeyPair {
    ml_dsa_65::generate_key_pair([seed; 32])
}
fn witness(state: &GovernanceState) -> AuthorizationWitness {
    let governance = state.canonical_component_bytes().unwrap();
    let components: Vec<_> = COMPONENTS
        .into_iter()
        .map(|id| {
            Component::from_local_encoding(
                id,
                if id == ComponentId::Governance {
                    &governance
                } else {
                    b"synthetic other component"
                },
                LIMIT,
            )
            .unwrap()
        })
        .collect();
    AuthorizationWitness {
        descriptors: components
            .iter()
            .map(Component::descriptor)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        governance,
    }
}
fn fixture(skew_authorization_height: bool) -> Fixture {
    let network = [1; 32];
    let founder = pair(1);
    let revocation = pair(2);
    let old = [3, 4, 5].map(pair);
    let new = [6, 7, 8].map(pair);
    let address =
        crate::wallet::WalletKeys::from_seed(network, zeroize::Zeroizing::new([9; 32]), 0)
            .unwrap()
            .address();
    let mut governance = GovernanceState::new(
        network,
        *founder.verification_key.as_ref(),
        *revocation.verification_key.as_ref(),
        old.each_ref().map(|key| *key.verification_key.as_ref()),
        address.clone(),
        vec![address],
    )
    .unwrap();
    let action = Action {
        network,
        sequence: 1,
        kind: ActionKind::ReplaceCheckpointSigners {
            replacements: new
                .iter()
                .enumerate()
                .map(|(slot, pair)| SlotReplacement {
                    slot: slot as u8,
                    key: *pair.verification_key.as_ref(),
                })
                .collect(),
        },
    };
    let signatures = [
        (SignerRole::Founder, &founder),
        (SignerRole::Revocation, &revocation),
    ]
    .into_iter()
    .map(|(role, key)| Authorization {
        role,
        signature: *ml_dsa_65::sign(
            &key.signing_key,
            &action.signing_bytes(role).unwrap(),
            SIGNATURE_CONTEXT,
            [10; 32],
        )
        .unwrap()
        .as_ref(),
    })
    .collect();
    let replacement = SignedAction { action, signatures };
    let mut states = vec![governance.clone()];
    let mut witnesses = vec![witness(&governance)];
    let rules = HeaderRules {
        network,
        genesis: [2; 32],
        genesis_timestamp: 1,
        genesis_target: [0xff; 32],
        target_interval: 300,
        pow_iterations: 0,
        max_headers: 1000,
    };
    let mut parent = rules.genesis;
    let mut headers = Vec::new();
    for height in 1..=40 {
        governance
            .apply_block(
                height,
                if height == 1 {
                    std::slice::from_ref(&replacement)
                } else {
                    &[]
                },
            )
            .unwrap();
        let witness = witness(if skew_authorization_height && height == 30 {
            &states[29]
        } else {
            &governance
        });
        let root = commitment::aggregate_descriptors(network, height, parent, &witness.descriptors)
            .unwrap();
        let header = Header {
            network,
            height,
            parent,
            timestamp: 1 + height * 300,
            target: [0xff; 32],
            execution_commitment: root,
            body_commitment: [7; 32],
            nonce: 0,
        };
        parent = header.id().unwrap();
        headers.push(header);
        states.push(governance.clone());
        witnesses.push(witness);
    }
    let chain = VerifiedHeaders::verify(rules, headers).unwrap();
    let sources: Vec<_> = (1..=3)
        .map(|id| SourceObservation {
            authenticated_identity: [id; 32],
            transport_address: IpAddr::from([10, id, 0, 1]),
            chain: &chain,
        })
        .collect();
    Fixture {
        plan: AdmissionPlan::select(&sources, Work::one()).unwrap(),
        states,
        witnesses,
        old,
        new,
    }
}
fn signed(
    fixture: &Fixture,
    authorization_height: u64,
    checkpoint_block: Hash,
    old_keys: bool,
) -> Certificate {
    let state = &fixture.states[authorization_height as usize];
    let statement = Statement {
        network: state.network(),
        checkpoint_height: 1,
        checkpoint_block,
        authorization_height,
        authorization_block: fixture.plan.headers().id(authorization_height).unwrap(),
        roster_sequence: state.active_roster().epoch_sequence,
        roster_digest: state.active_roster().digest(state.network()),
    };
    let keys = if old_keys { &fixture.old } else { &fixture.new };
    let votes = [0, 2].map(|slot| Vote {
        slot,
        signature: *ml_dsa_65::sign(
            &keys[usize::from(slot)].signing_key,
            &statement.encode().unwrap(),
            DOMAIN,
            [32 + slot; 32],
        )
        .unwrap()
        .as_ref(),
    });
    Certificate { statement, votes }
}

#[test]
fn current_epoch_signers_can_authenticate_an_older_anchor_and_real_conflict() {
    let fixture = fixture(false);
    let selected = fixture.plan.headers().id(1).unwrap();
    let certificate = signed(&fixture, 30, selected, false);
    assert_eq!(
        certificate.evaluate_current(
            &fixture.witnesses[30],
            &fixture.plan,
            &fixture.states[40],
            LIMIT
        ),
        Ok(CurrentOutcome::Consistent)
    );
    let contradictory = signed(&fixture, 30, [99; 32], false);
    assert_eq!(
        contradictory.evaluate_current(
            &fixture.witnesses[30],
            &fixture.plan,
            &fixture.states[40],
            LIMIT
        ),
        Ok(CurrentOutcome::Conflict {
            height: 1,
            selected,
            certified: [99; 32]
        })
    );
}

#[test]
fn removed_keys_cannot_halt_admission_by_backdating_an_old_authorization_context() {
    let fixture = fixture(false);
    let backdated = signed(&fixture, 24, [99; 32], true);
    assert_eq!(
        backdated.evaluate_current(
            &fixture.witnesses[24],
            &fixture.plan,
            &fixture.states[40],
            LIMIT
        ),
        Ok(CurrentOutcome::Historical)
    );
    let wrong_keys = signed(&fixture, 30, [99; 32], true);
    assert_eq!(
        wrong_keys.evaluate_current(
            &fixture.witnesses[30],
            &fixture.plan,
            &fixture.states[40],
            LIMIT
        ),
        Err(CertificateError::Signature)
    );
}

#[test]
fn component_height_or_current_head_mismatch_cannot_authorize_a_conflict() {
    let fixture = fixture(false);
    let selected = fixture.plan.headers().id(1).unwrap();
    let certificate = signed(&fixture, 30, selected, false);
    assert_eq!(
        certificate.evaluate_current(
            &fixture.witnesses[30],
            &fixture.plan,
            &fixture.states[39],
            LIMIT
        ),
        Err(CertificateError::Witness)
    );
    let mut corrupted = fixture.witnesses[30].clone();
    corrupted.governance[0] ^= 1;
    assert_eq!(
        certificate.evaluate_current(&corrupted, &fixture.plan, &fixture.states[40], LIMIT),
        Err(CertificateError::Witness)
    );
    let skewed = self::fixture(true);
    let certificate = signed(&skewed, 30, [99; 32], false);
    assert_eq!(
        certificate.evaluate_current(
            &skewed.witnesses[30],
            &skewed.plan,
            &skewed.states[40],
            LIMIT
        ),
        Err(CertificateError::Witness)
    );
}
