//! Bounded synthetic authorization tests; no native checkpoint is admitted.
use super::super::tests::{Directory, synthetic_candidate};
use super::*;
use crate::eng2::{checkpoint_observer::Observer, resident::peers::NetworkStatus};
use crate::eng2_governance::{
    Action, ActionKind, Authorization, GovernanceState, SIGNATURE_CONTEXT, SignedAction,
    SignerRole, SlotReplacement,
};
use std::sync::Arc;

fn readiness<'a>(
    store: &Store,
    network: &'a NetworkStatus,
    observer: &'a Observer,
) -> ResidentSigningReadiness<'a> {
    ResidentSigningReadiness {
        head: ResidentSigningReadiness::head(store).unwrap(),
        network,
        observer,
    }
}
// Exercise the same guarded closure path used separately for new proposals and
// new votes. This fixture cannot bypass the actual Store admission checks.
fn guarded_actions(store: &Store, gate: &dyn SigningReadiness, expected: bool) {
    let proposed = with_signing_readiness(store, Some(gate), || {
        let candidate = synthetic_candidate();
        Ok(Proposal {
            statement: candidate.statement().clone(),
            witness: candidate.witness().clone(),
        })
    })
    .unwrap();
    assert_eq!(proposed.is_some(), expected);
    let voted = with_signing_readiness(store, Some(gate), || {
        let candidate = synthetic_candidate();
        let pair = ml_dsa_65::generate_key_pair([3; 32]);
        let vote = Vote {
            slot: 0,
            signature: *ml_dsa_65::sign(
                &pair.signing_key,
                &candidate.statement().encode().unwrap(),
                Statement::signing_context(),
                [42; 32],
            )
            .unwrap()
            .as_ref(),
        };
        candidate.verify_vote(&vote)?;
        Ok(vote)
    })
    .unwrap();
    assert_eq!(voted.is_some(), expected);
}
#[test]
fn checkpoint_signing_requires_completed_current_round_and_revokes_stale_head_evidence() {
    let dir = Directory::new();
    let store = dir.store();
    let head = (0, store.engine().state().tip());
    let network = Arc::new(NetworkStatus::new([[1; 32], [2; 32]]));
    let observer = Observer::default();
    let gate = readiness(&store, &network, &observer);
    guarded_actions(&store, &gate, false);
    let connection = network.connected([1; 32]).unwrap();
    guarded_actions(&store, &gate, false);
    network.round([1; 32], 8, None).unwrap();
    guarded_actions(&store, &gate, false);
    network.round([1; 32], 0, Some((head.0, [9; 32]))).unwrap();
    guarded_actions(&store, &gate, false);
    network.round([1; 32], 0, Some(head)).unwrap();
    guarded_actions(&store, &gate, true);
    // Public miner sessions cannot establish or block a signing reference.
    let unpinned = network.connected([7; 32]).unwrap();
    network.round([7; 32], 8, None).unwrap();
    guarded_actions(&store, &gate, true);
    drop(unpinned);
    let behind = network.connected([2; 32]).unwrap();
    network.round([2; 32], 8, None).unwrap();
    guarded_actions(&store, &gate, false);
    network.round([2; 32], 0, Some(head)).unwrap();
    guarded_actions(&store, &gate, true);
    network.begin_round([1; 32]).unwrap();
    guarded_actions(&store, &gate, false);
    network.round([1; 32], 0, Some(head)).unwrap();
    let mut changed = readiness(&store, &network, &observer);
    changed.head.4[0] ^= 1;
    assert_eq!(changed.alarm(&store), Some(Alarm::Unavailable));
    guarded_actions(&store, &changed, false);
    drop(behind);
    drop(connection);
    guarded_actions(&store, &gate, false);
}
#[test]
fn checkpoint_quorum_conflict_blocks_new_signing_but_keeps_public_exports() {
    let dir = Directory::new();
    let store = dir.store();
    let root = dir.private("conflict-export");
    let network = Arc::new(NetworkStatus::new([[1; 32], [2; 32]]));
    let _connection = network.connected([1; 32]).unwrap();
    network
        .round([1; 32], 0, Some((0, store.engine().state().tip())))
        .unwrap();
    let observer = crate::eng2::checkpoint_observer::tests::synthetic_current_conflict();
    let gate = readiness(&store, &network, &observer);
    assert_eq!(gate.alarm(&store), Some(Alarm::CurrentQuorumConflict));
    guarded_actions(&store, &gate, false);
    let key = dir.0.join("synthetic-signer.bin");
    super::tests::key_fixture(&key, &store, 0, 3);
    let mut host = Host::open(
        &root,
        &store,
        crate::eng2::snapshot::tests::limits(),
        Some(&key),
    )
    .unwrap();
    let tick = host
        .tick_resident(&store, 100_000, &[], &network, &observer)
        .unwrap();
    assert!(tick.exported_current);
    assert_eq!(tick.status.alarm, Some(Alarm::CurrentQuorumConflict));
    let budget = crate::p2p::Budget::new(2 * 1024 * 1024);
    host.enable_wallet_export(&store, WalletPolicy::default(), &budget)
        .unwrap();
    host.tick_wallet_export(&store, 100_000, &budget).unwrap();
    assert_eq!(host.wallet_export_state(), Some(false));
    assert!(tick.proposal.is_none() && tick.vote.is_none());
    assert!(root.join("explorer.json").is_file());
    assert!(root.join("checkpoint-status-eng2.json").is_file());
    assert_eq!(store.engine().state().height(), 0);
}
fn signed_rotation(state: &GovernanceState) -> SignedAction {
    let action = Action {
        network: state.network(),
        sequence: 1,
        kind: ActionKind::ReplaceCheckpointSigners {
            replacements: vec![SlotReplacement {
                slot: 0,
                key: *ml_dsa_65::generate_key_pair([9; 32])
                    .verification_key
                    .as_ref(),
            }],
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
    SignedAction { action, signatures }
}
#[test]
fn checkpoint_replacement_authority_changes_only_at_the_executed_activation_boundary() {
    let dir = Directory::new();
    let store = dir.store();
    let engine = store.engine();
    let signer = |seed| {
        let pair = ml_dsa_65::generate_key_pair([seed; 32]);
        ExistingSigner {
            network: engine.state().network(),
            genesis: engine.genesis().id(),
            rules: engine.genesis().rules_commitment(),
            slot: 0,
            public: *pair.verification_key.as_ref(),
            key: pair.signing_key,
        }
    };
    let old = signer(3);
    let new = signer(9);
    let mut governance = engine.state().governance().clone();
    let check = |signer: &ExistingSigner, governance: &GovernanceState| {
        signer.check_authorization(
            engine.state().network(),
            engine.genesis().id(),
            engine.genesis().rules_commitment(),
            governance.active_roster(),
        )
    };
    let action = signed_rotation(&governance);
    governance.apply_block(1, &[action]).unwrap();
    for height in 2..=24 {
        governance.apply_block(height, &[]).unwrap();
        assert!(check(&new, &governance).is_err());
        assert!(check(&old, &governance).is_ok());
    }
    governance.apply_block(25, &[]).unwrap();
    assert!(check(&new, &governance).is_ok());
    assert!(check(&old, &governance).is_err());
    // The actual Store remains genesis: a separately advanced synthetic
    // governance value does not authorize loading or signing against that Store.
    assert!(new.check_current(&store).is_err());
    assert!(old.check_current(&store).is_ok());
    assert_eq!(governance.active_roster().activated_height, 25);
    assert_eq!(ActiveRoster::THRESHOLD, 2);
}

#[test]
fn pending_authorization_blocks_proposal_and_vote_even_with_current_peer_round() {
    let dir = Directory::new();
    let store = dir.store();
    let network = Arc::new(NetworkStatus::new([[1; 32]]));
    let _connection = network.connected([1; 32]).unwrap();
    network
        .round([1; 32], 0, Some((0, store.engine().state().tip())))
        .unwrap();
    let observer = crate::eng2::checkpoint_observer::tests::synthetic_pending_authorization();
    let gate = readiness(&store, &network, &observer);
    assert_eq!(gate.alarm(&store), Some(Alarm::CurrentQuorumConflict));
    guarded_actions(&store, &gate, false);
}
