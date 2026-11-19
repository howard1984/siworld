use super::*;
use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65KeyPair};
use native::encryption::PaymentAddress;

// Deterministic ephemeral fixtures are unrelated to any network custody.
fn pair(seed: u8) -> MLDSA65KeyPair {
    ml_dsa_65::generate_key_pair([seed; 32])
}
fn address(seed: u8) -> PaymentAddress {
    let keys =
        crate::wallet::WalletKeys::from_seed([7; 32], zeroize::Zeroizing::new([seed; 32]), 0)
            .unwrap();
    keys.address()
}
fn fixture() -> GovernanceState {
    GovernanceState::new(
        [7; 32],
        *pair(1).verification_key.as_ref(),
        *pair(2).verification_key.as_ref(),
        [3, 4, 5].map(|n| *pair(n).verification_key.as_ref()),
        address(6),
        vec![address(8)],
    )
    .unwrap()
}
fn signed(sequence: u64, kind: ActionKind, roles: &[SignerRole]) -> SignedAction {
    let action = Action {
        network: [7; 32],
        sequence,
        kind,
    };
    let signatures = roles
        .iter()
        .copied()
        .map(|role| {
            let seed = match role {
                SignerRole::Founder => 1,
                SignerRole::Revocation => 2,
                SignerRole::Checkpoint(slot) => 3 + slot,
            };
            Authorization {
                role,
                signature: *ml_dsa_65::sign(
                    &pair(seed).signing_key,
                    &action.signing_bytes(role).unwrap(),
                    SIGNATURE_CONTEXT,
                    [19; 32],
                )
                .unwrap()
                .as_ref(),
            }
        })
        .collect();
    SignedAction { action, signatures }
}
fn replacement() -> ActionKind {
    ActionKind::ReplaceCheckpointSigners {
        replacements: vec![SlotReplacement {
            slot: 0,
            key: *pair(9).verification_key.as_ref(),
        }],
    }
}
fn advance(state: &mut GovernanceState, height: u64) {
    while state.height() < height {
        state.apply_block(state.height() + 1, &[]).unwrap();
    }
}
#[test]
fn unchanged_owner_authorization_survives_288_blocks_and_cannot_replay() {
    let mut state = fixture();
    let authorization = signed(
        1,
        ActionKind::ProposeIssuanceFee {
            amount_atoms: 100_000_000,
        },
        &[SignerRole::Founder],
    );
    let original_bytes = authorization.encode().unwrap();
    advance(&mut state, 288);
    let events = state
        .apply_block(289, std::slice::from_ref(&authorization))
        .unwrap();
    assert_eq!(events[0].included_height, 289);
    assert_eq!(authorization.encode().unwrap(), original_bytes);
    let before_replay = state.clone();
    assert!(state.apply_block(290, &[authorization]).is_err());
    assert_eq!(state, before_replay);
}
#[test]
fn roster_replacement_requires_both_owner_roles_and_is_atomic() {
    let initial = fixture();
    for roles in [
        vec![SignerRole::Founder],
        vec![SignerRole::Revocation],
        vec![SignerRole::Checkpoint(0)],
        vec![SignerRole::Founder, SignerRole::Founder],
    ] {
        let mut state = initial.clone();
        assert!(
            state
                .apply_block(1, &[signed(1, replacement(), &roles)])
                .is_err()
        );
        assert_eq!(state, initial);
    }
    let mut state = initial;
    let events = state
        .apply_block(
            1,
            &[signed(
                1,
                replacement(),
                &[SignerRole::Founder, SignerRole::Revocation],
            )],
        )
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].effective_height, 25);
    assert_eq!(state.active_roster().epoch_sequence, 0);
    advance(&mut state, 24);
    assert_eq!(state.active_roster().epoch_sequence, 0);
    state.apply_block(25, &[]).unwrap();
    assert_eq!(state.active_roster().epoch_sequence, 1);
    assert_eq!(state.active_roster().activated_height, 25);
    assert_eq!(
        state.active_roster().keys()[0],
        *pair(9).verification_key.as_ref()
    );
    assert_eq!(ActiveRoster::THRESHOLD, 2);
}
#[test]
fn batch_slots_preserve_order_and_reject_duplicates_cardinality_and_noops() {
    for replacements in [
        vec![],
        vec![SlotReplacement {
            slot: 3,
            key: *pair(9).verification_key.as_ref(),
        }],
        vec![
            SlotReplacement {
                slot: 0,
                key: *pair(9).verification_key.as_ref(),
            },
            SlotReplacement {
                slot: 0,
                key: *pair(10).verification_key.as_ref(),
            },
        ],
        vec![
            SlotReplacement {
                slot: 1,
                key: *pair(9).verification_key.as_ref(),
            },
            SlotReplacement {
                slot: 0,
                key: *pair(10).verification_key.as_ref(),
            },
        ],
        vec![SlotReplacement {
            slot: 0,
            key: *pair(4).verification_key.as_ref(),
        }],
        vec![SlotReplacement {
            slot: 0,
            key: *pair(3).verification_key.as_ref(),
        }],
    ] {
        let mut state = fixture();
        let before = state.clone();
        let action = signed(
            1,
            ActionKind::ReplaceCheckpointSigners { replacements },
            &[SignerRole::Founder, SignerRole::Revocation],
        );
        assert!(state.apply_block(1, &[action]).is_err());
        assert_eq!(state, before);
    }
    let mut state = fixture();
    state
        .apply_block(
            1,
            &[signed(
                1,
                ActionKind::ReplaceCheckpointSigners {
                    replacements: vec![
                        SlotReplacement {
                            slot: 0,
                            key: *pair(9).verification_key.as_ref(),
                        },
                        SlotReplacement {
                            slot: 2,
                            key: *pair(10).verification_key.as_ref(),
                        },
                    ],
                },
                &[SignerRole::Founder, SignerRole::Revocation],
            )],
        )
        .unwrap();
    advance(&mut state, 25);
    assert_eq!(
        state.active_roster().keys()[1],
        *pair(4).verification_key.as_ref()
    );
    assert_eq!(
        state.active_roster().keys()[2],
        *pair(10).verification_key.as_ref()
    );
}
#[test]
fn signatures_bind_network_payload_roles_and_sequence_and_replay_is_rejected() {
    let original = signed(
        1,
        replacement(),
        &[SignerRole::Founder, SignerRole::Revocation],
    );
    let mut wrong_network = original.clone();
    wrong_network.action.network = [8; 32];
    assert!(fixture().apply_block(1, &[wrong_network]).is_err());
    for mutate in 0..5 {
        let mut action = original.clone();
        match mutate {
            0 => action.action.sequence = 2,
            1 => action.signatures[0].role = SignerRole::Revocation,
            2 => action.signatures.swap(0, 1),
            4 => action.signatures[0].signature = action.signatures[1].signature,
            _ => {
                action.action.kind = ActionKind::ReplaceCheckpointSigners {
                    replacements: vec![SlotReplacement {
                        slot: 0,
                        key: *pair(10).verification_key.as_ref(),
                    }],
                }
            }
        }
        assert!(fixture().apply_block(1, &[action]).is_err());
    }
    let mut state = fixture();
    state
        .apply_block(1, std::slice::from_ref(&original))
        .unwrap();
    advance(&mut state, 25);
    let before = state.clone();
    assert!(state.apply_block(26, &[original]).is_err());
    assert_eq!(state, before);
}
#[test]
fn destination_changes_wait_4032_and_revocation_can_only_cancel_before_activation() {
    let mut state = fixture();
    let old = state.active_fee_destination().clone();
    let next = address(9);
    let proposal = ActionKind::ProposeDestination {
        target: DestinationTarget::Fees,
        address: Box::new(canonical_address(&next)),
    };
    assert!(
        state
            .clone()
            .apply_block(1, &[signed(1, proposal.clone(), &[SignerRole::Revocation])])
            .is_err()
    );
    state
        .apply_block(1, &[signed(1, proposal.clone(), &[SignerRole::Founder])])
        .unwrap();
    advance(&mut state, 4032);
    assert_eq!(state.active_fee_destination(), &old);
    let mut canceled = state.clone();
    canceled
        .apply_block(
            4033,
            &[signed(
                2,
                ActionKind::CancelDestination {
                    proposal_sequence: 1,
                },
                &[SignerRole::Revocation],
            )],
        )
        .unwrap_err();
    assert_eq!(canceled, state);
    state.apply_block(4033, &[]).unwrap();
    assert_eq!(state.active_fee_destination(), &next);
    let mut canceled = fixture();
    canceled
        .apply_block(1, &[signed(1, proposal, &[SignerRole::Founder])])
        .unwrap();
    canceled
        .apply_block(
            2,
            &[signed(
                2,
                ActionKind::CancelDestination {
                    proposal_sequence: 1,
                },
                &[SignerRole::Revocation],
            )],
        )
        .unwrap();
    advance(&mut canceled, 4033);
    assert_eq!(canceled.active_fee_destination(), &old);
}
#[test]
fn dual_key_rotation_has_full_delay_and_old_signatures_expire_atomically() {
    let kind = ActionKind::RotateOwnerKeys {
        founder: Box::new(*pair(11).verification_key.as_ref()),
        revocation: Box::new(*pair(12).verification_key.as_ref()),
    };
    for roles in [vec![SignerRole::Founder], vec![SignerRole::Revocation]] {
        let mut state = fixture();
        let before = state.clone();
        assert!(
            state
                .apply_block(1, &[signed(1, kind.clone(), &roles)])
                .is_err()
        );
        assert_eq!(state, before);
    }
    let mut state = fixture();
    state
        .apply_block(
            1,
            &[signed(
                1,
                kind,
                &[SignerRole::Founder, SignerRole::Revocation],
            )],
        )
        .unwrap();
    advance(&mut state, 4032);
    assert_eq!(
        state.active_owner_keys().0,
        pair(1).verification_key.as_ref()
    );
    state.apply_block(4033, &[]).unwrap();
    assert_eq!(
        state.active_owner_keys().0,
        pair(11).verification_key.as_ref()
    );
    let before = state.clone();
    assert!(
        state
            .apply_block(
                4034,
                &[signed(
                    2,
                    replacement(),
                    &[SignerRole::Founder, SignerRole::Revocation]
                )]
            )
            .is_err()
    );
    assert_eq!(state, before);
}
#[test]
fn canonical_governance_and_action_codecs_reject_cross_network_truncation_and_trailing_bytes() {
    let mut state = fixture();
    state
        .apply_block(
            1,
            &[signed(
                1,
                replacement(),
                &[SignerRole::Founder, SignerRole::Revocation],
            )],
        )
        .unwrap();
    let bytes = state.canonical_component_bytes().unwrap();
    assert_eq!(
        GovernanceState::decode_component(&bytes, [7; 32]).unwrap(),
        state
    );
    assert!(GovernanceState::decode_component(&bytes, [8; 32]).is_err());
    assert!(GovernanceState::decode_component(&bytes[..bytes.len() - 1], [7; 32]).is_err());
    assert!(
        GovernanceState::decode_component(&[bytes.as_slice(), &[0]].concat(), [7; 32]).is_err()
    );
    let original = signed(
        1,
        replacement(),
        &[SignerRole::Founder, SignerRole::Revocation],
    );
    let encoded = original.encode().unwrap();
    assert_eq!(SignedAction::decode(&encoded).unwrap(), original);
    assert!(SignedAction::decode(&encoded[..encoded.len() - 1]).is_err());
    assert!(SignedAction::decode(&[encoded.as_slice(), &[0]].concat()).is_err());
    let digest = state.active_roster().digest([7; 32]);
    assert_ne!(digest, state.active_roster().digest([8; 32]));
}
#[test]
fn invalid_second_action_rolls_back_first_action_and_block_activation() {
    let mut state = fixture();
    let before = state.clone();
    let first = signed(
        1,
        replacement(),
        &[SignerRole::Founder, SignerRole::Revocation],
    );
    let mut second = signed(
        2,
        ActionKind::ProposeDestination {
            target: DestinationTarget::Fees,
            address: Box::new(canonical_address(&address(9))),
        },
        &[SignerRole::Founder],
    );
    second.signatures[0].signature[0] ^= 1;
    assert!(state.apply_block(1, &[first, second]).is_err());
    assert_eq!(state, before);
}
#[test]
fn address_codec_validates_field_words_and_kem_key_and_fund_member_index() {
    let mut bytes = canonical_address(&address(9));
    assert_eq!(decode_address(&bytes).unwrap(), address(9));
    bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_address(&bytes).is_err());
    let mut state = fixture();
    let action = ActionKind::ProposeDestination {
        target: DestinationTarget::FundMember(1),
        address: Box::new(canonical_address(&address(9))),
    };
    assert!(
        state
            .apply_block(1, &[signed(1, action, &[SignerRole::Founder])])
            .is_err()
    );
    assert_eq!(
        state.canonical_fee_destination_bytes().unwrap(),
        canonical_address(state.active_fee_destination())
    );
}

#[test]
fn height_and_activation_overflows_leave_governance_unchanged() {
    for (delay, kind, roles) in [
        (
            24,
            replacement(),
            vec![SignerRole::Founder, SignerRole::Revocation],
        ),
        (
            4032,
            ActionKind::ProposeDestination {
                target: DestinationTarget::Fees,
                address: Box::new(canonical_address(&address(9))),
            },
            vec![SignerRole::Founder],
        ),
    ] {
        let mut state = fixture();
        state.height = u64::MAX - delay;
        let before = state.clone();
        assert!(
            state
                .apply_block(state.height() + 1, &[signed(1, kind, &roles)])
                .is_err()
        );
        assert_eq!(state, before);
    }
    let mut state = fixture();
    state.height = u64::MAX;
    let before = state.clone();
    assert!(state.apply_block(0, &[]).is_err());
    assert_eq!(state, before);
}

#[test]
fn canonical_state_rejects_impossible_epoch_and_zero_inclusion_context() {
    let mut state = fixture();
    state.roster.activated_height = 1;
    state.height = 1;
    assert!(state.canonical_component_bytes().is_err());
    let mut state = fixture();
    state.owner_activated_height = 1;
    state.height = 1;
    assert!(state.canonical_component_bytes().is_err());
    let mut state = fixture();
    state
        .apply_block(
            1,
            &[signed(
                1,
                replacement(),
                &[SignerRole::Founder, SignerRole::Revocation],
            )],
        )
        .unwrap();
    state.pending[0].included_height = 0;
    state.pending[0].effective_height = 24;
    if let PendingKind::Roster(roster) = &mut state.pending[0].kind {
        roster.activated_height = 24;
    }
    assert!(state.canonical_component_bytes().is_err());
}

// Tag 4 is the dedicated cancellation for jointly authorized changes.
fn joint_cancel(sequence: u64, proposal_sequence: u64, roles: &[SignerRole]) -> SignedAction {
    let mut bytes = b"SWG2ACT1".to_vec();
    bytes.extend_from_slice(&[7; 32]);
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.push(4);
    bytes.extend_from_slice(&proposal_sequence.to_le_bytes());
    let kind = Action::decode_unsigned(&bytes).unwrap().kind;
    signed(sequence, kind, roles)
}
fn rotation() -> ActionKind {
    ActionKind::RotateOwnerKeys {
        founder: Box::new(*pair(11).verification_key.as_ref()),
        revocation: Box::new(*pair(12).verification_key.as_ref()),
    }
}
#[test]
fn joint_cancellation_requires_both_current_owners_for_rotation_and_roster() {
    for kind in [rotation(), replacement()] {
        let mut state = fixture();
        state
            .apply_block(
                1,
                &[signed(
                    1,
                    kind,
                    &[SignerRole::Founder, SignerRole::Revocation],
                )],
            )
            .unwrap();
        for roles in [
            vec![SignerRole::Founder],
            vec![SignerRole::Revocation],
            vec![SignerRole::Checkpoint(0)],
        ] {
            let mut rejected = state.clone();
            assert!(
                rejected
                    .apply_block(2, &[joint_cancel(2, 1, &roles)])
                    .is_err()
            );
            assert_eq!(rejected, state);
        }
        let mut wrong_route = state.clone();
        assert!(
            wrong_route
                .apply_block(
                    2,
                    &[signed(
                        2,
                        ActionKind::CancelDestination {
                            proposal_sequence: 1
                        },
                        &[SignerRole::Revocation]
                    )]
                )
                .is_err()
        );
        assert_eq!(wrong_route, state);
        let cancel = joint_cancel(2, 1, &[SignerRole::Founder, SignerRole::Revocation]);
        let bytes = cancel.encode().unwrap();
        assert_eq!(SignedAction::decode(&bytes).unwrap(), cancel);
        let mut cross_network = cancel.clone();
        cross_network.action.network = [8; 32];
        let before = state.clone();
        assert!(state.apply_block(2, &[cross_network]).is_err());
        assert_eq!(state, before);
        state.apply_block(2, std::slice::from_ref(&cancel)).unwrap();
        assert!(state.pending.is_empty());
        let before = state.clone();
        assert!(state.apply_block(3, &[cancel]).is_err());
        assert_eq!(state, before);
        advance(&mut state, 4033);
        assert_eq!(
            state.active_owner_keys().0,
            pair(1).verification_key.as_ref()
        );
        assert_eq!(state.active_roster().epoch_sequence, 0);
    }
}
#[test]
fn joint_cancellation_is_only_valid_strictly_before_effective_height() {
    for (kind, effective) in [(rotation(), 4033), (replacement(), 25)] {
        let mut state = fixture();
        state
            .apply_block(
                1,
                &[signed(
                    1,
                    kind,
                    &[SignerRole::Founder, SignerRole::Revocation],
                )],
            )
            .unwrap();
        advance(&mut state, effective - 2);
        let cancel = joint_cancel(2, 1, &[SignerRole::Founder, SignerRole::Revocation]);
        let mut canceled = state.clone();
        canceled
            .apply_block(effective - 1, std::slice::from_ref(&cancel))
            .unwrap();
        assert!(canceled.pending.is_empty());
        state.apply_block(effective - 1, &[]).unwrap();
        let mut rejected = state.clone();
        rejected
            .apply_block(effective, std::slice::from_ref(&cancel))
            .unwrap_err();
        assert_eq!(rejected, state);
        // A successful block commits the activation even when cancellation is absent.
        state.apply_block(effective, &[]).unwrap();
        let before = state.clone();
        let mut current_cancel = cancel;
        if effective == 4033 {
            for (index, authorization) in current_cancel.signatures.iter_mut().enumerate() {
                authorization.signature = *ml_dsa_65::sign(
                    &pair(11 + index as u8).signing_key,
                    &current_cancel
                        .action
                        .signing_bytes(authorization.role)
                        .unwrap(),
                    SIGNATURE_CONTEXT,
                    [19; 32],
                )
                .unwrap()
                .as_ref();
            }
        }
        assert!(state.apply_block(effective + 1, &[current_cancel]).is_err());
        assert_eq!(state, before);
    }
}
#[test]
fn joint_cancellation_cannot_cancel_founder_only_destinations() {
    let mut state = fixture();
    state
        .apply_block(
            1,
            &[signed(
                1,
                ActionKind::ProposeDestination {
                    target: DestinationTarget::Fees,
                    address: Box::new(canonical_address(&address(9))),
                },
                &[SignerRole::Founder],
            )],
        )
        .unwrap();
    let before = state.clone();
    assert!(
        state
            .apply_block(
                2,
                &[joint_cancel(
                    2,
                    1,
                    &[SignerRole::Founder, SignerRole::Revocation]
                )]
            )
            .is_err()
    );
    assert_eq!(state, before);
}

#[test]
fn issuance_fee_genesis_parameters_are_frozen_and_validated() {
    let state = fixture();
    assert_eq!(state.issuance_fee_atoms(), 5_000_000_000);
    assert_eq!(
        state.issuance_fee_parameters(),
        IssuanceFeeParameters {
            initial_atoms: 5_000_000_000,
            minimum_atoms: 100_000_000,
            maximum_atoms: 1_000_000_000_000,
        }
    );
    assert!(state.pending_issuance_fee().is_none());
    for invalid in [
        IssuanceFeeParameters {
            initial_atoms: 0,
            ..IssuanceFeeParameters::default()
        },
        IssuanceFeeParameters {
            minimum_atoms: 0,
            ..IssuanceFeeParameters::default()
        },
        IssuanceFeeParameters {
            maximum_atoms: u64::MAX,
            ..IssuanceFeeParameters::default()
        },
    ] {
        assert!(
            GovernanceState::new_with_issuance_fee(
                [7; 32],
                *pair(1).verification_key.as_ref(),
                *pair(2).verification_key.as_ref(),
                [3, 4, 5].map(|n| *pair(n).verification_key.as_ref()),
                address(6),
                vec![address(8)],
                invalid,
            )
            .is_err()
        );
    }
}
#[test]
fn issuance_fee_proposal_requires_founder_and_waits_exactly_4032_blocks() {
    let proposal = ActionKind::ProposeIssuanceFee {
        amount_atoms: 6_000_000_000,
    };
    for roles in [
        vec![SignerRole::Revocation],
        vec![SignerRole::Checkpoint(0)],
        vec![SignerRole::Founder, SignerRole::Revocation],
    ] {
        let mut state = fixture();
        let before = state.clone();
        assert!(
            state
                .apply_block(1, &[signed(1, proposal.clone(), &roles)])
                .is_err()
        );
        assert_eq!(state, before);
    }
    let mut state = fixture();
    let inclusion = state
        .apply_block(1, &[signed(1, proposal, &[SignerRole::Founder])])
        .unwrap();
    assert_eq!(inclusion[0].new_issuance_fee_atoms, Some(6_000_000_000));
    assert_eq!(inclusion[0].effective_height, 4033);
    assert_eq!(
        state.pending_issuance_fee(),
        Some(PendingIssuanceFee {
            amount_atoms: 6_000_000_000,
            proposal_sequence: 1,
            included_height: 1,
            effective_height: 4033,
        })
    );
    advance(&mut state, 4032);
    assert_eq!(state.issuance_fee_atoms(), 5_000_000_000);
    state.apply_block(4033, &[]).unwrap();
    assert_eq!(state.issuance_fee_atoms(), 6_000_000_000);
    assert!(state.pending_issuance_fee().is_none());
    let bytes = state.canonical_component_bytes().unwrap();
    assert_eq!(
        GovernanceState::decode_component(&bytes, [7; 32]).unwrap(),
        state
    );
}
#[test]
fn issuance_fee_revocation_can_cancel_only_before_activation() {
    let mut state = fixture();
    state
        .apply_block(
            1,
            &[signed(
                1,
                ActionKind::ProposeIssuanceFee {
                    amount_atoms: 9_000_000_000,
                },
                &[SignerRole::Founder],
            )],
        )
        .unwrap();
    let cancel = ActionKind::CancelIssuanceFee {
        proposal_sequence: 1,
    };
    for roles in [
        vec![SignerRole::Founder],
        vec![SignerRole::Founder, SignerRole::Revocation],
    ] {
        let mut rejected = state.clone();
        assert!(
            rejected
                .apply_block(2, &[signed(2, cancel.clone(), &roles)])
                .is_err()
        );
        assert_eq!(rejected, state);
    }
    advance(&mut state, 4031);
    let mut canceled = state.clone();
    let records = canceled
        .apply_block(
            4032,
            &[signed(2, cancel.clone(), &[SignerRole::Revocation])],
        )
        .unwrap();
    assert_eq!(records[0].new_issuance_fee_atoms, None);
    advance(&mut canceled, 4034);
    assert_eq!(canceled.issuance_fee_atoms(), 5_000_000_000);
    assert!(canceled.pending_issuance_fee().is_none());
    state.apply_block(4032, &[]).unwrap();
    let before = state.clone();
    assert!(
        state
            .apply_block(
                4033,
                &[signed(2, cancel.clone(), &[SignerRole::Revocation])]
            )
            .is_err()
    );
    assert_eq!(state, before);
    state.apply_block(4033, &[]).unwrap();
    let before = state.clone();
    assert!(
        state
            .apply_block(4034, &[signed(2, cancel, &[SignerRole::Revocation])])
            .is_err()
    );
    assert_eq!(state, before);
}
#[test]
fn issuance_fee_bounds_pending_uniqueness_and_cross_kind_cancellation_are_enforced() {
    for amount_atoms in [0, 99_999_999, 1_000_000_000_001, u64::MAX] {
        let mut state = fixture();
        let before = state.clone();
        assert!(
            state
                .apply_block(
                    1,
                    &[signed(
                        1,
                        ActionKind::ProposeIssuanceFee { amount_atoms },
                        &[SignerRole::Founder]
                    )]
                )
                .is_err()
        );
        assert_eq!(state, before);
    }
    for amount_atoms in [100_000_000, 1_000_000_000_000] {
        let mut state = fixture();
        state
            .apply_block(
                1,
                &[signed(
                    1,
                    ActionKind::ProposeIssuanceFee { amount_atoms },
                    &[SignerRole::Founder],
                )],
            )
            .unwrap();
        let before = state.clone();
        for (kind, roles) in [
            (
                ActionKind::ProposeIssuanceFee {
                    amount_atoms: 2_000_000_000,
                },
                vec![SignerRole::Founder],
            ),
            (
                ActionKind::CancelDestination {
                    proposal_sequence: 1,
                },
                vec![SignerRole::Revocation],
            ),
            (
                ActionKind::CancelJointChange {
                    proposal_sequence: 1,
                },
                vec![SignerRole::Founder, SignerRole::Revocation],
            ),
        ] {
            assert!(state.apply_block(2, &[signed(2, kind, &roles)]).is_err());
            assert_eq!(state, before);
        }
    }
    let mut state = fixture();
    state
        .apply_block(
            1,
            &[signed(
                1,
                ActionKind::ProposeDestination {
                    target: DestinationTarget::Fees,
                    address: Box::new(canonical_address(&address(9))),
                },
                &[SignerRole::Founder],
            )],
        )
        .unwrap();
    let before = state.clone();
    assert!(
        state
            .apply_block(
                2,
                &[signed(
                    2,
                    ActionKind::CancelIssuanceFee {
                        proposal_sequence: 1
                    },
                    &[SignerRole::Revocation]
                )]
            )
            .is_err()
    );
    assert_eq!(state, before);
}
#[test]
fn issuance_fee_codecs_bind_amount_context_and_reject_replay_and_malformed_state() {
    let proposal = signed(
        1,
        ActionKind::ProposeIssuanceFee {
            amount_atoms: 6_000_000_000,
        },
        &[SignerRole::Founder],
    );
    let bytes = proposal.encode().unwrap();
    assert_eq!(SignedAction::decode(&bytes).unwrap(), proposal);
    let cancel = signed(
        2,
        ActionKind::CancelIssuanceFee {
            proposal_sequence: 1,
        },
        &[SignerRole::Revocation],
    );
    assert_eq!(
        SignedAction::decode(&cancel.encode().unwrap()).unwrap(),
        cancel
    );
    for mutation in 0..3 {
        let mut altered = proposal.clone();
        match mutation {
            0 => {
                altered.action.kind = ActionKind::ProposeIssuanceFee {
                    amount_atoms: 7_000_000_000,
                }
            }
            1 => altered.action.network = [8; 32],
            _ => altered.action.sequence = 2,
        }
        assert!(fixture().apply_block(1, &[altered]).is_err());
    }
    let mut state = fixture();
    state
        .apply_block(1, std::slice::from_ref(&proposal))
        .unwrap();
    let encoded = state.canonical_component_bytes().unwrap();
    assert_eq!(&encoded[..8], b"SWG2GOV2");
    assert_eq!(
        GovernanceState::decode_component(&encoded, [7; 32]).unwrap(),
        state
    );
    let before = state.clone();
    assert!(state.apply_block(2, &[proposal]).is_err());
    assert_eq!(state, before);
    let mut invalid = state.clone();
    if let PendingKind::IssuanceFee { amount_atoms } = &mut invalid.pending[0].kind {
        *amount_atoms = 0;
    }
    assert!(invalid.canonical_component_bytes().is_err());
    let mut invalid = state.clone();
    invalid.pending.push(invalid.pending[0].clone());
    assert!(invalid.canonical_component_bytes().is_err());
    let mut invalid = state.clone();
    invalid.issuance_fee_atoms = 7_000_000_000;
    assert!(invalid.canonical_component_bytes().is_err());
    let mut other = fixture();
    other.apply_block(1, &[]).unwrap();
    assert_ne!(encoded, other.canonical_component_bytes().unwrap());
    advance(&mut state, 4033);
    advance(&mut other, 4033);
    assert_ne!(
        state.canonical_component_bytes().unwrap(),
        other.canonical_component_bytes().unwrap()
    );
}
#[test]
fn issuance_fee_activation_and_multiple_actions_remain_atomic() {
    let mut state = fixture();
    state
        .apply_block(
            1,
            &[signed(
                1,
                ActionKind::ProposeIssuanceFee {
                    amount_atoms: 6_000_000_000,
                },
                &[SignerRole::Founder],
            )],
        )
        .unwrap();
    advance(&mut state, 4032);
    let before = state.clone();
    let mut invalid = signed(
        2,
        ActionKind::ProposeIssuanceFee {
            amount_atoms: 7_000_000_000,
        },
        &[SignerRole::Founder],
    );
    invalid.signatures[0].signature[0] ^= 1;
    assert!(state.apply_block(4033, &[invalid]).is_err());
    assert_eq!(state, before);
    state.apply_block(4033, &[]).unwrap();
    assert_eq!(state.issuance_fee_atoms(), 6_000_000_000);
    let before = fixture();
    let mut state = before.clone();
    assert!(
        state
            .apply_block(
                1,
                &[
                    signed(
                        1,
                        ActionKind::ProposeIssuanceFee {
                            amount_atoms: 7_000_000_000
                        },
                        &[SignerRole::Founder]
                    ),
                    signed(
                        2,
                        ActionKind::ProposeIssuanceFee {
                            amount_atoms: 8_000_000_000
                        },
                        &[SignerRole::Founder]
                    ),
                ]
            )
            .is_err()
    );
    assert_eq!(state, before);
}
