use super::*;
use crate::eng2::{
    certificate::{SIGNATURE_BYTES, STATEMENT_BYTES, Statement, Vote},
    commitment::{COMPONENTS, Component, ComponentId, aggregate_descriptors},
    selection::{HeaderRules, SourceObservation, VerifiedHeaders},
    state_components::Limits,
};
use crate::{eng2_governance::GovernanceState, state::Config};
use native::{encryption::PaymentAddress, multi_asset::F};
use p3_field::PrimeCharacteristicRing;
use siworld_core::{pow::Work, v1_economics::FundAllocation};
use std::{net::IpAddr, path::PathBuf};

// Synthetic public framing and ephemeral governance-signature fixtures only.
// No wallet custody, identity initialization or native proof generation occurs.
fn genesis() -> Genesis {
    let config = Config::asert_development([51; 32], 1, [0xff; 32], 1)
        .unwrap()
        .with_fund_wallets(
            FundAllocation::new_bps(vec![5000, 5000], 1).unwrap(),
            vec![[6; 1952], [7; 1952]],
        )
        .unwrap();
    let address = PaymentAddress::new([F::ZERO; 12], [0; 1184]).unwrap();
    let governance = GovernanceState::new(
        config.network,
        [1; 1952],
        [2; 1952],
        [[3; 1952], [4; 1952], [5; 1952]],
        address.clone(),
        vec![address.clone(), address],
    )
    .unwrap();
    Genesis::seal(config, governance, FeeMode::LegacyMiner).unwrap()
}
fn policy() -> Policy {
    Policy {
        state: ImportLimits {
            chain: Limits {
                max_leaves: 1000,
                max_nullifiers: 1000,
                max_component_bytes: 1024 * 1024,
            },
            max_snapshot_bytes: 16 * 1024 * 1024,
        },
        max_headers: 1000,
        max_verification_bytes: 32 * 1024 * 1024,
    }
}
fn selected(genesis: &Genesis, count: u64) -> (AdmissionPlan, AuthorizationWitness) {
    selected_with_governance(genesis, count, genesis.initial_governance().clone())
}
fn selected_with_governance(
    genesis: &Genesis,
    count: u64,
    mut governance: GovernanceState,
) -> (AdmissionPlan, AuthorizationWitness) {
    let config = genesis.config();
    for height in 1..=count {
        governance.apply_block(height, &[]).unwrap();
    }
    let governance_bytes = governance.canonical_component_bytes().unwrap();
    let components = COMPONENTS.map(|id| {
        Component::from_local_encoding(
            id,
            if id == ComponentId::Governance {
                &governance_bytes
            } else {
                b"synthetic component framing"
            },
            policy().state.chain.max_component_bytes,
        )
        .unwrap()
    });
    let witness = AuthorizationWitness {
        descriptors: components.each_ref().map(Component::descriptor),
        governance: governance_bytes,
    };
    let mut headers = Vec::new();
    let mut parent = genesis.id();
    for height in 1..=count {
        let header = Header {
            network: config.network,
            height,
            parent,
            timestamp: 1 + height * 300,
            target: [0xff; 32],
            nonce: 0,
            body_commitment: [11; 32],
            execution_commitment: aggregate_descriptors(
                config.network,
                height,
                parent,
                &witness.descriptors,
            )
            .unwrap(),
        };
        parent = header.id().unwrap();
        headers.push(header);
    }
    let chain = VerifiedHeaders::verify(
        HeaderRules {
            network: config.network,
            genesis: genesis.id(),
            genesis_timestamp: 1,
            genesis_target: [0xff; 32],
            target_interval: 300,
            pow_iterations: 1,
            max_headers: 1000,
        },
        headers,
    )
    .unwrap();
    let sources = (1..=3)
        .map(|id| SourceObservation {
            authenticated_identity: [id; 32],
            transport_address: IpAddr::from([10, id, 0, 1]),
            chain: &chain,
        })
        .collect::<Vec<_>>();
    (
        AdmissionPlan::select(&sources, Work::one()).unwrap(),
        witness,
    )
}
fn certificate(plan: &AdmissionPlan, genesis: &Genesis) -> Certificate {
    Certificate {
        statement: Statement {
            network: genesis.config().network,
            checkpoint_height: 72,
            checkpoint_block: plan.headers().id(72).unwrap(),
            authorization_height: plan.pin().tip_height,
            authorization_block: plan.pin().tip_id,
            roster_sequence: 0,
            roster_digest: genesis
                .initial_governance()
                .active_roster()
                .digest(genesis.config().network),
        },
        votes: [0, 1].map(|slot| Vote {
            slot,
            signature: [0; SIGNATURE_BYTES],
        }),
    }
}

fn pair(seed: u8) -> libcrux_ml_dsa::ml_dsa_65::MLDSA65KeyPair {
    libcrux_ml_dsa::ml_dsa_65::generate_key_pair([seed; 32])
}
fn test_governance(owners: [u8; 2], roster: [u8; 3]) -> GovernanceState {
    let address = PaymentAddress::new([F::ZERO; 12], [0; 1184]).unwrap();
    GovernanceState::new(
        genesis().config().network,
        *pair(owners[0]).verification_key.as_ref(),
        *pair(owners[1]).verification_key.as_ref(),
        roster.map(|seed| *pair(seed).verification_key.as_ref()),
        address.clone(),
        vec![address],
    )
    .unwrap()
}

#[test]
fn attacker_roster_and_valid_self_signatures_cannot_replace_pinned_governance() {
    use libcrux_ml_dsa::ml_dsa_65;
    let genesis = genesis();
    let attacker = test_governance([11, 12], [13, 14, 15]);
    let (plan, witness) = selected_with_governance(&genesis, 96, attacker.clone());
    let plan = AdmissionPlan::select_signed(&[plan.headers()], Work::one())
        .unwrap()
        .at_checkpoint(72, 73, 96)
        .unwrap();
    let mut certificate = certificate(&plan, &genesis);
    certificate.statement.roster_digest = attacker.active_roster().digest(genesis.config().network);
    for vote in &mut certificate.votes {
        vote.signature = *ml_dsa_65::sign(
            &pair(13 + vote.slot).signing_key,
            &certificate.statement.encode().unwrap(),
            Statement::signing_context(),
            [71; 32],
        )
        .unwrap()
        .as_ref();
    }
    certificate
        .check_signatures(attacker.active_roster().keys())
        .unwrap();
    witness
        .verify_binding(
            &certificate.statement,
            plan.headers(),
            policy().state.chain.max_component_bytes,
        )
        .unwrap();
    // Work inclusion and valid attacker signatures are insufficient. The same
    // gate used by import compares independently replayed pinned governance.
    let mut legitimate = genesis.initial_governance().clone();
    for height in 1..=96 {
        replay_governance(&mut legitimate, height, &[]).unwrap();
    }
    assert!(check_governance_lineage(&legitimate, &witness.governance).is_err());
}

#[test]
fn public_governance_replay_requires_dual_owner_auth_and_full_activation_delay() {
    use crate::eng2_governance::{
        Action, ActionKind, Authorization, SIGNATURE_CONTEXT, SignedAction, SignerRole,
        SlotReplacement,
    };
    use libcrux_ml_dsa::ml_dsa_65;
    let initial = test_governance([1, 2], [3, 4, 5]);
    let action = Action {
        network: initial.network(),
        sequence: 1,
        kind: ActionKind::ReplaceCheckpointSigners {
            replacements: vec![SlotReplacement {
                slot: 0,
                key: *pair(9).verification_key.as_ref(),
            }],
        },
    };
    let signatures = [(SignerRole::Founder, 1), (SignerRole::Revocation, 2)]
        .map(|(role, seed)| Authorization {
            role,
            signature: *ml_dsa_65::sign(
                &pair(seed).signing_key,
                &action.signing_bytes(role).unwrap(),
                SIGNATURE_CONTEXT,
                [72; 32],
            )
            .unwrap()
            .as_ref(),
        })
        .to_vec();
    let signed = SignedAction { action, signatures };
    let mut state = initial.clone();
    let mut one_owner = signed.clone();
    one_owner.signatures.pop();
    assert!(replay_governance(&mut state, 1, &[one_owner.encode().unwrap()]).is_err());
    assert_eq!(state, initial);
    replay_governance(&mut state, 1, &[signed.encode().unwrap()]).unwrap();
    for height in 2..=24 {
        replay_governance(&mut state, height, &[]).unwrap();
    }
    assert_eq!(state.active_roster().epoch_sequence, 0);
    replay_governance(&mut state, 25, &[]).unwrap();
    assert_eq!(state.active_roster().epoch_sequence, 1);
    assert_eq!(state.active_roster().activated_height, 25);
    assert_eq!(
        state.active_roster().keys()[0],
        *pair(9).verification_key.as_ref()
    );
    check_governance_lineage(&state, &state.canonical_component_bytes().unwrap()).unwrap();
}
struct NoRead;
impl Source for NoRead {
    fn receipt(&mut self, _: u64, _: usize) -> Result<Vec<u8>, String> {
        panic!("rejected preflight read receipt source")
    }
    fn body(&mut self, _: u64, _: usize) -> Result<Vec<u8>, String> {
        panic!("rejected preflight read body source")
    }
}

#[test]
fn checkpoint_reanchoring_preserves_work_and_requires_confirmed_available_tail() {
    let genesis = genesis();
    let (plan, _) = selected(&genesis, 96);
    let anchored = plan.at_checkpoint(72, 73, 96).unwrap();
    assert_eq!(anchored.pin().anchor_height, 72);
    assert_eq!(anchored.pin().tip_id, plan.pin().tip_id);
    assert_eq!(anchored.pin().cumulative_work, plan.pin().cumulative_work);
    assert_eq!(anchored.pin().local_work_floor, plan.pin().local_work_floor);
    for checkpoint in [1, 11, 13, 71] {
        let arbitrary = plan.at_checkpoint(checkpoint, checkpoint + 1, 96).unwrap();
        assert_eq!(arbitrary.pin().anchor_height, checkpoint);
        assert_eq!(arbitrary.pin().cumulative_work, plan.pin().cumulative_work);
    }
    for (checkpoint, first, last) in [(0, 1, 96), (73, 74, 96), (72, 74, 96), (72, 73, 95)] {
        assert!(plan.at_checkpoint(checkpoint, first, last).is_err());
    }
    let (short, _) = selected(&genesis, 95);
    assert!(short.at_checkpoint(72, 73, 95).is_err());
    let (long, _) = selected(&genesis, 385);
    assert!(long.at_checkpoint(72, 73, 385).is_err());
    let stronger = AdmissionPlan::select_signed(&[plan.headers()], Work::from(25)).unwrap();
    assert!(stronger.at_checkpoint(72, 73, 96).is_err());
}

#[test]
fn signed_selection_keeps_automatic_source_rule_and_rejects_equal_work_forks() {
    let genesis = genesis();
    let (long, _) = selected(&genesis, 96);
    let (short, _) = selected(&genesis, 95);
    let selected =
        AdmissionPlan::select_signed(&[short.headers(), long.headers()], Work::one()).unwrap();
    assert_eq!(selected.pin().tip_id, long.pin().tip_id);
    let one_source = [SourceObservation {
        authenticated_identity: [1; 32],
        transport_address: IpAddr::from([10, 1, 0, 1]),
        chain: long.headers(),
    }];
    assert!(AdmissionPlan::select(&one_source, Work::one()).is_err());
    assert!(AdmissionPlan::select_signed(&[], Work::one()).is_err());
    assert!(AdmissionPlan::select_signed(&[long.headers()], Work::zero()).is_err());
    let mut fork = (1..=96)
        .map(|h| long.headers().header(h).unwrap().clone())
        .collect::<Vec<_>>();
    fork.last_mut().unwrap().nonce = 1;
    let fork = VerifiedHeaders::verify(long.headers().rules().clone(), fork).unwrap();
    assert!(AdmissionPlan::select_signed(&[long.headers(), &fork], Work::one()).is_err());
}

#[test]
fn unpinned_context_bad_witness_and_non_signatures_never_read_sources() {
    let genesis = genesis();
    let encoded = genesis.encode().unwrap();
    let (plan, witness) = selected(&genesis, 96);
    let plan = plan.at_checkpoint(72, 73, 96).unwrap();
    let certificate = certificate(&plan, &genesis).encode().unwrap();
    let witness_bytes = witness
        .encode(policy().state.chain.max_component_bytes)
        .unwrap();
    let mut cases = vec![(
        encoded.clone(),
        genesis.id(),
        certificate.to_vec(),
        witness_bytes.clone(),
    )];
    cases.push((
        encoded.clone(),
        [99; 32],
        certificate.to_vec(),
        witness_bytes.clone(),
    ));
    cases.push((
        encoded.clone(),
        genesis.id(),
        certificate[..STATEMENT_BYTES + 1 + SIGNATURE_BYTES].to_vec(),
        witness_bytes.clone(),
    ));
    for slots in [[0, 3], [1, 1], [2, 0]] {
        let mut bad = certificate.to_vec();
        bad[STATEMENT_BYTES] = slots[0];
        bad[STATEMENT_BYTES + 1 + SIGNATURE_BYTES] = slots[1];
        cases.push((encoded.clone(), genesis.id(), bad, witness_bytes.clone()));
    }
    for offset in [8, 9] {
        let mut bytes = encoded.clone();
        bytes[offset] ^= 1;
        cases.push((
            bytes,
            genesis.id(),
            certificate.to_vec(),
            witness_bytes.clone(),
        ));
    }
    cases.push((
        encoded.clone(),
        genesis.id(),
        certificate[..certificate.len() - 1].to_vec(),
        witness_bytes.clone(),
    ));
    let mut bad = witness_bytes.clone();
    *bad.last_mut().unwrap() ^= 1;
    cases.push((encoded.clone(), genesis.id(), certificate.to_vec(), bad));
    for (bytes, pin, certificate, witness) in cases {
        let result = verify(
            Input {
                genesis: &bytes,
                pinned_genesis: pin,
                plan: &plan,
                certificate: &certificate,
                witness: &witness,
                snapshot: b"untrusted snapshot",
            },
            &mut NoRead,
            policy(),
            || false,
        );
        assert!(result.is_err());
    }
    assert!(
        verify(
            Input {
                genesis: &encoded,
                pinned_genesis: genesis.id(),
                plan: &plan,
                certificate: &certificate,
                witness: &witness_bytes,
                snapshot: &[]
            },
            &mut NoRead,
            policy(),
            || true
        )
        .is_err()
    );
}

fn unverified_test_capability() -> VerifiedImport {
    VerifiedImport {
        engine: Engine::new(genesis(), policy().state.chain).unwrap(),
        headers: vec![],
        anchor: 0,
        receipts: vec![],
        bodies: vec![],
        certificate: vec![],
        witness: vec![],
        snapshot: vec![],
        verification_bytes: 0,
    }
}

#[cfg(any(unix, windows))]
#[test]
fn canceled_install_and_existing_database_are_non_destructive_without_keys() {
    #[cfg(unix)]
    use std::os::unix::fs::DirBuilderExt;
    let path: PathBuf = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("eng2-import-reject-{}", std::process::id()));
    assert!(!path.exists());
    assert!(
        unverified_test_capability()
            .install(&path, &mut NoRead, || true)
            .is_err()
    );
    assert!(!path.exists());
    #[cfg(unix)]
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .unwrap();
    #[cfg(windows)]
    drop(siworld_miner_platform::Directory::create(&path).unwrap());
    std::fs::write(path.join("chain.redb"), b"existing public fixture").unwrap();
    assert!(
        unverified_test_capability()
            .install(&path, &mut NoRead, || false)
            .is_err()
    );
    assert_eq!(
        std::fs::read(path.join("chain.redb")).unwrap(),
        b"existing public fixture"
    );
    assert!(!path.join("checkpoint-import.redb").exists());
    assert!(!path.join("native-peer-identity.secret").exists());
    // Remove only this invocation's synthetic rejection-test files.
    std::fs::remove_file(path.join("chain.redb")).unwrap();
    std::fs::remove_dir(path).unwrap();
}
