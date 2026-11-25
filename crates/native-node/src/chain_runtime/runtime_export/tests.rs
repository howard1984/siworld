use super::*;
use crate::eng2::{
    genesis::{FeeMode, Genesis},
    snapshot::tests::{bootstrap, limits},
};
use std::path::PathBuf;

pub(super) struct Directory(pub(super) PathBuf);
impl Directory {
    pub(super) fn new() -> Self {
        let mut id = [0; 16];
        getrandom::fill(&mut id).unwrap();
        let path =
            std::env::temp_dir().join(format!("eng2-runtime-export-{}", crate::local::hex(&id)));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub(super) fn store(&self) -> Store {
        let state = bootstrap();
        let genesis = Genesis::seal(
            state.chain.config.clone(),
            state.governance().clone(),
            FeeMode::LegacyMiner,
        )
        .unwrap();
        Store::create(&self.0.join("chain.redb"), genesis, limits().chain).unwrap()
    }
    #[cfg(unix)]
    pub(super) fn private(&self, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = self.0.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
pub(super) fn keys(value: &Value) -> Vec<String> {
    let mut keys = value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    keys
}
#[test]
fn cadence_requires_a_positive_12_multiple_and_24_confirmations() {
    for head in 0..600 {
        let expected = if head < 36 {
            None
        } else {
            Some((head - 24) / 12 * 12)
        };
        assert_eq!(eligible_checkpoint(head), expected);
        if let Some(height) = expected {
            assert!((24..36).contains(&(head - height)));
        }
    }
    assert_eq!(
        eligible_checkpoint(u64::MAX),
        Some((u64::MAX - 24) / 12 * 12)
    );
}
#[test]
fn checkpoint_upgrade_keeps_old_certificates_and_retires_published_candidates() {
    assert!(confirmed_checkpoint(72, 96));
    assert!(confirmed_checkpoint(72, 167));
    assert!(confirmed_checkpoint(432, 472));
    assert!(confirmed_checkpoint(444, 472));
    assert!(!confirmed_checkpoint(456, 472));
    for height in [1, 11, 13, 71, 73, 431, 445, u64::MAX - 24] {
        assert!(confirmed_checkpoint(height, height + 24));
        assert!(!confirmed_checkpoint(height, height + 23));
    }
    assert!(!confirmed_checkpoint(u64::MAX, 0));
    assert!(!confirmed_checkpoint(444, 467));
    assert!(!confirmed_checkpoint(0, 24));
    assert!(pending_obsolete(72, Some(72), 96));
    assert!(pending_obsolete(72, None, 472));
    assert!(!pending_obsolete(444, Some(432), 472));
}

#[test]
fn real_durable_genesis_exports_exact_current_ledgers_and_no_claimed_checkpoint() {
    let dir = Directory::new();
    let store = dir.store();
    let value = public_projection(&store, 123, None).unwrap();
    assert_eq!(
        keys(&value),
        [
            "blocks",
            "checkpoint",
            "economics",
            "genesis",
            "governance",
            "height",
            "network",
            "published_unix_seconds",
            "tip",
            "version"
        ]
    );
    assert_eq!(value["version"], 2);
    assert_eq!(value["height"], 0);
    assert_eq!(
        value["network"],
        crate::local::hex(&store.engine().state().network())
    );
    assert_eq!(
        value["genesis"],
        crate::local::hex(&store.engine().genesis().id())
    );
    assert_eq!(value["tip"], value["genesis"]);
    assert_eq!(value["blocks"], json!([]));
    assert!(value["checkpoint"].is_null());
    let governance = &value["governance"];
    assert_eq!(
        keys(governance),
        [
            "changes",
            "current_signers",
            "fee_address",
            "fund_addresses",
            "issuance_fee"
        ]
    );
    assert_eq!(
        governance["issuance_fee"]["current_atoms"],
        store
            .engine()
            .state()
            .governance()
            .issuance_fee_atoms()
            .to_string()
    );
    assert_eq!(governance["issuance_fee"]["current_atoms"], "5000000000");
    for field in [
        "changes",
        "current_signers",
        "fee_address",
        "fund_addresses",
    ] {
        assert!(governance[field].is_null());
    }
    let economics = &value["economics"];
    assert_eq!(
        keys(economics),
        [
            "burned_atoms",
            "circulating_estimate_atoms",
            "funds",
            "holder_pool_atoms",
            "issued_atoms",
            "locked_reward_atoms",
            "unlock_schedule",
            "unlock_schedule_complete"
        ]
    );
    for key in [
        "issued_atoms",
        "burned_atoms",
        "holder_pool_atoms",
        "locked_reward_atoms",
    ] {
        assert_eq!(economics[key], "0");
    }
    assert_eq!(economics["unlock_schedule_complete"], true);
    assert_eq!(
        economics["funds"].as_array().unwrap().len(),
        store
            .engine()
            .genesis()
            .config()
            .fund_allocation
            .as_ref()
            .unwrap()
            .basis_points()
            .len()
    );
    assert!(
        PreparedCheckpoint::prepare_from_archive(&store, limits())
            .unwrap()
            .is_none()
    );
    assert!(public_projection(&store, 1u64 << 53, None).is_err());
}
#[test]
fn exact_execution_witness_uses_compact_tree_and_nullifier_encodings() {
    let state = bootstrap();
    let binding = crate::eng2::snapshot::tests::binding(&state, [0; 32]);
    let raw = state.canonical_components(binding, limits().chain).unwrap();
    let descriptors = execution_descriptors(&state, &raw, limits()).unwrap();
    assert_eq!(
        commitment::aggregate_descriptors(
            state.network(),
            state.height(),
            binding.parent,
            &descriptors
        )
        .unwrap(),
        state.execution_commitment(binding, limits().chain).unwrap()
    );
    let mut wrong = raw.clone();
    wrong[7].push(1);
    let wrong = execution_descriptors(&state, &wrong, limits()).unwrap();
    assert_ne!(
        commitment::aggregate_descriptors(state.network(), state.height(), binding.parent, &wrong)
            .unwrap(),
        state.execution_commitment(binding, limits().chain).unwrap()
    );
    let mut too_small = limits();
    too_small.chain.max_component_bytes = 1;
    assert!(execution_descriptors(&state, &raw, too_small).is_err());
}
// This fixture exercises signature and byte-format guards only. It is never
// appended to Store, and is not evidence of a native checkpoint at height 72.
pub(super) fn synthetic_candidate() -> PreparedCheckpoint {
    let state = bootstrap();
    let binding = crate::eng2::snapshot::tests::binding(&state, [0; 32]);
    let raw = state.canonical_components(binding, limits().chain).unwrap();
    let descriptors = execution_descriptors(&state, &raw, limits()).unwrap();
    let header = Header {
        network: state.network(),
        height: 96,
        parent: [7; 32],
        timestamp: 300,
        target: [0xff; 32],
        execution_commitment: [8; 32],
        body_commitment: [6; 32],
        nonce: 0,
    };
    let roster = state.governance().active_roster().clone();
    let statement = Statement {
        network: state.network(),
        checkpoint_height: 72,
        checkpoint_block: [3; 32],
        authorization_height: 96,
        authorization_block: header.id().unwrap(),
        roster_sequence: roster.epoch_sequence,
        roster_digest: roster.digest(state.network()),
    };
    PreparedCheckpoint {
        network: state.network(),
        genesis: [2; 32],
        rules: [9; 32],
        anchor: header.clone(),
        authorization: header,
        roster,
        statement,
        witness: AuthorizationWitness {
            descriptors,
            governance: raw[7].clone(),
        },
        snapshot: super::super::snapshot::encode_components(&raw, limits()).unwrap(),
    }
}
#[test]
fn synthetic_vote_authenticates_exact_candidate_and_cannot_certify_actual_genesis() {
    let candidate = synthetic_candidate();
    let message = candidate.statement.encode().unwrap();
    let vote = |slot: u8, seed: u8| Vote {
        slot,
        signature: *ml_dsa_65::sign(
            &ml_dsa_65::generate_key_pair([seed; 32]).signing_key,
            &message,
            Statement::signing_context(),
            [42; 32],
        )
        .unwrap()
        .as_ref(),
    };
    let first = vote(0, 3);
    let second = vote(1, 4);
    candidate.verify_vote(&first).unwrap();
    candidate.verify_vote(&second).unwrap();
    assert!(candidate.verify_vote(&vote(0, 4)).is_err());
    assert!(candidate.verify_vote(&vote(3, 3)).is_err());
    let certificate = Certificate {
        statement: candidate.statement.clone(),
        votes: [first.clone(), second.clone()],
    };
    certificate
        .check_signatures(candidate.roster.keys())
        .unwrap();
    let duplicate = Certificate {
        statement: candidate.statement.clone(),
        votes: [first.clone(), first.clone()],
    };
    assert!(duplicate.check_signatures(candidate.roster.keys()).is_err());
    let dir = Directory::new();
    let store = dir.store();
    assert!(candidate.certify(&store, [first, second], 123).is_err());
}
#[test]
fn arbitrary_candidate_cannot_restore_outside_actual_durable_chain() {
    let dir = Directory::new();
    let store = dir.store();
    let candidate = synthetic_candidate();
    assert!(
        PreparedCheckpoint::restore(
            &store,
            candidate.statement,
            candidate.witness,
            candidate.snapshot,
            limits()
        )
        .is_err()
    );
}
