use super::super::snapshot::tests::{binding, bootstrap};
use super::*;
use crate::fixtures::candidate;
use native::{codec::encode_digest, multi_asset::F};
use p3_field::PrimeCharacteristicRing;

fn fixture(parent: &SnapshotState) -> (Header, body::Body) {
    let old = candidate(&parent.chain, 1_500_000);
    let body = body::Body {
        network: old.network,
        height: old.height,
        profile: body::tests::policy().profile,
        transactions: old.transactions,
        reward_mode: old.reward_mode,
        rewards: old.rewards,
        fee_output: crate::wire::RewardRecord {
            commitment: encode_digest(&[F::from_u32(1_700_000); 12]),
            ciphertext: [91; 1313],
        },
        fund_claims: Vec::new(),
        governance: Vec::new(),
        issuances: old.issuances,
        settlement_proof: vec![1],
    };
    let header = Header {
        network: body.network,
        height: body.height,
        parent: old.parent,
        timestamp: old.timestamp,
        target: old.target,
        execution_commitment: [41; 32],
        body_commitment: body.commitment(body::tests::policy()).unwrap(),
        nonce: 0,
    };
    (header, body)
}

#[test]
fn preflight_borrows_actual_parent_and_rejects_substituted_header_or_body() {
    let parent = bootstrap();
    let before = parent.chain.fingerprint();
    let (header, body) = fixture(&parent);
    let context = binding(&parent, parent.tip());
    let prepared =
        PreparedBlock::prepare(&parent, &header, &body, context, body::tests::policy()).unwrap();
    assert!(std::ptr::eq(prepared.parent(), &parent));
    let staged = prepared.ledgers();
    assert_eq!(staged.economics.height(), 1);
    assert_eq!(staged.fund.height(), 1);
    assert_eq!(staged.governance.height(), 1);
    assert_eq!(
        staged.economics.fund_credited(),
        staged.fund.total_entitlement()
    );
    assert_eq!(parent.economics.height(), 0);
    assert_eq!(parent.fund.height(), 0);
    assert_eq!(parent.governance.height(), 0);
    drop(prepared);
    let mut changed = header.clone();
    changed.body_commitment[0] ^= 1;
    assert!(
        PreparedBlock::prepare(&parent, &changed, &body, context, body::tests::policy()).is_err()
    );
    changed = header.clone();
    changed.parent[0] ^= 1;
    assert!(
        PreparedBlock::prepare(&parent, &changed, &body, context, body::tests::policy()).is_err()
    );
    let mut changed = body.clone();
    changed.fee_output.ciphertext[0] ^= 1;
    assert!(
        PreparedBlock::prepare(&parent, &header, &changed, context, body::tests::policy()).is_err()
    );
    let bad_context = Binding {
        parent: [77; 32],
        ..context
    };
    assert!(
        PreparedBlock::prepare(&parent, &header, &body, bad_context, body::tests::policy())
            .is_err()
    );
    assert_eq!(parent.chain.fingerprint(), before);
}

#[test]
fn actual_native_transaction_verifier_rejects_synthetic_proofs_without_mutating_state() {
    let parent = bootstrap();
    let (header, body) = fixture(&parent);
    let context = binding(&parent, parent.tip());
    let before = parent.chain.fingerprint();
    let economics = parent.economics.clone();
    let fund = parent.fund.clone();
    let governance = parent.governance.clone();
    let prepared =
        PreparedBlock::prepare(&parent, &header, &body, context, body::tests::policy()).unwrap();
    assert!(
        prepared
            .verify_transactions(&NativeVerifier::new().unwrap())
            .is_err()
    );
    assert_eq!(parent.chain.fingerprint(), before);
    assert_eq!(parent.economics, economics);
    assert_eq!(parent.fund, fund);
    assert_eq!(parent.governance, governance);
    assert_eq!(parent.nullifiers.len(), 0);
}

#[test]
fn preflight_rejects_actual_ledger_height_mismatch_without_changing_parent() {
    let mut parent = bootstrap();
    let (header, body) = fixture(&parent);
    let context = binding(&parent, parent.tip());
    parent
        .fund
        .advance(1, siworld_core::v1_economics::subsidy(1).unwrap())
        .unwrap();
    let before = parent.chain.fingerprint();
    assert!(
        PreparedBlock::prepare(&parent, &header, &body, context, body::tests::policy()).is_err()
    );
    assert_eq!(parent.chain.fingerprint(), before);
    assert_eq!(parent.fund.height(), 1);
    assert_eq!(parent.height(), 0);
}

#[test]
fn new_governance_action_is_authenticated_and_keeps_its_inclusion_destination_frozen() {
    use crate::eng2_governance::{
        self, Action, ActionKind, Authorization, DestinationTarget, SignedAction, SignerRole,
    };
    use libcrux_ml_dsa::ml_dsa_65;
    let parent = bootstrap();
    let (mut header, mut body) = fixture(&parent);
    let context = binding(&parent, parent.tip());
    let replacement = crate::wallet::WalletKeys::from_seed(
        parent.network(),
        zeroize::Zeroizing::new([62; 32]),
        0,
    )
    .unwrap()
    .address();
    let mut address = [0u8; eng2_governance::ADDRESS_BYTES];
    address[..48].copy_from_slice(&encode_digest(&replacement.owner()));
    address[48..].copy_from_slice(replacement.encapsulation_key());
    let action = Action {
        network: parent.network(),
        sequence: 1,
        kind: ActionKind::ProposeDestination {
            target: DestinationTarget::Fees,
            address: Box::new(address),
        },
    };
    let role = SignerRole::Founder;
    let signature = *ml_dsa_65::sign(
        &ml_dsa_65::generate_key_pair([1; 32]).signing_key,
        &action.signing_bytes(role).unwrap(),
        eng2_governance::SIGNATURE_CONTEXT,
        [12; 32],
    )
    .unwrap()
    .as_ref();
    body.governance.push(SignedAction {
        action,
        signatures: vec![Authorization { role, signature }],
    });
    header.body_commitment = body.commitment(body::tests::policy()).unwrap();
    let before = parent.governance.clone();
    let prepared =
        PreparedBlock::prepare(&parent, &header, &body, context, body::tests::policy()).unwrap();
    assert_eq!(prepared.ledgers.frozen.sequence(), 0);
    assert_eq!(prepared.ledgers.governance.sequence(), 1);
    assert_eq!(prepared.ledgers.inclusions.len(), 1);
    assert_eq!(prepared.ledgers.inclusions[0].effective_height, 4033);
    assert_eq!(
        prepared.ledgers.settlement.fee_owner,
        before.active_fee_destination().owner()
    );
    assert_eq!(
        prepared
            .ledgers
            .frozen
            .canonical_fee_destination_bytes()
            .unwrap(),
        before.canonical_fee_destination_bytes().unwrap()
    );
    drop(prepared);
    body.governance[0].signatures[0].signature[0] ^= 1;
    header.body_commitment = body.commitment(body::tests::policy()).unwrap();
    assert!(
        PreparedBlock::prepare(&parent, &header, &body, context, body::tests::policy()).is_err()
    );
    assert_eq!(parent.governance, before);
}

#[test]
fn legacy_engine_rejects_profile_fee_output_and_native_proof_substitution_atomically() {
    let initial = bootstrap();
    let genesis = super::super::genesis::Genesis::seal(
        initial.chain.config.clone(),
        initial.governance.clone(),
        super::super::genesis::FeeMode::LegacyMiner,
    )
    .unwrap();
    let limits = super::super::state_components::Limits {
        max_leaves: 10_000,
        max_nullifiers: 10_000,
        max_component_bytes: 16 * 1024 * 1024,
    };
    let mut engine = Engine::new(genesis, limits).unwrap();
    let before = engine.state().chain.fingerprint();
    let (mut header, mut body) = fixture(engine.state());
    body.profile = crate::proofs::protocol_profile_fingerprint();
    let policy = engine.body_policy();
    header.body_commitment = body.commitment(policy).unwrap();
    let verifier = NativeVerifier::new().unwrap();
    assert!(engine.apply(&header, &body, &verifier).is_err());
    body.fee_output = legacy_fee_output();
    header.body_commitment = body.commitment(policy).unwrap();
    assert!(engine.apply(&header, &body, &verifier).is_err());
    // Preparing a work template still requires the exact actual native proofs;
    // skipping final PoW cannot become a proof or execution-root bypass.
    assert!(
        engine
            .prepare_header(&body, header.timestamp, &verifier)
            .is_err()
    );
    body.profile[0] ^= 1;
    assert!(engine.apply(&header, &body, &verifier).is_err());
    assert_eq!(engine.state().height(), 0);
    assert_eq!(engine.state().chain.fingerprint(), before);
    assert_eq!(engine.state().economics, initial.economics);
    assert_eq!(engine.state().fund, initial.fund);
    assert_eq!(engine.state().governance, initial.governance);
}
