use super::super::snapshot::tests::{binding, bootstrap};
use super::*;
use crate::fixtures::candidate;
use native::{codec::encode_digest, multi_asset::F};
use p3_field::PrimeCharacteristicRing;

fn candidate_engine() -> Engine {
    let parent = bootstrap();
    let genesis = Genesis::seal(
        parent.chain.config.clone(),
        parent.governance.clone(),
        FeeMode::LegacyMiner,
    )
    .unwrap();
    Engine::new(genesis, super::super::snapshot::tests::limits().chain).unwrap()
}

fn fee_candidate(
    engine: &Engine,
) -> (
    Header,
    super::super::candidate_registry::CandidateRegistry,
    super::super::fee_windowed_body::FeeWindowedBody,
) {
    use crate::proof_codec::v2::{self, Identity, Relation};
    let identity = |relation, seed| Identity {
        relation,
        profile: [seed; 32],
    };
    let registry = super::super::candidate_registry::CandidateRegistry::for_candidate_framing(
        engine.state().network(),
        engine.genesis().id(),
        engine.genesis().rules_commitment(),
        identity(Relation::Transaction, 31),
        identity(Relation::Issuance, 37),
        identity(Relation::CompleteFee, 41),
    )
    .unwrap();
    // Synthetic records select the current parent snapshot. Their short proof
    // frames are structural inputs without cryptographic proof validity.
    let mut body = body::tests::body();
    body.network = engine.state().network();
    body.height = engine.state().height() + 1;
    body.profile = registry.suite().id();
    body.fund_claims.clear();
    body.governance.clear();
    let snapshot = engine.state().chain().tip_snapshot().selector;
    for tx in &mut body.transactions {
        tx.record.snapshot = snapshot;
        tx.proof = v2::encode(
            registry.transaction(),
            &[1],
            v2::MAX_TRANSACTION_PROOF_BYTES,
        )
        .unwrap();
    }
    let network = body.network;
    body.transactions
        .sort_by_key(|tx| tx.record.statement_id(&network));
    body.settlement_proof = v2::encode(registry.fee(), &[2], v2::MAX_FEE_PROOF_BYTES).unwrap();
    let authorizations = super::super::windowed_authorization::WindowedAuthorizationBody {
        network: body.network,
        genesis: registry.genesis(),
        rules_commitment: registry.rules(),
        height: body.height,
        fund_claims: Vec::new(),
        governance: Vec::new(),
    };
    let candidate = super::super::fee_windowed_body::FeeWindowedBody {
        body,
        authorizations,
    };
    let header = Header {
        network,
        height: candidate.body.height,
        parent: engine.state().tip(),
        timestamp: engine.state().chain().timestamp()
            + engine.state().chain().config.target_interval,
        target: engine.state().chain().next_target(),
        execution_commitment: [41; 32],
        body_commitment: candidate.commitment(&registry).unwrap(),
        nonce: 0,
    };
    (header, registry, candidate)
}

#[test]
fn fee_first_preparation_uses_one_transition_without_reinterpreting_legacy_fees() {
    use super::super::fee_windowed_body::PreparedCandidateBody;
    let engine = candidate_engine();
    let (header, registry, candidate) = fee_candidate(&engine);
    let body = PreparedCandidateBody::prepare(&candidate, &registry).unwrap();
    let before = engine.state().chain().fingerprint();
    let prepared = engine.prepare_fee_candidate(7, &header, &body).unwrap();
    assert!(std::ptr::eq(prepared.parent(), engine.state()));
    assert_eq!(prepared.header(), &header);
    assert_eq!(prepared.ledgers().economics.height(), 1);
    assert_eq!(prepared.ledgers().fund.height(), 1);
    assert_eq!(prepared.ledgers().governance.height(), 1);
    assert!(prepared.settlement_policy().is_err());
    assert_eq!(prepared.parent().fee_mode(), FeeMode::LegacyMiner);
    assert_eq!(engine.state().height(), 0);
    assert_eq!(engine.state().chain().fingerprint(), before);
    assert!(!registry.suite().activation_supported());

    let mut legacy = candidate.body.clone();
    legacy.profile = body::tests::policy().profile;
    legacy.fee_output = legacy_fee_output();
    let mut legacy_header = header.clone();
    legacy_header.body_commitment = legacy.commitment(body::tests::policy()).unwrap();
    let reference = PreparedBlock::prepare_inner(
        engine.state(),
        &legacy_header,
        &legacy,
        engine.binding(engine.state().tip()),
        body::tests::policy(),
        HeaderUse::Template,
    )
    .unwrap();
    assert_eq!(
        prepared.ledgers().economics.component_bytes().unwrap(),
        reference.ledgers().economics.component_bytes().unwrap()
    );
    assert_eq!(prepared.ledgers().fund, reference.ledgers().fund);
    assert_eq!(
        prepared.ledgers().governance,
        reference.ledgers().governance
    );
    assert!(
        engine
            .prepare_fee_candidate(7, &legacy_header, &body)
            .is_err()
    );
    assert!(
        PreparedBlock::prepare(
            engine.state(),
            &header,
            &candidate.body,
            engine.binding(engine.state().tip()),
            body::tests::policy(),
        )
        .is_err()
    );
}

#[test]
fn fee_candidate_preparation_rejects_unknown_parent_snapshot_without_mutation() {
    use super::super::fee_windowed_body::PreparedCandidateBody;
    let engine = candidate_engine();
    let (mut header, registry, mut candidate) = fee_candidate(&engine);
    candidate.body.transactions[0].record.snapshot.block_id[0] ^= 1;
    let network = candidate.body.network;
    candidate
        .body
        .transactions
        .sort_by_key(|tx| tx.record.statement_id(&network));
    let body = PreparedCandidateBody::prepare(&candidate, &registry).unwrap();
    header.body_commitment = body.commitment();
    let before = engine.state().chain().fingerprint();
    assert!(matches!(
        engine.prepare_fee_candidate(7, &header, &body),
        Err(reason) if reason == "unknown or removed canonical snapshot"
    ));
    assert_eq!(engine.state().chain().fingerprint(), before);
    assert_eq!(engine.state().height(), 0);
}

#[test]
fn fee_candidate_preparation_authenticates_windowed_governance_once() {
    use super::super::fee_windowed_body::PreparedCandidateBody;
    use crate::eng2_governance::{
        Action, ActionKind, Authorization, SignedAction, SignerRole, WindowedSignedAction,
    };
    use libcrux_ml_dsa::ml_dsa_65;
    let engine = candidate_engine();
    let (mut header, registry, mut candidate) = fee_candidate(&engine);
    let mut action = WindowedSignedAction {
        signed: SignedAction {
            action: Action {
                network: engine.state().network(),
                sequence: 1,
                kind: ActionKind::ProposeIssuanceFee {
                    amount_atoms: 100_000_000,
                },
            },
            signatures: vec![Authorization {
                role: SignerRole::Founder,
                signature: [0; 3309],
            }],
        },
        valid_from: 1,
        valid_until: 288,
    };
    action.signed.signatures[0].signature = *ml_dsa_65::sign(
        &ml_dsa_65::generate_key_pair([1; 32]).signing_key,
        &action.signing_bytes(SignerRole::Founder).unwrap(),
        WindowedSignedAction::signature_context(),
        [41; 32],
    )
    .unwrap()
    .as_ref();
    candidate.authorizations.governance.push(action);
    let body = PreparedCandidateBody::prepare(&candidate, &registry).unwrap();
    header.body_commitment = body.commitment();
    let prepared = engine.prepare_fee_candidate(7, &header, &body).unwrap();
    assert_eq!(prepared.prepared.ledgers.frozen.sequence(), 0);
    assert_eq!(prepared.prepared.ledgers.governance.sequence(), 1);
    assert_eq!(prepared.prepared.ledgers.inclusions.len(), 1);
    assert_eq!(
        prepared.prepared.ledgers.inclusions[0].effective_height,
        4033
    );
    assert_eq!(prepared.ledgers().fund.height(), 1);
    assert_eq!(prepared.ledgers().economics.height(), 1);
    assert_eq!(engine.state().governance().sequence(), 0);
    drop(prepared);
    candidate.authorizations.governance[0].signed.signatures[0].signature[0] ^= 1;
    let body = PreparedCandidateBody::prepare(&candidate, &registry).unwrap();
    header.body_commitment = body.commitment();
    assert!(matches!(
        engine.prepare_fee_candidate(7, &header, &body),
        Err(reason) if reason == "governance ML-DSA-65 signature invalid"
    ));
    assert_eq!(engine.state().governance().sequence(), 0);
    assert_eq!(engine.state().height(), 0);
}

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
