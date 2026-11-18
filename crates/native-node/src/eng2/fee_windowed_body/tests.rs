use super::*;
use crate::proof_codec::v2::{Identity, Relation};
use std::io::Cursor;

fn registry(seed: u8) -> CandidateRegistry {
    CandidateRegistry::for_candidate_framing(
        [17; 32],
        [seed; 32],
        [seed + 1; 32],
        Identity {
            relation: Relation::Transaction,
            profile: [seed + 2; 32],
        },
        Identity {
            relation: Relation::Issuance,
            profile: [seed + 3; 32],
        },
        Identity {
            relation: Relation::CompleteFee,
            profile: [seed + 4; 32],
        },
    )
    .unwrap()
}
fn fixture(registry: &CandidateRegistry) -> FeeWindowedBody {
    let mut body = super::super::body::tests::body();
    let claims = std::mem::take(&mut body.fund_claims)
        .into_iter()
        .map(|claim| WindowedFundClaim {
            valid_until: claim.height + 287,
            claim,
        })
        .collect();
    let governance = std::mem::take(&mut body.governance)
        .into_iter()
        .map(|signed| WindowedSignedAction {
            signed,
            valid_from: body.height,
            valid_until: body.height + 287,
        })
        .collect();
    body.profile = registry.suite().id();
    for tx in &mut body.transactions {
        tx.proof = v2::encode(registry.transaction(), &[1], MAX_TRANSACTION_PROOF_BYTES).unwrap();
    }
    for issuance in &mut body.issuances {
        issuance.proof = v2::encode(registry.issuance(), &[2], MAX_ISSUANCE_PROOF_BYTES).unwrap();
    }
    body.settlement_proof = v2::encode(registry.fee(), &[3], MAX_FEE_PROOF_BYTES).unwrap();
    let authorizations = WindowedAuthorizationBody {
        network: body.network,
        genesis: registry.genesis(),
        rules_commitment: registry.rules(),
        height: body.height,
        fund_claims: claims,
        governance,
    };
    FeeWindowedBody {
        body,
        authorizations,
    }
}
#[test]
fn one_streaming_body_roundtrips_and_has_one_prepared_commitment() {
    let registry = registry(2);
    let body = fixture(&registry);
    let encoded = body.encode(&registry).unwrap();
    assert_eq!(body.encoded_len(&registry).unwrap(), encoded.len());
    let decoded = FeeWindowedBody::read_from(
        &mut Cursor::new(&encoded),
        encoded.len() as u64,
        &registry,
        body.body.height,
    )
    .unwrap();
    assert_eq!(decoded, body);
    let mut emitted = Vec::new();
    body.write_to(&mut emitted, &registry).unwrap();
    assert_eq!(emitted, encoded);
    let prepared = PreparedCandidateBody::prepare(&body, &registry).unwrap();
    assert_eq!(prepared.commitment(), body.commitment(&registry).unwrap());
    assert_eq!(prepared.body(), &body);
    assert!(!prepared.registry().suite().activation_supported());
    let mut changed = body.clone();
    changed.body.fee_output.ciphertext[0] ^= 1;
    assert_ne!(
        changed.commitment(&registry).unwrap(),
        prepared.commitment()
    );
    let mut changed = body.clone();
    changed.authorizations.governance[0].valid_until += 1;
    assert_ne!(
        changed.commitment(&registry).unwrap(),
        prepared.commitment()
    );
}
#[test]
fn versions_are_mutually_rejected_and_legacy_operations_cannot_mix() {
    let registry = registry(2);
    let body = fixture(&registry);
    let encoded = body.encode(&registry).unwrap();
    assert!(
        Body::decode(
            &encoded,
            body.body.network,
            body.body.height,
            policy(&registry).unwrap()
        )
        .is_err()
    );
    let legacy = body.body.encode(policy(&registry).unwrap()).unwrap();
    assert!(
        FeeWindowedBody::read_from(
            &mut Cursor::new(&legacy),
            legacy.len() as u64,
            &registry,
            body.body.height
        )
        .is_err()
    );
    let mut mixed = body.clone();
    mixed
        .body
        .fund_claims
        .push(body.authorizations.fund_claims[0].claim.clone());
    assert!(mixed.encode(&registry).is_err());
    let mut mixed = body.clone();
    mixed.body.transactions[0].proof = vec![1];
    assert!(mixed.encode(&registry).is_err());
    let mut wrong_relation = body;
    wrong_relation.body.settlement_proof = v2::encode(
        Identity {
            relation: Relation::Settlement,
            ..registry.fee()
        },
        &[1],
        MAX_FEE_PROOF_BYTES,
    )
    .unwrap();
    assert!(wrong_relation.encode(&registry).is_err());
}
#[test]
fn context_and_length_rejections_stop_before_fee_allocation() {
    let registry = registry(2);
    let body = fixture(&registry);
    let encoded = body.encode(&registry).unwrap();
    for offset in [0, 8, 40, 72, 104, 136, 144, 152, 156] {
        let mut changed = encoded.clone();
        changed[offset] ^= 0x80;
        let mut input = Cursor::new(changed);
        assert!(
            FeeWindowedBody::read_from(
                &mut input,
                encoded.len() as u64,
                &registry,
                body.body.height
            )
            .is_err()
        );
        assert_eq!(input.position(), PREFIX_BYTES as u64);
    }
    let mut changed = encoded.clone();
    changed[PREFIX_BYTES + 12] ^= 1;
    let mut input = Cursor::new(changed);
    assert!(
        FeeWindowedBody::read_from(
            &mut input,
            encoded.len() as u64,
            &registry,
            body.body.height
        )
        .is_err()
    );
    assert_eq!(input.position(), (PREFIX_BYTES + v2::FRAME_BYTES) as u64);
}
#[test]
fn payload_counts_truncation_and_trailing_data_are_rejected() {
    let registry = registry(2);
    let body = fixture(&registry);
    let encoded = body.encode(&registry).unwrap();
    let mut changed = encoded.clone();
    let start = PREFIX_BYTES + body.body.settlement_proof.len();
    changed[start..start + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(
        FeeWindowedBody::read_from(
            &mut Cursor::new(changed),
            encoded.len() as u64,
            &registry,
            body.body.height
        )
        .is_err()
    );
    assert!(
        FeeWindowedBody::read_from(
            &mut Cursor::new(&encoded[..encoded.len() - 1]),
            encoded.len() as u64,
            &registry,
            body.body.height
        )
        .is_err()
    );
    let mut changed = encoded.clone();
    changed.push(0);
    let new_length = changed.len() as u64;
    changed[144..152].copy_from_slice(&new_length.to_le_bytes());
    let old_payload = u64::from_le_bytes(changed[156..164].try_into().unwrap());
    changed[156..164].copy_from_slice(&(old_payload + 1).to_le_bytes());
    assert!(
        FeeWindowedBody::read_from(
            &mut Cursor::new(changed),
            new_length,
            &registry,
            body.body.height
        )
        .is_err()
    );
}
#[test]
fn semantic_suite_excludes_genesis_rules_and_derived_frame_profiles() {
    let first = registry(2);
    let second = registry(20);
    assert_eq!(first.suite(), second.suite());
    assert_eq!(first.suite().id(), second.suite().id());
    assert_ne!(first.fee(), second.fee());
    assert_ne!(first.fee_binding(), second.fee_binding());
    assert!(!first.suite().activation_supported());
    let bytes = first.suite().encode();
    assert_eq!(&bytes[bytes.len() - 2..], &[0, 0]);
    assert!(
        CandidateRegistry::for_candidate_framing(
            [17; 32],
            [2; 32],
            [3; 32],
            first.fee(),
            first.issuance(),
            first.fee()
        )
        .is_err()
    );
}
