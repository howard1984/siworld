use super::*;
use crate::eng2_governance::{Action, ActionKind, Authorization, SignerRole};
use native::{codec::encode_digest, multi_asset::F};
use p3_field::PrimeCharacteristicRing;

pub(crate) fn policy() -> Policy {
    Policy {
        profile: [19; 32],
        max_body_bytes: 2 * 1024 * 1024,
        max_settlement_proof_bytes: 4096,
    }
}
fn digest(value: u32) -> DigestBytes {
    encode_digest(&[F::from_u32(value); 12])
}
fn claim(member: u8) -> PublicFundClaim {
    PublicFundClaim {
        network: [17; 32],
        height: 8,
        spend: crate::fund_spend::FundSpend {
            account: member,
            counter: 1,
            amount: 1,
            owner: digest(300),
            rho: digest(301),
            rseed: digest(302),
            commitment: digest(303 + u32::from(member)),
            ciphertext: [4; 1313],
            verifying_key: [5; 1952],
            signature: [6; 3309],
        },
        encapsulation_coins: [7; 32],
    }
}
pub(crate) fn body() -> Body {
    let network = [17; 32];
    let mut transactions = Vec::new();
    for index in 1..=64u32 {
        let mut public = [0; PUBLIC_BYTES];
        for field in 0..5 {
            public[field * 48..(field + 1) * 48].copy_from_slice(&digest(index * 5 + field as u32));
        }
        transactions.push(Transaction {
            record: PublicRecord::new(
                Snapshot {
                    height: 7,
                    block_id: [18; 32],
                },
                public,
                digest(900 + index),
            )
            .unwrap(),
            proof: vec![index as u8; index as usize + 1],
        });
    }
    transactions.sort_by_key(|tx| tx.record.statement_id(&network));
    Body {
        network,
        height: 8,
        profile: policy().profile,
        transactions,
        reward_mode: RewardMode::Voyager,
        rewards: vec![RewardRecord {
            commitment: digest(2001),
            ciphertext: [8; 1313],
        }],
        fee_output: RewardRecord {
            commitment: digest(2002),
            ciphertext: [9; 1313],
        },
        fund_claims: vec![claim(0), claim(1)],
        governance: [10, 11]
            .into_iter()
            .map(|sequence| SignedAction {
                action: Action {
                    network,
                    sequence,
                    kind: ActionKind::CancelDestination {
                        proposal_sequence: sequence - 1,
                    },
                },
                signatures: vec![Authorization {
                    role: SignerRole::Revocation,
                    signature: [10; 3309],
                }],
            })
            .collect(),
        issuances: Vec::new(),
        settlement_proof: vec![11; 2048],
    }
}

fn issuance(sequence: u64) -> IssuanceRecord {
    use native::issuance::{AssetMetadata, IssuanceDeclaration, SignedIssuance};
    use native::multi_asset::AssetId;
    IssuanceRecord {
        signed: SignedIssuance {
            declaration: IssuanceDeclaration {
                network: [17; 32],
                version: 1,
                issuer_key: [1; native::issuance::ISSUER_KEY_BYTES],
                sequence,
                asset_id: AssetId([sequence as u8; 32]),
                public_supply: 100,
                metadata: AssetMetadata {
                    name: "Synthetic asset".into(),
                    decimals: 2,
                },
                issuance_fee_atoms: 1,
                note_commitments: (1..=3).map(|index| [F::from_u32(index); 12]).collect(),
                note_ciphertext_digests: vec![[3; 32]; 3],
            },
            signature: Some([4; native::issuance::ISSUER_SIGNATURE_BYTES]),
        },
        ciphertexts: vec![vec![5; crate::issuance::CIPHERTEXT_BYTES]; 3],
        proof: vec![6; 64],
        fee_commitment: digest(2100),
        fee_rho: digest(2101),
    }
}

#[test]
fn exact_roundtrip_binds_every_public_and_opaque_field_without_authorizing_proofs() {
    let body = body();
    let bytes = body.encode(policy()).unwrap();
    assert_eq!(&bytes[..6], b"SW2B\x01\x00");
    assert_eq!(&bytes[6..38], &body.network);
    assert_eq!(&bytes[38..46], &body.height.to_le_bytes());
    assert_eq!(&bytes[46..78], &body.profile);
    assert_eq!(
        Body::decode(&bytes, body.network, body.height, policy()).unwrap(),
        body
    );
    assert_eq!(
        body.commitment(policy()).unwrap(),
        super::super::header::body_commitment(&bytes, policy().max_body_bytes).unwrap()
    );
    for index in [85, 85 + REWARD_RECORD_BYTES, bytes.len() - 1] {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert_ne!(
            super::super::header::body_commitment(&changed, changed.len()).unwrap(),
            body.commitment(policy()).unwrap()
        );
    }
    // These synthetic signatures and proofs are framing fixtures, deliberately
    // not authorization capabilities or valid native settlement proofs.
    assert_eq!(body.fund_claims[0].spend.signature, [6; 3309]);
}

#[test]
fn ordered_settlement_digest_matches_the_existing_transaction_statement_domain() {
    let original = body();
    let block = Block {
        network: original.network,
        height: original.height,
        parent: [0; 32],
        timestamp: 1,
        target: [255; 32],
        nonce: 0,
        transactions: original.transactions.clone(),
        reward_mode: original.reward_mode,
        rewards: original.rewards.clone(),
        fund_spends: Vec::new(),
        issuances: Vec::new(),
        settlement_proof: Vec::new(),
    };
    assert_eq!(original.list_digest(), block.list_digest());
    let mut changed = original.clone();
    changed.transactions[0].proof[0] ^= 1;
    assert_eq!(original.list_digest(), changed.list_digest());
    changed.transactions[0].record.fee_commit = digest(19_001);
    assert_ne!(original.list_digest(), changed.list_digest());
    changed = original.clone();
    changed.transactions[0].record.snapshot.height -= 1;
    assert_ne!(original.list_digest(), changed.list_digest());
    changed = original.clone();
    changed.transactions.swap(0, 1);
    assert_ne!(original.list_digest(), changed.list_digest());
}

#[test]
fn rejects_noncanonical_context_counts_lengths_and_order() {
    let body = body();
    let bytes = body.encode(policy()).unwrap();
    for index in [0, 4, 6, 38, 46, 78, 80, 81, 82, 83, 84] {
        let mut invalid = bytes.clone();
        invalid[index] = 255;
        assert!(
            Body::decode(&invalid, body.network, body.height, policy()).is_err(),
            "offset {index}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Body::decode(&trailing, body.network, body.height, policy()).is_err());
    for length in [0, 84, 85, 1446, bytes.len() - 1] {
        assert!(Body::decode(&bytes[..length], body.network, body.height, policy()).is_err());
    }
    let mut swapped = body.clone();
    swapped.transactions.swap(0, 1);
    assert!(swapped.encode(policy()).is_err());
    let mut duplicate = body.clone();
    duplicate.transactions[1] = duplicate.transactions[0].clone();
    assert!(duplicate.encode(policy()).is_err());
    let mut claims = body.clone();
    claims.fund_claims.swap(0, 1);
    assert!(claims.encode(policy()).is_err());
    let mut actions = body.clone();
    actions.governance.swap(0, 1);
    assert!(actions.encode(policy()).is_err());
    let mut context = body.clone();
    context.fund_claims[1].height += 1;
    assert!(context.encode(policy()).is_err());
    let mut rewards = body.clone();
    rewards.fee_output = rewards.rewards[0].clone();
    assert!(rewards.encode(policy()).is_err());
}

#[test]
fn bounds_are_local_and_checked_before_copying_opaque_proofs() {
    let body = body();
    let bytes = body.encode(policy()).unwrap();
    for bounded in [
        Policy {
            profile: [0; 32],
            ..policy()
        },
        Policy {
            profile: [20; 32],
            ..policy()
        },
        Policy {
            max_body_bytes: bytes.len() - 1,
            ..policy()
        },
        Policy {
            max_settlement_proof_bytes: body.settlement_proof.len() - 1,
            ..policy()
        },
    ] {
        assert!(body.encode(bounded).is_err());
        assert!(Body::decode(&bytes, body.network, body.height, bounded).is_err());
    }
    let mut empty = body.clone();
    empty.settlement_proof.clear();
    assert!(empty.encode(policy()).is_err());
    let mut huge_claim_length = bytes.clone();
    // Governance is the first variable-sized list after rewards, the mandatory
    // fee output, and fixed-size claims. Reject an asserted allocation length.
    let offset = 85 + 2 * REWARD_RECORD_BYTES + 2 * super::super::fund_claim::ENCODED_BYTES;
    huge_claim_length[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Body::decode(&huge_claim_length, body.network, body.height, policy()).is_err());
}

#[test]
fn holder_mode_issuance_and_stream_writer_use_the_identical_canonical_bytes() {
    let mut body = body();
    body.reward_mode = RewardMode::Holder;
    body.rewards = (0..5)
        .map(|index| RewardRecord {
            commitment: digest(2200 + index),
            ciphertext: [12; 1313],
        })
        .collect();
    body.issuances = vec![issuance(1), issuance(2)];
    body.issuances
        .sort_by_key(|record| record.signed.declaration.binding());
    let bytes = body.encode(policy()).unwrap();
    assert_eq!(body.encoded_len(policy()).unwrap(), bytes.len());
    assert_eq!(
        Body::decode(&bytes, body.network, body.height, policy()).unwrap(),
        body
    );
    let mut streamed = Vec::new();
    body.write_to(&mut streamed, policy()).unwrap();
    assert_eq!(bytes, streamed);
    body.issuances.swap(0, 1);
    assert!(body.encode(policy()).is_err());

    struct Interrupted;
    impl std::io::Write for Interrupted {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    body.issuances.clear();
    assert_eq!(
        body.write_to(&mut Interrupted, policy())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
}
