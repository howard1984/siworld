use super::*;
use crate::eng2::snapshot::tests::{bootstrap, limits};
use std::collections::BTreeMap;

// Synthetic header/witness fixtures exercise classification and cryptographic
// binding only. They are not native-executed checkpoint or reorganization data.
fn headers(count: u64, tag: u8) -> Vec<Header> {
    let network = bootstrap().network();
    let mut parent = [9; 32];
    (1..=count)
        .map(|height| {
            let header = Header {
                network,
                height,
                parent,
                timestamp: height * 300,
                target: [255; 32],
                execution_commitment: [tag; 32],
                body_commitment: [5; 32],
                nonce: height,
            };
            parent = header.id().unwrap();
            header
        })
        .collect()
}
fn statement(chain: &[Header], authorization: &Header) -> Statement {
    let roster = bootstrap().governance().active_roster().clone();
    Statement {
        network: authorization.network,
        checkpoint_height: 12,
        checkpoint_block: chain[11].id().unwrap(),
        authorization_height: authorization.height,
        authorization_block: authorization.id().unwrap(),
        roster_sequence: roster.epoch_sequence,
        roster_digest: roster.digest(authorization.network),
    }
}
#[test]
fn retained_authorization_is_bounded_exact_and_distinguishes_a_shorter_prefix() {
    let chain = headers(60, 4);
    let mut old = chain[35].clone();
    old.nonce += 1;
    let saved = statement(&chain, &old);
    for head in [35, 36, 60] {
        let (header, current) = authorization(
            saved.network,
            head,
            &saved,
            |height| Ok(chain[height as usize - 1].clone()),
            &mut |height, id| {
                let value = if height == 36 {
                    old.clone()
                } else {
                    chain[height as usize - 1].clone()
                };
                Ok((value.id().unwrap() == id).then_some(value))
            },
        )
        .unwrap();
        assert_eq!(header, old);
        assert!(!current);
    }
    let current_saved = statement(&chain, &chain[35]);
    assert!(
        authorization(
            saved.network,
            60,
            &current_saved,
            |height| Ok(chain[height as usize - 1].clone()),
            &mut |_, _| panic!("current prefix must not use retained authority")
        )
        .unwrap()
        .1
    );
    assert!(
        authorization(
            saved.network,
            35,
            &saved,
            |height| Ok(chain[height as usize - 1].clone()),
            &mut |_, _| Ok(None)
        )
        .is_err()
    );
    assert!(
        authorization(
            saved.network,
            11,
            &saved,
            |height| Ok(chain[height as usize - 1].clone()),
            &mut |_, _| Ok(Some(old.clone()))
        )
        .is_err()
    );
    assert!(
        authorization(
            saved.network,
            36,
            &saved,
            |height| Ok(chain[height as usize - 1].clone()),
            &mut |_, _| {
                let mut wrong = old.clone();
                wrong.height += 1;
                Ok(Some(wrong))
            }
        )
        .is_err()
    );
}
#[test]
fn retained_ancestry_accepts_24_links_but_rejects_25_and_missing_material() {
    let canonical = headers(70, 4);
    for depth in [24usize, 25] {
        let ancestor = 60 - depth;
        let mut fork = BTreeMap::new();
        let mut parent = canonical[ancestor - 1].id().unwrap();
        for height in ancestor + 1..=60 {
            let mut header = canonical[height - 1].clone();
            header.parent = parent;
            header.nonce += 1;
            parent = header.id().unwrap();
            fork.insert(parent, header);
        }
        let tip = fork.get(&parent).unwrap();
        let saved = statement(&canonical, tip);
        let result = authorization(
            saved.network,
            70,
            &saved,
            |height| Ok(canonical[height as usize - 1].clone()),
            &mut |height, id| {
                Ok(fork.get(&id).cloned().or_else(|| {
                    canonical
                        .get(height as usize - 1)
                        .filter(|header| header.id().unwrap() == id)
                        .cloned()
                }))
            },
        );
        assert_eq!(result.is_ok(), depth == 24);
    }
}
#[test]
fn witness_root_roster_and_signatures_are_checked_before_retirement() {
    let state = bootstrap();
    let binding = crate::eng2::snapshot::tests::binding(&state, [0; 32]);
    let mut raw = state.canonical_components(binding, limits().chain).unwrap();
    let mut governance = state.governance().clone();
    for height in 1..=36 {
        governance.apply_block(height, &[]).unwrap();
    }
    raw[7] = governance.canonical_component_bytes().unwrap();
    let witness = AuthorizationWitness {
        descriptors: execution_descriptors(&state, &raw, limits()).unwrap(),
        governance: raw[7].clone(),
    };
    let chain = headers(36, 4);
    let mut auth = chain[35].clone();
    auth.execution_commitment = commitment::aggregate_descriptors(
        auth.network,
        auth.height,
        auth.parent,
        &witness.descriptors,
    )
    .unwrap();
    let saved = statement(&chain, &auth);
    let roster = saved_roster(&saved, &witness, &auth, limits()).unwrap();
    let bytes = saved.encode().unwrap();
    let vote = |slot: u8, seed: u8| Vote {
        slot,
        signature: *ml_dsa_65::sign(
            &ml_dsa_65::generate_key_pair([seed; 32]).signing_key,
            &bytes,
            Statement::signing_context(),
            [42; 32],
        )
        .unwrap()
        .as_ref(),
    };
    let mut certificate = Certificate {
        statement: saved.clone(),
        votes: [vote(0, 3), vote(1, 4)],
    };
    certificate.check_signatures(roster.keys()).unwrap();
    certificate.votes[0].signature[0] ^= 1;
    assert!(certificate.check_signatures(roster.keys()).is_err());
    let mut wrong = witness.clone();
    wrong.governance.push(0);
    assert!(saved_roster(&saved, &wrong, &auth, limits()).is_err());
    let mut wrong = saved.clone();
    wrong.roster_digest[0] ^= 1;
    assert!(saved_roster(&wrong, &witness, &auth, limits()).is_err());
    let mut wrong = auth;
    wrong.execution_commitment[0] ^= 1;
    assert!(saved_roster(&saved, &witness, &wrong, limits()).is_err());
}
