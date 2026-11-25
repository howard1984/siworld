use super::*;
// Synthetic keys and state fields exercise authentication, never a live roster.
fn fixture() -> (Roster, Certificate) {
    let a = ml_dsa_65::generate_key_pair([17; 32]);
    let b = ml_dsa_65::generate_key_pair([29; 32]);
    let binding = Binding {
        network: [1; 32],
        genesis: [2; 32],
        verifier: [3; 32],
    };
    let roster = Roster::new(
        binding,
        [*a.verification_key.as_ref(), *b.verification_key.as_ref()],
    )
    .unwrap();
    let statement = Statement {
        binding,
        roster: roster.digest(),
        sequence: 1,
        issued_unix_seconds: 21_600,
        height: 72,
        block_id: [4; 32],
        cumulative_work: [5; 64],
        state_fingerprint: [6; 32],
        state_encoding_digest: [7; 32],
        permanent_prefix_digest: [8; 32],
        commitment_root: [9; 48],
        nullifier_digest: [10; 32],
        recent_roots_digest: [11; 32],
        holder_pool: 12,
        development_fund_digest: [13; 32],
        cumulative_issued: 14,
        cumulative_burned: 15,
        locked_rewards: 16,
        locked_schedule_digest: [17; 32],
        asset_registry_digest: [18; 32],
    };
    let votes = [a, b]
        .iter()
        .enumerate()
        .map(|(index, pair)| Vote {
            signer: index as u8,
            signature: *ml_dsa_65::sign(&pair.signing_key, &statement.encode(), CONTEXT, [19; 32])
                .unwrap()
                .as_ref(),
        })
        .collect();
    (roster, Certificate { statement, votes })
}
#[test]
fn two_of_two_certificate_roundtrips_and_requires_exact_content() {
    let (roster, certificate) = fixture();
    let bytes = certificate.encode().unwrap();
    let decoded = Certificate::decode(&bytes).unwrap();
    assert_eq!(decoded.encode().unwrap(), bytes);
    assert!(decoded.authenticate(&roster, None, 21_600).is_ok());
    let mut altered = decoded.clone();
    altered.statement.state_fingerprint[0] ^= 1;
    assert!(altered.authenticate(&roster, None, 21_600).is_err());
    for bytes in [
        &bytes[..bytes.len() - 1],
        &[bytes.as_slice(), &[0]].concat(),
    ] {
        assert!(Certificate::decode(bytes).is_err());
    }
}
#[test]
fn one_signature_unknown_signer_duplicate_and_wrong_network_are_rejected() {
    let (roster, certificate) = fixture();
    let mut bad = certificate.clone();
    bad.votes.pop();
    assert!(bad.authenticate(&roster, None, 21_600).is_err());
    for index in [0, 2, 255] {
        let mut bad = certificate.clone();
        bad.votes[1].signer = index;
        assert!(bad.authenticate(&roster, None, 21_600).is_err());
    }
    let mut bad = certificate.clone();
    bad.statement.binding.network[0] ^= 1;
    assert!(bad.authenticate(&roster, None, 21_600).is_err());
    let mut bad = certificate.clone();
    bad.votes[1].signature = bad.votes[0].signature;
    assert!(bad.authenticate(&roster, None, 21_600).is_err());
}
#[test]
fn rollback_equivocation_and_future_publication_are_rejected() {
    let (roster, certificate) = fixture();
    let cursor = Cursor {
        sequence: 1,
        height: 72,
        digest: certificate.statement.digest(),
    };
    assert!(
        certificate
            .authenticate(&roster, Some(cursor), 21_600)
            .is_ok()
    );
    assert!(
        certificate
            .authenticate(
                &roster,
                Some(Cursor {
                    sequence: 2,
                    ..cursor
                }),
                21_600
            )
            .is_err()
    );
    assert!(
        certificate
            .authenticate(
                &roster,
                Some(Cursor {
                    digest: [0; 32],
                    ..cursor
                }),
                21_600
            )
            .is_err()
    );
    assert!(
        certificate
            .authenticate(
                &roster,
                Some(Cursor {
                    height: 144,
                    ..cursor
                }),
                21_600
            )
            .is_err()
    );
    assert!(certificate.authenticate(&roster, None, 21_599).is_err());
}
#[test]
fn stale_checkpoint_retains_authenticity_but_cannot_authorize_pruning() {
    let (roster, certificate) = fixture();
    let authenticated = certificate
        .authenticate(&roster, None, 21_600 + MAX_AGE_SECONDS + 1)
        .unwrap();
    assert!(authenticated.pruning_fresh(21_600 + MAX_AGE_SECONDS));
    assert!(!authenticated.pruning_fresh(21_600 + MAX_AGE_SECONDS + 1));
    assert!(!authenticated.pruning_fresh(21_599));
    // A fresh valid publication restores eligibility without changing history.
    assert!(authenticated.pruning_fresh(21_600));
}
#[test]
fn checkpoint_height_waits_for_twenty_four_confirmations() {
    for tip in 0..96 {
        assert_eq!(scheduled_height(tip), None);
    }
    assert_eq!(scheduled_height(96), Some(72));
    assert_eq!(scheduled_height(167), Some(72));
    assert_eq!(scheduled_height(168), Some(144));
    let (roster, mut certificate) = fixture();
    certificate.statement.height = 73;
    assert!(certificate.authenticate(&roster, None, 21_600).is_err());
}

fn transition_fixture(sequence: u64, pair: [u8; 2]) -> (Roster, Certificate) {
    let keys = [17, 29, 43].map(|n| ml_dsa_65::generate_key_pair([n; 32]));
    let (legacy, mut certificate) = fixture();
    let roster = Roster::with_transition(
        legacy.binding(),
        [
            *keys[0].verification_key.as_ref(),
            *keys[1].verification_key.as_ref(),
        ],
        *keys[2].verification_key.as_ref(),
        5,
    )
    .unwrap();
    certificate.statement.sequence = sequence;
    certificate.statement.issued_unix_seconds = sequence * INTERVAL_SECONDS;
    certificate.statement.roster = roster.digest_for_sequence(sequence);
    certificate.votes = pair
        .into_iter()
        .map(|signer| Vote {
            signer,
            signature: *ml_dsa_65::sign(
                &keys[usize::from(signer)].signing_key,
                &certificate.statement.encode(),
                CONTEXT,
                [19; 32],
            )
            .unwrap()
            .as_ref(),
        })
        .collect();
    (roster, certificate)
}

#[test]
fn transition_preserves_legacy_digest_and_exact_legacy_certificates() {
    let (legacy, old) = fixture();
    let (upgraded, _) = transition_fixture(5, [0, 2]);
    assert_eq!(upgraded.digest_for_sequence(1), legacy.digest());
    assert_eq!(upgraded.digest_for_sequence(4), legacy.digest());
    assert_ne!(upgraded.digest_for_sequence(5), legacy.digest());
    assert_eq!(upgraded.digest_for_sequence(5), upgraded.digest());
    assert!(
        old.authenticate(&upgraded, None, 5 * INTERVAL_SECONDS)
            .is_ok()
    );
    assert_eq!(
        old.encode().unwrap(),
        Certificate::decode(&old.encode().unwrap())
            .unwrap()
            .encode()
            .unwrap()
    );
    let third = ml_dsa_65::generate_key_pair([43; 32]);
    let shifted = Roster::with_transition(
        legacy.binding(),
        legacy.keys,
        *third.verification_key.as_ref(),
        6,
    )
    .unwrap();
    assert_ne!(shifted.digest(), upgraded.digest());
}

#[test]
fn transition_accepts_each_distinct_pair_and_rejects_shape_and_key_substitution() {
    for pair in [[0, 1], [0, 2], [1, 2]] {
        let (roster, certificate) = transition_fixture(5, pair);
        let decoded = Certificate::decode(&certificate.encode().unwrap()).unwrap();
        assert!(
            decoded
                .authenticate(&roster, None, 5 * INTERVAL_SECONDS)
                .is_ok()
        );
        let mut bad = certificate.clone();
        bad.votes[1].signer = bad.votes[0].signer;
        assert!(
            bad.authenticate(&roster, None, 5 * INTERVAL_SECONDS)
                .is_err()
        );
        bad.votes[1].signer = 3;
        assert!(
            bad.authenticate(&roster, None, 5 * INTERVAL_SECONDS)
                .is_err()
        );
        bad = certificate.clone();
        bad.votes.swap(0, 1);
        assert!(
            bad.authenticate(&roster, None, 5 * INTERVAL_SECONDS)
                .is_err()
        );
        bad = certificate.clone();
        bad.votes.pop();
        assert!(
            bad.authenticate(&roster, None, 5 * INTERVAL_SECONDS)
                .is_err()
        );
        bad = certificate.clone();
        bad.votes.push(certificate.votes[0].clone());
        assert!(
            bad.authenticate(&roster, None, 5 * INTERVAL_SECONDS)
                .is_err()
        );
        bad = certificate.clone();
        bad.votes[1].signature = bad.votes[0].signature;
        assert!(
            bad.authenticate(&roster, None, 5 * INTERVAL_SECONDS)
                .is_err()
        );
    }
}

#[test]
fn transition_enforces_pinned_cutover_and_monotonic_history() {
    let (roster, certificate) = transition_fixture(5, [1, 2]);
    let (legacy, mut old) = fixture();
    old.statement.sequence = 5;
    old.statement.issued_unix_seconds = 5 * INTERVAL_SECONDS;
    old.votes = [17, 29]
        .into_iter()
        .enumerate()
        .map(|(index, seed)| {
            let key = ml_dsa_65::generate_key_pair([seed; 32]);
            Vote {
                signer: index as u8,
                signature: *ml_dsa_65::sign(
                    &key.signing_key,
                    &old.statement.encode(),
                    CONTEXT,
                    [19; 32],
                )
                .unwrap()
                .as_ref(),
            }
        })
        .collect();
    assert!(
        old.authenticate(&legacy, None, 5 * INTERVAL_SECONDS)
            .is_ok()
    );
    assert!(
        old.authenticate(&roster, None, 5 * INTERVAL_SECONDS)
            .is_err()
    );
    let (_, early_third) = transition_fixture(4, [0, 2]);
    assert!(
        early_third
            .authenticate(&roster, None, 5 * INTERVAL_SECONDS)
            .is_err()
    );
    let (equivalent, _) = transition_fixture(5, [0, 1]);
    assert!(
        certificate
            .authenticate(&legacy, None, 5 * INTERVAL_SECONDS)
            .is_err()
    );
    assert!(
        certificate
            .authenticate(&equivalent, None, 5 * INTERVAL_SECONDS)
            .is_ok()
    );
    let cursor = Cursor {
        sequence: 5,
        height: certificate.statement.height,
        digest: certificate.statement.digest(),
    };
    let (_, before) = transition_fixture(4, [0, 1]);
    assert!(
        before
            .authenticate(&roster, Some(cursor), 5 * INTERVAL_SECONDS)
            .is_err()
    );
    assert!(
        certificate
            .authenticate(&roster, Some(cursor), 5 * INTERVAL_SECONDS)
            .is_ok()
    );
    assert!(
        certificate
            .authenticate(
                &roster,
                Some(Cursor {
                    digest: [0; 32],
                    ..cursor
                }),
                5 * INTERVAL_SECONDS
            )
            .is_err()
    );
    assert!(Roster::with_transition(legacy.binding(), legacy.keys, legacy.keys[0], 5).is_err());
    assert!(
        Roster::with_transition(legacy.binding(), legacy.keys, [0; PUBLIC_KEY_BYTES], 5).is_err()
    );
    assert!(
        Roster::with_transition(
            legacy.binding(),
            legacy.keys,
            *ml_dsa_65::generate_key_pair([43; 32])
                .verification_key
                .as_ref(),
            0
        )
        .is_err()
    );
}
