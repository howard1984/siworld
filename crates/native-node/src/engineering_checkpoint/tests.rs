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
