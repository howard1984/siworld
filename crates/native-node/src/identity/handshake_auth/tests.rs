use super::*;

fn binding() -> Binding {
    Binding {
        network: [1; 32],
        genesis: [2; 32],
        verifier: [3; 32],
    }
}
fn identities() -> (NativeIdentity, NativeIdentity) {
    (
        NativeIdentity::from_seeds(binding(), &[4; 32], &[5; 32]),
        NativeIdentity::from_seeds(binding(), &[6; 32], &[7; 32]),
    )
}
fn transcript(first: &NativeIdentity, second: &NativeIdentity) -> Transcript {
    Transcript::new(
        binding(),
        ConnectionRole::Initiator,
        [fingerprint(first), fingerprint(second)],
        [[8; 32], [9; 32]],
        [10; 32],
        [11; 32],
    )
    .unwrap()
}

#[test]
fn both_fresh_signatures_are_required_and_encoding_is_exact() {
    let (first, second) = identities();
    let transcript = transcript(&first, &second);
    let descriptor = first.descriptor().unwrap();
    let signature = first.sign_channel_transcript(&transcript).unwrap();
    descriptor
        .verify_channel_transcript(&transcript, &signature)
        .unwrap();
    let bytes = signature.encode();
    assert_eq!(bytes.len(), SIGNATURE_BYTES);
    let decoded = Signatures::decode(&bytes).unwrap();
    descriptor
        .verify_channel_transcript(&transcript, &decoded)
        .unwrap();
    for offset in [0, 63, 64, SIGNATURE_BYTES - 1] {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(
            descriptor
                .verify_channel_transcript(&transcript, &Signatures::decode(&changed).unwrap())
                .is_err()
        );
    }
    assert!(Signatures::decode(&bytes[..SIGNATURE_BYTES - 1]).is_err());
    let mut extra = bytes.to_vec();
    extra.push(0);
    assert!(Signatures::decode(&extra).is_err());
    assert!(second.sign_channel_transcript(&transcript).is_err());
    let mut response = transcript.clone();
    response.sender = ConnectionRole::Responder;
    let signature = second.sign_channel_transcript(&response).unwrap();
    second
        .descriptor()
        .unwrap()
        .verify_channel_transcript(&response, &signature)
        .unwrap();
}

#[test]
fn context_roles_identities_nonces_and_transport_prefix_reject_replay() {
    let (first, second) = identities();
    let original = transcript(&first, &second);
    let signature = first.sign_channel_transcript(&original).unwrap();
    let descriptor = first.descriptor().unwrap();
    for field in 0..10 {
        let mut changed = original.clone();
        match field {
            0 => changed.binding.network[0] ^= 1,
            1 => changed.binding.genesis[0] ^= 1,
            2 => changed.binding.verifier[0] ^= 1,
            3 => changed.sender = ConnectionRole::Responder,
            4 => changed.endpoints[0][0] ^= 1,
            5 => changed.endpoints[1][0] ^= 1,
            6 => changed.nonces[0][0] ^= 1,
            7 => changed.nonces[1][0] ^= 1,
            8 => changed.transport_hash[0] ^= 1,
            _ => changed.prefix_hash[0] ^= 1,
        }
        assert!(
            descriptor
                .verify_channel_transcript(&changed, &signature)
                .is_err()
        );
    }
    let possession = descriptor.encode();
    assert!(
        descriptor
            .verify_channel_transcript(
                &original,
                &Signatures::decode(&possession[possession.len() - SIGNATURE_BYTES..]).unwrap()
            )
            .is_err()
    );
}

#[test]
fn invalid_context_and_reflected_endpoints_are_rejected_before_signing() {
    let (first, second) = identities();
    let original = transcript(&first, &second);
    for field in 0..8 {
        let mut changed = original.clone();
        match field {
            0 => changed.binding.network = [0; 32],
            1 => changed.endpoints[0] = [0; 32],
            2 => changed.endpoints[1] = changed.endpoints[0],
            3 => changed.nonces[0] = [0; 32],
            4 => changed.nonces[1] = changed.nonces[0],
            5 => changed.transport_hash = [0; 32],
            6 => changed.prefix_hash = [0; 32],
            _ => changed.binding.verifier[0] ^= 1,
        }
        assert!(first.sign_channel_transcript(&changed).is_err());
    }
}
