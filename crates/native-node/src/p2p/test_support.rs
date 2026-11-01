//! Synthetic identities for transport-interface tests, not production trust.
use super::*;
use crate::identity::{Descriptor, PeerPin};
use ed25519_dalek::{Signer, SigningKey};
use libcrux_ml_dsa::ml_dsa_65;
use zeroize::Zeroize;

pub(crate) fn expected(binding: Binding, seed: Hash) -> ExpectedPeer {
    let ed25519 = SigningKey::from_bytes(&seed);
    let mut pair = ml_dsa_65::generate_key_pair(seed);
    let mut bytes = [0; crate::identity::DESCRIPTOR_BYTES];
    bytes[..4].copy_from_slice(b"SWID");
    bytes[4..6].copy_from_slice(&crate::identity::VERSION.to_le_bytes());
    bytes[6..38].copy_from_slice(&binding.network);
    bytes[38..70].copy_from_slice(&binding.genesis);
    bytes[70..102].copy_from_slice(&binding.verifier);
    bytes[102..134].copy_from_slice(&ed25519.verifying_key().to_bytes());
    bytes[134..2086].copy_from_slice(pair.verification_key.as_ref());
    let mut message = b"siworld native peer identity descriptor v1\0".to_vec();
    message.extend_from_slice(&bytes[..2086]);
    bytes[2086..2150].copy_from_slice(&ed25519.sign(&message).to_bytes());
    let signature = ml_dsa_65::sign(
        &pair.signing_key,
        &message,
        b"siworld native peer identity v1",
        [0; 32],
    )
    .unwrap();
    bytes[2150..].copy_from_slice(signature.as_ref());
    pair.signing_key.as_mut_slice().zeroize();
    let descriptor = Descriptor::decode(&bytes, &binding).unwrap();
    let pin = PeerPin::from_trusted_descriptor(&descriptor, &binding).unwrap();
    ExpectedPeer::from_pinned_descriptor(binding, descriptor, pin).unwrap()
}

pub(crate) fn admission(binding: Binding, seed: Hash, role: ConnectionRole) -> AdmissionContext {
    AdmissionContext::new(expected(binding, seed), role, Cancellation::default())
}

pub(crate) fn parameters() -> NegotiatedParameters<'static> {
    NegotiatedParameters {
        tls_version: 0x0304,
        group: 0x11ec,
        cipher_suite: 0x1303,
        alpn: b"/siworld/native-hybrid/1",
        resumed: false,
        early_data: false,
    }
}
