#![cfg(not(target_arch = "wasm32"))]

use sivault_core::{
    controlled_credential::verify_possession,
    crypto::Secret,
    owner::{OwnerIdentity, verify_command},
};

#[test]
fn owner_identity_restores_and_signatures_are_domain_separated() {
    let entropy = Secret::new([0x42; 32]);
    let owner = OwnerIdentity::derive(&entropy);
    let restored = OwnerIdentity::derive(&entropy);
    let other = OwnerIdentity::derive(&Secret::new([0x43; 32]));
    assert_eq!(owner.identifier(), restored.identifier());
    assert_ne!(owner.identifier(), other.identifier());

    let transcript = b"synthetic scoped owner command";
    let signature = owner.sign_command(transcript).unwrap();
    verify_command(restored.verification_key(), transcript, &signature).unwrap();
    assert!(verify_command(other.verification_key(), transcript, &signature).is_err());
    assert!(verify_command(restored.verification_key(), b"another command", &signature).is_err());
    assert!(verify_possession(restored.verification_key(), transcript, &signature).is_err());
}
