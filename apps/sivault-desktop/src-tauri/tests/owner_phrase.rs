use sivault_core::owner::{OwnerIdentity, verify_command};
use siworld_native_wallet_core::{identity::Identity, vault::Material};

#[test]
fn owner_phrase_restore_is_independent_of_wallet_network_and_account() {
    let original = Material::generate([1; 32], 0).unwrap();
    let restored = Material::restore([2; 32], 7, original.words()).unwrap();
    let owner = OwnerIdentity::derive(&original.entropy);
    let other_device = OwnerIdentity::derive(&restored.entropy);
    assert_eq!(owner.identifier(), other_device.identifier());

    let first_wallet =
        Identity::derive(&original.entropy, original.network, original.account).unwrap();
    let second_wallet =
        Identity::derive(&restored.entropy, restored.network, restored.account).unwrap();
    assert_ne!(first_wallet.spend_key(), second_wallet.spend_key());

    let command = b"synthetic owner command";
    let signature = owner.sign_command(command).unwrap();
    verify_command(other_device.verification_key(), command, &signature).unwrap();
}
