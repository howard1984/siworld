#![cfg(not(target_arch = "wasm32"))]

mod support;

use libcrux_ml_dsa::ml_dsa_65;
use sivault_core::{
    controlled_channel::{PendingClient, ReleaserIdentity},
    controlled_credential::ReleaserVerifier,
    crypto::Secret,
    owner::OwnerIdentity,
};
use sivault_releaser::{
    enrollment::{self, Offer},
    message::Id,
    opening::{OpeningRecord, ReleaseMaterial, folder_key_id},
};
use support::{id, record, slot};

#[test]
fn enrollment_authenticates_scope_credentials_and_channel() {
    let owner = OwnerIdentity::derive(&Secret::new([21; 32]));
    let folder = ml_dsa_65::generate_key_pair([22; 32]).verification_key;
    let folder_id = folder_key_id(&folder);
    let releaser = ReleaserIdentity::generate().unwrap();
    let peer = Id(releaser.pins().identifier());
    let mut slot = slot();
    slot.suite = 1;
    let release = ReleaseMaterial {
        scope: OpeningRecord {
            slot,
            record: record(),
            record_id: id(23),
            salt: id(24),
        },
        folder_key: folder,
        verifier: ReleaserVerifier {
            stored_key: [25; 32],
            server_key: Secret::new([26; 32]),
        },
        share: Secret::new([27; 32]),
    };
    let connected = || {
        let pending = PendingClient::start(releaser.pins(), &slot.network.0, folder_id.0).unwrap();
        let (reply, server) = releaser.accept(&slot.network.0, pending.hello()).unwrap();
        (pending.finish(&reply).unwrap(), server)
    };
    let (client, server) = connected();
    let mut bytes = enrollment::sign(
        &owner,
        Offer {
            release: &release,
            releaser: peer,
            request: id(28),
            allowance: 2,
            expiry: 130,
            wrap_context_digest: id(29),
        },
        &client.binding(),
    )
    .unwrap();
    let verified =
        enrollment::verify(&bytes, &server.binding(), slot.network, peer, folder_id, 30).unwrap();
    assert_eq!(verified.release.scope, release.scope);
    assert_eq!(*verified.release.share, *release.share);
    assert_eq!(verified.allowance, 2);
    assert_eq!(verified.wrap_context_digest, id(29));
    let (_, other_session) = connected();
    for (binding, checked_peer, checked_folder, now) in [
        (other_session.binding(), peer, folder_id, 30),
        (server.binding(), id(30), folder_id, 30),
        (server.binding(), peer, id(31), 30),
        (server.binding(), peer, folder_id, 130),
    ] {
        assert!(
            enrollment::verify(
                &bytes,
                &binding,
                slot.network,
                checked_peer,
                checked_folder,
                now
            )
            .is_err()
        );
    }
    bytes[100] ^= 1;
    assert!(
        enrollment::verify(&bytes, &server.binding(), slot.network, peer, folder_id, 30).is_err()
    );
}
