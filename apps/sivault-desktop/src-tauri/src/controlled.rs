use std::path::Path;

use sivault_core::{
    controlled_credential::{ClientCredential, FolderIdentity},
    crypto::{self, Secret},
    owner::OwnerIdentity,
    standard::Safe,
};
use sivault_releaser::{
    administration::{self, Change},
    enrollment::{self, Offer},
    ledger::{Record, SlotIdentity},
    message::Id,
    opening::{self, OpeningRecord, ReleaseMaterial, folder_key_id},
    registration::{Registration, StoredRegistration},
};

use crate::{
    adapter::{BridgeError, Result},
    releaser::{LOOPBACK_DEPLOYMENT, LocalPeer, unix_now},
};

fn enrollment_failed() -> BridgeError {
    BridgeError::new(
        "CONTROLLED_ENROLLMENT_FAILED",
        "The controlled safe could not be enrolled.",
    )
}

fn denied() -> BridgeError {
    BridgeError::new(
        "CONTROLLED_OPEN_DENIED",
        "The releaser did not approve this opening.",
    )
}

fn random_id() -> Result<Id> {
    crypto::random().map(Id).map_err(|_| enrollment_failed())
}

pub(crate) fn create(
    path: &Path,
    password: &str,
    peer: &LocalPeer,
    allowance: u64,
    owner: &OwnerIdentity,
) -> Result<Safe> {
    if !(1..=1000).contains(&allowance) {
        return Err(enrollment_failed());
    }
    let safe_id = crypto::random::<16>().map_err(|_| enrollment_failed())?;
    let mut target = [0; 32];
    target[..16].copy_from_slice(&safe_id);
    let folder = Secret::new(crypto::random().map_err(|_| enrollment_failed())?);
    let key = Secret::new(crypto::random().map_err(|_| enrollment_failed())?);
    let share = Secret::new(crypto::random().map_err(|_| enrollment_failed())?);
    let possession = FolderIdentity::derive(&folder, &safe_id);
    let scope = OpeningRecord {
        slot: SlotIdentity {
            suite: 1,
            network: Id(LOOPBACK_DEPLOYMENT),
            safe: Id(target),
            slot: random_id()?,
            ledger: random_id()?,
        },
        record: Record {
            generation: 1,
            incarnation: random_id()?,
            manifest: random_id()?,
            root: random_id()?,
        },
        record_id: random_id()?,
        salt: random_id()?,
    };
    let context = scope.context();
    let credential =
        ClientCredential::new(password, &folder, &context).map_err(|_| enrollment_failed())?;
    let envelope = credential
        .wrap(&context, &share, &key)
        .map_err(|_| enrollment_failed())?;
    let material = ReleaseMaterial {
        scope: scope.clone(),
        folder_key: possession.verification_key().clone(),
        verifier: credential.enrollment_verifier(),
        share,
    };
    // Complete the initial encrypted payload before purchasing an allowance.
    let safe =
        Safe::create_controlled(path, safe_id, key.clone()).map_err(|_| enrollment_failed())?;
    let (session, pins) = peer.connect(folder_key_id(&material.folder_key).0)?;
    let digest = Id(crypto::mac(&folder, &context.encode()));
    let ack = enrollment::submit(
        session,
        owner,
        Offer {
            release: &material,
            releaser: Id(peer.identifier),
            request: random_id()?,
            allowance,
            expiry: unix_now()? + 60,
            wrap_context_digest: digest,
        },
        &pins,
    )
    .map_err(|_| enrollment_failed())?;
    Registration {
        peer: Id(peer.identifier),
        port: peer.address.port(),
        endpoint: (!peer.address.ip().is_loopback()).then_some(*peer.address.ip()),
        scope,
        allowance,
        enrollment_ack: ack,
        nonce: envelope.nonce,
        wrapped_key: envelope.ciphertext.to_vec(),
    }
    .publish_portable(&safe, &key, &folder, owner)
    .map_err(|_| enrollment_failed())?;
    Ok(safe)
}

pub(crate) fn open(path: &Path, password: &str, read_only: bool) -> Result<Safe> {
    let stored = StoredRegistration::read(path).map_err(|_| denied())?;
    let registration = stored.untrusted();
    if registration.scope.slot.network != Id(LOOPBACK_DEPLOYMENT) {
        return Err(denied());
    }
    let safe_id: [u8; 16] = registration.scope.slot.safe.0[..16]
        .try_into()
        .map_err(|_| denied())?;
    let folder = stored.folder_secret().map_err(|_| denied())?;
    let possession = FolderIdentity::derive(&folder, &safe_id);
    let context = registration.scope.context();
    let credential = ClientCredential::new(password, &folder, &context).map_err(|_| denied())?;
    let peer = LocalPeer {
        identifier: registration.peer.0,
        address: registration.address(),
    };
    let (session, _) = peer.connect(folder_key_id(possession.verification_key()).0)?;
    let key = opening::open(
        session,
        &registration.scope,
        credential,
        possession.signing_key(),
        &registration.envelope().map_err(|_| denied())?,
    )
    .map_err(|_| denied())?;
    stored.authenticate(&key).map_err(|_| denied())?;
    Safe::open_controlled(path, safe_id, key, read_only).map_err(|_| denied())
}

pub(crate) fn manage(path: &Path, owner: &OwnerIdentity, change: Change) -> Result<()> {
    let unavailable = || {
        BridgeError::new(
            "CONTROLLED_COMMAND_FAILED",
            crate::locale::CONTROLLED_COMMAND_FAILED,
        )
    };
    let stored = StoredRegistration::read(path).map_err(|_| unavailable())?;
    stored
        .authenticate_owner(owner)
        .map_err(|_| unavailable())?;
    let registration = stored.untrusted();
    if registration.scope.slot.network != Id(LOOPBACK_DEPLOYMENT) {
        return Err(unavailable());
    }
    let peer = LocalPeer {
        identifier: registration.peer.0,
        address: registration.address(),
    };
    let (session, pins) = peer.connect([0; 32])?;
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| unavailable())?;
    let counter = u64::try_from(time.as_nanos()).map_err(|_| unavailable())?;
    administration::submit(
        session,
        owner,
        &registration.scope,
        change,
        &pins,
        counter,
        time.as_secs(),
    )
    .map_err(|_| unavailable())
}
