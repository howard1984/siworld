//! Signed enrollment record carried inside the authenticated releaser channel.
//! Decoding authenticates the record, but never approves or provisions a slot.

use std::io::{Read, Write};

use libcrux_ml_dsa::ml_dsa_65::{MLDSA65Signature, MLDSA65VerificationKey};
use sha2::{Digest, Sha256};
use sivault_core::{
    Error, Result,
    controlled_channel::{ReleaserIdentity, ReleaserPins, stream::Session, verify_receipt},
    controlled_credential::{ChannelBinding, ReleaserVerifier},
    crypto::Secret,
    owner::{self, OwnerIdentity},
};
use zeroize::Zeroizing;

use crate::{
    ledger::{Record, SlotIdentity},
    message::{Body, Domain, Id, Kind, Message, Operation, Status},
    opening::{OpeningRecord, ReleaseMaterial, folder_key_id},
};

const PUBLIC_KEY_LEN: usize = MLDSA65VerificationKey::len();
const SIGNATURE_LEN: usize = MLDSA65Signature::len();
const MATERIAL_LEN: usize = 7 * 32 + 2 * PUBLIC_KEY_LEN;

pub struct VerifiedEnrollment {
    pub release: ReleaseMaterial,
    pub owner_key: MLDSA65VerificationKey,
    pub allowance: u64,
    pub request: Id,
    pub digest: Id,
    pub wrap_context_digest: Id,
}

pub struct Offer<'a> {
    pub release: &'a ReleaseMaterial,
    pub releaser: Id,
    pub request: Id,
    pub allowance: u64,
    pub expiry: u64,
    pub wrap_context_digest: Id,
}

/// Submit one enrollment and require a signed durable receipt from the pinned key.
pub fn submit<R: Read, W: Write>(
    mut session: Session<R, W>,
    identity: &OwnerIdentity,
    offer: Offer<'_>,
    pins: &ReleaserPins,
) -> Result<Id> {
    let request = offer.request;
    let scope = offer.release.scope.clone();
    if offer.releaser.0 != pins.identifier() {
        return Err(Error::Authentication);
    }
    let payload = sign(identity, offer, &session.binding()?)?;
    let digest = hash(b"enrollment", &payload[..payload.len() - SIGNATURE_LEN]);
    session.send(Kind::Enroll as u8, &payload)?;
    drop(payload);
    let ack = session.receive(Kind::EnrollAck as u8)?;
    let end = ack
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(Error::InvalidFormat)?;
    let (body, signature) = ack.split_at(end);
    verify_receipt(
        &pins.verification,
        &receipt_transcript(&session.binding()?, body),
        &MLDSA65Signature::new(signature.try_into().map_err(|_| Error::InvalidFormat)?),
    )?;
    let message = Message::decode(body).map_err(|_| Error::InvalidFormat)?;
    match message.body {
        Body::EnrollAck {
            enroll,
            releaser_key,
            ledger,
            durable_record,
            status: Status::Accepted,
        } if message.domain == domain(&scope, request)
            && enroll == digest
            && releaser_key.0 == pins.identifier()
            && ledger == scope.slot.ledger
            && durable_record != Id::default() =>
        {
            Ok(hash(b"enrollment-ack", &ack))
        }
        _ => Err(Error::Authentication),
    }
}

/// Send an acknowledgement only with the independently checkpointed journal
/// head obtained after provisioning the locally accepted offer.
pub fn acknowledge<R: Read, W: Write>(
    session: &mut Session<R, W>,
    identity: &ReleaserIdentity,
    enrollment: &VerifiedEnrollment,
    journal_head: Id,
) -> Result<()> {
    if journal_head == Id::default() {
        return Err(Error::Authentication);
    }
    let scope = &enrollment.release.scope;
    let mut ack = Message {
        domain: domain(scope, enrollment.request),
        body: Body::EnrollAck {
            enroll: enrollment.digest,
            releaser_key: Id(identity.pins().identifier()),
            ledger: scope.slot.ledger,
            durable_record: journal_head,
            status: Status::Accepted,
        },
    }
    .encode()
    .map_err(|_| Error::InvalidFormat)?;
    let signature = identity.sign_receipt(&receipt_transcript(&session.binding()?, &ack))?;
    ack.extend_from_slice(signature.as_slice());
    session.send(Kind::EnrollAck as u8, &ack)
}

pub fn sign(
    identity: &OwnerIdentity,
    offer: Offer<'_>,
    binding: &ChannelBinding,
) -> Result<Zeroizing<Vec<u8>>> {
    let Offer {
        release,
        releaser,
        request,
        allowance,
        expiry,
        wrap_context_digest,
    } = offer;
    let scope = &release.scope;
    let mut material = Zeroizing::new(Vec::with_capacity(MATERIAL_LEN));
    for field in [
        scope.record.root,
        scope.record_id,
        scope.salt,
        wrap_context_digest,
    ] {
        material.extend_from_slice(&field.0);
    }
    material.extend_from_slice(identity.verification_key().as_slice());
    material.extend_from_slice(release.folder_key.as_slice());
    material.extend_from_slice(&release.verifier.stored_key);
    material.extend_from_slice(release.verifier.server_key.as_ref());
    material.extend_from_slice(release.share.as_ref());
    let message = Message {
        domain: domain(scope, request),
        body: Body::Enroll {
            owner_key: Id(identity.identifier()),
            manifest: scope.record.manifest,
            releaser_key: releaser,
            ledger: scope.slot.ledger,
            allowance,
            record_manifest: hash(b"credential-record", &material),
            expiry,
        },
    };
    let mut bytes = Zeroizing::new(message.encode().map_err(|_| Error::InvalidFormat)?);
    bytes.reserve_exact(MATERIAL_LEN + SIGNATURE_LEN);
    bytes.extend_from_slice(&material);
    let signature = identity.sign_command(&transcript(binding, &bytes))?;
    bytes.extend_from_slice(signature.as_slice());
    Ok(bytes)
}

pub(crate) fn domain(scope: &OpeningRecord, request: Id) -> Domain {
    Domain {
        suite: scope.slot.suite,
        network: scope.slot.network,
        safe: scope.slot.safe,
        generation: scope.record.generation,
        slot: scope.slot.slot,
        incarnation: scope.record.incarnation,
        request,
        operation: Operation::Owner,
    }
}

/// Check the signed record and channel scope. The included owner key is
/// self-asserted; callers must compare an independently approved owner key
/// before provisioning. This does not establish possession of the folder key.
pub fn verify(
    bytes: &[u8],
    binding: &ChannelBinding,
    network: Id,
    releaser: Id,
    claimed_folder: Id,
    now: u64,
) -> Result<VerifiedEnrollment> {
    let signed_len = bytes
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(Error::InvalidFormat)?;
    let metadata_len = signed_len
        .checked_sub(MATERIAL_LEN)
        .ok_or(Error::InvalidFormat)?;
    let (signed, signature) = bytes.split_at(signed_len);
    let (header, material) = signed.split_at(metadata_len);
    let message = Message::decode(header).map_err(|_| Error::InvalidFormat)?;
    let domain = message.domain;
    let Body::Enroll {
        owner_key,
        manifest,
        releaser_key,
        ledger,
        allowance,
        record_manifest,
        expiry,
    } = message.body
    else {
        return Err(Error::InvalidFormat);
    };
    if domain.suite != 1
        || domain.network != network
        || domain.generation != 1
        || releaser_key != releaser
        || allowance == 0
        || expiry <= now
        || expiry - now > 120
        || [
            domain.safe,
            domain.slot,
            domain.incarnation,
            domain.request,
            manifest,
            ledger,
        ]
        .contains(&Id::default())
        || record_manifest != hash(b"credential-record", material)
    {
        return Err(Error::Authentication);
    }
    let [root, record_id, salt, wrap_context] = material[..128].as_chunks::<32>().0 else {
        return Err(Error::InvalidFormat);
    };
    let (owner_bytes, rest) = material[128..].split_at(PUBLIC_KEY_LEN);
    let (folder_bytes, secrets) = rest.split_at(PUBLIC_KEY_LEN);
    let verification =
        MLDSA65VerificationKey::new(owner_bytes.try_into().map_err(|_| Error::InvalidFormat)?);
    let folder_key =
        MLDSA65VerificationKey::new(folder_bytes.try_into().map_err(|_| Error::InvalidFormat)?);
    if owner_key.0 != owner::key_id(&verification) || folder_key_id(&folder_key) != claimed_folder {
        return Err(Error::Authentication);
    }
    owner::verify_command(
        &verification,
        &transcript(binding, signed),
        &MLDSA65Signature::new(signature.try_into().map_err(|_| Error::InvalidFormat)?),
    )?;
    let [stored, server, share] = secrets.as_chunks::<32>().0 else {
        return Err(Error::InvalidFormat);
    };
    Ok(VerifiedEnrollment {
        release: ReleaseMaterial {
            scope: OpeningRecord {
                slot: SlotIdentity {
                    suite: domain.suite,
                    network,
                    safe: domain.safe,
                    slot: domain.slot,
                    ledger,
                },
                record: Record {
                    generation: domain.generation,
                    incarnation: domain.incarnation,
                    manifest,
                    root: Id(*root),
                },
                record_id: Id(*record_id),
                salt: Id(*salt),
            },
            folder_key,
            verifier: ReleaserVerifier {
                stored_key: *stored,
                server_key: Secret::new(*server),
            },
            share: Secret::new(*share),
        },
        owner_key: verification,
        allowance,
        request: domain.request,
        digest: hash(b"enrollment", signed),
        wrap_context_digest: Id(*wrap_context),
    })
}

fn hash(label: &[u8], bytes: &[u8]) -> Id {
    let mut hash = Sha256::new();
    hash.update(b"SV-ENROLL-v1");
    hash.update([label.len() as u8]);
    hash.update(label);
    hash.update(bytes);
    Id(hash.finalize().into())
}

fn transcript(binding: &ChannelBinding, body: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(48 + body.len()));
    bytes.extend_from_slice(b"SV-ENROLL-SIGNED");
    bytes.extend_from_slice(binding.as_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn receipt_transcript(binding: &ChannelBinding, body: &[u8]) -> Vec<u8> {
    let mut bytes = b"SV-ENROLL-RECEIPT".to_vec();
    bytes.extend_from_slice(binding.as_bytes());
    bytes.extend_from_slice(body);
    bytes
}
