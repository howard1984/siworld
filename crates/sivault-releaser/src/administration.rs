//! Owner-signed single-slot refill and terminal revocation.

use std::{
    io::{Read, Write},
    path::Path,
};

use libcrux_ml_dsa::ml_dsa_65::{MLDSA65Signature, MLDSA65VerificationKey};
use sha2::{Digest, Sha256};
use sivault_core::{
    Error, Result,
    controlled_channel::{ReleaserIdentity, ReleaserPins, stream::Session, verify_receipt},
    controlled_credential::ChannelBinding,
    owner::{OwnerIdentity, key_id, verify_command},
};

use crate::{
    enrollment,
    journal::{Journal, MarkerStore},
    ledger::{Event, Outcome, Releaser},
    message::{AckPhase, Action, Body, Id, Kind, Message, OwnerMeta, Status},
    opening::{self, OpeningRecord, ReleaseMaterial},
    slot_store,
};

const SIGNATURE_LEN: usize = MLDSA65Signature::len();

#[derive(Clone, Copy)]
pub enum Change {
    Refill { current: u64, additional: u64 },
    Revoke,
}

pub fn submit<R: Read, W: Write>(
    mut session: Session<R, W>,
    owner: &OwnerIdentity,
    scope: &OpeningRecord,
    change: Change,
    pins: &ReleaserPins,
    counter: u64,
    now: u64,
) -> Result<()> {
    let request = Id(sivault_core::crypto::random()?);
    let (action, phase) = match change {
        Change::Refill {
            current,
            additional,
        } if additional > 0 => (
            Action::Refill {
                ledger: scope.slot.ledger,
                delta: additional,
                expected_total: current,
                new_total: current.checked_add(additional).ok_or(Error::Limit)?,
            },
            AckPhase::Active,
        ),
        Change::Refill { .. } => return Err(Error::InvalidFormat),
        Change::Revoke => (
            Action::Revoke {
                ledger: scope.slot.ledger,
                record: scope.record.manifest,
            },
            AckPhase::Deleted,
        ),
    };
    let kind = action.kind();
    let domain = enrollment::domain(scope, request);
    let mut bytes = Message {
        domain,
        body: Body::Owner {
            meta: Box::new(OwnerMeta {
                owner_key: Id(owner.identifier()),
                counter,
                command: request,
                predecessor: scope.record.root,
                manifest: scope.record.manifest,
                expiry: now.checked_add(60).ok_or(Error::Limit)?,
            }),
            action,
        },
    }
    .encode()
    .map_err(|_| Error::InvalidFormat)?;
    let binding = session.binding()?;
    let signature = owner.sign_command(&transcript(b"owner-command", &binding, &bytes))?;
    bytes.extend_from_slice(signature.as_slice());
    session.send(kind as u8, &bytes)?;
    let receipt = session.receive(Kind::CommandAck as u8)?;
    let (body, signature) = split_signature(&receipt)?;
    verify_receipt(
        &pins.verification,
        &transcript(b"command-receipt", &binding, body),
        &signature,
    )?;
    let ack = Message::decode(body).map_err(|_| Error::InvalidFormat)?;
    match ack.body {
        Body::CommandAck {
            command,
            protected_state,
            ledger_head,
            applied_counter,
            phase: actual,
            status: Status::Accepted,
        } if ack.domain == domain
            && command == request
            && protected_state != Id::default()
            && ledger_head != Id::default()
            && actual == phase
            && applied_counter == counter =>
        {
            Ok(())
        }
        _ => Err(Error::Authentication),
    }
}

pub struct Service<M> {
    releaser: Releaser<Journal<M>>,
    scope: OpeningRecord,
    release: Option<ReleaseMaterial>,
    owner: MLDSA65VerificationKey,
}

impl<M: MarkerStore> Service<M> {
    pub fn new(
        releaser: Releaser<Journal<M>>,
        release: ReleaseMaterial,
        owner: MLDSA65VerificationKey,
    ) -> Self {
        Self {
            scope: release.scope.clone(),
            releaser,
            release: Some(release),
            owner,
        }
    }

    pub fn serve<R: Read, W: Write>(
        &mut self,
        mut session: Session<R, W>,
        kind: u8,
        payload: &[u8],
        identity: &ReleaserIdentity,
        slot_path: &Path,
        now: u64,
    ) -> Result<()> {
        if kind == Kind::OpenInit as u8 {
            let release = self.release.as_ref().ok_or(Error::Authentication)?;
            return opening::serve_init(session, &mut self.releaser, release, payload)
                .map_err(|_| Error::Authentication);
        }
        if kind != Kind::Refill as u8 && kind != Kind::Revoke as u8 {
            return Err(Error::Authentication);
        }
        let binding = session.binding()?;
        let (body, signature) = split_signature(payload)?;
        verify_command(
            &self.owner,
            &transcript(b"owner-command", &binding, body),
            &signature,
        )?;
        let message = Message::decode(body).map_err(|_| Error::InvalidFormat)?;
        let Body::Owner { meta, action } = &message.body else {
            return Err(Error::InvalidFormat);
        };
        let domain = message.domain;
        if kind != action.kind() as u8
            || domain != enrollment::domain(&self.scope, meta.command)
            || meta.command == Id::default()
            || meta.owner_key != Id(key_id(&self.owner))
            || meta.manifest != self.scope.record.manifest
            || meta.predecessor != self.scope.record.root
            || meta.expiry.saturating_sub(now) > 120
        {
            return Err(Error::Authentication);
        }
        let command = meta.command;
        let mut hash = Sha256::new();
        hash.update(b"SV-OWNER-ADMIN-COMMAND-v1");
        hash.update(body);
        let digest = Id(hash.finalize().into());
        let Outcome::Command(receipt) = self
            .releaser
            .apply(Event::Owner {
                message: Box::new(message),
                digest,
                now,
            })
            .map_err(|_| Error::Authentication)?
        else {
            return Err(Error::Authentication);
        };
        let phase = if kind == Kind::Revoke as u8 {
            drop(self.release.take());
            slot_store::remove_revoked_material(slot_path).map_err(|_| Error::Authentication)?;
            self.releaser
                .apply(Event::ConfirmDeletion {
                    generation: domain.generation,
                    incarnation: domain.incarnation,
                    tombstone: digest,
                })
                .map_err(|_| Error::Authentication)?;
            AckPhase::Deleted
        } else {
            receipt.phase
        };
        let head = self.releaser.authority().protected_head();
        let mut response = Message {
            domain,
            body: Body::CommandAck {
                command,
                protected_state: digest,
                ledger_head: head,
                applied_counter: receipt.counter,
                phase,
                status: Status::Accepted,
            },
        }
        .encode()
        .map_err(|_| Error::InvalidFormat)?;
        let signature =
            identity.sign_receipt(&transcript(b"command-receipt", &binding, &response))?;
        response.extend_from_slice(signature.as_slice());
        session.send(Kind::CommandAck as u8, &response)
    }
}

fn split_signature(bytes: &[u8]) -> Result<(&[u8], MLDSA65Signature)> {
    let n = bytes
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(Error::InvalidFormat)?;
    let (body, signature) = bytes.split_at(n);
    Ok((
        body,
        MLDSA65Signature::new(signature.try_into().map_err(|_| Error::InvalidFormat)?),
    ))
}

fn transcript(label: &[u8], binding: &ChannelBinding, bytes: &[u8]) -> Vec<u8> {
    let mut message = b"SV-OWNER-ADMIN-v1".to_vec();
    message.push(label.len() as u8);
    message.extend_from_slice(label);
    message.extend_from_slice(binding.as_bytes());
    message.extend_from_slice(bytes);
    message
}
