//! One controlled opening over an authenticated channel.
//! Enrollment and owner commands establish the trusted record separately.

use std::{
    io::{Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};

use libcrux_ml_dsa::ml_dsa_65::{MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey};
use sha2::{Digest, Sha256};
use sivault_core::{
    controlled_channel::stream::Session,
    controlled_credential::{
        AttemptContext, ClientCredential, Envelope, RecordContext, ReleaserVerifier,
        sign_possession, verify_possession,
    },
    crypto::{Secret, random},
};
use zeroize::Zeroizing;

use crate::{
    ledger::{
        Attempt, DurableAuthority, Event, Outcome, Possession, Record, Releaser, SlotIdentity,
    },
    message::{Body, Domain, Id, Kind, Message, Operation, Stage, Status},
};

/// The record and its keys are installed through owner-authenticated enrollment.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpeningRecord {
    pub slot: SlotIdentity,
    pub record: Record,
    pub record_id: Id,
    pub salt: Id,
}

pub struct ReleaseMaterial {
    pub scope: OpeningRecord,
    pub folder_key: MLDSA65VerificationKey,
    pub verifier: ReleaserVerifier,
    pub share: Secret,
}

#[derive(Debug)]
pub enum Error {
    InvalidMessage,
    Denied,
    Clock,
    Channel(sivault_core::Error),
}

impl From<sivault_core::Error> for Error {
    fn from(value: sivault_core::Error) -> Self {
        Self::Channel(value)
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpeningPurpose {
    Normal,
    Recovery,
}

impl OpeningPurpose {
    fn operation(self) -> Operation {
        match self {
            Self::Normal => Operation::Normal,
            Self::Recovery => Operation::Recovery,
        }
    }
}

impl OpeningRecord {
    pub fn context(&self) -> RecordContext {
        self.context_for(OpeningPurpose::Normal)
    }

    pub fn context_for(&self, purpose: OpeningPurpose) -> RecordContext {
        RecordContext {
            suite: self.slot.suite,
            version: 1,
            deployment: self.slot.network.0,
            safe: self.slot.safe.0,
            generation: self.record.generation,
            slot: self.slot.slot.0,
            ledger: self.slot.ledger.0,
            operation: purpose.operation() as u8,
            record: self.record_id.0,
            argon_salt: self.salt.0,
        }
    }

    fn domain(&self, request: Id, purpose: OpeningPurpose) -> Domain {
        Domain {
            suite: self.slot.suite,
            network: self.slot.network,
            safe: self.slot.safe,
            generation: self.record.generation,
            slot: self.slot.slot,
            incarnation: self.record.incarnation,
            request,
            operation: purpose.operation(),
        }
    }
}

pub fn folder_key_id(key: &MLDSA65VerificationKey) -> Id {
    digest(b"folder-possession-id", key.as_slice())
}

/// Consume the session after a terminal response. This entry point accepts an
/// already-provisioned record and handles only the normal open operation.
pub fn serve<R: Read, W: Write, A: DurableAuthority>(
    mut session: Session<R, W>,
    releaser: &mut Releaser<A>,
    material: &ReleaseMaterial,
) -> Result<()> {
    let init_bytes = session.receive(Kind::OpenInit as u8)?;
    serve_init(session, releaser, material, &init_bytes)
}

pub fn serve_init<R: Read, W: Write, A: DurableAuthority>(
    session: Session<R, W>,
    releaser: &mut Releaser<A>,
    material: &ReleaseMaterial,
    init_bytes: &[u8],
) -> Result<()> {
    serve_init_for(
        session,
        releaser,
        material,
        init_bytes,
        OpeningPurpose::Normal,
    )
}

/// The caller selects the enrolled material for the requested purpose before
/// registering any challenge or spending any of the slot's shared allowance.
pub fn serve_init_for<R: Read, W: Write, A: DurableAuthority>(
    mut session: Session<R, W>,
    releaser: &mut Releaser<A>,
    material: &ReleaseMaterial,
    init_bytes: &[u8],
    purpose: OpeningPurpose,
) -> Result<()> {
    let init = Message::decode(init_bytes).map_err(|_| Error::InvalidMessage)?;
    let Body::OpenInit {
        client_nonce,
        reply_key_digest,
        record,
        commit_certificate: None,
    } = init.body
    else {
        return Err(Error::InvalidMessage);
    };
    let scope = &material.scope;
    if init.domain != scope.domain(init.domain.request, purpose)
        || record != scope.record_id
        || &reply_key_digest.0 != session.reply_key_digest()?
        || session.claimed_folder_key()? != &folder_key_id(&material.folder_key).0
    {
        return Err(Error::Denied);
    }
    let snapshot = releaser.snapshot().ok_or(Error::Denied)?;
    if snapshot.identity() != scope.slot || snapshot.active() != scope.record {
        return Err(Error::Denied);
    }
    let init_digest = digest(b"open-init", init_bytes);
    let server_nonce = Id(random()?);
    let challenge = Id(random()?);
    let current_time = now()?;
    let deadline = current_time.checked_add(30).ok_or(Error::Clock)?;
    let challenge_msg = Message {
        domain: init.domain,
        body: Body::OpenChallenge {
            init: init_digest,
            client_nonce,
            server_nonce,
            challenge,
            deadline,
            reply_key_digest,
        },
    };
    let challenge_bytes = challenge_msg.encode().map_err(|_| Error::InvalidMessage)?;
    let attempt = Attempt {
        domain: init.domain,
        record_manifest: scope.record.manifest,
        selected_record: record,
        challenge,
        init_digest,
        challenge_digest: digest(b"open-challenge", &challenge_bytes),
        client_nonce,
        server_nonce,
        reply_key_digest,
        deadline,
    };
    if !matches!(
        releaser.apply(Event::RegisterChallenge {
            attempt: attempt.clone(),
            now: current_time
        }),
        Ok(Outcome::ChallengeRecorded)
    ) {
        return refuse(&mut session, init.domain, init_digest, Stage::Init);
    }
    session.send(Kind::OpenChallenge as u8, &challenge_bytes)?;
    let proof = session.receive(Kind::OpenProof as u8)?;
    let [predecessor, client_proof, signature] = proof_fields(&proof)?;
    if predecessor != attempt.challenge_digest.0 {
        return Err(Error::InvalidMessage);
    }
    let transcript = transcript(&session, scope, &attempt, purpose)?;
    let signature = MLDSA65Signature::new(signature.try_into().map_err(|_| Error::InvalidMessage)?);
    if verify_possession(&material.folder_key, &transcript, &signature).is_err() {
        return refuse(
            &mut session,
            init.domain,
            digest(b"open-proof", &proof),
            Stage::Challenge,
        );
    }
    let charge = releaser.apply(Event::Charge {
        attempt,
        possession: Possession::Accepted,
        now: now()?,
    });
    if !matches!(charge, Ok(Outcome::CredentialReady(_))) {
        return refuse(
            &mut session,
            init.domain,
            digest(b"open-proof", &proof),
            Stage::Challenge,
        );
    }
    let predecessor = digest(b"open-proof", &proof);
    let Ok(mac) = material.verifier.evaluate_charged_proof(
        &transcript,
        client_proof.try_into().map_err(|_| Error::InvalidMessage)?,
    ) else {
        return refuse(&mut session, init.domain, predecessor, Stage::Challenge);
    };
    let mut result = Zeroizing::new(predecessor.0.to_vec());
    result.extend_from_slice(&mac);
    result.extend_from_slice(material.share.as_ref());
    session.send(Kind::OpenResult as u8, &result)?;
    Ok(())
}

pub fn open<R: Read, W: Write>(
    session: Session<R, W>,
    scope: &OpeningRecord,
    credential: ClientCredential,
    possession_key: &MLDSA65SigningKey,
    envelope: &Envelope,
) -> Result<Secret> {
    open_for(
        session,
        scope,
        credential,
        possession_key,
        envelope,
        OpeningPurpose::Normal,
    )
}

pub fn open_for<R: Read, W: Write>(
    mut session: Session<R, W>,
    scope: &OpeningRecord,
    credential: ClientCredential,
    possession_key: &MLDSA65SigningKey,
    envelope: &Envelope,
    purpose: OpeningPurpose,
) -> Result<Secret> {
    let domain = scope.domain(Id(random()?), purpose);
    let client_nonce = Id(random()?);
    let reply_key_digest = Id(*session.reply_key_digest()?);
    let init = Message {
        domain,
        body: Body::OpenInit {
            client_nonce,
            reply_key_digest,
            record: scope.record_id,
            commit_certificate: None,
        },
    };
    let init = init.encode().map_err(|_| Error::InvalidMessage)?;
    let init_digest = digest(b"open-init", &init);
    session.send(Kind::OpenInit as u8, &init)?;
    let challenge_bytes = response(
        &mut session,
        domain,
        init_digest,
        Stage::Init,
        Kind::OpenChallenge,
    )?;
    let challenge_msg = Message::decode(&challenge_bytes).map_err(|_| Error::InvalidMessage)?;
    let Body::OpenChallenge {
        init,
        client_nonce: echoed_nonce,
        server_nonce,
        challenge,
        deadline,
        reply_key_digest: echoed_reply,
    } = challenge_msg.body
    else {
        return Err(Error::InvalidMessage);
    };
    if challenge_msg.domain != domain
        || init != init_digest
        || echoed_nonce != client_nonce
        || echoed_reply != reply_key_digest
    {
        return Err(Error::InvalidMessage);
    }
    let attempt = Attempt {
        domain,
        record_manifest: scope.record.manifest,
        selected_record: scope.record_id,
        challenge,
        init_digest,
        challenge_digest: digest(b"open-challenge", &challenge_bytes),
        client_nonce,
        server_nonce,
        reply_key_digest,
        deadline,
    };
    let transcript = transcript(&session, scope, &attempt, purpose)?;
    let signature = sign_possession(possession_key, &transcript)?;
    let mut proof = Zeroizing::new(attempt.challenge_digest.0.to_vec());
    proof.extend_from_slice(&credential.proof(&transcript));
    proof.extend_from_slice(signature.as_slice());
    let predecessor = digest(b"open-proof", &proof);
    session.send(Kind::OpenProof as u8, &proof)?;
    let result = response(
        &mut session,
        domain,
        predecessor,
        Stage::Challenge,
        Kind::OpenResult,
    )?;
    if result.len() != 96 || result[..32] != predecessor.0 {
        return Err(Error::InvalidMessage);
    }
    let share = Secret::new(result[64..].try_into().map_err(|_| Error::InvalidMessage)?);
    Ok(credential.verify_and_unwrap(
        &scope.context_for(purpose),
        &transcript,
        result[32..64]
            .try_into()
            .map_err(|_| Error::InvalidMessage)?,
        &share,
        envelope,
    )?)
}

fn proof_fields(bytes: &[u8]) -> Result<[&[u8]; 3]> {
    if bytes.len() != 64 + MLDSA65Signature::len() {
        return Err(Error::InvalidMessage);
    }
    Ok([&bytes[..32], &bytes[32..64], &bytes[64..]])
}

fn response<R: Read, W: Write>(
    session: &mut Session<R, W>,
    domain: Domain,
    predecessor: Id,
    stage: Stage,
    expected: Kind,
) -> Result<Zeroizing<Vec<u8>>> {
    let (kind, bytes) = session.receive_message()?;
    if kind == expected as u8 {
        return Ok(bytes);
    }
    if kind == Kind::Error as u8
        && Message::decode(&bytes).is_ok_and(|message| {
            message.domain == domain
                && message.body
                    == Body::Error {
                        predecessor,
                        stage,
                        status: Status::Rejected,
                    }
        })
    {
        return Err(Error::Denied);
    }
    Err(Error::InvalidMessage)
}

fn refuse<R: Read, W: Write>(
    session: &mut Session<R, W>,
    domain: Domain,
    predecessor: Id,
    stage: Stage,
) -> Result<()> {
    let message = Message {
        domain,
        body: Body::Error {
            predecessor,
            stage,
            status: Status::Rejected,
        },
    };
    session.send(
        Kind::Error as u8,
        &message.encode().map_err(|_| Error::InvalidMessage)?,
    )?;
    Ok(())
}

fn transcript<R: Read, W: Write>(
    session: &Session<R, W>,
    scope: &OpeningRecord,
    attempt: &Attempt,
    purpose: OpeningPurpose,
) -> Result<Vec<u8>> {
    Ok(AttemptContext {
        request: attempt.domain.request.0,
        client_nonce: attempt.client_nonce.0,
        server_nonce: attempt.server_nonce.0,
        challenge: attempt.challenge.0,
        reply_key_digest: attempt.reply_key_digest.0,
        init_digest: attempt.init_digest.0,
        challenge_digest: attempt.challenge_digest.0,
        incarnation: attempt.domain.incarnation.0,
        deadline: attempt.deadline,
        channel_binding: session.binding()?,
    }
    .encode(&scope.context_for(purpose)))
}

fn digest(label: &[u8], bytes: &[u8]) -> Id {
    let mut hash = Sha256::new();
    hash.update(b"sivault/controlled/open/v1\0");
    hash.update(label);
    hash.update([0]);
    hash.update(bytes);
    Id(hash.finalize().into())
}

fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| Error::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_and_normal_openings_bind_distinct_domains_and_wraps() {
        let scope = OpeningRecord {
            slot: SlotIdentity {
                suite: 1,
                network: Id([1; 32]),
                safe: Id([2; 32]),
                slot: Id([3; 32]),
                ledger: Id([4; 32]),
            },
            record: Record {
                generation: 1,
                incarnation: Id([5; 32]),
                manifest: Id([6; 32]),
                root: Id([7; 32]),
            },
            record_id: Id([8; 32]),
            salt: Id([9; 32]),
        };
        let request = Id([10; 32]);
        let normal = scope.domain(request, OpeningPurpose::Normal);
        let recovery = scope.domain(request, OpeningPurpose::Recovery);
        assert_eq!(
            recovery,
            Domain {
                operation: Operation::Recovery,
                ..normal
            }
        );
        let normal = scope.context();
        let recovery = scope.context_for(OpeningPurpose::Recovery);
        assert_ne!(normal.encode(), recovery.encode());
        let folder = Secret::new([11; 32]);
        let share = Secret::new([12; 32]);
        let key = Secret::new([13; 32]);
        let password = "synthetic test input";
        let a = ClientCredential::new(password, &folder, &normal).unwrap();
        let b = ClientCredential::new(password, &folder, &recovery).unwrap();
        let transcript = b"synthetic attempt";
        let envelope = a.wrap(&normal, &share, &key).unwrap();
        let verifier = a.enrollment_verifier();
        assert!(
            verifier
                .evaluate_charged_proof(transcript, &b.proof(transcript))
                .is_err()
        );
        let mac = verifier
            .evaluate_charged_proof(transcript, &a.proof(transcript))
            .unwrap();
        assert!(
            b.verify_and_unwrap(&recovery, transcript, &mac, &share, &envelope)
                .is_err()
        );
    }
}
