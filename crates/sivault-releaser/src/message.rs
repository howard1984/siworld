//! Canonical noncredential metadata encoding, version 1.
//!
//! This is a local metadata format, not the approved cryptographic wire suite.
//! All integers are big endian. The fixed common transcript is followed by a
//! u32-length-delimited typed body. Field order is fixed; there are no extension
//! fields. Unknown tags, trailing bytes, and noncanonical options are rejected.
//! Digests are opaque, externally computed values; no cryptography is performed.

pub const VERSION: u16 = 1;
pub const MAX_MESSAGE_BYTES: usize = 4096;
pub const MAX_SHARE_IDS: usize = 64;
const MAGIC: &[u8; 4] = b"SVMN";

/// A fixed-width, opaque identifier or externally computed digest.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(
    not(target_arch = "wasm32"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Id(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(target_arch = "wasm32"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum Operation {
    Normal = 1,
    Recovery = 2,
    Decoy = 3,
    Owner = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(target_arch = "wasm32"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Domain {
    pub suite: u16,
    pub network: Id,
    pub safe: Id,
    pub generation: u64,
    pub slot: Id,
    pub incarnation: Id,
    pub request: Id,
    pub operation: Operation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    Enroll = 1,
    EnrollAck = 2,
    OpenInit = 3,
    OpenChallenge = 4,
    OpenProof = 5,
    OpenResult = 6,
    Error = 7,
    Refill = 8,
    Prepare = 9,
    Commit = 10,
    Retire = 11,
    Delete = 12,
    RestoreService = 13,
    CommandAck = 14,
    Revoke = 15,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    pub domain: Domain,
    pub body: Body,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Body {
    /// Metadata only; no record, verifier, share, or signature bytes.
    Enroll {
        owner_key: Id,
        manifest: Id,
        releaser_key: Id,
        ledger: Id,
        allowance: u64,
        record_manifest: Id,
        expiry: u64,
    },
    EnrollAck {
        enroll: Id,
        releaser_key: Id,
        ledger: Id,
        durable_record: Id,
        status: Status,
    },
    OpenInit {
        client_nonce: Id,
        reply_key_digest: Id,
        record: Id,
        commit_certificate: Option<Id>,
    },
    OpenChallenge {
        init: Id,
        client_nonce: Id,
        server_nonce: Id,
        challenge: Id,
        deadline: u64,
        reply_key_digest: Id,
    },
    Owner {
        meta: Box<OwnerMeta>,
        action: Action,
    },
    CommandAck {
        command: Id,
        protected_state: Id,
        ledger_head: Id,
        applied_counter: u64,
        phase: AckPhase,
        status: Status,
    },
    Error {
        predecessor: Id,
        stage: Stage,
        status: Status,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerMeta {
    pub owner_key: Id,
    pub counter: u64,
    pub command: Id,
    pub predecessor: Id,
    pub manifest: Id,
    pub expiry: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Revoke {
        ledger: Id,
        record: Id,
    },
    Refill {
        ledger: Id,
        delta: u64,
        expected_total: u64,
        new_total: u64,
    },
    Prepare {
        rotation: Id,
        old_root: Id,
        next_generation: u64,
        next_manifest: Id,
        next_root: Id,
        expected_head: Id,
        successor_record: Id,
        successor_incarnation: Id,
    },
    Commit {
        rotation: Id,
        old_root: Id,
        next_root: Id,
        receipts: Id,
        certificate: Id,
    },
    Retire {
        rotation: Id,
        old_root: Id,
        next_root: Id,
        certificate: Id,
    },
    Delete {
        rotation: Id,
        retired_record: Id,
        expected_fence: Id,
        share_ids: Vec<Id>,
    },
    RestoreService {
        ledger: Id,
        expected_head: Id,
        exact_record: Id,
        expected_tombstone: Id,
        target_incarnation: Id,
        witness: Id,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Status {
    Accepted = 1,
    Unavailable = 2,
    Rejected = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Stage {
    Enrollment = 1,
    Init = 2,
    Challenge = 3,
    Owner = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AckPhase {
    Active = 1,
    Prepared = 2,
    Fenced = 3,
    DeletionPending = 4,
    Deleted = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    TooLarge,
    Truncated,
    InvalidMagic,
    UnsupportedVersion,
    UnknownTag,
    CredentialMessageUnsupported,
    InvalidDomain,
    Noncanonical,
}

impl Body {
    pub fn kind(&self) -> Kind {
        match self {
            Self::Enroll { .. } => Kind::Enroll,
            Self::EnrollAck { .. } => Kind::EnrollAck,
            Self::OpenInit { .. } => Kind::OpenInit,
            Self::OpenChallenge { .. } => Kind::OpenChallenge,
            Self::Owner { action, .. } => action.kind(),
            Self::CommandAck { .. } => Kind::CommandAck,
            Self::Error { .. } => Kind::Error,
        }
    }
}

impl Action {
    pub fn kind(&self) -> Kind {
        match self {
            Self::Revoke { .. } => Kind::Revoke,
            Self::Refill { .. } => Kind::Refill,
            Self::Prepare { .. } => Kind::Prepare,
            Self::Commit { .. } => Kind::Commit,
            Self::Retire { .. } => Kind::Retire,
            Self::Delete { .. } => Kind::Delete,
            Self::RestoreService { .. } => Kind::RestoreService,
        }
    }
}

impl Message {
    pub fn validate(&self) -> Result<(), CodecError> {
        let owner = matches!(
            self.body,
            Body::Enroll { .. }
                | Body::EnrollAck { .. }
                | Body::Owner { .. }
                | Body::CommandAck { .. }
        );
        let open = matches!(
            self.body,
            Body::OpenInit { .. } | Body::OpenChallenge { .. }
        );
        if (owner && self.domain.operation != Operation::Owner)
            || (open && self.domain.operation == Operation::Owner)
        {
            return Err(CodecError::InvalidDomain);
        }
        if let Body::Owner {
            action: Action::Delete { share_ids, .. },
            ..
        } = &self.body
            && (share_ids.is_empty()
                || share_ids.len() > MAX_SHARE_IDS
                || share_ids.windows(2).any(|w| w[0] >= w[1]))
        {
            return Err(CodecError::Noncanonical);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut w = Writer(Vec::new());
        w.0.extend_from_slice(MAGIC);
        w.u16(self.domain.suite);
        w.u16(VERSION);
        w.id(self.domain.network);
        w.u8(self.body.kind() as u8);
        w.u8(self.domain.operation as u8);
        w.id(self.domain.safe);
        w.u64(self.domain.generation);
        w.id(self.domain.slot);
        w.id(self.domain.incarnation);
        w.id(self.domain.request);
        let mut b = Writer(Vec::new());
        self.body.write(&mut b);
        w.u32(b.0.len() as u32);
        w.0.extend_from_slice(&b.0);
        if w.0.len() > MAX_MESSAGE_BYTES {
            return Err(CodecError::TooLarge);
        }
        Ok(w.0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(CodecError::TooLarge);
        }
        let mut r = Reader(bytes);
        if r.take(4)? != MAGIC {
            return Err(CodecError::InvalidMagic);
        }
        let suite = r.u16()?;
        if r.u16()? != VERSION {
            return Err(CodecError::UnsupportedVersion);
        }
        let network = r.id()?;
        let kind = r.kind()?;
        let operation = r.operation()?;
        let domain = Domain {
            suite,
            network,
            operation,
            safe: r.id()?,
            generation: r.u64()?,
            slot: r.id()?,
            incarnation: r.id()?,
            request: r.id()?,
        };
        let len = r.u32()? as usize;
        let mut body = Reader(r.take(len)?);
        r.end()?;
        let result = Self {
            domain,
            body: Body::read(kind, &mut body)?,
        };
        body.end()?;
        result.validate()?;
        Ok(result)
    }
}

impl Body {
    fn write(&self, w: &mut Writer) {
        match self {
            Self::Enroll {
                owner_key,
                manifest,
                releaser_key,
                ledger,
                allowance,
                record_manifest,
                expiry,
            } => {
                w.ids(&[*owner_key, *manifest, *releaser_key, *ledger]);
                w.u64(*allowance);
                w.id(*record_manifest);
                w.u64(*expiry);
            }
            Self::EnrollAck {
                enroll,
                releaser_key,
                ledger,
                durable_record,
                status,
            } => {
                w.ids(&[*enroll, *releaser_key, *ledger, *durable_record]);
                w.u8(*status as u8);
            }
            Self::OpenInit {
                client_nonce,
                reply_key_digest,
                record,
                commit_certificate,
            } => {
                w.ids(&[*client_nonce, *reply_key_digest, *record]);
                w.option(*commit_certificate);
            }
            Self::OpenChallenge {
                init,
                client_nonce,
                server_nonce,
                challenge,
                deadline,
                reply_key_digest,
            } => {
                w.ids(&[*init, *client_nonce, *server_nonce, *challenge]);
                w.u64(*deadline);
                w.id(*reply_key_digest);
            }
            Self::Owner { meta, action } => {
                w.id(meta.owner_key);
                w.u64(meta.counter);
                w.ids(&[meta.command, meta.predecessor, meta.manifest]);
                w.u64(meta.expiry);
                match action {
                    Action::Revoke { ledger, record } => w.ids(&[*ledger, *record]),
                    Action::Refill {
                        ledger,
                        delta,
                        expected_total,
                        new_total,
                    } => {
                        w.id(*ledger);
                        w.u64(*delta);
                        w.u64(*expected_total);
                        w.u64(*new_total);
                    }
                    Action::Prepare {
                        rotation,
                        old_root,
                        next_generation,
                        next_manifest,
                        next_root,
                        expected_head,
                        successor_record,
                        successor_incarnation,
                    } => {
                        w.ids(&[*rotation, *old_root]);
                        w.u64(*next_generation);
                        w.ids(&[
                            *next_manifest,
                            *next_root,
                            *expected_head,
                            *successor_record,
                            *successor_incarnation,
                        ]);
                    }
                    Action::Commit {
                        rotation,
                        old_root,
                        next_root,
                        receipts,
                        certificate,
                    } => {
                        w.ids(&[*rotation, *old_root, *next_root, *receipts, *certificate]);
                    }
                    Action::Retire {
                        rotation,
                        old_root,
                        next_root,
                        certificate,
                    } => {
                        w.ids(&[*rotation, *old_root, *next_root, *certificate]);
                    }
                    Action::Delete {
                        rotation,
                        retired_record,
                        expected_fence,
                        share_ids,
                    } => {
                        w.ids(&[*rotation, *retired_record, *expected_fence]);
                        w.u16(share_ids.len() as u16);
                        w.ids(share_ids);
                    }
                    Action::RestoreService {
                        ledger,
                        expected_head,
                        exact_record,
                        expected_tombstone,
                        target_incarnation,
                        witness,
                    } => {
                        w.ids(&[
                            *ledger,
                            *expected_head,
                            *exact_record,
                            *expected_tombstone,
                            *target_incarnation,
                            *witness,
                        ]);
                    }
                }
            }
            Self::CommandAck {
                command,
                protected_state,
                ledger_head,
                applied_counter,
                phase,
                status,
            } => {
                w.ids(&[*command, *protected_state, *ledger_head]);
                w.u64(*applied_counter);
                w.u8(*phase as u8);
                w.u8(*status as u8);
            }
            Self::Error {
                predecessor,
                stage,
                status,
            } => {
                w.id(*predecessor);
                w.u8(*stage as u8);
                w.u8(*status as u8);
            }
        }
    }

    fn read(kind: Kind, r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(match kind {
            Kind::Enroll => Self::Enroll {
                owner_key: r.id()?,
                manifest: r.id()?,
                releaser_key: r.id()?,
                ledger: r.id()?,
                allowance: r.u64()?,
                record_manifest: r.id()?,
                expiry: r.u64()?,
            },
            Kind::EnrollAck => Self::EnrollAck {
                enroll: r.id()?,
                releaser_key: r.id()?,
                ledger: r.id()?,
                durable_record: r.id()?,
                status: r.status()?,
            },
            Kind::OpenInit => Self::OpenInit {
                client_nonce: r.id()?,
                reply_key_digest: r.id()?,
                record: r.id()?,
                commit_certificate: r.option()?,
            },
            Kind::OpenChallenge => Self::OpenChallenge {
                init: r.id()?,
                client_nonce: r.id()?,
                server_nonce: r.id()?,
                challenge: r.id()?,
                deadline: r.u64()?,
                reply_key_digest: r.id()?,
            },
            Kind::CommandAck => Self::CommandAck {
                command: r.id()?,
                protected_state: r.id()?,
                ledger_head: r.id()?,
                applied_counter: r.u64()?,
                phase: r.phase()?,
                status: r.status()?,
            },
            Kind::Error => Self::Error {
                predecessor: r.id()?,
                stage: r.stage()?,
                status: r.status()?,
            },
            Kind::OpenProof | Kind::OpenResult => {
                return Err(CodecError::CredentialMessageUnsupported);
            }
            Kind::Refill
            | Kind::Prepare
            | Kind::Commit
            | Kind::Retire
            | Kind::Delete
            | Kind::Revoke
            | Kind::RestoreService => {
                let meta = OwnerMeta {
                    owner_key: r.id()?,
                    counter: r.u64()?,
                    command: r.id()?,
                    predecessor: r.id()?,
                    manifest: r.id()?,
                    expiry: r.u64()?,
                };
                let action = match kind {
                    Kind::Revoke => Action::Revoke {
                        ledger: r.id()?,
                        record: r.id()?,
                    },
                    Kind::Refill => Action::Refill {
                        ledger: r.id()?,
                        delta: r.u64()?,
                        expected_total: r.u64()?,
                        new_total: r.u64()?,
                    },
                    Kind::Prepare => Action::Prepare {
                        rotation: r.id()?,
                        old_root: r.id()?,
                        next_generation: r.u64()?,
                        next_manifest: r.id()?,
                        next_root: r.id()?,
                        expected_head: r.id()?,
                        successor_record: r.id()?,
                        successor_incarnation: r.id()?,
                    },
                    Kind::Commit => Action::Commit {
                        rotation: r.id()?,
                        old_root: r.id()?,
                        next_root: r.id()?,
                        receipts: r.id()?,
                        certificate: r.id()?,
                    },
                    Kind::Retire => Action::Retire {
                        rotation: r.id()?,
                        old_root: r.id()?,
                        next_root: r.id()?,
                        certificate: r.id()?,
                    },
                    Kind::Delete => {
                        let rotation = r.id()?;
                        let retired_record = r.id()?;
                        let expected_fence = r.id()?;
                        let count = r.u16()? as usize;
                        if count == 0 || count > MAX_SHARE_IDS {
                            return Err(CodecError::Noncanonical);
                        }
                        let share_ids =
                            (0..count).map(|_| r.id()).collect::<Result<Vec<_>, _>>()?;
                        Action::Delete {
                            rotation,
                            retired_record,
                            expected_fence,
                            share_ids,
                        }
                    }
                    Kind::RestoreService => Action::RestoreService {
                        ledger: r.id()?,
                        expected_head: r.id()?,
                        exact_record: r.id()?,
                        expected_tombstone: r.id()?,
                        target_incarnation: r.id()?,
                        witness: r.id()?,
                    },
                    _ => return Err(CodecError::UnknownTag),
                };
                Self::Owner {
                    meta: Box::new(meta),
                    action,
                }
            }
        })
    }
}

struct Writer(Vec<u8>);
impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn id(&mut self, v: Id) {
        self.0.extend_from_slice(&v.0);
    }
    fn ids(&mut self, ids: &[Id]) {
        for id in ids {
            self.id(*id);
        }
    }
    fn option(&mut self, v: Option<Id>) {
        self.u8(u8::from(v.is_some()));
        if let Some(id) = v {
            self.id(id);
        }
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let (head, tail) = self.0.split_at_checked(len).ok_or(CodecError::Truncated)?;
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.take(N)?.try_into().map_err(|_| CodecError::Truncated)
    }
    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn id(&mut self) -> Result<Id, CodecError> {
        Ok(Id(self.array()?))
    }
    fn option(&mut self) -> Result<Option<Id>, CodecError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.id()?)),
            _ => Err(CodecError::Noncanonical),
        }
    }
    fn end(&self) -> Result<(), CodecError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(CodecError::Noncanonical)
        }
    }
    fn operation(&mut self) -> Result<Operation, CodecError> {
        match self.u8()? {
            1 => Ok(Operation::Normal),
            2 => Ok(Operation::Recovery),
            3 => Ok(Operation::Decoy),
            4 => Ok(Operation::Owner),
            _ => Err(CodecError::UnknownTag),
        }
    }
    fn kind(&mut self) -> Result<Kind, CodecError> {
        match self.u8()? {
            1 => Ok(Kind::Enroll),
            2 => Ok(Kind::EnrollAck),
            3 => Ok(Kind::OpenInit),
            4 => Ok(Kind::OpenChallenge),
            5 | 6 => Err(CodecError::CredentialMessageUnsupported),
            7 => Ok(Kind::Error),
            8 => Ok(Kind::Refill),
            9 => Ok(Kind::Prepare),
            10 => Ok(Kind::Commit),
            11 => Ok(Kind::Retire),
            12 => Ok(Kind::Delete),
            13 => Ok(Kind::RestoreService),
            14 => Ok(Kind::CommandAck),
            15 => Ok(Kind::Revoke),
            _ => Err(CodecError::UnknownTag),
        }
    }
    fn status(&mut self) -> Result<Status, CodecError> {
        match self.u8()? {
            1 => Ok(Status::Accepted),
            2 => Ok(Status::Unavailable),
            3 => Ok(Status::Rejected),
            _ => Err(CodecError::UnknownTag),
        }
    }
    fn phase(&mut self) -> Result<AckPhase, CodecError> {
        match self.u8()? {
            1 => Ok(AckPhase::Active),
            2 => Ok(AckPhase::Prepared),
            3 => Ok(AckPhase::Fenced),
            4 => Ok(AckPhase::DeletionPending),
            5 => Ok(AckPhase::Deleted),
            _ => Err(CodecError::UnknownTag),
        }
    }
    fn stage(&mut self) -> Result<Stage, CodecError> {
        match self.u8()? {
            1 => Ok(Stage::Enrollment),
            2 => Ok(Stage::Init),
            3 => Ok(Stage::Challenge),
            4 => Ok(Stage::Owner),
            _ => Err(CodecError::UnknownTag),
        }
    }
}
