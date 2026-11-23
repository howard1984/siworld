//! File-backed ledger with an independently stored restore-detection marker.
//! The journal contains admission metadata, not credentials or shares.

use std::{
    fs::{File, OpenOptions, TryLockError},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ledger::{
        Attempt, AuthorityError, DurableAuthority, Event, Ledger, Possession, Record, SlotIdentity,
        Transition,
    },
    message::{Id, Message},
};

#[cfg(any(target_os = "macos", windows))]
pub mod platform;

type Result<T> = std::result::Result<T, AuthorityError>;
const MAGIC: &[u8; 5] = b"SVLJ\x01";
const MAX_ENTRY: usize = 24 * 1024;
const MAX_FILE: u64 = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub instance: Id,
    pub head: Id,
}

/// A production adapter must persist the checkpoint in a platform credential
/// store outside the ordinary journal backup. A missing value is not an
/// enrollment invitation. Compare-and-store must reject a changed value and
/// report any uncertain outcome as an error.
pub trait MarkerStore {
    fn load(&mut self, slot: SlotIdentity) -> Result<Option<Checkpoint>>;
    fn compare_and_store(
        &mut self,
        slot: SlotIdentity,
        expected: Option<Checkpoint>,
        next: Checkpoint,
    ) -> Result<()>;
}

#[derive(Deserialize, Serialize)]
struct Header {
    slot: SlotIdentity,
    instance: Id,
    allowance: u64,
    record: Record,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    material: Option<Id>,
}

#[derive(Deserialize, Serialize)]
enum Entry {
    Challenge {
        attempt: Attempt,
        now: u64,
    },
    Charge {
        attempt: Attempt,
        now: u64,
    },
    Owner {
        message: Vec<u8>,
        digest: Id,
        now: u64,
    },
    Deletion {
        generation: u64,
        incarnation: Id,
        tombstone: Id,
    },
}

impl Entry {
    fn from_event(event: &Event) -> Result<Self> {
        Ok(match event {
            Event::RegisterChallenge { attempt, now } => Self::Challenge {
                attempt: attempt.clone(),
                now: *now,
            },
            Event::Charge {
                attempt,
                possession: Possession::Accepted,
                now,
            } => Self::Charge {
                attempt: attempt.clone(),
                now: *now,
            },
            Event::Charge { .. } => return Err(AuthorityError::InvalidEvidence),
            Event::Owner {
                message,
                digest,
                now,
            } => Self::Owner {
                message: message
                    .encode()
                    .map_err(|_| AuthorityError::InvalidEvidence)?,
                digest: *digest,
                now: *now,
            },
            Event::ConfirmDeletion {
                generation,
                incarnation,
                tombstone,
            } => Self::Deletion {
                generation: *generation,
                incarnation: *incarnation,
                tombstone: *tombstone,
            },
        })
    }

    fn into_event(self) -> Result<Event> {
        Ok(match self {
            Self::Challenge { attempt, now } => Event::RegisterChallenge { attempt, now },
            Self::Charge { attempt, now } => Event::Charge {
                attempt,
                possession: Possession::Accepted,
                now,
            },
            Self::Owner {
                message,
                digest,
                now,
            } => Event::Owner {
                message: Box::new(
                    Message::decode(&message).map_err(|_| AuthorityError::InvalidEvidence)?,
                ),
                digest,
                now,
            },
            Self::Deletion {
                generation,
                incarnation,
                tombstone,
            } => Event::ConfirmDeletion {
                generation,
                incarnation,
                tombstone,
            },
        })
    }
}

pub struct Journal<M> {
    file: File,
    marker: M,
    current: Ledger,
    checkpoint: Checkpoint,
    len: u64,
    poisoned: bool,
    material: Option<Id>,
}

impl<M: MarkerStore> Journal<M> {
    pub(crate) fn protected_head(&self) -> Id {
        self.checkpoint.head
    }

    /// Provision only after authenticated enrollment and local acceptance.
    /// The caller supplies a freshly generated random instance identifier.
    pub fn provision(
        path: &Path,
        marker: M,
        slot: SlotIdentity,
        instance: Id,
        allowance: u64,
        record: Record,
    ) -> Result<Self> {
        Self::provision_inner(path, marker, slot, instance, allowance, record, None)
    }

    pub(crate) fn provision_material(
        path: &Path,
        marker: M,
        slot: SlotIdentity,
        instance: Id,
        allowance: u64,
        record: Record,
        material: Id,
    ) -> Result<Self> {
        Self::provision_inner(
            path,
            marker,
            slot,
            instance,
            allowance,
            record,
            Some(material),
        )
    }

    fn provision_inner(
        path: &Path,
        mut marker: M,
        slot: SlotIdentity,
        instance: Id,
        allowance: u64,
        record: Record,
        material: Option<Id>,
    ) -> Result<Self> {
        if instance == Id::default() || marker.load(slot)?.is_some() {
            return Err(AuthorityError::InvalidEvidence);
        }
        let mut file = locked(path, true)?;
        let header = encode(&Header {
            slot,
            instance,
            allowance,
            record,
            material,
        })?;
        let checkpoint = Checkpoint {
            instance,
            head: head(Id::default(), &header),
        };
        file.write_all(MAGIC)
            .and_then(|()| file.write_all(&header))
            .and_then(|()| file.sync_all())
            .map_err(|_| AuthorityError::Unavailable)?;
        marker.compare_and_store(slot, None, checkpoint)?;
        Ok(Self {
            file,
            marker,
            current: Ledger::enrollment(slot, allowance, record),
            checkpoint,
            len: (MAGIC.len() + header.len()) as u64,
            poisoned: false,
            material,
        })
    }

    pub fn open(path: &Path, mut marker: M, slot: SlotIdentity) -> Result<Self> {
        let mut file = locked(path, false)?;
        let checkpoint = marker.load(slot)?.ok_or(AuthorityError::InvalidEvidence)?;
        let len = file
            .metadata()
            .map_err(|_| AuthorityError::Unavailable)?
            .len();
        if len > MAX_FILE {
            return Err(AuthorityError::InvalidEvidence);
        }
        let mut magic = [0; MAGIC.len()];
        file.read_exact(&mut magic)
            .map_err(|_| AuthorityError::InvalidEvidence)?;
        if &magic != MAGIC {
            return Err(AuthorityError::InvalidEvidence);
        }
        let mut position = MAGIC.len() as u64;
        let bytes = read_entry(&mut file, &mut position, len)?;
        let header: Header = decode(&bytes)?;
        if header.slot != slot || header.instance != checkpoint.instance {
            return Err(AuthorityError::InvalidEvidence);
        }
        let mut current = Ledger::enrollment(slot, header.allowance, header.record);
        let mut digest = head(Id::default(), &bytes);
        while position < len {
            let bytes = read_entry(&mut file, &mut position, len)?;
            digest = head(digest, &bytes);
            let next = current
                .transition(decode::<Entry>(&bytes)?.into_event()?)
                .map_err(|_| AuthorityError::InvalidEvidence)?;
            if next.next().revision() <= current.revision() {
                return Err(AuthorityError::InvalidEvidence);
            }
            current = next.next().clone();
        }
        if digest != checkpoint.head {
            return Err(AuthorityError::InvalidEvidence);
        }
        Ok(Self {
            file,
            marker,
            current,
            checkpoint,
            len,
            poisoned: false,
            material: header.material,
        })
    }

    pub(crate) fn require_material(&self, digest: Id) -> Result<()> {
        if self.material == Some(digest) {
            Ok(())
        } else {
            Err(AuthorityError::InvalidEvidence)
        }
    }

    fn check_current(&mut self, slot: SlotIdentity) -> Result<()> {
        if self.poisoned || slot != self.current.identity() {
            return Err(AuthorityError::InvalidEvidence);
        }
        self.poisoned = true;
        if self.marker.load(slot)? != Some(self.checkpoint)
            || self
                .file
                .metadata()
                .map_err(|_| AuthorityError::Unavailable)?
                .len()
                != self.len
        {
            return Err(AuthorityError::InvalidEvidence);
        }
        self.poisoned = false;
        Ok(())
    }
}

impl<M: MarkerStore> DurableAuthority for Journal<M> {
    fn recover_exclusive(&mut self, slot: SlotIdentity) -> Result<Ledger> {
        self.check_current(slot)?;
        Ok(self.current.clone())
    }

    fn commit(&mut self, expected: &Ledger, transition: &Transition) -> Result<()> {
        let slot = expected.identity();
        self.check_current(slot)?;
        if &self.current != expected {
            return Err(AuthorityError::Stale);
        }
        let verified = expected
            .transition(transition.event().clone())
            .map_err(|_| AuthorityError::InvalidEvidence)?;
        if &verified != transition {
            return Err(AuthorityError::InvalidEvidence);
        }
        if transition.next() == expected {
            return Ok(());
        }
        let entry = encode(&Entry::from_event(transition.event())?)?;
        let len = self.len + entry.len() as u64;
        if len > MAX_FILE {
            return Err(AuthorityError::Unavailable);
        }
        let next = Checkpoint {
            instance: self.checkpoint.instance,
            head: head(self.checkpoint.head, &entry),
        };
        // A failure between the two writes intentionally leaves the slot
        // unavailable. Do not truncate the journal or restore the old marker.
        self.poisoned = true;
        self.file
            .seek(SeekFrom::Start(self.len))
            .and_then(|_| self.file.write_all(&entry))
            .and_then(|()| self.file.sync_all())
            .map_err(|_| AuthorityError::Unavailable)?;
        self.marker
            .compare_and_store(slot, Some(self.checkpoint), next)?;
        self.checkpoint = next;
        self.current = transition.next().clone();
        self.len = len;
        self.poisoned = false;
        Ok(())
    }
}

fn locked(path: &Path, create: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .open(path)
        .map_err(|_| AuthorityError::Unavailable)?;
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => AuthorityError::NotExclusive,
        TryLockError::Error(_) => AuthorityError::Unavailable,
    })?;
    Ok(file)
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(value).map_err(|_| AuthorityError::InvalidEvidence)?;
    if body.is_empty() || body.len() > MAX_ENTRY {
        return Err(AuthorityError::InvalidEvidence);
    }
    let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(&bytes[4..]).map_err(|_| AuthorityError::InvalidEvidence)
}

fn read_entry(file: &mut File, position: &mut u64, end: u64) -> Result<Vec<u8>> {
    let mut prefix = [0; 4];
    file.read_exact(&mut prefix)
        .map_err(|_| AuthorityError::InvalidEvidence)?;
    let len = u32::from_be_bytes(prefix) as usize;
    if !(1..=MAX_ENTRY).contains(&len) || *position + 4 + len as u64 > end {
        return Err(AuthorityError::InvalidEvidence);
    }
    let mut bytes = prefix.to_vec();
    bytes.resize(4 + len, 0);
    file.read_exact(&mut bytes[4..])
        .map_err(|_| AuthorityError::InvalidEvidence)?;
    *position += bytes.len() as u64;
    Ok(bytes)
}

fn head(previous: Id, bytes: &[u8]) -> Id {
    let mut hash = Sha256::new();
    hash.update(b"sivault/ledger-journal/v1\0");
    hash.update(previous.0);
    hash.update(bytes);
    Id(hash.finalize().into())
}
