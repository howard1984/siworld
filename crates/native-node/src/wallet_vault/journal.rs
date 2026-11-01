//! Bounded encrypted payment reservations. Metadata is private wallet data.
use super::{RecoveryMaterial, storage};
use crate::audit::{AuditReport, replay_chain};
use crate::state::{BlockVerifier, Config};
use crate::wire::{
    Block, DigestBytes, Hash, MAX_ENVELOPE_BYTES, PublicRecord, SIDECAR_BYTES, Sidecar, Transaction,
};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use native::codec::{PublicTransaction, encode_digest};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"SWNJRN01";
const HEADER: usize = 8 + 24;
const MAX_ENTRIES: usize = 32;
const MAX_OPENING: usize = 65_536;
const MAX_PLAINTEXT: usize = 8 * 1024 * 1024;
pub(super) const MAX_FILE: usize = HEADER + MAX_PLAINTEXT + 16;

/// A local status, not proof of finality or permission to release inputs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PaymentStatus {
    Reserved,
    Prepared,
    Submitted,
    Accepted,
    Conflicted,
    Orphaned,
}
impl PaymentStatus {
    fn encode(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::Prepared => 1,
            Self::Submitted => 2,
            Self::Accepted => 3,
            Self::Conflicted => 4,
            Self::Orphaned => 5,
        }
    }
    fn decode(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(Self::Reserved),
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Submitted),
            3 => Ok(Self::Accepted),
            4 => Ok(Self::Conflicted),
            5 => Ok(Self::Orphaned),
            _ => Err("invalid payment journal status".into()),
        }
    }
}

/// Durable pre-proof reservation capability; fields cannot be forged by a UI.
pub struct ReservedPayment {
    id: Hash,
    context: Hash,
}
impl ReservedPayment {
    pub fn id(&self) -> Hash {
        self.id
    }
}

/// Exact protected relay material. It has no formatting or serialization traits.
pub struct PaymentPacket {
    network: Hash,
    envelope: Zeroizing<Vec<u8>>,
    sidecar: Zeroizing<[u8; SIDECAR_BYTES]>,
    opening: Zeroizing<Vec<u8>>,
}
impl PaymentPacket {
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
    pub fn opening(&self) -> &[u8] {
        &self.opening
    }
    pub fn transaction(&self) -> Result<Transaction, String> {
        Transaction::decode_envelope(&self.envelope, &self.network)
    }
    pub fn sidecar(&self) -> Result<Sidecar, String> {
        Sidecar::decode(self.sidecar.as_ref())
    }
    fn duplicate(&self) -> Self {
        Self {
            network: self.network,
            envelope: Zeroizing::new(self.envelope.to_vec()),
            sidecar: Zeroizing::new(*self.sidecar),
            opening: Zeroizing::new(self.opening.to_vec()),
        }
    }
    fn same(&self, other: &Self) -> bool {
        self.network == other.network
            && self.envelope.as_slice() == other.envelope.as_slice()
            && self.sidecar.as_ref() == other.sidecar.as_ref()
            && self.opening.as_slice() == other.opening.as_slice()
    }
}
struct Entry {
    nullifiers: [DigestBytes; 2],
    status: PaymentStatus,
    packet: Option<PaymentPacket>,
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.nullifiers.zeroize();
    }
}
impl Entry {
    fn duplicate(&self) -> Self {
        Self {
            nullifiers: self.nullifiers,
            status: self.status,
            packet: self.packet.as_ref().map(PaymentPacket::duplicate),
        }
    }
}

pub(super) struct Journal {
    key: Zeroizing<[u8; 32]>,
    network: Hash,
    context: Hash,
    generation: u64,
    ciphertext_hash: Hash,
    entries: BTreeMap<Hash, Entry>,
    poisoned: Cell<bool>,
}
impl Journal {
    fn empty(material: &RecoveryMaterial) -> Self {
        let mut hash = Zeroizing::new(blake3::Hasher::new_derive_key(
            "siworld native wallet payment journal key v1",
        ));
        hash.update(material.entropy.as_ref());
        hash.update(&material.network);
        hash.update(&material.account.to_le_bytes());
        let key = Zeroizing::new(*hash.finalize().as_bytes());
        let mut context = Zeroizing::new(blake3::Hasher::new_derive_key(
            "siworld native wallet payment journal context v1",
        ));
        context.update(material.entropy.as_ref());
        context.update(&material.network);
        context.update(&material.account.to_le_bytes());
        Self {
            key,
            network: material.network,
            context: *context.finalize().as_bytes(),
            generation: 0,
            ciphertext_hash: [0; 32],
            entries: BTreeMap::new(),
            poisoned: Cell::new(false),
        }
    }
    pub(super) fn create(
        owner: &storage::Directory,
        material: &RecoveryMaterial,
    ) -> Result<Self, String> {
        let mut journal = Self::empty(material);
        let encoded = journal.encode(&journal.entries, 0)?;
        owner.create_journal(&encoded)?;
        journal.ciphertext_hash = *blake3::hash(&encoded).as_bytes();
        Ok(journal)
    }
    pub(super) fn load(
        owner: &storage::Directory,
        material: &RecoveryMaterial,
    ) -> Result<Self, String> {
        let encoded = owner.read_journal()?;
        let mut journal = Self::empty(material);
        journal.ciphertext_hash = *blake3::hash(&encoded).as_bytes();
        if !(HEADER + 16..=MAX_FILE).contains(&encoded.len()) || &encoded[..8] != MAGIC {
            return Err("unsupported or malformed payment journal".into());
        }
        let cipher = XChaCha20Poly1305::new(
            <&Key>::try_from(journal.key.as_ref()).expect("fixed journal key width"),
        );
        let mut plaintext = Zeroizing::new(encoded[HEADER..encoded.len() - 16].to_vec());
        cipher
            .decrypt_inout_detached(
                <&XNonce>::try_from(&encoded[8..HEADER]).expect("fixed journal nonce width"),
                &journal.aad(&encoded[..HEADER]),
                plaintext.as_mut_slice().into(),
                <&Tag>::try_from(&encoded[encoded.len() - 16..]).expect("fixed journal tag width"),
            )
            .map_err(|_| "payment journal authentication failed")?;
        let mut reader = Reader {
            bytes: &plaintext,
            offset: 0,
        };
        journal.generation = reader.u64()?;
        let count = reader.u32()? as usize;
        if count > MAX_ENTRIES {
            return Err("payment journal entry limit".into());
        }
        let mut previous = None;
        let mut inputs = BTreeSet::new();
        for _ in 0..count {
            let id: Hash = reader.take(32)?.try_into().expect("fixed payment ID width");
            if previous.is_some_and(|old| old >= id) {
                return Err("payment journal IDs are not canonical".into());
            }
            previous = Some(id);
            let nullifiers = [
                reader.take(48)?.try_into().expect("fixed nullifier width"),
                reader.take(48)?.try_into().expect("fixed nullifier width"),
            ];
            for nf in &nullifiers {
                let _ = native::codec::decode_digest(nf)
                    .map_err(|_| "noncanonical journal nullifier")?;
                if !inputs.insert(*nf) {
                    return Err("payment journal has repeated input reservations".into());
                }
            }
            let status = PaymentStatus::decode(reader.take(1)?[0])?;
            let packet = match reader.take(1)?[0] {
                0 => None,
                1 => {
                    let size = reader.u32()? as usize;
                    if size > MAX_ENVELOPE_BYTES {
                        return Err("journal transaction envelope limit".into());
                    }
                    let envelope = Zeroizing::new(reader.take(size)?.to_vec());
                    let sidecar = Zeroizing::new(
                        reader
                            .take(SIDECAR_BYTES)?
                            .try_into()
                            .expect("fixed sidecar width"),
                    );
                    let size = reader.u32()? as usize;
                    if size == 0 || size > MAX_OPENING {
                        return Err("journal payment opening limit".into());
                    }
                    let packet = PaymentPacket {
                        network: journal.network,
                        envelope,
                        sidecar,
                        opening: Zeroizing::new(reader.take(size)?.to_vec()),
                    };
                    journal.check_packet(id, &nullifiers, &packet)?;
                    Some(packet)
                }
                _ => return Err("invalid payment journal packet marker".into()),
            };
            if matches!(status, PaymentStatus::Prepared | PaymentStatus::Submitted)
                && packet.is_none()
            {
                return Err("prepared payment journal entry has no packet".into());
            }
            if status == PaymentStatus::Reserved && packet.is_some() {
                return Err("reserved journal entry unexpectedly has a packet".into());
            }
            journal.entries.insert(
                id,
                Entry {
                    nullifiers,
                    status,
                    packet,
                },
            );
        }
        if reader.offset != plaintext.len() {
            return Err("trailing payment journal bytes".into());
        }
        Ok(journal)
    }
    fn check_healthy(&self) -> Result<(), String> {
        if self.poisoned.get() {
            Err("wallet journal I/O failed; close and inspect before reopening".into())
        } else {
            Ok(())
        }
    }
    fn ensure_current(&self, owner: &storage::Directory) -> Result<(), String> {
        self.check_healthy()?;
        let checked = (|| {
            let current = owner.read_journal()?;
            if *blake3::hash(&current).as_bytes() != self.ciphertext_hash {
                return Err("payment journal changed outside this owner session".into());
            }
            Ok(())
        })();
        if checked.is_err() {
            self.poisoned.set(true);
        }
        checked
    }
    pub(super) fn ids(&self) -> Vec<Hash> {
        self.entries.keys().copied().collect()
    }
    pub(super) fn status(
        &self,
        owner: &storage::Directory,
        id: Hash,
    ) -> Result<PaymentStatus, String> {
        self.ensure_current(owner)?;
        self.entries
            .get(&id)
            .map(|entry| entry.status)
            .ok_or("unknown wallet payment".into())
    }
    pub(super) fn packet(
        &self,
        owner: &storage::Directory,
        id: Hash,
    ) -> Result<PaymentPacket, String> {
        self.ensure_current(owner)?;
        self.entries
            .get(&id)
            .and_then(|entry| entry.packet.as_ref())
            .map(PaymentPacket::duplicate)
            .ok_or("payment has no durably prepared packet".into())
    }
    pub(super) fn reserve(
        &mut self,
        owner: &storage::Directory,
        record: &PublicRecord,
    ) -> Result<ReservedPayment, String> {
        self.ensure_current(owner)?;
        record.validate()?;
        let id = record.statement_id(&self.network);
        let nullifiers = PublicTransaction::decode(&record.body)
            .map_err(|_| "invalid wallet transaction fields")?
            .nf
            .map(|nf| encode_digest(&nf));
        if nullifiers[0] == nullifiers[1] {
            return Err("payment repeats an input nullifier".into());
        }
        if let Some(entry) = self.entries.get(&id) {
            if entry.nullifiers != nullifiers
                || matches!(
                    entry.status,
                    PaymentStatus::Accepted | PaymentStatus::Conflicted
                )
            {
                return Err("payment reservation is terminal or mismatched".into());
            }
            return Ok(ReservedPayment {
                id,
                context: self.context,
            });
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err("payment journal entry limit; no history is deleted automatically".into());
        }
        if self
            .entries
            .values()
            .any(|entry| entry.nullifiers.iter().any(|nf| nullifiers.contains(nf)))
        {
            return Err("payment input is already durably reserved".into());
        }
        let mut entries = self.duplicate_entries();
        entries.insert(
            id,
            Entry {
                nullifiers,
                status: PaymentStatus::Reserved,
                packet: None,
            },
        );
        self.commit(owner, entries)?;
        Ok(ReservedPayment {
            id,
            context: self.context,
        })
    }
    pub(super) fn prepare(
        &mut self,
        owner: &storage::Directory,
        ticket: &ReservedPayment,
        transaction: &Transaction,
        sidecar: &Sidecar,
        opening: Zeroizing<Vec<u8>>,
        validate_opening: impl FnOnce(&Transaction, &[u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        self.ensure_current(owner)?;
        if ticket.context != self.context {
            return Err("payment reservation belongs to a different wallet context".into());
        }
        let entry = self
            .entries
            .get(&ticket.id)
            .ok_or("payment must be durably reserved before proof")?;
        if matches!(
            entry.status,
            PaymentStatus::Accepted | PaymentStatus::Conflicted
        ) {
            return Err("cannot prepare a terminal wallet payment".into());
        }
        if opening.is_empty() || opening.len() > MAX_OPENING {
            return Err("private payment opening must contain 1 to 65536 bytes".into());
        }
        let packet = PaymentPacket {
            network: self.network,
            envelope: Zeroizing::new(transaction.encode_envelope(&self.network)?),
            sidecar: Zeroizing::new(sidecar.encode()?),
            opening,
        };
        self.check_packet(ticket.id, &entry.nullifiers, &packet)?;
        validate_opening(transaction, packet.opening())?;
        if let Some(existing) = &entry.packet {
            return if existing.same(&packet) {
                Ok(())
            } else {
                Err("a different exact packet is already durably prepared".into())
            };
        }
        let mut entries = self.duplicate_entries();
        let entry = entries
            .get_mut(&ticket.id)
            .expect("checked reservation exists");
        entry.packet = Some(packet);
        entry.status = PaymentStatus::Prepared;
        self.commit(owner, entries)
    }
    pub(super) fn submit(
        &mut self,
        owner: &storage::Directory,
        id: Hash,
        deliver: impl FnOnce(&PaymentPacket) -> Result<(), String>,
    ) -> Result<(), String> {
        self.ensure_current(owner)?;
        let entry = self.entries.get(&id).ok_or("unknown wallet payment")?;
        if !matches!(
            entry.status,
            PaymentStatus::Prepared | PaymentStatus::Submitted | PaymentStatus::Orphaned
        ) {
            return Err("payment is not ready for submission".into());
        }
        let packet = entry
            .packet
            .as_ref()
            .ok_or("payment has no durably prepared packet")?;
        // The exact packet was synchronized before this callback is reachable.
        // A crash after relay acceptance leaves an identical retry, not a new tx.
        deliver(packet)?;
        if entry.status == PaymentStatus::Submitted {
            return Ok(());
        }
        let mut entries = self.duplicate_entries();
        entries.get_mut(&id).expect("checked payment exists").status = PaymentStatus::Submitted;
        self.commit(owner, entries)
    }
    pub(super) fn reconcile(
        &mut self,
        owner: &storage::Directory,
        config: Config,
        blocks: &[Block],
        verifier: &impl BlockVerifier,
    ) -> Result<AuditReport, String> {
        self.ensure_current(owner)?;
        if config.network != self.network {
            return Err("payment reconciliation network mismatch".into());
        }
        let (state, report) = replay_chain(config, blocks, verifier)?;
        let accepted: BTreeSet<Hash> = blocks
            .iter()
            .flat_map(|block| {
                block
                    .transactions
                    .iter()
                    .map(|tx| tx.record.statement_id(&self.network))
            })
            .collect();
        let mut entries = self.duplicate_entries();
        let mut changed = false;
        for (id, entry) in &mut entries {
            let status = if accepted.contains(id) {
                PaymentStatus::Accepted
            } else if entry.nullifiers.iter().any(|nf| state.spent.contains(nf)) {
                PaymentStatus::Conflicted
            } else if matches!(
                entry.status,
                PaymentStatus::Accepted | PaymentStatus::Conflicted
            ) {
                PaymentStatus::Orphaned
            } else {
                entry.status
            };
            changed |= entry.status != status;
            entry.status = status;
        }
        if changed {
            self.commit(owner, entries)?;
        }
        Ok(report)
    }
    fn check_packet(
        &self,
        id: Hash,
        nullifiers: &[DigestBytes; 2],
        packet: &PaymentPacket,
    ) -> Result<(), String> {
        let tx = packet.transaction()?;
        if tx.record.statement_id(&self.network) != id
            || PublicTransaction::decode(&tx.record.body)
                .map_err(|_| "invalid journal transaction")?
                .nf
                .map(|nf| encode_digest(&nf))
                != *nullifiers
        {
            return Err("prepared packet differs from its durable reservation".into());
        }
        packet.sidecar()?.check_opening(&tx.record, &self.network)
    }
    fn duplicate_entries(&self) -> BTreeMap<Hash, Entry> {
        self.entries
            .iter()
            .map(|(id, entry)| (*id, entry.duplicate()))
            .collect()
    }
    fn commit(
        &mut self,
        owner: &storage::Directory,
        entries: BTreeMap<Hash, Entry>,
    ) -> Result<(), String> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or("payment journal generation overflow")?;
        let encoded = self.encode(&entries, generation)?;
        // After any failed I/O, disk may contain the old or new complete file.
        // In-memory continuation could overwrite a reservation, so fail closed.
        let replace = (|| {
            self.ensure_current(owner)?;
            owner.replace_journal(&encoded)
        })();
        if let Err(error) = replace {
            self.poisoned.set(true);
            return Err(error);
        }
        self.entries = entries;
        self.ciphertext_hash = *blake3::hash(&encoded).as_bytes();
        self.generation = generation;
        Ok(())
    }
    fn aad(&self, header: &[u8]) -> Vec<u8> {
        let mut aad = b"siworld native private payment journal v1:xchacha20poly1305".to_vec();
        aad.extend_from_slice(&self.context);
        aad.extend_from_slice(header);
        aad
    }
    fn encode(&self, entries: &BTreeMap<Hash, Entry>, generation: u64) -> Result<Vec<u8>, String> {
        let mut plaintext = Zeroizing::new(Vec::new());
        plaintext.extend_from_slice(&generation.to_le_bytes());
        plaintext.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (id, entry) in entries {
            let packet_size = entry.packet.as_ref().map_or(0, |packet| {
                4 + packet.envelope.len() + SIDECAR_BYTES + 4 + packet.opening.len()
            });
            if plaintext
                .len()
                .checked_add(32 + 96 + 2 + packet_size)
                .is_none_or(|size| size > MAX_PLAINTEXT)
            {
                return Err(
                    "payment journal byte limit; no history is deleted automatically".into(),
                );
            }
            plaintext.extend_from_slice(id);
            for nf in &entry.nullifiers {
                plaintext.extend_from_slice(nf);
            }
            plaintext.push(entry.status.encode());
            plaintext.push(u8::from(entry.packet.is_some()));
            if let Some(packet) = &entry.packet {
                plaintext.extend_from_slice(&(packet.envelope.len() as u32).to_le_bytes());
                plaintext.extend_from_slice(&packet.envelope);
                plaintext.extend_from_slice(packet.sidecar.as_ref());
                plaintext.extend_from_slice(&(packet.opening.len() as u32).to_le_bytes());
                plaintext.extend_from_slice(&packet.opening);
            }
        }
        let mut encoded = Vec::with_capacity(HEADER + plaintext.len() + 16);
        encoded.extend_from_slice(MAGIC);
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| "OS randomness unavailable")?;
        encoded.extend_from_slice(&nonce);
        let cipher = XChaCha20Poly1305::new(
            <&Key>::try_from(self.key.as_ref()).expect("fixed journal key width"),
        );
        let tag = cipher
            .encrypt_inout_detached(
                <&XNonce>::try_from(nonce.as_slice()).expect("fixed journal nonce width"),
                &self.aad(&encoded),
                plaintext.as_mut_slice().into(),
            )
            .map_err(|_| "payment journal encryption failed")?;
        encoded.extend_from_slice(&plaintext);
        encoded.extend_from_slice(&tag);
        Ok(encoded)
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(size)
            .ok_or("payment journal length overflow")?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or("truncated payment journal")?;
        self.offset = end;
        Ok(bytes)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("fixed length width"),
        ))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("fixed generation width"),
        ))
    }
}
