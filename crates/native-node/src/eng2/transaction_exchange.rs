//! Bounded pending-transaction exchange after block and checkpoint rounds.
//! Fee sidecars travel only inside the encrypted peer channel.
use super::transport::Peer;
use crate::{
    p2p,
    wire::{Hash, MAX_ENVELOPE_BYTES, SIDECAR_BYTES},
};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    sync::{Arc, Mutex},
    time::Duration,
};
const INVENTORY: u8 = 0x30;
const REQUEST: u8 = 0x31;
const PACKET: u8 = 0x32;
const VERSION: u8 = 1;
const MAX_IDS: usize = 128;
const MAX_REQUESTED: usize = 3;
const MAX_PACKET: usize = 4 + MAX_ENVELOPE_BYTES + SIDECAR_BYTES;

pub(crate) trait Owner {
    fn transaction_ids(&self) -> Vec<Hash>;
    fn has_transaction(&self, id: &Hash) -> bool;
    fn transaction_packet(&self, id: &Hash) -> Result<Option<Vec<u8>>, String>;
    /// Check the expected identity before independent native admission. A stale
    /// or conflicting transaction is a bounded rejection, not a state change.
    fn submit_transaction(
        &mut self,
        peer: Hash,
        expected: Hash,
        packet: &[u8],
        deadline: &p2p::Deadline,
    ) -> Result<Hash, String>;
}
pub(crate) fn initiate<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
) -> Result<(), p2p::Error> {
    let deadline = p2p::Deadline::new(Duration::from_secs(10));
    send(peer, owner, &deadline)?;
    receive(peer, owner, &deadline)
}
pub(crate) fn respond<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
) -> Result<(), p2p::Error> {
    let deadline = p2p::Deadline::new(Duration::from_secs(10));
    receive(peer, owner, &deadline)?;
    send(peer, owner, &deadline)
}
fn invalid() -> p2p::Error {
    p2p::Error::InvalidProtocol
}
fn lock<'a, O>(
    owner: &'a Arc<Mutex<O>>,
    deadline: &p2p::Deadline,
) -> Result<std::sync::MutexGuard<'a, O>, p2p::Error> {
    loop {
        deadline.check().map_err(|_| p2p::Error::Unavailable)?;
        match owner.try_lock() {
            Ok(guard) => {
                deadline.check().map_err(|_| p2p::Error::Unavailable)?;
                return Ok(guard);
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(_) => return Err(p2p::Error::Unavailable),
        }
    }
}
fn encode_ids(kind: u8, ids: &[Hash], maximum: usize) -> Result<Vec<u8>, p2p::Error> {
    if ids.len() > maximum || ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(4 + 32 * ids.len());
    bytes.extend_from_slice(&[kind, VERSION]);
    bytes.extend_from_slice(&(ids.len() as u16).to_le_bytes());
    for id in ids {
        bytes.extend_from_slice(id);
    }
    Ok(bytes)
}
fn decode_ids(bytes: &[u8], kind: u8, maximum: usize) -> Result<Vec<Hash>, p2p::Error> {
    if bytes.len() < 4 || bytes[..2] != [kind, VERSION] {
        return Err(invalid());
    }
    let count = u16::from_le_bytes(bytes[2..4].try_into().expect("fixed prefix")) as usize;
    if count > maximum || bytes.len() != 4 + 32 * count {
        return Err(invalid());
    }
    let ids: Vec<Hash> = bytes[4..].as_chunks::<32>().0.to_vec();
    if ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(invalid());
    }
    Ok(ids)
}
fn send<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    deadline: &p2p::Deadline,
) -> Result<(), p2p::Error> {
    let ids = lock(owner, deadline)?.transaction_ids();
    peer.send_application_before(0, &encode_ids(INVENTORY, &ids, MAX_IDS)?, deadline)?;
    let (request, bytes, guard) =
        peer.receive_application_before(deadline, 4 + 32 * MAX_REQUESTED)?;
    if request != 0 {
        return Err(invalid());
    }
    let wanted = decode_ids(&bytes, REQUEST, MAX_REQUESTED)?;
    if wanted.iter().any(|id| !ids.contains(id)) {
        return Err(invalid());
    }
    drop(bytes);
    drop(guard);
    for (index, id) in wanted.iter().enumerate() {
        // Charge before acquiring/encoding the possible maximum pending proof.
        let _charge = peer.reserve_application(MAX_PACKET + 7)?;
        let packet = lock(owner, deadline)?
            .transaction_packet(id)
            .map_err(|_| p2p::Error::Unavailable)?;
        let mut bytes =
            zeroize::Zeroizing::new(vec![PACKET, index as u8, u8::from(packet.is_some())]);
        if let Some(packet) = packet {
            let packet = zeroize::Zeroizing::new(packet);
            if packet.len() > MAX_PACKET {
                return Err(p2p::Error::ResourceExhausted);
            }
            bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&packet);
        }
        peer.send_application_before(0, &bytes, deadline)?;
    }
    Ok(())
}
fn receive<S: Read + Write, O: Owner>(
    peer: &mut Peer<S>,
    owner: &Arc<Mutex<O>>,
    deadline: &p2p::Deadline,
) -> Result<(), p2p::Error> {
    let (request, bytes, guard) = peer.receive_application_before(deadline, 4 + 32 * MAX_IDS)?;
    if request != 0 {
        return Err(invalid());
    }
    let ids = decode_ids(&bytes, INVENTORY, MAX_IDS)?;
    let wanted: Vec<_> = {
        let owner = lock(owner, deadline)?;
        ids.into_iter()
            .filter(|id| !owner.has_transaction(id))
            .take(MAX_REQUESTED)
            .collect()
    };
    drop(bytes);
    drop(guard);
    peer.send_application_before(0, &encode_ids(REQUEST, &wanted, MAX_REQUESTED)?, deadline)?;
    for (index, id) in wanted.iter().enumerate() {
        let (request, bytes, _guard) = peer.receive_application_before(deadline, MAX_PACKET + 7)?;
        let bytes = zeroize::Zeroizing::new(bytes);
        if request != 0 || bytes.len() < 3 || bytes[..2] != [PACKET, index as u8] {
            return Err(invalid());
        }
        match bytes[2] {
            0 if bytes.len() == 3 => {}
            1 if bytes.len() >= 7 => {
                let length =
                    u32::from_le_bytes(bytes[3..7].try_into().expect("fixed prefix")) as usize;
                if length > MAX_PACKET || bytes.len() != 7 + length {
                    return Err(invalid());
                }
                // A concurrent canonical block can legitimately consume these
                // inputs. Admission rejection does not stop node validation.
                let _decoded = peer.reserve_application(length)?;
                deadline.check().map_err(|_| p2p::Error::Unavailable)?;
                let _ = lock(owner, deadline)?.submit_transaction(
                    peer.peer(),
                    *id,
                    &bytes[7..],
                    deadline,
                );
            }
            _ => return Err(invalid()),
        }
        deadline.check().map_err(|_| p2p::Error::Unavailable)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests;
