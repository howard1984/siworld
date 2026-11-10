//! Bounded checkpoint batches after a completed bidirectional block round.
//! This phase never interrupts a header/body response and never mutates Store.
use super::{
    runtime_export::host::{Incoming, MAX_CHECKPOINT_PACKET_BYTES, MAX_MESSAGES_PER_TICK},
    transport::Peer,
};
use crate::{p2p, wire::Hash};
use std::{
    io::{Read, Write},
    time::Duration,
};
const BATCH: u8 = 0x20;
const PACKET: u8 = 0x21;
const VERSION: u16 = 1;
const REQUEST: u64 = 0;
const BATCH_BYTES: usize = 4;
const PACKET_PREFIX: usize = 6;
const PHASE_SECONDS: u64 = 10;
const MAX_GOVERNANCE_BYTES: usize = 131072;

/// This new reservation remains live for the complete decoded message, through
/// enqueue and Host consumption. Moving either field requires retaining both.
pub struct OwnedIncoming {
    pub message: Incoming,
    pub reservation: p2p::Reservation,
}
/// The initiator sends one complete batch before reading the responder's batch.
/// On any error discard this connection; the resident validator keeps running.
pub fn initiate<S: Read + Write>(
    peer: &mut Peer<S>,
    outgoing: &[Vec<u8>],
    network: Hash,
) -> Result<Vec<OwnedIncoming>, p2p::Error> {
    exchange(
        peer,
        outgoing,
        network,
        true,
        &p2p::Deadline::new(Duration::from_secs(PHASE_SECONDS)),
    )
}
/// The responder reads one complete batch before sending its batch. Call only
/// after the ordinary block-round completion marker has been consumed.
pub fn respond<S: Read + Write>(
    peer: &mut Peer<S>,
    outgoing: &[Vec<u8>],
    network: Hash,
) -> Result<Vec<OwnedIncoming>, p2p::Error> {
    exchange(
        peer,
        outgoing,
        network,
        false,
        &p2p::Deadline::new(Duration::from_secs(PHASE_SECONDS)),
    )
}
fn exchange<S: Read + Write>(
    peer: &mut Peer<S>,
    outgoing: &[Vec<u8>],
    network: Hash,
    initiator: bool,
    deadline: &p2p::Deadline,
) -> Result<Vec<OwnedIncoming>, p2p::Error> {
    if peer.application_network() != network || outgoing.len() > MAX_MESSAGES_PER_TICK {
        return Err(p2p::Error::InvalidProtocol);
    }
    for packet in outgoing {
        check_length(packet.len())?;
        let _decoded_charge = peer.reserve_application(packet.len())?;
        Incoming::decode(packet, network, MAX_GOVERNANCE_BYTES)
            .map_err(|_| p2p::Error::InvalidProtocol)?;
        deadline.check().map_err(|_| p2p::Error::Unavailable)?;
    }
    if initiator {
        send_batch(peer, outgoing, deadline)?;
        receive_batch(peer, network, deadline)
    } else {
        let received = receive_batch(peer, network, deadline)?;
        send_batch(peer, outgoing, deadline)?;
        Ok(received)
    }
}
fn check_length(length: usize) -> Result<(), p2p::Error> {
    if length == 0 || length > MAX_CHECKPOINT_PACKET_BYTES {
        Err(p2p::Error::ResourceExhausted)
    } else {
        Ok(())
    }
}
fn send_batch<S: Read + Write>(
    peer: &mut Peer<S>,
    outgoing: &[Vec<u8>],
    deadline: &p2p::Deadline,
) -> Result<(), p2p::Error> {
    let header = [
        BATCH,
        VERSION as u8,
        (VERSION >> 8) as u8,
        outgoing.len() as u8,
    ];
    peer.send_application_before(REQUEST, &header, deadline)?;
    for (index, packet) in outgoing.iter().enumerate() {
        // The source bytes retain their mailbox ownership; this reservation
        // accounts for the one additional bounded application-frame copy.
        let _scratch = peer.reserve_application(packet.len())?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(PACKET_PREFIX + packet.len())
            .map_err(|_| p2p::Error::ResourceExhausted)?;
        bytes.push(PACKET);
        bytes.push(index as u8);
        bytes.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        bytes.extend_from_slice(packet);
        peer.send_application_before(REQUEST, &bytes, deadline)?;
    }
    Ok(())
}
fn receive_batch<S: Read + Write>(
    peer: &mut Peer<S>,
    network: Hash,
    deadline: &p2p::Deadline,
) -> Result<Vec<OwnedIncoming>, p2p::Error> {
    let (request, header, header_charge) =
        peer.receive_application_before(deadline, BATCH_BYTES)?;
    if request != REQUEST
        || header.len() != BATCH_BYTES
        || header[0] != BATCH
        || header[1..3] != VERSION.to_le_bytes()
        || usize::from(header[3]) > MAX_MESSAGES_PER_TICK
    {
        return Err(p2p::Error::InvalidProtocol);
    }
    let count = usize::from(header[3]);
    drop(header);
    drop(header_charge);
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| p2p::Error::ResourceExhausted)?;
    for index in 0..count {
        let (request, bytes, wire_charge) =
            peer.receive_application_before(deadline, PACKET_PREFIX + MAX_CHECKPOINT_PACKET_BYTES)?;
        if request != REQUEST
            || bytes.len() < PACKET_PREFIX
            || bytes[0] != PACKET
            || usize::from(bytes[1]) != index
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        let length = u32::from_le_bytes(bytes[2..6].try_into().expect("fixed length")) as usize;
        check_length(length)?;
        if length.checked_add(PACKET_PREFIX) != Some(bytes.len()) {
            return Err(p2p::Error::InvalidProtocol);
        }
        // Wire Vec and its original charge stay live during decoding. The
        // decoded message receives a separate reservation from the same node
        // budget, which moves to the caller and its eventual mailbox.
        let reservation = peer.reserve_application(length)?;
        let message = Incoming::decode(&bytes[PACKET_PREFIX..], network, MAX_GOVERNANCE_BYTES)
            .map_err(|_| p2p::Error::InvalidProtocol)?;
        deadline.check().map_err(|_| p2p::Error::Unavailable)?;
        drop(bytes);
        drop(wire_charge);
        result.push(OwnedIncoming {
            message,
            reservation,
        });
    }
    Ok(result)
}
#[cfg(test)]
mod tests;
