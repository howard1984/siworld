//! Authenticated, bounded propagation exchanges on the existing peer channel.
//!
//! The candidate owner must hold its node-wide Pieces body claim before any
//! ledger or I/O operation and retain it through complete native admission.
//! These methods do not create a listener or activate an optional lane.

use super::*;
use crate::eng2::propagation::{
    authentication::{self, Authenticated, Descriptor, PIECE_BYTES, VerifiedPiece},
    framing,
    pipeline::{DescriptorLedger, Request as PieceRequest, Transfer},
    wire as codec,
};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

const GET_METADATA: u8 = 0x42;
const METADATA: u8 = 0x43;
const DESCRIPTOR: u8 = 0x44;
const VERSION: u8 = 1;
const DESCRIPTOR_PREFIX: usize = 6;
const DESCRIPTOR_CHUNK: usize = p2p::MAX_CONTROL_BYTES - DESCRIPTOR_PREFIX;
const MAX_INDEX_PIECES: usize = 3 * crate::wire::MAX_SLOTS
    + 2 * crate::eng2_governance::MAX_ACTIONS_PER_BLOCK
    + 2 * crate::issuance::RECORDS_CODEC_LIMIT
    + 3;
const FRAME_ALLOWANCE: usize = 128;
pub const CAPABILITY_HEIGHT: u64 = u64::MAX - 3;
const CAPABILITY: u8 = 0x45;
const OFFER: u8 = 0x46;
const CREDIT: u8 = 0x47;

pub(super) fn next_session() -> Result<u64, p2p::Error> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.try_update(
        std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,
        |value| value.checked_add(1),
    )
    .map_err(|_| p2p::Error::ResourceExhausted)
}

/// An authenticated bounded offer is not authority to adopt or allocate a body.
/// The receiver must independently qualify its header before granting credit.
#[derive(Debug)]
pub struct Offer {
    _reservation: p2p::Reservation,
    header: Box<Header>,
    body_bytes: usize,
    request: u64,
    peer: Hash,
    binding: p2p::Binding,
    session_id: u64,
    received_wire: u64,
}
impl PartialEq for Offer {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
            && self.body_bytes == other.body_bytes
            && self.request == other.request
            && self.peer == other.peer
            && self.binding == other.binding
            && self.session_id == other.session_id
            && self.received_wire == other.received_wire
    }
}
impl Eq for Offer {}
impl Offer {
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn body_bytes(&self) -> usize {
        self.body_bytes
    }
    pub fn request(&self) -> u64 {
        self.request
    }
    pub fn peer(&self) -> Hash {
        self.peer
    }
    pub fn binding(&self) -> p2p::Binding {
        self.binding
    }
    pub fn session_id(&self) -> u64 {
        self.session_id
    }
    pub fn maximum_wire(&self) -> Result<u64, p2p::Error> {
        maximum_wire(self.body_bytes)
    }
}

/// A one-use grant bound to this exact authenticated peer instance and block.
pub struct Credit {
    deadline: p2p::Deadline,
    block: Hash,
    height: u64,
    body_bytes: usize,
    request: u64,
    peer: Hash,
    binding: p2p::Binding,
    session_id: u64,
    maximum_wire: u64,
}
impl Credit {
    pub fn block(&self) -> Hash {
        self.block
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn peer(&self) -> Hash {
        self.peer
    }
    pub fn binding(&self) -> p2p::Binding {
        self.binding
    }
    pub fn session_id(&self) -> u64 {
        self.session_id
    }
    pub fn maximum_wire(&self) -> u64 {
        self.maximum_wire
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PropagationRequest {
    Capability,
    Offer(Offer),
    Metadata { height: u64, id: Hash },
    Pieces(codec::Query),
}

/// Temporary authenticated metadata retains its global allocation charge until
/// installed in the transfer's separately reserved body buffer.
pub struct Metadata {
    authenticated: Authenticated,
    first: VerifiedPiece,
    indices: Vec<VerifiedPiece>,
    _reservation: p2p::Reservation,
}
impl Metadata {
    pub fn into_transfer(
        self,
        ledger: DescriptorLedger,
        budget: &p2p::Budget,
    ) -> Result<Transfer, p2p::Error> {
        let mut transfer =
            Transfer::new(self.authenticated, self.first, ledger, budget).map_err(resource)?;
        for piece in self.indices {
            transfer
                .index_piece(piece, Instant::now())
                .map_err(resource)?;
        }
        Ok(transfer)
    }
}

fn resource(_: crate::eng2::propagation::pipeline::Error) -> p2p::Error {
    p2p::Error::ResourceExhausted
}
fn invalid<T>(_: T) -> p2p::Error {
    p2p::Error::InvalidProtocol
}
fn lock(transfer: &Mutex<Transfer>) -> Result<std::sync::MutexGuard<'_, Transfer>, p2p::Error> {
    transfer.lock().map_err(|_| p2p::Error::Unavailable)
}
fn pieces(length: usize) -> Result<usize, p2p::Error> {
    Ok(length
        .checked_add(8)
        .ok_or(p2p::Error::ResourceExhausted)?
        .div_ceil(PIECE_BYTES))
}
fn descriptor_bytes(length: usize) -> Result<usize, p2p::Error> {
    pieces(length)?
        .checked_mul(32)
        .and_then(|n| n.checked_add(8))
        .ok_or(p2p::Error::ResourceExhausted)
}
pub(crate) fn maximum_wire(length: usize) -> Result<u64, p2p::Error> {
    let count = pieces(length)?;
    let descriptor = descriptor_bytes(length)?;
    let descriptor_frames = descriptor.div_ceil(DESCRIPTOR_CHUNK);
    length
        .checked_add(descriptor)
        .and_then(|n| n.checked_add(count.checked_mul(FRAME_ALLOWANCE + 8)?))
        .and_then(|n| n.checked_add(descriptor_frames.checked_mul(FRAME_ALLOWANCE)?))
        .and_then(|n| n.checked_add(6 * FRAME_ALLOWANCE + 8))
        .map(|n| n as u64)
        .ok_or(p2p::Error::ResourceExhausted)
}
fn metadata_allocation(length: usize) -> Result<usize, p2p::Error> {
    let count = pieces(length)?.min(MAX_INDEX_PIECES);
    descriptor_bytes(length)?
        .checked_mul(2)
        .and_then(|n| n.checked_add(count.checked_mul(PIECE_BYTES + 128)?))
        .and_then(|n| n.checked_add(2 * p2p::MAX_CONTROL_BYTES))
        .ok_or(p2p::Error::ResourceExhausted)
}
fn bounded_deadline(
    started: Instant,
    lifetime: Duration,
    cancel: p2p::Cancellation,
) -> Result<p2p::Deadline, p2p::Error> {
    if lifetime.is_zero() || lifetime > BODY_FETCH_TIMEOUT {
        return Err(p2p::Error::ResourceExhausted);
    }
    let deadline = p2p::Deadline::from_started(started, lifetime, cancel);
    deadline.check().map_err(|_| p2p::Error::Unavailable)?;
    Ok(deadline)
}

impl<S: Read + Write> Peer<S> {
    pub fn propagation_session_id(&self) -> u64 {
        self.propagation_session
    }
    pub fn propagation_supported(&self) -> bool {
        self.propagation_supported == Some(true)
    }
    pub fn probe_propagation(&mut self, request: u64) -> Result<bool, p2p::Error> {
        if request == 0 {
            return Err(p2p::Error::InvalidProtocol);
        }
        if let Some(available) = self.propagation_supported {
            return Ok(available);
        }
        let mut query = vec![GET_HEADER];
        query.extend_from_slice(&CAPABILITY_HEIGHT.to_le_bytes());
        self.send(request, &query)?;
        let (response, bytes, _charge) = self.receive()?;
        if response != request {
            return Err(p2p::Error::InvalidProtocol);
        }
        let available = if bytes.as_slice() == [CAPABILITY, VERSION] {
            true
        } else if bytes.len() == 9
            && bytes[0] == UNAVAILABLE
            && number(&bytes[1..]) == CAPABILITY_HEIGHT
        {
            false
        } else {
            return Err(p2p::Error::InvalidProtocol);
        };
        self.propagation_supported = Some(available);
        Ok(available)
    }
    pub fn send_propagation_capabilities(&mut self, request: u64) -> Result<(), p2p::Error> {
        if request == 0 {
            return Err(p2p::Error::InvalidProtocol);
        }
        self.send(request, &[CAPABILITY, VERSION])?;
        self.propagation_supported = Some(true);
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn offer_propagation(
        &mut self,
        request: u64,
        header: &Header,
        body_bytes: usize,
        started: Instant,
        lifetime: Duration,
        cancel: p2p::Cancellation,
    ) -> Result<Option<Credit>, p2p::Error> {
        let deadline = bounded_deadline(started, lifetime, cancel)?;
        if !self.propagation_supported()
            || request == 0
            || header.height == 0
            || header.network != self.session.binding().network
            || body_bytes == 0
            || body_bytes > self.policy.max_body_bytes
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        let block = header.id().map_err(invalid)?;
        let maximum_wire = maximum_wire(body_bytes)?;
        let mut offer = vec![OFFER, VERSION];
        offer.extend_from_slice(&(body_bytes as u64).to_le_bytes());
        offer.extend_from_slice(&header.encode().map_err(invalid)?);
        self.send_application_before(request, &offer, &deadline)?;
        let (response, bytes, _charge) = self.receive_application_before(&deadline, 51)?;
        if response != request
            || bytes.len() != 51
            || bytes[..2] != [CREDIT, VERSION]
            || bytes[3..35] != block
            || number(&bytes[35..43]) != header.height
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        let granted = number(&bytes[43..51]);
        match bytes[2] {
            0 if granted == 0 => Ok(None),
            1 if granted == maximum_wire => Ok(Some(Credit {
                deadline,
                block,
                height: header.height,
                body_bytes,
                request,
                peer: self.peer(),
                binding: self.session.binding(),
                session_id: self.propagation_session,
                maximum_wire,
            })),
            _ => Err(p2p::Error::InvalidProtocol),
        }
    }
    fn matches_offer(&self, offer: &Offer) -> bool {
        offer.request != 0
            && offer.peer == self.peer()
            && offer.binding == self.session.binding()
            && offer.session_id == self.propagation_session
    }
    fn send_credit(
        &mut self,
        offer: &Offer,
        maximum_wire: u64,
        deadline: &p2p::Deadline,
    ) -> Result<(), p2p::Error> {
        if !self.matches_offer(offer) {
            return Err(p2p::Error::InvalidProtocol);
        }
        let mut bytes = vec![CREDIT, VERSION, u8::from(maximum_wire != 0)];
        bytes.extend_from_slice(&offer.header.id().map_err(invalid)?);
        bytes.extend_from_slice(&offer.header.height.to_le_bytes());
        bytes.extend_from_slice(&maximum_wire.to_le_bytes());
        self.send_application_before(offer.request, &bytes, deadline)
    }
    pub fn reject_propagation_offer(
        &mut self,
        offer: Offer,
        started: Instant,
        lifetime: Duration,
        cancel: p2p::Cancellation,
    ) -> Result<(), p2p::Error> {
        self.send_credit(&offer, 0, &bounded_deadline(started, lifetime, cancel)?)
    }
    /// The caller first independently qualifies the known-parent header and
    /// obtains fixed-peer policy approval and the sole node-wide Pieces claim.
    /// Offer/credit/metadata is one query; its continuation is a second query.
    pub fn accept_propagation_offer(
        &mut self,
        offer: Offer,
        ledger: &mut DescriptorLedger,
        ownership: &p2p::BodyClaim,
    ) -> Result<Metadata, p2p::Error> {
        let block = offer.header.id().map_err(invalid)?;
        if !self.propagation_supported()
            || !self.matches_offer(&offer)
            || block != ledger.block()
            || !ownership.matches(
                &self.session.shared_budget(),
                offer.binding,
                offer.header.height,
                block,
            )
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        ledger
            .bind_claim(offer.binding, ownership)
            .map_err(resource)?;
        let reservation = self.reserve_application(metadata_allocation(offer.body_bytes)?)?;
        let attempt = ledger
            .begin(self.peer(), maximum_wire(offer.body_bytes)?, Instant::now())
            .map_err(resource)?;
        let deadline = ledger.io_deadline();
        ownership.account_received_offer(offer.received_wire)?;
        let before = self.session.io_totals();
        let result = self.with_body_accounting(ownership, |peer| {
            ownership.begin_query(peer.peer())?;
            peer.send_credit(&offer, maximum_wire(offer.body_bytes)?, &deadline)?;
            peer.receive_propagation_metadata_before(
                offer.request,
                &offer.header,
                Some(offer.body_bytes),
                ownership,
                reservation,
                &deadline,
            )
        });
        let after = self.session.io_totals();
        ledger
            .sent(attempt, after.sent - before.sent)
            .map_err(resource)?;
        ledger
            .completed(
                attempt,
                offer.received_wire + after.received - before.received,
                result.is_ok(),
                Instant::now(),
            )
            .map_err(resource)?;
        result
    }
    /// Consume a credit exactly once and retain its original absolute deadline.
    pub fn send_credited_metadata(
        &mut self,
        credit: Credit,
        header: &Header,
        body: &Body,
    ) -> Result<(), p2p::Error> {
        credit
            .deadline
            .check()
            .map_err(|_| p2p::Error::Unavailable)?;
        if credit.peer != self.peer()
            || credit.binding != self.session.binding()
            || credit.session_id != self.propagation_session
            || credit.block != header.id().map_err(invalid)?
            || credit.height != header.height
            || credit.body_bytes != body.encoded_len(self.policy).map_err(invalid)?
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        let before = self.session.io_totals().sent;
        self.send_propagation_metadata_before(credit.request, header, body, &credit.deadline)?;
        if self.session.io_totals().sent - before > credit.maximum_wire {
            return Err(p2p::Error::ResourceExhausted);
        }
        Ok(())
    }
    /// The caller has already acquired the exact candidate's Pieces claim.
    /// Busy must defer before calling this method, without spending a source.
    pub fn fetch_propagation_metadata(
        &mut self,
        header: &Header,
        ledger: &mut DescriptorLedger,
        ownership: &p2p::BodyClaim,
    ) -> Result<Metadata, p2p::Error> {
        self.fetch_propagation_metadata_mapped(None, header, ledger, ownership)
    }
    /// Map the outer socket-turn request without changing candidate accounting.
    pub fn fetch_propagation_metadata_at(
        &mut self,
        request: u64,
        header: &Header,
        ledger: &mut DescriptorLedger,
        ownership: &p2p::BodyClaim,
    ) -> Result<Metadata, p2p::Error> {
        if request == 0 {
            return Err(p2p::Error::InvalidProtocol);
        }
        self.fetch_propagation_metadata_mapped(Some(request), header, ledger, ownership)
    }
    fn fetch_propagation_metadata_mapped(
        &mut self,
        external_request: Option<u64>,
        header: &Header,
        ledger: &mut DescriptorLedger,
        ownership: &p2p::BodyClaim,
    ) -> Result<Metadata, p2p::Error> {
        let block = header.id().map_err(invalid)?;
        if block != ledger.block()
            || header.height == 0
            || header.network != self.session.binding().network
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        if !ownership.matches(
            &self.session.shared_budget(),
            self.session.binding(),
            header.height,
            block,
        ) {
            return Err(p2p::Error::InvalidProtocol);
        }
        ledger
            .bind_claim(self.session.binding(), ownership)
            .map_err(resource)?;
        if !ownership.can_query(self.peer(), 2) {
            return Err(p2p::Error::ResourceExhausted);
        }
        let _reservation =
            self.reserve_application(metadata_allocation(self.policy.max_body_bytes)?)?;
        let attempt = ledger
            .begin(
                self.peer(),
                maximum_wire(self.policy.max_body_bytes)?,
                Instant::now(),
            )
            .map_err(resource)?;
        let request = external_request.unwrap_or(attempt.sequence());
        let deadline = ledger.io_deadline();
        let before = self.session.io_totals();
        let result =
            self.fetch_metadata_exchange(request, header, ownership, _reservation, &deadline);
        let after = self.session.io_totals();
        ledger
            .sent(attempt, after.sent - before.sent)
            .map_err(resource)?;
        ledger
            .completed(
                attempt,
                after.received - before.received,
                result.is_ok(),
                Instant::now(),
            )
            .map_err(resource)?;
        result
    }

    #[cfg(feature = "eng2-runtime")]
    pub(crate) fn fetch_propagation_confirmation_at(
        &mut self,
        request: u64,
        header: &Header,
        transfer: &Mutex<Transfer>,
        ownership: &p2p::BodyClaim,
    ) -> Result<bool, p2p::Error> {
        if request == 0 {
            return Err(p2p::Error::InvalidProtocol);
        }
        if !lock(transfer)?.confirmation_available(self.peer(), ownership) {
            return Ok(false);
        }
        // Reserve memory before consuming the one confirmation slot. A local
        // reservation rejection leaves the first source free to proceed.
        let reservation =
            self.reserve_application(metadata_allocation(self.policy.max_body_bytes)?)?;
        let Some((attempt, deadline)) = lock(transfer)?
            .begin_confirmation(
                self.peer(),
                maximum_wire(self.policy.max_body_bytes)?,
                ownership,
            )
            .map_err(resource)?
        else {
            return Ok(false);
        };
        let before = self.session.io_totals();
        let result =
            self.fetch_metadata_exchange(request, header, ownership, reservation, &deadline);
        let after = self.session.io_totals();
        lock(transfer)?
            .complete_confirmation(
                attempt,
                after.sent - before.sent,
                after.received - before.received,
                result.as_ref().ok().map(|metadata| &metadata.authenticated),
            )
            .map_err(resource)?;
        result.map(|_| true)
    }

    fn fetch_metadata_exchange(
        &mut self,
        request: u64,
        header: &Header,
        ownership: &p2p::BodyClaim,
        reservation: p2p::Reservation,
        deadline: &p2p::Deadline,
    ) -> Result<Metadata, p2p::Error> {
        self.with_body_accounting(ownership, |peer| {
            let block = header.id().map_err(invalid)?;
            let mut query = vec![GET_METADATA, VERSION];
            query.extend_from_slice(&header.height.to_le_bytes());
            query.extend_from_slice(&block);
            ownership.begin_query(peer.peer())?;
            peer.send_application_before(request, &query, deadline)?;
            peer.receive_propagation_metadata_before(
                request,
                header,
                None,
                ownership,
                reservation,
                deadline,
            )
        })
    }

    fn receive_propagation_metadata_before(
        &mut self,
        request: u64,
        header: &Header,
        expected_length: Option<usize>,
        ownership: &p2p::BodyClaim,
        _reservation: p2p::Reservation,
        deadline: &p2p::Deadline,
    ) -> Result<Metadata, p2p::Error> {
        let block = header.id().map_err(invalid)?;
        let (response, start, start_charge) = self.receive_application_before(deadline, 18)?;
        if response != request || start.len() != 18 || start[..2] != [METADATA, VERSION] {
            return Err(p2p::Error::InvalidProtocol);
        }
        let body_bytes = usize::try_from(u64::from_le_bytes(
            start[2..10].try_into().expect("fixed length"),
        ))
        .map_err(invalid)?;
        let descriptor_length =
            u32::from_le_bytes(start[10..14].try_into().expect("fixed descriptor length")) as usize;
        let index_count =
            u32::from_le_bytes(start[14..18].try_into().expect("fixed index count")) as usize;
        if expected_length.is_some_and(|expected| expected != body_bytes)
            || body_bytes == 0
            || body_bytes > self.policy.max_body_bytes
            || descriptor_length != descriptor_bytes(body_bytes)?
            || index_count == 0
            || index_count > pieces(body_bytes)?.min(MAX_INDEX_PIECES)
        {
            return Err(p2p::Error::ResourceExhausted);
        }
        drop(start);
        drop(start_charge);
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(descriptor_length)
            .map_err(|_| p2p::Error::ResourceExhausted)?;
        while encoded.len() < descriptor_length {
            let (response, part, _charge) =
                self.receive_application_before(deadline, p2p::MAX_CONTROL_BYTES)?;
            if response != request
                || part.len() <= DESCRIPTOR_PREFIX
                || part[..2] != [DESCRIPTOR, VERSION]
                || u32::from_le_bytes(part[2..6].try_into().expect("fixed descriptor offset"))
                    as usize
                    != encoded.len()
                || part.len() - DESCRIPTOR_PREFIX
                    != DESCRIPTOR_CHUNK.min(descriptor_length - encoded.len())
            {
                return Err(p2p::Error::InvalidProtocol);
            }
            encoded.extend_from_slice(&part[DESCRIPTOR_PREFIX..]);
        }
        let descriptor =
            Descriptor::decode(&encoded, self.policy.max_body_bytes).map_err(invalid)?;
        if descriptor.body_bytes != body_bytes as u64 {
            return Err(p2p::Error::InvalidProtocol);
        }
        drop(encoded);
        let (response, frame, first_charge) =
            self.receive_application_before(deadline, PIECE_BYTES + 38)?;
        let first = codec::decode_piece(&frame, pieces(body_bytes)?).map_err(invalid)?;
        if response != request || first.block != block || first.index != 0 {
            return Err(p2p::Error::InvalidProtocol);
        }
        let (authenticated, first) = descriptor
            .authenticate(header, first.bytes.to_vec(), self.policy.max_body_bytes)
            .map_err(invalid)?;
        let mut verified = first.bytes().len();
        ownership.received(verified, authenticated.body_bytes())?;
        drop(frame);
        drop(first_charge);
        let mut indices = Vec::with_capacity(index_count - 1);
        let mut previous = 0;
        for _ in 1..index_count {
            let (response, frame, _charge) =
                self.receive_application_before(deadline, PIECE_BYTES + 38)?;
            let piece =
                codec::decode_piece(&frame, authenticated.piece_count()).map_err(invalid)?;
            if response != request || piece.block != block || piece.index <= previous {
                return Err(p2p::Error::InvalidProtocol);
            }
            previous = piece.index;
            let piece = authenticated
                .verify(piece.index, piece.bytes.to_vec())
                .map_err(invalid)?;
            verified += piece.bytes().len();
            ownership.received(verified, authenticated.body_bytes())?;
            indices.push(piece);
        }
        Ok(Metadata {
            authenticated,
            first,
            indices,
            _reservation,
        })
    }

    /// Consume one previously assigned batch. The owner retains the sole Pieces
    /// claim while workers borrow its unchanged deadline and shared transfer.
    pub fn fetch_propagation_batch(
        &mut self,
        requests: &[PieceRequest],
        transfer: &Mutex<Transfer>,
        ownership: &p2p::BodyClaim,
    ) -> Result<(), p2p::Error> {
        self.fetch_propagation_batch_observed(requests, transfer, ownership, &|_| Ok(()))
    }
    pub fn fetch_propagation_batch_observed(
        &mut self,
        requests: &[PieceRequest],
        transfer: &Mutex<Transfer>,
        ownership: &p2p::BodyClaim,
        observe: &dyn Fn(&Transfer) -> Result<(), p2p::Error>,
    ) -> Result<(), p2p::Error> {
        self.fetch_propagation_batch_mapped(None, requests, transfer, ownership, observe)
    }
    /// Echo one outer turn's nonzero request for every candidate subexchange.
    pub fn fetch_propagation_batch_observed_at(
        &mut self,
        request: u64,
        requests: &[PieceRequest],
        transfer: &Mutex<Transfer>,
        ownership: &p2p::BodyClaim,
        observe: &dyn Fn(&Transfer) -> Result<(), p2p::Error>,
    ) -> Result<(), p2p::Error> {
        if request == 0 {
            return Err(p2p::Error::InvalidProtocol);
        }
        self.fetch_propagation_batch_mapped(Some(request), requests, transfer, ownership, observe)
    }
    fn fetch_propagation_batch_mapped(
        &mut self,
        external_request: Option<u64>,
        requests: &[PieceRequest],
        transfer: &Mutex<Transfer>,
        ownership: &p2p::BodyClaim,
        observe: &dyn Fn(&Transfer) -> Result<(), p2p::Error>,
    ) -> Result<(), p2p::Error> {
        self.with_body_accounting(ownership, |peer| {
            if requests
                .first()
                .is_none_or(|request| request.peer != peer.peer())
            {
                return Err(p2p::Error::Unconfigured);
            }
            let (deadline, count, height) = lock(transfer)?
                .prepare_io(requests, ownership)
                .map_err(resource)?;
            // indices (4 each), a geometrically grown run vector (at most 16
            // each), and final run encoding (at most 8 each) coexist briefly.
            // Keep their original global-budget charge through the whole I/O.
            let query_charge = requests
                .len()
                .checked_mul(32)
                .and_then(|bytes| bytes.checked_add(128))
                .ok_or(p2p::Error::ResourceExhausted)?;
            let _query_reservation = peer.session.shared_budget().reserve(query_charge)?;
            let query = codec::encode_query(height, requests, count).map_err(invalid)?;
            let sequence = external_request.unwrap_or(requests[0].sequence);
            let before = peer.session.io_totals();
            let sent = ownership
                .begin_query(peer.peer())
                .and_then(|()| peer.send_application_before(sequence, &query, &deadline));
            lock(transfer)?
                .sent(
                    peer.peer(),
                    peer.session.io_totals().sent - before.sent,
                    Instant::now(),
                )
                .map_err(resource)?;
            let mut accounted = 0;
            let result = (|| {
                sent?;
                for _ in 0..requests.len() {
                    let frame_before = peer.session.io_totals().received;
                    let (response, frame, _charge) =
                        peer.receive_application_before(&deadline, PIECE_BYTES + 38)?;
                    let piece = codec::decode_piece(&frame, count).map_err(invalid)?;
                    let assigned = requests
                        .iter()
                        .find(|request| request.piece == piece.index)
                        .ok_or(p2p::Error::InvalidProtocol)?;
                    if response != sequence || piece.block != assigned.block {
                        return Err(p2p::Error::InvalidProtocol);
                    }
                    let received = peer.session.io_totals().received - frame_before;
                    // The source's bytes are charged even when authentication or a
                    // stale/duplicate assignment fails. Do not charge them twice.
                    accounted += received;
                    lock(transfer)?
                        .received(*assigned, piece.bytes.to_vec(), received, Instant::now())
                        .map_err(resource)?;
                    let progress = lock(transfer)?;
                    ownership.received(progress.verified_bytes(), progress.body_bytes())?;
                    observe(&progress)?;
                }
                Ok(())
            })();
            if result.is_err() {
                let partial = peer.session.io_totals().received - before.received - accounted;
                let _ = lock(transfer)?.disconnected(peer.peer(), partial, Instant::now());
            }
            result
        })
    }

    pub fn receive_propagation_request(
        &mut self,
        started: Instant,
        lifetime: Duration,
        cancel: p2p::Cancellation,
    ) -> Result<(u64, PropagationRequest), p2p::Error> {
        let deadline = bounded_deadline(started, lifetime, cancel)?;
        self.receive_propagation_request_before(&deadline)
    }
    pub(crate) fn receive_propagation_request_before(
        &mut self,
        deadline: &p2p::Deadline,
    ) -> Result<(u64, PropagationRequest), p2p::Error> {
        let before = self.session.io_totals().received;
        let (request, bytes, _charge) =
            self.receive_application_before(deadline, p2p::MAX_CONTROL_BYTES)?;
        let query = self.decode_propagation_request(
            request,
            &bytes,
            self.session.io_totals().received - before,
        )?;
        Ok((request, query))
    }
    pub(super) fn propagation_request(
        &self,
        request: u64,
        bytes: &[u8],
        received_wire: u64,
    ) -> Option<Result<PropagationRequest, p2p::Error>> {
        matches!(
            bytes.first(),
            Some(&OFFER) | Some(&GET_METADATA) | Some(&0x40)
        )
        .then(|| self.decode_propagation_request(request, bytes, received_wire))
    }
    fn decode_propagation_request(
        &self,
        request: u64,
        bytes: &[u8],
        received_wire: u64,
    ) -> Result<PropagationRequest, p2p::Error> {
        if request == 0 {
            return Err(p2p::Error::InvalidProtocol);
        }
        let query = if bytes.len() == 9
            && bytes[0] == GET_HEADER
            && number(&bytes[1..]) == CAPABILITY_HEIGHT
        {
            PropagationRequest::Capability
        } else if bytes.len() == 10 + crate::eng2::header::HEADER_BYTES
            && bytes[..2] == [OFFER, VERSION]
        {
            if !self.propagation_supported() {
                return Err(p2p::Error::InvalidProtocol);
            }
            let body_bytes = usize::try_from(number(&bytes[2..10])).map_err(invalid)?;
            if body_bytes == 0 || body_bytes > self.policy.max_body_bytes {
                return Err(p2p::Error::ResourceExhausted);
            }
            let header =
                Header::decode(&bytes[10..], &self.session.binding().network).map_err(invalid)?;
            if header.height == 0 {
                return Err(p2p::Error::InvalidProtocol);
            }
            PropagationRequest::Offer(Offer {
                _reservation: self.reserve_application(
                    std::mem::size_of::<Offer>() + std::mem::size_of::<Header>(),
                )?,
                header: Box::new(header),
                body_bytes,
                request,
                peer: self.peer(),
                binding: self.session.binding(),
                session_id: self.propagation_session,
                received_wire,
            })
        } else if bytes.len() == 42 && bytes[..2] == [GET_METADATA, VERSION] {
            let height = u64::from_le_bytes(bytes[2..10].try_into().expect("fixed height"));
            if height == 0 {
                return Err(p2p::Error::InvalidProtocol);
            }
            PropagationRequest::Metadata {
                height,
                id: bytes[10..42].try_into().expect("fixed block identity"),
            }
        } else {
            let maximum = pieces(self.policy.max_body_bytes)?;
            let count = codec::query_piece_count(bytes, maximum).map_err(invalid)?;
            let charge = count
                .checked_mul(std::mem::size_of::<usize>())
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<codec::Query>()))
                .ok_or(p2p::Error::ResourceExhausted)?;
            let reservation = self.session.shared_budget().reserve(charge)?;
            let mut query = codec::decode_query(bytes, maximum).map_err(invalid)?;
            query.retain_reservation(reservation);
            PropagationRequest::Pieces(query)
        };
        Ok(query)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send_propagation_metadata(
        &mut self,
        request: u64,
        header: &Header,
        body: &Body,
        started: Instant,
        lifetime: Duration,
        cancel: p2p::Cancellation,
    ) -> Result<(), p2p::Error> {
        self.send_propagation_metadata_before(
            request,
            header,
            body,
            &bounded_deadline(started, lifetime, cancel)?,
        )
    }
    pub(crate) fn send_propagation_metadata_before(
        &mut self,
        request: u64,
        header: &Header,
        body: &Body,
        deadline: &p2p::Deadline,
    ) -> Result<(), p2p::Error> {
        if header.network != self.session.binding().network
            || body.network != header.network
            || body.height != header.height
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        let length = body.encoded_len(self.policy).map_err(invalid)?;
        let _charge = self.reserve_body(length)?;
        let encoded = body.encode(self.policy).map_err(invalid)?;
        header
            .verify_body(&encoded, self.policy.max_body_bytes)
            .map_err(invalid)?;
        let descriptor = Descriptor::build(&encoded, self.policy.max_body_bytes)
            .map_err(invalid)?
            .encode(self.policy.max_body_bytes)
            .map_err(invalid)?;
        let indices = framing::index_pieces(body, self.policy).map_err(invalid)?;
        let mut start = vec![METADATA, VERSION];
        start.extend_from_slice(&(length as u64).to_le_bytes());
        start.extend_from_slice(
            &u32::try_from(descriptor.len())
                .map_err(invalid)?
                .to_le_bytes(),
        );
        start.extend_from_slice(&u32::try_from(indices.len()).map_err(invalid)?.to_le_bytes());
        self.send_application_before(request, &start, deadline)?;
        for (index, part) in descriptor.chunks(DESCRIPTOR_CHUNK).enumerate() {
            let mut frame = vec![DESCRIPTOR, VERSION];
            frame.extend_from_slice(&((index * DESCRIPTOR_CHUNK) as u32).to_le_bytes());
            frame.extend_from_slice(part);
            self.send_application_before(request, &frame, deadline)?;
        }
        let block = header.id().map_err(invalid)?;
        for index in indices {
            let piece = authentication::encoded_piece(&encoded, index).map_err(invalid)?;
            self.send_application_before(
                request,
                &codec::encode_piece(block, index, &piece).map_err(invalid)?,
                deadline,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send_propagation_pieces(
        &mut self,
        request: u64,
        query: &codec::Query,
        header: &Header,
        body: &Body,
        started: Instant,
        lifetime: Duration,
        cancel: p2p::Cancellation,
    ) -> Result<(), p2p::Error> {
        self.send_propagation_pieces_before(
            request,
            query,
            header,
            body,
            &bounded_deadline(started, lifetime, cancel)?,
        )
    }
    pub(crate) fn send_propagation_pieces_before(
        &mut self,
        request: u64,
        query: &codec::Query,
        header: &Header,
        body: &Body,
        deadline: &p2p::Deadline,
    ) -> Result<(), p2p::Error> {
        if query.block != header.id().map_err(invalid)?
            || query.height != header.height
            || header.network != self.session.binding().network
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        let length = body.encoded_len(self.policy).map_err(invalid)?;
        let _charge = self.reserve_body(length)?;
        let encoded = body.encode(self.policy).map_err(invalid)?;
        header
            .verify_body(&encoded, self.policy.max_body_bytes)
            .map_err(invalid)?;
        let count = pieces(length)?;
        if query.pieces.is_empty()
            || query.pieces.len() > count
            || query.pieces.windows(2).any(|pair| pair[0] >= pair[1])
            || query.pieces.last().is_some_and(|&index| index >= count)
        {
            return Err(p2p::Error::InvalidProtocol);
        }
        for &index in &query.pieces {
            let piece = authentication::encoded_piece(&encoded, index).map_err(invalid)?;
            self.send_application_before(
                request,
                &codec::encode_piece(query.block, index, &piece).map_err(invalid)?,
                deadline,
            )?;
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::eng2::{genesis::FeeMode, propagation::pipeline::Limits};
    use std::{os::unix::net::UnixStream, thread};

    fn fixture() -> (Genesis, Policy, Body, Header) {
        let state = crate::eng2::snapshot::tests::bootstrap();
        let genesis =
            Genesis::seal(state.chain.config, state.governance, FeeMode::LegacyMiner).unwrap();
        let policy = Policy {
            profile: crate::proofs::protocol_profile_fingerprint(),
            max_body_bytes: 4 * 1024 * 1024,
            max_settlement_proof_bytes: 3 * 1024 * 1024,
        };
        let mut body = crate::eng2::body::tests::body();
        body.network = genesis.config().network;
        body.profile = policy.profile;
        body.governance.clear();
        body.fund_claims.clear();
        body.transactions
            .sort_by_key(|tx| tx.record.statement_id(&body.network));
        body.settlement_proof = vec![8; 24 * 1024 + 7];
        let header = Header {
            network: body.network,
            height: body.height,
            parent: genesis.id(),
            timestamp: 123,
            target: [255; 32],
            execution_commitment: [2; 32],
            body_commitment: body.commitment(policy).unwrap(),
            nonce: 1,
        };
        (genesis, policy, body, header)
    }
    fn peer(
        socket: UnixStream,
        genesis: &Genesis,
        policy: Policy,
        budget: p2p::Budget,
    ) -> Peer<UnixStream> {
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        Peer::new(
            p2p::Session::from_test_channel(socket, binding(genesis), budget),
            genesis,
            policy,
        )
        .unwrap()
    }
    fn ledger(header: &Header) -> DescriptorLedger {
        DescriptorLedger::new(
            header.id().unwrap(),
            &[[9; 32]],
            Limits {
                requests: 4,
                wire_bytes: 64 * 1024 * 1024,
                peer_requests: 1,
                peer_wire_bytes: 64 * 1024 * 1024,
                parallel: 1,
                lifetime: Duration::from_secs(3),
            },
            Instant::now(),
        )
        .unwrap()
    }

    #[test]
    fn metadata_then_one_batch_roundtrip_retains_one_body_claim_and_exact_io_accounting() {
        let (genesis, policy, body, header) = fixture();
        let (client, server) = UnixStream::pair().unwrap();
        let budget = p2p::Budget::new(64 * 1024 * 1024);
        let available = budget.available().unwrap();
        let mut client = peer(client, &genesis, policy, budget.clone());
        let mut server = peer(server, &genesis, policy, p2p::Budget::new(64 * 1024 * 1024));
        let expected = body.encode(policy).unwrap();
        let server_header = header.clone();
        let worker = thread::spawn(move || {
            let started = Instant::now();
            let cancel = p2p::Cancellation::default();
            let (sequence, request) = server
                .receive_propagation_request(started, Duration::from_secs(3), cancel.clone())
                .unwrap();
            assert_eq!(sequence, 91);
            assert!(
                matches!(request,PropagationRequest::Metadata {height,id} if height==server_header.height&&id==server_header.id().unwrap())
            );
            server
                .send_propagation_metadata(
                    sequence,
                    &server_header,
                    &body,
                    started,
                    Duration::from_secs(3),
                    cancel.clone(),
                )
                .unwrap();
            let (sequence, request) = server
                .receive_propagation_request(started, Duration::from_secs(3), cancel.clone())
                .unwrap();
            assert_eq!(sequence, 91);
            let PropagationRequest::Pieces(query) = request else {
                panic!("expected pieces")
            };
            server
                .send_propagation_pieces(
                    sequence,
                    &query,
                    &server_header,
                    &body,
                    started,
                    Duration::from_secs(3),
                    cancel,
                )
                .unwrap();
            server.session.io_totals()
        });
        let deadline = p2p::Deadline::new(Duration::from_secs(3));
        let ownership = client
            .claim_body(&header, p2p::BodyMode::Pieces, &deadline)
            .unwrap();
        assert!(matches!(
            client.claim_body(&header, p2p::BodyMode::Legacy, &deadline),
            Err(p2p::BodyClaimError::Busy)
        ));
        let mut ledger = ledger(&header);
        let metadata = client
            .fetch_propagation_metadata_at(91, &header, &mut ledger, &ownership)
            .unwrap();
        let mut transfer = metadata.into_transfer(ledger, &budget).unwrap();
        let batch = transfer
            .next_batch([9; 32], None, usize::MAX, Instant::now())
            .unwrap();
        assert!(!batch.is_empty());
        let transfer = Mutex::new(transfer);
        client
            .fetch_propagation_batch_observed_at(91, &batch, &transfer, &ownership, &|_| Ok(()))
            .unwrap();
        assert!(
            client
                .fetch_propagation_batch(&batch, &transfer, &ownership)
                .is_err()
        );
        let transfer = transfer.into_inner().unwrap();
        let sources = transfer.sources();
        let client_io = client.session.io_totals();
        let server_io = worker.join().unwrap();
        assert_eq!(client_io.sent, server_io.received);
        assert_eq!(client_io.received, server_io.sent);
        assert_eq!(sources[0].sent, client_io.sent);
        assert_eq!(sources[0].received, client_io.received);
        assert_eq!(sources[0].requested, 1);
        assert_eq!(sources[0].queries, 2);
        assert_eq!(transfer.verified_bytes(), expected.len());
        let received = transfer
            .finish(&header, policy, Instant::now(), ownership)
            .unwrap();
        assert_eq!(received.body.encode(policy).unwrap(), expected);
        assert!(matches!(
            client.claim_body(&header, p2p::BodyMode::Legacy, &deadline),
            Err(p2p::BodyClaimError::Busy)
        ));
        let (accounts, metadata) = budget.retained_body_accounting();
        assert_eq!(accounts, 1);
        assert!(metadata > 0);
        assert!(budget.available().unwrap() + metadata < available);
        drop(received);
        let (accounts, metadata) = budget.retained_body_accounting();
        assert_eq!(accounts, 1);
        assert!(metadata > 0);
        assert_eq!(budget.available().unwrap() + metadata, available);
        assert!(matches!(
            client.claim_body(&header, p2p::BodyMode::Legacy, &deadline),
            Err(p2p::BodyClaimError::SourceUsed)
        ));
        assert!(
            budget
                .claim_body(
                    binding(&genesis),
                    header.height,
                    header.id().unwrap(),
                    [8; 32],
                    p2p::BodyMode::Legacy,
                    &deadline
                )
                .is_ok()
        );
    }

    #[test]
    fn failed_metadata_keeps_partial_bytes_and_allows_bounded_failed_source_retry() {
        let (genesis, policy, _body, header) = fixture();
        let (client, server) = UnixStream::pair().unwrap();
        let budget = p2p::Budget::new(64 * 1024 * 1024);
        let mut client = peer(client, &genesis, policy, budget.clone());
        let mut server = peer(server, &genesis, policy, p2p::Budget::new(64 * 1024 * 1024));
        let worker = thread::spawn(move || {
            let deadline = p2p::Deadline::new(Duration::from_secs(3));
            let (sequence, _) = server
                .receive_propagation_request_before(&deadline)
                .unwrap();
            server
                .send_application_before(sequence, &[METADATA, VERSION, 0], &deadline)
                .unwrap();
            server.session.io_totals()
        });
        let deadline = p2p::Deadline::new(Duration::from_secs(3));
        let ownership = client
            .claim_body(&header, p2p::BodyMode::Pieces, &deadline)
            .unwrap();
        let mut ledger = ledger(&header);
        assert!(
            client
                .fetch_propagation_metadata(&header, &mut ledger, &ownership)
                .is_err()
        );
        let after = client.session.io_totals();
        let remote = worker.join().unwrap();
        assert!(after.received > 0 && after.sent > 0);
        assert_eq!(after.received, remote.sent);
        assert!(
            client
                .fetch_propagation_metadata(&header, &mut ledger, &ownership)
                .is_err()
        );
        let final_io = client.session.io_totals();
        assert_eq!(after.received, final_io.received);
        assert_eq!(after.sent, final_io.sent);
        let (accounts, metadata) = budget.retained_body_accounting();
        assert_eq!(accounts, 1);
        assert!(metadata > 0);
        assert!(budget.available().unwrap() + metadata < 64 * 1024 * 1024);
        drop(ownership);
        let (accounts, metadata) = budget.retained_body_accounting();
        assert_eq!(accounts, 1);
        assert!(metadata > 0);
        assert_eq!(budget.available().unwrap() + metadata, 64 * 1024 * 1024);
        let retry = client
            .claim_body(&header, p2p::BodyMode::Legacy, &deadline)
            .unwrap();
        assert_eq!(retry.deadline().expires_at(), deadline.expires_at());
        assert_eq!(retry.source_ordinal(), Some(2));
        drop(retry);
        assert!(
            budget
                .claim_body(
                    binding(&genesis),
                    header.height,
                    header.id().unwrap(),
                    [8; 32],
                    p2p::BodyMode::Legacy,
                    &deadline,
                )
                .is_ok()
        );
    }

    #[test]
    fn negotiated_offer_credit_metadata_and_continuation_share_one_candidate_ledger() {
        let (genesis, policy, body, header) = fixture();
        let expected = body.encode(policy).unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        let budget = p2p::Budget::new(64 * 1024 * 1024);
        let mut source = peer(a, &genesis, policy, p2p::Budget::new(64 * 1024 * 1024));
        let mut receiver = peer(b, &genesis, policy, budget.clone());
        let received_header = header.clone();
        let worker = thread::spawn(move || {
            let started = Instant::now();
            let lifetime = Duration::from_secs(3);
            let cancel = p2p::Cancellation::default();
            let (request, capability) = receiver
                .receive_propagation_request(started, lifetime, cancel.clone())
                .unwrap();
            assert!(matches!(capability, PropagationRequest::Capability));
            receiver.send_propagation_capabilities(request).unwrap();
            let before = receiver.session.io_totals();
            let (_, request) = receiver
                .receive_propagation_request(started, lifetime, cancel.clone())
                .unwrap();
            let PropagationRequest::Offer(offer) = request else {
                panic!("expected offer")
            };
            assert_eq!(offer.header(), &received_header);
            assert_eq!(offer.request(), 77);
            assert_eq!(offer.peer(), [9; 32]);
            let deadline = bounded_deadline(started, lifetime, cancel).unwrap();
            let ownership = receiver
                .claim_body(&received_header, p2p::BodyMode::Pieces, &deadline)
                .unwrap();
            let mut ledger = ledger(&received_header);
            let metadata = receiver
                .accept_propagation_offer(offer, &mut ledger, &ownership)
                .unwrap();
            let mut transfer = metadata.into_transfer(ledger, &budget).unwrap();
            let batch = transfer
                .next_batch([9; 32], None, usize::MAX, Instant::now())
                .unwrap();
            let transfer = Mutex::new(transfer);
            let observations = std::sync::atomic::AtomicUsize::new(0);
            receiver
                .fetch_propagation_batch_observed_at(
                    77,
                    &batch,
                    &transfer,
                    &ownership,
                    &|progress| {
                        assert!(progress.verified_bytes() > 0);
                        observations.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(
                observations.load(std::sync::atomic::Ordering::Relaxed),
                batch.len()
            );
            let transfer = transfer.into_inner().unwrap();
            let stats = transfer.sources()[0];
            let after = receiver.session.io_totals();
            assert_eq!(stats.queries, 2);
            assert_eq!(stats.requested, 1);
            assert_eq!(stats.received, after.received - before.received);
            assert_eq!(stats.sent, after.sent - before.sent);
            transfer
                .finish(&received_header, policy, Instant::now(), ownership)
                .unwrap()
                .body
                .encode(policy)
                .unwrap()
        });
        assert!(source.probe_propagation(12).unwrap());
        let started = Instant::now();
        let cancel = p2p::Cancellation::default();
        let credit = source
            .offer_propagation(
                77,
                &header,
                expected.len(),
                started,
                Duration::from_secs(3),
                cancel.clone(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(credit.block(), header.id().unwrap());
        assert_eq!(credit.session_id(), source.propagation_session_id());
        source
            .send_credited_metadata(credit, &header, &body)
            .unwrap();
        let (request, query) = source
            .receive_propagation_request(started, Duration::from_secs(3), cancel.clone())
            .unwrap();
        assert_eq!(request, 77);
        let PropagationRequest::Pieces(query) = query else {
            panic!("expected continuation")
        };
        source
            .send_propagation_pieces(
                request,
                &query,
                &header,
                &body,
                started,
                Duration::from_secs(3),
                cancel,
            )
            .unwrap();
        assert_eq!(worker.join().unwrap(), expected);
    }

    #[test]
    fn credit_from_another_session_and_expired_credit_cannot_write_metadata() {
        let (genesis, policy, body, header) = fixture();
        let (a, _first_remote) = UnixStream::pair().unwrap();
        let (b, _second_remote) = UnixStream::pair().unwrap();
        let first = peer(a, &genesis, policy, p2p::Budget::default());
        let mut second = peer(b, &genesis, policy, p2p::Budget::default());
        let credit = |session, deadline| Credit {
            deadline,
            block: header.id().unwrap(),
            height: header.height,
            body_bytes: body.encoded_len(policy).unwrap(),
            request: 1,
            peer: [9; 32],
            binding: binding(&genesis),
            session_id: session,
            maximum_wire: maximum_wire(body.encoded_len(policy).unwrap()).unwrap(),
        };
        assert!(
            second
                .send_credited_metadata(
                    credit(
                        first.propagation_session_id(),
                        p2p::Deadline::new(Duration::from_secs(3))
                    ),
                    &header,
                    &body
                )
                .is_err()
        );
        let expired = p2p::Deadline::from_started(
            Instant::now() - Duration::from_secs(4),
            Duration::from_secs(3),
            p2p::Cancellation::default(),
        );
        assert!(
            second
                .send_credited_metadata(
                    credit(second.propagation_session_id(), expired),
                    &header,
                    &body
                )
                .is_err()
        );
        assert_eq!(second.session.io_totals().sent, 0);
    }
    #[test]
    fn sparse_missing_piece_runs_precharge_the_full_query_before_socket_io() {
        let (genesis, policy, mut body, mut header) = fixture();
        body.settlement_proof = vec![8; 64 * PIECE_BYTES];
        header.body_commitment = body.commitment(policy).unwrap();
        let encoded = body.encode(policy).unwrap();
        let expected = encoded.clone();
        let descriptor = Descriptor::build(&encoded, policy.max_body_bytes).unwrap();
        let (local_auth, _) = descriptor
            .authenticate(
                &header,
                authentication::encoded_piece(&encoded, 0).unwrap(),
                policy.max_body_bytes,
            )
            .unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        let budget = p2p::Budget::new(64 * 1024 * 1024);
        let mut client = peer(a, &genesis, policy, budget.clone());
        let mut server = peer(b, &genesis, policy, p2p::Budget::new(64 * 1024 * 1024));
        let server_header = header.clone();
        let worker = thread::spawn(move || {
            let started = Instant::now();
            let cancel = p2p::Cancellation::default();
            let (sequence, request) = server
                .receive_propagation_request(started, Duration::from_secs(3), cancel.clone())
                .unwrap();
            assert!(matches!(request, PropagationRequest::Metadata { .. }));
            server
                .send_propagation_metadata(
                    sequence,
                    &server_header,
                    &body,
                    started,
                    Duration::from_secs(3),
                    cancel.clone(),
                )
                .unwrap();
            let (sequence, request) = server
                .receive_propagation_request(started, Duration::from_secs(3), cancel.clone())
                .unwrap();
            let PropagationRequest::Pieces(query) = request else {
                panic!("expected sparse pieces")
            };
            assert!(
                query
                    .pieces
                    .windows(2)
                    .filter(|pair| pair[1] > pair[0] + 1)
                    .count()
                    > 10
            );
            server
                .send_propagation_pieces(
                    sequence,
                    &query,
                    &server_header,
                    &body,
                    started,
                    Duration::from_secs(3),
                    cancel,
                )
                .unwrap();
        });
        let deadline = p2p::Deadline::new(Duration::from_secs(3));
        let ownership = client
            .claim_body(&header, p2p::BodyMode::Pieces, &deadline)
            .unwrap();
        let mut ledger = ledger(&header);
        let metadata = client
            .fetch_propagation_metadata(&header, &mut ledger, &ownership)
            .unwrap();
        let mut transfer = metadata.into_transfer(ledger, &budget).unwrap();
        // Simulate already authenticated local envelope interiors. Alternating
        // pieces leave enough disjoint runs to exceed the fixed frame prefix.
        for index in (2..local_auth.piece_count()).step_by(2) {
            if transfer
                .authenticated_bytes(local_auth.range(index).unwrap())
                .is_some()
            {
                continue;
            }
            let piece = local_auth
                .verify(
                    index,
                    authentication::encoded_piece(&encoded, index).unwrap(),
                )
                .unwrap();
            transfer.index_piece(piece, Instant::now()).unwrap();
        }
        let batch = transfer
            .next_batch([9; 32], None, usize::MAX, Instant::now())
            .unwrap();
        let query = codec::encode_query(header.height, &batch, local_auth.piece_count()).unwrap();
        assert!(query.len() > 128);
        let stats = transfer.sources()[0];
        let before = client.session.io_totals();
        let transfer = Mutex::new(transfer);
        client
            .fetch_propagation_batch(&batch, &transfer, &ownership)
            .unwrap();
        let actual_query = client.session.io_totals().sent - before.sent;
        assert!(actual_query > 128);
        assert!(stats.reserved_wire >= stats.received + stats.sent + actual_query);
        let transfer = transfer.into_inner().unwrap();
        let stats = transfer.sources()[0];
        assert!(stats.received + stats.sent <= stats.reserved_wire);
        assert_eq!(stats.queries, 2);
        assert_eq!(
            transfer
                .finish(&header, policy, Instant::now(), ownership)
                .unwrap()
                .body
                .encode(policy)
                .unwrap(),
            expected
        );
        worker.join().unwrap();
    }

    #[test]
    fn compact_query_expansion_keeps_a_global_charge_and_rejects_before_allocation_when_full() {
        let (genesis, policy, _, _) = fixture();
        let mut bytes = vec![0x40, VERSION];
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&[3; 32]);
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&1000u32.to_le_bytes());
        let (a, _remote) = UnixStream::pair().unwrap();
        let budget = p2p::Budget::new(16 * 1024);
        let client = peer(a, &genesis, policy, budget.clone());
        let before = budget.available().unwrap();
        let query = client
            .decode_propagation_request(1, &bytes, bytes.len() as u64)
            .unwrap();
        assert!(before - budget.available().unwrap() >= 1000 * std::mem::size_of::<usize>());
        let PropagationRequest::Pieces(query) = query else {
            panic!("expected query")
        };
        assert_eq!(query.pieces.len(), 1000);
        drop(query);
        assert_eq!(budget.available().unwrap(), before);
        let blocker = budget.reserve(before - 1024).unwrap();
        let remaining = budget.available().unwrap();
        assert!(matches!(
            client.decode_propagation_request(1, &bytes, bytes.len() as u64),
            Err(p2p::Error::ResourceExhausted)
        ));
        assert_eq!(budget.available().unwrap(), remaining);
        drop(blocker);
        assert_eq!(budget.available().unwrap(), before);
    }

    #[cfg(feature = "eng2-runtime")]
    fn source_confirmation_two_lanes(second_has_body: bool) {
        use std::sync::{Arc, Condvar};
        let (genesis, policy, body, header) = fixture();
        let budget = p2p::Budget::new(64 * 1024 * 1024);
        let mut clients = Vec::new();
        let mut workers = Vec::new();
        let concurrent = Arc::new((Mutex::new(0usize), Condvar::new()));
        for index in 1..=2u8 {
            let (a, b) = UnixStream::pair().unwrap();
            a.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            a.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
            let client = Peer::new(
                p2p::Session::from_test_peer_channel(
                    a,
                    binding(&genesis),
                    budget.clone(),
                    [index; 32],
                    p2p::Role::Miner,
                ),
                &genesis,
                policy,
            )
            .unwrap();
            let mut server = peer(b, &genesis, policy, p2p::Budget::new(64 * 1024 * 1024));
            clients.push(client);
            let body = body.clone();
            let header = header.clone();
            let concurrent = concurrent.clone();
            workers.push(thread::spawn(move || {
                let start = Instant::now(); let cancel = p2p::Cancellation::default();
                let (request,message) = server.receive_propagation_request(start, Duration::from_secs(3), cancel.clone()).unwrap();
                assert_eq!(request, 90 + u64::from(index));
                assert!(matches!(message, PropagationRequest::Metadata {height,id} if height==header.height && id==header.id().unwrap()));
                if index == 2 && !second_has_body {
                    server.send_unavailable(request, header.height).unwrap();
                    return server.session.io_totals();
                }
                server.send_propagation_metadata(request, &header, &body, start, Duration::from_secs(3), cancel.clone()).unwrap();
                let (request,message) = server.receive_propagation_request(start, Duration::from_secs(3), cancel.clone()).unwrap();
                let PropagationRequest::Pieces(query) = message else { panic!("expected body continuation"); };
                if second_has_body {
                    let (count, changed) = &*concurrent;
                    let mut count = count.lock().unwrap();
                    *count += 1;
                    changed.notify_all();
                    let (count, _) = changed.wait_timeout_while(count, Duration::from_secs(1), |n| *n < 2).unwrap();
                    assert_eq!(*count, 2, "both body requests must be in flight");
                }
                server.send_propagation_pieces(request, &query, &header, &body, start, Duration::from_secs(3), cancel).unwrap();
                server.session.io_totals()
            }));
        }
        let mut second = clients.pop().unwrap();
        let mut first = clients.pop().unwrap();
        let deadline = p2p::Deadline::new(Duration::from_secs(3));
        let owner = first
            .claim_body(&header, p2p::BodyMode::Pieces, &deadline)
            .unwrap();
        let expiry = owner.deadline().expires_at();
        let generation = owner.progress_attempt();
        let mut ledger = DescriptorLedger::new(
            header.id().unwrap(),
            &[[1; 32], [2; 32]],
            Limits {
                requests: 4,
                wire_bytes: 64 * 1024 * 1024,
                peer_requests: 1,
                peer_wire_bytes: 64 * 1024 * 1024,
                parallel: 3,
                lifetime: Duration::from_secs(3),
            },
            Instant::now(),
        )
        .unwrap();
        let metadata = first
            .fetch_propagation_metadata_at(91, &header, &mut ledger, &owner)
            .unwrap();
        let transfer = Mutex::new(metadata.into_transfer(ledger, &budget).unwrap());
        let confirmed = second.fetch_propagation_confirmation_at(92, &header, &transfer, &owner);
        if second_has_body {
            assert!(confirmed.unwrap());
        } else {
            assert!(confirmed.is_err());
        }
        assert_eq!(owner.deadline().expires_at(), expiry);
        assert_eq!(owner.progress_attempt(), generation);
        let connected = std::collections::BTreeSet::from([[1; 32], [2; 32]]);
        let mut locked = transfer.lock().unwrap();
        let maximum = locked.batch_capacity(&connected);
        let first_batch = locked
            .next_batch([1; 32], None, maximum, Instant::now())
            .unwrap();
        let second_batch = if second_has_body {
            let maximum = locked.batch_capacity(&connected);
            locked
                .next_batch([2; 32], None, maximum, Instant::now())
                .unwrap()
        } else {
            vec![]
        };
        assert!(!first_batch.is_empty());
        if second_has_body {
            assert!(!second_batch.is_empty());
        }
        drop(locked);
        thread::scope(|scope| {
            scope.spawn(|| {
                first
                    .fetch_propagation_batch_observed_at(
                        91,
                        &first_batch,
                        &transfer,
                        &owner,
                        &|_| Ok(()),
                    )
                    .unwrap()
            });
            if second_has_body {
                scope.spawn(|| {
                    second
                        .fetch_propagation_batch_observed_at(
                            92,
                            &second_batch,
                            &transfer,
                            &owner,
                            &|_| Ok(()),
                        )
                        .unwrap()
                });
            }
        });
        let first_remote = workers.remove(0).join().unwrap();
        let second_remote = workers.remove(0).join().unwrap();
        let finished = transfer.into_inner().unwrap();
        let sources = finished.sources();
        for (source, local, remote) in [
            (sources[0], first.session.io_totals(), first_remote),
            (sources[1], second.session.io_totals(), second_remote),
        ] {
            assert_eq!((source.sent, source.received), (local.sent, local.received));
            assert_eq!((local.sent, local.received), (remote.received, remote.sent));
            assert_eq!(source.requested, 1);
        }
        assert_eq!(
            sources.iter().map(|s| s.queries).sum::<u64>(),
            if second_has_body { 4 } else { 3 }
        );
        assert_eq!(
            finished
                .finish(&header, policy, Instant::now(), owner)
                .unwrap()
                .body
                .encode(policy)
                .unwrap(),
            body.encode(policy).unwrap()
        );
    }

    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn source_confirmation_real_two_lanes_transfer_concurrently_under_one_owner() {
        source_confirmation_two_lanes(true);
    }

    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn source_confirmation_real_negative_metadata_leaves_the_first_holder_complete() {
        source_confirmation_two_lanes(false);
    }

    #[cfg(feature = "eng2-runtime")]
    #[test]
    fn source_confirmation_slow_real_lane_cannot_renew_the_original_deadline() {
        let (genesis, policy, body, header) = fixture();
        let budget = p2p::Budget::new(64 * 1024 * 1024);
        let (a, b) = UnixStream::pair().unwrap();
        let mut first = peer(a, &genesis, policy, budget.clone());
        let mut first_server = peer(b, &genesis, policy, p2p::Budget::new(64 * 1024 * 1024));
        let server_body = body.clone();
        let server_header = header.clone();
        let initial = thread::spawn(move || {
            let start = Instant::now();
            let cancel = p2p::Cancellation::default();
            let (request, _) = first_server
                .receive_propagation_request(start, Duration::from_secs(3), cancel.clone())
                .unwrap();
            first_server
                .send_propagation_metadata(
                    request,
                    &server_header,
                    &server_body,
                    start,
                    Duration::from_secs(3),
                    cancel,
                )
                .unwrap();
            first_server
        });
        let deadline = p2p::Deadline::new(Duration::from_millis(400));
        let owner = first
            .claim_body(&header, p2p::BodyMode::Pieces, &deadline)
            .unwrap();
        let mut ledger = DescriptorLedger::new(
            header.id().unwrap(),
            &[[9; 32], [2; 32]],
            Limits {
                requests: 4,
                wire_bytes: 64 * 1024 * 1024,
                peer_requests: 1,
                peer_wire_bytes: 64 * 1024 * 1024,
                parallel: 3,
                lifetime: Duration::from_secs(3),
            },
            Instant::now(),
        )
        .unwrap();
        let metadata = first
            .fetch_propagation_metadata_at(91, &header, &mut ledger, &owner)
            .unwrap();
        let _live_first_server = initial.join().unwrap();
        let transfer = Mutex::new(metadata.into_transfer(ledger, &budget).unwrap());
        let expiry = owner.deadline().expires_at();
        let generation = owner.progress_attempt();
        let (a, b) = UnixStream::pair().unwrap();
        a.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        a.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut second = Peer::new(
            p2p::Session::from_test_peer_channel(
                a,
                binding(&genesis),
                budget.clone(),
                [2; 32],
                p2p::Role::Miner,
            ),
            &genesis,
            policy,
        )
        .unwrap();
        let mut second_server = peer(b, &genesis, policy, p2p::Budget::new(64 * 1024 * 1024));
        let (seen_send, seen) = std::sync::mpsc::sync_channel(1);
        let delayed_header = header.clone();
        let delayed = thread::spawn(move || {
            let start = Instant::now();
            let cancel = p2p::Cancellation::default();
            let (request, _) = second_server
                .receive_propagation_request(start, Duration::from_secs(3), cancel.clone())
                .unwrap();
            seen_send.send(()).unwrap();
            std::thread::sleep(
                expiry.saturating_duration_since(Instant::now()) + Duration::from_millis(20),
            );
            let _ = second_server.send_propagation_metadata(
                request,
                &delayed_header,
                &body,
                start,
                Duration::from_secs(3),
                cancel,
            );
        });
        thread::scope(|scope| {
            let pending = scope
                .spawn(|| second.fetch_propagation_confirmation_at(92, &header, &transfer, &owner));
            seen.recv_timeout(Duration::from_secs(1)).unwrap();
            let connected = std::collections::BTreeSet::from([[9; 32], [2; 32]]);
            assert_eq!(transfer.lock().unwrap().batch_capacity(&connected), 0);
            assert!(pending.join().unwrap().is_err());
        });
        delayed.join().unwrap();
        assert_eq!(owner.deadline().expires_at(), expiry);
        assert_eq!(owner.progress_attempt(), generation);
        assert!(owner.check_active().is_err());
        let mut transfer = transfer.into_inner().unwrap();
        assert!(matches!(
            transfer.next_batch([9; 32], None, usize::MAX, Instant::now()),
            Err(crate::eng2::propagation::pipeline::Error::Expired)
        ));
        assert_eq!(transfer.sources().iter().map(|s| s.queries).sum::<u64>(), 2);
    }
}
