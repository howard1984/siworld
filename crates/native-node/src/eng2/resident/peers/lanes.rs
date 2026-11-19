//! Independent authenticated optional sockets, each retained by one peer worker.
use super::super::header_lane::Hub;
use super::*;
use crate::eng2::transport::{Request, propagation::PropagationRequest};
mod pieces;
struct ConnectedLane {
    status: Arc<NetworkStatus>,
    headers: Arc<Hub>,
    peer: Hash,
    lane: Lane,
    ordinal: u64,
    session_id: u64,
}
impl Drop for ConnectedLane {
    fn drop(&mut self) {
        if let Ok(mut status) = self.status.inner.lock() {
            status.lanes.remove(&(self.peer, self.lane as u8));
        }
        if self.lane == Lane::Headers {
            self.headers.disconnected(self.peer);
        } else {
            self.headers.forget_body_tip(self.peer, self.session_id);
        }
    }
}
pub(super) fn lane_session(
    mut peer: Peer<p2p::NativeTlsChannel>,
    initiator: bool,
    lane: Lane,
    shared: &Arc<Shared>,
) -> Result<(), String> {
    let fingerprint = peer.peer();
    let _connected = {
        let ordinal = shared.network.admit_lane(fingerprint, lane)?;
        ConnectedLane {
            ordinal,
            session_id: peer.propagation_session_id(),
            status: shared.network.clone(),
            headers: shared.headers.clone(),
            peer: fingerprint,
            lane,
        }
    };
    peer.observe_connection(_connected.ordinal);
    match lane {
        Lane::Headers => headers(&mut peer, initiator, shared),
        Lane::Bodies => bodies(&mut peer, initiator, shared),
    }
}
fn pause(shared: &Shared, millis: u64) {
    for _ in 0..millis.div_ceil(10) {
        if shared.cancel.is_cancelled() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn headers(
    peer: &mut Peer<p2p::NativeTlsChannel>,
    initiator: bool,
    shared: &Shared,
) -> Result<(), String> {
    let mut sequence = 1u64;
    while !shared.cancel.is_cancelled() {
        if !peer.ready_for_cycle() {
            return Ok(());
        }
        if initiator {
            sequence = sequence
                .checked_add(1)
                .ok_or("header lane sequence exhausted")?;
            let outgoing = shared.headers.outgoing(peer.peer())?;
            peer.send_headers(sequence, &outgoing)
                .map_err(|_| "header lane transmission failed")?;
            for header in &outgoing {
                shared.block_events.header_forwarded(header);
            }
            let (request, incoming) = peer
                .receive_headers()
                .map_err(|_| "header lane response rejected")?;
            if request != sequence {
                return Err("header lane response sequence differs".into());
            }
            for header in incoming {
                if shared.headers.offer(header.clone(), peer.peer())? {
                    shared.block_events.header_qualified(&header);
                }
            }
        } else {
            let (request, incoming) = peer
                .receive_headers()
                .map_err(|_| "header lane request rejected")?;
            if request
                != sequence
                    .checked_add(1)
                    .ok_or("header lane sequence exhausted")?
            {
                return Err("header lane request sequence differs".into());
            }
            sequence = request;
            for header in incoming {
                if shared.headers.offer(header.clone(), peer.peer())? {
                    shared.block_events.header_qualified(&header);
                }
            }
            let outgoing = shared.headers.outgoing(peer.peer())?;
            peer.send_headers(request, &outgoing)
                .map_err(|_| "header lane response failed")?;
            for header in &outgoing {
                shared.block_events.header_forwarded(header);
            }
        }
        pause(shared, 50);
    }
    Ok(())
}
fn bodies(
    peer: &mut Peer<p2p::NativeTlsChannel>,
    initiator: bool,
    shared: &Shared,
) -> Result<(), String> {
    let mut outgoing = 1u64;
    let mut incoming = 1u64;
    let mut source_announced = false;
    while !shared.cancel.is_cancelled() {
        if !peer.ready_for_cycle() {
            return Ok(());
        }
        if initiator {
            pull_one(peer, shared, &mut outgoing, &mut source_announced)?;
            peer.finish_round(outgoing)
                .map_err(|_| "body lane turn completion failed")?;
            serve_turn(peer, shared, &mut incoming)?;
        } else {
            serve_turn(peer, shared, &mut incoming)?;
            pull_one(peer, shared, &mut outgoing, &mut source_announced)?;
            peer.finish_round(outgoing)
                .map_err(|_| "body lane turn completion failed")?;
        }
        pause(shared, 50);
    }
    Ok(())
}
fn pull_one(
    peer: &mut Peer<p2p::NativeTlsChannel>,
    shared: &Shared,
    sequence: &mut u64,
    source_announced: &mut bool,
) -> Result<(), String> {
    *sequence = sequence
        .checked_add(1)
        .ok_or("body lane sequence exhausted")?;
    if !peer.propagation_known() {
        peer.probe_propagation(*sequence)
            .map_err(|_| "body propagation negotiation failed")?;
        return Ok(());
    }
    if !*source_announced {
        refresh_body_tip(peer, &shared.headers, *sequence)?;
        *source_announced = true;
        return Ok(());
    }
    shared.transfers.reap(shared)?;
    if peer.propagation_supported() {
        if pieces::pull_batch(peer, shared, *sequence)? {
            return Ok(());
        }
        if pieces::offer(peer, shared, *sequence)? {
            return Ok(());
        }
        if let Some(download) = shared.headers.download_preferred(
            peer.peer(),
            p2p::BodyMode::Pieces,
            None,
            &shared.network.body_sources()?,
        )? {
            let mut ledger = shared.transfers.ledger(
                &download.header,
                &download.deadline,
                shared.headers.body_policy().max_body_bytes,
            )?;
            let validation = shared.transfers.capture(shared, &download);
            let metadata = peer.fetch_propagation_metadata_at(
                *sequence,
                &download.header,
                &mut ledger,
                download.ownership()?,
            );
            shared
                .transfers
                .metadata_observed(shared, &download, &ledger, metadata.is_ok());
            let metadata = metadata.map_err(|_| "piece metadata interrupted or rejected")?;
            shared
                .transfers
                .insert(download, metadata, ledger, validation, shared)?;
            return Ok(());
        }
    }
    if let Some(mut download) = shared.headers.download_preferred(
        peer.peer(),
        p2p::BodyMode::Legacy,
        None,
        &shared.network.body_sources()?,
    )? {
        let path = shared.headers.path(&download.header)?;
        let ownership = download.take_ownership()?;
        let received = peer.fetch_body_owned(
            *sequence,
            &download.header,
            ownership,
            Some(&|bytes, total| download.received(bytes, total)),
        );
        // Preserve every actual attempt, including partial reads and failures,
        // before an error can close this independently authenticated lane.
        let (timing, overwritten) = peer.take_fetch_observation();
        shared
            .block_events
            .body_fetch(peer.peer(), &download.header, timing, overwritten);
        let received = received.map_err(|_| "body lane download interrupted or rejected")?;
        if let Some(received) = received {
            download.decoded();
            // Socket turns finish after authenticated decode. The retained,
            // bounded admission owner alone can validate or append this body.
            shared.bodies.submit(super::super::body_admission::Ready {
                download,
                received,
                path,
            });
        } else {
            shared
                .headers
                .forget_body_tip(peer.peer(), peer.propagation_session_id());
            *source_announced = false;
        }
    } else {
        refresh_body_tip(peer, &shared.headers, *sequence)?;
        pause(shared, 50);
    }
    Ok(())
}
fn refresh_body_tip<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    headers: &Hub,
    request: u64,
) -> Result<(), String> {
    let (height, id) = peer
        .fetch_tip(request)
        .map_err(|_| "body lane heartbeat failed")?;
    headers.observe_body_tip(peer.peer(), peer.propagation_session_id(), height, id)
}
fn serve_turn<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    shared: &Shared,
    sequence: &mut u64,
) -> Result<(), String> {
    let before = peer.application_totals();
    receive_turn(peer, sequence, |peer, request, message| {
        match message {
            Request::Header {
                height: crate::eng2::transport::propagation::CAPABILITY_HEIGHT,
            } => {
                peer.send_propagation_capabilities(request)
                    .map_err(|_| "body propagation negotiation failed")?;
            }
            Request::Propagation(message) if peer.propagation_supported() => pieces::serve(
                peer,
                shared,
                request,
                message,
                peer.application_totals().received - before.received,
            )?,
            Request::GetTip => {
                let (height, id) = shared.headers.tip()?;
                peer.advertise_tip(request, height, id)
                    .map_err(|_| "body lane heartbeat failed")?;
            }
            Request::Body { height, id } => {
                if let Some(cached) = shared.headers.local_body(height, id)? {
                    let _charge = peer
                        .reserve_body(cached.length())
                        .map_err(|_| "local body serving budget unavailable")?;
                    peer.send_body(request, cached.header(), cached.body())
                        .map_err(|_| "local body serving failed")?;
                } else {
                    network::serve(peer, &shared.owner, request, Request::Body { height, id })
                        .map_err(|_| "body lane serving failed")?;
                }
            }
            _ => return Err("body lane message rejected".into()),
        }
        Ok(())
    })
}
fn receive_turn<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    sequence: &mut u64,
    serve: impl FnOnce(&mut Peer<S>, u64, Request) -> Result<(), String>,
) -> Result<(), String> {
    let (request, message) = peer
        .receive_request()
        .map_err(|_| "body lane request rejected")?;
    if request
        != sequence
            .checked_add(1)
            .ok_or("body lane sequence exhausted")?
    {
        return Err("body lane sequence differs".into());
    }
    *sequence = request;
    serve(peer, request, message)?;
    let (done, message) = peer
        .receive_request()
        .map_err(|_| "body lane turn completion rejected")?;
    if done != request || message != Request::RoundDone {
        return Err("body lane turn completion differs".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor, Read, Write};
    struct Script {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Script {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.input.read(bytes)
        }
    }
    impl Write for Script {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn frame(request: u64, message: u8, binding: p2p::Binding) -> Vec<u8> {
        let mut bytes = b"SWPF".to_vec();
        bytes.extend_from_slice(&p2p::VERSION.to_le_bytes());
        bytes.push(p2p::ENG2_MESSAGE);
        bytes.extend_from_slice(&request.to_le_bytes());
        bytes.extend_from_slice(&binding.network);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(message);
        bytes
    }
    #[test]
    fn body_turn_serves_one_request_and_rejects_cross_turn_sequences_or_extra_work() {
        let state = crate::eng2::snapshot::tests::bootstrap();
        let genesis = Genesis::seal(
            state.chain.config.clone(),
            state.governance.clone(),
            crate::eng2::genesis::FeeMode::LegacyMiner,
        )
        .unwrap();
        let binding = genesis.peer_binding();
        for (request, done, message, valid) in [
            (2, 2, 9, true),
            (3, 3, 9, false),
            (2, 3, 9, false),
            (2, 2, 8, false),
        ] {
            let mut input = frame(request, 8, binding);
            input.extend_from_slice(&frame(done, message, binding));
            let session = p2p::Session::from_test_channel(
                Script {
                    input: Cursor::new(input),
                    output: Vec::new(),
                },
                binding,
                p2p::Budget::default(),
            );
            let policy = crate::eng2::body::Policy {
                profile: crate::proofs::protocol_profile_fingerprint(),
                max_body_bytes: 1024,
                max_settlement_proof_bytes: 1024,
            };
            let mut peer = Peer::new(session, &genesis, policy).unwrap();
            let mut sequence = 1;
            let mut calls = 0;
            let result = receive_turn(&mut peer, &mut sequence, |_, _, message| {
                calls += 1;
                assert_eq!(message, Request::GetTip);
                Ok(())
            });
            assert_eq!(result.is_ok(), valid);
            assert_eq!(calls, usize::from(request == 2));
        }
    }
}
