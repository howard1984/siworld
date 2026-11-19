//! One bounded propagation exchange per original body socket turn.
use super::*;
use crate::eng2::{body::Body, header::Header, network::Owner};

pub(super) fn pull_batch<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    shared: &Shared,
    request: u64,
) -> Result<bool, String> {
    if let Some(job) = shared.transfers.confirmation(peer.peer())? {
        let usage = shared.relay.take(
            peer.peer(),
            peer.propagation_session_id(),
            job.download
                .header
                .id()
                .map_err(|_| "piece header identity rejected")?,
        )?;
        let operation = |peer: &mut Peer<S>| {
            peer.fetch_propagation_confirmation_at(
                request,
                &job.download.header,
                &job.transfer,
                &job.ownership,
            )
        };
        let result = if let Some(usage) = &usage {
            peer.with_wire_fence(usage.clone(), operation)
        } else {
            operation(peer)
        };
        if let Some(usage) = usage {
            let _ = shared.relay.close(usage);
        }
        if result.map_err(|_| "piece source confirmation interrupted or rejected")? {
            return Ok(true);
        }
    }
    let Some((job, requests)) = shared
        .transfers
        .batch(peer.peer(), &shared.network.body_sources()?)?
    else {
        return Ok(false);
    };
    // The transfer mutex is acquired only for assignments, accounting and
    // authenticated pieces. It is never retained across a socket read/write.
    let usage = shared.relay.take(
        peer.peer(),
        peer.propagation_session_id(),
        requests[0].block,
    )?;
    let operation = |peer: &mut Peer<S>| {
        peer.fetch_propagation_batch_observed_at(
            request,
            &requests,
            &job.transfer,
            &job.ownership,
            &|transfer| {
                job.download
                    .received(transfer.verified_bytes(), transfer.body_bytes());
                if let Some(pipeline) = &job.validation {
                    let _ = pipeline.observe(transfer);
                }
                Ok(())
            },
        )
    };
    let result = if let Some(usage) = &usage {
        peer.with_wire_fence(usage.clone(), operation)
    } else {
        operation(peer)
    };
    if let Some(usage) = usage {
        let _ = shared.relay.close(usage);
    }
    result.map_err(|_| "piece batch interrupted or rejected")?;
    Ok(true)
}
pub(super) fn offer<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    shared: &Shared,
    request: u64,
) -> Result<bool, String> {
    if !shared.relay.sender() || !shared.relay.selected(peer.peer(), peer.role()) {
        return Ok(false);
    }
    let Some((body, deadline)) = shared.headers.relay_body(peer.peer())? else {
        return Ok(false);
    };
    let permit = match shared.relay.open(
        peer.peer(),
        peer.propagation_session_id(),
        request,
        body.header(),
        body.length(),
        &deadline,
    ) {
        Ok(permit) => permit,
        Err(_) => return Ok(false),
    };
    shared.headers.relay_offered(body.header(), peer.peer())?;
    let now = Instant::now();
    let lifetime = deadline
        .expires_at()
        .checked_duration_since(now)
        .ok_or("relay body expired")?;
    let result = peer.with_wire_fence(permit.clone(), |peer| {
        peer.offer_propagation(
            request,
            body.header(),
            body.length(),
            now,
            lifetime,
            shared.cancel.clone(),
        )
        .and_then(|credit| match credit {
            Some(credit) => peer
                .send_credited_metadata(credit, body.header(), body.body())
                .map(|_| true),
            None => Ok(false),
        })
    });
    if matches!(result, Ok(true)) {
        shared.relay.save(
            peer.peer(),
            peer.propagation_session_id(),
            body.header()
                .id()
                .map_err(|_| "relay body identity rejected")?,
            deadline,
            permit,
        )?;
    } else {
        shared.relay.close(permit)?;
    }
    result.map_err(|_| "relay offer interrupted or rejected")?;
    Ok(true)
}
pub(super) fn serve<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    shared: &Shared,
    request: u64,
    message: PropagationRequest,
    received_wire: u64,
) -> Result<(), String> {
    match message {
        PropagationRequest::Capability => peer
            .send_propagation_capabilities(request)
            .map_err(|_| "piece capability response failed")?,
        PropagationRequest::Offer(offer) => {
            let accepted =
                shared.relay.selected(peer.peer(), peer.role()) && !shared.relay.sender();
            if !accepted {
                return peer
                    .reject_propagation_offer(
                        offer,
                        Instant::now(),
                        Duration::from_secs(10),
                        shared.cancel.clone(),
                    )
                    .map_err(|_| "relay refusal failed".into());
            }
            let header = offer.header().clone();
            // Qualification verifies the complete known-parent timestamp/work
            // context before a policy ticket, body buffer or Credit is granted.
            shared.headers.offer(header.clone(), peer.peer())?;
            let Some(download) = shared
                .headers
                .download_offered(&offer, &shared.network.body_sources()?)?
            else {
                return peer
                    .reject_propagation_offer(
                        offer,
                        Instant::now(),
                        Duration::from_secs(10),
                        shared.cancel.clone(),
                    )
                    .map_err(|_| "relay busy refusal failed".into());
            };
            let mut ledger = shared.transfers.ledger(
                &header,
                &download.deadline,
                shared.headers.body_policy().max_body_bytes,
            )?;
            let permit = match shared.relay.open(
                peer.peer(),
                peer.propagation_session_id(),
                request,
                &header,
                offer.body_bytes(),
                &download.deadline,
            ) {
                Ok(permit) => permit,
                Err(_) => {
                    return peer
                        .reject_propagation_offer(
                            offer,
                            Instant::now(),
                            Duration::from_secs(10),
                            shared.cancel.clone(),
                        )
                        .map_err(|_| "relay quota refusal failed".into());
                }
            };
            let validation = shared.transfers.capture(shared, &download);
            shared.relay.account(&permit, received_wire)?;
            let ownership = download.ownership()?;
            let metadata = peer.with_wire_fence(permit.clone(), |peer| {
                peer.accept_propagation_offer(offer, &mut ledger, ownership)
            });
            shared
                .transfers
                .metadata_observed(shared, &download, &ledger, metadata.is_ok());
            match metadata {
                Ok(metadata) => {
                    shared.relay.save(
                        peer.peer(),
                        peer.propagation_session_id(),
                        header.id().map_err(|_| "relay header identity rejected")?,
                        download.deadline.clone(),
                        permit,
                    )?;
                    shared
                        .transfers
                        .insert(download, metadata, ledger, validation, shared)?;
                }
                Err(_) => {
                    shared.relay.close(permit)?;
                    return Err("relay metadata interrupted or rejected".into());
                }
            }
        }
        PropagationRequest::Metadata { height, id } => {
            with_body(peer, shared, request, height, id, |peer, header, body| {
                peer.send_propagation_metadata(
                    request,
                    header,
                    body,
                    Instant::now(),
                    Duration::from_secs(180),
                    shared.cancel.clone(),
                )
            })?;
        }
        PropagationRequest::Pieces(query) => {
            let usage =
                shared
                    .relay
                    .take(peer.peer(), peer.propagation_session_id(), query.block)?;
            if let Some(usage) = &usage {
                shared.relay.account(usage, received_wire)?;
            }
            let result = with_body(
                peer,
                shared,
                request,
                query.height,
                query.block,
                |peer, header, body| {
                    let operation = |peer: &mut Peer<S>| {
                        peer.send_propagation_pieces(
                            request,
                            &query,
                            header,
                            body,
                            Instant::now(),
                            Duration::from_secs(180),
                            shared.cancel.clone(),
                        )
                    };
                    if let Some(usage) = &usage {
                        peer.with_wire_fence(usage.clone(), operation)
                    } else {
                        operation(peer)
                    }
                },
            );
            if let Some(usage) = usage {
                let _ = shared.relay.close(usage);
            }
            result?;
        }
    }
    Ok(())
}
fn with_body<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    shared: &Shared,
    request: u64,
    height: u64,
    id: Hash,
    send: impl FnOnce(&mut Peer<S>, &Header, &Body) -> Result<(), p2p::Error>,
) -> Result<(), String> {
    if let Some(body) = shared.headers.local_body(height, id)? {
        return send(peer, body.header(), body.body())
            .map_err(|_| "piece cached body response failed".into());
    }
    let prepared = {
        let owner = shared
            .owner
            .lock()
            .map_err(|_| "piece owner lock poisoned")?;
        let canonical = Owner::header(&*owner, height)?.filter(|h| h.id().ok() == Some(id));
        if let Some(header) = canonical {
            let length =
                Owner::block_size(&*owner, height)?.ok_or("piece canonical body unavailable")?;
            let charge = peer
                .reserve_body(length)
                .map_err(|_| "piece serving memory unavailable")?;
            let (stored, body) = Owner::block(&*owner, height)?;
            if stored != header {
                return Err("piece canonical identity changed".into());
            }
            Some((header, body, charge))
        } else if let Some(header) = Owner::branch_header(&*owner, id)? {
            if header.height != height || header.id().ok() != Some(id) {
                return Err("piece branch identity differs".into());
            }
            let length =
                Owner::branch_block_size(&*owner, id)?.ok_or("piece branch body unavailable")?;
            let charge = peer
                .reserve_body(length)
                .map_err(|_| "piece serving memory unavailable")?;
            let (stored, body) = Owner::branch_block(&*owner, id)?;
            if stored != header {
                return Err("piece branch identity changed".into());
            }
            Some((header, body, charge))
        } else {
            None
        }
    };
    match prepared {
        Some((header, body, _charge)) => {
            send(peer, &header, &body).map_err(|_| "piece body response failed".into())
        }
        None => peer
            .send_unavailable(request, height)
            .map_err(|_| "piece missing response failed".into()),
    }
}

#[cfg(all(test, unix))]
#[path = "pieces_tests.rs"]
mod tests;
