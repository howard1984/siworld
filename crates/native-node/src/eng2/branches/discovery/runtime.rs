//! Owner-side discovery state. The node keeps this object across rounds and
//! authenticated peers, and holds its owner lock only for these short methods.

use super::{Error, HeaderRequest, Ledger, Limits, Usage};
use crate::eng2::{
    body::{Body, Policy},
    branches::{BranchStore, Status},
    header::Header,
    network::DiscoveryAction,
    selection::VerifiedHeaders,
    store::Store,
};
use crate::wire::Hash;
use std::collections::BTreeSet;

pub(crate) fn resident_limits() -> Limits {
    Limits {
        maximum_candidates: 8,
        maximum_peers: 8,
        maximum_requests: 1024,
        maximum_headers: 2048,
        maximum_headers_per_candidate: 256,
        maximum_body_bytes: 4 * 1024 * 1024 * 1024,
        maximum_attempts_per_header: 4,
        candidate_lifetime_ms: 900_000,
        window_ms: 3_600_000,
    }
}
pub struct Discovery {
    ledger: Ledger,
    qualified: BTreeSet<Hash>,
    body_budget: crate::p2p::Budget,
    body_scope: crate::p2p::BodyScope,
}
impl Discovery {
    pub fn new(
        network: Hash,
        genesis: Hash,
        limits: Limits,
        now_ms: u64,
        body_budget: crate::p2p::Budget,
    ) -> Result<Self, Error> {
        let ledger = Ledger::new(network, genesis, limits, now_ms)?;
        let (identity, expires, _) = ledger.body_window();
        let body_scope = body_budget
            .resident_body_scope(
                identity,
                std::time::Instant::now() + std::time::Duration::from_millis(expires - now_ms),
            )
            .map_err(|_| Error::Capacity)?;
        body_budget
            .restrict_body_limits(&body_scope, limits.maximum_headers, limits.maximum_requests)
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            ledger,
            qualified: BTreeSet::new(),
            body_budget,
            body_scope,
        })
    }
    pub(crate) fn uses_budget(&self, budget: &crate::p2p::Budget) -> bool {
        budget.owns_body_scope(&self.body_scope)
    }
    pub(crate) fn body_scope(&self) -> crate::p2p::BodyScope {
        self.body_scope.clone()
    }
    pub(crate) fn renew_body_window(&mut self, now_ms: u64) -> Result<(), String> {
        if let Some(advance) = self
            .ledger
            .renew_body_window(now_ms)
            .map_err(|e| e.to_string())?
        {
            self.body_budget
                .advance_body_window(&advance)
                .map_err(|_| "body accounting window renewal rejected")?;
            self.qualified.clear();
        }
        Ok(())
    }
    pub fn usage(&self) -> Usage {
        self.ledger.usage()
    }
    pub fn next(
        &mut self,
        branches: &mut BranchStore,
        canonical: &Store,
        remote: (u64, Hash),
        peer: Hash,
        now_ms: u64,
    ) -> Result<DiscoveryAction, String> {
        self.next_kind(branches, canonical, remote, peer, now_ms, false)
    }
    pub(crate) fn next_headers(
        &mut self,
        branches: &mut BranchStore,
        canonical: &Store,
        remote: (u64, Hash),
        peer: Hash,
        now_ms: u64,
    ) -> Result<DiscoveryAction, String> {
        self.next_kind(branches, canonical, remote, peer, now_ms, true)
    }
    fn next_kind(
        &mut self,
        branches: &mut BranchStore,
        canonical: &Store,
        remote: (u64, Hash),
        peer: Hash,
        now_ms: u64,
        headers_only: bool,
    ) -> Result<DiscoveryAction, String> {
        self.renew_body_window(now_ms)?;
        canonical.ensure_exportable()?;
        if canonical.engine().genesis().id() != self.ledger.genesis
            || canonical.engine().state().network() != self.ledger.network
            || branches.rules.genesis != self.ledger.genesis
            || branches.rules.network != self.ledger.network
        {
            return Err("discovery immutable context differs".into());
        }
        if remote.0 == 0 {
            return Ok(DiscoveryAction::Deferred);
        }
        match self.ledger.begin(remote.0, remote.1, now_ms) {
            Ok(_) => (),
            Err(error) if deferred(error) => return Ok(DiscoveryAction::Deferred),
            Err(error) => return Err(error.to_string()),
        }
        loop {
            let cursor = self
                .ledger
                .cursor(remote.1, now_ms)
                .map_err(|e| e.to_string())?;
            if cursor.ancestor_confirmed {
                break;
            }
            let current_height = canonical.engine().state().height();
            if cursor.height <= current_height {
                let local_id = if cursor.height == 0 {
                    canonical.engine().genesis().id()
                } else {
                    canonical
                        .header(cursor.height)?
                        .id()
                        .map_err(|_| "canonical discovery identity rejected")?
                };
                if local_id == cursor.id {
                    self.ledger
                        .confirm_ancestor(remote.1, cursor.height, cursor.id, now_ms)
                        .map_err(|e| e.to_string())?;
                    break;
                }
            }
            match branches.entry(cursor.id)? {
                Some(entry) if entry.status != Status::Invalid => {
                    self.ledger
                        .receive_local(remote.1, entry.header, now_ms)
                        .map_err(|e| e.to_string())?;
                }
                Some(_) => return Ok(DiscoveryAction::Deferred),
                None => {
                    return match self.ledger.request(remote.1, peer, now_ms) {
                        Ok(request) => Ok(DiscoveryAction::Header(request)),
                        Err(error) if deferred(error) => Ok(DiscoveryAction::Deferred),
                        Err(error) => Err(error.to_string()),
                    };
                }
            }
        }
        let path = self
            .ledger
            .path(remote.1, now_ms)
            .map_err(|e| e.to_string())?;
        if !self.qualified.contains(&remote.1) {
            let cursor = self
                .ledger
                .cursor(remote.1, now_ms)
                .map_err(|e| e.to_string())?;
            let count = usize::try_from(cursor.height)
                .ok()
                .and_then(|h| h.checked_add(path.len()))
                .ok_or("discovery header count overflow")?;
            if count > branches.rules.max_headers {
                return Ok(DiscoveryAction::Deferred);
            }
            let mut headers = Vec::new();
            headers
                .try_reserve_exact(count)
                .map_err(|_| "discovery prefix reservation failed")?;
            for height in 1..=cursor.height {
                headers.push(canonical.header(height)?);
            }
            headers.extend(path.iter().cloned());
            let qualified = VerifiedHeaders::verify(branches.rules.clone(), headers)
                .map_err(|_| "discovered branch complete header qualification rejected")?;
            branches.retain_verified_headers(&qualified)?;
            self.qualified.insert(remote.1);
        }
        if headers_only {
            return Ok(DiscoveryAction::Ready);
        }
        // Request raw bodies in path order, allowing bounded source overlap.
        // Retention never changes canonical state or marks native validity.
        for header in path {
            let id = header
                .id()
                .map_err(|_| "discovered body identity rejected")?;
            if branches.body_size(id)?.is_none() {
                // Defer before reserving a real source ticket. Ordinary and
                // optional body lanes share this exact node Budget instance.
                let authorization = match self.body_budget.authorize_body(
                    &self.body_scope,
                    canonical.engine().genesis().peer_binding(),
                    header.height,
                    id,
                    &crate::p2p::Deadline::new(crate::eng2::transport::BODY_FETCH_TIMEOUT),
                ) {
                    Ok(authorization) => authorization,
                    Err(_) => return Ok(DiscoveryAction::Deferred),
                };
                let ownership = match self.body_budget.claim_body_authorized(
                    &authorization,
                    peer,
                    crate::p2p::BodyMode::Legacy,
                ) {
                    Ok(claim) => claim,
                    Err(
                        crate::p2p::BodyClaimError::Busy
                        | crate::p2p::BodyClaimError::Capacity
                        | crate::p2p::BodyClaimError::SourceUsed
                        | crate::p2p::BodyClaimError::QueryLimit,
                    ) => return Ok(DiscoveryAction::Deferred),
                    Err(_) => return Ok(DiscoveryAction::Deferred),
                };
                return match self.ledger.request_body(remote.1, id, peer, now_ms) {
                    Ok(request) => Ok(DiscoveryAction::Body {
                        request,
                        header,
                        ownership: Box::new(ownership),
                    }),
                    Err(error) if deferred(error) => Ok(DiscoveryAction::Deferred),
                    Err(error) => Err(error.to_string()),
                };
            }
        }
        Ok(DiscoveryAction::Ready)
    }
    pub fn received(
        &mut self,
        request: HeaderRequest,
        header: Option<Header>,
        now_ms: u64,
    ) -> Result<(), String> {
        match header {
            Some(header) => self.ledger.receive(request, header, now_ms).map(|_| ()),
            None => self.ledger.defer(request, now_ms),
        }
        .map_err(|e| e.to_string())
    }
    pub fn deferred(&mut self, request: HeaderRequest, now_ms: u64) -> Result<(), String> {
        self.ledger
            .defer(request, now_ms)
            .map_err(|e| e.to_string())
    }
    pub fn body(
        &mut self,
        branches: &mut BranchStore,
        request: HeaderRequest,
        header: &Header,
        body: &Body,
        policy: Policy,
        now_ms: u64,
    ) -> Result<(), String> {
        let expected = request.query();
        if !request.is_body()
            || expected.0 != header.height
            || expected.1
                != header
                    .id()
                    .map_err(|_| "discovery body identity rejected")?
        {
            self.ledger
                .defer(request, now_ms)
                .map_err(|e| e.to_string())?;
            return Err("discovery body request differs".into());
        }
        let length = body.encoded_len(policy)?;
        if length as u64 > self.ledger.remaining_body_bytes() {
            self.ledger
                .defer(request, now_ms)
                .map_err(|e| e.to_string())?;
            return Err("discovery body capacity exhausted".into());
        }
        branches.retain_body(header, body, policy)?;
        self.ledger
            .body_retained(request, length, now_ms)
            .map_err(|e| e.to_string())
    }
}
fn deferred(error: Error) -> bool {
    matches!(
        error,
        Error::Expired | Error::Capacity | Error::DuplicatePeer | Error::InFlight | Error::Complete
    )
}

#[cfg(test)]
mod tests;
