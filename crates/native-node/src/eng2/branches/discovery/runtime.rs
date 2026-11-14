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

pub struct Discovery {
    ledger: Ledger,
    qualified: BTreeSet<Hash>,
}
impl Discovery {
    pub fn new(network: Hash, genesis: Hash, limits: Limits, now_ms: u64) -> Result<Self, Error> {
        Ok(Self {
            ledger: Ledger::new(network, genesis, limits, now_ms)?,
            qualified: BTreeSet::new(),
        })
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
        if self
            .ledger
            .renew_expired_window(now_ms)
            .map_err(|e| e.to_string())?
        {
            self.qualified.clear();
        }
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
        // Raw bodies are acquired one at a time. No canonical state changes or
        // native-validity marks occur here, even when every body is retained.
        for header in path {
            let id = header
                .id()
                .map_err(|_| "discovered body identity rejected")?;
            if branches.body_size(id)?.is_none() {
                return match self.ledger.request_body(remote.1, id, peer, now_ms) {
                    Ok(request) => Ok(DiscoveryAction::Body { request, header }),
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
