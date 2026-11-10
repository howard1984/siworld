//! Bounded read-only wallet exports from the actual durably accepted store.
//! No pending pool, admitted anchor, socket or network listener is consulted.
use super::store::Store;
use crate::{p2p, wire::Hash};

#[path = "../../../native-wallet-engine/src/eng2_history.rs"]
pub mod codec;
use codec::{Context, HEADER_BYTES, ReceiptBlock};

#[cfg(all(test, unix))]
mod public_fixture;
#[cfg(test)]
mod tests;

pub const MAX_HEADER_PAGE: usize = codec::MAX_HEADER_PAGE;

/// Capture under the resident's canonical-owner lock. A later head change makes
/// this export request stale; callers refresh the pin rather than mix states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    network: Hash,
    genesis: Hash,
    rules: Hash,
    profile: Hash,
    fee_mode: u8,
    height: u64,
    tip: Hash,
}
impl Head {
    pub fn capture(store: &Store) -> Result<Self, String> {
        store.ensure_exportable()?;
        let engine = store.engine();
        let context = context(store)?;
        Ok(Self {
            network: engine.state().network(),
            genesis: context.genesis(),
            rules: context.rules(),
            profile: context.profile(),
            fee_mode: context.fee_mode(),
            height: engine.state().height(),
            tip: engine.state().tip(),
        })
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn tip(&self) -> Hash {
        self.tip
    }
    pub fn check_current(&self, store: &Store) -> Result<(), String> {
        if &Self::capture(store)? != self {
            return Err("wallet export accepted head changed; refresh the pin".into());
        }
        Ok(())
    }
    /// Public metadata has no balance, ordinary fee total or slot classification.
    /// A transport must enforce publication freshness and authenticate headers;
    /// this timestamp is not a signed assertion of current network connectivity.
    pub fn projection(&self, published: u64) -> Result<serde_json::Value, String> {
        if published > (1u64 << 53) - 1 || self.height > (1u64 << 53) - 1 {
            return Err("wallet head exceeds exact public JSON integer bounds".into());
        }
        Ok(
            serde_json::json!({"version":2,"network":crate::local::hex(&self.network),"genesis":crate::local::hex(&self.genesis),
            "rules":crate::local::hex(&self.rules),"profile":crate::local::hex(&self.profile),"fee_mode":self.fee_mode,
            "height":self.height,"tip":crate::local::hex(&self.tip),"published_unix_seconds":published}),
        )
    }
}
fn context(store: &Store) -> Result<Context, String> {
    let genesis = store.engine().genesis();
    let value = Context::from_genesis(&genesis.encode()?, genesis.id())?;
    if value.rules() != genesis.rules_commitment()
        || value.config() != genesis.config()
        || value.fee_mode() != genesis.fee_mode() as u8
    {
        return Err("wallet export immutable context differs from accepted engine".into());
    }
    Ok(value)
}
pub fn bootstrap(store: &Store, head: &Head) -> Result<Vec<u8>, String> {
    head.check_current(store)?;
    let bytes = store.engine().genesis().encode()?;
    Context::from_genesis(&bytes, head.genesis)?;
    head.check_current(store)?;
    Ok(bytes)
}

/// Retain the reservation while exported bytes remain owned. No buffer can be
/// moved out separately and silently shed its shared memory charge.
pub struct Export {
    bytes: Vec<u8>,
    height: u64,
    id: Hash,
    _reservation: p2p::Reservation,
}
impl Export {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn id(&self) -> Hash {
        self.id
    }
}
pub fn receipts(
    store: &Store,
    head: &Head,
    height: u64,
    budget: &p2p::Budget,
) -> Result<Export, String> {
    head.check_current(store)?;
    if height == 0 || height > head.height {
        return Err("wallet receipt height is not accepted".into());
    }
    let reservation = budget
        .reserve(3 * codec::MAX_RECEIPT_BYTES + 65536)
        .map_err(|_| "permanent wallet receipt memory unavailable")?;
    if let Some(bytes) = store.permanent_receipt(height)? {
        let header = store.header(height)?;
        let encoded = header
            .encode()
            .map_err(|_| "imported wallet receipt header rejected")?;
        let receipt = ReceiptBlock::decode(&context(store)?, &encoded, &bytes)?;
        if receipt.body_bytes() != store.block_size(height)? {
            return Err("permanent wallet receipt differs from accepted body length".into());
        }
        head.check_current(store)?;
        return Ok(Export {
            bytes,
            height,
            id: header
                .id()
                .map_err(|_| "imported wallet header identity rejected")?,
            _reservation: reservation,
        });
    }
    drop(reservation);
    // Fixed-width accepted index lookup precedes all proof-body allocations.
    let length = store.block_size(height)?;
    if length > codec::MAX_BODY_BYTES {
        return Err("wallet receipt source body exceeds bound".into());
    }
    let charge = length
        .checked_mul(3)
        .and_then(|n| n.checked_add(4 * codec::MAX_RECEIPT_BYTES + 65536))
        .ok_or("wallet receipt allocation charge overflow")?;
    let reservation = budget
        .reserve(charge)
        .map_err(|_| "wallet receipt export memory unavailable")?;
    let context = context(store)?;
    let (header, body) = store.block(height)?;
    if header.height != height {
        return Err("wallet receipt source height differs".into());
    }
    let canonical = body.encode(store.engine().body_policy())?;
    if canonical.len() != length {
        return Err("wallet receipt source length differs from accepted index".into());
    }
    let encoded_header = header
        .encode()
        .map_err(|_| "wallet receipt source header rejected")?;
    let bytes = ReceiptBlock::export(&context, &encoded_header, &canonical)?;
    head.check_current(store)?;
    Ok(Export {
        bytes,
        height,
        id: header
            .id()
            .map_err(|_| "wallet receipt source identity rejected")?,
        _reservation: reservation,
    })
}

/// Raw SWE2 headers, at most 128 per read. Callers still authenticate work,
/// difficulty and continuity; this page does not manufacture a selected chain.
pub fn header_page(
    store: &Store,
    head: &Head,
    from: u64,
    limit: usize,
    budget: &p2p::Budget,
) -> Result<Export, String> {
    head.check_current(store)?;
    if from == 0 || from > head.height || !(1..=MAX_HEADER_PAGE).contains(&limit) {
        return Err("wallet header page range rejected".into());
    }
    let count = limit.min(usize::try_from(head.height - from + 1).unwrap_or(usize::MAX));
    let length = 8 + 129 + 8 + 32 + 8 + 2 + count * HEADER_BYTES;
    let reservation = budget
        .reserve(
            length
                .checked_mul(2)
                .ok_or("wallet header page charge overflow")?,
        )
        .map_err(|_| "wallet header page memory unavailable")?;
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(b"SWE2WHP1");
    for field in [&head.network, &head.genesis, &head.rules, &head.profile] {
        bytes.extend_from_slice(field);
    }
    bytes.push(head.fee_mode);
    bytes.extend_from_slice(&head.height.to_le_bytes());
    bytes.extend_from_slice(&head.tip);
    bytes.extend_from_slice(&from.to_le_bytes());
    bytes.extend_from_slice(&(count as u16).to_le_bytes());
    for index in 0..count {
        bytes.extend(
            store
                .header(from + index as u64)?
                .encode()
                .map_err(|_| "wallet accepted header rejected")?,
        );
    }
    head.check_current(store)?;
    Ok(Export {
        bytes,
        height: from,
        id: head.tip,
        _reservation: reservation,
    })
}
