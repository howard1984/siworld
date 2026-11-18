//! Complete receipt-derived wallet scans, separate from block generation.
//!
//! Header work and receipt inclusion are checked through existing wallet code.
//! Native proofs, governance and the complete execution state are not verified.
//! Only sealed immutable synthetic input and synthetic custody exist here.
pub mod accounting;
pub mod history;
pub mod identity;
pub mod origin;
#[cfg(feature = "receipt-scan-synthetic")]
pub mod synthetic;

use crate::{
    eng2_history::{HEADER_BYTES, MAX_RECEIPT_BYTES, ReceiptBlock},
    eng2_light::{MAX_HEADERS, TRUST},
    wire::{DigestBytes, Hash},
};
use accounting::{PrivateReceipt, Totals};
use history::FrozenEng2History;
use identity::WithLocalScanIdentity;
use native::{
    codec::{PublicTransaction, encode_digest},
    multi_asset::AssetId,
};
use origin::Origin;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Incomplete(&'static str),
    Rejected(&'static str),
    Mismatch(&'static str),
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone)]
pub struct Limits {
    pub max_blocks: u64,
    pub max_receipt_bytes: u64,
    pub max_owned_notes: usize,
    pub max_nullifiers: usize,
    /// Cooperative only; an external guard supplies hard process limits.
    pub max_elapsed: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_blocks: 256,
            max_receipt_bytes: 64 * 1024 * 1024,
            max_owned_notes: 1024,
            max_nullifiers: 65536,
            max_elapsed: Duration::from_secs(120),
        }
    }
}
impl Limits {
    fn check_time(&self, start: Instant) -> Result<()> {
        if self.max_elapsed.is_zero() || start.elapsed() >= self.max_elapsed {
            return Err(Error::Incomplete("cooperative_deadline"));
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct ExpectedNote {
    pub origin: Origin,
    pub asset: AssetId,
    pub amount: u64,
    pub unlock_height: u64,
    pub nullifier: DigestBytes,
    pub spent: bool,
}
/// Expected values must be frozen independently before observing a scan.
#[derive(Clone)]
pub struct Expectations {
    pub history_manifest: Hash,
    pub spend_height: u64,
    pub balances: BTreeMap<AssetId, Totals>,
    pub notes: BTreeMap<DigestBytes, ExpectedNote>,
}
/// Contains private note associations. No Debug or general serializer exists.
pub struct ScanReport {
    manifest: Hash,
    height: u64,
    tip: Hash,
    spend_height: u64,
    receipt_bytes: u64,
    owned: BTreeMap<DigestBytes, PrivateReceipt>,
    nullifiers: BTreeSet<DigestBytes>,
    balances: BTreeMap<AssetId, Totals>,
}
impl ScanReport {
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn tip(&self) -> Hash {
        self.tip
    }
    pub fn receipt_bytes(&self) -> u64 {
        self.receipt_bytes
    }
    pub fn owned_notes(&self) -> usize {
        self.owned.len()
    }
    /// Private receipt association; not a public monitoring field.
    pub fn origin(&self, commitment: &DigestBytes) -> Option<&Origin> {
        self.owned.get(commitment).map(|row| &row.origin)
    }
    pub fn native_consensus_qualified(&self) -> bool {
        false
    }
    pub fn real_custody_used(&self) -> bool {
        false
    }
    pub fn trust_model(&self) -> &'static str {
        TRUST
    }
    /// Private caller access only; never include amounts in public status.
    pub fn balances(&self) -> &BTreeMap<AssetId, Totals> {
        &self.balances
    }
    pub fn matches(&self, expected: &Expectations) -> Result<()> {
        if expected.history_manifest != self.manifest || expected.spend_height != self.spend_height
        {
            return Err(Error::Mismatch("expectation_snapshot_or_spend_height"));
        }
        let mut observed = self.balances.clone();
        // Explicit expected zero rows are negative assertions, not receipts.
        for (asset, expected_total) in &expected.balances {
            expected_total.check()?;
            if expected_total == &Totals::default() {
                observed.entry(*asset).or_default();
            }
        }
        if observed != expected.balances {
            return Err(Error::Mismatch("asset_set_or_totals"));
        }
        if self.owned.len() != expected.notes.len() {
            return Err(Error::Mismatch("note_set"));
        }
        for (commitment, note) in &expected.notes {
            let got = self
                .owned
                .get(commitment)
                .ok_or(Error::Mismatch("note_absent"))?;
            if got.origin != note.origin
                || got.note.note().asset_id != note.asset
                || got.note.note().value != note.amount
                || got.note.note().unlock_height != note.unlock_height
                || got.note.nullifier != note.nullifier
                || self.nullifiers.contains(&got.note.nullifier) != note.spent
            {
                return Err(Error::Mismatch("note_origin_or_accounting"));
            }
        }
        Ok(())
    }
}
/// Rebuild a fresh complete wallet; an earlier report is never an input.
pub fn scan(
    history: &impl FrozenEng2History,
    identity: &impl WithLocalScanIdentity,
    spend_height: u64,
    limits: &Limits,
) -> Result<ScanReport> {
    let start = Instant::now();
    limits.check_time(start)?;
    if !history.synthetic_only() || !identity.synthetic_only() {
        return Err(Error::Incomplete("native_backend_not_implemented"));
    }
    if history.height() == 0
        || history.height() > limits.max_blocks
        || history.height() > MAX_HEADERS as u64
        || u64::try_from(history.frame_count()).ok() != Some(history.height())
        || spend_height
            > history
                .height()
                .checked_add(1)
                .ok_or(Error::Incomplete("spend_height_capacity"))?
    {
        return Err(Error::Incomplete("complete_prefix_or_height_budget"));
    }
    history.check_immutable()?;
    let mut wallet = identity.fresh(history.genesis(), history.genesis_id())?;
    if wallet.height() != 0 || !wallet.wallet().receipts().is_empty() {
        return Err(Error::Incomplete("fresh_identity_required"));
    }
    let mut owned = BTreeMap::<DigestBytes, PrivateReceipt>::new();
    let mut nullifiers = BTreeSet::new();
    let mut receipt_bytes = 0u64;
    for index in 0..history.frame_count() {
        limits.check_time(start)?;
        let (raw_header, raw_receipt) = history
            .frame(index)
            .ok_or(Error::Incomplete("missing_frame"))?;
        if raw_header.len() != HEADER_BYTES || raw_receipt.len() > MAX_RECEIPT_BYTES {
            return Err(Error::Rejected("frame_bounds"));
        }
        receipt_bytes = receipt_bytes
            .checked_add(
                u64::try_from(raw_receipt.len()).map_err(|_| Error::Incomplete("byte_capacity"))?,
            )
            .ok_or(Error::Incomplete("byte_capacity"))?;
        if receipt_bytes > limits.max_receipt_bytes {
            return Err(Error::Incomplete("receipt_byte_budget"));
        }
        let encoded: [u8; HEADER_BYTES] = raw_header
            .try_into()
            .map_err(|_| Error::Rejected("header_width"))?;
        let receipt = ReceiptBlock::decode(wallet.context(), &encoded, raw_receipt)
            .map_err(|_| Error::Rejected("receipt_authentication"))?;
        if receipt.header().height
            != (index as u64)
                .checked_add(1)
                .ok_or(Error::Incomplete("height_capacity"))?
        {
            return Err(Error::Rejected("prefix_continuity"));
        }
        let origins = origin::enumerate(&receipt)?;
        let staged = receipt
            .scan_receipts(wallet.wallet())
            .map_err(|_| Error::Rejected("receipt_decryption"))?;
        // Existing authentication/execution rules are reused unchanged.
        wallet
            .append(raw_header, raw_receipt)
            .map_err(|_| Error::Rejected("header_or_receipt_rejected"))?;
        for transaction in receipt.transactions() {
            let public = PublicTransaction::decode(&transaction.body)
                .map_err(|_| Error::Rejected("transaction_public_fields"))?;
            for nf in public.nf {
                if nullifiers.len() >= limits.max_nullifiers {
                    return Err(Error::Incomplete("nullifier_budget"));
                }
                if !nullifiers.insert(encode_digest(&nf)) {
                    return Err(Error::Rejected("canonical_nullifier_duplicate"));
                }
            }
        }
        for note in staged {
            if note.note().value == 0 {
                continue;
            }
            if owned.len() >= limits.max_owned_notes {
                return Err(Error::Incomplete("owned_note_budget"));
            }
            let matches = origins
                .get(&note.commitment)
                .ok_or(Error::Rejected("owned_origin_absent"))?;
            if matches.len() != 1 || owned.contains_key(&note.commitment) {
                return Err(Error::Rejected("owned_commitment_ambiguous"));
            }
            owned.insert(
                note.commitment,
                PrivateReceipt {
                    note,
                    origin: matches[0].clone(),
                },
            );
        }
        limits.check_time(start)?;
    }
    wallet
        .check_head(history.height(), history.tip(), None)
        .map_err(|_| Error::Incomplete("pinned_head_not_reached"))?;
    for row in wallet
        .wallet()
        .receipts()
        .iter()
        .filter(|r| r.note().value > 0)
    {
        if row.spent != nullifiers.contains(&row.nullifier) {
            return Err(Error::Rejected("wallet_spent_membership_differs"));
        }
    }
    let balances = accounting::totals(&owned, &nullifiers, spend_height)?;
    history.check_immutable()?;
    limits.check_time(start)?;
    Ok(ScanReport {
        manifest: history.manifest_sha256(),
        height: wallet.height(),
        tip: wallet.tip(),
        spend_height,
        receipt_bytes,
        owned,
        nullifiers,
        balances,
    })
}
