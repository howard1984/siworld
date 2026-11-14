//! Private checked per-asset accounting over canonical owned receipts.
use super::{Error, Result, origin::Origin};
use crate::{wallet::OwnedNote, wire::DigestBytes};
use native::multi_asset::AssetId;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Totals {
    pub received_notes: u64,
    pub spent_notes: u64,
    pub unspent_notes: u64,
    pub mature_notes: u64,
    pub locked_notes: u64,
    pub received_atoms: u128,
    pub spent_atoms: u128,
    pub unspent_atoms: u128,
    pub mature_atoms: u128,
    pub locked_atoms: u128,
}
fn add_amount(value: &mut u128, amount: u128) -> Result<()> {
    *value = value
        .checked_add(amount)
        .ok_or(Error::Rejected("amount_overflow"))?;
    Ok(())
}
fn increment(value: &mut u64) -> Result<()> {
    *value = value
        .checked_add(1)
        .ok_or(Error::Rejected("count_overflow"))?;
    Ok(())
}
impl Totals {
    pub fn add(&mut self, amount: u64, spent: bool, mature: bool) -> Result<()> {
        if amount == 0 {
            return Err(Error::Rejected("zero_accounting_note"));
        }
        let mut next = self.clone();
        increment(&mut next.received_notes)?;
        add_amount(&mut next.received_atoms, u128::from(amount))?;
        if spent {
            increment(&mut next.spent_notes)?;
            add_amount(&mut next.spent_atoms, u128::from(amount))?;
        } else {
            increment(&mut next.unspent_notes)?;
            add_amount(&mut next.unspent_atoms, u128::from(amount))?;
            if mature {
                increment(&mut next.mature_notes)?;
                add_amount(&mut next.mature_atoms, u128::from(amount))?;
            } else {
                increment(&mut next.locked_notes)?;
                add_amount(&mut next.locked_atoms, u128::from(amount))?;
            }
        }
        next.check()?;
        *self = next;
        Ok(())
    }
    pub fn check(&self) -> Result<()> {
        if self.spent_atoms.checked_add(self.unspent_atoms) != Some(self.received_atoms)
            || self.mature_atoms.checked_add(self.locked_atoms) != Some(self.unspent_atoms)
            || self.spent_notes.checked_add(self.unspent_notes) != Some(self.received_notes)
            || self.mature_notes.checked_add(self.locked_notes) != Some(self.unspent_notes)
        {
            return Err(Error::Rejected("accounting_conservation"));
        }
        Ok(())
    }
}
pub(crate) struct PrivateReceipt {
    pub(crate) note: OwnedNote,
    pub(crate) origin: Origin,
}
pub(crate) fn totals(
    notes: &BTreeMap<DigestBytes, PrivateReceipt>,
    canonical_nullifiers: &BTreeSet<DigestBytes>,
    spend_height: u64,
) -> Result<BTreeMap<AssetId, Totals>> {
    let mut totals = BTreeMap::<AssetId, Totals>::new();
    for receipt in notes.values() {
        let note = receipt.note.note();
        totals.entry(note.asset_id).or_default().add(
            note.value,
            canonical_nullifiers.contains(&receipt.note.nullifier),
            note.unlock_height <= spend_height,
        )?;
    }
    Ok(totals)
}
