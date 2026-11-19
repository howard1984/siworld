//! Conservative preallocation bounds for independently executed cache buffers.
use super::*;
use crate::eng2::{snapshot::SnapshotState, state_components};

pub(super) const CACHE_MEMORY: usize = 128 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) struct Shape {
    height: usize,
    leaves: usize,
    spent: usize,
    assets: usize,
}
impl Shape {
    pub(super) fn of(state: &SnapshotState) -> Result<Self> {
        let chain = state.chain();
        let mut assets = Some(0usize);
        chain.assets.visit_encoding(&mut |part| {
            assets = assets.and_then(|n| n.checked_add(part.len()));
        });
        Ok(Self {
            height: usize::try_from(state.height()).map_err(|_| Error::CapacityExceeded)?,
            leaves: chain.leaves.len(),
            spent: chain.spent.len(),
            assets: assets.ok_or(Error::CapacityExceeded)?,
        })
    }
    pub(super) fn advanced(self, blocks: usize) -> Result<Self> {
        let leaves = blocks
            .checked_mul(
                3 * crate::wire::MAX_SLOTS
                    + crate::wire::MAX_REWARDS
                    + 1
                    + crate::wire::MAX_FUND_SPENDS
                    + (crate::issuance::INITIAL_NOTES + 1) * crate::issuance::RECORDS_CODEC_LIMIT,
            )
            .ok_or(Error::CapacityExceeded)?;
        let spent = blocks
            .checked_mul(2 * crate::wire::MAX_SLOTS)
            .ok_or(Error::CapacityExceeded)?;
        Ok(Self {
            height: self
                .height
                .checked_add(blocks)
                .ok_or(Error::CapacityExceeded)?,
            // The wire admits at most 576 two-input/three-output transactions,
            // five rewards, one fee output and four three-note issuances.
            leaves: self
                .leaves
                .checked_add(leaves)
                .ok_or(Error::CapacityExceeded)?,
            spent: self
                .spent
                .checked_add(spent)
                .ok_or(Error::CapacityExceeded)?,
            assets: self
                .assets
                .checked_add(
                    blocks
                        .checked_mul(16 * 1024)
                        .ok_or(Error::CapacityExceeded)?,
                )
                .ok_or(Error::CapacityExceeded)?,
        })
    }
    pub(super) fn contains(self, state: &SnapshotState) -> Result<()> {
        let actual = Self::of(state)?;
        if actual.height > self.height
            || actual.leaves > self.leaves
            || actual.spent > self.spent
            || actual.assets > self.assets
        {
            Err(Error::CapacityExceeded)
        } else {
            Ok(())
        }
    }
    pub(super) fn components(self) -> Result<usize> {
        // Complete permanent tree/nullifier encodings, bounded recent roots,
        // governance/addresses, and at most one fund cohort/unlock per height.
        [
            self.leaves.checked_mul(96),
            self.spent.checked_mul(48),
            Some(self.assets),
            self.height.checked_mul(512),
            Some(1024 * 1024),
        ]
        .into_iter()
        .try_fold(0usize, |n, v| {
            n.checked_add(v?).filter(|n| *n <= CACHE_MEMORY)
        })
        .ok_or(Error::CapacityExceeded)
    }
    pub(super) fn workspace(self) -> Result<usize> {
        // During component construction chain encodings, their owned copies,
        // encoded snapshot and Vec-to-Arc copy can coexist. Reconstructed
        // ordered sets/tree, decoder and staged engine ownership are charged
        // conservatively at 1024 bytes per permanent leaf/nullifier.
        self.components()?
            .checked_mul(4)
            .and_then(|n| {
                self.leaves
                    .checked_add(self.spent)?
                    .checked_mul(1024)?
                    .checked_add(n)
            })
            .and_then(|n| n.checked_add(8 * 1024 * 1024))
            .ok_or(Error::CapacityExceeded)
    }
    pub(super) fn limits(
        self,
        original: state_components::Limits,
    ) -> Result<state_components::Limits> {
        Ok(state_components::Limits {
            max_leaves: original.max_leaves.min(self.leaves),
            max_nullifiers: original.max_nullifiers.min(self.spent),
            max_component_bytes: original.max_component_bytes.min(self.components()?),
        })
    }
}

pub(super) fn reserve(budget: &Budget, retained: usize, needed: usize) -> Result<p2p::Reservation> {
    if retained
        .checked_add(needed)
        .is_none_or(|n| n > CACHE_MEMORY)
    {
        return Err(Error::CapacityExceeded);
    }
    budget.reserve(needed).map_err(|_| Error::CapacityExceeded)
}
