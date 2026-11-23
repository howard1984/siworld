//! Fixed-size geometry, authenticated payload records, and allocation preflight.
//!
//! A caller must verify the root chains and hold the exclusive writer before
//! planning mutations. The segment reader never opens writable handles.

use std::collections::BTreeSet;

use crate::{Error, Result};

pub mod enrollment;
mod index;
pub mod payload;
pub mod records;
pub mod segments;
pub mod transaction;

impl Geometry {
    fn binding(self) -> [u8; 12] {
        let mut bytes = [0; 12];
        bytes[..4].copy_from_slice(&UNIT_BYTES.to_le_bytes());
        bytes[4..8].copy_from_slice(&UNITS_PER_SEGMENT.to_le_bytes());
        bytes[8..].copy_from_slice(&(self.units / UNITS_PER_SEGMENT).to_le_bytes());
        bytes
    }
}

pub const UNIT_BYTES: u32 = 65_536;
pub const UNITS_PER_SEGMENT: u32 = 16_384;
pub const FIRST_DATA_UNIT: u32 = 2_050;
const MAX_SEGMENTS: u32 = 4_096;

#[derive(Clone, Copy)]
pub struct Geometry {
    units: u32,
}

impl Geometry {
    pub fn new(segments: u32) -> Result<Self> {
        if !(1..=MAX_SEGMENTS).contains(&segments) {
            return Err(Error::Limit);
        }
        Ok(Self {
            units: segments * UNITS_PER_SEGMENT,
        })
    }

    pub fn location(self, unit: u32) -> Result<(u32, u32)> {
        if unit >= self.units {
            return Err(Error::InvalidFormat);
        }
        Ok((
            unit / UNITS_PER_SEGMENT,
            (unit % UNITS_PER_SEGMENT) * UNIT_BYTES,
        ))
    }

    fn data_range(self) -> std::ops::Range<u32> {
        FIRST_DATA_UNIT..self.units
    }
}

/// The decoded references of the most recent two complete roots of one view.
/// The preceding root may be absent immediately after enrollment.
#[derive(Clone, Copy)]
pub struct RootReferences<'a> {
    pub active: &'a [u32],
    pub preceding: &'a [u32],
}

pub enum PeerReferences<'a> {
    NotEnrolled,
    Authenticated(RootReferences<'a>),
    Unavailable,
}

/// Only original credentials with an explicit writable request can plan writes.
/// Both read-only cases return the same error before inspecting allocator state.
#[derive(Clone, Copy)]
pub enum Access {
    ReadOnly,
    OwnerWrite,
}

impl Access {
    pub fn for_credential(request_read_only: bool, decoy_credential: bool) -> Self {
        if request_read_only || decoy_credential {
            Self::ReadOnly
        } else {
            Self::OwnerWrite
        }
    }

    pub fn plan(
        self,
        geometry: Geometry,
        own: RootReferences<'_>,
        peer: PeerReferences<'_>,
        count: usize,
    ) -> Result<Vec<u32>> {
        if matches!(self, Self::ReadOnly) {
            return Err(Error::ReadOnly);
        }
        let range = geometry.data_range();
        let own = pinned(own, &range)?;
        let other = match peer {
            PeerReferences::NotEnrolled => BTreeSet::new(),
            PeerReferences::Authenticated(roots) => pinned(roots, &range)?,
            PeerReferences::Unavailable => return Err(Error::InvalidFormat),
        };
        if !own.is_disjoint(&other) {
            return Err(Error::InvalidFormat);
        }
        let free = range.len() - own.len() - other.len();
        if count > free {
            return Err(Error::Limit);
        }
        let mut result = Vec::new();
        result.try_reserve_exact(count).map_err(|_| Error::Limit)?;
        result.extend(
            range
                .filter(|unit| !own.contains(unit) && !other.contains(unit))
                .take(count),
        );
        Ok(result)
    }
}

fn pinned(roots: RootReferences<'_>, range: &std::ops::Range<u32>) -> Result<BTreeSet<u32>> {
    fn checked_root(root: &[u32], range: &std::ops::Range<u32>) -> Result<BTreeSet<u32>> {
        let mut units = BTreeSet::new();
        for &unit in root {
            if !range.contains(&unit) || !units.insert(unit) {
                return Err(Error::InvalidFormat);
            }
        }
        Ok(units)
    }
    let mut active = checked_root(roots.active, range)?;
    active.extend(checked_root(roots.preceding, range)?);
    Ok(active)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_boundaries_match_geometry_vector() {
        let one = Geometry::new(1).unwrap();
        assert_eq!(one.location(FIRST_DATA_UNIT).unwrap(), (0, 134_348_800));
        assert_eq!(one.location(16_383).unwrap(), (0, 1_073_676_288));
        assert!(matches!(one.location(16_384), Err(Error::InvalidFormat)));
        assert_eq!(Geometry::new(2).unwrap().location(16_384).unwrap(), (1, 0));
    }

    #[test]
    fn read_only_paths_fail_before_examining_invalid_roots() {
        let invalid = RootReferences {
            active: &[0, 0],
            preceding: &[],
        };
        for (requested, decoy) in [(true, false), (false, true), (true, true)] {
            assert!(matches!(
                Access::for_credential(requested, decoy).plan(
                    Geometry::new(1).unwrap(),
                    invalid,
                    PeerReferences::Unavailable,
                    usize::MAX,
                ),
                Err(Error::ReadOnly)
            ));
        }
    }

    #[test]
    fn owner_plan_excludes_active_and_previous_roots_of_both_views() {
        let geometry = Geometry::new(1).unwrap();
        let own = RootReferences {
            active: &[2050, 2054],
            preceding: &[2051, 2054],
        };
        let decoy = RootReferences {
            active: &[2052],
            preceding: &[2053],
        };
        let writable = Access::for_credential(false, false);
        assert_eq!(
            writable
                .plan(geometry, own, PeerReferences::Authenticated(decoy), 2)
                .unwrap(),
            [2055, 2056]
        );
        assert!(matches!(
            writable.plan(geometry, own, PeerReferences::Authenticated(decoy), 14_330),
            Err(Error::Limit)
        ));
        assert!(matches!(
            writable.plan(geometry, own, PeerReferences::Unavailable, 1),
            Err(Error::InvalidFormat)
        ));
        assert!(matches!(
            writable.plan(geometry, own, PeerReferences::Authenticated(own), 1),
            Err(Error::InvalidFormat)
        ));
    }
}
