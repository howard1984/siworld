//! Ordered publication of staged fixed-size records.
//!
//! The caller holds the exclusive writer, authenticates current roots and wraps,
//! and allocates only ranges unreferenced by either view's protected roots.

use super::{
    FIRST_DATA_UNIT, Geometry, UNIT_BYTES,
    records::{ROOT_BYTES, WRAP_BYTES},
};
use crate::{Error, Result};
use std::collections::BTreeSet;

pub trait Media {
    fn write(&mut self, unit: u32, offset: u32, ciphertext: &[u8]) -> Result<()>;
    fn barrier(&mut self) -> Result<()>;
}

pub struct WholeUnit<'a> {
    pub unit: u32,
    pub ciphertext: &'a [u8],
}

pub struct DecoyEnrollment<'a> {
    pub geometry: Geometry,
    pub real_slot: u8,
    pub live_real_wrap_lane: u8,
    pub live_real_root_lane: u8,
    pub decoy_pages: &'a [WholeUnit<'a>],
    pub decoy_wrap: &'a [u8],
    pub decoy_root: &'a [u8],
    pub real_pages: &'a [WholeUnit<'a>],
    pub alternate_real_wrap: &'a [u8],
    pub next_real_root: &'a [u8],
}

pub const fn wrap_offset(lane: u8) -> u32 {
    lane as u32 * 12_288
}

pub const fn root_offset(lane: u8) -> u32 {
    (lane as u32 + 1) * 4_096
}

fn pages_in_slot(pages: &[WholeUnit<'_>], slot: u8) -> Result<()> {
    let start = 2 + 1_024 * u32::from(slot);
    let mut seen = BTreeSet::new();
    if pages.is_empty()
        || pages.iter().any(|page| {
            !(start..start + 1_024).contains(&page.unit)
                || page.ciphertext.len() != UNIT_BYTES as usize
                || !seen.insert(page.unit)
        })
    {
        return Err(Error::InvalidFormat);
    }
    Ok(())
}

fn write_units(media: &mut impl Media, units: &[WholeUnit<'_>]) -> Result<()> {
    for unit in units {
        media.write(unit.unit, 0, unit.ciphertext)?;
    }
    Ok(())
}

impl DecoyEnrollment<'_> {
    /// On any error after the first write, discard in-memory state and reopen.
    pub fn commit(&self, media: &mut impl Media) -> Result<()> {
        if self.real_slot > 1
            || self.live_real_wrap_lane > 1
            || self.live_real_root_lane > 1
            || self.decoy_wrap.len() != WRAP_BYTES
            || self.alternate_real_wrap.len() != WRAP_BYTES
            || self.decoy_root.len() != ROOT_BYTES
            || self.next_real_root.len() != ROOT_BYTES
        {
            return Err(Error::InvalidFormat);
        }
        let real = u32::from(self.real_slot);
        let decoy = 1 - real;
        self.geometry.location(decoy)?;
        pages_in_slot(self.decoy_pages, decoy as u8)?;
        pages_in_slot(self.real_pages, self.real_slot)?;

        write_units(media, self.decoy_pages)?;
        media.write(decoy, wrap_offset(0), self.decoy_wrap)?;
        media.write(decoy, root_offset(0), self.decoy_root)?;
        media.barrier()?;

        // The old epoch still opens until the alternate root is committed.
        write_units(media, self.real_pages)?;
        media.write(
            real,
            wrap_offset(1 - self.live_real_wrap_lane),
            self.alternate_real_wrap,
        )?;
        media.barrier()?;

        media.write(
            real,
            root_offset(1 - self.live_real_root_lane),
            self.next_real_root,
        )?;
        media.barrier()
    }
}

pub struct DecoyUpdate<'a> {
    pub geometry: Geometry,
    pub decoy_slot: u8,
    pub live_root_lane: u8,
    pub data: &'a [WholeUnit<'a>],
    pub metadata: &'a [WholeUnit<'a>],
    pub next_root: &'a [u8],
}

impl DecoyUpdate<'_> {
    /// Validated allocation is supplied by the owner session, not the decoy.
    pub fn commit(&self, media: &mut impl Media) -> Result<()> {
        if self.decoy_slot > 1 || self.live_root_lane > 1 || self.next_root.len() != ROOT_BYTES {
            return Err(Error::InvalidFormat);
        }
        pages_in_slot(self.metadata, self.decoy_slot)?;
        let range = self.geometry.data_range();
        let mut seen = BTreeSet::new();
        for unit in self.data {
            if unit.unit < FIRST_DATA_UNIT
                || !range.contains(&unit.unit)
                || unit.ciphertext.len() != UNIT_BYTES as usize
                || !seen.insert(unit.unit)
            {
                return Err(Error::InvalidFormat);
            }
        }
        write_units(media, self.data)?;
        write_units(media, self.metadata)?;
        media.barrier()?;
        media.write(
            u32::from(self.decoy_slot),
            root_offset(1 - self.live_root_lane),
            self.next_root,
        )?;
        media.barrier()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::fixed::{records::Slot, segments::SegmentWriter};
    use std::{fs::File, io};

    struct Fault<'a> {
        media: &'a mut SegmentWriter,
        remaining: usize,
    }

    impl Media for Fault<'_> {
        fn write(&mut self, unit: u32, offset: u32, bytes: &[u8]) -> Result<()> {
            if self.remaining == 0 {
                self.media.write(unit, offset, &bytes[..bytes.len() / 2])?;
                return Err(io::Error::other("injected torn write").into());
            }
            self.remaining -= 1;
            self.media.write(unit, offset, bytes)
        }

        fn barrier(&mut self) -> Result<()> {
            if self.remaining == 0 {
                return Err(io::Error::other("injected barrier failure").into());
            }
            self.remaining -= 1;
            self.media.barrier()
        }
    }

    fn backend() -> (tempfile::TempDir, SegmentWriter) {
        let directory = tempfile::tempdir().unwrap();
        let file = File::create(directory.path().join("s-00000000")).unwrap();
        file.set_len(1 << 30).unwrap();
        let media = SegmentWriter::open(directory.path()).unwrap();
        (directory, media)
    }

    fn verify(media: &mut SegmentWriter, unit: u32, offset: u32, expected: &[u8]) {
        let mut actual = vec![0; expected.len()];
        media.segments().read(unit, offset, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn enrollment_cuts_never_replace_the_live_real_wrap_or_root() {
        let geometry = Geometry::new(1).unwrap();
        let real = Slot::new(geometry, [1; 16], 0).unwrap();
        let decoy = Slot::new(geometry, [1; 16], 1).unwrap();
        let real_key = real.metadata_seed(&[2; 32]);
        let decoy_key = decoy.metadata_seed(&[3; 32]);
        let (old, old_pages) = real.seal_index(&real_key, 3, 1, &[2], &[0; 8]).unwrap();
        let old_record = real.seal_root(&real_key, 0, &old).unwrap();
        let (new, new_pages) = real.seal_index(&real_key, 4, 2, &[3], &[0; 8]).unwrap();
        let new_record = real.seal_root(&real_key, 1, &new).unwrap();
        let (peer, peer_pages) = decoy
            .seal_index(&decoy_key, 1, 1, &[1026], &[0; 8])
            .unwrap();
        let peer_record = decoy.seal_root(&decoy_key, 0, &peer).unwrap();
        let old_wrap = [7; WRAP_BYTES];
        let new_wrap = [8; WRAP_BYTES];
        let peer_wrap = [9; WRAP_BYTES];
        let enrollment = DecoyEnrollment {
            geometry,
            real_slot: 0,
            live_real_wrap_lane: 0,
            live_real_root_lane: 0,
            decoy_pages: &[WholeUnit {
                unit: 1026,
                ciphertext: &peer_pages[0],
            }],
            decoy_wrap: &peer_wrap,
            decoy_root: &peer_record,
            real_pages: &[WholeUnit {
                unit: 3,
                ciphertext: &new_pages[0],
            }],
            alternate_real_wrap: &new_wrap,
            next_real_root: &new_record,
        };
        for cut in 0..=9 {
            let (_directory, mut media) = backend();
            media.write(0, wrap_offset(0), &old_wrap).unwrap();
            media.write(0, root_offset(0), &old_record).unwrap();
            media.write(2, 0, &old_pages[0]).unwrap();
            media.barrier().unwrap();
            let result = enrollment.commit(&mut Fault {
                media: &mut media,
                remaining: cut,
            });
            assert_eq!(result.is_ok(), cut == 9);
            verify(&mut media, 0, wrap_offset(0), &old_wrap);
            verify(&mut media, 0, root_offset(0), &old_record);
            verify(&mut media, 2, 0, &old_pages[0]);
            if cut >= 4 {
                verify(&mut media, 1, wrap_offset(0), &peer_wrap);
                verify(&mut media, 1, root_offset(0), &peer_record);
                verify(&mut media, 1026, 0, &peer_pages[0]);
            }
            if cut >= 8 {
                verify(&mut media, 0, wrap_offset(1), &new_wrap);
                verify(&mut media, 0, root_offset(1), &new_record);
                verify(&mut media, 3, 0, &new_pages[0]);
            } else {
                let mut record = [0; ROOT_BYTES];
                media
                    .segments()
                    .read(0, root_offset(1), &mut record)
                    .unwrap();
                assert!(real.open_root(&real_key, 1, &record).is_err());
            }
        }
    }

    #[test]
    fn decoy_update_cuts_keep_both_views_protected() {
        let data = vec![5; UNIT_BYTES as usize];
        let metadata = vec![6; UNIT_BYTES as usize];
        let old = [7; ROOT_BYTES];
        let next = [8; ROOT_BYTES];
        let geometry = Geometry::new(1).unwrap();
        let old_units = [2050, 2051, 2052, 2053];
        let allocated = crate::fixed::Access::OwnerWrite
            .plan(
                geometry,
                crate::fixed::RootReferences {
                    active: &[2052],
                    preceding: &[2053],
                },
                crate::fixed::PeerReferences::Authenticated(crate::fixed::RootReferences {
                    active: &[2050],
                    preceding: &[2051],
                }),
                1,
            )
            .unwrap();
        let update = DecoyUpdate {
            geometry,
            decoy_slot: 1,
            live_root_lane: 0,
            data: &[WholeUnit {
                unit: allocated[0],
                ciphertext: &data,
            }],
            metadata: &[WholeUnit {
                unit: 1027,
                ciphertext: &metadata,
            }],
            next_root: &next,
        };
        for cut in 0..=5 {
            let (_directory, mut media) = backend();
            for unit in old_units {
                media.write(unit, 0, &data).unwrap();
            }
            media.write(1, root_offset(0), &old).unwrap();
            media.barrier().unwrap();
            let result = update.commit(&mut Fault {
                media: &mut media,
                remaining: cut,
            });
            assert_eq!(result.is_ok(), cut == 5);
            for unit in old_units {
                verify(&mut media, unit, 0, &data);
            }
            verify(&mut media, 1, root_offset(0), &old);
            if cut >= 4 {
                verify(&mut media, 1, root_offset(1), &next);
                verify(&mut media, allocated[0], 0, &data);
                verify(&mut media, 1027, 0, &metadata);
            }
        }
    }
}
