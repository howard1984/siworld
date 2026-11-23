//! Staging an empty secondary slot from the authenticated primary slot.

use super::{
    Access, PeerReferences, RootReferences,
    index::{self, FileEntry, IndexEntry},
    payload::{FileRevision, PAYLOAD_BYTES},
    records::{ManagementGrant, ROOT_BYTES, Root, Slot, WRAP_BYTES, Wrap},
    segments::{SegmentWriter, Segments},
    transaction::{DecoyEnrollment, DecoyUpdate, Media, WholeUnit, root_offset, wrap_offset},
};
use crate::{Error, Result, crypto};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

pub struct RootChain {
    pub active: Root,
    pub active_lane: u8,
    pub index: Zeroizing<Vec<u8>>,
    pub protected_pages: BTreeSet<u32>,
    active_data: Vec<u32>,
    preceding_data: Vec<u32>,
}

pub fn read_chain(
    media: &mut Segments,
    slot_number: u8,
    slot: Slot,
    seed: &[u8; 32],
) -> Result<RootChain> {
    let mut roots = Vec::with_capacity(2);
    let mut record = [0; ROOT_BYTES];
    for lane in 0..2 {
        media.read(u32::from(slot_number), root_offset(lane), &mut record)?;
        match slot.open_root(seed, lane, &record) {
            Ok(root) => roots.push((lane, root)),
            Err(Error::Authentication) => {}
            Err(error) => return Err(error),
        }
    }
    roots.sort_unstable_by_key(|(_, root)| std::cmp::Reverse(root.sequence));
    if roots.len() == 2 && roots[0].1.sequence == roots[1].1.sequence {
        return Err(Error::InvalidFormat);
    }
    let mut roots = roots.into_iter();
    let (active_lane, active) = roots.next().ok_or(Error::Authentication)?;
    let (index, mut protected_pages) =
        slot.open_index(seed, &active, |unit, bytes| media.read(unit, 0, bytes))?;
    let active_data = data_units(index::decode(media.geometry(), &index)?);
    let mut preceding_data = Vec::new();
    if let Some((_, previous)) = roots.next() {
        let (old_index, pages) =
            slot.open_index(seed, &previous, |unit, bytes| media.read(unit, 0, bytes))?;
        if !protected_pages.is_disjoint(&pages) {
            return Err(Error::InvalidFormat);
        }
        protected_pages.extend(pages);
        preceding_data = data_units(index::decode(media.geometry(), &old_index)?);
    }
    Ok(RootChain {
        active,
        active_lane,
        index,
        protected_pages,
        active_data,
        preceding_data,
    })
}

fn data_units(entries: Vec<IndexEntry>) -> Vec<u32> {
    entries
        .into_iter()
        .filter_map(|entry| entry.file)
        .flat_map(|file| file.units)
        .collect()
}

impl RootChain {
    fn references(&self) -> RootReferences<'_> {
        RootReferences {
            active: &self.active_data,
            preceding: &self.preceding_data,
        }
    }
}

fn read_wrap(
    media: &mut Segments,
    number: u8,
    password: &str,
) -> Result<(u8, Wrap, Slot, RootChain)> {
    let geometry = media.geometry();
    let mut selected = None;
    for lane in 0..2 {
        let mut record = [0; WRAP_BYTES];
        media.read(u32::from(number), wrap_offset(lane), &mut record)?;
        match Wrap::open(geometry, number, lane, password, &record) {
            Ok(wrap) => {
                let slot = Slot::new(geometry, wrap.safe_id, number)?;
                let key = slot.metadata_seed(&wrap.local_seed);
                let chain = read_chain(media, number, slot, &key)?;
                if chain.active.epoch == wrap.epoch {
                    if selected.is_some() {
                        return Err(Error::InvalidFormat);
                    }
                    selected = Some((lane, wrap, slot, chain));
                }
            }
            Err(Error::Authentication) => {}
            Err(error) => return Err(error),
        }
    }
    selected.ok_or(Error::Authentication)
}

/// Read-only sessions use the same handle mode and listing interface regardless
/// of which slot authenticated. Path selection for export belongs to the caller.
pub struct ReadOnlySafe {
    media: Segments,
    entries: Vec<IndexEntry>,
    seed: crypto::Secret,
    safe_id: [u8; 16],
    slot: u8,
}

impl ReadOnlySafe {
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let mut media = Segments::open(path)?;
        let mut selected = None;
        for number in 0..2 {
            match read_wrap(&mut media, number, password) {
                Ok((_, wrap, _, chain)) => {
                    if selected.is_some() {
                        return Err(Error::Authentication);
                    }
                    selected = Some((number, wrap, chain));
                }
                Err(Error::Authentication) => {}
                Err(error) => return Err(error),
            }
        }
        let (slot, wrap, chain) = selected.ok_or(Error::Authentication)?;
        let entries = index::decode(media.geometry(), &chain.index)?;
        Ok(Self {
            media,
            entries,
            seed: wrap.local_seed,
            safe_id: wrap.safe_id,
            slot,
        })
    }

    pub fn entries(&self) -> impl Iterator<Item = ([u8; 16], [u8; 16], &str, bool, u64)> {
        self.entries.iter().map(|entry| {
            (
                entry.id,
                entry.parent,
                entry.name.as_str(),
                entry.file.is_none(),
                entry.size,
            )
        })
    }

    pub fn read_file(&mut self, id: [u8; 16], mut out: impl Write) -> Result<()> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or(Error::InvalidName)?;
        let file = entry.file.as_ref().ok_or(Error::InvalidName)?;
        let revision = FileRevision::new(
            self.media.geometry(),
            self.safe_id,
            self.slot,
            entry.id,
            file.revision,
            entry.size,
        )?;
        let mut record = vec![0; super::UNIT_BYTES as usize];
        for (ordinal, &unit) in file.units.iter().enumerate() {
            self.media.read(unit, 0, &mut record)?;
            let bytes = revision.open(&self.seed, unit, ordinal as u32, &record)?;
            out.write_all(&bytes)?;
        }
        Ok(())
    }
}

/// Add or replace a root-level decoy file. Only the committed real grant
/// authorizes this operation; a secondary credential cannot mint that grant.
pub fn put_decoy_file(
    media: &mut SegmentWriter,
    primary: u8,
    password: &str,
    name: &str,
    size: u64,
    mut input: impl Read,
) -> Result<()> {
    crate::standard::validate_name(name)?;
    if primary != 0 {
        return Err(Error::ReadOnly);
    }
    let geometry = media.segments().geometry();
    let (_, wrap, _, real) = read_wrap(media.segments(), primary, password)?;
    let grant = wrap.management.ok_or(Error::ReadOnly)?;
    let secondary = 1 - primary;
    let slot = Slot::new(geometry, wrap.safe_id, secondary)?;
    let peer = read_chain(media.segments(), secondary, slot, &grant.peer_metadata_seed)?;
    let mut entries = index::decode(geometry, &peer.index)?;
    let existing = entries
        .iter()
        .position(|e| e.parent == [0; 16] && e.name == name);
    let entry_id = match existing {
        Some(position) if entries[position].file.is_some() => entries[position].id,
        Some(_) => return Err(Error::InvalidName),
        None => crypto::random()?,
    };
    let revision_id = crypto::random()?;
    let revision = FileRevision::new(
        geometry,
        wrap.safe_id,
        secondary,
        entry_id,
        revision_id,
        size,
    )?;
    let count = usize::try_from(size.div_ceil(PAYLOAD_BYTES as u64)).map_err(|_| Error::Limit)?;
    let allocated = Access::OwnerWrite.plan(
        geometry,
        peer.references(),
        PeerReferences::Authenticated(real.references()),
        count,
    )?;
    let entry = IndexEntry {
        id: entry_id,
        parent: [0; 16],
        name: name.to_owned(),
        size,
        file: Some(FileEntry {
            revision: revision_id,
            units: allocated.clone(),
        }),
    };
    if let Some(position) = existing {
        entries[position] = entry;
    } else {
        entries.push(entry);
        entries.sort_unstable_by_key(|e| e.id);
    }
    let stream = index::encode(geometry, &entries)?;
    let page_count = stream.len().div_ceil(PAYLOAD_BYTES - 12);
    let pages: Vec<_> = slot
        .metadata_range()
        .filter(|unit| !peer.protected_pages.contains(unit))
        .take(page_count)
        .collect();
    if pages.len() != page_count {
        return Err(Error::Limit);
    }
    let (root, metadata) = slot.seal_index(
        &grant.peer_metadata_seed,
        peer.active.sequence + 1,
        peer.active.epoch,
        &pages,
        &stream,
    )?;
    let next_root = slot.seal_root(&grant.peer_metadata_seed, 1 - peer.active_lane, &root)?;
    let metadata: Vec<_> = pages
        .into_iter()
        .zip(&metadata)
        .map(|(unit, record)| WholeUnit {
            unit,
            ciphertext: record,
        })
        .collect();

    let mut buffer = Zeroizing::new(vec![0; PAYLOAD_BYTES]);
    let mut remaining = size;
    for (ordinal, unit) in allocated.into_iter().enumerate() {
        let used = remaining.min(PAYLOAD_BYTES as u64) as usize;
        input.read_exact(&mut buffer[..used])?;
        let record = revision.seal(
            &grant.peer_local_seed,
            unit,
            ordinal as u32,
            &buffer[..used],
        )?;
        media.write(unit, 0, &record)?;
        remaining -= used as u64;
    }
    if input.read(&mut buffer[..1])? != 0 {
        return Err(Error::InvalidFormat);
    }
    DecoyUpdate {
        geometry,
        decoy_slot: secondary,
        live_root_lane: peer.active_lane,
        data: &[],
        metadata: &metadata,
        next_root: &next_root,
    }
    .commit(media)
}

/// The caller must authenticate primary management authority before calling.
/// An uncommitted secondary slot can be replaced on retry; a committed grant cannot.
pub fn enroll_empty(
    media: &mut SegmentWriter,
    primary: u8,
    primary_password: &str,
    secondary_password: &str,
) -> Result<()> {
    use subtle::ConstantTimeEq;
    if primary != 0 {
        return Err(Error::ReadOnly);
    }
    let mut normalized_primary = crypto::password_bytes(primary_password)?;
    let mut normalized_secondary = crypto::password_bytes(secondary_password)?;
    let same = normalized_primary
        .as_bytes()
        .ct_eq(normalized_secondary.as_bytes());
    normalized_primary.zeroize();
    normalized_secondary.zeroize();
    if bool::from(same) {
        return Err(Error::InvalidPassword);
    }

    let geometry = media.segments().geometry();
    let (wrap_lane, mut wrap, slot, chain) =
        read_wrap(media.segments(), primary, primary_password)?;
    if wrap.management.is_some() {
        return Err(Error::InvalidFormat);
    }
    let secondary = 1 - primary;
    let peer = Slot::new(geometry, wrap.safe_id, secondary)?;
    let secondary_wrap = Wrap {
        safe_id: wrap.safe_id,
        epoch: 1,
        local_seed: Zeroizing::new(crypto::random()?),
        management: None,
    };
    let peer_key = peer.metadata_seed(&secondary_wrap.local_seed);
    let decoy_wrap = secondary_wrap.seal(geometry, secondary, 0, secondary_password)?;
    let decoy_location = peer.metadata_range().start;
    let (decoy_root, decoy_records) =
        peer.seal_index(&peer_key, 1, 1, &[decoy_location], &[0; 8])?;
    let decoy_root = peer.seal_root(&peer_key, 0, &decoy_root)?;
    let primary_key = slot.metadata_seed(&wrap.local_seed);
    let new_pages: Vec<_> = slot
        .metadata_range()
        .filter(|unit| !chain.protected_pages.contains(unit))
        .take(chain.active.page_count as usize)
        .collect();
    if new_pages.len() != chain.active.page_count as usize {
        return Err(Error::Limit);
    }
    wrap.epoch = chain.active.epoch.checked_add(1).ok_or(Error::Limit)?;
    let sequence = chain.active.sequence.checked_add(1).ok_or(Error::Limit)?;
    let (root, real_records) =
        slot.seal_index(&primary_key, sequence, wrap.epoch, &new_pages, &chain.index)?;
    let next_real_root = slot.seal_root(&primary_key, 1 - chain.active_lane, &root)?;
    wrap.management = Some(ManagementGrant {
        peer_metadata_seed: peer_key,
        peer_local_seed: secondary_wrap.local_seed,
    });
    let alternate_real_wrap = wrap.seal(geometry, primary, 1 - wrap_lane, primary_password)?;
    let real_pages: Vec<_> = new_pages
        .iter()
        .zip(&real_records)
        .map(|(&unit, record)| WholeUnit {
            unit,
            ciphertext: record,
        })
        .collect();
    DecoyEnrollment {
        geometry,
        real_slot: primary,
        live_real_wrap_lane: wrap_lane,
        live_real_root_lane: chain.active_lane,
        decoy_pages: &[WholeUnit {
            unit: decoy_location,
            ciphertext: &decoy_records[0],
        }],
        decoy_wrap: &decoy_wrap,
        decoy_root: &decoy_root,
        real_pages: &real_pages,
        alternate_real_wrap: &alternate_real_wrap,
        next_real_root: &next_real_root,
    }
    .commit(media)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::fixed::{Geometry, UNIT_BYTES, UNITS_PER_SEGMENT};

    #[test]
    fn real_grant_enrolls_and_replaces_a_decoy_file_without_read_only_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s-00000000");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(u64::from(UNIT_BYTES) * u64::from(UNITS_PER_SEGMENT))
            .unwrap();
        let geometry = Geometry::new(1).unwrap();
        let primary = "synth\u{00e9}tic primary";
        let decoy = "synthetic decoy";
        let wrap = Wrap {
            safe_id: [1; 16],
            epoch: 1,
            local_seed: Zeroizing::new([2; 32]),
            management: None,
        };
        let slot = Slot::new(geometry, wrap.safe_id, 0).unwrap();
        let key = slot.metadata_seed(&wrap.local_seed);
        let (root, pages) = slot.seal_index(&key, 1, 1, &[2], &[0; 8]).unwrap();
        let original_wrap = wrap.seal(geometry, 0, 0, primary).unwrap();
        let mut writer = SegmentWriter::open(dir.path()).unwrap();
        writer.write(0, wrap_offset(0), &original_wrap).unwrap();
        writer.write(2, 0, &pages[0]).unwrap();
        writer
            .write(0, root_offset(0), &slot.seal_root(&key, 0, &root).unwrap())
            .unwrap();
        writer.barrier().unwrap();
        assert!(matches!(
            enroll_empty(&mut writer, 0, primary, "synthe\u{301}tic primary"),
            Err(Error::InvalidPassword)
        ));
        enroll_empty(&mut writer, 0, primary, decoy).unwrap();
        assert!(matches!(
            enroll_empty(&mut writer, 1, decoy, "other"),
            Err(Error::ReadOnly)
        ));
        assert!(put_decoy_file(&mut writer, 0, decoy, "note.txt", 0, &[][..]).is_err());
        put_decoy_file(&mut writer, 0, primary, "note.txt", 3, &b"old"[..]).unwrap();
        put_decoy_file(&mut writer, 0, primary, "note.txt", 3, &b"new"[..]).unwrap();
        let mut old_wrap = [0; WRAP_BYTES];
        writer
            .segments()
            .read(0, wrap_offset(0), &mut old_wrap)
            .unwrap();
        assert_eq!(old_wrap.as_slice(), original_wrap);
        let mut before = [0; (UNIT_BYTES as usize) * 2];
        for i in 0..2 {
            writer
                .segments()
                .read(
                    i,
                    0,
                    &mut before[i as usize * UNIT_BYTES as usize..][..UNIT_BYTES as usize],
                )
                .unwrap();
        }
        drop(writer);
        {
            let real_view = ReadOnlySafe::open(dir.path(), primary).unwrap();
            assert_eq!(real_view.entries().count(), 0);
            let mut view = ReadOnlySafe::open(dir.path(), decoy).unwrap();
            let (id, _, name, is_dir, size) = view.entries().next().unwrap();
            assert_eq!((name, is_dir, size), ("note.txt", false, 3));
            let mut output = Vec::new();
            view.read_file(id, &mut output).unwrap();
            assert_eq!(output, b"new");
            assert!(matches!(SegmentWriter::open(dir.path()), Err(Error::Busy)));
        }
        let mut media = Segments::open(dir.path()).unwrap();
        let mut unit = vec![0; UNIT_BYTES as usize];
        for i in 0..2 {
            media.read(i, 0, &mut unit).unwrap();
            assert_eq!(
                unit,
                before[i as usize * UNIT_BYTES as usize..][..UNIT_BYTES as usize]
            );
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
