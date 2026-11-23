use super::{Geometry, payload::PAYLOAD_BYTES};
use crate::{Error, Result, standard::validate_name};
use std::collections::{BTreeSet, HashSet};
use zeroize::Zeroizing;

pub(super) struct IndexEntry {
    pub id: [u8; 16],
    pub parent: [u8; 16],
    pub name: String,
    pub size: u64,
    pub file: Option<FileEntry>,
}

pub(super) struct FileEntry {
    pub revision: [u8; 16],
    pub units: Vec<u32>,
}

pub(super) fn decode(geometry: Geometry, mut bytes: &[u8]) -> Result<Vec<IndexEntry>> {
    let count = u32::from_le_bytes(take(&mut bytes)?);
    if count > 100_000 || take::<4>(&mut bytes)? != [0; 4] {
        return Err(Error::InvalidFormat);
    }
    let mut entries: Vec<IndexEntry> = Vec::with_capacity((count as usize).min(1024));
    let mut used = HashSet::new();
    let mut revisions = HashSet::new();
    for _ in 0..count {
        let id = take(&mut bytes)?;
        let parent = take(&mut bytes)?;
        let [kind, padding] = take(&mut bytes)?;
        let name_len = u16::from_le_bytes(take(&mut bytes)?) as usize;
        let unit_count = u32::from_le_bytes(take(&mut bytes)?);
        let size = u64::from_le_bytes(take(&mut bytes)?);
        if id == [0; 16] || entries.last().is_some_and(|e| e.id >= id) || padding != 0 {
            return Err(Error::InvalidFormat);
        }
        let (name, rest) = bytes
            .split_at_checked(name_len)
            .ok_or(Error::InvalidFormat)?;
        bytes = rest;
        let name = std::str::from_utf8(name).map_err(|_| Error::InvalidFormat)?;
        validate_name(name)?;
        let file = match kind {
            2 if size == 0 && unit_count == 0 => None,
            1 if u64::from(unit_count) == size.div_ceil(PAYLOAD_BYTES as u64) => {
                let revision = take(&mut bytes)?;
                if revision == [0; 16]
                    || !revisions.insert(revision)
                    || unit_count as usize > bytes.len() / 4
                {
                    return Err(Error::InvalidFormat);
                }
                let mut units = Vec::with_capacity(unit_count as usize);
                for _ in 0..unit_count {
                    let unit = u32::from_le_bytes(take(&mut bytes)?);
                    if !geometry.data_range().contains(&unit) || !used.insert(unit) {
                        return Err(Error::InvalidFormat);
                    }
                    units.push(unit);
                }
                Some(FileEntry { revision, units })
            }
            _ => return Err(Error::InvalidFormat),
        };
        entries.push(IndexEntry {
            id,
            parent,
            name: name.to_owned(),
            size,
            file,
        });
    }
    if !bytes.is_empty() {
        return Err(Error::InvalidFormat);
    }
    let mut names = BTreeSet::new();
    for entry in &entries {
        if !names.insert((entry.parent, entry.name.as_str())) {
            return Err(Error::InvalidFormat);
        }
        let mut parent = entry.parent;
        let mut visited = BTreeSet::from([entry.id]);
        while parent != [0; 16] {
            let node = entries
                .binary_search_by_key(&parent, |e| e.id)
                .map_err(|_| Error::InvalidFormat)?;
            if entries[node].file.is_some() || visited.len() >= 128 || !visited.insert(parent) {
                return Err(Error::InvalidFormat);
            }
            parent = entries[node].parent;
        }
    }
    Ok(entries)
}

pub(super) fn encode(geometry: Geometry, entries: &[IndexEntry]) -> Result<Zeroizing<Vec<u8>>> {
    if entries.len() > 100_000 {
        return Err(Error::Limit);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend((entries.len() as u32).to_le_bytes());
    bytes.extend([0; 4]);
    for entry in entries {
        validate_name(&entry.name)?;
        bytes.extend(entry.id);
        bytes.extend(entry.parent);
        bytes.extend([if entry.file.is_some() { 1 } else { 2 }, 0]);
        bytes.extend((entry.name.len() as u16).to_le_bytes());
        let count = entry.file.as_ref().map_or(0, |file| file.units.len());
        bytes.extend(
            u32::try_from(count)
                .map_err(|_| Error::Limit)?
                .to_le_bytes(),
        );
        bytes.extend(entry.size.to_le_bytes());
        bytes.extend(entry.name.as_bytes());
        if let Some(file) = &entry.file {
            bytes.extend(file.revision);
            for unit in &file.units {
                bytes.extend(unit.to_le_bytes());
            }
        }
    }
    decode(geometry, &bytes)?;
    Ok(bytes)
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N]> {
    let (value, rest) = bytes.split_at_checked(N).ok_or(Error::InvalidFormat)?;
    *bytes = rest;
    value.try_into().map_err(|_| Error::InvalidFormat)
}
