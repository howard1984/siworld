//! Read-only access to physically fixed segments.

use super::{Geometry, UNIT_BYTES, UNITS_PER_SEGMENT, transaction::Media};
use crate::{Error, Result, standard::Directory};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

const SEGMENT_BYTES: u64 = UNIT_BYTES as u64 * UNITS_PER_SEGMENT as u64;

pub struct Segments {
    geometry: Geometry,
    files: Vec<File>,
}

impl Segments {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_access(path, false)
    }

    fn open_access(path: &Path, write: bool) -> Result<Self> {
        let directory = Directory::open(path)?;
        let mut numbers = std::collections::BTreeSet::new();
        for entry in fs::read_dir(path)? {
            let name = entry?.file_name();
            let name = name.to_str().ok_or(Error::InvalidFormat)?;
            let hex = name.strip_prefix("s-").ok_or(Error::InvalidFormat)?;
            if hex.len() != 8 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(Error::InvalidFormat);
            }
            let number = u32::from_str_radix(hex, 16).map_err(|_| Error::InvalidFormat)?;
            if number >= super::MAX_SEGMENTS || !numbers.insert(number) {
                return Err(Error::InvalidFormat);
            }
        }
        let count = numbers.len() as u32;
        let geometry = Geometry::new(count)?;
        if !numbers.into_iter().eq(0..count) {
            return Err(Error::InvalidFormat);
        }
        let mut files = Vec::with_capacity(count as usize);
        for index in 0..count {
            let file = directory.file_access(&format!("s-{index:08x}"), false, write)?;
            if file.metadata()?.len() != SEGMENT_BYTES {
                return Err(Error::InvalidFormat);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if file.metadata()?.nlink() != 1 {
                    return Err(Error::InvalidFormat);
                }
            }
            if index == 0 {
                if write {
                    file.try_lock().map_err(|_| Error::Busy)?;
                } else {
                    file.try_lock_shared().map_err(|_| Error::Busy)?;
                }
            }
            files.push(file);
        }
        Ok(Self { geometry, files })
    }

    pub fn geometry(&self) -> Geometry {
        self.geometry
    }

    pub fn read(&mut self, unit: u32, offset: u32, bytes: &mut [u8]) -> Result<()> {
        let file = self.position(unit, offset, bytes.len())?;
        file.read_exact(bytes)?;
        Ok(())
    }

    fn position(&mut self, unit: u32, offset: u32, len: usize) -> Result<&mut File> {
        if offset >= UNIT_BYTES || len > (UNIT_BYTES - offset) as usize {
            return Err(Error::InvalidFormat);
        }
        let (segment, start) = self.geometry.location(unit)?;
        let file = &mut self.files[segment as usize];
        file.seek(SeekFrom::Start(u64::from(start + offset)))?;
        Ok(file)
    }
}

/// An exclusive, non-creating backend for the fixed-size format candidate.
/// This is a byte storage interface, not a writable safe session.
pub struct SegmentWriter {
    segments: Segments,
    dirty: std::collections::BTreeSet<u32>,
}

impl SegmentWriter {
    pub fn open(path: &Path) -> Result<Self> {
        if !cfg!(unix)
            && !cfg!(all(
                windows,
                debug_assertions,
                feature = "dev-windows-write"
            ))
        {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            segments: Segments::open_access(path, true)?,
            dirty: Default::default(),
        })
    }

    pub fn segments(&mut self) -> &mut Segments {
        &mut self.segments
    }
}

impl Media for SegmentWriter {
    fn write(&mut self, unit: u32, offset: u32, ciphertext: &[u8]) -> Result<()> {
        let (segment, _) = self.segments.geometry.location(unit)?;
        self.dirty.insert(segment);
        self.segments
            .position(unit, offset, ciphertext.len())?
            .write_all(ciphertext)?;
        Ok(())
    }

    fn barrier(&mut self) -> Result<()> {
        for &segment in &self.dirty {
            self.segments.files[segment as usize].sync_all()?;
        }
        self.dirty.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn reads_exact_ranges_without_altering_fixture_layout() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s-00000000");
        // Sparse files are only used in the synthetic fixture.
        let mut file = File::create(&path).unwrap();
        file.set_len(SEGMENT_BYTES).unwrap();
        file.seek(SeekFrom::End(-2)).unwrap();
        file.write_all(b"ok").unwrap();
        let mut segments = Segments::open(dir.path()).unwrap();
        let mut buffer = [0; 2];
        segments
            .read(UNITS_PER_SEGMENT - 1, UNIT_BYTES - 2, &mut buffer)
            .unwrap();
        assert_eq!(&buffer, b"ok");
        assert!(
            segments
                .read(UNITS_PER_SEGMENT - 1, UNIT_BYTES - 1, &mut buffer)
                .is_err()
        );
        assert!(segments.read(UNITS_PER_SEGMENT, 0, &mut buffer).is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(file.metadata().unwrap().len(), SEGMENT_BYTES);
    }

    #[test]
    fn refuses_gaps_wrong_sizes_and_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s-00000001");
        let fixture = File::create(&path).unwrap();
        fixture.set_len(SEGMENT_BYTES).unwrap();
        assert!(Segments::open(dir.path()).is_err());
        drop(fixture);
        let first = dir.path().join("s-00000000");
        fs::rename(path, &first).unwrap();
        File::create(dir.path().join("sidecar")).unwrap();
        assert!(Segments::open(dir.path()).is_err());
        fs::remove_file(dir.path().join("sidecar")).unwrap();
        File::create(first).unwrap();
        assert!(Segments::open(dir.path()).is_err());
    }
}
