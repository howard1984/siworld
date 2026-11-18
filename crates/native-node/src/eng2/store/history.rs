//! Pinned reads captured by the existing canonical owner, never an external open.
use super::*;
use crate::eng2::historical::{Error, Result};

pub(crate) struct Read {
    transaction: redb::ReadTransaction,
    network: Hash,
    pub(crate) height: u64,
    pub(crate) tip: Hash,
    pub(crate) policy: super::super::body::Policy,
}
impl Store {
    pub(crate) fn historical_read(&self) -> Result<Read> {
        self.ensure_exportable().map_err(|_| Error::CaptureFailed)?;
        Ok(Read {
            transaction: self
                .database
                .begin_read()
                .map_err(|_| Error::CaptureFailed)?,
            network: self.engine.state().network(),
            height: self.engine.state().height(),
            tip: self.engine.state().tip(),
            policy: self.engine.body_policy(),
        })
    }
}
impl Read {
    pub(crate) fn header(&self, height: u64) -> Result<Option<Header>> {
        if height == 0 || height > self.height {
            return Ok(None);
        }
        let table = self
            .transaction
            .open_table(INDEX)
            .map_err(|_| Error::CaptureFailed)?;
        let Some(row) = table.get(height).map_err(|_| Error::CaptureFailed)? else {
            return Ok(None);
        };
        let (header, size) =
            decode_compact(row.value(), self.network).map_err(|_| Error::CaptureFailed)?;
        if header.height != height || size > self.policy.max_body_bytes {
            return Err(Error::CaptureFailed);
        }
        Ok(Some(header))
    }
    fn row<T>(&self, height: u64, f: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
        let table = self
            .transaction
            .open_table(BLOCKS)
            .map_err(|_| Error::CaptureFailed)?;
        let row = table
            .get(height)
            .map_err(|_| Error::CaptureFailed)?
            .ok_or(Error::BodyUnavailable)?;
        f(row.value())
    }
    pub(crate) fn size(&self, header: &Header) -> Result<usize> {
        let index = self
            .transaction
            .open_table(INDEX)
            .map_err(|_| Error::CaptureFailed)?;
        let row = index
            .get(header.height)
            .map_err(|_| Error::CaptureFailed)?
            .ok_or(Error::BodyUnavailable)?;
        let (indexed, body_bytes) =
            decode_compact(row.value(), self.network).map_err(|_| Error::CaptureFailed)?;
        if &indexed != header {
            return Err(Error::BodyUnavailable);
        }
        body_bytes
            .checked_add(HEADER_BYTES)
            .ok_or(Error::CapacityExceeded)
    }
    pub(crate) fn frame(&self, header: &Header) -> Result<Vec<u8>> {
        let size = self.size(header)?;
        self.row(header.height, |bytes| {
            if bytes.len() < HEADER_BYTES
                || bytes.len() != size
                || bytes.len() - HEADER_BYTES > self.policy.max_body_bytes
                || bytes[..HEADER_BYTES] != header.encode().map_err(|_| Error::CaptureFailed)?
            {
                return Err(Error::BodyUnavailable);
            }
            Ok(bytes.to_vec())
        })
    }
}
