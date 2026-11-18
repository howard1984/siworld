//! One immutable retained-branch transaction from its existing writer owner.
use super::*;
use crate::eng2::historical::{Error, Result};

pub(crate) struct Read {
    transaction: redb::ReadTransaction,
    network: Hash,
}
impl BranchStore {
    pub(crate) fn historical_read(&self) -> Result<Read> {
        Ok(Read {
            transaction: self
                .database
                .begin_read()
                .map_err(|_| Error::CaptureFailed)?,
            network: self.rules.network,
        })
    }
}
impl Read {
    pub(crate) fn header(&self, id: Hash) -> Result<Option<Header>> {
        let table = self
            .transaction
            .open_table(HEADERS)
            .map_err(|_| Error::CaptureFailed)?;
        let value = table.get(id.as_slice()).map_err(|_| Error::CaptureFailed)?;
        value
            .map(|v| {
                Entry::decode(v.value(), &self.network)
                    .map(|v| v.header)
                    .map_err(|_| Error::CaptureFailed)
            })
            .transpose()
    }
    fn body<T>(&self, id: Hash, f: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
        let table = self
            .transaction
            .open_table(BODIES)
            .map_err(|_| Error::CaptureFailed)?;
        let row = table
            .get(id.as_slice())
            .map_err(|_| Error::CaptureFailed)?
            .ok_or(Error::BodyUnavailable)?;
        f(row.value())
    }
    pub(crate) fn size(&self, header: &Header, maximum: usize) -> Result<usize> {
        self.body(header.id().map_err(|_| Error::CaptureFailed)?, |b| {
            if b.len() > maximum {
                return Err(Error::CapacityExceeded);
            }
            b.len()
                .checked_add(HEADER_BYTES)
                .ok_or(Error::CapacityExceeded)
        })
    }
    pub(crate) fn frame(&self, header: &Header) -> Result<Vec<u8>> {
        let encoded = header.encode().map_err(|_| Error::CaptureFailed)?;
        self.body(header.id().map_err(|_| Error::CaptureFailed)?, |b| {
            let mut out = Vec::with_capacity(HEADER_BYTES + b.len());
            out.extend_from_slice(&encoded);
            out.extend_from_slice(b);
            Ok(out)
        })
    }
}
