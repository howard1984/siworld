//! Locally authenticated checkpoint acceptance, independent of rollback history.

use super::*;
use crate::eng2::{
    certificate::{CERTIFICATE_BYTES, Certificate},
    runtime_export,
};
use crate::identity::storage_checkpoint::SEAL_BYTES;

const FLOOR: TableDefinition<&str, &[u8]> = TableDefinition::new("eng2-finalized-floor-v1");
const KEY: &str = "accepted";

fn digest(bytes: &[u8]) -> Hash {
    blake3::derive_key("siworld eng2 finalized floor v1", bytes)
}

pub(super) struct Floor {
    certificate: Certificate,
    bytes: Vec<u8>,
}

impl Floor {
    fn check_canonical(&self, store: &Store) -> Result<(), String> {
        let statement = &self.certificate.statement;
        if !runtime_export::confirmed_checkpoint(
            statement.checkpoint_height,
            statement.authorization_height,
        ) || store.header(statement.checkpoint_height)?.id().ok()
            != Some(statement.checkpoint_block)
        {
            return Err("finalized checkpoint differs from durable canonical chain".into());
        }
        Ok(())
    }

    pub(super) fn height(&self) -> u64 {
        self.certificate.statement.checkpoint_height
    }

    pub(super) fn carry(&self, transaction: &redb::WriteTransaction) -> Result<(), String> {
        transaction
            .open_table(FLOOR)
            .map_err(|_| "finalized checkpoint table unavailable")?
            .insert(KEY, self.bytes.as_slice())
            .map_err(|_| "finalized checkpoint write failed")?;
        Ok(())
    }
}

impl Store {
    pub(super) fn load_finalized_floor(&mut self) -> Result<(), String> {
        self.finalized = {
            let txn = self
                .database
                .begin_read()
                .map_err(|_| "finalized checkpoint read unavailable")?;
            match txn.open_table(FLOOR) {
                Ok(table) => {
                    let record = table
                        .get(KEY)
                        .map_err(|_| "finalized checkpoint record unavailable")?
                        .ok_or("finalized checkpoint record missing")?;
                    let bytes = record.value();
                    if bytes.len() != CERTIFICATE_BYTES + SEAL_BYTES {
                        return Err("finalized checkpoint record width rejected".into());
                    }
                    let identity = &self
                        .restart
                        .as_ref()
                        .ok_or("finalized checkpoint requires authenticated storage")?
                        .identity;
                    identity
                        .descriptor()
                        .map_err(|_| "finalized checkpoint identity unavailable")?
                        .verify_local_storage(
                            digest(&bytes[..CERTIFICATE_BYTES]),
                            &bytes[CERTIFICATE_BYTES..],
                        )
                        .map_err(|_| "finalized checkpoint local seal rejected")?;
                    let certificate = Certificate::decode(
                        &bytes[..CERTIFICATE_BYTES],
                        self.engine.state().network(),
                    )
                    .map_err(|_| "finalized checkpoint certificate framing rejected")?;
                    Some(Floor {
                        certificate,
                        bytes: bytes.to_vec(),
                    })
                }
                Err(redb::TableError::TableDoesNotExist(_)) => None,
                Err(_) => return Err("finalized checkpoint table unreadable".into()),
            }
        };
        if let Some(floor) = &self.finalized {
            floor.check_canonical(self)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn bind_conflict_evidence(&self, bytes: &[u8]) -> Result<[u8; SEAL_BYTES], String> {
        self.ensure_exportable()?;
        let identity = &self
            .restart
            .as_ref()
            .ok_or("checkpoint conflict evidence requires authenticated storage")?
            .identity;
        identity
            .seal_local_storage(blake3::derive_key(
                "siworld eng2 accepted checkpoint conflict v1",
                bytes,
            ))
            .map_err(|_| "checkpoint conflict evidence seal unavailable".into())
    }

    #[cfg(unix)]
    pub(crate) fn verify_conflict_evidence(&self, bytes: &[u8], seal: &[u8]) -> Result<(), String> {
        self.ensure_exportable()?;
        let identity = &self
            .restart
            .as_ref()
            .ok_or("checkpoint conflict evidence requires authenticated storage")?
            .identity;
        identity
            .descriptor()
            .map_err(|_| "checkpoint conflict evidence descriptor unavailable")?
            .verify_local_storage(
                blake3::derive_key("siworld eng2 accepted checkpoint conflict v1", bytes),
                seal,
            )
            .map_err(|_| "checkpoint conflict evidence seal invalid".into())
    }

    /// This certificate has passed native authorization and exact canonical
    /// membership locally. Its original authorization may have been on an
    /// unfinalized suffix since replaced; do not re-authorize it against a
    /// different header or treat the local storage seal as a peer quorum.
    pub fn finalized_checkpoint(&self) -> Result<Option<Certificate>, String> {
        self.ensure_exportable()?;
        #[cfg(unix)]
        if let Some(control) = &self.generation_control {
            return Ok(control.current()?.floor().cloned());
        }
        self.finalized
            .as_ref()
            .map(|floor| {
                floor.check_canonical(self)?;
                Ok(floor.certificate.clone())
            })
            .transpose()
    }

    pub(crate) fn finality_fence(&self) -> Option<(u64, Hash)> {
        #[cfg(unix)]
        if let Some(control) = &self.generation_control {
            return control.current().ok()?.floor().map(|certificate| {
                let statement = &certificate.statement;
                (statement.checkpoint_height, statement.checkpoint_block)
            });
        }
        self.finalized
            .as_ref()
            .map(|floor| (floor.height(), floor.certificate.statement.checkpoint_block))
    }

    pub(crate) fn check_finalized_ancestor(&self, height: u64) -> Result<(), String> {
        self.ensure_exportable()?;
        if self
            .finality_fence()
            .is_some_and(|(floor, _)| height < floor)
        {
            return Err("canonical ancestor precedes finalized checkpoint".into());
        }
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn admit_finalized_checkpoint(
        &mut self,
        certified: &runtime_export::CertifiedCheckpoint,
    ) -> Result<(), String> {
        if self.generation_control.is_some() {
            return self.advance_selected_floor(certified);
        }
        certified.check_current(self)?;
        self.persist_verified_floor(certified.certificate().clone())
    }

    // Call only with a certificate that has passed full authorization over
    // executed history, including when installing a verified checkpoint import.
    pub(super) fn persist_verified_floor(
        &mut self,
        certificate: Certificate,
    ) -> Result<(), String> {
        self.ensure_exportable()?;
        let height = certificate.statement.checkpoint_height;
        let mut floor = Floor {
            certificate,
            bytes: Vec::new(),
        };
        floor.check_canonical(self)?;
        if let Some(existing) = &self.finalized {
            existing.check_canonical(self)?;
            if existing.height() >= height {
                return Ok(());
            }
        }
        let identity = &self
            .restart
            .as_ref()
            .ok_or("finalized checkpoint requires authenticated storage")?
            .identity;
        let bytes = floor
            .certificate
            .encode()
            .map_err(|_| "finalized checkpoint certificate encoding rejected")?;
        let seal = identity
            .seal_local_storage(digest(&bytes))
            .map_err(|_| "finalized checkpoint local seal unavailable")?;
        floor.bytes.extend_from_slice(&bytes);
        floor.bytes.extend_from_slice(&seal);
        let mut txn = self
            .database
            .begin_write()
            .map_err(|_| "finalized checkpoint transaction unavailable")?;
        txn.set_durability(Durability::Immediate)
            .map_err(|_| "finalized checkpoint durability unavailable")?;
        txn.set_quick_repair(true);
        floor.carry(&txn)?;
        self.usable = false;
        txn.commit()
            .map_err(|_| "finalized checkpoint commit failed; verified reopen required")?;
        self.finalized = Some(floor);
        self.usable = true;
        Ok(())
    }
}
