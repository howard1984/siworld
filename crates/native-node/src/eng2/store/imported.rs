//! Durable installation of an already verified explicit checkpoint import.
//! Only a new canonical database is admitted; existing data is never replaced.
use super::*;
#[cfg(unix)]
use crate::eng2::import::{Installation, Source, VerifiedImport};

use super::{PERMANENT_RECEIPT_IDS as RECEIPT_IDS, PERMANENT_RECEIPTS as RECEIPTS};
#[cfg(unix)]
const ARTIFACTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eng2-imported-checkpoint-artifacts-v1");
const MARKER: &str = "signed-checkpoint-import";

fn receipt_hash(previous: Hash, height: u64, digest: Hash) -> Hash {
    let mut hash = blake3::Hasher::new_derive_key("siworld eng2 imported receipt index v1");
    hash.update(&previous);
    hash.update(&height.to_le_bytes());
    hash.update(&digest);
    *hash.finalize().as_bytes()
}
fn marker_seed(marker: &[u8]) -> Hash {
    blake3::derive_key("siworld eng2 signed import local index seed v1", marker)
}
pub(super) fn resume_context(
    txn: &redb::ReadTransaction,
    height: u64,
) -> Result<(u64, Hash), String> {
    let meta = txn
        .open_table(META)
        .map_err(|_| "import marker metadata unavailable")?;
    let Some(value) = meta.get(MARKER).map_err(|_| "import marker read failed")? else {
        return Ok((0, [0; 32]));
    };
    let bytes = value.value();
    if bytes.len() != 176 || &bytes[..8] != b"SW2IMP01" {
        return Err("import marker framing rejected".into());
    }
    let prefix = u64::from_le_bytes(bytes[8..16].try_into().expect("fixed import prefix"));
    if prefix == 0 || !prefix.is_multiple_of(72) || prefix >= height {
        return Err("import prefix height rejected".into());
    }
    let receipts = txn
        .open_table(RECEIPTS)
        .map_err(|_| "import permanent receipts missing")?;
    let ids = txn
        .open_table(RECEIPT_IDS)
        .map_err(|_| "import permanent receipt index missing")?;
    let count = receipts
        .len()
        .map_err(|_| "import receipt count unavailable")?;
    if !(prefix..=height).contains(&count)
        || ids
            .len()
            .map_err(|_| "import receipt index count unavailable")?
            != count
    {
        return Err("import permanent receipt prefix incomplete".into());
    }
    let mut digest = [0; 32];
    for h in 1..=prefix {
        let id = ids
            .get(h)
            .map_err(|_| "import receipt index read failed")?
            .ok_or("import receipt index gap")?;
        let id: Hash = id
            .value()
            .try_into()
            .map_err(|_| "import receipt digest width rejected")?;
        digest = receipt_hash(digest, h, id);
    }
    if digest.as_slice() != &bytes[144..176] {
        return Err("import receipt prefix digest differs".into());
    }
    let blocks = txn
        .open_table(BLOCKS)
        .map_err(|_| "import retained body table missing")?;
    if blocks
        .first()
        .map_err(|_| "import retained body range unavailable")?
        .map(|row| row.0.value())
        != Some(prefix + 1)
        || blocks
            .last()
            .map_err(|_| "import retained body range unavailable")?
            .map(|row| row.0.value())
            != Some(height)
        || blocks
            .len()
            .map_err(|_| "import retained body count unavailable")?
            != height - prefix
    {
        return Err("import retained body range differs from sealed prefix".into());
    }
    Ok((prefix, marker_seed(bytes)))
}

impl Store {
    pub fn imported_checkpoint_height(&self) -> Option<u64> {
        (self.imported_prefix != 0).then_some(self.imported_prefix)
    }
    /// Internal stored-digest check only; this returns an unauthenticated buffer.
    /// The caller must decode the receipt against the exact accepted header and
    /// body length before export. This read never reconstructs a missing proof.
    pub(crate) fn permanent_receipt(&self, height: u64) -> Result<Option<Vec<u8>>, String> {
        self.ensure_exportable()?;
        if height == 0 || height > self.engine.state().height() {
            return Ok(None);
        }
        let txn = self
            .database
            .begin_read()
            .map_err(|_| "import receipt transaction unavailable")?;
        let receipts = match txn.open_table(RECEIPTS) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) if self.imported_prefix == 0 => {
                return Ok(None);
            }
            Err(_) => return Err("permanent receipt table missing".into()),
        };
        let ids = txn
            .open_table(RECEIPT_IDS)
            .map_err(|_| "import receipt index missing")?;
        let bytes = receipts
            .get(height)
            .map_err(|_| "permanent receipt read failed")?;
        let Some(bytes) = bytes else {
            if height <= self.imported_prefix
                || ids
                    .get(height)
                    .map_err(|_| "permanent receipt index read failed")?
                    .is_some()
            {
                return Err("permanent receipt record and index differ".into());
            }
            return Ok(None);
        };
        if bytes.value().len() > crate::eng2::wallet_history::codec::MAX_RECEIPT_BYTES {
            return Err("import receipt size rejected".into());
        }
        let expected = ids
            .get(height)
            .map_err(|_| "import receipt digest unavailable")?
            .ok_or("import receipt digest missing")?;
        if blake3::hash(bytes.value()).as_bytes().as_slice() != expected.value() {
            return Err("import permanent receipt was modified".into());
        }
        Ok(Some(bytes.value().to_vec()))
    }
}

#[cfg(unix)]
impl VerifiedImport {
    /// The owner prepares this dedicated directory and its existing identity
    /// separately. This method never creates, copies, rotates or exports keys.
    /// Errors before admission preserve only an unadmitted candidate file.
    pub fn install(
        self,
        directory: &Path,
        source: &mut impl Source,
        canceled: impl Fn() -> bool,
    ) -> Result<Installation, String> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let check = || {
            if canceled() {
                Err("checkpoint import installation canceled")
            } else {
                Ok(())
            }
        };
        check()?;
        let meta =
            std::fs::symlink_metadata(directory).map_err(|_| "new import directory unavailable")?;
        if !directory.is_absolute()
            || directory
                .canonicalize()
                .map_err(|_| "import directory canonicalization failed")?
                != directory
            || !meta.file_type().is_dir()
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.permissions().mode() & 0o777 != 0o700
        {
            return Err("checkpoint import requires an owner-only canonical directory".into());
        }
        let target = directory.join("chain.redb");
        if std::fs::symlink_metadata(&target).is_ok() {
            return Err("checkpoint import will not replace an existing database".into());
        }
        let encoded = self.engine.genesis().encode()?;
        let mut file =
            crate::local::regular_read(&directory.join("genesis.bin"), false, 1024 * 1024)?;
        let mut supplied = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut supplied)
            .map_err(|_| "import target genesis read failed")?;
        if supplied != encoded {
            return Err("import target genesis differs from verified genesis".into());
        }
        let identity =
            crate::identity::NativeIdentity::load(directory, &self.engine.genesis().peer_binding())
                .map_err(|_| "import target requires its separately prepared existing identity")?;
        check()?;
        let candidate = directory.join("checkpoint-import.redb");
        let genesis = Genesis::decode(&encoded)?;
        let limits = self.engine.limits();
        let mut store = Store::create(&candidate, genesis, limits)?;
        let transaction = store
            .database
            .begin_write()
            .map_err(|_| "import candidate transaction unavailable")?;
        let mut digest = [0; 32];
        for (i, row) in self.receipts.iter().enumerate() {
            check()?;
            let height = i as u64 + 1;
            let bytes = source.receipt(height, row.length)?;
            if bytes.len() != row.length || blake3::hash(&bytes).as_bytes() != &row.digest {
                return Err("verified import receipt changed before installation".into());
            }
            transaction
                .open_table(RECEIPTS)
                .map_err(|_| "import receipt table unavailable")?
                .insert(height, bytes.as_slice())
                .map_err(|_| "import receipt write failed")?;
            transaction
                .open_table(RECEIPT_IDS)
                .map_err(|_| "import receipt index unavailable")?
                .insert(height, row.digest.as_slice())
                .map_err(|_| "import receipt digest write failed")?;
            digest = receipt_hash(digest, height, row.digest);
            let compact = compact_record(&self.headers[i], row.body_length)?;
            transaction
                .open_table(INDEX)
                .map_err(|_| "import header index unavailable")?
                .insert(height, compact.as_slice())
                .map_err(|_| "import header index write failed")?;
        }
        for (i, row) in self.bodies.iter().enumerate() {
            check()?;
            let height = self.anchor + i as u64 + 1;
            let body = source.body(height, row.length)?;
            if body.len() != row.length || blake3::hash(&body).as_bytes() != &row.digest {
                return Err("verified import tail changed before installation".into());
            }
            let header = &self.headers[height as usize - 1];
            let mut bytes = header
                .encode()
                .map_err(|_| "import installed header rejected")?
                .to_vec();
            bytes.extend_from_slice(&body);
            transaction
                .open_table(BLOCKS)
                .map_err(|_| "import tail table unavailable")?
                .insert(height, bytes.as_slice())
                .map_err(|_| "import tail write failed")?;
            let compact = compact_record(header, row.body_length)?;
            transaction
                .open_table(INDEX)
                .map_err(|_| "import tail index unavailable")?
                .insert(height, compact.as_slice())
                .map_err(|_| "import tail index write failed")?;
        }
        let mut marker = b"SW2IMP01".to_vec();
        marker.extend_from_slice(&self.anchor.to_le_bytes());
        marker.extend_from_slice(
            &self.headers[self.anchor as usize - 1]
                .id()
                .map_err(|_| "import checkpoint identity rejected")?,
        );
        for bytes in [&self.certificate, &self.witness, &self.snapshot] {
            marker.extend_from_slice(blake3::hash(bytes).as_bytes());
        }
        marker.extend_from_slice(&digest);
        for (key, bytes) in [
            ("certificate", &self.certificate),
            ("witness", &self.witness),
            ("snapshot", &self.snapshot),
        ] {
            transaction
                .open_table(ARTIFACTS)
                .map_err(|_| "import checkpoint artifacts unavailable")?
                .insert(key, bytes.as_slice())
                .map_err(|_| "import checkpoint artifact write failed")?;
        }
        transaction
            .open_table(ANCHORS)
            .map_err(|_| "import anchor archive unavailable")?
            .insert(self.anchor, self.snapshot.as_slice())
            .map_err(|_| "import anchor archive write failed")?;
        let final_root = self
            .headers
            .last()
            .ok_or("import verified head missing")?
            .execution_commitment;
        let encoded_head = head(&self.engine, final_root);
        {
            let mut meta = transaction
                .open_table(META)
                .map_err(|_| "import head metadata unavailable")?;
            meta.insert(MARKER, marker.as_slice())
                .map_err(|_| "import marker write failed")?;
            meta.insert("head", encoded_head.as_slice())
                .map_err(|_| "import head write failed")?;
        }
        check()?;
        transaction
            .commit()
            .map_err(|_| "import candidate durable commit failed")?;
        store.engine = self.engine;
        store.imported_prefix = self.anchor;
        store.import_seed = marker_seed(&marker);
        // The last cancellation boundary precedes sealing and atomic admission.
        // Synchronous finalization completes once started, as a normal commit.
        check()?;
        store.enable_authenticated_restart(identity)?;
        #[cfg(any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        ))]
        {
            let root = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(
                    (rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW).bits() as i32,
                )
                .open(directory)
                .map_err(|_| "import directory descriptor unavailable")?;
            rustix::fs::renameat_with(
                &root,
                "checkpoint-import.redb",
                &root,
                "chain.redb",
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|_| "import canonical admission failed without replacing existing data")?;
            if root.sync_all().is_err() {
                store.usable = false;
                return Ok(Installation::DurabilityUnconfirmed);
            }
            Ok(Installation::Durable(Box::new(store)))
        }
        #[cfg(not(any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        )))]
        {
            Err("atomic explicit checkpoint installation is unsupported on this platform".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // In-memory storage metadata only. These rows are not proof bodies,
    // checkpoint certificates, local identities or admitted Store fixtures.
    fn fixture() -> Database {
        let database = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .unwrap();
        let txn = database.begin_write().unwrap();
        let mut digest = [0; 32];
        for height in 1u64..=72 {
            let id = *blake3::hash(&height.to_le_bytes()).as_bytes();
            txn.open_table(RECEIPTS)
                .unwrap()
                .insert(height, id.as_slice())
                .unwrap();
            txn.open_table(RECEIPT_IDS)
                .unwrap()
                .insert(height, id.as_slice())
                .unwrap();
            digest = receipt_hash(digest, height, id);
        }
        for height in 73..=96 {
            txn.open_table(BLOCKS)
                .unwrap()
                .insert(height, b"synthetic metadata row".as_slice())
                .unwrap();
        }
        let mut marker = vec![0; 176];
        marker[..8].copy_from_slice(b"SW2IMP01");
        marker[8..16].copy_from_slice(&72u64.to_le_bytes());
        marker[144..].copy_from_slice(&digest);
        txn.open_table(META)
            .unwrap()
            .insert(MARKER, marker.as_slice())
            .unwrap();
        txn.commit().unwrap();
        database
    }

    #[test]
    fn import_manifest_allows_paired_later_receipts_without_changing_prefix_seed() {
        let database = fixture();
        let before = resume_context(&database.begin_read().unwrap(), 96).unwrap();
        assert_eq!(before.0, 72);
        let txn = database.begin_write().unwrap();
        for table in [RECEIPTS, RECEIPT_IDS] {
            txn.open_table(table)
                .unwrap()
                .insert(73, [2u8; 32].as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
        assert_eq!(
            resume_context(&database.begin_read().unwrap(), 96).unwrap(),
            before
        );
    }

    #[test]
    fn import_manifest_rejects_missing_modified_short_or_unpaired_receipt_ids() {
        for corruption in 0..4 {
            let database = fixture();
            let txn = database.begin_write().unwrap();
            {
                let mut ids = txn.open_table(RECEIPT_IDS).unwrap();
                match corruption {
                    0 => {
                        ids.remove(72).unwrap();
                        ids.insert(73, [0u8; 32].as_slice()).unwrap();
                    }
                    1 => {
                        ids.insert(72, [0u8; 32].as_slice()).unwrap();
                    }
                    2 => {
                        ids.insert(72, [0u8; 31].as_slice()).unwrap();
                    }
                    _ => {
                        ids.remove(72).unwrap();
                    }
                }
            }
            txn.commit().unwrap();
            assert!(resume_context(&database.begin_read().unwrap(), 96).is_err());
        }
    }

    #[test]
    fn import_manifest_rejects_incomplete_retained_body_ranges_and_counts() {
        for removed in [73, 84, 96] {
            let database = fixture();
            let txn = database.begin_write().unwrap();
            txn.open_table(BLOCKS).unwrap().remove(removed).unwrap();
            txn.commit().unwrap();
            assert!(resume_context(&database.begin_read().unwrap(), 96).is_err());
        }
        let database = fixture();
        assert!(resume_context(&database.begin_read().unwrap(), 72).is_err());
        assert!(resume_context(&database.begin_read().unwrap(), 97).is_err());
    }
}
