//! Atomic, public-only local snapshots; no admission or administrative capability.
use crate::{local::hex, state::Config, wire::Hash};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(super) struct PublicExport {
    root: PathBuf,
    published: Option<Hash>,
    checkpoint_published: Option<Hash>,
    next: Instant,
}
impl PublicExport {
    pub fn open(root: &Path) -> Result<Self, String> {
        let meta =
            fs::symlink_metadata(root).map_err(|_| "Public export directory unavailable.")?;
        if !meta.is_dir()
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.permissions().mode() & 0o777 != 0o700
        {
            return Err("Public export requires a private owner directory, mode 700.".into());
        }
        Ok(Self {
            root: root.into(),
            published: None,
            checkpoint_published: None,
            next: Instant::now(),
        })
    }

    /// Only a certificate already accepted by the canonical store is exported.
    /// Receivers independently authenticate the release-pinned authority quorum.
    pub fn publish_checkpoint(
        &mut self,
        store: &crate::store::Store,
        ids: &[Hash],
    ) -> Result<(), String> {
        if self.published != ids.last().copied() {
            return Ok(());
        }
        let Some(certificate) = store.latest_engineering_checkpoint()? else {
            return Ok(());
        };
        let statement = &certificate.statement;
        let height =
            usize::try_from(statement.height).map_err(|_| "Checkpoint export height limit.")?;
        if height == 0 || ids.get(height - 1) != Some(&statement.block_id) {
            return Err("Checkpoint export canonical prefix unavailable.".into());
        }
        let digest = statement.digest();
        if self.checkpoint_published == Some(digest) {
            return Ok(());
        }
        let bytes = certificate.encode()?;
        if bytes.len() > crate::engineering_checkpoint::MAX_CERTIFICATE_BYTES {
            return Err("Checkpoint export byte limit.".into());
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| "Checkpoint export randomness unavailable.")?;
        let temporary = self.root.join(format!("{}.tmp", hex(&random)));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|_| "Checkpoint export write unavailable.")?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "Checkpoint export write failed.")?;
            fs::rename(&temporary, self.root.join("checkpoint.bin"))
                .map_err(|_| "Checkpoint export commit failed.")?;
            fs::File::open(&self.root)
                .and_then(|f| f.sync_all())
                .map_err(|_| "Checkpoint export directory commit failed.")?;
            self.checkpoint_published = Some(digest);
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    /// Call only after all canonical compact records have been durably installed.
    pub fn publish(&mut self, config: &Config, ids: &[Hash]) -> Result<(), String> {
        let tip = ids.last().copied().unwrap_or(config.genesis_id());
        if self.published == Some(tip) || Instant::now() < self.next {
            return Ok(());
        }
        self.next = Instant::now() + Duration::from_secs(5);
        if ids.len() > 1_000_000 {
            return Err("Public export height limit.".into());
        }
        let snapshot = serde_json::json!({
            "version": 1, "network": hex(&config.network), "genesis": hex(&config.genesis_id()),
            "height": ids.len(), "tip": hex(&tip),
            "ids": ids.iter().map(|id| hex(id)).collect::<Vec<_>>()
        });
        let bytes = serde_json::to_vec(&snapshot).map_err(|_| "Public export encoding failed.")?;
        // Full local index only. Remote transfer uses pages of at most 128 identities.
        if bytes.len() > 68_000_512 {
            return Err("Public export index limit.".into());
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| "Public export randomness unavailable.")?;
        let temporary = self.root.join(format!("{}.tmp", hex(&random)));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|_| "Public export write unavailable.")?;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| "Public export permissions unavailable.")?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "Public export write failed.")?;
            fs::rename(&temporary, self.root.join("chain.json"))
                .map_err(|_| "Public export commit failed.")?;
            fs::File::open(&self.root)
                .and_then(|f| f.sync_all())
                .map_err(|_| "Public export directory commit failed.")?;
            self.published = Some(tip);
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    #[cfg(test)]
    pub fn allow_next(&mut self) {
        self.next = Instant::now();
    }
}
