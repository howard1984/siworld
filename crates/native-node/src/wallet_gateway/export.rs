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
            next: Instant::now(),
        })
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
