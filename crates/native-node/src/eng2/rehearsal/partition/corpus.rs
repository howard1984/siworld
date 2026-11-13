//! Read-only public corpus with independently supplied manifest fingerprints.
use super::*;
use crate::eng2::{
    body::{Body, Policy},
    header::Header,
};
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;

pub(super) struct Corpus {
    source: PathBuf,
    pub(super) genesis: Vec<u8>,
    manifest_bytes: Vec<u8>,
    manifest: Value,
    height: u64,
}
impl Corpus {
    pub(super) fn open(source: &Path, pin: &str, height: u64) -> Result<Self, String> {
        if source.canonicalize().ok().as_deref() != Some(source)
            || pin.len() != 64
            || !pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("canonical public corpus and independent SHA-256 pin required".into());
        }
        let genesis = bounded_bytes(&source.join("genesis.bin"), 1024 * 1024)?;
        let selected = Genesis::decode(&genesis)?;
        ceiling_value(&selected, 0)?;
        let manifest_bytes = bounded_bytes(&source.join("manifest.json"), 2 * 1024 * 1024)?;
        if crate::local::hex(&Sha256::digest(&manifest_bytes)) != pin {
            return Err("public corpus manifest SHA-256 differs".into());
        }
        let manifest: Value = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| "public corpus manifest rejected")?;
        replay::manifest_records(&manifest, &selected, height)?;
        if manifest["height"] != height {
            return Err("public corpus must contain the exact audited source height".into());
        }
        Ok(Self {
            source: source.into(),
            genesis,
            manifest_bytes,
            manifest,
            height,
        })
    }
    pub(super) fn record(&self, height: u64) -> Result<&Value, String> {
        if height == 0 || height > self.height {
            return Err("public corpus height outside audited source".into());
        }
        self.manifest["blocks"]
            .get((height - 1) as usize)
            .ok_or_else(|| "public corpus record missing".into())
    }
    pub(super) fn read(&self, height: u64, policy: Policy) -> Result<(Header, Body), String> {
        replay::read_frame(
            &self.source,
            self.record(height)?,
            &Genesis::decode(&self.genesis)?,
            policy,
        )
    }
    pub(super) fn headers(&self, height: u64, policy: Policy) -> Result<Vec<Header>, String> {
        (1..=height)
            .map(|h| self.read(h, policy).map(|(header, _)| header))
            .collect()
    }
    pub(super) fn unchanged(&self, policy: Policy) -> Result<(), String> {
        if bounded_bytes(&self.source.join("genesis.bin"), 1024 * 1024)? != self.genesis
            || bounded_bytes(&self.source.join("manifest.json"), 2 * 1024 * 1024)?
                != self.manifest_bytes
        {
            return Err("public corpus context changed".into());
        }
        for h in 1..=self.height {
            self.read(h, policy)?;
        }
        Ok(())
    }
}
