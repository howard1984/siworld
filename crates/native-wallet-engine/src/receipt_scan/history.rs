//! Immutable, fully pinned receipt input. No database or filesystem opener.
use super::{Error, Result};
#[cfg(feature = "receipt-scan-synthetic")]
use crate::eng2_history::Context;
use crate::wire::Hash;
use sha2::{Digest as _, Sha256};

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// Implementations are sealed until their snapshot and export trust is reviewed.
pub trait FrozenEng2History: sealed::Sealed {
    fn genesis(&self) -> &[u8];
    fn genesis_id(&self) -> Hash;
    fn height(&self) -> u64;
    fn tip(&self) -> Hash;
    fn manifest_sha256(&self) -> Hash;
    fn frame(&self, index: usize) -> Option<(&[u8], &[u8])>;
    fn frame_count(&self) -> usize;
    fn check_immutable(&self) -> Result<()>;
    fn synthetic_only(&self) -> bool;
}

#[derive(Clone)]
pub(crate) struct Frame {
    pub(crate) header: Box<[u8]>,
    pub(crate) receipt: Box<[u8]>,
}

/// A frozen in-memory synthetic generation, not a native canonical export.
#[derive(Clone)]
pub struct FrozenHistory {
    pub(crate) genesis: Box<[u8]>,
    pub(crate) genesis_id: Hash,
    pub(crate) height: u64,
    pub(crate) tip: Hash,
    pub(crate) frames: Box<[Frame]>,
    pub(crate) manifest: Hash,
    pub(crate) before: Hash,
    pub(crate) after: Hash,
}
impl sealed::Sealed for FrozenHistory {}
impl FrozenHistory {
    #[cfg(feature = "receipt-scan-synthetic")]
    pub(crate) fn synthetic(
        genesis: Vec<u8>,
        genesis_id: Hash,
        frames: Vec<Frame>,
        tip: Hash,
    ) -> Result<Self> {
        let context = Context::from_genesis(&genesis, genesis_id)
            .map_err(|_| Error::Incomplete("synthetic_context"))?;
        if !context.config().fixture
            || context.config().pow_iterations != 0
            || context.config().work_bits != 0
            || frames.is_empty()
        {
            return Err(Error::Incomplete("synthetic_fixture_required"));
        }
        let height =
            u64::try_from(frames.len()).map_err(|_| Error::Incomplete("height_capacity"))?;
        let mut value = Self {
            genesis: genesis.into_boxed_slice(),
            genesis_id,
            height,
            tip,
            frames: frames.into_boxed_slice(),
            manifest: [0; 32],
            before: [0; 32],
            after: [0; 32],
        };
        value.seal();
        Ok(value)
    }
    pub(crate) fn digest(&self) -> Hash {
        let mut hash = Sha256::new();
        hash.update(b"siworld synthetic immutable receipts v1");
        hash.update(self.genesis_id);
        hash.update(self.height.to_le_bytes());
        hash.update(self.tip);
        hash.update((self.genesis.len() as u64).to_le_bytes());
        hash.update(&self.genesis);
        for frame in &self.frames {
            hash.update((frame.header.len() as u64).to_le_bytes());
            hash.update(&frame.header);
            hash.update((frame.receipt.len() as u64).to_le_bytes());
            hash.update(&frame.receipt);
        }
        hash.finalize().into()
    }
    #[cfg(feature = "receipt-scan-synthetic")]
    pub(crate) fn seal(&mut self) {
        self.manifest = self.digest();
        self.before = self.manifest;
        self.after = self.manifest;
    }
}
impl FrozenEng2History for FrozenHistory {
    fn genesis(&self) -> &[u8] {
        &self.genesis
    }
    fn genesis_id(&self) -> Hash {
        self.genesis_id
    }
    fn height(&self) -> u64 {
        self.height
    }
    fn tip(&self) -> Hash {
        self.tip
    }
    fn manifest_sha256(&self) -> Hash {
        self.manifest
    }
    fn frame(&self, index: usize) -> Option<(&[u8], &[u8])> {
        self.frames
            .get(index)
            .map(|f| (f.header.as_ref(), f.receipt.as_ref()))
    }
    fn frame_count(&self) -> usize {
        self.frames.len()
    }
    fn check_immutable(&self) -> Result<()> {
        if self.before != self.manifest
            || self.after != self.manifest
            || self.digest() != self.manifest
        {
            return Err(Error::Incomplete("immutable_generation_changed"));
        }
        Ok(())
    }
    fn synthetic_only(&self) -> bool {
        true
    }
}
