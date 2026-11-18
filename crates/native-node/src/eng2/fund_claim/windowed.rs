//! Versioned fund authorization with an inclusive, signed block-height window.
//!
//! This candidate format does not change V1 block decoding or select a genesis.
//! The active destination, immutable member key and spend counter still govern
//! admission. A valid signature alone never authorizes a ledger debit twice.
use super::{AuthorizedFundClaim, GovernanceState, PublicFundClaim};
use crate::state::Config;

pub const VERSION: u16 = 2;
pub const MIN_VALIDITY_BLOCKS: u64 = 288;
pub const ENCODED_BYTES: usize = super::ENCODED_BYTES + 8;
const CONTEXT: &[u8] = b"siworld eng2 public fund claim v2";
const WINDOW_OFFSET: usize = 46;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowedFundClaim {
    /// In this format, `claim.height` is the first permitted inclusion height.
    pub claim: PublicFundClaim,
    pub valid_until: u64,
}

impl WindowedFundClaim {
    fn validate_window(&self) -> Result<(), String> {
        let minimum_end = self
            .claim
            .height
            .checked_add(MIN_VALIDITY_BLOCKS - 1)
            .ok_or("fund authorization window overflows")?;
        if self.claim.height == 0 || self.valid_until < minimum_end {
            return Err("fund authorization window is shorter than 288 blocks".into());
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate_window()?;
        let legacy = self.claim.encode();
        let mut bytes = Vec::with_capacity(ENCODED_BYTES);
        bytes.extend_from_slice(&legacy[..WINDOW_OFFSET]);
        bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.valid_until.to_le_bytes());
        bytes.extend_from_slice(&legacy[WINDOW_OFFSET..]);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != ENCODED_BYTES
            || &bytes[..4] != super::MAGIC
            || u16::from_le_bytes(bytes[4..6].try_into().expect("fixed version")) != VERSION
        {
            return Err("noncanonical windowed fund claim".into());
        }
        let valid_until = u64::from_le_bytes(
            bytes[WINDOW_OFFSET..WINDOW_OFFSET + 8]
                .try_into()
                .expect("fixed validity height"),
        );
        // Reuse only V1's structural field checks, never its authorization path.
        let mut fields = Vec::with_capacity(super::ENCODED_BYTES);
        fields.extend_from_slice(&bytes[..WINDOW_OFFSET]);
        fields[4..6].copy_from_slice(&super::VERSION.to_le_bytes());
        fields.extend_from_slice(&bytes[WINDOW_OFFSET + 8..]);
        let result = Self {
            claim: PublicFundClaim::decode(&fields)?,
            valid_until,
        };
        result.validate_window()?;
        Ok(result)
    }

    pub fn signing_message(&self) -> Result<Vec<u8>, String> {
        let bytes = self.encode()?;
        Ok(bytes[..ENCODED_BYTES - crate::fund_spend::SIGNATURE_BYTES].to_vec())
    }

    pub fn signature_context() -> &'static [u8] {
        CONTEXT
    }
}

impl AuthorizedFundClaim {
    /// Verify against the actual inclusion state, without rewriting signed bytes.
    /// The enclosing candidate engine must select this format explicitly and
    /// atomically consume the returned authority with its fund ledger transition.
    pub fn verify_windowed(
        signed: &WindowedFundClaim,
        config: &Config,
        frozen: &GovernanceState,
        height: u64,
    ) -> Result<Self, String> {
        signed.validate_window()?;
        let claim = &signed.claim;
        if !(claim.height..=signed.valid_until).contains(&height)
            || frozen.height() != height
            || claim.network != config.network
            || frozen.network() != config.network
        {
            return Err("windowed fund claim block context differs".into());
        }
        Self::verify_authenticated(
            claim,
            config,
            frozen,
            height,
            &signed.signing_message()?,
            CONTEXT,
        )
    }
}
