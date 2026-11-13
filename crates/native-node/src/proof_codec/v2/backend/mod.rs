//! Explicit inactive native proof configuration with two salted Merkle paths.
//!
//! This profile preserves polynomial masking and does not activate a network.
//! Nine field salts provide about 278.9 ideal field bits per row; private stream
//! seeds have 256 bits. These counts do not establish a full protocol hiding or
//! post-quantum security level. Both the hash model and combined disclosures
//! require separate qualification.
mod entropy;
mod issuance_trace;
mod owner;
mod pcs;
mod relations;
mod settlement_trace;
pub use relations::{
    IssuanceProver, IssuanceVerifier, SettlementProver, SettlementVerifier, TransactionProver,
    TransactionVerifier,
};

use ::native::FriParams;
pub use entropy::EntropyError;
pub use owner::{AccessError, OwnerError};
pub use pcs::{Challenger, Config, E, PrivateAttempt, PublicPreprocessing};

pub const SALT_ELEMENTS: usize = 9;
pub const RANDOM_CODEWORDS: usize = 8;
pub const INPUT_CAP_HEIGHT: usize = 1;
pub const FRI_CAP_HEIGHT: usize = 2;
pub const PROFILE_VERSION: u16 = 2;
pub const PROFILE_NAME: &[u8] = b"native-d8-w24-dual-hiding-mmcs-v2";

#[derive(Clone, Copy, Debug)]
pub struct Profile {
    params: FriParams,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileError {
    UnsupportedParameters,
}
impl Profile {
    pub fn new(params: FriParams) -> Result<Self, ProfileError> {
        if params.log_blowup == 0
            || params.log_blowup > 16
            || !(1..=256).contains(&params.num_queries)
            || params.max_log_arity != 1
            || params.query_pow_bits > 32
            || params.commit_pow_bits > 32
            || params.batch_pow_bits > 32
        {
            return Err(ProfileError::UnsupportedParameters);
        }
        Ok(Self { params })
    }
    pub fn transaction() -> Self {
        Self::new(FriParams {
            log_blowup: 7,
            num_queries: 41,
            query_pow_bits: 20,
            commit_pow_bits: 0,
            batch_pow_bits: 20,
            max_log_arity: 1,
        })
        .expect("fixed native V2 transaction parameters")
    }
    pub fn settlement() -> Self {
        Self::new(FriParams::transaction_candidate())
            .expect("fixed native V2 settlement parameters")
    }
    pub fn issuance() -> Self {
        Self::settlement()
    }
    pub const fn params(self) -> FriParams {
        self.params
    }
    pub fn minimum_height(self) -> usize {
        self.params.hiding_min_height()
    }
    /// Backend identity only. Admission must additionally bind relation, AIR,
    /// exact preprocessing key, outer codec and network/genesis identity.
    pub fn id(self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("siworld native dual hiding MMCS profile v2");
        h.update(PROFILE_NAME);
        h.update(&PROFILE_VERSION.to_le_bytes());
        for value in [
            8,
            24,
            12,
            12,
            SALT_ELEMENTS as u32,
            RANDOM_CODEWORDS as u32,
            INPUT_CAP_HEIGHT as u32,
            FRI_CAP_HEIGHT as u32,
            self.params.log_blowup,
            self.params.num_queries,
            self.params.query_pow_bits,
            self.params.commit_pow_bits,
            self.params.batch_pow_bits,
            self.params.max_log_arity,
            0,
        ] {
            h.update(&value.to_le_bytes());
        }
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests;
