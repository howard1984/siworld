//! Engineering-only checkpoint authentication. A quorum authenticates a claim;
//! it does not replace canonical-chain checks or permanent-data reconstruction.
use crate::{
    p2p::Binding,
    wire::{DigestBytes, Hash},
};
use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65Signature, MLDSA65VerificationKey};

pub const INTERVAL_SECONDS: u64 = 6 * 60 * 60;
pub const MAX_AGE_SECONDS: u64 = 18 * 60 * 60;
pub const HEIGHT_INTERVAL: u64 = 72;
pub const CONFIRMATIONS: u64 = 24;
pub const PUBLIC_KEY_BYTES: usize = 1952;
pub const SIGNATURE_BYTES: usize = 3309;
pub const MAX_CERTIFICATE_BYTES: usize = 8192;
pub(crate) const CONTEXT: &[u8] = b"siworld engineering checkpoint v1";
const MAGIC: &[u8; 8] = b"SWECP001";
mod release_roster;
pub use release_roster::release_roster;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub binding: Binding,
    pub roster: Hash,
    pub sequence: u64,
    pub issued_unix_seconds: u64,
    pub height: u64,
    pub block_id: Hash,
    pub cumulative_work: [u8; 64],
    pub state_fingerprint: Hash,
    pub state_encoding_digest: Hash,
    pub permanent_prefix_digest: Hash,
    pub commitment_root: DigestBytes,
    pub nullifier_digest: Hash,
    pub recent_roots_digest: Hash,
    pub holder_pool: u128,
    pub development_fund_digest: Hash,
    pub cumulative_issued: u128,
    pub cumulative_burned: u128,
    pub locked_rewards: u128,
    pub locked_schedule_digest: Hash,
    pub asset_registry_digest: Hash,
}
impl Statement {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        for value in [
            self.binding.network,
            self.binding.genesis,
            self.binding.verifier,
            self.roster,
        ] {
            bytes.extend_from_slice(&value);
        }
        for value in [self.sequence, self.issued_unix_seconds, self.height] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&self.block_id);
        bytes.extend_from_slice(&self.cumulative_work);
        for value in [
            self.state_fingerprint,
            self.state_encoding_digest,
            self.permanent_prefix_digest,
        ] {
            bytes.extend_from_slice(&value);
        }
        bytes.extend_from_slice(&self.commitment_root);
        bytes.extend_from_slice(&self.nullifier_digest);
        bytes.extend_from_slice(&self.recent_roots_digest);
        bytes.extend_from_slice(&self.holder_pool.to_le_bytes());
        bytes.extend_from_slice(&self.development_fund_digest);
        for value in [
            self.cumulative_issued,
            self.cumulative_burned,
            self.locked_rewards,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&self.locked_schedule_digest);
        bytes.extend_from_slice(&self.asset_registry_digest);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut reader = Reader(bytes);
        if &reader.array::<8>()? != MAGIC {
            return Err("checkpoint format mismatch".into());
        }
        let value = Self {
            binding: Binding {
                network: reader.array()?,
                genesis: reader.array()?,
                verifier: reader.array()?,
            },
            roster: reader.array()?,
            sequence: reader.u64()?,
            issued_unix_seconds: reader.u64()?,
            height: reader.u64()?,
            block_id: reader.array()?,
            cumulative_work: reader.array()?,
            state_fingerprint: reader.array()?,
            state_encoding_digest: reader.array()?,
            permanent_prefix_digest: reader.array()?,
            commitment_root: reader.array()?,
            nullifier_digest: reader.array()?,
            recent_roots_digest: reader.array()?,
            holder_pool: reader.u128()?,
            development_fund_digest: reader.array()?,
            cumulative_issued: reader.u128()?,
            cumulative_burned: reader.u128()?,
            locked_rewards: reader.u128()?,
            locked_schedule_digest: reader.array()?,
            asset_registry_digest: reader.array()?,
        };
        if !reader.0.is_empty() || value.encode() != bytes {
            return Err("noncanonical checkpoint statement".into());
        }
        value.check_shape()?;
        Ok(value)
    }
    fn check_shape(&self) -> Result<(), String> {
        if self.sequence == 0
            || self.issued_unix_seconds == 0
            || self.height == 0
            || !self.height.is_multiple_of(HEIGHT_INTERVAL)
        {
            return Err("checkpoint schedule or sequence invalid".into());
        }
        Ok(())
    }
    pub fn digest(&self) -> Hash {
        blake3::derive_key(
            "siworld engineering checkpoint statement v1",
            &self.encode(),
        )
    }
}
struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let (head, tail) = self.0.split_at_checked(N).ok_or("truncated checkpoint")?;
        self.0 = tail;
        Ok(head.try_into().expect("bounded field"))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn u128(&mut self) -> Result<u128, String> {
        Ok(u128::from_le_bytes(self.array()?))
    }
}

/// The two distinct public keys must be pinned by the engineering release.
/// No key supplied by a checkpoint or a transport can extend this roster.
pub struct Roster {
    binding: Binding,
    keys: [[u8; PUBLIC_KEY_BYTES]; 2],
}
impl Roster {
    pub(crate) fn binding(&self) -> Binding {
        self.binding
    }
    pub fn new(binding: Binding, keys: [[u8; PUBLIC_KEY_BYTES]; 2]) -> Result<Self, String> {
        if keys[0] == keys[1] || keys.iter().any(|key| key == &[0; PUBLIC_KEY_BYTES]) {
            return Err("checkpoint authorities must be distinct".into());
        }
        Ok(Self { binding, keys })
    }
    pub fn digest(&self) -> Hash {
        let mut hash = blake3::Hasher::new_derive_key("siworld engineering checkpoint roster v1");
        for value in [
            self.binding.network,
            self.binding.genesis,
            self.binding.verifier,
        ] {
            hash.update(&value);
        }
        for key in &self.keys {
            hash.update(key);
        }
        *hash.finalize().as_bytes()
    }
    pub(crate) fn index(&self, key: &[u8; PUBLIC_KEY_BYTES]) -> Result<u8, String> {
        self.keys
            .iter()
            .position(|value| value == key)
            .map(|index| index as u8)
            .ok_or("checkpoint signer is not pinned".into())
    }
}
#[derive(Clone)]
pub struct Vote {
    pub signer: u8,
    pub signature: [u8; SIGNATURE_BYTES],
}
#[derive(Clone)]
pub struct Certificate {
    pub statement: Statement,
    pub votes: Vec<Vote>,
}
pub struct AuthenticatedCheckpoint {
    statement: Statement,
}
impl AuthenticatedCheckpoint {
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn pruning_fresh(&self, now: u64) -> bool {
        now.checked_sub(self.statement.issued_unix_seconds)
            .is_some_and(|age| age <= MAX_AGE_SECONDS)
    }
}
#[derive(Clone, Copy)]
pub struct Cursor {
    pub sequence: u64,
    pub height: u64,
    pub digest: Hash,
}
impl Certificate {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.statement.check_shape()?;
        if self.votes.len() != 2 {
            return Err("two checkpoint signatures required".into());
        }
        let statement = self.statement.encode();
        let mut bytes = (statement.len() as u16).to_le_bytes().to_vec();
        bytes.extend_from_slice(&statement);
        bytes.push(2);
        for vote in &self.votes {
            bytes.push(vote.signer);
            bytes.extend_from_slice(&vote.signature);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err("checkpoint certificate byte limit".into());
        }
        let mut reader = Reader(bytes);
        let length = u16::from_le_bytes(reader.array()?) as usize;
        let (body, tail) = reader
            .0
            .split_at_checked(length)
            .ok_or("truncated checkpoint statement")?;
        let statement = Statement::decode(body)?;
        reader.0 = tail;
        if reader.array::<1>()? != [2] {
            return Err("two checkpoint signatures required".into());
        }
        let mut votes = Vec::with_capacity(2);
        for _ in 0..2 {
            votes.push(Vote {
                signer: reader.array::<1>()?[0],
                signature: reader.array()?,
            });
        }
        if !reader.0.is_empty() {
            return Err("trailing checkpoint certificate".into());
        }
        Ok(Self { statement, votes })
    }
    /// Authenticate the roster and monotonic cursor. This returns no ability to
    /// join a network, replace local state, or prune any proof.
    pub fn authenticate(
        &self,
        roster: &Roster,
        last: Option<Cursor>,
        now: u64,
    ) -> Result<AuthenticatedCheckpoint, String> {
        self.statement.check_shape()?;
        if self.statement.binding != roster.binding || self.statement.roster != roster.digest() {
            return Err("checkpoint network or authority roster mismatch".into());
        }
        if now < self.statement.issued_unix_seconds {
            return Err("checkpoint publication is in the future".into());
        }
        if let Some(last) = last
            && (self.statement.sequence < last.sequence
                || self.statement.height < last.height
                || self.statement.sequence == last.sequence
                    && self.statement.digest() != last.digest)
        {
            return Err("checkpoint sequence rollback or equivocation".into());
        }
        if self.votes.len() != 2 || self.votes[0].signer != 0 || self.votes[1].signer != 1 {
            return Err(
                "both distinct pinned checkpoint signers required in canonical order".into(),
            );
        }
        let message = self.statement.encode();
        for (vote, key) in self.votes.iter().zip(&roster.keys) {
            ml_dsa_65::verify(
                &MLDSA65VerificationKey::new(*key),
                &message,
                CONTEXT,
                &MLDSA65Signature::new(vote.signature),
            )
            .map_err(|_| "checkpoint signature invalid")?;
        }
        Ok(AuthenticatedCheckpoint {
            statement: self.statement.clone(),
        })
    }
}
pub fn scheduled_height(tip: u64) -> Option<u64> {
    let height = tip.checked_sub(CONFIRMATIONS)? / HEIGHT_INTERVAL * HEIGHT_INTERVAL;
    (height > 0).then_some(height)
}

#[cfg(test)]
mod tests;
