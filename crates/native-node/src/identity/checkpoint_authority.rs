//! Dedicated engineering checkpoint keys; private records never leave the host.
use super::{Error, Storage};
use crate::{
    engineering_checkpoint::{CONTEXT, PUBLIC_KEY_BYTES, Roster, Vote},
    p2p::Binding,
};
use libcrux_ml_dsa::ml_dsa_65::{self, MLDSA65SigningKey};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const FILE: &str = "engineering-checkpoint-authority.secret";
const MAGIC: &[u8; 8] = b"SWECA001";
const RECORD_BYTES: usize = 8 + 96 + 32 + 32;
pub struct Authority {
    binding: Binding,
    key: MLDSA65SigningKey,
    public: [u8; PUBLIC_KEY_BYTES],
    directory: PathBuf,
}
impl std::fmt::Debug for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CheckpointAuthority(REDACTED)")
    }
}
impl Drop for Authority {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}
impl Authority {
    /// Existing owner-only directory; atomic write-once key initialization.
    pub fn initialize(directory: &Path, binding: Binding) -> Result<Self, Error> {
        let storage = Storage::open(directory)?;
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| Error::Entropy)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(RECORD_BYTES));
        bytes.extend_from_slice(MAGIC);
        for value in [binding.network, binding.genesis, binding.verifier] {
            bytes.extend_from_slice(&value);
        }
        bytes.extend_from_slice(seed.as_ref());
        let checksum =
            blake3::derive_key("siworld engineering checkpoint authority record v1", &bytes);
        bytes.extend_from_slice(&checksum);
        storage.write_once(FILE, &bytes)?;
        Self::load(directory, binding)
    }
    pub fn load(directory: &Path, binding: Binding) -> Result<Self, Error> {
        let bytes = Storage::open(directory)?.read_exact(FILE, RECORD_BYTES)?;
        let mut expected = MAGIC.to_vec();
        for value in [binding.network, binding.genesis, binding.verifier] {
            expected.extend_from_slice(&value);
        }
        if bytes[..104] != expected
            || bytes[136..]
                != blake3::derive_key(
                    "siworld engineering checkpoint authority record v1",
                    &bytes[..136],
                )
        {
            return Err(Error::ContextMismatch);
        }
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(&bytes[104..136]).map_err(|_| Error::InvalidRecord)?,
        );
        let pair = ml_dsa_65::generate_key_pair(*seed);
        Ok(Self {
            binding,
            key: pair.signing_key,
            public: *pair.verification_key.as_ref(),
            directory: directory.to_owned(),
        })
    }
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.public
    }
    /// Recover a public vote after a crash without changing the statement at an
    /// already used sequence. The private key is never included in the record.
    #[cfg(feature = "native-p2p")]
    pub(crate) fn saved_vote(
        &self,
        sequence: u64,
    ) -> Result<Option<(crate::engineering_checkpoint::Statement, Vote)>, String> {
        let name = format!("engineering-checkpoint-vote-{sequence:020}.bin");
        if !self
            .directory
            .join(&name)
            .try_exists()
            .map_err(|_| "checkpoint vote metadata unavailable")?
        {
            return Ok(None);
        }
        const STATEMENT_BYTES: usize = 624;
        let storage = Storage::open(&self.directory)
            .map_err(|_| "checkpoint authority storage unavailable")?;
        let bytes = storage
            .read_exact(&name, STATEMENT_BYTES + 1 + 3309)
            .map_err(|_| "checkpoint saved vote unavailable")?;
        let statement =
            crate::engineering_checkpoint::Statement::decode(&bytes[..STATEMENT_BYTES])?;
        if statement.sequence != sequence {
            return Err("checkpoint saved sequence mismatch".into());
        }
        Ok(Some((
            statement,
            Vote {
                signer: bytes[STATEMENT_BYTES],
                signature: bytes[STATEMENT_BYTES + 1..]
                    .try_into()
                    .map_err(|_| "checkpoint saved vote shape")?,
            },
        )))
    }
    /// Only Store can construct a locally verified candidate. Persist a public
    /// vote before returning it; signing a different statement at the same
    /// sequence fails without overwriting the earlier vote.
    pub(crate) fn sign(
        &self,
        candidate: &crate::store::engineering_checkpoint::LocalCandidate,
        roster: &Roster,
    ) -> Result<Vote, String> {
        let statement = candidate.statement();
        if statement.binding != self.binding || statement.roster != roster.digest() {
            return Err("checkpoint signer context mismatch".into());
        }
        let signer = roster.index(&self.public)?;
        let storage = Storage::open(&self.directory)
            .map_err(|_| "checkpoint authority storage unavailable")?;
        let name = format!("engineering-checkpoint-vote-{:020}.bin", statement.sequence);
        let message = statement.encode();
        let length = message.len() + 1 + 3309;
        if let Ok(record) = storage.read_exact(&name, length) {
            if record[..message.len()] != message || record[message.len()] != signer {
                return Err("checkpoint signer equivocation refused".into());
            }
            return Ok(Vote {
                signer,
                signature: record[message.len() + 1..]
                    .try_into()
                    .map_err(|_| "invalid persisted checkpoint vote")?,
            });
        }
        let mut random = Zeroizing::new([0; 32]);
        getrandom::fill(random.as_mut()).map_err(|_| "checkpoint signing entropy unavailable")?;
        let signature = *ml_dsa_65::sign(&self.key, &message, CONTEXT, *random)
            .map_err(|_| "checkpoint signing failed")?
            .as_ref();
        let mut record = message;
        record.push(signer);
        record.extend_from_slice(&signature);
        storage
            .write_once(&name, &record)
            .map_err(|_| "checkpoint vote persistence conflict or I/O failure")?;
        Ok(Vote { signer, signature })
    }
}
