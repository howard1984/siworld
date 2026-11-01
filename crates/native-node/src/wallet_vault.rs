//! Versioned encrypted seed custody for the native engineering wallet.
//!
//! This is a local storage format, not a consensus or address format. The
//! 24-word English mnemonic encodes the 256-bit entropy consumed by the existing
//! wallet derivation; it is not the BIP39 PBKDF2 seed. A recovery record must also
//! retain the public network ID and account index. No secret type implements
//! Debug, Display or serialization. A frontend must render recovery words only
//! in a local protected backup view, never logs, telemetry or remote RPC.
use crate::wallet::{Wallet, WalletKeys};
use crate::wire::Hash;
use argon2::{Algorithm, Argon2, Block, Params, Version};
use bip39::{Language, Mnemonic};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use std::path::Path;
use zeroize::Zeroizing;

mod journal;
mod opening;
mod storage;
pub use journal::{PaymentPacket, PaymentStatus, ReservedPayment};
pub use opening::StoredPaymentOpening;
#[cfg(test)]
mod native_roundtrip;
#[cfg(test)]
mod tests;

const MAGIC: &[u8; 8] = b"SWNVLT01";
const AAD: &[u8] =
    b"siworld native wallet entropy vault v1:argon2id-v19:m65536:t3:p1:xchacha20poly1305";
const MEMORY_KIB: u32 = 65_536;
const HEADER_LEN: usize = 8 + 16 + 24;
const PLAINTEXT_LEN: usize = 32 + 4 + 32;
const VAULT_LEN: usize = HEADER_LEN + PLAINTEXT_LEN + 16;
const MAX_PASSWORD_BYTES: usize = 1024;
const MAX_MNEMONIC_BYTES: usize = 256;
const VAULT_FILENAME: &str = "seed.vault";

/// Public backup context; none of these fields authorize spending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryDescriptor {
    pub version: u16,
    pub network: Hash,
    pub account: u32,
}

/// An explicit local recovery view. Formatting is deliberately unavailable.
pub struct RecoveryWords(Zeroizing<String>);
impl RecoveryWords {
    /// Borrow only for the local protected backup view. Never log or transmit.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// An unpersisted wallet with a mandatory randomized backup challenge.
/// Dropping it erases the owned entropy and mnemonic buffers.
pub struct PendingWallet {
    material: RecoveryMaterial,
    mnemonic: Mnemonic,
    challenge: [usize; 3],
}
impl PendingWallet {
    /// Draw the complete 256-bit wallet entropy from the operating system.
    /// This API has no deterministic entropy injection on production paths.
    pub fn generate(network: Hash, account: u32) -> Result<Self, String> {
        valid_network(network)?;
        let mut entropy = Zeroizing::new([0; 32]);
        getrandom::fill(entropy.as_mut()).map_err(|_| "OS randomness unavailable")?;
        let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy.as_ref())
            .map_err(|_| "cannot encode wallet recovery words")?;
        let mut challenge = [0; 3];
        for index in 0..challenge.len() {
            loop {
                let mut random = [0; 1];
                getrandom::fill(&mut random).map_err(|_| "OS randomness unavailable")?;
                // Rejection sampling avoids modulo bias across 24 positions.
                if random[0] < 240 {
                    let position = usize::from(random[0] % 24) + 1;
                    if !challenge[..index].contains(&position) {
                        challenge[index] = position;
                        break;
                    }
                }
            }
        }
        Ok(Self {
            material: RecoveryMaterial {
                network,
                account,
                entropy,
            },
            mnemonic,
            challenge,
        })
    }

    /// The caller must protect this view from logs, clipboard history,
    /// browser persistence, remote APIs and screen recording.
    pub fn recovery_words(&self) -> RecoveryWords {
        RecoveryWords(Zeroizing::new(self.mnemonic.to_string()))
    }

    pub fn descriptor(&self) -> RecoveryDescriptor {
        self.material.descriptor()
    }

    /// Three distinct one-based word positions selected at creation.
    pub fn backup_challenge(&self) -> [usize; 3] {
        self.challenge
    }

    /// No file is created before the displayed recovery words are confirmed.
    /// A local UI must obtain these answers again rather than copying its own
    /// displayed words. This checks acknowledgement, not physical custody.
    pub fn confirm_backup(self, answers: [&str; 3]) -> Result<ConfirmedWallet, String> {
        for (position, answer) in self.challenge.into_iter().zip(answers) {
            if self.mnemonic.words().nth(position - 1) != Some(answer) {
                return Err("wallet backup confirmation did not match".into());
            }
        }
        Ok(ConfirmedWallet {
            material: self.material,
        })
    }
}

/// Creation capability obtained only after the backup challenge succeeds.
pub struct ConfirmedWallet {
    material: RecoveryMaterial,
}
impl ConfirmedWallet {
    /// Publish a complete vault in a new private directory, without overwrite.
    /// Parent directories must already exist and contain no symlink component.
    pub fn create(self, directory: &Path, passphrase: &str) -> Result<UnlockedWallet, String> {
        create(self.material, directory, passphrase)
    }
}

/// Native-wallet seed vault entry points. This initial seed format is immutable;
/// password rotation requires a separately specified migration.
pub struct WalletVault;
impl WalletVault {
    /// Restore exactly 24 canonical English words into a new directory. The
    /// public network/account recovery descriptor must match the original.
    /// A BIP39 optional passphrase is not supported by this wallet derivation.
    /// `passphrase` encrypts the local vault and does not alter wallet identity.
    pub fn restore(
        directory: &Path,
        network: Hash,
        account: u32,
        words: Zeroizing<String>,
        passphrase: &str,
    ) -> Result<UnlockedWallet, String> {
        valid_network(network)?;
        if words.len() > MAX_MNEMONIC_BYTES
            || words.split(' ').count() != 24
            || words
                .bytes()
                .any(|byte| !byte.is_ascii_lowercase() && byte != b' ')
        {
            return Err("recovery requires exactly 24 canonical English words".into());
        }
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &words)
            .map_err(|_| "invalid wallet recovery words or checksum")?;
        let bytes = Zeroizing::new(mnemonic.to_entropy());
        let entropy = Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| "wallet recovery requires 256-bit entropy")?,
        );
        create(
            RecoveryMaterial {
                network,
                account,
                entropy,
            },
            directory,
            passphrase,
        )
    }

    /// Authenticate bounded ciphertext under exclusive directory ownership.
    /// The expected network is checked before exposing any wallet keys.
    pub fn open(
        directory: &Path,
        expected_network: Hash,
        passphrase: &str,
    ) -> Result<UnlockedWallet, String> {
        valid_network(expected_network)?;
        let owner = storage::Directory::open(directory)?;
        let encoded = owner.read_vault()?;
        let material = decrypt(&encoded, passphrase)?;
        if material.network != expected_network {
            return Err("wallet belongs to a different network".into());
        }
        let journal = journal::Journal::load(&owner, &material)?;
        Ok(UnlockedWallet {
            material,
            journal,
            _owner: owner,
        })
    }
}

/// Exclusive custody session. Keep this alive for the entire wallet operation.
/// The seed remains in erasing memory; process/register/dependency copies,
/// swap, a compromised host and screenshots are outside this guarantee.
pub struct UnlockedWallet {
    material: RecoveryMaterial,
    journal: journal::Journal,
    _owner: storage::Directory,
}
impl UnlockedWallet {
    /// Synchronize both input-nullifier reservations before starting proof work.
    pub fn reserve_payment(
        &mut self,
        record: &crate::wire::PublicRecord,
    ) -> Result<ReservedPayment, String> {
        self.journal.reserve(&self._owner, record)
    }
    /// Persist exact transaction, checked fee sidecar and private opening before
    /// any relay attempt. The caller validates its bounded opening encoding.
    pub fn store_prepared_payment(
        &mut self,
        reservation: &ReservedPayment,
        transaction: &crate::wire::Transaction,
        sidecar: &crate::wire::Sidecar,
        opening: Zeroizing<Vec<u8>>,
        validate_opening: impl FnOnce(&crate::wire::Transaction, &[u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        self.journal.prepare(
            &self._owner,
            reservation,
            transaction,
            sidecar,
            opening,
            validate_opening,
        )
    }
    /// Retry only an identical synchronized packet. A relay failure retains it.
    pub fn submit_payment(
        &mut self,
        id: Hash,
        deliver: impl FnOnce(&PaymentPacket) -> Result<(), String>,
    ) -> Result<(), String> {
        self.journal.submit(&self._owner, id, deliver)
    }
    pub fn payment_ids(&self) -> Vec<Hash> {
        self.journal.ids()
    }
    pub fn payment_status(&self, id: Hash) -> Result<PaymentStatus, String> {
        self.journal.status(&self._owner, id)
    }
    pub fn payment_packet(&self, id: Hash) -> Result<PaymentPacket, String> {
        self.journal.packet(&self._owner, id)
    }
    /// Replay proofs and consensus before updating private acceptance/conflict
    /// status. The caller still authenticates which history is canonical.
    pub fn reconcile_payments(
        &mut self,
        config: crate::state::Config,
        blocks: &[crate::wire::Block],
        verifier: &impl crate::state::BlockVerifier,
    ) -> Result<crate::audit::AuditReport, String> {
        self.journal
            .reconcile(&self._owner, config, blocks, verifier)
    }
    pub fn descriptor(&self) -> RecoveryDescriptor {
        self.material.descriptor()
    }
    pub fn network(&self) -> Hash {
        self.material.network
    }
    pub fn account(&self) -> u32 {
        self.material.account
    }
    pub fn keys(&self) -> Result<WalletKeys, String> {
        self._owner.check_owner()?;
        WalletKeys::from_seed(
            self.material.network,
            Zeroizing::new(*self.material.entropy),
            self.material.account,
        )
    }
    /// Receipts are reconstructed through the existing authenticated canonical
    /// replay API. A restored seed alone does not authenticate a checkpoint.
    pub fn wallet(&self) -> Result<Wallet, String> {
        self._owner.check_owner()?;
        Wallet::from_seed(
            self.material.network,
            Zeroizing::new(*self.material.entropy),
            self.material.account,
        )
    }
}

struct RecoveryMaterial {
    network: Hash,
    account: u32,
    entropy: Zeroizing<[u8; 32]>,
}
impl RecoveryMaterial {
    fn descriptor(&self) -> RecoveryDescriptor {
        RecoveryDescriptor {
            version: 1,
            network: self.network,
            account: self.account,
        }
    }
}

fn valid_network(network: Hash) -> Result<(), String> {
    if network == [0; 32] {
        Err("wallet requires a nonzero network ID".into())
    } else {
        Ok(())
    }
}

fn create(
    material: RecoveryMaterial,
    directory: &Path,
    passphrase: &str,
) -> Result<UnlockedWallet, String> {
    if !(12..=MAX_PASSWORD_BYTES).contains(&passphrase.len()) {
        return Err("new wallet passphrases require 12 to 1024 UTF-8 bytes".into());
    }
    let encoded = encrypt(&material, passphrase)?;
    // Authenticate the complete ciphertext before any file is published.
    let check = decrypt(&encoded, passphrase)?;
    if check.network != material.network
        || check.account != material.account
        || check.entropy.as_ref() != material.entropy.as_ref()
    {
        return Err("wallet vault identity check failed".into());
    }
    let owner = storage::Directory::create(directory)?;
    let journal = journal::Journal::create(&owner, &material)?;
    owner.publish_with(&encoded, || Ok(()))?;
    Ok(UnlockedWallet {
        material,
        journal,
        _owner: owner,
    })
}

fn derive(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    if passphrase.is_empty() || passphrase.len() > MAX_PASSWORD_BYTES {
        return Err("wallet passphrase must contain 1 to 1024 UTF-8 bytes".into());
    }
    let params =
        Params::new(MEMORY_KIB, 3, 1, Some(32)).map_err(|_| "invalid wallet KDF profile")?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0; 32]);
    let mut memory = Zeroizing::new(vec![Block::default(); MEMORY_KIB as usize]);
    argon
        .hash_password_into_with_memory(passphrase.as_bytes(), salt, key.as_mut(), &mut memory)
        .map_err(|_| "wallet key derivation failed")?;
    Ok(key)
}

fn encrypt(material: &RecoveryMaterial, passphrase: &str) -> Result<[u8; VAULT_LEN], String> {
    let mut encoded = [0; VAULT_LEN];
    encoded[..MAGIC.len()].copy_from_slice(MAGIC);
    getrandom::fill(&mut encoded[MAGIC.len()..HEADER_LEN])
        .map_err(|_| "OS randomness unavailable")?;
    let derived = derive(passphrase, &encoded[8..24])?;
    let cipher =
        XChaCha20Poly1305::new(<&Key>::try_from(derived.as_ref()).expect("fixed key width"));
    let mut plaintext = Zeroizing::new([0; PLAINTEXT_LEN]);
    plaintext[..32].copy_from_slice(&material.network);
    plaintext[32..36].copy_from_slice(&material.account.to_le_bytes());
    plaintext[36..].copy_from_slice(material.entropy.as_ref());
    let tag = cipher
        .encrypt_inout_detached(
            <&XNonce>::try_from(&encoded[24..HEADER_LEN]).expect("fixed nonce width"),
            &authentication_data(&encoded[..HEADER_LEN]),
            plaintext.as_mut_slice().into(),
        )
        .map_err(|_| "wallet vault encryption failed")?;
    encoded[HEADER_LEN..HEADER_LEN + PLAINTEXT_LEN].copy_from_slice(plaintext.as_ref());
    encoded[HEADER_LEN + PLAINTEXT_LEN..].copy_from_slice(tag.as_ref());
    Ok(encoded)
}

fn decrypt(encoded: &[u8], passphrase: &str) -> Result<RecoveryMaterial, String> {
    if encoded.len() != VAULT_LEN || &encoded[..MAGIC.len()] != MAGIC {
        return Err("unsupported or malformed native wallet vault".into());
    }
    let derived = derive(passphrase, &encoded[8..24])?;
    let cipher =
        XChaCha20Poly1305::new(<&Key>::try_from(derived.as_ref()).expect("fixed key width"));
    let mut plaintext = Zeroizing::new([0; PLAINTEXT_LEN]);
    plaintext.copy_from_slice(&encoded[HEADER_LEN..HEADER_LEN + PLAINTEXT_LEN]);
    cipher
        .decrypt_inout_detached(
            <&XNonce>::try_from(&encoded[24..HEADER_LEN]).expect("fixed nonce width"),
            &authentication_data(&encoded[..HEADER_LEN]),
            plaintext.as_mut_slice().into(),
            <&Tag>::try_from(&encoded[HEADER_LEN + PLAINTEXT_LEN..]).expect("fixed tag width"),
        )
        .map_err(|_| "incorrect wallet passphrase or damaged vault")?;
    let network = plaintext[..32].try_into().expect("fixed network width");
    valid_network(network)?;
    Ok(RecoveryMaterial {
        network,
        account: u32::from_le_bytes(plaintext[32..36].try_into().expect("fixed account width")),
        entropy: Zeroizing::new(plaintext[36..].try_into().expect("fixed entropy width")),
    })
}

fn authentication_data(header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD.len() + HEADER_LEN);
    aad.extend_from_slice(AAD);
    aad.extend_from_slice(header);
    aad
}
