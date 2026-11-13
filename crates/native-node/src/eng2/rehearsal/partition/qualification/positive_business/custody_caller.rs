//! Existing isolated actor vaults and concrete payment-journal custody.
//!
//! Payment reservations and proved packets use the production encrypted journal.
//! Original pre-proof, issuance and reward openings also remain in caller-owned
//! erasing memory across ordinary errors. This memory is not crash recovery.
//! No raw opening export, secret formatting, key derivation policy, relay,
//! acceptance reconciliation, vault creation or implicit retry is provided.
use super::{Actors, Custody};
use crate::{
    eng2::{producer::ProducedBlock, store::Store},
    eng2_governance::{AddressBytes, canonical_address},
    wallet::{
        PreparedTransfer, Wallet, WalletPayment,
        issuance::{ISSUER_SIGNATURE_CONTEXT, WalletIssuance},
    },
    wallet_vault::{PaymentStatus, ReservedPayment, UnlockedWallet, WalletVault},
    wire::{Hash, PublicRecord},
};
use native::{
    encryption::{EncryptionContext, PaymentAddress, PaymentCiphertext, PaymentEncryptionOpening},
    multi_asset::Hasher,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const PAYMENT_LIMIT: usize = 4;
const REWARD_LIMIT: usize = 4;
const REWARD_BYTES_LIMIT: usize = 8192;

/// Fixed order: payer, recipient, issuance-fee destination, fund destination,
/// reward. Each address must come from independently authenticated genesis and
/// business inputs, not from deriving another actor from a shared seed.
/// Supply passwords from protected local memory, never CLI arguments or logs.
pub struct ExistingVault<'a> {
    pub directory: &'a Path,
    pub passphrase: &'a str,
    pub expected_account: u32,
    pub expected_address: &'a PaymentAddress,
}
struct Actor {
    vault: UnlockedWallet,
    scanner: Wallet,
}
/// Keeps all five exclusive vault sessions and their dedicated scanner views.
/// Opening a vault authenticates existing material; it does not establish who
/// controls the genesis issuer, governance authority or fund entitlement.
pub struct IsolatedActors {
    network: Hash,
    directories: [PathBuf; 5],
    actors: [Actor; 5],
}
impl IsolatedActors {
    /// `excluded_roots` must contain the actual node Store and evidence roots.
    /// All roots must already exist. The underlying vault API additionally
    /// anchors no-follow directory access, checks owner-only modes and locks.
    /// This acquires existing vault locks and decrypts material only when called
    /// explicitly by the owner. It never creates or restores a vault.
    pub fn open_existing(
        network: Hash,
        specifications: [ExistingVault<'_>; 5],
        excluded_roots: &[&Path],
        before_phase: &mut impl FnMut(&str) -> Result<(), String>,
    ) -> Result<Self, String> {
        owner_only()?;
        if network == [0; 32] || excluded_roots.len() < 2 {
            return Err("actor custody requires network and explicit excluded roots".into());
        }
        let excluded = excluded_roots
            .iter()
            .map(|path| canonical(path))
            .collect::<Result<Vec<_>, _>>()?;
        let directories = specifications
            .iter()
            .map(|spec| canonical(spec.directory))
            .collect::<Result<Vec<_>, _>>()?;
        let mut addresses = BTreeSet::new();
        for (index, directory) in directories.iter().enumerate() {
            if excluded.iter().any(|root| overlaps(directory, root))
                || directories[..index]
                    .iter()
                    .any(|other| overlaps(directory, other))
                || !addresses.insert(canonical_address(specifications[index].expected_address))
            {
                return Err("actor vault directories or complete addresses overlap".into());
            }
        }
        let mut actors = Vec::with_capacity(5);
        for specification in specifications {
            before_phase("before_existing_actor_vault_open")?;
            let vault =
                WalletVault::open(specification.directory, network, specification.passphrase)?;
            if vault.account() != specification.expected_account {
                return Err("actor vault account differs from independent input".into());
            }
            let scanner = vault.wallet()?;
            if canonical_address(&scanner.address())
                != canonical_address(specification.expected_address)
                || scanner.head().is_some()
                || !scanner.receipts().is_empty()
            {
                return Err("actor vault address or dedicated scanner differs".into());
            }
            actors.push(Actor { vault, scanner });
        }
        let actors = actors
            .try_into()
            .map_err(|_| "actor custody requires exactly five existing vaults")?;
        let directories = directories
            .try_into()
            .map_err(|_| "actor custody requires exactly five directories")?;
        Ok(Self {
            network,
            directories,
            actors,
        })
    }

    /// `retained` must outlive this call, including Result::Err: accepted block
    /// prefixes are not rolled back, and memory openings must not be discarded
    /// merely because later proof, append, scan or evidence output failed.
    /// The external gate must enforce the separately approved hard resource
    /// limit; an arbitrary successful closure does not establish that limit.
    /// The issuer callback must use a separately established issuer custody
    /// adapter. This method supplies the exact production context and message;
    /// the existing attach_signature path checks the resulting authorization.
    #[allow(clippy::too_many_arguments)]
    pub fn generate(
        &mut self,
        store: &mut Store,
        isolated_directory: &Path,
        output_directory: &Path,
        plan_path: &Path,
        plan_pin: &str,
        binding: (&Path, &str),
        retained: &mut RetainedMaterial,
        before_phase: &mut impl FnMut(&str) -> Result<(), String>,
        issuer_signer: &mut impl FnMut(
            &[u8],
            &[u8],
        )
            -> Result<[u8; native::issuance::ISSUER_SIGNATURE_BYTES], String>,
    ) -> Result<Value, String> {
        owner_only()?;
        if self.network != store.engine().state().chain().config.network || !retained.is_empty() {
            return Err("custody network differs or retained campaign is not empty".into());
        }
        let node = canonical(isolated_directory)?;
        let output_parent = canonical(
            output_directory
                .parent()
                .ok_or("custody output requires an existing parent")?,
        )?;
        let output = output_parent.join(
            output_directory
                .file_name()
                .ok_or("custody output requires a directory name")?,
        );
        if output != output_directory
            || self
                .directories
                .iter()
                .any(|vault| overlaps(vault, &node) || overlaps(vault, &output))
        {
            return Err("actual node or output directory overlaps actor custody".into());
        }
        let [payer, recipient, fee_destination, fund_destination, reward] = &mut self.actors;
        let mut actors = Actors {
            payer: &mut payer.scanner,
            recipient: &mut recipient.scanner,
            fee_destination: &mut fee_destination.scanner,
            fund_destination: &mut fund_destination.scanner,
            reward: &mut reward.scanner,
        };
        let mut custody = JournalCustody {
            network: self.network,
            payer: &mut payer.vault,
            retained,
            before_phase,
            issuer_signer,
        };
        super::generate(
            store,
            isolated_directory,
            output_directory,
            plan_path,
            plan_pin,
            binding,
            &mut actors,
            &mut custody,
        )
    }
}

struct RetainedPayment {
    kind: String,
    record: PublicRecord,
    recipient: AddressBytes,
    opening: PaymentEncryptionOpening,
    reservation: Option<ReservedPayment>,
    persisted: bool,
}
struct RetainedIssuance {
    _binding: Hash,
    _record_sha256: Hash,
    _recipient: AddressBytes,
    _openings: [PaymentEncryptionOpening; crate::issuance::INITIAL_NOTES],
}
struct RetainedReward {
    _header_id: Hash,
    _secret: Zeroizing<Vec<u8>>,
}
/// Caller-owned memory, intentionally without Debug, serialization or raw
/// getters. PaymentEncryptionOpening and Zeroizing erase their owned buffers
/// on drop. Host compromise, swap and process/register copies are not covered.
/// A crash loses this memory. Only proved payments have encrypted persistence.
#[derive(Default)]
pub struct RetainedMaterial {
    payments: Vec<RetainedPayment>,
    issuance: Option<RetainedIssuance>,
    rewards: Vec<RetainedReward>,
}
impl RetainedMaterial {
    fn is_empty(&self) -> bool {
        self.payments.is_empty() && self.issuance.is_none() && self.rewards.is_empty()
    }
    /// Counts disclose no note, balance, statement, destination or opening.
    /// The second count includes only packet writes followed by successful
    /// read-back/status checks; a later check failure may leave a durable write.
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.payments.len(),
            self.payments
                .iter()
                .filter(|payment| payment.persisted)
                .count(),
            usize::from(self.issuance.is_some()),
            self.rewards.len(),
        )
    }
}
struct JournalCustody<'a, G, S> {
    network: Hash,
    payer: &'a mut UnlockedWallet,
    retained: &'a mut RetainedMaterial,
    before_phase: &'a mut G,
    issuer_signer: &'a mut S,
}
impl<G, S> Custody for JournalCustody<'_, G, S>
where
    G: FnMut(&str) -> Result<(), String>,
    S: FnMut(&[u8], &[u8]) -> Result<[u8; native::issuance::ISSUER_SIGNATURE_BYTES], String>,
{
    fn before_phase(&mut self, phase: &str) -> Result<(), String> {
        (self.before_phase)(phase)
    }
    fn protect_prepared_payment(
        &mut self,
        kind: &str,
        recipient: &PaymentAddress,
        payment: &PreparedTransfer,
    ) -> Result<(), String> {
        (self.before_phase)("before_payment_reservation_and_memory_retention")?;
        if !matches!(kind, "standard" | "priority" | "consolidation" | "issuance")
            || self.retained.payments.len() >= PAYMENT_LIMIT
            || self.retained.payments.iter().any(|old| {
                old.kind == kind
                    || old.record.statement_id(&self.network)
                        == payment.record().statement_id(&self.network)
            })
        {
            return Err("unexpected or repeated business payment reservation".into());
        }
        self.retained.payments.push(RetainedPayment {
            kind: kind.to_owned(),
            record: payment.record().clone(),
            recipient: canonical_address(recipient),
            opening: copy_opening(payment.payment_opening()),
            reservation: None,
            persisted: false,
        });
        // A journal write may fail after a durable filesystem boundary. Keep
        // the original opening and statement even when reservation returns Err.
        let original = self
            .retained
            .payments
            .last_mut()
            .ok_or("original payment retention is absent")?;
        original.reservation = Some(self.payer.reserve_payment(payment.record())?);
        Ok(())
    }
    fn protect_payment(
        &mut self,
        kind: &str,
        recipient: &PaymentAddress,
        payment: &WalletPayment,
    ) -> Result<(), String> {
        (self.before_phase)("before_proved_payment_encrypted_journal_write")?;
        let original = self
            .retained
            .payments
            .iter_mut()
            .find(|old| old.kind == kind)
            .ok_or("proved business payment has no original reservation")?;
        let reservation = original
            .reservation
            .as_ref()
            .ok_or("original payment reservation did not complete")?;
        if original.persisted
            || original.record != payment.transaction.record
            || original.recipient != canonical_address(recipient)
            || original.opening.expose_encapsulation_coins()
                != payment.payment_opening().expose_encapsulation_coins()
            || reservation.id() != payment.transaction.record.statement_id(&self.network)
        {
            return Err("proved payment differs from original reserved material".into());
        }
        self.payer
            .store_wallet_payment(reservation, payment, recipient)?;
        self.payer
            .verified_payment_opening(reservation.id())
            .map(drop)?;
        if self.payer.payment_status(reservation.id())? != PaymentStatus::Prepared {
            return Err("encrypted payment journal did not retain prepared status".into());
        }
        original.persisted = true;
        Ok(())
    }
    fn protect_issuance(
        &mut self,
        recipient: &PaymentAddress,
        issuance: &WalletIssuance,
    ) -> Result<(), String> {
        (self.before_phase)("before_issuance_memory_retention")?;
        if self.retained.issuance.is_some()
            || issuance.record.signed.declaration.network != self.network
        {
            return Err("unexpected repeated or foreign issuance opening".into());
        }
        issuance.record.validate_shape()?;
        let mut openings = Vec::with_capacity(crate::issuance::INITIAL_NOTES);
        for index in 0..crate::issuance::INITIAL_NOTES {
            let opening = issuance
                .payment_opening(index)
                .ok_or("issuance original opening is absent")?;
            let bytes: &[u8; crate::issuance::CIPHERTEXT_BYTES] = issuance.record.ciphertexts
                [index]
                .as_slice()
                .try_into()
                .map_err(|_| "issuance ciphertext width differs")?;
            let mut note = opening
                .verify_payment(
                    recipient,
                    &issuance.record.signed.declaration.note_commitments[index],
                    &decode_payment(bytes),
                    &EncryptionContext::new(self.network),
                )
                .map_err(|_| "issuance original opening does not authenticate recipient")?;
            let matches = Hasher::new().note_cm(&note)
                == issuance.record.signed.declaration.note_commitments[index];
            super::erase_note(&mut note);
            if !matches {
                return Err("issuance original opening commitment differs".into());
            }
            openings.push(copy_opening(opening));
        }
        let openings = openings
            .try_into()
            .map_err(|_| "issuance opening count differs")?;
        self.retained.issuance = Some(RetainedIssuance {
            _binding: issuance.record.signed.declaration.binding(),
            _record_sha256: Sha256::digest(issuance.record.encode()?).into(),
            _recipient: canonical_address(recipient),
            _openings: openings,
        });
        Ok(())
    }
    fn protect_reward(&mut self, block: &ProducedBlock) -> Result<(), String> {
        (self.before_phase)("before_reward_memory_retention")?;
        if self.retained.rewards.len() >= REWARD_LIMIT
            || block.header.network != self.network
            || block.body.network != self.network
            || block.header.height != block.body.height
            || block.reward_secret.len() > REWARD_BYTES_LIMIT
        {
            return Err("reward opening context or retention bound differs".into());
        }
        crate::producer::validate_reward_material(
            self.network,
            block.body.height,
            block.body.reward_mode,
            &block.body.rewards,
            &block.reward_secret,
        )?;
        self.retained.rewards.push(RetainedReward {
            _header_id: block.header.id().map_err(|_| "reward header invalid")?,
            _secret: Zeroizing::new(block.reward_secret.to_vec()),
        });
        Ok(())
    }
    fn sign_issuance(
        &mut self,
        message: &[u8],
    ) -> Result<[u8; native::issuance::ISSUER_SIGNATURE_BYTES], String> {
        (self.before_phase)("before_independent_issuer_signature")?;
        (self.issuer_signer)(ISSUER_SIGNATURE_CONTEXT, message)
    }
}

/// Explicit restart inspection, not a native-chain acceptance API. Call only
/// after the original payer session has been dropped and its lock released.
/// The owner independently supplies the exact intended statement IDs; no
/// discovery of arbitrary journal entries or release of reservations occurs.
/// Reserved/incomplete, missing or non-Prepared entries cause failure.
pub fn inspect_prepared_recovery(
    specification: ExistingVault<'_>,
    network: Hash,
    expected_ids: &[Hash],
    before_phase: &mut impl FnMut(&str) -> Result<(), String>,
) -> Result<usize, String> {
    owner_only()?;
    if expected_ids.is_empty()
        || expected_ids.len() > PAYMENT_LIMIT
        || expected_ids.iter().copied().collect::<BTreeSet<_>>().len() != expected_ids.len()
    {
        return Err("recovery requires distinct independently expected payment IDs".into());
    }
    canonical(specification.directory)?;
    before_phase("before_existing_payer_vault_recovery_open")?;
    let vault = WalletVault::open(specification.directory, network, specification.passphrase)?;
    if vault.account() != specification.expected_account
        || canonical_address(&vault.wallet()?.address())
            != canonical_address(specification.expected_address)
    {
        return Err("recovery actor differs from independent custody input".into());
    }
    for id in expected_ids {
        before_phase("before_prepared_packet_recovery_validation")?;
        if vault.payment_status(*id)? != PaymentStatus::Prepared {
            return Err("recovery payment is not an exact prepared packet".into());
        }
        let packet = vault.payment_packet(*id)?;
        if packet.transaction()?.record.statement_id(&network) != *id {
            return Err("recovered payment statement identity differs".into());
        }
        packet
            .sidecar()?
            .check_opening(&packet.transaction()?.record, &network)?;
        vault.verified_payment_opening(*id).map(drop)?;
    }
    Ok(expected_ids.len())
}
fn copy_opening(opening: &PaymentEncryptionOpening) -> PaymentEncryptionOpening {
    PaymentEncryptionOpening::from_encapsulation_coins(*opening.expose_encapsulation_coins())
}
fn decode_payment(bytes: &[u8; crate::issuance::CIPHERTEXT_BYTES]) -> PaymentCiphertext {
    PaymentCiphertext {
        kem_ciphertext: bytes[..1088].try_into().expect("fixed issuance KEM width"),
        body: bytes[1088..1296]
            .try_into()
            .expect("fixed issuance body width"),
        tag: bytes[1296..1312]
            .try_into()
            .expect("fixed issuance tag width"),
        view_tag: bytes[1312],
    }
}
fn canonical(path: &Path) -> Result<std::path::PathBuf, String> {
    let canonical = fs::canonicalize(path).map_err(|_| "custody root is not accessible")?;
    if !path.is_absolute() || canonical != path || !canonical.is_dir() {
        return Err("custody requires exact existing canonical directory paths".into());
    }
    Ok(canonical)
}
fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}
fn owner_only() -> Result<(), String> {
    if std::env::var_os("CI").is_some() || std::env::var_os("GITHUB_ACTIONS").is_some() {
        Err("actor custody requires owner-local execution".into())
    } else {
        Ok(())
    }
}
