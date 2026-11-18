//! Create-only isolated actor vaults using the unchanged encrypted wallet format.
//! This capability does not confirm an owner mnemonic backup or accept entropy.
use super::{RecoveryMaterial, UnlockedWallet, WalletVault, create};
use crate::{eng2_governance::canonical_address, wire::Hash};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{fs, os::unix::fs::MetadataExt, path::Path};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    version: u32,
    campaign_id: String,
    network: String,
    prior_network: String,
    genesis_parameters_sha256: String,
}
/// Independently pinned public inputs selected before sealing the new genesis.
/// The caller must authenticate the referenced genesis parameter bytes as well.
#[derive(Clone)]
pub struct RehearsalBinding {
    bytes: Vec<u8>,
    digest: Hash,
    campaign: Hash,
    network: Hash,
    genesis_parameters: Hash,
}
fn digest(text: String) -> Result<Hash, String> {
    crate::eng2_operations::public_bytes(&Value::String(text), 32)?
        .try_into()
        .map_err(|_| "isolated initialization digest width differs".into())
}
impl RehearsalBinding {
    pub fn decode(bytes: &[u8], expected_sha256: Hash) -> Result<Self, String> {
        if bytes.is_empty()
            || bytes.len() > 4096
            || expected_sha256 == [0; 32]
            || Sha256::digest(bytes).as_slice() != expected_sha256
        {
            return Err("isolated initialization public pin differs".into());
        }
        let parameters: Parameters = serde_json::from_slice(bytes)
            .map_err(|_| "isolated initialization public schema rejected")?;
        let network = digest(parameters.network)?;
        let prior = digest(parameters.prior_network)?;
        let campaign = digest(parameters.campaign_id)?;
        let genesis_parameters = digest(parameters.genesis_parameters_sha256)?;
        if parameters.version != 1
            || network == [0; 32]
            || prior == [0; 32]
            || network == prior
            || campaign == [0; 32]
            || genesis_parameters == [0; 32]
        {
            return Err(
                "isolated initialization requires distinct new network and public pins".into(),
            );
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            digest: expected_sha256,
            campaign,
            network,
            genesis_parameters,
        })
    }
    pub fn network(&self) -> Hash {
        self.network
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn receipt(&self) -> Value {
        json!({"version":1,"campaign_id":crate::local::hex(&self.campaign),
            "network":crate::local::hex(&self.network),
            "initialization_parameters_sha256":crate::local::hex(&self.digest),
            "genesis_parameters_sha256":crate::local::hex(&self.genesis_parameters),
            "isolated_rehearsal":true,"genesis_sealed":false})
    }
    fn actor_record(&self, role: ActorRole, vault: &UnlockedWallet) -> Result<Vec<u8>, String> {
        let mut record = self.receipt();
        record["role"] = json!(role.name());
        record["account"] = json!(0);
        record["address_hex"] = json!(crate::local::hex(&canonical_address(
            &vault.wallet()?.address()
        )));
        record["encrypted_vault_format"] = json!("SWNVLT01");
        record["recovery_backup_verified"] = json!(false);
        serde_json::to_vec(&record)
            .map_err(|_| "isolated actor public binding encoding failed".into())
    }
}
#[derive(Clone, Copy)]
pub enum ActorRole {
    Payer,
    Recipient,
    FeeDestination,
    FundDestination,
    Reward,
}
impl ActorRole {
    pub fn name(self) -> &'static str {
        match self {
            Self::Payer => "payer",
            Self::Recipient => "recipient",
            Self::FeeDestination => "fee_destination",
            Self::FundDestination => "fund_destination",
            Self::Reward => "reward",
        }
    }
}
/// Check only the selected new path. Existing identity roots remain untouched.
pub(crate) fn new_private_path(path: &Path) -> Result<(), String> {
    let absent = matches!(fs::symlink_metadata(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound);
    if !path.is_absolute() || path.file_name().is_some_and(|name| name == ".git") || !absent {
        return Err("isolated custody requires an absent absolute path".into());
    }
    let parent = path.parent().ok_or("isolated custody parent missing")?;
    if parent.canonicalize().ok().as_deref() != Some(parent) {
        return Err("isolated custody parent must be canonical".into());
    }
    let metadata =
        fs::symlink_metadata(parent).map_err(|_| "isolated custody parent unavailable")?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
        || path
            .ancestors()
            .any(|part| fs::symlink_metadata(part.join(".git")).is_ok())
    {
        return Err("isolated custody requires an owner-private nonrepository parent".into());
    }
    Ok(())
}
impl WalletVault {
    /// New OS entropy, existing encryption/journal, public binding, then reopen.
    /// No mnemonic is displayed or automatically acknowledged. No retry occurs.
    pub fn create_isolated_rehearsal(
        directory: &Path,
        passphrase: &str,
        binding: &RehearsalBinding,
        role: ActorRole,
    ) -> Result<UnlockedWallet, String> {
        new_private_path(directory)?;
        if !(12..=super::MAX_PASSWORD_BYTES).contains(&passphrase.len()) {
            return Err("isolated actor passphrase bound rejected".into());
        }
        let mut entropy = Zeroizing::new([0; 32]);
        getrandom::fill(entropy.as_mut()).map_err(|_| "OS randomness unavailable")?;
        let vault = create(
            RecoveryMaterial {
                network: binding.network,
                account: 0,
                entropy,
            },
            directory,
            passphrase,
        )?;
        let record = binding.actor_record(role, &vault)?;
        vault._owner.write_rehearsal_binding(&record)?;
        drop(vault);
        Self::open_isolated_rehearsal(directory, passphrase, binding, role)
    }
    /// Reopen the actual encrypted vault and authenticate the exact public role.
    pub fn open_isolated_rehearsal(
        directory: &Path,
        passphrase: &str,
        binding: &RehearsalBinding,
        role: ActorRole,
    ) -> Result<UnlockedWallet, String> {
        let vault = Self::open(directory, binding.network, passphrase)?;
        if vault.account() != 0
            || vault._owner.read_rehearsal_binding()? != binding.actor_record(role, &vault)?
        {
            return Err("isolated actor public role or campaign differs".into());
        }
        Ok(vault)
    }
    pub fn isolated_rehearsal_receipt(
        vault: &UnlockedWallet,
        binding: &RehearsalBinding,
        role: ActorRole,
    ) -> Result<Value, String> {
        let record = binding.actor_record(role, vault)?;
        if vault.network() != binding.network
            || vault.account() != 0
            || vault._owner.read_rehearsal_binding()? != record
        {
            return Err("isolated actor public receipt differs from authenticated custody".into());
        }
        serde_json::from_slice(&record).map_err(|_| "isolated actor receipt decoding failed".into())
    }
}

#[cfg(test)]
mod tests;
