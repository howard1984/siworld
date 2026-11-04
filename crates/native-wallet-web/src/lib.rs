//! Worker-owned wallet material. Only recovery display and ciphertext/public
//! results cross the browser worker boundary. No networking exists in this crate.
use serde_json::json;
use wallet_core::{
    address, hex,
    identity::Identity,
    network,
    vault::{self, Material},
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

#[cfg(all(target_arch = "wasm32", feature = "wasm-parallel"))]
pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen]
pub fn prover_threads() -> usize {
    #[cfg(feature = "wasm-parallel")]
    {
        rayon::current_num_threads()
    }
    #[cfg(not(feature = "wasm-parallel"))]
    {
        1
    }
}

fn js(error: String) -> JsValue {
    JsValue::from_str(&error)
}

fn history_config(rules_hex: &str, genesis: &str) -> Result<engine::state::Config, JsValue> {
    let rules =
        wallet_core::hex_array::<{ engine::state::CONFIG_RULE_BYTES }>(rules_hex).map_err(js)?;
    let config = engine::state::Config::decode_rules(&rules).map_err(js)?;
    if hex(&config.genesis_id()) != genesis || config.fixture && !cfg!(feature = "browser-fixtures")
    {
        return Err(js(
            "Pinned engineering history configuration differs.".into()
        ));
    }
    Ok(config)
}

/// Public tree context only. Adjacent authentication bytes are dropped after append.
#[wasm_bindgen]
pub struct BrowserCommitmentTree {
    history: engine::history::CommitmentHistory,
}

#[wasm_bindgen]
impl BrowserCommitmentTree {
    pub fn create(rules_hex: &str, genesis: &str) -> Result<Self, JsValue> {
        Ok(Self {
            history: engine::history::CommitmentHistory::new(history_config(rules_hex, genesis)?)
                .map_err(js)?,
        })
    }

    pub fn restore(
        rules_hex: &str,
        genesis: &str,
        anchor: &BrowserWallet,
        encrypted: &[u8],
    ) -> Result<Self, JsValue> {
        let config = history_config(rules_hex, genesis)?;
        if anchor.challenge.is_some() || anchor.material.network != config.network {
            return Err(js(
                "Confirm the recovery backup on the same network first.".into()
            ));
        }
        let plain = Zeroizing::new(anchor.open_local(encrypted)?);
        Ok(Self {
            history: engine::history::CommitmentHistory::open_local(config, &plain).map_err(js)?,
        })
    }

    pub fn fork(&self) -> Self {
        Self {
            history: engine::history::CommitmentHistory {
                state: self.history.state.clone(),
            },
        }
    }

    pub fn summary(&self) -> String {
        let s = &self.history.state;
        json!({"height":s.height,"tip":hex(&s.tip),"output_count":s.tree.count}).to_string()
    }

    pub fn append(&mut self, bytes: &[u8]) -> Result<String, JsValue> {
        let block = engine::commitment::CommitmentBlock::decode(bytes).map_err(js)?;
        self.history.append(&block).map_err(js)?;
        Ok(json!({"height":block.height,"tip":hex(&block.id),
            "output_count":self.history.state.tree.count,
            "authentication_ciphertext_bytes":block.authentication_ciphertext_bytes})
        .to_string())
    }

    pub fn check_head(&self, height: &str, tip: &str, previous: &Self) -> Result<(), JsValue> {
        let s = &self.history.state;
        let prior = &previous.history.state;
        if s.config != prior.config
            || s.height.to_string() != height
            || hex(&s.tip) != tip
            || s.tip != prior.tip && s.cumulative_work <= prior.cumulative_work
        {
            return Err(js(
                "Historical candidate lacks the announced head or greater work.".into(),
            ));
        }
        Ok(())
    }

    pub fn sealed_cache(&self, anchor: &BrowserWallet) -> Result<Vec<u8>, JsValue> {
        if anchor.challenge.is_some()
            || anchor.material.network != self.history.state.config.network
        {
            return Err(js(
                "Confirm the recovery backup on the same network first.".into()
            ));
        }
        let plain = Zeroizing::new(self.history.cache().map_err(js)?);
        anchor.protect_local(&plain)
    }
}

#[wasm_bindgen]
pub struct BrowserWallet {
    material: Material,
    challenge: Option<[usize; 3]>,
    light: Option<engine::light::LightWallet>,
    candidate: Option<engine::light::LightWallet>,
}
#[wasm_bindgen]
impl BrowserWallet {
    pub fn create(network_id: &str, account: u32) -> Result<BrowserWallet, JsValue> {
        Ok(Self {
            material: Material::generate(network(network_id).map_err(js)?, account).map_err(js)?,
            challenge: Some(vault::challenge().map_err(js)?),
            light: None,
            candidate: None,
        })
    }
    pub fn restore(
        network_id: &str,
        account: u32,
        words: String,
    ) -> Result<BrowserWallet, JsValue> {
        Ok(Self {
            material: Material::restore(
                network(network_id).map_err(js)?,
                account,
                Zeroizing::new(words),
            )
            .map_err(js)?,
            challenge: None,
            light: None,
            candidate: None,
        })
    }
    pub fn unlock(
        network_id: &str,
        bytes: &[u8],
        password: String,
    ) -> Result<BrowserWallet, JsValue> {
        let password = Zeroizing::new(password);
        Ok(Self {
            material: Material::open(bytes, &password, network(network_id).map_err(js)?)
                .map_err(js)?,
            challenge: None,
            light: None,
            candidate: None,
        })
    }
    pub fn recovery_words(&self) -> Result<String, JsValue> {
        if self.challenge.is_none() {
            return Err(js(
                "Recovery display is available only during new-wallet backup.".into(),
            ));
        }
        Ok(self.material.words().to_string())
    }
    pub fn backup_positions(&self) -> Vec<u32> {
        self.challenge
            .map(|c| c.map(|i| i as u32).to_vec())
            .unwrap_or_default()
    }
    pub fn seal(&mut self, password: String, answers: String) -> Result<Vec<u8>, JsValue> {
        let password = Zeroizing::new(password);
        let answers = Zeroizing::new(answers);
        if let Some(positions) = self.challenge {
            let words = self.material.words();
            let answers: Vec<&str> = answers.split(' ').collect();
            if answers.len() != 3
                || positions
                    .iter()
                    .zip(&answers)
                    .any(|(p, a)| words.split(' ').nth(p - 1) != Some(*a))
            {
                return Err(js(
                    "Backup answers do not match. No wallet was saved.".into()
                ));
            }
        }
        let encrypted = self.material.seal(&password).map_err(js)?;
        // Authenticate before returning data for persistence.
        Material::open(&encrypted, &password, self.material.network).map_err(js)?;
        self.challenge = None;
        Ok(encrypted)
    }
    pub fn public_info(&self) -> Result<String, JsValue> {
        if self.challenge.is_some() {
            return Err(js(
                "Confirm the recovery backup before using this wallet.".into()
            ));
        }
        let identity = Identity::derive(
            &self.material.entropy,
            self.material.network,
            self.material.account,
        )
        .map_err(js)?;
        let addr = identity.address();
        Ok(json!({"version":1, "network":hex(&self.material.network), "account":self.material.account,
            "descriptor":address::Descriptor::new(self.material.network,self.material.account,addr),
            "full_address":address::full(self.material.network,addr).map_err(js)?,
            "short_address":address::short(self.material.network,addr).map_err(js)?,
            "balance_status":"unavailable", "send_available":false }).to_string())
    }

    /// Derive another account without returning recovery material to JavaScript.
    pub fn derive_account(&self, account: u32) -> Result<BrowserWallet, JsValue> {
        if self.challenge.is_some() {
            return Err(js(
                "Confirm the recovery backup before adding an account.".into()
            ));
        }
        Ok(Self {
            material: Material {
                network: self.material.network,
                account,
                entropy: Zeroizing::new(*self.material.entropy),
            },
            challenge: None,
            light: None,
            candidate: None,
        })
    }

    /// Private local display records; never forward these results to a server.
    pub fn light_history(&self) -> Result<String, JsValue> {
        let light = self
            .light
            .as_ref()
            .ok_or_else(|| js("Light sync is not initialized.".into()))?;
        Ok(serde_json::Value::Array(
            light
                .wallet
                .receipts()
                .iter()
                .filter(|receipt| {
                    receipt.note().value > 0
                        && receipt.output_index != 1
                        && receipt.output_index != 2
                })
                .map(|receipt| {
                    json!({
                        "id":hex(&receipt.commitment), "block_id":hex(&receipt.block_id),
                        "height":receipt.height, "asset":hex(&receipt.note().asset_id.0),
                        "amount_atoms":receipt.note().value.to_string(),
                        "unlock_height":receipt.note().unlock_height,
                        "spent":receipt.spent,
                        "kind":if receipt.output_index == 0 { "received" }
                            else if receipt.output_index < 8 { "mining" } else { "allocation" },
                    })
                })
                .collect(),
        )
        .to_string())
    }

    pub fn enable_light(&mut self, rules_hex: &str, genesis: &str) -> Result<String, JsValue> {
        if self.challenge.is_some() {
            return Err(js("Confirm your recovery backup first.".into()));
        }
        let rules = wallet_core::hex_array::<{ engine::state::CONFIG_RULE_BYTES }>(rules_hex)
            .map_err(js)?;
        let config = engine::state::Config::decode_rules(&rules).map_err(js)?;
        if config.network != self.material.network || hex(&config.genesis_id()) != genesis {
            return Err(js(
                "Pinned engineering genesis or wallet network differs.".into()
            ));
        }
        if config.fixture && !cfg!(feature = "browser-fixtures") {
            return Err(js(
                "Synthetic fixture networks are disabled in this build.".into()
            ));
        }
        self.light = Some(
            engine::light::LightWallet::new(
                config,
                Zeroizing::new(*self.material.entropy),
                self.material.account,
            )
            .map_err(js)?,
        );
        self.light_balance()
    }
    pub fn begin_candidate(&mut self) -> Result<(), JsValue> {
        let config = self
            .light
            .as_ref()
            .ok_or_else(|| js("Light sync is not initialized.".into()))?
            .state
            .config
            .clone();
        self.candidate = Some(
            engine::light::LightWallet::new(
                config,
                Zeroizing::new(*self.material.entropy),
                self.material.account,
            )
            .map_err(js)?,
        );
        Ok(())
    }
    pub fn begin_extension(&mut self) -> Result<(), JsValue> {
        self.candidate = Some(
            self.light
                .as_ref()
                .ok_or_else(|| js("Light sync is not initialized.".into()))?
                .fork(
                    Zeroizing::new(*self.material.entropy),
                    self.material.account,
                )
                .map_err(js)?,
        );
        Ok(())
    }
    /// Begin scanning after a locally verified birthday tree, without older decryption.
    pub fn begin_after_history(&mut self, tree: &BrowserCommitmentTree) -> Result<(), JsValue> {
        self.begin_candidate()?;
        let result = self
            .candidate
            .as_mut()
            .unwrap()
            .adopt_history(&tree.history)
            .map_err(js);
        if result.is_err() {
            self.candidate = None;
        }
        result
    }
    pub fn candidate_balance(&self) -> Result<String, JsValue> {
        self.candidate
            .as_ref()
            .ok_or_else(|| js("No synchronization candidate.".into()))?
            .balance_json()
            .map_err(js)
    }
    pub fn check_candidate(&self, height: &str, tip: &str) -> Result<(), JsValue> {
        let c = self
            .candidate
            .as_ref()
            .ok_or_else(|| js("No synchronization candidate.".into()))?;
        let accepted = self
            .light
            .as_ref()
            .ok_or_else(|| js("Light sync is not initialized.".into()))?;
        if c.state.height.to_string() != height || hex(&c.state.tip) != tip {
            return Err(js("Candidate does not reach the announced tip.".into()));
        }
        if c.state.tip != accepted.state.tip
            && c.state.cumulative_work <= accepted.state.cumulative_work
        {
            return Err(js(
                "Candidate has no greater verified cumulative work.".into()
            ));
        }
        Ok(())
    }
    pub fn commit_candidate(&mut self, height: &str, tip: &str) -> Result<String, JsValue> {
        self.check_candidate(height, tip)?;
        let mut candidate = self.candidate.take().unwrap();
        if let Some(previous) = &mut self.light {
            candidate.retain_prover(previous);
        }
        self.light = Some(candidate);
        self.light_balance()
    }
    pub fn abort_candidate(&mut self) {
        self.candidate = None;
    }
    pub fn append_compact(&mut self, bytes: &[u8]) -> Result<String, JsValue> {
        let compact = engine::compact::CompactBlock::decode(bytes).map_err(js)?;
        self.candidate
            .as_mut()
            .ok_or_else(|| js("No synchronization candidate.".into()))?
            .append(&compact)
            .map_err(js)?;
        let mut summary: serde_json::Value = serde_json::from_str(&self.candidate_balance()?)
            .map_err(|_| js("Cannot encode candidate balance.".into()))?;
        summary["observed_statements"] = json!(
            compact
                .block
                .transactions
                .iter()
                .map(|tx| hex(&tx.record.statement_id(&compact.block.network)))
                .collect::<Vec<_>>()
        );
        summary["block_timestamp"] = json!(compact.block.timestamp);
        summary["owned_receipts"] = json!(
            self.candidate
                .as_ref()
                .unwrap()
                .wallet
                .receipts()
                .iter()
                .any(|receipt| receipt.height == compact.block.height && receipt.note().value > 0)
        );
        Ok(summary.to_string())
    }
    pub fn light_balance(&self) -> Result<String, JsValue> {
        self.light
            .as_ref()
            .ok_or_else(|| js("Light sync is not initialized.".into()))?
            .balance_json()
            .map_err(js)
    }
    pub fn prepare_sip(
        &mut self,
        recipient: &str,
        resolved: &str,
        amount: &str,
        priority: bool,
        reserved_json: &str,
    ) -> Result<String, JsValue> {
        let bytes = address::resolve(
            recipient,
            self.material.network,
            (!resolved.is_empty()).then_some(resolved),
        )
        .map_err(js)?;
        let owner = native::codec::decode_digest(bytes[..48].try_into().unwrap())
            .map_err(|_| js("Invalid recipient owner.".into()))?;
        let recipient =
            native::encryption::PaymentAddress::new(owner, bytes[48..].try_into().unwrap())
                .map_err(|_| js("Invalid recipient key.".into()))?;
        if reserved_json.len() > 20000 {
            return Err(js("Reservation list exceeds limit.".into()));
        }
        let values: Vec<String> = serde_json::from_str(reserved_json)
            .map_err(|_| js("Invalid reservation journal.".into()))?;
        if values.len() > 128 {
            return Err(js("Reservation count limit.".into()));
        }
        let reserved = values
            .iter()
            .map(|s| wallet_core::hex_array::<48>(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(js)?;
        self.light
            .as_mut()
            .ok_or_else(|| js("Light sync is not initialized.".into()))?
            .prepare(
                &recipient,
                amount
                    .parse()
                    .map_err(|_| js("Use an integer atom amount.".into()))?,
                priority,
                &reserved,
            )
            .map_err(js)
    }
    pub fn prove_sip(&mut self) -> Result<Vec<u8>, JsValue> {
        let (mut envelope, sidecar) = self
            .light
            .as_mut()
            .ok_or_else(|| js("Light sync is not initialized.".into()))?
            .prove()
            .map_err(js)?;
        envelope.extend_from_slice(&sidecar);
        Ok(envelope)
    }
    pub fn cancel_prepared(&mut self) {
        if let Some(light) = &mut self.light {
            light.clear_prepared();
        }
    }

    /// Domain-separated local journal encryption; the key never crosses the worker.
    pub fn protect_local(&self, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        use chacha20poly1305::{
            Key, XChaCha20Poly1305, XNonce,
            aead::{AeadInOut, KeyInit},
        };
        if data.len() > 2_000_000 {
            return Err(js("Local journal byte limit.".into()));
        }
        let key = self.local_key();
        let cipher = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).unwrap());
        let mut out = b"SWNLOC01".to_vec();
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| js("Secure randomness unavailable.".into()))?;
        out.extend_from_slice(&nonce);
        let mut plain = Zeroizing::new(data.to_vec());
        let tag = cipher
            .encrypt_inout_detached(
                <&XNonce>::try_from(&nonce[..]).unwrap(),
                &self.material.network,
                plain.as_mut_slice().into(),
            )
            .map_err(|_| js("Journal encryption failed.".into()))?;
        out.extend_from_slice(&plain);
        out.extend_from_slice(&tag);
        Ok(out)
    }
    pub fn open_local(&self, bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        use chacha20poly1305::{
            Key, Tag, XChaCha20Poly1305, XNonce,
            aead::{AeadInOut, KeyInit},
        };
        if bytes.len() < 48 || bytes.len() > 2_000_048 || &bytes[..8] != b"SWNLOC01" {
            return Err(js("Invalid local encrypted journal.".into()));
        }
        let key = self.local_key();
        let cipher = XChaCha20Poly1305::new(<&Key>::try_from(key.as_ref()).unwrap());
        let end = bytes.len() - 16;
        let mut plain = Zeroizing::new(bytes[32..end].to_vec());
        cipher
            .decrypt_inout_detached(
                <&XNonce>::try_from(&bytes[8..32]).unwrap(),
                &self.material.network,
                plain.as_mut_slice().into(),
                <&Tag>::try_from(&bytes[end..]).unwrap(),
            )
            .map_err(|_| js("Journal authentication failed.".into()))?;
        Ok(plain.to_vec())
    }
}

impl BrowserWallet {
    fn local_key(&self) -> Zeroizing<[u8; 32]> {
        let mut h = blake3::Hasher::new_derive_key("siworld browser local journal key v1");
        h.update(self.material.entropy.as_ref());
        h.update(&self.material.network);
        h.update(&self.material.account.to_le_bytes());
        Zeroizing::new(*h.finalize().as_bytes())
    }
}

#[wasm_bindgen]
pub fn inspect_address(
    text: &str,
    network_id: &str,
    resolved_full: &str,
) -> Result<String, JsValue> {
    let network = network(network_id).map_err(js)?;
    let addr = address::resolve(
        text,
        network,
        (!resolved_full.is_empty()).then_some(resolved_full),
    )
    .map_err(js)?;
    Ok(json!({"full_address":address::full(network,&addr).map_err(js)?,"short_address":address::short(network,&addr).map_err(js)?,"address_hex":hex(&addr),"network":hex(&network)}).to_string())
}

#[wasm_bindgen]
pub fn seal_content(
    network_id: &str,
    account: u32,
    created_at: &str,
    kind: u8,
    title: String,
    secret: String,
    passphrase: String,
) -> Result<Vec<u8>, JsValue> {
    let password = Zeroizing::new(passphrase);
    let content = wallet_core::content_vault::Content {
        network: network(network_id).map_err(js)?,
        account,
        created_at: created_at
            .parse()
            .map_err(|_| js("Invalid content timestamp.".into()))?,
        kind,
        title: Zeroizing::new(title),
        secret: Zeroizing::new(secret),
    };
    let bytes = wallet_core::content_vault::seal(&content, &password).map_err(js)?;
    let checked = wallet_core::content_vault::open(&bytes, &password, content.network, account)
        .map_err(js)?;
    if checked.title != content.title
        || checked.secret != content.secret
        || checked.kind != kind
        || checked.created_at != content.created_at
    {
        return Err(js("Content encryption verification failed.".into()));
    }
    Ok(bytes)
}

#[wasm_bindgen]
pub fn open_content(
    network_id: &str,
    account: u32,
    bytes: &[u8],
    passphrase: String,
) -> Result<String, JsValue> {
    let password = Zeroizing::new(passphrase);
    let content = wallet_core::content_vault::open(
        bytes,
        &password,
        network(network_id).map_err(js)?,
        account,
    )
    .map_err(js)?;
    Ok(
        json!({"title":content.title.as_str(),"secret":content.secret.as_str(),
        "kind":content.kind,"created_at":content.created_at.to_string()})
        .to_string(),
    )
}

/// Linear memory never shrinks; sample after the operation as a WASM high-water mark.
#[wasm_bindgen]
pub fn linear_memory_bytes() -> usize {
    #[cfg(target_arch = "wasm32")]
    {
        std::arch::wasm32::memory_size::<0>() * 65536
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0
    }
}

#[wasm_bindgen]
pub struct BrowserVault {
    account: wallet_core::cloud_vault::Account,
}
#[wasm_bindgen]
impl BrowserVault {
    pub fn create() -> Result<BrowserVault, JsValue> {
        Ok(Self {
            account: wallet_core::cloud_vault::Account::create().map_err(js)?,
        })
    }
    pub fn restore(bytes: &[u8], password: String) -> Result<BrowserVault, JsValue> {
        let password = Zeroizing::new(password);
        Ok(Self {
            account: wallet_core::cloud_vault::Account::restore(bytes, &password).map_err(js)?,
        })
    }
    pub fn public_info(&self) -> String {
        json!({"locator":hex(&self.account.locator()),"public_key":hex(&self.account.public_key()),"revision":self.account.revision.to_string(),"digest":hex(&self.account.digest)}).to_string()
    }
    pub fn recovery(&self, password: String) -> Result<Vec<u8>, JsValue> {
        let password = Zeroizing::new(password);
        self.account.recovery(&password).map_err(js)
    }
    pub fn snapshot(&self, packages: String, password: String) -> Result<Vec<u8>, JsValue> {
        let password = Zeroizing::new(password);
        let packages = Zeroizing::new(packages);
        if packages.len() > 900000 {
            return Err(js("Vault collection exceeds limit.".into()));
        }
        let rows: Vec<String> =
            serde_json::from_str(&packages).map_err(|_| js("Invalid binary collection.".into()))?;
        if rows.len() > 100 {
            return Err(js("Vault package count limit.".into()));
        }
        let decoded = rows
            .iter()
            .map(|s| wallet_core::hex_array::<4196>(s).map(|a| a.to_vec()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(js)?;
        self.account.snapshot(&decoded, &password).map_err(js)
    }
    pub fn open_snapshot(
        &self,
        bytes: &[u8],
        password: String,
        revision: &str,
        previous: &str,
        signature: &str,
    ) -> Result<String, JsValue> {
        let password = Zeroizing::new(password);
        let revision = revision
            .parse()
            .map_err(|_| js("Invalid Vault revision.".into()))?;
        let previous = wallet_core::hex_array::<32>(previous).map_err(js)?;
        let signature = wallet_core::hex_array::<64>(signature).map_err(js)?;
        self.account
            .verify_revision(
                revision,
                &wallet_core::cloud_vault::digest(bytes),
                &previous,
                &signature,
            )
            .map_err(js)?;
        let rows = self
            .account
            .read_snapshot(bytes, &password, revision, previous)
            .map_err(js)?;
        Ok(json!(rows.iter().map(|b| hex(b)).collect::<Vec<_>>()).to_string())
    }
    pub fn accept(&mut self, revision: &str, digest: &str) -> Result<(), JsValue> {
        self.account
            .accept(
                revision
                    .parse()
                    .map_err(|_| js("Invalid Vault revision.".into()))?,
                wallet_core::hex_array(digest).map_err(js)?,
            )
            .map_err(js)
    }
    pub fn sign_request(
        &self,
        origin: &str,
        method: &str,
        challenge: &str,
        revision: &str,
        body: &[u8],
        previous: &str,
    ) -> Result<String, JsValue> {
        Ok(hex(&self
            .account
            .sign_request(
                origin,
                method,
                challenge,
                revision
                    .parse()
                    .map_err(|_| js("Invalid Vault revision.".into()))?,
                body,
                previous,
            )
            .map_err(js)?))
    }
    pub fn sign_revision(
        &self,
        revision: &str,
        body: &[u8],
        previous: &str,
    ) -> Result<String, JsValue> {
        Ok(hex(&self.account.sign_revision(
            revision
                .parse()
                .map_err(|_| js("Invalid Vault revision.".into()))?,
            &wallet_core::cloud_vault::digest(body),
            &wallet_core::hex_array(previous).map_err(js)?,
        )))
    }
}
