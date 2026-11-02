//! Worker-owned wallet material. Only recovery display and ciphertext/public
//! results cross the browser worker boundary. No networking exists in this crate.
use core::{
    address, hex,
    identity::Identity,
    network,
    vault::{self, Material},
};
use serde_json::json;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn js(error: String) -> JsValue {
    JsValue::from_str(&error)
}

#[wasm_bindgen]
pub struct BrowserWallet {
    material: Material,
    challenge: Option<[usize; 3]>,
}
#[wasm_bindgen]
impl BrowserWallet {
    pub fn create(network_id: &str, account: u32) -> Result<BrowserWallet, JsValue> {
        Ok(Self {
            material: Material::generate(network(network_id).map_err(js)?, account).map_err(js)?,
            challenge: Some(vault::challenge().map_err(js)?),
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
