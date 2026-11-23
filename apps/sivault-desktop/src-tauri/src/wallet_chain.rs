use crate::wallet::WalletScope;
use crate::wallet_endpoint::Head;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sivault_core::crypto;
use siworld_native_wallet_core::{
    hex, hex_array,
    recipient::{Descriptor, Network, ShortAddress, V2_LEN},
    vault::Material,
};
use siworld_native_wallet_engine::{
    eng2_light::Eng2LightState,
    state::base_fee,
    wallet_generation::{Binding, MAX_MANIFEST_BYTES, Manifest},
    wire::{MAX_ENVELOPE_BYTES, SIDECAR_BYTES},
};
use std::{
    fs::File,
    io::{Read, Write},
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const MAX_DEV_HEIGHT: u64 = 128;
type ScanResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub height: u64,
    pub available_atoms: String,
    pub locked_atoms: String,
    pub history: Vec<HistoryRow>,
    pub payment: Option<PaymentStatus>,
    pub standard_fee_atoms: String,
}

#[derive(Deserialize, Serialize)]
pub struct HistoryRow {
    pub id: String,
    pub height: u64,
    pub amount_atoms: String,
    pub kind: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    pub address: String,
    pub descriptor: String,
    pub amount: u64,
    pub fee: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentStatus {
    pub statement_id: String,
    pub amount_atoms: String,
    pub fee_atoms: String,
    pub height: Option<u64>,
    pub acknowledged: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    public: PaymentStatus,
    packet: Vec<u8>,
}

#[derive(Deserialize)]
struct ProofStatement {
    statement_id: String,
}

impl Drop for Journal {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.packet.zeroize();
    }
}

const MAX_JOURNAL: usize = 4 * (MAX_ENVELOPE_BYTES + SIDECAR_BYTES) + 4096;
const JOURNAL_DOMAIN: &[u8] = b"siworld isolated desktop wallet payment journal v1";

fn journal_key(scope: &WalletScope, material: &Material) -> (Zeroizing<[u8; 32]>, Vec<u8>) {
    let mut context = JOURNAL_DOMAIN.to_vec();
    context.extend(scope.network);
    context.extend(scope.genesis);
    context.extend(material.account.to_le_bytes());
    (
        crypto::derive(
            &material.entropy,
            scope.genesis[..16].try_into().unwrap(),
            &context,
        ),
        context,
    )
}

fn load_journal(
    path: &Path,
    scope: &WalletScope,
    material: &Material,
) -> ScanResult<Option<Journal>> {
    let path = path.with_extension("payment");
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take((MAX_JOURNAL + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_JOURNAL || bytes.len() < 24 + 16 {
        return Err("Development payment journal size rejected.".into());
    }
    let (key, context) = journal_key(scope, material);
    let plaintext = crypto::unseal(&key, bytes[..24].try_into()?, &context, &bytes[24..])?;
    Ok(Some(serde_json::from_slice(&plaintext)?))
}

fn payment_lock(path: &Path) -> Result<File, &'static str> {
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path.with_extension("payment-lock"))
        .map_err(|_| "payment_journal")?;
    file.try_lock().map_err(|_| "payment_pending")?;
    Ok(file)
}

fn save_journal(
    path: &Path,
    scope: &WalletScope,
    material: &Material,
    journal: &Journal,
    replace: bool,
) -> ScanResult<()> {
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().ok_or("Missing wallet directory.")?)?;
    let (key, context) = journal_key(scope, material);
    let nonce = crypto::random::<24>()?;
    let plaintext = Zeroizing::new(serde_json::to_vec(journal)?);
    let encrypted = crypto::seal(&key, &nonce, &context, &plaintext)?;
    file.write_all(&nonce)?;
    file.write_all(&encrypted)?;
    file.as_file().sync_all()?;
    let destination = path.with_extension("payment");
    if replace {
        file.persist(destination)?;
    } else {
        file.persist_noclobber(destination)?;
    }
    #[cfg(target_os = "macos")]
    File::open(path.parent().ok_or("Missing wallet directory.")?)?.sync_all()?;
    Ok(())
}

fn client(timeout: u64) -> ScanResult<Client> {
    Ok(Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(timeout))
        .build()?)
}

pub fn summarize(
    addr: SocketAddr,
    scope: &WalletScope,
    material: &Material,
    path: &Path,
) -> ScanResult<Summary> {
    let journal = load_journal(path, scope, material)?;
    let statement = journal
        .as_ref()
        .map(|j| hex_array(&j.public.statement_id))
        .transpose()?;
    let (wallet, included) = scan(addr, scope, material, statement)?;
    let balance: serde_json::Value = serde_json::from_str(&wallet.balance_json()?)?;
    let history: Vec<serde_json::Value> = serde_json::from_str(&wallet.history_json())?;
    let sip = "00".repeat(32);
    let row = balance["rows"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["asset"] == sip));
    let amount = |key: &str| {
        row.and_then(|row| row[key].as_str())
            .unwrap_or("0")
            .to_owned()
    };
    let history = history
        .into_iter()
        .rev()
        .filter(|row| row["asset"] == sip)
        .take(20)
        .map(serde_json::from_value)
        .collect::<Result<_, _>>()?;
    Ok(Summary {
        height: wallet.height(),
        available_atoms: amount("available_atoms"),
        locked_atoms: amount("locked_atoms"),
        history,
        standard_fee_atoms: base_fee(wallet.height()).to_string(),
        payment: journal.map(|mut row| {
            row.public.height = included;
            PaymentStatus {
                statement_id: row.public.statement_id.clone(),
                amount_atoms: row.public.amount_atoms.clone(),
                fee_atoms: row.public.fee_atoms.clone(),
                height: included,
                acknowledged: row.public.acknowledged,
            }
        }),
    })
}

pub fn send(
    addr: SocketAddr,
    scope: &WalletScope,
    material: &Material,
    path: &Path,
    request: SendRequest,
    confirm: impl FnOnce(&SendRequest) -> Result<bool, &'static str>,
) -> Result<Option<PaymentStatus>, &'static str> {
    let _lock = payment_lock(path)?;
    let journal = load_journal(path, scope, material).map_err(|_| "payment_journal")?;
    let statement = journal
        .as_ref()
        .map(|j| hex_array(&j.public.statement_id))
        .transpose()
        .map_err(|_| "payment_journal")?;
    let (mut wallet, included) =
        scan(addr, scope, material, statement).map_err(|_| "payment_network")?;
    if journal.is_some() && included.is_none() {
        return Err("payment_pending");
    }
    if request.amount == 0 || request.fee != base_fee(wallet.height()) {
        return Err("payment_fee");
    }
    let descriptor = Descriptor::decode(
        &hex_array::<V2_LEN>(&request.descriptor).map_err(|_| "payment_recipient")?,
    )
    .map_err(|_| "payment_recipient")?;
    let short = ShortAddress::parse(&request.address).map_err(|_| "payment_recipient")?;
    if short.network != Network::Testnet
        || descriptor.short_address() != short
        || descriptor.genesis() != scope.genesis
    {
        return Err("payment_recipient");
    }
    let details = Zeroizing::new(
        wallet
            .prepare_sip_recipient(
                scope.network,
                wallet.tip_snapshot().selector,
                descriptor
                    .native_recipient()
                    .map_err(|_| "payment_recipient")?,
                request.amount,
                false,
                &[],
            )
            .map_err(|_| "payment_funds")?,
    );
    let id = serde_json::from_str::<ProofStatement>(&details)
        .map_err(|_| "payment_proof")?
        .statement_id;
    drop(details);
    if !confirm(&request)? {
        return Ok(None);
    }
    let packet = wallet
        .prove_sip_for_genesis()
        .map_err(|_| "payment_proof")?;
    let mut journal_entry = Journal {
        public: PaymentStatus {
            statement_id: id,
            amount_atoms: request.amount.to_string(),
            fee_atoms: request.fee.to_string(),
            height: None,
            acknowledged: false,
        },
        packet,
    };
    save_journal(path, scope, material, &journal_entry, journal.is_some())
        .map_err(|_| "payment_journal")?;
    journal_entry.public.acknowledged = submit(addr, &journal_entry).unwrap_or(false);
    if journal_entry.public.acknowledged {
        let _ = save_journal(path, scope, material, &journal_entry, true);
    }
    Ok(Some(PaymentStatus {
        statement_id: journal_entry.public.statement_id.clone(),
        amount_atoms: journal_entry.public.amount_atoms.clone(),
        fee_atoms: journal_entry.public.fee_atoms.clone(),
        height: None,
        acknowledged: journal_entry.public.acknowledged,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalized_packets_are_atomically_encrypted_and_bound_to_wallet() {
        let scope = WalletScope::development(&format!("{}:{}:a", "01".repeat(32), "02".repeat(32)))
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("test.swnvlt");
        let material = Material {
            network: scope.network,
            account: 0,
            entropy: [42; 32].into(),
        };
        let entry = Journal {
            public: PaymentStatus {
                statement_id: "ab".repeat(32),
                amount_atoms: "120".into(),
                fee_atoms: "12".into(),
                acknowledged: false,
                height: None,
            },
            packet: vec![42; 300],
        };
        assert!(load_journal(&path, &scope, &material).unwrap().is_none());
        save_journal(&path, &scope, &material, &entry, false).unwrap();
        assert!(save_journal(&path, &scope, &material, &entry, false).is_err());
        let sealed = std::fs::read(path.with_extension("payment")).unwrap();
        assert!(!sealed.windows(40).any(|part| part == [42; 40]));
        let opened = load_journal(&path, &scope, &material).unwrap().unwrap();
        assert_eq!(opened.packet, entry.packet);
        assert_eq!(opened.public.statement_id, entry.public.statement_id);
        let wrong_account = Material {
            account: 1,
            ..material
        };
        assert!(load_journal(&path, &scope, &wrong_account).is_err());
    }
}

pub fn retry(
    addr: SocketAddr,
    scope: &WalletScope,
    material: &Material,
    path: &Path,
) -> Result<Option<PaymentStatus>, &'static str> {
    let _lock = payment_lock(path)?;
    let mut journal = load_journal(path, scope, material)
        .map_err(|_| "payment_journal")?
        .ok_or("payment_journal")?;
    let id = hex_array(&journal.public.statement_id).map_err(|_| "payment_journal")?;
    let (wallet, included) =
        scan(addr, scope, material, Some(id)).map_err(|_| "payment_network")?;
    journal.public.height = included;
    if included.is_none() {
        let verified = wallet
            .check_payment_packet_for_genesis(scope.network, &journal.packet)
            .map_err(|_| "payment_proof")?;
        if serde_json::from_str::<ProofStatement>(&verified)
            .map_err(|_| "payment_proof")?
            .statement_id
            != journal.public.statement_id
        {
            return Err("payment_journal");
        }
        journal.public.acknowledged = submit(addr, &journal).map_err(|_| "payment_network")?;
    }
    save_journal(path, scope, material, &journal, true).map_err(|_| "payment_journal")?;
    Ok(Some(journal.public.clone()))
}

fn submit(addr: SocketAddr, journal: &Journal) -> ScanResult<bool> {
    let response = client(12)?
        .post(format!("http://{addr}/api/v2/wallet/submit"))
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(journal.packet.clone())
        .send()?;
    if cfg!(debug_assertions) && std::env::var_os("SIVAULT_DEV_DIAGNOSTIC").is_some() {
        eprintln!(
            "Isolated wallet admission HTTP status: {}",
            response.status().as_u16()
        );
    }
    if response.status() != reqwest::StatusCode::ACCEPTED {
        return Ok(false);
    }
    let mut body = Vec::new();
    response.take(257).read_to_end(&mut body)?;
    let reply: serde_json::Value = serde_json::from_slice(&body)?;
    Ok(body.len() <= 256
        && reply
            == serde_json::json!({
                "status": "pending", "statement_id": &journal.public.statement_id
            }))
}

fn scan(
    addr: SocketAddr,
    scope: &WalletScope,
    material: &Material,
    statement: Option<[u8; 32]>,
) -> ScanResult<(Eng2LightState, Option<u64>)> {
    if !addr.ip().is_loopback() || !scope.is_development() {
        return Err("Wallet scan requires the isolated development scope.".into());
    }
    let client = client(4)?;
    let origin = format!("http://{addr}/api/v2/wallet");
    let start = Instant::now();
    let get = |path: &str, max: usize| -> ScanResult<Vec<u8>> {
        if start.elapsed() > Duration::from_secs(45) {
            return Err("Development wallet scan exceeded the time budget.".into());
        }
        let response = client.get(format!("{origin}/{path}")).send()?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|len| len > max as u64)
        {
            return Err("Development wallet artifact unavailable.".into());
        }
        let mut bytes = Vec::new();
        response.take((max + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > max {
            return Err("Development wallet artifact size rejected.".into());
        }
        Ok(bytes)
    };
    let head: Head = serde_json::from_slice(&get("head", 2048)?)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if !head.well_formed()
        || !head.matches(scope)
        || head.height > MAX_DEV_HEIGHT
        || head.published_unix_seconds < now.saturating_sub(300)
        || head.published_unix_seconds > now.saturating_add(30)
    {
        return Err("Development wallet head rejected.".into());
    }
    let tip = hex_array(&head.tip)?;
    let genesis = get("genesis", 140_000)?;
    let mut wallet = Eng2LightState::new(
        &genesis,
        scope.genesis,
        material.entropy.clone(),
        material.account,
    )?;
    let context = wallet.context();
    if context.config().network != scope.network {
        return Err("Development wallet network differs from the pinned genesis.".into());
    }
    let binding = Binding::new(
        scope.network,
        scope.genesis,
        context.rules(),
        context.profile(),
    );
    let manifest = Manifest::decode(
        &binding,
        &get(
            &format!("generations/{}/{}", head.height, head.tip),
            MAX_MANIFEST_BYTES,
        )?,
    )?;
    if (manifest.height, manifest.tip) != (head.height, tip) {
        return Err("Development wallet manifest differs from the selected head.".into());
    }
    let mut included = None;
    for descriptor in manifest.chunks {
        let raw = get(
            &format!("chunks/{}", hex(&descriptor.digest)),
            descriptor.bytes as usize,
        )?;
        let chunk = descriptor.decode_chunk(&binding, &raw)?;
        for (i, record) in chunk.records.into_iter().enumerate() {
            let height = chunk.from + i as u64;
            let receipt = get(
                &format!("receipts/{height}/{}", hex(&record.id)),
                record.receipt_bytes as usize,
            )?;
            record.check_receipt(&binding, &receipt)?;
            wallet.append(&record.header, &receipt)?;
            if let Some(statement) = statement {
                if included.is_none() && wallet.payment_receipt(height, &receipt, statement).is_ok()
                {
                    included = Some(height);
                }
            }
        }
    }
    wallet.check_head(head.height, tip, None)?;
    let fresh: Head = serde_json::from_slice(&get("head", 2048)?)?;
    if !fresh.well_formed()
        || !fresh.matches(scope)
        || (fresh.height, fresh.tip) != (head.height, head.tip)
    {
        return Err("Development wallet head changed during the scan.".into());
    }
    Ok((wallet, included))
}
