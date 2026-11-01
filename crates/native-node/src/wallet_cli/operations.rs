//! Explicit idle-node wallet operations. Private results go only to the
//! controlling terminal; every scan authenticates the complete bounded history.
use super::{passphrase, payment_confirmation::confirm_payment, require_terminal, terminal};
use crate::proofs::{NativeProver, NativeVerifier};
use crate::runtime::Node;
use crate::store::Store;
use crate::wallet::{FeeTier, Wallet};
use crate::wallet_policy::{SpendPolicy, WalletPrivacyPolicy};
use crate::wallet_vault::{PaymentStatus, UnlockedWallet, WalletVault};
use crate::wire::{DigestBytes, Hash};
use native::codec::decode_digest;
use native::encryption::PaymentAddress;
use native::multi_asset::SIP_ASSET_ID;
use serde_json::{Value, json};
use std::fs::File;
use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::wallet_balance_view as balance_view;

const MAX_SCAN_BLOCKS: u64 = 64;
const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivacyOverride {
    Configured,
    Enhanced,
    Skip,
}
impl PrivacyOverride {
    fn resolve(self, policy: &WalletPrivacyPolicy) -> SpendPolicy {
        match self {
            Self::Configured if policy.enhanced_privacy => SpendPolicy::EnhancedPrivacy,
            Self::Enhanced => SpendPolicy::EnhancedPrivacy,
            Self::Configured | Self::Skip => SpendPolicy::Manual,
        }
    }
}

enum Action<'a> {
    Balance,
    Privacy(bool),
    Pay {
        recipient: &'a Path,
        amount: u64,
        tier: FeeTier,
        privacy: PrivacyOverride,
    },
    Retry(Hash),
}
struct Request<'a> {
    wallet: &'a Path,
    network: &'a Path,
    action: Action<'a>,
}
fn unhex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2
        || text
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err("expected canonical lowercase hexadecimal data".into());
    }
    let mut bytes = [0; N];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |byte| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        bytes[index] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(bytes)
}
fn parse<'a>(command: &str, args: &'a [String]) -> Result<Request<'a>, String> {
    let count_valid = match command {
        "wallet-balance" => args.len() == 2,
        "wallet-pay" => matches!(args.len(), 5 | 6),
        "wallet-retry-payment" | "wallet-privacy" => args.len() == 3,
        _ => return Err("unsupported wallet operation".into()),
    };
    if !count_valid || args[..2].iter().any(String::is_empty) {
        return Err("invalid wallet operation arguments; use --help".into());
    }
    let action = match command {
        "wallet-balance" => Action::Balance,
        "wallet-privacy" => Action::Privacy(match args[2].as_str() {
            "on" => true,
            "off" => false,
            _ => return Err("enhanced privacy must be explicitly on or off".into()),
        }),
        "wallet-retry-payment" => Action::Retry(unhex(&args[2])?),
        "wallet-pay" => {
            if args[2].is_empty()
                || args[3].is_empty()
                || args[3].starts_with('0')
                || args[3].bytes().any(|byte| !byte.is_ascii_digit())
            {
                return Err("payment requires a recipient descriptor and positive canonical amount in atoms".into());
            }
            let amount = args[3]
                .parse::<u64>()
                .map_err(|_| "payment amount exceeds its limit")?;
            let tier = match args[4].as_str() {
                "standard" => FeeTier::Standard,
                "priority" => FeeTier::Priority,
                _ => return Err("fee tier must be standard or priority".into()),
            };
            let privacy = match args.get(5).map(String::as_str) {
                None => PrivacyOverride::Configured,
                Some("--enhanced-privacy") => PrivacyOverride::Enhanced,
                Some("--skip-privacy-delay" | "--no-privacy-delay") => PrivacyOverride::Skip,
                _ => {
                    return Err(
                        "payment accepts at most one explicit privacy option; use --help".into(),
                    );
                }
            };
            Action::Pay {
                recipient: Path::new(&args[2]),
                amount,
                tier,
                privacy,
            }
        }
        _ => return Err("unsupported wallet operation".into()),
    };
    Ok(Request {
        wallet: Path::new(&args[0]),
        network: Path::new(&args[1]),
        action,
    })
}
fn check_scan_budget(height: u64, bytes: u64) -> Result<(), String> {
    if height > MAX_SCAN_BLOCKS || bytes > MAX_SCAN_BYTES {
        return Err(
            "idle engineering wallet scan exceeds its 64-block or 4-GiB encoded-history allowance"
                .into(),
        );
    }
    Ok(())
}
fn check_payment_capacity(height: u64, encoded_bytes: u64) -> Result<(), String> {
    if height >= MAX_SCAN_BLOCKS {
        return Err("payment would exceed the idle engineering wallet's scan-height allowance; no payment was submitted".into());
    }
    let maximum_block = u64::try_from(crate::wire::MAX_BLOCK_BYTES)
        .map_err(|_| "maximum block size exceeds the wallet scan range")?;
    if encoded_bytes
        .checked_add(maximum_block)
        .is_none_or(|bytes| bytes > MAX_SCAN_BYTES)
    {
        return Err("payment would exceed the idle engineering wallet's encoded-history allowance; no payment was submitted".into());
    }
    Ok(())
}
struct Scanned {
    wallet: Wallet,
    encoded_bytes: u64,
}
fn scan(vault: &mut UnlockedWallet, node: &Node<NativeVerifier>) -> Result<Scanned, String> {
    let state = node.state();
    check_scan_budget(state.height, 0)?;
    let mut blocks = Vec::new();
    let mut bytes = 0u64;
    for height in 1..=state.height {
        let block = node.store().block(height)?;
        bytes = bytes
            .checked_add(
                u64::try_from(block.encoded_len()?).map_err(|_| "wallet history size overflow")?,
            )
            .ok_or("wallet history size overflow")?;
        check_scan_budget(height, bytes)?;
        blocks.push(block);
    }
    let verifier = NativeVerifier::new()?;
    let mut wallet = vault.wallet()?;
    wallet
        .reconcile(state.config.clone(), &blocks, &verifier)?
        .check_head(state.height, state.tip, state.fingerprint())?;
    vault
        .reconcile_payments(state.config.clone(), &blocks, &verifier)?
        .check_head(state.height, state.tip, state.fingerprint())?;
    Ok(Scanned {
        wallet,
        encoded_bytes: bytes,
    })
}
fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "wallet clock is before the supported epoch".into())
}
fn private_result(tty: &mut File, value: &Value) -> Result<(), String> {
    serde_json::to_writer_pretty(&mut *tty, value)
        .map_err(|_| "cannot display private wallet result")?;
    tty.write_all(b"\n")
        .and_then(|()| tty.flush())
        .map_err(|_| "cannot flush private wallet result".into())
}
fn status_name(status: PaymentStatus) -> &'static str {
    match status {
        PaymentStatus::Reserved => "reserved",
        PaymentStatus::Prepared => "prepared",
        PaymentStatus::Submitted => "submitted",
        PaymentStatus::Accepted => "accepted",
        PaymentStatus::Conflicted => "conflicted",
        PaymentStatus::Orphaned => "orphaned",
    }
}
fn terminal_payment(status: PaymentStatus) -> bool {
    matches!(status, PaymentStatus::Accepted | PaymentStatus::Conflicted)
}
fn privacy_warning_text(recent: bool) -> Option<&'static str> {
    recent.then_some("Spending immediately may reduce privacy")
}
fn balance(
    tty: &mut File,
    vault: &UnlockedWallet,
    wallet: &Wallet,
    node: &Node<NativeVerifier>,
) -> Result<(), String> {
    let state = node.state();
    let details = wallet.balance_details(state)?;
    let assets = |values: &std::collections::BTreeMap<native::multi_asset::AssetId, u128>| {
        values.iter().map(|(asset, amount)| json!({"asset_id":crate::local::hex(&asset.0),"amount_atoms":amount.to_string()})).collect::<Vec<_>>()
    };
    let tranches = details.tranches.iter().map(|tranche| json!({"asset_id":crate::local::hex(&tranche.asset.0),"amount_atoms":tranche.amount.to_string(),"unlock_height":tranche.unlock_height,"estimated_unlock_unix_seconds":tranche.estimated_timestamp})).collect::<Vec<_>>();
    let mut payment_blocked = false;
    let payments = vault
        .payment_ids()
        .into_iter()
        .map(|id| {
            vault.payment_status(id).map(|status| {
                payment_blocked |= !terminal_payment(status);
                json!({"payment_id":crate::local::hex(&id),"status":status_name(status)})
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let clock = now()?;
    let (privacy_pending, next_policy_time) = balance_view::privacy_pending(wallet, state, clock)?;
    let (privacy_policy, immediate_spend_warning) =
        balance_view::privacy_policy_view(wallet, state, clock)?;
    let summary = balance_view::summarize(&details.available, &details.locked, &privacy_pending)?;
    let balance_summary = summary
        .iter()
        .map(|row| {
            json!({
                "asset_id": crate::local::hex(&row.asset.0),
                "confirmed_owned_atoms": row.confirmed_owned.to_string(),
                "consensus_mature_atoms": row.consensus_mature.to_string(),
                "chain_locked_atoms": row.chain_locked.to_string(),
                "privacy_pending_atoms": row.privacy_pending.to_string(),
                "policy_ready_atoms": row.policy_ready.to_string(),
            })
        })
        .collect::<Vec<_>>();
    tty.write_all(
        balance_view::render(state.height, &state.tip, &summary, payment_blocked).as_bytes(),
    )
    .map_err(|_| "cannot display private wallet summary")?;
    private_result(
        tty,
        &json!({"version":1,"status":"verified_wallet_scan","height":state.height,"tip":crate::local::hex(&state.tip),"available":assets(&details.available),"locked":assets(&details.locked),"lock_batches":tranches,"next_unlock_height":details.next_unlock_height,"privacy_policy_pending":assets(&privacy_pending),"next_privacy_policy_unix_seconds":next_policy_time,"payments":payments,"scope":"idle-engineering-node-full-native-proof-replay","balance_summary":balance_summary,"privacy_policy":privacy_policy,"immediate_spend_privacy_warning":immediate_spend_warning,"payment_submission_blocked_by_pending_journal":payment_blocked}),
    )
}

struct Candidate {
    commitment: DigestBytes,
    value: u64,
    ready_at: Option<u64>,
}
enum Selection {
    Ready([Option<DigestBytes>; 2]),
    Waiting(Option<u64>),
}
#[cfg(test)]
impl Selection {
    fn inputs(&self) -> Option<[Option<DigestBytes>; 2]> {
        match self {
            Self::Ready(inputs) => Some(*inputs),
            Self::Waiting(_) => None,
        }
    }
}
fn select(candidates: &[Candidate], required: u64, clock: u64) -> Result<Selection, String> {
    if required == 0 {
        return Err("payment input requirement must be positive".into());
    }
    let choose = |ready: u64| {
        let mut candidates = candidates
            .iter()
            .filter(|candidate| candidate.ready_at.is_some_and(|time| time <= ready))
            .collect::<Vec<_>>();
        candidates.sort_by_key(|candidate| (candidate.value, candidate.commitment));
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.value >= required)
        {
            return Some([Some(candidate.commitment), None]);
        }
        if candidates.len() >= 2 {
            let first = candidates[candidates.len() - 1];
            let second = candidates[candidates.len() - 2];
            if u128::from(first.value) + u128::from(second.value) >= u128::from(required) {
                return Some([Some(first.commitment), Some(second.commitment)]);
            }
        }
        None
    };
    if let Some(inputs) = choose(clock) {
        return Ok(Selection::Ready(inputs));
    }
    let mut times = candidates
        .iter()
        .filter_map(|candidate| candidate.ready_at)
        .filter(|time| *time > clock)
        .collect::<Vec<_>>();
    times.sort_unstable();
    times.dedup();
    // Readiness is monotone. A binary search avoids quadratic rescanning of a
    // wallet with many individual reward or payment receipts.
    if let Some(&last) = times.last()
        && choose(last).is_some()
    {
        let mut left = 0;
        let mut right = times.len() - 1;
        while left < right {
            let middle = left + (right - left) / 2;
            if choose(times[middle]).is_some() {
                right = middle;
            } else {
                left = middle + 1;
            }
        }
        return Ok(Selection::Waiting(Some(times[left])));
    }
    let mut values = candidates
        .iter()
        .map(|candidate| candidate.value)
        .collect::<Vec<_>>();
    values.sort_unstable();
    if values
        .iter()
        .rev()
        .take(2)
        .map(|value| u128::from(*value))
        .sum::<u128>()
        >= u128::from(required)
    {
        return Ok(Selection::Waiting(None));
    }
    Err(
        "payment cannot be funded by at most two owned SIP notes; no reservation was created"
            .into(),
    )
}
fn recipient(path: &Path, network: Hash) -> Result<(PaymentAddress, Hash), String> {
    let mut bytes = Vec::new();
    crate::local::regular_read(path, false, 8192)?
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| "recipient descriptor unavailable")?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "invalid recipient descriptor encoding")?
        .strip_suffix('\n')
        .unwrap_or(
            std::str::from_utf8(&bytes).map_err(|_| "invalid recipient descriptor encoding")?,
        );
    let value: Value = serde_json::from_str(text).map_err(|_| "invalid recipient descriptor")?;
    // The canonical export roundtrip also rejects duplicate object keys.
    if serde_json::to_string(&value).map_err(|_| "invalid recipient descriptor")? != text
        || value.as_object().is_none_or(|object| object.len() != 4)
        || value["version"] != 1
        || value["network"] != crate::local::hex(&network)
        || value["account"]
            .as_u64()
            .is_none_or(|account| account > u64::from(u32::MAX))
    {
        return Err(
            "recipient descriptor is noncanonical or belongs to a different network".into(),
        );
    }
    let address: [u8; 1232] = unhex(
        value["address_hex"]
            .as_str()
            .ok_or("recipient descriptor lacks an address")?,
    )?;
    let owner = decode_digest(address[..48].try_into().expect("fixed owner width"))
        .map_err(|_| "invalid recipient owner")?;
    let address = PaymentAddress::new(
        owner,
        address[48..]
            .try_into()
            .expect("fixed encapsulation key width"),
    )
    .map_err(|_| "invalid recipient encapsulation key")?;
    Ok((address, *blake3::hash(&bytes).as_bytes()))
}
fn submit(
    vault: &mut UnlockedWallet,
    node: &mut Node<NativeVerifier>,
    network: &Path,
    id: Hash,
    tty: &mut File,
    encoded_bytes: u64,
) -> Result<(), String> {
    let status = vault.payment_status(id)?;
    if terminal_payment(status) {
        return private_result(
            tty,
            &json!({"version":1,"status":status_name(status),"payment_id":crate::local::hex(&id),"height":node.state().height}),
        );
    }
    check_payment_capacity(node.state().height, encoded_bytes)?;
    if status == PaymentStatus::Reserved {
        return Err("payment inputs are reserved but no complete proof packet is stored; preserve the wallet and node for recovery review".into());
    }
    vault.verified_payment_opening(id)?;
    let settings = crate::mining::load(network, node.state().config.network)?;
    let mut receipt = None;
    let result = vault.submit_payment(id, |packet| {
        receipt = Some(crate::local_payment::submit_and_mine_with_node(
            node,
            packet.envelope(),
            &packet.sidecar()?.encode()?,
            &settings,
        )?);
        Ok(())
    });
    // A commit may have succeeded even if later journal I/O failed. Always
    // re-authenticate canonical inclusion before reporting or attempting retry.
    let reconciled = scan(vault, node);
    match (result, reconciled) {
        (Ok(()), Ok(_)) => {
            if vault.payment_status(id)? != PaymentStatus::Accepted {
                return Err("mined payment did not reconcile as accepted; preserve wallet and node evidence".into());
            }
            let receipt = receipt.ok_or("missing payment mining receipt")?;
            private_result(
                tty,
                &json!({"version":1,"status":"accepted","payment_id":crate::local::hex(&id),"height":receipt.height,"tip":crate::local::hex(&receipt.tip),"state_fingerprint":crate::local::hex(&receipt.state_fingerprint),"local_reward_receipts_checked":receipt.local_reward_receipts_checked}),
            )
        }
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
    }
}
pub(super) fn run(command: &str, args: &[String]) -> Result<(), String> {
    let request = parse(command, args)?;
    require_terminal(
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
    )?;
    // Obtain the existing canonical owner lease before any wallet prompt or
    // database access. A live node is never bypassed with another redb writer.
    let _lease = crate::service::Lease::acquire(request.network)?;
    let config = crate::local::load(request.network)?;
    let verifier = NativeVerifier::new()?;
    let store = Store::open_existing(
        request.network.join("chain.redb"),
        config.clone(),
        &verifier,
    )?;
    check_scan_budget(store.state().height, 0)?;
    let mut node = Node::new(store, verifier);
    let mut tty = terminal()?;
    let password = passphrase(false)?;
    let mut vault = WalletVault::open(request.wallet, config.network, password.expose())?;
    let mut policy = crate::wallet_policy::load(request.wallet, config.network)?;
    if let Action::Privacy(enhanced_privacy) = &request.action {
        policy.enhanced_privacy = *enhanced_privacy;
        // The authenticated vault remains locked while the local sidecar is
        // atomically replaced. This never changes consensus configuration.
        crate::wallet_policy::save(request.wallet, config.network, policy)?;
        return private_result(
            &mut tty,
            &json!({"version":1,"status":"wallet_privacy_policy_saved","enhanced_privacy":policy.enhanced_privacy,"background_delay":policy.background_delay}),
        );
    }
    let Scanned {
        mut wallet,
        encoded_bytes,
    } = scan(&mut vault, &node)?;
    wallet.set_privacy_policy(policy);
    match request.action {
        Action::Balance => balance(&mut tty, &vault, &wallet, &node)?,
        Action::Privacy(_) => unreachable!("privacy configuration returns before wallet scan"),
        Action::Retry(id) => {
            drop(wallet);
            submit(
                &mut vault,
                &mut node,
                request.network,
                id,
                &mut tty,
                encoded_bytes,
            )?;
        }
        Action::Pay {
            recipient: path,
            amount,
            tier,
            privacy,
        } => {
            if config.fixture {
                return Err(
                    "wallet payment mining requires an initialized ASERT engineering network"
                        .into(),
                );
            }
            check_payment_capacity(node.state().height, encoded_bytes)?;
            for id in vault.payment_ids() {
                if !terminal_payment(vault.payment_status(id)?) {
                    return Err("wallet has an unresolved payment; inspect it and retry its exact stored packet".into());
                }
            }
            let (recipient, recipient_fingerprint) = recipient(path, config.network)?;
            crate::mining::load(request.network, config.network)?;
            if std::env::var("RAYON_NUM_THREADS").as_deref() != Ok("4")
                || std::env::var("SIWORLD_COMPOSITION_HIDING_WORKERS").as_deref() != Ok("2")
            {
                return Err("payment mining requires RAYON_NUM_THREADS=4 and SIWORLD_COMPOSITION_HIDING_WORKERS=2".into());
            }
            let fee = crate::state::base_fee(node.state().height)
                .checked_mul(if tier == FeeTier::Priority { 4 } else { 1 })
                .ok_or("payment fee overflow")?;
            let required = amount
                .checked_add(fee)
                .ok_or("payment plus fee exceeds the amount limit")?;
            let spend_policy = privacy.resolve(&policy);
            let clock = now()?;
            let candidates = wallet
                .receipts()
                .iter()
                .filter(|receipt| {
                    !receipt.spent
                        && receipt.note().asset_id == SIP_ASSET_ID
                        && receipt.note().value > 0
                })
                .map(|receipt| {
                    let note = receipt.note();
                    let ready_at = if note.unlock_height > node.state().height {
                        None
                    } else {
                        wallet.payment_ready_timestamp(&receipt.commitment, spend_policy)?
                    };
                    Ok(Candidate {
                        commitment: receipt.commitment,
                        value: note.value,
                        ready_at,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let selected = match select(&candidates, required, clock)? {
                Selection::Waiting(ready) => {
                    private_result(
                        &mut tty,
                        &json!({"version":1,"status":"waiting_for_unlock_or_wallet_privacy_policy","eligible_unix_seconds":ready,"height":node.state().height,"next_unlock_height":wallet.balance_details(node.state())?.next_unlock_height,"reservation_created":false}),
                    )?;
                    return Ok(());
                }
                Selection::Ready(selected) => selected,
            };
            let mut recent = false;
            if spend_policy == SpendPolicy::Manual {
                for commitment in selected.iter().flatten() {
                    recent |= wallet.manual_privacy_warning(commitment, clock)?;
                }
            }
            if let Some(warning) = privacy_warning_text(recent) {
                writeln!(tty, "{warning}")
                    .and_then(|()| tty.flush())
                    .map_err(|_| "cannot display the private payment warning")?;
            }
            let confirmation = json!({"recipient_descriptor_fingerprint":crate::local::hex(&recipient_fingerprint),"amount_atoms":amount.to_string(),"fee_atoms":fee.to_string(),"fee_tier":if tier == FeeTier::Priority { "priority" } else { "standard" },"action":"prove_and_mine_one_payment_block_on_idle_engineering_node"});
            private_result(&mut tty, &confirmation)?;
            confirm_payment(&mut tty)?;
            // Re-read actual time rather than accepting an injected scheduling
            // clock. The wallet independently enforces consensus maturity and
            // the explicitly selected wallet policy for every input.
            let prepared = wallet.prepare_transfer_with_policy(
                node.state(),
                selected,
                &recipient,
                SIP_ASSET_ID,
                amount,
                tier,
                now()?,
                spend_policy,
            )?;
            let reservation = vault.reserve_payment(prepared.record())?;
            let id = reservation.id();
            private_result(
                &mut tty,
                &json!({"version":1,"status":"durably_reserved_before_proof","payment_id":crate::local::hex(&id)}),
            )?;
            let payment = prepared.prove(&NativeProver::new()?)?;
            vault.store_wallet_payment(&reservation, &payment, &recipient)?;
            drop((payment, wallet));
            submit(
                &mut vault,
                &mut node,
                request.network,
                id,
                &mut tty,
                encoded_bytes,
            )?;
        }
    }
    // No private balances, receipt identifiers, amounts or payment IDs are
    // emitted to stdout or public node telemetry.
    Ok(())
}

#[cfg(test)]
mod tests;
