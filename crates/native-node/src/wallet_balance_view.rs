//! Private presentation of already authenticated, owned unspent notes.
use native::multi_asset::{AssetId, SIP_ASSET_ID};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct AssetBalance {
    pub asset: AssetId,
    pub confirmed_owned: u128,
    pub consensus_mature: u128,
    pub chain_locked: u128,
    pub privacy_pending: u128,
    pub policy_ready: u128,
}

pub(crate) fn summarize(
    mature: &BTreeMap<AssetId, u128>,
    locked: &BTreeMap<AssetId, u128>,
    privacy_pending: &BTreeMap<AssetId, u128>,
) -> Result<Vec<AssetBalance>, String> {
    let assets = mature
        .keys()
        .chain(locked.keys())
        .chain(privacy_pending.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    assets
        .into_iter()
        .map(|asset| {
            let consensus_mature = mature.get(&asset).copied().unwrap_or(0);
            let chain_locked = locked.get(&asset).copied().unwrap_or(0);
            let privacy_pending = privacy_pending.get(&asset).copied().unwrap_or(0);
            let confirmed_owned = consensus_mature
                .checked_add(chain_locked)
                .ok_or("wallet confirmed balance display overflow")?;
            let policy_ready = consensus_mature
                .checked_sub(privacy_pending)
                .ok_or("wallet privacy delay exceeds the mature display balance")?;
            Ok(AssetBalance {
                asset,
                confirmed_owned,
                consensus_mature,
                chain_locked,
                privacy_pending,
                policy_ready,
            })
        })
        .collect()
}

pub(crate) fn format_amount(asset: AssetId, amount: u128) -> String {
    if asset == SIP_ASSET_ID {
        const ATOMS_PER_SIP: u128 = 100_000_000;
        format!(
            "{}.{:08} SIP",
            amount / ATOMS_PER_SIP,
            amount % ATOMS_PER_SIP
        )
    } else {
        format!("{amount} atom")
    }
}

pub(crate) fn render(
    height: u64,
    tip: &[u8; 32],
    rows: &[AssetBalance],
    payment_blocked: bool,
) -> String {
    let mut text = format!(
        "\nVerified wallet scan at height {height}\nTip: {}\n\n",
        crate::local::hex(tip)
    );
    if rows.is_empty() {
        text.push_str("No confirmed owned unspent notes.\n");
    }
    for row in rows {
        if row.asset == SIP_ASSET_ID {
            text.push_str("SIP\n");
        } else {
            text.push_str(&format!("Asset {}\n", crate::local::hex(&row.asset.0)));
        }
        for (label, amount) in [
            ("Confirmed balance", row.confirmed_owned),
            ("Block unlock reached", row.consensus_mature),
            ("Awaiting block unlock", row.chain_locked),
            ("Privacy delay (included above)", row.privacy_pending),
            ("Eligible for input selection", row.policy_ready),
        ] {
            text.push_str(&format!(
                "  {label}: {}\n",
                format_amount(row.asset, amount)
            ));
        }
        text.push('\n');
    }
    text.push_str("Confirmed balance = block unlock reached + awaiting block unlock.\n");
    text.push_str("Block unlock reached = privacy delay + eligible for input selection.\n");
    text.push_str(
        "Input-selection eligibility is before reservation, input-count and fee checks.\n",
    );
    if payment_blocked {
        text.push_str("New payments blocked by an unresolved payment journal entry.\n");
    }
    text.push('\n');
    text
}

/// Classify mature notes for the configured manual-transfer policy. Background
/// automation has its own delay and never reduces normal manual availability.
pub(crate) fn privacy_pending(
    wallet: &crate::wallet::Wallet,
    state: &crate::state::State,
    clock: u64,
) -> Result<(BTreeMap<AssetId, u128>, Option<u64>), String> {
    let mut pending = BTreeMap::<AssetId, u128>::new();
    let mut next = None;
    if !wallet.privacy_policy().enhanced_privacy {
        return Ok((pending, next));
    }
    for receipt in wallet.receipts().iter().filter(|receipt| {
        !receipt.spent && receipt.note().value > 0 && receipt.note().unlock_height <= state.height
    }) {
        if let Some(ready) = wallet.payment_ready_timestamp(
            &receipt.commitment,
            crate::wallet_policy::SpendPolicy::EnhancedPrivacy,
        )? && ready > clock
        {
            let amount = pending.entry(receipt.note().asset_id).or_default();
            *amount = amount
                .checked_add(u128::from(receipt.note().value))
                .ok_or("wallet display amount overflow")?;
            next = Some(next.map_or(ready, |current: u64| current.min(ready)));
        }
    }
    Ok((pending, next))
}

/// A private configuration snapshot, without seed-derived timestamps or note IDs.
/// The warning is aggregate guidance only; a payment command checks its actual
/// selected notes and requires explicit confirmation before proof generation.
pub(crate) fn privacy_policy_view(
    wallet: &crate::wallet::Wallet,
    state: &crate::state::State,
    clock: u64,
) -> Result<(serde_json::Value, bool), String> {
    use crate::wallet_policy::WalletNetwork;
    let policy = wallet.privacy_policy();
    let network_class = match policy.network_class {
        WalletNetwork::Engineering => "engineering",
        WalletNetwork::Testnet => "testnet",
        WalletNetwork::Mainnet => "mainnet",
    };
    let mut immediate_spend_warning = false;
    for receipt in wallet.receipts().iter().filter(|receipt| {
        !receipt.spent && receipt.note().value > 0 && receipt.note().unlock_height <= state.height
    }) {
        if wallet.manual_privacy_warning(&receipt.commitment, clock)? {
            immediate_spend_warning = true;
            break;
        }
    }
    Ok((
        serde_json::json!({
            "network_class":network_class,
            "enhanced_privacy":policy.enhanced_privacy,
            "background_delay":policy.background_delay,
            "maximum_delay_seconds":crate::wallet::AUTO_DELAY_MAX_SECONDS,
        }),
        immediate_spend_warning,
    ))
}
