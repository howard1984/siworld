# Use a wallet

## Overview

Use a SIWORLD wallet to receive and send private transfers. The wallet
discovers its notes by decrypting the authenticated outputs locally and
uses the chosen network and genesis to verify payment status.

## Requirements

- A wallet from the trusted release channel and its matching network
  configuration. Start from [siworld.io](https://siworld.io/).
- A secure device and an offline place to record recovery words. If
  recovering, use the original phrase and its matching network.
- For a short receiving address, obtain the corresponding full contact
  through a trusted channel before creating a transfer.

## Steps

1. **Select the network.** Confirm the displayed network and genesis
   against the release manifest before creating or restoring an account.
2. **Create or restore the wallet.** Use its recovery flow. Protect the
   recovery words offline and keep signing material on the wallet device.
   Synchronize until authenticated history covers the account's activity.
3. **Receive.** Share the full `sivf1…` receiving address first. If you use
   a secondary `si1p…` address, verify its descriptor against the pinned
   genesis and the matching full address on the pinned network. Inspect
   incoming notes in the wallet.
4. **Send.** Verify the recipient, asset, amount, and fee tier. Review the
   selected inputs and change, then authorize the payment on your device.
5. **Check payment status.** Treat admission as pending and inclusion in the
   chain tail as provisional. Use checkpoint coverage for finality. Check
   a locked note's verified height before attempting to spend it.

## Verification

Compare the selected network, account address, and last verified height
with the expected values after restoring. For a payment, check the asset
and amount, inclusion, and checkpoint coverage in the wallet. Public data
alone cannot verify a recipient's decrypted contents. See
[wallet verification](../specs/09-addresses-and-wallets.md#wallet-verification).

## Troubleshooting

| Symptom | Check | Action |
| --- | --- | --- |
| Restored account has no activity | Network, account, and available authenticated history | Verify the recovery inputs and complete synchronization. |
| Short address is rejected | Full contact, network, genesis, and matching descriptor | Request a verified full address. |
| Payment remains provisional | Checkpoint coverage and selected branch | Wait for authenticated coverage and verify status again. |
| Note remains locked | Verified height and note unlock height | Wait until the required height is reached. |
