# Integrate SIWORLD with an exchange

## Overview

Use a full node and a compatible wallet to reconcile verified shielded
deposits and submit withdrawals. Use a release-specific network manifest
and the [wallet interfaces](../specs/09-addresses-and-wallets.md).

## Requirements

- Pin the network identifier, genesis, proof profile, software version,
  and executable digest from trusted release metadata.
- Use a wallet that verifies receipts and decrypts its notes locally.
  Keep viewing and spending material within the custody boundary.
- Maintain durable operation identifiers, signed withdrawal packets,
  payout metadata, and accounting state.

## Steps

1. **Verify the chain binding.** Require network ID
   `d38a665e4751c7cb6153ad56df86426303121524edca5158b8d60b4fc53b638f`
   in trusted release metadata and in the node's reported `network_id`.
   Obtain the genesis ID independently from the verified release manifest.
   Verify the SHA-256 of `genesis.bin` and check its computed ID using
   [the node guide](run-a-node.md#steps). Configure the same pair of
   identifiers in the wallet and integration. Repeat these checks when
   changing software, manifests, or data sources.
2. **Provision deposits.** Use a validated full `sivf1…` address on the
   pinned network as the primary format. For a secondary `si1p…` address,
   verify the version 2 descriptor against the pinned genesis and its
   matching full address. If resolution is unavailable, require the full
   address directly.
3. **Validate a deposit.** Match the note commitment to its authenticated
   receipt. Verify asset identifier, amount in atoms, output index, network,
   statement identifier, and block identifier.
4. **Settle a deposit.** Keep provisional inclusions separate. Check that
   the accepted checkpoint covers the authenticated inclusion before
   crediting the account. Deduplicate by network, statement identifier,
   and output index.
5. **Construct a withdrawal.** Verify the recipient, asset, amount, input
   maturity, fee tier, and change locally. Persist the exact signed packet
   and statement identifier against one withdrawal ID before submission.
6. **Reconcile a withdrawal.** A `pending` response is admission only.
   Resolve a timeout by checking for the same statement and canonical
   inclusion. Retry the same packet when appropriate and reconcile its
   final inclusion before marking the withdrawal settled.

## Verification

Use synthetic custody material on a supported local fixture. Verify that
a wrong network, wrong genesis, or mismatched short-address descriptor
stops processing. Verify one deposit, one withdrawal, duplicate observations, an ambiguous timeout,
and removal of a provisional inclusion. Each entry must reconcile once
against the independently verified status. Follow the
[private gateway and public export rules](../specs/10-rpc.md).

## Troubleshooting

| Symptom | Check | Action |
| --- | --- | --- |
| Different network or genesis | Node, wallet, address, and pinned data source | Suspend processing until the network and software agree. |
| Payment appears twice | Durable deduplication key and canonical receipt | Reuse the same accounting entry and reconcile its current inclusion. |
| Withdrawal times out | Saved packet and statement identifier | Reconcile before retrying the original packet. |
| Finality evidence is missing or conflicts | Certificate, chain binding, and verified ancestry | Pause settlement until there is valid, consistent evidence. |
