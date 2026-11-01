# V1 Wallet Recovery and Custody Design

Status: selected wallet requirements after native node/network integration.
These are wallet protections and do not add protocol-level multisignature
transactions. Completed interface tests alone do not establish durable wallet
recovery or protected production custody.

## Locked notes and transaction scheduling

Display available and locked amounts separately for every asset. For locked
notes show each prescribed batch, amount, unlock height, estimated date and
next unlock. The block height determines spendability; dates are projections.
Recover unlock heights by decrypting authenticated permanent ciphertexts,
rebuilding note commitments and reconciling permanent nullifiers. A seed-only
restore must find old unspent locked notes even after proofs are deleted.

Manual transfers immediately prepare and submit consensus-mature inputs after
normal fee, reservation and proof checks. A recent arrival or recently unlocked
note produces an immediate-spend privacy warning that requires explicit user
confirmation; it does not add a mandatory waiting period. Background selection
and optional consolidation retain a deterministic private delay from zero
through six hours. Engineering and test networks disable background delay by
default. Main-network background policy enables it by default. Opt-in enhanced
privacy also applies the delay to manual transfers. No setting permits spending
before consensus maturity or a Holder unlock height.

Derive each independent delay from the seed-derived scheduling key and note
commitment. Start it at the canonical block timestamp where the note first
becomes spendable (or arrives, for an unrestricted ordinary note). Canonical replay reconstructs the same schedule after seed
recovery; reorganization recomputes eligibility and removes orphan receipts.
Missing canonical eligibility fails closed. The caller supplies local time only
to wallet preparation; it never affects consensus validity or permits early
unlocking. Do not publish unlock queues, asset balances or note-to-time
associations. Clock behavior and durable wallet integration still require
wallet review and acceptance tests.

Small-note consolidation is opt-in local policy, uses the common two-input /
three-output format, preserves per-asset balances and SIP-only fees, and never
attempts an immature or reserved input. Use bounded work and avoid immediately
consolidating an entire unlock cohort. Reorganization invalidates orphaned
receipts and pending spends before selecting notes again.

## Shamir backup

Support a reviewed threshold backup format, initially 2-of-3, with independently
stored shares. Creating the wallet requires a verified backup exercise. Bind
the backup version, threshold, share index, wallet/network context and checksum;
reject duplicate indices, corrupted shares and shares from different backups.
Any two valid shares restore the same wallet and all recovery keys. One share
must not expose useful seed information under the selected reviewed scheme.

Threshold seed recovery reconstructs single-key spending authority. It is not
on-chain 2-of-3 authorization and must never be described as requiring two
approvals for each V1 payment. Select and pin a reviewed implementation and
format before release; no home-grown secret sharing is adopted by this design.
Provide loss/corruption, mixed-set and full-ciphertext-rescan tests.

## Hardware and offline interface

Define versioned preparation, review, authorization and return interfaces so
wallet state scanning remains separate from secret-key use. An offline device
must receive enough authenticated context to check recipients, assets,
amounts, fees, snapshot/network identity and lock heights before producing
witness authorization. Its result must bind the exact prepared transaction;
reject stale context and modified fields. Keep secrets and payment-opening
records outside node RPC and control-panel logs.

Hardware support and an offline signing implementation can ship later. The
interface design must not suggest that V1 already has a delegated or multiple
signer consensus policy. The [V2 authorization plan](v2/multisignature.md)
requires a separate versioned AIR and security/performance review.

## Development-fund custody

Existing development-fund key settings remain unchanged. Each configured
wallet retains single-key ML-DSA-65 consensus authorization. The team may
store that key offline as threshold Shamir shares, with separation of custody
and documented approval controls. The public procedure describes roles, not
holder identities, physical locations, share values or recovery material.
Maintain the private assignment and inventory outside the technical repository.

For a payout, verify that wallet's independently unlocked-minus-spent balance, recipient,
network and next counter independently. Authorize a controlled offline recovery
session with the required share holders, reconstruct only on the designated
offline signing device, sign the exact bounded payout statement and verify the
result before transfer. Re-encrypt retained custody material as required;
zeroize transient buffers, remove temporary files/swap/backups and verify the
recovery session left no reusable plaintext key copy. Record the public signed
payout and a private custody event without retaining shares or plaintext keys.

Rehearse recovery and replacement of a lost share with synthetic keys before
real custody. Operating procedures cannot replace ML-DSA verification,
consensus fund limits or independent cryptographic review. Actual custodians,
locations and the signing-device workflow require a private approved runbook.
