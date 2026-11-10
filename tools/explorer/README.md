# Public chain explorer

This static, read-only surface consumes a bounded projection of a full node's
accepted state. It is a presentation of node-reported data, not independent
consensus verification. It contains no wallet, transaction submission, address
search, transaction lookup, price feed, external assets or background polling.
Refreshes occur on page load, explicit refresh and network selection.

## Data path

The native wallet gateway reuses already authenticated compact records from its
existing bounded index work. It retains at most 101 header summaries in memory
and writes `explorer.json` atomically to its existing private public-export
directory. It performs no additional historical verification loop. Its exporter
contains an explicit field allowlist; it does not serialize runtime state.

The reference chain adapter in
`crates/native-wallet-web/tools/engineering-services.py` serves `GET /v1/explorer`
from that fixed file. It rejects symlinks, hard links, nonregular files, files
larger than 128 KiB, invalid scalar values and schema extensions. The projection
must match the current local chain index's network, genesis, height and tip.
A concurrent index update can therefore make a request unavailable; a later
manual refresh reads the next consistent export.

The production wallet archive is a separate adapter. Deploying these static
files alone does not enable this endpoint there. Its existing authenticated
public-export transfer and archive reader need the same bounded projection
contract before production use. No new node listener or administrative route is
required or provided by this directory.

The page accepts only the page's own origin over HTTPS, with loopback HTTP
permitted for local development. The adapter's exact-Origin requirement remains
unchanged. A same-origin browser GET may omit `Origin`; the existing trusted
reverse proxy must supply its configured application origin on the exact
read-only route. See `proxy-location.example.conf`. The example is not an active
deployment configuration and its upstream and origin must be matched to the
installed wallet service. Do not expose the private export directory directly.

## Configuration

Install `index.html`, `explorer.css`, `explorer.mjs`, `chain-client.mjs` and
`projection.mjs` as same-origin static files. Copy
`explorer-config.example.json` to `explorer-config.json` and replace both identity
placeholders with the release-pinned engineering network and genesis identifiers.
The example is intentionally rejected until configured.
The header reuses the website's existing
`/assets/siworld-horizontal-on-dark.svg`; that brand asset is not duplicated in
this technical directory. Website navigation uses its existing HTML routes.

The optional second network entry is `siworld-eng-2`, with its own independent
network, genesis and same-origin API prefix. Change `active` only after the new
network's public export exists. Switching networks aborts outstanding requests,
clears all displayed old data and clears imported block receipts. No receipts,
network state or API data are written to local storage.

## Projection versions 1 and 2

All names below form strict allowlists; extension fields are rejected at the
adapter and browser boundaries. Identifiers are 32-byte lowercase hex strings.
Heights are nonnegative safe integers, capped at 1,000,000 for this engineering
adapter. Timestamps are Unix seconds. Atomic amounts are canonical unsigned
decimal strings below 2^128; unavailable amounts are `null`. One SIP is 10^8
atoms. Values are formatted with integer arithmetic.

| Object | Fields |
| --- | --- |
| Root | `version`, `network`, `genesis`, `height`, `tip`, `published_unix_seconds`, `blocks`, `economics`, `checkpoint`, `governance` |
| Block, at most 101 | `height`, `hash`, `parent_hash`, `timestamp`, `target`, `slots_including_padding`, `reward_mode`, `work` |
| Economics | `issued_atoms`, `burned_atoms`, `holder_pool_atoms`, `locked_reward_atoms`, `unlock_schedule`, `unlock_schedule_complete`, `funds`, `circulating_estimate_atoms` |
| Unlock, next at most 64 | `height`, `atoms` |
| Fund, at most 32 | `index`, `entitled_atoms`, `released_atoms`, `spent_atoms` |
| Checkpoint, nullable | `height`, `hash`, `issued_unix_seconds`, `roster`, `signer_indices` |
| Governance v1 | `current_signers`, `fee_address`, `fund_addresses`, `changes`; all null |
| Governance v2 | The v1 fields, still null, plus required `issuance_fee` |
| Issuance fee v2 | `current_atoms`, `minimum_atoms`, `maximum_atoms`, `pending` |
| Pending issuance fee, nullable | `amount_atoms`, `proposal_sequence`, `included_height`, `effective_height` |

The block sample is contiguous and, when nonempty, ends at the reported tip.
Slot counts include padding. Reward mode is `holder` or `voyager` and never
classifies a slot as a real transaction. Work is checked against
`floor(2^256 / (target + 1))`. The interval summary uses up to 100 differences
between accepted block timestamps; nonpositive differences make it unavailable.
Estimated network work rate is the sum of work for the later block in each
interval divided by the complete timestamp span, in nonce attempts per second.
It does not measure a particular machine or the sequential hash operations
inside one attempt. Difficulty is relative to the easiest target.

Locked rewards cover the subsidy lock schedule. They do not represent maturity
or every restriction on spending. Circulating supply remains unavailable until
a separately specified model accounts for all relevant fund, pool, maturity and
lock states. Fund released allocation is distinct from spending. Only the next
64 subsidy unlock heights are exposed; the completeness flag marks truncation.
Version 1 governance fields remain `null` and contain no issuance-fee member.
Version 2 explicitly exposes the public issuance-fee rule. Its three amount
fields are nonnull canonical decimal strings. Bounds must be exactly
`100000000` and `1000000000000` atoms (1 and 10,000 SIP inclusive), and current
and pending amounts must fall within those bounds. `pending` is null or exactly
the four named fields. `proposal_sequence` is a positive canonical decimal
string at most 2^64 - 1; it is never converted to a JavaScript number. Pending
heights are safe JSON integers, with `0 < included_height <= height <
effective_height` and `effective_height = included_height + 4032`. A proposal
at its effective height must already be reflected in current state.

The UI shows current and pending amounts and inclusion/effective heights.
Version 1, unavailable data and validation failures show `Unknown`; no initial
amount is inferred from the network name or substituted for missing data. A
validated v2 null pending value shows `None`. Other active/pending governance
views still require a separately specified schema extension. A v2 runtime
producer must bind actual governance getters to the same accepted network,
genesis, height and tip as the projection. The existing eng-1 native exporter
continues to produce v1; these client and transport changes alone do not create
an eng-2 runtime export or prove a live deployment.

The schema excludes ordinary and priority transaction fees, fee aggregates,
real transaction counts,
real-versus-padding classification, peer identifiers, network addresses,
transaction first-seen times, nullifiers, commitments, wallet state, rich lists,
distribution statistics and user or address counts. No block or transaction
detail interface is included.

## Local public block receipts

The My blocks panel accepts only this public receipt-file shape:

```json
{
  "version": 1,
  "network": "<matching network identifier>",
  "genesis": "<matching genesis hash>",
  "blocks": [{"height": 1, "hash": "<block hash>", "reward_mode": "holder"}]
}
```

The import is capped at 2 MB and 20,000 records. It rejects additional fields,
duplicate hashes and mismatching network identities. It remains in tab memory
and is never sent to the server. Mode proportions describe only that imported
file. At most 100 imported rows are shown; matches are checked against the
current header sample only. Older rows are explicitly unverified by this view.
Current miner packages do not yet provide a dedicated safe public-receipt export
menu; this panel does not imply that export exists. Wallet files, viewing keys,
private miner status and secrets are not supported import formats.

## Validation

```sh
node --test tools/explorer/tests/*.test.mjs
python3 crates/native-wallet-web/tests/explorer-test.py
cargo test --offline --locked --manifest-path crates/native-node/Cargo.toml \
  --features wallet-light-gateway wallet_gateway::explorer::tests --lib
node tools/explorer/tests/fixture-server.mjs
```

The fixture server is loopback-only and supplies synthetic data, without node
or wallet access. Its standard input selects `full`, `empty`, `partial`, `error`,
`identity-error` or `delayed`. Inspect 1440×900 and 390×844 layouts, all sections,
keyboard focus, manual refresh, error recovery, file rejection and network
switching. These checks establish UI and projection behavior; they are not
production deployment or live-chain acceptance evidence.
To render the website header locally, set `EXPLORER_SITE_ASSETS` to a local copy
of the existing website's asset directory when starting the fixture server.
