# Engineering material preparation and checkpoint binding

Status: local engineering utility. This does not activate a genesis, change a
proof or consensus rule, start a service, or establish production key custody.
The utility is supported on Unix hosts.

Each material uses an independent 32-byte seed from the operating system. Seeds
are stored in plaintext in a new owner-only directory outside Git checkouts.
Directories require exact mode `0700`; secret records and `public.json` require
exact mode `0600`, current ownership and one hard link. Existing records are never
overwritten. All path components reject symlinks. Secret buffers owned by the
utility use `Zeroizing`; dependency-internal copies are outside that guarantee.
Existing wallets and V1 checkpoint authority files are not accepted.

## Preparation

Build the tool from the selected source, recording its commit and executable hash:

```sh
SIWORLD_BUILD_COMMIT=COMMIT cargo build --offline --locked --release \
  --manifest-path crates/native-node/Cargo.toml --bin siworld-eng2-materials
```

On each checkpoint signing host, run one preparation with that host's fixed slot:

```sh
siworld-eng2-materials prepare NETWORK_HEX checkpoint SLOT NEW_PRIVATE_DIRECTORY
```

Other supported purposes are `founder`, `revocation`, `fund-claim`, `fee-wallet`
and `fund-wallet`. The index is `0` for founder, revocation and fee-wallet;
checkpoint slots are `0..2`; fund member indices are `0..31`. Each wallet uses its
own independently generated seed and native account index `0`.

The new directory contains `pending.secret` and `public.json`. Only the latter is
collected for genesis assembly. It contains the complete public ML-DSA-65 key or
canonical native payment address, network, purpose and index. The standard output
contains only public fingerprints, source digests and the executable digest; it
never contains a key, address, seed, password or private path. A build without an
embedded commit reports a null commit rather than inventing provenance.

Fee destinations and fund-member payment addresses are ordinary native payment
addresses. A fund member's ML-DSA claim authority is separate from its payment
address. Generate independent records for these two purposes. No fund member
count, allocation, team index or entitlement is selected by this tool; genesis
assembly requires those explicit existing parameters.

## Post-genesis checkpoint binding

The public keys are generated before genesis sealing. Once an independently
inspected genesis includes all three public keys, return that public genesis and
its independently pinned identity and SHA-256 to each signing host:

```sh
siworld-eng2-materials bind-checkpoint PRIVATE_DIRECTORY GENESIS_FILE \
  EXPECTED_GENESIS_ID EXPECTED_GENESIS_SHA256
```

Binding rejects fixture/zero-work parameters before decoding and requires
production economic parameters and LegacyMiner mode. It verifies the complete
genesis, network, prepared purpose, slot and public key. It writes `checkpoint-bound.secret` once while preserving `pending.secret`.
No seed crosses machines. The output is compatible with the existing resident
checkpoint loader:

| Field | Bytes |
| --- | ---: |
| `SW2KEY01` | 8 |
| Network, genesis and rules commitment | 96 |
| Signer slot | 1 |
| Seed | 32 |
| Existing domain-separated BLAKE3 checksum | 32 |

This separates public-key generation from immutable genesis binding without
changing the runtime loader. A second bind, wrong genesis, wrong slot, altered
public record, permissive private mode, hard link or symlink fails without
replacing existing files. Interrupted preparation is preserved for explicit
inspection; there is no automatic repair or replacement identity.

## Reviewed local authority signing

Existing founder, revocation and fund-claim records can sign a reviewed public
operation without exporting their seed or creating another secret file:

```sh
siworld-eng2-materials sign PRIVATE_DIRECTORY NETWORK_HEX PURPOSE INDEX \
  AUTHORITY_SHA256 PUBLIC_REQUEST_FILE REQUEST_SHA256
```

`PURPOSE` is exactly `founder`, `revocation` or `fund-claim`. Founder and
revocation indices are zero; a fund-claim index must match the public claim's
member. `AUTHORITY_SHA256` independently pins the original preparation receipt's
`public_identity_sha256`, which hashes the raw ML-DSA-65 verification key.
`REQUEST_SHA256` independently pins the exact complete public request file.
Both pins and the nonzero network are mandatory lowercase 32-byte hashes.
Wallet and checkpoint material purposes cannot use this command.

The public file uses the canonical `governance-sign` or `claim-sign` request
specified in [operation files](eng2-operation-files.md). Its `confirmed_digest`
remains the independently reviewed, role-specific digest returned by public
preparation. A changed file, wrong network, purpose, index, authority, digest or
malformed custody record is rejected. Record and directory ownership, exact
permissions, single links, symlink rejection and checksum verification use the
same protected local custody rules as preparation and binding. The stored public
parameters must exactly equal those derived from the prepared authority.

Signing calls the existing operation signer in the same process. Owned record,
seed and signing-key buffers are erased on release. The seed is never sent to
another process, an argument, environment variable, temporary file, log or
output. The original custody files are preserved. This remains an engineering
utility with owner-protected plaintext seed storage; it does not establish
production encrypted custody or protection from operating-system compromise.

The result contains a detached `signature_hex`, public fingerprints,
`public_request_sha256`, `unsigned_payload_sha256`, `review_digest` and the
source/executable receipt. It does not echo public keys, addresses or the
operation payload. Governance signatures additionally identify their role.
Joint management authorization requires separately reviewed founder and
revocation files for the same unsigned action: their role-specific review
and file digests differ, while `unsigned_payload_sha256` must match. The existing
`governance-wrap` operation combines the public signatures; `claim-attach`
attaches a fund signature to the original public claim.

`signature_verified` establishes only local cryptographic verification.
`chain_state_verified`, `state_changed` and `submitted` remain false; fund
entitlement and current-recipient checks also remain false. Actual native block
admission checks active roles, sequence, recipient, member counter and available
fund balance. Public claim `rseed_hex` is a public 48-byte note opening and must
never contain the private 32-byte authority seed.


## Isolated actor vault and temporary issuer library

On Unix with `eng2-rehearsal`, `wallet_vault::rehearsal::RehearsalBinding::decode`
accepts at most 4,096 bytes of SHA-256-pinned public initialization JSON. Its
version-1 schema requires `campaign_id`, `network`, `prior_network`, and
`genesis_parameters_sha256`, each an exact nonzero lowercase 32-byte hex value.
The new network must differ from the prior network. The caller separately
checks the actual pre-genesis parameter bytes against their pin and network;
a referenced digest is not a genesis verifier. Unknown fields are rejected.

`WalletVault::create_isolated_rehearsal` creates one of five explicit actor
roles at account 0 using a new independent OS entropy draw. It preserves the
SWNVLT01 encrypted format, KDF, authenticated encryption, exclusive ownership
and encrypted payment journal. It writes an additional owner-only public
`rehearsal.json` role/campaign/address binding, closes the session, then reopens
and authenticates the persisted vault, journal and public binding. Its new
absolute path must be outside a repository under a canonical owner-only 0700
parent. Existing or partial directories are retained and never overwritten.
Each actor requires a separate invocation and independent entropy; a shared
seed or an address derived from another actor is not an initializer input.

This isolated library entry point does not expose recovery words or confirm a
mnemonic backup. Its receipt explicitly records `recovery_backup_verified`
as false. Ordinary `PendingWallet` backup challenges and creation are unchanged.
`open_isolated_rehearsal` and `isolated_rehearsal_receipt` authenticate the exact
public campaign/role binding against the actual unlocked wallet.

The rehearsal-only `Purpose::Issuer` retains value 7; existing purpose values
0 through 6 are unchanged. `eng2_materials::issuer::prepare_isolated_issuer`
requires the same independently pinned initialization binding and creates a
separate OS-random temporary ML-DSA-65 issuer through the existing SW2MAT01
protected material format. That format is owner-only plaintext, **not encrypted**.
It is an isolated temporary issuer; it does not represent a long-term public
network signer. Generic unbound `prepare` refuses this purpose.

`IssuerSigner::open` verifies the exact initialization bytes, network, issuer
purpose/index, seed checksum, rederived stored public record and independent
issuer public-key pin. Its typed `sign` method checks native declaration size
and policy, expected sequence, asset, supply, metadata and issuance fee, then
signs unchanged canonical declaration bytes with the fixed asset-issuance
context. The actual ML-DSA signature is verified before it is returned. One
signing attempt consumes the session, including failure; no generic-context
signing RPC, seed accessor, secret export or implicit retry is provided.

These library interfaces do not initialize a node, seal genesis, fund actors,
or connect peers. The explicit executable adapter below invokes the existing
business prover only for its business command. Existing V1 stores, identities
and material directories are not migrated by either initializer.

## Isolated custody, business and independent scan commands

The Linux owner build with `eng2-rehearsal,eng2-runtime` adds four exact forms:

```text
siworld-eng2-rehearsal --isolated-custody-init PLAN PLAN_SHA256 NEW_OUTPUT --json
siworld-eng2-rehearsal --isolated-custody-open PLAN PLAN_SHA256 NEW_OUTPUT --json
siworld-eng2-rehearsal --positive-business-existing PLAN PLAN_SHA256 NEW_OUTPUT --json
siworld-eng2-rehearsal --owned-balance-existing PLAN PLAN_SHA256 NEW_OUTPUT --json
```

All require a separately retained owner process guardian and actual cgroup-v2
hard memory, swap, PID and lifetime limits. They refuse CI execution. They do
not start a service or connect peers. Each command requires a new evidence
directory; failures preserve existing custody, encrypted journals and any
accepted block prefix. No automatic retry, regeneration or rollback occurs.

Private stdin is a fixed binary packet followed by EOF: `SWE2PWD1` (8 bytes),
then exactly five `u16le byte_length` plus UTF-8 passphrase byte frames in
payer, recipient, fee destination, fund destination, reward order. Each phrase
is 12..1024 bytes, excluding NUL, CR and LF. The packet is at most 5,138 bytes.
TTY, truncation, malformed UTF-8, an extra frame, trailing newline or any extra
byte fails. There is no password argument, environment, file or interactive
fallback. Owned packet and phrase buffers use `Zeroizing`. The external hard
guardian deadline bounds a sender that never closes stdin; the cooperative
resource gate cannot interrupt a blocked stdin read. The owner retains and
clears its own input buffer; the command creates no password repository.

The plan is strict version-1 JSON with the following fields. An input reference
is `{ "path": ABSOLUTE_CANONICAL_PATH, "sha256": LOWERCASE_SHA256 }`.
Optional fields may be omitted or null; unknown fields fail.

| Field | Meaning |
| --- | --- |
| `version`, `action` | 1 and exactly `init`, `open`, `business` or `scan` |
| `source_commit`, `binary_sha256` | Embedded source commit and actual executable SHA-256 |
| `initialization`, `prerequisites` | Public input references; maximum 4,096 and 262,144 bytes |
| `actors` | Exactly five `{role,directory}` records in the fixed stdin role order; role strings are `payer`, `recipient`, `fee_destination`, `fund_destination`, `reward` |
| `issuer_directory` | Separate temporary issuer directory |
| `excluded_roots` | 1..32 canonical existing roots, including actual V1/live material; none may overlap a custody, evidence or node directory |
| `resources` | Actual run-root and resource contract described below |
| `initial_receipt` | Pinned prior `custody.json`; mandatory after init; maximum 32,768 bytes |
| `genesis`, `qualification` | Sealed public genesis and existing qualification binding, required for business/scan; maximum 1 MiB and 8,192 bytes |
| `business` | Existing positive-business plan-v3 reference for business only; maximum 128 KiB |
| `expectations` | Independent scan expectation reference for scan only; maximum 16 MiB |
| `head`, `node_directory` | Exact `{height,tip}` and existing stopped node for business/scan |

Init excludes every optional input above. Open accepts only `initial_receipt`
and excludes the later genesis/node/business/scan fields. Every input pin is
checked against actual bounded bytes before custody use and again before a
completion receipt. Evidence files are create-only mode 0600 inside a new 0700
directory, with file and directory synchronization and a 64 MiB outer output
budget. Creation synchronizes the existing canonical parent before any evidence
is written. A parent synchronization failure retains the new empty directory
and returns failure. Custody, output and node directories must be disjoint descendants of
the selected canonical owner-only run root. The wallet vault library separately
requires absent nonrepository owner-only parents for new custody.

### Pre-genesis role projection

The prerequisites object is exactly `{version:1,parameters:PARAMETERS,
reward_role:"reward"}`. `PARAMETERS` uses the existing public genesis parameter
schema accepted by `siworld-eng2-genesis`, with only two destination substitutions:
`fee_destination` is exactly `$actor:fee_destination`, and every fund member
`destination` is exactly `$actor:fund_destination`. Fund allocation, independent
claim/checkpoint/governance authority keys, network, native proof profile,
economics, issuance limits and all other rules must already be present.
The initialization binding's `genesis_parameters_sha256` hashes this complete
prerequisites file, not an incomplete sealed genesis.

Before the first identity entropy draw, the current genesis serializers and
policy validate the prerequisite projection using public synthetic addresses.
Init then creates five independent encrypted actor vaults and one independent
owner-only plaintext temporary issuer, authenticates their actual disk readback,
and emits `custody.json`. This records all actual public addresses, issuer key,
prerequisite/initialization hashes and the genesis ID/encoded SHA-256 obtained
by applying those actual addresses to the unchanged serializers. No sealed
genesis file is silently created. Existing genesis tooling must seal the actual
public parameters; later commands require its exact encoded bytes to equal the
same projection. This removes an address/genesis circular dependency while
retaining every nonaddress rule and complete sealed-genesis verification.

### Existing canonical business owner

Business acquires the stopped-owner lease and calls `Store::resume_existing` on
the actual existing `chain.redb`. Source, executable, genesis, qualification,
start height/tip and the business plan's node path must agree. Five actual
encrypted vault sessions are opened using independently pinned complete public
addresses and account 0. The existing complete-prefix native verification and
four-step standard/priority/consolidation/issuance generator remain mandatory.
Real mature payer inputs must already exist in accepted native funding history;
creating a vault does not fund it.

The issuer callback receives the typed native declaration and unchanged fixed
signature context. Its separate issuer session checks the independently pinned
sequence, asset, checked supply sum, metadata and existing issuance fee against
the native chain policy before one real signature attempt. The ordinary wallet
signature attachment verifies that signature before proof. No arbitrary signing
context, seed export or synthetic business bypass is supplied.

Caller-owned positive payment, issuance and reward material remains in erasing
memory across ordinary generation errors until bounded accepted-prefix closeout
is written. These memory openings are not crash-recoverable. Accepted canonical
blocks and encrypted payment journals remain preserved on error, and no campaign
restart or recovery success is implied. Business completion alone leaves
independent scan, complete business acceptance, G1 and G2 false.

### Actual resource observations

`resources` requires `run_root`, exact nonroot `cgroup`,
`maximum_memory_bytes` (1..32 GiB), `maximum_pids` (1..64),
`maximum_run_bytes` (1..64 GiB), `maximum_run_entries` (1..200,000),
`minimum_disk_free_bytes` (at least 128 GiB), `deadline_seconds` (1..3,600),
`maximum_frame_bytes` (at least 190), `maximum_total_frame_bytes`
(at least the single-frame bound and at most 16 GiB), and
`maximum_decode_bytes` (64 KiB..4 GiB). These are conservative upper bounds;
the actual existing guardian may impose a shorter deadline or lower memory cap.

The gate reads actual unified cgroup membership, numeric bounded `memory.max`
and `memory.current`, `pids.max/current`, zero `memory.swap.max/current`, and
unchanged `memory.events`. It checks actual filesystem free space, run-root
identity, deadline and a complete bounded logical-byte/file inventory that
rejects symlinks, mount crossings and hardlinked files. No declared resource
manifest can replace those observations. The external retained guardian owns
hard lifetime enforcement, cleanup and wait/reap evidence; no new service or
resource-management framework is installed.

### Independent complete-prefix wallet observation

Scan is a separate process after the business owner drops all Store/vault locks.
It reacquires the stopped-node lease and opens `Observation::open_full_history`
read-only with exact height 1..16,384, tip, genesis and full frame count. All five
wallets come from freshly authenticated `vault.wallet()` views, without seed
export or generator scanner state. The existing portable light-wallet engine
validates complete header work and receipt inclusion for every height 1..head.
Before body copying, authenticated indexed frame sizes are checked and charged
against finite single-frame/total/decode budgets; metadata reserves 64 MiB, so
a smaller decode budget fails. No suffix, checkpoint or skipped body is accepted.

The strict scan expectation object requires `version:1`, `height`, `tip`,
`evaluation_height` equal to height, `roles`, `assets`, `asset_registry_sha256`,
`forbidden_commitments` and `forbidden_nullifiers`. Each forbidden set has at
most 10,000 unique exact lowercase 48-byte hexadecimal identities. Accepted
public outputs/nullifiers and owned notes must exclude them. Owned note count
is bounded at 10,000 across roles.

`roles` exactly equals the fixed five-role array emitted as `observed-roles.json`.
Each entry contains `role`, `address_hex`, commitment-sorted `notes`, and
asset-sorted `balances`. A note records `commitment`, `nullifier`, `height`,
`block_id`, `output_index`, complete tagged `origin`, `asset`, `value_atoms`,
`unlock_height`, `spent`, and `mature_at_evaluation_height`. Transaction origins
identify record/output indices and statement; issuance origins identify
record/output indices and declaration binding; reward/fund origins identify
their record index. Zero-valued owned notes remain included. A balance records
`asset`, decimal `received_atoms`, `spent_atoms`, `unspent_atoms`,
`available_atoms`, `locked_atoms`, and numeric `received_notes`, `spent_notes`,
`unspent_notes`; all sums/subtractions are checked. Exact equality rejects
extra, omitted or changed fields. Expectations must be authored independently;
copying observed output into them does not establish independent acceptance.

`assets` exactly equals asset-ID-sorted registry entries containing `asset`,
`height`, decimal `public_supply`, and `declaration`; the independent SHA-256
also covers the registry's complete canonical encoding, including sequences and
fees. All five registries must agree. `complete-prefix.json` inventories every
frame and exported receipt digest. Scan reopens the unchanged read-only source
head and rechecks frozen input bytes before completion. After writing the final
receipt, every command performs a final actual resource check, including that
receipt's bytes and directory entry. Completion requires both the retained
receipt and successful process exit; a failed final resource check preserves
the files and does not qualify the receipt as successful. It does not execute
native consensus, governance or transaction-proof validation; the independent
complete-prefix native replay and eleven-component comparison remain separate
required evidence. A successful scan never sets G1/G2 acceptance by itself.
