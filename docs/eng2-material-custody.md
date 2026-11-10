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
