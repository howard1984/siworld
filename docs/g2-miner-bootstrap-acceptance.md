# Miner bootstrap acceptance

## Status and scope

This procedure defines the G2 release gate for a new public-testnet miner. Source
tests, cross-compilation and a resumed engineering-network miner are separate
evidence classes. They do not substitute for a fresh Windows-machine run.

## Checkpoint service requirements

- Produce signed checkpoints at positive multiples of 12 blocks. Require at
  least 24 subsequent accepted blocks before certification. With continuous
  publication the latest eligible checkpoint trails the head by 24–35 blocks.
- Confirm the actual process, network, genesis, configuration and authorized
  signer slot on every registered signer. Record unavailable observations as
  unknown; a live network connection does not establish signer-process health.
- Record the certificate height, source head, publication time, signer quorum
  and manifest identity from each source. A repeated certificate must not reset
  its publication timestamp.
- Alert when the latest certified checkpoint trails an observed chain head by
  more than 48 blocks. Test 48 and 49 explicitly. Missing, stale or foreign-network
  data must not clear an incident. Verify first delivery, deduplication, one
  recovery message and retry until delivery acknowledgement, using injected
  faults before any live acceptance check.

Checkpoint verification must not depend on the publisher interval or height
multiples. Accept any positive checkpoint height after verifying authorized
signatures, at least 24 confirmations, and membership in the independently
selected main chain. Publisher cadence remains a local scheduling policy.

## Startup and interrupted acquisition

Query authenticated network sources for current checkpoint manifests before
choosing a bootstrap candidate. Recompute cumulative header work and reject
conflicting equal-work chains. Among offers on the same selected tip, prefer
the newest valid checkpoint. Preserve network, genesis, rules, proof-profile,
current-roster, signature, state-commitment and native-tail validation.

Resume a retained cache only when its exact manifest matches the selected
offer. Store a changed offer in a distinct bounded cache namespace. Preserve
the previous cache and its failure evidence. Bundled configuration or a bundled
checkpoint is a fallback; its presence is not evidence of current publication.

## Windows measurement

The operator performs the run on a Windows computer with no prior SIWORLD
installation or chain data. Record CPU, installed RAM, OS version, package
version, source commit, executable and ZIP SHA-256 digests, and source coverage.
Never remove an existing wallet or identity to manufacture a fresh-machine run.

Record monotonic phase durations and UTC timestamps for:

1. Download start and completion, ZIP bytes, and checksum verification.
2. First launch and authenticated network-manifest selection.
3. Checkpoint download completion, selected anchor height and source head.
4. Certificate/state verification and durable installation.
5. Native catch-up start, synchronized head and first actual PoW attempt.
6. First locally accepted block and its independently observed main-chain
   acceptance. PoW search alone does not satisfy this final condition.

Separate encrypted application-stream bytes, retried sessions, package bytes
and packet-level wire bytes. State the measurement scope; unavailable values
remain unknown. Preserve the sanitized bootstrap receipt, progress and worker
status. Exclude secrets, receiving addresses and network endpoints.

## Pass criteria

- Current valid checkpoint was obtained from a network source, with observed
  head lag at most 36 blocks during steady publication.
- Download, verification, catch-up and mining phases completed without bypasses.
- Native catch-up alone took at most 900 seconds. If it exceeds 900 seconds,
  parallel multicore validation becomes a prerequisite for public launch and
  this gate must be repeated on Windows after the implementation changes.
- Timing and byte accounting are complete, and a produced block is accepted
  by the independently observed main chain.
- Checkpoint freshness and delivery/recovery alarm evidence is retained.

Checkpoint admission changes do not reset the engineering chain or alter
transaction-proof, fee-proof or block-consensus rules. Other public-testnet
proof-privacy and platform release gates remain independent prerequisites.
