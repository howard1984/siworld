# Local proof-body retention

Proof retention is a local storage policy. It does not change block encoding,
header validation, native proof verification, chain selection, governance,
economic state or checkpoint signing authority.

## Configuration and eligibility

Resident peer configuration can include `"proof_retention": {"enabled": true}`.
Omitting the field or setting it to `null` leaves proof maintenance disabled.
Resident maintenance is implemented on Unix platforms. Other platforms reject an
enabled retention configuration rather than silently ignoring it. The configured
local role determines the policy:

- Miner: retain 96 complete recent blocks by default. `miner_blocks` can select
  a larger or smaller window, with a minimum of 24 blocks.
- Bootstrap or validator: retain at least 312 blocks and at least 24 hours after
  locally observing finality for the exact canonical block. The conjunction is
  conservative when observed block intervals differ from their target.
- Wallet-only roles cannot enable this maintenance.

An exact current `CertifiedCheckpoint`, authenticated under the existing
2-of-3 rules, is required for every pruning pass. Bodies above its height never
expire. A checkpoint older than 18 hours pauses maintenance and reports
`proof_pruning_checkpoint_stale`. Reading the same certificate cannot renew its
publication time. Missing, obsolete or conflicting checkpoint context cannot
supply pruning authority.

Service finality age uses accumulated locally observed monotonic runtime.
Restarts do not credit downtime. Gaps longer than two minutes, clock regression
or wall/monotonic drift beyond two seconds suspend age credit for that sample.
The first sample after restart only establishes a new clock baseline. This can
retain proofs longer than 24 hours; it cannot expire them earlier.

## Durable records

Before removing a canonical full body, the owner materializes the existing
permanent public receipt for that exact accepted header and body length. Receipt
and digest rows, headers and compact index, commitments, nullifiers, execution
state, checkpoint anchors and rollback records remain intact. A domain-separated
cursor is sealed with the existing local identity and committed atomically with
body deletion. The cursor authenticates the permanent receipt prefix during
ordinary restart. It is local recovery evidence, not checkpoint authority for
another node.

The existing exclusive owner pauses maintenance during canonical switching and
honors full-body pins for active signed bootstrap offers. Every canonical pass
removes at most four blocks and 64 MiB. Branch proof maintenance has an
independent bounded pass and must preserve headers and permanent public data.
Maintenance errors are reported separately and do not grant readiness or
checkpoint signing rights.

## Storage measurements and limitations

Deleting redb rows makes pages available for reuse. Persistent rollback
savepoints and in-flight readers can retain earlier pages; file length and
filesystem allocation need not decrease immediately. Reports distinguish full
body bytes removed, database logical length, database allocated bytes,
filesystem free bytes and pages reusable by redb. Logical proof deletion must
not be reported as physical filesystem space released.

Explicit audits that replay from genesis still require the original complete
proof history. Ordinary recovery instead verifies the same authenticated local
accepted-state record plus the sealed permanent receipt prefix. Fresh-node
admission uses the existing signed-checkpoint importer: pinned genesis and
header work checks, current 2-of-3 signatures, permanent-state reconstruction
and full native verification of the retained suffix. Neither permanent receipts
alone nor an unsigned snapshot can admit a new node.

## Noncanonical branch bodies

Branch proof expiry is limited to heights at or below the authenticated canonical
retention floor. It preserves every body inside the configured retention window,
every body above the latest valid checkpoint, and active bootstrap body promises.
Each pass scans at most 128 body keys and removes at most four bodies or 64 MiB.
The pass reserves memory from the existing shared budget; it does not increase
that budget. Expired bodies are replaced atomically with permanent public records
and their digests in a separate branch namespace. Headers and execution knowledge
are retained. A removed body loses its body-availability status; its public record
cannot grant native acceptance or checkpoint authority.

This is a bound on retained historical proof bodies, not on permanent public
history. The existing total branch-body admission limit remains in force. Public
records, headers and branch metadata continue to grow. Checkpoint age and local
service finality requirements can delay reclamation. A storage report must state
these limits and any pinned pages rather than promise a fixed database file size.

## Recovery compatibility and state comparison

A database with a nonzero sealed retention floor requires a reader that
understands the sealed permanent receipt prefix. Binaries predating this format
cannot serve as a rollback reader after proof deletion. Disabling maintenance
prevents further deletion; it does not restore removed proof bodies.

`restart-check` reports `state_sha256` only after authenticated local recovery
succeeds. It also reports the authenticated sealed floor as `pruned_through`.
The digest covers all eleven canonical state components, including the
complete economic and governance ledgers. SHA-256 input starts with
`SIWORLD-ENG2-RESTART-STATE-V1` followed by a zero byte, the 32-byte genesis ID,
the little-endian 64-bit height and the 32-byte tip ID. Each component then adds
its zero-based little-endian 64-bit index, little-endian 64-bit byte length and
complete canonical bytes. No raw state or private key material is exported.
The digest supports comparison of an unchanged committed state before and after
recovery. It does not replace native validation or authorize state adoption.
