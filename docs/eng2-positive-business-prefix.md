# Complete original history for positive business generation

The owner-local positive-business library requires plan version 3. Version 2
plans are rejected. A version-3 plan adds `history_budget`, an object containing
an absolute `path` and the independently pinned SHA-256 of its exact bytes.
The input is a private, owner-local JSON file; it is not a trusted checkpoint.

The budget schema is version 1 and has these required fields:

| Field | Meaning |
| --- | --- |
| `version` | Exactly `1`. |
| `height` | Exact original height, equal to the plan's `start_height`. |
| `tip` | Exact original header identifier, equal to `start_tip`. |
| `maximum_total_frame_bytes` | Complete original header-and-body byte budget, at most 16 GiB. |
| `maximum_frame_bytes` | Per-frame bound, no greater than the native body limit plus its header. |
| `maximum_decode_bytes` | Shared accounting limit for frozen metadata and per-frame allocation reservations, at most 4 GiB. |
| `deadline_seconds` | Original-history deadline from campaign start, no greater than the campaign deadline. |
| `minimum_disk_free_bytes` | Required free-space floor, at least 128 GiB. |

Every height from 1 through the exact original head must have a retained,
contiguous canonical header and a complete body. The original height plus the
four campaign blocks must fit the existing full-history height limit of 16,384.
A missing body, discontinuity, changed head, or exhausted bound rejects the run.
History is neither truncated nor replaced with a checkpoint or a recent suffix.
The campaign deadline is explicit and may be at most 3,600 seconds.

Before proving or appending a campaign block, the library inventories the whole
original prefix, checks the existing database size bound, reserves metadata,
and checks each frame against the explicit byte and allocation bounds. Output
capacity must cover every original frame, four maximum native frames, and a
bounded metadata allowance. Free space is observed before this reservation and
before each original frame is decoded and written. Other processes can consume
space between observations; the caller must retain its external disk guard.

The replay starts with an independently initialized native engine at genesis.
Every original block is decoded, natively verified, applied, and scanned in
height order. The resulting exact head and all 11 canonical state components
must equal the actual original store. The pinned budget is checked again before
campaign append and at closeout. The output includes the original full frames,
`history-budget.json`, and `original-prefix.json` with the exact original head,
frame count, total bytes, and budget digest.

The allocation budget reserves `4 * frame_bytes + 65,536` bytes for each frame,
in addition to the retained metadata charge. It accounts for source-frame work;
it does not measure or enforce whole-process memory, native verifier memory, or
the complete replay state's memory. The prefix receipt therefore records
`hard_process_guard_verified: false`. A retained process guardian with actual
memory, disk, deadline, and cleanup checks remains mandatory.

The caller must hold the existing stopped owner's service lease, open the exact
existing store, supply the five existing independently bound vaults, and retain
custody material on failure. This library does not establish that an arbitrary
caller actually holds a lease or operates a resource guardian. Its wallet scan
is part of generation and is not independent owned-balance acceptance evidence.
No full-business, G1, or G2 acceptance follows from a prefix receipt alone.
