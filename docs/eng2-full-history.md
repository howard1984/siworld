# Complete retained-history verification

The owner rehearsal build provides a paged export and comparison interface for
complete retained native history. It verifies every original frame from height
1 through the exact declared accepted height. Pages are transport records, not
state checkpoints. Existing short partition and replay interfaces retain their
96-block limit.

```
siworld-eng2-rehearsal --qualification-audit-history NODE NEW_OUTPUT BUDGET BUDGET_SHA256 BINDING BINDING_SHA256 --json
siworld-eng2-rehearsal --qualification-compare-history NODE EXPORT MANIFEST_SHA256 EXPECTATIONS EXPECTATIONS_SHA256 BINDING BINDING_SHA256 BUDGET BUDGET_SHA256 --json
```

These commands require the owner rehearsal feature, a pinned nonfixture genesis,
matching compile-time source declaration and executable identity, and a stopped
node's exclusive service lease. On both authenticated opens, the fixed-width
72-byte durable head must match the exact declared height within the 16,384-block
limit before any height-dependent index, frame or state traversal. The ordinary
observer and short interfaces retain their prior authentication rules.
The binding and exact public-state expectations
use the same schemas as the short qualification commands. The budget is an
independently SHA-256-pinned JSON object with exactly these fields:

```json
{"version":1,"height":144,"maximum_frame_bytes":1073741824,"deadline_seconds":900}
```

`height` is the exact expected full accepted height, not a window size or lower
bound. The example numbers describe the input format; they are not measured
throughput or capacity guarantees. A later observation requires a new exact
budget and a fresh export directory. Exceeding any bound rejects the operation;
it does not truncate history or silently change the budget.

| Input or work item | Hard bound |
| --- | --- |
| Complete accepted height | 16,384 blocks |
| Total original frame bytes per pass | 16 GiB, further restricted by the budget |
| Source database file | 64 GiB |
| Declared total operation deadline | 3,600 seconds, further restricted by the budget |
| Root manifest | 256 KiB |
| Records in one page | 96 |
| Encoded page | 1 MiB |
| Encoded record | 8 KiB |
| Page count at maximum height | 171 |
| Genesis input | 1 MiB |
| Expectations input | 128 KiB |
| Inclusion, exclusion or nullifier assertions per class | 128 |
| Retained leaves or nullifiers per engine | 1,000,000 |
| Canonical component encoding | 64 MiB per component |

Each frame also obeys the current canonical native body policy. Exported page
records consume at most 128 MiB in aggregate, plus bounded JSON page framing;
the explicit page cap gives an additional 171 MiB aggregate ceiling. The output
contains at most 16,384 frame files, 171 page files, one genesis file and one root
manifest. The frame-byte limit excludes this separately bounded metadata. The
comparison reads each frame twice: one native replay and one unchanged-input
check. It reads one page at a time and retains only the replay engines, bounded
assertion flags and final record. It never accumulates all frames or records in
memory.

The export opens the accepted-state database through the strictly read-only
observer. It requires complete retained frame count, authenticates the local
accepted-state seal and full compact header prefix, and checks each original
frame against its authenticated header and recorded body length. It independently
replays all frames with the native verifier, records all eleven component
oracles at each height, compares final actual component bytes, and independently
reopens the accepted state before writing the final manifest. Missing frames,
pruning, imported prefixes, authentication material or clean allocator state are
errors. The observer performs no recovery or repair.

The version-2 root manifest binds ordered, gap-free page ranges from height 1,
exact page byte lengths and SHA-256 digests, total original frame bytes, final
tip and all eleven final component oracles. Each comparison authenticates the
actual state, replays the full genesis prefix, checks every native header and
every replayed component oracle, and compares all eleven final actual component
bytes. It scans operation exclusions across the entire prefix, checks exact
public business values and nullifier assertions, then independently reopens
read-only and rechecks all pinned pages and frames. Budget, genesis,
expectations and manifest inputs are checked again before success.

The deadline is cooperative between bounded reads, authentication and native
verification calls. An external retained process-tree guardian must enforce
wall time, memory, CPU, disk floor, output and cleanup budgets around the exact
command. Native verification or database-library calls are not preempted by the
internal timer. No mining, proof generation, wallet scan, live fork recovery or
continuous-run acceptance is performed by these commands. A bounded history
export alone does not establish that a one-hour or twelve-hour run passed.


## Sequential native audit session

The Unix owner rehearsal build also provides a separately budgeted audit
session. The paged export and comparison interfaces above retain their existing
16 GiB limit. The session is one fresh process that holds one `Engine` created
from the independently pinned genesis. It natively executes every original
frame in order. Segments constrain work and retain evidence; they never select
a new replay origin. There is no resume, imported-state, prior-manifest or
execution-receipt input.

```
siworld-eng2-rehearsal --qualification-audit-session NODE RUN_ROOT NEW_OUTPUT BUDGET BUDGET_SHA256 EXPECTATIONS EXPECTATIONS_SHA256 BINDING BINDING_SHA256 --json
```

`NODE` and the absent `NEW_OUTPUT` must be separate descendants of the existing
canonical `RUN_ROOT`. Select the complete owner run root, including all retained
failed stores, signing journals, original data, binaries, wallet artifacts and
other run output. The observer reads metadata for the entire root and rejects
symlinks, hard-linked regular files, nested mounts, unsupported entries,
excessive nesting or incomplete enumeration. It does not delete any data.
Logical-byte accounting sums every regular file's full logical length, including
sparse files; directory entries have a separate complete count. Write-ahead
checks reserve a new entry and the complete planned file length.
Both authenticated source opens use the stopped node's exclusive service lease.
Source database repair, pruning and rollback maintenance are excluded.

The independently SHA-256-pinned budget has exactly the following fields. The
numbers illustrate syntax and do not establish capacity or authorize execution:

```json
{"version":1,"height":144,"maximum_total_frame_bytes":8589934592,"maximum_segment_frame_bytes":4294967296,"maximum_segment_blocks":96,"maximum_segments":32,"deadline_seconds":3600,"segment_deadline_seconds":900,"maximum_output_bytes":536870912,"maximum_run_logical_bytes":68719476736,"maximum_run_entries":200000,"minimum_disk_free_bytes":137438953472}
```

| Session input or work item | Hard bound |
| --- | --- |
| Exact accepted height | 16,384 blocks |
| Original frame bytes over the complete prefix | Explicit total, at most 64 GiB |
| Original frame bytes in each segment | Explicit maximum, at most 16 GiB |
| Blocks in a segment | Explicit maximum, at most 96 |
| Segment count | Explicit maximum, at most 256 |
| Whole session and each segment | Explicit deadlines, at most 3,600 seconds |
| Entire selected run, including audit output | Explicit logical-byte maximum, at most 64 GiB |
| Run entries and nesting | At most 200,000 entries and depth 64 |
| Free disk after a planned write | At least 128 GiB |
| Audit output | Explicit maximum, at most 16 GiB |
| One full eleven-component boundary | 1 GiB, with 64 MiB per component |
| Metadata or native-record page | 1 MiB, at most 96 records |
| Root manifest | 256 KiB |
| Genesis, budget and expectations inputs | 1 MiB, 4 KiB and 128 KiB |
| Retained leaves and nullifiers | 1,000,000 each |

A frame must fit within one segment. Segment ranges derive from actual frozen
lengths and cover every height exactly once, beginning at height 1. Source data,
all evidence and audit output must fit the complete run cap together; a nominal
64 GiB frame total does not imply that a 64 GiB database plus output fits that
cap. The exact total and segment budgets require an independent operational
execution grant. The interface supplies no default execution budget and makes
no one-hour or twelve-hour capacity guarantee. It does not throttle producers
or change work, timestamps, consensus rules or node production.

The session first reads and hashes the complete authenticated original frame
prefix, retaining bounded metadata pages. It then initializes the reference at
genesis, saves its full initial eleven-component encoding, and executes every
frame through the concrete `NativeVerifier` and ordinary `Engine::apply`.
Every native header, state commitment and eleven-component oracle is checked.
One assertion accumulator covers operation inclusions and exclusions across
all segments. The session preserves a single reference engine throughout.

After each segment it rechecks the original bytes, saves all eleven full
component encodings, and reconstructs a separate local component-codec check.
All reconstructed bytes, height, tip and cumulative work must equal the live
reference. This check does not replace that reference or admit saved state as
an execution origin. Each segment also retains the complete boundary header,
component oracles, assertion progress and the previous evidence-record digest.
These digests identify evidence; a saved record is not an execution proof.
The component codec's ordinary tests use component-only fixtures and do not
establish native block validity.

At the final exact head, the actual accepted state and its independent
read-only reopen must match every reference component byte. Exact public
business expectations, all operation assertions and final nullifier assertions
must match as well. A final complete-prefix pass against the reopened source
detects changes after earlier segments ended. Genesis, binding, budget,
expectations and every retained output are rechecked before the completion
manifest is written as the final output. The logical original-frame total
applies to each of four bounded reads: freeze, native replay, segment recheck
and final reopened-source recheck. Proof execution occurs in the native replay.

Any failure retains the partial output. Run the command only in a fresh output
directory; it cannot resume an interrupted session or consume its receipts.
A successful result requires the original process's successful exit and its
external guardian's wait, process-group, CPU, memory, disk and cleanup evidence.
A manifest alone, one segment, matching hashes or a reconstructed checkpoint
does not establish complete native execution. The internal deadlines are
cooperative around bounded operations; the retained external guardian must
preempt a stalled native or database call.

Wallet receipt scanning and private balance acceptance remain separate. The
session never loads wallet secrets, scans wallet balances, starts a node,
generates proofs, mutates chain state or grants continuous-run, G1 or G2
acceptance. Header and compact-receipt paging can support complete wallet scans
but cannot replace full native or public-economic verification.
