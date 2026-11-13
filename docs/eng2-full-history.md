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
