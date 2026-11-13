# Native block event observations

The engineering resident records two block event types separately from its
periodic status snapshot. Neither type establishes readiness, finality, current
chain membership or complete observation coverage.

`native-block-produced` is observed immediately when the native producer returns
`Search::Found`, before progress counters, phase export or local admission. The
candidate's native proof and execution template were verified by
`ProvedBlock::prepare_work`; nonce search then found valid proof of work. The
block can subsequently become stale or fail local admission. This event does not
assert that the producer accepted or propagated it. Its time is not the header
timestamp, proof-generation start or status-poll time.

`native-block-durably-accepted` is observed in `Store::append` immediately after
the canonical redb transaction commits successfully with immediate durability.
Complete native block verification and state staging precede that commit. The
same hook covers peer admission, local admission and each adopted replacement
block: `append_prevalidated` still calls the ordinary fully verified `append`.
Header discovery, competing-body retention, replacement prevalidation, ancestor
restoration, checkpoint import and authenticated startup do not emit acceptance
events. In-memory publication and rollback-savepoint capture occur after this
hook and can still fail. The event proves the verified database commit boundary;
it does not prove subsequent publication, eventual readiness or permanent
membership of the canonical chain. A later reorganization can remove that block.

## Process and source bindings

Every block event has version 1 and `record: "block-event"`. Its immutable
process bindings are `network_id`, `genesis_id`, `node_id`, `run_id`,
`binary_sha256` and `source_commit`. The node identifier is the fingerprint of
the existing loaded native peer identity. It is not a wallet or reward address.
The run identifier comes from the actual resident `RunIdentity`. The binary
digest is computed from the running executable at startup.

`source_commit` is the valid lowercase 40-digit compile-time
`SIWORLD_BUILD_COMMIT` declaration, or null when unavailable or malformed. It is
never taken from a runtime environment variable. The declaration is not source
attestation: `source_commit_externally_verified` remains false. A collector must
match the executable digest, declared commit, exact source state and build
receipt before attributing results to a candidate. A declared commit alone
cannot qualify a dirty build or replace artifact provenance. The recorder uses
`event_source: "native-runtime-hook"`; that identifies the code path, not an
independent attestation of collected files.

Events contain block identity, height, type and sequence, without block bodies,
transaction identities, amounts, wallet data, secret material or peer endpoints.
The logical deduplication key is `(kind, node_id, run_id, block_id)`. Each event
attempt receives an increasing sequence within the run. Reaccepting a previously
removed block may produce another record with the same logical key and a new
sequence. Keep the earliest qualified event for propagation statistics, while
retaining later records for chain-history analysis. No unbounded in-memory
deduplication set is kept. Sequence numbers describe recorder serialization
order. Concurrent hooks sample their times before acquiring the recorder lock,
so timestamp order need not match file sequence order.

## Clocks and propagation input

`event_unix_ms` is sampled from `SystemTime` at the native hook before recorder
locking and file I/O. Produced and accepted records respectively also expose
`produced_unix_ms` and `accepted_unix_ms`. If wall time is unavailable, those
fields are null. `elapsed_monotonic_ns` is a decimal string measured from this
recorder's process-local `Instant` origin. It orders local observations across
wall-clock corrections; it cannot be subtracted across machines or runs.

The recorder does not measure clock offsets or accuracy. `clock_offset_ms` and
`clock_uncertainty_ms` remain null, and `clock_calibration_measured` remains
false. A separate collector must measure bounded clock offsets and uncertainties,
associate samples with actual node runs, and account for drift. For the existing
`reorg-local-network.py propagation` input, supply each node's `run_id`,
`offset_ms`, `uncertainty_ms` and `calibrated_unix_ms`. The offset convention is
local clock minus reference clock. The existing summarizer requires a valid
sample within 300000 milliseconds of each corrected event time.

After checking provenance and stream integrity, a collector maps public node
fingerprints to independently pinned campaign aliases, groups records by block
identity, and builds the existing `block-production-acceptance` document. Use
the producer's explicit produced event and each node's explicit accepted event.
Production never substitutes for that producer's acceptance event. The campaign
run identifier is collector metadata, distinct from each actual resident run.
Keep `synthetic` truthful and preserve source-file hashes and the alias mapping
outside the statistics document. This module neither collects remote files nor
performs that conversion, clock calibration or independent verification. Status
heads and relay byte counts cannot supply missing native events.

## Bounded retention and incomplete observations

Each node uses exactly four reserved filenames,
`native-block-events-0.jsonl` through `native-block-events-3.jsonl`. Each segment
is at most 1048576 bytes and each complete record, including its newline, is at
most 2048 bytes. Files are private, and Windows uses the existing protected-file
API. No per-run directory or unbounded event queue is created. A new run starts
in the first absent slot, or replaces slot zero when all four already exist. It
never appends after a possibly interrupted record from an earlier run. Subsequent
rollovers replace the next slot. Oversized, symbolic-link or nonregular reserved
paths are rejected rather than repaired or truncated at startup. Old JSON
contents are not treated as authenticated input by the writer.

The recorder writes `record: "stream-marker"` metadata for
`native-event-stream-start` and, after network and producer workers join,
`native-event-stream-end`. These markers are not block events. The end marker
records event attempts, written events and dropped events. Every record is
flushed with `sync_data`. This adds synchronous diagnostic I/O at the observed
edge; the overhead has not been measured. A crash can leave a partial last
record, an absent end marker, or a committed block whose event was never written.
No exactly-once, power-loss or complete event-capture guarantee is claimed.

The independent `native_block_events` status diagnostic exposes start/end-marker
success, event attempts, written/dropped counters, segment rollovers, prior-slot
replacement and fixed error codes. It always reports
`coverage_established: false`. An I/O error disables further writes in that run,
preserves a fixed diagnostic and increments dropped-event counts on subsequent
attempts. It does not change block admission, append results, rollback, chain
selection or the existing status readiness fields. There is no retry that could
turn a partial record into an apparently valid event. A recording error also
prints one fixed error code without paths or private context.

Collectors must fail closed on missing markers, sequence gaps, malformed tails,
failed writes, unavailable diagnostics, mixed identities or missing timing.
Zero observed events is not evidence of zero actual events. Complete coverage
requires validated start/end markers or an independently delimited complete
prefix, matching counters, all required sequences and provenance, and no
unaccounted discarded segments. A rollover requires previously collected and
hashed segments to bridge the sequence range; otherwise retained records are
partial observations. Missing calibration leaves propagation latency unknown.
Neither the recorder nor the existing propagation summarizer certifies stream
integrity automatically. The collector is responsible for excluding incomplete
or unauthenticated input before producing all-node coverage statistics.

## Validation boundary

The small recorder tests use temporary private files and synthetic identifiers.
They cover event schemas, identity bindings, sequence/deduplication behavior,
unknown clocks, segment limits, interrupted records, rejected oversized logs and
write-failure diagnostics. They do not generate proofs, search nonces, open
network sockets or run a node. Source-level hook inspection and these tests do
not replace an integrated native production/peer/reorganization run, collection
and clock qualification, Windows execution, crash or power-loss testing, or G2.
