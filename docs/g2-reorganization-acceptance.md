# Reorganization acceptance

This procedure is an owner-operated release gate. Bounded storage and relay
tests do not substitute for actual native block proofs, independent state
checks, three simultaneously producing miners, or the continuous run below.
Never execute miners, packaging or this network campaign in Actions.

## Isolated topology and provenance

Use a dedicated rehearsal genesis, two nonmining services and at least three
outbound miners on independently provisioned machines, with distinct directories
and temporary test identities. Keep this network separate from the engineering
network. Before that hardware is ready, a local nonmining plumbing run may use
one service and one outbound nonmining resident; it cannot establish mining
throughput, stable miner concurrency or G2 completion.
Keep checkpoint signing journals outside canonical rollback storage. Record
the exact binary digest, source commit, genesis and network identifiers,
proof profile and resource limits before startup. Do not copy production
identities, chain databases, wallets or operations channels into the campaign.

The owner-local `scripts/reorg-local-network.py` tool validates a private run
marker, common genesis bytes, distinct node directories, configuration and
literal loopback endpoints. Its relay command forwards opaque encrypted
bytes and can disconnect both existing and new sessions through a local
control file. It exposes no network administration endpoint. The plan scope is `g2` for at least two services and three mining nodes, or
`plumbing` for at least one service and one nonmining outbound resident. The preflight
command starts no nodes; physical/free memory and total proving/database
resource requirements still require separate measurement. Status observations
compare fresh local heads only and deliberately never report G2 success.

Each plan contains version 1, a canonical private run root, binary path and
SHA-256, source commit, genesis SHA-256, genesis/network identifiers, minimum
free disk bytes, nodes and links. Each node supplies a neutral identifier,
role (`service` or `miner`), directory and configuration path. Each link
supplies an identifier, literal loopback listen/target endpoints and a private
control-file path inside the run root. Its control file is exactly
`{"version":1,"enabled":true}` or the corresponding false value. The run marker
`reorg-local-network.marker.json` is exactly
`{"version":1,"purpose":"isolated-reorganization-qualification"}`.

Run data and measurements remain outside version control. Record aggregate
transport bytes and timing without addresses, amounts, custody or transaction
associations. Opaque relay byte counts describe forwarded application streams;
they exclude packet overhead and do not independently establish node download
accounting.

## Required scenarios

1. Produce distinct valid blocks at the same height with at least three real
   miners. Partition and heal the topology. Verify convergence by common block
   identities and independently recomputed cumulative work.
2. Exercise depths one through 24 using persistent-savepoint ancestor restore
   followed by ordinary per-block transactional append and complete native
   verification. Verify the ancestor commitment and every adopted state
   commitment. Valid intermediate prefixes may be durable, but production,
   checkpoint signing and wallet exports remain paused during the transition.
   Record transition time separately from proof production and network I/O.
3. Exercise depths one, six, seven and 24 explicitly, including repeated
   reorganizations with real intermediate savepoints. At an old-chain rollback
   depth of 25 blocks, verify
   switching, mining and signing stop and an alert occurs. Missing savepoints or
   recovery failures preserve evidence and require manual handling; automatic
   isolated checkpoint recovery is outside this implementation scope.
4. Supply an invalid competing branch. Verify that the original canonical chain
   and all ledgers remain unchanged. The 24-block bound limits the old-chain
   rollback depth, not the length of the replacement path. Before committing
   ancestor restoration, fix the complete replacement material and prevalidate
   all of it in an in-memory Engine using native proofs and state commitments.
   Check that the same block identities, ordered headers and body bytes are used
   by subsequent appends. Exercise an old-chain rollback of at most 24 blocks
   with a replacement longer than 24 blocks and an invalid late block; the
   original chain must remain unchanged. Record separate actual evidence for
   this case; shorter-path storage prototypes do not qualify it.
   Resource-deferred verification is not a permanent consensus-invalid result.
5. Crash at named, rehearsal-only transition stages, including after ancestor
   restore, after replacement verification, before each append commit and after
   commit before in-memory publication. Reopen and independently verify a valid
   durable prefix with its matching state commitment; ordinary synchronization
   must continue from that prefix. Random process termination alone does not establish
   coverage of these transaction boundaries.
6. Independently compare rewards, reward pool, fund, fee recipient, governance,
   assets, wallet notes/spends and balances after each scenario. Exercise saved
   wallet hash disagreement, the 24-block rescan, confirmation counts and
   delayed-unconfirmed transaction rebroadcast. Do not change maturity rules.

Discard orphaned pending transactions in the initial implementation. Reinsert
only through ordinary wallet rebroadcast and native admission; automatic
transaction-pool restoration and fast deep switching are separate work.

## Continuous convergence gate

After the preceding scenarios pass, run the integrated candidate with at least
three simultaneous miners continuously for at least 12 hours. The clock starts
only after the final tested candidate is running. A previous version or an
incomplete implementation cannot contribute elapsed time. Preserve head-change,
partition, reorganization, manual-recovery-needed, crash and restart events with
monotonic durations and observation coverage. Missing observations remain
unknown. Any unresolved divergent branch fails this gate.

Record reorganization depth and ancestor. Verify the existing alert boundaries:
depth greater than six and the fourth reorganization within a rolling hour.
Measure propagation from production to acceptance by all observed nodes,
including clock-bias bounds and node coverage.

A passing campaign requires evidence for every scenario, complete state
comparisons and the full continuous interval. It does not by itself satisfy
independent proof-hiding, fee-privacy or fresh Windows bootstrap gates.


## Read-only reorganization observations

`observe` includes state availability, the reorganization status and alarm,
rollback depth and ancestor, template generation, and wallet export pause
state. A node with unavailable state or an active/manual reorganization does
not qualify as ready convergence even when its last reported head matches.
When a node run identifier is supplied in the plan, the status must match that
identifier. Fresh matching status does not establish an independently verified
state fingerprint or native block acceptance.

## Explicit production and acceptance samples

The `propagation` command reads a bounded event document inside the isolated
run root, verifies plan and binary provenance, and reports statistics without
starting nodes, opening sockets, or changing run data:

```sh
python3 scripts/reorg-local-network.py propagation "$RUN_PLAN" --samples "$EVENT_SAMPLES"
```

This command requires a campaign `run_id` in the plan and a distinct actual
resident `run_id` on each node entry. The event document has version 1,
`kind: "block-production-acceptance"`, an explicit boolean `synthetic`, and the
same campaign run, network, genesis, source commit and binary SHA-256 as the
plan. Each entry in `blocks` identifies `block_id`, `producer`,
`producer_run_id`, `produced_unix_ms` and an `accepted` list. Each acceptance
contains `node_id`, its resident `run_id`, and `accepted_unix_ms`. Repeated
observations of a node/block use the earliest explicit acceptance event.
Production is the instrumented time when a complete block becomes available
for propagation, not its claimed header timestamp or the start of proving.
Acceptance is recorded after complete native verification and durable canonical
commit, not merely receiving a header or retaining a competing body.
Production does not implicitly substitute for that producer's acceptance
event. Unknown nodes, mixed runs, duplicate block entries, nonfinite times
and local event-count limits are rejected. Plans contain at most 64 nodes;
expected node/block pairs and acceptance records are each bounded by 50000,
with at most 10000 blocks and a 1 MiB input document.

The `clocks` object maps node identifiers to a sample containing `run_id`,
`offset_ms`, `uncertainty_ms` and `calibrated_unix_ms`, or a bounded history of
at most 1000 such samples. The nearest nonstale valid sample is selected for
each event. The offset convention is local
clock minus reference clock: subtract the offset before comparing events.
The accepted-minus-produced point estimate is accompanied by conservative
lower and upper bounds using the sum of both clock uncertainties. A
calibration must be within 300000 milliseconds of the corrected event time.
This age rule assumes the supplied uncertainty covers drift over that
interval; the tool does not measure or independently attest clock accuracy.
Missing or stale calibration leaves latency unknown. Negative corrected
latencies are unknown, with separate inconsistent-order and uncertain-order
reasons; they never become zero-latency success samples.

For each block, report observed, expected, qualified and unknown node counts.
`all_nodes_latency` uses the maximum first-acceptance delay for a block only
when every expected node has an explicit event and valid timing. Its mean and
nearest-rank p50/p95/p99 therefore use only fully covered qualified blocks.
A block missing any node is excluded from this distribution.
`pooled_node_latency` is a separate distribution of qualified node/block
pairs; it is not an all-node propagation estimate. Empty distributions have
count zero and null statistics. Preserve incomplete-block and unknown-pair
counts alongside all distributions.

Synthetic input remains labeled synthetic. Other input remains
`declared-native-events`, with `event_source_independently_verified: false`.
The resident status files do not supply the required production/acceptance
event stream; native event instrumentation, collection and clock calibration
remain required before actual propagation can be reported. Status polling
and opaque relay byte counts cannot replace these events or qualify G2.

## Complete native journal validation

The independent `native-stream-integrity` entry point consumes existing local
collector snapshots. It does not load a node plan, inspect a process, contact a
host, change relay controls, open a database or execute a native verifier:

```sh
python3 scripts/reorg-local-network.py native-stream-integrity "$BINDINGS" \
  --bindings-sha256 "$BINDINGS_SHA256" --output "$NEW_INTEGRITY_OUTPUT" \
  --snapshot "$FIRST_SNAPSHOT" --snapshot "$FINAL_STOPPED_SNAPSHOT"
```

The independently pinned version-1 bindings contain the network and genesis
identifiers, exact source commit and executable SHA-256, and `nodes`. Each node
contains a unique `row`, `alias`, `node_id` and `run_id`, plus `directory` and
`unit`. The collector directory contains `index.private.json` with those exact
bindings and, under each alias, `snapshot.private.json` and retained journal
segments. The snapshot binds the same node, `status_before`, `status_after`,
`unit`, `process`, and one to four `files`. Each file entry names one of
`native-block-events-0.jsonl` through `native-block-events-3.jsonl` and supplies
its exact `local_file`, `bytes` and SHA-256. Inputs must be owned private regular
files without symbolic links or hard links. The command does not collect them.

Every snapshot must retain both status diagnostics. `native_block_events`
provides the shared recorder sequence, attempts, written count, dropped count,
marker state and fixed segment limits. `native_accept_observation` separately
provides `enabled`, `dropped_events`, `error_code`, `coverage_established` and
`scope: "ordinary-forward-admission"`. Both diagnostics must be enabled and
error-free with zero drops. A missing owner diagnostic is incomplete coverage;
the consumer never substitutes a zero. A collector that previously selected
only `native_block_events` must also retain `native_accept_observation` before
its snapshots can qualify. Collection and remote process ownership are separate
interfaces and receive no authority from this command.

Status context requires the actual network, genesis and resident run. The
resident status schema does not require source or executable fields; if either
is provided, it must match. Their absence does not weaken the mandatory source
and executable bindings in every journal record and snapshot binding.

The consumer validates all three block-event kinds before choosing propagation
samples: `native-block-produced`, `native-block-durably-accepted` and
`native-proof-rejected`. All share the same sequence and ring. Complete
start/end markers, every sequence from 1 through the end counter, exact
provenance, matching counts and complete newline-terminated records are
required. Repeated identical records across snapshots are retained once;
different bytes for the same sequence or marker are rejected. Unknown kinds,
duplicate JSON keys, nonfinite numbers, conflicting identities, missing
rollover coverage and partial tails fail closed. Recorder serialization order
does not impose monotonic timestamp order on concurrent hooks.

A rejection also binds the receiver, authenticated peer fingerprint, exact
header/block identifier, frame identifier, body commitment and byte length,
owner attempt, fixed native error code, and independent owner/stream drop
counts. Its deduplication key has five fields: kind, receiver, run, owner
attempt and frame identifier. Its schema contains no acceptance timestamp.
The recognized native relations are transaction, legacy settlement and
issuance. Parsing such a record does not independently prove a verifier result,
cover CompleteFee, establish current chain membership or qualify a competing
branch/replacement path. Exact source and artifact provenance remain external
requirements.

The output preserves every validated marker and event in `records`, with its
line SHA-256 and immutable source-file references. Only after full validation
does `earliest_logical_events` select produced/accepted rows. Repeated logical
production or acceptance uses the earliest process-local monotonic observation;
all later rows remain in `records`. Rejection rows never become acceptance
samples. The final snapshot must report the expected unit stopped, no resident
process, a written end marker and counters matching that marker. These supplied
facts do not replace an independently held native child or its termination
receipt. An incomplete/crashed stream needs a separately reviewed delimited
prefix contract; this command does not qualify it.

Bounds are 64 nodes, 1440 snapshots, 50000 source files, 50000 event sequences
per node, at most 50128 retained records including markers, 64 MiB of retained
raw record bytes, 16 GiB total input bytes read and 128 MiB serialized output.
The four native segments remain at most 1 MiB each, with records at most 2048
bytes including newline. Bindings and snapshot indexes are at most 32 KiB;
node snapshot metadata is at most 64 KiB. These are finite parser limits, not
measured RSS, throughput or proof/runtime budgets. Repeated snapshots count
against input limits; no truncation, automatic limit increase or source cleanup
occurs. The output is create-only. A successful command and complete output
still leave clock calibration, propagation statistics, native state checks and
G2 acceptance separate; `G2_case_pass` remains false.

## Nonexecuting fault capability assessment

`fault-capabilities` checks a selected node against the isolated marker,
campaign and resident run identifiers, fresh network/genesis-bound status,
frozen binary digest, node directory, and supplied same-user process facts.
The process-facts JSON must be inside the isolated root and contains `pid`,
`uid`, `run_id`, `campaign_run_id`, `executable`, `binary_sha256`,
`node_directory` and `start_token`. The actual local binary must be an owned
regular file and still match the frozen digest.

This is a supplied-facts consistency assessment. It does not inspect a live
PID, attest its executable or start time, send a signal, restart a process,
or support fault execution. Results explicitly retain
`live_process_identity_attested: false`, `signal_delivery_supported: false`
and `fault_injected: false`. PID reuse protection, an owned child-process
handle, named native boundary rendezvous, and authorized fault execution
remain prerequisites for the later isolated campaign. A matching status
snapshot or supplied start token alone cannot authorize killing a process.


## Direct-child rehearsal controller

`scripts/reorg-campaign.py` provides `topology`, `partition`, `heal` and
`run-node`. It accepts only the isolated run marker, frozen private executable
with mode 0500 and matching SHA-256, exact argument digest, owned directories,
and literal loopback topology from the plan. Partition controls are atomically
replaced individually; a change across several relays is not atomic. A direct
peer that bypasses the declared relays is rejected.

The controller holds the actual `Popen` object and a new process group. It does
not adopt PIDs or existing services. The default `status` mode validates a fresh
status PID/network/genesis and the matching run receipt's binary and configuration
digests. A restart must observe a new actual run identifier before returning.
Status observations establish neither production/acceptance events nor exact
transaction-boundary faults. Read-only database audit requires the owned node to
stop normally first. `stop_native` invokes the frozen native `stop` command with
the directory and exact run identifier and waits for its held child to exit;
forced termination cannot substitute for this audit prerequisite.

The optional `ipc` mode requires explicit native support for an inherited
socketpair, authenticated hello, ordered events, bounded clock replies, and
named boundary park/resume. Frames are limited to 16384 bytes and an absolute
five-second partial-frame deadline. The control token is ephemeral and excluded
from recorded events. The supported names cover restore/append before commit,
after commit, after publication and after capture, plus replacement prevalidation
and branch archive commit. A fault requires the exact armed boundary, height,
run and owned process; the controller then kills and reaps only that owned group.
A synthetic implementation of this protocol does not qualify a native boundary.

Child stdout, sanitized events and resource observations remain in the private
run directory. A resource guard samples owned-group RSS, all output bytes,
host disk, pressure-based available memory and monotonic progress. It does not
provide operating-system hard RSS limits. macOS observations preserve both
`vm_stat` and `memory_pressure -Q`; available bytes use the pressure-reported
free percentage and physical memory. Free, speculative and inactive pages are
not simply added together. Linux uses kernel `MemAvailable`. A missing or denied
sample stops rather than treating memory or RSS as zero.

For the bounded depth campaign, startup requires at least 96 GiB free disk and
8 GiB pressure-based available memory. Stop below 32 GiB free disk or 8 GiB
available memory, above 16 GiB output per depth or 64 GiB for the campaign, or
above 12 GiB aggregate sampled RSS. The two active producer groups may use
4 GiB each; the paused third producer and each nonmining service may use 1 GiB
each. Each miner has Rayon configured to four workers and composition hiding
to two; these settings do not describe the total thread count. Startup is
limited to 120 seconds, no-progress time to 180 seconds, each depth to
1800 seconds and the six-depth sequence to 10800 seconds. Sampling failure,
a native error or incomplete owned-group cleanup stops the sequence. No automatic
retry or budget increase is permitted. `run-node` is a bounded single-depth
observation command, not the 12-hour continuous qualification runner.

Checkpoint peer pins use the native public-identity interface. Write the target
node's `identity-public` JSON, containing exactly `version`, `fingerprint` and
`descriptor`, to a private campaign file, then pass that JSON and fingerprint to
`peer-pin` with the expected genesis. A raw descriptor binary or a larger setup
result is not accepted as a peer-pin file. Peer configuration must refer to the
same initialized target identity; never copy a production identity into the run.

Before healing a partition, stop owned nodes normally and export both canonical
branches with the native read-only audit. Preserve raw frames, manifests,
component hashes, ancestry and cumulative work before the losing branch can be
removed from canonical indices. Restart the same directories at the fixed
production caps, heal relays, stop normally again, and independently audit all
resulting states. A 25-block protection case expects manual recovery, stopped
production/signing and an alert; it must not be scored as failed merely because
it deliberately does not switch or converge. These material-production runs do
not substitute for the final candidate's full-state, boundary-crash or continuous
convergence qualification.
