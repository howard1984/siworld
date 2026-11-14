# Live reorganization control consumption

The `live-contract` entry point in `scripts/reorg-campaign.py` reads an
independently SHA-256-pinned local proposal and reports requirements. An optional
`--inert-trace` with `--trace-sha256` checks a synthetic control-flow model.
It starts no process, opens no socket, changes no relay control and reads no
native block, proof, database or custody. The existing fixture-only height
ceiling and loopback/IPC paths retain their original behavior.

```sh
python3 scripts/reorg-campaign.py live-contract "$PROPOSAL" \
  --input-sha256 "$PROPOSAL_SHA256" \
  --inert-trace "$MODEL_TRACE" --trace-sha256 "$MODEL_TRACE_SHA256"
```

The proposal and trace use control-consumption formats, separate from native wire records.
A read-only snapshot adapter also checks the isolated production interface's
manifest, requests, CLI installation outputs and immutable results. This is
source-level schema support; a qualified native build, actual origin and live
transport integration remain pending. `production_allowed`,
`native_controls_available`, `live_case_pass` and `G2_case_pass` remain false.
Model booleans and reference hashes never establish a real capability. A
live adapter needs registration, exact source and
executable bindings, actual resident identity, and independent operator review.

The proposal has version 1 and format
`live-control-consumption-proposal`. Its context binds campaign, case and
attempt identifiers; source commit and executable SHA-256; network, genesis,
rules commitment and proof profile; distinct node/run identities and two
partition groups. It supplies a common ancestor's height, block identifier and
cumulative work, one producer in each group, and depth 1, 6, 7, 23, 24 or 25.
Each group must include a miner and a service; the full topology contains at
least three miners and two services. Other miners remain paused during this
controlled two-producer case. This does not satisfy the separate requirement
for at least three simultaneous miners, actual competing blocks, or the final
continuous multi-miner interval.

The intended real profile is nonfixture production economics, minimum supported
positive work, maximum target, `pow_iterations=1`, `work_bits=0` and a 300-second
target interval. A supplied `fixture=false`, matching hash, positive model
integer or model trace cannot authenticate those properties. The actual
sealed genesis and native profile/proof validation must establish them before
live production. A fixture with zero PoW iterations is never nonfixture
evidence. A new native control implementation needs a new qualified candidate
and artifact provenance; earlier binaries cannot be relabeled.

For ancestor height H and rollback depth d, the old side stops at H+d and the
greater-work side at H+d+1. Depth counts removed old-chain blocks, not replacement
length. The model checks every relative parent link, exact height, distinct block
identity and strictly increasing cumulative work. The candidate must have
greater cumulative work; a larger height alone is insufficient. Actual work
must be independently checked by the native implementation using original
headers and full proofs, not inferred from model arithmetic or status.

The ordered consumption gates are:

1. All nodes agree on the same authenticated ancestor. All producers report
   quiescence, including cancellation/join of in-flight workers and templates.
2. The independent timer-heal is armed before partition. The exact topology
   has no bypass; actual per-host partition timing and receipts are retained.
3. Bound only the two selected producers to their finite target heights and
   resume through actual native controls. Serialize changes with admission.
   A newer control revision invalidates stale work at the native permission
   checks, including the check before final local acceptance. It does not prove
   that an already running proof was immediately interrupted.
4. Each side reaches its exact committed head. Native stop acknowledgments
   establish the requested pause before later local acceptance decisions under
   the canonical owner. They do not independently establish producer quiescence
   or joined in-flight workers. Those require separate retained-owner evidence.
   A status height or `mining=false` alone does not establish this gate.
5. Before heal, retain complete original frame/proof archives for both branches
   and full authenticated history/state audit pointers for every node. Reference
   completeness and all eleven actual state components require the qualified
   native audit adapter; model hashes are placeholders only. Never rewrite old
   headers, bodies, proofs, identities or signing journals to create a case.
6. Heal through the existing authorized owner. Verify drop rules are absent,
   the base firewall is unchanged, and all intended peers reconnect. Keep
   producers paused while reconciliation is observed.
7. For depths 1 through 24, use one path: restore the fork savepoint and append
   every replacement block through ordinary `Store::append`, checking complete
   native validity and state fingerprints. Retain full post-heal audits and
   reconcile every node to the greater-work branch. Depths above six require
   the corresponding alarm evidence. Missing savepoints, fingerprint mismatch
   or switching failure remain paused and require supported manual recovery;
   this contract introduces no automatic checkpoint recovery.
8. After material/state reconciliation, a separate native release may resume
   producers using templates bound to the adopted head. Depth 25 instead
   refuses before switching, pauses affected mining/signing, preserves canonical
   state and raises a persistent alarm. The model has no release step for 25.
   Its separate manual recovery must use the supported new-directory ordinary
   replay, authenticated restart and complete state audit. It must not silently
   reset, delete, edit or overwrite the existing database.

Every model phase repeats the immutable case context and all node/run bindings.
Its `origin` must be `inert-model`; real/native origin labels are rejected.
The model requires an uninterrupted phase prefix, complete raw-material/audit
reference maps, and explicit quiescence, cancellation and heal conditions.
Failed prerequisites cannot authorize a later phase. The input limit of 1 MiB
bounds this metadata/model parser, not native proof or raw archive sizes.
Model cumulative work is canonical unsigned decimal bounded to 512 bits.
Proposals contain at most 64 nodes and traces at most eight phases. No retry,
budget increase, actual mining, process adoption or remote operation is granted
by this interface. Node convergence, invalid-branch and crash handling,
economics/wallet reconciliation and the continuous run remain actual G2 gates.

## Native record snapshot adapter

The optional `--native-control-snapshot` and `--control-sha256` arguments extend
the read-only `live-contract` entry point. They do not install a manifest,
submit a request, start a resident or poll one. The snapshot envelope uses a control-consumption
format with version 1, format `native-control-record-snapshot` and origin
`offline-schema-snapshot`. Other origin claims are rejected. It also contains
an independently checked `campaign_sha256`, a proposal `node_alias`, the
canonical `control_directory`, pinned `manifest` and `initialization_output`
references, and at most 64 ordered `events`. Each event has pinned `request`
and `installation_output` references and a pinned `result` or null. A reference
has exactly `path` and `sha256`; the digest binds the original file bytes.
CLI-output paths are snapshot capture paths, not native control filenames.

```sh
python3 scripts/reorg-campaign.py live-contract "$PROPOSAL" \
  --input-sha256 "$PROPOSAL_SHA256" \
  --native-control-snapshot "$SNAPSHOT" --control-sha256 "$SNAPSHOT_SHA256"
```

The native manifest has exactly `version`, `purpose`, `campaign_sha256`,
`network_id`, `genesis_id`, `rules_commitment`, `proof_profile` and
`maximum_height`. Version is 1, purpose is `isolated-native-production`, and
the maximum is an integer from 1 through 1,000,000. Network, genesis, rules and
profile must match the proposal. Digests are nonzero lowercase hexadecimal.
The `native_initialization_contract` helper prepares these values in memory
and lists unmet prerequisites; it performs no initialization. Authentication of
an empty state, a stopped node with an exclusive service lease, an absent
control directory and a qualified Unix runtime/rehearsal build remain required.

The actual initialization CLI is
`siworld-eng2-rehearsal --isolated-production-init EMPTY_NODE MANIFEST MANIFEST_SHA256 --json`.
Its output has exactly `version`, `manifest_sha256`, `initial_policy`,
`chain_modified` and `identity_created`. The checked values are version 1,
policy `paused`, and both modification flags false. Matching output alone does
not authenticate the node's state or prove that this command ran. Starting a
resident also requires the exact installed digest in
`SIWORLD_ENG2_ISOLATED_PRODUCTION`. Every actual resident run begins paused at
revision zero; requests from an earlier run cannot resume it.

A native request has exactly `version`, `manifest_sha256`, `run_id`,
`source_commit`, `binary_sha256`, `revision`, `expected_height`, `expected_tip`,
`paused` and `stop_height`. The adapter binds the current proposal's actual run,
source and binary identities, the raw manifest digest, and consecutive revisions
starting at 1, with a maximum of 1,000,000. Native expected height is an integer
from 0 through 1,000,000 and expected tip is a nonzero digest. Pause is a strict
Boolean. Resume requires a finite ceiling above the expected height and no
higher than the manifest maximum; pause may use a zero ceiling. The
`prepare_native_request` helper returns a checked object only. The caller must
retain and pin the exact serialized bytes before any future submission.

The actual request CLI is
`siworld-eng2-rehearsal --isolated-production-request NODE REQUEST REQUEST_SHA256 --json`.
Its installation output has exactly `version`, `run_id`, `revision`,
`request_sha256`, `installed` and `acknowledged`. A successful installation has
`installed=true` and `acknowledged=false`. The snapshot rejects an installation
output that claims acknowledgement. It never infers an acknowledgement from a
resident status, height, current pause flag or production flag.

Native filenames are `request-RUN-REVISION.json` and
`result-RUN-REVISION.json`, where the revision uses sixteen decimal digits.
They reside beside `manifest.json` in the `isolated-production` directory.
The native writer installs records atomically without replacement. The
snapshot adapter consumes each path only once, requires the exact expected filename
and then rechecks every file's descriptor identity and original-byte digest.
It never replaces an existing request. Reusing a path, skipping a revision,
using an earlier run or changing bytes/inodes during consumption fails closed.

An immutable applied result has exactly `version`, `run_id`,
`manifest_sha256`, `source_commit`, `binary_sha256`, `revision`,
`request_sha256`, `height`, `tip`, `paused`, `stop_height` and `status`.
Its status must be `applied`; every identity, requested pause state, ceiling,
actual height and tip must match the corresponding request. Only this matching
result yields `record_acknowledgements[].acknowledged=true`. That value means
the copied record contents are consistent. It does not independently establish
native origin, build provenance, producer quiescence or operational permission.
A rejected result replaces `paused` and `stop_height` with
`reason=invalid_or_stale_request` and has status `rejected`. It never acknowledges
or advances the applied revision. A rejection or a missing result is terminal
within the snapshot; later records cannot claim progress past it. A rejected
next request terminates native production until a new authenticated resident
run. Existing networking remains governed by the resident's failure policy.

Native record reads are limited to 8,192 bytes, including the complete JSON.
They require a canonical, owner-only mode-0700 parent directory and a regular,
single-link, owner-only mode-0600 file. Descriptor-bound reads reject symlinks,
wrong ownership or modes, oversized data, duplicate JSON keys and changed file
identity or bytes. A second read catches replacement during this snapshot.
These observations do not prove historical immutability, retained remote
custody or the source of files created before the read. The envelope and all
capture files are metadata; no native database, block frame, proof or identity
file is opened.

All snapshot outputs retain `production_allowed=false`,
`native_controls_available=false`, `native_receipts_verified=false`,
`producer_quiescence_verified=false`, `live_case_pass=false` and
`G2_case_pass=false`. A source-level schema match cannot relabel an older binary
as a qualified control build. New native controls require their own exact
source, required CI and binary provenance. Full raw-branch and state audits,
the greater-work choice, depths 1 through 24 using savepoint restore plus
ordinary append, depth-25 refusal and supported manual recovery, at least three
simultaneous miners and the continuous twelve-hour gate remain separate.
