# Isolated native production controls

Unix builds with both `eng2-runtime` and `eng2-rehearsal` support an explicitly selected local production policy. The policy accepts only a nonfixture genesis with `pow_iterations = 1`, the maximum initial target, the normal target interval and production economics. It changes the local producer's permission to prepare and accept work. Incoming block validation, proof verification, chain selection, automatic reorganization depth, identities, peer endpoints and checkpoint signing remain governed by their existing interfaces.

Initialize the policy before the first block, while the authenticated node is stopped:

```text
siworld-eng2-rehearsal --isolated-production-init EMPTY_NODE MANIFEST MANIFEST_SHA256 --json
```

The manifest is strict JSON with these fields:

| Field | Value |
| --- | --- |
| `version` | `1` |
| `purpose` | `isolated-native-production` |
| `campaign_sha256` | Independently checked campaign manifest SHA-256 |
| `network_id` | Exact genesis network identifier |
| `genesis_id` | Exact immutable genesis identifier |
| `rules_commitment` | Exact immutable rules commitment |
| `proof_profile` | Compiled proof profile fingerprint |
| `maximum_height` | Integer from 1 through 1,000,000 |

Digest fields use nonzero lowercase hexadecimal. The manifest has an 8,192-byte limit. The node and control directories must be canonical, same-owner directories with mode `0700`. Inputs and records must be ordinary, single-link files with mode `0600`. The manifest is installed atomically in a new `isolated-production` directory and cannot replace an existing policy. Initialization checks an authenticated empty store and does not generate an identity or change chain state.

Set `SIWORLD_ENG2_ISOLATED_PRODUCTION` to the independently checked installed manifest SHA-256 when starting the resident. An initialized node rejects startup without the matching selection, and a runtime build without this interface rejects a selected or initialized policy. Each new actual resident run starts paused at revision zero; an earlier run's requests cannot resume it. The build must declare `SIWORLD_BUILD_COMMIT`, and runtime requests bind the actual resident binary SHA-256. A source declaration and a digest do not independently establish build provenance.

Install one request with:

```text
siworld-eng2-rehearsal --isolated-production-request NODE REQUEST REQUEST_SHA256 --json
```

The request has exactly these fields:

| Field | Value |
| --- | --- |
| `version` | `1` |
| `manifest_sha256` | Installed manifest SHA-256 |
| `run_id` | Actual current resident run identifier |
| `source_commit` | Compiled source commit, 40 lowercase hexadecimal characters |
| `binary_sha256` | Actual resident executable SHA-256 |
| `revision` | Next consecutive integer, starting at 1; maximum 1,000,000 |
| `expected_height` | Actual current canonical height |
| `expected_tip` | Actual current canonical tip identifier |
| `paused` | Boolean |
| `stop_height` | Integer not exceeding the manifest maximum |

A resume request requires `stop_height > expected_height`. A pause request may retain the previous ceiling or use zero. Both heights must stay within the manifest maximum. The resident validates the run, build, manifest, next revision and bounds before comparing the expected height and tip with the canonical head. It processes at most the next consecutive revision per poll. Installing a request reports `acknowledged: false`; wait for the matching immutable result before treating a pause or resume as applied.

Requests and results use `request-RUN-REVISION.json` and `result-RUN-REVISION.json`, with the revision represented as sixteen decimal digits. Both are installed atomically without replacement. An applied result records the request digest, actual height and tip, requested pause state and ceiling. A fully authenticated next request whose expected height or tip no longer matches the head produces `status: rejected`, `reason: head_compare_failed`, `paused: true` and `stop_height: min(previous_stop_height, current_height)`. This consumes the revision and request digest without granting permission or marking the control failed. Repeated polls verify the consumed request digest and do not rewrite its result. Production stays paused until a new consecutive request matches the current head and receives an applied acknowledgement; earlier work revisions remain invalid. No automatic retry or request replacement occurs.

Malformed requests, invalid identities, manifests, revisions or bounds still produce a rejection and terminate production. Missing or changed manifests, changed consumed requests, file permission failures and result-write failures also terminate production. Networking continues under the existing resident failure policy. A rejected request is never an applied acknowledgement or a new lease grant; an external lease controller must reconcile its immutable result and retain deadline enforcement.

The producer checks permission before expensive prover initialization, padding preparation, padding insertion, block preparation, work preparation, each bounded nonce chunk and final local acceptance. A policy revision change invalidates earlier work. Final permission and acknowledgement processing occur under the same canonical owner lock as acceptance. A pause acknowledgement therefore precedes any later acceptance decision. It does not imply that an already running proof was interrupted immediately.

The maximum is a ceiling on local production. Receiving and validating a peer's chain can advance the node beyond it. At the ceiling, `isolated_production_control.production_allowed` becomes false in resident status. The status also exposes the consumed revision, request digest, pause state, ceiling, failure flag and selected manifest digest. A consumed revision can have a rejected result; consult its immutable result before treating it as an applied policy. Status is a current observation; the immutable result preserves acknowledgement. Filesystem operations are byte bounded, but their latency is not given a hard real-time bound.

A depth exceeding twenty-four persists an immutable local refusal record in the separate branch archive before returning the refusal. The record binds the complete header rules, canonical tip and height, selected candidate, common ancestor and removed depth. Startup validates this record and its retained path before enabling activities. Unknown schemas, malformed fields and changed canonical or retained context fail closed. A refusal write failure leaves the current run stopped. Repeating the same record is idempotent; there is no clear or reset API. This record is local policy and does not prove native validity of the selected candidate. The automatic reorganization window remains twenty-four blocks.

These controls do not supply a recovery command for a stopped database. Preserve the stopped database and evidence. Recovery into a separately initialized authenticated empty node may use unchanged, independently audited native frames through the qualification replay interface, followed by authenticated restart and full state comparison. The existing prefix replay interface is limited to ninety-six blocks and is not a general long-history recovery interface. The refusal record does not replace independent corpus verification or full recovery acceptance.
