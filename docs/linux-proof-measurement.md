# Linux Native Proof Process Measurement

Status: isolated native transaction, settlement and issuance measurement
procedure. A process-tree diagnostic does not establish a full-node RAM
requirement, standalone verifier bound or testnet acceptance. Native V1
integration and independent review remain separate gates.

## Baseline and comparison hardware

Use the [minimum deployment configuration](v1-deployment.md#minimum-host-configuration):
x86-64-v3 CPU/OS support, at least four available vCPUs, and advertised RAM of
16 GB for validators or 32 GB for miners. Require at least 15 GiB / 30 GiB of
system-visible memory respectively, including visible deployment cgroup
limits. The collection adapter requires Ubuntu
24.04 and cgroup v2. Record full `lscpu`, exposed core/socket/logical topology,
affinity, VM detection, actual CPU model and ISA flags, RAM, OS/kernel and
resource constraints before each series. CPU vendor, model, exact topology and
virtualization are measurement metadata, not admission requirements. Preserve
the non-secret `GITHUB_ACTIONS` marker through the privileged supervisor.

Historical EPYC 7763 measurements used an Ubuntu 24.04 Microsoft VM exposing
two cores and four vCPUs; EPYC 9V45 records are comparison measurements. Frozen
model-specific collector profiles remain available to reproduce that evidence,
but do not define current hardware qualification.

The original short-lived runner is no longer available. A replacement requires
fresh qualification, and its results identify that new allocation. All three
trials of a configuration must run on one live machine; different jobs or VM
allocations must not be described as the same machine. VM-visible cores do not
prove physical host core count, exclusive access or identical contention. A
missing CI marker means unknown context, not a non-CI host. A new allocation's
results must retain its own measurement environment and qualification evidence.

## Hosted native diagnostics

The native cgroup workflows run on Ubuntu 24.04 and record actual CPU model,
topology, x86-64-v3/AVX2 features and VM context. Generic runner labels do not
establish minimum CPU or role memory compliance. Build release proof tools with pinned
dependencies and fixed x86-64-v3, never `target-cpu=native`. Check the generic
CPU/OS-state guard and inspect actual proof arithmetic for AVX2 instructions.

`scripts/measure-native-cgroup.py` creates three fresh process-tree scopes per
proof kind using `systemd-run --scope -p MemoryMax=5G -p MemorySwapMax=0`.
A small privileged recorder remains inside its owned scope until kernel
`memory.peak`, `memory.events`, CPU counters and exact limits are saved.
The proof child drops privileges; recorder evidence survives a killed proof.
Each lifetime peak includes setup, generation, verification and the recorder.
It is not a generation-only or verifier-only peak. All descendants remain
inside the scope. Never change unrelated host scopes or CPU/VM limits.

Attempt every declared trial. Missing counters, a failed proof, OOM/limit
events, timeout or surviving descendants fail the diagnostic after evidence
is retained. Upload only inspected allowlisted CPU/kernel counters, executable
identities and stage aggregates; exclude raw proof logs, openings and local
paths. A build/startup failure must retain its explicit failure status.

The 5-GiB zero-swap setting is a diagnostic boundary, not a miner RAM floor or
a formal production limit. [Multi-asset measurements](v1-multi-asset-evaluation.md)
and the [source-bound profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
identify accepted source, actual AIR, parameters and measured samples. An older
two-output or recursive executable cannot reproduce the current relation.

## CPU, timing and memory attribution

Record effective affinity/cpuset, quota, every visible ancestor's `cpu.max`,
`cpu.stat` and throttling, worker settings, source/dependency hashes and binary
identity. Report process/cgroup CPU seconds beside wall time. CPU seconds per
wall second estimate effective cores, not a precise count of active threads.
A VM-visible topology does not prove dedicated physical cores.

Record one-time preparation, generation and verification separately for each
trial; report all three values, medians and maxima. Measure single-worker
verification in a separate process rather than labeling a call in a four-worker
process as single-worker qualification. Process peaks from setup/prove/verify
cannot be split into per-stage peaks without additional instrumentation.

A phase sample may miss an allocation spike. Reconcile samples with the kernel
lifetime peak, identify overlapping prepared-key/workspace/buffer residency and
never sum overlapping estimates. Three successful runs do not bound grinding
tails or shared-host contention. Native acceptance must also qualify malformed
proof decoding, isolated verifier limits, simultaneous workers and whole-node
load, storage maintenance, operating-system reserve and recovery.

## Legacy and V2 controls

The D4 scalar-versus-AVX2 controls validate instrumentation only. The recursive
N=16 leaf/merge/root procedure and its old experimental limits are preserved
in [paused recursive measurement](v2/linux-recursive-measurement.md). They do
not define native V1 latency, memory or capacity acceptance. Follow
[native testnet acceptance](prover-acceptance.md) for the complete release gates.
