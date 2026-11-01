# Native V1 Node Operations Boundary

Status: native V1 node and network integration is incomplete. The isolated
proof executable is not a node runtime, and no native V1 deployment command is
available. The existing node executable runs the
[legacy recursive route](legacy/node-operations.md).

## Roles and platform qualification

Every full validator independently enforces consensus. A miner adds block
production, padding preparation and native settlement proving. There is no
privileged main node. Discovery services and the control panel are operational
services outside consensus.

The minimum CPU configuration is at least four available vCPUs and fixed
`x86-64-v3` release builds with AVX2 and CPU/OS-state admission checks. The
Linux collector requires Ubuntu 24.04 and cgroup v2. Advertised minimum RAM
is 16 GB for validators and 32 GB for miners; memory admission requires at
least 15 GiB / 30 GiB of system-visible memory respectively, including visible
deployment cgroup limits. The actual CPU model and resource allocation
must be recorded without a model requirement. These admission floors do not
establish sustained workload acceptance. The isolated 5-GiB proof cgroup does
not replace node/miner RAM requirements. macOS/Apple Silicon and Windows require separate
native packaging, crypto vectors, isolation, storage/recovery and load tests.

Both node roles use a 500-GB usable SSD installation floor and 1-TB
recommendation. This does not guarantee full-load lifetime; permanent public
data grows while proofs roll through three days after final confirmation.
The conditional minimum uplink is 43 Mbps with 100 Mbps recommended. See
[deployment qualification](v1-deployment.md), [wire budget](v1-network-budget.md)
and [storage model](v1-storage-and-sync.md).

## Integration and recovery requirements

Native release packaging must bind the accepted network identity, suite,
source/dependency hashes, trusted verifier artifacts and explicit checkpoint
trust policy. Operators must distinguish proof tools, a native runtime and a
legacy runtime; one cannot substitute for another. Start only reviewed native
deployment artifacts after the [acceptance gates](prover-acceptance.md) pass.

Public health telemetry must be authenticated, bounded and private to the
operator. It may report progress, resource pressure, stale samples and durable
incidents; it must not disclose fee openings, sender endpoints, transaction
classifications or payment associations. Panel actions cannot change
consensus validity or justify automatic destructive recovery.

Native reset, pause/resume and recovery interfaces require explicit state and
network identity checks, operation serialization, durable results and key/data
preservation. Existing legacy operational commands do not establish these
native features. See [implementation milestones](v1-node-network-plan.md) and
[RPC requirements](rpc.md).
