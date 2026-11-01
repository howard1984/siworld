# Node Operations

> **Superseded by V1 (Route A).** This page documents the legacy recursive implementation. The retained seven-node N=2 engineering testnet uses this classical proof route; it is not a native V1 testnet or post-quantum acceptance result. See the [current V1 overview](../v1-overview.md).

## Build

The controlled release packager below supports Linux x86_64. Other platform
adapters require separate packaging and qualification.

```sh
python3 scripts/build-prover-release.py --output .local/prover-release
python3 scripts/check-node-features.py
export PATH="$PWD/.local/prover-release/bin:$PATH"
```

The release package contains a generic-baseline launcher and a separate
x86-64-v3 worker. Start the packaged `bin/siworld-node` entry point; do not start
the internal worker directly. A Cargo build of the worker alone does not provide
the portable startup check. Default node binaries enable Plonky3 and reject mock networks. Explicit `development` builds support forgeable mock proofs. All-features builds are for verification, not deployment. Secret-file checks are implemented on Unix; unsupported adapters fail closed.

## Miner hardware requirements

The x86_64 release baseline is **x86-64-v3**. AVX2 is a minimum requirement;
AVX2 alone does not describe the entire v3 feature set. The CPU must also expose
the remaining x86-64-v3 instructions, including FMA, BMI1/BMI2, F16C, LZCNT and
MOVBE, with operating-system support for AVX register state. Virtual machines
must expose the required features to the guest. The generic-baseline launcher checks the CPU and OS-state support before
executing the internal worker and rejects an unsupported CPU with an explicit
error. It has no environment override or scalar fallback. Directly starting
the internal v3 worker is unsupported because it bypasses this admission check. The release build uses the fixed v3 target rather than
`target-cpu=native`, and release verification checks the actual proof binary
for AVX2 instructions.

AArch64 has a separate build target and requires its own hardware/resource
qualification. Historical M1 measurements do not qualify every AArch64 machine.
Native V1 hosted proof measurements used a 5-GiB zero-swap cgroup; that
boundary does not set minimum miner RAM. The [deployment profiles](../v1-deployment.md)
start qualification at 16 GiB for a full validator, 32 GiB for a miner and
500 GB usable SSD minimum and 1 TB recommended, with 100-Mbps uplink
recommended over the 43-Mbps minimum derived from the frozen proof cap and
[complete bounded wire budget](../v1-network-budget.md).
These admission floors do not establish sustained workload acceptance. Account separately for
prover, node, verifier, OS, caches, maintenance and reserves, then qualify the
aggregate under sustained maximum load. macOS and Windows require separate
packaging and resource/recovery qualification. Do not change retained-network
container or VM limits to accommodate new workers.

Historical Linux D8 measurements used an EPYC 7763 Ubuntu 24.04 Microsoft VM
exposing two cores and four vCPUs; EPYC 9V45 measurements provided a comparison.
These describe measurement environments without imposing a CPU-model requirement.
Current qualification checks x86-64-v3 CPU/OS support, at least four available
vCPUs and the role memory minimum. Record the actual machine before each
three-trial series without claiming dedicated host cores or full-node acceptance.
See the [qualification procedure](../linux-proof-measurement.md#baseline-and-comparison-hardware)
and [production acceptance plan](../prover-acceptance.md).

## Native V1 bandwidth target

Capacity stays **576 positions per 300-second target block**. The selected
transaction profile prioritizes at most two-second generation using four
workers on minimum-qualified hardware. Its admission cap includes at least 10% over the largest
measured proof body, rounded up to 64 KiB. The
[source-bound engineering profile](../../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
records the **655,360-byte (640-KiB)** transaction cap; the earlier 512-KiB
transaction cap is baseline evidence.
Settlement and issuance proof caps remain 524,288 bytes each.

The [complete conditional wire model](../v1-network-budget.md) derives minimum
uplink from 576 positions, three relay copies, the selected proof cap, bounded
issuance and control traffic, authenticated-channel framing, IPv6/TCP/link
overhead, reciprocal ACKs, retransmission and recovery allowances. Minimum
provisioned uplink must leave at least 15% of link capacity unused by that model.
**43 Mbps is the minimum; 100 Mbps remains recommended**. The model uses
approximately 36.502 Mbps, leaving 15.112% of the minimum link unused.
Actual listener qualification is required;
this model is not a throughput measurement. Bulk backup/checkpoint traffic
requires separate scheduling or bandwidth. These requirements do not change
the retained network, its existing decoders or container limits.

## Retained implementation commands

The commands below describe the existing node and its legacy proof route.
They do not activate the independent native V1 testnet. V1 deployment requires
the [native acceptance gates](../prover-acceptance.md), separate genesis and
qualified platform packaging.

## Wallet initialization

```sh
siworld-node init --datadir "$HOME/.siworld-test"
siworld-node address --datadir "$HOME/.siworld-test"
```

Initialization asks for a password through hidden terminal input. It creates an encrypted key and distinct role credentials, refuses key overwrite, and uses directory mode 0700 and secret-file mode 0600. Keep authenticated backups independently. Runtime files must remain outside the repository.

## Real-proof genesis

Collect public owner digests and run in an external runtime directory. Replace OWNER_HEX with the intended 64-hex public owner:

```sh
siworld-node genesis --network siworld-test-1 \
  --alloc OWNER_HEX:100 --proofs plonky3 \
  --container-size 4 --block-time 60 --miners 1 > genesis.json
```

Genesis calibrates work on the coordinator's machine. Distribute the same file and compare genesis IDs. Create it shortly before mining because its timestamp anchors difficulty. Small capacity reduces preparation cost; it is not a production throughput measurement.

## Run

```sh
siworld-node run --datadir "$HOME/.siworld-test" \
  --genesis genesis.json --mine
```

```sh
siworld-node run --datadir "$HOME/.siworld-peer" \
  --genesis genesis.json --peer /dns4/seed.example.org/tcp/30333
```

Peer TCP defaults to 30333; authenticated loopback RPC defaults to 127.0.0.1:30334. A configured peer node waits for synchronization before mining and pauses when disconnected. Transactions flood directly, without a source-anonymity layer.

## Wallet access

```sh
siworld-cli --auth-file "$HOME/.siworld-test/rpc-read.token" info
siworld-cli --auth-file "$HOME/.siworld-test/rpc-read.token" walletstatus
```

Spending requires startup with `--enable-wallet-spend`, the separate spend credential and password unlock. Balance scans require an unlocked wallet. `walletunlock` accepts 1 through 3,600 seconds, default 60.

Bundled sends additionally require an independent encrypted order ledger and witness initialized by `siworld-node orders-init`. Retain its current checkpoint separately. Generate a payment ID offline with `siworld-cli new-payment-id`, retain the complete order, and retry identical parameters with the same ID. Consult binary usage for ledger, backup, checkpoint and reconciliation commands, and read [RPC and recovery](rpc.md) before submitting payments.

## Maintenance

Stop the node before offline key migration, reconciliation or credential rotation. Startup replays full stored blocks including proofs. Pruning is not implemented. Monitor disk use and test restart/recovery on disposable networks. Proving memory, history growth and the local reorganization bound limit the operating envelope.

## Multi-asset proof and capacity boundary

The three-output codec uses 2,027 public body bytes and 2,115 permanent bytes
per position. The selected `b7/q41/g20` profile generated in 1.316 seconds
median across three trials, with a maximum of 1.332 seconds. Observed proof
bodies were 583,552–584,848 bytes and the combined process-tree cgroup peak
was 531,668,992 bytes. These are synthetic proof measurements, not full-node
throughput or a minimum RAM specification. The new transaction engineering freeze belongs to the isolated
`bench-multi-asset` implementation. The `bench-d8` source and two-output freeze
remain unchanged baseline evidence. The new key, codec and cap must be wired
into a separate native node decoder and admission path before network use.

Updated year-1/3/5 capacity and low-use tables are in
[V1 Storage, Retention and Bootstrap](../v1-storage-and-sync.md); reproduce them
with `python3 scripts/v1-storage-budget.py` using the frozen transaction cap.
Three-day rolling proof storage and permanent public records are separate
budgets. Database/index allowances require persistent-node measurement.
