# Mine on Linux

**Public releases**

Genesis ID and installation packages: Published at network launch.

## Overview

The `siworld-miner` command runs outbound RandomX mining and its validating
node in the same process. It synchronizes the selected chain and independently
validates work and blocks before producing new blocks. The miner uses local
node state and a receiving address.

## Requirements

- The Linux release for the installed architecture. The package source
  targets Ubuntu 24.04 on x86-64 and AArch64. The x86-64 build uses x86-64-v3.
  Check the package's platform and memory admission requirements.
- `tar`, `sha256sum`, `install`, the system C and C++ runtime libraries, and
  space for local chain state, retained blocks, and temporary synchronization
  data. A user service also needs an active systemd user manager.
- The archive and trusted checksum from [siworld.io](https://siworld.io/),
  the matching genesis and peer manifest, and a full receiving address or a
  short address with its verified full contact.

## Steps

### Install and verify the package

Set `ARCHIVE` to the downloaded tar archive filename. Keep its checksum file
alongside it and run the commands from the download directory.

```sh
sha256sum -c "$ARCHIVE.sha256" &&
tar -xzf "$ARCHIVE" &&
cd "${ARCHIVE%.tar.gz}" &&
install -Dm755 bin/siworld-miner "$HOME/.local/bin/siworld-miner" &&
"$HOME/.local/bin/siworld-miner" --version
```

Add `$HOME/.local/bin` to your command path. Keep the release notes,
checksums, and bundled notices available for later upgrades.

### Recommended memory

| Deployment | RandomX fast mode, installed RAM | RandomX light mode, installed RAM |
| --- | ---: | ---: |
| Miner with its embedded node | 16 GiB | 12 GiB |
| Miner plus a separately running node | 24 GiB | 16 GiB |

These installed-memory recommendations come from measured workloads.
Checkpoint import and larger workloads can change memory use. The
fast-mode selection threshold is configured separately.

### Configure the network and receiving address

Set `GENESIS_ID` to the expected ID from the trusted manifest and
`FULL_ADDRESS` to your validated `sivf1…` full receiving address. Use the release's
`genesis.bin` and `peers.json` in your working directory.

```sh
siworld-miner config init ./genesis.bin "$GENESIS_ID" ./peers.json "$FULL_ADDRESS"
siworld-miner config
```

For a supported `si1p…` short address, verify its version 2 descriptor
against the selected genesis and supply its matching full contact with
`--contact ./contact.txt`. Use the full address directly if that
verification is unavailable. Keep the instance directory for the chain it
was initialized against. For checkpoint bootstrap on a new instance,
initialize with `--chain-source checkpoint`, then run
`siworld-miner config bootstrap ./bootstrap-policy.json` using the trusted
import policy. The miner validates the checkpoint and catches up on subsequent
blocks before producing work.

### Select Voyager or Holder

The saved configuration field `reward_mode` accepts `voyager` or `holder`.
Voyager is the default. When the field is unset, an interactive start
offers Voyager as the default choice and a background start uses Voyager
for that run. Holder requires confirmation that its locked notes cannot
be spent early.

Set a mode while the miner is stopped.

```sh
siworld-miner config reward-mode voyager
# To select Holder instead, explicitly acknowledge the lock.
siworld-miner config reward-mode holder --confirm-holder
```

The two commands are alternatives. At initialization, the equivalent
options are `--reward-mode voyager` or
`--reward-mode holder --confirm-holder`.

| Mode | First miner subsidy note | Other effects |
| --- | --- | --- |
| Voyager | Base less the 5% burn and 20% additional Holder pool credit | Both deductions round down. |
| Holder | Base less four locked notes, plus the draw from the opening Holder pool | Each locked note is one-tenth of the base, rounded down. |

The miner base is the residual of the nominal 85% / 12% / 3% subsidy
allocation. Holder unlocks its four additional notes after 52,560, 105,120,
157,680, and 210,240 blocks. The first note in either mode matures after
24 blocks and includes the transfer fees. See the
[monetary policy](../specs/06-monetary-policy.md#allocation-and-miner-modes)
for rounding and the pre-block pool draw.

### Start, view, and stop

```sh
siworld-miner start
```

Use Ctrl+C in the foreground miner for a clean stop. For background
operation, use `siworld-miner start --background`, then
`siworld-miner status --watch` to open the status panel or
`siworld-miner stop` to stop the process. The package's user service can
manage the same commands under systemd. Use a single owner for one instance.
Wait for a clean stop before replacing the executable or changing the address.

## Verification

```sh
siworld-miner status
```

Check the network, verified height, synchronization status, and selected
mode before treating the miner as ready. The panel distinguishes accepted
blocks from detached blocks and immature or locked notes from spendable
notes. Local production totals describe notes recorded for the miner and
are separate from a wallet's unspent balance.

## Troubleshooting

| Symptom | Check | Action |
| --- | --- | --- |
| Hardware admission fails | Architecture, instruction set, and available memory | Use the supported package and satisfy its hardware requirements. |
| Synchronization does not advance | Package network, genesis, trusted peers, and disk space | Verify the chosen inputs before changing the instance. |
| Short address cannot be resolved | Full contact, network, and genesis binding | Import the verified matching full address. |
| Shutdown is pending | Status of local proof or database work | Leave the process running until it releases its store. |
