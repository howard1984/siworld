# Run a node

## Overview

A SIWORLD full node checks work, proofs, and state transitions. This guide
covers a validating node with an existing release package and the network
materials for the chain it will join.

## Requirements

- A platform supported by the chosen node release and sufficient space for
  the chain store, retained history, and staged synchronization data.
- The node executable, release checksums, genesis material, peer manifest,
  and expected genesis and network identifiers obtained through a trusted
  distribution channel. Use [siworld.io](https://siworld.io/) as the package
  entry point.
- A writable, owner-controlled node directory and the configuration for its
  role. Keep service identity material separate from wallet recovery material.

## Steps

1. Verify the archive checksum and compare its build and network metadata with
   the trusted release. Extract the complete package. Set `SIWORLD_NODE` to
   its node executable. Set `NODE_DIR` and `PEER_CONFIG` to the node
   directory and matching peer manifest.
2. Check that the trusted release manifest lists the public network ID
   `d38a665e4751c7cb6153ad56df86426303121524edca5158b8d60b4fc53b638f`.
   Take `GENESIS_ID` separately from that manifest. Verify the packaged
   `genesis.bin` checksum and place the file in `NODE_DIR`. Compare the
   executable's computed genesis ID with the pinned value before
   initializing anything.

   ```sh
   actual_genesis_id="$("$SIWORLD_NODE" genesis-id "$NODE_DIR")" &&
     test "$actual_genesis_id" = "$GENESIS_ID"
   ```

   Continue only if the check succeeds. See the
   [protocol parameters](../reference/parameters.md) for both identifiers.

3. For a new node, initialize the service identity explicitly and configure
   only independently trusted peer pins. Existing nodes reuse their service
   identity and authenticated store. Initialize an empty store for normal
   validation or use the package's signed checkpoint import procedure.

   ```sh
   "$SIWORLD_NODE" identity-init "$NODE_DIR" --expected-genesis "$GENESIS_ID"
   ```

   To start validation from genesis, initialize the store explicitly.

   ```sh
   "$SIWORLD_NODE" init-store "$NODE_DIR" --expected-genesis "$GENESIS_ID"
   ```

4. When starting from a signed checkpoint, set `BOOTSTRAP_POLICY` to the
   verified import policy for the package and network. Import into a
   separate empty state directory. The import checks checkpoint authority,
   cumulative work, state commitments, and the validated suffix.

   ```sh
   "$SIWORLD_NODE" bootstrap-signed "$NODE_DIR" "$PEER_CONFIG" "$BOOTSTRAP_POLICY" \
     --expected-genesis "$GENESIS_ID"
   ```

5. Run the node with the validated configuration. Back up the store
   according to the release's documented clean-stop procedure.

   ```sh
   "$SIWORLD_NODE" run "$NODE_DIR" "$PEER_CONFIG" --expected-genesis "$GENESIS_ID"
   ```

## Verification

```sh
"$SIWORLD_NODE" status "$NODE_DIR"
```

Compare the status field `network_id` with the pinned public network ID
and recheck the local genesis with `genesis-id`. Check that the validated
height and accepted checkpoint advance and that the store reports
availability. A reported peer head is a synchronization hint until the node
validates the corresponding chain. See [storage and synchronization](../specs/07-storage-and-sync.md).

## Troubleshooting

| Symptom | Check | Action |
| --- | --- | --- |
| Network or genesis mismatch | Executable, manifest, and data directory identify a different chain | Select the matching release and preserve the existing store. |
| Checkpoint import fails | Availability, peer pins, policy bounds, and target disk space | Correct the input and use the package's verified resume or clean import procedure. |
| Checkpoint stops advancing | Local validated height and checkpoint authentication status | Preserve the store and inspect local diagnostics before changing configuration. |
| Store already in use | Ownership and active processes | Stop the owning process cleanly before restarting. |
