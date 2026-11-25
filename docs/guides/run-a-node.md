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
   its node executable. Set `NODE_DIR`, `GENESIS_ID`, and `PEER_CONFIG` to
   the node directory, expected genesis ID, and matching peer manifest.
2. Place the release's `genesis.bin` in the node directory as described
   by the package. Check the executable's command list and compare the
   genesis identity before initializing anything.

   ```sh
   "$SIWORLD_NODE" --help
   "$SIWORLD_NODE" genesis-id "$NODE_DIR"
   ```

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

Compare the network and genesis with the release manifest. Check that the
validated height and accepted checkpoint advance and that the store reports
availability. A reported peer head is a synchronization hint until the node
validates the corresponding chain. See [storage and synchronization](../specs/07-storage-and-sync.md).

## Troubleshooting

| Symptom | Check | Action |
| --- | --- | --- |
| Genesis mismatch | Executable, manifest, and data directory identify a different chain | Select the matching release and preserve the existing store. |
| Checkpoint import fails | Availability, peer pins, policy bounds, and target disk space | Correct the input and use the package's verified resume or clean import procedure. |
| Checkpoint stops advancing | Local validated height and checkpoint authentication status | Preserve the store and inspect local diagnostics before changing configuration. |
| Store already in use | Ownership and active processes | Stop the owning process cleanly before restarting. |
