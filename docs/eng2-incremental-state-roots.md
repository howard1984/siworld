# Incremental permanent-state commitments

Status: component-encoding revision for the unactivated engineering network.
This revision does not change the existing network's state transition.

## Component 2: append tree

The execution encoding is exactly 58 bytes: little-endian u16 version 2,
little-endian u64 leaf count and the native commitment tree's canonical 48-byte
root. The existing native append-tree hash and empty-tree construction remain
unchanged. Appending a leaf changes at most the fixed tree depth; execution
commitment construction does not hash the complete historical leaf vector or
membership encoding on each block.

A raw snapshot still carries the complete ordered leaves, claimed count/root,
frontier and sorted membership values. Import reconstructs the actual tree and
unique membership from all leaves, rejects duplicate or noncanonical values, and
compares count, root, frontier and membership. Only the resulting actual tree
produces the compact execution encoding. A claimed cache root is insufficient.

## Component 3: nullifiers

The execution encoding is exactly 42 bytes: little-endian u16 version 2,
little-endian u64 unique value count and a 32-byte sparse-Merkle root. The key is
the complete canonical 48-byte nullifier encoding, interpreted byte by byte
from index zero, with the most significant bit first within each byte. The
path has exactly 384 bits. There is no secondary hash-to-key mapping or key
truncation that could alias two distinct canonical values.

All hashes use BLAKE3 `derive_key` with these exact context strings:

| Node | Context | Input bytes |
| --- | --- | --- |
| Empty leaf | `siworld eng2 nullifier empty leaf v2` | Empty |
| Occupied leaf | `siworld eng2 nullifier occupied leaf v2` | Complete 48-byte nullifier |
| Branch | `siworld eng2 nullifier branch v2` | u16 depth, little-endian; left hash; right hash |

Leaves are at depth 384. Define `E[384]` as the empty-leaf hash and
`E[d] = Branch(d, E[d+1], E[d+1])` for depths 383 through zero. The empty root is
`1430be5dd475622cd80eafcb5b86d425bb887f856bf90ff91741cc9873a06a88`.
An occupied path combines its actual leaf with the corresponding empty subtree
at each absent sibling. Left and right order is fixed by the complete key bits.
Hash collision resistance is required; a duplicate exact key is rejected.

The implementation stores a compressed Patricia trie with immutable shared
nodes. Each branch stores its divergence depth, representative exact key and
hashes normalized to the full sparse tree. Skipped depths are reconstructed with
the fixed empty hashes. Insertion derives every new hash from actual children;
there is no constructor that accepts a caller's root. Unchanged subtrees and
their normalized sibling hashes are shared. Cloning a candidate root is constant
time, and each insertion hashes only its bounded 384-bit path rather than all
historical values. A trie with N occupied values has exactly 2N-1 live nodes.

Canonical-field decoding precedes insertion. Duplicate, malformed or overflowing
insertions leave the parent root and membership unchanged. Batch insertion
stages a shared candidate and publishes it only after every value succeeds.
Different insertion orders yield the same full sparse root. Independently staged
forks cannot mutate their parent or each other.

The raw snapshot retains the bounded, strictly sorted complete nullifier list.
Import rebuilds the trie from every canonical value and derives the execution
encoding itself. It then compares the complete execution aggregate with the
selected work-verified header. Changing even one otherwise valid canonical
nullifier cannot preserve that authenticated state without a hash collision.

## Framing and integration

The existing component digest framing binds component ID, compact encoding
length and compact encoding bytes. The eleven-component aggregate binds network,
height, parent and all ordered descriptors. Raw snapshot transfer encodings for
components 2 and 3 are reconstruction material; they are not hashed in place of
the compact execution encodings. Certificate inclusion witnesses use the actual
compact component descriptors.

Full reconstruction remains an import-time operation. The ordinary native engine
must retain the actual append-tree state and persistent nullifier root, derive
candidate roots from the new verified outputs and nullifiers, and commit them
with its ordinary chain delta. Root derivation is not proof verification and does
not authorize a block, settlement or live network admission by itself.

`SnapshotState::execution_commitment` uses compact actual-state encodings without
rescanning permanent leaves or nullifiers. Its internal nullifier trie is created
only by empty initialization or reconstruction from all imported values. Raw
snapshot export and import retain the full reconstruction path. The enclosing
native versioned engine must still apply every accepted nullifier to that trie
and commit it atomically with its chain delta; the full native proof-tail engine
and its versioned verifier remain separate activation requirements.
The production `SnapshotState` deliberately has no `Clone` implementation, so
the engine cannot obtain an entire permanent-state copy for each staged block.

The shared checked-action path can derive a `ChainPreview` from its actual
`ChainDelta`. The preview borrows the parent and the staged append tree, copies
only the bounded timestamp and recent-root windows, and derives the staged
nullifier trie from the actual accepted insertions. Versioned ledger components
come from the actual economic, fund and governance objects, with network,
height, membership and entitlement checks. A preview's candidate commitment does
not authorize the confidential settlement, the header or state adoption. There
is no public constructor accepting an asserted proof-success flag.

The existing native transition uses the same bounded preview when publishing
its delta. Its wire format, proof profile, fee rules and economic behavior remain
unchanged. Candidate execution commitments agree before and after materializing
the newest selector and match complete raw-state reconstruction. The final
versioned proof profile and durable admission engine remain activation gates.
