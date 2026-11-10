# Engineering snapshot reconstruction

Status: implemented anchor-import primitive for a separately activated engineering
network. The complete native proof-tail transition, durable adoption, transport
integration and live recovery acceptance remain required before activation.

## Admission boundary

`ImportedAnchor::reconstruct` accepts an immutable admission plan selected from
complete, work-verified headers after the local source-diversity and positive
work-floor gates. The plan pins the network, genesis, anchor, head and work. The
anchor is `max(0, head_height - 312)`. Local bootstrap configuration supplies the
immutable rules, initial governance and allocation; peer metadata cannot replace
that configuration.

A successfully imported anchor is not a live admitted node. Its caller must
verify and execute the entire pinned proof tail in isolated storage, evaluate
the current optional certificate policy, and commit through durable storage
before exposing networking, signing, mining or transaction admission. Header
authentication alone does not prove that a snapshot's historical transitions
were valid; state reconstruction and complete-tail verification are distinct
requirements.

## Raw framing

The encoding starts with `SW2S`, little-endian version 1 and a little-endian
component count of 11. Each component then contains its u16 identifier, u64 byte
length and exact raw canonical state bytes. Identifiers must occur exactly once
in the fixed order 1 through 11. Unknown versions, counts, identifiers, reordered
components, integer overflows, truncation and trailing data are rejected. This
format contains neither trusted component digests nor a local cache seal.

For components 2 and 3, these raw bytes are full reconstruction material. Their
execution encodings are the versioned compact tree/count and sparse-Merkle
set/count encodings specified in `eng2-incremental-state-roots.md`; the importer
derives those encodings from the reconstructed values before hashing them.

Local import limits bound total bytes, per-component bytes, commitment leaves
and nullifiers before allocations or reconstruction. Resource limits are not a
smaller consensus-state capacity: operators must provide enough capacity for
the full valid permanent state and fund release horizon. In particular, the
fund component's own bound covers up to 420,768 active credit heights and 32
members; normal equal-credit ranges use compressed cohorts.

## Reconstructed state

The chain decoder rebuilds the commitment tree from every canonical leaf,
reconstructs membership, and compares the resulting count, root and frontier.
It rejects duplicate leaves, noncanonical fields, mismatched membership,
unordered nullifiers and invalid recent-root selectors. Context binds local
rules, network, genesis, height, parent, exact accumulated work and timestamp
history. The latest recent-root commitment is recomputed using the versioned
fee schedule. The genesis snapshot selects the first paid-block fee tier while
the genesis economic ledger still has zero issuance.

The economic, fund, governance and asset adapters decode actual state bytes and
re-encode them canonically. All network and height bindings must agree. Fund
allocation must equal local bootstrap configuration, aggregate fund entitlement
must equal economic fund credits, membership must match governance, and the fee
destination component must equal the full active governance payment address.

The importer recomputes all eleven component digests and their execution
aggregate, then compares it with the selected anchor header. It independently
checks the anchor's exact work, timestamp window and historical snapshot IDs
against verified headers. For an anchor at genesis, it compares the aggregate
with the entire locally initialized bootstrap state instead of trusting remote
genesis component bytes. No component hash supplied by a peer substitutes for
these reconstruction and consistency checks.
