# Reconstructed-anchor archive

Status: durable anchor-cache, selected-body storage and transfer reservations.
Native proof-tail verification, live-head admission, transport dispatch and retention
integration remain required before automatic synchronization can be activated.

## Selected proof-body storage

The archive also stores canonical versioned bodies whose complete bytes match
the exact selected standalone header. Storage checks the network, immutable
header identity, selected interval, explicit proof profile and local byte limits.
It does not establish native proof validity or an admitted live head.

A transfer durably pins the selected header identity at every inclusive height
from its anchor through its tip. Body descriptors and bounded chunk reads require
that exact active lease, authenticated peer, height and clock interval. Missing
bodies fail the request; snapshot-only storage is never advertised as a verified
complete tail. Descriptors recheck the complete cached body's header commitment.
Chunk reads avoid repeatedly hashing an entire body; the receiving admission
session must independently check the complete selected-header commitment before
decoding or execution. Completing or explicitly expiring a transfer atomically
removes both its reservation and its selected-header pins.

The archive metadata schema is version 2. Older or incomplete archives are rejected
and preserved; opening an existing file never initializes missing tables.

## Stored data and authentication

The archive uses separate versioned redb tables, bound to one local network,
genesis and rules commitment. It stores raw canonical snapshot reconstruction
bytes only after receiving an `ImportedAnchor` from actual all-component import.
The exact import binding and selected plan must match the archive. An existing
anchor record is immutable: different bytes at the same height and block ID are
rejected. A local BLAKE3 digest and length detect damaged stored records; neither
is a substitute for execution-commitment authentication.

Creation requires an absent file. Existing archives use guarded regular-file
opening, existing platform privacy controls and abort-on-repair behavior. Empty,
incompatible or damaged files are preserved and rejected. Initialization and
anchor writes use immediate database durability and the existing parent-directory
sync helper. The archive does not migrate or initialize an existing chain store.

On restart, a consumer still reauthenticates cached bytes with its current pinned
bootstrap and source-selected header plan. Possession of a cached anchor does
not establish a verified proof tail or an admitted live head. The archive offers
no API that advertises either condition.

## Bounded transfer reservations

Each transfer reservation binds an opaque local sequence, authenticated transport
peer identity, exact anchor height/hash, exact selected head height/hash, issued
time and deadline. The complete inclusive anchor-through-head interval is pinned;
for a long chain this contains 313 heights. The interval comes from an actual
`AdmissionPlan`, rather than a peer-provided range. Reservations and their
monotonic sequence survive database reopen.

Local policy bounds active reservations, reservation duration, snapshot bytes
and chunk bytes. Hard implementation ceilings are 64 reservations, one day per
reservation and 1 MiB per chunk; services may configure smaller resource limits.
Wrong-peer handles, missing reservations, out-of-range offsets, overflowing
ranges, early or late reads and regressed clocks are rejected. Chunk reads copy
only the bounded requested portion. The receiver must import and authenticate
the complete assembled snapshot before it can use the state.

Pins remain present until a durable authenticated completion or explicit expiry
operation releases them. An expired read alone does not silently release the
retention guard. Clock regression cannot expire reservations. Complete-window
pins are exposed to the retention owner; this archive does not delete proof or
permanent-state data. A pinned range is a resource reservation, not evidence that
every proof body in that range is present or verified. A future provider may
advertise readiness only after separately verifying durable reconstruction and
the entire proof-tail interval, while also applying real finality, reorganization
and capacity-alert policies.
