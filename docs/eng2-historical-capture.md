# Historical full-frame capture

Historical capture is an owner-local diagnostic read interface. It changes no
canonical selection, checkpoint authority, mining readiness or wallet
publication. Retention and execution flags are source provenance only.

A request binds the release, process run, executable, source identity, complete
network context, exact target height, tip, cumulative work, execution commitment,
original observation digest and replay anchor. Unknown fields and caller paths
are rejected. A successful response identifies an opaque capture and an immutable
object inventory. Ordered reads contain at most 65536 bytes. A batch contains
at most eight ordered reads; the complete batch is checked before progress.
A close receipt requires complete coverage of every original object.

The existing Driver owner captures canonical and retained-branch read
transactions under its mutex. The mutex is released before traversal, body
reads, hashing and encoding. One capture slot belongs to each Driver and is
shared by all controls. Cancellation, expiry, failure and close release the slot,
transactions and reservation. Each complete frame is read once for preparation;
transfer retains at most one complete frame. The old frame is released before
loading its replacement. No external reader opens or copies a live database.

Capture bounds are 4096 headers, 4 GiB of complete frames, 5 GiB of total objects,
128 MiB of logical buffer reservations, 60 seconds of preparation and 300 seconds
of retention. The input reservation moves into the capture without overlapping
a second full reservation or releasing the input charge. Encoded replies have
a separate 4 MiB limit. Header and native proof verification are synchronous;
a deadline rejects late completion rather than preempting one verification.
The logical budget does not replace a process memory guard or measured RSS.

The per-block state-growth reservation includes at most 576 transactions with
three outputs and two nullifiers each, five reward outputs, one fee output,
eight fund-spend outputs, and four issuances with three initial notes and one
fee note each. Asset encoding includes the asset identifier, height, supply,
declaration digest, issuer key and sequence, and fee commitment. The 16 KiB
per-block asset allowance exceeds four such records at the current codec
bounds. Permanent leaf/nullifier encodings, bounded recent roots, governance
and address records, and fund cohorts are charged separately. Each actual
post-execution state is checked against the reserved shape before retention.
These are conservative logical allocation checks, not a bound on verifier RSS.

Independent full replay verifies complete original headers, proof profile,
cumulative work and body commitments. It creates a fresh disposable Store and
executes every original body through ordinary native admission. An optional
checkpoint additionally requires original certificate, authorization witness
and snapshot bytes matching the actual independently executed states.

A process-local verified prefix can be seeded only from an actual replay
receipt and the same retained original files. Serialized prefix identifiers
are selectors, never execution authority. The cache binds the exact context,
release, executable, height, tip, work and execution commitment. Extension
requires that exact independently executed ancestor and runs the genuine native
verifier on every missing original body. Complete headers and work are checked
again. Historical bootstrap ranges are not observations of current heads.

The cache retains one final encoded state plus bounded per-height snapshot and
governance digests, not a full snapshot per height. It retains at most 4096
height records and 8208 original-file pins. Construction and extension reserve
workspace before cloning or encoding, including the still-live old prefix,
component copies, encoding buffers and frame decoding. Insufficient space
produces a finite capacity failure. Original-file identity includes owner,
mode, link count, device, inode, length and change timestamps; actual reads also
check the original digest. This is an owner-local immutable-file discipline,
not protection against host root.

Checkpoint authentication can use a zero-length suffix at an already executed
head. Original snapshot and governance bytes must match the independently
recorded digests at the checkpoint and authorization heights. The existing
confirmed-tail rules, witness binding, signatures and executed current-roster
evaluation remain required. A raw genesis-anchored suffix grants no current
checkpoint authority. Missing originals remain unavailable after cache reuse.

The finite file-channel actions are Header, Begin, Read, ReadBatch, Close and
Cancel. Header returns the exact original encoded header and release, run,
executable, source and network-context bindings. Its origin distinguishes a
canonical header from a retained branch. This metadata supplies no validity,
cumulative-work or independent-execution authority.
They use strictly increasing sequence numbers and a fixed inflight marker.
Channel activation requires an explicit pinned release and is disabled by
default. The `historical-exchange DIRECTORY REQUEST_FILE MAXIMUM_WAIT_MS`
command submits one bounded request and waits at most 60000 milliseconds for
the corresponding result. It returns the original bounded result bytes after
checking the response version and sequence. Result reads hold the existing
mailbox lock through metadata validation and reading, preventing an atomic
replacement from unlinking the opened result during the strict link check.
Reply parsing occurs after releasing the lock; general file checks remain in
force. A caller's shorter absolute deadline remains binding.

The separate `historical-verify` command consumes bounded stdin actions
Seed, Extend, Inspect and Drop in an owner-selected disposable directory. It
creates no listener, key, node identity, native publication or service control.
