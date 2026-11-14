# Reorganization shared memory admission

The resident shares one 640 MiB logical byte budget between production, network
buffers, exports and reorganization. Reorganization reserves
`4 * largest_encoded_body_bytes + 65536` before copying an archive, decoding a
body, prevalidating a replacement or restoring the canonical store. The guard
remains owned through replacement replay. These counters do not measure process
RSS or identify which peer owns a buffer.

A temporary exhausted reservation pauses production, forward admission, new
branch discovery and exports. It returns from the current owner turn without
restoring state or sleeping under the owner lock. Existing network operations
retain and release their own guards normally. Later owner turns retry no more
than once per 250 ms. Paused export preparation cancels its running worker and
nonblockingly discards an obsolete result only after that worker has finished.
Both buffered results and results still owned by a finished join handle release
their own reservations. Running tasks are never joined under the canonical
owner lock; later paused turns poll completion. The first contention begins a
single 900 second wait limit; repeated contention does not extend it. Overflow, unavailable budget
accounting and wait expiry require local recovery and keep activities paused.

The status field `reorganization_shared_byte_budget` reports one numeric
admission observation: the largest body, requested charge, maximum, used and
available bytes at that attempt, outcome, attempt count and wait policy. Used
bytes are captured under the same lock as the admission decision. The field
reports no endpoints, private paths, keys or proof contents. It explicitly
records that process RSS and reservation ownership attribution are not
established. A waiting observation does not create a completed switch event,
rollback depth or common ancestor result.

This changes local scheduling only. It does not increase any byte budget, reduce
the replay charge, alter verified-work selection, extend the 24 block rollback
window, bypass full native prevalidation or authorize clearing a persisted deep
refusal. In-flight production may finish an already started proof, but the
activity and template gates still prevent its commit while waiting.

The ordinary regressions use logical reservations and bounded synthetic
contention without large proof buffers, a miner or a network connection. The
owner-only native fixture separately checks that the same driver can complete
its fixed replacement after a competing guard is released. Full live healing,
restart and state comparison remain separate acceptance requirements.
