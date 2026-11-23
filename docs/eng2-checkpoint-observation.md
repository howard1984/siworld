# Checkpoint observation and authorization forks

Optional checkpoint certificates do not select the canonical chain. Header work,
full body validation, the existing reorganization depth limit and normal state
execution remain authoritative. An observer can stop mining and checkpoint
signing, but it cannot import a state or authorize a branch switch.

On Unix residents, a certificate signed by the independently executed current
quorum whose checkpoint anchor matches but whose authorization block differs
creates a pending authorization observation. Normal bounded peer synchronization
continues. Pending and obsolete-authorization certificates are not forwarded to
the checkpoint publication mailbox. A checkpoint anchor contradiction or two
distinct valid statements for the same network, roster epoch and checkpoint
height permanently stop the observer for that process run. Changing only the
authorization block still constitutes a distinct statement; retirement never
permits signing another statement at that checkpoint height and signer epoch.

A pending observation has two recovery paths:

- The identical statement becomes canonical and is fully verified with its
  authorization witness. A lawful roster rotation alone does not clear the gate;
  complete historical verification can clear the original pending entry without
  advancing the current observed checkpoint height.
- The checkpoint anchor remains canonical, and the exact saved authorization
  header is authenticated as belonging to an obsolete branch. The retained
  headers must connect to an exact canonical ancestor within the existing
  24-link bound. The full witness must bind the saved authorization execution
  commitment and the independently executed current signer roster; the quorum
  signatures are checked independently of that witness. Missing, malformed or
  unqualified material cannot retire an observation.

Pending observations retain their bounded authorization witness, with actual
witness bytes reserved from the existing shared memory budget. The canonical
owner can therefore verify retirement after retained headers arrive without
requiring a peer to replay the old certificate. At most eight unresolved
certificates are retained. Duplicate statements do not add entries. Unresolved
entries are never evicted. Capacity exhaustion or evidence preservation failure
stops observation. Retirement releases the pending entry and its witness charge.

When canonical peer tips already match, the block phase can retrieve a pending
observation's authorization headers using the existing exact identity requests.
The same node-owned discovery ledger, authenticated-peer attempts, expiry,
request allowance and capability probe accounting apply. Fetches run outside the
canonical owner lock. At most 24 old-branch links are requested; unavailable or
invalid material leaves the observation pending. A complete path undergoes the
existing header difficulty, timestamp, ancestry and work checks before entering
the retained branch store. This path fetches no bodies and cannot execute or
adopt a branch. It finishes in the block phase, before checkpoint and transaction
exchanges. The existing asynchronous checkpoint worker independently verifies
retained candidate and publication material, including native snapshot
reconstruction, before retiring its own obsolete material.

Clearing the last pending entry invalidates previous peer head evidence. Mining
and signing still require fresh completed block/checkpoint/transaction rounds,
canonical-owner guards and publication checks. The host skips retired anchors
and prepares a later eligible checkpoint under the unchanged 12-block cadence
and 24-confirmation requirement.

Unix residents retain independently verified public quorum evidence in the
owner-only `eng2-public` directory. Its `eng2-context.bin` binds network, genesis
and rules. The first certificate uses
`checkpoint-observed-{epoch:020}-{height:020}.certificate-eng2.bin`; a second
distinct valid statement uses
`checkpoint-observed-conflict-{epoch:020}-{height:020}.certificate-eng2.bin`.
Each file contains exactly 6,778 bytes in the existing certificate encoding.
Descriptor-relative, write-once atomic publication, `NOFOLLOW`, owner,
link-count, mode and durability checks remain in effect. Different valid
signature subsets for the same statement leave the first file unchanged.

A retired observation retains an anchor restriction. On one verified canonical
prefix, the highest retired anchor cryptographically binds the lower prefix, so
only its height and hash need remain in memory. Before raising this restriction,
both the previous and proposed anchors must still be available and match the
canonical prefix. A later anchor contradiction remains a hard conflict.

The fixed 56-byte `checkpoint-observed-retirement-eng2.bin` cursor addresses that
anchor's existing write-once quorum file by roster epoch and height. Startup
checks exact cursor/evidence framing and identities, checks signatures against
the executed roster when that epoch is current, and restores the restriction
without scanning historical files or waiting for peer replay. Historical
journal context restores only an additional restriction; it does not establish
current roster authorization. A missing or future canonical anchor keeps the
observer unavailable. Missing, malformed or conflicting referenced evidence
prevents startup. This cursor cannot grant checkpoint adoption or signing
permission.

Normal forward observations do not accumulate in a RAM table. Immutable quorum
files remain on disk: one certificate per hourly checkpoint is about 56.6 MiB of
logical data per year, excluding filesystem overhead. Automatic deletion of
quorum evidence is not implemented. Startup does not scan every historical
observation or reconstruct a global persistent conflict gate. Existing conflicts
at other epoch/height pairs are detected when either corresponding certificate
is observed again. The retirement cursor adds a bounded persistent restriction
for retired observations; it is not a complete historical conflict index.

Automatic authorization retirement and durable observation evidence are
implemented for Unix residents. Other platforms retain the previous policy that
an authorization-block contradiction latches a conflict for the process run.
This path does not add a Windows evidence backend.

Focused regressions use synthetic header views, authentic checkpoint signatures,
bounded temporary public files and local framed socket exchanges. They exercise
observation, header retrieval and installation boundaries. They do not establish
native fork execution, renewed checkpoint production or continuous production
acceptance; those require the affected process to cross the partition and heal
without restart on the deployed implementation.
