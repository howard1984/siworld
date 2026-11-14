# Checkpoint observation and authorization forks

Optional checkpoint certificates do not select the canonical chain. Header work,
full body validation, the existing reorganization depth limit and normal state
execution remain authoritative. An observer can stop mining and checkpoint
signing, but it cannot import a state or authorize a branch switch.

On Unix residents, a certificate signed by the independently executed current
quorum whose checkpoint anchor matches but whose authorization block differs
creates a pending authorization observation. Normal bounded peer synchronization
continues. Pending certificates are not forwarded to the checkpoint publication
mailbox. A checkpoint anchor contradiction or two distinct valid statements for
the same network, roster epoch and checkpoint height permanently stop the
observer for that process run.

Canonical adoption alone does not clear pending observations. The same statement
must arrive again with a complete authorization witness that binds to the
accepted authorization header and authenticates the roster. A lawful roster
rotation alone does not clear the gate; complete historical verification of the
original statement can clear its pending entry without advancing the current
observed checkpoint height. Clearing the last pending entry invalidates previous
peer head evidence. Mining and signing still require the existing fresh completed
peer rounds, canonical-owner guards and publication checks.

The observer reserves shared memory for at most eight unresolved full
certificates. Duplicate statements do not add entries. Unresolved entries are
never evicted. Capacity exhaustion or failure to preserve certificate evidence
stops the observer; these conditions cannot manufacture readiness.

Unix residents retain independently verified public quorum evidence in the
existing owner-only `eng2-public` directory. Its `eng2-context.bin` binds the
network, genesis and rules. The first certificate uses
`checkpoint-observed-{epoch:020}-{height:020}.certificate-eng2.bin`; a second
distinct valid statement uses
`checkpoint-observed-conflict-{epoch:020}-{height:020}.certificate-eng2.bin`.
Each file contains exactly 6,778 bytes in the existing certificate encoding.
Files use the existing descriptor-relative, write-once atomic publication,
`NOFOLLOW`, owner, link-count, mode and durability checks. Reads address one epoch
and height directly and verify stored signatures; they do not scan the directory.
Different valid signature subsets for the same statement leave the first file
unchanged.

Normal forward observations do not accumulate in a RAM table. Public evidence
files remain on disk: one certificate per hourly checkpoint is about 56.6 MiB of
logical data per year, excluding filesystem overhead. Evidence write failures
stop observation. Deleting evidence can remove the ability to detect a previously
observed statement; automatic retirement is not implemented.

The hard gate remains process-local. Reopening evidence and receiving either
certificate for a recorded conflicting epoch and height detects both retained
statements and stops again. Startup does not scan all prior observations or
reconstruct a global persistent conflict gate.

The automatic authorization recovery and durable observation evidence path are
currently implemented for Unix residents. Other platforms retain the previous
policy that an authorization-block contradiction latches a conflict for the
process run. The Windows protected-directory API is separate from the Unix public
export implementation; this change does not add a Windows evidence backend.

Focused regressions use synthetic header views, authentic checkpoint signatures
and bounded temporary public files. They exercise observation policy and evidence
storage; they do not establish native fork execution or continuous production
acceptance.
