# Engineering signed state import

Status: an explicit library admission path with bounded rejection tests.
Positive admission with an actual signed checkpoint and complete native proof
tail remains pending. This path does not start a service, join a network,
activate proof expiry or replace an existing database.

## Admission policy

The caller pins the complete sealed engineering genesis independently of its
download source. The current implementation requires its frozen profile and
`LegacyMiner` fee mode. `AdmissionPlan::select_signed` compares one to sixty-four
complete verified header histories, selects greatest cumulative work, rejects
equal-work competing tips and applies an explicit nonzero local work floor.
It does not infer that a supplied source is the only possible source or prove
the absence of an undiscovered heavier chain. Source discovery and independent
comparison remain host responsibilities. No automatic source or work-floor
default is installed.

Automatic synchronization retains its separate three authenticated identities
and three transport-derived source groups. A signed-mode plan does not satisfy
that automatic policy and grants no accepted state capability. Both planning
and reconstruction remain distinct from final signed import admission.

The selected checkpoint must be a positive multiple of seventy-two. Its
authorization height must identify that same eligible checkpoint, be at least
twenty-four blocks later and lie on the selected header history. The complete
selected tail contains between twenty-four and 312 blocks. Reanchoring checks
the available body range and reapplies the same explicit floor to tail work.
Every required full body must subsequently be read and verified.

An import authenticates two distinct ML-DSA-65 votes from the current three-key
roster and binds the authorization witness to the selected complete header.
Cryptographic verification against witness-supplied keys alone does not
establish authority. The importer replays every public governance action before
the checkpoint from pinned genesis, including management signatures, sequence
rules and delayed activation, and requires exact equality with the canonical
checkpoint governance component. Native tail execution continues that verified
lineage and must reproduce the entire witness governance component at its
authorization height. The final selected head must retain the certificate's
current roster. A work-committed attacker roster with valid self-signatures
therefore cannot replace genesis authority.

## Permanent prefix and verified tail

All eleven snapshot components are canonically reconstructed and their
aggregate must equal the selected checkpoint header's execution commitment.
Permanent `SWE2WLT1` receipts before and including the checkpoint authenticate
public body ranges against each selected header's body commitment. Their
ordered outputs rebuild the commitment tree, unique nullifiers rebuild the
spent set, and public declarations rebuild the asset registry. Every retained
commitment/recent-root snapshot is recomputed, including genesis when retained.
Public governance records are replayed independently as described above.

These proof-free public receipts are permanent history, not missing historical
STARK proofs. Historical economic and fund state are reconstructed from the
canonical signed snapshot; this implementation does not claim to replay those
ledgers from proof-free receipts. The authorized signatures attest the complete
checkpoint state. Every block after the checkpoint is decoded and executed
through the actual native verifier and shared execution path. Final height,
block identity, cumulative work and current-roster evaluation must all match.

Verification writes no destination files. Rejection or cancellation returns no
accepted engine or Store. The verified capability retains artifact bytes and
bounded per-row lengths and hashes, rather than all historical proof bodies.
Its `verification_bytes()` value counts logical input bytes validated once;
it excludes header acquisition, installation rereads and transport overhead.
Hosts must measure actual transferred bytes separately.

## Encrypted artifact transport

The ordinary authenticated hybrid session supports a versioned bootstrap offer
and exact-offset snapshot and permanent-receipt slices. Requests bind the
request identifier, immutable bundle, object type, receipt height and block
identity, offset and maximum response length. Every slice fits the existing
control-frame cap and retains its shared memory reservation. Complete headers
and full native tail bodies use the ordinary header/body exchanges. Cold-client
rounds advertise only the owner's actual admitted head, then finish the usual
reverse pull, checkpoint batch and transaction phase. Download progress never
becomes an accepted height.

Only explicit bootstrap and validator resident roles enable an offer. Its
capability can be constructed only from an actual durable Store and a current
certified checkpoint. Service maintenance materializes at most one missing
permanent receipt per tick and preserves all full proof bodies. The provider
holds one bounded snapshot copy; receipt slices are copied under the owner lock
and sent after releasing it. A changed signer epoch or canonical prefix makes
the offer unavailable. Publishing a replacement offer can retire the old
bundle; resumable acquisition requires exactly the same manifest and policy.
This implementation enables no expiry and establishes no pruning lease.

The quarantine stores chunks and ordered progress atomically, checks retained
chunk hashes on reopen, rejects changed complete-object hashes and exposes
bounded local reads to the signed importer. It creates no canonical database,
identity, signing host or readiness status. Provider hashes identify transfer
bytes and grant no authority. Actual encrypted stream counters include hybrid
handshake and record framing; they are distinct from artifact bytes, importer
verification bytes and local rereads. They are not TCP or Ethernet measurements.

Bounded tests exercise malformed framing, interrupted quarantine resume and
synthetic payloads through an actual hybrid session followed by all three round
phases. Complete native import over that transport, public client entry-point
integration and Windows real-machine acceptance remain separate pending gates.

The cold-client library acquires one header or artifact request per finite
ordinary round. It reconstructs complete verified header candidates, compares
their actual cumulative work and then pins one checkpoint bundle. The download
cursor advances over durable completed objects without rescanning the entire
prefix on every chunk. Resuming a candidate scans its stored header prefix once;
that prefix must be contiguous. Download completion grants no accepted Store.
Native signed verification and checked installation remain mandatory. The
result separates logical verification bytes and local cache rereads; encrypted
stream volume must still be obtained from the session counters. Public launch
commands and mining-readiness attachment are not supplied by this library.

## New-database installation

The owner separately prepares a dedicated canonical directory, its matching
genesis file and existing peer identity. On supported Unix systems installation
requires that directory to be owned by the current user with mode `0700`.
This API never initializes, copies, rotates or exports identities. Windows
installation uses the current-user checked directory and regular-file APIs,
closes its candidate before nonreplace promotion, then authenticates a reopened
canonical database under a checked file-identity pin. Any ambiguity after
promotion returns `DurabilityUnconfirmed`; it grants no overwrite or retry.
Resident command-line admission wiring and Windows real-machine acceptance
remain pending.

The installer refuses an existing canonical database and creates only a new
`checkpoint-import.redb` candidate. It rereads every source row and checks its
previously verified length and hash. One candidate transaction writes the
permanent prefix receipts and digest pairs, complete compact headers, full
verified tail bodies, checkpoint artifacts, anchor and final head. The import
manifest binds the prefix and artifact digests to the existing identity's
authenticated local restart seal. Missing prefix proofs remain explicitly
unavailable; they are never advertised as full blocks.

The final cancellation boundary precedes sealing and admission. Atomic
no-replace rename then admits the candidate as `chain.redb`, followed by parent
directory synchronization. A directory durability failure after rename returns
`Installation::DurabilityUnconfirmed`, with no usable Store. It is neither a
successful readiness result nor permission to overwrite the canonical file.
Earlier errors preserve any unadmitted candidate for inspection. This path
performs no proof deletion, compaction or automatic retry.

## Positive qualification plan

The first complete positive qualification requires actual accepted native
history through height 96 and a valid certificate for checkpoint height 72:

1. Independently pin sealed genesis and its fee mode, compare complete verified
   header candidates, set an explicit work floor and confirm full bodies 73
   through 96 are actually retained.
2. Obtain a genuine two-of-three current-roster certificate and its exact
   authorization witness. Supply the canonical height-72 snapshot, authenticated
   permanent receipts 1 through 72 and complete native bodies 73 through 96.
3. Verify canonical reconstruction, genesis-derived governance lineage, every
   permanent-prefix comparison, all actual native tail proofs and the exact
   authorization/current roster. A height-28 fixture cannot qualify this gate.
4. Use a separately prepared new target identity, install atomically and reopen
   with the same genesis and identity. Compare accepted height, tip, execution
   commitment, permanent rows, wallet receipts, authenticated compact header
   index and exact full-body availability boundary.
5. Record logical verification bytes, all actual source reads including
   installation, elapsed time, database size and allocated disk usage. Report
   download volume only from the actual transfer counter.
6. Reject one signature, unknown or duplicate slots, altered component/root,
   invalid lineage, incorrect authorization witness, competing selected history,
   insufficient confirmations/work, missing or corrupted prefix rows and tail
   bodies, modified source rereads, cancellation and an existing target. Check
   that pre-admission rejection exposes no canonical database or usable Store.

Bounded synthetic tests cover planning, certificate framing, governance lineage,
prefix-manifest corruption and early cancellation/existing-target refusal.
They do not replace the positive native qualification, post-rename failure
injection, long-offline recovery or service proof-retention acceptance.
