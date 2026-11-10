# Internal engineering genesis

The genesis and native execution engine provide canonical initialization and
fee-root selection. The separate [resident runtime](eng2-resident-runtime.md)
adds explicit networking, durable admission and authenticated local restart.
Neither entry point establishes a completed production deployment or native
block and wallet rehearsal merely by being available.

The internal genesis explicitly selects `LegacyMiner` for ordinary transaction
fees. Their standard and priority amounts and native settlement payment to miner
note zero retain the existing native rule. Public issuance fees use the separate
governance-frozen amount and active dedicated destination, bound in the genesis
rules and complete execution state. The confidential destination candidate is
rejected by the genesis
sealer; there is no fallback or per-block mode switch. A later different fee
rule requires a separately bound genesis and qualified complete proof profile.

The immutable rules digest uses BLAKE3 derive-key context
`siworld eng2 internal immutable rules v1`. It binds the fee-mode byte, complete
native canonical configuration, exact existing transaction/settlement/issuance
profile fingerprint, length-prefixed initial governance component and fixed
header/execution/fund/governance revision string. The genesis identifier derives
from that digest with context `siworld eng2 internal genesis v1`.

The canonical public genesis file consists of `SWE2GEN1`, fee-mode byte zero,
the 32-byte complete native proof-profile fingerprint, fixed-width native
configuration, little-endian u32 governance length and canonical governance
component. Governance bytes are bounded by 131,072. Decoding verifies the exact
local native profile, network, initial height and sequence, complete fund
membership, exact lengths and canonical re-encoding. Unsupported modes, altered
profiles, truncation and trailing bytes are rejected.

All founder, revocation, checkpoint and immutable fund authorization keys in the
file are public verification material. The file contains no signing key, seed,
wallet viewing key or private payment opening. Initial fund destinations must
match the configured member count.

The actual `SnapshotState` retains its selected fee mode. Genesis recent roots,
compact execution commitments, full component reconstruction and checked-delta
previews use that same fee kernel. The legacy mode uses the existing fee base;
the separately unactivated destination prototype uses its reduced base. A
state encoded under one kernel cannot silently pass reconstruction under the
other. Existing native V1 configuration bytes and genesis identifiers are not
modified by this new format.

The legacy engine verifies actual native transaction and issuance proofs, the
existing fixed-576 settlement relation, public fund-claim authorization and debit,
and governance signatures. The unused fee-output slot must contain only zero
bytes. It derives all eleven execution components from the checked chain delta
and actual candidate ledgers and compares their aggregate with the full header.
Only after these checks does it publish chain state and typed ledgers together.

`CommittedBlock` has no public constructor and exposes governance inclusions only
after successful engine publication. It certifies in-memory publication, not disk
durability. A host must durably save the accepted block and corresponding state
before exporting unified governance records or reporting durable acceptance.

The optional `eng2-rehearsal` feature provides the offline entry point
`siworld-eng2-rehearsal NEW_DIRECTORY --fee-mode legacy-miner --blocks 28 --json`.
It creates real native padding and settlement proofs, uses the versioned reward
plan, commits complete header/body history with immediate redb durability, scans
wallet public data under the accepted eng2 identities and attempts a mature
reward transfer and a private-pipe synthetic fund claim at height 26, after a
padding block at height 25 makes the first reward mature in the accepted parent
state. Height 27 consolidates mature rewards; height 28 pays the initial 50 SIP
issuance fee to the dedicated destination and produces a native three-note asset
issuance proof.
Signed governance proposal and cancellation records are exported after durable
publication. A fresh independent engine checks every block's
eleven-component commitment. These operations are executable acceptance steps;
their presence is not evidence that a run has passed.

`eng2::store::Store::audit_existing` deliberately verifies the entire retained
history. It is an audit entry point, not the normal production restart path.
The authenticated committed-state restart path is described in the resident
runtime specification and must be measured on the actual accepted native
fixture. The offline log does not activate a listener, live synchronization or
a miner daemon.
