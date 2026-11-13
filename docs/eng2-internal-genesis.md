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

## Public parameter sealing and inspection

The offline `siworld-eng2-genesis` tool seals existing canonical public
configuration and governance component bytes. It does not create parameters,
keys, node state, identities or services. It performs no network operations.
Its availability does not establish that deployment or key custody has been
qualified.

```
siworld-eng2-genesis seal-public CONFIG_RULES.bin GOVERNANCE.bin \
  --expected-config-sha256 C --expected-governance-sha256 G \
  --expected-network N --expected-profile P \
  --expected-fee-recipient-sha256 R --new-genesis NEW_FILE --json

siworld-eng2-genesis inspect GENESIS.bin \
  --expected-config-sha256 C --expected-governance-sha256 G \
  --expected-network N --expected-profile P \
  --expected-fee-recipient-sha256 R --json
```

All five independent expected values are mandatory 32-byte lowercase
hexadecimal strings. Configuration and governance are the existing canonical
`Config::encode_rules` and `GovernanceState::canonical_component_bytes` formats;
there is no additional consensus manifest format. Configure the complete
allocation, authority roles, checkpoint slots and payment destinations in a
separate public parameter preparation step. This tool never chooses them.

Both commands require non-fixture ASERT rules with production economic timing,
nonzero timestamp and target, canonical work selector zero, interval 300 and
work iterations in 1 through 1,000,000. Ordinary transfer fees remain explicitly
`LegacyMiner`. The issuance fee owner must equal the actual governance fee
owner, and the complete 1,232-byte fee destination must match R. Matching only
the owner with a substituted encapsulation key is insufficient.

The fixed known-fixture denylist contains SHA-256 fingerprints of public
ML-DSA-65 keys already reproducible from the repeated-byte seeds 1 through 5,
83 and 84, and the 24-member registry derivation in
`Config::with_test_fund_registry`. The tool contains only their fingerprints
and performs no key derivation. This finite check cannot establish that an
arbitrary key is privately generated or that a custodian controls it.
Independent authority signature and custody qualification remain necessary.

Input files must be bounded regular files without a final symlink. Config
length is exact; governance length is at most 131,072 bytes. A fixture flag is
rejected before shared configuration decoding can reach development helpers.
The output file must not exist. Sealing performs all semantic checks before
exclusive creation, writes and synchronizes the file, and on Unix synchronizes
its parent directory. It never overwrites or removes files. A write or sync
failure may leave a partial new file; inspect it separately rather than retrying
against that path. Inspection performs no writes. A relative or symlinked
parent path is resolved by the operating system; the caller selects the explicit
public input and output directories.

The receipt reconstructs the actual genesis state and reports all eleven
ordered execution-component byte lengths and domain-separated component digests.
Tree and nullifier execution encodings use the existing compact commitment
formats; full snapshot bytes carry the reconstruction vectors. Their byte lengths
and snapshot SHA-256 values are reported separately. The aggregate of execution
components must equal the direct execution commitment. Individual component
digests and the aggregate h0 root are separate fields. The receipt also reports
the genesis, rules, proof profile, peer verifier, exact public input hashes,
ASERT parameters and public authority/destination fingerprints. It does not
claim that an h0 block was mined.

The command reports the executing binary SHA-256. Its source commit is not
inferred or accepted as verified from a caller string. A separate build receipt
must bind the exact source archive, locked dependencies, command, toolchain,
target/features and binary hash. No provenance reporting field changes the
existing genesis encoding or rules-commitment formulas.

Failures return structured JSON with fixed error codes and no input echo. A
successful seal is not deployment, block admission, synchronization or proof
of authority-key ownership. The standalone binary requires neither
`eng2-runtime`, `native-p2p` nor `eng2-rehearsal`.

## Encoding public parameters

`encode-public` prepares the two existing canonical inputs to `seal-public`:

```
siworld-eng2-genesis encode-public PUBLIC_PARAMETERS.json \
  --expected-input-sha256 H --new-parameters NEW_DIRECTORY --json
```

H is the independently checked SHA-256 of the exact public JSON input bytes.
The input is a bounded regular file, at most 262,144 bytes, without a final
symlink. The output directory must be absent. All semantic checks and canonical
roundtrips finish before directory creation. It contains `config-rules.bin` and
`governance.bin`; no genesis, key, identity, chain database or service is created.
Files and the directory are synchronized. A filesystem failure may leave a
partial new directory; preserve and inspect it rather than overwriting it.

The input object contains exactly the following fields. Uppercase names in this
illustration stand for actual lowercase hexadecimal public encodings; the
illustration is not an executable fixture.

```json
{
  "version": 1,
  "network": "NETWORK_HEX",
  "proof_profile": "PROFILE_HEX",
  "fixture": false,
  "work_bits": 0,
  "genesis_timestamp": "TIMESTAMP_DECIMAL",
  "genesis_target": "FF_REPEATED_32_BYTES_LOWERCASE_HEX",
  "pow_iterations": 1,
  "target_interval": 300,
  "economics": "production",
  "fee_mode": "legacy-miner",
  "checkpoint_threshold": 2,
  "checkpoint_public_keys": ["SLOT0_PUBLIC_HEX", "SLOT1_PUBLIC_HEX", "SLOT2_PUBLIC_HEX"],
  "founder_public_key": "FOUNDER_PUBLIC_HEX",
  "revocation_public_key": "REVOCATION_PUBLIC_HEX",
  "fee_destination": "PAYMENT_ADDRESS_HEX",
  "fund": {
    "team_index": 0,
    "members": [
      {"basis_points": 10000, "public_key": "FUND_AUTHORITY_PUBLIC_HEX", "destination": "PAYMENT_ADDRESS_HEX"}
    ]
  },
  "issuance": {"max_metadata_bytes": 256, "max_per_block": 4}
}
```

Network and profile are 32 bytes. Each authority public key is exactly 1,952
bytes; each payment address is the existing 1,232-byte canonical encoding.
Copy public checkpoint keys from separately prepared `public_key_hex` values
in slot order, and payment addresses from `address_hex`. No custody file,
private seed, private key or secret field belongs in this input. Unknown fields
are rejected at every object level. The timestamp is a nonzero canonical decimal
u64 string without leading zeroes. Members number from one through 32; positive
basis-point shares sum to 10,000, the team index selects an existing member, and
fund authorities are distinct. Existing configuration and governance validators
check addresses, issuance limits, owner keys and the three nonzero distinct
checkpoint keys. Public bytes and distinctness do not prove independent key
custody or possession.

This command deliberately selects the minimum initial nonfixture ASERT work:
target bytes are all `ff`, iterations are one, the interval is 300 seconds and
economic timing is production. Later targets follow the existing ASERT rule.
Zero-iteration fixtures, other targets, intervals, work selectors, fee modes,
thresholds and profiles are rejected. These input restrictions do not modify
consensus validation or the runtime. The original sealer's known fixture-key
check remains in effect.

The encoder uses `Config::encode_rules` and
`GovernanceState::canonical_component_bytes`, their existing decoders, genesis
sealing and the same public-context checks as `seal-public`. The receipt reports
computed config, governance and fee-recipient hashes and the reconstructed
public genesis identity. These hashes describe the encoder's output; they do
not independently establish key ownership or a deployment approval. Compare
both output files with the reviewed public parameters, then pass their checked
hashes and network/profile/recipient pins to the existing `seal-public` command.

The three-key roster still needs two distinct votes. Two service nodes can
load slots zero and one while slot two remains an unconfigured local backup.
Slot zero must be online to propose. Each resident loads at most one signer;
miners may keep `checkpoint_key` null. A backup prepared on a service host does
not provide a third independent host failure domain.
