# Local operation files

Status: bounded native preparation, signing and body-import interfaces for the
separately activated local network. No command in this tool submits an operation
or changes chain state. The actual shared engine must verify the complete block,
its execution commitment and settlement proof before adoption. Public-network
activation and a production fund-key custody adapter are separate requirements.

## Command interface

Build locally with:

```sh
cargo build --offline --locked --manifest-path crates/native-node/Cargo.toml --bin siworld-eng2-operations
```

With no arguments, `siworld-eng2-operations` reads one public JSON command from
standard input. The command uses sorted, compact canonical JSON; one terminal
newline is permitted. Duplicate or unknown fields, alternate integer encodings,
uppercase hexadecimal and inputs exceeding 1,400,000 bytes reject. Public byte
fields use lowercase hexadecimal. Heights, counters, sequences and amounts use
canonical decimal strings, preserving integers larger than JavaScript's exact
number range. Bounded member and signer-slot indices use JSON integers.

A prepared command file can be canonicalized and executed without a shell
interpolating its contents:

```sh
python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin),sort_keys=True,separators=(",",":")),end="")' < public-command.json | crates/native-node/target/debug/siworld-eng2-operations > public-result.json
```

Supported public operations are:

| Operation | Input fields besides `operation` | Result |
| --- | --- | --- |
| `claim-prepare` | `network`, `height`, `member`, `amount_atoms`, `counter`, `destination_hex`, `authority_hex`, `rseed_hex` | Unsigned `claim_hex`, complete signing message/context and `review_digest` |
| `claim-attach` | Unsigned `claim_hex`, independently selected `authority_hex`, detached `signature_hex` | Canonical claim with its actual ML-DSA-65 signature verified |
| `governance-prepare` | `network`, `sequence`, `action` | Canonical unsigned request, required roles, complete role-bound signing messages/context, review digests and activation delay |
| `governance-wrap` | `request_hex`, ordered `signatures` with `role` and `signature_hex` | Canonical signed-action framing; authentication remains an engine check |
| `bundle-check` | `network`, `height`, `bundle` | Validated canonical pending-operation framing; signatures remain unverified |

The full claim destination is the 1,232-byte canonical owner-plus-KEM address.
The immutable fund member authority is a complete 1,952-byte ML-DSA-65 public key.
`rseed_hex` is the public note's canonical 48-byte field encoding. The public
fund claim format deliberately discloses the note opening and encapsulation
coins; it must never be used for confidential fees or wallet payments. Preparation
uses fresh OS encapsulation randomness but neither generates nor opens a key.

A valid signature does not prove released entitlement, the active recipient,
current member counter or current chain eligibility. Those checks occur against
the actual block's frozen governance and sole fund ledger. The tool marks
`submitted` and `state_changed` false, and explicitly leaves unchecked properties
false. Claims are bound to an exact inclusion height; prepare a new claim if the
candidate height changes.

## Internal rehearsal signing

Explicit private-pipe modes sign prepared public fund claims or individual
management authorizations:

```sh
siworld-eng2-operations --sign-claim-pipe NETWORK_HEX EXPECTED_AUTHORITY_HEX
siworld-eng2-operations --sign-governance-pipe NETWORK_HEX ROLE EXPECTED_AUTHORITY_HEX
```

Network and expected authority are independently selected public identities.
The caller must supply an unrecorded private pipe from the local rehearsal harness.
The adapter validates frame bounds and EOF, and does not inspect the operating-system
type of standard input. A regular file or terminal can also provide framed input.
The framing is:

1. A four-byte big-endian public-command byte length.
2. Canonical public JSON with exactly `operation:"claim-sign"`, `claim_hex` and
   `confirmed_digest` matching the prepared `review_digest`.
3. A four-byte big-endian private-input length equal to 32.
4. The existing disposable signing seed, followed immediately by EOF.

The seed is never a JSON field, argument, environment value or output. A
mismatched network, public key, review digest, private input width or trailing
byte rejects. Seed, expanded signing-key and signing-randomness owned buffers
are erased on release. Dependency-internal copies, the caller's seed storage,
swap, process compromise and operating-system capture remain outside that
claim. The adapter does not create, read or manage a persistent key file and
must not be treated as production custody.

The private mode is limited to owner-controlled internal rehearsal with
separately provisioned temporary synthetic keys. A production encrypted custody
adapter remains required before using this interface for long-lived fund keys.
Only fixed public failure JSON is emitted; raw private input and backend errors
are never printed.

The governance role is `founder` or `revocation`. This mode uses the same bounded
frames. Its public JSON has exactly
`operation:"governance-sign"`, `request_hex` and `confirmed_digest`; the digest
must match the selected role's `messages[].review_digest` from preparation.
The digest binds the canonical action, including network, full sequence and role.
The expected public key is selected independently through the command arguments
and must match the key derived from the private frame. A checkpoint role or an
owner role inappropriate for the action is rejected. Signing uses operating-system
entropy and returns an error when entropy is unavailable.

A successful result contains the detached public signature and marks
`signature_verified:true`, `chain_state_verified:false`, `state_changed:false`
and `submitted:false`. This verifies only the selected key's signature; active
owner authority, current sequence and admission remain shared-engine checks.
Joint actions require separate invocations for both roles before ordered wrapping.
The wrapper continues to report signatures as unverified against chain state.
This interface is for existing disposable internal-rehearsal keys, with no key-file
lookup, encrypted custody, graphical interface or network operation.

## Governance requests

Action objects use these exact variants:

- `propose-destination`: `type`, `target:"fees"`, `address_hex`; for
  `target:"fund"`, also include `member`.
- `cancel-destination`: `type`, `proposal_sequence`.
- `rotate-owners`: `type`, `founder_hex`, `revocation_hex`.
- `replace-checkpoint-signers`: `type`, `replacements`, each containing `slot`
  and `key_hex`, strictly increasing slots within zero through two.
- `cancel-joint`: `type`, `proposal_sequence`.
- `propose-issuance-fee`: `type`, decimal-string `amount_atoms`.
- `cancel-issuance-fee`: `type`, decimal-string `proposal_sequence`.

Founder authorization proposes destinations and public issuance-fee amounts;
revocation authorization cancels the corresponding pending proposal. Cancellation
variants cannot cancel another operation kind. Rotation, signer replacement and
cancellation of either joint change require both active management roles. The canonical
shared governance engine enforces current keys, sequence, activation boundary
and replay protection. Wrapping a single partial does not make a joint operation
eligible. No command activates or cancels a pending change outside that engine.

The issuance fee starts at 50 SIP (5,000,000,000 atoms). Genesis bounds are
1 through 10,000 SIP inclusive (100,000,000 through 1,000,000,000,000 atoms).
These three parameters are fixed by this rules version. A founder proposal takes
effect exactly 4,032 blocks after inclusion. Only one issuance-fee proposal may
be pending, and revocation cancellation must commit strictly before the effective
height. Fee proposals share the existing network-bound monotonic governance
sequence; cancellations do not reset it. The active amount, immutable parameters,
activation epoch and pending proposal are encoded in canonical governance
component 8 (`SWG2GOV2`), which the shared execution commitment binds. The state
exposes distinct active amount and pending amount/sequence/heights for clients;
a pending proposal does not replace the active amount. Recipient and issuance
payment verification remain shared-engine responsibilities.

## Candidate-body import and committed records

The canonical bundle has exactly `version:1`, `network`, decimal-string `height`,
`fund_claims` (claim hexadecimal strings) and `governance` (signed-action
hexadecimal strings). It accepts at most eight claims, strictly increasing member
indices, and at most 32 governance actions, strictly increasing sequences.
Every record must match the bundle network and inclusion height where applicable.

`PendingOperations::decode(bytes, expected_network, expected_height)` validates
only this public framing. `attach_to(candidate_body)` fills a matching empty
candidate body; a wrong context or existing operation leaves that body unchanged.
The caller then uses the real shared `PreparedBlock` and proof/commit path.
There is no direct ledger debit or state-apply bypass in this file interface.

`records::committed_governance_records(&CommittedBlock)` produces deterministic,
bounded governance JSON only from the actual engine's nonconstructible committed
block capability. Empty inclusion lists produce no record. The record binds the
network, block height/identity and complete post-execution commitment to ordered
inclusions with full decimal sequence, inclusion/effective heights and action
digest. An issuance-fee proposal additionally includes the exact public
`new_issuance_fee_atoms` decimal string; other actions omit this member. No local
clock, observation identity, private key or candidate success flag is added.

This capability means successful atomic in-memory adoption. The runtime must
finish its durable accepted header/body/state saving before calling the exporter
or publishing its result. The exporter itself performs no persistence, external
notification or network operation. Preparation, signature checks, transaction
verification or a candidate execution commitment alone cannot supply this
committed type. A failed block or failed durable save must publish no inclusion
or success record. The deterministic output lets a runtime identify repeated
exports of the same accepted block, but durable idempotent record-file wiring
remains a host integration requirement.

Fund release uses the canonical fund ledger: half of each credit, rounded down,
becomes available after 24 blocks; the remainder releases cumulatively over 48
periods of 8,766 blocks. Synthetic schedule tests do not establish a running
network claim. A local rehearsal's first claim requires at least 25 genuinely
proved sequential blocks and a committed output, followed by balance/counter
and independent replay checks. No synthetic height jump qualifies.

## Read-only issuance-fee view

`projection::issuance_fee_projection(&Engine, ProjectionHead)` returns only the
public `issuance_fee` object for explicit explorer projection version 2. The
expected head contains the canonical export index's network, genesis, height
and tip. Every field must match the actual engine; governance height and network
are checked independently. No historical or missing amount is defaulted.
Amounts and proposal sequence use exact decimal strings; pending heights use
JSON integers and come from the canonical governance state. Engineering explorer
heads above 1000000 are rejected.

The host must construct the rest of the projection from that same accepted
head, retain the strict field allowlist and publish only after durable state
saving. This getter adds no listener, export loop, relay, publication or runtime
observation. The existing eng-1 wallet-gateway exporter remains version 1.
