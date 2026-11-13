# Inactive semantic suite and unified fee-windowed body

This candidate is not selected by a genesis, Engine, Store, producer or transport.
Its framing tests use synthetic inner proof bytes, not valid STARKs. It does not
establish V2 transaction or issuance verification qualification.

`CandidateSemanticSuite` is constructed only from local fee source/limit inputs,
existing V2 transaction, issuance and CompleteFee backend profiles, the proposed
body layout identifier, and the existing fund/governance minimum windows. Its
two transaction/issuance qualification bytes are fixed to zero. Backend profile
IDs do not identify their AIR programs, exact keys or complete statement paths.
There is no activation method; `activation_supported()` is always false.

Semantic encoding excludes network, genesis, rules and final frame identities.
A future complete registry must authenticate all relation AIR/key/codec semantics
first, commit them and execution rules into a rules record, derive genesis, then
derive each frame identity with genesis/rules binding. A final per-genesis frame
profile cannot be an input to the earlier semantic/rules hash. The present code
neither derives nor selects a new genesis or a completed registry.

`CandidateRegistry::for_candidate_framing` is a local framing description with
explicit expected network/genesis/rules and three relation identities. Those
values must not come from the incoming body. It rejects missing context, wrong
relation tags and the generic Settlement relation in the fee slot. It does not
authenticate keys, relate supplied profiles to real preprocessing, or confer
canonical admission. The CompleteFee child factory must independently rebuild
and compare its exact shape and preprocessing identity.

## Candidate layout

The fixed prefix is 164 bytes. All integer declarations use little endian.

| Field | Bytes |
|---|---:|
| `SW2BFWA1` layout identifier | 8 |
| network, genesis, rules, semantic suite ID | 128 |
| actual inclusion height | 8 |
| complete encoded length including prefix | 8 |
| complete fee frame length | 4 |
| following payload length | 8 |

One complete relation-4 frame immediately follows the prefix. The payload then
contains a two-byte native slot count, five one-byte mode/count fields, subsidy
reward records, one fee-output record, fixed windowed fund claims, bounded
windowed governance records, issuance records and transaction records. There is
no second fee-proof field, legacy fund/governance list or nested legacy body.
Native body slots remain 64 through 576 in groups of 16; CompleteFee's internal
576 commitment reconstruction remains the separate checked-input adapter's job.

`Body` is reused as an in-memory record carrier. Its `settlement_proof` holds the
sole fee frame and its legacy operation lists must be empty. Its V1 encoding is
not emitted or accepted by this candidate reader. Windowed authorization
structural checks and record codecs are reused. Signatures bind their existing
network/window/role/sequence fields; genesis/rules are bound by this full body.
Direct per-signature genesis/rules binding remains an activation decision.

The reader checks prefix context, complete length, fee and payload declarations
before receiving the fee. The existing declaration-first receiver checks its
48-byte header before fee-frame allocation. Only then does a bounded payload
reader process counts and records. Every variable record declaration is checked
against both its codec maximum and remaining payload before allocation. The
adapter never buffers the combined encoded body; retained record decoding can
still temporarily hold one bounded encoded record plus its decoded object.
Future transport accounting must charge all retained decoded objects together.
The caller supplies the transport deadline and verifies the selected complete
header/body commitment. Receiving a structurally valid body proves no proof,
signature, authorized output, canonical membership or ledger transition.

The canonical body commitment streams exactly the prefix, unique fee frame and
payload under one candidate domain. `PreparedCandidateBody::prepare` provides an
immutable borrowed view and that same commitment for future producer/validator
adapters. It is a framing view, not an authenticated parent or state capability.
The old body format, `SW2BWIN2`, wrong genesis/rules/suite/height/lengths, relation-2
fee substitutions, legacy operation mixing, noncanonical ordering, malformed
windows, trailing payload and truncation are rejected at their respective layer.

## Shared transition integration contract

A future producer and validator must use one selected Engine staging path:

1. Select the complete registered rules and framing locally. Decode and prepare
   this one immutable body view; bind its one commitment into the complete header.
2. Capture the actual parent, generation, height and all eleven state components.
   Freeze only previously included governance whose delay has elapsed, once.
3. Verify every exact transaction with the registered V2 transaction verifier,
   including its authenticated snapshot fee basis, plus issuance proofs and fees.
   The retained `NativeTransactions` type alone is not that V2 qualification.
4. Derive one ordered CompleteFee statement from those checked transactions,
   the canonical deterministic tail, frozen full destination and this body. Run
   the sole trusted child verifier outside the owner lock. Bind its request to
   this same body commitment and captured parent/state context. A receipt only
   echoes the captured context; it does not authenticate that context or grant a
   delta. Recheck the actual canonical context after the child completes.
5. Apply this body's windowed signatures against the frozen authorization state,
   current keys, counters, recipients and balances at the real inclusion height.
   Advance economics and funds once, append subsidy-only rewards and exactly one
   verified fee output, and prepare one complete state delta/commitment.
6. Publish through the ordinary Engine/Store capability and transaction only
   after all checks pass. The producer's header preparation and validator's
   acceptance must consume the same staged result and enforce stale-parent rules.

Do not combine old `PreparedBlock` ledger advancement with a second independent
`prepare_candidate` advancement. Neither current helper can be attached directly
to a new header while preserving the old body's commitment rule. The selected
Engine, V2 verified-input capability, single ledger delta, child supervision,
state recheck, crash/reopen, branch/import and wallet/WASM paths remain required.
No such path is activated by this candidate.
