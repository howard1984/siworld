# Native V1 System Overview

Status: native transaction, fixed-576 settlement and three-note issuance proof
parameters are engineering-frozen for relation revision `native-v1-economics-1`.
The profiles bind snapshot-height input locks and revised reward relations to
actual-AIR reports, public keys and measured sources. Release validation and
native node, wallet and network integration remain incomplete. There is no
public native V1 testnet or production network. See the
[monetary rules](v1-economics.md).

**Engineering target ≥80-bit quantum security, pending independent review.**
The target applies to the specified estimator terms; it is not a reviewed
full-system security claim.

## Implementation boundaries

| Area | Present implementation | Remaining native V1 work |
| --- | --- | --- |
| Transaction proof | Private asset IDs, two inputs/three outputs, per-asset conservation, SIP-only fees, ciphertext binding, snapshot-height input locks and measured source-bound profile | Integrated release validation, bounded resource acceptance and complete wallet/node integration |
| Issuance and settlement | Three-initial-note fixed-supply issuance, signed declarations, declaration-bound fee receipts, atomic registry insertion and fixed-576 SIP-only settlement with one/five mode-dependent reward notes; revised keys and resource measurements | Launch-time fund and issuance-limit configuration, complete wallet/network integration and independent review |
| Existing node | Legacy two-output recursive proofs, storage, peer relay and local RPC | It does not activate native V1 |
| Native engineering runtime | Codecs, shared atomic transition, proof admission, exact missing-slot/proof compact recovery and replay interfaces | Authenticated live transport, deployed compact-relay qualification, pruning, checkpoint bootstrap and sustained-load qualification |
| Connection privacy | Hybrid authenticated transport and Dandelion++ designs | Reviewed implementation and actual-listener adversarial tests |

A proof executable or proof-tools image is not a node runtime. The retained
seven-node N=2 legacy engineering testnet keeps its history, verifier and keys.
A native V1 engineering network requires independent genesis, identity,
directories and keys; it imports no retained notes or proofs.

## Transaction flow

The selected design requires the following integrated behavior:

1. The wallet constructs the same two-input/three-output public format for SIP,
   issued assets and padding. Asset IDs are private and bound into notes.
   The relation balances each asset independently and pays fees only in SIP.
2. It generates a native D8/W24 transaction proof and locally checks encrypted
   outputs before broadcast. The AIR binds all ciphertext bytes, but does not
   prove encryption correctness or recipient decryptability.
3. A node resolves a canonical snapshot selector from trusted state, checks
   the bounded encoding and fee-opening sidecar, verifies the proof and
   atomically reserves nullifiers. Timeout/resource failure means unavailable
   verification; it is not evidence of an invalid transaction.
4. A miner selects 64–576 positions in groups of 16, adds valid fixed-shape
   padding and generates one separate native fee-settlement proof. Strict
   ordering by proof-independent BLAKE3 statement IDs and duplicate rejection
   are enforced by the isolated native codec and shared transition; this does
   not establish deployed network acceptance.
5. Compact references avoid retransmitting proofs already held by peers.
   Missing data requires authenticated bounded recovery. Production,
   validation and replay must share one atomic state transition.

The target block interval is 300 seconds; PoW timing is stochastic. Native V1
requires a 24-block local reorganization bound. It accepts the newest 4,096
canonical recent-root-tree snapshots. Expired or orphaned selectors require
transaction eviction and wallet reproof.

## Current transaction profile and measurements

The [three-relation manifest](../crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json)
freezes the revised fixed shapes and public keys; it does not adopt issuance
limits or qualify other capacities. [Reproduction](native-proof-profiles.md)
checks the actual-AIR reports. The separate source-bound
[transaction profile](../crates/bench-multi-asset/artifacts/v1-transaction-profile.json)
uses KoalaBear D8, standard Poseidon2 W24 and twelve-element digests: log blowup
7, 41 queries, query/batch grinding 20, commitment grinding zero, binary folding
and final-polynomial log length zero. The transaction AIR has **256 base rows,
1,392 main columns, 247 preprocessed columns and 101 public values**, with
2,898 constraints, maximum degree three and eight quotient chunks.

Three four-worker EPYC 7763 reference-VM trials took **1.531155, 1.429902 and
1.462878 seconds** for proof generation; the median was **1.462878 seconds**.
Those bodies were **581,392–585,808 bytes**. The selected one-worker trials
reached **588,832 bytes**, and median one-worker verification was
**17.006900 ms**. The four-worker maximum charged process-tree memory was
**525,234,176 bytes**, including preparation, generation, verification and the
recorder. No memory-limit or OOM events occurred. These measurements do not
bound wallet end-to-end latency, grinding tails, independent verifier memory
or whole-node capacity.

The transaction cap is **655,360 bytes (640 KiB)**, at least 10% above the
largest selected one/four-worker sample. Settlement uses a **655,360-byte (640 KiB)**
cap and issuance retains a separate **524,288-byte (512 KiB)** cap. These are admission limits, not mathematical
bounds on every randomized proof. The transaction instance reports
**81.692 quantum-halved Johnson challenge bits**, approximately **185 classical
conjectured bits** and **123.333 BHT commitment-collision bits** under the
selected accounting. Application BLAKE3 bindings and system composition require
separate review. Independent cryptographic review remains required.

## Capacity, storage and roles

The limits below remain planning budgets. Reconcile the revised reward-note,
settlement and permanent-record formats before capacity or storage acceptance.

The complete conditional capacity model gives **43 Mbps minimum uplink** and
**100 Mbps recommended** for 576 positions, three relay copies and bounded
network/recovery overhead. At least 15% of the minimum link remains unused.
Integrated wire measurements and issuance limits are still qualification gates.

Every node permanently retains public ledger data: headers/PoW, commitments
and tree state, ciphertexts, nullifiers, fee commitments, proof-free settlement
declarations, reward notes, signed fund records, issuance records and recent
root snapshots. Transaction, settlement and native issuance proofs plus private
fee sidecars expire three elapsed days after final confirmation. V1 has no
archive-node role. Default bootstrap trusts a genesis-pinned two-of-three
checkpoint authority, then verifies subsequent PoW and blocks; it cannot
reconstruct deleted historical proof validity.

Every validator enforces consensus independently. A miner adds production;
bootstrap services and the panel have no consensus authority. Initial
qualification profiles start at **16 GB RAM for validators** and a separate
**32 GB for miners**, with at least **15 GiB / 30 GiB of system-visible memory**
respectively. These are unqualified profiles. The 5-GiB diagnostic
proof scope is not a miner RAM requirement. Both roles use a 500-GB usable SSD
installation floor and 1-TB recommendation; actual lifetime depends on load,
issuance and database costs. One TB does not cover three full-load years under
the current reserve model.

## Privacy and launch gates

Fee commitments hide fee openings on chain. Sidecar recipients learn those
openings, and producers recognize their own padding. Uniform field counts and
lengths are a design requirement, not a guarantee of perfect indistinguishability.
Connection encryption does not hide endpoints; source privacy requires
separate implementation and adversarial analysis.

Complete the native transition, bounded admission, standalone verification,
wallet recovery, transport/source relay, durable public storage, retention,
checkpoint bootstrap and telemetry. Resolve issuance fees/resource limits and
asset-aware minimum outputs. Then complete independent review, maximum-load
hardware qualification and independent-host testnet observation.

See [decisions](00-decisions.md), [implementation milestones](v1-node-network-plan.md),
[testnet acceptance](prover-acceptance.md) and [the documentation index](README.md).
