# Isolated complete-fee public data adapter

The inactive `eng2::fee_child` adapter connects public data reconstructed from
native-checked block inputs to the existing V2 CompleteFee verifier and local
process guard. It introduces no proof parameters, AIR implementation, protocol
registration or ledger-transition authority. No Engine, Store, live transport or
producer entry point selects this adapter.

## Public statement encoding

All integers use unsigned little-endian encoding. Field elements use four-byte
canonical representatives strictly below the KoalaBear modulus; decoding never
reduces an out-of-range word. Digests contain twelve such elements. The encoding
is exactly 30,459 bytes for Voyager rewards or 30,715 bytes for Holder rewards.
The fixed header selects one of these lengths before vector allocation.

| Field | Width |
| --- | ---: |
| Magic `SWFCPU01` | 8 bytes |
| Version, exactly 1 | 2 bytes |
| Reward mode, Voyager 0 or Holder 1 | 1 byte |
| Reserved, exactly zero | 1 byte |
| Complete statement length | 4 bytes |
| Network and ordered transaction-list digest | 32 bytes each |
| Inclusion height, standard fee, priority fee | 8 bytes each |
| Settlement capacity, exactly 576 | 2 bytes |
| Policy fee owner and complete address owner | 48 bytes each |
| Complete ML-KEM-768 encapsulation key | 1,184 bytes |
| Ordered fee commitments, including canonical tail | 576 times 48 bytes |
| Each reward allocation amount, unlock height and commitment | 64 bytes |
| Dedicated fee-note commitment | 48 bytes |
| Complete payment KEM ciphertext | 1,088 bytes |
| Payment body, authentication tag and view tag | 208, 16 and 1 bytes |

The reward mode determines exactly one or five reward entries. The decoder
rejects unknown versions or modes, reserved bits, length disagreements, trailing
bytes, noncanonical field words, invalid public keys, inconsistent owners, zero
network or transaction-list identifiers, invalid reward plans and inconsistent
fee tiers. Public statement reconstruction still uses the existing CompleteFee
facade. The standard fee is reconstructed through the existing fee-schedule
constructor; no alternate tier rule is introduced.

`NativeCheckedFeeInputs::canonical_child_statement` exports only these public
fields from its held native-checked context. Its fee commitments preserve native
transaction order and use the existing deterministic zero-fee tail to reach 576
entries. The encoding contains no openings, blinds, fee-note value, wallet keys,
encapsulation coins, witness trace, arbitrary AIR, PCS key or public vector.
Encoding or decoding public bytes never constructs a native-checked capability.
Historical transaction fee tiers remain authenticated by the individual
transaction proof's retained snapshot basis, rather than by a new test against
one inclusion-height tier.

## Fixed local verifier configuration

`TrustedFactory` receives its network, protocol binding and expected complete-fee
frame identity from the fixed local adapter. These are configuration inputs;
constructing the factory does not authenticate or register them. A request file,
proof or receipt cannot select another AIR, relation or key. The AIR source
identity must match the existing CompleteFee source closure.

The existing composite frame profile already commits to genesis, rules, AIR,
proof parameters, preprocessing commitment, codec and trusted geometry. The
adapter uses this exact composite identity for both the guard's profile and
verifier-key binding fields, and checks the independently rebuilt verifier's
identity against it. It introduces no separate key hash or key-selection scheme.
Registration must first commit to genesis-independent suite inputs, then derive
rules and genesis, and only then derive this per-genesis frame profile.

The child input reader checks declared sizes and exact request-file length,
reads and checks the 48-byte complete-fee header against the fixed identity, and
only then allocates the bounded proof and statement bodies. The factory checks
all configured request bindings and both content digests, decodes the canonical
public data, reconstructs the statement and rebuilds the existing deterministic
preprocessing locally. This setup remains a substantial resource operation; no
fixed-root-only verifier is installed by the adapter.

## Process outcome and admission boundary

`PreparedRequest` borrows the original native-checked input and takes its sole
fee frame directly from that held body's settlement-proof field. The factory
accepts no external proof slice, including another proof of the same statement.
The existing `FeeGuard` stages that request and supervises one child. The factory provides a
library child entry point that creates no subprocess and emits no logs. A
platform integration must select and pin a fixed executable and mode; no such
executable mode is activated here.

The child emits a Verified or Rejected receipt only after configured statement
reconstruction and exact verifier-identity comparison. Invalid proof bodies and
semantic verification failures produce Rejected. Input mismatch, local setup or
configuration failure produces no semantic verdict. The guard treats process
failure, timeout, malformed output or binding mismatch as local deferral.

A receipt remains a process result. It grants no Engine or Store mutation
permission and does not replace the canonical owner's later context comparison.
Attempt identifiers must be unique within the private scratch space. The owner
must capture the canonical context independently, run outside owner locks, and
recheck that exact context before separately authorized admission.

The guard's existing deadline covers its hashing, staging, child startup, setup,
verification, exit and receipt comparison. Parent transaction checking and
canonical statement construction occur before that call. A complete operational
deadline, process resource containment, executable provenance, registered V2
transaction suite, network activation, wallet generation and joint disclosure
review remain integration and acceptance requirements.
