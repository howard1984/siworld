# Inactive CompleteFee input and reception adapters

`eng2::fee_candidate` is not used by the retained Engine, Store, producer or
transport. It does not register a genesis or change an accepted block format.

`NativeCheckedFeeInputs::from_native_checked` consumes `NativeTransactions`.
The latter can only be obtained by running the native transaction and issuance
verifier on a prepared block. There is no constructor from public commitment
arrays, serialized manifests or verification-child receipts. This establishes
block-local provenance only: the retained native transaction verifier is not a
registered V2 transaction suite, and this adapter grants no canonical admission
or ledger-transition authority.

The adapter requires confidential-destination state, takes the full fee address
from previously activated governance, maps the derived reward and fee policy,
and retains the actual checked body and parent lifetime. It takes transaction
fees in canonical body order, then appends the deterministic zero-fee tail from
`state::tail_slots(network, height, native_body_slots)`. The native body has
64 through 576 slots in groups of 16; the CompleteFee statement always has 576
commitments. Native dummy transactions remain in the body prefix. Internal tail
rows are not additional transactions and are not public real/padding labels.
Fee tiers remain authenticated by each transaction's snapshot fee root; the
settlement adapter does not reclassify historical fees using inclusion height.

`statement()` derives the list digest, full address and ciphertext, commitments,
policy and genesis/rules binding from the held object, then calls the existing
CompleteFee facade. It performs no verifier setup or proof verification. The
result still needs independently selected trusted verifier configuration,
isolated verification and current-parent checks before any future transition.

`LocalFeeSuite` exposes only the local source-program identity and existing
proof-limit bytes for the fee portion of a future semantic rules manifest. It
excludes genesis, rules and the derived frame identity. A future registry must
first select a complete genesis-independent semantic suite and rules, then
derive genesis and the CompleteFee frame identity. Feeding the final frame
identity back into genesis hashing would introduce a circular dependency.
No full-suite registry or additional cryptographic parameters are selected here.

The separate `receive` adapter accepts checked declarations for a proposed
fee-first data portion: one CompleteFee frame followed by one bounded body
payload. Its declared total excludes outer framing bytes. It reuses the existing
V2 receiver: declaration, then the 48-byte identity/inner-length header, then
frame allocation and reading. Only afterward may a supplied body parser read
exactly its declared payload through `Read::take`. The combined encoded body is
never buffered by this adapter. The caller must supply its trusted identity and
transport deadline. A future selected outer layout and semantic body parser
remain required; retained V1 body ordering cannot call this adapter unchanged.
Structural reception is not proof validity or a state-transition capability.

Remaining integration includes one selected fee-and-windowed-authorization body
and commitment rule, real transport and import readers, a registered V2
transaction verifier, bounded child statement encoding and trusted verifier
factory, cold-memory/deadline qualification, and one shared producer/validator
transition. That transition must freeze prior governance once, advance funds
and economics once, append exactly one verified fee output, and preserve
subsidy-only miner rewards. Engine/Store/restart/branch paths and wallet/WASM
snapshot fee-mode handling must agree before activation.
