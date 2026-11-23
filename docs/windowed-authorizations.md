# Windowed authorizations

The candidate authorization formats sign an inclusive inclusion interval. Both
endpoints are block heights. `valid_from` must be positive, and `valid_until`
must be at least `valid_from + 287`; overflow is rejected. This interval does
not bypass current authority, sequence, recipient, balance or spend-counter
checks. An authorization can be consumed only once in an accepted chain state.

## Canonical records

`WindowedFundClaim` uses the `SW2F` magic with version 2 and the V2 fund-claim
signature context. Its embedded `PublicFundClaim.height` is the first permitted
inclusion height. Its extra eight-byte `valid_until` field is signed together
with every original claim field. The version 1 exact-height claim codec remains
unchanged and rejects version 2 bytes.

`WindowedSignedAction` uses the `SWG2WIN2` magic, two eight-byte height endpoints,
and a four-byte length followed by a canonical signed governance action. Each
owner signs the V2 window, complete unsigned action and exact owner role under
the V2 signature context. Legacy signatures cannot authorize this record. The
signed-record limit is the legacy action limit plus 28 bytes. Unsigned requests
contain the same magic and endpoints followed by the legacy unsigned action;
they have a separate bounded decoder.

## Complete body envelope

`WindowedAuthorizationBody` frames the complete body using `SW2BWIN2`. Its prefix
contains the network, genesis identifier, rules commitment, inclusion height,
base-body byte length and operation counts. The canonical base body must have
empty legacy fund-claim and governance lists. Windowed claims follow at fixed
width, then windowed governance actions with individual length prefixes. Mixing
legacy and windowed operations in the same envelope is rejected.

Decoding checks the supplied sealed genesis and exact inclusion height before
decoding the base body. It checks body, record and count bounds before taking or
allocating the corresponding records. Fund members and governance sequences
must be strictly ordered. The complete envelope commitment binds both the base
transaction/proof body and all authorizations under a distinct domain.

## Candidate execution

`prepare_candidate` takes one existing engine so its genesis and parent state
cannot be supplied independently. It validates body framing and inclusion
context, then advances a frozen governance clone to the actual inclusion
height. Previously included operations activate before current recipients are
checked. A separate governance clone executes new actions using the same
activation, authority, sequence and action-transition functions as legacy
execution, with V2 signed messages.

The fund clone advances to the actual inclusion height before claims are
verified against immutable member authorities and current full recipients.
Claim capabilities debit this isolated ledger, including its existing counter
and balance checks. The method returns read-only candidate ledger and output
views. It does not verify transaction or settlement proofs, publish wallet
outputs, produce a committed-block capability, modify an engine or write a
durable store. Failure discards every staged mutation.

## Public preparation and signing

The operation tool accepts the explicit public commands
`windowed-claim-prepare`, `windowed-claim-attach`,
`windowed-governance-prepare` and `windowed-governance-wrap`. Preparation takes
canonical decimal-string endpoints and returns the exact V2 signing message,
context and review digest. Detached-signature attachment does not assert current
chain authority or entitlement.

The explicit local rehearsal flags `--sign-windowed-claim-pipe` and
`--sign-windowed-governance-pipe` retain the existing bounded public-request and
private-seed framing. They require independently selected public identities and
the exact confirmed V2 review digest. They do not provide production key custody
or chain submission.

## Activation boundary

Existing genesis sealing, version 1 body decoding, production, durable-store
admission and networking continue to select legacy authorization behavior.
The candidate envelope and ledger preparation are not an activation mechanism.
Activation requires one explicit genesis/rules/body-version selection shared by
production and validation, corresponding durable restart and network decoding,
operation submission and wallet integration, and reorganization boundary tests.
The candidate code does not select or generate a new proof profile.
