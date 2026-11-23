# Payment confirmation and checkpoint coverage

The checkpoint coverage described here is the acceptance contract for the
checkpoint-bounded network profile. An integration must verify that the
profile and the coverage query are actually supported before relying on them.

A payment with no authenticated inclusion in the accepted chain is
**unconfirmed**. A payment included in the accepted chain is **included** and
may show its confirmation count. It can still be moved or removed by a branch
change above the checkpoint. A payment is **checkpoint covered** only when a
verified, accepted checkpoint attests to a canonical prefix containing the
payment. No confirmation count substitutes for that evidence. Payments are
final once covered by a checkpoint, under the stated signer assumptions.
Before that, a payment can still be reversed. Safety assumes a quorum
intersection cannot sign incompatible histories and that the governance
recovery authorities are not compromised.

For exchange deposits, merchant orders, and other large or irreversible
deliveries, wait for checkpoint coverage before marking a payment as settled.
Check the expected network and genesis, successful matching of the payment
to the order, and the exact statement and block identity. A supported
payment query must bind the statement to an accepted receipt and that receipt
to the same authenticated chain view as the accepted checkpoint. Do not
treat an unsigned height, a service boolean without verifiable evidence, a
receipt from another block, or a pending certificate as finality.

An integration should store the confirmed statement ID, inclusion height and
block ID, and accepted checkpoint identity alongside the deposit or order.
Credit idempotently by the network and statement ID. A reorganization can
change a provisional payment's inclusion; update that view without issuing a
second credit. A stale service, missing receipt, failed signature, or
conflicting evidence is an unavailable result. Do not release delivery on
that result or reinterpret a previously verified settlement using a lower
untrusted checkpoint.

If checkpoint issuance pauses, previously verified coverage remains in
force under the checkpoint trust assumptions. A payment above the latest
checkpoint remains provisional even when its confirmation count grows. The
checkpoint mechanism does not guarantee availability against partitions,
censorship, or compromised signing assumptions.

A native integration can call `eng2::wallet_history::payment_status` under
the canonical owner lock with a `Head` pin, payment height, block ID and
statement ID. It returns typed canonical membership, confirmations and
checkpoint evidence. Read errors propagate separately from absence in the
specific hinted block.

The read-only wallet API also supports
`GET /api/v2/wallet/payment-proof/N/I?height=H&tip=T`, where N and I are the
known payment block height and identity. The payload starts with the eight
bytes `SWE2WPF1`, a little-endian 32-bit receipt length, and a little-endian
16-bit certificate length, followed by the exact receipt and the signed
certificate. For an independently verified history, compare the receipt
statement with the expected ID and require the signed checkpoint to cover the
payment block height. The browser checks two signatures against the three
keys pinned by genesis and requires the replayed active roster to match. It verifies the linked
headers (whose identities bind the execution and body commitments) and
receipt membership without executing RandomX. An unsigned suffix is
provisional, and its declared targets do not establish verified work.
Native nodes and native wallets keep full header work verification. Both the checkpoint block
and its authorization block must be proved members of that selected history.
A wallet without a verifiable proof that pins the current signer lineage
makes no new finality claim after an authenticated roster change. The request does not send
the statement ID or a wallet address to the server.

A current read service may be unable to prove a formerly accepted
certificate after its authorization block has been replaced above the signed
checkpoint. Consumers retain previous authenticated evidence through such a
reorganization and continue treating newly unprovable settlements as
unavailable until a usable certificate is published.


Each received history row identifies an exact output found when decoding the
receipt authenticated by its inclusion header. For a sent payment, the browser
creates a private local attestation only after checking the exact statement
against that receipt. It uses the original genesis, statement, height and
inclusion block ID when reopening this attestation. A header alone cannot
authenticate an outgoing payment. Evidence from receipts materialized before
proof pruning is checked in the same way as an unpruned receipt. This proves
membership through the inclusion header's body commitment and the header
path to the signed anchor; it does not expose an individual path through the
anchor's execution commitment.

If both the accepted view and a fully scanned rival view have valid
incompatible quorum certificates, the browser retains the first accepted
checkpoint and shows **Finality suspended**. A divergent head, unauthenticated
status flag, or missing receipt does not establish a conflict. The current
read service supplies only the proof for its selected view; it does not
supply portable competing-view or recovery proofs. A capable client leaves
finality suspended until it has supported, verified signer recovery evidence.
