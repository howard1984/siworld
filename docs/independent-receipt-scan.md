# Immutable engineering receipt scans

The receipt scanner authenticates a complete header/receipt prefix and reconstructs a fresh private wallet independently of transaction generation. It reuses the existing eng-2 header, receipt-range-proof, decryption and light-wallet implementations without changing their protocol rules.

Only sealed synthetic in-memory history and a publicly reproducible disposable identity are implemented. No filesystem, live database, real-custody, key-import or network backend exists. The optional receipt-scan-synthetic feature enables fixture construction and a closed example executable. It is disabled by default. Enabling it does not qualify any native consensus execution or production custody.

## Authentication and accounting

Every input frame is bound into an immutable SHA-256 generation. The scanner requires every height from 1 through the pinned tip, validates the exact header and body receipt, and calls Eng2LightState::append for work, difficulty, continuity, output frontier and receipt authentication. It fails closed on incomplete coverage, generation mismatch, resource limits and unsupported context.

Public outputs have complete origins: block ID and height; transaction statement/slot/output, issuance declaration/record/output, reward ordinal or fund account/counter/ordinal; and commitment. A category output_index alone is not a persistent identity. Positive owned commitments must have an unambiguous canonical origin.

All canonical transaction nullifiers are collected separately. Each owned spent bit is compared with canonical membership. Received/spent/unspent/mature/locked totals use checked u128 amounts and checked u64 counts by asset. Both received=spent+unspent and unspent=mature+locked are enforced. Maturity uses the committed unlock_height and an explicit spend_height. Explicit zero expected asset rows are negative assertions; extra observed assets or nonzero amounts cannot be omitted.

Replacement histories start from a fresh wallet. No old receipts, balance cache or spent flags are imported. This removes orphan-only notes and orphan-only spends. The disposable branch cases cover a retained note becoming unspent again, a replacement conflict spend, a note changing origin and two assets.

## Trust and format limits

The trust model remains eng2-header-work-and-body-receipt-authenticated-full-node-consensus. The scanner does not verify native transaction/issuance/settlement proofs, execute governance or recompute all execution-state components. Its light-wallet tree carrier fingerprint is not an eng-2 execution commitment.

The fixture bodies contain structural proof placeholders and synthetic reward amounts/assets. Their execution commitment is a synthetic marker. They are receipt-authentication fixtures, not native-valid blocks, accepted network data or native/privacy qualification. A successful synthetic comparison cannot establish production balances or deployment readiness.

The implementation supports the eng-2 receipt context with SWE2 header version 2, SWE2WLT1 receipts, legacy fee mode and the compiled proof profile. The context parser checks that profile against bootstrap bytes authenticated by an independently pinned genesis identifier. These checks authenticate header and receipt context; they do not verify native proofs or qualify portable salted V2 generation. The portable payment path still uses the historical transaction prover and verifier. Unknown profiles and fee modes are rejected through the existing context parser. No legacy fallback or consensus parameter change is introduced.

Native use still requires an independently reviewed stable canonical-owner export/snapshot and actual full native state/proof evidence for the identical complete history. The export must bind real execution/state identities, revision/lease and immutable per-height material. Those backends are not implemented here. Real custody must remain on its original host; no default key access is available.

## Disposable fixtures and validation

Synthetic expected amounts and note origins derive from fixed handwritten intents and case arithmetic, not scanner observations or a generator wallet projection. A disposable seed is used only by the explicit synthetic backend. Encryption uses fresh OS randomness. The common public ancestor is reused within one process, so replacement branches share the exact first frame. A fresh process can produce different receipt hashes; its actual fixture generation must be frozen before measurement.

Eight short integration cases cover complete three-block scans, fresh replacement accounting, maturity, malformed/missing history, resource boundaries, checked overflow, complete asset sets and full origins. Two separate ignored resource cases cover a 65-block prefix and a 129-block prefix crossing 128-header pages. Passing short cases alone does not establish either longer prefix.

The example accepts exactly --synthetic-only and an opaque evidence reference. It generates the fixed disposable cases internally. It accepts no history JSON, observed totals, seed, custody path, database path, input file or network endpoint. Standard output contains only status and the opaque reference. No private amounts, note associations or nullifiers are printed.

Elapsed-time checks are cooperative, not a preemptive deadline or RSS limiter. Owner-controlled validation needs an external hard wall-clock, process-memory and output guard. Minimum-difficulty header nonce search is bounded to 256 attempts with pow_iterations 0; no mining, proof generation or real network activity is performed by these fixtures.
