# Contributing

## Technical requirements

Keep implementation, tests, and the [protocol specifications](docs/README.md#protocol-specifications)
consistent. Use American English and the [glossary](docs/reference/glossary.md)
for public documentation. Record changes to consensus rules, compatibility,
and serialized formats explicitly.

## Consensus invariants

- Preserve canonical encodings, deterministic ordering, and integer-only state transitions.
- Verify untrusted inputs and proof bounds before allocation or execution.
- Use the same transition rules for production, validation, and replay.
- Check branch rollback, recovery, and rejection paths for consensus changes.
- Preserve dependency locks, reproducible public proof artifacts, and necessary attribution.

## Privacy invariants

Check public fields against the [security model](docs/security/security-model.md).
Keep wallet secrets, private fee openings, customer information, runtime data,
and internal records outside the repository. Use synthetic fixtures to cover
new or changed interfaces.

## Validation

From the repository root, run the publication and audit checks:

```sh
python3 scripts/check-repository.py
python3 scripts/check-audit-registry.py
git diff --check
```

Run formatting, compilation, and the relevant bounded offline tests for
changed source. Use the existing CI policy for validated dependency graphs
and offline test scope. Mining, live-network workloads, and miner packaging
are performed on owner-controlled machines.

## Change review

Describe the behavior, affected interfaces, compatibility impact, and local
validation results. Keep review descriptions technical, and use the
[security policy](SECURITY.md) for private vulnerability reports.
