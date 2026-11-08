# Offline engineering checkpoint rejection acceptance

Status: explicit acceptance target for Unix engineering fixtures. The target is
excluded from the native runtime package. It provides no node command, network
listener, signing operation or production checkpoint ingress.

Build the executable separately from a reviewed source revision:

```sh
cargo build --locked --release --manifest-path crates/native-node/Cargo.toml \
  --features checkpoint-rejection-acceptance \
  --bin siworld-checkpoint-rejection-acceptance
```

The invoking controller must bind its executable hash and build record to that
revision. It must admit an exact registered disposable validator directory,
its original configuration and transport identity metadata, and its final run.
The acceptance binary does not replace those external registration checks.

```text
siworld-checkpoint-rejection-acceptance DATA EXPECTED_FINAL_RUN_ID CURRENT_CERT OLD_VALID_CERT --json
```

The existing fixture must be stopped cleanly, have no signing authority, have
produced no local blocks and retain its existing exclusive service lease file.
Its immutable final export and current status must match exactly. Its original
outbound, nonmining peer configuration is `fixture-peers.json`. Inputs must be
owner-private, single-link regular files. No initialization or fixture restart
is supported.

The binary holds the existing exclusive lease throughout both database opens.
It uses the production exact-head authenticated restart check with a constructed
`NativeVerifier`. It does not replay proof history or an uncommitted tail,
repair a database, qualify a legacy restart record, migrate a cache, prune or
compact. The established native storage code authenticates the existing local
state seal through the fixture's persistent identity. The acceptance module
does not directly open or hash private identity, authority or wallet material.

The supplied current certificate must equal the actually persisted accepted
certificate. Both supplied certificates must authenticate against the compiled
release roster with the real system clock. The older certificate must have a
strictly lower sequence; importing a new good certificate to manufacture this
cursor is not permitted.

| Input | Production rejection boundary | Evidence scope |
| --- | --- | --- |
| One retained vote | Certificate decoder quorum check | Malformed quorum |
| Second signer changed to an unpinned index | Store authentication, canonical signer selection | Unknown roster index; no newly generated signing key |
| Signed state fingerprint changed | Store signature authentication | Tampered signed bytes |
| Signed block ID changed | Store signature authentication | Tampered signed bytes |
| Unchanged genuinely older quorum | Store persisted cursor | Authenticated sequence rollback |

For the state and block-ID inputs, the untrusted claimed sequence also advances
by one while all original signature bytes are retained. Otherwise the persisted
cursor would reject an equivocation before signature verification. These two
cases do not test an authenticated local-state or greatest-work-chain mismatch.
The separately existing Store tests cover those deeper checks with independent
synthetic authorities and a synthetic chain verifier. Neither evidence category
is a live P2P injection test.

After each rejection and an exact reopen, the binary compares the full state
fingerprint, canonical head and work, exact accepted certificate, stable proof
accounting and policy counters, local reward index, and digests of the committed
state, storage, qualification, checkpoint, finality and restart metadata tables.
Clock-dependent freshness fields and physical redb allocation are excluded from
semantic equality. No claim of byte-identical physical database files is made.

Any unexpected acceptance, rejection layer, state change or reopen failure
returns failure immediately. The executable performs no rollback, overwrite,
fixture cleanup or primary-service operation; preserve the fixture for review.
