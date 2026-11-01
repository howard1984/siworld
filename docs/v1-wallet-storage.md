# Native wallet seed storage and recovery

Status: implemented library interface for engineering integration. This is a
local custody format; it does not change the frozen transaction AIR, note format
or existing wallet derivation domains. A bounded encrypted payment journal is
included. The local web interface and complete valid-chain wallet acceptance
gate remain separate work.

## Recovery identity

`wallet_vault::PendingWallet::generate` obtains 32 bytes from the operating
system and encodes them as a 24-word English BIP39 mnemonic with checksum.
The **decoded 256-bit entropy** is the existing `WalletKeys::from_seed` input.
The BIP39 PBKDF2-derived 512-bit seed and optional BIP39 passphrase are not used.
Importing the words into an unrelated BIP39 wallet is not an interoperability
or asset-recovery mechanism for SIWORLD.

Recovery requires all of:

- The 24 words, in their original order.
- The 32-byte public network ID, encoded as 64 hexadecimal characters.
- The public unsigned 32-bit account index.
- The native wallet entropy derivation version, currently `1`.

The network and account participate in the existing key derivation and must be
recorded with the backup. Changing either produces a different address. The
local encryption passphrase protects the vault only; changing that passphrase
does not change the wallet identity. Repeated restoration of the same entropy,
network and account reproduces the spend, ML-KEM view and sender-change keys.

## Creation and mandatory backup acknowledgement

The local wallet frontend must:

1. Generate a `PendingWallet` and render its recovery words in a local protected
   view. Do not send them to a node, telemetry, browser storage or remote API.
2. Require the holder to record the words and the public recovery descriptor.
3. Hide the displayed words, then request the three distinct one-based positions
   returned by `backup_challenge`. Obtain fresh answers from the holder.
4. Call `confirm_backup` with those answers. Only a successful confirmation
   produces a `ConfirmedWallet` that can create a vault.
5. Obtain a local encryption passphrase of 12–1024 UTF-8 bytes through a hidden
   input. Keep the owned input buffer in erasing memory; never pass it on a
   command line or through an environment variable.
6. Call `ConfirmedWallet::create` with a new wallet directory. Keep the returned
   `UnlockedWallet` alive for the complete wallet operation.

The challenge records acknowledgement; it cannot prove that a holder has kept
a physically independent backup. A frontend must not answer the challenge from
its own previously displayed words. Restoration instead checks possession of a
complete mnemonic and its checksum.

## Vault envelope and resource bounds

The initial `seed.vault` file is exactly 132 bytes:

| Field | Bytes |
| --- | ---: |
| Local format magic `SWNVLT01` | 8 |
| Random Argon2 salt | 16 |
| Random XChaCha20 nonce | 24 |
| Encrypted network ID, account index and entropy | 68 |
| Authentication tag | 16 |

Version 1 fixes Argon2id v19 to 65,536 KiB, three passes, one lane and a
32-byte output. File contents cannot select stronger or unbounded KDF work.
Passphrases are bounded at 1024 UTF-8 bytes before KDF work. XChaCha20-Poly1305
authenticates the complete envelope header and the fixed format/KDF domain.
Malformed size/version fails before key derivation; a wrong passphrase or any
authenticated-data alteration fails before keys become available. Opening also
requires an expected network ID and rejects a mismatch.

The implementation wraps owned entropy, plaintext, derived keys, KDF memory and
mnemonic storage in erasing types and does not implement secret `Debug`,
`Display` or serialization. This does not guarantee erasure of compiler,
register, dependency-internal, swapped or host-compromise copies.

## File ownership and durability

Protected storage currently supports Unix systems and fails closed elsewhere.
Existing ancestor directories are opened component by component with
`NOFOLLOW`; symlinks, including ancestor symlinks, are rejected. Select a real
canonical directory path. The final wallet directory must belong to the
current user and have mode `0700` or stricter. Vault and lock files must be
regular files owned by that user, mode `0600` or stricter, with exactly one
hard link.

A persistent `.wallet.lock` inode carries a nonblocking exclusive lock for the
`UnlockedWallet` lifetime. A second process fails rather than using the same
wallet concurrently. Do not delete the lock file to bypass ownership.

Creation and restoration require a new directory and never overwrite an
existing vault. The implementation writes and synchronizes a randomly named
owner-only temporary file, publishes a same-directory exclusive hard link,
removes the temporary link and synchronizes the directory. A failure before
publication leaves no final partial vault. If publication succeeds but cleanup
or synchronization fails, the operation reports that state; it does not
silently overwrite or delete a potentially valid vault. Operators must inspect
such a failure before retrying. No automatic repair or destructive reset is
performed.

The seed vault is immutable. Password rotation, complete encrypted export,
receipt caches and archival payment history are not implemented by this
interface.

## Payment reservation and relay journal

Every initialized wallet also requires an authenticated `payments.journal`.
A missing, malformed, altered or different-account journal prevents opening;
the wallet never substitutes an empty journal. The encrypted file binds the
entropy, network and account through separate key/context derivation domains.
Each update uses a fresh operating-system XChaCha20 nonce and the same locked,
owner-only, synchronized temporary-file publication mechanism. Existing
journals are atomically replaced by rename; the seed vault is never replaced.
The live owner also checks the previous ciphertext fingerprint before writing.

The durable local API has this ordering:

1. Prepare the native transaction statement and call `reserve_payment(record)`.
   It checks and synchronizes both distinct input nullifiers before returning a
   reservation capability. An overlap in either input with any retained
   payment is rejected. Do this before starting proof generation.
2. Generate and independently verify the proof with the native prover. The
   journal API itself validates canonical framing and fee openings; it does not
   replace proof or note-ownership validation.
3. Call `store_wallet_payment` with that reservation, the native `WalletPayment`
   and its recipient address. The typed adapter retains and authenticates the
   original encapsulation coins without changing the proof suite. For lower
   level integration, `store_prepared_with_opening` accepts the exact transaction,
   checked sidecar and native `PaymentEncryptionOpening`. Both use the same
   synchronized encrypted journal.
   The generic `store_prepared_payment` interface also accepts the exact transaction,
   its fee sidecar and a bounded private opening encoding. The sidecar must
   match the statement identity and fee commitment. The supplied validation
   callback must validate the private opening against this transaction before
   the packet is persisted. No typed opening encoding is invented by the
   generic storage API; callers should prefer the typed native adapter.
4. Call `submit_payment` with the payment ID and a relay callback. The callback
   receives only the already synchronized exact packet after the live ownership
   lock and exact journal ciphertext have been rechecked. A callback failure
   leaves it prepared; a crash after network acceptance but before local
   acknowledgement leaves the identical packet available for retry. A different
   proof, sidecar or opening cannot replace an existing prepared packet, even
   when its statement identity is unchanged.
5. After restart, inspect `payment_ids`, `payment_status` and `payment_packet`.
   No automatic relay attempt runs during open. Relay admission still checks
   snapshot freshness, signatures, proof validity and canonical spend state.
6. Call `reconcile_payments` against independently accepted canonical history.
   It replays all supplied consensus/proof checks before atomically recording
   accepted statements, conflicting input spends or orphaned previous
   acceptance/conflict. The caller authenticates the selected history, as with
   wallet ciphertext rescanning.

Payment statuses and IDs are private wallet data and must not enter public
monitoring. Mutations, including idempotent retries, and status or packet reads
recheck live ownership and the exact durable ciphertext. An I/O error or
unexpected live-session file change poisons further journal operations; close
and inspect the directory before reopening. Restoring the file during that
session does not clear the error. The old
or new complete file may have reached disk after a failed synchronization.
Do not erase the file or retry with an empty history.

The typed local opening is exactly 1336 bytes before journal encryption:
eight-byte local format/version magic `SWNPO001`, network ID (32 bytes),
statement ID (32), recipient owner commitment (48), ML-KEM public key (1184)
and one payment's encapsulation coins (32). It never appears in the public
transaction or telemetry. Decoding validates the exact format, canonical owner,
ML-KEM public key, expected network and statement, rebuilds the encapsulation,
authenticates the payment and reconstructs its output commitment. Temporary
decoded note fields and owned opening buffers are erased. The per-payment
coins remain a disclosure secret; the adapter offers no automatic public
export. `verified_payment_opening` repeats these checks after reopening.

This initial journal permits at most 32 retained records and 8 MiB of plaintext,
with a 65,536-byte private-opening cap and the existing transaction-envelope
cap. It fails closed when full. It does not automatically release reservations,
delete terminal records, replace orphaned statements with a newly proved
statement or implement archival compaction. In particular, orphaned packets
retain their input reservations until a separately validated recovery flow is
available. No local status asserts finality.

Authenticated encryption detects alteration, not replacement by an older valid
backup after restart. External monotonic anchoring and a complete wallet
backup/recovery transaction are not implemented. A mnemonic restores keys and
confirmed notes, but not previously retained payment-opening disclosures or
unconfirmed payment intentions. Preserve the complete encrypted wallet directory
when those records matter; never restore an old copy over a live wallet.

## Recovery procedure

1. Use a clean trusted device and the matching wallet software. Keep recovery
   words off shared terminals, clipboard history and network services.
2. Select the original network ID and account index from the public recovery
   descriptor; do not infer them from an untrusted remote node.
3. Call `WalletVault::restore` with the 24 canonical lowercase English words, a
   new directory and a new local encryption passphrase. This creates a new
   encrypted vault without changing the receiving address.
4. Obtain the accepted canonical public history using the configured verified
   synchronization policy. Invoke the existing `Wallet::reconcile` replay and
   ciphertext scan API. It verifies authenticated ciphertext and note
   commitments, reconstructs spend/nullifier state and recovers note unlock
   heights. Seed restoration alone does not authenticate a checkpoint.
5. Compare the stable receiving address and recovered available/locked balances
   before resuming payments. A mnemonic cannot recover a recipient output whose
   original ciphertext was malformed or data unavailable under the network's
   retention policy.

Tests cover the known 256-bit BIP39 vector, stable account/network address
restoration, backup challenge, invalid checksum and word counts, bounded
malformed envelopes, authenticated tampering, wrong passphrases, exclusive
ownership, permissions, symlinks, hard links, overwrite refusal and interrupted
publication. Journal tests cover pre-proof durable reservations, second-input
conflicts, exact-packet restart/retry, sidecar/opening rejection, canonical
acceptance/conflict/orphan updates and fail-closed missing/corrupt/account-mixed
files. Typed-opening tests reject changed recipient, network, transaction,
coins and format, and prepare an actual wallet transfer from a synthetic funding
prefix before encrypted storage, restart and typed verification. The proof bytes
in that bounded storage test are synthetic. These tests use a synthetic verifier for journal state transitions and do
not qualify the production proof path. Full web-wallet recovery and a genuine genesis-funded reward to
payment to restored-recipient flow remain required integration tests.

## Opt-in complete native chain roundtrip

The ignored test
`wallet_vault::native_roundtrip::genuine_genesis_rewards_persist_pay_and_restore_with_native_proofs`
implements the next engineering gate. It is not part of routine unit tests.
Run it explicitly on an isolated build host, with an existing owner-only
evidence directory outside the source checkout:

```sh
SIWORLD_RUN_NATIVE_WALLET_ROUNDTRIP=1 \
SIWORLD_NATIVE_WALLET_RUN_ROOT="$SIWORLD_TEST_ROOT" \
cargo test --release --manifest-path crates/native-node/Cargo.toml \
  wallet_vault::native_roundtrip::genuine_genesis_rewards_persist_pay_and_restore_with_native_proofs \
  -- --ignored --exact --test-threads=1
```

The complete test uses a disposable ASERT engineering genesis, the production
economic timing profile, 24 public synthetic fund identities, actual frozen
native transaction and settlement proofs and `NativeVerifier` throughout. There
is no synthetic verifier or funded-history prefix. It produces 25 blocks with
64 fresh unique slots each, rejects the first reward at snapshot height 24 and
spends it at height 25. It backs up both wallet mnemonics, synchronizes the
sender's reservation and typed packet, restarts the sender, admits the retained
packet to the real mempool and includes it in block 26 with 63 fresh positions.
It then reopens and fully replays the chain database, restores the receiving
wallet into a new directory and checks the payment and sender journal status.
The full run generates 1664 transaction proofs and 26 settlement proofs.

This gate advances block timestamps by the 300-second target interval without
waiting five minutes between test blocks. It advances the wallet's injected
local scheduling clock to the derived privacy-delay eligibility timestamp;
it does not compress the 24-block maturity or any consensus unlock height.
It therefore establishes neither a continuous wall-clock soak nor observation
of a real elapsed privacy delay. The gate covers a standard-fee SIP transfer;
the complete two-tier, issuance and asset-transfer wallet flow remains another
acceptance gate.

The test checks a four-hour cooperative deadline between proof/verification
operations. Its process supervisor must also enforce an external four-hour
limit because an in-progress prover call cannot be preempted by that check.
Every run retains its isolated directory, public chain database, encrypted
wallet vaults/journals and a bounded `roundtrip-progress.json` on success or
failure. The progress file contains stage, accepted height, required height,
slot capacity and elapsed milliseconds; no private wallet identifiers, openings,
balances or individual fees are emitted. Preserve a failed run for diagnosis;
do not automatically repair, reset or resume it as successful evidence. A
passing compile or the presence of this test does not establish a completed
roundtrip. Record the exact executed source and observed test result separately.

## Interactive local CLI

The native engineering CLI provides explicit custody commands:

```text
wallet-create WALLET_DIR NETWORK_DIR [ACCOUNT]
wallet-restore WALLET_DIR NETWORK_DIR [ACCOUNT]
wallet-address WALLET_DIR NETWORK_DIR
wallet-configure-miner WALLET_DIR NETWORK_DIR voyager|holder
```

The optional create/restore account is a canonical unsigned 32-bit decimal;
omitting it selects account zero. The network ID comes from the protected
configuration in `NETWORK_DIR`. Restore with the originally recorded network
and account; a seed alone does not select either. A restored vault must use a
new wallet directory, and creation never overwrites an existing vault.

All four commands require interactive stdin and stderr plus a controlling
terminal before entropy generation or decryption. New passwords are entered
twice through hidden prompts. Creation displays the 24 recovery words directly
on that terminal, requests acknowledgement, clears the display/scrollback where
supported, and requests three fresh hidden word answers before writing a
vault. These terminal controls do not prove erasure of a screen recorder,
scrollback or host-compromise copy. Use a private trusted session without
recording, remote display or clipboard synchronization. Recovery words are
never written to stdout, logs, files, command arguments or environment options.
Restoration accepts the entire phrase only through a hidden prompt.

Successful create, restore and address stdout contains only a public JSON recovery descriptor with
`version`, `network`, `account` and `address_hex`. The address is the existing
1,232-byte payment format encoded as 2,464 lowercase hexadecimal characters:
48 canonical owner bytes followed by the 1,184-byte ML-KEM-768 encapsulation
key. Redirecting stdout saves only this public descriptor; private words remain
on the controlling terminal. The binary address imported by `configure-miner`
uses these raw bytes, not the JSON object.

`wallet-configure-miner` avoids converting that JSON into a separate binary
file: it authenticates the encrypted vault against the selected network,
derives its public payment address and atomically saves the miner preferences
in `NETWORK_DIR`. The mode must be exactly `voyager` or `holder`; there is no
default. The selected account is the vault's recorded account. The command
does not create or restore a wallet, and a wrong password or network mismatch
fails before updating preferences. New preferences apply to the next block
template; an existing template retains its original mode and destination.
Successful stdout contains only `version`, `network`, `reward_mode`, `status`
and `applies_to`. It does not export the address or private wallet material.

For example, after creating and backing up a wallet, select its Holder mode
explicitly:

```sh
siworld-native-node wallet-configure-miner wallet-directory network-directory holder
```

No address-file overwrite command,
secret export, public wallet RPC, balance scan or payment relay is introduced
by this custody frontend.
