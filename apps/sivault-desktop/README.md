# SIVault Desktop

Tauri 2 shell for offline and controlled safes. The React frontend displays metadata;
the Rust adapter owns `sivault_core::standard::Safe` and its key material.
The initial format stores each safe in a directory. Creation selects a parent
directory and creates a new named `.sivault` directory; opening selects that directory.

## Development

Use `npm ci`, `npm run build`, and `npm run tauri dev` from this directory.
`npm run dev` starts the browser preview on the loopback interface at port 1420.
The Rust crate is an independent workspace and uses the local core crate.
Run its integration fixture with `cargo test --manifest-path src-tauri/Cargo.toml`.
`npm run tauri build -- --debug --no-bundle` builds the native executable.
Packaging and signing are not enabled by this shell.

To include the SIWORLD mark in a branded build, place the approved
`siworld-icon.svg` in `src/branding.local/` before starting Vite or building.
An approved RGBA `siworld-icon-32.png` in the same directory supplies the
native build icon.
This directory is excluded from Git. The build embeds the image locally and
does not fetch it at runtime. Without the asset, the header displays the
SIVault name without an image.

Use `npm run test:e2e` with the preview running to test desktop and mobile layouts.
The browser preview has an explicit synthetic fixture mode in development builds.
It never reads user files, handles real passwords, or encrypts data. Synthetic
exports contain only fixed fixture text. Production builds exclude this mode;
browser use of a production build cannot operate on safes.

## Controlled Safe Development

Controlled safes require an enrolled, reachable releaser for each opening.
The desktop prototype supports one releaser slot, with a fixed initial
allowance, explicit refills and terminal revocation. The releaser must
authorize the owner's identifier and initial allowance before enrollment.
The releaser storage password, safe password and owner recovery phrase are
entered in native dialogs. A revoke receipt confirms removal of live share
material on that releaser; it does not recall data already disclosed or prove
erasure of backups. An unconfirmed command does not establish that an
unreachable releaser enforced it.

The controlled-safe setup dialog can show the owner's three assigned recovery
words after native phrase reentry. The local owner profile encrypts the
positions and does not store the words. It is not a portable recovery record.
This build does not support opening or resetting a safe with those words.

The releaser binds IPv4 loopback by default. A non-distributable debug
build with `desktop-e2e` can instead bind one Tailscale IPv4 address and
port named by `SIVAULT_TEST_RELEASER_BIND` and accept only the single Tailscale
IPv4 address named by `SIVAULT_TEST_RELEASER_PEER`. Both settings are required
together. The pinned authenticated channel is still required. An enrolled
releaser resumes on its stored port; do not change the pairing between runs.
Build and run the synthetic loopback lifecycle test on a development machine:

```sh
cargo test --locked --manifest-path src-tauri/Cargo.toml --features desktop-e2e --test controlled_desktop
```

On Windows, also enable `dev-windows-write` for synthetic tests of safe creation.
Run the releaser under the signed-in Windows desktop user, whose Credential
Manager store holds the local instance marker. A public-key-only SSH session
can build the executable but can lack access to that credential store. A
missing or inaccessible marker must not be worked around with a test marker
when validating the native store. Cargo may need registry index entries for
target-specific dependencies while resolving the locked workspace, even when
those dependencies are not compiled for Windows.

The test starts two native processes without opening their windows and uses
separate temporary data directories.

## Engineering Wallet

The wallet and vault share a window but not a key store or worker state.
Entering the wallet view first locks an open safe. The vault starts without
querying wallet state. Leaving the wallet view discards its public snapshot.

On macOS and in Windows debug builds, the executable starts a short-lived native wallet worker for
create, restore, unlock, or an enabled development-chain payment. A broker in the native shell presents recovery
and password dialogs. Values travel on private child pipes, never through
webview IPC or child process arguments. The worker reuses the wallet core's
encrypted V1 format and address derivation and exits without keeping a
signing session. The renderer receives a public receiving address, bounded
balance and history metadata, or a status code. The worker derives account zero
for the pinned engineering network. Wallet and SIVault keys are never
derived from one another. The default engineering scope does not send payments.
The Wallet view can save or clear a local node origin. Accepted origins are
literal loopback HTTP addresses with an explicit port, such as
`http://127.0.0.1:8180`. The setting is independent of custody and does not
configure network identity. Saving it makes no request directly. While the Wallet
view is visible, its header periodically probes the saved origin; the explicit
endpoint test uses the same bounded wallet head response without sending wallet
data, following redirects, or using a proxy. It does not authenticate the chain
or update wallet balance or history.
The prototype does not establish operating-system sandbox isolation for the
wallet worker.

### Isolated Development Chain

Build the frontend and compile with
`cargo build --locked --manifest-path src-tauri/Cargo.toml --profile wallet-demo --features custom-protocol,dev-wallet-chain`.
On Windows, add `dev-windows-write` only for synthetic safe tests. Do not
distribute this build. Set `SIVAULT_DEV_WALLET` to
`<network-id-hex>:<genesis-id-hex>:a` or use profile `b` for a second wallet.
Pins must come from the owner-controlled isolated chain, not an HTTP response.
The development profile stores custody and endpoint settings separately from
the engineering wallet. An optional absolute `SIVAULT_DEV_WALLET_DATA` sets
the isolated storage root.

On the owner-controlled Unix host, run an isolated producer with its owner-only
submission socket and a validation resident that exports wallet artifacts.
Build `dev_recipient_directory` from the native wallet core examples, then
run `wallet-dev-bridge.py --port PORT --export ARTIFACTS --submit-socket SOCKET
--directory-helper EXECUTABLE --genesis GENESIS`. This bridge binds only
IPv4 loopback. It is not a public node API. A remote development client must
connect through an authenticated loopback-to-loopback forward.

The wallet validates the pinned genesis, header work, receipt authentication,
and the complete selected generation before displaying its balance. The address
directory validates v2 records and serves bounded snapshot pages; it accepts
no recipient-specific lookup. The directory is in memory and unlocked wallets
can republish by unlocking again after service restart. The development
directory rejects new entries at 10,000 records; a wallet whose publication
fails displays an unpublished address. Public capacity and a distinct
directory-full status must be defined before public deployment.
The development reward setup verifies a directory descriptor before passing
the full recipient to the miner. Native short-address configuration is not
implemented; production integration must resolve and verify the descriptor
once at startup, cache it locally, and refuse to start on resolution failure.
Payments use the
genesis-bound native proof. The worker encrypts the finalized packet before
submitting it, and explicit retries reuse the exact packet. An acknowledgement
is pending until the worker verifies inclusion from an authenticated receipt.
The development UI displays recent incoming entries and the latest outgoing
payment; it is not a full transaction archive.

Renderer copy lives in `src/locale/en.ts`; protocol identifiers and user
file names are not translated.

## Command Contract

Safe and wallet commands are restricted to the local `main` window by generated
application permissions and the named capability. No renderer filesystem,
shell, network, or dialog plugin permissions are granted. Native dialogs execute
inside the authorized Rust commands. Source and destination paths are never
accepted from the renderer, and selected safe paths remain in Rust memory.

| Command | Input | Result |
| --- | --- | --- |
| `safe_create` | `name` | safe descriptor, or `null` if cancelled |
| `safe_create_controlled` | `name`, releaser `address`, `identifier`, `allowance` | safe descriptor after durable enrollment, or `null` if cancelled |
| `safe_manage_controlled` | `current`, `additional`, nullable `revokeLabel` | whether the selected command was confirmed |
| `owner_prepare` | none | whether native owner setup or restore completed |
| `owner_identifier` | none | public identifier of the prepared owner |
| `releaser_status` | none | current listener address, public identifier and enrollment state |
| `releaser_authorize` | `owner`, `allowance` | whether one enrollment was locally authorized |
| `releaser_set_running` | `enabled` | current listener status |
| `releaser_verify` | `address`, `identifier` | no value after authenticating the peer |
| `safe_open` | `readOnly` | safe descriptor, or `null` if cancelled |
| `safe_unlock` | `id`, `readOnly` | safe descriptor, or `null` if cancelled |
| `safe_list` | `sessionId`, nullable `parent` | direct child entry metadata |
| `safe_import` | `sessionId`, nullable `parent` | number imported, zero if cancelled |
| `safe_export` | `sessionId`, `entryId` | `true` if exported, `false` if cancelled |
| `safe_create_directory` | `sessionId`, `name`, nullable `parent` | entry metadata |
| `safe_lock` | `sessionId` | no value |
| `wallet_endpoint` | none | saved loopback origin or `null` |
| `wallet_set_endpoint` | `origin`, empty to clear | no value |
| `wallet_probe_endpoint` | none | no value on a well-formed response from the saved origin |
| `wallet_refresh_directory` | none | replace the development cache after a complete snapshot |
| `wallet_send` | `recipient`, `amount`, `fee` | payment status, or `null` if cancelled |
| `wallet_retry_payment` | none | status for the same journaled payment, or `null` if cancelled |

A safe descriptor contains `id`, `name`, `sessionId`, and `readOnly`.
Entry metadata contains `id`, nullable `parent`, `name`, `is_dir`, and `size`.
Errors contain a stable `code` and a displayable `message`.
The adapter holds one active safe, uses random opaque session identifiers, and
revokes a session by dropping the safe. Recent safe paths are retained only in
process memory. A reopened safe receives a new session identifier.

The macOS password prompt uses AppKit secure text fields and hands the value
to the Rust adapter in a `Zeroizing<String>`. Passwords do not enter the
webview or IPC payloads and are not written to disk or logs. This does not
claim erasure of OS input buffers. The renderer receives plaintext item names
and listing metadata, but not file contents, source paths, or derived keys.
This build is not for distribution.
Read-only imports and folder creation fail in Rust in addition to disabled UI
controls. Explicit export warns that the resulting file is unencrypted; there
are no previews, implicit plaintext temporary files, mounts, or external-editor
launches. Multiple imports commit individually; an error can leave earlier
selected files imported, and the folder list refreshes afterward.

On Windows, opt in to development writes with
`cargo build --manifest-path src-tauri/Cargo.toml --features custom-protocol,dev-windows-write`
after building the frontend. The flag does not enable writes in release
profiles. Windows publishes each generation with a same-directory hard link
and does not provide a directory durability barrier. Use only synthetic data.
Real power-loss and media-removal qualification on macOS and Windows is a
distribution gate (G-1); process-kill tests do not substitute for it.
Native tests and browser fixture
tests provide separate evidence; browser fixtures do not validate encryption,
native dialogs, IPC permissions, or platform durability.
