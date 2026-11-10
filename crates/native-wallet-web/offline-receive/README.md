# Offline Internal Receive Backup

This separate local application creates and verifies one receive-only account on
the pinned internal `siworld-eng-2` network. It has no chain client, balance query,
sending operation, address-directory publication or persistent browser storage.
The network parameter is fixed by an explicitly hashed input configuration;
the genesis remains unsealed. Account and offline birthday are both zero.

The application uses the existing native `BrowserWallet` implementation in a
separate worker. Preparation accepts only the recorded standard, nonfixture CI
WASM and JavaScript hashes. It does not modify the existing wallet build, worker,
configuration, IndexedDB databases, selected accounts or caches. A new dedicated
loopback origin is required; do not reuse another wallet application's port.
The server fails if that port is occupied and serves only integrity-checked
application files. It offers no upload, proxy, API, directory listing or request
logging. Stopping the server does not remove downloaded encrypted backups.

## Preparation

Use Python 3.9 or newer and the exact qualified CI core recorded in `prepare.py`.
Record the reviewed implementation commit and SHA-256 of the exact input
configuration bytes. Prepare into a fresh local directory:

```sh
python3 prepare.py prepare --context-file /private/input/context.json \
  --context-sha256 CONTEXT_SHA256 --core /private/input/core \
  --output /private/output/receive --port 8879 \
  --implementation-commit IMPLEMENTATION_COMMIT
python3 prepare.py serve --directory /private/output/receive
```

Inspect `build-manifest.json` before use. It records source hashes, configuration
hash, implementation revision, core revision, CI run and exact prepared assets.
The input must explicitly forbid an online API, address-directory use and
custody input. No genesis, wallet, keys or browser session is created
by preparation or by starting the static server.

## Owner workflow

1. Open the displayed loopback URL on the local computer. Create an account.
2. Privately write down all 24 recovery words, the network identifier and account
   zero. Continue to the three-word challenge; choose a backup password.
3. Download the encrypted JSON file. Reopen the exact original file in this
   application and enter its password. The complete public address is displayed
   only after successful decryption and address verification.
4. Share only the complete public receive address. Keep the encrypted file,
   password and recovery words private. Clear the session and stop the server.

Opening an existing encrypted file is supported without creating a new account.
Wrong passwords or foreign-network files are rejected. While creating a new
account, a different file, including a reserialized version, cannot substitute
for the original downloaded backup. Clear-session, page exit and five minutes of
inactivity terminate the worker, cancel pending UI work and remove displayed
recovery words, passwords and the current address. JavaScript strings cannot be
reliably zeroized; termination and reference clearing are not a forensic memory
erasure guarantee. Browser extensions, downloaded-file handling and local-device
security remain the owner's responsibility.

The custom `siworld-eng2-offline-receive-backup` JSON format is deliberately
separate from the standard wallet backup format. It is not directly importable
by the existing engineering wallet and must not be converted into an older
network's backup. The contained encrypted native vault authenticates the network
and account. The 24 words plus the exact network identifier and account zero
remain the independent recovery path for a future compatible internal-network
wallet; this tool does not implement mnemonic import. It does not claim that an
unsealed genesis or a public engineering deployment already exists.

## Validation

`node --test protocol.test.mjs` covers framing and a fake creation/challenge core.
`node --experimental-vm-modules --test ui.test.mjs` uses a disposable simulated
DOM and worker to exercise delayed completion after clearing. These tests do not
establish real creation or encryption acceptance. `python3 -m unittest discover
-s . -p 'prepare_test.py'` checks preparation and HTTP isolation with synthetic
core files. To test real encryption with the recorded core, set
`RECEIVE_CORE` to its directory and run `node --test core.test.mjs`. That test uses
only a fixed, public synthetic recovery phrase and explicitly refuses calls to
real creation. None of these checks creates or opens an owner's wallet.
