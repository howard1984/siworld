# SIVault Security Model

SIVault includes a provisional offline standard-folder implementation and a
releaser state model. Controlled credential and channel primitives are
separate from the desktop opening flow. The standard format uses Argon2id, RFC 8265
OpaqueString password preparation, independently derived keys, and the
published STREAM construction with 64 KiB authentication units.

An offline safe is intended to open locally with no network or wallet
dependency. An attacker with a complete copy can try passwords offline. A
controlled safe is intended to require a fresh response from an authorized
releaser for every opening, with no offline approval cache. Its lockout is
intended to bound online credential checks, not guessing against separately
retained older offline copies or compromised releaser state combined with a
copied folder.

| Threat | Boundary or limitation |
| --- | --- |
| Theft or copying of a locked safe | Hardware ownership is not authenticated. A complete copy remains a valid input. |
| Modification or rollback of stored data | Authenticated data can reject inconsistent changes. A complete historical snapshot can remain internally consistent; offline rollback detection requires an independent freshness reference. |
| Hostile safe files | Parsing is intended to run apart from wallet keys. Isolation must be verified on both desktop platforms; process separation alone is not sufficient. |
| Compromised host or open safe | Local malware can capture typed credentials or read plaintext. A later remote command cannot recover disclosed data or invalidate a key already held in memory. |
| Multiple observations of a fixed-size safe | Constant file sizes do not hide which bytes change or imply plausible deniability. |
| Relay or traffic observer | A relay can observe routing and timing and delay or drop messages. Release decisions must not depend on relay state. |
| Releaser unavailable or restored from stale state | An unavailable or unverified releaser must not grant a fresh opening. Availability depends on the remaining eligible releasers and their attempt budgets. |

The controlled channel derives traffic keys from two ML-KEM shared secrets.
It does not promise forward secrecy against later releaser key compromise for
captures that also expose the other KEM secret or endpoint state.
The desktop loopback identity check compares an identifier obtained separately
from the address, then verifies the channel handshake. An unprovisioned
listener uses a temporary identity and does not accept enrollment or release
shares. When a provisioned slot is resumed, the identity and port are recovered
from the encrypted local record. The credential verifier and share are
encrypted under a separate releaser-storage password; the journal commits a
digest of that ciphertext and refuses a substituted record.
The provisional controlled payload has no offline password slot. Its
single-slot registration record stores the pinned releaser identifier,
assigned allowance, record scope, and encrypted key envelope. Opening code
must authenticate the saved record with the freshly recovered key before
exposing files. The persistence test uses synthetic enrollment messages;
desktop enrollment and two-application acceptance are not implemented.

The releaser journal commits a charge before allowing credential evaluation.
The slot is unavailable when its attempt history cannot be verified against
the checkpoint in the operating system credential store. Restoring a wallet
backup does not restore approval authority or spent attempts. Restoring both
stores to a matching older state may evade detection. The attempt limit is
not a defense against someone who controls the releaser's device. Desktop
releaser startup uses the native checkpoint adapter for a provisioned slot;
the desktop owner enrollment flow is not yet connected.
On macOS the checkpoint is a local login Keychain item accessible to the
logged-in user. Releaser protection does not exceed the device's login protection.

The desktop and web shells have different trust boundaries. A web opener
depends on the origin delivering its code. The desktop renderer handles typed
passwords transiently; it does not receive derived keys, file plaintext or
content keys. This is not an isolation guarantee against a compromised renderer
or host. Sensitive data and signing credentials must not
enter build logs or automated validation. Desktop package signing, when
introduced, is an owner-controlled step outside CI.

The application uses an in-app folder browser, with explicit import and export.
It does not mount a filesystem or create implicit plaintext temporary copies.
The standard prototype retains immutable old records and does not yet reclaim
unreferenced objects. Removing an entry is not secure deletion. A damaged newest
record is refused without automatically opening an older generation. Explicit
historical recovery and power-loss acceptance on target filesystems remain
unimplemented. Unix mutation uses checked file and directory synchronization.
An explicit debug-only Windows option publishes immutable generation records
without replacement but has no confirmed directory durability barrier.
Distribution requires power-loss and media-removal validation on macOS and
Windows (G-1). Whole-folder snapshot rollback cannot be detected offline.

Fixed-size and decoy formats are not implemented. Their requirement is that
decoy openings are read-only, with matching read-only UI behavior available to
all fixed-size safes. Decoy contents are maintained from the real view. A
single-image deniability objective does not cover repeated images, IO traces,
timing, host artifacts or an unlocked process.

Controlled recovery uses three assigned positions in the owner's existing
24-word phrase with a 2,048-word vocabulary, with at most 33 bits of entropy.
Phrase checksum constraints or prior phrase knowledge may reduce that bound.
An attacker holding both the folder and
a releaser's retained matching state can search offline without the online
attempt limit; this is feasible for a funded attacker. Human-selected words
may have lower entropy. Compromise also exposes those phrase words and reduces
uncertainty about the owner's phrase. The owner phrase alone cannot restore
deleted shares.
