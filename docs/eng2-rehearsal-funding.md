# Existing reward funding for isolated rehearsal

`siworld-eng2-rehearsal --fund-payer-existing PLAN PLAN_SHA256 NEW_OUTPUT --json`
is an owner-local Unix command built with `eng2-runtime,eng2-rehearsal`. It opens
the existing five actor vaults and the exact existing stopped store under its
service lease. It creates no vault, seed, key, genesis, balance or network
connection. The existing source, executable, campaign, genesis, resource and
role bindings used by custody commands also apply to this command.

The custody envelope uses `action: "funding"` and a pinned `funding` input
`{"path": "/owner/run/funding.json", "sha256": "..."}`. `business` and
`expectations` must be absent or null. The envelope must select the existing
`initial_receipt`, `genesis`, `qualification`, five ordered `actors`,
`issuer_directory`, `head`, `node_directory`, `resources` and `excluded_roots`.
Its `source_commit` and `binary_sha256` must identify the actual compiled
executable. The existing framed private stdin supplies the five passwords;
passwords and openings are never command arguments or evidence fields.

The funding input is a strict version-1 object with these fields:

| Field | Required value or bound |
| --- | --- |
| `version` | `1` |
| `campaign_id`, `genesis_id` | Exact campaign and sealed genesis, each 64 lowercase hexadecimal characters |
| `isolated_directory` | Exact canonical existing node directory |
| `start_height`, `start_tip` | Exact existing head; tip is 64 lowercase hexadecimal characters |
| `deadline_seconds` | `1..3600`, within the retained owner process guard |
| `max_nonce_attempts` | `1..1000000`; no unbounded nonce search |
| `max_output_bytes` | `1048576..17179869184`; must retain the whole original prefix and reserved frame capacity |
| `history_budget` | Pinned `{path, sha256}` using the complete-history schema in [positive business history](eng2-positive-business-prefix.md) |
| `consolidation_max_note_value` | Positive SIP atom threshold for the two future consolidation inputs |
| `expected_before`, `expected_after` | Independently authored five-role wallet balance arrays |
| `payments` | Exactly five entries in the purpose order below |

Each payment contains `purpose`, `commitment`, `nullifier`, `reward_height`,
`input_atoms` and `amount_atoms`. Both identities have 96 lowercase hexadecimal
characters. Heights and atom amounts are unsigned JSON integers. The exact
purpose order is `standard`, `priority`, `consolidation-0`, `consolidation-1`,
`issuance`. Every entry selects a different canonical reward at output index
zero, owned by the existing reward vault. A reward at height H is usable only
when the current head is at least H + 24. Five such rewards can first exist at
height 29. Holder tranches with later unlock heights are not substitutes.

Each amount must be positive, and the selected reward must cover that amount
plus the current standard transaction fee. The two consolidation amounts must
not exceed `consolidation_max_note_value` and must together exceed their future
standard fee. Choose the other amounts to cover the separately planned payment,
priority and issuance costs. Also plan the first two business changes so the
automatic small-note selector still selects the intended consolidation pair.
Funding does not assert that arbitrary later business amounts are affordable.

Each wallet expectation array has five entries ordered `payer`, `recipient`,
`fee_destination`, `fund_destination`, `reward`. An entry contains `role`,
`address` (the complete 1232-byte address in lowercase hexadecimal) and
`balances`. Each balance contains `asset` (32-byte hexadecimal identifier),
`received_notes`, `spent_notes`, `unspent_notes` as unsigned integers and
`received_atoms`, `spent_atoms`, `unspent_atoms`, `available_atoms` as canonical
unsigned decimal strings. Assets are sorted and unique. Define these values
from the independently selected original funding inputs and transaction fees;
the final reward also remains assigned to the reward actor. Do not copy a tested
wallet scan into either expectation array.

The command retains and natively verifies every original frame from genesis,
compares all eleven state components, and checks the original balances before
reserving any payment. It prepares five independent ordinary payments, checks
their full payer address, amount and zero unlock height, and reserves the exact
reward inputs through the existing encrypted reward-vault journal. It writes
`funding/predictions.json` before any transaction proof or canonical append.
That receipt binds the original intent, statements, payer commitments and
nullifiers, values, fees and change commitments. Payer nullifiers are calculated
directly from the checked original payment openings under the existing payer
identity; this step does not scan or add a wallet receipt.

All five proved payments enter one actual native block through the existing
padding, settlement proof, template verification, bounded nonce search and
`Store::append` path. This is an explicit chain write and produces a new reward
for the unchanged reward actor. It is not a synthetic receipt or an artificial
balance insertion. The resulting ordinary payer outputs have unlock height zero
and can serve as five independent original inputs to a later four-step business
plan. The result checks those notes against the saved predictions and balances
against `expected_after`; it does not author independent scan expectations.

Original payment openings remain in caller-owned erasing custody memory, and
proved packets and payment openings are synchronized into the existing
encrypted reward journal before append. The newly produced reward opening uses
the existing memory-only retained custody path; it is not crash recoverable.
The reward vault can still recover the reward by scanning its on-chain
ciphertext. Only the original sender opening receipt lacks persistence.
Errors retain reservations, packets, files and any accepted prefix. There is no
automatic retry, reservation release or canonical rollback. Separate complete
history, economic-state and independently authored owned-balance acceptance
remain required; funding completion alone sets no G1 or G2 pass flag.
