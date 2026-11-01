# Native V1 Engineering Runtime

An isolated integration of the fixed D8/W24 native transaction, settlement and issuance
relations. The single-node service is accompanied by engineering interfaces for
verified transaction admission, authenticated-stream framing, bounded full-proof
synchronization, verified-work fork selection, atomic reorganizations, private
seed-wallet transfers and public subsidy replay.

The transport has no production hybrid authenticator or plaintext fallback.
The CLI does not start a network listener. Checkpoint bootstrap and proof pruning
remain separate implementation gates. The [wallet custody interface](../../docs/v1-wallet-storage.md)
implements an encrypted seed vault and payment journal, mnemonic restoration
and explicit interactive create, restore, address and miner-configuration
commands. An opt-in genuine native-proof roundtrip test covers genesis-funded
rewards, a standard-fee SIP payment, restart and receiving-wallet restoration;
its presence or a passing build does not establish a completed execution. The
local web interface, complete two-fee-tier and issued-asset wallet flow, and
independent-host network acceptance remain pending. Issuance
uses an explicit destination/policy, a declaration-bound SIP payment receipt,
native proof verification and the atomic persistent registry. Its bounded local
RPC dispatcher does not open an authenticated network endpoint. Compact relay
retrieves exact missing transaction/proof pairs before complete validation.
Remote CI covers protocol rejection, synchronization,
reorganization, wallet and audit tests, with separately selected native-proof
integration tests. These checks do not qualify a network deployment. No existing
network is modified or activated.

See [the runtime scope and commands](../../docs/v1-native-runtime.md) and
[the remaining network milestones](../../docs/v1-node-network-plan.md).
