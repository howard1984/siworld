# Hashrate alert inputs and response

Estimate network hashrate from accumulated verified work in an elapsed
one-hour observation interval. Compare it to the adjoining preceding hour.
Alert at a measured ratio of at least 3 or at most 1/3. A ratio is unavailable
without complete canonical evidence for both intervals or if the earlier
interval estimates zero work. Only canonical blocks contribute. Require one exact
ancestor relationship across both measured periods. Window boundaries are nominal; divide each
rate by its verified source-specific monotonic duration and reject endpoints
that exceed the sampling tolerance.

Estimate owned hashrate from native attempt-counter deltas across the same
hour and the configured miner roster. Bind both endpoints to the same
network, genesis, and process instance per miner. Alert below a measured
share of one-half. Restarts, missing miners, and counter decreases make the
share unavailable. Estimates have sampling noise; work-equivalent rate over
an hour is not a direct count of external hash attempts, and a computed share
may temporarily exceed one. An hour with zero canonical work can trigger the
network decrease rule, while its owned share remains unavailable. Local counters
measure work attempted rather than the canonical blocks a miner won.

Persist the open episode by genesis and alert type. Retain the immutable
alert and its evidence alongside episode changes so a failed write can be
retried without counting the same episode twice. Missing observations do
not clear episodes or initiate node controls. The first alert for an episode
references its chain and native evidence. Within five minutes, the duty owner
records a first response in the operations ledger after comparing evidence
freshness, chain-tip continuity, miner process identities, and native
counter movement. No single estimated ratio authorizes difficulty changes,
miner restarts, or checkpoint changes.

An automated read-only comparison is distinct from a human acknowledgment.
A native miner counter-stall alert identifies loss of observed work on one
miner; it does not establish a chain-wide outage. Keep a separate
episode bound to the process identity identifier for this alert and retain the original diagnostic.
