# Native V1 Network Capacity Budget

Status: conditional planning model for the [V1 economic revision](v1-economics.md).
The current codec permits one Voyager or five Holder reward notes and up to
eight signed fund claims per block, independently of the 32-wallet genesis
registry limit. The model includes those maximum records;
it does not establish measured network throughput. The
`native-v1-economics-1` proof profiles have fresh source-bound reference-host
evidence; public-key reproduction, complete CI, final admission policy and
actual hybrid transport overhead retain separate release/activation gates.

The engineering-frozen transaction proof cap is **655,360 bytes (640 KiB)**, independent
of the **655,360-byte** settlement cap and the **524,288-byte** issuance cap. Keep **576 positions per
300-second target block**. Under the assumptions below, **43 Mbps** is the
smallest integer uplink leaving 15% capacity unused; **100 Mbps sustained
uplink** remains the deployment recommendation. These are conditional resource
figures, not deployed-network qualification or a change to the retained network.

## Reproduction and evidence status

Use the explicit economic-record mode for current planning:

```sh
python3 scripts/v1-network-budget.py --native-protocol --economic-rewards
python3 scripts/v1-network-budget.py --native-protocol --economic-rewards --link-mbps 100
```

`--transaction-proof-cap-bytes`, `--settlement-proof-cap-bytes` and
`--issuance-proof-cap-bytes` set independent limits. Any revised scan result
requiring different limits needs the complete model rerun. The economic mode
requires `--native-protocol`; it is incompatible with `--legacy-baseline`.

The unflagged script uses generic framing, and `--native-protocol` without
`--economic-rewards` uses the single-reward codec layout. Both use the current
independent cap defaults unless explicit cap arguments are supplied; they do
not reproduce earlier numeric evidence unchanged. Reproduce the historical
native single-reward result with the command below; its transaction cap is
655,360 bytes and its issuance cap is 524,288 bytes:

```sh
python3 scripts/v1-network-budget.py --native-protocol --settlement-proof-cap-bytes 524288
```

`--legacy-baseline` explicitly restores all three
524,288-byte caps, a 30-Mbps link and no capacity reserve. These historical
layouts do not size the revised economic reward format or set its activation
requirements.

The source-bound b7/q41/g20 actual-AIR scan retains the 640-KiB transaction cap.
Its frozen settlement profile records the historical 524,288-byte admission
value. The current 655,360-byte settlement admission cap is a separate decoder
policy; it does not amend the measured profile or demonstrate maximum-fee,
maximum-claim qualification. The following budgets use current admission caps.
The selected four-worker generation samples range from 1.429902190 to
1.531155438 seconds, with a 1.462877730-second median. The largest body across
selected one- and four-worker trials is 588,832 bytes. The
[measurement record](v1-multi-asset-evaluation.md) binds those results to the
source and key; it does not qualify a different relation. Independent
verification-only memory and deployed-network qualification remain required. A sample
size margin is not a mathematical maximum proof length; wallets and decoders
must reject an oversized body without weakening security or truncating data.

## Payload and codec accounting

A capped transaction uses 655,360 proof bytes, 2,184 envelope bytes, a 78-byte
private sidecar and a four-byte gossip length prefix: **657,626 bytes** before
native application framing. Native messages have a 51-byte header. Compact
references contain both a statement digest and proof digest, **64 bytes** each.

The maximum economic compact fixed fields occupy **61,235 bytes**, including
five 1,361-byte reward records, eight 6,783-byte signed fund claim records and
the mode/count fields. At 576 positions and the separate settlement cap, the
compact payload is:

```text
61,235 + 576 * 64 + 655,360 = 753,459 bytes
```

Settlement is already carried in this compact body. Do not charge or send an
additional standalone copy in the selected relay schedule. Three transaction
copies and three compact bodies total **1,138,638,105 payload bytes** per
interval, before the remaining wire costs. An independent 8-KiB future block
record allowance is also charged per compact copy. It is additional planning
space, not an extracted database measurement.

The registry permits 1–32 wallets with positive basis-point shares totaling
10,000 and immutable ML-DSA-65 public keys. Its fixed 62,530-byte genesis
section is fetched once, not carried in each compact block. Each block credits
the per-wallet consensus ledger; it does not create an output for every
wallet. The eight-claim cap bounds signed withdrawals in a block independently
of the registry size. The designated development-team wallet receives fund
allocation residue. Actual shares and keys must be provided before genesis
activation; no V1 replacement or share-adjustment mechanism exists.

## Transport and load assumptions

| Category | Assumption |
| --- | --- |
| Relay | Three total application copies; the actual topology must enforce or separately budget greater fanout |
| Application framing | 51-byte native message header; four-byte transaction gossip prefix |
| Hybrid-channel records and multiplexing | 16-KiB plaintext records, 18-byte AEAD tag/length and 12-byte stream framing per record |
| Network packets | MTU 1,500; IPv6 40 bytes, TCP 32 bytes including options, effective payload 1,428 bytes |
| Link serialization | VLAN Ethernet, FCS, preamble and inter-frame gap add 42 bytes/packet; network plus link overhead is 114 bytes/packet |
| ACK traffic | Equal reciprocal incoming load; one outgoing ACK per two incoming segments, charged at 114 bytes |
| Inventories | Three complete 64-byte-reference inventories, even if compact propagation normally suppresses most requests |
| Missing references | Three sets of 36 request batches of 16 references, with count and end-marker messages; body recovery uses the separate reserve |
| Issuance | One additional capped proof plus at most 16 KiB declaration/record bytes per interval, each relayed three times |
| Hybrid handshake | Eight new connections/interval at a 32-KiB aggregate handshake budget, plus framing and packet overhead |
| Session hello | Eight 103-byte hellos, conservatively charged an additional application frame |
| Keepalive | Sixteen connections, one 64-byte keepalive every 30 seconds |
| Other control | 64 KiB/interval before framing for discovery, checkpoint manifests and bounded control |
| Retransmission | Extra 2% of the entire framed/packetized base |
| Missing-body recovery | Extra 5% of that base, including recovered bodies and their transport costs |

The production hybrid provider remains unqualified. The 16-KiB record,
30-byte record/multiplexing overhead and 32-KiB handshake allowances are
conditional assumptions, not measured provider bounds. The in-memory
256-KiB handshake reservation is not a transmitted-byte limit.

Issuance byte/rate limits remain a separate protocol decision. The one-proof /
16-KiB entry is a finite planning envelope requiring an adopted admission
limit. It conservatively overcounts when issuance occupies an ordinary
position. Unbounded permissionless issuance has no finite worst-case wire or
disk budget. Reconcile actual metadata, proof and initial-note limits before
qualification.

Different fanout, receive load, packet loss, MTU, tunnel overhead, bursts,
issuance limits or formats require a new model. A finite bandwidth number
cannot guarantee progress under arbitrary loss, partitions or adversarial
traffic. Global/per-peer limits, fair scheduling and bounded recovery remain
necessary. Full-block synchronization and bulk checkpoint/backup transfers
need their own rate-limited schedule; the control allowance covers manifests,
not checkpoint bodies.

## Result and remaining margin

After all wire costs, reserve at least 15% of total uplink capacity:

```text
minimum_link_mbps = ceil(wire_mbps / 0.85)
```

Multiplying load by 1.15 would leave less than 15% unused. The script uses
integer byte/rate arithmetic to select the link and checks that one lower
integer-Mbps link fails the reserve requirement.

The economic model uses **1,369,841,506 wire bytes per 300 seconds**, or
**36.52910683 Mbps**. Its minimum is **43 Mbps**; 42 Mbps fails the reserve.

| Link | Serialization at modeled load | Remaining rate | Remaining fraction |
| --- | ---: | ---: | ---: |
| 43 Mbps conditional minimum | 254.85 seconds | 6.471 Mbps | 15.048589% |
| 100 Mbps recommended | 109.59 seconds | 63.471 Mbps | 63.470893% |

For sensitivity, `--native-protocol --economic-rewards --duplicate-settlement`
adds a standalone settlement copy: **1,372,202,332 bytes**, **36.59206219 Mbps**
and a **44-Mbps** minimum. It is not the selected relay schedule. At the same
current admission caps, the native single-reward model uses 1,369,626,397 bytes /
36.52337059 Mbps. The economic records add 215,109 modeled wire bytes per
interval to that same-cap comparison. The historical 524,288-byte settlement
cap instead produced 1,369,154,385 bytes / 36.51078360 Mbps; do not attribute its
cap difference to economic records.

These are interval-average serialization figures, not propagation-latency
bounds. Measure actual application/packet counters, handshakes, reconstruction,
loss and queue growth with the real provider at the minimum and recommended
link classes. Report exceedances without lowering 576 positions or weakening
security. A smaller future proof requires a new security screen, measurements,
key/profile freeze and complete budget before reducing the uplink requirement.

## Integrated issuance envelope

Block v4 and compact v3 carry complete issuance records inside the compact
body. The codec can represent at most four fixed-three-note records; the
activated per-block limit and metadata limit must be explicit network
configuration. This codec bound does not choose an issuance policy.
Each record has a 534,181-byte budget allowance, including its independent
524,288-byte proof cap, issuer key/signature, ciphertexts and declaration-bound
fee receipt.
The enclosing compact encoding adds a one-byte count and four-byte record
lengths. Do not charge those same proofs again as standalone issuance traffic.

Reproduce that layout with the explicit record count:

```sh
python3 scripts/v1-network-budget.py --native-protocol --economic-rewards --integrated-issuances 1
python3 scripts/v1-network-budget.py --native-protocol --economic-rewards --integrated-issuances 4
```

| Configured maximum issuance records | Complete modeled rate | Minimum link with 15% unused |
| --- | ---: | ---: |
| 1 | 36.52846661 Mbps | 43 Mbps |
| 4 | 36.68234707 Mbps | 44 Mbps |

The existing 43-Mbps planning floor covers one issuance per block. Four
maximum records need 44 Mbps under the same assumptions; at 43 Mbps the spare
fraction is 14.692216%, below the selected reserve. Preserve the 100-Mbps
deployment recommendation. Pin the actual admission setting and rerun the
model before activation; transport overhead and sustained relay still require
measurement with the reviewed provider.
