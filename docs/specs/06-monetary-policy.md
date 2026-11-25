# 06. Monetary policy

| Field | Value |
| --- | --- |
| Title | 06. Monetary policy |
| Status | Active |
| Version | 1.0.0 |
| Applies to | Public RandomX genesis with 85% / 12% / 3% and immutable issuance fee |
| Last updated | 2026-11-25 |

## Abstract

Specifies SIP issuance, subsidy allocation and maturity, development fund accounting, and fixed-fee issuance.

## Motivation

Every validator must derive the same allocations, release amounts, and pool balance from the same parent and block. Integer accounting leaves no rounding discretion.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are
interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when,
they appear in all capitals.

### SIP subsidy

One SIP is 100,000,000 atoms. No subsidy is issued at height zero. For
height $h>0$, let $e=\lfloor(h-1)/4032\rfloor$. The subsidy $S(h)$ is $r_e$, where
$r_0=3{,}394{,}524{,}515$ atoms and
$r_{e+1}=\max(100{,}000{,}000,\lfloor r_e\cdot4{,}268{,}204{,}354/2^{32}\rfloor)$.
The 1 SIP tail begins at height 2,274,049 and continues without a hard cap.
Validators MUST use exact integer operations and MUST reject overflow.

### Allocation and miner modes

Given subsidy $S$, credit $F=\lfloor12S/100\rfloor$ to the development fund
and $C=\lfloor3S/100\rfloor$ to the Holder pool. The miner base is
$M=S-F-C$, nominally 85%. Let $P$ be the pre-block Holder pool and $G$ the
sum of transfer fees proven by the settlement proof.

| Mode | Encoding | First note at height $h+24$ | Other effects |
| --- | ---: | --- | --- |
| Voyager | 0 | $M-\lfloor5M/100\rfloor-\lfloor20M/100\rfloor+G$ | Burn $\lfloor5M/100\rfloor$ and credit $\lfloor20M/100\rfloor$ to the pool in addition to $C$. |
| Holder | 1 | $M-4\lfloor M/10\rfloor+\lfloor P/4032\rfloor+G$ | Create four notes of $\lfloor M/10\rfloor$ with height offsets 52,560, 105,120, 157,680, and 210,240. |

A Holder block MUST draw $\lfloor P/4032\rfloor$ before the block's pool credit.
A Voyager block MUST NOT draw from the pool. The validator MUST commit the
resulting pool, cumulative burn, fund credits, and miner reward notes as a
single transition. A detached branch MUST roll them back together. The
first subsidy allocates 407,342,941 atoms to the fund, 101,835,735 to the
pool, and 2,885,345,839 to the miner base before mode or fee settlement.

### Development fund

The genesis allocation MUST contain 1 to 32 positive member shares totaling
10,000 basis points. Each member receives the floor of its share of the fund
credit. The configured residual member receives the rounding remainder.
For a credit of $A$ atoms at height $h$, release $\lfloor A/2\rfloor$ at
$h+24$. For the remaining $L=A-\lfloor A/2\rfloor$, release the incremental
difference of $\lfloor L n/48\rfloor$ at period $n$, with periods of 8,766
blocks measured from $h$ and $1\le n\le48$.

A claim MUST authenticate under the member's ML-DSA-65 key, use the
next counter, stay within the released unspent allowance, and use the
member's active destination. The founder key MAY propose a new member
destination. The change becomes active 4,032 blocks after inclusion.
The revocation key MAY cancel an included proposal before its activation.
Changing a destination MUST preserve the existing ledger and claim counter.

### Issuance fee

The configured fixed issuance fee is 5,000,000,000 atoms (50 SIP). A valid
issuance MUST prove payment to the configured issuance fee destination.
That payment MUST NOT enter the miner's transfer-fee settlement. Under
this ruleset, governance MUST NOT change the issuance fee amount or its
destination. Fund claims and both types of fees move existing SIP.

## Rationale

The residual assignment conserves every atom. Mode-specific locks affect the time at which subsidy notes can be spent. Pre-block pool accounting makes the draw independent of the block's own credit.

## Security considerations

Every release and proposal uses consensus height. Clients should treat time conversions as estimates and keep balances derived from the verified canonical state.

## References

- [Parameters](../reference/parameters.md)
- [Transactions](02-transactions.md#public-issuance)
- [Transfer fees](04-blocks-and-fees.md#transfer-fees-and-settlement)
- [Integer accounting and fund implementation](../../crates/native-node/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
