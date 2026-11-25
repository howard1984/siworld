# 10. RPC

| Field | Value |
| --- | --- |
| Title | 10. RPC |
| Status | Active |
| Version | 1.0.0 |
| Applies to | Native wallet gateway and SIWORLD read-only chain export |
| Last updated | 2026-11-25 |

## Abstract

Documents the private wallet gateway and the read-only chain export consumed by public clients.

## Motivation

Separating data export from submission makes each integration depend on a clear capability. Chain identity and inclusion must be checked even when a transport is authenticated.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are
interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when,
they appear in all capitals.

### Private wallet gateway

Where enabled, private IPC uses a local Unix-domain socket. A request is
a one-byte operation followed by a four-byte little-endian payload length
and that many payload bytes. A response uses the same framing with a
status byte. Status 0 indicates success. Status 1 carries an error object.
The service MUST reject truncated and over-limit requests. Integrations MUST
restrict socket access to the owner and MUST NOT proxy it as a public endpoint.

| Operation | Request | Successful payload |
| --- | --- | --- |
| 0 | Empty | JSON head with `network`, `genesis`, `height`, `compact_available_height`, and `tip` |
| 1 | JSON `tip`, `from`, and `limit` | JSON object containing `ids`, capped at 128 IDs per pinned page |
| 2 | Exactly 32 raw block-ID bytes | Compact public block bytes |
| 3 | Canonical transaction envelope followed by its private fee sidecar | JSON `status: pending` and the `statement_id` |

The submission-only gateway MUST reject operations 0, 1, and 2.
Admission acknowledgment does not establish inclusion. Clients SHOULD
persist the exact packet and reconcile the corresponding statement
identifier before retrying after an ambiguous response.

### Read-only export

The explorer client uses `GET /v1/head`, `GET /v1/explorer`, and
`GET /v1/chain` relative to the selected export base. A chain page is
requested with `tip`, `from`, and `limit`. Pages MUST match the pinned
head rather than follow changes to an unpinned tip. Clients MUST bound
response sizes and validate the network, genesis, heights, and identifiers
against the selected configuration. Missing data or an incompatible
head MUST be treated as unavailable. The read-only export does not provide
custody, signing, or node administration.

## Rationale

Public data can be served independently of transaction admission. Pinning pages to a tip prevents a client from combining pages across branches or export updates.

## Security considerations

An export is an observation of a node's view. Clients making settlement decisions MUST independently verify the receipt and checkpoint evidence required by their policy. Private submission data can include fee openings and must be handled within the configured custody boundary.

## References

- [Explorer client](../../tools/explorer/chain-client.mjs)
- [Node gateway implementation](../../crates/native-node/)
- [Exchange integration](../guides/exchange-integration.md)
- [Storage and synchronization](07-storage-and-sync.md)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
