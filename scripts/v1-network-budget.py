"""Reproduce a conditional V1 uplink wire budget, not measured throughput.

The defaults describe IPv6/TCP over a 1500-byte MTU VLAN Ethernet link,
three application relay copies, reciprocal incoming load and delayed ACKs.
All reserves and incomplete protocol-format allowances are explicit.
"""

import argparse
import json

INTERVAL_SECONDS = 300
TRANSACTION_PROOF_CAP = 655_360
SETTLEMENT_PROOF_CAP = 655_360
ISSUANCE_PROOF_CAP = 524_288
TRANSACTION_ENVELOPE_BYTES = 2184
SIDECAR_BYTES = 78
SETTLEMENT_ENVELOPE_BYTES = 159
CAPACITY_HEADROOM_PERCENT = 15
RECOMMENDED_LINK_MBPS = 100
MSS = 1428  # 1500 - IPv6(40) - TCP with options(32).
PACKET_OVERHEAD = 114  # IPv6/TCP(72) + VLAN Ethernet, FCS, preamble and IFG(42).


def ceil_div(n, d):
    return (n + d - 1) // d


def wire_message(payload):
    if payload <= 0:
        raise ValueError('positive message size required')
    framed = payload + 16  # Application message type/length budget.
    framed += ceil_div(framed, 16_384) * 30  # AEAD tag/length(18) + mux frame(12).
    packets = ceil_div(framed, MSS)
    # Outgoing data plus uplink ACKs for equal reciprocal incoming traffic.
    return framed + packets * PACKET_OVERHEAD + ceil_div(packets, 2) * PACKET_OVERHEAD


def report(positions=576, link_mbps=None, transaction_proof_cap=TRANSACTION_PROOF_CAP,
           settlement_proof_cap=SETTLEMENT_PROOF_CAP, issuance_proof_cap=ISSUANCE_PROOF_CAP,
           capacity_headroom_percent=CAPACITY_HEADROOM_PERCENT):
    if not 64 <= positions <= 576 or positions % 16:
        raise ValueError('positions must be a multiple of 16 in [64, 576]')
    if min(transaction_proof_cap, settlement_proof_cap, issuance_proof_cap) <= 0:
        raise ValueError('positive proof caps required')
    if not 0 <= capacity_headroom_percent < 100:
        raise ValueError('capacity headroom must be in [0, 100)')
    if link_mbps is not None and link_mbps <= 0:
        raise ValueError('positive link rate required')
    copies = 3
    transaction_and_sidecar = transaction_proof_cap + TRANSACTION_ENVELOPE_BYTES + SIDECAR_BYTES
    settlement_envelope = settlement_proof_cap + SETTLEMENT_ENVELOPE_BYTES
    inventory = positions * 32
    payload = copies * (positions * transaction_and_sidecar + settlement_envelope)
    components = {
        'transaction_and_sidecar_wire': copies * positions * wire_message(transaction_and_sidecar),
        'settlement_wire': copies * wire_message(settlement_envelope),
        'issuance_wire_allowance': copies * wire_message(issuance_proof_cap + 16_384),
        'inventory_wire': copies * wire_message(inventory),
        'compact_block_and_block_record_wire': copies * wire_message(inventory + 8192),
        'all_id_requests_wire': copies * wire_message(inventory + 16),
        'handshake_wire_allowance': 8 * wire_message(32_768),
        'keepalive_wire_allowance': 16 * 10 * wire_message(64),
        'other_control_wire_allowance': wire_message(65_536),
    }
    base = sum(components.values())
    components['retransmission_reserve'] = ceil_div(base * 2, 100)
    components['recovery_reserve'] = ceil_div(base * 5, 100)
    total = sum(components.values())
    # Reserve the requested fraction of link capacity after every modeled wire cost.
    minimum_link = ceil_div(total * 8 * 100,
                            INTERVAL_SECONDS * 1_000_000 * (100 - capacity_headroom_percent))
    if link_mbps is None:
        link_mbps = minimum_link
    capacity = link_mbps * 1_000_000 * INTERVAL_SECONDS // 8
    return {
        'status': 'conditional-planning-budget-not-network-acceptance',
        'positions': positions, 'interval_seconds': INTERVAL_SECONDS,
        'relay_copies': copies,
        'parameters': {
            'transaction_proof_cap_bytes': transaction_proof_cap,
            'settlement_proof_cap_bytes': settlement_proof_cap,
            'issuance_proof_cap_bytes': issuance_proof_cap,
            'transaction_envelope_bytes': TRANSACTION_ENVELOPE_BYTES,
            'sidecar_bytes': SIDECAR_BYTES,
            'settlement_envelope_bytes': SETTLEMENT_ENVELOPE_BYTES,
            'capacity_headroom_percent': capacity_headroom_percent,
            'headroom_formula': 'ceil(wire_mbps / (1 - capacity_headroom_percent / 100))',
        },
        'minimum_link_mbps': minimum_link, 'evaluated_link_mbps': link_mbps,
        'recommended_link_mbps': RECOMMENDED_LINK_MBPS,
        'transaction_settlement_payload_bytes': payload,
        'components_bytes_per_interval': components,
        'wire_bytes_per_interval': total,
        'wire_mbps': total * 8 / INTERVAL_SECONDS / 1_000_000,
        'link_capacity_bytes_per_interval': capacity,
        'remaining_bytes_per_interval': capacity - total,
        'remaining_mbps': (capacity - total) * 8 / INTERVAL_SECONDS / 1_000_000,
        'remaining_percent': (capacity - total) * 100 / capacity,
        'meets_capacity_headroom': (capacity - total) * 100 >= capacity * capacity_headroom_percent,
        'serialization_seconds': total * 8 / (link_mbps * 1_000_000),
    }


NATIVE_FRAME_BYTES = 51
NATIVE_GOSSIP_LENGTH_BYTES = 4
NATIVE_REFERENCE_BYTES = 64
NATIVE_COMPACT_FIXED_BYTES = 1525
NATIVE_MAXIMUM_REWARD_NOTES = 5
NATIVE_REWARD_RECORD_BYTES = 1361
NATIVE_MAXIMUM_FUND_PAYOUTS = 8
NATIVE_SIGNED_FUND_PAYOUT_BYTES = 6783
NATIVE_MAXIMUM_FUND_WALLETS = 32
NATIVE_GENESIS_FUND_REGISTRY_BYTES = 2 + NATIVE_MAXIMUM_FUND_WALLETS * (2 + 1952)
NATIVE_ECONOMIC_COMPACT_FIXED_BYTES = (
    NATIVE_COMPACT_FIXED_BYTES + 2
    + (NATIVE_MAXIMUM_REWARD_NOTES - 1) * NATIVE_REWARD_RECORD_BYTES
    + NATIVE_MAXIMUM_FUND_PAYOUTS * NATIVE_SIGNED_FUND_PAYOUT_BYTES)
NATIVE_MISSING_BATCH = 16
NATIVE_HELLO_BYTES = 103
NATIVE_EXTRA_BLOCK_RECORD_BYTES = 8192


def native_protocol_report(positions=576, link_mbps=None,
                           transaction_proof_cap=TRANSACTION_PROOF_CAP,
                           settlement_proof_cap=SETTLEMENT_PROOF_CAP,
                           issuance_proof_cap=ISSUANCE_PROOF_CAP,
                           capacity_headroom_percent=CAPACITY_HEADROOM_PERCENT,
                           duplicate_settlement=False, economic_rewards=False,
                           integrated_issuances=None):
    """Budget current native framing with explicitly unqualified channel costs.

    The compact body already contains settlement. A separate settlement copy
    is charged only for the opt-in duplicate-traffic sensitivity calculation.
    The 8-KiB future-record allowance and full-reference inventory allowance
    remain conservative additions to the implemented compact codec. HELLO is
    charged an additional application frame even though session setup writes
    its fixed bytes directly. Hybrid record and handshake sizes are assumptions,
    not measurements or bounds established by the unavailable provider.
    Economic rewards opt in to the maximum compact record: five reward notes,
    eight signed fund payouts and two explicit mode/count bytes. The independent
    8-KiB future-record allowance is retained in addition to that encoded size.
    """
    if integrated_issuances is not None and (not economic_rewards
            or type(integrated_issuances) is not int or not 0 <= integrated_issuances <= 4):
        raise ValueError('Integrated issuance requires economic mode and a count from zero to four')
    # Preserve default-report validation and metadata without changing its model.
    result = report(positions, link_mbps, transaction_proof_cap,
                    settlement_proof_cap, issuance_proof_cap,
                    capacity_headroom_percent)
    copies = result['relay_copies']

    def native_wire(payload):
        # Reuse exact record/packet/ACK rounding with the current 51-byte header.
        return wire_message(payload + NATIVE_FRAME_BYTES - 16)

    transaction = (transaction_proof_cap + TRANSACTION_ENVELOPE_BYTES
                   + SIDECAR_BYTES + NATIVE_GOSSIP_LENGTH_BYTES)
    compact_fixed = (NATIVE_ECONOMIC_COMPACT_FIXED_BYTES if economic_rewards
                     else NATIVE_COMPACT_FIXED_BYTES)
    # Block v4 / compact v3 carry complete issuance records, including proofs.
    # The activated count is an explicit network setting; four is a codec bound.
    issuance_record = (4 + 2 + 32 + 1952 + 8 + 32 + 8 + 2 + 256 + 1 + 8
                       + 3 * (48 + 32 + 1313) + 3309 + 48 + 48 + 4
                       + issuance_proof_cap)
    if integrated_issuances is not None:
        compact_fixed += 1 + integrated_issuances * (4 + issuance_record)
    compact = compact_fixed + positions * NATIVE_REFERENCE_BYTES + settlement_proof_cap
    request_batches = positions // NATIVE_MISSING_BATCH
    request_payload = 2 + NATIVE_MISSING_BATCH * NATIVE_REFERENCE_BYTES
    components = {
        'transaction_and_sidecar_wire': copies * positions * native_wire(transaction),
        'settlement_wire': (copies * native_wire(settlement_proof_cap
                                                + SETTLEMENT_ENVELOPE_BYTES)
                            if duplicate_settlement else 0),
        'issuance_wire_allowance': (copies * native_wire(issuance_proof_cap + 16_384)
                                  if integrated_issuances is None else 0),
        'inventory_wire_allowance': copies * native_wire(2 + positions * NATIVE_REFERENCE_BYTES),
        'compact_block_and_block_record_wire': copies * native_wire(
            compact + NATIVE_EXTRA_BLOCK_RECORD_BYTES),
        # Every request contains 16 exact statement/proof pairs. Charge its
        # END_BATCH even when no body recovery is needed; bodies use the reserve.
        'all_id_requests_wire': copies * request_batches * (
            native_wire(request_payload) + native_wire(0)),
        'handshake_wire_allowance': 8 * native_wire(32_768),
        'hello_wire_allowance': 8 * native_wire(NATIVE_HELLO_BYTES),
        'keepalive_wire_allowance': 16 * 10 * native_wire(64),
        'other_control_wire_allowance': native_wire(65_536),
    }
    base = sum(components.values())
    components['retransmission_reserve'] = ceil_div(base * 2, 100)
    components['recovery_reserve'] = ceil_div(base * 5, 100)
    total = sum(components.values())
    minimum_link = ceil_div(total * 8 * 100,
                            INTERVAL_SECONDS * 1_000_000 * (100 - capacity_headroom_percent))
    evaluated_link = minimum_link if link_mbps is None else link_mbps
    capacity = evaluated_link * 1_000_000 * INTERVAL_SECONDS // 8
    parameters = result['parameters']
    parameters.update({
        'application_frame_bytes': NATIVE_FRAME_BYTES,
        'gossip_length_prefix_bytes': NATIVE_GOSSIP_LENGTH_BYTES,
        'compact_reference_bytes': NATIVE_REFERENCE_BYTES,
        'compact_fixed_bytes': compact_fixed,
        'compact_payload_bytes': compact,
        'extra_block_record_allowance_bytes': NATIVE_EXTRA_BLOCK_RECORD_BYTES,
        'missing_reference_batch_size': NATIVE_MISSING_BATCH,
        'missing_request_payload_bytes': request_payload,
        'missing_request_batches_per_copy': request_batches,
        'standalone_settlement_duplicate': duplicate_settlement,
        'handshake_payload_allowance_bytes': 32_768,
        'hybrid_provider_qualified': False,
    })
    if economic_rewards:
        parameters.update({
            'economic_rewards': True,
            'maximum_reward_notes': NATIVE_MAXIMUM_REWARD_NOTES,
            'maximum_signed_fund_payouts': NATIVE_MAXIMUM_FUND_PAYOUTS,
            'signed_fund_payout_bytes': NATIVE_SIGNED_FUND_PAYOUT_BYTES,
            'maximum_registered_fund_wallets': NATIVE_MAXIMUM_FUND_WALLETS,
            'genesis_fund_registry_bytes': NATIVE_GENESIS_FUND_REGISTRY_BYTES,
            'genesis_fund_registry_repeated_per_block': False,
        })
    if integrated_issuances is not None:
        parameters.update({'integrated_issuance_records': integrated_issuances,
                           'maximum_issuance_record_bytes': issuance_record,
                           'issuance_policy_activated': False})
    result.update({
        'model': 'native-protocol-framing-with-conditional-channel-allowances',
        'minimum_link_mbps': minimum_link,
        'evaluated_link_mbps': evaluated_link,
        'transaction_settlement_payload_bytes': copies * (
            positions * transaction + compact
            + (settlement_proof_cap + SETTLEMENT_ENVELOPE_BYTES
               if duplicate_settlement else 0)),
        'components_bytes_per_interval': components,
        'wire_bytes_per_interval': total,
        'wire_mbps': total * 8 / INTERVAL_SECONDS / 1_000_000,
        'link_capacity_bytes_per_interval': capacity,
        'remaining_bytes_per_interval': capacity - total,
        'remaining_mbps': (capacity - total) * 8 / INTERVAL_SECONDS / 1_000_000,
        'remaining_percent': (capacity - total) * 100 / capacity,
        'meets_capacity_headroom': ((capacity - total) * 100
                                    >= capacity * capacity_headroom_percent),
        'serialization_seconds': total * 8 / (evaluated_link * 1_000_000),
    })
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--positions', type=int, default=576)
    parser.add_argument('--link-mbps', type=int)
    parser.add_argument('--transaction-proof-cap-bytes', type=int, default=TRANSACTION_PROOF_CAP)
    parser.add_argument('--settlement-proof-cap-bytes', type=int, default=SETTLEMENT_PROOF_CAP)
    parser.add_argument('--issuance-proof-cap-bytes', type=int, default=ISSUANCE_PROOF_CAP)
    parser.add_argument('--capacity-headroom-percent', type=int, default=CAPACITY_HEADROOM_PERCENT)
    parser.add_argument('--native-protocol', action='store_true',
                        help='use native 51-byte framing and exact-proof compact references')
    parser.add_argument('--duplicate-settlement', action='store_true',
                        help='with --native-protocol, also charge a separate settlement copy')
    parser.add_argument('--economic-rewards', action='store_true',
                        help='with --native-protocol, include five reward notes and eight signed fund payouts')
    parser.add_argument('--integrated-issuances', type=int,
                        help='with native economic mode, budget zero to four issuance records inside compact bodies')
    parser.add_argument('--legacy-baseline', action='store_true',
                        help='reproduce the prior 524288-byte proof caps and 30-Mbps link without extra headroom')
    args = parser.parse_args()
    if args.native_protocol and args.legacy_baseline:
        parser.error('--native-protocol and --legacy-baseline are mutually exclusive')
    if args.duplicate_settlement and not args.native_protocol:
        parser.error('--duplicate-settlement requires --native-protocol')
    if args.economic_rewards and not args.native_protocol:
        parser.error('--economic-rewards requires --native-protocol')
    if args.integrated_issuances is not None and (not args.economic_rewards
            or not 0 <= args.integrated_issuances <= 4):
        parser.error('--integrated-issuances requires native economic mode and a count from zero to four')
    if args.native_protocol:
        print(json.dumps(native_protocol_report(
            args.positions, args.link_mbps, args.transaction_proof_cap_bytes,
            args.settlement_proof_cap_bytes, args.issuance_proof_cap_bytes,
            args.capacity_headroom_percent, args.duplicate_settlement, args.economic_rewards,
            args.integrated_issuances),
            indent=2, sort_keys=True))
    elif args.legacy_baseline:
        print(json.dumps(report(args.positions, 30, 524_288, 524_288, 524_288, 0),
                         indent=2, sort_keys=True))
    else:
        print(json.dumps(report(args.positions, args.link_mbps, args.transaction_proof_cap_bytes,
                                args.settlement_proof_cap_bytes, args.issuance_proof_cap_bytes,
                                args.capacity_headroom_percent), indent=2, sort_keys=True))
