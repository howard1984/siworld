"""Reproduce a component storage model for the proposed native V1 codec.

The estimates are not measured whole-node disk bounds. All quantities use
decimal bytes. Proof lengths are caps; index/state allocation is a planning
allowance. Block and issuance records have explicit provisional byte reserves;
the database working allowance is not a measurement or a protocol bound.
"""

import argparse
import json
from fractions import Fraction

BLOCKS_PER_DAY = 288
MIN_POSITIONS = 64
MAX_POSITIONS = 576
TRANSACTION_PROOF_CAP = 655_360
SETTLEMENT_PROOF_CAP = 655_360
ISSUANCE_PROOF_CAP = 524_288
SIDECAR_BYTES = 78
RETENTION_BLOCKS = 3 * BLOCKS_PER_DAY + 24
SYSTEM_BYTES = 20_000_000_000
BLOCK_RECORD_ALLOWANCE = 8192
ECONOMIC_BLOCK_RECORD_ALLOWANCE = 65_536
ECONOMIC_GENESIS_REGISTRY_ALLOWANCE = 65_536
ISSUANCE_RECORD_ALLOWANCE = 16_384
DATABASE_WORKING_ALLOWANCE = 16_000_000_000


def positions_per_day(transactions):
    if not 0 <= transactions <= BLOCKS_PER_DAY * MAX_POSITIONS:
        raise ValueError('workload exceeds the fixed position capacity')
    return max(BLOCKS_PER_DAY * MIN_POSITIONS, ((transactions + 15) // 16) * 16)


def ceil_fraction(value):
    return -(-value.numerator // value.denominator)


def estimate(positions, years, permanent_bytes=2115, extra_permanent_bytes=0,
             block_record_bytes=BLOCK_RECORD_ALLOWANCE,
             issuance_bytes_per_block=ISSUANCE_RECORD_ALLOWANCE,
             database_working_bytes=DATABASE_WORKING_ALLOWANCE,
             transaction_proof_cap=TRANSACTION_PROOF_CAP,
             settlement_proof_cap=SETTLEMENT_PROOF_CAP,
             issuance_proof_cap=ISSUANCE_PROOF_CAP,
             genesis_registry_bytes=0):
    if not BLOCKS_PER_DAY * MIN_POSITIONS <= positions <= BLOCKS_PER_DAY * MAX_POSITIONS:
        raise ValueError('position rate outside fixed block capacity')
    if (years <= 0 or permanent_bytes <= 0 or min(extra_permanent_bytes, block_record_bytes,
                                                   issuance_bytes_per_block, database_working_bytes,
                                                   genesis_registry_bytes) < 0):
        raise ValueError('positive lifetime and byte budgets required')
    if min(transaction_proof_cap, settlement_proof_cap, issuance_proof_cap) <= 0:
        raise ValueError('positive proof caps required')
    rolling_records = ceil_fraction(Fraction(positions * RETENTION_BLOCKS, BLOCKS_PER_DAY))
    rolling_positions = ((rolling_records + 15) // 16) * 16
    transaction_rolling = rolling_positions * transaction_proof_cap
    sidecar_rolling = rolling_positions * SIDECAR_BYTES
    settlement_rolling = RETENTION_BLOCKS * settlement_proof_cap
    transaction_settlement_sidecar_rolling = transaction_rolling + sidecar_rolling + settlement_rolling
    issuance_rolling = RETENTION_BLOCKS * issuance_proof_cap
    rolling = transaction_settlement_sidecar_rolling + issuance_rolling
    permanent = positions * 365 * years * permanent_bytes
    block_records = BLOCKS_PER_DAY * 365 * years * block_record_bytes
    issuance_records = BLOCKS_PER_DAY * 365 * years * issuance_bytes_per_block
    indexes_and_state = ceil_fraction(Fraction(
        permanent + block_records + issuance_records + genesis_registry_bytes, 4))
    used = (rolling + permanent + block_records + issuance_records + indexes_and_state +
            SYSTEM_BYTES + database_working_bytes + extra_permanent_bytes + genesis_registry_bytes)
    return dict(positions_per_day=positions, years=years,
                rolling_positions=rolling_positions, rolling_bytes=rolling,
                transaction_proof_rolling_bytes=transaction_rolling,
                sidecar_rolling_bytes=sidecar_rolling,
                settlement_proof_rolling_bytes=settlement_rolling,
                transaction_settlement_sidecar_rolling_bytes=transaction_settlement_sidecar_rolling,
                issuance_proof_rolling_allowance_bytes=issuance_rolling,
                permanent_public_bytes=permanent,
                permanent_block_record_allowance_bytes=block_records,
                permanent_issuance_allowance_bytes=issuance_records,
                genesis_registry_allowance_bytes=genesis_registry_bytes,
                database_working_allowance_bytes=database_working_bytes,
                index_state_allowance_bytes=indexes_and_state,
                system_bytes=SYSTEM_BYTES,
                extra_permanent_bytes=extra_permanent_bytes, used_bytes=used,
                device_bytes_with_20_percent_free=ceil_fraction(Fraction(used * 5, 4)))


def report(permanent_bytes=2115, transaction_proof_cap=TRANSACTION_PROOF_CAP,
           settlement_proof_cap=SETTLEMENT_PROOF_CAP, issuance_proof_cap=ISSUANCE_PROOF_CAP,
           economic_rewards=False):
    block_record_bytes = (ECONOMIC_BLOCK_RECORD_ALLOWANCE if economic_rewards
                          else BLOCK_RECORD_ALLOWANCE)
    genesis_registry_bytes = ECONOMIC_GENESIS_REGISTRY_ALLOWANCE if economic_rewards else 0
    result = {'status': 'proposed-codec-component-planning-model',
            'permanent_bytes_per_position': permanent_bytes,
            'parameters': {
                'transaction_proof_cap_bytes': transaction_proof_cap,
                'settlement_proof_cap_bytes': settlement_proof_cap,
                'issuance_proof_cap_bytes': issuance_proof_cap,
                'sidecar_bytes': SIDECAR_BYTES,
                'finality_delay_blocks': 24, 'retention_days_after_finality': 3,
                'index_state_percent_of_permanent_records': 25,
                'device_free_percent': 20,
            },
            'block_record_allowance_bytes_per_block': block_record_bytes,
            'genesis_registry_allowance_bytes': genesis_registry_bytes,
            'issuance_record_allowance_bytes_per_block': ISSUANCE_RECORD_ALLOWANCE,
            'database_working_allowance_bytes': DATABASE_WORKING_ALLOWANCE, 'retention_blocks_at_target_rate': RETENTION_BLOCKS,
            'cases': {name: [estimate(positions, year, permanent_bytes,
                                     block_record_bytes=block_record_bytes,
                                     genesis_registry_bytes=genesis_registry_bytes,
                                     transaction_proof_cap=transaction_proof_cap,
                                     settlement_proof_cap=settlement_proof_cap,
                                     issuance_proof_cap=issuance_proof_cap) for year in (1, 3, 5)]
                      for name, positions in (
                          ('maximum', BLOCKS_PER_DAY * MAX_POSITIONS),
                          ('transactions_10000_per_day', positions_per_day(10_000)),
                          ('transactions_50000_per_day_adaptive_packing', positions_per_day(50_000)),
                          ('transactions_50000_per_day_uniform_176', BLOCKS_PER_DAY * 176))}}
    if economic_rewards:
        result['parameters']['economic_rewards'] = True
        result['parameters'].update({'maximum_registered_fund_wallets': 32,
                                     'maximum_signed_fund_payouts_per_block': 8,
                                     'encoded_genesis_fund_registry_bytes': 62_530})
        result.update({
            'planning_only': True,
            'measured_database_bound': False,
            'block_record_allowance_basis': (
                'five reward notes and eight signed fund payouts with provisional record overhead'),
        })
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--permanent-bytes', type=int, default=2115)
    parser.add_argument('--transaction-proof-cap-bytes', type=int, default=TRANSACTION_PROOF_CAP)
    parser.add_argument('--settlement-proof-cap-bytes', type=int, default=SETTLEMENT_PROOF_CAP)
    parser.add_argument('--issuance-proof-cap-bytes', type=int, default=ISSUANCE_PROOF_CAP)
    parser.add_argument('--economic-rewards', action='store_true',
                        help='allow 64 KiB per block for five reward notes and eight signed fund payouts')
    parser.add_argument('--legacy-baseline', action='store_true',
                        help='reproduce the prior model with all proof caps set to 524288 bytes')
    args = parser.parse_args()
    if args.economic_rewards and args.legacy_baseline:
        parser.error('--economic-rewards and --legacy-baseline are mutually exclusive')
    caps = (524_288, 524_288, 524_288) if args.legacy_baseline else (
        args.transaction_proof_cap_bytes, args.settlement_proof_cap_bytes, args.issuance_proof_cap_bytes)
    print(json.dumps(report(args.permanent_bytes, *caps, economic_rewards=args.economic_rewards),
                     indent=2, sort_keys=True))
