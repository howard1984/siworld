"""Extract numeric twenty-year evidence for an immutable native fund registry."""
import argparse
import json
from pathlib import Path


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def extract_simulation(log, output):
    marker = 'V1_ECONOMICS_SIMULATION='
    records = []
    for line in log.read_text().splitlines():
        prefix, found, record = line.partition(marker)
        if found:
            if prefix not in ('', 'test v1_economics::tests::seeded_twenty_year_modes_preserve_supply_and_curve ... '):
                raise ValueError('Unexpected simulation record prefix')
            records.append(record)
    if len(records) != 1:
        raise ValueError('Exactly one completed simulation record required')
    result = json.loads(records[0])
    if (type(result.get('economics_rule_version')) is not int
            or result['economics_rule_version'] != 3
            or type(result.get('holder_claim_before_injection')) is not int
            or result['holder_claim_before_injection'] != 1):
        raise ValueError('Simulation must use claim-before-injection economics version three')
    for key in ('height', 'issued', 'miner_subsidy_credited', 'holder_pool', 'burned', 'locked_subsidy'):
        if type(result.get(key)) is not int or result[key] < 0:
            raise ValueError('Invalid simulation integer')
    if result['height'] != 20 * 365 * 288:
        raise ValueError('Simulation did not cover twenty production years')
    shares = result.get('synthetic_wallet_basis_points')
    count = result.get('wallet_count')
    team_index = result.get('team_remainder_index')
    if (type(count) is not int or not 21 <= count <= 32
            or not isinstance(shares, list) or len(shares) != count
            or any(type(value) is not int or value <= 0 for value in shares)
            or sum(shares) != 10_000 or type(team_index) is not int
            or not 0 <= team_index < count):
        raise ValueError('Simulation must cover twenty-one to thirty-two exact-share wallets')
    entitlement, unlocked, spent = (result.get(key) for key in
                                   ('fund_entitlement', 'fund_unlocked', 'fund_spent'))
    if (any(type(value) is not int or value < 0 for value in (entitlement, unlocked, spent))
            or not spent <= unlocked <= entitlement):
        raise ValueError('Invalid simulated fund balances')
    if (result['issued'] != result['miner_subsidy_credited'] + result['holder_pool']
            + result['burned'] + entitlement
            or result['locked_subsidy'] > result['miner_subsidy_credited']):
        raise ValueError('Simulation violates issuance conservation or locked-subset bounds')
    wallets = result.get('fund_wallets')
    if not isinstance(wallets, list) or len(wallets) != count:
        raise ValueError('Simulation must report every fund wallet')
    fields = {'index', 'basis_points', 'entitlement', 'direct_unlocked',
              'vesting_unlocked', 'spent', 'available', 'spend_count'}
    for index, wallet in enumerate(wallets):
        if (not isinstance(wallet, dict) or set(wallet) != fields
                or any(type(value) is not int or value < 0 for value in wallet.values())
                or wallet['index'] != index or wallet['basis_points'] != shares[index]):
            raise ValueError('Invalid simulated fund wallet')
        released = wallet['direct_unlocked'] + wallet['vesting_unlocked']
        if (not wallet['spent'] <= released <= wallet['entitlement']
                or wallet['available'] != released - wallet['spent']):
            raise ValueError('Inconsistent simulated fund wallet balance')
    if (sum(wallet['entitlement'] for wallet in wallets) != entitlement
            or sum(wallet['direct_unlocked'] + wallet['vesting_unlocked'] for wallet in wallets) != unlocked
            or sum(wallet['spent'] for wallet in wallets) != spent):
        raise ValueError('Simulated fund aggregates differ from wallet balances')
    def numeric_tree(value):
        if type(value) is int:
            return value >= 0
        if isinstance(value, list):
            return all(numeric_tree(item) for item in value)
        if isinstance(value, dict):
            return all(isinstance(key, str) and key.replace('_', '').isalnum()
                       and numeric_tree(item) for key, item in value.items())
        return False
    if not numeric_tree(result):
        raise ValueError('Simulation must contain only numeric public evidence')
    write(output, {'schema': 1, 'status': 'candidate-pending-review', 'simulation': result,
                   'acceptance': False, 'cryptographic_approval': False, 'network_activation': False})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    extract_simulation(args.log, args.output)
