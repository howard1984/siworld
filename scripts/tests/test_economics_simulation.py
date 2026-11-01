"""Sanitized economic evidence must cover the configured wallet allocation."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('fund_simulation', ROOT / 'scripts/check-fund-simulation.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def record():
    result = {'economics_rule_version': 3, 'holder_claim_before_injection': 1,
            'height': 20 * 365 * 288, 'issued': 100, 'miner_subsidy_credited': 50,
            'holder_pool': 10, 'burned': 10, 'locked_subsidy': 20,
            'synthetic_wallet_basis_points': [450] * 20 + [1000],
            'team_remainder_index': 20, 'wallet_count': 21,
            'fund_entitlement': 30, 'fund_unlocked': 20, 'fund_spent': 10}
    result['fund_wallets'] = [
        {'index': index, 'basis_points': share, 'entitlement': 30 if index == 20 else 0,
         'direct_unlocked': 10 if index == 20 else 0, 'vesting_unlocked': 10 if index == 20 else 0,
         'spent': 10 if index == 20 else 0, 'available': 10 if index == 20 else 0,
         'spend_count': 1 if index == 20 else 0}
        for index, share in enumerate(result['synthetic_wallet_basis_points'])]
    return result


class EconomicsSimulationTests(unittest.TestCase):
    def extract(self, evidence):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'simulation.log'
            output = Path(directory) / 'evidence.json'
            log.write_text('V1_ECONOMICS_SIMULATION=' + json.dumps(evidence) + '\n')
            MODULE.extract_simulation(log, output)
            return json.loads(output.read_text())

    def test_completed_twenty_one_wallet_reference_is_preserved(self):
        result = self.extract(record())
        self.assertEqual(result['simulation'], record())
        self.assertFalse(result['network_activation'])

    def test_old_two_wallet_or_invalid_basis_point_records_are_rejected(self):
        for changes in ({'economics_rule_version': 2},
                        {'holder_claim_before_injection': 0},
                        {'holder_claim_before_injection': True},
                        {'wallet_count': 2},
                        {'wallet_count': 33},
                        {'synthetic_wallet_basis_points': [450] * 20 + [999]},
                        {'synthetic_wallet_basis_points': [0] + [500] * 20},
                        {'team_remainder_index': 21},
                        {'team_remainder_index': True},
                        {'fund_wallets': []},
                        {'fund_spent': 21},
                        {'fund_unlocked': 31}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.extract({**record(), **changes})

    def test_evidence_without_current_pool_rule_identity_is_rejected(self):
        for field in ('economics_rule_version', 'holder_claim_before_injection'):
            evidence = record()
            del evidence[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.extract(evidence)

    def test_supply_conservation_and_locked_subset_are_checked(self):
        for changes in ({'issued': 101}, {'miner_subsidy_credited': 49},
                        {'holder_pool': 11}, {'burned': 11},
                        {'locked_subsidy': 51}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.extract({**record(), **changes})


if __name__ == '__main__':
    unittest.main()
