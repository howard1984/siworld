"""Exercise wire overhead, independent proof caps and capacity headroom."""

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'v1-network-budget.py'
spec = importlib.util.spec_from_file_location('v1_network_budget', SCRIPT)
budget = importlib.util.module_from_spec(spec)
spec.loader.exec_module(budget)


class NetworkBudgetTests(unittest.TestCase):
    def test_original_512_kib_scenario_is_reproducible(self):
        result = budget.report(link_mbps=30, transaction_proof_cap=524_288,
                               capacity_headroom_percent=0)
        self.assertEqual(result['transaction_settlement_payload_bytes'], 911_844_957)
        self.assertEqual(result['wire_bytes_per_interval'], 1_097_405_014)
        self.assertGreater(result['remaining_bytes_per_interval'], 0)
        self.assertLess(result['remaining_percent'], 3)

    def test_selected_640_kib_profile_requires_43_mbps(self):
        result = budget.report()
        self.assertEqual(result['parameters']['transaction_proof_cap_bytes'], 655_360)
        self.assertEqual(result['wire_bytes_per_interval'], 1_369_283_487)
        self.assertEqual(result['minimum_link_mbps'], 43)
        self.assertTrue(result['meets_capacity_headroom'])
        self.assertFalse(budget.report(link_mbps=42)['meets_capacity_headroom'])

    def test_minimum_link_keeps_fifteen_percent_of_capacity_free(self):
        for cap in (524_288, 655_360, 704 * 1024, 768 * 1024, 832 * 1024):
            result = budget.report(transaction_proof_cap=cap)
            minimum = result['minimum_link_mbps']
            self.assertEqual(result['evaluated_link_mbps'], minimum)
            self.assertGreaterEqual(result['remaining_percent'], 15)
            self.assertTrue(result['meets_capacity_headroom'])
            below = budget.report(transaction_proof_cap=cap, link_mbps=minimum - 1)
            self.assertFalse(below['meets_capacity_headroom'])
            self.assertEqual(result['wire_bytes_per_interval'], below['wire_bytes_per_interval'])

    def test_larger_transaction_cap_does_not_expand_other_proofs(self):
        base = budget.report(transaction_proof_cap=524_288)
        larger = budget.report(transaction_proof_cap=768 * 1024)
        base_components = base['components_bytes_per_interval']
        larger_components = larger['components_bytes_per_interval']
        self.assertGreater(larger_components['transaction_and_sidecar_wire'],
                           base_components['transaction_and_sidecar_wire'])
        for component in ('settlement_wire', 'issuance_wire_allowance', 'inventory_wire',
                          'handshake_wire_allowance', 'keepalive_wire_allowance'):
            self.assertEqual(base_components[component], larger_components[component])
        self.assertEqual(larger['parameters']['settlement_proof_cap_bytes'], 655_360)
        self.assertEqual(larger['parameters']['issuance_proof_cap_bytes'], 524_288)
        expected_payload = 3 * (576 * (768 * 1024 + 2184 + 78) + 655_360 + 159)
        self.assertEqual(larger['transaction_settlement_payload_bytes'], expected_payload)

    def test_each_wire_reserve_is_added_before_capacity_headroom(self):
        result = budget.report(transaction_proof_cap=768 * 1024)
        components = result['components_bytes_per_interval']
        base = sum(value for name, value in components.items()
                   if name not in ('retransmission_reserve', 'recovery_reserve'))
        self.assertEqual(components['retransmission_reserve'], budget.ceil_div(base * 2, 100))
        self.assertEqual(components['recovery_reserve'], budget.ceil_div(base * 5, 100))
        self.assertEqual(result['wire_bytes_per_interval'], sum(components.values()))
        self.assertEqual(result['minimum_link_mbps'],
                         budget.ceil_div(result['wire_bytes_per_interval'] * 8 * 100,
                                         300 * 1_000_000 * 85))

    def test_network_floor_does_not_change_the_wire_load(self):
        floor = budget.report(transaction_proof_cap=524_288)
        recommended = budget.report(link_mbps=100, transaction_proof_cap=524_288)
        self.assertEqual(floor['wire_bytes_per_interval'], recommended['wire_bytes_per_interval'])
        self.assertGreater(recommended['remaining_percent'], 70)
        self.assertLess(budget.report(link_mbps=25)['remaining_bytes_per_interval'], 0)
        self.assertEqual(recommended['recommended_link_mbps'], 100)

    def test_exact_packet_boundaries_include_ack_and_crypto_framing(self):
        self.assertGreater(budget.wire_message(1428), 1428 + 114)
        self.assertGreater(budget.wire_message(16_384), budget.wire_message(16_383))
        with self.assertRaises(ValueError):
            budget.wire_message(0)

    def test_native_protocol_counts_current_framing_and_compact_settlement_once(self):
        result = budget.native_protocol_report()
        parameters = result['parameters']
        self.assertEqual(parameters['application_frame_bytes'], 51)
        self.assertEqual(parameters['gossip_length_prefix_bytes'], 4)
        self.assertEqual(parameters['compact_reference_bytes'], 64)
        self.assertEqual(parameters['compact_fixed_bytes'], 1525)
        self.assertEqual(parameters['compact_payload_bytes'], 693_749)
        self.assertEqual(parameters['missing_request_payload_bytes'], 1026)
        self.assertEqual(parameters['missing_request_batches_per_copy'], 36)
        self.assertFalse(parameters['hybrid_provider_qualified'])
        self.assertEqual(result['components_bytes_per_interval']['settlement_wire'], 0)
        self.assertEqual(result['wire_bytes_per_interval'], 1_369_626_397)
        self.assertEqual(result['minimum_link_mbps'], 43)
        self.assertTrue(result['meets_capacity_headroom'])
        self.assertFalse(budget.native_protocol_report(link_mbps=42)['meets_capacity_headroom'])

    def test_duplicate_settlement_crosses_the_43_mbps_headroom_boundary(self):
        result = budget.native_protocol_report(link_mbps=43, duplicate_settlement=True)
        self.assertTrue(result['parameters']['standalone_settlement_duplicate'])
        self.assertEqual(result['wire_bytes_per_interval'], 1_371_987_223)
        self.assertEqual(result['minimum_link_mbps'], 44)
        self.assertFalse(result['meets_capacity_headroom'])
        self.assertTrue(budget.native_protocol_report(
            link_mbps=44, duplicate_settlement=True)['meets_capacity_headroom'])

    def test_native_protocol_caps_and_reserves_remain_independent(self):
        base = budget.native_protocol_report()
        larger = budget.native_protocol_report(transaction_proof_cap=768 * 1024)
        self.assertEqual(larger['parameters']['settlement_proof_cap_bytes'], 655_360)
        self.assertEqual(larger['parameters']['issuance_proof_cap_bytes'], 524_288)
        self.assertEqual(base['parameters']['compact_payload_bytes'],
                         larger['parameters']['compact_payload_bytes'])
        components = larger['components_bytes_per_interval']
        unreserved = sum(value for name, value in components.items()
                         if name not in ('retransmission_reserve', 'recovery_reserve'))
        self.assertEqual(components['retransmission_reserve'], budget.ceil_div(unreserved * 2, 100))
        self.assertEqual(components['recovery_reserve'], budget.ceil_div(unreserved * 5, 100))
        self.assertEqual(larger['wire_bytes_per_interval'], sum(components.values()))
        self.assertEqual(budget.native_protocol_report(64)['parameters']
                         ['missing_request_batches_per_copy'], 4)
        for arguments in ({'positions': 65}, {'link_mbps': 0},
                          {'transaction_proof_cap': 0}, {'capacity_headroom_percent': 100}):
            with self.assertRaises(ValueError):
                budget.native_protocol_report(**arguments)

    def test_economic_rewards_cover_maximum_compact_records_without_other_cost_changes(self):
        historical = budget.native_protocol_report()
        result = budget.native_protocol_report(economic_rewards=True)
        parameters = result['parameters']
        self.assertEqual(parameters['compact_fixed_bytes'], 61_235)
        self.assertEqual(parameters['compact_payload_bytes'], 753_459)
        self.assertEqual(parameters['extra_block_record_allowance_bytes'], 8192)
        self.assertEqual(parameters['maximum_reward_notes'], 5)
        self.assertEqual(parameters['maximum_signed_fund_payouts'], 8)
        self.assertEqual(parameters['maximum_registered_fund_wallets'], 32)
        self.assertEqual(parameters['genesis_fund_registry_bytes'], 62_530)
        self.assertFalse(parameters['genesis_fund_registry_repeated_per_block'])
        self.assertTrue(parameters['economic_rewards'])
        self.assertEqual(result['wire_bytes_per_interval'], 1_369_841_506)
        self.assertEqual(result['minimum_link_mbps'], 43)
        self.assertTrue(result['meets_capacity_headroom'])
        self.assertFalse(budget.native_protocol_report(
            link_mbps=42, economic_rewards=True)['meets_capacity_headroom'])
        for component, value in historical['components_bytes_per_interval'].items():
            if component not in ('compact_block_and_block_record_wire',
                                 'retransmission_reserve', 'recovery_reserve'):
                self.assertEqual(result['components_bytes_per_interval'][component], value)
        self.assertEqual(result['parameters']['transaction_proof_cap_bytes'], 655_360)
        self.assertEqual(result['parameters']['settlement_proof_cap_bytes'], 655_360)
        self.assertEqual(result['parameters']['issuance_proof_cap_bytes'], 524_288)

    def test_eight_claim_records_are_charged_independently_of_genesis_wallet_count(self):
        result = budget.native_protocol_report(economic_rewards=True)
        p = result['parameters']
        self.assertEqual(p['compact_fixed_bytes'], 1525 + 2 + 4 * 1361 + 8 * 6783)
        self.assertEqual(p['compact_payload_bytes'], p['compact_fixed_bytes'] + 576 * 64 + 655_360)
        # The immutable public registry is fetched with genesis, not every block.
        self.assertNotIn('genesis_fund_registry_wire', result['components_bytes_per_interval'])
        self.assertLess(p['maximum_signed_fund_payouts'], p['maximum_registered_fund_wallets'])

    def test_economic_budget_matches_native_record_limits(self):
        root = SCRIPT.parents[1]
        for relative, name, expected in (
                ('crates/native-node/src/wire.rs', 'MAX_FUND_SPENDS', 8),
                ('crates/native-node/src/fund_spend.rs', 'ENCODED_BYTES', 6783),
                ('crates/core/src/v1_economics.rs', 'MAX_FUND_WALLETS', 32)):
            source = (root / relative).read_text()
            value = re.search(r'pub const ' + name + r': usize = ([\d_]+);', source)
            self.assertIsNotNone(value, relative)
            self.assertEqual(int(value[1].replace('_', '')), expected, relative)

    def test_economic_rewards_still_reserve_fifteen_percent_for_each_proof_cap(self):
        for cap in (524_288, 655_360, 768 * 1024):
            result = budget.native_protocol_report(transaction_proof_cap=cap,
                                                   economic_rewards=True)
            minimum = result['minimum_link_mbps']
            self.assertGreaterEqual(result['remaining_percent'], 15)
            self.assertTrue(result['meets_capacity_headroom'])
            self.assertFalse(budget.native_protocol_report(
                transaction_proof_cap=cap, link_mbps=minimum - 1,
                economic_rewards=True)['meets_capacity_headroom'])
        duplicated = budget.native_protocol_report(economic_rewards=True,
                                                   duplicate_settlement=True)
        self.assertEqual(duplicated['minimum_link_mbps'], 44)

    def test_economic_reward_cli_requires_native_protocol_and_preserves_legacy(self):
        for flags in (['--economic-rewards'], ['--economic-rewards', '--legacy-baseline'],
                      ['--economic-rewards', '--native-protocol', '--legacy-baseline']):
            result = subprocess.run([sys.executable, str(SCRIPT), *flags],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
        result = json.loads(subprocess.check_output(
            [sys.executable, str(SCRIPT), '--native-protocol', '--economic-rewards'], text=True))
        self.assertEqual(result, budget.native_protocol_report(economic_rewards=True))
        legacy = json.loads(subprocess.check_output(
            [sys.executable, str(SCRIPT), '--legacy-baseline'], text=True))
        self.assertEqual(legacy, budget.report(576, 30, 524_288, 524_288, 524_288, 0))

    def test_only_fixed_capacity_groups_are_accepted(self):
        self.assertGreater(budget.report(64)['remaining_bytes_per_interval'], 0)
        for positions in (0, 63, 65, 577, 592):
            with self.assertRaises(ValueError):
                budget.report(positions)
        for arguments in ({'transaction_proof_cap': 0}, {'settlement_proof_cap': -1},
                          {'issuance_proof_cap': 0}, {'capacity_headroom_percent': -1},
                          {'capacity_headroom_percent': 100}, {'link_mbps': 0}):
            with self.assertRaises(ValueError):
                budget.report(**arguments)

    def test_integrated_issuance_is_carried_once_in_the_compact_body(self):
        empty = budget.native_protocol_report(economic_rewards=True, integrated_issuances=0)
        one = budget.native_protocol_report(economic_rewards=True, integrated_issuances=1)
        four = budget.native_protocol_report(economic_rewards=True, integrated_issuances=4)
        for value in (empty, one, four):
            self.assertEqual(value['components_bytes_per_interval']['issuance_wire_allowance'], 0)
            self.assertEqual(value['components_bytes_per_interval']['settlement_wire'], 0)
            self.assertGreaterEqual(value['remaining_percent'], 15)
        self.assertGreater(four['wire_bytes_per_interval'], one['wire_bytes_per_interval'])
        self.assertGreater(one['wire_bytes_per_interval'], empty['wire_bytes_per_interval'])
        self.assertEqual(one['wire_bytes_per_interval'], 1_369_817_498)
        self.assertEqual(four['wire_bytes_per_interval'], 1_375_588_015)
        self.assertEqual(four['minimum_link_mbps'], 44)
        self.assertFalse(budget.native_protocol_report(economic_rewards=True,
            integrated_issuances=4, link_mbps=43)['meets_capacity_headroom'])
        for arguments in ({'integrated_issuances': 1},
                          {'economic_rewards': True, 'integrated_issuances': -1},
                          {'economic_rewards': True, 'integrated_issuances': 5}):
            with self.assertRaises(ValueError):
                budget.native_protocol_report(**arguments)


if __name__ == '__main__':
    unittest.main()
