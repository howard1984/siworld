"""Rejection checks for the source-bound three-relation engineering manifest."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('native_proof_profiles', ROOT / 'scripts/ci/check-native-proof-profiles.py')
PROFILES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILES)


class NativeProofProfileTests(unittest.TestCase):
    def profile(self):
        return json.loads((ROOT / PROFILES.MANIFEST).read_text())

    def test_all_three_relations_bind_unchanged_transaction_profile(self):
        value = self.profile()
        PROFILES.validate(value)
        self.assertEqual([row['kind'] for row in value['relations']], list(PROFILES.KINDS))
        self.assertEqual([row['capacity'] for row in value['relations']], [0, 576, 3])
        self.assertFalse(value['cryptographic_approval'])
        self.assertFalse(value['network_activation'])
        self.assertFalse(value['node_integration'])

    def test_source_key_capacity_parameters_and_status_changes_are_rejected(self):
        original = self.profile()
        mutations = [
            lambda p: p.update(network_activation=True),
            lambda p: p.update(cryptographic_approval=True),
            lambda p: p.update(node_integration=True),
            lambda p: p.update(transaction_profile_sha256='0' * 64),
            lambda p: p['tool_source_sha256'].update({PROFILES.PROVENANCE.canonical_path(PROFILES.TOOLS[1]): '0' * 64}),
            lambda p: p['relations'].pop(),
            lambda p: p['relations'][1].update(capacity=575),
            lambda p: p['relations'][2]['parameters'].update(num_queries=35),
            lambda p: p['relations'][1]['parameters'].update(max_log_arity=True),
            lambda p: p['relations'][1]['public_verifier_key'].update(sha256='0' * 64),
            lambda p: p['relations'][2]['security']['screen'].update(passes_selected_model=False),
            lambda p: p['relations'][0]['public_verifier_key'].update(hex=p['relations'][1]['public_verifier_key']['hex']),
        ]
        for change in mutations:
            with self.subTest(change=mutations.index(change)):
                value = copy.deepcopy(original)
                change(value)
                with self.assertRaises((ValueError, KeyError)):
                    PROFILES.validate(value)


    def test_relation_parameters_reject_equal_noninteger_values(self):
        original = self.profile()
        for index, relation in enumerate(original['relations']):
            for name, number in relation['parameters'].items():
                replacements = [float(number)]
                if number in (0, 1):
                    replacements.append(bool(number))
                for replacement in replacements:
                    for location in ('parameters', 'security.fri'):
                        with self.subTest(kind=relation['kind'], parameter=name,
                                          location=location,
                                          replacement_type=type(replacement).__name__):
                            value = copy.deepcopy(original)
                            target = value['relations'][index]
                            parameters = (target['parameters'] if location == 'parameters'
                                          else target['security']['fri'])
                            parameters[name] = replacement
                            with self.assertRaises(ValueError):
                                PROFILES.validate(value)


if __name__ == '__main__':
    unittest.main()
