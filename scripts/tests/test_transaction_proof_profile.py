"""Reject changed native profile sources, verifier keys and policy before CI use."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('freeze', ROOT / 'scripts/ci/check-transaction-proof-profile.py')
freeze = importlib.util.module_from_spec(spec)
spec.loader.exec_module(freeze)


class FreezeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.value = json.loads((ROOT / freeze.DEFAULT).read_text())

    def test_complete_frozen_profile(self):
        freeze.validate(self.value)

    def test_source_drift_or_removed_source_is_rejected(self):
        for name in freeze.REQUIRED_SOURCES:
            changed = copy.deepcopy(self.value)
            changed['source_sha256'][name] = '0' * 64
            with self.assertRaises(ValueError):
                freeze.validate(changed)
        changed = copy.deepcopy(self.value)
        changed['source_sha256'].pop(next(iter(freeze.REQUIRED_SOURCES)))
        with self.assertRaises(ValueError):
            freeze.validate(changed)

    def test_profile_key_resource_and_claim_tampering_is_rejected(self):
        changes = [
            (('parameters', 'num_queries'), 35),
            (('profiles', 'transaction', 'verifier_artifact_sha256'), '0' * 64),
            (('profiles', 'settlement', 'security', 'screen', 'quantum_johnson_challenge_union_bits'), 79.9),
            (('envelope', 'sidecar_bytes'), 62),
            (('resources', 'max_leaf_proof_bytes'), 524289),
            (('resources', 'verifier_cpu_ms'), 500),
            (('cryptographic_approval',), True),
            (('network_activation',), True),
        ]
        for path, replacement in changes:
            changed = copy.deepcopy(self.value)
            parent = changed
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = replacement
            with self.assertRaises(ValueError, msg=str(path)):
                freeze.validate(changed)


if __name__ == '__main__':
    unittest.main()
