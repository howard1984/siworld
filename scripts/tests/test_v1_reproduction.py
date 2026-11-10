"""Require exact native reproduction outside reviewed source relocations."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('reproduction', ROOT / 'scripts/check-v1-reproduction.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class NativeReproductionTests(unittest.TestCase):
    def setUp(self):
        self.expected = json.loads((ROOT / CHECK.FREEZE.DEFAULT).read_text())
        self.reproduced = copy.deepcopy(self.expected)
        self.reproduced['source_sha256'] = {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in CHECK.FREEZE.REQUIRED_SOURCES}

    def test_exact_current_source_reproduction(self):
        CHECK.validate(self.expected, self.reproduced)

    def test_historical_hash_cannot_replace_current_source_identity(self):
        self.assertNotEqual(self.expected['source_sha256'], self.reproduced['source_sha256'])
        with self.assertRaisesRegex(ValueError, 'current source'):
            CHECK.validate(self.expected, self.expected)

    def test_non_source_fields_must_match_exactly(self):
        changes = [
            (('profiles', 'transaction', 'verifier_artifact_hex'), '00'),
            (('profiles', 'settlement', 'security', 'screen', 'classical_conjectured_union_bits'), 1000),
            (('suite',), 'changed'),
            (('limitations',), []),
            (('unexpected',), True),
        ]
        for path, value in changes:
            changed = copy.deepcopy(self.reproduced)
            parent = changed
            for name in path[:-1]:
                parent = parent[name]
            parent[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                CHECK.validate(self.expected, changed)
        changed = copy.deepcopy(self.reproduced)
        del changed['limitations']
        with self.assertRaises(ValueError):
            CHECK.validate(self.expected, changed)

    def test_changed_runtime_source_hash_rejected(self):
        self.reproduced['source_sha256']['crates/bench-d8/src/lib.rs'] = '0' * 64
        with self.assertRaises(ValueError):
            CHECK.validate(self.expected, self.reproduced)


if __name__ == '__main__':
    unittest.main()
