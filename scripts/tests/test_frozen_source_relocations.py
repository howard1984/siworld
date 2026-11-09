"""Reject source changes beyond the exact dependency relocation identities."""
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('relocations', ROOT / 'scripts/frozen-source-relocations.py')
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


class SourceRelocationTests(unittest.TestCase):
    def test_exact_approved_pairs_and_mutated_bytes(self):
        for name, pairs in R.SOURCE_PAIRS.items():
            body = (ROOT / name).read_bytes()
            for old, current in pairs.items():
                with self.subTest(name=name):
                    self.assertEqual(hashlib.sha256(body).hexdigest(), current)
                    self.assertTrue(R.matches(ROOT, name, body, old))
                    self.assertFalse(R.matches(ROOT, name, body + b'\n', old))
                    self.assertFalse(R.matches(ROOT, name, body, '0' * 64))

    def test_changed_dependency_tree_rejects_all_relocation_exceptions(self):
        name = 'crates/bench-d8/Cargo.lock'
        expected = next(iter(R.SOURCE_PAIRS[name]))
        with mock.patch.object(R, 'fixed_dependency', return_value=False):
            self.assertFalse(R.matches(ROOT, name, (ROOT / name).read_bytes(), expected))

    def test_runtime_code_has_no_hash_exception(self):
        self.assertFalse(R.matches(ROOT, 'crates/bench-d8/src/lib.rs', b'changed', '0' * 64))
        self.assertFalse(any(name.endswith('.rs') for name in R.SOURCE_PAIRS))

    def test_only_three_historical_workflow_aliases_are_accepted(self):
        for name in R.RETIRED:
            self.assertEqual(R.canonical_path('scripts/tests/fixtures/retired-workflows/' + name), '.github/workflows/' + name)
        name = 'scripts/tests/fixtures/retired-workflows/unrecognized.yml'
        self.assertEqual(R.canonical_path(name), name)

    def test_historical_alias_collision_is_rejected_in_both_orders(self):
        original = '.github/workflows/multi-asset-native.yml'
        retired = 'scripts/tests/fixtures/retired-workflows/multi-asset-native.yml'
        self.assertEqual(R.canonical_sources([retired]), {original: retired})
        for paths in ([original, retired], [retired, original]):
            with self.assertRaisesRegex(ValueError, 'Ambiguous historical source path'):
                R.canonical_sources(paths)

    def test_source_boundary_cannot_drop_or_add_files(self):
        body = b'unchanged';digest = hashlib.sha256(body).hexdigest()
        self.assertTrue(R.mapping_matches(ROOT, {'source': digest}, ['source'], lambda *_: body))
        self.assertFalse(R.mapping_matches(ROOT, {}, ['source'], lambda *_: body))
        self.assertFalse(R.mapping_matches(ROOT, {'source': digest}, ['source', 'extra'], lambda *_: body))
