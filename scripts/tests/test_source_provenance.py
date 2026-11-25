"""Reject source changes beyond the exact dependency relocation identities."""
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('relocations', ROOT / 'scripts/bench/source-provenance.py')
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


class SourceRelocationTests(unittest.TestCase):
    def test_exact_approved_pairs_and_mutated_bytes(self):
        for name, pairs in R.SOURCE_PAIRS.items():
            body = R.source_bytes(ROOT, name)
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
            self.assertFalse(R.matches(ROOT, name, R.source_bytes(ROOT, name), expected))

    def test_runtime_code_has_no_hash_exception(self):
        self.assertFalse(R.matches(ROOT, 'crates/native-proof/src/lib.rs', b'changed', '0' * 64))
        tooling = {
            'scripts/native-proof-artifacts.rs',
            'scripts/prover-launcher.rs',
            'crates/bench-d8/src/bin/checkpoint.rs',
            'crates/bench-d8/src/bin/fee-settlement-bench.rs',
            'crates/bench-d8/src/bin/native-verifier-bench.rs',
            'crates/bench-d8/src/bin/v1-freeze-artifacts.rs',
            'crates/bench-d8/src/bin/v1_transaction_scan.rs',
        }
        self.assertLessEqual({name for name in R.SOURCE_PAIRS if name.endswith('.rs')}, tooling)

    def test_only_three_historical_workflow_aliases_are_accepted(self):
        for recorded, fixture in R.WORKFLOW_FIXTURES.items():
            self.assertEqual(R.canonical_path(fixture), recorded)
            self.assertEqual(R.current_path(recorded), fixture)
        name = 'scripts/tests/fixtures/retired-workflows/unrecognized.yml'
        self.assertEqual(R.canonical_path(name), name)

    def test_historical_alias_collision_is_rejected_in_both_orders(self):
        original = '.github/workflows/multi-asset-native.yml'
        retired = 'scripts/tests/fixtures/source-provenance/multi-asset-workflow.txt'
        self.assertEqual(R.canonical_sources([retired]), {original: retired})
        for paths in ([original, retired], [retired, original]):
            with self.assertRaisesRegex(ValueError, 'Ambiguous historical source path'):
                R.canonical_sources(paths)

    def test_source_boundary_cannot_drop_or_add_files(self):
        body = b'unchanged';digest = hashlib.sha256(body).hexdigest()
        self.assertTrue(R.mapping_matches(ROOT, {'source': digest}, ['source'], lambda *_: body))
        self.assertFalse(R.mapping_matches(ROOT, {}, ['source'], lambda *_: body))
        self.assertFalse(R.mapping_matches(ROOT, {'source': digest}, ['source', 'extra'], lambda *_: body))
