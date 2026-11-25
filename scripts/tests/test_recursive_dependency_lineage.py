"""Reject changed dependency patches, source identities and prepared trees."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('d8_builder_lineage',
    Path(__file__).parents[1] / 'bench/build-recursive-proof-benchmark.py')
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class DependencyLineageTests(unittest.TestCase):
    def test_published_patch_and_lineage_are_consistent(self):
        value = BUILD.validate_lineage()
        self.assertEqual(value['base_revision'], BUILD.BASE_PIN)
        self.assertEqual(value['downstream_revision'], BUILD.DOWNSTREAM_REVISION)
        self.assertEqual(value['patch_sha256'], BUILD.sha(BUILD.PATCH))

    def test_modified_patch_cannot_be_compiled_with_existing_lineage(self):
        with tempfile.TemporaryDirectory() as temporary:
            changed = Path(temporary) / 'changed.patch'
            changed.write_bytes(BUILD.PATCH.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'patch SHA-256'):
                BUILD.validate_lineage(patch_path=changed)

    def test_changed_base_review_downstream_or_patch_hash_is_rejected(self):
        original = BUILD.LINEAGE.read_text()
        for old in (BUILD.BASE_PIN, BUILD.PIN, BUILD.REVIEW_REVISION, BUILD.REVIEW_TREE,
                    BUILD.DOWNSTREAM_REVISION, BUILD.DOWNSTREAM_TREE, BUILD.PATCH_SHA256):
            with self.subTest(revision=old), tempfile.TemporaryDirectory() as temporary:
                changed = Path(temporary) / 'changed.toml'
                changed.write_text(original.replace(old, '0' * len(old)))
                with self.assertRaisesRegex(ValueError, 'fixed source revisions'):
                    BUILD.validate_lineage(manifest_path=changed)

    def test_prepared_source_requires_exact_fork_revision_and_tree(self):
        lineage = BUILD.validate_lineage()
        for head, tree, accepted in ((BUILD.PIN, BUILD.DOWNSTREAM_TREE, True),
                                    ('a' * 40, BUILD.DOWNSTREAM_TREE, False),
                                    (BUILD.PIN, 'b' * 40, False)):
            with self.subTest(head=head, tree=tree), \
                    mock.patch.object(BUILD.subprocess, 'check_output', side_effect=[head, tree]):
                if accepted:
                    result = BUILD.validate_prepared_source(Path('/synthetic/upstream'), lineage)
                    self.assertEqual(result['downstream_tree'], tree)
                else:
                    with self.assertRaises(ValueError):
                        BUILD.validate_prepared_source(Path('/synthetic/upstream'), lineage)


if __name__ == '__main__':
    unittest.main()
