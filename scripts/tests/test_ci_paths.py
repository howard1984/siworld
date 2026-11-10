"""Select related jobs without treating unavailable change evidence as a skip."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('paths', ROOT / 'scripts/ci-paths.py')
PATHS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PATHS)


class PathSelectionTests(unittest.TestCase):
    def test_documentation_does_not_run_rust_workloads(self):
        self.assertFalse(any(PATHS.select(['docs/architecture.md', 'README.md']).values()))

    def test_workflow_and_shared_build_changes_run_all_jobs(self):
        for path in ('Cargo.lock', '.github/workflows/ci.yml', '.cargo/config.toml'):
            with self.subTest(path=path):
                self.assertTrue(all(PATHS.select([path]).values()))

    def test_related_crate_selects_only_required_job_families(self):
        jobs = PATHS.select(['crates/native-wallet-web/src/lib.rs'])
        self.assertTrue(jobs['wallet'])
        self.assertFalse(jobs['offline-fund-keys'])

    def test_invalid_or_unavailable_diff_runs_all_jobs(self):
        for error in (ValueError('invalid metadata'), subprocess.CalledProcessError(1, ['git'])):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'outputs'
                with patch.object(PATHS, 'changed', side_effect=error), \
                     patch.dict(os.environ, {'GITHUB_OUTPUT': str(output)}), \
                     patch('sys.argv', ['paths.py', 'a' * 40, 'b' * 40]):
                    PATHS.main()
                self.assertEqual(len(output.read_text().splitlines()), len(PATHS.RULES))
                self.assertTrue(all(line.endswith('=true') for line in output.read_text().splitlines()))

    def test_full_commit_ids_required(self):
        with self.assertRaises(ValueError):
            PATHS.changed('--invalid', 'b' * 40)


if __name__ == '__main__':
    unittest.main()
