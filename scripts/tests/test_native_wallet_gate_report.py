"""Exercise the native wallet gate's strict private-to-public boundary."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('native_wallet_gate', ROOT / 'scripts/native-wallet-gate-report.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class NativeWalletGateTests(unittest.TestCase):
    COMMIT = 'a' * 40
    THREAD = ('wallet_vault::native_roundtrip::'
              'genuine_genesis_rewards_persist_pay_and_restore_with_native_proofs')
    FIELDS = {'schema', 'source_commit', 'stage', 'accepted_height', 'required_height',
              'slots_per_block', 'elapsed_ms', 'genuine_native_wallet_gate_passed'}

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.private = Path(self.temporary.name) / 'private'
        self.private.mkdir()
        (self.private / 'runs').mkdir()
        GATE.prepare(self.private, self.COMMIT)
        self.run = self.private / 'runs' / ('native-wallet-roundtrip-' + 'b' * 32)
        self.run.mkdir()

    def record(self, **changes):
        value = dict(schema=1, stage='complete', accepted_height=26,
                     required_height=26, slots_per_block=64, elapsed_ms=1000)
        value.update(changes)
        (self.run / 'roundtrip-progress.json').write_text(json.dumps(value))
        return value

    def log(self, location=None, message='private-token-mnemonic-individual-fee'):
        path = location or GATE.SOURCE + ':311:9'
        (self.private / 'roundtrip.log').write_text(
            f"thread '{self.THREAD}' panicked at {path}:\n{message}\n")

    def report(self, outcome='failure'):
        return GATE.build_report(self.private, self.COMMIT, outcome)

    def assert_invalid(self, value):
        self.assertFalse(value['genuine_native_wallet_gate_passed'])
        self.assertEqual(value['stage'], 'invalid-progress')
        self.assertEqual(value['failure_category'], 'invalid-evidence')
        self.assertEqual(value['accepted_height'], 0)
        self.assertEqual(value['elapsed_ms'], 0)
        self.assertNotIn('failure_location', value)

    def test_complete_success_has_only_allowlisted_fields(self):
        self.record()
        self.log()
        value = self.report('success')
        self.assertEqual(set(value), self.FIELDS)
        self.assertTrue(value['genuine_native_wallet_gate_passed'])
        self.assertEqual(value['accepted_height'], 26)
        self.assertEqual(value['required_height'], 26)
        self.assertEqual(value['slots_per_block'], 64)
        self.assertNotIn('private-token', json.dumps(value))

    def test_failed_process_is_not_passed_even_if_progress_says_complete(self):
        self.record()
        value = self.report()
        self.assertFalse(value['genuine_native_wallet_gate_passed'])
        self.assertEqual(value['failure_category'], 'test-process-failed')

    def test_failure_exports_only_exact_static_location_and_never_panic_text(self):
        self.record(stage='native-funding', accepted_height=12)
        self.log()
        value = self.report()
        self.assertEqual(set(value), self.FIELDS | {'failure_category', 'failure_location'})
        self.assertEqual(value['stage'], 'native-funding')
        self.assertEqual(value['accepted_height'], 12)
        self.assertEqual(value['failure_category'], 'native-test-panic')
        self.assertEqual(value['failure_location'], GATE.SOURCE + ':311:9')
        self.assertNotIn('private-token', json.dumps(value))
        self.assertNotIn(self.temporary.name, json.dumps(value))

    def test_new_run_without_progress_still_emits_safe_failure_location(self):
        self.log()
        value = self.report()
        self.assertEqual(value['stage'], 'no-progress')
        self.assertEqual(value['accepted_height'], 0)
        self.assertEqual(value['elapsed_ms'], 0)
        self.assertEqual(value['failure_category'], 'native-test-panic')
        self.assertEqual(value['failure_location'], GATE.SOURCE + ':311:9')

    def test_crate_relative_panic_location_is_canonicalized(self):
        self.record(stage='native-funding', accepted_height=24)
        self.log(GATE.CRATE_SOURCE + ':194:18')
        value = self.report()
        self.assertEqual(value['failure_category'], 'native-test-panic')
        self.assertEqual(value['failure_location'], GATE.SOURCE + ':194:18')

    def test_no_progress_and_no_log_has_fixed_failure_category(self):
        value = self.report()
        self.assertEqual(value['stage'], 'no-progress')
        self.assertEqual(value['failure_category'], 'no-progress')
        self.assertEqual(set(value), self.FIELDS | {'failure_category'})

    def test_missing_run_is_distinct_from_missing_progress(self):
        self.run.rmdir()
        value = self.report()
        self.assertEqual(value['stage'], 'no-progress')
        self.assertEqual(value['failure_category'], 'missing-run')

    def test_skipped_test_without_prepare_is_not_started(self):
        (self.private / 'gate-start.json').unlink()
        value = self.report('skipped')
        self.assertEqual(value['stage'], 'not-started')
        self.assertEqual(value['failure_category'], 'test-not-started')
        self.assertFalse(value['genuine_native_wallet_gate_passed'])

    def test_extra_progress_fields_and_hostile_embedded_secrets_are_rejected(self):
        for field in ('private_key', 'wallet_path', 'nullifiers', 'fee_opening'):
            with self.subTest(field=field):
                self.record(**{field: 'PRIVATE-SECRET-MUST-NOT-ESCAPE'})
                value = self.report('success')
                self.assert_invalid(value)
                self.assertNotIn('PRIVATE-SECRET', json.dumps(value))

    def test_progress_types_ranges_and_stage_height_invariants_are_strict(self):
        mutations = [dict(schema=True), dict(stage='complete-private-key'), dict(stage=3),
                     dict(accepted_height=True), dict(accepted_height=26.0),
                     dict(accepted_height=-1), dict(accepted_height=27),
                     dict(stage='native-funding', accepted_height=26),
                     dict(stage='native-payment-accepted', accepted_height=25),
                     dict(stage='complete', accepted_height=25),
                     dict(required_height=True), dict(required_height=25),
                     dict(slots_per_block=64.0), dict(slots_per_block=576),
                     dict(elapsed_ms=True), dict(elapsed_ms=0), dict(elapsed_ms=-1),
                     dict(elapsed_ms=GATE.MAX_ELAPSED_MS), dict(elapsed_ms='private-secret')]
        for changes in mutations:
            with self.subTest(changes=changes):
                self.record(**changes)
                self.assert_invalid(self.report('success'))

    def test_duplicate_json_keys_malformed_non_object_and_oversized_input_are_rejected(self):
        valid = json.dumps(self.record())
        values = ('{"stage":"private-secret","stage":"complete"}', 'private-secret',
                  '[]', valid.replace('1000', 'NaN'), '[' * 2000,
                  ' ' * (GATE.MAX_JSON_BYTES + 1))
        for raw in values:
            with self.subTest(size=len(raw)):
                (self.run / 'roundtrip-progress.json').write_text(raw)
                self.assert_invalid(self.report('success'))

    def test_multiple_runs_and_malformed_run_name_are_rejected(self):
        self.record()
        other = self.private / 'runs' / ('native-wallet-roundtrip-' + 'c' * 32)
        other.mkdir()
        self.assert_invalid(self.report('success'))
        other.rmdir()
        self.run.rename(self.run.parent / 'native-wallet-roundtrip-private-secret')
        self.assert_invalid(self.report('success'))

    def test_stale_progress_before_prepare_marker_is_rejected(self):
        self.record()
        marker = json.loads((self.private / 'gate-start.json').read_text())
        old = marker['started_ns'] - 1
        os.utime(self.run / 'roundtrip-progress.json', ns=(old, old))
        self.assert_invalid(self.report('success'))

    def test_marker_source_root_identity_schema_and_numeric_types_are_bound(self):
        path = self.private / 'gate-start.json'
        original = json.loads(path.read_text())
        changes = [dict(source_commit='c' * 40), dict(schema=True), dict(started_ns=True),
                   dict(started_ns=2**100), dict(run_root_inode=original['run_root_inode'] + 1),
                   dict(run_root_device=False), dict(extra='private-secret')]
        self.record()
        for update in changes:
            with self.subTest(update=update):
                value = dict(original)
                value.update(update)
                path.write_text(json.dumps(value))
                self.assert_invalid(self.report('success'))

    def test_symlink_and_hardlink_progress_are_rejected(self):
        self.record()
        path = self.run / 'roundtrip-progress.json'
        original = path.read_text()
        outside = self.private / 'untrusted-private-secret.json'
        outside.write_text(original)
        path.unlink()
        path.symlink_to(outside)
        self.assert_invalid(self.report('success'))
        path.unlink()
        os.link(outside, path)
        self.assert_invalid(self.report('success'))

    def test_symlink_run_directory_is_rejected(self):
        self.run.rmdir()
        elsewhere = self.private / 'untrusted'
        elsewhere.mkdir()
        self.run.symlink_to(elsewhere, target_is_directory=True)
        self.assert_invalid(self.report('success'))

    def test_unapproved_paths_or_multiple_locations_are_never_exported(self):
        self.record(stage='native-funding', accepted_height=1)
        locations = ('/private/secret/' + GATE.SOURCE + ':1:2',
                     '../' + GATE.SOURCE + ':1:2', GATE.SOURCE + '/../../secret:1:2',
                     'crates/native-node/src/secret.rs:1:2', GATE.SOURCE + ':0:1',
                     GATE.SOURCE + ':1:10000', GATE.SOURCE + ':1:2:private-secret')
        for location in locations:
            with self.subTest(location=location):
                self.log(location)
                value = self.report()
                self.assertEqual(value['failure_category'], 'test-process-failed')
                self.assertNotIn('failure_location', value)
                self.assertNotIn('secret', json.dumps(value))
        self.log()
        path = self.private / 'roundtrip.log'
        path.write_text(path.read_text() * 2)
        self.assertNotIn('failure_location', self.report())

    def test_large_symlink_and_invalid_utf8_logs_never_escape(self):
        self.record(stage='native-funding', accepted_height=1)
        path = self.private / 'roundtrip.log'
        for raw in (b'x' * (GATE.MAX_LOG_BYTES + 1), b'\xffprivate-secret'):
            path.write_bytes(raw)
            self.assertNotIn('failure_location', self.report())
        path.unlink()
        path.symlink_to(self.run / 'roundtrip-progress.json')
        self.assertNotIn('failure_location', self.report())

    def test_incomplete_success_and_cancellation_cannot_pass(self):
        self.record(stage='native-payment-accepted', accepted_height=26)
        value = self.report('success')
        self.assertEqual(value['failure_category'], 'incomplete-progress')
        self.assertFalse(value['genuine_native_wallet_gate_passed'])
        self.assertEqual(self.report('cancelled')['failure_category'], 'test-process-cancelled')

    def test_prepare_rejects_existing_run_marker_and_log(self):
        with self.assertRaises((ValueError, FileExistsError)):
            GATE.prepare(self.private, self.COMMIT)
        self.run.rmdir()
        (self.private / 'gate-start.json').unlink()
        self.log()
        with self.assertRaises(ValueError):
            GATE.prepare(self.private, self.COMMIT)

    def test_source_validation_requires_exact_checkout_commit(self):
        with mock.patch.object(GATE.subprocess, 'check_output', return_value=self.COMMIT + '\n'):
            self.assertEqual(GATE.source_commit(self.COMMIT), self.COMMIT)
            for value in ('PRIVATE-SECRET', self.COMMIT.upper(), 'b' * 40, True, 'a' * 64):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    GATE.source_commit(value)

    def test_cli_failure_writes_only_sanitized_json_and_never_prints_private_error(self):
        self.record(stage='native-funding', accepted_height=4)
        self.log()
        output = Path(self.temporary.name) / 'public/gate.json'
        args = ['report', '--private-root', str(self.private), '--source-commit', self.COMMIT,
                '--outcome', 'failure', '--output', str(output)]
        error = io.StringIO()
        with mock.patch.object(GATE, 'source_commit', return_value=self.COMMIT), contextlib.redirect_stderr(error):
            self.assertEqual(GATE.main(args), 1)
        self.assertEqual(error.getvalue(), '')
        value = json.loads(output.read_text())
        self.assertEqual(value['failure_location'], GATE.SOURCE + ':311:9')
        self.assertNotIn('private-token', output.read_text())
        with mock.patch.object(GATE, 'source_commit', side_effect=ValueError('PRIVATE-SECRET')), contextlib.redirect_stderr(error):
            self.assertEqual(GATE.main(args), 1)
        self.assertEqual(error.getvalue(), 'Native wallet gate evidence validation failed\n')

    def test_cli_success_and_output_reuse_is_rejected(self):
        self.record()
        output = Path(self.temporary.name) / 'public/gate.json'
        args = ['report', '--private-root', str(self.private), '--source-commit', self.COMMIT,
                '--outcome', 'success', '--output', str(output)]
        with mock.patch.object(GATE, 'source_commit', return_value=self.COMMIT):
            self.assertEqual(GATE.main(args), 0)
            self.assertTrue(json.loads(output.read_text())['genuine_native_wallet_gate_passed'])
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(GATE.main(args), 1)

    def test_workflow_reports_always_and_uploads_only_explicit_public_files(self):
        text = (ROOT / '.github/workflows/native-wallet-roundtrip.yml').read_text()
        run = text.index('id: roundtrip')
        prepare = text.index('scripts/native-wallet-gate-report.py prepare', run)
        timeout = text.index('timeout --signal=TERM', prepare)
        report = text.index('name: Preserve only an allowlisted outcome', timeout)
        upload = text.index('name: Upload sanitized gate outcome', report)
        self.assertIn('if: ${{ always() }}', text[report:upload])
        self.assertIn('scripts/native-wallet-gate-report.py report', text[report:upload])
        self.assertIn("steps.roundtrip.outcome || 'skipped'", text[report:upload])
        self.assertIn('if: ${{ always() }}', text[upload:])
        self.assertIn('.local/native-wallet/public/gate.json', text[upload:])
        self.assertIn('.local/native-wallet/public/hardware.json', text[upload:])
        self.assertNotIn('*.json', text[upload:])
        self.assertNotIn('private/', text[upload:])
        self.assertLess(prepare, timeout)


if __name__ == '__main__':
    unittest.main()
