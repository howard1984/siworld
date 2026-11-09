"""Control hardware cannot replace baseline proof-freeze evidence."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('control_freeze_fixtures',
    ROOT / 'scripts/tests/test_economics_freeze.py')
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)
F = FIXTURE.F


def control_summary():
    source = FIXTURE.completed_summary()
    source.update(status='control-diagnostic-only', hardware_profile='epyc9v45-control',
        baseline_eligible=False)
    source['hardware']['required_hardware_profile'] = 'epyc9v45-control'
    source['hardware']['hardware']['cpu_model'] = 'AMD EPYC 9V45'
    for entry in source['profile_results']:
        for row in entry['trials']:
            row['hardware_profile'] = 'epyc9v45-control'
    for relation in source['repeated_measurements'].values():
        for group in relation['workers'].values():
            for row in group['trials']:
                row['hardware_profile'] = 'epyc9v45-control'
    return source


class EconomicsControlTests(unittest.TestCase):
    def test_control_summary_and_partial_relabeling_cannot_freeze(self):
        original = control_summary()
        for relabel in ('none', 'status', 'summary-profile', 'requested-profile', 'model'):
            source = copy.deepcopy(original)
            if relabel != 'none':
                source['status'] = 'candidate-pending-review'
            if relabel in ('summary-profile', 'requested-profile', 'model'):
                source['hardware_profile'] = 'epyc7763-baseline'
            if relabel in ('requested-profile', 'model'):
                source['hardware']['required_hardware_profile'] = 'epyc7763-baseline'
            if relabel == 'model':
                source['hardware']['hardware']['cpu_model'] = 'AMD EPYC 7763'
            with self.subTest(relabel=relabel), self.assertRaises(ValueError):
                F.economic_summary(source)
        with self.assertRaises(ValueError):
            F.economic_trial(original['profile_results'][0]['trials'][0], 'transaction', 4,
                original['profile_results'][0]['parameters'])

    def test_control_qualification_checks_its_actual_cpu_and_keeps_control_role(self):
        hardware = control_summary()['hardware']['hardware']
        result = F.HARDWARE.qualify_hardware_profile(hardware, 'epyc9v45-control')
        self.assertEqual(result['role'], 'control')
        self.assertTrue(result['profile_qualified'])
        self.assertFalse(result['same_physical_instance_established'])
        with self.assertRaises(ValueError):
            F.HARDWARE.qualify_hardware_profile(hardware, 'epyc7763-baseline')
        hardware['cpu_model'] = 'AMD EPYC 7763'
        with self.assertRaises(ValueError):
            F.HARDWARE.qualify_hardware_profile(hardware, 'epyc9v45-control')

    def workflow(self):
        return (ROOT / 'scripts/tests/fixtures/retired-workflows/v1-economics.yml').read_text()

    def test_workflow_requires_baseline_on_pr_and_gates_selected_key_exports(self):
        workflow = self.workflow()
        self.assertIn("HARDWARE_PROFILE: ${{ github.event_name == 'workflow_dispatch' "
            "&& inputs.hardware_profile || 'epyc7763-baseline' }}", workflow)
        self.assertIn('default: epyc7763-baseline\n        options:\n'
            '          - epyc7763-baseline\n          - epyc9v45-control', workflow)
        selected = workflow.split('      - name: Reproduce the actually selected transaction key as pending evidence\n')[1]
        selected = selected.split('      - name:', 1)[0]
        self.assertIn("if: ${{ env.HARDWARE_PROFILE == 'epyc7763-baseline' && ", selected)
        self.assertIn('freeze.economic_summary(summary, require_admission_margin=False)', selected)
        self.assertLess(workflow.index('--qualify-only'), workflow.index('name: Build and test revised AIRs'))
        upload = workflow.split('      - uses: actions/upload-artifact@')[-1]
        self.assertIn('if: ${{ always() }}', upload)
        self.assertIn('path: .local/economics-candidate/public/**/*.json', upload)

    def test_workflow_failure_evidence_never_marks_control_or_failed_baseline_as_eligible(self):
        match = re.search(r"python3 - <<'PY_STATUS'\n(.*?)\n\s+PY_STATUS", self.workflow(), re.S)
        self.assertIsNotNone(match)
        script = textwrap.dedent(match.group(1))
        for profile, qualified, expected in (('epyc9v45-control', True, False),
                ('epyc7763-baseline', False, False), ('epyc7763-baseline', True, True)):
            with self.subTest(profile=profile, qualified=qualified), tempfile.TemporaryDirectory() as directory:
                public = Path(directory) / '.local/economics-candidate/public'
                preflight = public / 'preflight/hardware-qualification.json'
                preflight.parent.mkdir(parents=True)
                preflight.write_text(json.dumps({'profile_qualified': qualified}))
                subprocess.run([sys.executable, '-c', script], cwd=directory, check=True,
                    env={**os.environ, 'HARDWARE_PROFILE': profile, 'RESULT': 'failure', 'GITHUB_SHA': 'a' * 40})
                status = json.loads((public / 'workflow-status.json').read_text())
                self.assertEqual(status['baseline_eligible'], expected)
                self.assertEqual(status['job_status_before_upload'], 'failure')
                self.assertEqual(status['required_hardware_profile'], profile)
                self.assertFalse(status['acceptance'])
                self.assertFalse(status['network_activation'])
                self.assertFalse(status['cryptographic_approval'])
                if profile == 'epyc9v45-control':
                    self.assertEqual(status['status'], 'control-diagnostic-only')


if __name__ == '__main__':
    unittest.main()
