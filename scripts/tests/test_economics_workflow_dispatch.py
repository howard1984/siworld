"""Keep economic parameter grids opt-in without changing frozen evidence."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class EconomicsWorkflowDispatchTests(unittest.TestCase):
    def workflow(self):
        return (ROOT / '.github/workflows/v1-economic-regressions.yml').read_text()

    def step(self, title):
        return self.workflow().split('      - name: ' + title + '\n')[1].split('      - name:', 1)[0]

    def test_parameter_grid_requires_explicit_dispatch_and_defaults_off(self):
        workflow = self.workflow()
        self.assertTrue(workflow.startswith('name: V1 economic regressions\n'))
        self.assertIn('measure_wallet_grid:\n'
            '        description: Run the three-trial EPYC 7763 economic proof grid\n'
            '        type: boolean\n        default: false', workflow)
        for title in ('Qualify the requested CPU profile before building proof tools',
                'Measure all requested coordinates three times on the target CPU'):
            step = self.step(title)
            self.assertIn("if: ${{ github.event_name == 'workflow_dispatch' "
                "&& inputs.measure_wallet_grid }}", step)
            self.assertNotIn("github.event_name == 'pull_request'", step)

    def test_selected_key_exports_require_opt_in_and_baseline_hardware(self):
        workflow = self.workflow()
        self.assertIn("HARDWARE_PROFILE: ${{ github.event_name == 'workflow_dispatch' "
            "&& inputs.hardware_profile || 'epyc7763-baseline' }}", workflow)
        selected = self.step('Reproduce the actually selected transaction key as pending evidence')
        self.assertIn("if: ${{ github.event_name == 'workflow_dispatch' "
            "&& inputs.measure_wallet_grid && env.HARDWARE_PROFILE == 'epyc7763-baseline' }}", selected)
        self.assertNotIn("github.event_name == 'pull_request'", selected)
        self.assertIn('freeze.economic_summary(summary, require_admission_margin=False)', selected)
        upload = workflow.split('      - uses: actions/upload-artifact@')[-1]
        self.assertIn('if: ${{ always() }}', upload)
        self.assertIn('path: .local/economics-candidate/public/**/*.json', upload)

    def test_regular_pr_screening_and_tests_remain_unconditional(self):
        workflow = self.workflow()
        self.assertIn("on:\n  pull_request:\n    paths:", workflow)
        self.assertIn("      - '.github/workflows/v1-economic-regressions.yml'\n", workflow)
        self.assertIn('group: v1-economic-regressions-${{ github.ref }}', workflow)
        for title in ('Test economic-candidate measurement rejection and resource reporting',
                'Build and test revised AIRs without replacing prior freeze evidence',
                'Screen actual transaction, five-reward settlement and issuance AIRs'):
            self.assertNotIn('        if:', self.step(title))
        self.assertIn("run: python3 -m unittest discover -s scripts/tests -p 'test_economics*.py'", workflow)
        self.assertIn('v1-transaction-scan screen .local/economics-candidate/public/screen.json', workflow)


if __name__ == '__main__':
    unittest.main()
