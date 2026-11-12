"""Offline engineering-v2 build configuration checks; no compiler or network."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('wallet_build', Path(__file__).resolve().parents[1] / 'build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class EngineeringBuild(unittest.TestCase):
    def setUp(self):
        self.pin = dict(version=2, name='siworld-eng-2', network='1'*64, genesis='2'*64,
                        rules='3'*64, profile='4'*64, fee_mode=0, api='http://127.0.0.1:8890', read_only=True)

    def test_read_only_pins(self):
        value = build.engineering_v2_manifest(self.pin)
        self.assertIs(value['read_only'], True)
        self.assertIs(value['desktop_send_measured'], False)
        self.assertEqual(value['genesis'], self.pin['genesis'])

    def test_engineering_page_labels_match_the_selected_runtime(self):
        template = (Path(__file__).resolve().parents[1] / 'web/wallet.html').read_text()
        page = build.engineering_v2_html(template)
        self.assertIn('siworld-eng-2', page)
        self.assertIn('SIWORLD-ENG-2', page)
        self.assertIn('authenticated receipts locally', page)
        self.assertIn('Recipient full engineering-v2 address', page)
        self.assertIn('Short-address publication is unavailable', page)
        self.assertNotIn('eng-1', page)
        self.assertNotIn('V1', page)
        self.assertIn('siworld-eng-1', template)
        self.assertEqual(template, (Path(__file__).resolve().parents[1] / 'web/wallet.html').read_text())

    def test_unsafe_profiles_are_rejected(self):
        for changes in ({'read_only': False}, {'fee_mode': 1}, {'version': True}, {'network': '0'*64},
                        {'api': 'https://example.test/path'}, {'api': 'https://user:pass@example.test'},
                        {'api': 'http://example.test'}, {'api': 'https://example.test:bad'},
                        {'api': None}, {'desktop_send_measured': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                build.engineering_v2_manifest({**self.pin, **changes})


if __name__ == '__main__':
    unittest.main()
