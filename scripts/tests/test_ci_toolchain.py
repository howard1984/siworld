"""Install the WASM target for the repository toolchain, not a runner override."""
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ToolchainSetupTests(unittest.TestCase):
    def test_wasm_setup_passes_explicit_repository_channel(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        block = workflow.split('      - name: Install pinned toolchain and WASM target\n', 1)[1]
        lines = block.split('      - name:', 1)[0].splitlines()[1:]
        command = '\n'.join(line[10:] for line in lines)
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            rustup = temporary / 'rustup'
            rustup.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$RUSTUP_TEST_ARGS"\n')
            rustup.chmod(0o700)
            output = temporary / 'args'
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'],
                       RUSTUP_TOOLCHAIN='unrelated-runner-override', RUSTUP_TEST_ARGS=str(output),
                       GITHUB_PATH=str(temporary / 'github-path'))
            subprocess.run(['bash', '-euo', 'pipefail', '-c', command], cwd=ROOT, env=env, check=True)
            channel = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
            self.assertEqual(output.read_text().splitlines(),
                             ['toolchain', 'install', channel, '--target', 'wasm32-unknown-unknown',
                              'run', channel, 'cargo', 'install', '--locked', '--version', '0.2.120',
                              'wasm-bindgen-cli', '--bin', 'wasm-bindgen', '--root',
                              os.environ['HOME'] + '/.local/siworld-wasm-bindgen'])
            self.assertEqual((temporary / 'github-path').read_text().strip(),
                             os.environ['HOME'] + '/.local/siworld-wasm-bindgen/bin')


if __name__ == '__main__':
    unittest.main()
