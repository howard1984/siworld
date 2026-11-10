#!/usr/bin/env python3
"""Check that the active Actions surface contains offline validation only."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def main():
    directory = ROOT / '.github/workflows'
    # Runtime historical hash inputs are excluded from Git and never scheduled.
    import subprocess
    active = subprocess.check_output(['git', '-c', 'protocol.allow=never', 'ls-files',
                                      '.github/workflows'], cwd=ROOT, text=True).splitlines()
    if active != ['.github/workflows/ci.yml']:
        raise SystemExit('Only the offline validation workflow may be tracked')
    text = (directory / 'ci.yml').read_text()
    if 'cancel-in-progress: true' not in text or 'needs: changes' not in text or re.search(r'^  push:', text, re.M):
        raise SystemExit('Path selection, concurrency cancellation and PR-only validation required')
    if any(token in text for token in ('workflow_dispatch:', 'schedule:', 'self-hosted',
            'windows-latest', 'secrets.', 'contents: write', 'actions/upload-artifact',
            'build-windows-miner', 'build-native-runtime', '--check-hardware',
            'eng2-runtime', 'eng2-rehearsal',
            'run-network', 'run-native', 'ssh ', 'gh release')):
        raise SystemExit('Hosted CI contains a local-only operation')
    safe_setup = {'Install pinned toolchain', 'Install pinned toolchain and WASM target',
                  'Acquire locked dependencies', 'Install checksum-pinned secret scanner'}
    for block in re.split(r'^      - ', text, flags=re.M)[1:]:
        if not re.search(r'^        run:', block, flags=re.M):
            continue
        name = block.splitlines()[0].removeprefix('name: ')
        if name not in safe_setup and 'shell: bash --noprofile --norc -c "exec bash \\"$GITHUB_WORKSPACE/scripts/ci-offline.sh\\" \\"$1\\"" -- {0}' not in block:
            raise SystemExit('Validation command lacks mandatory network isolation')
    print('Active workflow contains isolated offline validation only.')


if __name__ == '__main__':
    main()
