#!/usr/bin/env python3
"""Build the isolated Linux native runtime behind the baseline CPU admission guard."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]

def package(worker, output, receipt, release):
    if worker.name != 'siworld-native-node' or not worker.is_file() or not os.access(worker, os.X_OK):
        raise ValueError('Expected the native runtime executable')
    with worker.open('rb') as source:
        header = source.read(20)
    if header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\x3e\x00':
        raise ValueError('Expected Linux x86_64 ELF')
    release.validate_receipt(worker, receipt, release.digest(ROOT / '.cargo/config.toml'))
    expected = receipt['binary_sha256']
    isa = release.inspect_proof(worker)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.native-package-', dir=output.parent) as temporary:
        staging = Path(temporary) / 'release'
        (staging / 'bin').mkdir(parents=True)
        (staging / 'libexec').mkdir()
        launcher = staging / 'bin/siworld-native-node'
        subprocess.run(['rustc', str(ROOT / 'scripts/native-runtime-launcher.rs'),
                        '--edition=2021', '-O', '-D', 'warnings', '-C', 'target-cpu=x86-64',
                        '-o', str(launcher)], cwd=ROOT, check=True)
        installed = staging / 'libexec/siworld-native-node'
        shutil.copy2(worker, installed)
        if expected != release.digest(worker) or expected != release.digest(installed) or isa['binary_sha256'] != expected:
            raise ValueError('Native worker changed during packaging')
        key_worker = worker.with_name('siworld-checkpoint-key')
        if 'checkpoint_key_sha256' in receipt:
            key_digest = receipt['checkpoint_key_sha256']
            if not key_worker.is_file() or release.digest(key_worker) != key_digest:
                raise ValueError('Checkpoint key worker digest mismatch')
            key_installed = staging / 'libexec/siworld-checkpoint-key'
            shutil.copy2(key_worker, key_installed)
            if release.digest(key_installed) != key_digest:
                raise ValueError('Checkpoint key worker changed during packaging')
            shutil.copy2(launcher, staging / 'bin/siworld-checkpoint-key')
        qualify_worker = worker.with_name('siworld-restart-qualify')
        if 'restart_qualify_sha256' in receipt:
            qualify_digest = receipt['restart_qualify_sha256']
            if not qualify_worker.is_file() or release.digest(qualify_worker) != qualify_digest:
                raise ValueError('Restart qualification worker digest mismatch')
            qualify_installed = staging / 'libexec/siworld-restart-qualify'
            shutil.copy2(qualify_worker, qualify_installed)
            if release.digest(qualify_installed) != qualify_digest:
                raise ValueError('Restart qualification worker changed during packaging')
            shutil.copy2(launcher, staging / 'bin/siworld-restart-qualify')
        (staging / 'build-receipt.json').write_text(json.dumps({
            'worker': 'siworld-native-node', 'worker_isa': 'x86-64-v3',
            'bootstrap_isa': 'x86-64', 'bootstrap_sha256': release.digest(launcher),
            'worker_build_receipt': receipt, 'isa_inspection': isa,
        }, indent=2) + '\n')
        if output.exists():
            raise ValueError('Refusing to overwrite a release directory')
        staging.rename(output)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--engineering-network', action='store_true',
                        help='Include the explicit pinned-peer engineering listener')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('controlled_release', ROOT / 'scripts/build-prover-release.py')
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)
    release.validate_platform()
    release.validate_environment(os.environ)
    release.validate_config(tomllib.loads((ROOT / '.cargo/config.toml').read_text()))
    if args.output.exists():
        raise ValueError('Refusing to overwrite a release directory')
    manifest = ROOT / 'crates/native-node/Cargo.toml'
    features = ['native-p2p', 'wallet-light-gateway'] if args.engineering_network else []
    command = ['cargo', 'build', '--release', '--locked', '--manifest-path', str(manifest),
               '--bin', 'siworld-native-node', '--bin', 'siworld-checkpoint-key',
               '--bin', 'siworld-restart-qualify']
    if features:
        command += ['--features', ','.join(features)]
    subprocess.run(command, cwd=ROOT, check=True)
    target = Path(os.environ.get('CARGO_TARGET_DIR', str(manifest.parent / 'target')))
    if not target.is_absolute():
        target = ROOT / target
    worker = target / 'release/siworld-native-node'
    receipt = {
        'binary_sha256': release.digest(worker),
        'effective_rustflags': ' '.join(release.V3_FLAGS),
        'cargo_working_directory': 'repository-root',
        'repository_config_sha256': release.digest(ROOT / '.cargo/config.toml'),
        'cargo_features': features,
        'checkpoint_key_sha256': release.digest(worker.with_name('siworld-checkpoint-key')),
        'restart_qualify_sha256': release.digest(worker.with_name('siworld-restart-qualify')),
    }
    package(worker, args.output.resolve(), receipt, release)
    print(json.dumps({'worker': 'siworld-native-node', 'packaged': True}))

if __name__ == '__main__':
    main()
