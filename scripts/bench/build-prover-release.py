#!/usr/bin/env python3
"""Package Linux x86-64-v3 workers behind an independently compiled CPU guard."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
V3_FLAGS = ['-C', 'target-cpu=x86-64-v3']
NAMES = {'siworld-node', 'siworld-cli', 'siworld-devnet', 'siworld-proof-pipeline',
         'siworld-aggregation-bench', 'siworld-bench-plonky3', 'composition-bench', 'leaf_params', 'recursive-proof-benchmark', 'v1-transaction-scan', 'fee-settlement-bench', 'native-verifier-bench'}
PROOF_WORKERS = NAMES - {'siworld-cli'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_environment(environment):
    blocked = sorted(name for name, value in environment.items() if value and (
        name in {'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
                 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC', 'RUSTC_BOOTSTRAP',
                 'CARGO_BUILD_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_BUILD_RUSTC',
                 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER'}
        or (name.startswith('CARGO_TARGET_') and name.endswith('_RUSTFLAGS'))
        or name.startswith('CARGO_PROFILE_RELEASE_')))
    if blocked:
        raise ValueError('Controlled release rejects compiler/profile overrides: ' + ', '.join(blocked))


def validate_config(config):
    flags = config['target']['cfg(target_arch = "x86_64")']['rustflags']
    if flags != V3_FLAGS:
        raise ValueError('The x86_64 repository baseline must be exactly x86-64-v3')


def validate_platform():
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('This release packager supports Linux x86_64 only; other adapters are not qualified')


def validate_worker(worker):
    if worker.name not in NAMES or not worker.is_file() or not os.access(worker, os.X_OK):
        raise ValueError('Expected a supported executable worker')
    # Reject cross-target or unrelated executables before generating any package.
    with worker.open('rb') as source:
        header = source.read(20)
    if header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\x3e\x00':
        raise ValueError('Expected a Linux little-endian x86_64 ELF worker')


def validate_receipt(worker, receipt, config_sha):
    required = {'binary_sha256': digest(worker),
                'effective_rustflags': ' '.join(V3_FLAGS),
                'cargo_working_directory': 'repository-root',
                'repository_config_sha256': config_sha}
    for key, expected in required.items():
        if receipt.get(key) != expected:
            raise ValueError('Controlled worker build receipt mismatch: ' + key)


def inspect_proof(worker):
    spec = importlib.util.spec_from_file_location('prover_isa', ROOT / 'scripts/bench/check-prover-isa.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect(worker)


def package(workers, output, external_receipt=None):
    validate_platform()
    if output.exists():
        raise ValueError('Refusing to overwrite a release directory')
    workers = [worker.resolve(strict=True) for worker in workers]
    if not workers or len({worker.name for worker in workers}) != len(workers):
        raise ValueError('Expected distinct workers')
    config_sha = digest(ROOT / '.cargo/config.toml')
    source_hashes = {worker.name: digest(worker) for worker in workers}
    for worker in workers:
        validate_worker(worker)
    if external_receipt is not None:
        if len(workers) != 1:
            raise ValueError('An external receipt must describe exactly one worker')
        validate_receipt(workers[0], external_receipt, config_sha)
    # Inspect the actual proof executable, not its baseline launcher. Metadata
    # alone cannot establish that vectorized field arithmetic was linked.
    isa = {worker.name: inspect_proof(worker) for worker in workers if worker.name in PROOF_WORKERS}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.prover-package-', dir=output.parent) as temporary:
        staging = Path(temporary) / 'release'
        (staging / 'bin').mkdir(parents=True)
        (staging / 'libexec').mkdir()
        compiler = ['rustc', str(ROOT / 'scripts/bench/prover-launcher.rs'), '--edition=2021',
                    '-O', '-D', 'warnings', '-C', 'target-cpu=x86-64']
        launcher = Path(temporary) / 'launcher-bootstrap'
        subprocess.run([*compiler, '-o', str(launcher)], check=True, cwd=ROOT)
        receipts = []
        for worker in workers:
            installed = staging / 'libexec' / worker.name
            shutil.copy2(worker, installed)
            shutil.copy2(launcher, staging / 'bin' / worker.name)
            expected_hash = source_hashes[worker.name]
            if (digest(installed) != expected_hash
                    or digest(worker) != expected_hash
                    or (worker.name in isa and isa[worker.name]['binary_sha256'] != expected_hash)
                    or (external_receipt is not None
                        and external_receipt['binary_sha256'] != expected_hash)):
                raise ValueError('Worker changed during packaging')
            receipts.append({'name': worker.name, 'worker_sha256': digest(installed),
                             'isa_inspection': isa.get(worker.name)})
        (staging / 'build-receipt.json').write_text(json.dumps({
            'worker_isa': 'x86-64-v3', 'bootstrap_isa': 'x86-64',
            'bootstrap_sha256': digest(launcher), 'workers': receipts,
            'compiler': subprocess.check_output(['rustc', '-vV'], text=True),
            'repository_config_sha256': config_sha,
            'worker_build_receipt': external_receipt,
        }, indent=2) + '\n')
        if output.exists():
            raise ValueError('Refusing to overwrite a release directory')
        staging.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', type=Path, help='Package one controlled-built worker instead of building nodes')
    parser.add_argument('--worker-receipt', type=Path, help='Required controlled build receipt for --worker')
    args = parser.parse_args()
    if bool(args.worker) != bool(args.worker_receipt):
        parser.error('--worker and --worker-receipt must be supplied together')
    validate_platform()
    validate_environment(os.environ)
    validate_config(tomllib.loads((ROOT / '.cargo/config.toml').read_text()))
    if args.output.exists():
        raise ValueError('Refusing to overwrite a release directory')
    receipt = None
    if args.worker:
        workers = [args.worker]
        receipt = json.loads(args.worker_receipt.read_text())
    else:
        subprocess.run(['cargo', 'build', '--release', '--locked', '-p', 'siworld-node',
                        '--bin', 'siworld-node', '--bin', 'siworld-cli'], check=True, cwd=ROOT)
        target = Path(os.environ.get('CARGO_TARGET_DIR', 'target'))
        if not target.is_absolute():
            target = ROOT / target
        workers = [target / 'release' / name for name in ('siworld-node', 'siworld-cli')]
    package(workers, args.output.resolve(), receipt)


if __name__ == '__main__':
    main()
