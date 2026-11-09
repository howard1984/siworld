"""Build an unsigned miner package on an owner-controlled development machine."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

from windows_miner_pe import audit

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'x86_64-pc-windows-msvc'
REPOSITORY = 'howard1984/siworld'
WORKER_FLAGS = '-C target-cpu=x86-64-v3 -C target-feature=+crt-static'
LAUNCHER_FLAGS = '-C target-cpu=x86-64 -C target-feature=+crt-static'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def build(manifest, directory, flags, extra=None):
    environment = {**os.environ, 'RUSTFLAGS': flags, **(extra or {})}
    subprocess.run(['cargo', *(['xwin'] if sys.platform == 'darwin' else []), 'build', '--release', '--locked', '--offline', '--target', TARGET,
                    '--manifest-path', str(ROOT / manifest), '--target-dir', str(directory)],
                   cwd=ROOT, env=environment, check=True)


def local_context(environment):
    """Reject hosted execution and record the actual local build method."""
    if any(environment.get(key) for key in ('CI', 'GITHUB_ACTIONS', 'GITHUB_RUN_ID', 'RUNNER_ENVIRONMENT')):
        raise ValueError('Miner packaging is restricted to owner-controlled local machines')
    if sys.platform not in ('darwin', 'win32'):
        raise ValueError('Use a Mac cross-build or a native Windows development host')
    for name in ('CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'):
        if environment.get(name):
            raise ValueError(f'Unreviewed compiler override: {name}')
    return {'host_platform': sys.platform,
            'method': 'cargo-xwin-msvc' if sys.platform == 'darwin' else 'native-msvc',
            'owner_controlled': True, 'ci': False}


def source_revision(expected):
    top = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], cwd=ROOT, text=True).strip()
    if Path(top).resolve() != ROOT:
        raise ValueError('Package source must be its own Git checkout')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if revision != expected:
        raise ValueError('Checked-out source differs from the requested commit')
    if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=ROOT):
        raise ValueError('Official package requires an unmodified source checkout')
    return revision


def package(output, expected_commit):
    provenance = local_context(os.environ)
    revision = source_revision(expected_commit)
    compiler = subprocess.check_output(['rustc', '-vV'], text=True)
    if sys.platform == 'win32' and f'host: {TARGET}' not in compiler.splitlines():
        raise ValueError('Native Windows builds require an x64 MSVC Rust toolchain')
    if output.exists():
        raise SystemExit('Output must be a new directory; existing artifacts are preserved')
    output.mkdir(parents=True)
    # Reuse source-bound release dependencies from the same CI job's tests.
    worker_target = Path(os.environ.get('CARGO_TARGET_DIR', output / 'worker-target')).resolve()
    launcher_target = output / 'launcher-target'
    build('crates/miner-cli/Cargo.toml', worker_target,
          WORKER_FLAGS)
    worker = worker_target / TARGET / 'release/siworld-miner-worker.exe'
    worker_hash = digest(worker)
    build('crates/miner-launcher/Cargo.toml', launcher_target,
          LAUNCHER_FLAGS,
          {'SIWORLD_WORKER_SHA256': worker_hash})
    folder = output / 'siworld-miner-windows-x86_64'
    (folder / 'libexec').mkdir(parents=True)
    shutil.copy2(worker, folder / 'libexec/siworld-miner-worker.exe')
    shutil.copy2(launcher_target / TARGET / 'release/siworld-miner.exe', folder)
    for name in ('LICENSE', 'NOTICE'):
        shutil.copy2(ROOT / name, folder / name)
    shutil.copy2(ROOT / 'docs/windows-native-miner.md', folder / 'README.md')
    pe_audit = {path.relative_to(folder).as_posix(): audit(path)
                for path in sorted(folder.rglob('*.exe'))}
    (folder / 'pe-imports.json').write_text(json.dumps(pe_audit, indent=2) + '\n', encoding='utf-8')
    sources = {}
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    for name in sorted(filter(None, tracked)):
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            raise ValueError('Source manifest requires regular tracked files')
        sources[name] = digest(path)
    dependency_tree = subprocess.check_output([
        'cargo', 'tree', '--locked', '--offline', '--target', TARGET, '--edges', 'normal,build',
        '--manifest-path', str(ROOT / 'crates/miner-cli/Cargo.toml'),
    ], cwd=ROOT, text=True)
    (folder / 'dependencies.txt').write_text(dependency_tree, encoding='utf-8')
    source_revision(revision)
    (folder / 'build-info.json').write_text(json.dumps({
        'format': 2, 'target': TARGET, 'signed': False, 'distribution': 'test-only',
        'source_repository': f'https://github.com/{REPOSITORY}',
        'source_revision': revision, 'source_modified': False,
        'build': provenance, 'rustflags': {'launcher': LAUNCHER_FLAGS, 'worker': WORKER_FLAGS},
        'worker_sha256': worker_hash,
        'rustc': compiler.strip(),
        'source_sha256': sources,
        'qualification': 'Local build only; Windows 10/11 physical mining acceptance remains required',
    }, indent=2) + '\n', encoding='utf-8')
    (folder / 'release-notes.md').write_text(
        '# Windows native miner engineering package\n\n'
        'Foreground PowerShell/CMD onboarding with explicit reward mode, recipient, BACKEDUP and START gates. '
        'The miner uses authenticated outbound connections and current-user local storage. '
        'No service, inbound listener, firewall rule or automatic update is installed.\n\n'
        'This package is unsigned. A trusted engineering-network bundle and mutual peer pairing are required. '
        'Real Windows 10/11 hardware compatibility, Defender/SmartScreen behavior, sustained mining and rewards '
        'remain subject to physical-machine acceptance. Synthetic CI transport tests do not qualify proof throughput.\n', encoding='utf-8')
    # PE inspection is host-independent. Cross-built executables run only on Windows.
    if sys.platform == 'win32':
        subprocess.run([str(folder / 'siworld-miner.exe'), '--help'], check=True)
    contents = sorted(path for path in folder.rglob('*') if path.is_file())
    (folder / 'SHA256SUMS').write_text(''.join(
        f'{digest(path)}  {path.relative_to(folder).as_posix()}\n' for path in contents), encoding='ascii')
    archive = output / (folder.name + '.zip')
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as target:
        for path in sorted(folder.rglob('*')):
            if path.is_file():
                target.write(path, path.relative_to(output))
    (output / 'provenance.json').write_text(json.dumps({
        'format': 1, 'distribution': 'test-only', 'source_repository': f'https://github.com/{REPOSITORY}',
        'source_revision': revision, 'build': provenance,
        'archive': {'name': archive.name, 'sha256': digest(archive)},
        'build_info_sha256': digest(folder / 'build-info.json'),
    }, indent=2) + '\n', encoding='utf-8')
    (output / 'SHA256SUMS').write_text(''.join(
        f'{digest(path)}  {path.name}\n' for path in [archive, output / 'provenance.json']), encoding='ascii')
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--expected-commit', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.expected_commit):
        parser.error('A full source commit is required')
    package(args.output.resolve(), args.expected_commit)


if __name__ == '__main__':
    main()
