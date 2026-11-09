#!/usr/bin/env python3
"""Prepare, test and package a pinned D8 checkpoint in an isolated directory.

This adapter never modifies a Cargo cache, retained deployment or published
history. Cargo uses an exact fork revision; the separately hashed patch is an
audit archive. Correctness smoke tests are distinct from the final-parameter checkpoint.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PIN = 'd3d15b2b5d1325fb38ebc8979c1cae04b761e71f'
URL = 'https://github.com/howard1984/siworld'
BASE_PIN = '3a69ba61f713c8400b14eb3d8f0e52caa13512c7'
UPSTREAM_URL = 'https://github.com/Plonky3/Plonky3-recursion'
PATCH = ROOT / 'crates/bench-stark/patches/recursion-d8-w24.patch'
APPLICATION = ROOT / 'crates/bench-d8'
LINEAGE = APPLICATION / 'dependency-lineage.toml'
DEPENDENCY_VERSION = 'd8-w24-review-v1'
REVIEW_REVISION = 'cb50fe9bb2dcd76fc7de1b71d0cd3f099eb235db'
REVIEW_TREE = 'e57b72819dbb2a27b5b20cb5b035f3f664e06c3a'
DOWNSTREAM_REVISION = 'd3d15b2b5d1325fb38ebc8979c1cae04b761e71f'
DOWNSTREAM_TREE = '11f7507a135f825a2ba6c790b9ad6d50a4e40b81'
PATCH_SHA256 = '78cc3dc553120147bd3b87371533a3769beed2e62ec034bff5a6378528007c3d'
FEATURES = 'experimental-fanin,phase-profile,security-report'
DEPENDENCIES = {'p3-circuit': 'circuit', 'p3-circuit-prover': 'circuit-prover', 'p3-recursion': 'recursion'}
APP_TESTS = ('constraints', 'acc_mode_binds_statement', 'hashed_limbs', 'outputs_are',
             'nullifiers', 'unlock_height', 'poseidon2_air_layout',
             'd8_w24_eight_input_smoke_binds_statement',
             'd8_ciphertext_limbs_and_padding_are_constrained')
FIXTURE = {'generator': 'siworld-d8-synthetic-v1', 'first_seed': 100, 'slots': 16,
           'anchor_height': 1000, 'base_fee': 678904, 'anchor_rng_seed': 21, 'dummy': False}


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_lineage(manifest_path=None, patch_path=None):
    """Reject modified patches or lineage before fetching or compiling code."""
    manifest_path = manifest_path or LINEAGE
    patch_path = patch_path or PATCH
    manifest = tomllib.loads(manifest_path.read_text())
    expected = {'schema': 1, 'version': DEPENDENCY_VERSION,
        'source_mode': 'fixed-fork-revision', 'source_url': URL, 'source_revision': PIN,
        'upstream_url': UPSTREAM_URL, 'base_revision': BASE_PIN, 'upstream_review_revision': REVIEW_REVISION,
        'upstream_review_tree': REVIEW_TREE, 'downstream_revision': DOWNSTREAM_REVISION,
        'downstream_tree': DOWNSTREAM_TREE,
        'patch_file': 'crates/bench-stark/patches/recursion-d8-w24.patch',
        'patch_sha256': PATCH_SHA256, 'suite': 'KoalaBear-D8-Poseidon2-W24-digest12'}
    if manifest != expected or type(manifest.get('schema')) is not int:
        raise ValueError('D8 dependency lineage does not match the fixed source revisions')
    if sha(patch_path) != PATCH_SHA256:
        raise ValueError('D8 dependency patch SHA-256 does not match its fixed lineage')
    return manifest


def validate_prepared_source(upstream, lineage):
    """Verify the exact fork checkout without rewriting dependency sources."""
    head = subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD'],
                                   text=True, cwd=ROOT).strip()
    tree = subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD^{tree}'],
                                   text=True, cwd=ROOT).strip()
    if head != lineage['source_revision']:
        raise ValueError('Prepared D8 dependency source revision mismatch')
    if tree != lineage['downstream_tree']:
        raise ValueError('Prepared D8 dependency tree differs from the fixed downstream revision')
    return {'version': lineage['version'], 'source_mode': lineage['source_mode'],
        'source_url': lineage['source_url'], 'source_revision': head,
        'base_revision': lineage['base_revision'], 'downstream_revision': lineage['downstream_revision'],
        'downstream_tree': tree, 'upstream_review_revision': lineage['upstream_review_revision'],
        'patch_sha256': lineage['patch_sha256']}


def registry_pins(lock):
    values = set()
    for block in lock.split('[[package]]')[1:]:
        fields = dict(re.findall(r'^([a-z]+) = "([^"\n]+)"$', block, re.M))
        if fields.get('source', '').startswith('registry+'):
            values.add(tuple(fields[key] for key in ('name', 'version', 'checksum')))
    return values


def validate_application_dependencies(text):
    """Require exact Git source identities; no local-path adapter is applied."""
    dependencies = tomllib.loads(text)['workspace']['dependencies']
    for name in DEPENDENCIES:
        declaration = dependencies[name]
        if declaration.get('git') != URL or declaration.get('rev') != PIN or 'path' in declaration:
            raise ValueError('Dependency does not use the exact pinned recursion source: ' + name)


TEST_PHASES = frozenset(('leaf_setup', 'leaf_proof', 'leaf_verification', 'merge_setup', 'merge_proof', 'merge_verification', 'public_digest_rejection', 'last_child_rejection', 'transcript.native_equivalence.begin', 'transcript.native_equivalence.complete', 'transcript.interleaving.begin', 'transcript.interleaving.complete', 'binary_compression.begin', 'binary_compression.complete', 'suite_geometry.begin', 'suite_geometry.complete', 'prepared_batch_work.begin', 'prepared_batch_work.native_prove', 'prepared_batch_work.native_verify', 'prepared_batch_work.prepare', 'prepared_batch_work.recursive_prove', 'prepared_batch_work.recursive_verify', 'prepared_batch_work.invalid_nonce', 'prepared_batch_work.invalid_opening_coefficients', 'prepared_batch_work.generic_batch_capture', 'prepared_batch_work.generic_batch_replay', 'prepared_batch_work.complete', 'scalar_witness_bus.begin', 'scalar_witness_bus.prepare', 'scalar_witness_bus.valid_runner', 'scalar_witness_bus.valid_prove', 'scalar_witness_bus.valid_verify', 'scalar_witness_bus.invalid_coefficients', 'scalar_witness_bus.complete', 'statement_preprocessor.begin', 'statement_preprocessor.complete', 'scalar_witness_bus.portable_roundtrip'))


ERROR_CATEGORIES = ('UnsupportedDegree', 'MissingWForExtension', 'Verify', 'MissingTableProver',
    'DuplicateTableSource', 'InvalidMetadata', 'RelationMismatch', 'Prove',
    'PrivateInputLengthMismatch', 'PublicInputLengthMismatch', 'UnclaimedPrivateInput',
    'WitnessNotSet', 'WitnessConflict', 'BitDecompositionMismatch', 'CoefficientsNotBaseBound',
    'RecomposeCoeffLookupsUnavailable', 'GlobalCumulativeSumMismatch', 'OodEvaluationMismatch')


def sanitized_diagnostics(output, step, exit_code):
    codes = sorted(set(re.findall(r'^error\[([A-Z][0-9]{4})\]', output, flags=re.M)))
    failed = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. FAILED$', output, flags=re.M)
    locations = []
    for path, line, column in re.findall(r'(?:-->|panicked at)\s+(\S+\.rs):(\d+):(\d+)', output):
        # Keep only a conventional relative Rust source suffix. Diagnostic
        # messages and source excerpts can contain proof values or host paths.
        suffix = path.rsplit('/src/', 1)[-1]
        relative = ('src/' + suffix) if '/src/' in path else path
        if not relative.startswith('/') and re.fullmatch(r'[A-Za-z0-9_./-]+\.rs', relative) and '..' not in Path(relative).parts:
            locations.append({'source': relative, 'line': int(line), 'column': int(column)})
    return {'event': 'd8_build_failure', 'step': step, 'exit_code': exit_code,
            'compiler_error_codes': codes, 'failed_tests': failed[:32], 'source_locations': locations[:32],
            'validation_error_categories': [label for label in ERROR_CATEGORIES
                if re.search(r'\b' + label + r'(?:\(|\s*\{|\b)', output)],
            'last_test_phase': ([phase for phase in re.findall(r'^D8_TEST_PHASE ([a-z0-9_.]{1,80})$', output, flags=re.M) if phase in TEST_PHASES] or [None])[-1]}


def run_logged(command, log, nonempty_tests=False, minimum_tests=1):
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    log.write_text(result.stdout)
    if result.returncode != 0:
        print(json.dumps(sanitized_diagnostics(result.stdout, log.stem, result.returncode)), flush=True)
        raise ValueError('A controlled build/test command failed; retain its private log')
    count = sum(int(value) for value in re.findall(r'running (\d+) tests?\b', result.stdout))
    if nonempty_tests and count < minimum_tests:
        print(json.dumps({'event': 'd8_build_failure', 'step': log.stem,
            'classification': 'required-tests-missing', 'selected_tests': count,
            'minimum_required_tests': minimum_tests}), flush=True)
        raise ValueError('A required correctness filter selected zero tests or omitted required cases')
    if nonempty_tests:
        passed = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. ok$', result.stdout, flags=re.M)
        print(json.dumps({'event': 'd8_build_tests_passed', 'step': log.stem,
            'selected_tests': count, 'passed_tests': passed[:64]}), flush=True)


def archive_sources(workspace, upstream, output):
    with tarfile.open(output, 'w') as archive:
        for directory, prefix in ((workspace, 'application'), (upstream, 'recursion')):
            for path in sorted(directory.rglob('*')):
                relative = path.relative_to(directory)
                if any(part in ('.git', 'target', '.local') for part in relative.parts) or path.is_dir():
                    continue
                if path.is_symlink():
                    raise ValueError('Source freeze rejects symbolic links')
                info = archive.gettarinfo(str(path), arcname=str(Path(prefix) / relative))
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                info.mtime = 0
                with path.open('rb') as stream:
                    archive.addfile(info, stream)


def write_bootstrap(destination, workspace, upstream, receipt, source_revision):
    checkpoint = load_script('measure-d8-checkpoint')
    bundle = destination / 'frozen-bundle'
    bundle.mkdir()
    release = destination / 'release'
    shutil.copytree(release, bundle / 'release')
    archive_sources(workspace, upstream, bundle / 'source.tar')
    shutil.copyfile(PATCH, bundle / 'recursion.patch')
    shutil.copyfile(workspace / 'Cargo.lock', bundle / 'Cargo.lock')
    shutil.copyfile(ROOT / '.cargo/config.toml', bundle / 'cargo-config.toml')
    (bundle / 'leaf-input.json').write_text(json.dumps(FIXTURE, indent=2) + '\n')
    parameters = {layer: {'log_blowup': 3, 'queries': 148 if layer == 'leaf' else 140,
        'commit_grinding': 0 if layer == 'leaf' else 16, 'query_grinding': 16,
        'batch_grinding': 16, 'max_log_arity': 1, 'final_poly_log': 0} for layer in checkpoint.LAYERS}
    configuration = {'suite': checkpoint.SUITE, 'source_revision': source_revision,
        'recursion_revision': PIN, 'parameters': parameters,
        'resource_limits': dict(checkpoint.RESOURCE_LIMITS)}
    (bundle / 'configuration.json').write_text(json.dumps(configuration, indent=2) + '\n')
    (bundle / 'root-model.json').write_text(json.dumps({
        'checkpoint_mode': 'n16-full', 'projection': None,
        'scope': 'Actual complete N=16 proofs in one process tree with all prepared layers resident.',
        'memory_attribution': 'Per-stage boundary readings and cgroup samples are lower bounds; '
            'the kernel lifetime peak includes setup and all three warm trials. '
            'Serialized retained proof bytes exclude allocator and object overhead.'}, indent=2) + '\n')
    paths = {'launcher': 'release/bin/d8-checkpoint', 'worker': 'release/libexec/d8-checkpoint',
        'build_receipt': 'release/build-receipt.json', 'cargo_config': 'cargo-config.toml',
        'configuration': 'configuration.json', 'root_model': 'root-model.json',
        'dependency_lock': 'Cargo.lock', 'source_archive': 'source.tar',
        'recursion_patch': 'recursion.patch', 'leaf_input_fixture': 'leaf-input.json'}
    manifest = {'schema': 1, 'stage': 'bootstrap', 'checkpoint_mode': 'n16-full',
        'suite': checkpoint.SUITE, 'poseidon2_parameters': 'Plonky3-standard',
        'source_revision': source_revision, 'recursion_revision': PIN,
        'execution': {'slots': 16, 'jobs': 1, 'native_workers': 2, 'rayon_threads': 2, 'hiding_workers': 2},
        'parameters': parameters, 'resource_limits': dict(checkpoint.RESOURCE_LIMITS),
        'files': {role: {'path': relative, 'sha256': sha(bundle / relative)}
            for role, relative in paths.items()}}
    path = bundle / 'bootstrap-manifest.json'
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    checkpoint.load_bootstrap(path, sha(path))
    (destination / 'bootstrap-receipt.json').write_text(json.dumps({
        'bootstrap_manifest': str(path.resolve()), 'bootstrap_manifest_sha256': sha(path),
        'binary_sha256': receipt['binary_sha256'],
        'resource_limits': dict(checkpoint.RESOURCE_LIMITS), 'acceptance': False}, indent=2) + '\n')
    return path


def build(args):
    controlled = load_script('build-composition-intra')
    release = load_script('build-prover-release')
    release.validate_platform()
    configuration = controlled.controlled_configuration(os.environ)
    if not PATCH.is_file() or not (APPLICATION / 'Cargo.toml').is_file() or not (APPLICATION / 'Cargo.lock').is_file():
        raise ValueError('Published D8 application, exact dependency patch and lockfile are required')
    lineage = validate_lineage()
    validate_application_dependencies((APPLICATION / 'Cargo.toml').read_text())
    if args.output.exists():
        raise ValueError('Refusing to overwrite an existing D8 build or its evidence')
    destination = args.output.resolve()
    destination.mkdir(parents=True)
    upstream = destination / 'upstream'
    subprocess.run(['git', 'init', '--quiet', str(upstream)], check=True, cwd=ROOT)
    subprocess.run(['git', '-C', str(upstream), 'fetch', '--depth=1',
                    str(args.source.resolve()) if args.source else URL, PIN], check=True, cwd=ROOT)
    subprocess.run(['git', '-C', str(upstream), 'checkout', '--quiet', '--detach', 'FETCH_HEAD'], check=True, cwd=ROOT)
    dependency_source = validate_prepared_source(upstream, lineage)
    (destination / 'dependency-receipt.json').write_text(json.dumps(dependency_source, indent=2) + '\n')
    workspace = destination / 'application'
    shutil.copytree(APPLICATION, workspace, ignore=shutil.ignore_patterns('target', '.local', '.git'))
    manifest = workspace / 'Cargo.toml'
    original_lock = registry_pins((APPLICATION / 'Cargo.lock').read_text())
    if args.prepare_only:
        return {'prepared': True, 'dependency_source': dependency_source, 'acceptance': False}
    # Cargo configuration fixes test/proof code to v3. Check CPU/OS support
    # with an independently compiled generic bootstrap before executing it.
    guard = destination / 'cpu-check'
    subprocess.run(['rustc', str(ROOT / 'scripts/prover-launcher.rs'), '--edition=2021', '-O',
                    '-D', 'warnings', '-C', 'target-cpu=x86-64', '-o', str(guard)], check=True, cwd=ROOT)
    subprocess.run([str(guard), '--check-cpu'], check=True, cwd=ROOT, stdout=subprocess.DEVNULL)
    run_logged(['cargo', 'test', '--release', '--manifest-path', str(upstream / 'Cargo.toml'),
        '-p', 'p3-recursion', '--lib', 'batch_pow'],
        destination / 'opening-batch-grinding-rejection-tests.log', nonempty_tests=True, minimum_tests=7)
    run_logged(['cargo', 'test', '--release', '--manifest-path', str(upstream / 'Cargo.toml'),
        '-p', 'p3-recursion', '--test', 'd8_scalar_w24'],
        destination / 'd8-transcript-and-codec-tests.log', nonempty_tests=True, minimum_tests=7)
    run_logged(['cargo', 'test', '--release', '--manifest-path', str(upstream / 'Cargo.toml'),
        '-p', 'p3-poseidon2-circuit-air', '--lib',
        'scalar_w24_d8_challenger_air_binds_initial_capacity_and_squeeze_chain'],
        destination / 'd8-challenger-air-rejection-tests.log', nonempty_tests=True)
    run_logged(['cargo', 'test', '--release', '--manifest-path', str(upstream / 'Cargo.toml'),
        '-p', 'p3-recursion', '--test', 'prepared_recursion',
        'positive_opening_batch_grinding_full_and_prepared_recursion'],
        destination / 'opening-batch-grinding-test.log', nonempty_tests=True)
    base = ['cargo', 'test', '--release', '--locked', '--manifest-path', str(manifest), '--features', FEATURES, '--lib']
    for index, test in enumerate(APP_TESTS):
        run_logged([*base, test], destination / ('app-test-' + str(index + 1) + '.log'), nonempty_tests=True)
    run_logged(['cargo', 'build', '--release', '--locked', '--manifest-path', str(manifest),
        '--features', FEATURES, '--bin', 'd8-checkpoint'], destination / 'build.log')
    if registry_pins((workspace / 'Cargo.lock').read_text()) != original_lock:
        raise ValueError('Registry dependency versions/checksums changed during the D8 build')
    target = Path(os.environ.get('CARGO_TARGET_DIR', str(workspace / 'target')))
    if not target.is_absolute():
        target = ROOT / target
    binary = target / 'release/d8-checkpoint'
    receipt = {**configuration, 'recursion_commit': PIN, 'dependency_patch_sha256': sha(PATCH),
        'dependency_source': dependency_source,
        'repository_config_sha256': sha(ROOT / '.cargo/config.toml'),
        'cargo_working_directory': 'repository-root', 'binary_sha256': sha(binary),
        'rustc_version': subprocess.check_output(['rustc', '-vV'], text=True, cwd=ROOT)}
    (destination / 'build-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    release.package([binary], destination / 'release', receipt)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, cwd=ROOT).strip()
    bootstrap = write_bootstrap(destination, workspace, upstream, receipt, revision)
    return {'prepared': True, 'correctness_tests_passed': True, 'acceptance': False,
        'bootstrap_manifest_sha256': sha(bootstrap), 'binary_sha256': sha(binary)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source', type=Path, help='Optional local clone to fetch at the exact upstream revision')
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(build(args), indent=2))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(json.dumps({'event': 'd8_build_adapter_failure',
            'classification': type(error).__name__, 'acceptance': False}), flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
