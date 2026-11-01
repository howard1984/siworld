#!/usr/bin/env python3
"""Qualify three frozen fixed-576 settlement proofs on minimum-role hardware.

Uses the existing native-scan Holder fixture, not the separate maximal-priority
fee witness or combined complete-block acceptance test. The proof relation and
parameters remain frozen; no settlement-generation time gate is introduced.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

import importlib.util

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_transaction_qualification',
                                            ROOT / 'scripts/qualify-native-transaction.py')
Q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Q)
M, F = Q.M, Q.F
PROOF_MAX = 655_360
ADMISSION_MAX = PROOF_MAX * 9 // 10
PARAMETERS = F.parameters('settlement')


def admission(rows):
    """Every fresh scope must pass, including the 90-percent byte threshold."""
    return len(rows) == 3 and all(
        row.get('resource_control_pass') is True and row.get('proof_report_valid') is True
        and type(row.get('memory_peak_bytes')) is int and 0 < row['memory_peak_bytes'] <= M.MEMORY_MAX
        and type(row.get('measurement', {}).get('proof_bytes')) is int
        and 0 < row['measurement']['proof_bytes'] <= min(PROOF_MAX, ADMISSION_MAX)
        for row in rows)


def bound_profile(args):
    manifest = json.loads(args.manifest.read_text())
    F.validate(manifest, reproduced=args.reproduced)
    relation = next(row for row in manifest['relations'] if row['kind'] == 'settlement')
    frozen = F.transaction_profile()
    screen = json.loads(args.screen.read_text())
    selected = M.profiles(screen, 'settlement').get((8, 20))
    if (not selected or selected['parameters'] != PARAMETERS
            or relation['parameters'] != PARAMETERS
            or selected['security'] != M.security_summary(relation['security'])):
        raise ValueError('Settlement relation or actual security report differs from the frozen profile')
    for name in ('air_source_sha256', 'dependencies_sha256'):
        if M.digest(screen[name]) != frozen[name]:
            raise ValueError('Settlement source identity differs from the frozen manifest')
    return {**selected, **{name: screen[name] for name in ('air_source_sha256', 'dependencies_sha256')},
            'public_verifier_key_sha256': relation['public_verifier_key']['sha256']}


def collect(args):
    args.output.mkdir(parents=True, exist_ok=False)
    hardware = Q.H.qualify_and_record(args.output, args.hardware_profile)
    if hardware is None:
        return 1
    profile = bound_profile(args)
    executable, worker = args.executable.resolve(strict=True), args.worker.resolve(strict=True)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('Invalid source commit')
    identity = {name: profile[name] for name in ('air_source_sha256', 'dependencies_sha256')}
    identity['binary_sha256'] = M.sha(worker)
    rows = []
    with tempfile.TemporaryDirectory(prefix='native-settlement-private-', dir=args.private_parent) as temporary:
        private = Path(temporary)
        for trial in range(1, 4):
            stem = 'settlement-' + str(trial)
            config = dict(uid=os.getuid(), gid=os.getgid(),
                unit='siworld-native-' + uuid.uuid4().hex + '.scope', kind='settlement',
                parameters=PARAMETERS.copy(), workers=4, trial=trial, timeout=args.timeout,
                executable=str(executable), hardware_profile='diagnostic', qualification_profile=args.hardware_profile,
                private_output=str(private / (stem + '-raw.json')),
                private_log=str(private / (stem + '.log')),
                result=str(private / (stem + '-result.json')), scan_mode='economics-candidate', **identity)
            path = private / (stem + '-config.json')
            M.write_json(path, config)
            row = Q.collect_trial(config, path, profile)
            rows.append(row)
    passed = admission(rows)
    M.write_json(args.output / 'summary.json', dict(schema=1, source_commit=commit,
        kind='settlement', parameters=PARAMETERS.copy(), capacity=576, workers=4,
        qualification_adapter_sha256=M.sha(Path(M.__file__)),
        hardware_profile=args.hardware_profile, hardware=hardware, **identity,
        public_verifier_key_sha256=profile['public_verifier_key_sha256'],
        reproduced_public_keys_match=True, actual_security_report=profile['security'],
        proof_body_limit_bytes=PROOF_MAX, measurement_ceiling_bytes=ADMISSION_MAX,
        generation_limit_ns=None, diagnostic_memory_max_bytes=M.MEMORY_MAX,
        diagnostic_swap_max_bytes=0, trials=rows, summary=M.medians(rows),
        engineering_target_pass=passed, minimum_configuration_qualified=passed,
        measurement_scope='native-scan fixed-576 Holder fixture; separate maximal-priority and complete-block gates remain required',
        acceptance=False, cryptographic_approval=False, network_activation=False))
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('executable', 'worker', 'screen', 'reproduced', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--manifest', type=Path, default=ROOT / F.MANIFEST)
    parser.add_argument('--private-parent', type=Path)
    parser.add_argument('--hardware-profile', choices=('minimum-validator', 'minimum-miner'),
                        default='minimum-miner')
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error('timeout must be between 1 and 600 seconds')
    try:
        return collect(args)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print('Settlement qualification failed: ' + type(error).__name__, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
