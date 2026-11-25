#!/usr/bin/env python3
"""Prepare and record pending V1 economic-relation evidence without refreezing it."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
KINDS = ('transaction', 'settlement', 'issuance')


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')


def prepare(output):
    """Reuse the pinned graph, without invoking or weakening prior freeze guards."""
    output.mkdir(parents=True, exist_ok=False)
    application = ROOT / 'crates/bench-multi-asset'
    text = (application / 'Cargo.toml').read_text()
    if text.count('[package]\n') != 1 or text.count('path = "../native-proof"') != 1:
        raise ValueError('Unexpected candidate manifest shape')
    text = text.replace('[package]\n', '[package]\nautobins = false\n', 1)
    text = text.replace('path = "../native-proof"', 'path = ' + json.dumps(str(ROOT / 'crates/native-proof')))
    text += '\n[lib]\npath = ' + json.dumps(str(application / 'src/lib.rs')) + '\n'
    text += '\n[[bin]]\nname = "native-proof-artifacts"\npath = ' + json.dumps(str(ROOT / 'scripts/bench/native-proof-artifacts.rs')) + '\n'
    (output / 'Cargo.toml').write_text(text)
    shutil.copyfile(application / 'Cargo.lock', output / 'Cargo.lock')


def extract_simulation(log, output):
    marker = 'V1_ECONOMICS_SIMULATION='
    records = []
    for line in log.read_text().splitlines():
        prefix, found, record = line.partition(marker)
        if found:
            if prefix not in ('', 'test v1_economics::tests::seeded_twenty_year_modes_preserve_supply_and_curve ... '):
                raise ValueError('Unexpected simulation record prefix')
            records.append(record)
    if len(records) != 1:
        raise ValueError('Exactly one completed simulation record required')
    result = json.loads(records[0])
    for key in ('height', 'issued', 'miner_subsidy_credited', 'holder_pool', 'burned', 'locked_subsidy'):
        if type(result.get(key)) is not int or result[key] < 0:
            raise ValueError('Invalid simulation integer')
    if result['height'] != 20 * 365 * 288:
        raise ValueError('Simulation did not cover twenty production years')
    def numeric_tree(value):
        if type(value) is int:
            return value >= 0
        if isinstance(value, list):
            return all(numeric_tree(item) for item in value)
        if isinstance(value, dict):
            return all(isinstance(key, str) and key.replace('_', '').isalnum()
                       and numeric_tree(item) for key, item in value.items())
        return False
    if not numeric_tree(result):
        raise ValueError('Simulation must contain only numeric public evidence')
    write(output, {'schema': 1, 'status': 'candidate-pending-review', 'simulation': result,
                   'acceptance': False, 'cryptographic_approval': False, 'network_activation': False})


def freeze_module():
    spec = importlib.util.spec_from_file_location('candidate_freeze', ROOT / 'scripts/bench/multi-asset-profile.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def keys(executable, screen_path, output, measurement_summary=None):
    output.mkdir(parents=True, exist_ok=False)
    screen = json.loads(screen_path.read_text())
    if screen.get('cryptographic_approval') is not False or screen.get('network_activation') is not False:
        raise ValueError('Unexpected screen approval claim')
    measured = None
    summary_bytes = None
    if measurement_summary is not None:
        summary_bytes = measurement_summary.read_bytes()
        summary = json.loads(summary_bytes)
        measured = freeze_module().economic_summary(summary, require_admission_margin=False)
        if any(summary.get(name) != screen.get(name) for name in ('air_source_sha256', 'dependencies_sha256')):
            raise ValueError('Selected measurement differs from the actual-AIR screen')
    relations = []
    for kind in KINDS:
        selected = None if measured is None else (measured['selected']['parameters']
            if kind == 'transaction' else measured['repeated_measurements'][kind]['parameters'])
        coordinate = selected['log_blowup'] if selected else (7 if kind == 'transaction' else 8)
        grinding = selected['query_pow_bits'] if selected else 20
        matches = [entry['minimum_passing_report'] for entry in screen['reports']
                   if (entry['kind'], entry['log_blowup'], entry['grinding']) == (kind, coordinate, grinding)]
        if len(matches) != 1 or matches[0] is None:
            raise ValueError('Required candidate coordinate failed the actual-AIR screen')
        report = matches[0]
        if report['shape']['status'] != 'actual-extracted' or report['screen']['passes_selected_model'] is not True:
            raise ValueError('Candidate requires an actual extracted passing security report')
        p = report['fri']
        if selected is not None and p != selected:
            raise ValueError('Actual selected queries differ from the actual-AIR screen')
        args = [str(executable), '--candidate', kind, str(p['log_blowup']), str(p['num_queries']), str(p['query_pow_bits'])]
        first, second = output / (kind + '.json'), output / (kind + '-reproduced.json')
        subprocess.run(args + [str(first)], check=True)
        subprocess.run(args + [str(second)], check=True)
        a, b = json.loads(first.read_text()), json.loads(second.read_text())
        if a != b or a.get('status') != 'candidate-pending-review' or a.get('acceptance') is not False:
            raise ValueError('Public candidate keys did not reproduce exactly')
        if a['security'] != report or a['parameters'] != p:
            raise ValueError('Candidate key report differs from the actual-AIR screen')
        key = a['public_verifier_key']
        if hashlib.sha256(bytes.fromhex(key['hex'])).hexdigest() != key['sha256']:
            raise ValueError('Candidate key identity mismatch')
        relations.append(a)
    paths = sorted(set((ROOT / 'crates/bench-multi-asset/src').rglob('*.rs'))
                   | set((ROOT / 'crates/native-node/src').rglob('*.rs'))
                   | {ROOT / item for item in ('crates/bench-multi-asset/Cargo.toml',
                       'crates/bench-multi-asset/Cargo.lock', 'crates/native-node/Cargo.toml',
                       'crates/native-node/Cargo.lock', 'crates/core/src/v1_economics.rs',
                       'crates/core/src/v1_economics_tests.rs', 'scripts/bench/native-proof-artifacts.rs')})
    source = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if measured is not None and summary['source_commit'] != commit:
        raise ValueError('Selected measurement was produced from a different source commit')
    evidence = {} if measured is None else {'measurement_summary_sha256': hashlib.sha256(summary_bytes).hexdigest(),
        'measurement_mode': 'economics-candidate', 'selected_by_actual_measurement': True}
    write(output / 'candidate-manifest.json', {'schema': 1, 'status': 'candidate-pending-review',
          'source_commit': commit, **evidence,
          'sources_sha256': source, 'relations': relations, 'measurement_qualification': 'separate-required',
          'acceptance': False, 'cryptographic_approval': False, 'network_activation': False})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prepare_parser = sub.add_parser('prepare')
    prepare_parser.add_argument('output', type=Path)
    simulation_parser = sub.add_parser('simulation')
    simulation_parser.add_argument('log', type=Path)
    simulation_parser.add_argument('output', type=Path)
    keys_parser = sub.add_parser('keys')
    keys_parser.add_argument('executable', type=Path)
    keys_parser.add_argument('screen', type=Path)
    keys_parser.add_argument('output', type=Path)
    keys_parser.add_argument('--measurement-summary', type=Path)
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args.output)
    elif args.command == 'simulation':
        extract_simulation(args.log, args.output)
    else:
        keys(args.executable.resolve(strict=True), args.screen, args.output, args.measurement_summary)


if __name__ == '__main__':
    main()
