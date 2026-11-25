#!/usr/bin/env python3
"""Bind three native engineering relations to public keys and unchanged sources.

This offline manifest is not a consensus activation or independent security
approval. The issuance key covers exactly three initial notes; policy/resource
limits and durable node integration remain separate requirements.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

_provenance_spec = importlib.util.spec_from_file_location(
    'source_provenance', Path(__file__).resolve().parents[1] / 'bench/source-provenance.py')
PROVENANCE = importlib.util.module_from_spec(_provenance_spec)
_provenance_spec.loader.exec_module(PROVENANCE)

ROOT = Path(__file__).resolve().parents[2]
TRANSACTION = 'crates/bench-multi-asset/artifacts/v1-transaction-profile.json'
MANIFEST = 'crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json'
TOOLS = ('scripts/ci/check-native-proof-profiles.py', 'scripts/bench/native-proof-artifacts.rs')
KINDS = ('transaction', 'settlement', 'issuance')
CAPACITIES = (0, 576, 3)
SHAPES = ((256, 1420, 243), (1024, 516, 587), (128, 438, 10))
ECONOMICS_REVISION = 'native-v1-economics-1'
ECONOMICS_SHAPES = ((256, 1392, 247), (1024, 581, 609), (128, 438, 10))
ECONOMICS_PUBLIC_VALUES = (101, 7050, 72)
ECONOMICS_RESOURCES = 'fresh three-trial measurements at one and four workers; complete profile-bound kernel evidence'
RELATION_KEYS = frozenset(('kind', 'capacity', 'parameters', 'security', 'public_verifier_key',
    'cryptographic_approval', 'network_activation'))
PERFORMANCE_KEYS = frozenset(('complete', 'trial_count', 'generation_median_ns', 'generation_min_ns',
    'generation_max_ns', 'verification_median_ns', 'process_wall_median_ns',
    'memory_peak_median_bytes', 'memory_peak_max_bytes', 'proof_bytes_min', 'proof_bytes_max', 'acceptance'))


def freeze_module(root=ROOT):
    spec = importlib.util.spec_from_file_location('native_transaction_freeze', root / 'scripts/bench/multi-asset-profile.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool_hashes(root):
    return {PROVENANCE.canonical_path(name): sha(root / name) for name in TOOLS}


def check_tool_hashes(value, root):
    names = tuple(map(PROVENANCE.canonical_path, TOOLS))
    if not PROVENANCE.mapping_matches(root, value, names, PROVENANCE.source_bytes):
        raise ValueError('Native proof tool source differs from its recorded identity')


def parameters(kind):
    return dict(log_blowup=7 if kind == 'transaction' else 8,
                num_queries=41 if kind == 'transaction' else 36,
                query_pow_bits=20, commit_pow_bits=0, batch_pow_bits=20,
                max_log_arity=1, log_final_poly_len=0)


def transaction_profile(root=ROOT):
    value = json.loads((root / TRANSACTION).read_text())
    freeze_module(root).validate(value, root)
    return value


def validate_relation(value, kind, transaction, freeze):
    index = KINDS.index(kind)
    if set(value) != {'kind', 'capacity', 'parameters', 'security', 'public_verifier_key',
                      'cryptographic_approval', 'network_activation'}:
        raise ValueError('Unexpected native relation fields')
    p = parameters(kind)
    if (value['kind'] != kind or type(value['capacity']) is not int
            or value['capacity'] != CAPACITIES[index] or value['parameters'] != p
            or not isinstance(value['parameters'], dict)
            or any(type(n) is not int for n in value['parameters'].values())
            or value['cryptographic_approval'] is not False or value['network_activation'] is not False):
        raise ValueError('Native relation identity or parameters changed')
    security = value['security']
    summary = freeze.MEASUREMENT.security_summary(security)
    shape = summary['shape']
    rows, main, pre = SHAPES[index]
    if (not summary['screen']['passes_selected_model'] or security['fri'] != p
            or not isinstance(security['fri'], dict)
            or any(type(number) is not int for number in security['fri'].values())
            or (shape['base_trace_rows'], shape['main_width'], shape['preprocessed_width']) != (rows, main, pre)):
        raise ValueError('Native actual-AIR security or shape changed')
    key = value['public_verifier_key']
    if set(key) != {'encoding', 'hex', 'sha256', 'width', 'degree_bits'} or key['encoding'] != 'SWMP-v1':
        raise ValueError('Unexpected native public-key fields')
    raw = bytes.fromhex(key['hex'])
    if not 48 <= len(raw) <= 4143 or raw[:7] != b'SWMP\x01\x00' + bytes([index + 1]):
        raise ValueError('Native public-key header or length changed')
    if int.from_bytes(raw[7:11], 'little') != CAPACITIES[index]:
        raise ValueError('Native public-key capacity changed')
    words = [int.from_bytes(raw[i:i+4], 'little') for i in range(11, 47, 4)]
    if (words[:6] != [p[n] for n in ('log_blowup', 'num_queries', 'query_pow_bits',
                                    'commit_pow_bits', 'batch_pow_bits', 'max_log_arity')]
            or words[6:] != [pre, rows.bit_length(), len(raw) - 47]
            or key['width'] != pre or key['degree_bits'] != rows.bit_length()
            or key['sha256'] != hashlib.sha256(raw).hexdigest()):
        raise ValueError('Native public-key dimensions, parameters or hash changed')
    # Preserve and reproduce the original transaction commitment; no existing
    # proof profile, public verifier key or measured source is rewritten.
    if kind == 'transaction':
        original = bytes.fromhex(transaction['public_verifier_key']['hex'])
        if raw[47:] != original[43:] or summary != transaction['selected_security']:
            raise ValueError('Transaction key or security differs from frozen profile')
    return value


def economic_performance(transaction, kind):
    entry = transaction['repeated_measurements'][kind]
    if entry.get('measured') is not True or set(entry.get('workers', {})) != {'1', '4'}:
        raise ValueError('Fresh one-worker and four-worker measurements required')
    result = {}
    for workers, group in entry['workers'].items():
        summary = group['summary']
        if (set(summary) != PERFORMANCE_KEYS or summary['complete'] is not True
                or type(summary['trial_count']) is not int or summary['trial_count'] != 3
                or summary['acceptance'] is not False):
            raise ValueError('Incomplete native three-trial performance summary')
        numbers = {name: value for name, value in summary.items()
                   if name not in ('complete', 'trial_count', 'acceptance')}
        if any(type(value) is not int or value <= 0 for value in numbers.values()):
            raise ValueError('Native performance fields must be positive integer measurements')
        if (summary['generation_min_ns'] > summary['generation_median_ns']
                or summary['generation_median_ns'] > summary['generation_max_ns']
                or summary['memory_peak_median_bytes'] > summary['memory_peak_max_bytes']
                or summary['proof_bytes_min'] > summary['proof_bytes_max']
                or summary['memory_peak_max_bytes'] > 5368709120
                or summary['proof_bytes_max'] > (655360 if kind == 'transaction' else 524288)
                or (kind == 'transaction' and workers == '4' and summary['generation_max_ns'] > 2000000000)):
            raise ValueError('Native performance limits or summary order changed')
        result[workers] = {name: value for name, value in summary.items() if name != 'acceptance'}
    return result


def economic_relation(value, kind, transaction, freeze, reproduced=False):
    """Check genuine key-tool output, then retain only the public relation fields."""
    expected = RELATION_KEYS if reproduced else RELATION_KEYS | {'performance'}
    if reproduced and set(value) == RELATION_KEYS | {'status', 'acceptance'}:
        if value['status'] != 'candidate-pending-review' or value['acceptance'] is not False:
            raise ValueError('Unexpected candidate key status or acceptance claim')
    elif set(value) != expected:
        raise ValueError('Unexpected revised native relation fields')
    index = KINDS.index(kind)
    measured = transaction['repeated_measurements'][kind]
    p = measured['parameters']
    if (value['kind'] != kind or type(value['capacity']) is not int
            or value['capacity'] != CAPACITIES[index] or value['parameters'] != p
            or not isinstance(value['parameters'], dict)
            or any(type(number) is not int for number in value['parameters'].values())
            or not isinstance(p, dict) or any(type(number) is not int for number in p.values())
            or value['cryptographic_approval'] is not False or value['network_activation'] is not False):
        raise ValueError('Revised native identity or measured parameters changed')
    if kind == 'transaction' and p != transaction['parameters']:
        raise ValueError('Native transaction parameters differ from measured selection')
    security = value['security']
    summary = freeze.MEASUREMENT.security_summary(security)
    shape = summary['shape']
    rows, main, pre = ECONOMICS_SHAPES[index]
    dimensions = (shape['base_trace_rows'], shape['main_width'], shape['preprocessed_width'])
    if (not summary['screen']['passes_selected_model'] or security.get('fri') != p
            or not isinstance(security.get('fri'), dict)
            or any(type(number) is not int for number in security['fri'].values())
            or dimensions != (rows, main, pre) or any(type(number) is not int for number in dimensions)
            or type(shape['public_values']) is not int
            or shape['public_values'] != ECONOMICS_PUBLIC_VALUES[index]
            or summary != measured['security']):
        raise ValueError('Revised actual-AIR security, measured report or shape changed')
    key = value['public_verifier_key']
    if (not isinstance(key, dict) or set(key) != {'encoding', 'hex', 'sha256', 'width', 'degree_bits'}
            or key['encoding'] != 'SWMP-v1' or not isinstance(key['hex'], str)
            or type(key['width']) is not int or type(key['degree_bits']) is not int):
        raise ValueError('Unexpected revised native public-key fields')
    raw = bytes.fromhex(key['hex'])
    if not 48 <= len(raw) <= 4143 or raw[:7] != b'SWMP\x01\x00' + bytes([index + 1]):
        raise ValueError('Revised native public-key header or length changed')
    if int.from_bytes(raw[7:11], 'little') != CAPACITIES[index]:
        raise ValueError('Revised native public-key capacity changed')
    words = [int.from_bytes(raw[i:i+4], 'little') for i in range(11, 47, 4)]
    if (words[:6] != [p[name] for name in ('log_blowup', 'num_queries', 'query_pow_bits',
                                        'commit_pow_bits', 'batch_pow_bits', 'max_log_arity')]
            or words[6:] != [pre, rows.bit_length(), len(raw) - 47]
            or key['width'] != pre or key['degree_bits'] != rows.bit_length()
            or key['sha256'] != hashlib.sha256(raw).hexdigest()):
        raise ValueError('Revised native key parameters, dimensions or hash changed')
    if kind == 'transaction':
        original = bytes.fromhex(transaction['public_verifier_key']['hex'])
        if raw[47:] != original[43:] or summary != transaction['selected_security']:
            raise ValueError('Revised transaction key differs from the selected public verifier')
    clean_security = {**summary, 'shape': {'status': 'actual-extracted', **shape}, 'fri': p}
    result = {name: value[name] for name in RELATION_KEYS}
    result.update(security=clean_security, performance=economic_performance(transaction, kind))
    if not reproduced and result != value:
        raise ValueError('Revised native manifest includes unbound or nonpublic relation fields')
    return result


def create_economics(reproduced, transaction, freeze, root=ROOT):
    if transaction.get('relation_revision') != ECONOMICS_REVISION:
        raise ValueError('Unexpected transaction economic revision')
    relations = [economic_relation(json.loads((reproduced / (kind + '.json')).read_text()),
        kind, transaction, freeze, reproduced=True) for kind in KINDS]
    return {'schema': 2, 'status': 'engineering-frozen-native-relations',
        'relation_revision': ECONOMICS_REVISION, 'suite': freeze.SUITE,
        'cryptographic_approval': False, 'network_activation': False,
        'transaction_profile': TRANSACTION, 'transaction_profile_sha256': sha(root / TRANSACTION),
        'tool_source_sha256': tool_hashes(root),
        'scope': 'transaction; settlement at 576 positions; issuance at three initial notes',
        'resource_qualification': ECONOMICS_RESOURCES,
        'verification_measurement': transaction['verification_measurement'],
        'verification_only_process': False, 'node_integration': False, 'relations': relations}


def validate_economics(value, root=ROOT, reproduced=None):
    expected = {'schema', 'status', 'relation_revision', 'suite', 'cryptographic_approval',
        'network_activation', 'transaction_profile', 'transaction_profile_sha256', 'tool_source_sha256',
        'scope', 'resource_qualification', 'verification_measurement', 'verification_only_process',
        'node_integration', 'relations'}
    if set(value) != expected or type(value['schema']) is not int or value['schema'] != 2:
        raise ValueError('Unexpected revised native manifest schema')
    freeze = freeze_module(root)
    transaction = transaction_profile(root)
    if transaction.get('schema') != 2 or transaction.get('relation_revision') != ECONOMICS_REVISION:
        raise ValueError('Revised native manifest requires the revised transaction profile')
    wanted = {'status': 'engineering-frozen-native-relations', 'relation_revision': ECONOMICS_REVISION,
        'suite': freeze.SUITE, 'transaction_profile': TRANSACTION,
        'transaction_profile_sha256': sha(root / TRANSACTION),
        'scope': 'transaction; settlement at 576 positions; issuance at three initial notes',
        'resource_qualification': ECONOMICS_RESOURCES,
        'verification_measurement': transaction['verification_measurement']}
    check_tool_hashes(value['tool_source_sha256'], root)
    if any(value[name] != expected_value for name, expected_value in wanted.items()):
        raise ValueError('Revised native source, measurement scope or revision changed')
    if any(value[name] is not False for name in ('cryptographic_approval', 'network_activation',
                                                'node_integration', 'verification_only_process')):
        raise ValueError('Revised native freeze cannot claim approval, integration or activation')
    if not isinstance(value['relations'], list) or len(value['relations']) != len(KINDS):
        raise ValueError('Exactly three revised native relations required')
    for kind, relation in zip(KINDS, value['relations']):
        economic_relation(relation, kind, transaction, freeze)
        if reproduced is not None:
            actual = economic_relation(json.loads((reproduced / (kind + '.json')).read_text()),
                kind, transaction, freeze, reproduced=True)
            if actual != relation:
                raise ValueError('Reproduced revised native key or security differs')
    return value


def create(reproduced, root=ROOT):
    freeze = freeze_module(root)
    transaction = transaction_profile(root)
    if transaction.get('schema') == 2:
        return create_economics(reproduced, transaction, freeze, root)
    relations = [validate_relation(json.loads((reproduced / (kind + '.json')).read_text()),
                                   kind, transaction, freeze) for kind in KINDS]
    return {'schema': 1, 'status': 'engineering-frozen-native-relations',
            'suite': freeze.SUITE, 'cryptographic_approval': False, 'network_activation': False,
            'transaction_profile': TRANSACTION, 'transaction_profile_sha256': sha(root / TRANSACTION),
            'tool_source_sha256': tool_hashes(root),
            'scope': 'transaction; settlement at 576 positions; issuance at three initial notes',
            'resource_qualification': 'existing isolated diagnostics; no new performance measurement',
            'node_integration': False, 'relations': relations}


def validate(value, root=ROOT, reproduced=None):
    if value.get('schema') == 2:
        return validate_economics(value, root, reproduced)
    expected = {'schema', 'status', 'suite', 'cryptographic_approval', 'network_activation',
                'transaction_profile', 'transaction_profile_sha256', 'tool_source_sha256',
                'scope', 'resource_qualification', 'node_integration', 'relations'}
    if set(value) != expected or type(value['schema']) is not int or value['schema'] != 1:
        raise ValueError('Unexpected native freeze manifest schema')
    freeze = freeze_module(root)
    transaction = transaction_profile(root)
    check_tool_hashes(value['tool_source_sha256'], root)
    for name, wanted in {'status': 'engineering-frozen-native-relations', 'suite': freeze.SUITE,
                         'transaction_profile': TRANSACTION,
                         'transaction_profile_sha256': sha(root / TRANSACTION),
                         'scope': 'transaction; settlement at 576 positions; issuance at three initial notes',
                         'resource_qualification': 'existing isolated diagnostics; no new performance measurement'}.items():
        if value[name] != wanted:
            raise ValueError('Native manifest source, scope or status changed')
    if any(value[n] is not False for n in ('cryptographic_approval', 'network_activation', 'node_integration')):
        raise ValueError('Native freeze cannot claim approval, integration or activation')
    if not isinstance(value['relations'], list) or len(value['relations']) != 3:
        raise ValueError('Exactly three fixed native relations required')
    for kind, relation in zip(KINDS, value['relations']):
        validate_relation(relation, kind, transaction, freeze)
        if reproduced is not None and relation != json.loads((reproduced / (kind + '.json')).read_text()):
            raise ValueError('Reproduced native key or security report differs')
    return value


def prepare(output, root=ROOT):
    transaction_profile(root)
    output.mkdir(parents=True, exist_ok=False)
    application = root / 'crates/bench-multi-asset'
    text = (application / 'Cargo.toml').read_text()
    text = text.replace('[package]\n', '[package]\nautobins = false\n', 1)
    text = text.replace('path = "../native-proof"', 'path = ' + json.dumps(str(root / 'crates/native-proof')))
    text += '\n[lib]\npath = ' + json.dumps(str(application / 'src/lib.rs')) + '\n'
    text += '\n[[bin]]\nname = "native-proof-artifacts"\npath = ' + json.dumps(str(root / 'scripts/bench/native-proof-artifacts.rs')) + '\n'
    text += '\n[[test]]\nname = \"public_codec_rejections\"\npath = ' + json.dumps(str(root / 'crates/bench-multi-asset/tests/public_codec_rejections.rs')) + '\n'
    (output / 'Cargo.toml').write_text(text)
    shutil.copyfile(application / 'Cargo.lock', output / 'Cargo.lock')
    return output / 'Cargo.toml'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', type=Path)
    mode.add_argument('--create', type=Path, metavar='REPRODUCED_DIRECTORY')
    mode.add_argument('--check', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--reproduced', type=Path)
    args = parser.parse_args()
    if args.prepare:
        if args.output or args.reproduced:
            parser.error('prepare accepts only its output directory')
        print(prepare(args.prepare))
    elif args.create:
        if not args.output or args.reproduced:
            parser.error('create requires output and no reproduced option')
        value = create(args.create)
        validate(value)
        with args.output.open('x') as stream:
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.write('\n')
        print('Three source-bound native engineering relations recorded.')
    else:
        if args.output:
            parser.error('output is only valid with create')
        validate(json.loads(args.check.read_text()), reproduced=args.reproduced)
        print('Native relation parameters, source identity and public keys validated.')


if __name__ == '__main__':
    main()
