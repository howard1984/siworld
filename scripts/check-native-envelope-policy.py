#!/usr/bin/env python3
"""Check native runtime admission limits without rewriting measured profiles.

Policy version one increases only the runtime settlement-proof body allowance.
The source-bound measurement artifacts, AIR, preprocessing keys and FRI profiles
remain immutable. This check does not establish resource or network acceptance.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
POLICY_VERSION = 1
MANIFEST = 'crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json'
MANIFEST_SHA256 = 'c50622d69bdb6db816121dd716255f64ab796c37fdab8a96675e34875ecb8664'
WIRE = 'crates/native-node/src/wire.rs'
CODEC = 'crates/native-node/src/proof_codec.rs'
PROOFS = 'crates/native-node/src/proofs.rs'
ISSUANCE = 'crates/native-node/src/issuance.rs'
BODY_LIMITS = {'transaction': 655_360, 'settlement': 655_360, 'issuance': 524_288}
SETTLEMENT_MEASUREMENT_LIMIT = 589_824
PARAMETERS = {'transaction': (7, 41), 'settlement': (8, 36)}


def read(root, name):
    path = root / name
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Policy source escapes repository root')
    return path.read_bytes()


def integer_expression(expression):
    """Accept only integer literals, addition and multiplication; never eval."""
    def value(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mult)):
            left, right = value(node.left), value(node.right)
            return left + right if isinstance(node.op, ast.Add) else left * right
        raise ValueError('Unexpected runtime admission constant expression')
    try:
        return value(ast.parse(expression, mode='eval').body)
    except (SyntaxError, TypeError) as error:
        raise ValueError('Invalid runtime admission constant expression') from error


def constant(source, name):
    matches = re.findall(r'\bconst\s+' + re.escape(name)
                         + r'\s*:\s*usize\s*=\s*([^;]+);', source)
    if len(matches) != 1:
        raise ValueError('Missing or ambiguous runtime admission constant: ' + name)
    return integer_expression(matches[0].strip())


def require_constant(source, name, expected):
    if constant(source, name) != expected:
        raise ValueError('Runtime admission constant differs: ' + name)


def validate(root=ROOT):
    manifest_bytes = read(root, MANIFEST)
    if hashlib.sha256(manifest_bytes).hexdigest() != MANIFEST_SHA256:
        raise ValueError('Immutable measured native manifest changed')
    manifest = json.loads(manifest_bytes)
    profile_bytes = read(root, manifest['transaction_profile'])
    if hashlib.sha256(profile_bytes).hexdigest() != manifest['transaction_profile_sha256']:
        raise ValueError('Immutable measured transaction profile changed')
    profile = json.loads(profile_bytes)
    if profile['max_settlement_proof_bytes'] != 524_288:
        raise ValueError('Historical measured settlement admission value changed')
    adapter = read(root, PROOFS).decode()
    manifest_pins = re.findall(r'\bMANIFEST_SHA256\s*:\s*&str\s*=\s*"([a-f0-9]{64})"', adapter)
    if manifest_pins != [MANIFEST_SHA256]:
        raise ValueError('Runtime verifier does not authenticate the measured manifest')
    require_constant(adapter, 'SETTLEMENT_CAPACITY', 576)
    for kind, (blowup, queries) in PARAMETERS.items():
        relation = next(entry for entry in manifest['relations'] if entry['kind'] == kind)
        expected = dict(log_blowup=blowup, num_queries=queries, query_pow_bits=20,
                        commit_pow_bits=0, batch_pow_bits=20, max_log_arity=1,
                        log_final_poly_len=0)
        if relation['parameters'] != expected:
            raise ValueError('Measured native FRI profile differs: ' + kind)
        raw = bytes.fromhex(relation['public_verifier_key']['hex'])
        words = [int.from_bytes(raw[offset:offset + 4], 'little') for offset in range(11, 35, 4)]
        if words != [blowup, queries, 20, 0, 20, 1]:
            raise ValueError('Measured native key header differs: ' + kind)
        if adapter.count('"' + relation['public_verifier_key']['hex'] + '"') != 1:
            raise ValueError('Runtime native public key differs: ' + kind)
        selections = re.findall(r'Self::' + kind.title() + r'\s*=>\s*\((\d+),\s*(\d+)\)', adapter)
        if selections != [(str(blowup), str(queries))]:
            raise ValueError('Runtime native FRI selection differs: ' + kind)
    fri = re.findall(r'\bFriParams\s*\{([^}]+)\}', adapter)
    for name, expected in (('query_pow_bits', 20), ('commit_pow_bits', 0),
                           ('batch_pow_bits', 20), ('max_log_arity', 1)):
        values = re.findall(r'\b' + name + r'\s*:\s*(\d+)\s*,', '\n'.join(fri))
        if values != [str(expected)]:
            raise ValueError('Runtime native FRI field differs: ' + name)
    for kind, arguments in (('transaction', r'Relation::Transaction\.params\(\)'),
                            ('settlement', r'SETTLEMENT_CAPACITY,\s*Relation::Settlement\.params\(\)')):
        constructor = (r'let\s+' + kind + r'\s*=\s*' + kind.title()
                       + r'Prover::new\(\s*' + arguments + r'\s*\)\s*;')
        if len(re.findall(constructor, adapter)) != 1:
            raise ValueError('Runtime prover does not use the fixed native profile: ' + kind)
    wire = read(root, WIRE).decode()
    codec = read(root, CODEC).decode()
    issuance = read(root, ISSUANCE).decode()
    for name, expected in (('MAX_TX_PROOF', BODY_LIMITS['transaction']),
                           ('MAX_SETTLEMENT_PROOF', BODY_LIMITS['settlement']),
                           ('MIN_SLOTS', 64), ('MAX_SLOTS', 576), ('GROUP', 16)):
        require_constant(wire, name, expected)
    for name, kind in (('MAX_TRANSACTION_PROOF_BODY_LEN', 'transaction'),
                       ('MAX_SETTLEMENT_PROOF_BODY_LEN', 'settlement'),
                       ('MAX_ISSUANCE_PROOF_BODY_LEN', 'issuance')):
        require_constant(codec, name, BODY_LIMITS[kind])
    require_constant(codec, 'MAX_DECLARED_VECTOR_BYTES', 4_194_304)
    require_constant(issuance, 'MAX_PROOF_BYTES', BODY_LIMITS['issuance'])
    if SETTLEMENT_MEASUREMENT_LIMIT != BODY_LIMITS['settlement'] * 90 // 100:
        raise ValueError('Settlement measurement headroom changed')
    return {'policy_version': POLICY_VERSION, 'manifest_sha256': MANIFEST_SHA256,
            'proof_body_limits_bytes': dict(BODY_LIMITS), 'settlement_capacity': 576,
            'required_settlement_three_trial_maximum_bytes': SETTLEMENT_MEASUREMENT_LIMIT,
            'resource_acceptance': False, 'network_activation': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    validate()
    print('Native envelope policy version 1 and unchanged measured proof identities validated; '
          'resource acceptance remains a separate measured gate.')


if __name__ == '__main__':
    main()
