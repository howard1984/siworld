"""Validate engineering-frozen V1 sources, public verifier keys and resource policy."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('frozen_source_relocations', ROOT / 'scripts/frozen-source-relocations.py')
RELOCATIONS = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(RELOCATIONS)
DEFAULT = Path('crates/bench-d8/artifacts/v1-native-freeze.json')
PARAMETERS = dict(log_blowup=8, num_queries=36, query_pow_bits=20,
                  commit_pow_bits=0, batch_pow_bits=20, max_log_arity=1,
                  log_final_poly_len=0)
REQUIRED_SOURCES = {
    'crates/bench-d8/' + name for name in ('Cargo.toml', 'Cargo.lock',
        'src/lib.rs', 'src/common.rs', 'src/air.rs', 'src/trace.rs',
        'src/transaction.rs', 'src/codec.rs', 'src/encryption.rs',
        'src/envelope.rs', 'src/padding_pool.rs', 'src/snapshots.rs',
        'src/proof_codec.rs', 'src/fee_settlement.rs', 'src/fee_settlement_air.rs',
        'src/native_security.rs', 'src/native_verifier.rs', 'src/bin/v1-freeze-artifacts.rs',
        'src/bin/native-verifier-bench.rs', 'src/bin/v1_transaction_scan.rs', 'src/bin/fee-settlement-bench.rs')
} | {'.cargo/config.toml', 'rust-toolchain.toml', 'scripts/check-v1-freeze.py', 'scripts/measure-native-cgroup.py',
     'scripts/build-d8-checkpoint.py', 'scripts/build-prover-release.py',
     'scripts/prover-launcher.rs', '.github/workflows/d8-native-cgroup.yml'}


def validate(value, root=ROOT):
    if value.get('schema') != 1 or value.get('status') != 'engineering-frozen':
        raise ValueError('engineering-frozen schema required')
    if value.get('cryptographic_approval') is not False or value.get('network_activation') is not False:
        raise ValueError('engineering freeze cannot assert audit approval or activation')
    if value.get('dependency_revision') != 'd3d15b2b5d1325fb38ebc8979c1cae04b761e71f':
        raise ValueError('unexpected dependency revision')
    if value.get('resource_policy') != 'local-admission-and-process-isolation-not-consensus-validity':
        raise ValueError('unexpected resource policy')
    if value.get('parameters') != PARAMETERS:
        raise ValueError('unexpected frozen FRI parameters')
    sources = value.get('source_sha256', {})
    if set(sources) != REQUIRED_SOURCES:
        raise ValueError('incomplete or unexpected source boundary')
    for name, expected in sources.items():
        path = root / name
        if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
            raise ValueError('source escapes fixed root')
        if not RELOCATIONS.matches(root, name, path.read_bytes(), expected):
            raise ValueError('frozen source changed: ' + name)
    envelope = value.get('envelope', {})
    for name, expected in dict(version=1, prefix_bytes=1899, max_bytes=526187,
            sidecar_bytes=78, permanent_transaction_bytes=1830,
            settlement_prefix_bytes=159, settlement_max_bytes=524447,
            fee_blind_field_elements=8, transaction_id_excludes_proof_and_sidecar=True).items():
        if envelope.get(name) != expected:
            raise ValueError('frozen envelope differs: ' + name)
    for kind, expected_type in (('transaction', 1), ('settlement', 2)):
        profile = value['profiles'][kind]
        raw = bytes.fromhex(profile['verifier_artifact_hex'])
        if not 43 <= len(raw) <= 4139 or raw[:7] != b'SWVK\x01\x00' + bytes([expected_type]):
            raise ValueError('invalid public verifier artifact')
        if hashlib.sha256(raw).hexdigest() != profile['verifier_artifact_sha256']:
            raise ValueError('public verifier artifact hash mismatch')
        if int.from_bytes(raw[39:43], 'little') != len(raw) - 43:
            raise ValueError('public verifier artifact length mismatch')
        words = [int.from_bytes(raw[o:o+4], 'little') for o in range(7, 31, 4)]
        if words != [8, 36, 20, 0, 20, 1]:
            raise ValueError('public verifier artifact profile mismatch')
        security = profile['security']
        screen = security['screen']
        if security['p3_security_version'] != '0.9.0-rc.2' or security['fri'] != PARAMETERS:
            raise ValueError('security report profile mismatch')
        for name, minimum in dict(classical_conjectured_union_bits=128,
                classical_johnson_union_bits=100,
                quantum_johnson_challenge_union_bits=80, bht_collision_bits=80).items():
            bits = screen[name]
            if not isinstance(bits, (int, float)) or not minimum <= bits < 10000:
                raise ValueError('security term below target: ' + name)
        if screen.get('passes_selected_model') is not True or security['shape']['status'] != 'actual-extracted':
            raise ValueError('actual AIR security screen required')
    resources = value['resources']
    for name, expected in dict(max_leaf_proof_bytes=524288, max_settlement_proof_bytes=524288,
            proof_decoder_declared_vector_bytes=4194304,
            verifier_process_memory_bytes=134217728, verifier_cpu_ms=250,
            verifier_wall_timeout_ms=2000, verifier_processes=2,
            block576_transaction_cpu_ms=144000, block576_with_settlement_cpu_ms=144250,
            verified_pool_bytes=536870912, verified_pool_count=2048,
            unverified_queue_bytes=67108864, unverified_queue_count=128,
            peer_unverified_bytes=2097152, peer_unverified_count=4,
            peer_verified_bytes=16777216, peer_verified_count=64,
            negative_cache_bytes=1048576, negative_cache_count=8192, negative_cache_ttl_seconds=300,
            abuse_cache_bytes=1048576, abuse_cache_count=4096, abuse_cache_ttl_seconds=600,
            reconstruction_bytes=671088640, reconstruction_blocks=2,
            padding_pool_min=64, padding_pool_max=128, padding_pool_bytes=68157440,
            minimum_uplink_bps=25000000, max_block_slots=576, block_target_seconds=300,
            maximum_reorg_depth=24, proof_retention_seconds_after_finality=2419200).items():
        if resources.get(name) != expected:
            raise ValueError('frozen resource policy differs: ' + name)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=DEFAULT)
    args = parser.parse_args()
    validate(json.loads(args.manifest.read_text()))
    print('V1 engineering profile, source hashes, security screens and public key encodings validated.')


if __name__ == '__main__':
    main()
