"""Exact source identities for dependency relocation and offline-check adapters.

Historical measurement records are immutable. These pairs cover only reviewed
URL changes and the validators that read those records. No AIR, proof parameter,
registry package version or runtime Rust source is covered by an exception.
"""
import hashlib
import tomllib

SOURCE_PAIRS = {'crates/bench-d8/Cargo.lock': {'66ac717f68367604fe91cd20270c67ad2f8a5a0d76471fc29411b7bb752fbbb5': '98f5f1898071a03a779a9010b91b34623c0fd78681daaf7cacdc770cb9fa1ba4'}, 'crates/bench-d8/Cargo.toml': {'4b8db86ab2b7aa6582374d8c79f66e45a52cdaca08ae20a5ca954626e2328761': '15dc61c603f50bd7f57733c395a767937729c81f1a93fbea2c60dc9e3341f6fd'}, 'crates/bench-multi-asset/Cargo.lock': {'f19f34ddfd3d5ff8ee91c7a742aa75d25c54bddfb0762cef1dda30a63894ec6e': '1dbb86942fec657e1fe5c7c3d24bc81a08919cf1cc8512aa0fbb8d54944ed2b7'}, 'crates/bench-multi-asset/Cargo.toml': {'5283ec818eb517a3d2af73bb71e88e36e20fbc3473e6a58844bc798f05b82cb3': 'af055305677e727a4566d0f7901f0ec03658ee566c9f13577d7ac088e5d6a983'}, 'scripts/build-d8-checkpoint.py': {'4dd93b79d2f048b70ce89b8013a662849ee4acd60ef2da51a4aa7bdcafe364ae': 'bf9d91f72bd9544eafa4a67f2864bb7bc24fa9cf77e0bf5b3099e94ba003819c'}, 'scripts/check-v1-freeze.py': {'44f488166c8af5d0b804d31540c000451a633de7323bae4037c60223fb28405a': 'beb4b120a84d4e7447a7ea0b0109282d80369173111e8769b5cda1bd027d3d13'}, 'scripts/freeze-multi-asset.py': {'4607a99d9be9c97a47185e83ae1f5732f56789fdddf6bd13d11f03911bce33c6': 'e59db62d28072e35ef7c17845ef2e21ff62bdcc98356e3e2c5314b5bc4f4910a'}}
RETIRED = frozenset(('d8-native-cgroup.yml', 'multi-asset-native.yml', 'v1-economics.yml'))


def canonical_path(name):
    prefix = 'scripts/tests/fixtures/retired-workflows/'
    if name.startswith(prefix) and name[len(prefix):] in RETIRED:
        return '.github/workflows/' + name[len(prefix):]
    return name


def canonical_sources(names):
    result = {}
    for name in names:
        canonical = canonical_path(name)
        if canonical in result:
            raise ValueError('Ambiguous historical source path')
        result[canonical] = name
    return result


def fixed_dependency(root):
    value = tomllib.loads((root / 'crates/bench-d8/dependency-lineage.toml').read_text())
    return (value.get('source_url') == 'https://github.com/howard1984/siworld'
        and value.get('source_revision') == value.get('downstream_revision')
        == 'd3d15b2b5d1325fb38ebc8979c1cae04b761e71f'
        and value.get('downstream_tree') == '11f7507a135f825a2ba6c790b9ad6d50a4e40b81'
        and value.get('patch_file') == 'crates/bench-stark/patches/recursion-d8-w24.patch'
        and value.get('patch_sha256') == '78cc3dc553120147bd3b87371533a3769beed2e62ec034bff5a6378528007c3d'
        and hashlib.sha256((root / value['patch_file']).read_bytes()).hexdigest() == value['patch_sha256'])


def matches(root, name, body, expected):
    actual = hashlib.sha256(body).hexdigest()
    if actual == expected:
        return True
    return (SOURCE_PAIRS.get(name, {}).get(expected) == actual and fixed_dependency(root))


def mapping_matches(root, expected, names, loader):
    return (isinstance(expected, dict) and set(expected) == set(names)
        and all(matches(root, name, loader(root, name), expected[name]) for name in names))
