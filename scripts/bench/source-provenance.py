"""Exact source identities for dependency relocation and offline-check adapters.

Historical measurement records are immutable. These pairs cover only reviewed
URL changes and the validators that read those records. No AIR, proof parameter,
registry package version or runtime Rust source is covered by an exception.
"""
import hashlib
import tomllib

# These exact transitions cover publication path and tool-name updates.
# Historical pins and the pinned dependency tree remain mandatory.
SOURCE_PAIRS = {
    'crates/bench-d8/Cargo.lock': {
        '66ac717f68367604fe91cd20270c67ad2f8a5a0d76471fc29411b7bb752fbbb5':
            '587e53ebc0a909157f96268ebc3ce7b9c77a65ac0d0475f5379db07b61a133ee',
        '98f5f1898071a03a779a9010b91b34623c0fd78681daaf7cacdc770cb9fa1ba4':
            '587e53ebc0a909157f96268ebc3ce7b9c77a65ac0d0475f5379db07b61a133ee',
    },
    'crates/bench-d8/Cargo.toml': {
        '15dc61c603f50bd7f57733c395a767937729c81f1a93fbea2c60dc9e3341f6fd':
            'dce1d796aeb6d930ceb9e9a7360e4534f64a0ce8bbd7cd2b4d51102b6efb109b',
        '4b8db86ab2b7aa6582374d8c79f66e45a52cdaca08ae20a5ca954626e2328761':
            'dce1d796aeb6d930ceb9e9a7360e4534f64a0ce8bbd7cd2b4d51102b6efb109b',
    },
    'crates/bench-d8/src/bin/checkpoint.rs': {
        '5e92666a8284666fcf4adb32e1394d8a55dea63992583284132cb5517ae78a24':
            '012837f50e78cbef8055a6c92755bb0187279c6873f069d662098ed96affb095',
    },
    'crates/bench-d8/src/bin/fee-settlement-bench.rs': {
        '91d5a0799665ad2899ccbf31dc36dcc1979a1f65d61b23afcc1342a891a5110f':
            '2b8fcc018eaeb814c732a6bf7418c0a1d0ac27143404a0b2617777dc4b496dda',
    },
    'crates/bench-d8/src/bin/native-verifier-bench.rs': {
        'd1eda805b0ede8e5510c04b2c6d82729c988a43b75d2fc2d0d688f9542f944d5':
            '2956856be84dc5df9803a6ca97d085b1103c0b2f613c03f316abaedb01668f9b',
    },
    'crates/bench-d8/src/bin/v1-freeze-artifacts.rs': {
        '8abf8a779a4f51469e4a60eba3400c812679d75e928fa9d633d2a92b5df62643':
            '60b7c20aba0a7bfaf834f48e515b18e40c2fbce7fb2db9b3897c8c8752396889',
    },
    'crates/bench-d8/src/bin/v1_transaction_scan.rs': {
        '1858f0b0ea5b08fe202af15c11b27f07c26ae9176af1996f480f1932c9dd257e':
            '0e68afd68cbd6d837f8eba19add74a34eff5ab4a08853a573f3c519ec036a3c4',
    },
    'crates/bench-multi-asset/Cargo.lock': {
        '1dbb86942fec657e1fe5c7c3d24bc81a08919cf1cc8512aa0fbb8d54944ed2b7':
            '03ea9e74c10eec2950c7f98029dc2d7c59e2b74e0f742a90fab77a08d636fa24',
        'f19f34ddfd3d5ff8ee91c7a742aa75d25c54bddfb0762cef1dda30a63894ec6e':
            '03ea9e74c10eec2950c7f98029dc2d7c59e2b74e0f742a90fab77a08d636fa24',
    },
    'crates/bench-multi-asset/Cargo.toml': {
        '5283ec818eb517a3d2af73bb71e88e36e20fbc3473e6a58844bc798f05b82cb3':
            'f12186c5079857c6db641faab37ef5d70e74e2395b0b5113f345e7b59901eadc',
        'af055305677e727a4566d0f7901f0ec03658ee566c9f13577d7ac088e5d6a983':
            'f12186c5079857c6db641faab37ef5d70e74e2395b0b5113f345e7b59901eadc',
    },
    'scripts/build-composition-intra.py': {
        'b77f4b77209a33b9de12ac7287a69644aa6fca2a41c3f8bb37849fdfc7bf7c3b':
            '6af64cb8a906c345fc4ccd2b2f0115315143b6cc1ecc04cadcd1ab55d22b1cb3',
    },
    'scripts/build-d8-checkpoint.py': {
        '4dd93b79d2f048b70ce89b8013a662849ee4acd60ef2da51a4aa7bdcafe364ae':
            'a76c7f80a410ee0a7322707106ad525651108d78b3d88fea82c9f48e18c9af6c',
        'bf9d91f72bd9544eafa4a67f2864bb7bc24fa9cf77e0bf5b3099e94ba003819c':
            'a76c7f80a410ee0a7322707106ad525651108d78b3d88fea82c9f48e18c9af6c',
    },
    'scripts/build-prover-release.py': {
        '88b76809b4700c4ed33ce96c9c5a84ec2ba73781380420459282a119b2be6fba':
            'd36e35b4b16ab82170fcae42bdb188f90cec3919a87fa356ca2da53679baafd8',
    },
    'scripts/check-native-proof-profiles.py': {
        'd5163be57866ad4ae0f9a09fd90829fcbd16f5ce35a8114fa1efa146b5ab483b':
            'f086c90b0d258a822a45291b419f8e7fb4a36a3cee9c9348894e907a1eb40df1',
    },
    'scripts/check-v1-freeze.py': {
        '44f488166c8af5d0b804d31540c000451a633de7323bae4037c60223fb28405a':
            '3673d6a75d625897ce3de911de77a63d86f6a627c65969c2359c1d94d25e81a6',
        'beb4b120a84d4e7447a7ea0b0109282d80369173111e8769b5cda1bd027d3d13':
            '3673d6a75d625897ce3de911de77a63d86f6a627c65969c2359c1d94d25e81a6',
    },
    'scripts/freeze-multi-asset.py': {
        '4607a99d9be9c97a47185e83ae1f5732f56789fdddf6bd13d11f03911bce33c6':
            '61ca4f995581dd4a7dad278be0ada4b7178bab209a142d65960637dc948be2a9',
        'e59db62d28072e35ef7c17845ef2e21ff62bdcc98356e3e2c5314b5bc4f4910a':
            '61ca4f995581dd4a7dad278be0ada4b7178bab209a142d65960637dc948be2a9',
    },
    'scripts/measure-multi-asset.py': {
        'e56706434bf62640b4d129d3439424f05f9abe72ae8b0cd38b7439d514a8ad6b':
            '569e830eabc28f1a2af36b3a0a8cae9e59b9567fef49bd20fdd0a6e2c9d0e4a3',
    },
    'scripts/measure-native-cgroup.py': {
        'a1d610ce60aa855e958956fc9400ea3ce9dc8bddbf17f00b735b6aca22d66efc':
            '17d3971368a047eb3f5311897eb075bab414e46c236defaa070f010518249a64',
    },
    'scripts/native-proof-artifacts.rs': {
        '413ac7df4d85a1ea1203603da0ead53466548aa246eae9965f341105b08899e8':
            '691babd6abfa459d2df3b12e15db74da0a9db1a402bbcf179f4fd0361b8db50a',
    },
    'scripts/prover-launcher.rs': {
        'e2ececc1547045c2966f0cc5d09321e823bed1d20a050abcb9439263bed5a8dd':
            'aa4c5fd343240f9ca6df30b8be96de57a67b01ad6d1d13c2eab60bdaaeb88a35',
    },
    'scripts/v1-economics-candidate.py': {
        'fa835a86a6e276ef02f35fedaa58db59e152fb8c0f2feedbf3ee18635612e345':
            '9e39834f15a7100211ec26f8cd7b6e8405e1100e8e52b16e7289fb1c53af7723',
    },
}


# Historical manifests retain their recorded path keys and exact fixture bytes.
WORKFLOW_FIXTURES = {
    '.github/workflows/d8-native-cgroup.yml': 'scripts/tests/fixtures/source-provenance/recursive-proof-workflow.txt',
    '.github/workflows/multi-asset-native.yml': 'scripts/tests/fixtures/source-provenance/multi-asset-workflow.txt',
    '.github/workflows/v1-economics.yml': 'scripts/tests/fixtures/source-provenance/monetary-proof-workflow.txt',
}
RELOCATED = {
    'scripts/build-composition-intra.py': 'scripts/bench/build-composition-intra.py',
    'scripts/build-d8-checkpoint.py': 'scripts/bench/build-recursive-proof-benchmark.py',
    'scripts/build-prover-release.py': 'scripts/bench/build-prover-release.py',
    'scripts/check-native-proof-profiles.py': 'scripts/ci/check-native-proof-profiles.py',
    'scripts/check-prover-isa.py': 'scripts/bench/check-prover-isa.py',
    'scripts/check-v1-freeze.py': 'scripts/ci/check-transaction-proof-profile.py',
    'scripts/freeze-multi-asset.py': 'scripts/bench/multi-asset-profile.py',
    'scripts/measure-multi-asset.py': 'scripts/bench/measure-multi-asset.py',
    'scripts/measure-native-cgroup.py': 'scripts/bench/measure-native-cgroup.py',
    'scripts/measure-proof-cgroup.py': 'scripts/bench/measure-proof-cgroup.py',
    'scripts/native-proof-artifacts.rs': 'scripts/bench/native-proof-artifacts.rs',
    'scripts/prover-launcher.rs': 'scripts/bench/prover-launcher.rs',
    'scripts/v1-economics-candidate.py': 'scripts/bench/prepare-monetary-proof-profile.py',
    'crates/bench-d8/src/bin/v1-freeze-artifacts.rs': 'crates/native-proof/src/bin/transaction-proof-artifacts.rs',
}
RELOCATED.update(WORKFLOW_FIXTURES)
RECORDED = {current: recorded for recorded, current in RELOCATED.items()}
# Older release trees stored workflow source fixtures under their original basenames.
RECORDED.update({
    'scripts/tests/fixtures/retired-workflows/' + name.rsplit('/', 1)[1]: name
    for name in WORKFLOW_FIXTURES
})


def canonical_path(name):
    if name in RECORDED:
        return RECORDED[name]
    return name.replace('crates/native-proof/', 'crates/bench-d8/', 1) if name.startswith('crates/native-proof/') else name


def current_path(name):
    if name in RELOCATED:
        return RELOCATED[name]
    return name.replace('crates/bench-d8/', 'crates/native-proof/', 1) if name.startswith('crates/bench-d8/') else name


def source_bytes(root, name):
    path = root / current_path(name)
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Recorded source escapes repository root')
    return path.read_bytes()


def canonical_sources(names):
    result = {}
    for name in names:
        canonical = canonical_path(name)
        if canonical in result:
            raise ValueError('Ambiguous historical source path')
        result[canonical] = name
    return result


def fixed_dependency(root):
    value = tomllib.loads((root / 'crates/native-proof/dependency-lineage.toml').read_text())
    return (value.get('source_url') == 'https://github.com/howard1984/siworld'
        and value.get('source_revision') == value.get('downstream_revision')
        == 'd3d15b2b5d1325fb38ebc8979c1cae04b761e71f'
        and value.get('downstream_tree') == '11f7507a135f825a2ba6c790b9ad6d50a4e40b81'
        and value.get('patch_file') == 'crates/bench-stark/patches/recursive-stark-width-24.patch'
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
