"""Compare a reproduced transaction proof profile with the recorded profile."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('freeze', ROOT / 'scripts/ci/check-transaction-proof-profile.py')
FREEZE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FREEZE)


def validate(expected, reproduced, root=ROOT):
    FREEZE.validate(expected, root)
    FREEZE.validate(reproduced, root)
    for name in FREEZE.REQUIRED_SOURCES:
        actual = hashlib.sha256(FREEZE.RELOCATIONS.source_bytes(root, name)).hexdigest()
        if reproduced['source_sha256'][name] != actual:
            raise ValueError('reproduction does not bind current source: ' + name)
    expected_fields = {key: value for key, value in expected.items() if key != 'source_sha256'}
    reproduced_fields = {key: value for key, value in reproduced.items() if key != 'source_sha256'}
    if expected_fields != reproduced_fields:
        raise ValueError('reproduced native profile, verifier key or security report changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=FREEZE.DEFAULT)
    parser.add_argument('--reproduced', type=Path, required=True)
    args = parser.parse_args()
    validate(json.loads(args.manifest.read_text()), json.loads(args.reproduced.read_text()))
    print('Native profile, security reports and public verifier artifacts reproduced; exact source relocations validated.')


if __name__ == '__main__':
    main()
