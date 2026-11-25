#!/usr/bin/env python3
"""Reject proof executables without packed AVX2 arithmetic instructions."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

PATTERN = re.compile(r'\bvpmulu?dq\b.*\bymm\d+')


def inspect(binary):
    count, examples = 0, []
    process = subprocess.Popen(['objdump', '-d', '-C', '-M', 'intel', str(binary)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in process.stdout:
        if PATTERN.search(line):
            count += 1
            if len(examples) < 3:
                examples.append(line.strip())
    error = process.stderr.read()
    if process.wait() != 0:
        raise ValueError('Cannot inspect proof executable: ' + error.strip())
    if not count:
        raise ValueError('Proof executable has no AVX2 packed arithmetic; release rejected')
    return {'required_isa': 'x86-64-v3', 'avx2_packed_multiply_instructions': count,
            'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'instruction_examples': examples}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(inspect(args.binary.resolve(strict=True)), indent=2))


if __name__ == '__main__':
    main()
