#!/usr/bin/env python3
"""Role admission and hardware evidence without changing frozen collectors."""
import argparse
import importlib.util
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('minimum_measurement', ROOT / 'scripts/measure-multi-asset.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
H = M.module('measure-proof-cgroup.py')
MINIMUM_MEMORY = {'minimum-validator': 16 * 1024**3, 'minimum-miner': 32 * 1024**3}
X86_64_V3_FLAGS = {
    'avx': ('avx',), 'avx2': ('avx2',), 'bmi1': ('bmi1', 'bmi'), 'bmi2': ('bmi2',),
    'f16c': ('f16c',), 'fma': ('fma',), 'lzcnt': ('lzcnt', 'abm'), 'movbe': ('movbe',),
    'xsave': ('xsave',), 'sse3': ('sse3', 'pni'), 'ssse3': ('ssse3',),
    'sse4.1': ('sse4_1',), 'sse4.2': ('sse4_2',), 'popcnt': ('popcnt',),
    'cmpxchg16b': ('cx16',), 'lahf_sahf': ('lahf_lm',),
}


def v3_features(flags):
    """Linux flag evidence; the generic launcher separately checks AVX OS state."""
    return {name: bool(flags) and all(any(alias in cpu for alias in aliases) for cpu in flags)
            for name, aliases in X86_64_V3_FLAGS.items()}


def total_memory(text):
    match = re.search(r'^MemTotal:\s+([1-9][0-9]*)\s+kB\s*$', text, re.MULTILINE)
    if not match:
        raise ValueError('Missing Linux memory capacity')
    return int(match[1]) * 1024


def qualify_hardware_profile(hardware, profile):
    if profile not in MINIMUM_MEMORY:
        raise ValueError('Unknown minimum hardware role')
    if hardware.get('os') != 'Ubuntu 24.04' or hardware.get('architecture') != 'x86_64':
        raise ValueError('Current collector requires Ubuntu 24.04 x86_64')
    if not isinstance(hardware.get('cpu_model'), str) or not hardware['cpu_model'].strip():
        raise ValueError('Actual CPU model is required as measurement metadata')
    if type(hardware.get('exposed_physical_cores')) is not int or hardware['exposed_physical_cores'] < 1:
        raise ValueError('Exposed core count is required as measurement metadata')
    features = hardware.get('x86_64_v3_features')
    if not isinstance(features, dict) or any(features.get(name) is not True for name in X86_64_V3_FLAGS):
        raise ValueError('Every CPU must expose the complete x86-64-v3 feature set')
    for name in ('logical_cpus', 'online_logical_cpus', 'affinity_cpus'):
        if type(hardware.get(name)) is not int or hardware[name] < 4:
            raise ValueError('At least four online and affinity-available vCPUs are required')
    memory = hardware.get('memory_total_bytes')
    if type(memory) is not int or memory < MINIMUM_MEMORY[profile]:
        raise ValueError('Memory capacity is below the selected role minimum')
    return dict(profile=profile, role=profile.removeprefix('minimum-'), profile_qualified=True,
        minimum_vcpus=4, minimum_memory_bytes=MINIMUM_MEMORY[profile],
        same_physical_instance_established=False,
        identity_scope='Actual CPU model, exposed topology and memory are measurement metadata; '
                       'CPU vendor, model, exact core topology and virtualization are not admission requirements.')


def parse_cpu_max(value):
    return H.parse_cpu_max(value)


def qualify_cpu_profile(ancestry, profile):
    if profile not in MINIMUM_MEMORY:
        raise ValueError('Unknown minimum hardware role')
    if any(row.get('cpu_limit') and row['cpu_limit']['quota_cores'] is not None
           and row['cpu_limit']['quota_cores'] < 4 for row in ancestry):
        raise ValueError('Visible inherited CPU quota is below four vCPUs')


def qualify_memory_profile(ancestry, profile):
    """Check deployment limits before entering the separate 5-GiB proof scope."""
    if profile not in MINIMUM_MEMORY:
        raise ValueError('Unknown minimum hardware role')
    for row in ancestry:
        value = row.get('memory.max')
        if value not in (None, 'max') and H.memory_max_bytes(value) < MINIMUM_MEMORY[profile]:
            raise ValueError('Visible inherited memory limit is below the role minimum')


def qualify_and_record(output, profile):
    record = dict(required_hardware_profile=profile, profile_qualified=False, acceptance=False)
    try:
        hardware, evidence = H.qualify()
        cpus = Path('/proc/cpuinfo').read_text().split('\n\n')
        flags = [set(line.split(':', 1)[1].split()) for cpu in cpus
                 for line in cpu.splitlines() if line.startswith('flags')]
        hardware.update(memory_total_bytes=total_memory(Path('/proc/meminfo').read_text()),
                        x86_64_v3_features=v3_features(flags))
        record.update(hardware=hardware, lscpu=evidence['lscpu_json'], lscpu_text=evidence['lscpu_text'])
        record['qualification'] = qualify_hardware_profile(hardware, profile)
        ancestry = M.current_cpu_ancestry(H)
        for row in ancestry:
            path = Path(row['path']) / 'memory.max'
            row['memory.max'] = path.read_text().strip() if path.is_file() else None
        record['visible_cpu_limits'] = M.clean_cpu_limits(ancestry)
        record['visible_memory_limits'] = [dict(ancestor_level=index,
            memory_max_bytes=(None if row['memory.max'] in (None, 'max')
                              else H.memory_max_bytes(row['memory.max'])),
            limit_readable=row['memory.max'] is not None) for index, row in enumerate(ancestry)]
        qualify_cpu_profile(ancestry, profile)
        qualify_memory_profile(ancestry, profile)
        record['profile_qualified'] = True
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        record.update(failure='minimum-isa-cpu-memory-or-cgroup-unavailable', classification=type(error).__name__)
        M.write_json(output / 'hardware-qualification.json', record)
        print('Minimum hardware qualification failed; inspect the sanitized hardware report.', file=sys.stderr)
        return None
    M.write_json(output / 'hardware-qualification.json', record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hardware-profile', choices=tuple(MINIMUM_MEMORY), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    return 0 if qualify_and_record(args.output, args.hardware_profile) is not None else 1


if __name__ == '__main__':
    raise SystemExit(main())
