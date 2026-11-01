#!/usr/bin/env python3
"""Measure fixed native settlement without changing frozen library sources.

Each trial owns a fresh systemd scope and one setup/prove/verify process tree.
Only allowlisted measurements and kernel counters are exported. Raw proof logs
and temporary application configuration remain outside public artifacts.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / '.local/native-v1-full-load'
SPEC = importlib.util.spec_from_file_location('cgroup', ROOT / 'scripts/measure-native-cgroup.py')
CG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CG)
LIMIT = 589824
PARAMETERS = dict(log_blowup=8, num_queries=36, query_pow_bits=20,
                  commit_pow_bits=0, batch_pow_bits=20, max_log_arity=1)
ERRORS = (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError)


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def prepare(output, root=ROOT):
    """Reuse the frozen library and lockfile through an isolated application."""
    output.mkdir(parents=True, exist_ok=False)
    application = root / 'crates/bench-multi-asset'
    text = (application / 'Cargo.toml').read_text()
    if text.count('[package]\n') != 1 or text.count('path = "../bench-d8"') != 1:
        raise ValueError('Unexpected source manifest structure')
    text = text.replace('[package]\n', '[package]\nautobins = false\n', 1)
    text = text.replace('path = "../bench-d8"',
                        'path = ' + json.dumps(str(root / 'crates/bench-d8')))
    text += '\n[lib]\npath = ' + json.dumps(str(application / 'src/lib.rs')) + '\n'
    text += '\n[[bin]]\nname = "settlement-full-load"\npath = '
    text += json.dumps(str(root / 'scripts/settlement-full-load.rs')) + '\n'
    (output / 'Cargo.toml').write_text(text)
    shutil.copyfile(application / 'Cargo.lock', output / 'Cargo.lock')
    return output / 'Cargo.toml'


def metrics(value):
    integer_fields = {'schema': 1, 'capacity': 576, 'workers': 4,
                      'active_fee_slots': 576, 'reward_note_count': 5, 'max_fund_claims': 8}
    if any(type(value.get(key)) is not int or value[key] != number
           for key, number in integer_fields.items()):
        raise ValueError('Invalid full-load report dimensions')
    if (value.get('schema') != 1 or value.get('suite') != CG.SUITE
            or value.get('statement') != 'native-v1-confidential-miner-note'
            or value.get('capacity') != 576 or value.get('parameters') != PARAMETERS
            or any(type(number) is not int for number in value['parameters'].values())
            or value.get('workers') != 4 or value.get('verified') is not True
            or value.get('fee_tier') != 'priority' or value.get('active_fee_slots') != 576
            or value.get('reward_note_count') != 5 or value.get('fund_claims_measured') is not False
            or value.get('max_fund_claims') != 8 or len(value.get('trials', [])) != 1):
        raise ValueError('Invalid full-load proof report')
    trial = value['trials'][0]
    result = {key: CG.integer(trial[key], key, positive=True) for key in
              ('proof_body_bytes', 'generation_ns', 'verification_ns')}
    result['setup_ns'] = CG.integer(value['setup_ns'], 'setup_ns', positive=True)
    return result


def command(unit, path):
    if not re.fullmatch(r'siworld-native-[a-f0-9]{32}\.scope', unit):
        raise ValueError('Unexpected owned scope name')
    return ['sudo', '--non-interactive', 'systemd-run', '--scope', '--quiet', '--unit=' + unit,
            '-p', 'MemoryAccounting=yes', '-p', 'CPUAccounting=yes', '-p', 'MemoryMax=5G',
            '-p', 'MemorySwapMax=0', '/usr/bin/python3', str(Path(__file__).resolve()),
            '--record', str(path)]


def cpu_capacity(membership=Path('/proc/self/cgroup'), mount=Path('/sys/fs/cgroup')):
    """Check affinity and every visible ancestor quota without exporting paths."""
    rows = [line[3:] for line in membership.read_text().splitlines() if line.startswith('0::')]
    if len(rows) != 1:
        raise ValueError('Unified cgroup membership required')
    relative = Path(rows[0])
    if not relative.is_absolute() or '..' in relative.parts:
        raise ValueError('Invalid cgroup membership')
    group = mount / str(relative).lstrip('/')
    quotas = []
    while True:
        try:
            quota, period = (group / 'cpu.max').read_text().split()
        except FileNotFoundError:
            # The true hierarchy root has no CPU bandwidth controller file.
            # A namespaced mount root may expose one; honor it when present.
            if group == mount:
                break
            raise
        if int(period) <= 0:
            raise ValueError('Invalid CPU quota period')
        if quota != 'max':
            if int(quota) <= 0:
                raise ValueError('Invalid CPU quota')
            quotas.append(1000 * int(quota) // int(period))
        if group == mount:
            break
        group = group.parent
    affinity = len(os.sched_getaffinity(0))
    return dict(affinity_logical_cpus=affinity,
                minimum_visible_quota_millicpus=min(quotas, default=None),
                four_vcpu_capacity_visible=affinity >= 4 and all(quota >= 4000 for quota in quotas))


def drain(group):
    """Clean up only descendants in the recorder's exact randomly named scope."""
    remaining = CG.member_pids(group)
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 5
    while CG.member_pids(group) and time.monotonic() < deadline:
        time.sleep(0.05)
    return remaining


def record(config):
    result = dict(schema=1, trial=config['trial'],
                  scope_sha256=hashlib.sha256(config['unit'].encode()).hexdigest(),
                  source_commit=config['source_commit'], binary_sha256=config['binary_sha256'],
                  workers=4, memory_max_bytes=CG.MEMORY_MAX, memory_swap_max_bytes=0,
                  peak_scope='one fresh setup/prove/verify process tree plus its recorder',
                  complete=False, acceptance=False, resource_control_pass=False,
                  proof_report_valid=False, proof_body_limit_pass=False)
    group, child, before, after = None, None, None, None
    code, timed_out, remaining = None, False, set()
    started = time.monotonic_ns()
    try:
        if os.geteuid() != 0 or config['uid'] <= 0 or config['gid'] <= 0:
            raise ValueError('Root recorder and nonroot worker required')
        group = CG.scoped_group(Path('/proc/self/cgroup').read_text(), config['unit'])
        Path('/proc/self/oom_score_adj').write_text('-1000')
        before = CG.snapshot(group)
        result['memory_before'] = before

        def unprivileged():
            Path('/proc/self/oom_score_adj').write_text('0')
            os.setgroups([])
            os.setgid(config['gid'])
            os.setuid(config['uid'])

        with Path(config['log']).open('xb') as log:
            child = subprocess.Popen([config['binary'], '--trials', '1', '--output', config['raw']],
                cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                start_new_session=True, preexec_fn=unprivileged,
                env={'PATH': '/usr/bin:/bin', 'RAYON_NUM_THREADS': '4',
                     'SIWORLD_COMPOSITION_HIDING_WORKERS': '2'})
            try:
                code = child.wait(timeout=1800)
            except subprocess.TimeoutExpired:
                timed_out = True
                CG.kill_owned_tree(child, group)
                code = child.wait()
    except ERRORS as error:
        result.update(failure='scope-recorder-failed', error_class=type(error).__name__)
    finally:
        if child is not None and child.poll() is None:
            try:
                CG.kill_owned_tree(child, group)
                code = child.wait(timeout=5)
            except ERRORS:
                result['cleanup_failed'] = True
        if group is not None:
            try:
                remaining = drain(group)
                after = CG.snapshot(group)
                result.update(memory_after=after, memory_peak_bytes=after['memory.peak'])
            except ERRORS as error:
                result.update(failure='final-counters-unavailable', error_class=type(error).__name__)
    result.update(exit_code=code, timed_out=timed_out,
                  process_wall_ns=time.monotonic_ns() - started,
                  remaining_descendants_at_exit=len(remaining))
    if before is not None and after is not None:
        try:
            result.update(CG.assess(before, after, code, timed_out, remaining))
        except ERRORS as error:
            result.update(failure='kernel-counters-invalid', error_class=type(error).__name__)
    try:
        result['measurement'] = metrics(json.loads(Path(config['raw']).read_text()))
        result['proof_report_valid'] = True
        result['proof_body_limit_pass'] = result['measurement']['proof_body_bytes'] <= LIMIT
    except ERRORS:
        pass
    result['complete'] = (result['resource_control_pass'] and result['proof_report_valid']
                          and result['proof_body_limit_pass'] and 'failure' not in result
                          and not result.get('cleanup_failed', False))
    write(config['result'], result)
    return 0 if result['complete'] else 1


def collect():
    binary = Path(os.environ['CARGO_TARGET_DIR']) / 'release/settlement-full-load'
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if not re.fullmatch('[a-f0-9]{40}', source):
        raise ValueError('Invalid source commit')
    cpu_text = Path('/proc/cpuinfo').read_text()
    models = sorted(set(re.findall(r'^model name\s*:\s*(.+)$', cpu_text, re.M)))
    cpu = dict(actual_cpu_models=models,
               epyc7763_match=bool(models) and all('AMD EPYC 7763' in model for model in models),
               required_workers=4, **cpu_capacity())
    write(BASE / 'public/cpu.json', cpu)
    rows = []
    for trial in range(1, 4):
        unit = 'siworld-native-' + uuid.uuid4().hex + '.scope'
        config = dict(uid=os.getuid(), gid=os.getgid(), unit=unit, trial=trial,
                      binary=str(binary.resolve()), binary_sha256=binary_hash, source_commit=source,
                      raw=str(BASE / f'private/raw-{trial}.json'), log=str(BASE / f'private/worker-{trial}.log'),
                      result=str(BASE / f'private/scope-result-{trial}.json'))
        path = BASE / f'private/config-{trial}.json'
        write(path, config)
        try:
            completed = subprocess.run(command(unit, path), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, timeout=1840, check=False)
            (BASE / f'private/scope-{trial}.log').write_text(completed.stdout)
            row = json.loads(Path(config['result']).read_text())
            row['scope_exit_code'] = completed.returncode
            if completed.returncode != 0:
                row['complete'] = False
        except ERRORS as error:
            cleanup_failed = False
            if isinstance(error, subprocess.TimeoutExpired):
                # Never select a node or another job's scope for timeout cleanup.
                try:
                    cleanup = subprocess.run(['sudo', '--non-interactive', 'systemctl', 'kill',
                        '--kill-who=all', '--signal=SIGKILL', unit], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=10, check=False)
                    cleanup_failed = cleanup.returncode != 0
                except ERRORS:
                    cleanup_failed = True
            try:
                row = json.loads(Path(config['result']).read_text())
            except ERRORS:
                row = dict(schema=1, trial=trial)
            row.update(complete=False, failure='scope-or-recorder-failed',
                       error_class=type(error).__name__, scope_cleanup_failed=cleanup_failed,
                       acceptance=False)
        # Preserve the root-owned recorder evidence unchanged. The runner owns
        # a separate allowlisted export containing the scope's exit status.
        write(BASE / f'public/trial-{trial}.json', row)
        rows.append(row)
    complete = all(row.get('complete') is True for row in rows)
    measured = [row['measurement'] for row in rows if row.get('proof_report_valid') is True]
    summary = dict(schema=1, source_commit=source, binary_sha256=binary_hash, parameters=PARAMETERS,
                   capacity=576, workers=4, trials=rows, all_measurements_complete=complete,
                   proof_body_limit_bytes=LIMIT, wire_cap_bytes=655360,
                   max_proof_body_bytes=max((row['proof_body_bytes'] for row in measured), default=None),
                   max_generation_ns=max((row['generation_ns'] for row in measured), default=None),
                   max_memory_peak_bytes=max((row.get('memory_peak_bytes', 0) for row in rows), default=None),
                   **cpu, epyc7763_baseline_complete=complete and cpu['epyc7763_match']
                   and cpu['four_vcpu_capacity_visible'],
                   memory_boundary_is_miner_requirement=False, fund_claims_measured=False, max_fund_claims=8,
                   fund_claims_scope='independently signed block-envelope records checked after settlement; not AIR inputs',
                   fund_claims_code_references=['crates/native-node/src/state.rs::State::apply',
                       'crates/native-node/src/fund_spend.rs::FundSpend::verify',
                       'crates/native-node/src/wire.rs::MAX_FUND_SPENDS'],
                   acceptance=False, cryptographic_approval=False, network_activation=False)
    write(BASE / 'public/summary.json', summary)
    return 0 if complete else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--prepare', type=Path)
    modes.add_argument('--record', type=Path)
    args = parser.parse_args()
    if args.prepare:
        print(prepare(args.prepare.resolve()))
        return 0
    if args.record:
        return record(json.loads(args.record.read_text()))
    return collect()


if __name__ == '__main__':
    sys.exit(main())
