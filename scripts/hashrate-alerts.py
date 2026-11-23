"""Evaluate authenticated chain-work intervals and local PoW counter deltas.

The reader supplies contiguous, verified canonical intervals and independently
bound miner counters. This evaluator writes no state and has no transport or
node-control capability; the caller persists episodes and routes alerts.
"""
from dataclasses import dataclass
from fractions import Fraction
from typing import Mapping

SECOND = 10**9
HOUR = 3600 * SECOND
MAX_SAMPLE_AGE = 30 * SECOND
MAX_BOUNDARY_SKEW = 30 * SECOND
RESPONSE = 300 * SECOND
RULES = frozenset(('network_hashrate_increase', 'network_hashrate_decrease', 'owned_hashrate_share_below_half'))


@dataclass(frozen=True)
class WorkInterval:
    network: str
    genesis: str
    start_ns: int
    end_ns: int
    start_block: str
    end_block: str
    work: int
    evidence_sha256: str
    duration_ns: int = HOUR


@dataclass(frozen=True)
class MinerInterval:
    network: str
    genesis: str
    start_ns: int
    end_ns: int
    start_attempts: int
    end_attempts: int
    start_process: str
    end_process: str
    evidence_sha256: str
    duration_ns: int = HOUR


def _duration(value):
    return type(value) is int and abs(value - HOUR) <= MAX_BOUNDARY_SKEW


def _hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _chain_window(window, now_ns):
    return (
        isinstance(window, WorkInterval)
        and type(now_ns) is int
        and all(_hash(x) for x in (window.network, window.genesis, window.start_block, window.end_block, window.evidence_sha256))
        and type(window.start_ns) is int and type(window.end_ns) is int
        and 0 <= window.start_ns < window.end_ns <= now_ns
        and window.end_ns - window.start_ns == HOUR
        and _duration(window.duration_ns)
        and type(window.work) is int and window.work >= 0
        and (window.work == 0) == (window.start_block == window.end_block)
    )


def evaluate(now_ns, previous, current, expected_miner_ids, miners, episodes: Mapping[tuple[str, str], int]):
    """Return alert transitions, persisted episodes and unknown measurements.

    Compare adjacent complete one-hour intervals from one canonical view.
    Compute rates as exact work per elapsed time, and use native logical
    attempts over the same interval for the owned estimate. Missing inputs
    cannot clear an active episode.
    """
    active = dict(episodes)
    alerts = []
    unknown = []

    def process(kind, condition, evidence=()):
        if condition is None:
            unknown.append(kind)
            return
        key = (current.genesis, kind)
        if condition and key not in active:
            active[key] = now_ns
            alerts.append({
                'kind': kind, 'since_ns': now_ns, 'observed_ns': now_ns,
                'dedupe': [current.genesis, kind, now_ns],
                'evidence_sha256': current.evidence_sha256,
                'supporting_evidence_sha256': list(evidence),
                'first_response_due_ns': now_ns + RESPONSE,
                'action': 'ledger_alert_only',
            })
        elif not condition:
            active.pop(key, None)

    current_ok = _chain_window(current, now_ns) and now_ns - current.end_ns <= MAX_SAMPLE_AGE
    comparable = (
        current_ok and _chain_window(previous, now_ns)
        and (previous.network, previous.genesis, previous.end_ns, previous.end_block)
        == (current.network, current.genesis, current.start_ns, current.start_block)
        and previous.work > 0
    )
    previous_evidence = (previous.evidence_sha256,) if comparable else ()
    current_rate = Fraction(current.work * HOUR, current.duration_ns) if current_ok else None
    previous_rate = Fraction(previous.work * HOUR, previous.duration_ns) if comparable else None
    process('network_hashrate_increase', current_rate >= 3 * previous_rate if comparable else None, previous_evidence)
    process('network_hashrate_decrease', 3 * current_rate <= previous_rate if comparable else None, previous_evidence)

    roster = tuple(expected_miner_ids)
    owned = None
    miner_evidence = ()
    if current_ok and current.work > 0 and roster and len(roster) == len(set(roster)) and set(miners) == set(roster):
        samples = [miners[miner] for miner in roster]
        if all(
            isinstance(m, MinerInterval)
            and (m.network, m.genesis, m.start_ns, m.end_ns) ==
            (current.network, current.genesis, current.start_ns, current.end_ns)
            and _hash(m.start_process) and m.start_process == m.end_process
            and _hash(m.evidence_sha256) and _duration(m.duration_ns)
            and type(m.start_attempts) is int and type(m.end_attempts) is int
            and 0 <= m.start_attempts <= m.end_attempts
            for m in samples
        ):
            owned = sum(Fraction((m.end_attempts - m.start_attempts) * HOUR, m.duration_ns) for m in samples)
            miner_evidence = tuple(m.evidence_sha256 for m in samples)
    process('owned_hashrate_share_below_half', 2 * owned < current_rate if owned is not None else None, miner_evidence)
    return {
        'alerts': alerts, 'episodes': active, 'unknown': unknown,
        'network_work_per_hour': current_rate,
        'previous_network_work_per_hour': previous_rate,
        'owned_attempts_per_hour': owned,
    }


def duty_event(window, alert):
    """Adapt a new episode to the fleet duty outbox format.

    Use a conservative whole-second deadline when converting the native
    nanosecond clock. This is a request for triage, not a delivery receipt.
    """
    if not isinstance(window, str) or not 1 <= len(window) <= 100:
        raise ValueError('invalid duty window')
    kind = alert['kind']
    observed = alert['observed_ns']
    genesis, dedupe_kind, opened = alert['dedupe']
    evidence = [alert['evidence_sha256'], *alert['supporting_evidence_sha256']]
    if (kind not in RULES or kind != dedupe_kind or not _hash(genesis)
            or not 1 <= len(evidence) <= 65 or not all(map(_hash, evidence))
            or type(observed) is not int or observed < 0 or opened != observed
            or alert['first_response_due_ns'] != observed + RESPONSE):
        raise ValueError('invalid hashrate episode')
    return {
        'window': window, 'key': f'{kind}:{genesis}', 'rule': kind,
        'subject': 'fleet', 'status': 'warning',
        'observed_at': observed // SECOND, 'opened_at': opened // SECOND,
        'notify_by': alert['first_response_due_ns'] // SECOND,
        'recipient': 'on_call',
        'evidence': {'genesis': genesis, 'sha256': evidence, 'observed_ns': observed},
    }


def first_response(event, performed, observed_at_ns, evidence_sha256):
    """Create a local ledger receipt after an actual evidence comparison."""
    allowed = {'confirmed_estimate', 'evidence_unavailable', 'estimate_not_reproduced'}
    if (event.get('rule') not in RULES or performed not in allowed or not _hash(evidence_sha256)
            or type(observed_at_ns) is not int):
        raise ValueError('invalid duty response')
    triggered = event['evidence']['observed_ns']
    if observed_at_ns < triggered:
        raise ValueError('duty response predates alarm')
    return {
        'window': event['window'], 'key': event['key'], 'performed': performed,
        'triggered_ns': triggered, 'triaged_ns': observed_at_ns,
        'within_5m': observed_at_ns - triggered <= RESPONSE,
        'evidence_sha256': evidence_sha256, 'action': 'ledger_alert_only',
    }
