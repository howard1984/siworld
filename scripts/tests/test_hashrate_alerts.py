"""Offline fixture exercises alert thresholds, dedupe and evidence gaps."""
import importlib.util
import sys
import unittest
from pathlib import Path
from dataclasses import replace

spec = importlib.util.spec_from_file_location("hashrate_alerts", Path(__file__).resolve().parents[1] / "hashrate-alerts.py")
policy = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = policy
spec.loader.exec_module(policy)

HOUR = policy.HOUR
network, genesis, a, b, c, receipt, process = (f"{i:064x}" for i in range(1, 8))
base = policy.WorkInterval(network, genesis, 0, HOUR, a, b, 900, receipt)
surge = policy.WorkInterval(network, genesis, HOUR, 2 * HOUR, b, c, 9000, receipt)
miner = policy.MinerInterval(network, genesis, HOUR, 2 * HOUR, 100, 1000, process, process, receipt)


def evaluation(previous=base, current=surge, sample=miner, episodes=None, at=2 * HOUR):
    return policy.evaluate(at, previous, current, ("owned",), {"owned": sample}, episodes or {})


def kinds(v):
    return [alert["kind"] for alert in v["alerts"]]


up = "network_hashrate_increase"
down = "network_hashrate_decrease"
small = "owned_hashrate_share_below_half"

class HashrateAlertTests(unittest.TestCase):
    def test_surge_and_inclusive_thresholds(self):
        assert kinds(evaluation()) == [up, small]
        assert all(v["first_response_due_ns"] - v["observed_ns"] == 300 * policy.SECOND for v in evaluation()["alerts"])
        assert kinds(evaluation(current=replace(surge, work=2700))) == [up, small]
        assert up not in kinds(evaluation(current=replace(surge, work=2699)))
        assert kinds(evaluation(current=replace(surge, work=300))) == [down]
        assert down not in kinds(evaluation(current=replace(surge, work=301)))
        assert small not in kinds(evaluation(sample=replace(miner, end_attempts=4600)))

    def test_owned_share_threshold_and_missing_counter(self):
        assert small in kinds(evaluation(sample=replace(miner, end_attempts=4599)))
        assert small in evaluation(sample=replace(miner, end_process=b))["unknown"]
        assert small in evaluation(sample=replace(miner, end_attempts=99))["unknown"]
        assert small in policy.evaluate(2 * HOUR, base, surge, ("owned", "missing"), {"owned": miner}, {})["unknown"]
        assert kinds(evaluation(current=replace(surge, end_block=b, work=0))) == [down]

    def test_missing_or_stale_chain_evidence(self):
        assert set(evaluation(current=replace(surge, network=c))["unknown"]) == {up, down, small}
        assert set(evaluation(current=replace(surge, start_block=a))["unknown"]) == {up, down}
        assert set(evaluation(at=2 * HOUR + policy.MAX_SAMPLE_AGE + 1)["unknown"]) == {up, down, small}
        assert evaluation()["alerts"][0]["supporting_evidence_sha256"] == [receipt]

    def test_scoped_dedupe_and_outage(self):
        state = evaluation()["episodes"]
        assert evaluation(episodes=state)["alerts"] == []
        assert evaluation(episodes=state, current=None)["episodes"] == state
        assert evaluation(episodes=state, current=replace(surge, work=900))["episodes"] == {}
        assert kinds(evaluation(previous=replace(base, genesis=a), current=replace(surge, genesis=a), sample=replace(miner, genesis=a), episodes=state)) == [up, small]


    def test_elapsed_duration_changes_ratio_threshold(self):
        self.assertNotIn(up, kinds(evaluation(current=replace(surge, work=2700, duration_ns=HOUR + policy.SECOND))))
        self.assertIn(up, kinds(evaluation(current=replace(surge, work=2700, duration_ns=HOUR - policy.SECOND))))
        self.assertIn(small, kinds(evaluation(sample=replace(miner, end_attempts=4600, duration_ns=HOUR + policy.SECOND))))
        stale_duration = replace(surge, duration_ns=HOUR + policy.MAX_BOUNDARY_SKEW + 1)
        self.assertEqual(set(evaluation(current=stale_duration)["unknown"]), policy.RULES)

    def test_duty_outbox_event_and_first_response_receipt(self):
        alert = evaluation()["alerts"][0]
        event = policy.duty_event("fixture", alert)
        self.assertEqual(event["recipient"], "on_call")
        self.assertEqual(event["notify_by"] - event["observed_at"], 300)
        self.assertEqual(event["evidence"]["sha256"], [receipt, receipt])
        due = alert["first_response_due_ns"]
        on_time = policy.first_response(event, "confirmed_estimate", due, receipt)
        self.assertTrue(on_time["within_5m"])
        self.assertEqual(on_time["key"], event["key"])
        late = policy.first_response(event, "evidence_unavailable", due + 1, receipt)
        self.assertFalse(late["within_5m"])
        with self.assertRaises(ValueError):
            policy.first_response(event, "confirmed_estimate", event["evidence"]["observed_ns"] - 1, receipt)


if __name__ == "__main__":
    unittest.main()
