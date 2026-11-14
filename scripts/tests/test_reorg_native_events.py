"""Synthetic local journal fixtures; no native code, sockets or process probes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "reorg_native_events", Path(__file__).parents[1] / "reorg_native_events.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write(path, body):
    path.write_bytes(body)
    path.chmod(0o600)


class JournalFixture:
    def __init__(self, root):
        self.bindings = {"version": 1, "network_id": "1" * 64,
                         "genesis_id": "2" * 64, "source_commit": "3" * 40,
                         "binary_sha256": "4" * 64,
                         "nodes": [{"row": 1, "alias": "node-a", "node_id": "5" * 64,
                                    "run_id": "6" * 64, "directory": "/synthetic/node-a",
                                    "unit": "synthetic-native-service"}]}
        self.node = self.bindings["nodes"][0]
        common = {key: self.bindings[key] for key in MODULE.CONTEXT}
        common.update(version=1, record="block-event", event_source="native-runtime-hook",
                      node_id=self.node["node_id"], run_id=self.node["run_id"],
                      source_commit_externally_verified=False, event_unix_ms=1000,
                      elapsed_monotonic_ns="0")
        self.start = {**common, "record": "stream-marker", "kind": "native-event-stream-start",
                      "event_attempts": 0, "written_events": 0, "dropped_events": 0,
                      "error_code": None}
        event = {**common, "source_commit_origin": "compile-time-declaration",
                 "height": 1, "block_id": "7" * 64, "clock_offset_ms": None,
                 "clock_uncertainty_ms": None, "clock_calibration_measured": False}
        self.produced = {**event, "kind": "native-block-produced", "sequence": 1,
                         "event_unix_ms": 1010, "elapsed_monotonic_ns": "10",
                         "produced_unix_ms": 1010}
        self.produced["deduplication_key"] = [self.produced["kind"], self.node["node_id"],
                                              self.node["run_id"], self.produced["block_id"]]
        self.rejected = {**event, "kind": "native-proof-rejected", "sequence": 2,
                         "block_id": "8" * 64, "event_unix_ms": 1020,
                         "elapsed_monotonic_ns": "20", "receiver_node_id": self.node["node_id"],
                         "peer_id": "9" * 64, "frame_id": "a" * 64,
                         "body_commitment": "b" * 64, "body_bytes": 100,
                         "owner_attempt": 7, "native_error_code": "transaction-proof-invalid",
                         "owner_dropped_before": 0, "stream_dropped_before": 0}
        self.rejected["deduplication_key"] = [self.rejected["kind"], self.node["node_id"],
                                              self.node["run_id"], 7, self.rejected["frame_id"]]
        self.accepted = {**event, "kind": "native-block-durably-accepted", "sequence": 3,
                         "event_unix_ms": 1030, "elapsed_monotonic_ns": "30",
                         "accepted_unix_ms": 1030}
        self.accepted["deduplication_key"] = [self.accepted["kind"], self.node["node_id"],
                                              self.node["run_id"], self.accepted["block_id"]]
        self.end = {**self.start, "kind": "native-event-stream-end", "event_unix_ms": 1040,
                    "elapsed_monotonic_ns": "40", "event_attempts": 3, "written_events": 3}
        self.roots, self.snapshots = [], []
        for number, (before, after) in enumerate(((0, 1), (1, 3))):
            directory = root / ("snapshot-" + str(number))
            directory.mkdir(mode=0o700)
            parent = directory / self.node["alias"]
            parent.mkdir(mode=0o700)
            write(directory / "index.private.json", encoded({"version": 1, "bindings": self.bindings}))
            snapshot = {"binding": {**{key: self.bindings[key] for key in MODULE.CONTEXT}, **self.node},
                        "status_before": self.status(before, False),
                        "status_after": self.status(after, number == 1),
                        "unit": {"MainPID": "0" if number else "1"},
                        "process": None if number else {"synthetic": True}, "files": []}
            self.roots.append(directory)
            self.snapshots.append(snapshot)
        self.rewrite(0, [self.start, self.produced])
        self.rewrite(1, [self.rejected, self.accepted, self.end])

    def status(self, count, ended):
        diagnostic = {"enabled": True, "error_code": None, "last_sequence": count,
                      "event_attempts": count, "written_events": count, "dropped_events": 0,
                      "stream_start_written": True, "stream_end_written": ended,
                      "segment_rollovers": 0, "retention_replaced_prior_slot": False,
                      "coverage_established": False, "segment_count_limit": 4,
                      "segment_bytes_limit": 1048576, "record_bytes_limit": 2048,
                      "source_commit_available": True, "source_commit_externally_verified": False,
                      "clock_calibration_measured": False}
        owner = {"enabled": True, "dropped_events": 0, "error_code": None,
                 "coverage_established": False, "scope": "ordinary-forward-admission"}
        return {**{key: self.bindings[key] for key in ("network_id", "genesis_id")},
                "run_id": self.node["run_id"], "native_block_events": diagnostic,
                "native_accept_observation": owner}

    def save_snapshot(self, number):
        write(self.roots[number] / self.node["alias"] / "snapshot.private.json",
              encoded(self.snapshots[number]))

    def rewrite(self, number, records=None, raw=None):
        body = raw if raw is not None else b"".join(encoded(record) for record in records)
        name = "native-block-events-" + str(number) + ".jsonl"
        path = self.roots[number] / self.node["alias"] / name
        write(path, body)
        self.snapshots[number]["files"] = [{"name": name, "bytes": len(body),
                                             "sha256": hashlib.sha256(body).hexdigest(),
                                             "local_file": str(path)}]
        self.save_snapshot(number)

    def validate(self):
        return MODULE.validate(self.bindings, self.roots)


class NativeJournalTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return JournalFixture(Path(temporary.name).resolve())

    def test_three_kinds_share_coverage_before_propagation_selection(self):
        fixture = self.fixture()
        result = fixture.validate()
        self.assertEqual([row["record"].get("sequence") for row in result["records"]],
                         [None, 1, 2, 3, None])
        self.assertEqual(result["streams"][0]["attempts"], 3)
        self.assertEqual(result["streams"][0]["kind_counts"]["native-proof-rejected"], 1)
        self.assertEqual({row["kind"] for row in result["earliest_logical_events"]},
                         MODULE.PROPAGATION_KINDS)
        self.assertFalse(result["G2_case_pass"])

    def test_identical_overlap_is_retained_once(self):
        fixture = self.fixture()
        fixture.rewrite(1, [fixture.start, fixture.produced, fixture.rejected,
                            fixture.accepted, fixture.end])
        self.assertEqual(len(fixture.validate()["records"]), 5)

    def test_optional_status_artifact_fields_may_be_absent_but_cannot_conflict(self):
        fixture = self.fixture()
        fixture.validate()
        for field in ("source_commit", "binary_sha256"):
            with self.subTest(field=field):
                fixture = self.fixture()
                fixture.snapshots[1]["status_after"][field] = "c" * len(fixture.bindings[field])
                fixture.save_snapshot(1)
                with self.assertRaisesRegex(MODULE.IntegrityError, "^status_context_mismatch$"):
                    fixture.validate()

    def test_owner_attempt_gaps_and_all_current_native_relations(self):
        for code in sorted(MODULE.NATIVE_ERRORS):
            with self.subTest(code=code):
                fixture = self.fixture()
                fixture.rejected["native_error_code"] = code
                fixture.rewrite(1, [fixture.rejected, fixture.accepted, fixture.end])
                self.assertEqual(fixture.validate()["streams"][0]["attempts"], 3)

    def test_exact_record_bound_and_above_bound(self):
        for size, succeeds in ((2048, True), (2049, False)):
            with self.subTest(size=size):
                fixture = self.fixture()
                original = encoded(fixture.start)
                padded = original[:-1] + b" " * (size - len(original)) + b"\n"
                fixture.rewrite(0, raw=padded + encoded(fixture.produced))
                if succeeds:
                    fixture.validate()
                else:
                    with self.assertRaisesRegex(MODULE.IntegrityError, "^native_record_bound_rejected$"):
                        fixture.validate()

    def test_rejection_fields_fail_closed(self):
        mutations = [
            ("receiver_node_id", "c" * 64, "native_rejection_schema_rejected"),
            ("peer_id", "not-a-fingerprint", "native_rejection_schema_rejected"),
            ("frame_id", "C" * 64, "native_rejection_schema_rejected"),
            ("body_commitment", None, "native_rejection_schema_rejected"),
            ("body_bytes", True, "native_rejection_schema_rejected"),
            ("owner_attempt", 0, "native_rejection_schema_rejected"),
            ("native_error_code", "timeout", "native_rejection_schema_rejected"),
            ("owner_dropped_before", 1, "native_rejection_drop"),
            ("stream_dropped_before", 1, "native_rejection_drop"),
            ("deduplication_key", ["native-proof-rejected", "5" * 64, "6" * 64, 7, "c" * 64],
             "native_rejection_dedup_rejected"),
            ("accepted_unix_ms", 1020, "native_rejection_schema_rejected"),
        ]
        for field, value, code in mutations:
            with self.subTest(field=field):
                fixture = self.fixture()
                fixture.rejected[field] = value
                fixture.rewrite(1, [fixture.rejected, fixture.accepted, fixture.end])
                with self.assertRaisesRegex(MODULE.IntegrityError, "^" + code + "$"):
                    fixture.validate()
        fixture = self.fixture()
        del fixture.rejected["peer_id"]
        fixture.rewrite(1, [fixture.rejected, fixture.accepted, fixture.end])
        with self.assertRaisesRegex(MODULE.IntegrityError, "^native_rejection_schema_rejected$"):
            fixture.validate()

    def test_stream_unknown_sequence_identity_tail_and_duplicate_failures(self):
        cases = ("unknown", "gap", "conflict", "context", "tail", "duplicate-json", "nan", "missing-prefix", "missing-end")
        codes = ("native_event_kind_rejected", "native_event_sequence_gap",
                 "conflicting_duplicate_record", "native_record_context_mismatch",
                 "partial_segment_tail", "duplicate_json_key", "nonfinite_json_number",
                 "complete_stream_markers_required", "complete_stream_markers_required")
        for case, code in zip(cases, codes):
            with self.subTest(case=case):
                fixture = self.fixture()
                records = [fixture.rejected, fixture.accepted, fixture.end]
                if case == "unknown":
                    fixture.rejected["kind"] = "future-native-kind"
                elif case == "gap":
                    records.remove(fixture.rejected)
                elif case == "conflict":
                    altered = copy.deepcopy(fixture.produced)
                    altered.update(event_unix_ms=1011, produced_unix_ms=1011)
                    records.insert(0, altered)
                elif case == "context":
                    fixture.rejected["run_id"] = "c" * 64
                elif case == "missing-end":
                    records.remove(fixture.end)
                fixture.rewrite(1, records)
                if case in {"tail", "duplicate-json", "nan"}:
                    body = b"".join(encoded(record) for record in records)
                    if case == "tail":
                        body = body[:-1]
                    elif case == "duplicate-json":
                        body = body.replace(b'"version":1', b'"version":1,"version":1', 1)
                    else:
                        body = body.replace(b'"body_bytes":100', b'"body_bytes":NaN', 1)
                    fixture.rewrite(1, raw=body)
                if case == "missing-prefix":
                    fixture.roots = fixture.roots[1:]
                with self.assertRaisesRegex(MODULE.IntegrityError, "^" + code + "$"):
                    fixture.validate()

    def test_both_independent_diagnostics_and_final_stop_are_required(self):
        cases = ("owner-missing", "owner-drop", "owner-error", "owner-scope", "stream-drop",
                 "stream-error", "stream-counters", "not-stopped", "no-end-diagnostic",
                 "stream-error-missing", "process-missing")
        codes = ("owner_diagnostic_required", "owner_diagnostic_incomplete_or_drop",
                 "owner_diagnostic_incomplete_or_drop", "owner_diagnostic_incomplete_or_drop",
                 "native_stream_counter_or_drop", "native_stream_diagnostic_incomplete",
                 "native_stream_counter_or_drop", "final_stopped_diagnostic_required",
                 "final_stopped_diagnostic_required", "native_stream_diagnostic_incomplete",
                 "final_stopped_diagnostic_required")
        for case, code in zip(cases, codes):
            with self.subTest(case=case):
                fixture = self.fixture()
                snapshot = fixture.snapshots[1]
                status = snapshot["status_after"]
                if case == "owner-missing":
                    del status["native_accept_observation"]
                elif case.startswith("owner-"):
                    key, value = {"owner-drop": ("dropped_events", 1),
                                  "owner-error": ("error_code", "native_rejection_output_unavailable"),
                                  "owner-scope": ("scope", "competing-replacement")}[case]
                    status["native_accept_observation"][key] = value
                elif case == "not-stopped":
                    snapshot["unit"]["MainPID"] = "1"
                elif case == "process-missing":
                    del snapshot["process"]
                elif case == "stream-error-missing":
                    del status["native_block_events"]["error_code"]
                else:
                    key, value = {"stream-drop": ("dropped_events", 1),
                                  "stream-error": ("error_code", "native_event_log_write_failed"),
                                  "stream-counters": ("written_events", 2),
                                  "no-end-diagnostic": ("stream_end_written", False)}[case]
                    status["native_block_events"][key] = value
                fixture.save_snapshot(1)
                with self.assertRaisesRegex(MODULE.IntegrityError, "^" + code + "$"):
                    fixture.validate()

    def test_segment_and_retention_caps_and_create_only_output(self):
        fixture = self.fixture()
        fixture.snapshots[1]["files"][0]["bytes"] = 1048577
        fixture.save_snapshot(1)
        with self.assertRaisesRegex(MODULE.IntegrityError, "^snapshot_segment_metadata_rejected$"):
            fixture.validate()
        fixture = self.fixture()
        with patch.object(MODULE, "MAX_RETAINED_BYTES", 1):
            with self.assertRaisesRegex(MODULE.IntegrityError, "^retained_record_budget_exceeded$"):
                fixture.validate()
        output = fixture.roots[0] / "new-integrity.json"
        MODULE.write_result(output, fixture.validate())
        with self.assertRaises(FileExistsError):
            MODULE.write_result(output, {"result": "PASS"})


if __name__ == "__main__":
    unittest.main()
