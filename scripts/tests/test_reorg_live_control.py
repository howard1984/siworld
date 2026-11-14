"""Bounded inert control-flow fixtures; no mining, proof, process or transport."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "reorg_live_control", Path(__file__).parents[1] / "reorg_live_control.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def identifier(text):
    return hashlib.sha256(text.encode()).hexdigest()


def proposal(depth):
    nodes = [{"alias": alias, "role": role, "group": group,
              "node_id": identifier("node-" + alias), "run_id": identifier("run-" + alias)}
             for alias, role, group in (("m1", "miner", "old"), ("m2", "miner", "old"),
                                       ("s1", "service", "old"), ("m3", "miner", "candidate"),
                                       ("s2", "service", "candidate"))]
    return {"version": 1, "format": "live-control-consumption-proposal", "campaign_id": "model-campaign",
            "case_id": "model-depth-" + str(depth), "attempt_id": "model-attempt-1",
            "source_commit": "1" * 40, "binary_sha256": identifier("model-binary"),
            "network_id": identifier("model-network"), "genesis_id": identifier("model-genesis"),
            "rules_commitment": identifier("model-rules"), "proof_profile": identifier("model-profile"),
            "depth": depth, "ancestor": {"height": 7, "id": identifier("common"), "work": "100"},
            "nodes": nodes, "producers": {"old": "m1", "candidate": "m3"},
            "production_profile": {"fixture": False, "pow_iterations": 1,
                                   "target": "f" * 64, "work_bits": 0, "target_interval": 300}}


def inert_trace(plan):
    contract = MODULE.requirements(plan)
    branches, tips = {}, {}
    for group in ("old", "candidate"):
        previous = plan["ancestor"]
        blocks = []
        for offset in range(1, plan["depth"] + (group == "candidate") + 1):
            block = {"height": plan["ancestor"]["height"] + offset,
                     "id": identifier(group + "-" + str(offset)), "work": str(100 + offset),
                     "parent": previous["id"]}
            blocks.append(block)
            previous = block
        branches[group] = blocks
        tips[group] = {key: previous[key] for key in ("height", "id", "work")}
    aliases = sorted(node["alias"] for node in plan["nodes"])
    audits = {alias: identifier("audit-" + alias) for alias in aliases}
    heads = {node["alias"]: tips[node["group"]] for node in plan["nodes"]}
    reconciled = heads if plan["depth"] == 25 else {alias: tips["candidate"] for alias in aliases}
    payloads = {
        "common-paused": {"heads": {alias: plan["ancestor"] for alias in aliases},
                          "producer_quiescent": contract["miners"], "inflight_cancelled": contract["miners"]},
        "partitioned": {"groups": contract["groups"], "independent_heal_armed": True, "no_bypass": True},
        "production-bounded": {"branches": branches, "active_producers": contract["producers"],
                               "other_miners_paused": contract["paused_during_controlled_production"]},
        "branches-paused": {"heads": heads, "producer_quiescent": contract["miners"],
                            "inflight_cancelled": contract["miners"]},
        "materials-sealed": {"raw_frame_and_proof_refs": {group: identifier("raw-" + group) for group in branches},
                             "complete_state_audit_refs": audits},
        "healed": {"drop_rules_absent": True, "base_firewall_unchanged": True, "reconnected": aliases},
        "reconciled": {"path": contract["expected_path"], "heads": reconciled,
                       "state_audit_refs": audits if plan["depth"] == 25 else
                       {alias: identifier("after-" + alias) for alias in aliases},
                       "refused_nodes": contract["groups"]["old"] if plan["depth"] == 25 else [],
                       "mining_and_signing_paused": contract["groups"]["old"] if plan["depth"] == 25 else [],
                       "alarmed_nodes": contract["groups"]["old"] if plan["depth"] > 6 else []},
        "released": {"resumed_miners": contract["miners"], "new_template_parent": tips["candidate"]["id"]},
    }
    node_runs = {node["alias"]: {key: node[key] for key in ("node_id", "run_id")} for node in plan["nodes"]}
    records = [{"sequence": index, "phase": phase, "context": copy.deepcopy(contract["context"]),
                "node_runs": copy.deepcopy(node_runs), "data": copy.deepcopy(payloads[phase])}
               for index, phase in enumerate(contract["phases"], 1)]
    return {"version": 1, "origin": "inert-model", "plan_sha256": contract["plan_sha256"], "records": records}


class LiveControlModelTests(unittest.TestCase):
    def test_all_six_depths_have_one_replay_path_or_depth25_refusal(self):
        for depth in sorted(MODULE.DEPTHS):
            with self.subTest(depth=depth):
                plan = proposal(depth)
                contract = MODULE.requirements(plan)
                self.assertEqual(contract["stop_heights"], {"old": 7 + depth, "candidate": 8 + depth})
                self.assertEqual(contract["expected_path"], "depth25-refusal-and-manual-recovery" if depth == 25 else
                                 "savepoint-restore-and-ordinary-append")
                self.assertEqual(contract["paused_during_controlled_production"], ["m2"])
                self.assertIn("three-simultaneous", contract["required_separate_concurrency_gate"])
                self.assertFalse(contract["production_allowed"])

    def test_complete_model_and_every_prefix_never_qualify_real_execution(self):
        for depth in sorted(MODULE.DEPTHS):
            plan = proposal(depth)
            trace = inert_trace(plan)
            for count in range(len(trace["records"]) + 1):
                with self.subTest(depth=depth, count=count):
                    prefix = {**trace, "records": trace["records"][:count]}
                    result = MODULE.check_inert_trace(plan, prefix)
                    self.assertEqual(result["model_complete"], count == len(trace["records"]))
                    self.assertFalse(result["production_allowed"])
                    self.assertFalse(result["native_receipts_verified"])
                    self.assertFalse(result["nonfixture_proof_verified"])
                    self.assertFalse(result["G2_case_pass"])

    def test_each_phase_binds_context_run_and_uninterrupted_order(self):
        plan = proposal(6)
        original = inert_trace(plan)
        for index in range(len(original["records"])):
            for field in ("context", "node_runs", "sequence"):
                with self.subTest(index=index, field=field):
                    trace = copy.deepcopy(original)
                    if field == "context":
                        trace["records"][index][field]["proof_profile"] = "c" * 64
                    elif field == "node_runs":
                        trace["records"][index][field]["m1"]["run_id"] = "c" * 64
                    else:
                        trace["records"][index][field] += 1
                    with self.assertRaisesRegex(ValueError, "^inert_phase_(binding_mismatch|order_rejected)$"):
                        MODULE.check_inert_trace(plan, trace)

    def test_exact_ancestry_height_and_positive_greater_work(self):
        mutations = ("parent", "height", "zero-work", "lower-candidate-work", "duplicate-id", "short-branch")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                plan = proposal(6); trace = inert_trace(plan)
                branches = trace["records"][2]["data"]["branches"]
                if mutation == "parent": branches["old"][0]["parent"] = "c" * 64
                elif mutation == "height": branches["old"][0]["height"] += 1
                elif mutation == "zero-work": branches["candidate"][0]["work"] = "100"
                elif mutation == "lower-candidate-work":
                    for index, block in enumerate(branches["old"], 1): block["work"] = str(100 + 2 * index)
                elif mutation == "duplicate-id": branches["candidate"][0]["id"] = branches["old"][0]["id"]
                else: branches["old"].pop()
                with self.assertRaisesRegex(ValueError, "^inert_(branch_|positive_work|candidate_greater_work)"):
                    MODULE.check_inert_trace(plan, trace)

    def test_quiescence_partition_and_heal_require_explicit_conditions(self):
        mutations = ((0, "producer_quiescent", []), (0, "inflight_cancelled", []),
                     (3, "producer_quiescent", []), (3, "inflight_cancelled", []),
                     (1, "independent_heal_armed", False), (1, "no_bypass", False),
                     (5, "drop_rules_absent", False), (5, "base_firewall_unchanged", False),
                     (5, "reconnected", ["m1"]))
        for index, field, value in mutations:
            with self.subTest(index=index, field=field):
                plan = proposal(7); trace = inert_trace(plan)
                trace["records"][index]["data"][field] = value
                with self.assertRaisesRegex(ValueError, "^inert_(quiescence|partition_guard|heal_confirmation)_required$"):
                    MODULE.check_inert_trace(plan, trace)

    def test_original_materials_state_and_current_replay_path_are_required(self):
        for mutation in ("raw", "audit", "wrong-path", "head", "alarm"):
            with self.subTest(mutation=mutation):
                plan = proposal(24); trace = inert_trace(plan)
                if mutation == "raw": trace["records"][4]["data"]["raw_frame_and_proof_refs"]["old"] = "bad"
                elif mutation == "audit": del trace["records"][4]["data"]["complete_state_audit_refs"]["m1"]
                elif mutation == "wrong-path": trace["records"][6]["data"]["path"] = "checkpoint-resync"
                elif mutation == "head": trace["records"][6]["data"]["heads"]["m1"] = plan["ancestor"]
                else: trace["records"][6]["data"]["alarmed_nodes"] = []
                with self.assertRaisesRegex(ValueError, "^inert_(complete_material_refs_required|reconciliation_required|reconciled_head_mismatch|reorganization_alarm_required)$"):
                    MODULE.check_inert_trace(plan, trace)

    def test_depth25_preserves_state_pauses_signing_and_has_no_release(self):
        for mutation in ("release", "state", "switch", "pause", "alarm"):
            with self.subTest(mutation=mutation):
                plan = proposal(25); trace = inert_trace(plan)
                data = trace["records"][6]["data"]
                if mutation == "release": trace["records"].append(copy.deepcopy(trace["records"][-1]))
                elif mutation == "state": data["state_audit_refs"]["m1"] = "c" * 64
                elif mutation == "switch": data["heads"]["m1"] = data["heads"]["m3"]
                elif mutation == "pause": data["mining_and_signing_paused"] = []
                else: data["alarmed_nodes"] = []
                with self.assertRaisesRegex(ValueError, "^inert_(phase_count_rejected|depth25_refusal_required|reconciled_head_mismatch)$"):
                    MODULE.check_inert_trace(plan, trace)

    def test_fixture_and_real_origin_cannot_bypass_pending_and_files_are_bounded(self):
        for field, value in (("fixture", True), ("pow_iterations", 0)):
            plan = proposal(1); plan["production_profile"][field] = value
            with self.assertRaisesRegex(ValueError, "^nonfixture_positive_work_intent_required$"):
                MODULE.requirements(plan)
        plan = proposal(1); trace = inert_trace(plan); trace["origin"] = "native-receipt"
        with self.assertRaisesRegex(ValueError, "^explicit_inert_trace_required$"):
            MODULE.check_inert_trace(plan, trace)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "proposal.json"
            body = json.dumps(plan).encode()
            for length, accepted in ((MODULE.CAP, True), (MODULE.CAP + 1, False)):
                raw = body + b" " * (length - len(body)); path.write_bytes(raw); path.chmod(0o600)
                sha = hashlib.sha256(raw).hexdigest()
                if accepted: self.assertEqual(MODULE.load_bound(path, sha), plan)
                else:
                    with self.assertRaisesRegex(ValueError, "^private_bounded_input_required$"):
                        MODULE.load_bound(path, sha)
            path.write_bytes(body)
            with self.assertRaisesRegex(ValueError, "^input_hash_mismatch$"):
                MODULE.load_bound(path, "0" * 64)


class NativeSchemaAdapterTests(unittest.TestCase):
    """Copied synthetic metadata only; no native command or process is started."""

    def _write(self, path, value):
        path.write_bytes(MODULE.encode_native_record(value)); path.chmod(0o600)
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def _replace(self, reference, value):
        reference.update(self._write(Path(reference["path"]), value))

    def _snapshot(self, temporary, statuses=("applied",)):
        plan = proposal(6)
        root = Path(temporary).resolve()
        controls = root / "node" / "isolated-production"
        controls.parent.mkdir(mode=0o700); controls.mkdir(mode=0o700)
        outputs = root / "outputs"; outputs.mkdir(mode=0o700)
        campaign = identifier("synthetic-schema-campaign")
        init = MODULE.native_initialization_contract(plan, campaign, 96)
        manifest_ref = self._write(controls / "manifest.json", init["manifest"])
        initialization = {"version": 1, "manifest_sha256": manifest_ref["sha256"],
                          "initial_policy": "paused", "chain_modified": False, "identity_created": False}
        snapshot = {"version": 1, "format": "native-control-record-snapshot", "origin": "offline-schema-snapshot",
                    "campaign_sha256": campaign, "node_alias": "m1", "control_directory": str(controls),
                    "manifest": manifest_ref, "initialization_output": self._write(outputs / "initialize.json", initialization),
                    "events": []}
        for index, status in enumerate(statuses, 1):
            height = 7 if index == 1 else 13
            tip = plan["ancestor"]["id"] if index == 1 else identifier("synthetic-later-tip")
            request = MODULE.prepare_native_request(plan, Path(manifest_ref["path"]).read_bytes(),
                        manifest_ref["sha256"], campaign, "m1", index - 1, height, tip, index > 1,
                        13 if index == 1 else 0)
            name = MODULE.native_record_name("request", request["run_id"], index)
            request_ref = self._write(controls / name, request)
            installed = {"version": 1, "run_id": request["run_id"], "revision": index,
                         "request_sha256": request_ref["sha256"], "installed": True, "acknowledged": False}
            event = {"request": request_ref, "installation_output": self._write(outputs / (str(index) + "-installed.json"), installed),
                     "result": None}
            if status is not None:
                result = {"version": 1, "run_id": request["run_id"], "manifest_sha256": manifest_ref["sha256"],
                          "source_commit": request["source_commit"], "binary_sha256": request["binary_sha256"],
                          "revision": index, "request_sha256": request_ref["sha256"], "height": height,
                          "tip": tip, "status": status}
                result.update({"paused": request["paused"], "stop_height": request["stop_height"]} if status == "applied"
                              else {"reason": "invalid_or_stale_request"})
                event["result"] = self._write(controls / MODULE.native_record_name("result", request["run_id"], index), result)
            snapshot["events"].append(event)
        return plan, snapshot

    def test_manifest_exact_context_and_initialization_gate(self):
        plan = proposal(1); campaign = identifier("synthetic-campaign")
        init = MODULE.native_initialization_contract(plan, campaign, 96)
        self.assertEqual((init["initial_policy"], init["initial_revision"]), ("paused", 0))
        self.assertFalse(init["initialization_executed"])
        self.assertFalse(init["preconditions_verified"])
        self.assertIn("independently-authenticated-empty-node", init["required_preconditions"])
        self.assertIn("stopped-node-with-exclusive-service-lease", init["required_preconditions"])
        self.assertEqual(MODULE.native_initialization_contract(plan, campaign, 1_000_000)["manifest"]["maximum_height"], 1_000_000)
        for field, value in (("maximum_height", 0), ("maximum_height", 1_000_001), ("maximum_height", True),
                             ("version", True), ("campaign_sha256", "0" * 64), ("network_id", "a" * 64),
                             ("purpose", "fixture"), ("extra", 1)):
            with self.subTest(field=field, value=value):
                changed = {**init["manifest"], field: value}
                with self.assertRaises(ValueError): MODULE.check_native_manifest(plan, changed, campaign)

    def test_native_byte_utf8_duplicate_and_nonfinite_boundaries(self):
        body = b'{"version":1}'
        self.assertEqual(MODULE.native_json(body + b" " * (8192 - len(body))), {"version": 1})
        for raw in (b"", body + b" " * 8192, b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}',
                    '{"x":1}'.encode("utf-16"), b"[]"):
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(ValueError): MODULE.native_json(raw)

    def test_request_binds_run_build_revision_and_finite_ceiling(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, snapshot = self._snapshot(temporary)
            manifest = MODULE.read_native_record(snapshot["manifest"])["value"]
            request = MODULE.read_native_record(snapshot["events"][0]["request"])["value"]
            for field, value in (("run_id", "a" * 64), ("source_commit", "a" * 40), ("binary_sha256", "b" * 64),
                                 ("manifest_sha256", "c" * 64), ("revision", 2), ("revision", True),
                                 ("expected_tip", "0" * 64), ("expected_height", 1_000_001),
                                 ("stop_height", 7), ("stop_height", 97), ("paused", 1), ("extra", 1)):
                with self.subTest(field=field, value=value):
                    changed = {**request, field: value}
                    with self.assertRaises(ValueError):
                        MODULE.check_native_request(plan, manifest, snapshot["manifest"]["sha256"], "m1", 0, changed)
            paused = {**request, "paused": True, "stop_height": 0}
            self.assertEqual(MODULE.check_native_request(plan, manifest, snapshot["manifest"]["sha256"], "m1", 0, paused), paused)
            final_revision = {**paused, "revision": 1_000_000, "expected_height": 1_000_000}
            self.assertEqual(MODULE.check_native_request(plan, manifest, snapshot["manifest"]["sha256"], "m1", 999_999,
                                                        final_revision), final_revision)
            with self.assertRaises(ValueError):
                MODULE.check_native_request(plan, manifest, snapshot["manifest"]["sha256"], "m1", 1_000_000, final_revision)

    def test_initialization_and_installation_outputs_never_acknowledge(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, snapshot = self._snapshot(temporary)
            initial = MODULE.read_native_record(snapshot["initialization_output"])["value"]
            self.assertFalse(MODULE.check_native_initialization_output(initial, snapshot["manifest"]["sha256"])["preconditions_verified"])
            for field in ("chain_modified", "identity_created"):
                with self.assertRaises(ValueError):
                    MODULE.check_native_initialization_output({**initial, field: True}, snapshot["manifest"]["sha256"])
            event = snapshot["events"][0]
            request = MODULE.read_native_record(event["request"])["value"]
            installed = MODULE.read_native_record(event["installation_output"])["value"]
            self.assertFalse(MODULE.check_native_installation_output(installed, request, event["request"]["sha256"])["acknowledged"])
            for changed in ({**installed, "acknowledged": True}, {**installed, "status": "applied"}):
                with self.assertRaises(ValueError): MODULE.check_native_installation_output(changed, request, event["request"]["sha256"])

    def test_applied_result_matches_every_request_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, snapshot = self._snapshot(temporary)
            event = snapshot["events"][0]
            request = MODULE.read_native_record(event["request"])["value"]
            result = MODULE.read_native_record(event["result"])["value"]
            self.assertTrue(MODULE.check_native_result(result, request, event["request"]["sha256"])["acknowledged"])
            for field, value in (("run_id", "a" * 64), ("manifest_sha256", "b" * 64), ("source_commit", "c" * 40),
                                 ("binary_sha256", "d" * 64), ("revision", 2), ("request_sha256", "e" * 64),
                                 ("height", 8), ("tip", "f" * 64), ("paused", True), ("stop_height", 14), ("extra", 1)):
                with self.subTest(field=field):
                    with self.assertRaises(ValueError):
                        MODULE.check_native_result({**result, field: value}, request, event["request"]["sha256"])

    def test_raw_request_hash_is_preserved_without_reserialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, snapshot = self._snapshot(temporary)
            event = snapshot["events"][0]
            path = Path(event["request"]["path"])
            path.write_bytes(path.read_bytes() + b" \n")
            event["request"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            for field in ("installation_output", "result"):
                value = MODULE.read_native_record(event[field])["value"]
                value["request_sha256"] = event["request"]["sha256"]; self._replace(event[field], value)
            checked = MODULE.check_native_control_snapshot(plan, snapshot)
            self.assertEqual(checked["applied_revision"], 1)
            self.assertTrue(checked["record_acknowledgements"][0]["acknowledged"])

    def test_resume_then_pause_never_promotes_to_live_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, snapshot = self._snapshot(temporary, ("applied", "applied"))
            checked = MODULE.check_native_control_snapshot(plan, snapshot)
            self.assertEqual((checked["initial_revision"], checked["applied_revision"]), (0, 2))
            self.assertTrue(checked["requested_paused"])
            self.assertEqual(checked["requested_stop_height"], 0)
            self.assertEqual([row["acknowledged"] for row in checked["record_acknowledgements"]], [True, True])
            for field in ("production_allowed", "native_receipts_verified", "native_controls_available",
                          "nonfixture_proof_verified", "producer_quiescence_verified", "G2_case_pass", "live_case_pass"):
                self.assertFalse(checked[field])

    def test_pending_and_rejected_next_revisions_are_terminal(self):
        for status in (None, "rejected"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                plan, snapshot = self._snapshot(temporary, (status,))
                checked = MODULE.check_native_control_snapshot(plan, snapshot)
                self.assertEqual(checked["applied_revision"], 0)
                self.assertEqual(checked["pending_revision"], 1 if status is None else None)
                self.assertEqual(checked["terminal_rejection"], status == "rejected")
                self.assertTrue(all(not row["acknowledged"] for row in checked["record_acknowledgements"]))
                snapshot["events"].append(copy.deepcopy(snapshot["events"][0]))
                with self.assertRaisesRegex(ValueError, "native_(pending_revision|rejection)_is_terminal"):
                    MODULE.check_native_control_snapshot(plan, snapshot)
        with tempfile.TemporaryDirectory() as temporary:
            plan, snapshot = self._snapshot(temporary, ())
            checked = MODULE.check_native_control_snapshot(plan, snapshot)
            self.assertEqual(checked["applied_revision"], 0)
            self.assertTrue(checked["requested_paused"])
            self.assertEqual(checked["record_acknowledgements"], [])
            snapshot["events"] = [{}] * 65
            with self.assertRaisesRegex(ValueError, "native_snapshot_schema_rejected"):
                MODULE.check_native_control_snapshot(plan, snapshot)

    def test_revision_gaps_old_run_wrong_names_and_reused_paths_fail(self):
        for mutation in ("revision", "old-run", "wrong-name", "reused-output"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                plan, snapshot = self._snapshot(temporary)
                event = snapshot["events"][0]
                if mutation in {"revision", "old-run"}:
                    request = MODULE.read_native_record(event["request"])["value"]
                    request["revision" if mutation == "revision" else "run_id"] = 2 if mutation == "revision" else "a" * 64
                    self._replace(event["request"], request)
                elif mutation == "wrong-name":
                    original = Path(event["request"]["path"]); target = original.with_name("other-request.json")
                    target.write_bytes(original.read_bytes()); target.chmod(0o600); event["request"]["path"] = str(target)
                else:
                    event["installation_output"] = snapshot["initialization_output"]
                with self.assertRaises(ValueError): MODULE.check_native_control_snapshot(plan, snapshot)

    def test_status_and_claimed_native_origin_cannot_substitute(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, snapshot = self._snapshot(temporary)
            event = snapshot["events"][0]
            self._replace(event["result"], {"version": 1, "revision": 1, "paused": True, "production_allowed": False})
            with self.assertRaisesRegex(ValueError, "native_immutable_result_required"):
                MODULE.check_native_control_snapshot(plan, snapshot)
            snapshot["origin"] = "native-receipt"
            with self.assertRaisesRegex(ValueError, "native_snapshot_schema_rejected"):
                MODULE.check_native_control_snapshot(plan, snapshot)

    def test_private_files_enforce_mode_link_type_hash_and_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / "record.json"
            body = b'{"version":1}'
            for length, accepted in ((8192, True), (8193, False), (0, False)):
                raw = body + b" " * (length - len(body)) if length else b""
                path.write_bytes(raw); path.chmod(0o600)
                reference = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
                if accepted: self.assertEqual(MODULE.read_native_record(reference)["bytes"], 8192)
                else:
                    with self.assertRaises(ValueError): MODULE.read_native_record(reference)
            reference = self._write(path, {"version": 1})
            with self.assertRaises(ValueError): MODULE.read_native_record({**reference, "sha256": "a" * 64})
            for mode in (0o400, 0o644):
                path.chmod(mode)
                with self.assertRaises(ValueError): MODULE.read_native_record(reference)
            path.chmod(0o600)
            symbolic = root / "symbolic.json"; symbolic.symlink_to(path)
            with self.assertRaises(ValueError): MODULE.read_native_record({**reference, "path": str(symbolic)})
            linked = root / "hardlink.json"; os.link(path, linked)
            with self.assertRaises(ValueError): MODULE.read_native_record(reference)

    def test_same_path_same_bytes_replacement_during_snapshot_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, snapshot = self._snapshot(temporary)
            event = snapshot["events"][0]
            original = MODULE.read_native_record
            changed = False

            def read_and_replace(reference):
                nonlocal changed
                record = original(reference)
                if reference == event["result"] and not changed:
                    path = Path(event["request"]["path"])
                    replacement = path.with_name("synthetic-replacement.json")
                    replacement.write_bytes(path.read_bytes()); replacement.chmod(0o600)
                    os.replace(replacement, path); changed = True
                return record

            with mock.patch.object(MODULE, "read_native_record", side_effect=read_and_replace):
                with self.assertRaisesRegex(ValueError, "native_snapshot_record_replaced"):
                    MODULE.check_native_control_snapshot(plan, snapshot)


if __name__ == "__main__":
    unittest.main()
