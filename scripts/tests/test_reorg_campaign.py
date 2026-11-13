"""Synthetic IPC children and topology tests; no native proofs or miners."""
import copy
import hashlib
import importlib.util
import json
import os
import signal
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("reorg_campaign", Path(__file__).parents[1] / "reorg-campaign.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

STUB = r'''
import hashlib,json,os,secrets,socket,sys,time
if "SIWORLD_REORG_CONTROL_FD" not in os.environ:
 from pathlib import Path
 root=Path(sys.argv[1]);run=secrets.token_hex(32);started=time.time_ns()//1000000
 receipt={"run_id":run,"process_id":os.getpid(),"network_id":sys.argv[3],
 "binary_sha256":hashlib.sha256(open(sys.argv[0],"rb").read()).hexdigest(),
 "configuration_sha256":hashlib.sha256(open(sys.argv[2],"rb").read()).hexdigest(),"started_unix_ms":started}
 directory=root/"service-runs"/run;directory.mkdir(parents=True)
 (directory/"run.json").write_text(json.dumps(receipt))
 status={"run_id":run,"process_id":os.getpid(),"network_id":sys.argv[3],"genesis_id":sys.argv[4],
 "updated_unix_ms":time.time_ns()//1000000,"state_available":True,"height":0,"tip":"a"*64,"cumulative_work":"0"}
 (root/"service-status.json").write_text(json.dumps(status))
 while True: time.sleep(1)
channel=socket.socket(fileno=int(os.environ["SIWORLD_REORG_CONTROL_FD"]))
stream=channel.makefile("rwb",buffering=0)
sequence=0
run=secrets.token_hex(16)
context={"version":1,"token":os.environ["SIWORLD_REORG_CONTROL_TOKEN"],
 "campaign_id":os.environ["SIWORLD_REORG_CAMPAIGN_ID"],"node_id":os.environ["SIWORLD_REORG_NODE_ID"],
 "network_id":sys.argv[3],"genesis_id":sys.argv[4],
 "binary_sha256":hashlib.sha256(open(sys.argv[0],"rb").read()).hexdigest(),
 "process_id":os.getpid(),"run_id":run}
mode=sys.argv[5]
def emit(kind,**values):
 global sequence
 frame={**context,"kind":kind,"sequence":sequence,"unix_ms":time.time_ns()//1000000,"monotonic_ns":time.monotonic_ns(),**values}
 sequence+=1
 stream.write(json.dumps(frame).encode()+b"\n")
if mode=="wrong-token": context["token"]="wrong"
if mode=="wrong-pid": context["process_id"]+=1
if mode=="oversize": stream.write(b"x"*17000);time.sleep(10)
emit("hello")
emit("block_produced",height=1,block_id="a"*64)
emit("block_durable_accepted",height=1,block_id="a"*64)
for raw in stream:
 request=json.loads(raw)
 if request["kind"]=="clock_ping":
  emit("clock_reply",probe_id=request["probe_id"])
 elif request["kind"]=="arm_boundary":
  arm={key:request[key] for key in ["boundary","height","arm_id"]}
  if mode=="wrong-boundary": arm["height"]+=1
  emit("boundary_parked",parked=True,**arm)
 elif request["kind"]=="resume_boundary":
  emit("block_durable_accepted",height=2,block_id="b"*64)
'''


def fixture(root, mode="good"):
    root.chmod(0o700)
    (root / "reorg-local-network.marker.json").write_text(json.dumps(MODULE.NETWORK.MARKER))
    binary = root / "synthetic-child"
    binary.write_text("#!" + str(Path(sys.executable).resolve()) + "\n" + STUB)
    binary.chmod(0o500)
    plan = {"version": 1, "scope": "g2", "root": str(root), "run_id": "campaign-a",
            "binary": str(binary), "binary_sha256": MODULE.NETWORK.digest(binary),
            "source_commit": "3" * 40, "network_id": "1" * 64, "genesis_id": "2" * 64,
            "genesis_sha256": hashlib.sha256(b"synthetic genesis only").hexdigest(),
            "minimum_free_disk_bytes": 0, "nodes": [], "links": []}
    topology = {"version": 1, "run_id": plan["run_id"], "groups": [["m1", "s1"], ["m2", "m3", "s2"]], "edges": []}
    for name in ["m1", "s1", "m2", "m3", "s2"]:
        role = "service" if name.startswith("s") else "miner"
        directory = root / name
        directory.mkdir(mode=0o700)
        (directory / "genesis.bin").write_bytes(b"synthetic genesis only")
        (directory / "native-peer-identity.secret").write_text("synthetic path fixture, not a key")
        config = {"version": 2, "engineering": True, "role": "validator" if role == "service" else "miner",
                  "listen": "127.0.0.1:500" + name[1] if role == "service" else None,
                  "mining": role == "miner", "checkpoint_key": None, "peers": []}
        for target in ["s1", "s2"]:
            if target == name:
                continue
            identifier = name + "-" + target
            listen = "127.0.0.1:" + str(6100 + len(plan["links"]))
            control = root / (identifier + ".json")
            control.write_text(json.dumps({"version": 1, "enabled": True}))
            plan["links"].append({"id": identifier, "listen": listen, "target": "127.0.0.1:500" + target[1], "control": str(control)})
            topology["edges"].append({"link_id": identifier, "source": name, "target": target})
            config["peers"].append({"endpoint": listen})
        configuration = directory / "peers.json"
        configuration.write_text(json.dumps(config))
        arguments = [str(directory), str(configuration), plan["network_id"], plan["genesis_id"], mode]
        plan["nodes"].append({"id": name, "role": role, "directory": str(directory),
                              "configuration": str(configuration), "arguments_sha256": MODULE.arguments_digest(arguments)})
    path = root / "plan.json"
    path.write_text(json.dumps(plan))
    return plan, topology


def arguments(plan, node="m1", mode="good"):
    entry = MODULE.node_entry(plan, node)
    return [entry["directory"], entry["configuration"], plan["network_id"], plan["genesis_id"], mode]


class TopologyTests(unittest.TestCase):
    def test_two_halves_bind_to_configs_and_partition_changes_only_crossing_controls(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            plan, topology = fixture(Path(temporary).resolve())
            MODULE.checked_plan(Path(plan["root"]) / "plan.json")
            assessment = MODULE.partition_topology(plan, topology)
            self.assertEqual(len(assessment["crossing_links"]), 5)
            with patch.object(MODULE.socket, "socketpair", side_effect=AssertionError("no IPC expected")):
                MODULE.set_partition(plan, topology, True)
            for link in plan["links"]:
                self.assertEqual(json.loads(Path(link["control"]).read_text())["enabled"],
                                 link["id"] not in assessment["crossing_links"])
            MODULE.set_partition(plan, topology, False)
            self.assertTrue(all(json.loads(Path(link["control"]).read_text())["enabled"] for link in plan["links"]))
            self.assertFalse(assessment["nodes_started"])
            self.assertFalse(assessment["g2_passed"])

    def test_missing_service_duplicate_member_wrong_target_and_bypass_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, original = fixture(Path(temporary).resolve())
            wrong = copy.deepcopy(original)
            wrong["groups"] = [["m1"], ["s1", "m2", "m3", "s2"]]
            with self.assertRaises(ValueError): MODULE.partition_topology(plan, wrong)
            wrong = copy.deepcopy(original)
            wrong["groups"][0].append("m1")
            with self.assertRaises(ValueError): MODULE.partition_topology(plan, wrong)
            wrong = copy.deepcopy(original)
            wrong["edges"][0]["target"] = "m2"
            with self.assertRaises(ValueError): MODULE.partition_topology(plan, wrong)
            config = Path(plan["nodes"][0]["configuration"])
            value = json.loads(config.read_text())
            value["peers"].append({"endpoint": "127.0.0.1:5002"})
            config.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "undeclared_partition_bypass"):
                MODULE.partition_topology(plan, original)


class OwnedChildTests(unittest.TestCase):
    def test_exact_park_sigkill_reap_and_same_directory_restart_gets_new_run(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            plan, _ = fixture(Path(temporary).resolve())
            child = MODULE.OwnedChild(plan, "m1", arguments(plan))
            try:
                collector = MODULE.EventCollector(plan)
                collector.register(child)
                sample = child.clock_probe(collector)
                self.assertGreaterEqual(sample["uncertainty_ms"], 1)
                child.arm("append_after_commit", 7)
                child.reached(child.receive())
                first_run = child.run_id
                receipt = child.kill_parked()
                self.assertEqual(receipt["exit_signal"], 9)
                self.assertTrue(receipt["child_reaped"])
                self.assertFalse(receipt["g2_passed"])
                self.assertNotIn("token", json.dumps(receipt))
                restart = child.restart()
                self.assertEqual(restart["previous_run_id"], first_run)
                self.assertNotEqual(child.run_id, first_run)
                self.assertFalse(restart["state_recovery_independently_verified"])
            finally:
                child.close()
            self.assertIsNotNone(child.process.returncode)

    def test_boundary_mismatch_unarmed_fault_and_live_restart_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            plan, _ = fixture(Path(temporary).resolve(), "wrong-boundary")
            child = MODULE.OwnedChild(plan, "m1", arguments(plan, mode="wrong-boundary"))
            try:
                with self.assertRaisesRegex(ValueError, "owned_parked_child_required"): child.kill_parked()
                with self.assertRaisesRegex(ValueError, "reaped_owned_child_required"): child.restart()
                child.clock_probe(self.collector(plan, child))
                child.arm("restore_before_commit", 2)
                with self.assertRaisesRegex(ValueError, "exact_armed_boundary_required"): child.reached(child.receive())
                with self.assertRaisesRegex(ValueError, "owned_parked_child_required"): child.kill_parked()
            finally:
                child.close()

    @staticmethod
    def collector(plan, child):
        value = MODULE.EventCollector(plan)
        value.register(child)
        return value

    def test_context_pid_and_frame_limit_fail_closed_and_cleanup_owned_child(self):
        for mode in ["wrong-token", "wrong-pid", "oversize"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
                plan, _ = fixture(Path(temporary).resolve(), mode)
                with self.assertRaises(ValueError): MODULE.OwnedChild(plan, "m1", arguments(plan, mode=mode))

    def test_existing_status_unfrozen_arguments_and_writable_binary_cannot_launch(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            plan, _ = fixture(Path(temporary).resolve())
            with patch.object(MODULE.subprocess, "Popen", side_effect=AssertionError("must not launch")):
                with self.assertRaises(ValueError): MODULE.OwnedChild(plan, "m1", arguments(plan) + ["changed"])
                Path(plan["binary"]).chmod(0o700)
                with self.assertRaises(ValueError): MODULE.OwnedChild(plan, "m1", arguments(plan))
                Path(plan["binary"]).chmod(0o500)
                status = Path(plan["nodes"][0]["directory"]) / "service-status.json"
                status.write_text("{}")
                with self.assertRaises(ValueError): MODULE.OwnedChild(plan, "m1", arguments(plan))

    def test_partial_frame_absolute_deadline_is_not_extended_by_another_receive(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            plan, _ = fixture(Path(temporary).resolve())
            child = MODULE.OwnedChild(plan, "m1", arguments(plan))
            try:
                child.buffer = bytearray(b"x")
                child.frame_started = time.monotonic() - 6
                with self.assertRaisesRegex(ValueError, "native_control_frame_deadline"):
                    child.receive()
            finally:
                child.close()

    def test_binary_change_after_park_refuses_fault(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            plan, _ = fixture(Path(temporary).resolve())
            child = MODULE.OwnedChild(plan, "m1", arguments(plan))
            try:
                child.clock_probe(self.collector(plan, child))
                child.arm("append_before_commit", 3)
                child.reached(child.receive())
                binary = Path(plan["binary"])
                binary.chmod(0o700)
                binary.write_text(binary.read_text() + "\n# changed fixture\n")
                binary.chmod(0o500)
                with self.assertRaisesRegex(ValueError, "binary_digest_mismatch"): child.kill_parked()
                self.assertIsNone(child.process.poll())
            finally:
                child.close()


class StatusModeTests(unittest.TestCase):
    def test_fresh_direct_child_receipt_and_status_bind_without_claiming_native_events(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            plan, _ = fixture(Path(temporary).resolve())
            child = MODULE.OwnedChild(plan, "m1", arguments(plan), "status")
            try:
                deadline = time.monotonic() + 3
                while True:
                    try:
                        value = child.status()
                        break
                    except FileNotFoundError:
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.01)
                self.assertTrue(value["status_identity_matched"])
                self.assertFalse(value["native_control_ipc_connected"])
                self.assertFalse(value["durable_acceptance_instrumented"])
                self.assertFalse(value["named_boundary_support"])
                self.assertEqual(value["status"]["process_id"], child.process.pid)
                path = Path(plan["nodes"][0]["directory"]) / "service-status.json"
                status = json.loads(path.read_text())
                status["process_id"] += 1
                path.write_text(json.dumps(status))
                with self.assertRaises(ValueError): child.status()
            finally:
                child.close()
            self.assertTrue(child.output.closed)
            self.assertIsNotNone(child.process.returncode)

    def test_status_restart_observes_a_new_run_before_returning(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            plan, _ = fixture(Path(temporary).resolve())
            child = MODULE.OwnedChild(plan, "m1", arguments(plan), "status")
            try:
                deadline = time.monotonic() + 3
                while child.run_id is None:
                    try:
                        child.status()
                    except FileNotFoundError:
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(.01)
                original = child.run_id
                os.killpg(child.process.pid, signal.SIGKILL)
                child.process.wait(timeout=3)
                result = child.restart()
                self.assertIsNotNone(child.run_id)
                self.assertNotEqual(original, child.run_id)
                self.assertEqual(result["run_id"], child.run_id)
            finally:
                child.close()

    def test_permission_denied_group_cleanup_still_reaps_only_held_direct_child(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            plan, _ = fixture(Path(temporary).resolve())
            child = MODULE.OwnedChild(plan, "m1", arguments(plan))
            with patch.object(MODULE.os, "killpg", side_effect=PermissionError("synthetic group denial")):
                child.close()
            self.assertFalse(child.cleanup_group_verified)
            self.assertIsNotNone(child.process.returncode)
            self.assertTrue(child.output.closed)
            self.assertEqual(child.stream.fileno(), -1)


class BudgetTests(unittest.TestCase):
    @staticmethod
    def sample(plan):
        return {"free_disk_bytes":100*MODULE.GIB,"host_free_bytes":8*MODULE.GIB,
                "depth_output_bytes":0,"campaign_output_bytes":0,"startup_elapsed_seconds":0,
                "no_progress_seconds":0,"depth_elapsed_seconds":0,"campaign_elapsed_seconds":0,
                "group_rss_bytes":{node["id"]:MODULE.GIB for node in plan["nodes"]}}

    def test_latest_disk_memory_time_and_unknown_limits_stop_without_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, _ = fixture(Path(temporary).resolve())
            sample = self.sample(plan)
            self.assertTrue(MODULE.budget_assessment(plan, sample, initial=True)["allowed"])
            changes = [{"free_disk_bytes":95*MODULE.GIB}, {"host_free_bytes":8*MODULE.GIB-1},
                       {"depth_output_bytes":16*MODULE.GIB+1}, {"campaign_output_bytes":64*MODULE.GIB+1},
                       {"startup_elapsed_seconds":121}, {"no_progress_seconds":181},
                       {"depth_elapsed_seconds":1801}, {"campaign_elapsed_seconds":10801},
                       {"host_free_bytes":None}, {"host_free_bytes":float("nan")},
                       {"group_rss_bytes":{}}]
            for change in changes:
                with self.subTest(change=change):
                    result = MODULE.budget_assessment(plan, {**sample, **change}, initial=True)
                    self.assertFalse(result["allowed"])
                    self.assertTrue(result["sampling_limits_not_os_hard_limits"])
            live = MODULE.budget_assessment(plan,{**sample,"free_disk_bytes":31*MODULE.GIB})
            self.assertIn("host_free_disk_below_stop_threshold",live["stop_reasons"])
            self.assertFalse(live["retry_or_budget_increase_authorized"])

    def test_active_and_paused_group_limits_and_sampling_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, _ = fixture(Path(temporary).resolve())
            sample = self.sample(plan)
            sample["group_rss_bytes"]["m1"] = 4*MODULE.GIB
            self.assertTrue(MODULE.budget_assessment(plan,sample)["allowed"])
            sample["group_rss_bytes"]["m3"] = MODULE.GIB+1
            result = MODULE.budget_assessment(plan,sample)
            self.assertIn("owned_group_rss_limit:m3",result["stop_reasons"])


def host_sample():
    return {"free_disk_bytes": 100 * MODULE.GIB, "host_free_bytes": 12 * MODULE.GIB,
            "sampled_unix_ms": time.time_ns() // 1000000,
            "host_memory_observation": {"basis": "synthetic-memory-sample"}}


class ResourceGuardTests(unittest.TestCase):
    def test_initial_denial_cannot_start_a_child_or_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, _ = fixture(Path(temporary).resolve())
            sample = {**host_sample(), "free_disk_bytes": 95 * MODULE.GIB}
            with patch.object(MODULE, "sample_host_resources", return_value=sample), \
                    patch.object(MODULE.subprocess, "Popen", side_effect=AssertionError("must not start")):
                result = MODULE.run_owned(plan, "m1", arguments(plan), 1)
            self.assertFalse(result["nodes_started"])
            self.assertEqual(result["stopped_reason"], "initial_resource_gate_denied")
            self.assertIn("host_free_disk_below_start_threshold", result["last_resource_assessment"]["stop_reasons"])

    def test_live_unknown_rss_stops_and_reaps_child_with_failure_in_log(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            plan, _ = fixture(Path(temporary).resolve())
            with patch.object(MODULE, "sample_host_resources", return_value=host_sample()), \
                    patch.object(MODULE, "sample_owned_group_rss", return_value={"group_rss_bytes": {}}):
                result = MODULE.run_owned(plan, "m1", arguments(plan), 2, control_mode="ipc")
            self.assertEqual(result["stopped_reason"], "sampled_resource_or_progress_limit")
            self.assertIn("unknown_owned_group_rss", result["last_resource_assessment"]["stop_reasons"])
            self.assertTrue(result["owned_process_group_cleanup_verified"])
            output = Path(plan["nodes"][0]["directory"]) / result["raw_event_file"]
            self.assertIn('"allowed":false', output.read_text())

    def test_sampling_exception_is_retained_and_not_treated_as_available_memory(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan, _ = fixture(Path(temporary).resolve())
            guard = MODULE.ResourceGuard(plan)
            with patch.object(MODULE, "sample_host_resources", side_effect=PermissionError("synthetic denial")):
                result = guard.check([], initial=True)
            self.assertFalse(result["allowed"])
            self.assertEqual(result["stop_reasons"], ["resource_sampling_unavailable"])
            self.assertFalse(result["retry_or_budget_increase_authorized"])

    def test_logical_output_includes_child_stdout_and_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "child.output").write_bytes(b"x" * 4097)
            self.assertEqual(MODULE.output_bytes(root), 4097)
            (root / "link").symlink_to(root / "child.output")
            with self.assertRaisesRegex(ValueError, "campaign_output_symlink_rejected"):
                MODULE.output_bytes(root)

    def test_macos_pressure_sample_preserves_basis_without_summing_inactive_pages(self):
        responses = [type("Result", (), {"stdout": str(32 * MODULE.GIB)})(),
                     type("Result", (), {"stdout": "Pages inactive: 999999.\n"})(),
                     type("Result", (), {"stdout": "System-wide memory free percentage: 30%\n"})()]
        with patch.object(MODULE.platform, "system", return_value="Darwin"), \
                patch.object(MODULE.subprocess, "run", side_effect=responses), \
                patch.object(MODULE.NETWORK.shutil, "disk_usage", return_value=type("Usage", (), {"free": 100 * MODULE.GIB})()):
            sample = MODULE.sample_host_resources("/")
        self.assertEqual(sample["host_free_bytes"], 32 * MODULE.GIB * 30 // 100)
        self.assertEqual(sample["host_memory_observation"]["basis"], "macos-pressure-reported-free-percentage")
        self.assertIn("999999", sample["host_memory_observation"]["vm_stat"])


class EventTests(unittest.TestCase):
    def test_owned_channel_events_coverage_and_clock_histories_stay_distinct_from_native_g2(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            plan, _ = fixture(Path(temporary).resolve())
            child = MODULE.OwnedChild(plan, "m1", arguments(plan))
            try:
                collector = MODULE.EventCollector(plan)
                collector.register(child)
                child.clock_probe(collector)
                observed_plan, document = collector.document()
                result = MODULE.NETWORK.propagation(observed_plan, document)
                self.assertEqual(len(document["missing_node_sessions"]), 4)
                self.assertEqual(len(document["blocks"]), 1)
                self.assertEqual(result["coverage"]["complete_blocks"], 0)
                self.assertEqual(result["coverage"]["unknown_latency_pairs"], 4)
                self.assertEqual(result["all_nodes_latency"]["count"], 0)
                self.assertFalse(result["g2_passed"])
                self.assertNotIn(child.token, json.dumps(document))
            finally:
                child.close()

    def test_command_persists_initial_clock_consumed_events_without_token(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            plan, _ = fixture(Path(temporary).resolve())
            with patch.object(MODULE, "sample_host_resources", return_value=host_sample()), \
                    patch.object(MODULE, "sample_owned_group_rss", return_value={"group_rss_bytes": {"m1": 1024}}):
                result = MODULE.run_owned(plan, "m1", arguments(plan), 1, control_mode="ipc")
            path=Path(plan["nodes"][0]["directory"])/result["raw_event_file"]
            events=[json.loads(line) for line in path.read_text().splitlines()]
            events = [value for value in events if value["kind"] != "resource_sample"]
            self.assertEqual([value["kind"] for value in events],
                             ["block_produced", "block_durable_accepted", "clock_calibration"])
            self.assertTrue(result["owned_process_group_cleanup_verified"])
            self.assertNotIn('"token"',path.read_text())
            self.assertEqual(result["statistics"]["coverage"]["complete_blocks"],0)

    def test_clock_history_selects_fresh_sample_without_resurrecting_old_measurement(self):
        clocks = {"m1": [{"offset_ms": 20, "uncertainty_ms": 5, "calibrated_unix_ms": 1000},
                         {"offset_ms": 30, "uncertainty_ms": 2, "calibrated_unix_ms": 1000000}]}
        self.assertEqual(MODULE.NETWORK.calibrated_time(clocks, "m1", 1000030), (1000000, 2, None))
        self.assertEqual(MODULE.NETWORK.calibrated_time(clocks, "m1", 5000000)[2], "clock_calibration_stale")


if __name__ == "__main__":
    unittest.main()
