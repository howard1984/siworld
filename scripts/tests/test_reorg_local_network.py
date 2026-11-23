"""Bounded infrastructure checks; these do not execute a miner or qualify G2."""
import asyncio
import copy
import contextlib
import io
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "reorg_local_network", Path(__file__).parents[1] / "reorg-local-network.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BoundaryTests(unittest.TestCase):
    def test_only_literal_loopback_endpoints_are_accepted(self):
        for value, expected in [("127.0.0.1:1234", ("127.0.0.1", 1234)),
                                ("[::1]:1234", ("::1", 1234))]:
            self.assertEqual(MODULE.loopback(value), expected)
        for value in ["localhost:1234", "192.0.2.1:1234", "0.0.0.0:1234",
                      "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:01234",
                      "[::]:1234", "127.0.0.1:1234/", "example.test:1234"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                MODULE.loopback(value)

    def test_runtime_tool_refuses_actions_and_ci(self):
        for environment in [{"GITHUB_ACTIONS": "true"}, {"CI": "true"}, {"CI": "1"}]:
            with patch.dict(os.environ, environment, clear=True), self.assertRaises(ValueError):
                MODULE.owner_local()
        with patch.dict(os.environ, {}, clear=True):
            MODULE.owner_local()

    def test_run_paths_cannot_escape_or_traverse_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real = root / "real"
            real.mkdir()
            (real / "file").write_text("synthetic")
            (root / "alias").symlink_to(real, target_is_directory=True)
            self.assertEqual(MODULE.child_path(root, str(real / "file")), real / "file")
            for value in [str(root.parent / "other"), str(root / "alias" / "file"),
                          str(root / "real" / ".." / "real" / "file")]:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    MODULE.child_path(root, value)



class PlanScopeTests(unittest.TestCase):
    @staticmethod
    def fixture(root):
        (root / "reorg-local-network.marker.json").write_text(json.dumps(MODULE.MARKER))
        nodes = []
        genesis = b"synthetic public genesis bytes for topology validation only"
        for role in ["service", "miner"]:
            directory = root / role
            directory.mkdir(mode=0o700)
            (directory / "genesis.bin").write_bytes(genesis)
            # This marker is not a key and is never passed to a native runtime.
            (directory / "native-peer-identity.secret").write_text("synthetic path fixture")
            config = {"version": 2, "engineering": True,
                      "role": "validator" if role == "service" else "miner",
                      "listen": "127.0.0.1:5011" if role == "service" else None,
                      "mining": False, "peers": [], "checkpoint_key": None}
            configuration = directory / "peers.json"
            configuration.write_text(json.dumps(config))
            nodes.append({"id": role, "role": role, "directory": str(directory),
                          "configuration": str(configuration)})
        plan = {"version": 1, "scope": "plumbing", "root": str(root), "nodes": nodes,
                "links": [], "genesis_sha256": hashlib.sha256(genesis).hexdigest(),
                "genesis_id": "1" * 64, "network_id": "2" * 64,
                "source_commit": "3" * 40, "binary_sha256": "4" * 64}
        path = root / "plan.json"
        path.write_text(json.dumps(plan))
        return path, plan

    def test_two_nonmining_nodes_are_plumbing_but_cannot_qualify_as_g2_topology(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            path, plan = self.fixture(Path(temporary).resolve())
            self.assertEqual(MODULE.load_plan(path)["scope"], "plumbing")
            plan["scope"] = "g2"
            path.write_text(json.dumps(plan))
            with self.assertRaises(ValueError):
                MODULE.load_plan(path)

    def test_plumbing_mode_cannot_enable_mining(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            path, plan = self.fixture(Path(temporary).resolve())
            config_path = Path(plan["nodes"][1]["configuration"])
            config = json.loads(config_path.read_text())
            config["mining"] = True
            config_path.write_text(json.dumps(config))
            with self.assertRaises(ValueError):
                MODULE.load_plan(path)


class ObservationTests(unittest.TestCase):
    def test_reorganization_pause_and_alarm_are_observed_without_state_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, plan = PlanScopeTests.fixture(Path(temporary).resolve())
            for node in plan["nodes"]:
                node["run_id"] = node["id"] + "-run"
                status = {"genesis_id": plan["genesis_id"], "network_id": plan["network_id"],
                          "run_id": node["run_id"], "updated_unix_ms": 10000,
                          "height": 12, "tip": "a" * 64, "cumulative_work": "12", "ready": True,
                          "state_available": True, "reorganization_status": "applying_validated_branch",
                          "reorganization_alarm": "reorganization_depth_exceeds_six",
                          "reorganization_depth": 7, "reorganization_ancestor_height": 5,
                          "template_generation": 2, "wallet_export_paused": True}
                (Path(node["directory"]) / "service-status.json").write_text(json.dumps(status))
            with patch.object(MODULE.time, "time_ns", return_value=10000 * 1000000):
                result = MODULE.observe(plan)
            self.assertFalse(result["all_observed_heads_equal"])
            self.assertFalse(result["full_state_fingerprint_verified"])
            self.assertFalse(result["g2_passed"])
            self.assertEqual(result["nodes"][0]["reorganization_depth"], 7)
            self.assertTrue(result["nodes"][0]["wallet_export_paused"])
            self.assertEqual(result["nodes"][0]["reorganization_alarm"], "reorganization_depth_exceeds_six")

    def test_wrong_run_stale_future_and_unavailable_state_do_not_qualify_equal_heads(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, plan = PlanScopeTests.fixture(Path(temporary).resolve())
            for node in plan["nodes"]:
                node["run_id"] = node["id"] + "-run"
                status = {"genesis_id": plan["genesis_id"], "network_id": plan["network_id"],
                          "run_id": node["run_id"], "updated_unix_ms": 100000,
                          "height": 1, "tip": "a" * 64, "cumulative_work": "1", "ready": True,
                          "state_available": True, "reorganization_status": "ready"}
                (Path(node["directory"]) / "service-status.json").write_text(json.dumps(status))
            path = Path(plan["nodes"][0]["directory"]) / "service-status.json"
            baseline = json.loads(path.read_text())
            for change in [{"run_id": "another-run"}, {"updated_unix_ms": 69999},
                           {"updated_unix_ms": 100001}, {"state_available": False}]:
                path.write_text(json.dumps({**baseline, **change}))
                with self.subTest(change=change), patch.object(MODULE.time, "time_ns", return_value=100000 * 1000000):
                    result = MODULE.observe(plan)
                    self.assertFalse(result["all_observed_heads_equal"])
                    if "state_available" not in change:
                        self.assertFalse(result["nodes"][0]["available"])


def campaign_fixture(root):
    path, plan = PlanScopeTests.fixture(root)
    plan.update(run_id="campaign-a", minimum_free_disk_bytes=0, binary=str(root / "native-binary"))
    Path(plan["binary"]).write_bytes(b"synthetic frozen binary fixture; never executed")
    Path(plan["binary"]).chmod(0o500)
    plan["binary_sha256"] = MODULE.digest(Path(plan["binary"]))
    for node in plan["nodes"]:
        node["run_id"] = node["id"] + "-run"
    path.write_text(json.dumps(plan))
    samples = {key: plan[key] for key in ["run_id", "network_id", "genesis_id", "source_commit", "binary_sha256"]}
    samples.update(version=1, kind="block-production-acceptance", synthetic=True,
                   clocks={"miner": {"run_id": "miner-run", "offset_ms": 20,
                                     "uncertainty_ms": 1, "calibrated_unix_ms": 1000},
                           "service": {"run_id": "service-run", "offset_ms": -30,
                                       "uncertainty_ms": 2, "calibrated_unix_ms": 1000}},
                   blocks=[{"block_id": "a" * 64, "producer": "miner", "producer_run_id": "miner-run",
                            "produced_unix_ms": 1000,
                            "accepted": [{"node_id": "service", "run_id": "service-run", "accepted_unix_ms": 1200},
                                         {"node_id": "service", "run_id": "service-run", "accepted_unix_ms": 1100},
                                         {"node_id": "miner", "run_id": "miner-run", "accepted_unix_ms": 1020}]},
                           {"block_id": "b" * 64, "producer": "miner", "producer_run_id": "miner-run",
                            "produced_unix_ms": 2000,
                            "accepted": [{"node_id": "service", "run_id": "service-run", "accepted_unix_ms": 2260},
                                         {"node_id": "miner", "run_id": "miner-run", "accepted_unix_ms": 2000}]}])
    return path, plan, samples


class PropagationTests(unittest.TestCase):
    def test_command_reads_only_owned_samples_inside_the_frozen_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, plan, samples = campaign_fixture(Path(temporary).resolve())
            sample_path = path.parent / "events.json"
            sample_path.write_text(json.dumps(samples))
            with patch.dict(os.environ, {}, clear=True), \
                    patch.object(MODULE.os, "kill", side_effect=AssertionError("signals prohibited")), \
                    patch.object(MODULE.asyncio, "start_server", side_effect=AssertionError("ports prohibited")), \
                    patch.object(MODULE.asyncio, "open_connection", side_effect=AssertionError("connections prohibited")), \
                    patch.object(MODULE.sys, "argv", ["reorg-local-network.py", "propagation", str(path),
                                                    "--samples", str(sample_path)]), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                MODULE.main()
            self.assertEqual(json.loads(output.getvalue())["all_nodes_latency"]["mean_ms"], 230)
            with patch.dict(os.environ, {}, clear=True), \
                    patch.object(MODULE.sys, "argv", ["reorg-local-network.py", "propagation", str(path),
                                                    "--samples", str(path.parent.parent / "outside-events.json")]), \
                    self.assertRaisesRegex(ValueError, "path_outside_run_root"):
                MODULE.main()

    def test_first_acceptance_clock_correction_and_complete_block_quantiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, plan, samples = campaign_fixture(Path(temporary).resolve())
            result = MODULE.propagation(plan, samples)
            self.assertEqual(result["sample_source"], "synthetic")
            self.assertFalse(result["event_source_independently_verified"])
            self.assertFalse(result["status_snapshots_are_acceptance_events"])
            self.assertFalse(result["relay_bytes_are_propagation"])
            self.assertFalse(result["g2_passed"])
            self.assertEqual(result["coverage"], {"expected_node_block_pairs": 4, "observed_node_block_pairs": 4,
                                                "qualified_latency_pairs": 4, "unknown_latency_pairs": 0,
                                                "complete_blocks": 2, "incomplete_blocks": 0})
            self.assertEqual(result["all_nodes_latency"]["mean_ms"], 230)
            self.assertEqual(result["all_nodes_latency"]["p50_ms"], 150)
            self.assertEqual(result["all_nodes_latency"]["p95_ms"], 310)
            self.assertEqual(result["pooled_node_latency"]["mean_ms"], 120)
            first = result["blocks"][0]
            self.assertEqual(first["all_nodes_latency_lower_ms"], 147)
            self.assertEqual(first["all_nodes_latency_upper_ms"], 153)
            self.assertEqual(first["nodes"][0]["first_accepted_unix_ms"], 1100)

    def test_missing_acceptance_and_clock_samples_remain_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, plan, samples = campaign_fixture(Path(temporary).resolve())
            samples["blocks"][1]["accepted"] = samples["blocks"][1]["accepted"][1:]
            result = MODULE.propagation(plan, samples)
            self.assertEqual(result["coverage"]["observed_node_block_pairs"], 3)
            self.assertEqual(result["all_nodes_latency"]["count"], 1)
            self.assertIsNone(result["blocks"][1]["all_nodes_latency_ms"])
            self.assertEqual(result["blocks"][1]["nodes"][0]["unknown_reason"], "acceptance_event_missing")
            del samples["clocks"]["service"]
            result = MODULE.propagation(plan, samples)
            self.assertEqual(result["all_nodes_latency"]["count"], 0)
            self.assertEqual(result["blocks"][0]["nodes"][0]["unknown_reason"], "clock_calibration_missing")
            self.assertEqual(result["coverage"]["unknown_latency_pairs"], 2)

    def test_stale_clocks_and_negative_delays_never_become_zero_latency_successes(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, plan, original = campaign_fixture(Path(temporary).resolve())
            for accepted, reason in [(900, "clock_or_event_order_inconsistent"),
                                     (999, "clock_or_event_order_uncertain")]:
                samples = copy.deepcopy(original)
                samples["blocks"][0]["accepted"][-1]["accepted_unix_ms"] = accepted
                result = MODULE.propagation(plan, samples)
                value = result["blocks"][0]["nodes"][1]
                self.assertIsNone(value["latency_ms"])
                self.assertEqual(value["unknown_reason"], reason)
                self.assertIsNone(result["blocks"][0]["all_nodes_latency_ms"])
            samples = copy.deepcopy(original)
            samples["clocks"]["miner"]["calibrated_unix_ms"] = 1000000
            result = MODULE.propagation(plan, samples)
            self.assertEqual(result["pooled_node_latency"]["count"], 0)
            self.assertEqual(result["blocks"][0]["nodes"][0]["unknown_reason"], "clock_calibration_stale")

    def test_mismatched_runs_provenance_nonfinite_and_duplicate_blocks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, plan, original = campaign_fixture(Path(temporary).resolve())
            variants = [[], None]
            value = copy.deepcopy(original)
            value["version"] = True
            variants.append(value)
            value = copy.deepcopy(original)
            value["clocks"]["miner"] = []
            variants.append(value)
            value = copy.deepcopy(original)
            value["blocks"][0]["accepted"][0] = []
            variants.append(value)
            for key in ["run_id", "network_id", "genesis_id", "source_commit", "binary_sha256", "kind"]:
                value = copy.deepcopy(original)
                value[key] = "wrong"
                variants.append(value)
            value = copy.deepcopy(original)
            value["clocks"]["miner"]["run_id"] = "previous-run"
            variants.append(value)
            value = copy.deepcopy(original)
            value["blocks"][0]["accepted"][0]["run_id"] = "previous-run"
            variants.append(value)
            value = copy.deepcopy(original)
            value["blocks"][0]["produced_unix_ms"] = float("nan")
            variants.append(value)
            value = copy.deepcopy(original)
            value["blocks"].append(value["blocks"][0])
            variants.append(value)
            for index, value in enumerate(variants):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    MODULE.propagation(plan, value)

    def test_work_bounds_and_empty_samples_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, plan, samples = campaign_fixture(Path(temporary).resolve())
            with patch.object(MODULE, "MAX_ACCEPTANCE_EVENTS", 1), self.assertRaises(ValueError):
                MODULE.propagation(plan, samples)
            with patch.object(MODULE, "MAX_PROPAGATION_BLOCKS", 1), self.assertRaises(ValueError):
                MODULE.propagation(plan, samples)
            samples["blocks"] = []
            result = MODULE.propagation(plan, samples)
            self.assertEqual(result["coverage"]["complete_blocks"], 0)
            self.assertEqual(result["all_nodes_latency"]["count"], 0)
            self.assertIsNone(result["all_nodes_latency"]["mean_ms"])


class FaultCapabilityTests(unittest.TestCase):
    def fixture(self, root):
        path, plan, _ = campaign_fixture(root)
        node = plan["nodes"][0]
        status = {"run_id": node["run_id"], "process_id": 424242,
                  "network_id": plan["network_id"], "genesis_id": plan["genesis_id"], "updated_unix_ms": 10000}
        (Path(node["directory"]) / "service-status.json").write_text(json.dumps(status))
        process = {"pid": 424242, "uid": os.geteuid(), "run_id": node["run_id"],
                   "campaign_run_id": plan["run_id"], "executable": plan["binary"],
                   "binary_sha256": plan["binary_sha256"], "node_directory": node["directory"],
                   "start_token": "synthetic-start-token"}
        return path, plan, node, process

    def test_matching_supplied_facts_never_authorize_or_execute_a_signal(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, plan, node, process = self.fixture(Path(temporary).resolve())
            facts = path.parent / "process-facts.json"
            facts.write_text(json.dumps(process))
            with patch.dict(os.environ, {}, clear=True), patch.object(MODULE.time, "time_ns", return_value=10000 * 1000000), \
                    patch.object(MODULE.os, "kill", side_effect=AssertionError("signals prohibited")), \
                    patch.object(MODULE.asyncio, "start_server", side_effect=AssertionError("ports prohibited")), \
                    patch.object(MODULE.sys, "argv", ["reorg-local-network.py", "fault-capabilities", str(path),
                                                    "--node", node["id"], "--process-facts", str(facts)]), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                MODULE.main()
            result = json.loads(output.getvalue())
            self.assertTrue(result["supplied_facts_match"])
            self.assertTrue(result["frozen_binary_digest_verified"])
            self.assertFalse(result["live_process_identity_attested"])
            self.assertFalse(result["signal_delivery_supported"])
            self.assertFalse(result["fault_injected"])
            self.assertFalse(result["g2_passed"])
            self.assertIn("owned_child_process_handle", result["missing_capabilities"])

    def test_other_users_runs_binaries_directories_and_statuses_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, plan, node, original = self.fixture(Path(temporary).resolve())
            changes = [{"uid": os.geteuid() + 1}, {"pid": 1}, {"run_id": "old-run"},
                       {"campaign_run_id": "old-campaign"}, {"executable": "/not-the-binary"},
                       {"binary_sha256": "0" * 64}, {"node_directory": str(Path(plan["root"]))},
                       {"start_token": ""}]
            for change in changes:
                with self.subTest(change=change), patch.object(MODULE.time, "time_ns", return_value=10000 * 1000000), \
                        self.assertRaises(ValueError):
                    MODULE.fault_capabilities(plan, node["id"], {**original, **change})
            status_path = Path(node["directory"]) / "service-status.json"
            status = json.loads(status_path.read_text())
            for change in [{"run_id": "old-run"}, {"process_id": 424243}, {"updated_unix_ms": 10001}]:
                status_path.write_text(json.dumps({**status, **change}))
                with self.subTest(change=change), patch.object(MODULE.time, "time_ns", return_value=10000 * 1000000), \
                        self.assertRaises(ValueError):
                    MODULE.fault_capabilities(plan, node["id"], original)

    def test_changed_frozen_binary_and_missing_isolation_marker_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, plan, node, process = self.fixture(Path(temporary).resolve())
            marker = Path(plan["root"]) / "reorg-local-network.marker.json"
            marker.unlink()
            with self.assertRaises(FileNotFoundError):
                MODULE.fault_capabilities(plan, node["id"], process)
            marker.write_text(json.dumps(MODULE.MARKER))
            binary = Path(plan["binary"])
            binary.chmod(0o700)
            binary.write_bytes(b"changed synthetic binary; never executed")
            binary.chmod(0o500)
            with self.assertRaisesRegex(ValueError, "binary_digest_mismatch"):
                MODULE.fault_capabilities(plan, node["id"], process)


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.echo_clients = set()

        async def echo(reader, writer):
            task = asyncio.current_task()
            self.echo_clients.add(task)
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                self.echo_clients.discard(task)

        self.echo = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = self.echo.sockets[0].getsockname()[1]
        self.relay = MODULE.Relay({"id": "synthetic-link", "target": f"127.0.0.1:{port}"})
        self.server = await asyncio.start_server(self.relay.connected, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        self.echo.close()
        await self.server.wait_closed()
        await self.echo.wait_closed()
        await self.relay.set_enabled(False)
        await asyncio.gather(*list(self.echo_clients), return_exceptions=True)

    async def test_partition_closes_existing_stream_and_heal_uses_new_connection(self):
        await self.relay.set_enabled(True)
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        body = bytes(range(256)) * 1024
        writer.write(body)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(body)), 3), body)
        self.assertEqual(self.relay.bytes, [len(body), len(body)])
        await self.relay.set_enabled(False)
        self.assertEqual(await asyncio.wait_for(reader.read(1), 3), b"")
        writer.close()
        await writer.wait_closed()
        await self.relay.set_enabled(True)
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(b"new-session")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(11), 3), b"new-session")
        self.assertEqual(self.relay.accepted, 2)
        writer.close()
        await writer.wait_closed()

    async def test_disabled_link_rejects_new_connections(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.assertEqual(await asyncio.wait_for(reader.read(1), 3), b"")
        self.assertEqual(self.relay.accepted, 0)
        self.assertEqual(self.relay.rejected, 1)
        writer.close()
        await writer.wait_closed()


if __name__ == "__main__":
    unittest.main()
