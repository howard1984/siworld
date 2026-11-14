#!/usr/bin/env python3
"""Isolated topology, direct-child control, and native event collection.

Only a process created by this controller can be controlled. No existing PID,
service directory, or external network endpoint can be adopted. Native event
and named-boundary support must be supplied by the selected rehearsal binary.
"""
import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import socket
import stat
import subprocess
import time

SPEC = importlib.util.spec_from_file_location("reorg_network", Path(__file__).with_name("reorg-local-network.py"))
NETWORK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NETWORK)
require = NETWORK.require
MAX_FRAME = 16384
MAX_EVENTS = 50000
BOUNDARIES = {
    "restore_before_commit", "restore_after_commit", "restore_after_publish", "restore_after_capture",
    "append_before_commit", "append_after_commit", "append_after_publish", "append_after_capture",
    "replacement_prevalidated", "branch_archive_committed",
}
CONTEXT = ("campaign_id", "node_id", "network_id", "genesis_id", "binary_sha256")


def checked_plan(path):
    plan = NETWORK.load_plan(path)
    NETWORK.preflight(plan)
    NETWORK.run_identifier(plan.get("run_id"))
    return plan


def node_entry(plan, identifier):
    nodes = [node for node in plan["nodes"] if node["id"] == identifier]
    require(len(nodes) == 1, "explicit_campaign_node_required")
    return nodes[0]


def partition_topology(plan, topology):
    """Bind each directed relay to its actual source config and target listener."""
    require(topology.get("version") == 1 and topology.get("run_id") == plan["run_id"], "topology_run_mismatch")
    nodes = {node["id"]: node for node in plan["nodes"]}
    groups = topology.get("groups")
    require(isinstance(groups, list) and len(groups) == 2 and all(isinstance(group, list) for group in groups),
            "two_partition_groups_required")
    members = [node for group in groups for node in group]
    require(len(members) == len(set(members)) and set(members) == set(nodes), "partition_membership_rejected")
    for group in groups:
        require(any(nodes[node]["role"] == "miner" for node in group) and
                any(nodes[node]["role"] == "service" for node in group), "partition_producer_and_service_required")
    edges = topology.get("edges")
    require(isinstance(edges, list) and len(edges) == len(plan["links"]), "complete_relay_edges_required")
    links = {link["id"]: link for link in plan["links"]}
    require(len(links) == len(edges) and {edge["link_id"] for edge in edges} == set(links), "relay_edge_identity_rejected")
    configs = {name: NETWORK.bounded_json(node["configuration"]) for name, node in nodes.items()}
    crossing = []
    for edge in edges:
        source, target = edge["source"], edge["target"]
        require(source in nodes and target in nodes and source != target, "relay_node_binding_rejected")
        link = links[edge["link_id"]]
        require(configs[target]["listen"] is not None and
                NETWORK.loopback(link["target"]) == NETWORK.loopback(configs[target]["listen"]), "relay_target_binding_rejected")
        require(any(NETWORK.loopback(peer["endpoint"]) == NETWORK.loopback(link["listen"])
                    for peer in configs[source]["peers"]), "relay_source_binding_rejected")
        if (source in groups[0]) != (target in groups[0]):
            crossing.append(link["id"])
    # A peer endpoint outside the declared relays would bypass the partition.
    for name, config in configs.items():
        declared = {NETWORK.loopback(links[edge["link_id"]]["listen"]) for edge in edges if edge["source"] == name}
        require({NETWORK.loopback(peer["endpoint"]) for peer in config["peers"]} == declared,
                "undeclared_partition_bypass")
    require(crossing, "cross_partition_links_required")
    return {"version": 1, "scope": "validated-isolated-partition-topology", "run_id": plan["run_id"],
            "groups": groups, "crossing_links": sorted(crossing), "links": sorted(links),
            "nodes_started": False, "partition_applied": False, "g2_passed": False}


def set_partition(plan, topology, partitioned):
    """Change only owned run-local relay controls; no firewall or socket call."""
    assessment = partition_topology(plan, topology)
    root = Path(plan["root"])
    require(NETWORK.bounded_json(root / "reorg-local-network.marker.json") == NETWORK.MARKER, "isolated_run_marker_required")
    for link in plan["links"]:
        path = NETWORK.child_path(root, link["control"])
        previous = NETWORK.bounded_json(path)
        require(set(previous) == {"version", "enabled"} and previous["version"] == 1 and type(previous["enabled"]) is bool,
                "relay_control_rejected")
    for link in plan["links"]:
        path = NETWORK.child_path(root, link["control"])
        temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
        enabled = not partitioned or link["id"] not in assessment["crossing_links"]
        with temporary.open("x", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump({"version": 1, "enabled": enabled}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    return {**assessment, "partition_applied": partitioned, "controls_updated": True,
            "transition_atomic_across_relays": False}


def binary_identity(plan):
    path = Path(plan["binary"])
    metadata = path.lstat()
    require(path.is_absolute() and path.resolve() == path and stat.S_ISREG(metadata.st_mode) and
            metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o500,
            "private_frozen_executable_required")
    require(NETWORK.digest(path) == plan["binary_sha256"], "binary_digest_mismatch")
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)


def arguments_digest(arguments):
    import hashlib
    return hashlib.sha256(json.dumps(arguments, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


class OwnedChild:
    """One unreaped direct Popen child; PID-only attachment is not supported."""
    def __init__(self, plan, node_id, arguments, control_mode="ipc"):
        NETWORK.owner_local()
        NETWORK.preflight(plan)
        require(control_mode in {"ipc", "status"}, "explicit_control_mode_required")
        self.control_mode = control_mode
        self.plan = plan
        self.node = node_entry(plan, node_id)
        self.directory = NETWORK.child_path(Path(plan["root"]), self.node["directory"])
        require(NETWORK.bounded_json(Path(plan["root"]) / "reorg-local-network.marker.json") == NETWORK.MARKER,
                "isolated_run_marker_required")
        require(isinstance(arguments, list) and 0 < len(arguments) <= 32 and
                all(isinstance(value, str) and 0 < len(value) <= 4096 and "\0" not in value for value in arguments),
                "bounded_direct_arguments_required")
        require(str(self.directory) in arguments and self.node["configuration"] in arguments and
                arguments_digest(arguments) == self.node.get("arguments_sha256"), "frozen_node_arguments_required")
        require(not (self.directory / "service-status.json").exists() and
                not (self.directory / "rehearsal-controller.started").exists(), "fresh_owned_launch_required")
        self.binary_identity = binary_identity(plan)
        self.arguments = list(arguments)
        self.token = secrets.token_hex(32)
        self.launch_id = secrets.token_hex(16)
        self.context = {"campaign_id": plan["run_id"], "node_id": node_id,
                        "network_id": plan["network_id"], "genesis_id": plan["genesis_id"],
                        "binary_sha256": plan["binary_sha256"]}
        self.process = None
        self.cleanup_group_verified = True
        self.stream = None
        self.buffer = bytearray()
        self.frame_started = None
        self.sequence = -1
        self.run_id = None
        self.armed = None
        self.parked = False
        self.started_ns = time.monotonic_ns()
        self.started_unix_ms = time.time_ns() // 1000000
        self.configuration_sha256 = NETWORK.digest(Path(self.node["configuration"]))
        self.output = (self.directory / "rehearsal-child.output").open("xb")
        os.chmod(self.directory / "rehearsal-child.output", 0o600)
        self._launch()

    def _launch(self):
        if self.control_mode == "status":
            try:
                self.process = subprocess.Popen([self.plan["binary"], *self.arguments], cwd=self.directory,
                                                env={"PATH": os.defpath, "LANG": "C", "RAYON_NUM_THREADS": "4",
                                                     "SIWORLD_COMPOSITION_HIDING_WORKERS": "2"},
                                                stdin=subprocess.DEVNULL, stdout=self.output, stderr=self.output,
                                                close_fds=True, start_new_session=True)
                self._marker()
                require(binary_identity(self.plan) == self.binary_identity, "frozen_binary_changed_during_launch")
            except BaseException:
                self.close()
                raise
            return
        parent, child = socket.socketpair()
        parent.settimeout(5)
        environment = {"PATH": os.defpath, "LANG": "C", "RAYON_NUM_THREADS": "4",
                       "SIWORLD_COMPOSITION_HIDING_WORKERS": "2",
                       "SIWORLD_REORG_CONTROL_FD": str(child.fileno()),
                       "SIWORLD_REORG_CONTROL_TOKEN": self.token,
                       "SIWORLD_REORG_CAMPAIGN_ID": self.plan["run_id"],
                       "SIWORLD_REORG_NODE_ID": self.context["node_id"]}
        try:
            # No shell, privilege transition or PID adoption.
            self.process = subprocess.Popen([self.plan["binary"], *self.arguments], cwd=self.directory,
                                            env=environment, stdin=subprocess.DEVNULL,
                                            stdout=self.output, stderr=self.output,
                                            pass_fds=(child.fileno(),), close_fds=True, start_new_session=True)
            self.stream = parent
            child.close()
            self._marker()
            hello = self.receive()
            require(hello["kind"] == "hello" and self.run_id is not None, "native_hello_required")
            require(binary_identity(self.plan) == self.binary_identity, "frozen_binary_changed_during_launch")
        except BaseException:
            child.close()
            parent.close()
            self.close()
            raise

    def _marker(self):
        marker = self.directory / "rehearsal-controller.started"
        if not marker.exists():
            with marker.open("x", encoding="utf-8") as file:
                os.chmod(marker, 0o600)
                file.write(self.launch_id + "\n")
        require(marker.read_text() == self.launch_id + "\n", "owned_launch_marker_mismatch")

    def status(self):
        require(self.control_mode == "status" and self.process.returncode is None, "owned_status_mode_required")
        status_path = NETWORK.child_path(Path(self.plan["root"]), str(self.directory / "service-status.json"), exists=False)
        value = NETWORK.bounded_json(status_path)
        now = time.time_ns() // 1000000
        run = NETWORK.run_identifier(value.get("run_id"))
        require(value.get("process_id") == self.process.pid and value.get("network_id") == self.plan["network_id"] and
                value.get("genesis_id") == self.plan["genesis_id"] and
                type(value.get("updated_unix_ms")) is int and
                self.started_unix_ms <= value["updated_unix_ms"] <= now and now - value["updated_unix_ms"] <= 30000,
                "fresh_owned_status_identity_required")
        receipt_path = NETWORK.child_path(Path(self.plan["root"]), str(self.directory / "service-runs" / run / "run.json"), exists=False)
        receipt = NETWORK.bounded_json(receipt_path)
        require(receipt.get("run_id") == run and receipt.get("process_id") == self.process.pid and
                receipt.get("network_id") == self.plan["network_id"] and
                receipt.get("binary_sha256") == self.plan["binary_sha256"] and
                receipt.get("configuration_sha256") == self.configuration_sha256 and
                type(receipt.get("started_unix_ms")) is int and
                self.started_unix_ms <= receipt["started_unix_ms"] <= value["updated_unix_ms"],
                "owned_native_run_receipt_mismatch")
        require(self.run_id is None or self.run_id == run, "owned_status_run_changed")
        require(binary_identity(self.plan) == self.binary_identity and
                NETWORK.digest(Path(self.node["configuration"])) == self.configuration_sha256,
                "owned_binary_or_configuration_changed")
        self.run_id = run
        fields = {"height", "tip", "cumulative_work", "state_available", "ready", "phase", "updated_unix_ms",
                  "run_id", "process_id", "reorganization_status", "reorganization_alarm", "reorganization_depth"}
        return {"status": {key: value[key] for key in fields if key in value}, "status_identity_matched": True,
                "native_control_ipc_connected": False, "durable_acceptance_instrumented": False,
                "named_boundary_support": False, "g2_passed": False}

    def restart(self):
        require(self.cleanup_group_verified, "previous_group_cleanup_unverified")
        require(self.process is not None and self.process.returncode is not None and self.run_id is not None,
                "reaped_owned_child_required")
        require((self.directory / "rehearsal-controller.started").read_text() == self.launch_id + "\n",
                "owned_launch_marker_mismatch")
        require(binary_identity(self.plan) == self.binary_identity, "frozen_binary_changed_before_restart")
        previous = self.run_id
        if self.stream is not None:
            self.stream.close()
        self.started_ns = time.monotonic_ns()
        self.started_unix_ms = time.time_ns() // 1000000
        self.token = secrets.token_hex(32)
        self.buffer.clear()
        self.frame_started = None
        self.sequence = -1
        self.run_id = None
        self.armed = None
        self.parked = False
        self._launch()
        if self.control_mode == "status":
            deadline = time.monotonic() + 5
            try:
                while True:
                    try:
                        self.status()
                        break
                    except (OSError, ValueError, KeyError, TypeError):
                        require(time.monotonic() < deadline, "restart_fresh_status_deadline")
                        time.sleep(0.01)
            except BaseException:
                self.close()
                raise
        require(self.run_id != previous, "restart_requires_fresh_native_run")
        return {"previous_run_id": previous, "run_id": self.run_id, "same_node_directory": True,
                "same_frozen_binary": True, "state_recovery_independently_verified": False}

    def stop_native(self, timeout=30):
        """Ask only this held native run to stop before read-only database audit."""
        require(self.control_mode == "status" and type(timeout) is int and 1 <= timeout <= 30,
                "bounded_native_status_stop_required")
        self.status()
        require(binary_identity(self.plan) == self.binary_identity, "frozen_binary_changed_before_stop")
        run = self.run_id
        stopped = subprocess.run([self.plan["binary"], "stop", str(self.directory), run],
                                 cwd=self.directory, env={"PATH": os.defpath, "LANG": "C"},
                                 stdin=subprocess.DEVNULL, stdout=self.output, stderr=self.output,
                                 close_fds=True, timeout=timeout, check=True)
        code = self.process.wait(timeout=timeout)
        require(stopped.returncode == 0 and code == 0, "owned_native_normal_stop_failed")
        return {"node_id": self.context["node_id"], "run_id": run, "normal_stop_requested": True,
                "child_reaped": True, "forced_kill_used": False, "read_only_audit_performed": False}

    def send(self, kind, **values):
        require(self.control_mode == "ipc" and self.process is not None and self.process.returncode is None,
                "owned_ipc_child_required")
        frame = {"version": 1, "kind": kind, "token": self.token, **self.context,
                 "run_id": self.run_id, **values}
        encoded = json.dumps(frame, separators=(",", ":")).encode() + b"\n"
        require(len(encoded) <= MAX_FRAME, "control_frame_limit")
        self.stream.sendall(encoded)

    def receive(self):
        require(self.control_mode == "ipc" and self.process is not None and self.process.returncode is None,
                "owned_ipc_child_required")
        original_timeout = self.stream.gettimeout()
        call_deadline = time.monotonic() + (original_timeout if original_timeout is not None else 5)
        try:
            while b"\n" not in self.buffer:
                now = time.monotonic()
                frame_deadline = self.frame_started + 5 if self.frame_started is not None else call_deadline
                require(now < frame_deadline, "native_control_frame_deadline")
                remaining = min(call_deadline, frame_deadline) - now
                if remaining <= 0:
                    raise socket.timeout()
                self.stream.settimeout(remaining)
                part = self.stream.recv(min(4096, MAX_FRAME + 1 - len(self.buffer)))
                require(part, "native_control_channel_closed")
                if not self.buffer:
                    self.frame_started = time.monotonic()
                self.buffer.extend(part)
                require(len(self.buffer) <= MAX_FRAME, "native_control_frame_limit")
        finally:
            self.stream.settimeout(original_timeout)
        encoded, _, remainder = self.buffer.partition(b"\n")
        self.buffer = bytearray(remainder)
        self.frame_started = time.monotonic() if remainder else None
        frame = json.loads(encoded)
        require(isinstance(frame, dict) and type(frame.get("version")) is int and frame.get("version") == 1 and frame.get("token") == self.token and
                all(frame.get(key) == value for key, value in self.context.items()), "native_control_context_mismatch")
        require(frame.get("process_id") == self.process.pid and type(frame.get("sequence")) is int and
                frame["sequence"] == self.sequence + 1, "native_process_or_sequence_mismatch")
        if self.run_id is None:
            require(frame.get("kind") == "hello", "native_hello_required")
            self.run_id = NETWORK.run_identifier(frame.get("run_id"))
        require(frame.get("run_id") == self.run_id, "native_control_run_mismatch")
        self.sequence = frame["sequence"]
        # Return only schema fields; never retain the ephemeral token or arbitrary child text.
        fields = {"kind", "sequence", "run_id", "process_id", "unix_ms", "monotonic_ns", "height", "block_id",
                  "boundary", "arm_id", "probe_id", "parked"}
        return {key: value for key, value in frame.items() if key in fields}

    def arm(self, boundary, height):
        require(boundary in BOUNDARIES and type(height) is int and height >= 0 and self.armed is None,
                "explicit_named_boundary_required")
        self.armed = {"boundary": boundary, "height": height, "arm_id": secrets.token_hex(16)}
        self.send("arm_boundary", **self.armed)

    def reached(self, frame):
        require(self.armed is not None and frame.get("kind") == "boundary_parked" and
                frame.get("parked") is True and all(frame.get(key) == value for key, value in self.armed.items()),
                "exact_armed_boundary_required")
        self.parked = True

    def kill_parked(self):
        require(self.control_mode == "ipc" and self.parked and self.armed is not None and self.process.returncode is None,
                "owned_parked_child_required")
        require(binary_identity(self.plan) == self.binary_identity, "frozen_binary_changed_before_fault")
        # The group leader has never been reaped, so this PGID cannot be recycled.
        os.killpg(self.process.pid, signal.SIGKILL)
        code = self.process.wait(timeout=5)
        require(code == -signal.SIGKILL, "owned_child_kill_unconfirmed")
        return {"version": 1, "scope": "owned-child-named-boundary-fault", "node_id": self.context["node_id"],
                "campaign_id": self.plan["run_id"], "run_id": self.run_id, "launch_id": self.launch_id,
                **self.armed, "exit_signal": signal.SIGKILL, "child_reaped": True, "g2_passed": False}

    def resume(self):
        require(self.parked and self.armed is not None, "owned_parked_child_required")
        self.send("resume_boundary", **self.armed)
        self.parked = False
        self.armed = None

    def clock_probe(self, collector):
        require(not self.parked, "clock_probe_requires_running_child")
        probe = secrets.token_hex(16)
        before_ns = time.monotonic_ns()
        before_wall = time.time_ns() / 1_000_000
        self.send("clock_ping", probe_id=probe)
        while time.monotonic_ns() - before_ns <= 5_000_000_000:
            frame = self.receive()
            if frame["kind"] in {"block_produced", "block_durable_accepted"}:
                collector.record(self.context["node_id"], frame)
                continue
            require(frame["kind"] == "clock_reply" and frame.get("probe_id") == probe,
                    "matching_clock_reply_required")
            after_wall = time.time_ns() / 1_000_000
            after_ns = time.monotonic_ns()
            return collector.calibrate(self.context["node_id"], frame.get("unix_ms"),
                                       before_wall, before_ns, after_wall, after_ns)
        raise ValueError("clock_probe_deadline")

    def close(self):
        try:
            if self.process is not None and self.process.returncode is None:
                # Keep the group leader unreaped until all group operations end.
                # macOS may return EPERM for a group containing only zombies;
                # inspect live membership before attempting the final signal.
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    self.cleanup_group_verified = False
                    self.process.send_signal(signal.SIGTERM)
                time.sleep(0.1)
                try:
                    live = live_owned_group_members(self.process.pid)
                    if live:
                        try:
                            os.killpg(self.process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        except PermissionError:
                            self.cleanup_group_verified = False
                            self.process.send_signal(signal.SIGKILL)
                        time.sleep(0.1)
                        if live_owned_group_members(self.process.pid):
                            self.cleanup_group_verified = False
                except (OSError, ValueError, subprocess.SubprocessError):
                    self.cleanup_group_verified = False
                    self.process.send_signal(signal.SIGKILL)
                self.process.wait(timeout=5)
        finally:
            if self.stream is not None:
                self.stream.close()
            self.output.close()


class EventCollector:
    """Native channel events only; transport receipt time is not acceptance."""
    def __init__(self, plan):
        self.plan = plan
        self.runs = {}
        self.produced = {}
        self.accepted = {}
        self.clocks = {}
        self.count = 0
        self.last_times = {}
        self.sink = None

    def register(self, child):
        node = child.context["node_id"]
        require(node not in self.runs and child.run_id is not None, "unique_owned_node_session_required")
        self.runs[node] = child.run_id

    def record(self, node, event):
        require(node in self.runs and event.get("run_id") == self.runs[node], "event_owned_session_mismatch")
        require(self.count < MAX_EVENTS, "native_event_limit")
        kind = event.get("kind")
        require(kind in {"block_produced", "block_durable_accepted"}, "native_block_event_required")
        require(type(event.get("height")) is int and event["height"] > 0 and
                isinstance(event.get("block_id"), str) and len(event["block_id"]) == 64 and
                set(event["block_id"]) <= set("0123456789abcdef"), "native_block_identity_required")
        NETWORK.milliseconds(event.get("unix_ms"))
        require(type(event.get("monotonic_ns")) is int and event["monotonic_ns"] >= 0, "native_monotonic_time_required")
        require(event["monotonic_ns"] >= self.last_times.get(node, -1), "native_event_monotonic_regression")
        self.last_times[node] = event["monotonic_ns"]
        self.count += 1
        if self.sink is not None:
            self.sink({"node_id": node, **event})
        identity = event["block_id"]
        if kind == "block_produced":
            require(identity not in self.produced, "duplicate_block_production_event")
            self.produced[identity] = {"block_id": identity, "producer": node, "producer_run_id": self.runs[node],
                                       "height": event["height"], "produced_unix_ms": event["unix_ms"]}
        else:
            key = (node, identity)
            previous = self.accepted.get(key)
            if previous is None or event["monotonic_ns"] < previous["monotonic_ns"]:
                self.accepted[key] = {"node_id": node, "run_id": self.runs[node],
                                      "accepted_unix_ms": event["unix_ms"], "monotonic_ns": event["monotonic_ns"]}

    def calibrate(self, node, child_time, before_wall_ms, before_ns, after_wall_ms, after_ns):
        require(node in self.runs and 0 <= after_ns - before_ns <= 5_000_000_000, "bounded_clock_roundtrip_required")
        NETWORK.milliseconds(child_time)
        NETWORK.milliseconds(before_wall_ms)
        NETWORK.milliseconds(after_wall_ms)
        elapsed = (after_ns - before_ns) / 1_000_000
        discontinuity = abs((after_wall_ms - before_wall_ms) - elapsed)
        midpoint = (before_wall_ms + after_wall_ms) / 2
        sample = {"run_id": self.runs[node], "offset_ms": child_time - midpoint,
                  "uncertainty_ms": elapsed / 2 + discontinuity + 1,
                  "calibrated_unix_ms": midpoint}
        require(len(self.clocks.get(node, [])) < 1000, "clock_sample_limit")
        self.clocks.setdefault(node, []).append(sample)
        if self.sink is not None:
            self.sink({"kind": "clock_calibration", "node_id": node, **sample})
        return sample

    def document(self):
        blocks = []
        for identity, production in self.produced.items():
            accepted = [{key: value for key, value in event.items() if key != "monotonic_ns"}
                        for (node, block), event in self.accepted.items() if block == identity]
            blocks.append({**production, "accepted": accepted})
        plan = {**self.plan, "nodes": [{**node, "run_id": self.runs.get(node["id"], "unobserved-" + node["id"]),
                                        "session_available": node["id"] in self.runs}
                                       for node in self.plan["nodes"]]}
        samples = {key: plan[key] for key in ["run_id", "network_id", "genesis_id", "source_commit", "binary_sha256"]}
        samples.update(version=1, kind="block-production-acceptance", synthetic=False,
                       origin="owned-child-native-control-channel", clocks=self.clocks, blocks=blocks,
                       missing_node_sessions=[node["id"] for node in self.plan["nodes"] if node["id"] not in self.runs],
                       unmatched_acceptance_blocks=sorted({block for _, block in self.accepted} - set(self.produced)))
        return plan, samples


def output_bytes(root):
    """Count all run-local logical file bytes, including child output."""
    total = count = 0
    for directory, subdirectories, filenames in os.walk(root, followlinks=False):
        for name in [*subdirectories, *filenames]:
            path = Path(directory) / name
            metadata = path.lstat()
            require(not stat.S_ISLNK(metadata.st_mode), "campaign_output_symlink_rejected")
            require(metadata.st_uid == os.geteuid(), "campaign_output_owner_mismatch")
            count += 1
            require(count <= 200000, "campaign_output_entry_limit")
            if stat.S_ISREG(metadata.st_mode):
                total += metadata.st_size
            else:
                require(stat.S_ISDIR(metadata.st_mode), "campaign_output_type_rejected")
    return total


def sample_host_resources(root):
    """Use pressure-reported memory on macOS or kernel MemAvailable on Linux."""
    system = platform.system()
    details = {}
    if system == "Darwin":
        physical = subprocess.run(["sysctl", "-n", "hw.memsize"], check=True,
                                  capture_output=True, text=True, timeout=3).stdout.strip()
        require(physical.isdigit(), "physical_memory_sample_required")
        pages = subprocess.run(["vm_stat"], check=True, capture_output=True,
                               text=True, timeout=3).stdout
        pressure = subprocess.run(["memory_pressure", "-Q"], check=True,
                                  capture_output=True, text=True, timeout=3).stdout
        require(len(pages) <= 32768 and len(pressure) <= 32768, "host_memory_sample_limit")
        found = re.search(r"System-wide memory free percentage:\s*(\d+)%", pressure)
        require(found is not None and 0 <= int(found[1]) <= 100, "memory_pressure_percentage_required")
        available = int(physical) * int(found[1]) // 100
        # Preserve the original observations. Free/speculative/inactive pages are
        # deliberately not added together as if they were kernel MemAvailable.
        details = {"physical_bytes": int(physical), "pressure_free_percentage": int(found[1]),
                   "vm_stat": pages, "memory_pressure": pressure,
                   "basis": "macos-pressure-reported-free-percentage", "estimated_available_bytes": True}
    elif system == "Linux":
        memory = Path("/proc/meminfo").read_text()
        require(len(memory) <= 32768, "host_memory_sample_limit")
        found = re.search(r"^MemAvailable:\s*(\d+) kB$", memory, re.MULTILINE)
        require(found is not None, "kernel_available_memory_required")
        available = int(found[1]) * 1024
        details = {"basis": "linux-kernel-MemAvailable", "estimated_available_bytes": False}
    else:
        raise ValueError("unsupported_host_memory_sampling")
    return {"sampled_unix_ms": time.time_ns() // 1000000,
            "free_disk_bytes": NETWORK.shutil.disk_usage(root).free,
            "host_free_bytes": available, "host_memory_observation": details}


class ResourceGuard:
    """Bound one explicit set of owned groups; absence or sampling failure stops."""
    def __init__(self, plan, managed_nodes=None, depth_root=None, campaign_started=None):
        self.plan = plan
        self.managed_nodes = set(managed_nodes if managed_nodes is not None else
                                 (node["id"] for node in plan["nodes"]))
        require(self.managed_nodes and self.managed_nodes <= {node["id"] for node in plan["nodes"]},
                "explicit_managed_nodes_required")
        self.depth_root = NETWORK.child_path(Path(plan["root"]), str(depth_root or plan["root"]))
        self.started = time.monotonic()
        self.campaign_started = self.started if campaign_started is None else campaign_started
        require(0 <= self.campaign_started <= self.started, "campaign_monotonic_start_required")
        self.last_progress = self.started
        self.started_ready = None
        self.previous_progress = None

    def progress(self, value):
        if self.previous_progress != value:
            self.previous_progress = value
            self.last_progress = time.monotonic()

    def ready(self):
        if self.started_ready is None:
            self.started_ready = time.monotonic()
            self.last_progress = self.started_ready

    def check(self, children, initial=False):
        require({child.context["node_id"] for child in children} == (set() if initial else self.managed_nodes),
                "exact_owned_guard_set_required")
        now = time.monotonic()
        try:
            host = sample_host_resources(self.plan["root"])
            groups = ({node: 0 for node in self.managed_nodes} if initial else
                      sample_owned_group_rss(children)["group_rss_bytes"])
            sample = {**host, "group_rss_bytes": groups,
                      "depth_output_bytes": output_bytes(self.depth_root),
                      "campaign_output_bytes": output_bytes(Path(self.plan["root"])),
                      "startup_elapsed_seconds": (self.started_ready or now) - self.started,
                      "no_progress_seconds": now - self.last_progress,
                      "depth_elapsed_seconds": now - self.started,
                      "campaign_elapsed_seconds": now - self.campaign_started}
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            return {"sample": {"sampled_unix_ms": time.time_ns() // 1000000}, "allowed": False,
                    "stop_reasons": ["resource_sampling_unavailable"],
                    "sampling_limits_not_os_hard_limits": True, "retry_or_budget_increase_authorized": False}
        result = budget_assessment(self.plan, sample, initial=initial, expected_nodes=self.managed_nodes)
        return {"sample": sample, **result}


def run_owned(plan, node, arguments, seconds, boundary=None, height=None, control_mode="status"):
    """Run one fresh isolated child with sampled resource and progress guards."""
    require(type(seconds) is int and 1 <= seconds <= 1800, "bounded_depth_duration_required")
    require(control_mode == "ipc" or boundary is None, "status_mode_has_no_named_fault_support")
    guard = ResourceGuard(plan, managed_nodes={node})
    first = guard.check([], initial=True)
    if not first["allowed"]:
        return {"version": 1, "scope": "owned-child-campaign-observation", "node_id": node,
                "stopped_reason": "initial_resource_gate_denied", "last_resource_assessment": first,
                "nodes_started": False, "g2_passed": False}
    collector = EventCollector(plan)
    child = OwnedChild(plan, node, arguments, control_mode)
    fault = None
    observations = []
    latest_budget = first
    stopped = None
    sample_path = child.directory / ("rehearsal-events-" + child.launch_id + ".jsonl")
    try:
        with sample_path.open("x", encoding="utf-8") as stream:
            os.chmod(sample_path, 0o600)
            records = 0

            def persist(value):
                nonlocal records
                require(records < MAX_EVENTS, "campaign_log_record_limit")
                require("token" not in value, "control_token_cannot_be_logged")
                stream.write(json.dumps(value, separators=(",", ":")) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
                records += 1

            collector.sink = persist
            persist({"kind": "resource_sample", **first})
            deadline = time.monotonic() + seconds
            next_budget = time.monotonic()
            if control_mode == "ipc":
                collector.register(child)
                last_clock = time.monotonic()
                child.clock_probe(collector)
                guard.ready()
                if boundary is not None:
                    child.arm(boundary, height)
                child.stream.settimeout(0.2)
            while time.monotonic() < deadline:
                if time.monotonic() >= next_budget:
                    latest_budget = guard.check([child])
                    persist({"kind": "resource_sample", **latest_budget})
                    if not latest_budget["allowed"]:
                        stopped = "sampled_resource_or_progress_limit"
                        break
                    next_budget = time.monotonic() + 2
                if control_mode == "status":
                    try:
                        observation = child.status()
                        guard.ready()
                        state = observation["status"]
                        guard.progress((state.get("height"), state.get("tip"), state.get("cumulative_work")))
                    except FileNotFoundError:
                        observation = {"status_identity_matched": False, "observation_error": "fresh_owned_status_not_yet_present"}
                    except (OSError, ValueError, KeyError, TypeError):
                        observation = {"status_identity_matched": False, "observation_error": "fresh_owned_status_validation_failed"}
                        stopped = "owned_status_validation_failed"
                    persist(observation)
                    observations.append(observation)
                    require(len(observations) <= 43200, "status_observation_limit")
                    if stopped is not None:
                        break
                    time.sleep(min(1, max(0, deadline - time.monotonic())))
                    continue
                try:
                    frame = child.receive()
                except socket.timeout:
                    if child.armed is None and time.monotonic() - last_clock >= 60:
                        child.stream.settimeout(5)
                        child.clock_probe(collector)
                        child.stream.settimeout(0.2)
                        last_clock = time.monotonic()
                    continue
                if frame["kind"] in {"block_produced", "block_durable_accepted"}:
                    collector.record(node, frame)
                    guard.progress((frame["kind"], frame["height"], frame["block_id"]))
                elif frame["kind"] == "boundary_parked":
                    child.reached(frame)
                    fault = child.kill_parked()
                    persist(frame)
                    break
                else:
                    raise ValueError("unexpected_campaign_event")
    finally:
        child.close()
    if not child.cleanup_group_verified:
        stopped = "owned_process_group_cleanup_unverified"
    result = {"version": 1, "scope": "owned-child-campaign-observation", "node_id": node,
              "run_id": child.run_id, "launch_id": child.launch_id, "control_mode": control_mode,
              "fault": fault, "raw_event_file": sample_path.name,
              "last_resource_assessment": latest_budget, "stopped_reason": stopped,
              "owned_process_group_cleanup_verified": child.cleanup_group_verified,
              "native_state_recovery_verified": False, "g2_passed": False}
    if control_mode == "ipc":
        sampling_plan, samples = collector.document()
        result.update(sampling_plan=sampling_plan, samples=samples,
                      statistics=NETWORK.propagation(sampling_plan, samples))
    else:
        result.update(status_observations=observations, native_control_ipc_connected=False,
                      durable_acceptance_instrumented=False, named_boundary_support=False,
                      propagation_measured=False)
    return result


GIB = 1024 ** 3
BUDGET = {"initial_free_disk_bytes": 96 * GIB, "minimum_free_disk_bytes": 32 * GIB,
          "maximum_depth_output_bytes": 16 * GIB, "maximum_campaign_output_bytes": 64 * GIB,
          "minimum_host_free_bytes": 8 * GIB, "active_group_rss_bytes": 4 * GIB,
          "other_group_rss_bytes": GIB, "campaign_rss_bytes": 12 * GIB,
          "startup_seconds": 120, "no_progress_seconds": 180,
          "depth_seconds": 1800, "campaign_seconds": 10800}


def budget_assessment(plan, sample, active_miners=("m1", "m2"), initial=False, expected_nodes=None):
    """Sampling controls only. Unknown measurements never authorize production."""
    reasons = []
    all_nodes = {node["id"] for node in plan["nodes"]}
    expected = all_nodes if expected_nodes is None else set(expected_nodes)
    require(expected and expected <= all_nodes, "explicit_budget_node_scope_required")
    require(set(active_miners) <= {node["id"] for node in plan["nodes"] if node["role"] == "miner"},
            "explicit_active_miners_required")
    fields = ["free_disk_bytes", "host_free_bytes", "depth_output_bytes", "campaign_output_bytes",
              "startup_elapsed_seconds", "no_progress_seconds", "depth_elapsed_seconds", "campaign_elapsed_seconds"]
    for key in fields:
        value = sample.get(key)
        if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
            reasons.append("unknown_" + key)
    if reasons:
        return {"allowed": False, "stop_reasons": reasons, "sampling_limits_not_os_hard_limits": True,
                "retry_or_budget_increase_authorized": False}
    if sample["free_disk_bytes"] < (BUDGET["initial_free_disk_bytes"] if initial else BUDGET["minimum_free_disk_bytes"]):
        reasons.append("host_free_disk_below_start_threshold" if initial else "host_free_disk_below_stop_threshold")
    if sample["host_free_bytes"] < BUDGET["minimum_host_free_bytes"]:
        reasons.append("host_free_memory_below_threshold")
    comparisons = [("depth_output_bytes", "maximum_depth_output_bytes"),
                   ("campaign_output_bytes", "maximum_campaign_output_bytes"),
                   ("startup_elapsed_seconds", "startup_seconds"),
                   ("no_progress_seconds", "no_progress_seconds"),
                   ("depth_elapsed_seconds", "depth_seconds"),
                   ("campaign_elapsed_seconds", "campaign_seconds")]
    for key, maximum in comparisons:
        if sample[key] > BUDGET[maximum]:
            reasons.append(key + "_limit")
    groups = sample.get("group_rss_bytes", {})
    if set(groups) != expected or any(type(value) is not int or value < 0 for value in groups.values()):
        reasons.append("unknown_owned_group_rss")
    else:
        for node, value in groups.items():
            if value > BUDGET["active_group_rss_bytes" if node in active_miners else "other_group_rss_bytes"]:
                reasons.append("owned_group_rss_limit:" + node)
        if sum(groups.values()) > BUDGET["campaign_rss_bytes"]:
            reasons.append("campaign_sampled_rss_limit")
    return {"allowed": not reasons, "stop_reasons": reasons,
            "sampling_limits_not_os_hard_limits": True, "retry_or_budget_increase_authorized": False}


def live_owned_group_members(group_id):
    """Inspect only numeric membership and process state, without command text."""
    result = subprocess.run(["ps", "-axo", "pid=,pgid=,uid=,state="], capture_output=True,
                            text=True, timeout=3, check=True)
    require(len(result.stdout) <= 2 * 1024 * 1024, "process_sample_limit")
    live = []
    for line in result.stdout.splitlines():
        fields = line.split()
        require(len(fields) == 4 and all(value.isdigit() for value in fields[:3]),
                "numeric_group_membership_required")
        pid, group, user = map(int, fields[:3])
        if group == group_id:
            require(user == os.geteuid(), "owned_group_user_mismatch")
            if not fields[3].startswith("Z"):
                live.append(pid)
    return live


def sample_owned_group_rss(children):
    """Read numeric PID/group/UID/RSS columns; never collect process arguments."""
    groups = {child.process.pid: child.context["node_id"] for child in children
              if child.process is not None and child.process.returncode is None}
    require(len(groups) == len(children), "unreaped_owned_groups_required")
    result = subprocess.run(["ps", "-axo", "pid=,pgid=,uid=,rss="], capture_output=True, text=True,
                            timeout=3, check=True)
    require(len(result.stdout) <= 2 * 1024 * 1024, "process_sample_limit")
    samples = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        require(len(parts) == 4 and all(value.isdigit() for value in parts), "numeric_process_sample_required")
        _, group, user, rss = map(int, parts)
        if group in groups:
            require(user == os.geteuid(), "owned_group_user_mismatch")
            node = groups[group]
            samples[node] = samples.get(node, 0) + rss * 1024
    return {"sampled_unix_ms": time.time_ns() // 1000000, "group_rss_bytes": samples,
            "owned_group_count": len(groups), "sampled_group_count": len(samples),
            "sampling_not_os_enforcement": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["topology", "partition", "heal", "run-node", "live-contract"])
    parser.add_argument("plan", type=Path)
    parser.add_argument("--topology", type=Path)
    parser.add_argument("--node")
    parser.add_argument("--arguments", type=Path)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--control-mode", choices=["status", "ipc"], default="status")
    parser.add_argument("--kill-boundary", choices=sorted(BOUNDARIES))
    parser.add_argument("--height", type=int)
    parser.add_argument("--input-sha256")
    parser.add_argument("--inert-trace", type=Path)
    parser.add_argument("--trace-sha256")
    parser.add_argument("--native-control-snapshot", type=Path)
    parser.add_argument("--control-sha256")
    arguments = parser.parse_args()
    if arguments.command == "live-contract":
        import reorg_live_control
        NETWORK.owner_local()
        proposal = reorg_live_control.load_bound(arguments.plan, arguments.input_sha256)
        result = reorg_live_control.requirements(proposal)
        if arguments.inert_trace is not None:
            trace = reorg_live_control.load_bound(arguments.inert_trace, arguments.trace_sha256)
            result["inert_model"] = reorg_live_control.check_inert_trace(proposal, trace)
        if arguments.native_control_snapshot is not None:
            snapshot = reorg_live_control.load_bound(arguments.native_control_snapshot, arguments.control_sha256)
            result["native_record_snapshot"] = reorg_live_control.check_native_control_snapshot(proposal, snapshot)
        print(json.dumps(result, sort_keys=True))
        return
    plan = checked_plan(arguments.plan)
    if arguments.command == "run-node":
        require(arguments.arguments is not None, "explicit_frozen_arguments_required")
        values = NETWORK.bounded_json(NETWORK.child_path(Path(plan["root"]), str(arguments.arguments)))
        result = run_owned(plan, arguments.node, values, arguments.seconds, arguments.kill_boundary, arguments.height,
                           arguments.control_mode)
    else:
        require(arguments.topology is not None, "explicit_topology_required")
        topology = NETWORK.bounded_json(NETWORK.child_path(Path(plan["root"]), str(arguments.topology)))
        result = partition_topology(plan, topology) if arguments.command == "topology" else set_partition(plan, topology, arguments.command == "partition")
    print(json.dumps(result, sort_keys=True))
    if result.get("stopped_reason") is not None:
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({"error": "isolated_campaign_request_rejected"}))
        raise SystemExit(1)
