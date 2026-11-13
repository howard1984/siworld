#!/usr/bin/env python3
"""Owner-local transport faults and observations for isolated reorganization runs.

This tool never creates keys, starts miners, changes a node database or reports
G2 success. Its relays forward opaque encrypted bytes between literal loopback
addresses. Use separate native execution and ledger checks for acceptance.
"""
import argparse
import asyncio
import hashlib
import ipaddress
import json
import math
import os
import re
from pathlib import Path
import shutil
import stat
import sys
import time

MAX_JSON = 1024 * 1024
CHUNK = 65536
MAX_CONNECTIONS = 64
MAX_NODES = 64
MAX_PROPAGATION_BLOCKS = 10000
MAX_ACCEPTANCE_EVENTS = 50000
MAX_CLOCK_AGE_MS = 300000
MARKER = {"version": 1, "purpose": "isolated-reorganization-qualification"}


def require(value, code):
    if not value:
        raise ValueError(code)


def owner_local():
    require(not os.environ.get("GITHUB_ACTIONS") and
            os.environ.get("CI", "").lower() not in {"1", "true"},
            "owner_local_execution_required")


def bounded_json(path):
    path = Path(path)
    m = path.lstat()
    require(stat.S_ISREG(m.st_mode) and not path.is_symlink() and
            m.st_uid == os.geteuid() and m.st_size <= MAX_JSON,
            "owned_bounded_regular_json_required")
    with path.open("rb") as stream:
        body = stream.read(MAX_JSON + 1)
    require(len(body) <= MAX_JSON, "json_size_exceeded")
    return json.loads(body)


def loopback(value):
    """Accept literal IP endpoints only; never resolve a hostname."""
    require(isinstance(value, str), "literal_loopback_endpoint_required")
    try:
        if value.startswith("["):
            address, port = value[1:].split("]:")
        else:
            address, port = value.rsplit(":", 1)
        ip = ipaddress.ip_address(address)
        number = int(port)
        require(ip.is_loopback and 0 < number < 65536 and str(number) == port,
                "literal_loopback_endpoint_required")
    except (ValueError, TypeError):
        raise ValueError("literal_loopback_endpoint_required") from None
    return str(ip), number


def child_path(root, value, exists=True):
    path = Path(value)
    require(path.is_absolute() and path.is_relative_to(root), "path_outside_run_root")
    require(".." not in path.parts, "noncanonical_run_path")
    for candidate in [root, *reversed(path.parents), path]:
        if candidate.is_relative_to(root) and candidate.exists():
            require(not candidate.is_symlink(), "symlink_in_run_path")
    if exists:
        require(path.exists() and path.resolve() == path, "canonical_existing_path_required")
    return path


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(CHUNK), b""):
            result.update(part)
    return result.hexdigest()


def load_plan(path):
    owner_local()
    plan = bounded_json(path)
    require(plan.get("version") == 1, "plan_version_rejected")
    root = Path(plan["root"])
    require(root.is_absolute() and root.resolve() == root and root.is_dir(), "canonical_run_root_required")
    m = root.stat()
    require(m.st_uid == os.geteuid() and stat.S_IMODE(m.st_mode) == 0o700,
            "private_owned_run_root_required")
    require(bounded_json(root / "reorg-local-network.marker.json") == MARKER,
            "isolated_run_marker_required")
    scope = plan.get("scope", "g2")
    require(scope in {"g2", "plumbing"}, "network_scope_rejected")
    require(isinstance(plan.get("nodes"), list) and (5 if scope == "g2" else 2) <= len(plan["nodes"]) <= MAX_NODES,
            "minimum_topology_required")
    identifiers = set()
    directories = []
    miners = services = 0
    for node in plan["nodes"]:
        require(node["id"] not in identifiers and node["id"].replace("-", "").isalnum(),
                "unique_neutral_node_identifier_required")
        identifiers.add(node["id"])
        directory = child_path(root, node["directory"])
        require(all(not directory.is_relative_to(other) and not other.is_relative_to(directory)
                    for other in directories), "node_directories_overlap")
        directories.append(directory)
        configuration = child_path(root, node["configuration"])
        require(configuration.is_relative_to(directory), "configuration_outside_node_directory")
        config = bounded_json(configuration)
        require(node["role"] in {"miner", "service"}, "node_role_rejected")
        require(config.get("version") == 2 and config.get("engineering") is True,
                "engineering_configuration_required")
        require(set(config) == {"version", "engineering", "role", "listen", "mining", "peers", "checkpoint_key"},
                "configuration_fields_rejected")
        if node["role"] == "miner":
            miners += 1
            require(config["role"] == "miner" and config["listen"] is None and
                    config["mining"] is (scope == "g2"), "outbound_mining_configuration_required")
        else:
            services += 1
            require(config["role"] in {"validator", "bootstrap"} and config["mining"] is False and
                    config["listen"] is not None, "nonmining_service_configuration_required")
            loopback(config["listen"])
        for peer in config["peers"]:
            loopback(peer["endpoint"])
        if config["checkpoint_key"] is not None:
            child_path(root, config["checkpoint_key"])
        require(digest(child_path(root, str(directory / "genesis.bin"))) == plan["genesis_sha256"],
                "genesis_bytes_differ")
        child_path(root, str(directory / "native-peer-identity.secret"))
    require(miners >= (3 if scope == "g2" else 1) and services >= (2 if scope == "g2" else 1),
            "minimum_topology_required")
    names = set()
    listeners = set()
    for link in plan["links"]:
        require(link["id"] not in names, "duplicate_link_identifier")
        names.add(link["id"])
        listen = loopback(link["listen"])
        require(listen not in listeners and listen != loopback(link["target"]), "relay_endpoint_collision")
        listeners.add(listen)
        child_path(root, link["control"])
    for key, size in [("genesis_id", 64), ("network_id", 64), ("source_commit", 40), ("binary_sha256", 64)]:
        require(isinstance(plan.get(key), str) and len(plan[key]) == size and
                set(plan[key]) <= set("0123456789abcdef"), "explicit_provenance_required")
    return plan


def preflight(plan):
    binary = Path(plan["binary"])
    require(binary.is_absolute() and binary.resolve() == binary and binary.is_file(), "canonical_binary_required")
    require(digest(binary) == plan["binary_sha256"], "binary_digest_mismatch")
    require(shutil.disk_usage(plan["root"]).free >= plan["minimum_free_disk_bytes"], "insufficient_free_disk")
    return {"version": 1, "scope": "isolated-network-preflight", "node_count": len(plan["nodes"]), "network_scope": plan.get("scope", "g2"),
            "link_count": len(plan["links"]), "source_commit": plan["source_commit"],
            "binary_sha256": plan["binary_sha256"], "loopback_only": True,
            "resource_measurements_required": ["physical_memory", "free_memory", "proving_process_tree_peak"],
            "miners_started": False, "g2_passed": False}


def observe(plan):
    now = time.time_ns() // 1000000
    observations = []
    for node in plan["nodes"]:
        value = {"id": node["id"], "role": node["role"], "available": False}
        try:
            status = bounded_json(Path(node["directory"]) / "service-status.json")
            require(isinstance(status, dict), "status_record_required")
            if status.get("state_available") is True:
                require(type(status.get("height")) is int and status["height"] >= 0 and
                        isinstance(status.get("tip"), str) and re.fullmatch(r"[0-9a-f]{64}", status["tip"]) and
                        isinstance(status.get("cumulative_work"), str) and 0 < len(status["cumulative_work"]) <= 128,
                        "status_head_rejected")
            require(status.get("genesis_id") == plan["genesis_id"] and status.get("network_id") == plan["network_id"],
                    "node_context_mismatch")
            require(0 <= now - status["updated_unix_ms"] <= 30000, "node_status_stale")
            if "run_id" in node:
                require(status.get("run_id") == node["run_id"], "node_run_mismatch")
            value.update(available=True, **{key: status.get(key) for key in
                         ["height", "tip", "cumulative_work", "ready", "phase", "run_id", "connections", "updated_unix_ms",
                          "state_available", "reorganization_status", "reorganization_alarm",
                          "reorganization_depth", "reorganization_ancestor_height", "template_generation",
                          "wallet_export_enabled", "wallet_export_paused"]})
        except (OSError, ValueError, KeyError, TypeError):
            value["observation_error"] = "missing_stale_or_inconsistent_status"
        observations.append(value)
    complete = all(value["available"] and value.get("ready") is True and
                   value.get("state_available") is True and
                   value.get("reorganization_status") in {None, "ready", "unconfigured"}
                   for value in observations)
    heads = {(v.get("height"), v.get("tip"), v.get("cumulative_work")) for v in observations}
    return {"version": 1, "scope": "fresh-local-status-observation", "observed_unix_ms": now,
            "nodes": observations, "all_observed_heads_equal": complete and len(heads) == 1,
            "full_state_fingerprint_verified": False, "g2_passed": False}


def run_identifier(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value),
            "explicit_run_identifier_required")
    return value


def campaign_runs(plan):
    run_identifier(plan.get("run_id"))
    runs = {node["id"]: run_identifier(node.get("run_id")) for node in plan["nodes"]}
    require(0 < len(runs) == len(plan["nodes"]) <= MAX_NODES and len(set(runs.values())) == len(runs),
            "distinct_bounded_node_runs_required")
    return runs


def milliseconds(value, *, signed=False):
    require(type(value) in {int, float} and math.isfinite(value) and
            (-86400000 <= value <= 86400000 if signed else 0 <= value <= 10 ** 15),
            "finite_milliseconds_required")
    return value


def summary(values):
    """Nearest-rank quantiles of explicitly qualified point estimates only."""
    values = sorted(values)
    result = {"count": len(values), "mean_ms": None, "minimum_ms": None,
              "maximum_ms": None, "p50_ms": None, "p95_ms": None, "p99_ms": None}
    if values:
        result.update(mean_ms=math.fsum(values) / len(values), minimum_ms=values[0], maximum_ms=values[-1])
        for percentile in [50, 95, 99]:
            result[f"p{percentile}_ms"] = values[math.ceil(percentile * len(values) / 100) - 1]
    return result


def calibrated_time(clocks, node, timestamp):
    clock = clocks.get(node)
    if clock is None or clock == []:
        return None, None, "clock_calibration_missing"
    candidates = clock if isinstance(clock, list) else [clock]
    qualified = []
    for sample in candidates:
        corrected = timestamp - sample["offset_ms"]
        distance = abs(corrected - sample["calibrated_unix_ms"])
        if distance <= MAX_CLOCK_AGE_MS:
            qualified.append((distance, corrected, sample["uncertainty_ms"]))
    if not qualified:
        return None, None, "clock_calibration_stale"
    _, corrected, uncertainty = min(qualified)
    return corrected, uncertainty, None


def propagation(plan, samples):
    """Summarize explicit native events; status and relay bytes are not events."""
    runs = campaign_runs(plan)
    require(isinstance(samples, dict), "event_document_required")
    require(type(samples.get("version")) is int and samples.get("version") == 1 and samples.get("kind") == "block-production-acceptance" and
            type(samples.get("synthetic")) is bool, "explicit_event_sample_required")
    for key in ["run_id", "network_id", "genesis_id", "source_commit", "binary_sha256"]:
        require(samples.get(key) == plan[key], "event_provenance_mismatch")
    clocks = samples.get("clocks", {})
    require(isinstance(clocks, dict) and set(clocks) <= set(runs), "clock_node_rejected")
    for node, clock in clocks.items():
        records = clock if isinstance(clock, list) else [clock]
        require(0 < len(records) <= 1000, "bounded_clock_history_required")
        for record in records:
            require(isinstance(record, dict), "clock_record_required")
            require(record.get("run_id") == runs[node], "clock_run_mismatch")
            milliseconds(record["offset_ms"], signed=True)
            require(milliseconds(record["uncertainty_ms"]) <= 86400000, "clock_uncertainty_rejected")
            milliseconds(record["calibrated_unix_ms"])
    blocks = samples.get("blocks")
    require(isinstance(blocks, list) and len(blocks) <= MAX_PROPAGATION_BLOCKS and
            len(blocks) * len(runs) <= MAX_ACCEPTANCE_EVENTS, "event_block_limit")
    reports, identifiers, pooled, complete = [], set(), [], []
    event_count = observed_pairs = qualified_pairs = 0
    for block in blocks:
        require(isinstance(block, dict), "block_event_record_required")
        identity = block.get("block_id")
        require(isinstance(identity, str) and re.fullmatch(r"[0-9a-f]{64}", identity) and
                identity not in identifiers, "unique_block_identity_required")
        identifiers.add(identity)
        producer = block["producer"]
        require(producer in runs and block.get("producer_run_id") == runs[producer], "producer_run_mismatch")
        generated = milliseconds(block["produced_unix_ms"])
        generated, producer_uncertainty, producer_error = calibrated_time(clocks, producer, generated)
        events = block.get("accepted")
        require(isinstance(events, list), "acceptance_events_required")
        event_count += len(events)
        require(event_count <= MAX_ACCEPTANCE_EVENTS, "acceptance_event_limit")
        first = {}
        for event in events:
            require(isinstance(event, dict), "acceptance_event_record_required")
            node = event["node_id"]
            require(node in runs and event.get("run_id") == runs[node], "acceptance_run_mismatch")
            timestamp = milliseconds(event["accepted_unix_ms"])
            first[node] = min(first.get(node, timestamp), timestamp)
        per_node = []
        for node in runs:
            value = {"node_id": node, "first_accepted_unix_ms": first.get(node),
                     "latency_ms": None, "latency_lower_ms": None, "latency_upper_ms": None,
                     "combined_clock_uncertainty_ms": None, "unknown_reason": None}
            if node not in first:
                value["unknown_reason"] = "acceptance_event_missing"
            else:
                accepted, uncertainty, error = calibrated_time(clocks, node, first[node])
                value["unknown_reason"] = producer_error or error
                if value["unknown_reason"] is None:
                    delay = accepted - generated
                    combined = uncertainty + producer_uncertainty
                    value.update(combined_clock_uncertainty_ms=combined,
                                 latency_lower_ms=max(0, delay - combined), latency_upper_ms=max(0, delay + combined))
                    if delay < 0:
                        if delay + combined < 0:
                            value.update(latency_lower_ms=None, latency_upper_ms=None,
                                         unknown_reason="clock_or_event_order_inconsistent")
                        else:
                            value["unknown_reason"] = "clock_or_event_order_uncertain"
                    else:
                        value["latency_ms"] = delay
                        pooled.append(delay)
                        qualified_pairs += 1
            per_node.append(value)
        observed_pairs += len(first)
        qualified = [value for value in per_node if value["latency_ms"] is not None]
        all_nodes = max((value["latency_ms"] for value in qualified), default=None) if len(qualified) == len(runs) else None
        if all_nodes is not None:
            complete.append(all_nodes)
        reports.append({"block_id": identity, "producer": producer, "nodes": per_node,
                        "observed_nodes": len(first), "expected_nodes": len(runs),
                        "qualified_nodes": len(qualified), "unknown_nodes": len(runs) - len(qualified),
                        "all_nodes_latency_ms": all_nodes,
                        "all_nodes_latency_lower_ms": max(value["latency_lower_ms"] for value in qualified) if all_nodes is not None else None,
                        "all_nodes_latency_upper_ms": max(value["latency_upper_ms"] for value in qualified) if all_nodes is not None else None})
    expected = len(blocks) * len(runs)
    return {"version": 1, "scope": "explicit-production-acceptance-statistics",
            "sample_source": "synthetic" if samples["synthetic"] else "declared-native-events",
            "run_id": plan["run_id"], "source_commit": plan["source_commit"],
            "binary_sha256": plan["binary_sha256"], "genesis_id": plan["genesis_id"],
            "network_id": plan["network_id"], "blocks": reports,
            "coverage": {"expected_node_block_pairs": expected, "observed_node_block_pairs": observed_pairs,
                         "qualified_latency_pairs": qualified_pairs, "unknown_latency_pairs": expected - qualified_pairs,
                         "complete_blocks": len(complete), "incomplete_blocks": len(blocks) - len(complete)},
            "pooled_node_latency": summary(pooled), "all_nodes_latency": summary(complete),
            "clock_calibrations": clocks, "clock_age_limit_ms": MAX_CLOCK_AGE_MS,
            "quantiles": "nearest-rank; qualified point estimates only",
            "event_source_independently_verified": False,
            "status_snapshots_are_acceptance_events": False, "relay_bytes_are_propagation": False,
            "g2_passed": False}


def fault_capabilities(plan, node_id, process):
    """Check supplied facts only; never inspect, signal, spawn or restart a PID."""
    runs = campaign_runs(plan)
    require(isinstance(process, dict), "process_fact_record_required")
    require(node_id in runs, "explicit_fault_node_required")
    preflight(plan)
    root = Path(plan["root"])
    require(bounded_json(root / "reorg-local-network.marker.json") == MARKER, "isolated_run_marker_required")
    node = next(node for node in plan["nodes"] if node["id"] == node_id)
    directory = child_path(root, node["directory"])
    binary = Path(plan["binary"])
    metadata = binary.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid(), "owned_binary_required")
    require(type(process.get("pid")) is int and process["pid"] > 1 and
            type(process.get("uid")) is int and process["uid"] == os.geteuid(), "same_user_process_required")
    require(process.get("run_id") == runs[node_id] and process.get("campaign_run_id") == plan["run_id"], "fault_run_mismatch")
    require(process.get("executable") == str(binary) and process.get("binary_sha256") == plan["binary_sha256"] and
            process.get("node_directory") == str(directory), "fault_binary_or_directory_mismatch")
    run_identifier(process.get("start_token"))
    status = bounded_json(directory / "service-status.json")
    require(isinstance(status, dict), "fault_status_record_required")
    require(status.get("run_id") == runs[node_id] and status.get("process_id") == process["pid"] and
            status.get("network_id") == plan["network_id"] and status.get("genesis_id") == plan["genesis_id"],
            "fault_status_identity_mismatch")
    now = time.time_ns() // 1000000
    require(type(status.get("updated_unix_ms")) is int and 0 <= now - status["updated_unix_ms"] <= 30000,
            "fault_status_stale")
    return {"version": 1, "scope": "nonexecuting-fault-capability-assessment", "node_id": node_id,
            "campaign_run_id": plan["run_id"], "node_run_id": runs[node_id],
            "supplied_facts_match": True, "frozen_binary_digest_verified": True,
            "live_process_identity_attested": False, "signal_delivery_supported": False,
            "fault_injected": False, "g2_passed": False,
            "missing_capabilities": ["live_pid_start_and_executable_attestation", "owned_child_process_handle",
                                     "named_native_boundary_rendezvous", "authorized_fault_execution"]}


class Relay:
    def __init__(self, link):
        self.link = link
        self.enabled = False
        self.connections = set()
        self.accepted = 0
        self.rejected = 0
        self.bytes = [0, 0]
        self.server = None

    async def pump(self, reader, writer, direction):
        while data := await reader.read(CHUNK):
            self.bytes[direction] += len(data)
            writer.write(data)
            await writer.drain()

    async def connected(self, reader, writer):
        task = asyncio.current_task()
        if not self.enabled or len(self.connections) >= MAX_CONNECTIONS:
            self.rejected += 1
            writer.close()
            await writer.wait_closed()
            return
        self.connections.add(task)
        self.accepted += 1
        target_writer = None
        pipes = []
        try:
            host, port = loopback(self.link["target"])
            target_reader, target_writer = await asyncio.wait_for(asyncio.open_connection(host, port), 5)
            pipes = [asyncio.create_task(self.pump(reader, target_writer, 0)),
                     asyncio.create_task(self.pump(target_reader, writer, 1))]
            await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            for pipe in pipes:
                pipe.cancel()
            await asyncio.gather(*pipes, return_exceptions=True)
            for stream in [writer, target_writer]:
                if stream is not None:
                    stream.close()
            for stream in [writer, target_writer]:
                if stream is not None:
                    try:
                        await stream.wait_closed()
                    except OSError:
                        pass
            self.connections.discard(task)

    async def set_enabled(self, enabled):
        self.enabled = enabled
        if not enabled:
            tasks = list(self.connections)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def run(self, seconds):
        host, port = loopback(self.link["listen"])
        self.server = await asyncio.start_server(self.connected, host, port, limit=CHUNK)
        deadline = time.monotonic() + seconds
        try:
            while time.monotonic() < deadline:
                try:
                    control = bounded_json(self.link["control"])
                    require(set(control) == {"version", "enabled"} and control["version"] == 1 and
                            type(control["enabled"]) is bool, "relay_control_rejected")
                    enabled = control["enabled"]
                except (OSError, ValueError, TypeError):
                    enabled = False
                if enabled != self.enabled:
                    await self.set_enabled(enabled)
                await asyncio.sleep(0.1)
        finally:
            self.server.close()
            await self.server.wait_closed()
            await self.set_enabled(False)
        return {"version": 1, "scope": "opaque-loopback-relay", "link_id": self.link["id"],
                "accepted_connections": self.accepted, "rejected_connections": self.rejected,
                "forwarded_request_bytes": self.bytes[0], "forwarded_response_bytes": self.bytes[1],
                "g2_passed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["preflight", "observe", "propagation", "fault-capabilities", "relay"])
    parser.add_argument("plan", type=Path)
    parser.add_argument("--link")
    parser.add_argument("--samples", type=Path)
    parser.add_argument("--process-facts", type=Path)
    parser.add_argument("--node")
    parser.add_argument("--seconds", type=int, default=60)
    args = parser.parse_args()
    plan = load_plan(args.plan)
    if args.command == "propagation":
        preflight(plan)
        require(args.samples is not None, "explicit_samples_required")
        result = propagation(plan, bounded_json(child_path(Path(plan["root"]), str(args.samples))))
    elif args.command == "fault-capabilities":
        require(args.process_facts is not None, "explicit_process_facts_required")
        result = fault_capabilities(plan, args.node,
                                   bounded_json(child_path(Path(plan["root"]), str(args.process_facts))))
    elif args.command == "relay":
        require(1 <= args.seconds <= 86400, "relay_duration_rejected")
        links = [link for link in plan["links"] if link["id"] == args.link]
        require(len(links) == 1, "explicit_link_required")
        result = asyncio.run(Relay(links[0]).run(args.seconds))
    else:
        result = preflight(plan) if args.command == "preflight" else observe(plan)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"error": "isolated_network_request_rejected"}), file=sys.stderr)
        raise SystemExit(1)
