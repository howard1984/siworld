"""Bounded local validation of complete, externally bound native event journals.

This module reads retained collector snapshots only. It opens no network or
database, starts no child, and makes no admission or G2 acceptance decision.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SEGMENT_BYTES = 1048576
RECORD_BYTES = 2048
MAX_SNAPSHOTS = 1440
MAX_NODES = 64
MAX_RECORDS = 50000
MAX_RETAINED_BYTES = 64 * 1024 * 1024
MAX_READ_BYTES = 16 * 1024 * 1024 * 1024
MAX_SOURCES = 50000
MAX_OUTPUT_BYTES = 128 * 1024 * 1024
PROPAGATION_KINDS = {"native-block-produced", "native-block-durably-accepted"}
REJECTION_KIND = "native-proof-rejected"
EVENT_KINDS = PROPAGATION_KINDS | {REJECTION_KIND}
MARKER_KINDS = {"native-event-stream-start", "native-event-stream-end"}
CONTEXT = ("network_id", "genesis_id", "source_commit", "binary_sha256")
COMMON = {"version", "record", "kind", "event_source", "network_id",
          "genesis_id", "source_commit", "source_commit_externally_verified",
          "binary_sha256", "node_id", "run_id", "event_unix_ms",
          "elapsed_monotonic_ns"}
EVENT = COMMON | {"source_commit_origin", "sequence", "block_id", "height",
                  "clock_offset_ms", "clock_uncertainty_ms",
                  "clock_calibration_measured", "deduplication_key"}
REJECTION = {"receiver_node_id", "peer_id", "frame_id", "body_commitment",
             "body_bytes", "owner_attempt", "native_error_code",
             "owner_dropped_before", "stream_dropped_before"}
MARKER = COMMON | {"event_attempts", "written_events", "dropped_events", "error_code"}
NATIVE_ERRORS = {"transaction-proof-invalid", "settlement-proof-invalid",
                 "issuance-proof-invalid"}


class IntegrityError(ValueError):
    """A fixed validation code without input values or private paths."""


def require(value, code):
    if not value:
        raise IntegrityError(code)


def uint(value, maximum=2**64 - 1):
    return type(value) is int and 0 <= value <= maximum


def hex_text(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def parse(body):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def constant(_):
        raise IntegrityError("nonfinite_json_number")

    return json.loads(body, object_pairs_hook=pairs, parse_constant=constant)


def read_owned(path, cap):
    path = Path(path).absolute()
    require(".." not in path.parts and path.resolve(strict=True) == path,
            "canonical_input_path_required")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
                before.st_nlink == 1 and stat.S_IMODE(before.st_mode) & 0o077 == 0 and
                before.st_size <= cap, "owned_bounded_private_file_required")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            body = stream.read(cap + 1)
        after = os.fstat(fd)
        require(len(body) == before.st_size <= cap and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_ctime_ns), "input_changed_during_read")
        return body
    finally:
        os.close(fd)


def validate_bindings(bindings):
    require(isinstance(bindings, dict) and set(bindings) ==
            {"version", *CONTEXT, "nodes"} and type(bindings["version"]) is int and
            bindings["version"] == 1, "bindings_schema_rejected")
    for key in CONTEXT:
        require(hex_text(bindings[key], 40 if key == "source_commit" else 64),
                "bindings_provenance_rejected")
    nodes = bindings["nodes"]
    require(isinstance(nodes, list) and 1 <= len(nodes) <= MAX_NODES, "node_count_cap")
    seen = {key: set() for key in ("row", "alias", "node_id", "run_id")}
    for node in nodes:
        require(isinstance(node, dict) and set(node) ==
                {"row", "alias", "node_id", "run_id", "directory", "unit"},
                "node_binding_schema_rejected")
        require(uint(node["row"], MAX_NODES) and node["row"] > 0 and
                isinstance(node["alias"], str) and
                re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", node["alias"]) and
                hex_text(node["node_id"]) and hex_text(node["run_id"]) and
                all(isinstance(node[key], str) and 0 < len(node[key]) <= 4096
                    for key in ("directory", "unit")), "node_binding_rejected")
        for key, values in seen.items():
            require(node[key] not in values, "duplicate_node_binding")
            values.add(node[key])


def status_diagnostic(status, bindings, node):
    require(isinstance(status, dict) and all(status.get(key) == bindings[key]
            for key in ("network_id", "genesis_id")) and
            status.get("run_id") == node["run_id"] and
            all(key not in status or status[key] == bindings[key]
                for key in ("source_commit", "binary_sha256")),
            "status_context_mismatch")
    diagnostic = status.get("native_block_events")
    require(isinstance(diagnostic, dict) and "error_code" in diagnostic and
            diagnostic.get("enabled") is True and
            diagnostic.get("error_code") is None and
            diagnostic.get("stream_start_written") is True and
            type(diagnostic.get("stream_end_written")) is bool and
            diagnostic.get("source_commit_available") is True and
            diagnostic.get("source_commit_externally_verified") is False and
            diagnostic.get("coverage_established") is False and
            diagnostic.get("clock_calibration_measured") is False,
            "native_stream_diagnostic_incomplete")
    for key in ("event_attempts", "written_events", "last_sequence", "dropped_events",
                "segment_rollovers"):
        require(uint(diagnostic.get(key)), "native_stream_counter_rejected")
    require(diagnostic["event_attempts"] == diagnostic["written_events"] ==
            diagnostic["last_sequence"] and diagnostic["dropped_events"] == 0,
            "native_stream_counter_or_drop")
    require(type(diagnostic.get("retention_replaced_prior_slot")) is bool and
            diagnostic.get("segment_count_limit") == 4 and
            diagnostic.get("segment_bytes_limit") == SEGMENT_BYTES and
            diagnostic.get("record_bytes_limit") == RECORD_BYTES,
            "native_stream_limits_rejected")
    owner = status.get("native_accept_observation")
    require(isinstance(owner, dict), "owner_diagnostic_required")
    require(set(owner) == {"enabled", "dropped_events", "error_code",
                           "coverage_established", "scope"} and
            owner["enabled"] is True and uint(owner["dropped_events"]) and
            owner["dropped_events"] == 0 and owner["error_code"] is None and
            owner["coverage_established"] is False and
            owner["scope"] == "ordinary-forward-admission",
            "owner_diagnostic_incomplete_or_drop")
    return diagnostic


def record_schema(record, bindings, node):
    require(isinstance(record, dict) and type(record.get("version")) is int and
            record["version"] == 1 and record.get("event_source") == "native-runtime-hook",
            "native_record_source_rejected")
    require(all(record.get(key) == bindings[key] for key in CONTEXT) and
            all(record.get(key) == node[key] for key in ("node_id", "run_id")) and
            record.get("source_commit_externally_verified") is False,
            "native_record_context_mismatch")
    require(uint(record.get("event_unix_ms")) and record["event_unix_ms"] > 0 and
            isinstance(record.get("elapsed_monotonic_ns"), str) and
            re.fullmatch(r"0|[1-9][0-9]{0,38}", record["elapsed_monotonic_ns"]) and
            int(record["elapsed_monotonic_ns"]) <= 2**128 - 1,
            "native_record_timing_rejected")
    if record.get("record") == "stream-marker":
        require(set(record) == MARKER and isinstance(record.get("kind"), str) and
                record["kind"] in MARKER_KINDS,
                "native_marker_schema_rejected")
        for key in ("event_attempts", "written_events", "dropped_events"):
            require(uint(record[key], MAX_RECORDS), "native_marker_counter_rejected")
        require(record["event_attempts"] == record["written_events"] and
                record["dropped_events"] == 0 and record["error_code"] is None,
                "native_marker_counter_or_drop")
        return ("marker", record["kind"])
    kind = record.get("kind")
    require(record.get("record") == "block-event" and isinstance(kind, str) and
            kind in EVENT_KINDS,
            "native_event_kind_rejected")
    require(uint(record.get("sequence"), MAX_RECORDS) and record["sequence"] > 0 and
            hex_text(record.get("block_id")) and uint(record.get("height")) and
            record["height"] > 0 and
            record.get("source_commit_origin") == "compile-time-declaration" and
            record.get("clock_offset_ms") is None and
            record.get("clock_uncertainty_ms") is None and
            record.get("clock_calibration_measured") is False,
            "native_event_schema_rejected")
    if kind in PROPAGATION_KINDS:
        field = "produced_unix_ms" if kind == "native-block-produced" else "accepted_unix_ms"
        require(set(record) == EVENT | {field} and type(record.get(field)) is int and
                record[field] == record["event_unix_ms"] and
                record.get("deduplication_key") ==
                [kind, node["node_id"], node["run_id"], record["block_id"]],
                "propagation_event_identity_or_time_rejected")
    else:
        require(set(record) == EVENT | REJECTION and
                record.get("receiver_node_id") == node["node_id"] and
                all(hex_text(record.get(key)) for key in
                    ("peer_id", "frame_id", "body_commitment")) and
                uint(record.get("body_bytes")) and uint(record.get("owner_attempt")) and
                record["owner_attempt"] > 0 and
                isinstance(record.get("native_error_code"), str) and
                record["native_error_code"] in NATIVE_ERRORS,
                "native_rejection_schema_rejected")
        require(uint(record.get("owner_dropped_before")) and
                record["owner_dropped_before"] == 0 and
                uint(record.get("stream_dropped_before")) and
                record["stream_dropped_before"] == 0, "native_rejection_drop")
        deduplication = record.get("deduplication_key")
        require(isinstance(deduplication, list) and len(deduplication) == 5 and
                type(deduplication[3]) is int and deduplication ==
                [kind, node["node_id"], node["run_id"], record["owner_attempt"],
                 record["frame_id"]], "native_rejection_dedup_rejected")
    return ("event", record["sequence"])


def validate(bindings, roots):
    """Validate every kind and both diagnostics before selecting propagation rows."""
    validate_bindings(bindings)
    require(1 <= len(roots) <= MAX_SNAPSHOTS, "snapshot_count_cap")
    records = {node["alias"]: {} for node in bindings["nodes"]}
    sources, final, previous = [], {}, {}
    read_bytes = retained_bytes = record_count = 0

    def read_source(path, cap):
        nonlocal read_bytes
        body = read_owned(path, cap)
        read_bytes += len(body)
        require(read_bytes <= MAX_READ_BYTES and len(sources) < MAX_SOURCES,
                "snapshot_input_budget_exceeded")
        sources.append({"path": str(Path(path).absolute()), "bytes": len(body),
                        "sha256": hashlib.sha256(body).hexdigest()})
        return body

    for supplied_root in roots:
        root = Path(supplied_root).absolute()
        require(root.resolve(strict=True) == root and root.is_dir() and
                root.stat().st_uid == os.geteuid() and
                stat.S_IMODE(root.stat().st_mode) & 0o077 == 0,
                "private_snapshot_root_required")
        index = parse(read_source(root / "index.private.json", 32768))
        require(isinstance(index, dict) and index.get("version") == 1 and
                type(index["version"]) is int and index.get("bindings") == bindings,
                "snapshot_binding_mismatch")
        for node in bindings["nodes"]:
            alias = node["alias"]
            parent = root / alias
            snapshot = parse(read_source(parent / "snapshot.private.json", 65536))
            expected = {key: bindings[key] for key in CONTEXT}
            expected.update(node)
            require(isinstance(snapshot, dict) and snapshot.get("binding") == expected,
                    "snapshot_node_binding_mismatch")
            before = status_diagnostic(snapshot["status_before"], bindings, node)
            after = status_diagnostic(snapshot["status_after"], bindings, node)
            require(previous.get(alias, 0) <= before["event_attempts"] <=
                    after["event_attempts"], "snapshot_counter_regression")
            previous[alias] = after["event_attempts"]
            final[alias] = snapshot
            files = snapshot.get("files")
            require(isinstance(files, list) and 1 <= len(files) <= 4,
                    "snapshot_segments_required")
            segment_names = set()
            for entry in files:
                require(isinstance(entry, dict) and
                        set(entry) == {"name", "bytes", "sha256", "local_file"} and
                        isinstance(entry["name"], str) and
                        re.fullmatch(r"native-block-events-[0-3]\.jsonl", entry["name"]) and
                        entry["name"] not in segment_names and
                        entry["local_file"] == str(parent / entry["name"]) and
                        uint(entry["bytes"], SEGMENT_BYTES) and hex_text(entry["sha256"]),
                        "snapshot_segment_metadata_rejected")
                segment_names.add(entry["name"])
                body = read_source(parent / entry["name"], SEGMENT_BYTES)
                require(len(body) == entry["bytes"] and
                        hashlib.sha256(body).hexdigest() == entry["sha256"],
                        "snapshot_segment_hash_mismatch")
                require(body and body.endswith(b"\n"), "partial_segment_tail")
                for line in body.splitlines(keepends=True):
                    require(0 < len(line) <= RECORD_BYTES and line.endswith(b"\n"),
                            "native_record_bound_rejected")
                    record = parse(line)
                    key = record_schema(record, bindings, node)
                    existing = records[alias].get(key)
                    require(existing is None or existing[0] == line,
                            "conflicting_duplicate_record")
                    if existing is None:
                        record_count += 1
                        retained_bytes += len(line)
                        require(record_count <= MAX_RECORDS + 2 * MAX_NODES and
                                retained_bytes <= MAX_RETAINED_BYTES,
                                "retained_record_budget_exceeded")
                        records[alias][key] = (line, record)

    streams, retained, earliest, block_heights = [], [], [], {}
    for node in bindings["nodes"]:
        alias = node["alias"]
        rows = records[alias]
        require(all(("marker", kind) in rows for kind in MARKER_KINDS),
                "complete_stream_markers_required")
        start = rows[("marker", "native-event-stream-start")][1]
        end = rows[("marker", "native-event-stream-end")][1]
        require(start["event_attempts"] == 0, "nonzero_start_marker")
        total = end["event_attempts"]
        require({key[1] for key in rows if key[0] == "event"} == set(range(1, total + 1)),
                "native_event_sequence_gap")
        low, high = (int(marker["elapsed_monotonic_ns"]) for marker in (start, end))
        require(low <= high, "stream_marker_time_reversed")
        snapshot = final[alias]
        diagnostic = snapshot["status_after"]["native_block_events"]
        require(isinstance(snapshot.get("unit"), dict) and
                snapshot["unit"].get("MainPID") == "0" and "process" in snapshot and
                snapshot["process"] is None and
                diagnostic["stream_end_written"] is True and
                diagnostic["event_attempts"] == total, "final_stopped_diagnostic_required")
        ordered = [rows[("marker", "native-event-stream-start")]]
        ordered.extend(rows[("event", sequence)] for sequence in range(1, total + 1))
        ordered.append(rows[("marker", "native-event-stream-end")])
        counts = {kind: 0 for kind in EVENT_KINDS}
        logical, attempts = {}, set()
        for line, record in ordered:
            retained.append({"alias": alias, "record": record,
                             "line_sha256": hashlib.sha256(line).hexdigest()})
            if record["record"] != "block-event":
                continue
            require(low <= int(record["elapsed_monotonic_ns"]) <= high,
                    "native_event_outside_stream")
            kind = record["kind"]
            counts[kind] += 1
            prior_height = block_heights.setdefault(record["block_id"], record["height"])
            require(prior_height == record["height"], "conflicting_block_height")
            if kind == REJECTION_KIND:
                require(record["owner_attempt"] not in attempts,
                        "reused_owner_rejection_attempt")
                attempts.add(record["owner_attempt"])
            else:
                key = (kind, record["block_id"])
                prior = logical.get(key)
                if prior is None or int(record["elapsed_monotonic_ns"]) < int(prior["elapsed_monotonic_ns"]):
                    logical[key] = record
        # This selection occurs only after the complete three-kind stream,
        # shared sequence/counters and independent owner diagnostic were checked.
        earliest.extend({"alias": alias, **record} for record in logical.values())
        streams.append({"alias": alias, "run_id": node["run_id"], "attempts": total,
                        "kind_counts": counts, "complete_stream": True,
                        "owner_dropped_events": 0, "stream_dropped_events": 0,
                        "unique_propagation_events": len(logical)})
    return {"version": 1, "result": "PASS", "bindings": bindings,
            "scope": "complete native journal integrity; timing and G2 acceptance separate",
            "validated_event_kinds": sorted(EVENT_KINDS), "streams": streams,
            "records": retained, "earliest_logical_events": earliest, "sources": sources,
            "source_bytes_read": read_bytes, "retained_record_bytes": retained_bytes,
            "native_rejection_scope": "ordinary-forward-admission",
            "clock_calibration_verified": False, "G2_case_pass": False}


def write_result(path, result):
    body = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
    require(len(body) <= MAX_OUTPUT_BYTES, "integrity_output_budget_exceeded")
    path = Path(path).absolute()
    require(".." not in path.parts and path.parent.resolve(strict=True) == path.parent,
            "canonical_output_parent_required")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
