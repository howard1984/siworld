"""Read-only live requirements, an inert model and native control snapshots.

Native record shapes follow the isolated production interface. Reading matching
records does not establish their native origin. Live execution remains disabled.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

DEPTHS = {1, 6, 7, 23, 24, 25}
CAP = 1024 * 1024
CONTEXT = ("campaign_id", "case_id", "attempt_id", "source_commit", "binary_sha256",
           "network_id", "genesis_id", "rules_commitment", "proof_profile")
PHASES = ("common-paused", "partitioned", "production-bounded", "branches-paused",
          "materials-sealed", "healed", "reconciled", "released")
PENDING = ("qualified-native-control-build-and-registration",
           "actual-run-exact-height-and-quiescence-adapter",
           "native-nonfixture-positive-work-and-ancestry-validation",
           "complete-raw-history-and-eleven-component-audit-adapter",
           "retained-remote-owner-partition-heal-and-receipt-adapter",
           "depth25-supported-manual-recovery-adapter")


def require(value, code):
    if not value:
        raise ValueError(code)


def hex_text(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def integer(value):
    return type(value) is int and 0 <= value < 2**64


def work(value):
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,154}", value),
            "canonical_model_work_required")
    number = int(value)
    require(number < 2**512, "model_work_overflow")
    return number


def head(value):
    require(isinstance(value, dict) and set(value) == {"height", "id", "work"} and
            integer(value["height"]) and hex_text(value["id"]), "model_head_rejected")
    work(value["work"])
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_bound(path, expected_sha256):
    path = Path(path).absolute()
    require(hex_text(expected_sha256) and path.resolve(strict=True) == path,
            "canonical_bound_input_required")
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid() and
            metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) & 0o077 == 0 and
            metadata.st_size <= CAP, "private_bounded_input_required")
    with path.open("rb") as stream:
        body = stream.read(CAP + 1)
    require(len(body) == metadata.st_size <= CAP and
            hashlib.sha256(body).hexdigest() == expected_sha256, "input_hash_mismatch")

    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate_json_key")
            value[key] = item
        return value

    def nonfinite(_):
        raise ValueError("nonfinite_json_rejected")

    return json.loads(body, object_pairs_hook=pairs, parse_constant=nonfinite)


def requirements(plan):
    require(isinstance(plan, dict) and set(plan) ==
            {"version", "format", *CONTEXT, "depth", "ancestor", "nodes", "producers",
             "production_profile"} and type(plan["version"]) is int and plan["version"] == 1 and
            plan["format"] == "live-control-consumption-proposal", "proposal_schema_rejected")
    for key in CONTEXT:
        if key.endswith("_id") and key in {"campaign_id", "case_id", "attempt_id"}:
            require(isinstance(plan[key], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", plan[key]),
                    "case_context_rejected")
        else:
            require(hex_text(plan[key], 40 if key == "source_commit" else 64),
                    "case_provenance_rejected")
    depth = plan["depth"]
    require(type(depth) is int and depth in DEPTHS, "supported_depth_required")
    ancestor = head(plan["ancestor"])
    require(ancestor["height"] > 0 and ancestor["height"] + depth + 1 < 2**64,
            "ancestor_height_rejected")
    require(work(ancestor["work"]) > 0, "positive_ancestor_model_work_required")
    require(plan["production_profile"] == {"fixture": False, "pow_iterations": 1,
            "target": "f" * 64, "work_bits": 0, "target_interval": 300} and
            plan["production_profile"]["fixture"] is False and
            all(type(plan["production_profile"][key]) is int
                for key in ("pow_iterations", "work_bits", "target_interval")),
            "nonfixture_positive_work_intent_required")
    nodes = plan["nodes"]
    require(isinstance(nodes, list) and 5 <= len(nodes) <= 64, "live_topology_required")
    aliases, identities, runs = set(), set(), set()
    groups = {"old": [], "candidate": []}
    miners = []
    for node in nodes:
        require(isinstance(node, dict) and set(node) == {"alias", "node_id", "run_id", "role", "group"} and
                isinstance(node["alias"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", node["alias"]) and
                hex_text(node["node_id"]) and hex_text(node["run_id"]) and
                node["role"] in {"miner", "service"} and node["group"] in groups,
                "live_node_binding_rejected")
        require(node["alias"] not in aliases and node["node_id"] not in identities and
                node["run_id"] not in runs, "duplicate_live_node_binding")
        aliases.add(node["alias"]); identities.add(node["node_id"]); runs.add(node["run_id"])
        groups[node["group"]].append(node["alias"])
        if node["role"] == "miner":
            miners.append(node["alias"])
    require(len(miners) >= 3 and len(nodes) - len(miners) >= 2, "three_miners_two_services_required")
    producers = plan["producers"]
    require(isinstance(producers, dict) and set(producers) == set(groups), "two_producers_required")
    for group, members in groups.items():
        require(producers[group] in members and producers[group] in miners and
                any(node["role"] == "service" and node["alias"] in members for node in nodes),
                "partition_producer_and_service_required")
    return {"version": 1, "scope": "read-only live-control consumption proposal",
            "plan_sha256": digest(plan), "context": {key: plan[key] for key in CONTEXT},
            "depth": depth, "ancestor": ancestor,
            "stop_heights": {"old": ancestor["height"] + depth,
                             "candidate": ancestor["height"] + depth + 1},
            "groups": {key: sorted(value) for key, value in groups.items()},
            "miners": sorted(miners), "producers": producers,
            "paused_during_controlled_production": sorted(set(miners) - set(producers.values())),
            "phases": list(PHASES[:-1] if depth == 25 else PHASES),
            "expected_path": "depth25-refusal-and-manual-recovery" if depth == 25 else "savepoint-restore-and-ordinary-append",
            "failure_disposition": "remain paused, preserve original material, require supported manual recovery; no automatic checkpoint recovery",
            "required_separate_concurrency_gate": "at-least-three-simultaneous-miners-with-real-competition",
            "pending_interfaces": list(PENDING), "production_allowed": False,
            "native_controls_available": False, "live_case_pass": False, "G2_case_pass": False}


def check_inert_trace(plan, trace):
    """Check model ordering/arithmetic only; never upgrade a real receipt claim."""
    contract = requirements(plan)
    require(isinstance(trace, dict) and set(trace) == {"version", "origin", "plan_sha256", "records"} and
            type(trace["version"]) is int and trace["version"] == 1 and
            trace["origin"] == "inert-model" and trace["plan_sha256"] == contract["plan_sha256"],
            "explicit_inert_trace_required")
    records = trace["records"]
    require(isinstance(records, list) and len(records) <= len(contract["phases"]), "inert_phase_count_rejected")
    node_runs = {node["alias"]: {key: node[key] for key in ("node_id", "run_id")} for node in plan["nodes"]}
    tips, sealed, all_ids = {}, None, {plan["ancestor"]["id"]}
    for sequence, record in enumerate(records, 1):
        require(isinstance(record, dict) and set(record) ==
                {"sequence", "phase", "context", "node_runs", "data"} and
                type(record["sequence"]) is int and record["sequence"] == sequence and
                record["phase"] == contract["phases"][sequence - 1], "inert_phase_order_rejected")
        require(record["context"] == contract["context"] and record["node_runs"] == node_runs,
                "inert_phase_binding_mismatch")
        phase, data = record["phase"], record["data"]
        require(isinstance(data, dict), "inert_phase_data_required")
        if phase in {"common-paused", "branches-paused"}:
            require(set(data) == {"heads", "producer_quiescent", "inflight_cancelled"} and
                    data["producer_quiescent"] == contract["miners"] and
                    data["inflight_cancelled"] == contract["miners"], "inert_quiescence_required")
            expected = {node["alias"]: plan["ancestor"] if phase == "common-paused" else tips[node["group"]]
                        for node in plan["nodes"]}
            require(data["heads"] == expected, "inert_exact_head_required")
        elif phase == "partitioned":
            require(data == {"groups": contract["groups"], "independent_heal_armed": True,
                             "no_bypass": True}, "inert_partition_guard_required")
        elif phase == "production-bounded":
            require(set(data) == {"branches", "active_producers", "other_miners_paused"} and
                    data["active_producers"] == contract["producers"] and
                    data["other_miners_paused"] == contract["paused_during_controlled_production"] and
                    isinstance(data["branches"], dict) and set(data["branches"]) == {"old", "candidate"},
                    "inert_production_scope_rejected")
            for group, blocks in data["branches"].items():
                require(isinstance(blocks, list) and len(blocks) == plan["depth"] + (group == "candidate"),
                        "inert_branch_length_rejected")
                previous = plan["ancestor"]
                for block in blocks:
                    require(isinstance(block, dict) and set(block) == {"height", "id", "work", "parent"},
                            "inert_block_schema_rejected")
                    current = head({key: block[key] for key in ("height", "id", "work")})
                    require(current["height"] == previous["height"] + 1 and block["parent"] == previous["id"] and
                            current["id"] not in all_ids, "inert_branch_ancestry_rejected")
                    require(work(current["work"]) > work(previous["work"]), "inert_positive_work_required")
                    all_ids.add(current["id"])
                    previous = current
                tips[group] = previous
            require(work(tips["candidate"]["work"]) > work(tips["old"]["work"]),
                    "inert_candidate_greater_work_required")
        elif phase == "materials-sealed":
            require(set(data) == {"raw_frame_and_proof_refs", "complete_state_audit_refs"} and
                    set(data["raw_frame_and_proof_refs"]) == {"old", "candidate"} and
                    set(data["complete_state_audit_refs"]) == set(node_runs) and
                    all(hex_text(value) for value in [*data["raw_frame_and_proof_refs"].values(),
                                                     *data["complete_state_audit_refs"].values()]),
                    "inert_complete_material_refs_required")
            sealed = data
        elif phase == "healed":
            require(data == {"drop_rules_absent": True, "base_firewall_unchanged": True,
                             "reconnected": sorted(node_runs)}, "inert_heal_confirmation_required")
        elif phase == "reconciled":
            require(set(data) == {"path", "heads", "state_audit_refs", "refused_nodes",
                                  "mining_and_signing_paused", "alarmed_nodes"} and
                    data["path"] == contract["expected_path"] and
                    set(data["state_audit_refs"]) == set(node_runs) and
                    all(hex_text(value) for value in data["state_audit_refs"].values()),
                    "inert_reconciliation_required")
            expected = {node["alias"]: tips[node["group"]] if plan["depth"] == 25 else tips["candidate"]
                        for node in plan["nodes"]}
            require(data["heads"] == expected, "inert_reconciled_head_mismatch")
            if plan["depth"] == 25:
                require(data["refused_nodes"] == contract["groups"]["old"] and
                        data["mining_and_signing_paused"] == contract["groups"]["old"] and
                        data["alarmed_nodes"] == contract["groups"]["old"] and
                        data["state_audit_refs"] == sealed["complete_state_audit_refs"],
                        "inert_depth25_refusal_required")
            else:
                require(data["refused_nodes"] == [] and data["mining_and_signing_paused"] == [] and
                        data["alarmed_nodes"] == (contract["groups"]["old"] if plan["depth"] > 6 else []),
                        "inert_reorganization_alarm_required")
        elif phase == "released":
            require(data == {"resumed_miners": contract["miners"], "new_template_parent": tips["candidate"]["id"]},
                    "inert_template_parent_required")
    return {"scope": "inert arithmetic and ordering only", "model_prefix_valid": True,
            "model_complete": len(records) == len(contract["phases"]),
            "next_model_phase": contract["phases"][len(records)] if len(records) < len(contract["phases"]) else None,
            "validated_model_phases": len(records), "nonfixture_proof_verified": False,
            "native_receipts_verified": False, "production_allowed": False,
            "live_case_pass": False, "G2_case_pass": False, "pending_interfaces": list(PENDING)}


# Native wire records are separate from the control-flow model and snapshot envelope.
NATIVE_MAX_BYTES = 8192
NATIVE_MAX_HEIGHT = 1_000_000
NATIVE_MAX_REVISION = 1_000_000
NATIVE_MAX_EVENTS = 64
NATIVE_MANIFEST_FIELDS = {"version", "purpose", "campaign_sha256", "network_id",
                          "genesis_id", "rules_commitment", "proof_profile", "maximum_height"}
NATIVE_REQUEST_FIELDS = {"version", "manifest_sha256", "run_id", "source_commit", "binary_sha256",
                         "revision", "expected_height", "expected_tip", "paused", "stop_height"}
NATIVE_RESULT_COMMON = {"version", "run_id", "manifest_sha256", "source_commit", "binary_sha256",
                        "revision", "request_sha256", "height", "tip", "status"}


def native_hex(value, width=64):
    return hex_text(value, width) and value != "0" * width


def native_json(body):
    require(isinstance(body, bytes) and 0 < len(body) <= NATIVE_MAX_BYTES,
            "native_record_byte_bound_rejected")

    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "native_duplicate_json_key")
            value[key] = item
        return value

    def nonfinite(_):
        raise ValueError("native_nonfinite_json_rejected")

    value = json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite)
    require(isinstance(value, dict), "native_record_object_required")
    return value


def encode_native_record(value):
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    native_json(body)
    return body


def check_native_manifest(plan, value, campaign_sha256):
    requirements(plan)
    require(isinstance(value, dict) and set(value) == NATIVE_MANIFEST_FIELDS and
            type(value["version"]) is int and value["version"] == 1 and
            value["purpose"] == "isolated-native-production" and
            native_hex(campaign_sha256) and value["campaign_sha256"] == campaign_sha256 and
            type(value["maximum_height"]) is int and
            1 <= value["maximum_height"] <= NATIVE_MAX_HEIGHT,
            "native_manifest_schema_rejected")
    for field in ("network_id", "genesis_id", "rules_commitment", "proof_profile"):
        require(native_hex(value[field]) and value[field] == plan[field],
                "native_manifest_context_rejected")
    return value


def native_initialization_contract(plan, campaign_sha256, maximum_height):
    value = {"version": 1, "purpose": "isolated-native-production",
             "campaign_sha256": campaign_sha256, "maximum_height": maximum_height,
             **{key: plan[key] for key in ("network_id", "genesis_id", "rules_commitment", "proof_profile")}}
    body = encode_native_record(check_native_manifest(plan, value, campaign_sha256))
    return {"manifest": value, "manifest_sha256": hashlib.sha256(body).hexdigest(),
            "manifest_bytes": len(body), "initial_policy": "paused", "initial_revision": 0,
            "required_preconditions": ["independently-authenticated-empty-node",
                                       "stopped-node-with-exclusive-service-lease",
                                       "absent-isolated-production-directory",
                                       "qualified-unix-runtime-and-rehearsal-build"],
            "preconditions_verified": False, "initialization_executed": False,
            "production_allowed": False}


def check_native_initialization_output(value, manifest_sha256):
    require(isinstance(value, dict) and set(value) ==
            {"version", "manifest_sha256", "initial_policy", "chain_modified", "identity_created"} and
            type(value["version"]) is int and value["version"] == 1 and
            native_hex(manifest_sha256) and value["manifest_sha256"] == manifest_sha256 and
            value["initial_policy"] == "paused" and value["chain_modified"] is False and
            value["identity_created"] is False, "native_initialization_output_rejected")
    return {"output_consistent": True, "preconditions_verified": False, "production_allowed": False}


def check_native_request(plan, manifest, manifest_sha256, alias, previous_revision, value):
    requirements(plan)
    require(isinstance(manifest, dict), "native_manifest_schema_rejected")
    check_native_manifest(plan, manifest, manifest.get("campaign_sha256"))
    nodes = {node["alias"]: node for node in plan["nodes"]}
    require(isinstance(alias, str) and alias in nodes and native_hex(manifest_sha256) and
            type(previous_revision) is int and 0 <= previous_revision < NATIVE_MAX_REVISION,
            "native_request_binding_rejected")
    require(isinstance(value, dict) and set(value) == NATIVE_REQUEST_FIELDS and
            type(value["version"]) is int and value["version"] == 1 and
            all(native_hex(value[key], 40 if key == "source_commit" else 64) for key in
                ("manifest_sha256", "run_id", "source_commit", "binary_sha256", "expected_tip")) and
            value["manifest_sha256"] == manifest_sha256 and
            value["run_id"] == nodes[alias]["run_id"] and
            value["source_commit"] == plan["source_commit"] and
            value["binary_sha256"] == plan["binary_sha256"] and
            type(value["revision"]) is int and value["revision"] == previous_revision + 1 and
            type(value["expected_height"]) is int and 0 <= value["expected_height"] <= NATIVE_MAX_HEIGHT and
            type(value["stop_height"]) is int and 0 <= value["stop_height"] <= manifest["maximum_height"] and
            type(value["paused"]) is bool and
            (value["paused"] or value["stop_height"] > value["expected_height"]),
            "native_request_context_or_ceiling_rejected")
    return value


def prepare_native_request(plan, manifest_body, manifest_sha256, campaign_sha256, alias,
                           previous_revision, expected_height, expected_tip, paused, stop_height):
    require(isinstance(manifest_body, bytes) and
            hashlib.sha256(manifest_body).hexdigest() == manifest_sha256, "native_manifest_hash_mismatch")
    selected = check_native_manifest(plan, native_json(manifest_body), campaign_sha256)
    nodes = {node["alias"]: node for node in plan["nodes"]}
    require(isinstance(alias, str) and alias in nodes and type(previous_revision) is int and
            0 <= previous_revision < NATIVE_MAX_REVISION, "native_request_binding_rejected")
    value = {"version": 1, "manifest_sha256": manifest_sha256, "run_id": nodes[alias]["run_id"],
             "source_commit": plan["source_commit"], "binary_sha256": plan["binary_sha256"],
             "revision": previous_revision + 1, "expected_height": expected_height,
             "expected_tip": expected_tip, "paused": paused, "stop_height": stop_height}
    check_native_request(plan, selected, manifest_sha256, alias, previous_revision, value)
    return value


def native_record_name(kind, run_id, revision):
    require(kind in {"request", "result"} and native_hex(run_id) and
            type(revision) is int and 1 <= revision <= NATIVE_MAX_REVISION,
            "native_record_name_rejected")
    return "{}-{}-{:016d}.json".format(kind, run_id, revision)


def check_native_installation_output(value, request, request_sha256):
    require(isinstance(value, dict) and set(value) ==
            {"version", "run_id", "revision", "request_sha256", "installed", "acknowledged"} and
            type(value["version"]) is int and value["version"] == 1 and
            native_hex(request_sha256) and value["request_sha256"] == request_sha256 and
            value["run_id"] == request["run_id"] and type(value["revision"]) is int and
            value["revision"] == request["revision"] and value["installed"] is True and
            value["acknowledged"] is False, "native_installation_output_rejected")
    return {"installed": True, "acknowledged": False}


def check_native_result(value, request, request_sha256):
    require(isinstance(value, dict) and isinstance(value.get("status"), str) and
            value["status"] in {"applied", "rejected"},
            "native_immutable_result_required")
    applied = value["status"] == "applied"
    fields = NATIVE_RESULT_COMMON | ({"paused", "stop_height"} if applied else {"reason"})
    require(set(value) == fields and type(value["version"]) is int and value["version"] == 1 and
            all(value[key] == request[key] for key in
                ("run_id", "manifest_sha256", "source_commit", "binary_sha256")) and
            type(value["revision"]) is int and value["revision"] == request["revision"] and
            native_hex(request_sha256) and value["request_sha256"] == request_sha256 and
            integer(value["height"]) and native_hex(value["tip"]), "native_result_binding_rejected")
    if applied:
        require(value["height"] == request["expected_height"] and value["tip"] == request["expected_tip"] and
                type(value["paused"]) is bool and value["paused"] == request["paused"] and
                type(value["stop_height"]) is int and value["stop_height"] == request["stop_height"],
                "native_applied_result_context_rejected")
    else:
        require(value["reason"] == "invalid_or_stale_request", "native_rejection_reason_rejected")
    return {"acknowledged": applied, "record_status": value["status"],
            "revision": value["revision"], "production_allowed": False,
            "native_receipts_verified": False}


def read_native_record(reference):
    """Read one pinned private snapshot, retaining inode identity for rechecks."""
    require(isinstance(reference, dict) and set(reference) == {"path", "sha256"} and
            isinstance(reference["path"], str) and native_hex(reference["sha256"]) and
            os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "native_private_reference_required")
    path = Path(reference["path"])
    require(path.is_absolute() and path.resolve(strict=True) == path, "native_canonical_record_required")
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    file_fd = current_fd = parent_fd = None
    try:
        parent = os.fstat(directory_fd)
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and
                stat.S_IMODE(parent.st_mode) == 0o700, "native_private_directory_required")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        file_fd = os.open(path.name, flags, dir_fd=directory_fd)
        before = os.fstat(file_fd)

        def identity(metadata):
            return [metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode,
                    metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns]

        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
                before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
                0 < before.st_size <= NATIVE_MAX_BYTES, "native_private_record_rejected")
        chunks, length = [], 0
        while length <= NATIVE_MAX_BYTES:
            part = os.read(file_fd, NATIVE_MAX_BYTES + 1 - length)
            if not part:
                break
            chunks.append(part); length += len(part)
        body = b"".join(chunks)
        current_fd = os.open(path.name, flags, dir_fd=directory_fd)
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        current_parent = os.fstat(parent_fd)
        require((parent.st_dev, parent.st_ino) == (current_parent.st_dev, current_parent.st_ino) and
                current_parent.st_uid == os.geteuid() and stat.S_IMODE(current_parent.st_mode) == 0o700 and
                identity(before) == identity(os.fstat(file_fd)) == identity(os.fstat(current_fd)) and
                len(body) == before.st_size and hashlib.sha256(body).hexdigest() == reference["sha256"],
                "native_record_changed_or_hash_mismatch")
        return {"value": native_json(body), "sha256": reference["sha256"],
                "bytes": len(body), "file_identity": identity(before)}
    finally:
        for descriptor in (file_fd, current_fd, parent_fd, directory_fd):
            if descriptor is not None:
                os.close(descriptor)


def check_native_control_snapshot(plan, snapshot):
    """Check copied record consistency only, never resident origin or G2 validity."""
    requirements(plan)
    require(isinstance(snapshot, dict) and set(snapshot) ==
            {"version", "format", "origin", "campaign_sha256", "node_alias", "control_directory",
             "manifest", "initialization_output", "events"} and type(snapshot["version"]) is int and
            snapshot["version"] == 1 and snapshot["format"] == "native-control-record-snapshot" and
            snapshot["origin"] == "offline-schema-snapshot" and native_hex(snapshot["campaign_sha256"]) and
            isinstance(snapshot["control_directory"], str) and
            isinstance(snapshot["events"], list) and len(snapshot["events"]) <= NATIVE_MAX_EVENTS,
            "native_snapshot_schema_rejected")
    directory = Path(snapshot["control_directory"])
    require(directory.is_absolute() and directory.name == "isolated-production" and
            directory.resolve(strict=True) == directory, "native_control_directory_rejected")
    nodes = {node["alias"]: node for node in plan["nodes"]}
    alias = snapshot["node_alias"]
    require(isinstance(alias, str) and alias in nodes, "native_snapshot_node_rejected")
    retained, paths = [], set()

    def consume(reference, expected=None):
        require(isinstance(reference, dict) and isinstance(reference.get("path"), str) and
                reference["path"] not in paths and
                (expected is None or reference["path"] == str(expected)), "native_record_path_reused_or_wrong")
        loaded = read_native_record(reference)
        paths.add(reference["path"]); retained.append((reference, loaded))
        return loaded

    manifest_record = consume(snapshot["manifest"], directory / "manifest.json")
    manifest_sha256 = manifest_record["sha256"]
    manifest = check_native_manifest(plan, manifest_record["value"], snapshot["campaign_sha256"])
    check_native_initialization_output(consume(snapshot["initialization_output"])["value"], manifest_sha256)
    revision, paused, ceiling, pending, rejected = 0, True, 0, None, False
    acknowledgements = []
    for index, event in enumerate(snapshot["events"]):
        require(isinstance(event, dict) and set(event) == {"request", "installation_output", "result"},
                "native_snapshot_event_rejected")
        next_revision = revision + 1
        request_record = consume(event["request"],
                                 directory / native_record_name("request", nodes[alias]["run_id"], next_revision))
        request = check_native_request(plan, manifest, manifest_sha256, alias, revision, request_record["value"])
        check_native_installation_output(consume(event["installation_output"])["value"],
                                         request, request_record["sha256"])
        if event["result"] is None:
            require(index == len(snapshot["events"]) - 1, "native_pending_revision_is_terminal")
            pending = next_revision
            break
        result_record = consume(event["result"],
                                directory / native_record_name("result", nodes[alias]["run_id"], next_revision))
        checked = check_native_result(result_record["value"], request, request_record["sha256"])
        acknowledgements.append(checked)
        if not checked["acknowledged"]:
            require(index == len(snapshot["events"]) - 1, "native_rejection_is_terminal")
            rejected = True
            break
        revision, paused, ceiling = next_revision, request["paused"], request["stop_height"]
    # A second descriptor-bound read catches path replacement or byte changes
    # during this snapshot. It does not prove historical custody before reading.
    for reference, before in retained:
        require(read_native_record(reference) == before, "native_snapshot_record_replaced")
    return {"scope": "offline native record consistency only", "schema_checked": True,
            "initial_policy": "paused", "initial_revision": 0, "applied_revision": revision,
            "requested_paused": paused, "requested_stop_height": ceiling, "pending_revision": pending,
            "terminal_rejection": rejected,
            "record_acknowledgements": acknowledgements, "snapshot_records": len(retained),
            "initialization_preconditions_verified": False, "producer_quiescence_verified": False,
            "native_receipts_verified": False, "native_controls_available": False,
            "nonfixture_proof_verified": False, "production_allowed": False,
            "live_case_pass": False, "G2_case_pass": False,
            "pending_interfaces": list(PENDING)}
