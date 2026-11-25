#!/usr/bin/env python3
"""Validate the public audit registry without contacting a remote service."""

import json
from pathlib import Path, PurePosixPath
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / ".github" / "audit-registry.json"
STATUSES = {"planned", "in_progress", "completed", "blocked"}


def fail(message):
    raise ValueError(message)


def public_path(root, value):
    if not isinstance(value, str) or not value:
        fail("audit paths must be non-empty relative public paths")
    parts = PurePosixPath(value)
    if parts.is_absolute() or any(part.casefold() in ("..", ".local", ".git") for part in parts.parts):
        fail("audit path escapes the publication boundary")
    target = (root / value).resolve()
    if root.resolve() not in target.parents:
        fail("audit path escapes the repository")
    if any(part.casefold() in (".local", ".git") for part in target.relative_to(root.resolve()).parts):
        fail("audit path resolves into private repository data")
    return target


def validate(value, root=ROOT):
    if value.get("version") != 1 or value.get("project") != "siworld":
        fail("unsupported audit registry header")
    audits = value.get("audits")
    if not isinstance(audits, list) or not audits:
        fail("audit registry must contain entries")
    identifiers = set()
    for entry in audits:
        required = {"id", "area", "status", "scope", "excluded", "implementation_paths",
                    "report", "accepted_commit", "findings"}
        if set(entry) != required:
            fail(f"{entry.get('id', '<unknown>')}: schema mismatch")
        identifier = entry["id"]
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            fail("audit ids must be unique non-empty strings")
        identifiers.add(identifier)
        if entry["status"] not in STATUSES or not isinstance(entry["scope"], str) or not entry["scope"].strip():
            fail(f"{identifier}: invalid status or scope")
        if not isinstance(entry["excluded"], list) or not all(isinstance(item, str) and item for item in entry["excluded"]):
            fail(f"{identifier}: excluded scope must be a string list")
        paths = entry["implementation_paths"]
        if not isinstance(paths, list) or not paths:
            fail(f"{identifier}: implementation paths are required")
        for path in paths:
            if not public_path(root, path).exists():
                fail(f"{identifier}: implementation path does not exist: {path}")
        if entry["status"] == "completed":
            if not isinstance(entry["report"], str) or not entry["report"]:
                fail(f"{identifier}: completed audit needs a report path")
            if not isinstance(entry["accepted_commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", entry["accepted_commit"]):
                fail(f"{identifier}: completed audit needs an accepted commit")
        if entry["report"] is not None:
            if not public_path(root, entry["report"]).is_file():
                fail(f"{identifier}: report path does not exist")
        if not isinstance(entry["findings"], list):
            fail(f"{identifier}: findings must be a list")
    return len(audits)


def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail("duplicate audit registry key")
        value[key] = item
    return value


def main():
    value = json.loads(REGISTRY.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    count = validate(value)
    print(f"validated {count} audit scopes")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"audit registry invalid: {exc}", file=sys.stderr)
        raise SystemExit(1)
