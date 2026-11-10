"""Negative cases for the public audit evidence boundary."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("audit_registry", ROOT / "scripts/check-audit-registry.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
repository_spec = importlib.util.spec_from_file_location("repository_manifest", ROOT / "scripts/check-repository.py")
repository = importlib.util.module_from_spec(repository_spec)
repository_spec.loader.exec_module(repository)


class RepositoryManifestTests(unittest.TestCase):
    def test_explorer_publication_is_exactly_scoped(self):
        names = (
            "README.md", "chain-client.mjs", "explorer-config.example.json",
            "explorer.css", "explorer.mjs", "index.html", "projection.mjs",
            "proxy-location.example.conf", "tests/fixture-server.mjs",
            "tests/projection.test.mjs",
        )
        for name in names:
            self.assertTrue(repository.allowed(Path("tools/explorer") / name))
        for name in (
            "private.json", "screenshot.png", "other.mjs", "index.html.bak",
            "tests/other.mjs", "runtime/explorer.json", "brand.svg",
        ):
            self.assertFalse(repository.allowed(Path("tools/explorer") / name))

    def test_wallet_text_assets_are_exactly_scoped(self):
        for name in repository.PUBLIC_TEXT_ASSETS:
            self.assertTrue(repository.allowed(Path(name)))
        for name in ("private.json", "screenshot.png", "other.js", "startup.js.bak"):
            self.assertFalse(repository.allowed(Path("crates/native-node/src/web_wallet/assets") / name))

    def test_removed_sp1_workspace_is_outside_publication_boundary(self):
        for name in (
            "Cargo.toml", "Cargo.lock", "README.md",
            "script/Cargo.toml", "script/build.rs", "script/src/main.rs",
            "program/Cargo.toml", "program/Cargo.lock", "program/src/main.rs",
            "aggregate/Cargo.toml", "aggregate/Cargo.lock", "aggregate/src/main.rs",
        ):
            path = Path("crates/bench-stark/sp1") / name
            with self.subTest(path=path):
                self.assertFalse(repository.allowed(path))

    def test_remaining_plonky3_and_native_sources_are_allowed(self):
        for name in (
            "crates/bench-stark/Cargo.toml",
            "crates/bench-stark/common/src/lib.rs",
            "crates/bench-stark/plonky3/src/lib.rs",
            "crates/bench-d8/src/common.rs",
            "crates/bench-multi-asset/src/multi_asset_air.rs",
        ):
            with self.subTest(path=name):
                self.assertTrue(repository.allowed(Path(name)))


class AuditRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = json.loads((ROOT / ".github/audit-registry.json").read_text())

    def test_open_scopes_do_not_imply_a_completed_audit(self):
        self.assertEqual(audit.validate(self.registry), 5)

    def test_completed_status_requires_report_and_full_commit_identity(self):
        value = copy.deepcopy(self.registry)
        value["audits"][0]["status"] = "completed"
        with self.assertRaises(ValueError):
            audit.validate(value)
        value["audits"][0]["report"] = "SECURITY.md"
        value["audits"][0]["accepted_commit"] = "short"
        with self.assertRaises(ValueError):
            audit.validate(value)

    def test_private_and_outside_report_references_fail(self):
        for path in (".local/report.md", ".LOCAL/report.md", ".GIT/report.md", "../report.md", "/tmp/report.md"):
            value = copy.deepcopy(self.registry)
            value["audits"][0]["report"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                audit.validate(value)

    def test_symlink_escape_and_duplicate_keys_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "public"
            root.mkdir()
            outside = Path(directory) / "private.md"
            outside.write_text("Private evidence")
            (root / "report.md").symlink_to(outside)
            with self.assertRaises(ValueError):
                audit.public_path(root, "report.md")
            private = root / ".local"
            private.mkdir()
            (private / "report.md").write_text("Private evidence")
            (root / "private-alias.md").symlink_to(private / "report.md")
            with self.assertRaises(ValueError):
                audit.public_path(root, "private-alias.md")
        with self.assertRaises(ValueError):
            json.loads('{"status":"planned","status":"completed"}', object_pairs_hook=audit.unique_pairs)


if __name__ == "__main__":
    unittest.main()
