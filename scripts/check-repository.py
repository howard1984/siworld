"""Validate the publication boundary and relative documentation links."""

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {
    ".editorconfig", ".gitattributes", ".gitignore", "Cargo.toml", "Cargo.lock",
    "rust-toolchain.toml", "LICENSE", "NOTICE", "README.md", "CONTRIBUTING.md",
    "SECURITY.md", ".gitleaks.toml",
}
DOCUMENTS = {
    "native-hiding-proof-v2.md",
    "00-decisions.md", "11-risks-open-questions.md", "bht-security-accounting.md", "d8-dependency-patch.md",
    "README.md", "whitepaper.md", "architecture.md", "protocol.md",
    "cryptography.md", "security-model.md", "node-operations.md", "rpc.md",
    "benchmarks.md", "testing.md", "development.md",
    "proof-composition.md", "worker-control.md", "memory-budgets.md",
    "proof-security-review.md", "prover-acceptance.md", "d8-w24-recursion.md",
    "d4-security-controls.md", "d8-parameter-screen.md", "linux-proof-measurement.md",
    "v1-node-network-plan.md", "v1-deployment.md", "v1-network-design.md",
    "route-a-v1.md", "fee-settlement.md", "fee-settlement-evaluation.md",
    "v1-multi-asset.md", "v1-multi-asset-evaluation.md", "v1-storage-and-sync.md", "v1-network-budget.md",
    "multi-asset-air-optimization.md", "v1-overview.md", "dependency-advisories.md",
    "native-proof-profiles.md", "v1-native-runtime.md", "v1-economics.md", "v1-wallet-protection.md",
    "v1-protocol-byte-compatibility.md",
    "v1-native-identity.md", "v1-hybrid-handshake.md", "v1-wallet-storage.md",
    "v1-offline-fund-keys.md",
    "v1-browser-wallet.md", "windows-native-miner.md", "native-proof-storage.md",
    "checkpoint-rejection-acceptance.md", "checkpoint-rejection-ci.md",
    "engineering-checkpoint-roster-transition.md", "offline-validation.md",
    "eng2-protocol.md", "eng2-reorganization.md", "g2-reorganization-acceptance.md", "eng2-anchor-archive.md", "eng2-block-body.md",
    "eng2-incremental-state-roots.md", "eng2-internal-genesis.md", "eng2-material-custody.md",
    "eng2-isolated-sync-staging.md", "eng2-public-fund-claims.md",
    "eng2-snapshot-import.md", "eng2-operation-files.md", "eng2-resident-runtime.md",
    "eng2-wallet-history.md", "engineering-signed-state-import.md",
    "g2-miner-bootstrap-acceptance.md",
}
PUBLIC_ARTIFACTS = {
    "crates/core/artifacts/v1-economics-simulation.json",
    "crates/bench-d8/artifacts/v1-native-freeze.json",
    "crates/bench-multi-asset/artifacts/v1-transaction-profile.json",
    "crates/bench-multi-asset/artifacts/v1-native-proof-profiles.json",
    "crates/bench-multi-asset/artifacts/v1-native-fixed576-settlement.json",
    *(f"crates/prover/keys/root-n{n}.bin" for n in (2, 4, 8, 16, 32, 64, 128)),
    "crates/prover/tests/data/root-proof-n16.bin",
    "crates/prover/tests/data/root-statement-n16.bin",
}
CRATES = {
    "core", "crypto", "poseidon2", "state", "circuits", "consensus",
    "storage", "prover", "node", "native-node", "bench-stark", "bench-d8", "bench-multi-asset", "fund-keytool",
    "native-wallet-core", "native-wallet-web", "native-wallet-engine",
    "miner-cli", "miner-launcher", "miner-platform",
}
EXPLORER_FILES = {
    "tools/explorer/README.md",
    "tools/explorer/chain-client.mjs",
    "tools/explorer/explorer-config.example.json",
    "tools/explorer/explorer.css",
    "tools/explorer/explorer.mjs",
    "tools/explorer/index.html",
    "tools/explorer/projection.mjs",
    "tools/explorer/proxy-location.example.conf",
    "tools/explorer/tests/fixture-server.mjs",
    "tools/explorer/tests/frontend.test.mjs",
    "tools/explorer/tests/projection.test.mjs",
}
PUBLIC_TEXT_ASSETS = {
    'crates/native-wallet-web/networks/eng2-readonly.json',
    'crates/native-wallet-web/releases/eng2-readonly.json',
    'crates/native-wallet-web/tests/eng2-admission.test.mjs',
    'crates/native-wallet-web/tests/eng2-entry.test.mjs',
    'crates/native-wallet-web/tests/eng2-payments.test.mjs',
    'crates/native-wallet-web/tests/eng2-rollback.test.mjs',
    'crates/native-wallet-web/tests/eng2-session-rollback.test.mjs',
    'crates/native-wallet-web/tests/eng2-sources.test.mjs',
    'crates/native-wallet-web/tests/eng2-website.test.mjs',
    'crates/native-wallet-web/tests/public-fetch.test.mjs',
    'crates/native-wallet-web/tests/wallet-history.test.mjs',
    'crates/native-wallet-web/tests/wallet-sync-ui.test.mjs',
    'crates/native-wallet-web/web/assets/wallet-startup.js',
    'crates/native-wallet-web/web/sdk/eng2-admission.js',
    'crates/native-wallet-web/web/sdk/eng2-custody-storage.js',
    'crates/native-wallet-web/web/sdk/eng2-custody.js',
    'crates/native-wallet-web/web/sdk/eng2-payments.js',
    'crates/native-wallet-web/web/sdk/eng2-rollback.js',
    'crates/native-wallet-web/web/sdk/eng2-sources.js',
    'crates/native-wallet-web/web/sdk/eng2-wallet-session.js',
    'crates/native-wallet-web/web/sdk/public-fetch.js',
    'crates/native-wallet-web/web/sdk/runtime-profile.js',

    "crates/native-wallet-web/ENG2.md",
    "crates/native-wallet-web/offline-receive/app.mjs",
    "crates/native-wallet-web/offline-receive/context.mjs",
    "crates/native-wallet-web/offline-receive/core.test.mjs",
    "crates/native-wallet-web/offline-receive/index.html",
    "crates/native-wallet-web/offline-receive/protocol.mjs",
    "crates/native-wallet-web/offline-receive/protocol.test.mjs",
    "crates/native-wallet-web/offline-receive/session.mjs",
    "crates/native-wallet-web/offline-receive/style.css",
    "crates/native-wallet-web/offline-receive/ui.test.mjs",
    "crates/native-wallet-web/offline-receive/worker.mjs",
    "crates/native-wallet-web/tests/eng2-session.test.mjs",
    "crates/native-wallet-web/web/sdk/eng2-context.js",
    "crates/native-wallet-web/web/sdk/eng2-session.js",
    "crates/native-wallet-web/web/sdk/eng2-storage.js",
    "crates/miner-cli/help.txt",
    "crates/native-wallet-web/web/sdk/commitment-session.js",
    "crates/native-wallet-web/tests/commitment-session.test.mjs",
    "crates/native-wallet-web/tests/shared-history.browser.mjs",
    "crates/native-wallet-web/web/sdk/wallet-accounts.js",
    "crates/native-wallet-web/web/assets/wallet-list.js",
    "crates/native-wallet-web/web/assets/wallet-history.js",
    "crates/native-wallet-web/tests/wallet-accounts.test.mjs",
    "crates/native-wallet-web/tests/storage-selection.test.mjs",
    "crates/native-wallet-web/tests/wallet-lifecycle.browser.mjs",
    "crates/native-wallet-web/tests/light-history.test.mjs",
    "crates/native-wallet-web/tests/online-storage.test.mjs",
    "crates/native-wallet-web/web/sdk/proof-progress.js",
    "crates/native-wallet-web/tests/proof-progress.test.mjs",
    "crates/native-wallet-web/web/vault.html",
    "crates/native-wallet-web/web/sdk/online-storage.js",
    "crates/native-wallet-web/web/sdk/light-session.js",
    "crates/native-wallet-web/web/sdk/cloud-session.js",
    "crates/native-wallet-web/web/sdk/cloud-worker.js",
    "crates/native-wallet-web/web/sdk/vault-network.js",
    "crates/native-wallet-web/web/assets/vault-application.js",
    "crates/native-wallet-web/web/assets/cloud-vault.js",

    "crates/native-wallet-web/web/assets/native-vault.js",
    "crates/native-wallet-web/web/sdk/content-worker.js",
    "crates/native-wallet-web/web/sdk/content-storage.js",
    "crates/native-wallet-web/tests/content-vault.test.mjs",
    "crates/native-wallet-web/web/wallet.html",
    "crates/native-wallet-web/web/assets/native-wallet.css",
    "crates/native-wallet-web/web/assets/native-wallet.js",
    "crates/native-wallet-web/web/sdk/network.js",
    "crates/native-wallet-web/web/sdk/storage.js",
    "crates/native-wallet-web/web/sdk/worker.js",
    "crates/native-wallet-web/tests/browser-core.test.mjs",
    "crates/native-node/src/web_wallet/assets/index.html",
    "crates/native-node/src/web_wallet/assets/startup.css",
    "crates/native-node/src/web_wallet/assets/startup.js",
    "crates/native-node/src/web_wallet/assets/wallet.css",
    "crates/native-node/src/web_wallet/assets/wallet.js",
}
NON_ENGLISH = re.compile(
    "[\u3400-\u9fff\uf900-\ufaff\u3040-\u30ff\uac00-\ud7af]"
)


def allowed(path):
    name = path.as_posix()
    if path.parts[:3] == ("crates", "bench-stark", "sp1"):
        return False
    if len(path.parts) == 1:
        return name in ROOT_FILES
    if path.parts[0] == "docs":
        if len(path.parts) == 2:
            return path.name in DOCUMENTS
        scoped = {
            "legacy": {"README.md", "whitepaper.md", "architecture.md", "protocol.md",
                       "cryptography.md", "node-operations.md", "rpc.md", "worker-control.md",
                       "benchmarks.md", "security-model.md"},
            "v2": {"README.md", "proof-composition.md", "d8-w24-recursion.md",
                   "proof-security-review.md", "d8-parameter-screen.md", "d4-security-controls.md",
                   "linux-recursive-measurement.md", "multisignature.md"},
        }
        return len(path.parts) == 3 and path.name in scoped.get(path.parts[1], set())
    if name in {".cargo/config.toml", "scripts/prover-launcher.rs",
                "scripts/native-proof-artifacts.rs", "scripts/native-runtime-launcher.rs",
                "scripts/settlement-full-load.rs",
                "crates/bench-stark/patches/recursion-d8-w24.patch"}:
        return True
    if name in {"scripts/ci-offline.sh", "scripts/ci-fetch.sh", "scripts/ci-bin/cargo"}:
        return True
    if path.parts[:4] == ("scripts", "tests", "fixtures", "retired-workflows"):
        return len(path.parts) == 5 and path.suffix == ".yml"
    if path.parts[0] == "scripts":
        return path.suffix == ".py" and (len(path.parts) == 2 or (len(path.parts) == 3 and path.parts[1] == "tests"))
    if path.parts[0] == "tools":
        return name in EXPLORER_FILES or name in {
            "tools/control-panel/memory_trend.py", "tools/control-panel/test_memory_trend.py"
        }
    if name in {".github/audit-registry.json", ".github/repository-profile.json"}:
        return True
    if path.parts[0] == ".github":
        return path.suffix in {".yml", ".yaml", ".md"} or path.name == "CODEOWNERS"
    if path.parts[0] == "crates" and path.parts[1] in CRATES:
        return (
            name in PUBLIC_ARTIFACTS or name in PUBLIC_TEXT_ASSETS
            or path.suffix in {".rs", ".toml", ".lock", ".py"}
            or path.name == "README.md"
        )
    return False


def main():
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
    ).decode().split("\0")
    errors = []
    for name in sorted(set(filter(None, names))):
        relative = Path(name)
        path = ROOT / relative
        if not allowed(relative):
            errors.append(f"Outside the publication manifest: {name}")
            continue
        if path.is_symlink() or not path.is_file():
            errors.append(f"Expected a regular file: {name}")
            continue
        if name in PUBLIC_ARTIFACTS and path.suffix != ".json":
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeError:
            errors.append(f"Expected UTF-8 text: {name}")
            continue
        if NON_ENGLISH.search(name + content):
            errors.append(f"Non-English text: {name}")
        if re.search(r"(?:/Users/|/home/)[A-Za-z0-9_.-]+/", content):
            errors.append(f"Personal filesystem path: {name}")
        if path.suffix == ".md":
            for target in re.findall(r"(?<!!)\[[^\]]*\]\(([^\s)]+)\)", content):
                if target.startswith(("https://", "http://", "#", "mailto:")):
                    continue
                target = unquote(target.split("#", 1)[0])
                resolved = (path.parent / target).resolve()
                if not resolved.is_relative_to(ROOT) or not resolved.exists():
                    errors.append(f"Invalid relative link in {name}: {target}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Publication manifest, English text and documentation links validated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
