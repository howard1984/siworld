"""Validate the publication boundary and relative documentation links."""

import json
import re
import subprocess
import sys
from pathlib import Path
from html import unescape
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {
    ".editorconfig", ".gitattributes", ".gitignore", "Cargo.toml", "Cargo.lock",
    "rust-toolchain.toml", "LICENSE", "NOTICE", "README.md", "CONTRIBUTING.md",
    "SECURITY.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md", ".gitleaks.toml",
}
DOCUMENTS = {
    "README.md",
    "guides/exchange-integration.md",
    "guides/mine-on-linux.md",
    "guides/mine-on-windows.md",
    "guides/run-a-node.md",
    "guides/wallet.md",
    "reference/glossary.md",
    "reference/parameters.md",
    "security/security-model.md",
    "specs/01-notes-and-state.md",
    "specs/02-transactions.md",
    "specs/03-proof-system.md",
    "specs/04-blocks-and-fees.md",
    "specs/05-consensus.md",
    "specs/06-monetary-policy.md",
    "specs/07-storage-and-sync.md",
    "specs/08-p2p-network.md",
    "specs/09-addresses-and-wallets.md",
    "specs/10-rpc.md",
    "whitepaper.md",
}
BRAND_IMAGES = {
    "brand/siworld-on-dark.png",
    "brand/siworld-on-light.png",
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
    "native-wallet-core", "native-wallet-web", "native-wallet-engine", "randomx-pow",
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
        return path.relative_to("docs").as_posix() in DOCUMENTS
    if path.parts[0] == "brand":
        return name in BRAND_IMAGES or name == "brand/LICENSE"
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


MARKDOWN_LINK = re.compile(r"!?\[[^\[\]\n]*\]\(<?([^\s)>]+)>?")
REFERENCE_LINK = re.compile(r"^ {0,3}\[[^\]\n]+\]:\s*<?([^\s>]+)>?", re.MULTILINE)
HTML_LINK = re.compile(r"""\b(href|src|srcset)=["']([^"']+)["']""", re.IGNORECASE)
HEADING = re.compile(r"^ {0,3}#{1,6}\s+(.+)$", re.MULTILINE)
FENCED_OR_COMMENT = re.compile(
    r"^ {0,3}(`{3,}|~{3,})[^\n]*\n.*?^ {0,3}\1[`~]*[ \t]*$|<!--.*?-->",
    re.MULTILINE | re.DOTALL,
)


def markdown_body(content):
    return FENCED_OR_COMMENT.sub("", content)


def markdown_targets(content):
    body = markdown_body(content)
    yield from MARKDOWN_LINK.findall(body)
    yield from REFERENCE_LINK.findall(body)
    for attribute, value in HTML_LINK.findall(body):
        if attribute.lower() == "srcset":
            yield from (entry.split()[0] for entry in value.split(",") if entry.strip())
        else:
            yield value


def markdown_anchors(content):
    body = markdown_body(content)
    anchors = set(re.findall(r"""\b(?:id|name)=["']([^"']+)["']""", body))
    counts = {}
    headings = HEADING.findall(body)
    headings += re.findall(r"^([^\n]+)\n {0,3}(?:=+|-+)[ \t]*$", body, re.MULTILINE)
    for heading in headings:
        heading = re.sub(r"\s+#+\s*$", "", heading)
        heading = re.sub(r"</?[^>]+>", "", heading)
        heading = re.sub(r"!?\[([^\]]+)\]\([^)]+\)", r"\1", heading)
        slug = re.sub(r"[^\w -]", "", unescape(heading).strip().lower()).replace(" ", "-")
        count = counts.get(slug, 0)
        anchor = f"{slug}-{count}" if count else slug
        while anchor in anchors:
            count += 1
            anchor = f"{slug}-{count}"
        counts[slug] = count + 1
        anchors.add(anchor)
    return anchors


def check_links(path, content, names, errors):
    for target in markdown_targets(content):
        link = urlsplit(unescape(target))
        if link.scheme in {"http", "https", "mailto"} or link.netloc:
            continue
        resolved = (path.parent / unquote(link.path)).resolve() if link.path else path
        if not resolved.is_relative_to(ROOT):
            errors.append(f"Invalid relative link in {path.relative_to(ROOT)}: {target}")
            continue
        name = resolved.relative_to(ROOT).as_posix()
        directory = resolved.is_dir() and any(item.startswith(name + "/") for item in names)
        if (name not in names or not resolved.is_file()) and not directory:
            errors.append(f"Missing publication target in {path.relative_to(ROOT)}: {target}")
        elif link.fragment and resolved.suffix == ".md":
            anchors = markdown_anchors(resolved.read_text(encoding="utf-8"))
            if unquote(link.fragment) not in anchors:
                errors.append(f"Missing heading anchor in {path.relative_to(ROOT)}: {target}")


def main():
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
    ).decode().split("\0")
    names = set(filter(None, names))
    errors = []
    for name in sorted(names):
        relative = Path(name)
        path = ROOT / relative
        if not allowed(relative):
            errors.append(f"Outside the publication manifest: {name}")
            continue
        if path.is_symlink() or not path.is_file():
            errors.append(f"Expected a regular file: {name}")
            continue
        if name in BRAND_IMAGES:
            if not path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
                errors.append(f"Expected a PNG image: {name}")
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
            check_links(path, content, names, errors)
    profile = ROOT / ".github/repository-profile.json"
    for entry in json.loads(profile.read_text(encoding="utf-8"))["navigation"]:
        if entry["path"] not in names or not (ROOT / entry["path"]).is_file():
            errors.append(f"Missing repository navigation target: {entry['path']}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Publication manifest, English text, documentation links, and heading anchors validated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
