#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".tmp", "node_modules", "__pycache__"}
TEXT_SUFFIXES = {".md", ".py", ".ts", ".mjs", ".js", ".json", ".yml", ".yaml", ".sh", ".txt"}


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def release_files() -> list[Path]:
    files = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.relative_to(ROOT).parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {"VERSION", "Makefile"}:
            files.append(path)
    return sorted(files)


def main() -> None:
    errors: list[str] = []
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    package = read_json(ROOT / "package.json")
    manifest = read_json(ROOT / "openclaw.plugin.json")
    sbom = read_json(ROOT / "SBOM.spdx.json")
    skill_version = (ROOT / "skills/data-broker-removal/VERSION").read_text(encoding="utf-8").strip()

    for label, value in {
        "package": package.get("version"),
        "manifest": manifest.get("version"),
        "skill": skill_version,
        "sbom": sbom.get("packages", [{}])[0].get("versionInfo"),
    }.items():
        if value != version:
            fail(errors, f"version mismatch: {label}={value!r}, root={version!r}")

    if package.get("openclaw", {}).get("extensions") != ["./dist/index.js"]:
        fail(errors, "package must load compiled dist/index.js")
    for path in [ROOT / "dist/index.js", ROOT / "dist/lib/live-scan.mjs"]:
        if not path.is_file():
            fail(errors, f"compiled release file missing: {path.relative_to(ROOT)}")

    tsc = ROOT / "node_modules/.bin/tsc"
    if not tsc.is_file():
        fail(errors, "local TypeScript compiler is missing; run npm ci --ignore-scripts")
    else:
        with tempfile.TemporaryDirectory(prefix="rightout-build-check-") as tmp:
            build = subprocess.run(
                [str(tsc), "-p", "tsconfig.build.json", "--outDir", tmp],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if build.returncode != 0:
                fail(errors, f"clean TypeScript build failed: {build.stderr.strip()}")
            else:
                for relative in [Path("index.js"), Path("lib/live-scan.mjs")]:
                    generated = Path(tmp) / relative
                    committed = ROOT / "dist" / relative
                    if not generated.is_file() or not committed.is_file() or generated.read_bytes() != committed.read_bytes():
                        fail(errors, f"compiled artifact is stale: dist/{relative}")

    tool = manifest.get("toolMetadata", {}).get("rightout_live_scan", {})
    if manifest.get("contracts", {}).get("tools") != ["rightout_live_scan"]:
        fail(errors, "manifest tool contract mismatch")
    if tool.get("optional") is not True or tool.get("replaySafe") is not False:
        fail(errors, "live tool must be optional and non-replay-safe")
    secret_paths = {item.get("path") for item in manifest.get("configContracts", {}).get("secretInputs", {}).get("paths", [])}
    if secret_paths != {"braveApiKey", "profiles.*.payload"}:
        fail(errors, "SecretInput contract mismatch")

    scan_files = [path for path in release_files() if path.resolve() != Path(__file__).resolve()]
    combined = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in scan_files)
    secret_patterns = {
        "private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "GitHub token": r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
        "AWS access key": r"\bAKIA[0-9A-Z]{16}\b",
        "absolute user path": r"/Users/[A-Za-z0-9._-]+/",
    }
    for label, pattern in secret_patterns.items():
        if re.search(pattern, combined):
            fail(errors, f"release text contains {label}")
    for email in re.findall(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", combined):
        if not email.lower().endswith("@example.invalid"):
            fail(errors, f"non-fixture email found: {email}")

    runner = (ROOT / "skills/data-broker-removal/scripts/data_broker_removal.py").read_text(encoding="utf-8")
    for token in ["urllib.request", "requests.", "http.client", "smtplib", "RIGHTOUT_ENABLE_UNSAFE_LOCAL_LIVE", "OPENCLAW_APPROVAL_RECEIPT_KEY"]:
        if token in runner:
            fail(errors, f"offline runner contains prohibited token: {token}")
    runtime_js = "\n".join((ROOT / path).read_text(encoding="utf-8") for path in ["index.ts", "lib/live-scan.mjs"])
    if "globalThis.fetch" in combined or re.search(r"\bfetch\s*\(", runtime_js) or re.search(r"(?<!guarded)fetch\s*\(", runner):
        fail(errors, "unguarded fetch path detected")
    index = (ROOT / "index.ts").read_text(encoding="utf-8")
    for required in [
        "requireApproval",
        'allowedDecisions: ["allow-once", "deny"]',
        'timeoutBehavior: "deny"',
        "scopeBinding",
        "approvalBindings.delete(toolCallId)",
        "rightout_approval_binding_failed",
        "capture: false",
        "registerSecurityAuditCollector",
    ]:
        if required not in index:
            fail(errors, f"approval/security invariant missing: {required}")
    live_scan = (ROOT / "lib/live-scan.mjs").read_text(encoding="utf-8")
    for required in [
        'createHmac("sha256", scanSecret)',
        "randomBytes(32)",
        "parsed.search",
        "parsed.hash",
        "candidate_path_pattern",
        "jsonLdContainsMatchingPerson",
        "throwIfAborted(signal)",
    ]:
        if required not in live_scan:
            fail(errors, f"live-scan security invariant missing: {required}")

    proc = subprocess.run(
        ["npm", "pack", "--dry-run", "--json", "--ignore-scripts"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        fail(errors, f"npm pack dry-run failed: {proc.stderr.strip()}")
    else:
        packed = {item["path"] for item in json.loads(proc.stdout)[0]["files"]}
        for required in ["dist/index.js", "dist/lib/live-scan.mjs", "openclaw.plugin.json", "skills/data-broker-removal/SKILL.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "SBOM.spdx.json"]:
            if required not in packed:
                fail(errors, f"release archive missing: {required}")
        if any(
            path.startswith(("tests/", "node_modules/"))
            or "/__pycache__/" in f"/{path}"
            or path.endswith((".pyc", ".pyo"))
            for path in packed
        ):
            fail(errors, "release archive contains tests, node_modules, or Python bytecode")

    result = {"ok": not errors, "errors": errors, "version": version, "files_scanned": len(release_files())}
    print(json.dumps(result, indent=2, sort_keys=True))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
