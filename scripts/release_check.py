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
    catalog = read_json(ROOT / "skills/data-broker-removal/references/brokers/core.json")
    sbom = read_json(ROOT / "SBOM.spdx.json")
    skill_version = (ROOT / "skills/data-broker-removal/VERSION").read_text(encoding="utf-8").strip()
    if not (ROOT / f"docs/release-notes-v{version}.md").is_file():
        fail(errors, "versioned release notes are missing")

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
    required_config = set(tool.get("configSignals", [{}])[0].get("required", []))
    if "operatorAttestations" not in required_config:
        fail(errors, "operator attestation config signal is missing")
    attestation_schema = manifest.get("configSchema", {}).get("properties", {}).get("operatorAttestations", {})
    expected_attestation_fields = {
        "braveTermsAccepted",
        "braveTermsVersion",
        "braveCustomerResponsibilitiesAccepted",
        "authorizedProfileIds",
        "authorizedBrokerIds",
    }
    if set(attestation_schema.get("required", [])) != expected_attestation_fields:
        fail(errors, "operator attestation schema is not revision-complete")
    attestation_properties = attestation_schema.get("properties", {})
    if (
        attestation_properties.get("braveTermsVersion", {}).get("const") != "2026-02-11"
        or attestation_properties.get("braveTermsAccepted", {}).get("const") is not True
        or attestation_properties.get("braveCustomerResponsibilitiesAccepted", {}).get("const") is not True
    ):
        fail(errors, "Brave terms/customer attestation constants are incomplete")
    live_brokers = [item for item in catalog.get("brokers", []) if item.get("scan", {}).get("supported") is True]
    if [item.get("id") for item in live_brokers] != ["truepeoplesearch"]:
        fail(errors, "live catalog must contain only the Brave-index TruePeopleSearch scope")
    if live_brokers[0].get("scan", {}).get("automated_access_policy") != "search_index_only_no_publisher_access":
        fail(errors, "live broker must use search-index-only discovery")
    spokeo = next((item for item in catalog.get("brokers", []) if item.get("id") == "spokeo"), {})
    if spokeo.get("scan", {}).get("supported") is not False or spokeo.get("scan", {}).get("automated_access_policy") != "prohibited_by_published_terms":
        fail(errors, "Spokeo automation prohibition is not fail-closed")

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
        "operatorAttestationSnapshot",
        "validateOperatorAttestations",
        "capture: false",
        "registerSecurityAuditCollector",
    ]:
        if required not in index:
            fail(errors, f"approval/security invariant missing: {required}")
    live_scan = (ROOT / "lib/live-scan.mjs").read_text(encoding="utf-8")
    for required in [
        'const BRAVE_TERMS_VERSION = "2026-02-11"',
        "braveCustomerResponsibilitiesAccepted",
        "hasIndexCandidate",
        'to_broker_pages: []',
        'state: "indirect_exposure"',
        "publisher_requests: 0",
        "search_result_storage: 0",
        "validateOperatorAttestations(validated, operatorAttestations)",
        "rightout_operator_attestation_required",
        "throwIfAborted(signal)",
    ]:
        if required not in live_scan:
            fail(errors, f"live-scan security invariant missing: {required}")
    for prohibited in ["verifyCandidate", "directPageMatches", "candidate_path_pattern", "allowedHosts: officialDomains", 'method: "GET"']:
        if prohibited in live_scan:
            fail(errors, f"publisher-fetch path must be absent: {prohibited}")

    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    for required in [".rightout-install.lock", "lock_acquired=1", 'rmdir "$lock_dir"']:
        if required not in installer:
            fail(errors, f"installer concurrency invariant missing: {required}")

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    action_uses = re.findall(r"uses:\s*([^\s#]+)", workflow)
    if not action_uses or any(not re.fullmatch(r"[^@\s]+@[a-f0-9]{40}", value) for value in action_uses):
        fail(errors, "CI actions must be pinned to full commit SHAs")

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
