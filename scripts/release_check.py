#!/usr/bin/env python3
from __future__ import annotations

import json
import posixpath
import re
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".tmp", "node_modules", "__pycache__"}
TEXT_SUFFIXES = {".md", ".py", ".ts", ".mjs", ".js", ".json", ".yml", ".yaml", ".sh", ".txt"}
MARKET_IDS = {
    "eu_eea", "uk", "us_california", "us_other", "canada", "brazil",
    "australia", "japan", "singapore", "india", "other",
}
MARKET_DOCUMENTATION_HEADINGS = {
    "eu_eea": "### EU and EEA",
    "uk": "### United Kingdom",
    "us_california": "### United States — California",
    "us_other": "### Other US states",
    "canada": "### Canada",
    "brazil": "### Brazil",
    "australia": "### Australia",
    "japan": "### Japan",
    "singapore": "### Singapore",
    "india": "### India",
    "other": "### All other markets",
}


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


def validate_market_policy_report(report: dict, analysis: str, package_files: set[str]) -> list[str]:
    errors: list[str] = []
    markets = report.get("markets")
    if report.get("report_version") != 1 or not isinstance(markets, list):
        return ["market-policy runtime report is invalid"]
    by_id = {
        item.get("market_id"): item
        for item in markets
        if isinstance(item, dict) and isinstance(item.get("market_id"), str)
    }
    if set(by_id) != MARKET_IDS or len(markets) != len(MARKET_IDS):
        errors.append("market-policy runtime coverage does not exactly match the documented 11-market contract")
    core_ids = {
        market_id
        for market_id, item in by_id.items()
        if item.get("coverage_class") == "core"
    }
    if core_ids != {"eu_eea", "uk", "us_california"}:
        errors.append("market-policy core market set is invalid")
    stale_core = sorted(
        market_id
        for market_id in core_ids
        if by_id[market_id].get("source_status") != "current"
    )
    if stale_core:
        errors.append(f"core market-policy sources require review before release: {', '.join(stale_core)}")
    uk = by_id.get("uk", {})
    if (
        uk.get("evidence_status") != "evidenced"
        or uk.get("rightout_support", {}).get("controller_request") != "catalog_limited_1_uk_email_route"
        or uk.get("safe_default") != "dedicated_uk_contract_or_human_gate"
        or "only_cognism_uk_email_route_is_currently_evidenced" not in uk.get("open_requirements", [])
    ):
        errors.append("UK market policy must bind the separate catalog-limited route and preserve the wider evidence gap")
    california = by_id.get("us_california", {})
    if (
        california.get("rightout_support", {}).get("universal_broker_request") != "human_verified_drop_filing_record_only"
        or california.get("rightout_support", {}).get("gpc_preference") != "human_verified_signal_record_only"
        or "gpc_provider_compliance_requires_site_specific_evidence" not in california.get("open_requirements", [])
    ):
        errors.append("California market policy must keep DROP human-only and GPC site compliance evidence-bound")
    us_other = by_id.get("us_other", {})
    if us_other.get("rightout_support", {}).get("gpc_preference") != "human_verified_signal_legal_effect_needs_market_evidence":
        errors.append("non-California US GPC effect must remain market-specific needs_evidence")
    for market_id, item in by_id.items():
        if (
            item.get("source_status") not in {"current", "review_due", "stale"}
            or item.get("operational_authority") != "diagnostic_only_not_authorization"
            or not isinstance(item.get("rightout_support"), dict)
            or item.get("rightout_support", {}).get("gpc_preference") not in {
                "human_verified_signal_record_only",
                "human_verified_signal_legal_effect_needs_market_evidence",
                "unsupported_or_not_evidenced",
            }
            or not isinstance(item.get("safe_default"), str)
            or not isinstance(item.get("open_requirements"), list)
            or not isinstance(item.get("next_review_at"), str)
        ):
            errors.append(f"market-policy record is incomplete: {market_id}")
    required_rules = {
        "technical_discovery_support_is_not_legal_or_provider_authorization",
        "publisher_automation_requires_current_written_provider_authorization_in_every_market",
        "provider_specific_route_eligibility_does_not_create_a_universal_privacy_right",
        "unsupported_or_uncertain_rights_execution_stops_at_a_human_gate",
        "no_market_claims_universal_or_permanent_deletion",
        "preference_signal_is_not_deletion_request_or_deletion_proof",
    }
    if set(report.get("cross_market_rules", [])) != required_rules:
        errors.append("cross-market safety rules are incomplete")
    for market_id, heading in MARKET_DOCUMENTATION_HEADINGS.items():
        if heading not in analysis:
            errors.append(f"market analysis does not document runtime market: {market_id}")
    for required_file in {
        "docs/market-analysis-2026-07.md",
        "docs/roadmap-v0.10.0.md",
    }:
        if required_file not in package_files:
            errors.append(f"market-safety release document is not packaged: {required_file}")
    return errors


def main() -> None:
    errors: list[str] = []
    catalog_validation = subprocess.run(
        [sys.executable, "skills/data-broker-removal/scripts/data_broker_removal.py", "validate"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if catalog_validation.returncode != 0:
        detail = catalog_validation.stderr.strip() or catalog_validation.stdout.strip()
        fail(errors, f"catalog semantic validation failed: {detail}")
    provenance_check = subprocess.run(
        [sys.executable, "scripts/catalog_provenance.py", "--check"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if provenance_check.returncode != 0:
        fail(errors, f"catalog provenance check failed: {provenance_check.stderr.strip()}")
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    package = read_json(ROOT / "package.json")
    package_lock = read_json(ROOT / "package-lock.json")
    shrinkwrap_path = ROOT / "npm-shrinkwrap.json"
    if not shrinkwrap_path.is_file():
        fail(errors, "npm-shrinkwrap.json is missing")
        shrinkwrap = {}
    else:
        shrinkwrap = read_json(shrinkwrap_path)
        if shrinkwrap != package_lock:
            fail(errors, "npm-shrinkwrap.json must exactly match package-lock.json")
    manifest = read_json(ROOT / "openclaw.plugin.json")
    catalog = read_json(ROOT / "skills/data-broker-removal/references/brokers/core.json")
    parity_catalog = read_json(ROOT / "skills/data-broker-removal/references/brokers/unbroker-parity.json")
    provider_terms = read_json(ROOT / "skills/data-broker-removal/references/brokers/provider-terms.json")
    parity_baseline = read_json(ROOT / "docs/unbroker-parity-baseline.json")
    parity_evidence = read_json(ROOT / "docs/unbroker-parity-evidence.json")
    upstream_refresh = read_json(ROOT / "docs/unbroker-upstream-refresh.json")
    scan_coverage = read_json(ROOT / "docs/scan-coverage.json")
    sbom = read_json(ROOT / "SBOM.spdx.json")
    skill_sbom_path = ROOT / "skills/data-broker-removal/SBOM.spdx.json"
    if not skill_sbom_path.is_file():
        fail(errors, "skill SBOM is missing")
    elif read_json(skill_sbom_path) != sbom:
        fail(errors, "skill SBOM must exactly match the root production SBOM")
    skill_version = (ROOT / "skills/data-broker-removal/VERSION").read_text(encoding="utf-8").strip()
    release_notes_path = ROOT / f"docs/release-notes-v{version}.md"
    if not release_notes_path.is_file():
        fail(errors, "versioned release notes are missing")
    elif re.search(r"status:\s*(?:release candidate|prerelease)|tagged publication gates pending", release_notes_path.read_text(encoding="utf-8"), re.I):
        fail(errors, "release notes contain a prerelease status that would contradict a final GitHub release")
    if not (ROOT / f"docs/parity-matrix-v{version}.md").is_file():
        fail(errors, "versioned Unbroker parity matrix is missing")
    correction_path = ROOT / "docs/release-correction-v0.8.0.md"
    if not correction_path.is_file():
        fail(errors, "audited v0.8.0 public release correction is missing")
    audit_path = ROOT / f"docs/audit-v{version}.md"
    checklist_path = ROOT / f"docs/release-checklist-v{version}.md"
    parity_path = ROOT / f"docs/parity-matrix-v{version}.md"
    if not audit_path.is_file():
        fail(errors, "versioned independent closing audit is missing")
    if not checklist_path.is_file():
        fail(errors, "versioned release checklist is missing")
    elif "- [ ]" in checklist_path.read_text(encoding="utf-8"):
        fail(errors, "versioned release checklist has open items")
    if parity_path.is_file() and re.search(
        r"implementation in progress|pending final audit|\|\s*(?:missing|pending)\s*\|",
        parity_path.read_text(encoding="utf-8"),
        re.I,
    ):
        fail(errors, "versioned parity matrix contains a pending verdict")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## {version} - Unreleased" in changelog or not re.search(rf"^## {re.escape(version)} - \d{{4}}-\d{{2}}-\d{{2}}$", changelog, re.M):
        fail(errors, "changelog version is not release-dated")
    benchmark = (ROOT / "docs/feature-benchmark.md").read_text(encoding="utf-8")
    for invariant in [
        "Vendor-published inventory/features",
        "https://petsymposium.org/popets/2025/popets-2025-0125.pdf",
        "real-provider effectiveness remains `needs_evidence`",
        "Inventory size is therefore not treated as an effectiveness proxy",
    ]:
        if invariant not in benchmark:
            fail(errors, f"competitive evidence invariant missing: {invariant}")
    market_analysis = (ROOT / "docs/market-analysis-2026-07.md").read_text(encoding="utf-8")
    market_policy_check = subprocess.run(
        [
            "node",
            "--input-type=module",
            "--eval",
            'import { marketPolicyHealth } from "./lib/market-readiness.mjs"; process.stdout.write(JSON.stringify(marketPolicyHealth()));',
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    try:
        market_policy_report = json.loads(market_policy_check.stdout)
    except json.JSONDecodeError:
        market_policy_report = {}
    if market_policy_check.returncode != 0:
        fail(errors, f"market-policy runtime check failed: {market_policy_check.stderr.strip()}")
    else:
        errors.extend(validate_market_policy_report(
            market_policy_report,
            market_analysis,
            set(package.get("files", [])),
        ))

    brokers = catalog.get("brokers", [])
    parity_counts = {
        "people_search": sum(item.get("category") == "people_search" for item in brokers),
        "scan": sum(item.get("scan", {}).get("supported") is True for item in brokers),
        "email": sum(item.get("removal", {}).get("channel") == "email" for item in brokers),
        "browser_form": sum(item.get("removal", {}).get("channel") == "browser_form" for item in brokers),
        "direct_rescan": sum(item.get("direct_rescan", {}).get("supported") is True for item in brokers),
        "inbound_verification": sum(item.get("verification", {}).get("supported") is True for item in brokers),
        "eu_processes": sum(str(item.get("process_class", "")).startswith("eu_") for item in brokers),
        "eu_email": sum(
            item.get("process_class") == "eu_controller_email_erasure" and item.get("removal", {}).get("channel") == "email"
            for item in brokers
        ),
        "us_executable": sum(
            item.get("removal", {}).get("supported") is True
            and item.get("human_only") is False
            and any(value in {"US", "US-CA"} for value in item.get("removal", {}).get("eligible_jurisdictions", []))
            for item in brokers
        ),
        "executable": sum(
            item.get("removal", {}).get("supported") is True and item.get("human_only") is False
            for item in brokers
        ),
    }
    required_capabilities = sorted(item.get("id") for item in parity_baseline.get("capabilities", []) if item.get("required") is True)
    evidenced_capabilities = parity_evidence.get("capabilities", [])
    if sorted(item.get("id") for item in evidenced_capabilities) != required_capabilities:
        fail(errors, "full Unbroker capability evidence does not exactly match the pinned baseline")
    accepted_capability_statuses = {"implemented", "equivalent_or_stronger"}
    invalid_capabilities = [
        item.get("id") for item in evidenced_capabilities
        if item.get("status") not in accepted_capability_statuses
    ]
    if invalid_capabilities:
        fail(errors, f"Unbroker capability classification is invalid: {', '.join(invalid_capabilities)}")
    documented_gaps = sorted(
        item.get("id") for item in evidenced_capabilities
        if item.get("status") not in accepted_capability_statuses
    )
    if documented_gaps:
        fail(errors, "machine evidence contains an unresolved technical capability gap")
    expected_broker_ids = sorted(parity_baseline.get("broker_ids", []))
    actual_broker_ids = sorted(item.get("id") for item in parity_catalog.get("brokers", []))
    if parity_catalog.get("schema_version") != 2 or actual_broker_ids != expected_broker_ids or len(actual_broker_ids) != 22:
        fail(errors, "exact Unbroker broker surface mismatch")
    invalid_market_contracts = sorted(
        item.get("id")
        for item in parity_catalog.get("brokers", [])
        if (
            item.get("execution_jurisdictions") != ["US", "US-CA"]
            or item.get("execution_market_ids") != ["us_california", "us_other"]
            or item.get("provider_request_contract") != "us_provider_delete_opt_out_v1"
        )
    )
    if invalid_market_contracts:
        fail(errors, f"parity routes lack the exact market-execution contract: {', '.join(invalid_market_contracts)}")
    provider_terms_brokers = provider_terms.get("brokers", [])
    if (
        provider_terms.get("schema_version") != 1
        or provider_terms.get("policy") != {
            "default_publisher_automation": "deny",
            "permission_requirement": "current_written_provider_authorization",
            "operator_attestation_alone_is_insufficient": True,
        }
        or sorted(item.get("id") for item in provider_terms_brokers) != expected_broker_ids
        or sum(item.get("status") == "explicit_automation_prohibition" for item in provider_terms_brokers) != 8
        or sum(item.get("status") == "needs_evidence" for item in provider_terms_brokers) != 14
    ):
        fail(errors, "provider-terms default-deny contract does not exactly cover the 22 reference brokers")
    baseline_contracts = parity_baseline.get("broker_contracts", {})
    actual_contracts = {item.get("id"): item.get("reference_contract") for item in parity_catalog.get("brokers", [])}
    if actual_contracts != baseline_contracts or sorted(actual_contracts) != expected_broker_ids:
        fail(errors, "per-broker Unbroker method/input/route contract mismatch")
    rehold = next((item for item in parity_catalog.get("brokers", []) if item.get("id") == "rehold"), {})
    current_rehold = rehold.get("current_contract", {})
    if (
        current_rehold.get("method") != rehold.get("method")
        or current_rehold.get("action_url") != rehold.get("action_url")
        or current_rehold.get("inputs") != rehold.get("disclosure_fields")
        or current_rehold.get("verification") != rehold.get("verification")
        or current_rehold.get("supersedes_reference_reason")
        != "pinned_optout_route_now_404_official_information_control_route_requires_exact_listing_and_email"
        or {
            (item.get("url"), item.get("fact_scope"), item.get("last_verified"))
            for item in current_rehold.get("evidence", [])
        }
        != {
            ("https://rehold.com/", "official_homepage_current_information_control_link", "2026-07-13"),
            ("https://rehold.com/page/privacy", "official_privacy_policy_exact_listing_and_email_requirements", "2026-07-13"),
        }
    ):
        fail(errors, "Rehold current executable contract is not exactly machine-bound to current official evidence")
    parity_methods = {
        "web_form": sum(item.get("method") == "web_form" for item in parity_catalog.get("brokers", [])),
        "email": sum(item.get("method") == "email" for item in parity_catalog.get("brokers", [])),
        "phone": sum(item.get("method") == "phone" for item in parity_catalog.get("brokers", [])),
    }
    if parity_methods != {"web_form": 20, "email": 1, "phone": 1}:
        fail(errors, "Unbroker method-for-method surface mismatch")
    source_blockers = sorted(item.get("id") for item in parity_catalog.get("brokers", []) if item.get("source_status") == "needs_evidence")
    if source_blockers:
        fail(errors, f"Unbroker official-route evidence is incomplete: {', '.join(source_blockers)}")
    if (
        parity_evidence.get("release_ready") is not True
        or parity_evidence.get("software_release_ready") is not True
        or parity_evidence.get("release_blockers")
        or parity_evidence.get("unbroker_normalized_contract_surface_complete") is not True
        or parity_evidence.get("unbroker_recipe_surface_complete") is not False
        or parity_evidence.get("unbroker_exact_playbook_choreography_complete") is not False
        or parity_evidence.get("unbroker_capability_parity_complete") is not True
        or parity_evidence.get("technical_parity_gate_passed") is not True
        or parity_evidence.get("policy", {}).get("complete_technical_capability_parity_claimed") is not True
        or parity_evidence.get("policy", {}).get("default_operational_autonomy_claimed") is not False
        or parity_evidence.get("unbroker_default_autonomy_complete") is not False
        or parity_evidence.get("autonomous_form_execution_ready") is not False
        or "not a claim of default autonomous form execution" not in parity_evidence.get("release_ready_meaning", "")
    ):
        fail(errors, "machine-readable technical-parity and operational-boundary verdict is invalid")
    if (
        upstream_refresh.get("schema_version") != 1
        or upstream_refresh.get("pinned_commit") != parity_baseline.get("reference", {}).get("commit")
        or upstream_refresh.get("pinned_commit") != parity_catalog.get("reference_commit")
        or upstream_refresh.get("unbroker_subtree_unchanged") is not True
        or upstream_refresh.get("pinned_subtree_sha") != upstream_refresh.get("current_subtree_sha")
    ):
        fail(errors, "Unbroker upstream-refresh evidence is invalid")
    upstream_check = subprocess.run(
        ["node", "scripts/verify-unbroker-upstream.mjs"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if upstream_check.returncode != 0:
        fail(errors, f"live Unbroker upstream refresh failed: {upstream_check.stderr.strip()}")
    scan_coverage_check = subprocess.run(
        ["node", "scripts/verify-scan-coverage.mjs"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if scan_coverage_check.returncode != 0:
        detail = scan_coverage_check.stderr.strip() or scan_coverage_check.stdout.strip()
        fail(errors, f"runtime/documented scan coverage mismatch: {detail}")
    if scan_coverage.get("human_only_controller_portal_lanes") != 3:
        fail(errors, "scan coverage must preserve the three reviewed human-only controller portal lanes")
    for test_file in [
        "cases.test.mjs", "direct-rescan.test.mjs", "file-keyed-store.test.mjs", "form-runtime.test.mjs",
        "listing-tokens.test.mjs", "verification-runtime.test.mjs", "adversarial-input-property.test.mjs",
        "controller-outcome-runtime.test.mjs", "submission-reconciliation-runtime.test.mjs", "dedupe-recovery-runtime.test.mjs",
        "removal-lane-matrix.test.mjs", "catalog-health.test.mjs", "retention-runtime.test.mjs", "state-rotation-runtime.test.mjs",
        "campaigns.test.mjs", "campaign-runtime.test.mjs", "parity-autopilot.test.mjs", "parity-catalog.test.mjs",
        "parity-evidence.test.mjs", "parity-scan.test.mjs", "browser-session.test.mjs", "parity-email.test.mjs",
        "registry.test.mjs", "report-export.test.mjs", "parity-form-matrix.test.mjs", "parity-source-refresh.test.mjs",
        "feature-runtime.test.mjs", "webmail-runtime.test.mjs", "discovery-session-runtime.test.mjs", "drop-runtime.test.mjs",
        "browser-backend-runtime.test.mjs", "full-autonomy-runtime.test.mjs", "form-session-runtime.test.mjs",
        "provider-terms.test.mjs", "peopleconnect-runtime.test.mjs", "scan-catalog.test.mjs",
        "campaign-live-scan-runtime.test.mjs", "upstream-contract.test.mjs",
        "autonomy-worker.test.mjs", "autonomy-worker-runtime.test.mjs", "recipes.test.mjs",
        "smtp.test.mjs", "imap.test.mjs", "transport-digest.test.mjs",
        "controller-replies.test.mjs", "controller-reply-runtime.test.mjs",
        "evidence-vault.test.mjs", "evidence-runtime.test.mjs", "custom-targets.test.mjs",
        "effectiveness.test.mjs", "team-access.test.mjs", "team-runtime.test.mjs", "dashboard.test.mjs",
        "market-readiness.test.mjs", "uk-rights.test.mjs",
        "preference-controls.test.mjs",
    ]:
        if not (ROOT / "tests/plugin" / test_file).is_file():
            fail(errors, f"parity evidence test missing: {test_file}")

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
    coverage_script = package.get("scripts", {}).get("test:coverage", "")
    for invariant in ["--test-coverage-lines=85", "--test-coverage-branches=70", "--test-coverage-functions=85"]:
        if invariant not in coverage_script:
            fail(errors, f"coverage gate missing: {invariant}")
    if manifest.get("activation") != {"onStartup": False}:
        fail(errors, "manifest must explicitly declare lazy onStartup activation")
    sbom_versions = {
        item.get("name"): item.get("versionInfo")
        for item in sbom.get("packages", [])
        if isinstance(item, dict)
    }
    sbom_check = subprocess.run(
        ["npm", "sbom", "--omit=dev", "--sbom-format", "spdx"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    try:
        generated_sbom = json.loads(sbom_check.stdout)
    except json.JSONDecodeError:
        generated_sbom = {}
    committed_components = {
        (item.get("name"), item.get("versionInfo"))
        for item in sbom.get("packages", [])
        if isinstance(item, dict)
    }
    generated_components = {
        (item.get("name"), item.get("versionInfo"))
        for item in generated_sbom.get("packages", [])
        if isinstance(item, dict)
    }
    if sbom_check.returncode != 0 or committed_components != generated_components or len(committed_components) < 40:
        fail(errors, "committed production SBOM is incomplete or stale")
    root_lock_dependencies = package_lock.get("packages", {}).get("", {}).get("dependencies", {})
    for dependency, declared_version in package.get("dependencies", {}).items():
        if not isinstance(declared_version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", declared_version):
            fail(errors, f"production dependency must be exactly pinned: {dependency}={declared_version!r}")
            continue
        locked_version = package_lock.get("packages", {}).get(f"node_modules/{dependency}", {}).get("version")
        if root_lock_dependencies.get(dependency) != declared_version or locked_version != declared_version:
            fail(errors, f"production dependency lock mismatch: {dependency}")
        if shrinkwrap.get("packages", {}).get(f"node_modules/{dependency}", {}).get("version") != declared_version:
            fail(errors, f"production dependency shrinkwrap mismatch: {dependency}")
        if sbom_versions.get(dependency) != declared_version:
            fail(errors, f"production dependency SBOM mismatch: {dependency}")
    for path in [
        ROOT / "dist/index.js", ROOT / "dist/lib/live-scan.mjs", ROOT / "dist/lib/scan-catalog.mjs", ROOT / "dist/lib/countries.mjs", ROOT / "dist/lib/direct-rescan.mjs",
        ROOT / "dist/lib/file-keyed-store.mjs", ROOT / "dist/lib/catalog-health.mjs", ROOT / "dist/lib/market-readiness.mjs",
        ROOT / "dist/lib/listing-tokens.mjs", ROOT / "dist/lib/removal.mjs", ROOT / "dist/lib/uk-rights.mjs", ROOT / "dist/lib/form-removal.mjs",
        ROOT / "dist/lib/browser-form.mjs", ROOT / "dist/lib/imap.mjs", ROOT / "dist/lib/verification.mjs",
        ROOT / "dist/lib/cases.mjs", ROOT / "dist/lib/smtp.mjs", ROOT / "dist/lib/campaigns.mjs",
        ROOT / "dist/lib/parity-catalog.mjs", ROOT / "dist/lib/parity-email.mjs", ROOT / "dist/lib/parity-autopilot.mjs",
        ROOT / "dist/lib/registry.mjs", ROOT / "dist/lib/report-export.mjs", ROOT / "dist/lib/parity-source-refresh.mjs",
        ROOT / "dist/lib/autonomy-worker.mjs", ROOT / "dist/lib/recipes.mjs", ROOT / "dist/lib/controller-replies.mjs",
        ROOT / "dist/lib/evidence-vault.mjs", ROOT / "dist/lib/custom-targets.mjs", ROOT / "dist/lib/effectiveness.mjs",
        ROOT / "dist/lib/team-access.mjs", ROOT / "dist/lib/dashboard.mjs",
        ROOT / "dist/lib/drop.mjs", ROOT / "dist/lib/preference-controls.mjs",
    ]:
        if not path.is_file():
            fail(errors, f"compiled release file missing: {path.relative_to(ROOT)}")

    with tempfile.TemporaryDirectory(prefix="rightout-bindings-check-") as tmp:
        private_dir = Path(tmp)
        profile_path = private_dir / "profile.json"
        smtp_path = private_dir / "smtp.json"
        consent_recorded = datetime.now(timezone.utc) - timedelta(minutes=1)
        consent_expires = consent_recorded + timedelta(days=364)
        profile_path.write_text(json.dumps({
            "fullName": "Release Fixture",
            "city": "Exampleville",
            "region": "CA",
            "country": "US",
            "contactEmail": "release-fixture@example.invalid",
            "jurisdictions": ["US", "US-CA"],
            "consent": {
                "authorized": True,
                "recordedAt": consent_recorded.isoformat().replace("+00:00", "Z"),
                "validUntil": consent_expires.isoformat().replace("+00:00", "Z"),
                "scope": ["scan", "broker_removal"],
            },
        }), encoding="utf-8")
        smtp_path.write_text(json.dumps({
            "host": "smtp.gmail.com",
            "port": 465,
            "secure": True,
            "username": "release-fixture",
            "password": "dummy-app-password",
            "fromAddress": "release-fixture@example.invalid",
        }), encoding="utf-8")
        profile_path.chmod(0o600)
        smtp_path.chmod(0o600)
        binding_check = subprocess.run(
            ["node", "scripts/compute-removal-bindings.mjs", "profile_a1b2c3d4e5f60718", str(profile_path), str(smtp_path)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        try:
            binding_result = json.loads(binding_check.stdout)
        except json.JSONDecodeError:
            binding_result = {}
        binding_values = [
            binding_result.get("scanProfileDigests", {}).get("profile_a1b2c3d4e5f60718"),
            binding_result.get("authorizedProfileDigests", {}).get("profile_a1b2c3d4e5f60718"),
            binding_result.get("smtpTransportDigest"),
        ]
        repeat_check = subprocess.run(
            ["node", "scripts/compute-removal-bindings.mjs", "profile_a1b2c3d4e5f60718", str(profile_path), str(smtp_path)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        try:
            repeat_result = json.loads(repeat_check.stdout)
        except json.JSONDecodeError:
            repeat_result = {}
        repeat_values = [
            repeat_result.get("scanProfileDigests", {}).get("profile_a1b2c3d4e5f60718"),
            repeat_result.get("authorizedProfileDigests", {}).get("profile_a1b2c3d4e5f60718"),
            repeat_result.get("smtpTransportDigest"),
        ]
        if binding_check.returncode != 0 or not all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) for value in binding_values):
            fail(errors, f"binding helper failed: {binding_check.stderr.strip()}")
        if repeat_check.returncode != 0 or binding_values != repeat_values:
            fail(errors, "binding helper output is not deterministic")
        if any(value in binding_check.stdout for value in ["Release Fixture", "release-fixture@example.invalid", "dummy-app-password"]):
            fail(errors, "binding helper leaked fixture values")
        profile_link = private_dir / "profile-link.json"
        profile_link.symlink_to(profile_path)
        nofollow_check = subprocess.run(
            ["node", "scripts/compute-removal-bindings.mjs", "profile_a1b2c3d4e5f60718", str(profile_link), str(smtp_path)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if nofollow_check.returncode == 0 or nofollow_check.stderr.strip() != "profile_file_unavailable":
            fail(errors, "binding helper did not reject a symlinked private profile")

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
                for relative in [
                    Path("index.js"), Path("lib/live-scan.mjs"), Path("lib/scan-catalog.mjs"), Path("lib/countries.mjs"), Path("lib/direct-rescan.mjs"), Path("lib/file-keyed-store.mjs"),
                    Path("lib/catalog-health.mjs"), Path("lib/market-readiness.mjs"),
                    Path("lib/listing-tokens.mjs"), Path("lib/removal.mjs"), Path("lib/uk-rights.mjs"), Path("lib/form-removal.mjs"),
                    Path("lib/browser-form.mjs"), Path("lib/imap.mjs"), Path("lib/verification.mjs"),
                    Path("lib/cases.mjs"), Path("lib/smtp.mjs"), Path("lib/campaigns.mjs"),
                    Path("lib/parity-catalog.mjs"), Path("lib/parity-email.mjs"), Path("lib/parity-autopilot.mjs"), Path("lib/provider-terms.mjs"),
                    Path("lib/registry.mjs"), Path("lib/report-export.mjs"), Path("lib/parity-source-refresh.mjs"),
                    Path("lib/autonomy-worker.mjs"), Path("lib/recipes.mjs"), Path("lib/controller-replies.mjs"),
                    Path("lib/evidence-vault.mjs"), Path("lib/custom-targets.mjs"), Path("lib/effectiveness.mjs"),
                    Path("lib/team-access.mjs"), Path("lib/dashboard.mjs"),
                    Path("lib/drop.mjs"), Path("lib/preference-controls.mjs"),
                ]:
                    generated = Path(tmp) / relative
                    committed = ROOT / "dist" / relative
                    if not generated.is_file() or not committed.is_file() or generated.read_bytes() != committed.read_bytes():
                        fail(errors, f"compiled artifact is stale: dist/{relative}")

    tool = manifest.get("toolMetadata", {}).get("rightout_live_scan", {})
    removal_tool = manifest.get("toolMetadata", {}).get("rightout_submit_removal", {})
    purge_tool = manifest.get("toolMetadata", {}).get("rightout_purge_subject_state", {})
    controller_outcome_tool = manifest.get("toolMetadata", {}).get("rightout_record_controller_outcome", {})
    reconciliation_tool = manifest.get("toolMetadata", {}).get("rightout_reconcile_submission", {})
    rotation_tool = manifest.get("toolMetadata", {}).get("rightout_rotate_state_key", {})
    health_tool = manifest.get("toolMetadata", {}).get("rightout_catalog_health", {})
    dashboard_tool = manifest.get("toolMetadata", {}).get("rightout_export_dashboard", {})
    effectiveness_tool = manifest.get("toolMetadata", {}).get("rightout_effectiveness", {})
    team_overview_tool = manifest.get("toolMetadata", {}).get("rightout_team_overview", {})
    drop_status_tool = manifest.get("toolMetadata", {}).get("rightout_record_drop_status", {})
    gpc_observation_tool = manifest.get("toolMetadata", {}).get("rightout_record_gpc_observed", {})
    canary_schema = (
        manifest.get("configSchema", {}).get("properties", {})
        .get("effectivenessCanaries", {}).get("additionalProperties", {}).get("items", {})
    )
    canary_required = {
        "schemaVersion", "profileId", "brokerId", "kind", "startedAt", "observedAt",
        "proofReference", "authorizationReferenceSha256", "deploymentEvidenceSha256",
    }
    canary_kinds = {
        "identity_reviewed", "submission_delivered", "controller_confirmed",
        "direct_absence", "reappearance", "human_handoff",
    }
    if (
        set(canary_schema.get("required", [])) != canary_required
        or canary_schema.get("properties", {}).get("schemaVersion", {}).get("const") != 2
        or set(canary_schema.get("properties", {}).get("kind", {}).get("enum", [])) != canary_kinds
        or canary_schema.get("properties", {}).get("authorizationReferenceSha256", {}).get("pattern") != "^[a-f0-9]{64}$"
        or canary_schema.get("properties", {}).get("deploymentEvidenceSha256", {}).get("pattern") != "^[a-f0-9]{64}$"
        or not canary_schema.get("allOf")
    ):
        fail(errors, "authorized-canary v2 config contract is incomplete")
    expected_tools = [
        "rightout_live_scan", "rightout_direct_rescan", "rightout_submit_removal",
        "rightout_submit_form_removal", "rightout_poll_verification", "rightout_poll_controller_reply", "rightout_open_verification",
        "rightout_rotate_state_key", "rightout_purge_subject_state", "rightout_record_controller_outcome",
        "rightout_create_evidence_snapshot", "rightout_evidence_status", "rightout_export_evidence", "rightout_custom_target_status",
        "rightout_effectiveness", "rightout_team_session_binding", "rightout_team_overview", "rightout_export_dashboard",
        "rightout_reconcile_submission", "rightout_next_actions", "rightout_case_status",
        "rightout_export_report", "rightout_catalog_health", "rightout_setup", "rightout_doctor", "rightout_due_rechecks",
        "rightout_start_campaign", "rightout_campaign_status", "rightout_campaign_next",
        "rightout_worker_enable", "rightout_worker_status", "rightout_worker_tick", "rightout_worker_complete",
        "rightout_worker_resume", "rightout_worker_revoke", "rightout_revoke_campaign",
        "rightout_refresh_registries", "rightout_registry_status", "rightout_record_drop_filed",
        "rightout_record_drop_status", "rightout_record_gpc_observed", "rightout_registry_search",
        "rightout_unbroker_parity_health", "rightout_refresh_parity_sources", "rightout_submit_parity_email", "rightout_begin_webmail_session",
        "rightout_webmail_session_step", "rightout_begin_webmail_verification",
        "rightout_begin_discovery_session", "rightout_discovery_session_step",
        "rightout_begin_form_session", "rightout_form_session_step",
    ]
    if manifest.get("contracts", {}).get("tools") != expected_tools:
        fail(errors, "manifest tool contract mismatch")
    if tool.get("optional") is not True or tool.get("replaySafe") is not False:
        fail(errors, "live tool must be optional and non-replay-safe")
    if removal_tool.get("optional") is not True or removal_tool.get("replaySafe") is not False:
        fail(errors, "removal tool must be optional and non-replay-safe")
    if purge_tool.get("optional") is not True or purge_tool.get("replaySafe") is not False:
        fail(errors, "subject purge tool must be optional and non-replay-safe")
    if controller_outcome_tool.get("optional") is not True or controller_outcome_tool.get("replaySafe") is not False:
        fail(errors, "controller outcome tool must be optional and non-replay-safe")
    if reconciliation_tool.get("optional") is not True or reconciliation_tool.get("replaySafe") is not False:
        fail(errors, "submission reconciliation tool must be optional and non-replay-safe")
    if rotation_tool.get("optional") is not True or rotation_tool.get("replaySafe") is not False:
        fail(errors, "state-key rotation tool must be optional and non-replay-safe")
    if health_tool.get("optional") is not True or health_tool.get("replaySafe") is not True:
        fail(errors, "catalog-health tool must be optional and replay-safe")
    if dashboard_tool.get("optional") is not True or dashboard_tool.get("replaySafe") is not False:
        fail(errors, "dashboard export must be optional and non-replay-safe")
    if effectiveness_tool.get("replaySafe") is not True or team_overview_tool.get("replaySafe") is not True:
        fail(errors, "effectiveness and team overview must be replay-safe")
    for label, value in {
        "DROP status": drop_status_tool,
        "GPC observation": gpc_observation_tool,
    }.items():
        if value.get("optional") is not True or value.get("replaySafe") is not False:
            fail(errors, f"{label} tool must be optional and non-replay-safe")
        if set((value.get("configSignals") or [{}])[0].get("required", [])) != {"profiles", "stateEncryptionKey"}:
            fail(errors, f"{label} config signals are incomplete")
    if set((purge_tool.get("configSignals") or [{}])[0].get("required", [])) != {"stateEncryptionKey"}:
        fail(errors, "subject purge config signals are incomplete")
    if set((rotation_tool.get("configSignals") or [{}])[0].get("required", [])) != {"stateEncryptionKey", "previousStateEncryptionKeys"}:
        fail(errors, "state-key rotation config signals are incomplete")
    secret_paths = {item.get("path") for item in manifest.get("configContracts", {}).get("secretInputs", {}).get("paths", [])}
    if secret_paths != {
        "braveApiKey", "profiles.*.payload", "smtpTransport.username", "smtpTransport.password",
        "smtpTransport.oauthAccessToken", "smtpTransport.fromAddress", "imapTransport.username", "imapTransport.password",
        "imapTransport.oauthAccessToken", "imapTransport.address", "stateEncryptionKey", "previousStateEncryptionKeys.*", "browserControlToken",
    }:
        fail(errors, "SecretInput contract mismatch")
    config_properties = manifest.get("configSchema", {}).get("properties", {})
    retention_schema = config_properties.get("stateRetentionDays", {})
    previous_keys_schema = config_properties.get("previousStateEncryptionKeys", {})
    team_schema = config_properties.get("teamAccess", {})
    canary_schema = config_properties.get("effectivenessCanaries", {})
    if retention_schema != {"type": "integer", "minimum": 30, "maximum": 730, "default": 365}:
        fail(errors, "state retention schema mismatch")
    if previous_keys_schema.get("minItems") != 1 or previous_keys_schema.get("maxItems") != 3 or previous_keys_schema.get("uniqueItems") is not True:
        fail(errors, "previous state-key schema mismatch")
    if team_schema.get("maxProperties") != 100 or canary_schema.get("maxProperties") != 20:
        fail(errors, "team/effectiveness config schema mismatch")
    required_config = set(tool.get("configSignals", [{}])[0].get("required", []))
    if {"operatorAttestations", "stateEncryptionKey"} - required_config:
        fail(errors, "operator attestation config signal is missing")
    removal_required_config = set(removal_tool.get("configSignals", [{}])[0].get("required", []))
    if removal_required_config != {"smtpTransport", "stateEncryptionKey", "profiles", "removalAttestations"}:
        fail(errors, "removal config signals are incomplete")
    attestation_schema = manifest.get("configSchema", {}).get("properties", {}).get("operatorAttestations", {})
    expected_attestation_fields = {
        "braveTermsAccepted",
        "braveTermsVersion",
        "braveCustomerResponsibilitiesAccepted",
        "subjectConsentReviewed",
        "authorizedProfileIds",
        "authorizedProfileDigests",
        "authorizedBrokerIds",
    }
    if set(attestation_schema.get("required", [])) != expected_attestation_fields:
        fail(errors, "operator attestation schema is not revision-complete")
    attestation_properties = attestation_schema.get("properties", {})
    if (
        attestation_properties.get("braveTermsVersion", {}).get("const") != "2026-02-11"
        or attestation_properties.get("braveTermsAccepted", {}).get("const") is not True
        or attestation_properties.get("braveCustomerResponsibilitiesAccepted", {}).get("const") is not True
        or attestation_properties.get("subjectConsentReviewed", {}).get("const") is not True
    ):
        fail(errors, "Brave terms/customer attestation constants are incomplete")
    removal_schema = manifest.get("configSchema", {}).get("properties", {}).get("removalAttestations", {})
    expected_removal_fields = {
        "rightoutRemovalPolicyAccepted",
        "rightoutRemovalPolicyVersion",
        "subjectConsentReviewed",
        "smtpAccountAuthorized",
        "minimumDisclosureAccepted",
        "authorizedProfileIds",
        "authorizedProfileDigests",
        "authorizedBrokerIds",
        "authorizedRequestKinds",
        "smtpTransportDigest",
    }
    if set(removal_schema.get("required", [])) != expected_removal_fields:
        fail(errors, "removal attestation schema is not revision-complete")
    removal_properties = removal_schema.get("properties", {})
    if (
        removal_properties.get("rightoutRemovalPolicyVersion", {}).get("const") != "2026-07-16-global2"
        or removal_properties.get("rightoutRemovalPolicyAccepted", {}).get("const") is not True
        or removal_properties.get("subjectConsentReviewed", {}).get("const") is not True
        or removal_properties.get("smtpAccountAuthorized", {}).get("const") is not True
        or removal_properties.get("minimumDisclosureAccepted", {}).get("const") is not True
        or removal_properties.get("authorizedRequestKinds", {}).get("maxItems") != 3
        or removal_properties.get("authorizedRequestKinds", {}).get("items", {}).get("enum") != [
            "delete_and_opt_out", "gdpr_erasure_objection", "uk_erasure_objection",
        ]
    ):
        fail(errors, "removal policy/consent/SMTP attestation constants are incomplete")
    controller_reply_schema = manifest.get("configSchema", {}).get("properties", {}).get("controllerReplyAttestations", {})
    if (
        controller_reply_schema.get("properties", {}).get("rightoutControllerReplyPolicyVersion", {}).get("const")
        != "2026-07-16-global2"
    ):
        fail(errors, "controller-reply policy is not bound to the current EU/UK/US contract revision")
    live_brokers = [item for item in catalog.get("brokers", []) if item.get("scan", {}).get("supported") is True]
    if len(live_brokers) != 21:
        fail(errors, "live catalog must contain the reviewed 21-broker Brave-index scope")
    if any(item.get("scan", {}).get("automated_access_policy") != "search_index_only_no_publisher_access" for item in live_brokers):
        fail(errors, "every live broker must use search-index-only discovery")
    removal_brokers = [item for item in catalog.get("brokers", []) if item.get("removal", {}).get("supported") is True]
    if (
        len(removal_brokers) != 29
        or len({item.get("id") for item in removal_brokers}) != 29
        or sum(item.get("process_class") == "eu_controller_email_erasure" for item in removal_brokers) != 18
        or sum(item.get("process_class") == "uk_controller_email_erasure" for item in removal_brokers) != 1
        or sum(item.get("process_class") == "us_data_broker_email_deletion" for item in removal_brokers) != 8
        or any(item.get("human_only") is not False for item in removal_brokers)
    ):
        fail(errors, "removal catalog must contain the reviewed 29-target US, EU, and UK scope")
    removal_lane = next((item.get("removal", {}) for item in removal_brokers if item.get("id") == "beenverified"), {})
    if (
        removal_lane.get("recipient") != "privacy@beenverified.com"
        or removal_lane.get("disclosure_fields") != ["full_name", "contact_email", "region", "country"]
        or removal_lane.get("confirmation_policy") != "submitted_until_later_rescan"
    ):
        fail(errors, "removal broker must use the catalog-locked minimum-disclosure lane")
    form_lane = next((item.get("removal", {}) for item in removal_brokers if item.get("id") == "intelius"), {})
    if (
        form_lane.get("form_url") != "https://suppression.peopleconnect.us/"
        or form_lane.get("disclosure_fields") != ["contact_email"]
        or form_lane.get("captcha_policy", form_lane.get("form_recipe", {}).get("captcha_policy")) != "fail_closed_human_task"
    ):
        fail(errors, "browser-form broker must use the catalog-locked minimum-disclosure lane")
    fullenrich_lane = next((item.get("removal", {}) for item in removal_brokers if item.get("id") == "fullenrich_eu"), {})
    emetriq_lane = next((item.get("removal", {}) for item in removal_brokers if item.get("id") == "emetriq_eu"), {})
    if (
        fullenrich_lane.get("recipient") != "support@fullenrich.com"
        or fullenrich_lane.get("disclosure_fields") != ["contact_email", "country"]
        or emetriq_lane.get("recipient") != "datenschutz@emetriq.com"
        or emetriq_lane.get("disclosure_fields") != ["contact_email", "country"]
        or any(lane.get("request_kinds") != ["gdpr_erasure_objection"] for lane in [fullenrich_lane, emetriq_lane])
        or any(lane.get("confirmation_policy") != "submitted_until_controller_response" for lane in [fullenrich_lane, emetriq_lane])
    ):
        fail(errors, "EU removal lanes must keep official destinations, minimum disclosure, and controller-response semantics")
    cognism_uk = next((item for item in removal_brokers if item.get("id") == "cognism_uk"), {})
    uk_lane = cognism_uk.get("removal", {})
    if (
        cognism_uk.get("process_class") != "uk_controller_email_erasure"
        or cognism_uk.get("jurisdictions") != ["UK"]
        or cognism_uk.get("eu_process") is not None
        or uk_lane.get("recipient") != "privacy@cognism.com"
        or uk_lane.get("request_kinds") != ["uk_erasure_objection"]
        or uk_lane.get("template_id") != "uk_erasure_objection_v1"
        or uk_lane.get("rights_contract_id") != "uk_controller_erasure_objection_v1"
        or uk_lane.get("eligible_jurisdictions") != ["UK"]
        or uk_lane.get("identity_verification") != "controller_may_request_proportionate_follow_up_human_review"
        or uk_lane.get("deadline_policy") != "one_calendar_month_conservative_recheck_v1"
        or uk_lane.get("processing_days") != 28
    ):
        fail(errors, "UK removal lane must remain separate from the EU gate and bind request, identity, and deadline contracts")
    spokeo = next((item for item in catalog.get("brokers", []) if item.get("id") == "spokeo"), {})
    if spokeo.get("scan", {}).get("supported") is not False or spokeo.get("scan", {}).get("automated_access_policy") != "prohibited_by_published_terms":
        fail(errors, "Spokeo automation prohibition is not fail-closed")
    california_drop = next((item for item in catalog.get("brokers", []) if item.get("id") == "california_drop"), {})
    if (
        california_drop.get("human_only") is not True
        or california_drop.get("jurisdictions") != ["US-CA"]
        or california_drop.get("last_verified") != "2026-07-16"
        or "portal status" not in california_drop.get("notes", "").lower()
        or "not direct record-level deletion proof" not in california_drop.get("notes", "").lower()
    ):
        fail(errors, "California DROP catalog fact must remain current, human-only, and explicitly non-proof")

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
    allowed_public_emails = {
        item.get("removal", {}).get("recipient", "").lower()
        for item in catalog.get("brokers", [])
        if item.get("removal", {}).get("supported") is True
    }
    allowed_public_emails.update(
        item.get("rescue_email", "").lower()
        for item in parity_catalog.get("brokers", [])
        if item.get("rescue_email")
    )
    for email in re.findall(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", combined):
        local, domain = email.lower().rsplit("@", 1)
        safe_fixture = domain.endswith(".invalid") or (
            local in {"test-message", "opaque"}
            and domain in {"beenverified.com", "peopleconnect.us"}
        )
        if not safe_fixture and email.lower() not in allowed_public_emails:
            fail(errors, f"non-fixture email found: {email}")

    runner = (ROOT / "skills/data-broker-removal/scripts/data_broker_removal.py").read_text(encoding="utf-8")
    for token in ["urllib.request", "requests.", "http.client", "smtplib", "RIGHTOUT_ENABLE_UNSAFE_LOCAL_LIVE", "OPENCLAW_APPROVAL_RECEIPT_KEY"]:
        if token in runner:
            fail(errors, f"offline runner contains prohibited token: {token}")
    if '"indirect_exposure": by_state["indirect_exposure"]' not in runner or 'by_state["found"] + by_state["indirect_exposure"]' in runner:
        fail(errors, "offline report must keep indirect_exposure separate from found")
    runtime_js = "\n".join((ROOT / path).read_text(encoding="utf-8") for path in ["index.ts", "lib/live-scan.mjs", "lib/removal.mjs", "lib/smtp.mjs"])
    if re.search(r"(?<![\w.])fetch\s*\(", runtime_js) or re.search(r"(?<!guarded)fetch\s*\(", runner):
        fail(errors, "unguarded fetch path detected")
    browser_form = (ROOT / "lib/browser-form.mjs").read_text(encoding="utf-8")
    if "globalThis.fetch" not in browser_form or "safeBridgeUrl" not in browser_form or "redirect: \"error\"" not in browser_form:
        fail(errors, "sandbox browser bridge fetch contract is missing")
    index = (ROOT / "index.ts").read_text(encoding="utf-8")
    for required in [
        "requireApproval",
        'allowedDecisions: ["allow-once", "deny"]',
        "scanScopeBinding",
        "removalScopeBinding",
        "approvalBindings.delete(toolCallId)",
        "rightout_approval_binding_failed",
        "scanAttestationSnapshot",
        "removalAttestationSnapshot",
        "validateOperatorAttestations",
        "capture: false",
        "registerSecurityAuditCollector",
    ]:
        if required not in index:
            fail(errors, f"approval/security invariant missing: {required}")
    for required in [
        "rightout_record_drop_status",
        "rightout_record_gpc_observed",
        "portal_status_is_direct_deletion_proof: false",
        "site_compliance_verified: false",
        "preference_controls",
    ]:
        if required not in index:
            fail(errors, f"DROP/GPC runtime invariant missing: {required}")
    drop_contract = (ROOT / "lib/drop.mjs").read_text(encoding="utf-8")
    preference_contract = (ROOT / "lib/preference-controls.mjs").read_text(encoding="utf-8")
    cases_source = (ROOT / "lib/cases.mjs").read_text(encoding="utf-8")
    report_export = (ROOT / "lib/report-export.mjs").read_text(encoding="utf-8")
    for required in [
        "california_drop_human_status_v2",
        "portal_status_is_not_direct_record_level_deletion_proof",
        "ordinary_processing_days: 90",
        "broker_access_cycle_days: 45",
        "status_authority: \"human_observed_portal_claim_only\"",
    ]:
        if required not in drop_contract:
            fail(errors, f"DROP contract invariant missing: {required}")
    for required in [
        "opt_out_sale_or_sharing_preference",
        "not_a_deletion_request_or_deletion_proof",
        "needs_evidence_per_site",
        "browser_configuration_performed_by_rightout: false",
        "provider_writes: 0",
    ]:
        if required not in preference_contract:
            fail(errors, f"GPC contract invariant missing: {required}")
    for required in [
        "recordDropStatus",
        "drop_ordinary_processing_deadline_elapsed",
        "brokerCase.mechanism_deletion_confirmed = false",
        "brokerCase.removal_confirmation_scope = null",
    ]:
        if required not in cases_source:
            fail(errors, f"DROP state-machine invariant missing: {required}")
    if "Preference signals are not deletion requests or deletion proof." not in report_export:
        fail(errors, "report export must preserve the GPC non-deletion boundary")
    for required in [
        "globalThis.fetch", 'url.protocol !== "http:"', 'redirect: "error"',
        "AbortController", "128_000", 'url.searchParams.set("deep", "true")',
    ]:
        if required not in index:
            fail(errors, f"loopback browser-doctor probe invariant missing: {required}")
    if "openKeyedStore" in index or "openSyncKeyedStore" in index or "resolveStateDir(process.env)" not in index:
        fail(errors, "community plugin must use the public state-directory resolver, not bundled-only keyed stores")
    live_scan = (ROOT / "lib/live-scan.mjs").read_text(encoding="utf-8")
    for required in [
        'const BRAVE_TERMS_VERSION = "2026-02-11"',
        'const BRAVE_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"',
        "braveCustomerResponsibilitiesAccepted",
        "hasIndexCandidate",
        'to_broker_pages: []',
        'state: "indirect_exposure"',
        "publisher_requests: 0",
        "raw_search_result_storage: 0",
        "validateOperatorAttestations(validated, operatorAttestations)",
        "rightout_operator_attestation_required",
        "throwIfAborted(signal)",
    ]:
        if required not in live_scan:
            fail(errors, f"live-scan security invariant missing: {required}")
    for prohibited in ["verifyCandidate", "directPageMatches", "candidate_path_pattern", "allowedHosts: officialDomains", 'method: "GET"']:
        if prohibited in live_scan:
            fail(errors, f"publisher-fetch path must be absent: {prohibited}")
    direct_rescan = (ROOT / "lib/direct-rescan.mjs").read_text(encoding="utf-8")
    listing_tokens = (ROOT / "lib/listing-tokens.mjs").read_text(encoding="utf-8")
    for required in ["exact_encrypted_index_candidate_urls", "maxRedirects: 0", "known_listing_set_only", "full_name_plus_", "provider_writes: 0"]:
        if required not in direct_rescan:
            fail(errors, f"direct-rescan invariant missing: {required}")
    for required in ["aes-256-gcm", "setAAD", "getAuthTag", "rightout_listing_token_key_required"]:
        if required not in listing_tokens:
            fail(errors, f"listing-token encryption invariant missing: {required}")
    file_store = (ROOT / "lib/file-keyed-store.mjs").read_text(encoding="utf-8")
    for required in ["O_NOFOLLOW", "aes-256-gcm", "setAAD", "O_EXCL", "handle.sync()", "rightout_state_encryption_key_required", "rightout_state_lock_timeout"]:
        if required not in file_store:
            fail(errors, f"community file-state invariant missing: {required}")
    removal = (ROOT / "lib/removal.mjs").read_text(encoding="utf-8")
    for required in [
        'const RIGHTOUT_REMOVAL_POLICY_VERSION = "2026-07-16-global2"',
        'new Set(["delete_and_opt_out", "gdpr_erasure_objection", "uk_erasure_objection"])',
        'UK_RIGHTS_CONTRACT.template_id',
        'state: "submitted"',
        'removal_confirmed: false',
        'forms_submitted: 0',
        'captcha_bypasses: 0',
        'local_pii_storage: 0',
        '"submitted_until_later_rescan", "submitted_until_controller_response"',
        "validateRemovalOperatorAttestations",
        "subject_consent_required",
        "ALLOWED_SMTP_ENDPOINTS",
    ]:
        if required not in removal:
            fail(errors, f"removal security invariant missing: {required}")
    smtp = (ROOT / "lib/smtp.mjs").read_text(encoding="utf-8")
    for required in [
        "requireTLS: !transport.secure",
        "disableFileAccess: true",
        "disableUrlAccess: true",
        'rejectUnauthorized: true, minVersion: "TLSv1.2"',
        "connectionTimeout: 10_000",
        'addEventListener("abort"',
    ]:
        if required not in smtp:
            fail(errors, f"SMTP security invariant missing: {required}")

    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    for required in [".rightout-install.lock", "lock_acquired=1", 'rmdir "$lock_dir"', "--ignore-scripts"]:
        if required not in installer:
            fail(errors, f"installer concurrency invariant missing: {required}")

    workflow_paths = [ROOT / ".github/workflows/ci.yml", ROOT / ".github/workflows/release.yml"]
    workflows = {path: path.read_text(encoding="utf-8") for path in workflow_paths}
    workflow_validation = subprocess.run(
        ["node", "scripts/validate-workflows.mjs", *[str(path) for path in workflow_paths]],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if workflow_validation.returncode != 0:
        detail = workflow_validation.stderr.strip() or workflow_validation.stdout.strip()
        fail(errors, f"workflow structural validation failed: {detail}")
    workflow = workflows[workflow_paths[0]]
    release_workflow = workflows[workflow_paths[1]]
    if "npm audit --omit=dev --audit-level=high" not in workflow:
        fail(errors, "CI must audit production dependencies at high severity")
    action_uses = [value for text in workflows.values() for value in re.findall(r"uses:\s*([^\s#]+)", text)]
    external_uses = [value for value in action_uses if not value.startswith("./")]
    local_uses = [value for value in action_uses if value.startswith("./")]
    def valid_local_use(value: str) -> bool:
        path = ROOT / value.removeprefix("./")
        return path.is_file() or (path.is_dir() and any((path / name).is_file() for name in ("action.yml", "action.yaml")))

    if (
        not external_uses
        or any(not re.fullmatch(r"[^@\s]+@[a-f0-9]{40}", value) for value in external_uses)
        or any(not valid_local_use(value) for value in local_uses)
    ):
        fail(errors, "CI actions must be pinned to full commit SHAs")
    for invariant in [
        "needs: [test-matrix, installer, openclaw-compatibility]",
        "uses: ./.github/workflows/release.yml",
    ]:
        if invariant not in workflow:
            fail(errors, f"tag release is not gated by the full CI matrix: {invariant}")
    for invariant in [
        "workflow_call:", 'git merge-base --is-ancestor "$GITHUB_SHA" origin/main', "actions/attest@",
        "RELEASE-EVIDENCE.json", "rightout.release-evidence.v1", "npm run test:coverage",
        'verification.verified', 'gh attestation verify "$ARCHIVE"',
        "docs/release-correction-v0.8.0.md", "--json isPrerelease", "--json body",
    ]:
        if invariant not in release_workflow:
            fail(errors, f"release workflow invariant missing: {invariant}")
    if "npm run test:coverage" not in workflow:
        fail(errors, "CI coverage threshold gate is missing")
    if not (ROOT / ".github" / "dependabot.yml").is_file() or not (ROOT / ".github" / "workflows" / "codeql.yml").is_file():
        fail(errors, "Dependabot or CodeQL configuration is missing")

    with tempfile.TemporaryDirectory(prefix="rightout-pack-content-check-") as tmp:
        proc = subprocess.run(
            ["npm", "pack", "--json", "--ignore-scripts", "--pack-destination", tmp],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            fail(errors, f"npm pack content check failed: {proc.stderr.strip()}")
        else:
            result = json.loads(proc.stdout)[0]
            archive = Path(tmp) / result["filename"]
            archive_files: dict[str, bytes] = {}
            with tarfile.open(archive, "r:gz") as bundle:
                for member in bundle.getmembers():
                    if not member.isfile() or not member.name.startswith("package/"):
                        continue
                    relative = member.name.removeprefix("package/")
                    extracted = bundle.extractfile(member)
                    if extracted is not None:
                        archive_files[relative] = extracted.read()
            packed = set(archive_files)
            for required in [
                "dist/index.js", "dist/lib/live-scan.mjs", "dist/lib/direct-rescan.mjs", "dist/lib/file-keyed-store.mjs",
                "dist/lib/catalog-health.mjs", "dist/lib/market-readiness.mjs",
                "dist/lib/listing-tokens.mjs", "dist/lib/removal.mjs", "dist/lib/uk-rights.mjs", "dist/lib/form-removal.mjs",
                "dist/lib/browser-form.mjs", "dist/lib/imap.mjs", "dist/lib/verification.mjs",
                "dist/lib/cases.mjs", "dist/lib/smtp.mjs", "dist/lib/campaigns.mjs",
                "dist/lib/parity-catalog.mjs", "dist/lib/parity-email.mjs", "dist/lib/parity-autopilot.mjs", "dist/lib/provider-terms.mjs",
                "dist/lib/registry.mjs", "dist/lib/report-export.mjs", "dist/lib/parity-source-refresh.mjs", "scripts/compute-removal-bindings.mjs",
                "dist/lib/autonomy-worker.mjs", "dist/lib/recipes.mjs", "dist/lib/controller-replies.mjs",
                "dist/lib/evidence-vault.mjs", "dist/lib/custom-targets.mjs", "dist/lib/effectiveness.mjs",
                "dist/lib/team-access.mjs", "dist/lib/dashboard.mjs", "scripts/custom-target-intake.mjs",
                "dist/lib/drop.mjs", "dist/lib/preference-controls.mjs",
                "openclaw.plugin.json", "skills/data-broker-removal/SKILL.md", "LICENSE",
                "THIRD_PARTY_NOTICES.md", "SBOM.spdx.json", "npm-shrinkwrap.json",
                "CONTRIBUTING.md", "docs/README.md", "docs/authorized-canary.md",
                "docs/broker-coverage.md", "docs/catalog-provenance.json",
                "docs/market-analysis-2026-07.md", "docs/roadmap-v0.10.0.md",
                "docs/deployment-compliance.md", "docs/unbroker-parity-baseline.json", "docs/unbroker-parity-evidence.json",
                "docs/unbroker-upstream-refresh.json", "docs/scan-coverage.json", "scripts/verify-unbroker-upstream.mjs",
                "scripts/unbroker-upstream-contract.mjs", "scripts/verify-scan-coverage.mjs", "dist/lib/scan-catalog.mjs",
                "skills/data-broker-removal/references/brokers/unbroker-parity.json",
                "skills/data-broker-removal/references/brokers/provider-terms.json",
                "skills/data-broker-removal/references/brokers/recipe-pack.json",
            ]:
                if required not in packed:
                    fail(errors, f"release archive missing: {required}")
            for relative, archived_bytes in archive_files.items():
                current = ROOT / relative
                if not current.is_file() or current.read_bytes() != archived_bytes:
                    fail(errors, f"release archive content differs from current tree: {relative}")
            if any(
                path.startswith(("tests/", "node_modules/"))
                or re.fullmatch(r"docs/(?:audit|release-checklist|release-notes|parity-matrix).+", path) is not None
                or "/__pycache__/" in f"/{path}"
                or path.endswith((".pyc", ".pyo"))
                for path in packed
            ):
                fail(errors, "release archive contains tests, node_modules, or Python bytecode")
            packaged_text = "\n".join(
                data.decode("utf-8", errors="ignore")
                for path, data in archive_files.items()
                if path.endswith(".md")
            )
            for stale_claim in ["NO-GO for publication", "Current pre-publication score", "release evidence/audit pending"]:
                if stale_claim in packaged_text:
                    fail(errors, f"release archive contains stale verdict text: {stale_claim}")
            for markdown_path, markdown_bytes in archive_files.items():
                if not markdown_path.endswith(".md"):
                    continue
                markdown = markdown_bytes.decode("utf-8", errors="ignore")
                for raw_target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", markdown):
                    target = raw_target.strip().split(" ", 1)[0].strip("<>")
                    if not target or target.startswith(("#", "mailto:")) or re.match(r"^[a-z][a-z0-9+.-]*://", target, re.I):
                        continue
                    target = unquote(target.split("#", 1)[0].split("?", 1)[0])
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(markdown_path), target))
                    if resolved.startswith("../") or resolved not in packed:
                        fail(errors, f"release archive has broken relative Markdown link: {markdown_path} -> {raw_target}")

    result = {"ok": not errors, "errors": errors, "version": version, "files_scanned": len(release_files()), "parity_counts": parity_counts}
    print(json.dumps(result, indent=2, sort_keys=True))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
