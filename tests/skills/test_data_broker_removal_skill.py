#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import copy
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "data-broker-removal"
RUNNER = SKILL / "scripts" / "data_broker_removal.py"
VALIDATOR = SKILL / "scripts" / "validate_data_broker_removal.py"
INSTALLER = ROOT / "install.sh"
DUMMY_SUBJECT_ID = "subj_314c841b03067a74"

SPEC = importlib.util.spec_from_file_location("rightout_runner", RUNNER)
assert SPEC and SPEC.loader
rightout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rightout)


def run(args: list[str], expect: int = 0, env_extra: dict[str, str] | None = None) -> dict:
    env = {**os.environ, "PYTHONNOUSERSITE": "1"}
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(args, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != expect:
        raise AssertionError(
            f"expected {expect}, got {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    result = {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
    if proc.stdout.strip().startswith("{"):
        result.update(json.loads(proc.stdout))
    return result


def load_catalog() -> dict:
    return json.loads((SKILL / "references" / "brokers" / "core.json").read_text(encoding="utf-8"))


def fixture_case(*, human_only: bool = False, fields: list[str] | None = None) -> dict:
    return rightout.make_case(
        DUMMY_SUBJECT_ID,
        {
            "id": "dummy_fixture_unit",
            "name": "Synthetic unit fixture",
            "category": "test_fixture",
            "lane": "human_task" if human_only else "web_form",
            "approval_gate": "send_request",
            "required_fields": fields or ["name", "contact_email"],
            "official_url": "https://example.invalid/rightout-dummy-fixture",
            "human_only": human_only,
            "fixture_only": True,
        },
    )


class PublicBoundaryTests(unittest.TestCase):
    def test_validator_and_doctor_prove_split_live_plugin_boundary(self) -> None:
        result = run([sys.executable, str(VALIDATOR), "--skill-dir", str(SKILL)])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["doctor"]["capability_posture"], "minimum_unbroker_workflow_parity_with_separate_native_approvals")
        self.assertEqual(result["doctor"]["live_approval_adapter"], "native_openclaw_plugin_permission_allow_once")
        self.assertEqual(result["doctor"]["live_pii_input"], "secretref_profile_not_tool_params")
        self.assertEqual(result["doctor"]["removal_tool"], "rightout_submit_removal")
        self.assertEqual(result["doctor"]["direct_rescan_tool"], "rightout_direct_rescan")

    def test_public_command_surface_excludes_live_and_mutating_commands(self) -> None:
        help_result = run([sys.executable, str(RUNNER), "--help"])
        unsafe = {"intake-subject", "record", "render-email", "import-hibp", "mark-storage", "report", "tasks", "due", "next"}
        for command in unsafe:
            self.assertNotIn(command, help_result["stdout"])
        self.assertIn("scan-only-dummy", help_result["stdout"])

    def test_dead_live_command_handlers_are_absent(self) -> None:
        text = RUNNER.read_text(encoding="utf-8")
        for name in ["cmd_intake_subject", "cmd_record", "cmd_render_email", "cmd_import_hibp", "cmd_mark_storage"]:
            self.assertNotIn(f"def {name}(", text)

    def test_environment_flag_cannot_enable_live_command(self) -> None:
        denied = run(
            [sys.executable, str(RUNNER), "intake-subject"],
            expect=2,
            env_extra={"RIGHTOUT_ENABLE_UNSAFE_LOCAL_LIVE": "1", "OPENCLAW_APPROVAL_RECEIPT_KEY": "dummy-not-a-secret"},
        )
        self.assertIn("invalid choice", denied["stderr"])

    def test_runner_contains_no_receipt_or_hmac_security_boundary(self) -> None:
        text = RUNNER.read_text(encoding="utf-8")
        tree = ast.parse(text)
        imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertNotIn("hmac", imports)
        self.assertNotIn("OPENCLAW_APPROVAL_RECEIPT_KEY", text)
        self.assertNotIn("RIGHTOUT_ENABLE_UNSAFE_LOCAL_LIVE", text)
        self.assertNotIn("--approval-receipt", text)

    def test_internal_real_subject_persistence_is_hard_disabled(self) -> None:
        subject = rightout.dummy_subject()
        subject["dummy"] = False
        with tempfile.TemporaryDirectory(prefix="rightout-boundary-") as tmp, self.assertRaises(SystemExit) as error:
            rightout.save_subject(Path(tmp).resolve(), subject)
        self.assertIn("Python runner has no live capability", str(error.exception))

    def test_non_fixture_catalog_transition_is_hard_disabled(self) -> None:
        case = rightout.make_case(DUMMY_SUBJECT_ID, load_catalog()["brokers"][0])
        with self.assertRaises(SystemExit) as error:
            rightout.transition(case, "searching", "synthetic check")
        self.assertIn("Python runner has no live capability", str(error.exception))

    def test_live_capability_functions_are_not_public_commands(self) -> None:
        doctor = run([sys.executable, str(RUNNER), "doctor"])
        self.assertEqual(set(doctor["public_commands"]), rightout.PUBLIC_COMMANDS)


class FilesystemSecurityTests(unittest.TestCase):
    def test_invalid_subject_ids_are_rejected(self) -> None:
        for value in ["../escape", "subj_name", "subj_123", "SUBJ_1111111111111111", "subj_1111111111111111/extra"]:
            with self.subTest(value=value), self.assertRaises(SystemExit):
                rightout.validate_subject_id(value)

    def test_invalid_broker_ids_are_rejected(self) -> None:
        for value in ["../escape", "UPPER", "a", "space value", "slash/value"]:
            with self.subTest(value=value), self.assertRaises(SystemExit):
                rightout.validate_broker_id(value)

    def test_symlink_workdir_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-symlink-") as tmp_raw:
            tmp = Path(tmp_raw).resolve()
            outside = tmp / "outside"
            outside.mkdir()
            link = tmp / "workdir"
            link.symlink_to(outside, target_is_directory=True)
            denied = run([sys.executable, str(RUNNER), "scan-only-dummy", "--workdir", str(link)], expect=1)
            self.assertIn("symlink", denied["stderr"])

    def test_symlink_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-artifact-link-") as tmp_raw:
            tmp = Path(tmp_raw).resolve()
            base = tmp / "subjects" / DUMMY_SUBJECT_ID
            base.mkdir(parents=True)
            outside = tmp / "outside.json"
            outside.write_text("unchanged", encoding="utf-8")
            (base / "report.json").symlink_to(outside)
            with self.assertRaises(SystemExit):
                rightout.write_json(base / "report.json", {"ok": True})
            self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged")

    def test_dummy_outputs_are_private_and_atomic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-private-") as tmp_raw:
            tmp = Path(tmp_raw).resolve()
            result = run([sys.executable, str(RUNNER), "e2e-dummy", "--workdir", str(tmp)])
            base = tmp / "subjects" / result["report"]["subject_id"]
            self.assertEqual(stat.S_IMODE(base.stat().st_mode), 0o700)
            for name in ["dossier.json", "metadata.json", "plan.json", "report.json", "audit.jsonl"]:
                self.assertEqual(stat.S_IMODE((base / name).stat().st_mode), 0o600)
            self.assertFalse(list(tmp.rglob("*.tmp.*")))

    def test_plan_revision_conflict_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-revision-") as tmp_raw:
            tmp = Path(tmp_raw).resolve()
            subject = rightout.dummy_subject()
            rightout.save_subject(tmp, subject)
            plan = rightout.plan_for_subject(SKILL, subject)
            rightout.save_plan(tmp, plan, event="created")
            stale = copy.deepcopy(plan)
            rightout.save_plan(tmp, plan, event="updated", expected_revision=1)
            with self.assertRaises(SystemExit) as error:
                rightout.save_plan(tmp, stale, event="stale", expected_revision=1)
            self.assertIn("revision conflict", str(error.exception))

    def test_cli_output_uses_opaque_relative_artifact_reference(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-ref-") as tmp:
            result = run([sys.executable, str(RUNNER), "scan-only-dummy", "--workdir", str(Path(tmp).resolve())])
            self.assertEqual(result["artifact_ref"], f"subjects/{DUMMY_SUBJECT_ID}/report.json")
            self.assertNotIn(str(Path(tmp).resolve()), result["stdout"])


class ReportingAndStateTests(unittest.TestCase):
    def test_scan_only_report_is_complete_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-scan-report-") as tmp:
            report = run([sys.executable, str(RUNNER), "scan-only-dummy", "--workdir", str(Path(tmp).resolve())])["report"]
        self.assertTrue(report["scan_only"])
        scan = report["scan_report"]
        self.assertTrue(scan["found"])
        self.assertTrue(scan["not_found"])
        self.assertTrue(scan["inconclusive"])
        self.assertTrue(scan["not_checked"])
        self.assertTrue(scan["coverage_gaps"])
        self.assertEqual(scan["invariants"], {"network_calls": 0, "provider_writes": 0, "real_pii_processed": False, "submissions": 0})
        self.assertEqual(report["removal_summary"]["requests_submitted"], 0)

    def test_indirect_exposure_never_enters_found_bucket(self) -> None:
        case = fixture_case()
        case["state"] = "indirect_exposure"
        report = rightout.build_scan_report({"cases": [case], "scan_only": True})
        self.assertEqual(report["found"], [])
        self.assertEqual(len(report["indirect_exposure"]), 1)
        self.assertEqual(report["indirect_exposure"][0]["state"], "indirect_exposure")
        self.assertEqual(rightout.REPORT_STAGES["indirect_exposure"], "indirect_signal")

    def test_removal_report_exercises_full_dummy_status_matrix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-removal-report-") as tmp:
            report = run([sys.executable, str(RUNNER), "e2e-dummy", "--workdir", str(Path(tmp).resolve())])["report"]
        removal = report["removal_report"]
        for key in ["submitted", "awaiting_verification", "awaiting_processing", "confirmed_removed", "reappeared", "human_tasks"]:
            self.assertTrue(removal[key], key)
            self.assertTrue(all(item["fixture_only"] for item in removal[key]))

    def test_report_distinguishes_catalog_coverage_from_fixtures(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-coverage-") as tmp:
            report = run([sys.executable, str(RUNNER), "scan-only-dummy", "--workdir", str(Path(tmp).resolve())])["report"]
        self.assertEqual(report["coverage"]["catalog_case_count"], len(load_catalog()["brokers"]))
        self.assertEqual(report["coverage"]["fixture_case_count"], 3)
        self.assertTrue(all(not item["fixture_only"] for item in report["scan_report"]["not_checked"]))

    def test_proof_references_are_opaque(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-proof-") as tmp:
            report = run([sys.executable, str(RUNNER), "e2e-dummy", "--workdir", str(Path(tmp).resolve())])["report"]
        refs = [ref for bucket in report["removal_report"].values() if isinstance(bucket, list) for item in bucket for ref in item["proof_references"]]
        self.assertTrue(refs)
        self.assertTrue(all(re.fullmatch(r"dummy-proof-[a-z0-9-]+", ref) for ref in refs))
        self.assertNotIn("listing", " ".join(refs))

    def test_hibp_metadata_is_sanitized_and_attributed(self) -> None:
        items = rightout.normalize_hibp_items(
            [{"Name": "SyntheticBreach", "Domain": "example.invalid", "BreachDate": "2026-01-01", "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True}]
        )
        summary = rightout.summarize_hibp(items)
        self.assertIn("credential_exposure", summary["risk_counts"])
        plan = rightout.add_dummy_fixture_cases(rightout.plan_for_subject(SKILL, rightout.dummy_subject()), ["submitted"])
        report = rightout.build_report(plan, {"summary": summary, "imported_at": "2026-07-11T00:00:00+00:00"})
        self.assertEqual(report["hibp"]["source_name"], "Have I Been Pwned")
        self.assertFalse(report["hibp"]["raw_leaked_values_included"])

    def test_hibp_rejects_raw_or_unknown_fields(self) -> None:
        for item in [
            {"Name": "SyntheticBreach", "DataClasses": ["Email addresses"], "Account": "synthetic@example.invalid"},
            {"Name": "SyntheticBreach", "DataClasses": ["Password: dummy-value"]},
        ]:
            with self.subTest(item=item), self.assertRaises(SystemExit):
                rightout.normalize_hibp_items([item])

    def test_invalid_state_transition_is_rejected(self) -> None:
        case = fixture_case()
        with self.assertRaises(SystemExit):
            rightout.transition(case, "submitted", "synthetic invalid jump")

    def test_sensitive_fields_require_explicit_human_only_gate(self) -> None:
        case = fixture_case(human_only=True, fields=["name", "government_id"])
        case["state"] = "approval_required"
        evidence = {
            "source_url": "https://example.invalid/rightout-dummy-fixture",
            "official_channel": "official_web_form",
            "confirmation_status": "submitted",
            "redacted_proof": "dummy-proof-sensitive",
            "human_completed": True,
            "dummy": True,
        }
        with self.assertRaises(SystemExit):
            rightout.transition(case, "submitted", "synthetic request recorded", evidence, disclosed=["name", "government_id"])
        evidence["sensitive_field_gate"] = "human_only_explicit"
        rightout.transition(case, "submitted", "synthetic request recorded", evidence, disclosed=["name", "government_id"])
        self.assertEqual(case["state"], "submitted")

    def test_dummy_paths_make_no_network_or_provider_calls(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-network-deny-") as tmp, mock.patch("socket.socket.connect", side_effect=AssertionError("network denied")):
            with contextlib.redirect_stdout(io.StringIO()):
                rightout.cmd_scan_only_dummy(argparse.Namespace(skill_dir=str(SKILL), workdir=str(Path(tmp).resolve())))
        tree = ast.parse(RUNNER.read_text(encoding="utf-8"))
        imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        imports |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
        self.assertFalse({"requests", "httpx", "smtplib", "imaplib", "urllib.request"} & imports)


class CatalogValidationTests(unittest.TestCase):
    def test_catalog_is_schema_v4_and_valid(self) -> None:
        catalog = load_catalog()
        self.assertEqual(catalog["schema_version"], 4)
        self.assertEqual(rightout.validate_catalog_data(catalog), [])

    def test_email_removal_lane_is_catalog_locked_and_minimum_disclosure(self) -> None:
        catalog = load_catalog()
        broker = next(item for item in catalog["brokers"] if item["id"] == "beenverified")
        self.assertEqual(broker["removal"]["recipient"], "privacy@beenverified.com")
        self.assertEqual(broker["removal"]["disclosure_fields"], ["full_name", "contact_email", "region", "country"])
        self.assertEqual(broker["removal"]["confirmation_policy"], "submitted_until_later_rescan")
        unsafe = load_catalog()
        next(item for item in unsafe["brokers"] if item["id"] == "beenverified")["removal"]["recipient"] = "attacker@example.invalid"
        self.assertTrue(rightout.validate_catalog_data(unsafe))

    def test_eu_processes_separate_erasure_from_browser_preference(self) -> None:
        catalog = load_catalog()
        adsquare = next(item for item in catalog["brokers"] if item["id"] == "adsquare_eu")
        edaa = next(item for item in catalog["brokers"] if item["id"] == "edaa_yoc")
        self.assertEqual(adsquare["removal"]["request_kinds"], ["gdpr_erasure_objection"])
        self.assertEqual(adsquare["removal"]["confirmation_policy"], "submitted_until_controller_response")
        self.assertEqual(edaa["eu_process"]["erasure_semantics"], "preference_only_not_controller_erasure")
        unsafe = load_catalog()
        next(item for item in unsafe["brokers"] if item["id"] == "edaa_yoc")["eu_process"]["erasure_semantics"] = "controller_erasure_request_not_yet_confirmed"
        self.assertTrue(any("process tuple" in error for error in rightout.validate_catalog_data(unsafe)))

    def test_catalog_rejects_unsafe_ids(self) -> None:
        catalog = load_catalog()
        catalog["brokers"][0]["id"] = "../unsafe"
        self.assertTrue(any("unsafe id" in error for error in rightout.validate_catalog_data(catalog)))

    def test_catalog_rejects_missing_or_stale_provenance(self) -> None:
        missing = load_catalog()
        del missing["brokers"][0]["sources"]
        self.assertTrue(rightout.validate_catalog_data(missing))
        stale = load_catalog()
        stale["brokers"][0]["last_verified"] = "2025-01-01"
        self.assertTrue(any("stale" in error for error in rightout.validate_catalog_data(stale)))

    def test_catalog_rejects_false_or_unofficial_urls(self) -> None:
        catalog = load_catalog()
        catalog["brokers"][0]["official_url"] = "https://evil.invalid/drop"
        self.assertTrue(any("official URL" in error for error in rightout.validate_catalog_data(catalog)))

    def test_catalog_rejects_inconsistent_lanes(self) -> None:
        catalog = load_catalog()
        catalog["brokers"][0]["lane"] = "web_form"
        self.assertTrue(any("registry category" in error for error in rightout.validate_catalog_data(catalog)))

    def test_catalog_rejects_direct_publisher_fetch_policy(self) -> None:
        unsafe = load_catalog()
        scan = next(item for item in unsafe["brokers"] if item["id"] == "truepeoplesearch")["scan"]
        scan["candidate_path_pattern"] = "^/.*$"
        self.assertTrue(any("live-scan policy" in error for error in rightout.validate_catalog_data(unsafe)))
        unsafe_strategy = load_catalog()
        next(item for item in unsafe_strategy["brokers"] if item["id"] == "truepeoplesearch")["scan"]["strategy"] = "brave_site_query_then_same_domain_verify"
        self.assertTrue(any("live-scan policy" in error for error in rightout.validate_catalog_data(unsafe_strategy)))
        unsafe_direct = load_catalog()
        next(item for item in unsafe_direct["brokers"] if item["id"] == "truepeoplesearch")["direct_rescan"]["publisher_terms_gate"] = "model_attestation"
        self.assertTrue(any("direct-rescan policy" in error for error in rightout.validate_catalog_data(unsafe_direct)))

    def test_published_automation_prohibition_disables_live_scan(self) -> None:
        catalog = load_catalog()
        spokeo = next(item for item in catalog["brokers"] if item["id"] == "spokeo")
        self.assertFalse(spokeo["scan"]["supported"])
        self.assertTrue(spokeo["human_only"])
        self.assertEqual(spokeo["scan"]["automated_access_policy"], "prohibited_by_published_terms")
        unsafe = load_catalog()
        next(item for item in unsafe["brokers"] if item["id"] == "spokeo")["scan"]["supported"] = True
        self.assertTrue(rightout.validate_catalog_data(unsafe))

    def test_live_broker_id_must_fit_public_tool_contract(self) -> None:
        catalog = load_catalog()
        next(item for item in catalog["brokers"] if item["id"] == "spokeo")["id"] = "people_search_broker_id_too_long"
        self.assertTrue(any("public tool contract" in error for error in rightout.validate_catalog_data(catalog)))

    def test_controller_domains_cannot_self_authorize(self) -> None:
        catalog = load_catalog()
        legal = next(item for item in catalog["brokers"] if item["category"] == "legal_request")
        legal["allowed_domains"] = ["controller.example"]
        self.assertTrue(any("self-authorize" in error for error in rightout.validate_catalog_data(catalog)))

    def test_catalog_sensitive_fields_require_human_gate(self) -> None:
        catalog = load_catalog()
        catalog["brokers"][0]["required_fields"].append("government_id")
        self.assertTrue(any("sensitive fields" in error for error in rightout.validate_catalog_data(catalog)))

    def test_catalog_has_no_third_party_list_sources(self) -> None:
        catalog = load_catalog()
        urls = [source["url"] for broker in catalog["brokers"] for source in broker["sources"]]
        self.assertFalse(any(any(domain in url for domain in ["privacyguides.org", "inteltechniques.com", "badbool.com"]) for url in urls))


class InstallerTests(unittest.TestCase):
    @staticmethod
    def isolated_env(tmp: Path) -> dict[str, str]:
        home = tmp / "home"
        state = tmp / "state"
        temp_dir = tmp / "tmp"
        home.mkdir()
        state.mkdir()
        temp_dir.mkdir()
        return {
            "HOME": str(home),
            "OPENCLAW_STATE_DIR": str(state),
            "OPENCLAW_CONFIG_PATH": str(state / "openclaw.json"),
            "OPENCLAW_BIN": str(ROOT / "node_modules" / ".bin" / "openclaw"),
            "TMPDIR": str(temp_dir),
        }

    def test_fresh_and_force_install_are_runtime_validated(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-install-") as tmp_raw:
            tmp = Path(tmp_raw).resolve()
            env = self.isolated_env(tmp)
            env.update({
                "RIGHTOUT_TEST_BRAVE_KEY": "dummy-test-key",
                "RIGHTOUT_TEST_STATE_KEY": "dummy-state-key-with-more-than-32-characters",
                "RIGHTOUT_TEST_PROFILE": json.dumps({
                    "fullName": "Avery Example",
                    "city": "Exampleville",
                    "region": "CA",
                    "country": "US",
                }),
            })
            first = run([str(INSTALLER)], env_extra=env)
            self.assertIn("plugin installed and runtime-validated", first["stdout"])
            self.assertIn("native OpenClaw allow-once/deny", first["stdout"])
            run(
                [env["OPENCLAW_BIN"], "config", "set", "plugins.entries.rightout.config.braveApiKey", "--ref-provider", "default", "--ref-source", "env", "--ref-id", "RIGHTOUT_TEST_BRAVE_KEY"],
                env_extra=env,
            )
            run(
                [env["OPENCLAW_BIN"], "config", "set", "plugins.entries.rightout.config.stateEncryptionKey", "--ref-provider", "default", "--ref-source", "env", "--ref-id", "RIGHTOUT_TEST_STATE_KEY"],
                env_extra=env,
            )
            run(
                [env["OPENCLAW_BIN"], "config", "set", "plugins.entries.rightout.config.profiles.profile_a1b2c3d4e5f60718.payload", "--ref-provider", "default", "--ref-source", "env", "--ref-id", "RIGHTOUT_TEST_PROFILE"],
                env_extra=env,
            )
            run(
                [
                    env["OPENCLAW_BIN"], "config", "set",
                    "plugins.entries.rightout.config.operatorAttestations",
                    json.dumps({
                        "braveTermsAccepted": True,
                        "braveTermsVersion": "2026-02-11",
                        "braveCustomerResponsibilitiesAccepted": True,
                        "subjectConsentReviewed": True,
                        "authorizedProfileIds": ["profile_a1b2c3d4e5f60718"],
                        "authorizedProfileDigests": {
                            "profile_a1b2c3d4e5f60718": "0" * 64,
                        },
                        "authorizedBrokerIds": ["truepeoplesearch"],
                    }),
                    "--strict-json",
                ],
                env_extra=env,
            )
            run(
                [env["OPENCLAW_BIN"], "config", "set", "gateway.tools.deny", '["rightout_live_scan","rightout_direct_rescan","rightout_submit_removal","rightout_submit_form_removal","rightout_poll_verification","rightout_open_verification","rightout_purge_subject_state"]', "--strict-json"],
                env_extra=env,
            )
            validation = run([env["OPENCLAW_BIN"], "config", "validate"], env_extra=env)
            self.assertIn("Config valid", validation["stdout"])
            audit = run([env["OPENCLAW_BIN"], "secrets", "audit", "--check"], env_extra=env)
            self.assertIn("plaintext=0", audit["stdout"])
            self.assertIn("unresolved=0", audit["stdout"])
            security = run([env["OPENCLAW_BIN"], "security", "audit", "--deep"], env_extra=env)
            self.assertNotIn("rightout.secretref", security["stdout"] + security["stderr"])
            self.assertNotIn("rightout.scan_operator_attestations", security["stdout"] + security["stderr"])
            self.assertNotIn("rightout.removal_operator_attestations", security["stdout"] + security["stderr"])
            self.assertNotIn("rightout.state_encryption_key", security["stdout"] + security["stderr"])
            self.assertNotIn("rightout.gateway.tools_invoke", security["stdout"] + security["stderr"])
            second = run([str(INSTALLER), "--force"], env_extra=env)
            self.assertIn("plugin installed and runtime-validated", second["stdout"])
            inspection = run(
                [env["OPENCLAW_BIN"], "plugins", "inspect", "rightout", "--runtime", "--json"],
                env_extra=env,
            )
            self.assertEqual(inspection["plugin"]["status"], "loaded")
            self.assertEqual(inspection["typedHooks"], [{"name": "before_tool_call"}])

    def test_failed_preflight_does_not_register_plugin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-preflight-") as tmp_raw:
            tmp = Path(tmp_raw).resolve()
            source = tmp / "bad-source"
            shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(".git", "node_modules", ".tmp", "__pycache__"))
            manifest_path = source / "openclaw.plugin.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["toolMetadata"]["rightout_live_scan"]["replaySafe"] = True
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            env = self.isolated_env(tmp)
            denied = run([str(source / "install.sh")], expect=1, env_extra=env)
            self.assertIn("validation command returned", denied["stderr"])
            self.assertFalse((tmp / "state" / "openclaw.json").exists())

    def test_post_install_runtime_failure_restores_config_and_prior_extension(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-rollback-") as tmp_raw:
            tmp = Path(tmp_raw).resolve()
            env = self.isolated_env(tmp)
            run([str(INSTALLER)], env_extra=env)
            config_path = Path(env["OPENCLAW_CONFIG_PATH"])
            config_before = config_path.read_bytes()
            extension = Path(env["OPENCLAW_STATE_DIR"]) / "extensions" / "rightout"
            marker = extension / "rollback-marker"
            marker.write_text("prior-install", encoding="utf-8")

            wrapper = tmp / "openclaw-fail-runtime-inspect"
            wrapper.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"$*\" == \"plugins inspect rightout --runtime --json\" ]]; then\n"
                "  echo injected-runtime-inspection-failure >&2\n"
                "  exit 70\n"
                "fi\n"
                "exec \"$REAL_OPENCLAW\" \"$@\"\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o700)
            failed_env = {
                **env,
                "OPENCLAW_BIN": str(wrapper),
                "REAL_OPENCLAW": str(ROOT / "node_modules" / ".bin" / "openclaw"),
            }
            failed = run([str(INSTALLER), "--force"], expect=70, env_extra=failed_env)
            self.assertIn("restoring the previous OpenClaw state", failed["stderr"])
            self.assertEqual(config_path.read_bytes(), config_before)
            self.assertEqual(marker.read_text(encoding="utf-8"), "prior-install")
            self.assertEqual(list(Path(env["TMPDIR"]).glob("rightout-install*")), [])
            inspection = run(
                [env["OPENCLAW_BIN"], "plugins", "inspect", "rightout", "--runtime", "--json"],
                env_extra=env,
            )
            self.assertEqual(inspection["plugin"]["status"], "loaded")

    def test_forged_prior_install_path_is_never_touched_during_rollback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-containment-") as tmp_raw:
            tmp = Path(tmp_raw).resolve()
            env = self.isolated_env(tmp)
            forged_extension = tmp / "outside" / "extensions" / "rightout"
            forged_extension.mkdir(parents=True)
            marker = forged_extension / "must-survive"
            marker.write_text("outside-managed-root", encoding="utf-8")
            wrapper = tmp / "openclaw-forged-prior-path"
            wrapper.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"${1:-}\" == \"--version\" ]]; then echo 'OpenClaw 2026.6.11'; exit 0; fi\n"
                "if [[ \"$*\" == \"config file\" ]]; then echo \"$OPENCLAW_CONFIG_PATH\"; exit 0; fi\n"
                "if [[ \"$*\" == \"plugins inspect rightout --json\" ]]; then\n"
                "  printf '%s\\n' \"$FORGED_INSPECTION\"\n"
                "  exit 0\n"
                "fi\n"
                "if [[ \"$*\" == \"plugins inspect rightout --runtime --json\" ]]; then\n"
                "  exit 70\n"
                "fi\n"
                "exec \"$REAL_OPENCLAW\" \"$@\"\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o700)
            failed_env = {
                **env,
                "OPENCLAW_BIN": str(wrapper),
                "REAL_OPENCLAW": str(ROOT / "node_modules" / ".bin" / "openclaw"),
                "FORGED_INSPECTION": json.dumps({"install": {"installPath": str(forged_extension)}}),
            }
            run([str(INSTALLER)], expect=70, env_extra=failed_env)
            self.assertEqual(marker.read_text(encoding="utf-8"), "outside-managed-root")
            self.assertFalse(Path(env["OPENCLAW_CONFIG_PATH"]).exists())
            self.assertFalse((Path(env["OPENCLAW_STATE_DIR"]) / "extensions" / "rightout").exists())
            self.assertEqual(list(Path(env["TMPDIR"]).glob("rightout-install*")), [])

    def test_concurrent_installer_is_denied_and_lock_is_cleaned(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-concurrent-") as tmp_raw:
            tmp = Path(tmp_raw).resolve()
            env = self.isolated_env(tmp)
            ready = tmp / "first-installer-ready"
            release = tmp / "release-first-installer"
            wrapper = tmp / "openclaw-block-first-installer"
            wrapper.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"${1:-}\" == \"--version\" ]]; then echo 'OpenClaw 2026.6.11'; exit 0; fi\n"
                "if [[ \"$*\" == \"config file\" ]]; then echo \"$OPENCLAW_CONFIG_PATH\"; exit 0; fi\n"
                "if [[ \"$*\" == \"plugins inspect rightout --json\" ]]; then\n"
                "  : > \"$FIRST_INSTALLER_READY\"\n"
                "  while [[ ! -e \"$RELEASE_FIRST_INSTALLER\" ]]; do sleep 0.05; done\n"
                "  exit 1\n"
                "fi\n"
                "if [[ \"${1:-}\" == \"plugins\" && \"${2:-}\" == \"install\" ]]; then\n"
                "  exit 77\n"
                "fi\n"
                "exit 78\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o700)
            concurrent_env = {
                **os.environ,
                **env,
                "PYTHONNOUSERSITE": "1",
                "OPENCLAW_BIN": str(wrapper),
                "FIRST_INSTALLER_READY": str(ready),
                "RELEASE_FIRST_INSTALLER": str(release),
            }
            first = subprocess.Popen(
                [str(INSTALLER)],
                cwd=ROOT,
                env=concurrent_env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            deadline = time.monotonic() + 15
            while not ready.exists() and first.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            if not ready.exists():
                release.touch()
                first.terminate()
                first_stdout, first_stderr = first.communicate(timeout=15)
                self.fail(f"first installer did not acquire the transaction lock\nstdout:\n{first_stdout}\nstderr:\n{first_stderr}")
            second = run([str(INSTALLER)], expect=1, env_extra=concurrent_env)
            self.assertIn("another RightOut installer transaction is active", second["stderr"])
            release.touch()
            first_stdout, first_stderr = first.communicate(timeout=90)
            self.assertEqual(first.returncode, 77, f"stdout:\n{first_stdout}\nstderr:\n{first_stderr}")
            self.assertFalse((Path(env["OPENCLAW_STATE_DIR"]) / ".rightout-install.lock").exists())
            self.assertFalse(Path(env["OPENCLAW_CONFIG_PATH"]).exists())
            self.assertEqual(list(Path(env["TMPDIR"]).glob("rightout-install*")), [])

    def test_source_symlink_is_rejected_before_install(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-source-link-") as tmp_raw:
            tmp = Path(tmp_raw).resolve()
            source = tmp / "linked-source"
            shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(".git", "node_modules", ".tmp", "__pycache__"))
            (source / "unsafe-link").symlink_to("README.md")
            env = self.isolated_env(tmp)
            denied = run([str(source / "install.sh")], expect=1, env_extra=env)
            self.assertIn("source package contains a symlink", denied["stderr"])
            self.assertFalse((tmp / "state" / "openclaw.json").exists())


if __name__ == "__main__":
    unittest.main()
