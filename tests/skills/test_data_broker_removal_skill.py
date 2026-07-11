#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "data-broker-removal"
RUNNER = SKILL / "scripts" / "data_broker_removal.py"
VALIDATOR = SKILL / "scripts" / "validate_data_broker_removal.py"


def signed_receipt(data: dict, key: str) -> dict:
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {**data, "signature": hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()}


def run(args: list[str], expect: int = 0, cwd: Path = ROOT) -> dict:
    env = {**os.environ, "OPENCLAW_ALLOW_TEST_RECEIPTS": "1"}
    proc = subprocess.run(args, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != expect:
        raise AssertionError(
            f"expected {expect}, got {proc.returncode}: {' '.join(args)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    if not proc.stdout.strip():
        return {"stderr": proc.stderr}
    return json.loads(proc.stdout)


class DataBrokerRemovalSkillTest(unittest.TestCase):
    def test_validator_and_dummy_e2e(self) -> None:
        result = run([sys.executable, str(VALIDATOR), "--skill-dir", str(SKILL)])
        self.assertTrue(result["ok"], result)
        self.assertGreaterEqual(result["doctor"]["broker_count"], 8)
        self.assertIn("send_request", result["e2e_report"]["approval_gates_present"])
        self.assertEqual(result["e2e_report"]["report_version"], 2)
        self.assertIn("broker_statuses", result["e2e_report"])

    def test_skill_dir_is_accepted_before_or_after_subcommand(self) -> None:
        before = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "doctor"])
        after = run([sys.executable, str(RUNNER), "doctor", "--skill-dir", str(SKILL)])
        self.assertTrue(before["ok"])
        self.assertEqual(before["broker_count"], after["broker_count"])

    def test_real_pii_requires_gates_and_storage_marker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-real-") as tmp_raw:
            tmp = Path(tmp_raw)
            subject = {
                "subject_id": "subj_realish",
                "dummy": False,
                "consent": True,
                "consent_scope": ["audit", "plan"],
                "jurisdictions": ["EU", "DE"],
                "profile": {"name": "Realish Example", "contact_email": "realish@example.invalid"},
                "created_at": "2026-07-11T00:00:00+00:00",
            }
            subject_dir = tmp / "subjects" / subject["subject_id"]
            subject_dir.mkdir(parents=True)
            (subject_dir / "dossier.json").write_text(json.dumps(subject), encoding="utf-8")
            (subject_dir / "metadata.json").write_text(
                json.dumps({k: subject[k] for k in ["subject_id", "dummy", "consent", "consent_scope", "jurisdictions"]}),
                encoding="utf-8",
            )
            denied = run(
                [sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "plan", "--workdir", tmp_raw, "--subject-id", subject["subject_id"]],
                expect=1,
            )
            self.assertIn("requires process_real_pii", denied["stderr"])
            run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "mark-storage", "--workdir", tmp_raw, "--method", "filevault"])
            receipt_args: list[str] = []
            for gate in ["process_real_pii", "store_dossier"]:
                receipt = tmp / f"{gate}.json"
                receipt.write_text(
                    json.dumps(
                        {
                            "approval_id": f"test-{gate}",
                            "subject_id": subject["subject_id"],
                            "gate": gate,
                            "issued_by": "openclaw-approval-boundary",
                            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                            "scope": {"broker_id": "*", **({"allow_unencrypted_local": True} if gate == "store_dossier" else {})},
                            "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
                            "non_goals": ["no external writes"],
                        }
                    ),
                    encoding="utf-8",
                )
                receipt_args.extend(["--approval-receipt", str(receipt)])
            planned = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "plan",
                    "--workdir",
                    tmp_raw,
                    "--subject-id",
                    subject["subject_id"],
                    *receipt_args,
                ]
            )
            self.assertTrue(planned["ok"])
            self.assertGreaterEqual(planned["summary"]["case_count"], 1)

    def test_subject_wide_plan_rejects_broker_scoped_receipts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-scope-") as tmp_raw:
            tmp = Path(tmp_raw)
            subject = {
                "subject_id": "subj_scope",
                "dummy": False,
                "consent": True,
                "consent_scope": ["audit", "plan"],
                "jurisdictions": ["US"],
                "profile": {"name": "Scope Example", "contact_email": "scope@example.invalid"},
                "created_at": "2026-07-11T00:00:00+00:00",
            }
            subject_dir = tmp / "subjects" / subject["subject_id"]
            subject_dir.mkdir(parents=True)
            (subject_dir / "dossier.json").write_text(json.dumps(subject), encoding="utf-8")
            (subject_dir / "metadata.json").write_text(
                json.dumps({k: subject[k] for k in ["subject_id", "dummy", "consent", "consent_scope", "jurisdictions"]}),
                encoding="utf-8",
            )
            receipt_args: list[str] = []
            for gate in ["process_real_pii", "store_dossier"]:
                receipt = tmp / f"scoped_{gate}.json"
                receipt.write_text(
                    json.dumps(
                        {
                            "approval_id": f"test-scoped-{gate}",
                            "subject_id": subject["subject_id"],
                            "gate": gate,
                            "issued_by": "openclaw-approval-boundary",
                            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                            "scope": {"broker_id": "spokeo", **({"allow_unencrypted_local": True} if gate == "store_dossier" else {})},
                            "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
                            "non_goals": ["no external writes"],
                        }
                    ),
                    encoding="utf-8",
                )
                receipt_args.extend(["--approval-receipt", str(receipt)])
            denied = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "plan",
                    "--workdir",
                    tmp_raw,
                    "--subject-id",
                    subject["subject_id"],
                    *receipt_args,
                ],
                expect=1,
            )
            self.assertIn("requires process_real_pii", denied["stderr"])

    def test_storage_marker_rejects_manual_approval_as_encryption(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-storage-") as tmp:
            denied = run(
                [sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "mark-storage", "--workdir", tmp, "--method", "manual-approved"],
                expect=1,
            )
            self.assertIn("storage method must be", denied["stderr"])

    def test_live_intake_requires_process_and_store_gates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-intake-live-") as tmp_raw:
            tmp = Path(tmp_raw)
            subject = {
                "subject_id": "subj_live_intake",
                "dummy": False,
                "consent": True,
                "consent_scope": ["audit", "plan"],
                "jurisdictions": ["US"],
                "profile": {"name": "Live Intake", "contact_email": "live.intake@example.invalid"},
                "created_at": "2026-07-11T00:00:00+00:00",
            }
            source = tmp / "subject.json"
            source.write_text(json.dumps(subject), encoding="utf-8")
            denied = run(
                [sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "intake-subject", "--workdir", tmp_raw, "--subject-file", str(source)],
                expect=1,
            )
            self.assertIn("real PII intake requires approval gate", denied["stderr"])
            receipt_args: list[str] = []
            for gate in ["process_real_pii", "store_dossier"]:
                receipt = tmp / f"intake_{gate}.json"
                receipt.write_text(
                    json.dumps(
                        {
                            "approval_id": f"test-intake-{gate}",
                            "subject_id": subject["subject_id"],
                            "gate": gate,
                            "issued_by": "openclaw-approval-boundary",
                            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                            "scope": {"broker_id": "*", **({"allow_unencrypted_local": True} if gate == "store_dossier" else {})},
                            "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
                            "non_goals": ["no external writes"],
                        }
                    ),
                    encoding="utf-8",
                )
                receipt_args.extend(["--approval-receipt", str(receipt)])
            ok = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "intake-subject",
                    "--workdir",
                    tmp_raw,
                    "--subject-file",
                    str(source),
                    *receipt_args,
                ]
            )
            self.assertTrue(ok["ok"])
            self.assertTrue((tmp / "subjects" / subject["subject_id"] / "dossier.json").exists())

    def test_dummy_e2e_outputs_are_private_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-perms-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            base = Path(e2e["workdir"])
            self.assertEqual(stat.S_IMODE(base.stat().st_mode), 0o700)
            for rel in ["dossier.json", "metadata.json", "plan.json", "report.json", "audit.jsonl"]:
                self.assertEqual(stat.S_IMODE((base / rel).stat().st_mode), 0o600, rel)

    def test_scan_only_dummy_reports_locations_without_submission_actions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-scan-only-") as tmp:
            result = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "scan-only-dummy", "--workdir", tmp])
            report = result["report"]
            self.assertTrue(report["scan_only"])
            self.assertEqual(report["removal_summary"]["requests_submitted"], 0)
            self.assertGreater(report["state_counts"].get("found", 0), 0)
            self.assertTrue(report["broker_statuses"])
            self.assertTrue(all(action.get("allowed_now") is False for action in report["user_next_steps"] if action.get("gate") == "send_request"))
            blocked_actions = {"queue_human_task", "prepare_web_form", "prepare_web_form_or_email", "prepare_email", "await_approval_for_web_form"}
            self.assertFalse(blocked_actions & {action["action"] for action in report["user_next_steps"]})
            self.assertNotIn("approval_required", report["state_counts"])
            self.assertNotIn("submitted", report["state_counts"])

    def test_hibp_import_adds_redacted_risk_signals_to_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-hibp-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            subject_id = e2e["report"]["subject_id"]
            hibp = Path(tmp) / "hibp.json"
            hibp.write_text(
                json.dumps(
                    [
                        {
                            "Name": "ExampleBreach",
                            "Title": "Example Breach",
                            "Domain": "example.invalid",
                            "BreachDate": "2026-01-01",
                            "DataClasses": ["Email addresses", "Phone numbers", "Physical addresses"],
                            "IsVerified": True,
                            "IsSpamList": True,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            imported = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "import-hibp",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--hibp-json",
                    str(hibp),
                ]
            )
            self.assertEqual(imported["summary"]["breach_count"], 1)
            self.assertIn("phone_exposure", imported["summary"]["risk_counts"])
            report = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "report", "--workdir", tmp, "--subject-id", subject_id])
            self.assertEqual(report["hibp"]["breach_count"], 1)
            self.assertIn("prioritize people-search brokers", " ".join(report["hibp"]["recommendations"]))

    def test_live_hibp_import_requires_process_and_store_gates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-hibp-live-") as tmp_raw:
            tmp = Path(tmp_raw)
            subject = {
                "subject_id": "subj_hibp_live",
                "dummy": False,
                "consent": True,
                "consent_scope": ["audit", "plan", "breach_intelligence"],
                "jurisdictions": ["US"],
                "profile": {"name": "Hibp Live", "contact_email": "hibp.live@example.invalid"},
                "created_at": "2026-07-11T00:00:00+00:00",
            }
            subject_dir = tmp / "subjects" / subject["subject_id"]
            subject_dir.mkdir(parents=True)
            (subject_dir / "dossier.json").write_text(json.dumps(subject), encoding="utf-8")
            (subject_dir / "metadata.json").write_text(
                json.dumps({k: subject[k] for k in ["subject_id", "dummy", "consent", "consent_scope", "jurisdictions"]}),
                encoding="utf-8",
            )
            hibp = tmp / "hibp.json"
            hibp.write_text(json.dumps([{"Name": "ExampleBreach", "DataClasses": ["Email addresses"]}]), encoding="utf-8")
            denied = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "import-hibp",
                    "--workdir",
                    tmp_raw,
                    "--subject-id",
                    subject["subject_id"],
                    "--hibp-json",
                    str(hibp),
                ],
                expect=1,
            )
            self.assertIn("HIBP import requires approval gate", denied["stderr"])

    def test_live_hibp_import_requires_breach_intelligence_scope(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-hibp-scope-") as tmp_raw:
            tmp = Path(tmp_raw)
            subject = {
                "subject_id": "subj_hibp_scope",
                "dummy": False,
                "consent": True,
                "consent_scope": ["audit", "plan"],
                "jurisdictions": ["US"],
                "profile": {"name": "Hibp Scope", "contact_email": "hibp.scope@example.invalid"},
                "created_at": "2026-07-11T00:00:00+00:00",
            }
            subject_dir = tmp / "subjects" / subject["subject_id"]
            subject_dir.mkdir(parents=True)
            (subject_dir / "dossier.json").write_text(json.dumps(subject), encoding="utf-8")
            (subject_dir / "metadata.json").write_text(
                json.dumps({k: subject[k] for k in ["subject_id", "dummy", "consent", "consent_scope", "jurisdictions"]}),
                encoding="utf-8",
            )
            hibp = tmp / "hibp.json"
            hibp.write_text(json.dumps([{"Name": "ExampleBreach", "DataClasses": ["Email addresses"]}]), encoding="utf-8")
            denied = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "import-hibp",
                    "--workdir",
                    tmp_raw,
                    "--subject-id",
                    subject["subject_id"],
                    "--hibp-json",
                    str(hibp),
                ],
                expect=1,
            )
            self.assertIn("breach_intelligence", denied["stderr"])

    def test_hibp_import_rejects_unbounded_or_malformed_exports(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-hibp-bad-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            subject_id = e2e["report"]["subject_id"]
            bad_class = Path(tmp) / "bad-class.json"
            bad_class.write_text(json.dumps([{"Name": "ExampleBreach", "DataClasses": ["Password: hunter2"]}]), encoding="utf-8")
            denied_class = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "import-hibp",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--hibp-json",
                    str(bad_class),
                ],
                expect=1,
            )
            self.assertIn("potential raw PII", denied_class["stderr"])
            too_many = Path(tmp) / "too-many.json"
            too_many.write_text(json.dumps([{"Name": f"Breach{i}", "DataClasses": ["Email addresses"]} for i in range(251)]), encoding="utf-8")
            denied_many = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "import-hibp",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--hibp-json",
                    str(too_many),
                ],
                expect=1,
            )
            self.assertIn("too many entries", denied_many["stderr"])

    def test_gdpr_template_requires_verified_controller_scope(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-gdpr-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            subject_id = e2e["report"]["subject_id"]
            denied = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "render-email",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--broker-id",
                    "radaris",
                    "--listing-url",
                    "https://example.invalid/relative-listing",
                    "--kind",
                    "gdpr_erasure",
                ],
                expect=1,
            )
            self.assertIn("controller_url", denied["stderr"])

    def test_live_render_requires_process_gate_and_encrypted_storage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-render-live-") as tmp_raw:
            tmp = Path(tmp_raw)
            subject = {
                "subject_id": "subj_live_render",
                "dummy": False,
                "consent": True,
                "consent_scope": ["audit", "plan", "live_scan", "send_request"],
                "jurisdictions": ["US"],
                "profile": {"name": "Live Render", "state": "NY", "contact_email": "live.render@example.invalid"},
                "created_at": "2026-07-11T00:00:00+00:00",
            }
            subject_dir = tmp / "subjects" / subject["subject_id"]
            subject_dir.mkdir(parents=True)
            (subject_dir / "dossier.json").write_text(json.dumps(subject), encoding="utf-8")
            (subject_dir / "metadata.json").write_text(
                json.dumps({k: subject[k] for k in ["subject_id", "dummy", "consent", "consent_scope", "jurisdictions"]}),
                encoding="utf-8",
            )
            run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "mark-storage", "--workdir", tmp_raw, "--method", "filevault"])
            receipt_args: list[str] = []
            for gate in ["process_real_pii", "store_dossier"]:
                receipt = tmp / f"{gate}.json"
                receipt.write_text(
                    json.dumps(
                        {
                            "approval_id": f"test-{gate}",
                            "subject_id": subject["subject_id"],
                            "gate": gate,
                            "issued_by": "openclaw-approval-boundary",
                            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                            "scope": {"broker_id": "*", **({"allow_unencrypted_local": True} if gate == "store_dossier" else {})},
                            "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
                            "non_goals": ["no external writes"],
                        }
                    ),
                    encoding="utf-8",
                )
                receipt_args.extend(["--approval-receipt", str(receipt)])
            run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "plan",
                    "--workdir",
                    tmp_raw,
                    "--subject-id",
                    subject["subject_id"],
                    *receipt_args,
                ]
            )
            run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "record",
                    "--workdir",
                    tmp_raw,
                    "--subject-id",
                    subject["subject_id"],
                    "--broker-id",
                    "spokeo",
                    "--state",
                    "found",
                    "--note",
                    "listing found",
                    "--evidence",
                    '{"listing_urls":["https://example.invalid/live-listing"]}',
                    "--approval-receipt",
                    str(tmp / "process_real_pii.json"),
                    "--approval-receipt",
                    str(tmp / "store_dossier.json"),
                ],
                expect=1,
            )
            live_scan_receipt = tmp / "live_scan.json"
            live_scan_receipt.write_text(
                json.dumps(
                    {
                        "approval_id": "test-live-scan",
                        "subject_id": subject["subject_id"],
                        "gate": "live_scan",
                        "issued_by": "openclaw-approval-boundary",
                        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                        "scope": {"broker_id": "spokeo"},
                        "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
                        "non_goals": ["no external writes"],
                    }
                ),
                encoding="utf-8",
            )
            run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "record",
                    "--workdir",
                    tmp_raw,
                    "--subject-id",
                    subject["subject_id"],
                    "--broker-id",
                    "spokeo",
                    "--state",
                    "found",
                    "--note",
                    "listing found",
                    "--evidence",
                    '{"listing_urls":["https://example.invalid/live-listing"]}',
                    "--approval-receipt",
                    str(live_scan_receipt),
                    "--approval-receipt",
                    str(tmp / "process_real_pii.json"),
                ]
            )
            send_receipt = tmp / "send_request.json"
            send_receipt.write_text(
                json.dumps(
                    {
                        "approval_id": "test-send",
                        "subject_id": subject["subject_id"],
                        "gate": "send_request",
                        "issued_by": "openclaw-approval-boundary",
                        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                        "scope": {"broker_id": "spokeo"},
                        "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
                        "non_goals": ["no provider writes"],
                    }
                ),
                encoding="utf-8",
            )
            denied = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "render-email",
                    "--workdir",
                    tmp_raw,
                    "--subject-id",
                    subject["subject_id"],
                    "--broker-id",
                    "spokeo",
                    "--listing-url",
                    "https://example.invalid/live-listing",
                    "--approval-receipt",
                    str(send_receipt),
                    "--approval-receipt",
                    str(tmp / "store_dossier.json"),
                ],
                expect=1,
            )
            self.assertIn("process_real_pii", denied["stderr"])
            (tmp / ".data-broker-removal-storage.json").unlink()
            store_no_allow = tmp / "store_dossier_no_allow.json"
            store_no_allow.write_text(
                json.dumps(
                    {
                        "approval_id": "test-store-no-allow",
                        "subject_id": subject["subject_id"],
                        "gate": "store_dossier",
                        "issued_by": "openclaw-approval-boundary",
                        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                        "scope": {"broker_id": "*"},
                        "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
                        "non_goals": ["no provider writes"],
                    }
                ),
                encoding="utf-8",
            )
            denied_storage = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "render-email",
                    "--workdir",
                    tmp_raw,
                    "--subject-id",
                    subject["subject_id"],
                    "--broker-id",
                    "spokeo",
                    "--listing-url",
                    "https://example.invalid/live-listing",
                    "--approval-receipt",
                    str(send_receipt),
                    "--approval-receipt",
                    str(store_no_allow),
                    "--approval-receipt",
                    str(tmp / "process_real_pii.json"),
                ],
                expect=1,
            )
            self.assertIn("encrypted storage marker", denied_storage["stderr"])

    def test_live_receipts_must_be_openclaw_issued(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-receipt-") as tmp_raw:
            tmp = Path(tmp_raw)
            subject = {
                "subject_id": "subj_receipt",
                "dummy": False,
                "consent": True,
                "consent_scope": ["audit", "plan"],
                "jurisdictions": ["US"],
                "profile": {"name": "Receipt Test", "contact_email": "receipt@example.invalid"},
                "created_at": "2026-07-11T00:00:00+00:00",
            }
            subject_dir = tmp / "subjects" / subject["subject_id"]
            subject_dir.mkdir(parents=True)
            (subject_dir / "dossier.json").write_text(json.dumps(subject), encoding="utf-8")
            (subject_dir / "metadata.json").write_text(
                json.dumps({k: subject[k] for k in ["subject_id", "dummy", "consent", "consent_scope", "jurisdictions"]}),
                encoding="utf-8",
            )
            run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "mark-storage", "--workdir", tmp_raw, "--method", "filevault"])
            receipt = tmp / "bad_receipt.json"
            receipt.write_text(
                json.dumps(
                    {
                        "approval_id": "test-bad",
                        "subject_id": subject["subject_id"],
                        "gate": "process_real_pii",
                        "issued_by": "local-json",
                        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                        "scope": {"broker_id": "*"},
                        "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
                        "non_goals": ["no external writes"],
                    }
                ),
                encoding="utf-8",
            )
            denied = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "plan",
                    "--workdir",
                    tmp_raw,
                    "--subject-id",
                    subject["subject_id"],
                    "--approval-receipt",
                    str(receipt),
                ],
                expect=1,
            )
            self.assertIn("issued_by openclaw-approval-boundary", denied["stderr"])

    def test_live_receipts_require_signature_outside_test_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-receipt-signature-") as tmp_raw:
            tmp = Path(tmp_raw)
            subject = {
                "subject_id": "subj_unsigned",
                "dummy": False,
                "consent": True,
                "consent_scope": ["audit", "plan"],
                "jurisdictions": ["US"],
                "profile": {"name": "Unsigned Receipt", "contact_email": "unsigned@example.invalid"},
                "created_at": "2026-07-11T00:00:00+00:00",
            }
            subject_dir = tmp / "subjects" / subject["subject_id"]
            subject_dir.mkdir(parents=True)
            (subject_dir / "dossier.json").write_text(json.dumps(subject), encoding="utf-8")
            (subject_dir / "metadata.json").write_text(
                json.dumps({k: subject[k] for k in ["subject_id", "dummy", "consent", "consent_scope", "jurisdictions"]}),
                encoding="utf-8",
            )
            receipt = tmp / "unsigned.json"
            receipt.write_text(
                json.dumps(
                    {
                        "approval_id": "unsigned",
                        "subject_id": "subj_unsigned",
                        "gate": "process_real_pii",
                        "issued_by": "openclaw-approval-boundary",
                        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                        "scope": {"broker_id": "*"},
                        "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
                        "non_goals": ["no external writes"],
                    }
                ),
                encoding="utf-8",
            )
            env = {k: v for k, v in os.environ.items() if k not in {"OPENCLAW_ALLOW_TEST_RECEIPTS", "OPENCLAW_APPROVAL_RECEIPT_KEY"}}
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "plan",
                    "--workdir",
                    tmp_raw,
                    "--subject-id",
                    "subj_unsigned",
                    "--approval-receipt",
                    str(receipt),
                ],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("OPENCLAW_APPROVAL_RECEIPT_KEY", proc.stderr)

    def test_signed_live_receipts_work_outside_test_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-signed-receipt-") as tmp_raw:
            tmp = Path(tmp_raw)
            key = "unit-test-approval-key"
            subject = {
                "subject_id": "subj_signed",
                "dummy": False,
                "consent": True,
                "consent_scope": ["audit", "plan"],
                "jurisdictions": ["US"],
                "profile": {"name": "Signed Receipt", "contact_email": "signed@example.invalid"},
                "created_at": "2026-07-11T00:00:00+00:00",
            }
            subject_dir = tmp / "subjects" / subject["subject_id"]
            subject_dir.mkdir(parents=True)
            (subject_dir / "dossier.json").write_text(json.dumps(subject), encoding="utf-8")
            (subject_dir / "metadata.json").write_text(
                json.dumps({k: subject[k] for k in ["subject_id", "dummy", "consent", "consent_scope", "jurisdictions"]}),
                encoding="utf-8",
            )
            receipt_args: list[str] = []
            for gate in ["process_real_pii", "store_dossier"]:
                receipt = tmp / f"signed_{gate}.json"
                body = {
                    "approval_id": f"signed-{gate}",
                    "subject_id": subject["subject_id"],
                    "gate": gate,
                    "issued_by": "openclaw-approval-boundary",
                    "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "scope": {"broker_id": "*", **({"allow_unencrypted_local": True} if gate == "store_dossier" else {})},
                    "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
                    "non_goals": ["no external writes"],
                }
                receipt.write_text(json.dumps(signed_receipt(body, key)), encoding="utf-8")
                receipt_args.extend(["--approval-receipt", str(receipt)])
            env = {k: v for k, v in os.environ.items() if k != "OPENCLAW_ALLOW_TEST_RECEIPTS"}
            env["OPENCLAW_APPROVAL_RECEIPT_KEY"] = key
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "plan",
                    "--workdir",
                    tmp_raw,
                    "--subject-id",
                    subject["subject_id"],
                    *receipt_args,
                ],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(json.loads(proc.stdout)["ok"])

    def test_submitted_requires_confirmation_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-submit-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            subject_id = e2e["report"]["subject_id"]
            denied = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "record",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--broker-id",
                    "spokeo",
                    "--state",
                    "submitted",
                    "--note",
                    "request submitted",
                    "--disclosed",
                    "email",
                ],
                expect=1,
            )
            self.assertIn("confirmation_status", denied["stderr"])

    def test_submitted_success_records_confirmation_and_recheck(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-submit-ok-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            subject_id = e2e["report"]["subject_id"]
            ok = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "record",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--broker-id",
                    "spokeo",
                    "--state",
                    "submitted",
                    "--note",
                    "request submitted",
                    "--disclosed",
                    "email",
                    "--evidence",
                    '{"source_url":"https://www.spokeo.com/optout","confirmation_status":"submitted","redacted_proof":"dummy-confirmation"}',
                ]
            )
            self.assertTrue(ok["ok"])
            case = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "show",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--broker-id",
                    "spokeo",
                ]
            )
            self.assertEqual(case["state"], "submitted")
            self.assertIsNotNone(case["next_recheck_at"])

    def test_submitted_rejects_non_official_source_url(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-submit-bad-url-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            subject_id = e2e["report"]["subject_id"]
            denied = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "record",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--broker-id",
                    "spokeo",
                    "--state",
                    "submitted",
                    "--note",
                    "request submitted",
                    "--disclosed",
                    "email",
                    "--evidence",
                    '{"source_url":"https://evil.invalid/not-official","confirmation_status":"submitted","redacted_proof":"dummy-confirmation"}',
                ],
                expect=1,
            )
            self.assertIn("official broker/controller domain", denied["stderr"])
            denied_self_authorized = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "record",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--broker-id",
                    "spokeo",
                    "--state",
                    "submitted",
                    "--note",
                    "request submitted",
                    "--disclosed",
                    "email",
                    "--evidence",
                    '{"source_url":"https://evil.invalid/not-official","confirmation_status":"submitted","redacted_proof":"dummy-confirmation","allowed_domains":["evil.invalid"]}',
                ],
                expect=1,
            )
            self.assertIn("official broker/controller domain", denied_self_authorized["stderr"])
            denied_channel_only = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "record",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--broker-id",
                    "spokeo",
                    "--state",
                    "submitted",
                    "--note",
                    "request submitted",
                    "--disclosed",
                    "email",
                    "--evidence",
                    '{"official_channel":"official_email","confirmation_status":"submitted","redacted_proof":"dummy-confirmation"}',
                ],
                expect=1,
            )
            self.assertIn("source_url evidence", denied_channel_only["stderr"])

    def test_human_only_cases_require_human_completed_for_submitted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-human-only-submit-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            subject_id = e2e["report"]["subject_id"]
            denied = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "record",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--broker-id",
                    "california_drop",
                    "--state",
                    "submitted",
                    "--note",
                    "request submitted",
                    "--disclosed",
                    "name",
                    "--disclosed",
                    "state",
                    "--disclosed",
                    "contact_email",
                    "--evidence",
                    '{"source_url":"https://privacy.ca.gov/drop/","confirmation_status":"submitted","redacted_proof":"dummy-confirmation"}',
                ],
                expect=1,
            )
            self.assertIn("human_completed", denied["stderr"])
            ok = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "record",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--broker-id",
                    "california_drop",
                    "--state",
                    "submitted",
                    "--note",
                    "request submitted",
                    "--disclosed",
                    "name",
                    "--disclosed",
                    "state",
                    "--disclosed",
                    "contact_email",
                    "--evidence",
                    '{"source_url":"https://privacy.ca.gov/drop/","confirmation_status":"submitted","redacted_proof":"dummy-confirmation","human_completed":true}',
                ]
            )
            self.assertTrue(ok["ok"])

    def test_next_actions_marks_human_only_cases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-human-actions-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            subject_id = e2e["report"]["subject_id"]
            nxt = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "next", "--workdir", tmp, "--subject-id", subject_id])
            california = [a for a in nxt["actions"] if a["case"] == "california_drop"][0]
            self.assertTrue(california["human_only"])
            self.assertEqual(california["action"], "await_human_completion_for_registry")

    def test_gdpr_controller_lane_requires_verified_controller_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-gdpr-controller-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            subject_id = e2e["report"]["subject_id"]
            run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "record",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--broker-id",
                    "eu_gdpr_controller_erasure",
                    "--state",
                    "action_selected",
                    "--note",
                    "controller rights lane selected",
                    "--evidence",
                    '{"listing_urls":["https://example.invalid/controller-listing"]}',
                ]
            )
            denied = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "render-email",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--broker-id",
                    "eu_gdpr_controller_erasure",
                    "--listing-url",
                    "https://example.invalid/controller-listing",
                    "--kind",
                    "gdpr_erasure",
                ],
                expect=1,
            )
            self.assertIn("controller_url", denied["stderr"])

    def test_gdpr_controller_lane_accepts_verified_controller_domain(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dbroker-gdpr-controller-ok-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            subject_id = e2e["report"]["subject_id"]
            run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "record",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--broker-id",
                    "eu_gdpr_controller_erasure",
                    "--state",
                    "action_selected",
                    "--note",
                    "controller rights lane selected",
                    "--evidence",
                    '{"listing_urls":["https://example.invalid/controller-listing"],"controller_url":"https://privacy.example.invalid/rights","controller_verified":true,"allowed_domains":["example.invalid"]}',
                ]
            )
            draft = run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--skill-dir",
                    str(SKILL),
                    "render-email",
                    "--workdir",
                    tmp,
                    "--subject-id",
                    subject_id,
                    "--broker-id",
                    "eu_gdpr_controller_erasure",
                    "--listing-url",
                    "https://example.invalid/controller-listing",
                    "--kind",
                    "gdpr_erasure",
                ]
            )
            self.assertTrue(draft["ok"])
            body = json.loads(Path(draft["draft"]).read_text(encoding="utf-8"))
            self.assertEqual(body["to"], "https://privacy.example.invalid/rights")


if __name__ == "__main__":
    unittest.main()
