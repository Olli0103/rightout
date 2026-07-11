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
DUMMY_SUBJECT_ID = "subj_314c841b03067a74"


def run(args: list[str], expect: int = 0, cwd: Path = ROOT, env_extra: dict[str, str] | None = None) -> dict:
    env = {**os.environ, "OPENCLAW_ALLOW_TEST_RECEIPTS": "1"}
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(args, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != expect:
        raise AssertionError(
            f"expected {expect}, got {proc.returncode}: {' '.join(map(str, args))}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    if not proc.stdout.strip():
        return {"stderr": proc.stderr}
    return json.loads(proc.stdout)


def signed_receipt(data: dict, key: str) -> dict:
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {**data, "signature": hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()}


def live_subject(subject_id: str = "subj_1111111111111111", scopes: list[str] | None = None) -> dict:
    return {
        "subject_id": subject_id,
        "dummy": False,
        "consent": True,
        "consent_scope": scopes or ["audit", "plan", "breach_intelligence", "live_scan", "send_request"],
        "jurisdictions": ["US", "US-CA", "EU", "DE"],
        "profile": {"name": "Live Example", "state": "CA", "contact_email": "live.example@example.invalid"},
        "created_at": "2026-07-11T00:00:00+00:00",
    }


def write_subject(workdir: Path, subject: dict) -> None:
    subject_dir = workdir / "subjects" / subject["subject_id"]
    subject_dir.mkdir(parents=True)
    (subject_dir / "dossier.json").write_text(json.dumps(subject), encoding="utf-8")
    (subject_dir / "metadata.json").write_text(
        json.dumps({k: subject[k] for k in ["subject_id", "dummy", "consent", "consent_scope", "jurisdictions"]}),
        encoding="utf-8",
    )


class DataBrokerRemovalSkillTest(unittest.TestCase):
    def test_validator_and_dummy_e2e(self) -> None:
        result = run([sys.executable, str(VALIDATOR), "--skill-dir", str(SKILL)])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["doctor"]["broker_count"], 3)
        self.assertIn("send_request", result["e2e_report"]["approval_gates_present"])
        self.assertEqual(result["e2e_report"]["report_version"], 2)
        self.assertIn("broker_statuses", result["e2e_report"])

    def test_skill_dir_is_accepted_before_or_after_subcommand(self) -> None:
        before = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "doctor"])
        after = run([sys.executable, str(RUNNER), "doctor", "--skill-dir", str(SKILL)])
        self.assertTrue(before["ok"])
        self.assertEqual(before["broker_count"], after["broker_count"])

    def test_public_runner_disables_live_intake_even_with_receipts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-live-intake-") as tmp_raw:
            tmp = Path(tmp_raw)
            subject = live_subject()
            source = tmp / "subject.json"
            source.write_text(json.dumps(subject), encoding="utf-8")
            receipts = []
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
                            "scope": {"broker_id": "*", "allow_unencrypted_local": True},
                            "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
                            "non_goals": ["no external writes"],
                        }
                    ),
                    encoding="utf-8",
                )
                receipts.extend(["--approval-receipt", str(receipt)])
            denied = run(
                [sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "intake-subject", "--workdir", tmp_raw, "--subject-file", str(source), *receipts],
                expect=1,
            )
            self.assertIn("public community runner", denied["stderr"])

    def test_external_subject_cannot_claim_dummy_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-dummy-bypass-") as tmp_raw:
            subject = {
                "subject_id": "subj_2222222222222222",
                "dummy": True,
                "consent": True,
                "consent_scope": ["audit", "plan"],
                "jurisdictions": ["US"],
                "profile": {"name": "Fake Dummy", "contact_email": "fake@example.invalid"},
            }
            source = Path(tmp_raw) / "subject.json"
            source.write_text(json.dumps(subject), encoding="utf-8")
            denied = run(
                [sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "intake-subject", "--workdir", tmp_raw, "--subject-file", str(source)],
                expect=1,
            )
            self.assertIn("cannot declare dummy:true", denied["stderr"])

    def test_live_plan_is_disabled_even_with_signed_receipts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-live-plan-") as tmp_raw:
            tmp = Path(tmp_raw)
            key = "unit-test-approval-key"
            subject = live_subject("subj_3333333333333333")
            write_subject(tmp, subject)
            receipts = []
            for gate in ["process_real_pii", "store_dossier"]:
                body = {
                    "approval_id": f"signed-{gate}",
                    "subject_id": subject["subject_id"],
                    "gate": gate,
                    "issued_by": "openclaw-approval-boundary",
                    "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "scope": {"broker_id": "*", "allow_unencrypted_local": True},
                    "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
                    "non_goals": ["no external writes"],
                }
                receipt = tmp / f"{gate}.json"
                receipt.write_text(json.dumps(signed_receipt(body, key)), encoding="utf-8")
                receipts.extend(["--approval-receipt", str(receipt)])
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
                    *receipts,
                ],
                expect=1,
                env_extra={"OPENCLAW_APPROVAL_RECEIPT_KEY": key},
            )
            self.assertIn("public community runner", denied["stderr"])

    def test_live_hibp_import_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-hibp-live-") as tmp_raw:
            tmp = Path(tmp_raw)
            subject = live_subject("subj_4444444444444444")
            write_subject(tmp, subject)
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
            self.assertIn("public community runner", denied["stderr"])

    def test_invalid_subject_ids_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-id-") as tmp:
            denied = run(
                [sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "plan", "--workdir", tmp, "--subject-id", "../escape"],
                expect=1,
            )
            self.assertIn("invalid subject_id", denied["stderr"])

    def test_symlink_subject_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-symlink-") as tmp_raw:
            tmp = Path(tmp_raw)
            target = tmp / "outside"
            target.mkdir()
            subjects = tmp / "subjects"
            subjects.mkdir()
            (subjects / DUMMY_SUBJECT_ID).symlink_to(target, target_is_directory=True)
            denied = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "intake-dummy", "--workdir", tmp_raw], expect=1)
            self.assertIn("refusing to follow symlink", denied["stderr"])

    def test_dummy_e2e_outputs_are_private_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-perms-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            base = Path(e2e["workdir"])
            self.assertEqual(stat.S_IMODE(base.stat().st_mode), 0o700)
            for rel in ["dossier.json", "metadata.json", "plan.json", "report.json", "audit.jsonl"]:
                self.assertEqual(stat.S_IMODE((base / rel).stat().st_mode), 0o600, rel)

    def test_scan_only_dummy_reports_without_submission_actions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-scan-only-") as tmp:
            result = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "scan-only-dummy", "--workdir", tmp])
            report = result["report"]
            self.assertTrue(report["scan_only"])
            self.assertEqual(report["removal_summary"]["requests_submitted"], 0)
            self.assertGreater(report["state_counts"].get("found", 0), 0)
            self.assertNotIn("submitted", report["state_counts"])
            blocked_actions = {"queue_human_task", "prepare_web_form", "prepare_web_form_or_email", "prepare_email", "await_approval_for_web_form"}
            self.assertFalse(blocked_actions & {action["action"] for action in report["user_next_steps"]})

    def test_scan_only_plan_rejects_submission_transitions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-scan-only-submit-") as tmp:
            result = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "scan-only-dummy", "--workdir", tmp])
            subject_id = result["report"]["subject_id"]
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
                    "--evidence",
                    '{"source_url":"https://privacy.ca.gov/drop/","confirmation_status":"submitted","redacted_proof":"dummy-confirmation","human_completed":true}',
                ],
                expect=1,
            )
            self.assertIn("scan_only plans cannot advance", denied["stderr"])

    def test_hibp_import_adds_attributed_risk_signals_to_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-hibp-") as tmp:
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
            report = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "report", "--workdir", tmp, "--subject-id", subject_id])
            self.assertEqual(report["hibp"]["source_name"], "Have I Been Pwned")
            self.assertIn("haveibeenpwned.com", report["hibp"]["source_url"])
            self.assertIn("phone_exposure", report["hibp"]["risk_counts"])

    def test_hibp_import_rejects_unbounded_or_malformed_exports(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-hibp-bad-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            subject_id = e2e["report"]["subject_id"]
            bad_class = Path(tmp) / "bad-class.json"
            bad_class.write_text(json.dumps([{"Name": "ExampleBreach", "DataClasses": ["Password: hunter2"]}]), encoding="utf-8")
            denied_class = run(
                [sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "import-hibp", "--workdir", tmp, "--subject-id", subject_id, "--hibp-json", str(bad_class)],
                expect=1,
            )
            self.assertIn("potential raw PII", denied_class["stderr"])
            too_many = Path(tmp) / "too-many.json"
            too_many.write_text(json.dumps([{"Name": f"Breach{i}", "DataClasses": ["Email addresses"]} for i in range(251)]), encoding="utf-8")
            denied_many = run(
                [sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "import-hibp", "--workdir", tmp, "--subject-id", subject_id, "--hibp-json", str(too_many)],
                expect=1,
            )
            self.assertIn("too many entries", denied_many["stderr"])

    def test_human_only_cases_require_human_completed_for_submission(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-human-only-") as tmp:
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

    def test_next_actions_marks_human_only_cases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-human-actions-") as tmp:
            e2e = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "e2e-dummy", "--workdir", tmp])
            subject_id = e2e["report"]["subject_id"]
            nxt = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "next", "--workdir", tmp, "--subject-id", subject_id])
            california = [a for a in nxt["actions"] if a["case"] == "california_drop"][0]
            self.assertTrue(california["human_only"])
            self.assertEqual(california["action"], "await_human_completion_for_registry")

    def test_gdpr_controller_lane_requires_verified_controller_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-gdpr-controller-") as tmp:
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

    def test_controller_evidence_cannot_self_authorize_unrelated_domain(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightout-gdpr-self-auth-") as tmp:
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
                    "approval_required",
                    "--note",
                    "approval required",
                    "--evidence",
                    '{"gate":"send_request"}',
                ]
            )
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
                    "eu_gdpr_controller_erasure",
                    "--state",
                    "submitted",
                    "--note",
                    "request submitted",
                    "--disclosed",
                    "name",
                    "--evidence",
                    '{"source_url":"https://evil.invalid/request","controller_url":"https://evil.invalid/request","controller_verified":true,"allowed_domains":["evil.invalid"],"confirmation_status":"submitted","redacted_proof":"dummy","human_completed":true}',
                ],
                expect=1,
            )
            self.assertIn("controller_url must match verified allowed_domains", denied["stderr"])

    def test_verify_link_checks_allowed_domains(self) -> None:
        ok = run([sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "verify-link", "--url", "https://privacy.ca.gov/drop/", "--allowed-domain", "privacy.ca.gov"])
        self.assertTrue(ok["ok"])
        denied = run(
            [sys.executable, str(RUNNER), "--skill-dir", str(SKILL), "verify-link", "--url", "https://evil.invalid/drop/", "--allowed-domain", "privacy.ca.gov"],
        )
        self.assertFalse(denied["ok"])


if __name__ == "__main__":
    unittest.main()
