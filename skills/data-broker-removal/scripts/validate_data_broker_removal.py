#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import datetime as dt
from pathlib import Path


def run(cmd: list[str], cwd: Path, expect: int = 0) -> dict:
    env = {**os.environ, "OPENCLAW_ALLOW_TEST_RECEIPTS": "1"}
    proc = subprocess.run(cmd, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != expect:
        raise SystemExit(f"command returned {proc.returncode}, expected {expect}: {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    if not proc.stdout.strip():
        return {"ok": proc.returncode == 0, "stderr": proc.stderr}
    return json.loads(proc.stdout)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--skill-dir", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()

    skill_dir = Path(args.skill_dir).expanduser().resolve()
    runner = skill_dir / "scripts" / "data_broker_removal.py"
    doctor = run([sys.executable, str(runner), "--skill-dir", str(skill_dir), "doctor"], skill_dir)
    validation = run([sys.executable, str(runner), "--skill-dir", str(skill_dir), "validate"], skill_dir)
    with tempfile.TemporaryDirectory(prefix="dbroker-e2e-") as tmp:
        e2e_dir = str(Path(tmp) / "e2e")
        scan_dir = str(Path(tmp) / "scan-only")
        e2e = run([sys.executable, str(runner), "--skill-dir", str(skill_dir), "e2e-dummy", "--workdir", e2e_dir], skill_dir)
        subject_id = e2e["report"]["subject_id"]
        scan_only = run([sys.executable, str(runner), "--skill-dir", str(skill_dir), "scan-only-dummy", "--workdir", scan_dir], skill_dir)
        actions = run([sys.executable, str(runner), "--skill-dir", str(skill_dir), "next", "--workdir", e2e_dir, "--subject-id", subject_id], skill_dir)
        tasks = run([sys.executable, str(runner), "--skill-dir", str(skill_dir), "tasks", "--workdir", e2e_dir, "--subject-id", subject_id], skill_dir)
        hibp_input = Path(tmp) / "hibp.json"
        hibp_input.write_text(json.dumps([{
            "Name": "ExampleBreach",
            "Title": "Example Breach",
            "Domain": "example.invalid",
            "BreachDate": "2026-01-01",
            "DataClasses": ["Email addresses", "Phone numbers", "Physical addresses"],
            "IsVerified": True,
            "IsSpamList": True
        }]), encoding="utf-8")
        hibp = run([sys.executable, str(runner), "--skill-dir", str(skill_dir), "import-hibp", "--workdir", e2e_dir, "--subject-id", subject_id, "--hibp-json", str(hibp_input)], skill_dir)
        report2 = run([sys.executable, str(runner), "--skill-dir", str(skill_dir), "report", "--workdir", e2e_dir, "--subject-id", subject_id], skill_dir)
        link_ok = run([sys.executable, str(runner), "--skill-dir", str(skill_dir), "verify-link", "--url", "https://privacy.example.invalid/verify/token", "--allowed-domain", "example.invalid"], skill_dir)
        link_bad = run([sys.executable, str(runner), "--skill-dir", str(skill_dir), "verify-link", "--url", "http://evil.invalid/verify/token", "--allowed-domain", "example.invalid"], skill_dir)
        real = {
            "subject_id": "subj_realish",
            "dummy": False,
            "consent": True,
            "consent_scope": ["audit", "plan"],
            "jurisdictions": ["US"],
            "profile": {
                "name": "Realish Example",
                "state": "NY",
                "contact_email": "realish@example.invalid"
            },
            "created_at": "2026-07-11T00:00:00+00:00"
        }
        real_dir = Path(e2e_dir) / "subjects" / "subj_realish"
        real_dir.mkdir(parents=True)
        (real_dir / "dossier.json").write_text(json.dumps(real), encoding="utf-8")
        (real_dir / "metadata.json").write_text(json.dumps({k: real[k] for k in ["subject_id", "dummy", "consent", "consent_scope", "jurisdictions"]}), encoding="utf-8")
        gate_denied = run([sys.executable, str(runner), "--skill-dir", str(skill_dir), "plan", "--workdir", e2e_dir, "--subject-id", "subj_realish"], skill_dir, expect=1)
        storage_marker = run([sys.executable, str(runner), "--skill-dir", str(skill_dir), "mark-storage", "--workdir", e2e_dir, "--method", "filevault", "--note", "dummy validation marker"], skill_dir)
        receipts = []
        for gate in ["process_real_pii", "store_dossier"]:
            path = Path(tmp) / f"{gate}.json"
            path.write_text(json.dumps({
                "approval_id": f"test-{gate}",
                "subject_id": "subj_realish",
                "gate": gate,
                "issued_by": "openclaw-approval-boundary",
                "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "scope": {"broker_id": "*", **({"allow_unencrypted_local": True} if gate == "store_dossier" else {})},
                "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat(),
                "non_goals": ["no external writes"]
            }), encoding="utf-8")
            receipts.extend(["--approval-receipt", str(path)])
        real_planned = run([sys.executable, str(runner), "--skill-dir", str(skill_dir), "plan", "--workdir", e2e_dir, "--subject-id", "subj_realish", *receipts], skill_dir)
    report = e2e["report"]
    errors: list[str] = []
    if not doctor.get("ok"):
        errors.append("doctor failed")
    if not validation.get("ok"):
        errors.append("schema validation failed")
    if report["mode"] != "dummy":
        errors.append("dummy e2e did not run in dummy mode")
    if report.get("report_version") != 2:
        errors.append("report v2 fields missing")
    if not report.get("broker_statuses"):
        errors.append("report has no broker_statuses")
    if "removal_summary" not in report:
        errors.append("report removal_summary missing")
    if scan_only["report"].get("scan_only") is not True:
        errors.append("scan-only dummy did not produce scan_only report")
    if scan_only["report"].get("removal_summary", {}).get("requests_submitted") != 0:
        errors.append("scan-only dummy reported submitted requests")
    if not hibp.get("summary", {}).get("risk_counts"):
        errors.append("HIBP import produced no risk counts")
    if "hibp" not in report2:
        errors.append("report did not include imported HIBP summary")
    if "approval_required" not in report["state_counts"]:
        errors.append("dummy e2e did not exercise approval_required")
    if "provider_write" not in report["approval_gates_present"]:
        errors.append("provider_write gate missing")
    if "send_request" not in report["approval_gates_present"]:
        errors.append("send_request gate missing")
    if not actions.get("actions"):
        errors.append("next produced no actions")
    if not tasks.get("tasks"):
        errors.append("tasks produced no approval/human task digest")
    if report2["subject_id"] != subject_id:
        errors.append("report subject mismatch")
    if not link_ok.get("ok") or link_bad.get("ok"):
        errors.append("verification link scoping failed")
    if "requires process_real_pii" not in gate_denied.get("stderr", ""):
        errors.append("real PII planning denial did not mention required gates")
    if not storage_marker.get("ok"):
        errors.append("encrypted storage marker failed")
    if not real_planned.get("ok"):
        errors.append("real PII planning with scoped receipts failed")
    print(json.dumps({"ok": not errors, "errors": errors, "doctor": doctor, "validation": validation, "e2e_report": report, "actions_checked": len(actions.get("actions", [])), "tasks_checked": len(tasks.get("tasks", []))}, indent=2, sort_keys=True))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
