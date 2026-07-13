#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


def run_json(cmd: list[str], cwd: Path, expect: int = 0) -> dict:
    env = {**os.environ, "PYTHONNOUSERSITE": "1"}
    proc = subprocess.run(cmd, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != expect:
        raise SystemExit(
            f"validation command returned {proc.returncode}, expected {expect}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    if not proc.stdout.strip():
        return {"stderr": proc.stderr}
    return json.loads(proc.stdout)


def run_text(cmd: list[str], cwd: Path, expect: int = 0) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env={**os.environ, "PYTHONNOUSERSITE": "1"},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != expect:
        raise SystemExit(f"validation command returned {proc.returncode}, expected {expect}")
    return proc


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--skill-dir", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()

    skill_dir = Path(args.skill_dir).expanduser().resolve()
    runner = skill_dir / "scripts" / "data_broker_removal.py"
    doctor = run_json([sys.executable, str(runner), "--skill-dir", str(skill_dir), "doctor"], skill_dir)
    validation = run_json([sys.executable, str(runner), "--skill-dir", str(skill_dir), "validate"], skill_dir)
    help_text = run_text([sys.executable, str(runner), "--help"], skill_dir).stdout

    errors: list[str] = []
    unsafe_commands = {
        "intake-subject",
        "record",
        "render-email",
        "import-hibp",
        "mark-storage",
        "report",
        "tasks",
        "due",
        "next",
    }
    for command in unsafe_commands:
        if command in help_text:
            errors.append(f"unsafe public command is exposed: {command}")

    with tempfile.TemporaryDirectory(prefix="rightout-validation-") as tmp_raw:
        tmp = Path(tmp_raw).resolve()
        e2e_dir = tmp / "e2e"
        scan_dir = tmp / "scan-only"
        e2e = run_json([sys.executable, str(runner), "--skill-dir", str(skill_dir), "e2e-dummy", "--workdir", str(e2e_dir)], skill_dir)
        scan = run_json([sys.executable, str(runner), "--skill-dir", str(skill_dir), "scan-only-dummy", "--workdir", str(scan_dir)], skill_dir)
        blocked = run_text([sys.executable, str(runner), "intake-subject"], skill_dir, expect=2)
        if "invalid choice" not in blocked.stderr:
            errors.append("unsafe command denial is not parser-enforced")

        subject_id = e2e["report"]["subject_id"]
        artifact_dir = e2e_dir / "subjects" / subject_id
        if stat.S_IMODE(artifact_dir.stat().st_mode) != 0o700:
            errors.append("artifact directory is not mode 0700")
        for name in ["dossier.json", "metadata.json", "plan.json", "report.json", "audit.jsonl"]:
            path = artifact_dir / name
            if stat.S_IMODE(path.stat().st_mode) != 0o600:
                errors.append(f"artifact is not mode 0600: {name}")
        if list(tmp.rglob("*.tmp.*")):
            errors.append("atomic-write temporary files remain")

        outside = tmp / "outside"
        outside.mkdir()
        symlink = tmp / "symlink-workdir"
        symlink.symlink_to(outside, target_is_directory=True)
        denied = run_text(
            [sys.executable, str(runner), "--skill-dir", str(skill_dir), "scan-only-dummy", "--workdir", str(symlink)],
            skill_dir,
            expect=1,
        )
        if "symlink" not in denied.stderr:
            errors.append("symlink workdir was not rejected")

    e2e_report = e2e["report"]
    scan_report = scan["report"]
    if not doctor.get("ok") or doctor.get("capability_posture") != "normalized_unbroker_contract_surface_provider_authorization_gated":
        errors.append("doctor did not prove the split live-plugin/dummy-runner posture")
    if doctor.get("live_approval_adapter") != "native_openclaw_allow_once_or_bounded_campaign":
        errors.append("doctor did not prove the native approval boundary")
    if doctor.get("live_pii_input") != "secretref_profile_not_tool_params":
        errors.append("doctor did not prove the private-profile boundary")
    if doctor.get("removal_tool") != "rightout_submit_removal":
        errors.append("doctor did not prove the separate removal tool boundary")
    if doctor.get("direct_rescan_tool") != "rightout_direct_rescan":
        errors.append("doctor did not prove the direct-rescan boundary")
    if doctor.get("controller_outcome_tool") != "rightout_record_controller_outcome":
        errors.append("doctor did not prove the controller-outcome boundary")
    if doctor.get("submission_reconciliation_tool") != "rightout_reconcile_submission":
        errors.append("doctor did not prove the submission-reconciliation boundary")
    if not validation.get("ok") or validation.get("catalog_schema_version") != 6:
        errors.append("catalog validation failed")
    if e2e_report.get("report_version") != 4:
        errors.append("report v4 is missing")
    for section in ["scan_report", "removal_report", "user_summary", "hibp"]:
        if section not in e2e_report:
            errors.append(f"report section missing: {section}")
    if set(e2e_report["removal_report"]) < {
        "submitted",
        "awaiting_verification",
        "awaiting_processing",
        "confirmed_removed",
        "reappeared",
        "human_tasks",
        "proof_reference_policy",
    }:
        errors.append("removal report status matrix is incomplete")
    if scan_report.get("scan_only") is not True:
        errors.append("scan-only report posture missing")
    if scan_report.get("removal_summary", {}).get("requests_submitted") != 0:
        errors.append("scan-only report contains submitted requests")
    scan_sections = scan_report.get("scan_report", {})
    if not scan_sections.get("found") or not scan_sections.get("not_found") or not scan_sections.get("inconclusive"):
        errors.append("scan-only report does not exercise found/not-found/inconclusive")
    invariants = scan_sections.get("invariants", {})
    if invariants != {"network_calls": 0, "provider_writes": 0, "real_pii_processed": False, "submissions": 0}:
        errors.append("scan-only invariant matrix failed")
    if e2e_report.get("hibp", {}).get("raw_leaked_values_included") is not False:
        errors.append("HIBP section does not prove sanitized posture")

    print(
        json.dumps(
            {
                "ok": not errors,
                "errors": errors,
                "doctor": doctor,
                "validation": validation,
                "report_version": e2e_report.get("report_version"),
                "scan_only_invariants": invariants,
                "removal_state_counts": e2e_report.get("removal_summary"),
            },
            indent=2,
            sort_keys=True,
        )
    )
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
