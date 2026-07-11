#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SUBJECT_ID_RE = re.compile(r"^subj_[a-f0-9]{16,64}$")
BROKER_ID_RE = re.compile(r"^[a-z0-9_]{2,80}$")
DUMMY_SUBJECT_ID = "subj_314c841b03067a74"
COMMUNITY_LIVE_DISABLED = True
ALLOWED_STATES: dict[str, set[str]] = {
    "new": {"searching", "found", "not_found", "inconclusive", "indirect_exposure", "blocked"},
    "searching": {"not_found", "found", "inconclusive", "indirect_exposure", "blocked"},
    "not_found": {"searching", "found", "inconclusive", "indirect_exposure", "blocked"},
    "inconclusive": {"searching", "action_selected", "human_task_queued", "blocked"},
    "found": {"action_selected", "approval_required", "human_task_queued", "indirect_exposure", "blocked"},
    "indirect_exposure": {"action_selected", "approval_required", "human_task_queued", "not_found", "found", "blocked"},
    "action_selected": {"approval_required", "human_task_queued", "blocked"},
    "approval_required": {"submitted", "human_task_queued", "blocked"},
    "submitted": {"verification_pending", "awaiting_processing", "human_task_queued", "blocked"},
    "verification_pending": {"awaiting_processing", "confirmed_removed", "human_task_queued", "blocked"},
    "awaiting_processing": {"confirmed_removed", "human_task_queued", "blocked"},
    "confirmed_removed": {"reappeared", "confirmed_removed"},
    "reappeared": {"found", "indirect_exposure", "action_selected"},
    "human_task_queued": {"found", "indirect_exposure", "action_selected", "submitted", "verification_pending", "awaiting_processing", "confirmed_removed", "blocked"},
    "blocked": {"searching", "found", "not_found", "inconclusive", "indirect_exposure", "action_selected", "human_task_queued"},
}

LIVE_ACTION_GATES = {"process_real_pii", "store_dossier", "live_scan", "send_request", "schedule_recheck", "provider_write"}
ENCRYPTED_STORAGE_METHODS = {"age", "filevault", "luks", "encrypted-volume"}
LANES = {"registry", "web_form", "web_form_or_email", "email", "guided_flow", "operator_browser", "human_task", "monitor_only"}
REQUEST_KINDS = {"generic", "gdpr_erasure", "uk_gdpr_erasure", "ccpa_delete", "indirect_delete_my_pii"}
SAFE_EVIDENCE_KEYS = {"kind", "dummy", "gate", "lane", "listing_urls", "matcher", "verification", "source_url", "confirmation_status", "redacted_proof"}
SAFE_EVIDENCE_KEYS |= {"official_channel", "controller_url", "controller_verified", "allowed_domains", "human_completed"}
HIBP_RISK_BY_DATA_CLASS = {
    "Email addresses": "email_exposure",
    "Passwords": "credential_exposure",
    "Password hints": "credential_exposure",
    "Usernames": "account_identity_exposure",
    "Phone numbers": "phone_exposure",
    "Physical addresses": "address_exposure",
    "Geographic locations": "location_exposure",
    "Dates of birth": "identity_proofing_risk",
    "Names": "identity_correlation",
    "IP addresses": "technical_exposure",
    "Social media profiles": "social_graph_exposure",
}
HIBP_ALLOWED_DATA_CLASSES = set(HIBP_RISK_BY_DATA_CLASS) | {
    "Account balances",
    "Bank account numbers",
    "Biometric data",
    "Credit cards",
    "Device information",
    "Education levels",
    "Employment statuses",
    "Ethnicities",
    "Genders",
    "Government issued IDs",
    "Health insurance information",
    "Historical passwords",
    "Home ownership statuses",
    "Income levels",
    "Instant messenger identities",
    "Job titles",
    "Marital statuses",
    "Partial credit card data",
    "Passport numbers",
    "Purchases",
    "Security questions and answers",
    "Sexual orientations",
    "Spoken languages",
    "Survey results",
}
HIBP_MAX_IMPORT_BYTES = 1_000_000
HIBP_MAX_ITEMS = 250
REPORT_STAGES = {
    "found": "found_exposure",
    "indirect_exposure": "found_exposure",
    "not_found": "not_found",
    "inconclusive": "needs_review",
    "approval_required": "ready_for_operator_approval",
    "submitted": "request_sent",
    "verification_pending": "waiting_for_verification",
    "awaiting_processing": "waiting_for_broker",
    "confirmed_removed": "confirmed_removed",
    "reappeared": "reappeared",
    "human_task_queued": "human_task",
    "blocked": "blocked",
    "action_selected": "ready_for_operator_approval",
    "searching": "in_progress",
    "new": "not_scanned",
}
PII_PATTERN = re.compile(
    r"(@|\b\d{3}[- .]?\d{3}[- .]?\d{4}\b|\b\d{3}-\d{2}-\d{4}\b|\b\d{5}(?:-\d{4})?\b|"
    r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b|\b\d+\s+[A-Z][A-Za-z]*(?:\s+[A-Z][A-Za-z]*)*\s+"
    r"(?:Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct)\b|"
    r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b)"
)
HIBP_DIRECT_IDENTIFIER_PATTERN = re.compile(
    r"(@|\b\d{3}[- .]?\d{3}[- .]?\d{4}\b|\b\d{3}-\d{2}-\d{4}\b|"
    r"\b\d+\s+[A-Z][A-Za-z]*(?:\s+[A-Z][A-Za-z]*)*\s+"
    r"(?:Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct)\b)"
)
HIBP_SAFE_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._&'()+:/,-]{0,119}$")
HIBP_DOMAIN_PATTERN = re.compile(r"^(unknown|[A-Za-z0-9.-]{1,253})$")
HIBP_HASH_OR_SECRET_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,}\b|password\s*[:=]", re.IGNORECASE)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    secure_dir(path.parent)
    write_text_secure(path, json.dumps(data, indent=2, sort_keys=True) + "\n")
    secure_file(path)


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    secure_dir(path.parent)
    with secure_open_text(path, append=True) as f:
        f.write(json.dumps(data, sort_keys=True) + "\n")
    secure_file(path)


def secure_open_text(path: Path, append: bool = False):
    reject_symlink_path(path)
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_APPEND if append else os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, "a" if append else "w", encoding="utf-8")


def write_text_secure(path: Path, text: str) -> None:
    with secure_open_text(path, append=False) as f:
        f.write(text)


def secure_file(path: Path) -> None:
    reject_symlink_path(path)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except PermissionError:
        raise SystemExit(f"could not chmod 0600: {path}")


def secure_dir(path: Path) -> None:
    reject_symlink_path(path)
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    except PermissionError:
        raise SystemExit(f"could not chmod 0700: {path}")


def reject_symlink_path(path: Path) -> None:
    current = path if path.is_absolute() else path.resolve().anchor
    probe = Path(path.anchor) if path.is_absolute() else Path.cwd().anchor
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        probe = probe / part
        if probe.is_symlink():
            raise SystemExit("refusing to follow symlink in RightOut storage path")


def safe_join(root: Path, *parts: str) -> Path:
    root = root.expanduser().resolve()
    path = root.joinpath(*parts)
    resolved_parent = path.parent.resolve()
    if root != resolved_parent and root not in resolved_parent.parents:
        raise SystemExit("path escapes RightOut workdir")
    reject_symlink_path(path.parent)
    if path.exists():
        reject_symlink_path(path)
    return path


def storage_marker_path(workdir: Path) -> Path:
    return workdir / ".data-broker-removal-storage.json"


def mark_encrypted_storage(workdir: Path, method: str, note: str) -> dict[str, Any]:
    if method not in ENCRYPTED_STORAGE_METHODS:
        raise SystemExit("storage method must be age, filevault, luks, or encrypted-volume")
    secure_dir(workdir)
    verified = False
    verification = "operator_attestation_only"
    if method == "filevault" and sys.platform == "darwin":
        import subprocess

        proc = subprocess.run(["fdesetup", "status"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
        verified = proc.returncode == 0 and "FileVault is On" in proc.stdout
        verification = "macos_filevault_status" if verified else "operator_attestation_only"
    marker = {
        "created_at": now(),
        "method": method,
        "note": note,
        "real_pii_allowed": True,
        "verification": verification,
        "verified_by_runner": verified,
    }
    write_json(storage_marker_path(workdir), marker)
    return marker


def has_encrypted_storage_marker(workdir: Path) -> bool:
    path = storage_marker_path(workdir)
    if not path.exists():
        return False
    marker = load_json(path)
    return marker.get("real_pii_allowed") is True and marker.get("method") in ENCRYPTED_STORAGE_METHODS and marker.get("verified_by_runner") is True


def skill_dir_arg(args: argparse.Namespace) -> Path:
    return Path(args.skill_dir).expanduser().resolve()


def catalog_path(skill_dir: Path) -> Path:
    return skill_dir / "references" / "brokers" / "core.json"


def load_catalog(skill_dir: Path) -> dict[str, Any]:
    catalog = load_json(catalog_path(skill_dir))
    ids = [b["id"] for b in catalog["brokers"]]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate broker ids in catalog")
    return catalog


def opaque_subject_id(seed: str | None = None) -> str:
    if not seed:
        return f"subj_{uuid.uuid4().hex[:16]}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    return f"subj_{digest}"


def dummy_subject() -> dict[str, Any]:
    return {
        "subject_id": opaque_subject_id("dummy-openclaw-data-broker-removal"),
        "dummy": True,
        "consent": True,
        "consent_scope": ["audit", "dummy_scan", "dummy_plan", "breach_intelligence"],
        "jurisdictions": ["US", "US-CA", "EU"],
        "profile": {
            "name": "Avery Example",
            "aliases": ["A. Example"],
            "state": "CA",
            "city": "Exampleville",
            "contact_email": "avery.example@example.invalid",
            "phone": "+1-555-0100",
            "address": "100 Example Street",
        },
        "created_at": now(),
    }


def validate_subject_id(subject_id: str) -> str:
    if not isinstance(subject_id, str) or not SUBJECT_ID_RE.fullmatch(subject_id):
        raise SystemExit("invalid subject_id")
    return subject_id


def validate_broker_id(broker_id: str) -> str:
    if not isinstance(broker_id, str) or not BROKER_ID_RE.fullmatch(broker_id):
        raise SystemExit("invalid broker_id")
    return broker_id


def is_builtin_dummy_subject(subject: dict[str, Any]) -> bool:
    expected = dummy_subject()
    return (
        subject.get("dummy") is True
        and subject.get("subject_id") == expected["subject_id"]
        and subject.get("profile") == expected["profile"]
        and set(subject.get("jurisdictions", [])) == set(expected["jurisdictions"])
    )


def reject_public_live_mode(reason: str) -> None:
    if COMMUNITY_LIVE_DISABLED and os.environ.get("RIGHTOUT_ENABLE_UNSAFE_LOCAL_LIVE") != "1":
        raise SystemExit(
            f"{reason}; public RightOut disables live PII/submission authority until a platform-owned OpenClaw approval adapter is integrated"
        )


def approved_gates(raw: list[str] | None) -> set[str]:
    gates = set(raw or [])
    unknown = gates - LIVE_ACTION_GATES
    if unknown:
        raise SystemExit(f"unknown approval gate(s): {', '.join(sorted(unknown))}")
    return gates


def load_approval_receipts(raw_paths: list[str] | None) -> list[dict[str, Any]]:
    receipts = []
    for raw in raw_paths or []:
        receipt = load_json(Path(raw).expanduser().resolve())
        required = {"approval_id", "subject_id", "gate", "scope", "expires_at", "non_goals", "issued_by", "created_at"}
        missing = required - set(receipt)
        if missing:
            raise SystemExit(f"approval receipt missing fields: {sorted(missing)}")
        if receipt["gate"] not in LIVE_ACTION_GATES:
            raise SystemExit(f"approval receipt has unknown gate: {receipt['gate']}")
        if receipt["issued_by"] != "openclaw-approval-boundary":
            raise SystemExit(f"approval receipt must be issued_by openclaw-approval-boundary: {receipt['approval_id']}")
        if os.environ.get("OPENCLAW_ALLOW_TEST_RECEIPTS") != "1":
            verify_receipt_signature(receipt)
        created = dt.datetime.fromisoformat(receipt["created_at"])
        if created.tzinfo is None:
            raise SystemExit(f"approval receipt created_at is timezone-less: {receipt['approval_id']}")
        if created > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
            raise SystemExit(f"approval receipt created_at is in the future: {receipt['approval_id']}")
        expires = dt.datetime.fromisoformat(receipt["expires_at"])
        if expires.tzinfo is None or expires < dt.datetime.now(dt.timezone.utc):
            raise SystemExit(f"approval receipt expired or timezone-less: {receipt['approval_id']}")
        receipts.append(receipt)
    return receipts


def canonical_receipt_payload(receipt: dict[str, Any]) -> bytes:
    payload = {k: v for k, v in receipt.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_receipt_signature(receipt: dict[str, Any]) -> None:
    key = os.environ.get("OPENCLAW_APPROVAL_RECEIPT_KEY")
    if not key:
        raise SystemExit("approval receipt signature verification requires OPENCLAW_APPROVAL_RECEIPT_KEY")
    signature = receipt.get("signature")
    if not isinstance(signature, str):
        raise SystemExit(f"approval receipt missing signature: {receipt['approval_id']}")
    expected = hmac.new(key.encode("utf-8"), canonical_receipt_payload(receipt), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise SystemExit(f"approval receipt signature invalid: {receipt['approval_id']}")


def receipt_gates(receipts: list[dict[str, Any]], subject_id: str, broker_id: str | None = None) -> set[str]:
    gates = set()
    for receipt in receipts:
        if receipt["subject_id"] != subject_id:
            continue
        scoped_broker = receipt.get("scope", {}).get("broker_id")
        if scoped_broker is None:
            raise SystemExit(f"approval receipt missing scope.broker_id: {receipt['approval_id']}")
        if broker_id is None and scoped_broker != "*":
            continue
        if broker_id and scoped_broker not in {"*", broker_id}:
            continue
        gates.add(receipt["gate"])
    return gates


def receipts_allow_unencrypted_local(args: argparse.Namespace, subject_id: str, broker_id: str | None = None) -> bool:
    for receipt in load_approval_receipts(getattr(args, "approval_receipt", None)):
        if receipt["subject_id"] != subject_id:
            continue
        scoped_broker = receipt.get("scope", {}).get("broker_id")
        if broker_id is None and scoped_broker != "*":
            continue
        if broker_id and scoped_broker not in {"*", broker_id}:
            continue
        if receipt["gate"] == "store_dossier" and receipt.get("scope", {}).get("allow_unencrypted_local") is True:
            return True
    return False


def effective_gates(args: argparse.Namespace, plan: dict[str, Any] | None = None, subject_id: str | None = None, broker_id: str | None = None) -> set[str]:
    raw = approved_gates(getattr(args, "approved_gate", None))
    if raw and (not plan or plan.get("mode") != "dummy"):
        raise SystemExit("--approved-gate is only valid for dummy mode; live work requires --approval-receipt")
    gates = set(raw)
    if subject_id:
        gates |= receipt_gates(load_approval_receipts(getattr(args, "approval_receipt", None)), subject_id, broker_id)
    return gates


def subject_has_real_pii(subject: dict[str, Any]) -> bool:
    if is_builtin_dummy_subject(subject):
        return False
    return True


def validate_consent(subject_or_meta: dict[str, Any]) -> None:
    if subject_or_meta.get("consent") is not True:
        raise SystemExit("recorded subject consent is required")
    scope = subject_or_meta.get("consent_scope")
    if not isinstance(scope, list) or not scope:
        raise SystemExit("recorded consent_scope is required")


def require_consent_scope(subject_or_meta: dict[str, Any], scope_name: str) -> None:
    validate_consent(subject_or_meta)
    if scope_name not in set(subject_or_meta.get("consent_scope", [])):
        raise SystemExit(f"consent_scope does not include {scope_name}")


def assert_no_pii_in_path(path: Path) -> None:
    text = str(path)
    if PII_PATTERN.search(text):
        raise SystemExit(f"potential PII in path: {path}")


def assert_no_pii_text(value: Any, label: str) -> None:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    if PII_PATTERN.search(text):
        raise SystemExit(f"potential raw PII in {label}")


def validate_evidence(evidence: dict[str, Any] | None) -> None:
    if evidence is None:
        return
    unknown = set(evidence) - SAFE_EVIDENCE_KEYS
    if unknown:
        raise SystemExit(f"unsupported evidence keys: {sorted(unknown)}")
    assert_no_pii_text(evidence, "evidence")


def subject_dir(workdir: Path, subject_id: str) -> Path:
    validate_subject_id(subject_id)
    path = safe_join(workdir, "subjects", subject_id)
    assert_no_pii_in_path(path)
    return path


def subject_paths(workdir: Path, subject_id: str) -> dict[str, Path]:
    base = subject_dir(workdir, subject_id)
    return {
        "base": base,
        "dossier": base / "dossier.json",
        "metadata": base / "metadata.json",
        "plan": base / "plan.json",
        "audit": base / "audit.jsonl",
        "report": base / "report.json",
        "hibp": base / "hibp.json",
        "tasks": base / "tasks.json",
        "drafts": base / "drafts",
    }


def save_subject(workdir: Path, subject: dict[str, Any], allow_unencrypted_local: bool = False) -> dict[str, Path]:
    paths = subject_paths(workdir, subject["subject_id"])
    secure_dir(paths["base"])
    validate_consent(subject)
    if subject_has_real_pii(subject) and not has_encrypted_storage_marker(workdir) and not allow_unencrypted_local:
        raise SystemExit("real PII dossier storage requires runner-verified encrypted storage marker or explicit allow_unencrypted_local scope")
    metadata = {k: subject[k] for k in ["subject_id", "dummy", "consent", "consent_scope", "jurisdictions", "created_at"] if k in subject}
    write_json(paths["metadata"], metadata)
    write_json(paths["dossier"], subject)
    append_jsonl(paths["audit"], {"at": now(), "event": "subject_saved", "subject_id": subject["subject_id"], "dummy": subject.get("dummy", False)})
    return paths


def load_subject(workdir: Path, subject_id: str) -> dict[str, Any]:
    return load_json(subject_paths(workdir, subject_id)["dossier"])


def load_metadata(workdir: Path, subject_id: str) -> dict[str, Any]:
    path = subject_paths(workdir, subject_id)["metadata"]
    if not path.exists():
        raise SystemExit("subject metadata missing; refuse to open dossier before approval metadata exists")
    return load_json(path)


def load_plan(workdir: Path, subject_id: str) -> dict[str, Any]:
    return load_json(subject_paths(workdir, subject_id)["plan"])


def save_plan(workdir: Path, plan: dict[str, Any], event: str = "plan_saved") -> None:
    paths = subject_paths(workdir, plan["subject_id"])
    secure_dir(paths["base"])
    write_json(paths["plan"], plan)
    append_jsonl(paths["audit"], {"at": now(), "event": event, "subject_id": plan["subject_id"], "summary": summarize(plan)})


def make_case(subject_id: str, broker: dict[str, Any]) -> dict[str, Any]:
    validate_subject_id(subject_id)
    validate_broker_id(broker["id"])
    return {
        "subject_id": subject_id,
        "broker_id": broker["id"],
        "broker_name": broker["name"],
        "category": broker["category"],
        "state": "new",
        "lane": broker["lane"],
        "approval_gate": broker.get("approval_gate"),
        "disclosure_fields": broker.get("disclosure_fields", []),
        "official_url": broker.get("official_url"),
        "requires_controller_contact": broker.get("requires_controller_contact", False),
        "allowed_domains": broker.get("allowed_domains", []),
        "human_only": broker.get("human_only", False),
        "evidence": [],
        "disclosures": [],
        "next_recheck_at": None,
        "history": [{"at": now(), "state": "new", "note": "case created"}],
    }


def plan_for_subject(skill_dir: Path, subject: dict[str, Any]) -> dict[str, Any]:
    catalog = load_catalog(skill_dir)
    jurisdictions = set(subject.get("jurisdictions", []))
    cases = []
    for broker in catalog["brokers"]:
        broker_jurisdictions = set(broker.get("jurisdictions", []))
        if broker_jurisdictions and broker_jurisdictions.isdisjoint(jurisdictions) and "selected" not in broker_jurisdictions:
            continue
        cases.append(make_case(subject["subject_id"], broker))
    return {
        "created_at": now(),
        "mode": "dummy" if is_builtin_dummy_subject(subject) else "approval_bound_live",
        "runner_fixture": "rightout_builtin_dummy_v1" if is_builtin_dummy_subject(subject) else None,
        "scan_only": False,
        "subject_id": subject["subject_id"],
        "jurisdictions": sorted(jurisdictions),
        "consent_scope": subject.get("consent_scope", []),
        "case_count": len(cases),
        "cases": cases,
        "non_goals": ["legal advice", "hard CAPTCHA bypass", "public-record erasure", "provider writes without approval"],
    }


def scan_only_plan_for_subject(skill_dir: Path, subject: dict[str, Any]) -> dict[str, Any]:
    plan = plan_for_subject(skill_dir, subject)
    plan["scan_only"] = True
    plan["mode"] = "dummy_scan_only" if is_builtin_dummy_subject(subject) else "approval_bound_scan_only"
    plan["non_goals"].extend(["submission", "request drafting", "provider writes"])
    return plan


def official_domains_for_case(case: dict[str, Any]) -> list[str]:
    domains = list(case.get("allowed_domains", []))
    official_url = case.get("official_url")
    if official_url:
        host = urlparse(official_url).hostname
        if host:
            domains.append(host)
    return sorted(set(d for d in domains if d))


def require_official_submission_evidence(case: dict[str, Any], evidence: dict[str, Any] | None) -> None:
    evidence = evidence or {}
    if case.get("human_only") is True and evidence.get("human_completed") is not True:
        raise SystemExit("submitted for human_only case requires human_completed evidence")
    if case.get("requires_controller_contact"):
        controller_url = evidence.get("controller_url")
        if evidence.get("controller_verified") is not True or not controller_url:
            raise SystemExit("submitted controller-rights case requires verified controller_url evidence")
        scope = verify_link_scope(controller_url, case.get("allowed_domains", []))
        if not scope["ok"]:
            raise SystemExit("submitted controller_url must match verified allowed_domains")
    source_url = evidence.get("source_url")
    if not source_url:
        raise SystemExit("submitted requires source_url evidence from the official broker/controller channel")
    if source_url:
        source_domains = official_domains_for_case(case)
        if case.get("requires_controller_contact") and evidence.get("controller_url"):
            controller_host = urlparse(evidence["controller_url"]).hostname
            if controller_host:
                source_domains.append(controller_host)
        scope = verify_link_scope(source_url, sorted(set(source_domains)))
        if not scope["ok"]:
            raise SystemExit("submitted source_url must be an official broker/controller domain")
    official_channel = evidence.get("official_channel")
    if official_channel and official_channel not in {"official_web_form", "official_email", "official_registry", "verified_controller", "operator_browser"}:
        raise SystemExit("submitted official_channel must name a recognized official channel")


def transition(case: dict[str, Any], new_state: str, note: str, evidence: dict[str, Any] | None = None, disclosed: list[str] | None = None) -> None:
    current = case["state"]
    if new_state != current and new_state not in ALLOWED_STATES.get(current, set()):
        raise SystemExit(f"invalid transition for {case['broker_id']}: {current} -> {new_state}")
    assert_no_pii_text(note, "note")
    validate_evidence(evidence)
    if new_state == "found" and not (evidence and evidence.get("listing_urls")):
        raise SystemExit("found requires listing_urls evidence")
    if new_state == "submitted":
        if not disclosed:
            raise SystemExit("submitted requires disclosed field names")
        confirmation = (evidence or {}).get("confirmation_status")
        if confirmation not in {"submitted", "pending_confirmation", "confirmed_receipt"}:
            raise SystemExit("submitted requires confirmation_status evidence")
        if not ((evidence or {}).get("source_url") or (evidence or {}).get("official_channel")):
            raise SystemExit("submitted requires source_url or official_channel evidence")
        require_official_submission_evidence(case, evidence)
    if new_state == "confirmed_removed" and not (evidence and evidence.get("verification") == "later_scan"):
        raise SystemExit("confirmed_removed requires later_scan verification evidence")
    case["state"] = new_state
    event = {"at": now(), "state": new_state, "note": note}
    if evidence:
        event["evidence"] = evidence
        case["evidence"].append({"at": event["at"], **evidence})
    if disclosed:
        allowed = set(case.get("disclosure_fields", []))
        bad = sorted(set(disclosed) - allowed)
        if bad:
            raise SystemExit(f"disclosure outside planned fields for {case['broker_id']}: {bad}")
        disclosure_event = {"at": event["at"], "fields": sorted(disclosed), "channel": case.get("lane")}
        case["disclosures"].append(disclosure_event)
        event["disclosed_fields"] = sorted(disclosed)
    if new_state in {"submitted", "awaiting_processing"} and not case.get("next_recheck_at"):
        case["next_recheck_at"] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)).date().isoformat()
    case["history"].append(event)


def next_actions(plan: dict[str, Any], approved_gates: set[str] | None = None) -> list[dict[str, Any]]:
    approved_gates = approved_gates or set()
    actions = []
    for case in plan["cases"]:
        gate = case.get("approval_gate")
        if case["state"] == "new":
            actions.append({"case": case["broker_id"], "action": "scan_or_matcher", "gate": "live_scan", "allowed_now": plan["mode"] == "dummy" or "live_scan" in approved_gates})
        elif case["state"] in {"found", "indirect_exposure", "inconclusive"}:
            if plan.get("scan_only"):
                actions.append({"case": case["broker_id"], "action": "review_scan_result_before_removal_plan", "gate": case.get("approval_gate"), "allowed_now": False, "scan_only": True})
                continue
            if case.get("human_only"):
                actions.append({"case": case["broker_id"], "action": "queue_human_task", "gate": gate, "allowed_now": True, "human_only": True})
                continue
            allowed = gate not in LIVE_ACTION_GATES or gate in approved_gates or plan["mode"] == "dummy"
            actions.append({"case": case["broker_id"], "action": f"prepare_{case['lane']}", "gate": gate, "allowed_now": allowed})
        elif case["state"] == "approval_required":
            if case.get("human_only"):
                actions.append({"case": case["broker_id"], "action": f"await_human_completion_for_{case['lane']}", "gate": gate, "allowed_now": False, "human_only": True})
                continue
            actions.append({"case": case["broker_id"], "action": f"await_approval_for_{case['lane']}", "gate": gate, "allowed_now": gate in approved_gates or plan["mode"] == "dummy"})
        elif case["state"] == "submitted":
            actions.append({"case": case["broker_id"], "action": "wait_or_verify", "gate": None, "allowed_now": True})
        elif case["state"] == "awaiting_processing":
            actions.append({"case": case["broker_id"], "action": "recheck_later", "gate": "schedule_recheck", "allowed_now": plan["mode"] == "dummy" or "schedule_recheck" in approved_gates})
    return actions


def simulate_dummy(plan: dict[str, Any]) -> dict[str, Any]:
    for case in plan["cases"]:
        if case["broker_id"] == "google_results_about_you":
            transition(case, "inconclusive", "monitor-only lane is not source removal", {"kind": "dummy_monitor_only"})
            transition(case, "human_task_queued", "provider write would require approval", {"gate": "provider_write"})
            continue
        transition(case, "searching", "dummy read-only scan started", {"kind": "dummy_scan"})
        if case["broker_id"] in {"intelius_peopleconnect", "spokeo", "california_drop"}:
            transition(case, "found", "dummy exposure confirmed", {"listing_urls": ["https://example.invalid/listing"], "dummy": True})
            transition(case, "action_selected", f"selected lane {case['lane']}", {"lane": case["lane"]})
            transition(case, "approval_required", "live submission would require explicit approval", {"gate": case.get("approval_gate")})
        elif case["broker_id"] == "checkpeople":
            transition(case, "not_found", "dummy guided matcher returned no result", {"matcher": "dummy"})
        elif case["broker_id"] == "radaris":
            transition(case, "indirect_exposure", "dummy relative record contains subject email", {"kind": "dummy_indirect", "listing_urls": ["https://example.invalid/relative-listing"]})
            transition(case, "approval_required", "targeted delete-my-PII request would require approval", {"gate": case.get("approval_gate")})
        else:
            transition(case, "inconclusive", "dummy scan could not prove found or not_found", {"kind": "dummy_inconclusive"})
    return plan


def simulate_dummy_scan_only(plan: dict[str, Any]) -> dict[str, Any]:
    for case in plan["cases"]:
        transition(case, "searching", "dummy scan-only check started", {"kind": "dummy_scan"})
        if case["broker_id"] in {"intelius_peopleconnect", "spokeo", "california_drop"}:
            transition(case, "found", "dummy exposure found; no removal request prepared in scan-only mode", {"listing_urls": ["https://example.invalid/listing"], "dummy": True})
        elif case["broker_id"] == "checkpeople":
            transition(case, "not_found", "dummy scan-only matcher returned no result", {"matcher": "dummy"})
        elif case["broker_id"] == "radaris":
            transition(case, "indirect_exposure", "dummy relative record contains subject email; no request prepared in scan-only mode", {"kind": "dummy_indirect", "listing_urls": ["https://example.invalid/relative-listing"]})
        else:
            transition(case, "inconclusive", "dummy scan-only check could not prove found or not_found", {"kind": "dummy_inconclusive"})
    return plan


def load_hibp_intelligence(workdir: Path, subject_id: str) -> dict[str, Any] | None:
    path = subject_paths(workdir, subject_id)["hibp"]
    if not path.exists():
        return None
    return load_json(path)


def sanitize_label(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    if HIBP_DIRECT_IDENTIFIER_PATTERN.search(text) or HIBP_HASH_OR_SECRET_PATTERN.search(text):
        raise SystemExit(f"potential raw PII in {label}")
    if not HIBP_SAFE_LABEL_PATTERN.match(text):
        raise SystemExit(f"unsupported characters in {label}")
    return text[:120]


def load_hibp_json(path: Path) -> Any:
    path = path.expanduser().resolve()
    if path.stat().st_size > HIBP_MAX_IMPORT_BYTES:
        raise SystemExit(f"HIBP input exceeds {HIBP_MAX_IMPORT_BYTES} bytes; import a reduced export")
    return load_json(path)


def normalize_hibp_items(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict) and "breaches" in raw:
        raw = raw["breaches"]
    if not isinstance(raw, list):
        raise SystemExit("HIBP input must be a list or an object with breaches")
    if len(raw) > HIBP_MAX_ITEMS:
        raise SystemExit(f"HIBP input has too many entries; max {HIBP_MAX_ITEMS}")
    items = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise SystemExit("HIBP breach entries must be objects")
        data_classes = entry.get("DataClasses") or entry.get("dataClasses") or []
        if not isinstance(data_classes, list):
            raise SystemExit("HIBP DataClasses must be a list")
        safe_classes = [sanitize_label(value, "HIBP data class") for value in data_classes]
        unknown_classes = sorted(set(safe_classes) - HIBP_ALLOWED_DATA_CLASSES)
        if unknown_classes:
            raise SystemExit(f"unsupported HIBP data class(es): {unknown_classes}")
        risk_tags = sorted({HIBP_RISK_BY_DATA_CLASS.get(value, "other_exposure") for value in safe_classes})
        if entry.get("IsSensitive") is True:
            risk_tags.append("sensitive_breach")
        if entry.get("IsSpamList") is True:
            risk_tags.append("spam_list_exposure")
        if entry.get("IsMalware") is True or entry.get("IsStealerLog") is True:
            risk_tags.append("malware_or_stealer_log")
        items.append(
            {
                "name": sanitize_label(entry.get("Name") or entry.get("name"), "HIBP breach name"),
                "title": sanitize_label(entry.get("Title") or entry.get("title") or entry.get("Name") or entry.get("name"), "HIBP breach title"),
                "domain": sanitize_domain(entry.get("Domain") or entry.get("domain") or ""),
                "breach_date": sanitize_breach_date(entry.get("BreachDate") or entry.get("breachDate") or ""),
                "data_classes": sorted(set(safe_classes)),
                "risk_tags": sorted(set(risk_tags)),
                "verified": bool(entry.get("IsVerified", entry.get("verified", False))),
                "sensitive": bool(entry.get("IsSensitive", entry.get("sensitive", False))),
                "spam_list": bool(entry.get("IsSpamList", entry.get("spamList", False))),
                "malware_or_stealer_log": bool(entry.get("IsMalware", False) or entry.get("IsStealerLog", False)),
            }
        )
    return items


def sanitize_domain(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    if HIBP_DIRECT_IDENTIFIER_PATTERN.search(text) or not HIBP_DOMAIN_PATTERN.match(text):
        raise SystemExit("unsupported HIBP breach domain")
    return text


def sanitize_breach_date(value: Any) -> str:
    text = str(value or "unknown").strip()
    if text == "unknown":
        return text
    try:
        dt.date.fromisoformat(text)
    except ValueError:
        raise SystemExit("HIBP breach date must be YYYY-MM-DD")
    return text


def summarize_hibp(items: list[dict[str, Any]]) -> dict[str, Any]:
    risk_counts: dict[str, int] = {}
    data_classes: set[str] = set()
    high_priority = []
    for item in items:
        data_classes.update(item.get("data_classes", []))
        for tag in item.get("risk_tags", []):
            risk_counts[tag] = risk_counts.get(tag, 0) + 1
        if {"address_exposure", "phone_exposure", "identity_proofing_risk", "malware_or_stealer_log", "sensitive_breach"} & set(item.get("risk_tags", [])):
            high_priority.append(item["name"])
    recommendations = []
    if risk_counts.get("address_exposure") or risk_counts.get("phone_exposure"):
        recommendations.append("prioritize people-search brokers that match by address or phone")
    if risk_counts.get("credential_exposure") or risk_counts.get("malware_or_stealer_log"):
        recommendations.append("separate account-security remediation from broker removal")
    if risk_counts.get("spam_list_exposure"):
        recommendations.append("expect marketing-list recirculation and schedule rechecks")
    return {
        "breach_count": len(items),
        "data_classes": sorted(data_classes),
        "risk_counts": dict(sorted(risk_counts.items())),
        "high_priority_breaches": sorted(set(high_priority)),
        "recommendations": recommendations,
    }


def build_report(plan: dict[str, Any], intelligence: dict[str, Any] | None = None) -> dict[str, Any]:
    summary = summarize(plan)
    broker_statuses = []
    for case in sorted(plan["cases"], key=lambda c: (REPORT_STAGES.get(c["state"], c["state"]), c["broker_id"])):
        broker_statuses.append(
            {
                "broker_id": case["broker_id"],
                "broker_name": case.get("broker_name", case["broker_id"]),
                "category": case.get("category"),
                "lane": case["lane"],
                "state": case["state"],
                "report_stage": REPORT_STAGES.get(case["state"], "unknown"),
                "source_url": case.get("official_url"),
                "next_recheck_at": case.get("next_recheck_at"),
                "last_note": case["history"][-1]["note"] if case.get("history") else None,
            }
        )
    removal_summary = {
        "requests_submitted": summary["state_counts"].get("submitted", 0),
        "awaiting_processing": summary["state_counts"].get("awaiting_processing", 0),
        "confirmed_removed": summary["state_counts"].get("confirmed_removed", 0),
        "reappeared": summary["state_counts"].get("reappeared", 0),
    }
    report = {
        **summary,
        "report_version": 2,
        "scan_only": bool(plan.get("scan_only")),
        "generated_at": now(),
        "coverage": {
            "broker_count": plan["case_count"],
            "categories": sorted({c.get("category", "unknown") for c in plan["cases"]}),
            "jurisdictions": plan.get("jurisdictions", []),
        },
        "broker_statuses": broker_statuses,
        "removal_summary": removal_summary,
        "report_sections": [
            "found exposure",
            "not found",
            "inconclusive",
            "requests submitted",
            "awaiting verification",
            "confirmed removals",
            "human tasks",
            "HIBP risk signals",
        ],
        "user_next_steps": next_actions(plan),
    }
    if intelligence:
        report["hibp"] = {
            **intelligence.get("summary", intelligence),
            "source_name": "Have I Been Pwned",
            "source_url": "https://haveibeenpwned.com/",
            "license_url": "https://haveibeenpwned.com/API/v3#License",
            "attribution": "Breach metadata derived from Have I Been Pwned operator-supplied/API export; HIBP risk signals are not broker-removal evidence.",
            "imported_at": intelligence.get("imported_at"),
        }
    return report


def summarize(plan: dict[str, Any]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for case in plan["cases"]:
        counts[case["state"]] = counts.get(case["state"], 0) + 1
    return {
        "subject_id": plan["subject_id"],
        "mode": plan["mode"],
        "case_count": plan["case_count"],
        "state_counts": counts,
        "next_actions": next_actions(plan),
        "approval_gates_present": sorted({c.get("approval_gate") for c in plan["cases"] if c.get("approval_gate")}),
        "human_tasks": [c["broker_id"] for c in plan["cases"] if c["state"] == "human_task_queued"],
        "due_rechecks": [c["broker_id"] for c in due_cases(plan)],
    }


def due_cases(plan: dict[str, Any], today: dt.date | None = None) -> list[dict[str, Any]]:
    today = today or dt.datetime.now(dt.timezone.utc).date()
    due = []
    for case in plan["cases"]:
        value = case.get("next_recheck_at")
        if not value:
            continue
        try:
            when = dt.date.fromisoformat(value)
        except ValueError:
            continue
        if when <= today:
            due.append(case)
    return due


def find_case(plan: dict[str, Any], broker_id: str) -> dict[str, Any]:
    validate_broker_id(broker_id)
    for case in plan["cases"]:
        if case["broker_id"] == broker_id:
            return case
    raise SystemExit(f"unknown broker in plan: {broker_id}")


def check_gate(plan: dict[str, Any], gate: str | None, gates: set[str]) -> bool:
    dummy_authorized = plan.get("mode") == "dummy" and plan.get("subject_id") == DUMMY_SUBJECT_ID and plan.get("runner_fixture") == "rightout_builtin_dummy_v1"
    scan_dummy_authorized = plan.get("mode") == "dummy_scan_only" and plan.get("subject_id") == DUMMY_SUBJECT_ID and plan.get("runner_fixture") == "rightout_builtin_dummy_v1"
    return dummy_authorized or scan_dummy_authorized or not gate or gate not in LIVE_ACTION_GATES or gate in gates


def require_plan_scope(plan: dict[str, Any], scope_name: str) -> None:
    if plan.get("mode") in {"dummy", "dummy_scan_only"} and plan.get("runner_fixture") == "rightout_builtin_dummy_v1":
        return
    if scope_name not in set(plan.get("consent_scope", [])):
        raise SystemExit(f"consent_scope does not include {scope_name}")


def state_required_gate(state: str) -> str | None:
    if state in {"found", "not_found", "inconclusive", "indirect_exposure", "confirmed_removed"}:
        return "live_scan"
    if state in {"submitted", "verification_pending", "awaiting_processing"}:
        return "send_request"
    return None


def subject_action_required_gates(state: str) -> set[str]:
    if state in {"found", "not_found", "inconclusive", "indirect_exposure", "confirmed_removed"}:
        return {"process_real_pii"}
    if state in {"submitted", "verification_pending", "awaiting_processing"}:
        return {"process_real_pii", "send_request"}
    return set()


def request_kind_for_subject(subject: dict[str, Any], requested: str) -> str:
    if requested not in REQUEST_KINDS:
        raise SystemExit(f"unknown request kind: {requested}")
    jurisdictions = set(subject.get("jurisdictions", []))
    if requested == "gdpr_erasure" and not jurisdictions.intersection({"EU", "EEA", "DE", "AT", "FR", "ES", "IT", "NL", "IE", "BE", "DK", "SE", "FI", "PL", "PT", "CZ", "SK", "SI", "HR", "HU", "RO", "BG", "GR", "LT", "LV", "EE", "LU", "MT", "CY", "NO", "IS", "LI"}):
        raise SystemExit("gdpr_erasure requires plausible EU/EEA jurisdiction")
    if requested == "uk_gdpr_erasure" and "UK" not in jurisdictions and "GB" not in jurisdictions:
        raise SystemExit("uk_gdpr_erasure requires plausible UK jurisdiction")
    if requested == "ccpa_delete" and "US-CA" not in jurisdictions:
        raise SystemExit("ccpa_delete requires plausible California jurisdiction")
    return requested


def template_for_kind(skill_dir: Path, kind: str) -> Path:
    mapping = {
        "generic": "delete-my-pii-email.md",
        "gdpr_erasure": "gdpr-erasure-email.md",
        "uk_gdpr_erasure": "gdpr-erasure-email.md",
        "ccpa_delete": "delete-my-pii-email.md",
        "indirect_delete_my_pii": "delete-my-pii-email.md",
    }
    path = skill_dir / "templates" / mapping[kind]
    if not path.exists():
        raise SystemExit(f"missing template for {kind}: {path.name}")
    return path


def verified_controller_url(case: dict[str, Any]) -> str | None:
    for evidence in case.get("evidence", []):
        if evidence.get("controller_verified") is True and evidence.get("controller_url"):
            scope = verify_link_scope(evidence["controller_url"], case.get("allowed_domains", []))
            if scope["ok"]:
                return evidence["controller_url"]
    return None


def render_email(skill_dir: Path, subject: dict[str, Any], case: dict[str, Any], listing_url: str, kind: str = "generic") -> dict[str, str]:
    kind = request_kind_for_subject(subject, kind)
    if case["state"] not in {"found", "indirect_exposure", "action_selected", "approval_required"}:
        raise SystemExit(f"cannot render email from state {case['state']}")
    if case["lane"] != "registry" and listing_url == "blind-opt-out":
        raise SystemExit("blind direct opt-out is disabled for non-registry lanes; confirm first")
    if case["state"] in {"found", "action_selected", "approval_required"} and not any(e.get("listing_urls") for e in case.get("evidence", [])):
        raise SystemExit("render-email requires listing evidence unless this is indirect exposure or registry flow")
    evidence_urls = {url for e in case.get("evidence", []) for url in e.get("listing_urls", [])}
    if case["lane"] != "registry" and listing_url not in evidence_urls:
        raise SystemExit("listing_url must match verified case evidence")
    recipient_url = "OFFICIAL_BROKER_CHANNEL_ONLY"
    recipient_lock = "operator must replace only with broker official_url/privacy address verified from broker record"
    if kind in {"gdpr_erasure", "uk_gdpr_erasure"} or case.get("requires_controller_contact"):
        verified_controller = verified_controller_url(case)
        if not verified_controller:
            raise SystemExit("controller-rights draft requires recorded controller_url evidence with verified allowed_domains")
        recipient_url = verified_controller
        recipient_lock = "operator must use only the verified controller privacy/DPO contact recorded as evidence"
    template = template_for_kind(skill_dir, kind).read_text(encoding="utf-8")
    profile = subject["profile"]
    body = template
    replacements = {
        "name": profile.get("name", ""),
        "state": profile.get("state", ""),
        "jurisdiction": ", ".join(subject.get("jurisdictions", [])),
        "contact_email": profile.get("contact_email", ""),
        "listing_url": listing_url,
        "request_kind": kind,
    }
    for key, value in replacements.items():
        body = body.replace("{{" + key + "}}", value)
    return {
        "to": recipient_url,
        "subject": "Request to delete my personal information",
        "body": body,
        "broker_id": case["broker_id"],
        "request_kind": kind,
        "recipient_lock": recipient_lock,
    }


def verify_link_scope(url: str, allowed_domains: list[str]) -> dict[str, Any]:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or ""
    ok = parsed.scheme == "https" and any(host == d or host.endswith("." + d) for d in allowed_domains)
    return {"ok": ok, "host": host, "allowed_domains": allowed_domains}


def cmd_doctor(args: argparse.Namespace) -> None:
    skill_dir = skill_dir_arg(args)
    required = [
        skill_dir / "SKILL.md",
        skill_dir / "README.md",
        skill_dir / "LICENSE",
        skill_dir / "THIRD_PARTY_NOTICES.md",
        skill_dir / "references" / "security-model.md",
        skill_dir / "references" / "operations.md",
        skill_dir / "references" / "state-machine.md",
        skill_dir / "references" / "legal" / "ccpa-cpra.md",
        skill_dir / "references" / "legal" / "gdpr.md",
        skill_dir / "references" / "legal" / "drop.md",
        catalog_path(skill_dir),
    ]
    missing = [str(p) for p in required if not p.exists()]
    catalog = load_catalog(skill_dir) if not missing else {"brokers": []}
    print(json.dumps({"ok": not missing, "missing": missing, "broker_count": len(catalog["brokers"]), "runner": "openclaw-data-broker-removal"}, indent=2))
    if missing:
        raise SystemExit(1)


def cmd_plan_dummy(args: argparse.Namespace) -> None:
    subject = dummy_subject()
    plan = plan_for_subject(skill_dir_arg(args), subject)
    print(json.dumps(plan, indent=2, sort_keys=True))


def cmd_intake_dummy(args: argparse.Namespace) -> None:
    workdir = Path(args.workdir).expanduser().resolve()
    subject = dummy_subject()
    save_subject(workdir, subject)
    print(json.dumps({"ok": True, "subject_id": subject["subject_id"], "dummy": True}, indent=2))


def cmd_intake_subject(args: argparse.Namespace) -> None:
    workdir = Path(args.workdir).expanduser().resolve()
    subject = load_json(Path(args.subject_file).expanduser().resolve())
    if "subject_id" not in subject:
        subject["subject_id"] = opaque_subject_id()
    validate_subject_id(subject["subject_id"])
    if subject.get("dummy") is True:
        raise SystemExit("external subject files cannot declare dummy:true; use intake-dummy or e2e-dummy for runner-owned fixtures")
    validate_consent(subject)
    gates = effective_gates(args, subject_id=subject["subject_id"])
    if subject_has_real_pii(subject):
        reject_public_live_mode("real PII intake is not enabled in the public community runner")
        missing = sorted({"process_real_pii", "store_dossier"} - gates)
        if missing:
            raise SystemExit(f"real PII intake requires approval gate(s): {', '.join(missing)}")
        if not has_encrypted_storage_marker(workdir) and not receipts_allow_unencrypted_local(args, subject["subject_id"]):
            raise SystemExit("real PII intake requires runner-verified encrypted storage marker or explicit allow_unencrypted_local scope")
    save_subject(workdir, subject, allow_unencrypted_local=receipts_allow_unencrypted_local(args, subject["subject_id"]))
    print(json.dumps({"ok": True, "subject_id": subject["subject_id"], "dummy": subject.get("dummy", False)}, indent=2))


def cmd_plan(args: argparse.Namespace) -> None:
    skill_dir = skill_dir_arg(args)
    workdir = Path(args.workdir).expanduser().resolve()
    meta = load_metadata(workdir, args.subject_id)
    validate_subject_id(args.subject_id)
    validate_consent(meta)
    require_consent_scope(meta, "audit")
    gates = effective_gates(args, subject_id=args.subject_id)
    if meta.get("dummy") is not True and not {"process_real_pii", "store_dossier"}.issubset(gates):
        raise SystemExit("real PII planning requires process_real_pii and store_dossier approval gates")
    if meta.get("dummy") is not True and not has_encrypted_storage_marker(workdir) and not receipts_allow_unencrypted_local(args, args.subject_id):
        raise SystemExit("real PII planning requires encrypted storage marker or explicit allow_unencrypted_local scope")
    subject = load_subject(workdir, args.subject_id)
    validate_consent(subject)
    if subject_has_real_pii(subject):
        reject_public_live_mode("real PII planning is not enabled in the public community runner")
    plan = plan_for_subject(skill_dir, subject)
    save_plan(workdir, plan, event="plan_created")
    print(json.dumps({"ok": True, "summary": summarize(plan)}, indent=2, sort_keys=True))


def cmd_next(args: argparse.Namespace) -> None:
    plan = load_plan(Path(args.workdir).expanduser().resolve(), args.subject_id)
    print(json.dumps({"ok": True, "actions": next_actions(plan, effective_gates(args, plan=plan, subject_id=args.subject_id))}, indent=2, sort_keys=True))


def cmd_record(args: argparse.Namespace) -> None:
    workdir = Path(args.workdir).expanduser().resolve()
    plan = load_plan(workdir, args.subject_id)
    validate_subject_id(args.subject_id)
    validate_broker_id(args.broker_id)
    case = find_case(plan, args.broker_id)
    evidence = json.loads(args.evidence) if args.evidence else None
    disclosed = args.disclosed or []
    gate = case.get("approval_gate")
    gates = effective_gates(args, plan=plan, subject_id=args.subject_id, broker_id=args.broker_id)
    required_gate = state_required_gate(args.state)
    if plan.get("scan_only") and args.state in {
        "action_selected",
        "approval_required",
        "submitted",
        "verification_pending",
        "awaiting_processing",
        "confirmed_removed",
        "human_task_queued",
    }:
        raise SystemExit("scan_only plans cannot advance to removal, submission, verification, or human-task states")
    if required_gate and not check_gate(plan, required_gate, gates):
        raise SystemExit(f"{args.state} for {args.broker_id} requires approval gate: {required_gate}")
    if plan.get("mode") != "dummy":
        reject_public_live_mode(f"{args.state} recording is not enabled for live subjects in the public community runner")
        missing_subject_gates = sorted(subject_action_required_gates(args.state) - gates)
        if missing_subject_gates:
            raise SystemExit(f"{args.state} for {args.broker_id} requires approval gate(s): {', '.join(missing_subject_gates)}")
    if required_gate == "live_scan":
        require_plan_scope(plan, "live_scan")
    if required_gate == "send_request":
        require_plan_scope(plan, "send_request")
    if args.state in {"submitted", "verification_pending", "awaiting_processing"} and not check_gate(plan, gate, gates):
        raise SystemExit(f"{args.state} for {args.broker_id} requires approval gate: {gate}")
    transition(case, args.state, args.note, evidence=evidence, disclosed=disclosed)
    save_plan(workdir, plan, event="case_recorded")
    print(json.dumps({"ok": True, "case": args.broker_id, "state": args.state}, indent=2))


def cmd_show(args: argparse.Namespace) -> None:
    plan = load_plan(Path(args.workdir).expanduser().resolve(), args.subject_id)
    print(json.dumps(find_case(plan, args.broker_id), indent=2, sort_keys=True))


def cmd_report(args: argparse.Namespace) -> None:
    workdir = Path(args.workdir).expanduser().resolve()
    plan = load_plan(workdir, args.subject_id)
    report = build_report(plan, load_hibp_intelligence(workdir, args.subject_id))
    write_json(subject_paths(workdir, args.subject_id)["report"], report)
    print(json.dumps(report, indent=2, sort_keys=True))


def cmd_import_hibp(args: argparse.Namespace) -> None:
    workdir = Path(args.workdir).expanduser().resolve()
    meta = load_metadata(workdir, args.subject_id)
    validate_consent(meta)
    require_consent_scope(meta, "audit")
    require_consent_scope(meta, "breach_intelligence")
    gates = effective_gates(args, subject_id=args.subject_id)
    if meta.get("dummy") is not True:
        reject_public_live_mode("live HIBP import is not enabled in the public community runner")
        missing = sorted({"process_real_pii", "store_dossier"} - gates)
        if missing:
            raise SystemExit(f"HIBP import requires approval gate(s): {', '.join(missing)}")
        if not has_encrypted_storage_marker(workdir) and not receipts_allow_unencrypted_local(args, args.subject_id):
            raise SystemExit("HIBP import requires encrypted storage marker or explicit allow_unencrypted_local scope")
    items = normalize_hibp_items(load_hibp_json(Path(args.hibp_json)))
    result = {
        "imported_at": now(),
        "source": "haveibeenpwned",
        "mode": "operator_supplied_export_or_api_result",
        "contains_raw_account": False,
        "breaches": items,
        "summary": summarize_hibp(items),
    }
    write_json(subject_paths(workdir, args.subject_id)["hibp"], result)
    append_jsonl(subject_paths(workdir, args.subject_id)["audit"], {"at": now(), "event": "hibp_imported", "summary": result["summary"]})
    print(json.dumps({"ok": True, "summary": result["summary"]}, indent=2, sort_keys=True))


def cmd_tasks(args: argparse.Namespace) -> None:
    workdir = Path(args.workdir).expanduser().resolve()
    plan = load_plan(workdir, args.subject_id)
    tasks = [
        {"broker_id": c["broker_id"], "state": c["state"], "note": c["history"][-1]["note"]}
        for c in plan["cases"]
        if c["state"] in {"human_task_queued", "approval_required", "blocked"}
    ]
    write_json(subject_paths(workdir, args.subject_id)["tasks"], tasks)
    print(json.dumps({"ok": True, "tasks": tasks}, indent=2, sort_keys=True))


def cmd_due(args: argparse.Namespace) -> None:
    plan = load_plan(Path(args.workdir).expanduser().resolve(), args.subject_id)
    print(json.dumps({"ok": True, "due": [c["broker_id"] for c in due_cases(plan)]}, indent=2, sort_keys=True))


def cmd_render_email(args: argparse.Namespace) -> None:
    skill_dir = skill_dir_arg(args)
    workdir = Path(args.workdir).expanduser().resolve()
    plan = load_plan(workdir, args.subject_id)
    validate_subject_id(args.subject_id)
    validate_broker_id(args.broker_id)
    if plan.get("scan_only"):
        raise SystemExit("scan_only plans cannot render request drafts")
    case = find_case(plan, args.broker_id)
    gates = effective_gates(args, plan=plan, subject_id=args.subject_id, broker_id=args.broker_id)
    if not check_gate(plan, "send_request", gates):
        raise SystemExit("rendering live request content requires send_request approval unless dummy mode")
    require_plan_scope(plan, "send_request")
    if plan.get("mode") != "dummy":
        reject_public_live_mode("live request rendering is not enabled in the public community runner")
        if "process_real_pii" not in gates:
            raise SystemExit("rendering live request content requires process_real_pii approval")
        if "store_dossier" not in gates:
            raise SystemExit("persisting rendered request content requires store_dossier approval")
        if not has_encrypted_storage_marker(workdir) and not receipts_allow_unencrypted_local(args, args.subject_id):
            raise SystemExit("persisting rendered request content requires encrypted storage marker or explicit allow_unencrypted_local scope")
    subject = load_subject(workdir, args.subject_id)
    validate_consent(subject)
    draft = render_email(skill_dir, subject, case, args.listing_url, kind=args.kind)
    draft_path = subject_paths(workdir, args.subject_id)["drafts"] / f"{args.broker_id}.json"
    write_json(draft_path, draft)
    print(json.dumps({"ok": True, "draft": str(draft_path), "recipient_lock": draft["recipient_lock"]}, indent=2))


def cmd_verify_link(args: argparse.Namespace) -> None:
    print(json.dumps(verify_link_scope(args.url, args.allowed_domain), indent=2, sort_keys=True))


def cmd_mark_storage(args: argparse.Namespace) -> None:
    workdir = Path(args.workdir).expanduser().resolve()
    marker = mark_encrypted_storage(workdir, args.method, args.note)
    print(json.dumps({"ok": True, "marker": marker}, indent=2, sort_keys=True))


def cmd_e2e_dummy(args: argparse.Namespace) -> None:
    skill_dir = skill_dir_arg(args)
    workdir = Path(args.workdir).expanduser().resolve()
    subject = dummy_subject()
    subject_id = subject["subject_id"]
    paths = save_subject(workdir, subject)
    plan = simulate_dummy(plan_for_subject(skill_dir, subject))
    write_json(paths["plan"], plan)
    report = build_report(plan)
    write_json(paths["report"], report)
    append_jsonl(paths["audit"], {"at": now(), "event": "dummy_e2e_completed", "summary": report})
    print(json.dumps({"ok": True, "workdir": str(paths["base"]), "report": report}, indent=2, sort_keys=True))


def cmd_scan_only_dummy(args: argparse.Namespace) -> None:
    skill_dir = skill_dir_arg(args)
    workdir = Path(args.workdir).expanduser().resolve()
    subject = dummy_subject()
    subject_id = subject["subject_id"]
    paths = save_subject(workdir, subject)
    plan = simulate_dummy_scan_only(scan_only_plan_for_subject(skill_dir, subject))
    write_json(paths["plan"], plan)
    report = build_report(plan)
    write_json(paths["report"], report)
    append_jsonl(paths["audit"], {"at": now(), "event": "dummy_scan_only_completed", "summary": report})
    print(json.dumps({"ok": True, "workdir": str(paths["base"]), "report": report}, indent=2, sort_keys=True))


def cmd_validate(args: argparse.Namespace) -> None:
    skill_dir = skill_dir_arg(args)
    catalog = load_catalog(skill_dir)
    errors = []
    for broker in catalog["brokers"]:
        for key in ["id", "name", "category", "lane", "disclosure_fields", "approval_gate"]:
            if key not in broker:
                errors.append(f"{broker.get('id', '<unknown>')} missing {key}")
        if broker.get("lane") not in LANES:
            errors.append(f"{broker.get('id')} invalid lane {broker.get('lane')}")
        if broker.get("approval_gate") not in LIVE_ACTION_GATES:
            errors.append(f"{broker.get('id')} invalid approval gate {broker.get('approval_gate')}")
        if not str(broker.get("official_url", "")).startswith("https://"):
            errors.append(f"{broker.get('id')} official_url must be https")
        if not broker.get("provenance"):
            errors.append(f"{broker.get('id')} missing provenance")
    if not (skill_dir / "templates" / "delete-my-pii-email.md").exists():
        errors.append("missing delete-my-pii template")
    if not (skill_dir / "templates" / "gdpr-erasure-email.md").exists():
        errors.append("missing gdpr-erasure template")
    gdpr = (skill_dir / "references" / "legal" / "gdpr.md").read_text(encoding="utf-8")
    if "DSGVO" not in gdpr or "Article 17" not in gdpr:
        errors.append("gdpr reference must cover DSGVO and Article 17")
    for rel in ["SKILL.md", "README.md", "THIRD_PARTY_NOTICES.md", "LICENSE"]:
        if "Olli" in (skill_dir / rel).read_text(encoding="utf-8"):
            errors.append(f"{rel} contains Olli-specific text")
    print(json.dumps({"ok": not errors, "errors": errors, "broker_count": len(catalog["brokers"])}, indent=2))
    if errors:
        raise SystemExit(1)


def main() -> None:
    if "--skill-dir" in sys.argv[2:]:
        idx = sys.argv.index("--skill-dir")
        if idx + 1 >= len(sys.argv):
            raise SystemExit("--skill-dir requires a value")
        value = sys.argv[idx + 1]
        del sys.argv[idx : idx + 2]
        sys.argv[1:1] = ["--skill-dir", value]
    parser = argparse.ArgumentParser(description="OpenClaw data broker removal deterministic runner")
    parser.add_argument("--skill-dir", default=str(Path(__file__).resolve().parents[1]))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    sub.add_parser("plan-dummy")
    intake = sub.add_parser("intake-dummy")
    intake.add_argument("--workdir", required=True)
    intake_subject = sub.add_parser("intake-subject")
    intake_subject.add_argument("--workdir", required=True)
    intake_subject.add_argument("--subject-file", required=True)
    intake_subject.add_argument("--approval-receipt", action="append")
    plan = sub.add_parser("plan")
    plan.add_argument("--workdir", required=True)
    plan.add_argument("--subject-id", required=True)
    plan.add_argument("--approved-gate", action="append")
    plan.add_argument("--approval-receipt", action="append")
    nxt = sub.add_parser("next")
    nxt.add_argument("--workdir", required=True)
    nxt.add_argument("--subject-id", required=True)
    nxt.add_argument("--approved-gate", action="append")
    nxt.add_argument("--approval-receipt", action="append")
    record = sub.add_parser("record")
    record.add_argument("--workdir", required=True)
    record.add_argument("--subject-id", required=True)
    record.add_argument("--broker-id", required=True)
    record.add_argument("--state", required=True)
    record.add_argument("--note", required=True)
    record.add_argument("--evidence")
    record.add_argument("--disclosed", action="append")
    record.add_argument("--approved-gate", action="append")
    record.add_argument("--approval-receipt", action="append")
    show = sub.add_parser("show")
    show.add_argument("--workdir", required=True)
    show.add_argument("--subject-id", required=True)
    show.add_argument("--broker-id", required=True)
    report = sub.add_parser("report")
    report.add_argument("--workdir", required=True)
    report.add_argument("--subject-id", required=True)
    tasks = sub.add_parser("tasks")
    tasks.add_argument("--workdir", required=True)
    tasks.add_argument("--subject-id", required=True)
    due = sub.add_parser("due")
    due.add_argument("--workdir", required=True)
    due.add_argument("--subject-id", required=True)
    storage = sub.add_parser("mark-storage")
    storage.add_argument("--workdir", required=True)
    storage.add_argument("--method", required=True)
    storage.add_argument("--note", default="operator-approved encrypted local storage")
    email = sub.add_parser("render-email")
    email.add_argument("--workdir", required=True)
    email.add_argument("--subject-id", required=True)
    email.add_argument("--broker-id", required=True)
    email.add_argument("--listing-url", required=True)
    email.add_argument("--kind", default="generic", choices=sorted(REQUEST_KINDS))
    email.add_argument("--approved-gate", action="append")
    email.add_argument("--approval-receipt", action="append")
    verify = sub.add_parser("verify-link")
    verify.add_argument("--url", required=True)
    verify.add_argument("--allowed-domain", action="append", required=True)
    e2e = sub.add_parser("e2e-dummy")
    e2e.add_argument("--workdir", required=True)
    scan_only = sub.add_parser("scan-only-dummy")
    scan_only.add_argument("--workdir", required=True)
    hibp = sub.add_parser("import-hibp")
    hibp.add_argument("--workdir", required=True)
    hibp.add_argument("--subject-id", required=True)
    hibp.add_argument("--hibp-json", required=True)
    hibp.add_argument("--approval-receipt", action="append")
    sub.add_parser("validate")
    args = parser.parse_args()
    if args.command == "doctor":
        cmd_doctor(args)
    elif args.command == "plan-dummy":
        cmd_plan_dummy(args)
    elif args.command == "intake-dummy":
        cmd_intake_dummy(args)
    elif args.command == "intake-subject":
        cmd_intake_subject(args)
    elif args.command == "plan":
        cmd_plan(args)
    elif args.command == "next":
        cmd_next(args)
    elif args.command == "record":
        cmd_record(args)
    elif args.command == "show":
        cmd_show(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "tasks":
        cmd_tasks(args)
    elif args.command == "due":
        cmd_due(args)
    elif args.command == "mark-storage":
        cmd_mark_storage(args)
    elif args.command == "render-email":
        cmd_render_email(args)
    elif args.command == "verify-link":
        cmd_verify_link(args)
    elif args.command == "e2e-dummy":
        cmd_e2e_dummy(args)
    elif args.command == "scan-only-dummy":
        cmd_scan_only_dummy(args)
    elif args.command == "import-hibp":
        cmd_import_hibp(args)
    elif args.command == "validate":
        cmd_validate(args)


if __name__ == "__main__":
    main()
