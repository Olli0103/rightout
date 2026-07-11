#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SUBJECT_ID_RE = re.compile(r"^subj_[a-f0-9]{16,64}$")
BROKER_ID_RE = re.compile(r"^[a-z0-9_]{2,80}$")
DUMMY_SUBJECT_ID = "subj_314c841b03067a74"
COMMUNITY_LIVE_DISABLED = True
PUBLIC_COMMANDS = {"doctor", "plan-dummy", "scan-only-dummy", "e2e-dummy", "validate", "verify-link"}
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
LANES = {"registry", "web_form", "web_form_or_email", "email", "guided_flow", "operator_browser", "search_index", "human_task", "monitor_only"}
SAFE_EVIDENCE_KEYS = {"kind", "dummy", "gate", "lane", "listing_urls", "matcher", "verification", "source_url", "confirmation_status", "redacted_proof"}
SAFE_EVIDENCE_KEYS |= {"official_channel", "controller_url", "controller_verified", "human_completed", "sensitive_field_gate"}
SENSITIVE_FIELDS = {"date_of_birth", "full_date_of_birth", "government_id", "passport", "drivers_license", "identity_document", "utility_bill"}
PROOF_REF_RE = re.compile(r"^(?:proof_[a-f0-9]{12,64}|dummy-proof-[a-z0-9-]{3,64})$")
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
HIBP_ALLOWED_ENTRY_KEYS = {
    "Name", "name", "Title", "title", "Domain", "domain", "BreachDate", "breachDate",
    "DataClasses", "dataClasses", "IsVerified", "verified", "IsSensitive", "sensitive",
    "IsSpamList", "spamList", "IsMalware", "IsStealerLog",
}
REPORT_STAGES = {
    "found": "found_exposure",
    "indirect_exposure": "indirect_signal",
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
    return json.loads(read_text_secure(path))


def write_json(path: Path, data: Any) -> None:
    secure_dir(path.parent)
    write_text_secure(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    secure_dir(path.parent)
    line = json.dumps(data, sort_keys=True) + "\n"
    with file_lock(path):
        existing = read_text_secure(path) if path.exists() else ""
        atomic_write_text(path, existing + line)


def secure_open_text(path: Path, append: bool = False):
    reject_symlink_path(path)
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_APPEND if append else os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, "a" if append else "w", encoding="utf-8")


def write_text_secure(path: Path, text: str) -> None:
    with file_lock(path):
        atomic_write_text(path, text)


def read_text_secure(path: Path) -> str:
    reject_symlink_path(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SystemExit("could not safely read RightOut storage artifact") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit("RightOut storage artifact is not a regular file")
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


@contextlib.contextmanager
def file_lock(path: Path):
    secure_dir(path.parent)
    lock_path = path.parent / f".{path.name}.lock"
    reject_symlink_path(lock_path)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit("unsafe RightOut lock artifact")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def atomic_write_text(path: Path, text: str) -> None:
    reject_symlink_path(path)
    secure_dir(path.parent)
    fd, raw_tmp = tempfile.mkstemp(prefix=f".{path.name}.tmp.", dir=str(path.parent))
    tmp = Path(raw_tmp)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        reject_symlink_path(path)
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def secure_file(path: Path) -> None:
    reject_symlink_path(path)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except PermissionError:
        raise SystemExit("could not apply private file permissions")


def secure_dir(path: Path) -> None:
    reject_symlink_path(path)
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    except PermissionError:
        raise SystemExit("could not apply private directory permissions")


def reject_symlink_path(path: Path) -> None:
    path = path.expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    probe = Path(path.anchor)
    parts = path.parts[1:]
    for part in parts:
        probe = probe / part
        if probe.is_symlink():
            raise SystemExit("refusing to follow symlink in RightOut storage path")


def safe_join(root: Path, *parts: str) -> Path:
    root = root.expanduser()
    if not root.is_absolute():
        root = Path.cwd() / root
    reject_symlink_path(root)
    root = root.resolve()
    path = root.joinpath(*parts)
    try:
        path.relative_to(root)
    except ValueError:
        raise SystemExit("path escapes RightOut workdir")
    reject_symlink_path(path.parent)
    if path.exists():
        reject_symlink_path(path)
    return path


def skill_dir_arg(args: argparse.Namespace) -> Path:
    return Path(args.skill_dir).expanduser().resolve()


def catalog_path(skill_dir: Path) -> Path:
    return skill_dir / "references" / "brokers" / "core.json"


def load_catalog(skill_dir: Path) -> dict[str, Any]:
    catalog = load_json(catalog_path(skill_dir))
    errors = validate_catalog_data(catalog)
    if errors:
        raise SystemExit("catalog validation failed: " + "; ".join(errors))
    return catalog


def validate_catalog_data(catalog: Any, today: dt.date | None = None) -> list[str]:
    today = today or dt.datetime.now(dt.timezone.utc).date()
    errors: list[str] = []
    if not isinstance(catalog, dict):
        return ["catalog must be an object"]
    if catalog.get("schema_version") != 2:
        errors.append("catalog schema_version must be 2")
    brokers = catalog.get("brokers")
    if not isinstance(brokers, list) or not brokers:
        return errors + ["catalog brokers must be a non-empty list"]
    seen: set[str] = set()
    reserved_ids = {"con", "prn", "aux", "nul", "clock$", ".", ".."}
    forbidden_source_domains = {"privacyguides.org", "inteltechniques.com", "badbool.com"}
    allowed_source_licenses = {"official-facts-only-no-content-copy", "MIT", "CC0-1.0", "Apache-2.0"}
    required = {
        "id", "name", "category", "jurisdictions", "official_url", "official_domains", "lane",
        "required_fields", "prerequisites", "approval_gate", "last_verified", "freshness_days",
        "source_license", "sources", "notes",
    }
    for index, broker in enumerate(brokers):
        label = f"broker[{index}]"
        if not isinstance(broker, dict):
            errors.append(f"{label} must be an object")
            continue
        broker_id = broker.get("id")
        if not isinstance(broker_id, str) or not BROKER_ID_RE.fullmatch(broker_id):
            errors.append(f"{label} has unsafe id")
            broker_id = label
        else:
            label = broker_id
            if broker_id in seen:
                errors.append(f"{label} is duplicated")
            seen.add(broker_id)
            if broker_id.lower() in reserved_ids or broker_id.startswith("dummy_fixture_"):
                errors.append(f"{label} uses a reserved id")
        missing = sorted(required - set(broker))
        if missing:
            errors.append(f"{label} missing fields: {missing}")
        lane = broker.get("lane")
        if lane not in LANES:
            errors.append(f"{label} has invalid lane")
        gate = broker.get("approval_gate")
        if gate not in LIVE_ACTION_GATES:
            errors.append(f"{label} has invalid approval gate")
        official_domains = broker.get("official_domains")
        if not isinstance(official_domains, list) or not official_domains or not all(isinstance(item, str) and item for item in official_domains):
            errors.append(f"{label} official_domains must be a non-empty string list")
            official_domains = []
        validate_catalog_url(broker.get("official_url"), official_domains, label, "official_url", errors)
        fields = broker.get("required_fields")
        if not isinstance(fields, list) or not fields or not all(isinstance(field, str) and re.fullmatch(r"[a-z][a-z0-9_]{1,63}", field) for field in fields):
            errors.append(f"{label} required_fields must contain safe field ids")
            fields = []
        prerequisites = broker.get("prerequisites")
        if not isinstance(prerequisites, list) or not prerequisites or not all(isinstance(item, str) and re.fullmatch(r"[a-z][a-z0-9_]{1,79}", item) for item in prerequisites):
            errors.append(f"{label} prerequisites must contain safe ids")
        freshness = broker.get("freshness_days")
        if not isinstance(freshness, int) or not 30 <= freshness <= 365:
            errors.append(f"{label} freshness_days must be between 30 and 365")
            freshness = 180
        verified = parse_catalog_date(broker.get("last_verified"), label, "last_verified", errors)
        if verified and (verified > today or (today - verified).days > freshness):
            errors.append(f"{label} provenance is stale or future-dated")
        if broker.get("source_license") not in allowed_source_licenses:
            errors.append(f"{label} has unsupported source_license")
        sources = broker.get("sources")
        if not isinstance(sources, list) or not sources:
            errors.append(f"{label} sources must be a non-empty list")
        else:
            for source_index, source in enumerate(sources):
                source_label = f"{label}.sources[{source_index}]"
                if not isinstance(source, dict):
                    errors.append(f"{source_label} must be an object")
                    continue
                if not {"url", "title", "publisher", "license_scope", "last_verified"}.issubset(source):
                    errors.append(f"{source_label} missing provenance fields")
                validate_catalog_url(source.get("url"), official_domains, source_label, "url", errors)
                source_host = urlparse(str(source.get("url", ""))).hostname or ""
                if source_host in forbidden_source_domains or any(source_host.endswith("." + item) for item in forbidden_source_domains):
                    errors.append(f"{source_label} uses a forbidden third-party list source")
                source_date = parse_catalog_date(source.get("last_verified"), source_label, "last_verified", errors)
                if source_date and (source_date > today or (today - source_date).days > freshness):
                    errors.append(f"{source_label} is stale or future-dated")
                for text_key in ["title", "publisher", "license_scope"]:
                    if not isinstance(source.get(text_key), str) or not source[text_key].strip():
                        errors.append(f"{source_label} missing {text_key}")
        sensitive = set(fields) & SENSITIVE_FIELDS
        if sensitive and not (broker.get("human_only") is True and broker.get("sensitive_fields_gate") == "human_only_explicit"):
            errors.append(f"{label} sensitive fields require human_only_explicit gate")
        category = broker.get("category")
        if category == "registry" and not (lane == "registry" and broker.get("human_only") is True):
            errors.append(f"{label} registry category must use human-only registry lane")
        if category == "monitor_only" and not (lane == "monitor_only" and gate == "provider_write" and broker.get("human_only") is True):
            errors.append(f"{label} monitor_only category has inconsistent lane")
        if category == "legal_request" and not (
            lane == "human_task"
            and gate == "send_request"
            and broker.get("human_only") is True
            and broker.get("requires_controller_contact") is True
            and broker.get("allowed_domains") == []
            and broker.get("controller_domain_policy") == "platform_verified_out_of_band_only"
        ):
            errors.append(f"{label} legal_request must not self-authorize controller domains")
        if category == "people_search":
            if not isinstance(broker.get("id"), str) or not re.fullmatch(r"[a-z0-9_]{2,24}", broker["id"]):
                errors.append(f"{label} live broker id exceeds the public tool contract")
            scan = broker.get("scan")
            if not isinstance(scan, dict):
                errors.append(f"{label} has unsafe or incomplete live-scan policy")
                continue
            if scan.get("supported") is False:
                if not (
                    lane == "human_task"
                    and gate == "process_real_pii"
                    and broker.get("human_only") is True
                    and scan.get("manual_only") is True
                    and scan.get("automated_access_policy") == "prohibited_by_published_terms"
                    and isinstance(scan.get("terms_url"), str)
                    and isinstance(scan.get("reason"), str)
                    and scan["reason"].startswith("official_terms_prohibit_")
                ):
                    errors.append(f"{label} disabled people-search lane is not fail-closed")
                else:
                    validate_catalog_url(scan["terms_url"], official_domains, label, "scan.terms_url", errors)
                continue
            if not (lane == "search_index" and gate == "live_scan" and broker.get("human_only") is False):
                errors.append(f"{label} people_search has inconsistent live-scan lane")
            if not (
                scan.get("supported") is True
                and scan.get("automated_access_policy") == "search_index_only_no_publisher_access"
                and scan.get("terms_status") == "publisher_not_accessed"
                and scan.get("strategy") == "brave_site_query_no_publisher_fetch"
                and scan.get("query_fields") == ["full_name", "city", "region"]
                and scan.get("search_provider_host") == "api.search.brave.com"
                and scan.get("not_found_policy") == "never_from_index_absence"
                and "candidate_path_pattern" not in scan
                and "max_candidates" not in scan
            ):
                errors.append(f"{label} has unsafe or incomplete live-scan policy")
    return errors


def validate_catalog_url(value: Any, allowed_domains: list[str], label: str, field: str, errors: list[str]) -> None:
    if not isinstance(value, str):
        errors.append(f"{label} {field} must be an https URL")
        return
    parsed = urlparse(value)
    host = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or host in {"localhost", "127.0.0.1", "::1"}
        or host.endswith(".invalid")
        or not any(host == domain or host.endswith("." + domain) for domain in allowed_domains)
    ):
        errors.append(f"{label} {field} is not an allowed official URL")


def parse_catalog_date(value: Any, label: str, field: str, errors: list[str]) -> dt.date | None:
    if not isinstance(value, str):
        errors.append(f"{label} {field} must be YYYY-MM-DD")
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        errors.append(f"{label} {field} must be YYYY-MM-DD")
        return None


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
    if COMMUNITY_LIVE_DISABLED:
        raise SystemExit(
            f"{reason}; the Python runner has no live capability. Live scans exist only in the optional "
            "rightout_live_scan plugin tool behind native OpenClaw allow-once approval"
        )


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
        raise SystemExit("potential PII in RightOut storage path")


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
    proof = evidence.get("redacted_proof")
    if proof is not None and (not isinstance(proof, str) or not PROOF_REF_RE.fullmatch(proof)):
        raise SystemExit("redacted_proof must be an opaque proof reference")


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


def save_subject(workdir: Path, subject: dict[str, Any]) -> dict[str, Path]:
    if COMMUNITY_LIVE_DISABLED and not is_builtin_dummy_subject(subject):
        reject_public_live_mode("only the runner-owned synthetic subject may be persisted")
    paths = subject_paths(workdir, subject["subject_id"])
    secure_dir(paths["base"])
    validate_consent(subject)
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


def save_plan(workdir: Path, plan: dict[str, Any], event: str = "plan_saved", expected_revision: int | None = None) -> None:
    paths = subject_paths(workdir, plan["subject_id"])
    secure_dir(paths["base"])
    revision_lock = paths["base"] / ".plan-revision"
    with file_lock(revision_lock):
        current_revision = 0
        if paths["plan"].exists():
            current = load_json(paths["plan"])
            current_revision = int(current.get("revision", 0))
        if expected_revision is not None and current_revision != expected_revision:
            raise SystemExit("plan revision conflict; reload before writing")
        plan["revision"] = current_revision + 1
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
        "disclosure_fields": broker.get("required_fields", broker.get("disclosure_fields", [])),
        "official_url": broker.get("official_url"),
        "requires_controller_contact": broker.get("requires_controller_contact", False),
        "allowed_domains": broker.get("allowed_domains", []),
        "human_only": broker.get("human_only", False),
        "fixture_only": broker.get("fixture_only", False),
        "last_verified": broker.get("last_verified"),
        "evidence": [],
        "disclosures": [],
        "next_recheck_at": None,
        "history": [{"at": now(), "state": "new", "note": "case created"}],
    }


def plan_for_subject(skill_dir: Path, subject: dict[str, Any]) -> dict[str, Any]:
    if COMMUNITY_LIVE_DISABLED and not is_builtin_dummy_subject(subject):
        reject_public_live_mode("only the runner-owned synthetic subject may be planned")
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
        "revision": 0,
        "mode": "dummy" if is_builtin_dummy_subject(subject) else "approval_bound_live",
        "runner_fixture": "rightout_builtin_dummy_v1" if is_builtin_dummy_subject(subject) else None,
        "scan_only": False,
        "subject_id": subject["subject_id"],
        "jurisdictions": sorted(jurisdictions),
        "consent_scope": subject.get("consent_scope", []),
        "case_count": len(cases),
        "catalog_case_count": len(cases),
        "fixture_case_count": 0,
        "cases": cases,
        "non_goals": ["legal advice", "hard CAPTCHA bypass", "public-record erasure", "provider writes without approval"],
    }


def scan_only_plan_for_subject(skill_dir: Path, subject: dict[str, Any]) -> dict[str, Any]:
    plan = plan_for_subject(skill_dir, subject)
    plan["scan_only"] = True
    plan["mode"] = "dummy_scan_only" if is_builtin_dummy_subject(subject) else "approval_bound_scan_only"
    plan["non_goals"].extend(["submission", "request drafting", "provider writes"])
    return plan


def add_dummy_fixture_cases(plan: dict[str, Any], scenarios: list[str]) -> dict[str, Any]:
    for scenario in scenarios:
        broker = {
            "id": f"dummy_fixture_{scenario}",
            "name": f"Synthetic {scenario.replace('_', ' ')} fixture",
            "category": "test_fixture",
            "jurisdictions": ["TEST"],
            "official_url": "https://example.invalid/rightout-dummy-fixture",
            "lane": "human_task" if scenario == "human_task" else "web_form",
            "required_fields": ["name", "contact_email"],
            "approval_gate": "send_request",
            "human_only": scenario == "human_task",
            "fixture_only": True,
            "last_verified": "synthetic",
        }
        case = make_case(plan["subject_id"], broker)
        case["dummy_scenario"] = scenario
        plan["cases"].append(case)
    plan["fixture_case_count"] = len(scenarios)
    plan["case_count"] = len(plan["cases"])
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
    if COMMUNITY_LIVE_DISABLED and not case.get("fixture_only") and new_state != "new":
        reject_public_live_mode("catalog cases cannot transition in the dummy-only community runner")
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
        sensitive = sorted(set(disclosed) & SENSITIVE_FIELDS)
        if sensitive and not (
            case.get("human_only") is True
            and (evidence or {}).get("human_completed") is True
            and (evidence or {}).get("sensitive_field_gate") == "human_only_explicit"
        ):
            raise SystemExit("sensitive disclosure fields require an explicit human-only gate")
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
            if case.get("fixture_only"):
                actions.append({"case": case["broker_id"], "action": "run_synthetic_fixture", "gate": None, "allowed_now": True})
            elif case.get("category") == "people_search" and case.get("approval_gate") == "live_scan":
                actions.append({"case": case["broker_id"], "action": "use_rightout_live_scan_plugin", "gate": "live_scan", "allowed_now": False})
            else:
                actions.append({"case": case["broker_id"], "action": "human_or_unsupported_lane_not_checked", "gate": gate, "allowed_now": False})
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
        if not case.get("fixture_only"):
            continue
        transition(case, "searching", "dummy read-only scan started", {"kind": "dummy_scan"})
        transition(case, "found", "synthetic exposure fixture found", {"listing_urls": ["https://example.invalid/dummy-listing"], "dummy": True})
        scenario = case["dummy_scenario"]
        if scenario == "human_task":
            transition(case, "human_task_queued", "synthetic human task queued", {"kind": "dummy_human_task"})
            continue
        transition(case, "action_selected", "synthetic removal lane selected", {"lane": case["lane"]})
        transition(case, "approval_required", "synthetic approval boundary exercised", {"gate": "send_request"})
        proof_slug = scenario.replace("_", "-")
        submit_evidence = {
            "source_url": "https://example.invalid/rightout-dummy-fixture",
            "official_channel": "official_web_form",
            "confirmation_status": "submitted",
            "redacted_proof": f"dummy-proof-{proof_slug}",
            "dummy": True,
        }
        transition(case, "submitted", "synthetic request state recorded", submit_evidence, disclosed=["name", "contact_email"])
        if scenario == "awaiting_verification":
            transition(case, "verification_pending", "synthetic verification wait recorded", {"kind": "dummy_wait"})
        if scenario in {"awaiting_processing", "confirmed_removed", "reappeared"}:
            transition(case, "awaiting_processing", "synthetic processing wait recorded", {"kind": "dummy_wait"})
        if scenario in {"confirmed_removed", "reappeared"}:
            transition(case, "confirmed_removed", "synthetic later scan confirmed removal", {"verification": "later_scan", "redacted_proof": f"dummy-proof-{proof_slug}-later-scan", "dummy": True})
        if scenario == "reappeared":
            transition(case, "reappeared", "synthetic listing reappeared on a later scan", {"listing_urls": ["https://example.invalid/dummy-listing"], "dummy": True})
    return plan


def simulate_dummy_scan_only(plan: dict[str, Any]) -> dict[str, Any]:
    for case in plan["cases"]:
        if not case.get("fixture_only"):
            continue
        transition(case, "searching", "dummy scan-only check started", {"kind": "dummy_scan"})
        if case["dummy_scenario"] == "found":
            transition(case, "found", "dummy exposure found; no removal request prepared in scan-only mode", {"listing_urls": ["https://example.invalid/listing"], "dummy": True})
        elif case["dummy_scenario"] == "not_found":
            transition(case, "not_found", "dummy scan-only matcher returned no result", {"matcher": "dummy"})
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
        unexpected = sorted(set(entry) - HIBP_ALLOWED_ENTRY_KEYS)
        if unexpected:
            raise SystemExit("HIBP input contains unsupported fields; import breach metadata only")
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


def report_case_ref(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "broker_id": case["broker_id"],
        "broker_name": case.get("broker_name", case["broker_id"]),
        "lane": case.get("lane"),
        "state": case.get("state"),
        "fixture_only": bool(case.get("fixture_only")),
    }


def proof_references(case: dict[str, Any]) -> list[str]:
    refs = []
    for evidence in case.get("evidence", []):
        ref = evidence.get("redacted_proof")
        if isinstance(ref, str) and PROOF_REF_RE.fullmatch(ref):
            refs.append(ref)
    return sorted(set(refs))


def build_scan_report(plan: dict[str, Any]) -> dict[str, Any]:
    checked = [case for case in plan["cases"] if case.get("fixture_only") and case.get("state") != "new"]
    not_checked = [case for case in plan["cases"] if not case.get("fixture_only")]
    by_state = {
        state: [report_case_ref(case) for case in checked if case.get("state") == state]
        for state in ["found", "not_found", "inconclusive", "indirect_exposure", "blocked"]
    }
    return {
        "posture": "synthetic_dummy_only_no_network",
        "checked_count": len(checked),
        "catalog_not_checked_count": len(not_checked),
        "where_checked": [
            {
                **report_case_ref(case),
                "source_url": case.get("official_url"),
                "evidence_strength": "synthetic_fixture_only",
                "last_checked_at": case.get("history", [{}])[-1].get("at"),
            }
            for case in checked
        ],
        "found": by_state["found"],
        "indirect_exposure": by_state["indirect_exposure"],
        "not_found": by_state["not_found"],
        "inconclusive": by_state["inconclusive"] + by_state["blocked"],
        "not_checked": [
            {
                **report_case_ref(case),
                "source_url": case.get("official_url"),
                "reason": "not_checked_by_offline_dummy_runner",
            }
            for case in not_checked
        ],
        "coverage_gaps": [
            "offline_dummy_runner_performs_no_live_network_calls",
            "live_people_search_coverage_is_limited_to_supported_catalog_brokers",
            "legal_registry_and_monitor_lanes_are_not_proof_of_personal_exposure",
            "synthetic_fixture_results_do_not_describe_a_real_person",
        ],
        "invariants": {
            "network_calls": 0,
            "submissions": 0 if plan.get("scan_only") else "synthetic_state_machine_only",
            "provider_writes": 0,
            "real_pii_processed": False,
        },
    }


def build_removal_report(plan: dict[str, Any]) -> dict[str, Any]:
    buckets = {
        "submitted": "submitted",
        "awaiting_verification": "verification_pending",
        "awaiting_processing": "awaiting_processing",
        "confirmed_removed": "confirmed_removed",
        "reappeared": "reappeared",
        "human_tasks": "human_task_queued",
    }
    report: dict[str, Any] = {
        name: [
            {**report_case_ref(case), "proof_references": proof_references(case), "next_recheck_at": case.get("next_recheck_at")}
            for case in plan["cases"]
            if case.get("state") == state
        ]
        for name, state in buckets.items()
    }
    report["proof_reference_policy"] = "opaque redacted references only; no tokens, screenshots, listing URLs, or personal data"
    report["posture"] = "synthetic_state_machine_validation_only"
    return report


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
                "checked": bool(case.get("fixture_only") and case.get("state") != "new"),
                "fixture_only": bool(case.get("fixture_only")),
                "last_verified": case.get("last_verified"),
            }
        )
    scan_report = build_scan_report(plan)
    removal_report = build_removal_report(plan)
    removal_summary = {name: len(removal_report[name]) for name in ["submitted", "awaiting_verification", "awaiting_processing", "confirmed_removed", "reappeared", "human_tasks"]}
    removal_summary["requests_submitted"] = removal_summary["submitted"]
    report = {
        **summary,
        "report_version": 3,
        "scan_only": bool(plan.get("scan_only")),
        "generated_at": now(),
        "coverage": {
            "case_count": plan["case_count"],
            "catalog_case_count": plan.get("catalog_case_count", plan["case_count"]),
            "fixture_case_count": plan.get("fixture_case_count", 0),
            "categories": sorted({c.get("category", "unknown") for c in plan["cases"]}),
            "jurisdictions": plan.get("jurisdictions", []),
            "gaps": scan_report["coverage_gaps"],
        },
        "broker_statuses": broker_statuses,
        "scan_report": scan_report,
        "removal_report": removal_report,
        "removal_summary": removal_summary,
        "user_summary": {
            "headline": "Synthetic scan-only validation completed" if plan.get("scan_only") else "Synthetic removal-state validation completed",
            "risk": "No real-person risk assessment was performed; all results are dummy fixtures.",
            "progress": {
                "synthetic_checks_completed": scan_report["checked_count"],
                "catalog_lanes_not_checked": scan_report["catalog_not_checked_count"],
                "current_removal_states": removal_summary,
            },
            "next_steps": [
                "Use only the approval-gated rightout_live_scan tool for live discovery.",
                "Configure private subject data only through OpenClaw SecretRefs; never paste it into chat or runner files.",
                "Do not treat synthetic results as evidence of exposure or removal.",
            ],
            "limits": scan_report["coverage_gaps"],
        },
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
            "raw_leaked_values_included": False,
        }
    else:
        report["hibp"] = {
            "source_name": "Have I Been Pwned",
            "attribution": "No HIBP data imported; HIBP signals, when present in a future approved integration, are risk intelligence rather than broker evidence.",
            "breach_count": 0,
            "risk_counts": {},
            "raw_leaked_values_included": False,
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


def verify_link_scope(url: str, allowed_domains: list[str]) -> dict[str, Any]:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or ""
    ok = parsed.scheme == "https" and any(host == d or host.endswith("." + d) for d in allowed_domains)
    return {"ok": ok, "host": host, "allowed_domains": allowed_domains}


def cmd_doctor(args: argparse.Namespace) -> None:
    skill_dir = skill_dir_arg(args)
    plugin_root = skill_dir.parents[1]
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
        plugin_root / "index.ts",
        plugin_root / "lib" / "live-scan.mjs",
        plugin_root / "openclaw.plugin.json",
    ]
    missing = [str(p) for p in required if not p.exists()]
    catalog = load_catalog(skill_dir) if not missing else {"brokers": []}
    print(json.dumps({
        "ok": not missing,
        "missing": missing,
        "broker_count": len(catalog["brokers"]),
        "runner": "openclaw-data-broker-removal",
        "capability_posture": "approval_gated_live_plugin_plus_dummy_runner",
        "public_commands": sorted(PUBLIC_COMMANDS),
        "live_tool": "rightout_live_scan",
        "live_approval_adapter": "native_openclaw_plugin_permission_allow_once",
        "live_pii_input": "secretref_profile_not_tool_params",
    }, indent=2))
    if missing:
        raise SystemExit(1)


def cmd_plan_dummy(args: argparse.Namespace) -> None:
    subject = dummy_subject()
    plan = plan_for_subject(skill_dir_arg(args), subject)
    print(json.dumps(plan, indent=2, sort_keys=True))


def cmd_verify_link(args: argparse.Namespace) -> None:
    print(json.dumps(verify_link_scope(args.url, args.allowed_domain), indent=2, sort_keys=True))


def cmd_e2e_dummy(args: argparse.Namespace) -> None:
    skill_dir = skill_dir_arg(args)
    workdir = Path(args.workdir).expanduser()
    subject = dummy_subject()
    subject_id = subject["subject_id"]
    paths = save_subject(workdir, subject)
    plan = plan_for_subject(skill_dir, subject)
    add_dummy_fixture_cases(plan, ["submitted", "awaiting_verification", "awaiting_processing", "confirmed_removed", "reappeared", "human_task"])
    plan = simulate_dummy(plan)
    plan["revision"] = 1
    write_json(paths["plan"], plan)
    report = build_report(plan)
    write_json(paths["report"], report)
    append_jsonl(paths["audit"], {"at": now(), "event": "dummy_e2e_completed", "summary": report})
    print(json.dumps({"ok": True, "artifact_ref": f"subjects/{subject_id}/report.json", "report": report}, indent=2, sort_keys=True))


def cmd_scan_only_dummy(args: argparse.Namespace) -> None:
    skill_dir = skill_dir_arg(args)
    workdir = Path(args.workdir).expanduser()
    subject = dummy_subject()
    subject_id = subject["subject_id"]
    paths = save_subject(workdir, subject)
    plan = scan_only_plan_for_subject(skill_dir, subject)
    add_dummy_fixture_cases(plan, ["found", "not_found", "inconclusive"])
    plan = simulate_dummy_scan_only(plan)
    plan["revision"] = 1
    write_json(paths["plan"], plan)
    report = build_report(plan)
    write_json(paths["report"], report)
    append_jsonl(paths["audit"], {"at": now(), "event": "dummy_scan_only_completed", "summary": report})
    print(json.dumps({"ok": True, "artifact_ref": f"subjects/{subject_id}/report.json", "report": report}, indent=2, sort_keys=True))


def cmd_validate(args: argparse.Namespace) -> None:
    skill_dir = skill_dir_arg(args)
    plugin_root = skill_dir.parents[1]
    catalog = load_json(catalog_path(skill_dir))
    errors = validate_catalog_data(catalog)
    gdpr = (skill_dir / "references" / "legal" / "gdpr.md").read_text(encoding="utf-8")
    if "DSGVO" not in gdpr or "Article 17" not in gdpr:
        errors.append("gdpr reference must cover DSGVO and Article 17")
    manifest_path = plugin_root / "openclaw.plugin.json"
    if not manifest_path.is_file():
        errors.append("OpenClaw plugin manifest is missing")
    else:
        manifest = load_json(manifest_path)
        tool = manifest.get("toolMetadata", {}).get("rightout_live_scan", {})
        secret_paths = {
            item.get("path")
            for item in manifest.get("configContracts", {}).get("secretInputs", {}).get("paths", [])
            if isinstance(item, dict)
        }
        if manifest.get("id") != "rightout" or manifest.get("contracts", {}).get("tools") != ["rightout_live_scan"]:
            errors.append("OpenClaw plugin tool contract is inconsistent")
        if tool.get("optional") is not True or tool.get("replaySafe") is not False:
            errors.append("live tool must be optional and non-replay-safe")
        required_config = set((tool.get("configSignals") or [{}])[0].get("required", []))
        if "operatorAttestations" not in required_config:
            errors.append("live tool must require operator attestations")
        if {"braveApiKey", "profiles.*.payload"} - secret_paths:
            errors.append("live secrets must use declared SecretInput contracts")
    print(json.dumps({"ok": not errors, "errors": errors, "broker_count": len(catalog.get("brokers", [])), "catalog_schema_version": catalog.get("schema_version")}, indent=2))
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
    verify = sub.add_parser("verify-link")
    verify.add_argument("--url", required=True)
    verify.add_argument("--allowed-domain", action="append", required=True)
    e2e = sub.add_parser("e2e-dummy")
    e2e.add_argument("--workdir", required=True)
    scan_only = sub.add_parser("scan-only-dummy")
    scan_only.add_argument("--workdir", required=True)
    sub.add_parser("validate")
    args = parser.parse_args()
    if args.command == "doctor":
        cmd_doctor(args)
    elif args.command == "plan-dummy":
        cmd_plan_dummy(args)
    elif args.command == "verify-link":
        cmd_verify_link(args)
    elif args.command == "e2e-dummy":
        cmd_e2e_dummy(args)
    elif args.command == "scan-only-dummy":
        cmd_scan_only_dummy(args)
    elif args.command == "validate":
        cmd_validate(args)


if __name__ == "__main__":
    main()
