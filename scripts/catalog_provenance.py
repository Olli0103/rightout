#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "skills/data-broker-removal/references/brokers/core.json"
REPORT = ROOT / "docs/catalog-provenance.json"


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def expected() -> dict[str, object]:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    source_facts = []
    for broker in sorted(catalog["brokers"], key=lambda item: item["id"]):
        source_facts.append({
            "id": broker["id"],
            "official_url": broker["official_url"],
            "human_action_url": broker.get("human_action_url"),
            "official_domains": sorted(broker["official_domains"]),
            "last_verified": broker["last_verified"],
            "sources": sorted(
                ({key: source[key] for key in ["url", "publisher", "fact_scope", "last_verified"]} for source in broker["sources"]),
                key=lambda item: (item["url"], item["publisher"]),
            ),
        })
    return {
        "schema_version": 1,
        "catalog_id": catalog["catalog_id"],
        "catalog_schema_version": catalog["schema_version"],
        "broker_count": len(catalog["brokers"]),
        "source_count": sum(len(item["sources"]) for item in catalog["brokers"]),
        "catalog_sha256": hashlib.sha256(CATALOG.read_bytes()).hexdigest(),
        "normalized_source_facts_sha256": hashlib.sha256(canonical(source_facts)).hexdigest(),
    }


def main() -> None:
    generated = expected()
    if len(sys.argv) == 2 and sys.argv[1] == "--print":
        print(json.dumps(generated, indent=2, sort_keys=True))
        return
    if len(sys.argv) != 2 or sys.argv[1] != "--check":
        raise SystemExit("usage: catalog_provenance.py --check|--print")
    try:
        committed = json.loads(REPORT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"catalog provenance report unavailable: {exc}") from None
    if committed != generated:
        raise SystemExit("catalog provenance report is stale; review source facts and regenerate intentionally")
    print(json.dumps({"ok": True, **generated}, sort_keys=True))


if __name__ == "__main__":
    main()
