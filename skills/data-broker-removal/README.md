# RightOut OpenClaw skill

Version `0.2.0-rc.1`. This skill ships inside the RightOut OpenClaw plugin.

Live people-search discovery is available only through the optional `rightout_live_scan` tool. It accepts an opaque SecretRef-backed profile ID and supported broker IDs, then requires a native OpenClaw `allow-once` approval. The result contains no raw PII, raw page content, API key, search query, or candidate URL. It performs no submissions, email, forms, scheduling, or provider writes.

The Python runner remains an offline, dummy-only validation harness:

```bash
python3 scripts/validate_data_broker_removal.py --skill-dir .
python3 scripts/data_broker_removal.py scan-only-dummy --workdir .tmp/rightout-scan-only
python3 scripts/data_broker_removal.py e2e-dummy --workdir .tmp/rightout-e2e
```

Report v3 separates catalog coverage from synthetic fixtures and includes full removal-state reporting for test coverage only. `found` live results mean one structured JSON-LD `Person` record on a query-free catalog-policy page matched exact full name and city/region; loose-text, index-negative, or blocked cases remain `inconclusive`.

Catalog records are clean-room entries derived from official-source facts and URLs. Commercial service claims are used only in the repository's benchmark, never as RightOut evidence.
