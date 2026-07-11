# RightOut OpenClaw skill

Version `0.2.0`. This skill ships inside the RightOut OpenClaw plugin.

Live people-search discovery is available only through the optional `rightout_live_scan` tool and Brave Search. The tool accepts an opaque SecretRef-backed profile ID and supported broker IDs, then requires a native OpenClaw `allow-once` approval bound to Brave terms revision `2026-02-11`, customer responsibilities, exact profile, and search scope. It never requests a broker page and returns no raw PII, Search Result, API key, query, or URL.

The Python runner remains an offline, dummy-only validation harness:

```bash
python3 scripts/validate_data_broker_removal.py --skill-dir .
python3 scripts/data_broker_removal.py scan-only-dummy --workdir .tmp/rightout-scan-only
python3 scripts/data_broker_removal.py e2e-dummy --workdir .tmp/rightout-e2e
```

Report v3 separates catalog coverage from synthetic fixtures and includes full removal-state reporting for test coverage only. A live `indirect_exposure` means only that Brave returned an HTTPS result on the selected official domain. Index-negative or provider-failure cases remain `inconclusive`.

Catalog records are clean-room entries derived from official-source facts and URLs. Commercial service claims are used only in the repository's benchmark, never as RightOut evidence.
