# RightOut OpenClaw skill

Version `0.3.0`. This skill ships inside the RightOut plugin.

Live work uses two optional tools with separate native OpenClaw approvals:

- `rightout_live_scan`: Brave index-only discovery for supported brokers;
- `rightout_submit_removal`: one catalog-locked BeenVerified deletion/opt-out email for an attested `US-CA` profile.

Both accept opaque references only. Profiles, consent, provider credentials, and operator attestations stay in SecretRef-backed plugin config. A successful email result is only `submitted`; no current live path emits `confirmed_removed`.

The Python runner is an offline dummy validation harness:

```bash
python3 scripts/validate_data_broker_removal.py --skill-dir .
python3 scripts/data_broker_removal.py scan-only-dummy --workdir .tmp/rightout-scan-only
python3 scripts/data_broker_removal.py e2e-dummy --workdir .tmp/rightout-e2e
```

Report v4 separates catalog coverage, live semantics, and synthetic state-machine coverage. `fixture_only` results are never real-person evidence.

Catalog records are clean-room facts from official sources. Hermes Unbroker and commercial products are architecture/UX benchmarks only.
