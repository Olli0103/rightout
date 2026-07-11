# Contributing

RightOut is conservative by design. Contributions should improve safety, provenance, test coverage, or operator usability without weakening approval boundaries.

## Broker Catalog Changes

For each new broker or controller flow:

- use an official broker/controller URL where possible;
- include source provenance and a freshness date;
- write original notes instead of copying third-party prose;
- record jurisdiction and lane accurately;
- list only required disclosure field names, never sample PII;
- keep CAPTCHA, phone, fax, mail, government-ID, and account-creation requirements as human tasks;
- add or update tests when behavior changes.

Do not import bulk datasets unless the license is compatible and attribution is documented in `THIRD_PARTY_NOTICES.md`.

## Safety Rules

- No live broker submissions in tests.
- No real PII in fixtures, paths, logs, reports, or screenshots.
- No provider writes without an explicit approval gate.
- No deletion claims until a recheck confirms the listing is gone.

## Validation

Run:

```bash
make test
make scan-only-dummy
make e2e-dummy
```

