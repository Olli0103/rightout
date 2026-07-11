# Security Policy

RightOut handles privacy-sensitive workflows and should be treated as approval-bound tooling.

## Supported Use

Use dummy validation only in the public runner. Do not process real PII, persist live dossiers, query live brokers, submit forms, send emails, schedule automation, or write to providers until a platform-owned OpenClaw approval adapter exists.

## Reporting Issues

Please open a GitHub security advisory or private report for:

- PII leakage in logs, paths, reports, or fixtures;
- approval-gate bypasses;
- unsafe live submission paths;
- incorrect `confirmed_removed` state transitions;
- copied third-party broker-list content without compatible license handling.

Do not include real personal data in reports.
