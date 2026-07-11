# Install RightOut

RightOut is an OpenClaw workspace skill. The installer copies the skill into an OpenClaw workspace and validates it locally.

## One-Line Install

```bash
git clone https://github.com/Olli0103/rightout.git
cd rightout
./install.sh
```

By default this installs to:

```text
~/.openclaw/workspace/skills/data-broker-removal
```

## Update An Existing Install

```bash
./install.sh --force
```

`--force` does not delete the existing skill outright. It moves the previous install to a timestamped backup next to the target, then installs the new copy.

## Install To A Custom Workspace

```bash
./install.sh --target-root /path/to/openclaw/workspace
```

or:

```bash
OPENCLAW_WORKSPACE=/path/to/openclaw/workspace ./install.sh
```

## Validate

The installer runs:

```bash
python3 ~/.openclaw/workspace/skills/data-broker-removal/scripts/validate_data_broker_removal.py \
  --skill-dir ~/.openclaw/workspace/skills/data-broker-removal
```

Skip validation only when you are packaging or debugging:

```bash
./install.sh --no-validate
```

## After Install

Use the skill when asking OpenClaw to audit, scan-only review, plan, or stage data-broker removal work.

Start with dummy checks:

```bash
python3 ~/.openclaw/workspace/skills/data-broker-removal/scripts/data_broker_removal.py \
  --skill-dir ~/.openclaw/workspace/skills/data-broker-removal doctor
python3 ~/.openclaw/workspace/skills/data-broker-removal/scripts/data_broker_removal.py \
  --skill-dir ~/.openclaw/workspace/skills/data-broker-removal scan-only-dummy --workdir .tmp/rightout-scan-only
```

## Safety

RightOut does not perform live scans, submit forms, send email, schedule rechecks, or write provider data without explicit approval gates. Dummy validation does not require real PII.

