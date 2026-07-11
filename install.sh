#!/usr/bin/env bash
set -euo pipefail

SKILL_NAME="data-broker-removal"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$REPO_ROOT/skills/$SKILL_NAME"
TARGET_ROOT="${OPENCLAW_WORKSPACE:-$HOME/.openclaw/workspace}"
FORCE=0
VALIDATE=1

usage() {
  cat <<'EOF'
Usage: ./install.sh [--target-root PATH] [--force] [--no-validate]

Installs the RightOut OpenClaw skill to:
  $TARGET_ROOT/skills/data-broker-removal

Options:
  --target-root PATH  OpenClaw workspace root. Defaults to ~/.openclaw/workspace
  --force             Back up and replace an existing skill install
  --no-validate       Skip post-install validator
  -h, --help          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-root)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --target-root" >&2
        exit 2
      fi
      TARGET_ROOT="$2"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --no-validate)
      VALIDATE=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "$SOURCE_DIR" ]]; then
  echo "source skill not found: $SOURCE_DIR" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

TARGET_SKILLS="$TARGET_ROOT/skills"
TARGET_DIR="$TARGET_SKILLS/$SKILL_NAME"
mkdir -p "$TARGET_SKILLS"

STAGING="$(mktemp -d "$TARGET_SKILLS/.${SKILL_NAME}.staging.XXXXXX")"
cleanup() {
  rm -rf "$STAGING"
}
trap cleanup EXIT

if [[ -e "$TARGET_DIR" ]]; then
  if [[ "$FORCE" != "1" ]]; then
    echo "target already exists: $TARGET_DIR" >&2
    echo "rerun with --force to back it up and replace it" >&2
    exit 1
  fi
fi

cp -R "$SOURCE_DIR"/. "$STAGING"/

if [[ "$VALIDATE" == "1" ]]; then
  python3 "$STAGING/scripts/validate_data_broker_removal.py" --skill-dir "$STAGING"
fi

backup=""
if [[ -e "$TARGET_DIR" ]]; then
  backup="${TARGET_DIR}.backup.$(date -u +%Y%m%dT%H%M%SZ).$$"
  mv "$TARGET_DIR" "$backup"
  echo "Backed up existing install to: $backup"
fi

mv "$STAGING" "$TARGET_DIR"
trap - EXIT

cat <<EOF
RightOut installed.

Skill: $TARGET_DIR
Validate: python3 "$TARGET_DIR/scripts/validate_data_broker_removal.py" --skill-dir "$TARGET_DIR"
Dummy scan: python3 "$TARGET_DIR/scripts/data_broker_removal.py" --skill-dir "$TARGET_DIR" scan-only-dummy --workdir .tmp/rightout-scan-only
EOF
