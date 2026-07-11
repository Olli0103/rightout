#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
OPENCLAW_BIN="${OPENCLAW_BIN:-openclaw}"
FORCE=0
LINK=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [--force] [--link]

Validates and installs the complete RightOut OpenClaw plugin. OpenClaw owns the
copy/link, config registration, dependency install, and replacement behavior.

Options:
  --force  Replace an existing RightOut plugin registration
  --link   Link this checkout for development instead of copying it
  -h       Show this help

Environment:
  OPENCLAW_BIN  OpenClaw executable (default: openclaw)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1 ;;
    --link) LINK=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown installer argument" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [[ ! -x "$OPENCLAW_BIN" ]] && ! command -v "$OPENCLAW_BIN" >/dev/null 2>&1; then
  echo "OpenClaw 2026.6.11 or newer is required" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for package validation" >&2
  exit 1
fi
if [[ "$LINK" != "1" ]] && ! command -v npm >/dev/null 2>&1; then
  echo "npm is required to build the release archive" >&2
  exit 1
fi
if find "$REPO_ROOT" \( -path "$REPO_ROOT/node_modules" -o -path "$REPO_ROOT/.git" -o -path "$REPO_ROOT/.tmp" \) -prune -o -type l -print -quit | grep -q .; then
  echo "source package contains a symlink" >&2
  exit 1
fi

python3 "$REPO_ROOT/skills/data-broker-removal/scripts/validate_data_broker_removal.py" \
  --skill-dir "$REPO_ROOT/skills/data-broker-removal" >/dev/null

version_output="$($OPENCLAW_BIN --version)"
python3 - "$version_output" <<'PY'
import re
import sys

value = sys.argv[1]
match = re.search(r"\b(\d{4})\.(\d+)\.(\d+)\b", value)
if not match or tuple(map(int, match.groups())) < (2026, 6, 11):
    raise SystemExit("OpenClaw 2026.6.11 or newer is required")
PY

package_source="$REPO_ROOT"
pack_dir=""
inspection=""
transaction_dir="$(mktemp -d -t rightout-install.XXXXXX)"
mutation_started=0
install_succeeded=0
lock_acquired=0
lock_dir=""
early_cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ "$lock_acquired" == "1" ]]; then
    rmdir "$lock_dir" 2>/dev/null || status=1
  fi
  rm -rf "$transaction_dir"
  exit "$status"
}
trap early_cleanup EXIT INT TERM
chmod 700 "$transaction_dir"
config_path_raw="$($OPENCLAW_BIN config file)"
config_path="$(python3 - "$config_path_raw" <<'PY'
import os
import sys

print(os.path.abspath(os.path.expanduser(sys.argv[1].strip())))
PY
)"
state_root="$(python3 - "${OPENCLAW_STATE_DIR:-$(dirname "$config_path")}" <<'PY'
import os
import sys

print(os.path.abspath(os.path.expanduser(sys.argv[1])))
PY
)"
managed_extensions="$state_root/extensions"
extension_path="$managed_extensions/rightout"
lock_dir="$state_root/.rightout-install.lock"
config_existed=0
previous_extension=0

python3 - "$state_root" "$config_path" <<'PY'
import os
import sys
from pathlib import Path

def reject_symlink_ancestors(value: str, include_target: bool) -> None:
    path = Path(value)
    parts = path.parts
    current = Path(parts[0])
    limit = len(parts) if include_target else len(parts) - 1
    for part in parts[1:limit]:
        current /= part
        if current.is_symlink():
            raise SystemExit(f"installer path contains a symlink ancestor: {value}")

state_root, config_path = sys.argv[1:]
reject_symlink_ancestors(state_root, True)
reject_symlink_ancestors(config_path, False)
managed_extensions = os.path.join(state_root, "extensions")
if os.path.lexists(managed_extensions) and os.path.islink(managed_extensions):
    raise SystemExit("OpenClaw managed extensions directory must not be a symlink")
PY

if ! mkdir "$lock_dir" 2>/dev/null; then
  echo "another RightOut installer transaction is active; remove the stale .rightout-install.lock only after manually verifying that no installer is running" >&2
  exit 1
fi
lock_acquired=1
chmod 700 "$lock_dir"

if [[ -L "$config_path" ]]; then
  echo "OpenClaw config path must not be a symlink" >&2
  exit 1
fi
if [[ -f "$config_path" ]]; then
  cp -p "$config_path" "$transaction_dir/openclaw.json"
  config_existed=1
fi

previous_inspection="$transaction_dir/previous-inspection.json"
if "$OPENCLAW_BIN" plugins inspect rightout --json >"$previous_inspection" 2>/dev/null; then
  previous_path="$(python3 - "$previous_inspection" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
print(data.get("install", {}).get("installPath", ""))
PY
)"
  previous_path="$(python3 - "$previous_path" <<'PY'
import os
import sys

print(os.path.abspath(os.path.expanduser(sys.argv[1])))
PY
)"
  if [[ "$previous_path" == "$extension_path" && -L "$previous_path" ]]; then
    echo "managed RightOut extension must not be a symlink" >&2
    exit 1
  fi
  if [[ "$previous_path" == "$extension_path" && -e "$previous_path" ]]; then
    tar -cpf "$transaction_dir/rightout.tar" -C "$managed_extensions" "rightout"
    previous_extension=1
  fi
fi

rollback_install() {
  echo "RightOut install validation failed; restoring the previous OpenClaw state" >&2
  python3 - "$extension_path" "$managed_extensions" <<'PY'
import os
import shutil
import sys

path = os.path.abspath(sys.argv[1])
managed_extensions = os.path.abspath(sys.argv[2])
if path != os.path.join(managed_extensions, "rightout") or os.path.dirname(path) != managed_extensions:
    raise SystemExit("unsafe rollback extension path")
if os.path.islink(path):
    os.unlink(path)
elif os.path.isdir(path):
    shutil.rmtree(path)
elif os.path.exists(path):
    os.unlink(path)
PY
  if [[ "$previous_extension" == "1" ]]; then
    mkdir -p "$managed_extensions"
    tar -xpf "$transaction_dir/rightout.tar" -C "$managed_extensions"
  fi
  if [[ "$config_existed" == "1" ]]; then
    config_tmp="$(dirname "$config_path")/.rightout-rollback.$$"
    cp -p "$transaction_dir/openclaw.json" "$config_tmp"
    mv -f "$config_tmp" "$config_path"
  else
    rm -f "$config_path"
  fi
}

finish() {
  status=$?
  trap - EXIT INT TERM
  if [[ "$mutation_started" == "1" && "$install_succeeded" != "1" ]]; then
    rollback_install || status=1
  fi
  [[ -z "$inspection" ]] || rm -f "$inspection"
  [[ -z "$pack_dir" ]] || rm -rf "$pack_dir"
  rm -rf "$transaction_dir"
  if [[ "$lock_acquired" == "1" ]]; then
    rmdir "$lock_dir" 2>/dev/null || status=1
    lock_acquired=0
  fi
  exit "$status"
}
trap finish EXIT INT TERM
if [[ "$LINK" != "1" ]]; then
  pack_dir="$(mktemp -d -t rightout-pack.XXXXXX)"
  package_source="$(npm pack "$REPO_ROOT" --pack-destination "$pack_dir" --silent | tail -n 1)"
  package_source="$pack_dir/$package_source"
  if [[ ! -f "$package_source" ]]; then
    echo "npm did not produce the RightOut release archive" >&2
    exit 1
  fi
fi

install_args=(plugins install "$package_source")
if [[ "$FORCE" == "1" ]]; then install_args+=(--force); fi
if [[ "$LINK" == "1" ]]; then install_args+=(--link); fi
mutation_started=1
"$OPENCLAW_BIN" "${install_args[@]}"

inspection="$(mktemp -t rightout-inspect.XXXXXX)"
"$OPENCLAW_BIN" plugins inspect rightout --runtime --json >"$inspection"
python3 - "$inspection" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
plugin = data.get("plugin", {})
typed_hooks = {item.get("name") for item in data.get("typedHooks", [])}
tools = {name for item in data.get("tools", []) for name in item.get("names", [])}
if plugin.get("status") != "loaded":
    raise SystemExit("RightOut runtime inspection did not report loaded")
if "rightout_live_scan" not in tools or "before_tool_call" not in typed_hooks:
    raise SystemExit("RightOut live tool or native approval hook is missing")
PY
"$OPENCLAW_BIN" plugins doctor
install_succeeded=1

cat <<EOF
RightOut plugin installed and runtime-validated.

Version: $(tr -d '\n' < "$REPO_ROOT/VERSION")
Tool: rightout_live_scan (optional, non-replay-safe)
Approval: native OpenClaw allow-once/deny, fail closed
PII input: operator-configured SecretRef profile only
Live scan readiness: install complete; provider/profile SecretRefs still required
EOF
