#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/utils/perf_summary.sh [run-json] [config-json]

Defaults:
  run-json     scripts/out/perf/perf_run.json
  config-json  scripts/out/perf/perf_config.json

Outputs:
  Prints a summary to stdout.

Exit codes:
  2 on missing input files or missing tools.
  1 on runtime failure.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 2
  fi
}

require_cmd python3

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEFAULT_RUN="$PROJECT_ROOT/scripts/out/perf/perf_run.json"
DEFAULT_CFG="$PROJECT_ROOT/scripts/out/perf/perf_config.json"

RUN_JSON="${1:-}"
CONFIG_JSON="${2:-}"
if [ -z "$RUN_JSON" ]; then
  RUN_JSON="$DEFAULT_RUN"
fi
if [ -z "$CONFIG_JSON" ]; then
  CONFIG_JSON="$DEFAULT_CFG"
fi

if [ ! -f "$RUN_JSON" ]; then
  echo "ERROR: run report not found: $RUN_JSON" >&2
  exit 2
fi
if [ ! -f "$CONFIG_JSON" ]; then
  echo "ERROR: perf config not found: $CONFIG_JSON" >&2
  exit 2
fi

python3 - <<'PY' "$RUN_JSON" "$CONFIG_JSON"
import json
import sys
from pathlib import Path

run_path = Path(sys.argv[1])
cfg_path = Path(sys.argv[2])

def read_json(path):
    if not path.exists():
        return None
    return json.loads(path.read_text())

run = read_json(run_path)
cfg = read_json(cfg_path)

print("perf summary")
if run:
    print(f"  timestamp: {run.get('timestamp')}")
    print(f"  pid: {run.get('pid')}")
    print(f"  cwd: {run.get('cwd')}")
    print(f"  exe: {run.get('exe')}")
    print(f"  perf_config_path: {run.get('perf_config_path')}")
else:
    print("  run report missing")

if cfg:
    present = sum(1 for e in cfg.get("entries", []) if e.get("present"))
    total = len(cfg.get("entries", []))
    print(f"  perf params set: {present}/{total}")
else:
    print("  perf config missing")
PY
