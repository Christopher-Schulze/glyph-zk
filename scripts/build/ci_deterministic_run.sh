#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  scripts/build/ci_deterministic_run.sh [options]

Options:
  --preset NAME        Build preset (default: default)
  --adapters LIST      Adapter list (comma-separated or "all")
  --features LIST      Extra cargo feature list (comma-separated)
  --cmd build|test     Run build or tests (default: build)
  --profile NAME       Cargo profile (release-fast, release, etc)
  --no-release         Disable --release for builds
  -h, --help           Show this help text

Key env:
  RUN_ID, OUT_DIR, CLEAN_ON_STALE
  RUSTUP_TOOLCHAIN, RUSTFLAGS, RUST_MIN_STACK
  GLYPH_ACCEL_PROFILE, GLYPH_PCS_BASEFOLD_PAR_MIN, GLYPH_STWO_PAR_MIN

Outputs:
  scripts/out/ci/<run_id>_<preset>_<cmd>.meta.json
  scripts/out/ci/<run_id>_<preset>_<cmd>.clean.json

Exit codes:
  0 on success
  2 on invalid input
  1 on runtime failure
USAGE
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $cmd" >&2
    exit 2
  fi
}

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT_OUT="${PROJECT_OUT:-$PROJECT_ROOT/scripts/out}"
cd "$PROJECT_ROOT"

require_cmd python3
require_cmd cargo
require_cmd rustc
require_cmd rustup
require_cmd git

merge_features() {
  local base="$1"
  local extra="$2"
  local combined=""
  local item
  for item in ${base//,/ } ${extra//,/ }; do
    item="$(echo "$item" | tr '[:upper:]' '[:lower:]' | xargs)"
    [[ -z "$item" ]] && continue
    if [[ ",$combined," != *",$item,"* ]]; then
      if [[ -z "$combined" ]]; then
        combined="$item"
      else
        combined="${combined},${item}"
      fi
    fi
  done
  echo "$combined"
}

PRESET="default"
ADAPTERS=""
FEATURES=""
CMD="build"
PROFILE=""
RELEASE=1
CLEAN_ON_STALE="${CLEAN_ON_STALE:-1}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --preset)
            PRESET="${2:-}"
            shift 2
            ;;
        --adapters)
            ADAPTERS="${2:-}"
            shift 2
            ;;
        --features)
            FEATURES="${2:-}"
            shift 2
            ;;
        --cmd)
            CMD="${2:-}"
            shift 2
            ;;
        --profile)
            PROFILE="${2:-}"
            shift 2
            ;;
        --no-release)
            RELEASE=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/ci}"
mkdir -p "$OUT_DIR"
META_PATH="$OUT_DIR/${RUN_ID}_${PRESET}_${CMD}.meta.json"
CLEAN_PATH="$OUT_DIR/${RUN_ID}_${PRESET}_${CMD}.clean.json"

if [ -n "$PROFILE" ]; then
    RELEASE=0
fi

target_size_kb() {
    if [ -d "$PROJECT_ROOT/target" ]; then
        du -sk "$PROJECT_ROOT/target" | awk '{print $1}'
    else
        echo "0"
    fi
}

cache_state() {
    python3 - <<'PY' "$PROJECT_ROOT"
import os, sys
root = sys.argv[1]
target = os.path.join(root, "target")
if not os.path.isdir(target):
    print("absent")
    raise SystemExit(0)
rustc_info = os.path.join(target, ".rustc_info.json")
if not os.path.isfile(rustc_info):
    print("stale")
    raise SystemExit(0)
cargo_lock = os.path.join(root, "Cargo.lock")
try:
    lock_mtime = os.path.getmtime(cargo_lock)
    rustc_mtime = os.path.getmtime(rustc_info)
except Exception:
    print("stale")
    raise SystemExit(0)
print("ok" if rustc_mtime >= lock_mtime else "stale")
PY
}

cache_before_kb="$(target_size_kb)"
cache_status="$(cache_state)"
cache_action="none"

if [ "$cache_status" != "ok" ] && [ "$CLEAN_ON_STALE" = "1" ]; then
    cache_action="cargo_clean"
    cargo clean -p glyph
fi

cache_after_kb="$(target_size_kb)"
python3 - <<'PY' "$CLEAN_PATH" "$RUN_ID" "$cache_status" "$cache_action" "$cache_before_kb" "$cache_after_kb"
import json, sys
out = {
    "run_id": sys.argv[2],
    "cache_status": sys.argv[3],
    "cache_action": sys.argv[4],
    "size_kb_before": int(sys.argv[5]),
    "size_kb_after": int(sys.argv[6]),
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)
PY

python3 - <<'PY' "$META_PATH" "$RUN_ID" "$PRESET" "$CMD" "$ADAPTERS" "$FEATURES" "$PROFILE" "$RELEASE"
import json, os, platform, subprocess, sys

def cmd_out(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8").strip()
    except Exception:
        return ""

def env_pick(*keys):
    out = {}
    for k in keys:
        v = os.environ.get(k)
        if v is not None:
            out[k] = v
    return out

meta = {
    "run_id": sys.argv[2],
    "preset": sys.argv[3],
    "cmd": sys.argv[4],
    "adapters": sys.argv[5],
    "features": sys.argv[6],
    "profile": sys.argv[7],
    "release": sys.argv[8] == "1",
    "timestamp": cmd_out(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"]),
    "git_commit": cmd_out(["git", "rev-parse", "--short", "HEAD"]),
    "rustc": cmd_out(["rustc", "-V"]),
    "cargo": cmd_out(["cargo", "-V"]),
    "rustup_toolchain": cmd_out(["rustup", "show", "active-toolchain"]),
    "os": platform.platform(),
    "cpu": cmd_out(["bash", "-lc", "sysctl -n machdep.cpu.brand_string 2>/dev/null || lscpu | awk -F: '/Model name/ {print $2}' | sed 's/^ *//g' | head -n 1"]),
    "env": env_pick(
        "RUSTUP_TOOLCHAIN",
        "RUSTFLAGS",
        "RUST_MIN_STACK",
        "GLYPH_ACCEL_PROFILE",
        "GLYPH_PCS_BASEFOLD_PAR_MIN",
        "GLYPH_STWO_PAR_MIN",
        "GLYPH_PCS_BASEFOLD_CPU_ONLY",
        "GLYPH_BN254_SIMD",
        "GLYPH_BN254_MUL_MONT",
        "GLYPH_SKIP_FUZZ",
        "NVCC",
    ),
}

with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2)
PY

BUILD_ARGS=(--preset "$PRESET")
if [ -n "$ADAPTERS" ]; then
    BUILD_ARGS+=(--adapters "$ADAPTERS")
fi
if [ -n "$FEATURES" ]; then
    BUILD_ARGS+=(--features "$FEATURES")
fi
if [ -n "$PROFILE" ]; then
    BUILD_ARGS+=(--profile "$PROFILE")
fi
if [ "$RELEASE" = "1" ]; then
    BUILD_ARGS+=(--release)
fi

case "$CMD" in
    build)
        bash scripts/build/glyph_build.sh "${BUILD_ARGS[@]}"
        ;;
    test)
        export GLYPH_TEST_PROFILE="${PROFILE:-release-fast}"
        TEST_NO_DEFAULT=0
        TEST_FEATURES=""
        case "$PRESET" in
            default)
                ;;
            core)
                TEST_NO_DEFAULT=1
                TEST_FEATURES="adapter-core"
                ;;
            snark)
                TEST_NO_DEFAULT=1
                TEST_FEATURES="adapter-core,snark"
                ;;
            ivc)
                TEST_NO_DEFAULT=1
                TEST_FEATURES="adapter-core,ivc"
                ;;
            hash)
                TEST_NO_DEFAULT=1
                TEST_FEATURES="adapter-core,hash"
                ;;
            binius)
                TEST_NO_DEFAULT=1
                TEST_FEATURES="adapter-core,binius"
                ;;
            stark-babybear)
                TEST_NO_DEFAULT=1
                TEST_FEATURES="adapter-core,stark-babybear"
                ;;
            stark-goldilocks)
                TEST_NO_DEFAULT=1
                TEST_FEATURES="adapter-core,stark-goldilocks"
                ;;
            stark-m31)
                TEST_NO_DEFAULT=1
                TEST_FEATURES="adapter-core,stark-m31"
                ;;
            cuda)
                TEST_NO_DEFAULT=1
                TEST_FEATURES="adapter-core,cuda"
                ;;
            full)
                TEST_NO_DEFAULT=1
                TEST_FEATURES="full"
                ;;
            *)
                ;;
        esac
        if [ -n "$FEATURES" ]; then
            TEST_FEATURES="$(merge_features "$TEST_FEATURES" "$FEATURES")"
        fi
        if [ "$TEST_NO_DEFAULT" = "1" ]; then
            export GLYPH_TEST_NO_DEFAULT=1
        fi
        if [ -n "$TEST_FEATURES" ]; then
            export GLYPH_TEST_FEATURES="$TEST_FEATURES"
        fi
        bash scripts/tests/run_tests.sh
        ;;
    *)
        echo "ERROR: unknown cmd: $CMD" >&2
        exit 2
        ;;
esac
