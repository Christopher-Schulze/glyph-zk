#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/benchmarks/bench_packed_gkr_layout_sweep.sh

Optional env:
  ARITIES
  PACK_FACTORS
  SEED
  REPEAT
  CHAINID
  CONTRACT
  RUSTUP_TOOLCHAIN
  OUT_DIR
  OUT_FILE

Outputs:
  Writes bench_v1 JSON to OUT_FILE.

Exit codes:
  2 on invalid input or missing tools.
  1 on runtime failure.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi
export COLUMNS="${COLUMNS:-120}"
export LINES="${LINES:-40}"
if command -v stty >/dev/null 2>&1; then
  stty cols "$COLUMNS" rows "$LINES" 2>/dev/null || true
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT_ROOT="$ROOT"
PROJECT_OUT="${PROJECT_OUT:-$ROOT/scripts/out}"
OUT_DIR="${OUT_DIR:-$PROJECT_OUT/benchmarks/packed_gkr_layout_sweep}"
OUT_FILE="${OUT_FILE:-$OUT_DIR/layout.json}"
mkdir -p "${OUT_DIR}"

source "$PROJECT_ROOT/scripts/benchmarks/common.sh"
bench_init "packed_gkr_layout_sweep"
require_cmd cargo

ARITIES="${ARITIES:-2,4,8,16}"
PACK_FACTORS="${PACK_FACTORS:-1,2,4}"
SEED="${SEED:-2779096485}"
REPEAT="${REPEAT:-8}"
CHAINID="${CHAINID:-31337}"
CONTRACT="${CONTRACT:-0x1111111111111111111111111111111111111111}"

bench_log_basic
bench_log_kv "arities" "$ARITIES"
bench_log_kv "pack_factors" "$PACK_FACTORS"
bench_log_kv "seed" "$SEED"
bench_log_kv "repeat" "$REPEAT"
bench_log_kv "chainid" "$CHAINID"
bench_log_kv "contract" "$CONTRACT"

export GLYPH_LAYOUT_ARITIES="${ARITIES}"
export GLYPH_LAYOUT_PACK_FACTORS="${PACK_FACTORS}"
export GLYPH_LAYOUT_SEED="${SEED}"
export GLYPH_LAYOUT_REPEAT="${REPEAT}"
export GLYPH_LAYOUT_CHAINID="${CHAINID}"
export GLYPH_LAYOUT_CONTRACT="${CONTRACT}"

export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"
cargo run --bin bench_glyph_packed_gkr_layout --no-default-features --features adapter-core,hash > "${OUT_FILE}"
echo "Wrote ${OUT_FILE}"
bench_finalize
