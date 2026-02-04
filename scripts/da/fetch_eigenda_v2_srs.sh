#!/bin/bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/da/fetch_eigenda_v2_srs.sh

Optional env:
  EIGENDA_V2_SRS_DIR  destination directory (default: scripts/da/srs/eigenda_v2)

Outputs:
  Downloads SRS files and verifies checksums when sha256sum or shasum is available.

Exit codes:
  1 on download or verification failure.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
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

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SRS_DIR="${EIGENDA_V2_SRS_DIR:-$ROOT_DIR/scripts/da/srs/eigenda_v2}"
BASE_URL="https://raw.githubusercontent.com/Layr-Labs/eigenda/master/resources/srs"
MANIFEST="srs-files-16777216.sha256"

if [ -z "${SRS_DIR:-}" ] || [ "$SRS_DIR" = "/" ]; then
  echo "ERROR: invalid SRS dir: $SRS_DIR" >&2
  exit 2
fi

mkdir -p "$SRS_DIR"
mkdir -p "$SRS_DIR/SRSTables"

DOWNLOAD_CMD=""
if command -v curl >/dev/null 2>&1; then
  DOWNLOAD_CMD="curl"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOAD_CMD="wget"
else
  echo "ERROR: required command not found: curl or wget" >&2
  exit 2
fi

fetch() {
  local path="$1"
  local url="$2"
  local dest="$SRS_DIR/$path"
  local tmp="${dest}.tmp.$$"
  if [ -f "$dest" ]; then
    echo "$path already exists."
    return
  fi
  if [[ "$path" = /* ]] || [[ "$path" = *".."* ]]; then
    echo "ERROR: invalid path in manifest: $path" >&2
    exit 2
  fi
  mkdir -p "$(dirname "$dest")"
  if [ "$DOWNLOAD_CMD" = "curl" ]; then
    curl -fsSL "$url" -o "$tmp"
  else
    wget "$url" -O "$tmp"
  fi
  mv "$tmp" "$dest"
}

fetch "$MANIFEST" "$BASE_URL/$MANIFEST"

if [ ! -s "$SRS_DIR/$MANIFEST" ]; then
  echo "ERROR: manifest missing or empty: $SRS_DIR/$MANIFEST" >&2
  exit 2
fi

while read -r _hash path; do
  _hash="${_hash//$'\r'/}"
  path="${path//$'\r'/}"
  if [ -z "${path:-}" ]; then
    continue
  fi
  if [[ ! "$_hash" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "ERROR: invalid hash in manifest: $_hash $path" >&2
    exit 2
  fi
  path="${path#./}"
  path="${path#\*}"
  fetch "$path" "$BASE_URL/$path"
done < "$SRS_DIR/$MANIFEST"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$SRS_DIR" && sha256sum -c "$MANIFEST")
elif command -v shasum >/dev/null 2>&1; then
  (cd "$SRS_DIR" && shasum -a 256 -c "$MANIFEST")
else
  echo "WARN: sha256sum/shasum not found; skipping checksum verification." >&2
fi
