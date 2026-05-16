#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMAND="${1:-campaign}"
CONFIG_PATH="${BLINDREVOKE_BENCH_CONFIG:-$ROOT_DIR/tests/blindrevoke.config.json}"
OUTPUT_DIR="${BLINDREVOKE_BENCH_OUTPUT_DIR:-}"

ARGS=(
  "$ROOT_DIR/tests/blindrevoke-bench.js"
  "$COMMAND"
  "--config"
  "$CONFIG_PATH"
)

if [[ -n "$OUTPUT_DIR" ]]; then
  ARGS+=("--output-dir" "$OUTPUT_DIR")
fi

node "${ARGS[@]}"
