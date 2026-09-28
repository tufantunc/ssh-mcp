#!/usr/bin/env bash
# Differential classification run: the branch base vs the working tree.
# Usage: scripts/differential-run.sh [base-ref]   (default 1ccee48)
set -euo pipefail
BASE_REF="${1:-1ccee48}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ssh-mcp-diff.XXXXXX")"
git -C "$ROOT" worktree add --detach "$WORK/base" "$BASE_REF"
trap 'git -C "$ROOT" worktree remove --force "$WORK/base" >/dev/null 2>&1; rm -rf "$WORK"' EXIT

# The base tree classifies the SAME corpus with its own sources and this
# tree's dependencies: same runner, same corpus, one symlink.
mkdir -p "$WORK/base/test/differential"
cp "$ROOT/test/differential/corpus.json" "$WORK/base/test/differential/"
cp "$ROOT/test/differential/runner.test.ts" "$WORK/base/test/differential/"
ln -s "$ROOT/node_modules" "$WORK/base/node_modules"

(cd "$ROOT" && SSH_MCP_DISABLE_MAIN=1 SSH_MCP_DIFFERENTIAL_OUT="$WORK/out-head.json" \
  npx vitest --run test/differential/runner.test.ts >/dev/null)
(cd "$WORK/base" && SSH_MCP_DISABLE_MAIN=1 SSH_MCP_DIFFERENTIAL_OUT="$WORK/out-base.json" \
  npx vitest --run test/differential/runner.test.ts >/dev/null)

node "$ROOT/scripts/differential-compare.mjs" "$WORK/out-base.json" "$WORK/out-head.json"
