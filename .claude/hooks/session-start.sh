#!/bin/bash
# Ovid SessionStart hook (Claude Code on the web).
#
# Prepares a remote session so the observation/perf tests and the local
# gate work immediately:
#   1. installs `strace` — the boundary observer's backend; the
#      observation integration tests and perf guardrails need it
#      (see CLAUDE.md "Build, test, lint");
#   2. warms the cargo dependency + build cache so the first
#      `cargo test`/`cargo clippy` is not a cold compile.
#
# Runs only in the remote environment, is idempotent, and never blocks on
# input. It is intentionally best-effort: a step that cannot run (no apt,
# no network for a mirror) prints a note and the session still starts —
# the tests that need the missing piece will report it themselves.
set -uo pipefail

# Local (non-web) sessions already have the developer's own toolchain.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0

echo "[ovid session-start] preparing remote session"

# 1. strace — boundary observer backend (idempotent: skip if present).
if command -v strace >/dev/null 2>&1; then
  echo "[ovid session-start] strace already installed"
elif command -v apt-get >/dev/null 2>&1; then
  echo "[ovid session-start] installing strace"
  if command -v sudo >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y -qq strace \
      || echo "[ovid session-start] WARN: strace install failed; observation tests will be limited"
  else
    apt-get update -qq && apt-get install -y -qq strace \
      || echo "[ovid session-start] WARN: strace install failed; observation tests will be limited"
  fi
else
  echo "[ovid session-start] WARN: no apt-get; install strace manually for observation tests"
fi

# 2. Warm the cargo cache. `fetch --locked` primes deps from the committed
#    lockfile; the workspace build then populates the compile cache that
#    the container snapshots, so the first test/lint run is fast.
if command -v cargo >/dev/null 2>&1; then
  echo "[ovid session-start] fetching dependencies (locked)"
  cargo fetch --locked || echo "[ovid session-start] WARN: cargo fetch failed"
  echo "[ovid session-start] warming build cache (cargo build --workspace)"
  cargo build --workspace --locked || echo "[ovid session-start] WARN: warm build failed"
else
  echo "[ovid session-start] WARN: cargo not found on PATH"
fi

echo "[ovid session-start] done"
