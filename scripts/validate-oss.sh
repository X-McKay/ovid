#!/usr/bin/env bash
# Open-source validation suite (see .claude/skills/oss-validation and
# docs/VALIDATION.md).
#
# Clones pinned refs of real repositories of varying complexity, runs
# `ovid inventory` (all) and an observed workload (where cheap), measures
# wall time, and computes inventory accuracy against independent ground
# truth (cargo metadata, package manifests). Results are written to
# validation-workdir/results.md.
#
# Network note: acquisition and ground-truth commands run on the host and
# use whatever proxy configuration the host has. Observed workloads run in
# Ovid's scrubbed sandbox; pass-through of proxy variables is explicit via
# OVID_VALIDATE_INHERIT below.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OVID="${OVID_BIN:-$ROOT/target/release/ovid}"
WORK="$ROOT/validation-workdir"
RESULTS="$WORK/results.md"

# Environment variables observed workloads may need for toolchains and
# proxied networking. Only names listed here are passed through.
INHERIT_VARS=(PATH HOME https_proxy HTTPS_PROXY http_proxy HTTP_PROXY no_proxy NO_PROXY \
    SSL_CERT_FILE CARGO_HTTP_CAINFO CURL_CA_BUNDLE GIT_SSL_CAINFO REQUESTS_CA_BUNDLE CARGO_HOME RUSTUP_HOME)
INHERIT_ARGS=()
for var in "${INHERIT_VARS[@]}"; do
    INHERIT_ARGS+=(--inherit-env "$var")
done

mkdir -p "$WORK"
: > "$RESULTS"

if [ ! -x "$OVID" ]; then
    echo "building release binary…"
    (cd "$ROOT" && cargo build --release -p ovid-cli -q)
fi

log() { echo "[validate] $*" >&2; }

# ---------------------------------------------------------------------------
# Repo table: name | url | ref | ecosystem
# ---------------------------------------------------------------------------
REPOS=(
  "fd|https://github.com/sharkdp/fd|master|rust"
  "ripgrep|https://github.com/BurntSushi/ripgrep|master|rust"
  "flask|https://github.com/pallets/flask|main|python"
  "express|https://github.com/expressjs/express|master|node"
  "gin|https://github.com/gin-gonic/gin|master|go"
  "tokio|https://github.com/tokio-rs/tokio|master|rust-workspace"
)

echo "# OSS validation results" >> "$RESULTS"
echo "" >> "$RESULTS"
echo "Host: $(nproc) CPUs, $(free -m | awk '/^Mem:/{print $2}') MiB RAM, $(uname -r)" >> "$RESULTS"
echo "Ovid commit: $(git -C "$ROOT" rev-parse --short HEAD)" >> "$RESULTS"
echo "" >> "$RESULTS"
echo "| Repo | Rev | Files | Inventory wall (ms) | Components (decl/res) | Accuracy | Notes |" >> "$RESULTS"
echo "|---|---|---:|---:|---|---|---|" >> "$RESULTS"

for entry in "${REPOS[@]}"; do
    IFS='|' read -r name url ref eco <<< "$entry"
    out="$WORK/$name"
    log "=== $name ($eco) ==="
    rm -rf "$out"

    start_ms=$(date +%s%3N)
    "$OVID" inventory "$url" --ref "$ref" --out "$out" > "$WORK/$name.summary.txt" 2>&1 || {
        echo "| $name | clone-failed | - | - | - | - | acquisition failed |" >> "$RESULTS"
        continue
    }
    end_ms=$(date +%s%3N)
    # Re-run on the cached clone to time pure inventory (excluding network
    # transfer, per spec §12.2's measurement rule).
    start2_ms=$(date +%s%3N)
    "$OVID" inventory "$url" --ref "$ref" --out "$out" > /dev/null 2>&1
    end2_ms=$(date +%s%3N)
    inv_ms=$((end2_ms - start2_ms))
    total_ms=$((end_ms - start_ms))
    log "$name: cold ${total_ms}ms, warm inventory ${inv_ms}ms"

    repo_dir=$(python3 - "$out" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]+"/ovid.json"))
print(m["repository"]["canonical_url"], m["repository"]["revision"][:10], m["repository"]["file_count"])
PY
)
    # Find the on-disk clone used (content-addressed under out/.workdir).
    clone_dir=$(find "$out/.workdir/sources" -maxdepth 1 -mindepth 1 -type d | head -1)

    accuracy=$(python3 "$ROOT/scripts/accuracy.py" "$out/ovid.json" "$clone_dir" "$eco" 2>>"$WORK/$name.summary.txt" || echo "n/a")
    read -r _url rev files <<< "$repo_dir"

    decl_res=$(python3 - "$out" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]+"/ovid.json"))
cs=m["inventory"]["components"]
print(f"{sum(1 for c in cs if c['states'].get('declared'))}/{sum(1 for c in cs if c['states'].get('resolved'))} of {len(cs)}")
PY
)
    echo "| $name | $rev | $files | $inv_ms | $decl_res | $accuracy | cold acquire+inventory ${total_ms}ms |" >> "$RESULTS"
done

# ---------------------------------------------------------------------------
# Observed workload demonstrations (dynamic boundary evidence on real repos)
# ---------------------------------------------------------------------------
echo "" >> "$RESULTS"
echo "## Observed workloads" >> "$RESULTS"
echo "" >> "$RESULTS"

observe_case() {
    local name="$1" locator="$2" ref="$3" cmd="$4" timeout="$5"
    local out="$WORK/$name-observe"
    rm -rf "$out"
    log "observe $name: $cmd"
    local start_ms end_ms
    start_ms=$(date +%s%3N)
    if "$OVID" observe "$locator" --ref "$ref" --run "$cmd" --timeout "$timeout" \
        "${INHERIT_ARGS[@]}" --out "$out" > "$WORK/$name-observe.summary.txt" 2>&1; then
        end_ms=$(date +%s%3N)
        python3 - "$out" "$name" "$cmd" "$((end_ms - start_ms))" <<'PY' >> "$RESULTS"
import json,sys
m=json.load(open(sys.argv[1]+"/ovid.json"))
w=m["workloads"][0]
c=m["completeness"]
ext=len(m["external_systems"]); unres=len(m["unresolved"]); tools=len(m["build"]["tools"])
print(f"- **{sys.argv[2]}** — `{sys.argv[3]}` — {w['status']} in {w['duration_ms']} ms "
      f"(pipeline total {sys.argv[4]} ms); events {c['events_captured']} captured / "
      f"{c['events_collapsed']} collapsed / {c['noise_dropped']} noise; "
      f"{ext} external system(s), {tools} missing tool(s), {unres} unresolved")
PY
    else
        echo "- **$name** — \`$cmd\` — pipeline failed (see $name-observe.summary.txt)" >> "$RESULTS"
    fi
}

# Python import via stdlib only (fails fast if flask cannot import: that
# failure evidence is the point).
observe_case "flask" "https://github.com/pallets/flask" "main" "python3 -c 'import flask' || true" 120
# Rust: metadata + lockfile verification exercises heavy file boundaries.
observe_case "fd" "https://github.com/sharkdp/fd" "master" "cargo metadata --format-version 1 --offline > /dev/null" 300
# Rust: full debug build of a small crate under observation (network via proxy).
observe_case "fd-build" "https://github.com/sharkdp/fd" "master" "cargo build -q" 1800

echo "" >> "$RESULTS"
echo "Generated $(date -u +%FT%TZ)" >> "$RESULTS"
log "done -> $RESULTS"
