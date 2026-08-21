#!/usr/bin/env bash
# Open-source validation suite (see .claude/skills/oss-validation and
# docs/VALIDATION.md).
#
# Clones pinned refs of real repositories of varying complexity, runs
# `ovid inspect` (all) and `ovid prove` on explicit workloads (where
# cheap), measures wall time, and computes inventory accuracy against
# independent ground truth (cargo metadata, package manifests). Results
# are written to validation-workdir/results.md.
#
# Network note: acquisition and ground-truth commands run on the host and
# use whatever proxy configuration the host has. Observed workloads run in
# Ovid's scrubbed sandbox; pass-through of proxy variables is explicit via
# OVID_VALIDATE_INHERIT below.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OVID="${OVID_BIN:-$ROOT/target/release/ovid}"
# The workdir must live OUTSIDE the Ovid cargo workspace: ground-truth
# `cargo metadata` runs inside the clones and must not walk up into
# Ovid's own workspace manifest.
WORK="${OVID_VALIDATION_WORKDIR:-${TMPDIR:-/tmp}/ovid-validation-workdir}"
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
echo "| Repo | Rev | Files | Inspect wall (ms) | Components (decl/res) | Accuracy | Notes |" >> "$RESULTS"
echo "|---|---|---:|---:|---|---|---|" >> "$RESULTS"

for entry in "${REPOS[@]}"; do
    IFS='|' read -r name url ref eco <<< "$entry"
    out="$WORK/$name"
    log "=== $name ($eco) ==="
    rm -rf "$out"

    start_ms=$(date +%s%3N)
    "$OVID" inspect "$url" --ref "$ref" --out "$out" > "$WORK/$name.summary.txt" 2>&1 || {
        echo "| $name | clone-failed | - | - | - | - | acquisition failed |" >> "$RESULTS"
        continue
    }
    end_ms=$(date +%s%3N)
    # Re-run on the cached clone to time pure inventory (excluding network
    # transfer, per spec §12.2's measurement rule).
    start2_ms=$(date +%s%3N)
    "$OVID" inspect "$url" --ref "$ref" --out "$out" > /dev/null 2>&1
    end2_ms=$(date +%s%3N)
    inv_ms=$((end2_ms - start2_ms))
    total_ms=$((end_ms - start_ms))
    log "$name: cold ${total_ms}ms, warm inspect ${inv_ms}ms"

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
    echo "| $name | $rev | $files | $inv_ms | $decl_res | $accuracy | cold acquire+inspect ${total_ms}ms |" >> "$RESULTS"
done

# ---------------------------------------------------------------------------
# Proved workloads (the causal loop on real repos). Remote sources on the
# process backend require the explicit --trusted-process opt-in; these
# are well-known repositories pinned by ref.
# ---------------------------------------------------------------------------
echo "" >> "$RESULTS"
echo "## Proved workloads" >> "$RESULTS"
echo "" >> "$RESULTS"

prove_case() {
    local name="$1" locator="$2" ref="$3" timeout="$4"; shift 4
    local out="$WORK/$name-prove"
    rm -rf "$out"
    log "prove $name: $*"
    local start_ms end_ms
    start_ms=$(date +%s%3N)
    if "$OVID" prove "$locator" --ref "$ref" --trusted-process --timeout "$timeout" \
        "${INHERIT_ARGS[@]}" --out "$out" -- "$@" \
        > "$WORK/$name-prove.summary.txt" 2>&1; then :; fi
    end_ms=$(date +%s%3N)
    if [ -f "$out/proof.json" ]; then
        python3 - "$out" "$name" "$*" "$((end_ms - start_ms))" <<'PY' >> "$RESULTS"
import json,sys
p=json.load(open(sys.argv[1]+"/proof.json"))
verdict=p["baseline"]["verdict"]
world=p["world"]["status"]
by={"required":0,"optional":0,"unresolved":0}
for c in p["conclusions"]:
    by[c["conclusion"]["necessity"]] += 1
print(f"- **{sys.argv[2]}** — `{sys.argv[3]}` — baseline {verdict}, world {world} "
      f"(pipeline total {sys.argv[4]} ms, {p['trials_executed']} trials); "
      f"{by['required']} required / {by['optional']} optional / {by['unresolved']} unresolved")
PY
    else
        echo "- **$name** — pipeline failed (see $name-prove.summary.txt)" >> "$RESULTS"
    fi
}

# Python import via stdlib only (fails fast if flask cannot import: that
# failure evidence is the point).
prove_case "flask" "https://github.com/pallets/flask" "main" 300 sh -c "python3 -c 'import flask' || true"
# Rust: metadata + lockfile verification exercises heavy file boundaries.
prove_case "fd" "https://github.com/sharkdp/fd" "master" 600 sh -c "cargo metadata --format-version 1 --no-deps > /dev/null"

echo "" >> "$RESULTS"
echo "Generated $(date -u +%FT%TZ)" >> "$RESULTS"
log "done -> $RESULTS"
