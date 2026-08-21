# Ovid

**A causal dependency verifier: Ovid experimentally determines what a
repository workload needs, explains why, and verifies that the inferred
environment can reproduce the workload.**

`ovid prove` runs a workload under controlled conditions — a stable
baseline from an immutable snapshot, then enforced interventions
(deny-all egress today; per-dependency treatments next) — and classifies
every external dependency as **required**, **optional**, or honestly
**unresolved**. It then synthesizes the smallest credible world and
marks it **verified** only after a clean replay passes. Every conclusion
is scoped (one revision, one workload, one environment, one policy) and
links back to immutable, hash-chained evidence — Ovid can always answer
*"why do you believe this?"*

A claim reads as *"postgres:5432 was required for `test` at revision
`abc123`, under environment `env:…`: the stable baseline passed, the
enforced no-egress treatment failed 2/2, and the generated world
replayed successfully"* — never as *"this repository always requires
PostgreSQL"*.

## Purpose

Conventional SBOMs say a package is declared or installed. They cannot say
whether it is exercised, which undeclared build tools were needed, which
databases and services the code actually contacts, or whether a dependency
is required or optional. Ovid closes that gap with a hybrid model:

- **static inventory** supplies declared/resolved composition
  (manifests + lockfiles across Cargo, npm/pnpm/yarn, Python, Go,
  Maven/Gradle, RubyGems, Composer);
- **dynamic observation** watches real execution boundaries (process
  exec, file opens *and misses*, stat-scan misses, socket connects,
  listeners) via an interchangeable observer backend;
- **active experimentation** establishes causality: failed operations
  seed resolution proposals, and counterfactual reruns separate
  *required* from *optional* dependencies;
- **explicit unresolved reporting** keeps unknowns visible instead of
  guessing.

## Features

The 0.2 surface (primary):

- `ovid inspect` — fast, static-only inspection: composition, declared
  endpoints, and ranked workload candidates. Never executes repository
  code.
- `ovid prove` — the primary loop: provision, freeze an immutable
  snapshot, repeated baseline (a flaky workload never receives causal
  labels), enforced deny-all-egress intervention with confirmation,
  required/optional/unresolved classification, world synthesis, and
  clean-replay verification. Writes `proof.json` + typed journal
  evidence; stable exit codes (0 completed, 20 baseline/replay failed).
- `ovid replay` — rebuild the environment from a proved bundle, rerun
  the locked workload from clean state, and update the lock's
  verification status from the outcome.
- `ovid doctor` — host capability report (observation, isolation,
  backends) with exact remediation, before a failed run makes you
  discover the gaps.
- Safety default: a **remote** repository never executes on the host
  process — use the microsandbox guest VM, or opt in explicitly with
  `--trusted-process`.

The evidence machinery beneath (also exposed via the legacy commands):

- `ovid inventory` — non-executing static inventory with language stats,
  merged declared+resolved components, PURL normalization.
- `ovid observe` — run one explicit command in a supervised sandbox
  (scrubbed environment, ephemeral copy-on-write workspace, resource
  limits, deadlines) under strace-based boundary observation.
- `ovid analyze` — discover build/test commands from CI files, package
  scripts, Makefiles, Dockerfiles, and docs; execute them; propose
  resolutions for missing tools (via tool-resolver packs) and refused
  services (via service packs); synthesize a proposed world lock and
  Compose replay file; run environment-variable counterfactuals.
- `ovid tomography` — the full loop in one command: discover workloads,
  run each **twice** (first in an isolated network namespace with
  deny-all egress and loopback intact, then with network access), and
  classify every external dependency from the counterfactual pair
  (`required` only when a single controlled dependency flips the
  outcome; group-level changes stay honestly `unresolved`). One bundle
  carries both runs, the experiment evidence, and the world lock.
- **DNS identity capture** — resolver traffic (port 53) is decoded from
  observed syscalls into DNS query/answer evidence, so external
  dependencies are identified by *hostname* (grouping CDN address
  rotation into one logical dependency), resolver bypass (queries sent
  to servers not in `/etc/resolv.conf`, e.g. hardcoded `8.8.8.8`) is
  flagged, and destinations with no observed resolution are explicitly
  marked `ip-only` rather than silently nameless.
- `ovid explain` — traverse any claim to its supporting evidence.
- `ovid diff` — compare two analyses (components, versions, external
  systems, listeners, tools).
- `ovid world export` — emit the world lock or a Compose replay.
- `ovid packs` — list/validate declarative packs.
- **Evidence ledger**: append-only, hash-chained JSONL with tamper
  detection; the chain head is published in every manifest's provenance.
- **Exports**: Ovid manifest (YAML/JSON), CycloneDX 1.5, SPDX 2.3,
  integration plan (Markdown), world lock, Compose.
- **Pack extensibility**: runner recipes, service packs, protocol
  classifiers, and tool resolvers as schema-validated YAML — new
  ecosystem support without core code changes.

## Design

```mermaid
flowchart LR
    CLI[ovid CLI] --> RA[Repository acquisition\nfingerprinting]
    RA --> INV[Inventory scanners]
    RA --> PL[Planner\naction graph]
    PL --> SB[Sandbox backends\nprocess / Firecracker]
    SB --> OBS[Boundary observer\nstrace backend]
    OBS --> AGG[Aggregation]
    AGG --> LED[(Evidence ledger\nhash-chained)]
    INV --> LED
    AGG --> GW[Gateway analysis\nprotocol classification]
    GW --> RES[Resolution proposals\ntools / services / stubs]
    RES --> WORLD[World synthesis\nlock + compose]
    LED --> CLAIMS[Claims + confidence]
    CLAIMS --> OUT[Manifest, CycloneDX, SPDX,\nintegration plan, diffs]
    WORLD --> OUT
```

Key decisions (full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)):

- **The evidence ledger is canonical.** Manifests, claims, and exports
  are projections; ledger records are immutable and hash-chained.
- **Claim states never collapse.** `declared`, `resolved`, `loaded`,
  `exercised`, `causally_required` are independent dimensions; static
  scanners can never set dynamic states.
- **Failures are first-class.** An `execve`/stat `ENOENT` or an
  `ECONNREFUSED` is evidence that seeds the resolution loop.
- **Causality requires counterfactuals.** `required`/`optional` labels
  come only from rerun comparisons or natural counterfactuals (workload
  succeeded while a dependency was down); everything else is
  `unresolved`.
- **Three execution backends.** A supervised process sandbox (trusted
  repositories, unix hosts), a Firecracker MicroVM layer (untrusted
  code; jailer + read-only source device + overlay + vsock + snapshots)
  that fails closed on hosts without KVM, and a microsandbox (libkrun)
  guest-VM backend (`--backend microsandbox`) whose guest is always
  Linux — so observation and network counterfactuals work identically
  on Linux/KVM, macOS/Apple Silicon, and Windows/WHP hosts. Manifests
  always record which isolation tier produced the evidence.
- **Packs over analyzers.** Ecosystem knowledge is declarative YAML
  evaluated by generic code.

## Getting started

### Install

One-liner (downloads the latest prebuilt release for your platform,
sha256-verified; falls back to building from source with cargo):

```sh
curl -fsSL https://raw.githubusercontent.com/X-McKay/ovid/main/scripts/install.sh | sh
```

Alternatives:

```sh
# Build-from-git one-liner (needs Rust 1.85+; installs to ~/.cargo/bin)
cargo install --locked --git https://github.com/X-McKay/ovid ovid-cli

# From a checkout
cargo install --locked --path crates/ovid-cli
```

The installer honors `OVID_INSTALL_DIR` (default `~/.local/bin`) and
`OVID_VERSION` (a release tag; default latest). On a private fork,
clone first and run `scripts/install.sh` from the checkout with
`OVID_REPO_URL` pointing at your remote.

### Runtime prerequisites

- Linux for full native execution (`strace` for observation:
  `apt-get install strace`; unprivileged user namespaces for offline
  counterfactual legs). The workspace also compiles on macOS and
  Windows — static analysis works everywhere; on those hosts use the
  microsandbox backend for execution
- `git` for URL-based acquisition
- Optional: `/dev/kvm` + Firecracker for the MicroVM backend
- Optional: the `msb` CLI (<https://microsandbox.dev>) for
  `--backend microsandbox` — libkrun guest VMs on Linux/KVM,
  macOS/Apple Silicon, or Windows/WHP

### Run

```sh
# Check what this host can do (observation, isolation, backends)
ovid doctor

# Static look first: composition + ranked workload candidates
ovid inspect .

# Prove what the test workload needs (the primary loop)
ovid prove . --workload test

# ... or prove an explicit command
ovid prove . --workload test -- make integration-test

# Prove a remote repository (guest VM; or add --trusted-process)
ovid prove https://github.com/org/repo --backend microsandbox

# Re-verify the generated world from clean state
ovid replay .ovid/runs/<id>

# Why do you believe this?
ovid explain postgres --from .ovid/runs/<id>

# Compare two revisions' bundles
ovid diff --before out-v1/ --after out-v2/
```

The legacy commands (`inventory`, `observe`, `analyze`, `tomography`)
remain available while the 0.2 migration completes; `tomography` is
still the way to get the full manifest + standards exports in one run.

`ovid prove` writes a lean bundle to `.ovid/runs/<analysis-id>` (and
records it in `.ovid/latest`):

```text
.ovid/runs/<id>/
├── proof.json                # scope, baseline, trials, conclusions, world status
├── evidence.jsonl            # hash-chained ledger of typed journal events
├── claims.json               # requires / optionally-uses claims with evidence links
├── world.lock.yaml           # world lock; status verified only after clean replay
├── compose.yaml              # local replay environment
└── timings.json              # per-stage wall-clock + trial count
```

Legacy analyses write the full bundle:

```text
ovid-output/
├── ovid.yaml / ovid.json     # the manifest (human / machine, same document)
├── evidence.jsonl            # immutable hash-chained evidence ledger
├── claims.json               # normalized claims with evidence links
├── cyclonedx.json, spdx.json # standards exports
├── world.lock.yaml           # reproducible world (analyze mode)
├── compose.yaml              # local replay environment (analyze mode)
└── integration-plan.md       # human-readable plan
```

`ovid.yaml` is written in reading order with section banners: a
`summary` section (headline, counts, ranked findings) comes first, the
dynamic story (workloads, external systems, unresolved, completeness)
follows, and the bulk inventory sits near the end. `summary.findings`
is typed (`severity`, `kind`, `subject`, `detail`) so CI and agents can
gate on it without parsing prose; provenance (tools, packs, evidence
chain head) closes the manifest.

### Notes on trust

The process backend is for repositories you trust: it scrubs the
environment, isolates writes into an ephemeral workspace, and enforces
resource limits, but it is **not** a security boundary against hostile
code. Hostile-repository analysis requires the Firecracker backend on a
Linux/KVM worker (see `docs/ARCHITECTURE.md#execution-backends`).

## Testing

```sh
cargo test --workspace                                   # unit + integration + golden
cargo test -p ovid-cli --test perf -- --ignored --nocapture  # perf guardrails
UPDATE_GOLDENS=1 cargo test -p ovid-cli --test golden    # regenerate goldens
```

Validation against real open-source repositories (performance and
accuracy measurements) is documented in
[docs/VALIDATION.md](docs/VALIDATION.md) and reproducible with
`scripts/validate-oss.sh`.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `strace unavailable: boundary observation was not captured` in limitations | Install strace (`apt-get install strace`). The run still completes; only observation is missing. |
| `observe` fails with `spawn "cargo": No such file or directory` | The sandbox scrubs `PATH` to system defaults. Pass `--inherit-env PATH` (and usually `--inherit-env HOME` for toolchain caches like `~/.cargo`). |
| Workload needs network (dependency download) but hangs/fails | The sandbox does not provide a registry proxy in process mode; run the dependency-fetch step yourself first, or use `--in-place` against a pre-fetched checkout. |
| `git clone failed` for a URL | Check the ref (`--ref`), network access, and credentials; Ovid clones with hooks disabled and never runs repo code during acquisition. |
| `UnsupportedHost: /dev/kvm not present` | You asked for the Firecracker backend on a host without KVM. Use the process backend (default) for trusted repos, or provision a Linux/KVM worker. |
| `tomography` offline run warns about missing isolation | `unshare -r -n` (unprivileged user namespaces) is unavailable — often disabled via `kernel.unprivileged_userns_clone=0` or distro hardening. The offline run falls back to stripping proxy variables and says so in limitations. |
| External systems show `identity: ip-only` | No DNS resolution was observed for those destinations (e.g. the address was hardcoded, or resolution happened before observation started). The manifest lists how many, so absence of a name reads as unknown, not nameless. |
| Analysis is slow on a huge repository | Use `--in-place` to skip the ephemeral copy (trusted checkouts only), and prefer `inventory` mode for fleet-style sweeps. |
| Golden test failure after your change | Expected if output changed intentionally — regenerate with `UPDATE_GOLDENS=1` and commit the diff; otherwise you introduced a regression. |
| `pack validation failed` | Packs must have `api_version: ovid.dev/pack/v1` and digest-pinned service images. Run `ovid packs validate <dir>` for the exact error. |
| Ledger `chain break at record …` | The evidence file was edited or truncated. Evidence is immutable; rerun the analysis. |

## Repository layout

```text
crates/            13-crate workspace (core -> evidence -> ... -> cli)
packs/             built-in declarative packs (runners, services, protocols, resolvers)
fixtures/          test fixture repositories + golden files
scripts/           validation and maintenance scripts
docs/              architecture, validation results
.claude/skills/    task playbooks for consistent future development
```

## License

Apache-2.0
