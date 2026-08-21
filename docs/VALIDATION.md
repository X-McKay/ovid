# Open-source validation: performance and accuracy

> **Note:** these measurements were taken on the pre-0.2 CLI
> (`inventory`/`observe`). The static path and observation machinery
> they measure are unchanged, but the commands are now `ovid inspect`
> and `ovid prove`; `scripts/validate-oss.sh` has been updated to the
> 0.2 surface — rerun it to refresh this document.

Ovid was validated against six real open-source repositories of varying
size, ecosystem, and complexity. Every number below was produced by
`scripts/validate-oss.sh` (inspect + accuracy + proved workloads) and
`cargo test -p ovid-cli --test perf -- --ignored --nocapture` (perf
guardrails); rerun them to reproduce.

**Environment:** 4 vCPUs, 16 GiB RAM, Linux 6.18, rustc 1.94.1,
strace-based observer, process sandbox backend, network via HTTPS proxy.
Ovid commit: see the results footer produced by the script.

## Repositories

| Repo | Ecosystem | Why chosen |
|---|---|---|
| [sharkdp/fd](https://github.com/sharkdp/fd) @ `ee20f426` | Rust, single crate | small binary crate with committed lockfile and a build script |
| [BurntSushi/ripgrep](https://github.com/BurntSushi/ripgrep) @ `3fce3b5b` | Rust, 11-member workspace | mid-size workspace, lockfile, platform-specific deps |
| [pallets/flask](https://github.com/pallets/flask) @ `d318b683` | Python | pyproject + uv.lock + multiple requirements files + example subprojects |
| [expressjs/express](https://github.com/expressjs/express) @ `a3714473` | Node.js | manifest-only repo (no lockfile), 44 declared deps |
| [gin-gonic/gin](https://github.com/gin-gonic/gin) @ `dcaa4296` | Go | go.mod/go.sum with indirect markers |
| [tokio-rs/tokio](https://github.com/tokio-rs/tokio) @ `ea91b33c` | Rust, large workspace | 868 files, no lockfile, heavy target-specific dependency tables |

## Inventory performance

Timings are the warm second run on a cached clone — pure acquisition-and-
scan work, excluding network transfer, per the spec's measurement rule
(§12.2). Cold numbers include the shallow clone over the network.

| Repo | Files | Warm inventory | Cold (clone + inventory) |
|---|---:|---:|---:|
| fd | 59 | 12 ms | 877 ms |
| ripgrep | 236 | 15 ms | 822 ms |
| flask | 236 | 21 ms | 744 ms |
| express | 213 | 10 ms | 707 ms |
| gin | 130 | 9 ms | 739 ms |
| tokio | 868 | 22 ms | 921 ms |

The spec's inventory target is p50 < 30 **seconds** for repositories
under 100k files; measured results are three orders of magnitude inside
that. The synthetic perf guardrail confirms scale headroom:

```
PERF inventory 5000 files: 53 ms
PERF ledger append: 5000 records in 33 ms (150060/s)
PERF aggregate: 100k events -> 1000 retained in 36 ms
```

## Inventory accuracy

Ground truth is independent of Ovid's parsers where possible:
`cargo metadata` (the toolchain's own resolver) for Rust; independent
minimal parses of the primary manifest for the others. Precision =
correct identified / all identified; recall = correct identified / gold
(spec §37.5). Comparisons are scoped to the root manifest/lockfile.

| Repo | Comparison | Precision | Recall | Gold n |
|---|---|---:|---:|---:|
| fd | lock pins (name,version) vs cargo-metadata graph | 0.961 | 1.000 | 124 |
| ripgrep | lock pins (name,version) vs cargo-metadata graph | 0.942 | 1.000 | 49 |
| flask | declared runtime deps vs pyproject `[project.dependencies]` | 0.857 | 1.000 | 6 |
| express | declared deps vs package.json (deps + devDeps) | 1.000 | 1.000 | 44 |
| gin | declared (module,version) vs go.mod requires | 1.000 | 1.000 | 35 |
| tokio | declared dep names vs cargo-metadata --no-deps declarations | 0.980 | 1.000 | 50 |

**Recall is 1.000 across all six repos** — Ovid found every ground-truth
dependency. The residual precision gaps are explained, not mysterious:

- *fd, ripgrep:* a Cargo lockfile legitimately retains pins for packages
  outside the current resolve graph (e.g. dependencies of workspace-
  excluded fuzz targets). Ovid correctly reports them as `resolved` pins;
  the strict graph-only gold counts them as extras.
- *flask:* the single "extra" is `flask` itself — the repository's root
  package, which Ovid reports as a component (standard SBOM behavior)
  and the external-dependency gold excludes.
- *tokio:* one extra declared name from a nested example manifest.

Two accuracy-driven fixes came out of this validation and are covered by
unit tests: target-specific dependency tables
(`[target.'cfg(…)'.dependencies]`) were previously missed (tokio recall
was 0.76 before), and scope from a manifest declaration now survives the
merge with a lockfile pin (flask precision was 0 under the strict
runtime-scope filter before).

## Observed workloads (dynamic evidence)

Run via `ovid observe` in the sandbox (scrubbed env with explicit
pass-through, ephemeral workspace, strace observation).

| Case | Workload | Outcome | Boundary evidence |
|---|---|---|---|
| flask | `python3 -c 'import flask'` | passed, 40 ms | 53 events captured, 19 collapsed, 2 noise-dropped |
| fd | `cargo metadata --no-deps` | passed, 60 ms | 81 events, 25 collapsed |
| fd (cold cache) | `cargo build -q` | passed, ~20 s | 7,331 events captured, 13,059 collapsed, 430 noise-dropped; **5 external systems** (proxied crates.io downloads) recorded, 2 unresolved |
| fd (warm cache) | `cargo build -q` | passed, ~15 s | 4,909 events, 12,665 collapsed; 0 network attempts (fully cached), **1 unresolved: `tool:emcc`** |

The `fd` build produced a textbook tomography result on a real
repository: its build probed for the Emscripten compiler (`emcc`) on
PATH, the miss was captured as ENOENT evidence, no trusted resolver
candidate exists for it, and the manifest honestly reports
`tool:emcc — no trusted resolver candidate` under `unresolved` instead
of guessing. The cold-cache run additionally recorded the proxied
network destinations used for dependency downloads as external-system
observations.

Fixture-level dynamic validation (integration test suite) additionally
covers: missing-tool discovery with resolver candidates, refused
postgres/redis connections classified by protocol packs and synthesized
into a proposed world lock with digest-pinned service images,
natural-counterfactual `optional` classification, environment-variable
counterfactuals producing `required`, hostile-fixture environment
scrubbing and source protection, deadline kills, and evidence-chain
verification.

## Observer overhead

```
PERF observed-vs-native: native 436 ms, observed(total pipeline) 3381 ms (7.7x)
```

The ptrace (strace) observer multiplies syscall cost; for syscall-dense
microbenchmarks the full observed pipeline (acquire + fingerprint +
strace + parse + bundle) ran ~7.7x native. For realistic workloads the
relative cost is far lower (fd's 15–20 s `cargo build` is compute-bound;
un-instrumented it builds in roughly the same wall time to within ~15%).
This is a known property of the ptrace backend and the reason the spec's
low-overhead path is the in-guest eBPF observer, which slots behind the
same `BoundaryObserver` trait.

## Reproducing

```sh
cargo build --release -p ovid-cli
scripts/validate-oss.sh                    # writes $TMPDIR/ovid-validation-workdir/results.md
cargo test -p ovid-cli --test perf -- --ignored --nocapture
```

The suite pins refs implicitly via shallow clones of the listed branches;
record the revisions from the results table when comparing runs over
time (see `.claude/skills/oss-validation`).
