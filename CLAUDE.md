# CLAUDE.md — working on Ovid

Ovid is an evidence-backed causal dependency verifier
(see `docs/ovid_detailed_technical_spec.md` if present, and
`docs/ARCHITECTURE.md` for the implemented shape). This file defines the
conventions that keep the codebase consistent. Follow it for every change.

## Build, test, lint

```sh
cargo build --workspace                 # build everything
cargo test --workspace                  # unit + integration + golden tests
cargo test -p ovid-cli --test perf -- --ignored --nocapture   # perf guardrails
cargo clippy --workspace --all-targets -- -D warnings         # must be clean
cargo fmt --all                         # rustfmt.toml: max_width 100
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps    # doc build must pass
```

CI (`.github/workflows/ci.yml`) enforces all of the above. Do not merge
with warnings; do not `#[allow]` a lint without a comment explaining why.
`strace` must be installed to run the observation integration tests.

## Non-negotiable design invariants

These come from the spec and are load-bearing; tests enforce most of them:

1. **The evidence ledger is canonical** (ADR-004). Manifests, claims,
   and exports are projections. Any new fact must be written to the
   ledger *first* and referenced by id. Never mutate a ledger record.
2. **Claim states stay independent** (§6.3). `declared`, `resolved`,
   `installed`, `loaded`, `exercised`, `causally_required` are separate
   booleans in `ovid_core::ClaimStates`. Never infer one from another —
   a static scanner must never set `loaded`/`exercised`.
3. **Failures are first-class evidence** (§6.2). Aggregation may collapse
   repeated successes but must preserve every failure signature and
   account for everything it drops (`EventsDropped`, collapsed counters).
4. **Causality only from counterfactuals** (§20). `Required`/`Optional`
   labels require a rerun comparison (or a natural counterfactual: the
   workload succeeded while the dependency was unavailable). Everything
   else is `Unresolved`. Never guess.
5. **Unresolved beats wrong** (§6.6, FR-048). Unknown protocols, tools
   without resolver candidates, and ambiguous matches stay explicitly
   unresolved in manifests — do not force a resolution.
6. **T5 (heuristic/model) evidence can never confirm a claim alone**
   (ADR-007). The confidence model caps proposal-only claims at 0.5.
7. **Ecosystem knowledge lives in packs, not core** (ADR-005). New
   language/tool/service/protocol support goes into `packs/*.yaml` and
   generic evaluation code — never framework-specific analyzers in core
   crates.
8. **Isolation honesty.** Every backend claims exactly its own tier in
   provenance: the process backend `TrustedProcess`, the microsandbox
   backend alone `MicrovmGuest` (libkrun guest VM). Never fall back
   silently from a VM tier to process execution; unavailable backends
   fail construction with `UnsupportedHost`, and laboratory
   capabilities are truthful (a capability is claimed only when its
   mechanism exists).
9. **No secrets in outputs.** The sandbox scrubs the environment; new
   code paths must not copy host environment or credentials into
   ledgers, manifests, logs, or world locks (generated secrets are
   referenced, never stored).
10. **Only the domain classifier mints causal labels** (proposal §7.5;
    docs/ovid_improvement_proposal.md). `ovid_domain::CausalConclusion`
    has no public constructor — never add one, never bypass
    `classify_intervention`. Its gates are load-bearing: stable passing
    baseline, `Enforced` treatment, consistent variant outcomes, and
    single-dependency variation for `required`.
11. **Enforcement is evidence; experiments are never weakened**
    (proposal §7.6, ADR-014). A laboratory refuses treatments it cannot
    enforce (`LabError::Unsupported`); the use case classifies affected
    candidates `unresolved`. Never downgrade a treatment (e.g. proxy-var
    stripping instead of a network namespace) on the prove path.
12. **Verified worlds come only from clean replay** (proposal §7.7,
    ADR-015). `VerifiedWorld` is constructible only via
    `ReplayEvidence::from_clean_replay` on a passing untreated trial;
    writers project `WorldStatus`, they never promote it.
13. **Remote sources never execute on the host process by default**
    (proposal §15.2, ADR-011). The `--trusted-process` gate in
    `ovid prove` fires before acquisition; keep it that way for any new
    executing command.
14. **Baseline and variants fork from one immutable snapshot**
    (proposal §10.8, ADR-013). Laboratory adapters must give every trial
    a pristine fork of the frozen post-provision snapshot — full
    fidelity, including caches provisioning installed — and destroy the
    overlay after the result is persisted.

## Code conventions

- Rust 2021, MSRV in `Cargo.toml` (`rust-version`). All deps are declared
  in `[workspace.dependencies]` and inherited with `.workspace = true`.
- Crate layering (no cycles):
  `core -> {domain, evidence, repository} -> {application, inventory, packs} ->
  {planner, observer, sandbox, gateway} -> {world, output} -> cli`.
  New crates slot into this order; the CLI is the only place that wires
  everything together. Two extra rules from the 0.2 architecture
  (proposal §5.1): `ovid-domain` stays pure (no I/O, no process, no
  filesystem dependencies), and `ovid-application` may depend on the
  domain but on **no concrete adapter** — new integrations go behind its
  ports and are wired in `ovid-cli` (adapters live as CLI modules until
  extraction is justified). `ovid-testkit` is dev-dependency-only.
- Every public item gets a doc comment; module docs cite the spec section
  they implement (e.g. `(spec §17.2, FR-043)`). Keep that traceability —
  it is how reviewers check behavior against the spec.
- Errors: `ovid_core::OvidError` in library crates, `anyhow` only in the
  CLI. Parsers are defensive: malformed repository input becomes a
  warning in the report, never a panic or hard error.
- Untrusted input rules: bound every read from a repository
  (`RepoSnapshot::read_file` with an explicit limit), never follow
  symlinks out of the tree, and treat mined commands as hostile until
  scored (dangerous commands are dropped in `ovid-planner`).
- Determinism: anything hashed or golden-tested must iterate sorted
  containers (`BTreeMap`/sorted `Vec`). Tests use
  `IdGenerator::deterministic()`.

## Testing rules

- Every crate keeps unit tests next to the code (`#[cfg(test)]`).
- Cross-crate behavior is tested end-to-end in
  `crates/ovid-cli/tests/integration.rs` against `fixtures/` — add a
  fixture rather than mocking when testing new discovery behavior.
- Golden tests (`crates/ovid-cli/tests/golden.rs`) pin inventory output
  for fixtures. If your change intentionally alters output, regenerate:
  `UPDATE_GOLDENS=1 cargo test -p ovid-cli --test golden` and commit the
  diff with an explanation.
- Perf guardrails live in `crates/ovid-cli/tests/perf.rs` (ignored by
  default). They are order-of-magnitude regression guards — keep
  thresholds generous and print measurements.
- New pack kinds/fields require: schema validation tests in
  `ovid-packs`, at least one builtin pack exercising them, and a
  registry test.
- Prove-loop behavior is tested twice: truth scenarios against the
  scripted `ovid_testkit::FixtureLaboratory`
  (`crates/ovid-application/tests/truth.rs` — known ground truth, zero
  real execution) and end-to-end through the real process laboratory
  (`crates/ovid-cli/tests/prove.rs` + `fixtures/prove-truth`). A change
  to classification or enforcement rules needs a truth scenario, not
  just a unit test.

## Skills

Task-specific playbooks live in `.claude/skills/`:

- `add-scanner` — adding an ecosystem inventory scanner.
- `add-pack` — authoring/validating packs.
- `add-boundary-event` — extending the normalized event model end to end.
- `oss-validation` — running the open-source validation suite and
  updating `docs/VALIDATION.md`.

Use them; they encode the end-to-end checklists (code + tests + goldens +
docs) that keep changes consistent.

## Commit hygiene

- One logical change per commit; message explains *why* plus the spec
  requirement it serves when applicable.
- Run the full local gate before committing:
  `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.
- Never commit: real credentials, unpinned service images in packs
  (validation rejects them), `target/`, or generated analysis bundles.
