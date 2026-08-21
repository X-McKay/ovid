---
name: extend-prove
description: Change the prove loop — causal classification rules, treatments, enforcement, or the laboratory gateway/egress. Use when adding or altering how Ovid decides required/optional/unresolved, how a treatment is enforced, or how egress is named and blocked.
---

# Extending the prove loop

This is the causal core (proposal §7, §10; ADRs 010–015, 017). Its
invariants are load-bearing and enforced by tests — read CLAUDE.md
invariants 4, 6, 8, 10–15 before touching anything here. The golden rule:
**unresolved beats wrong** (spec §6.6). A change that makes Ovid *more*
willing to mint a causal label needs more evidence, not less.

## The layering (never invert it)

`ovid-domain` (pure: no I/O, no process, no fs) → `ovid-application`
(ports only, no concrete adapter) → `ovid-cli` (adapters: the real
laboratory, gateway wiring). A new label rule lives in the domain; a new
way to *enforce* or *observe* lives in the CLI adapter behind a port.

## Where each kind of change goes

| Change | File(s) | Guardrail |
|---|---|---|
| New/changed causal rule | `ovid-domain/src/classify.rs` | `CausalConclusion` has **no public constructor** (inv. 10) — mint labels only here |
| New treatment | `ovid-domain/src/trial.rs` (`Treatment` + `describe()`), `ovid-application/src/ports.rs` (`LabCapabilities::can_enforce`), CLI adapter in `ovid-cli/src/lab.rs` | a lab that can't enforce refuses (`LabError::Unsupported`) → classify `unresolved`, never weaken (inv. 11) |
| Candidate evidence shape | `ovid-application/src/ports.rs` (`NetworkCandidate`/`CandidateEvidence`, `merge_candidates`) | merges are conservative: one success anywhere ⇒ available; AND boolean strength across trials |
| Scheduler step | `ovid-application/src/prove.rs` | reserve trial budget; journal every conclusion; report what was dropped |
| Gateway policy / egress | `ovid-gateway/src/proxy.rs`, `ovid-cli/src/lab.rs` | `--egress deny` contacts nothing real (inv. 15); reject credential-bearing upstreams; never forward a refused request |
| World promotion | `ovid-domain/src/world.rs` | `VerifiedWorld` only via `ReplayEvidence::from_clean_replay` (inv. 12) |

## Checklist

1. **Decide the evidence, then the label.** A `required`/`optional` label
   needs a counterfactual (inv. 4): an enforced intervention that changed
   one dependency, or a demonstrated natural/enforced-deny counterfactual
   during a stable passing baseline. If you cannot point to the
   counterfactual, the answer is `unresolved`.
2. **Mint only in `classify.rs`.** Add a `classify_*` function returning
   `Vec<CausalConclusion>`; reuse `unresolved(...)` for the not-proven
   path. Never add a public constructor or a `Necessity`-setting API
   anywhere else. Re-export the new function in `ovid-domain/src/lib.rs`.
3. **Gate on the baseline.** Every causal path first checks
   `BaselineVerdict::StablePassing` (`baseline.supports_experiments()`);
   an unstable baseline yields only `unresolved`.
4. **Enforcement is evidence (inv. 11).** A treatment that the laboratory
   cannot enforce must route through `classify_unenforceable`, not a
   weakened variant. Distinguish *enforced* absence (e.g. gateway
   `refused`) from *incidental* absence (e.g. `forward-failed`, a missing
   tool): they carry different confidence and different reasons — see
   `classify_enforced_deny` vs `classify_natural_counterfactual`.
5. **Thread candidate fields conservatively.** New booleans on
   `NetworkCandidate`/`CandidateEvidence` default to the weaker value and
   are ANDed in `merge_candidates` so a single contradicting trial
   downgrades the claim. Update every constructor (grep the struct name)
   and the `ovid-testkit` convenience builders.
6. **Journal it.** Every conclusion goes through `journal_conclusions`;
   new evidence (e.g. a gateway intent) is appended to the ledger *first*
   and referenced by id (inv. 1). Pick the honest trust tier — host-
   enforced facts (exit codes, gateway decisions) are T0/T1; guest
   observations are T2; heuristics/models are T5 and can never confirm a
   claim alone (inv. 6).
7. **Test twice (mandatory for classification/enforcement changes).**
   - a **truth scenario** in `crates/ovid-application/tests/truth.rs`
     against `ovid_testkit::FixtureLaboratory` (known ground truth, zero
     real execution) — script the outcomes/candidates and assert the
     `Necessity` *and* the reason text;
   - domain unit tests in `classify.rs` for the rule in isolation;
   - if the enforcement/observation path changed, an end-to-end test in
     `crates/ovid-cli/tests/prove.rs` against `fixtures/prove-truth`.
   A change to classification or enforcement rules needs a truth
   scenario, not just a unit test (CLAUDE.md testing rules).
8. **Docs + traceability.** Update `docs/ARCHITECTURE.md` (structural
   rules, ADR list, gateway section), add a `CHANGELOG.md` Unreleased
   entry, and cite the spec/proposal section in the new item's doc
   comment. If the change is an architecture decision, add the next
   `ADR-0NN`.

## Local gate before committing

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

The egress integration path needs `strace` and Linux user namespaces; on
a host without them the laboratory reports reduced capabilities and the
affected candidates stay `unresolved` — that is correct behavior, not a
bug to work around.
