# AGENTS.md — operating Ovid with an AI agent

This file orients any coding agent (Codex, Claude Code, others) working in
this repository. The skills referenced below are plain Markdown playbooks
under `.claude/skills/`; they are tool-agnostic — read the relevant one
before acting, whichever agent you are.

## Authority order

1. `CLAUDE.md` — the contributing contract: build/test/lint gate, the
   non-negotiable design invariants, code conventions, and commit hygiene.
   Follow it for any code change.
2. The skill for the task at hand (below).
3. `docs/ARCHITECTURE.md` — the implemented shape and ADRs;
   `docs/ovid_detailed_technical_spec.md` and
   `docs/ovid_improvement_proposal.md` — the "why".

## Skills (read before the matching task)

Operating Ovid the tool:
- `.claude/skills/setup-ovid/SKILL.md` — install Ovid and host
  prerequisites (`strace`, user namespaces, `msb`); verify with
  `ovid doctor`.
- `.claude/skills/use-ovid/SKILL.md` — choose the command (inspect / prove
  / replay), the egress posture, the backend and trust opt-ins; read
  results honestly. Also answers "is it safe to run against real systems?"
- `.claude/skills/troubleshoot-ovid/SKILL.md` — diagnose failing or
  surprising runs.

Developing Ovid:
- `.claude/skills/extend-prove/SKILL.md` — causal classification,
  treatments, enforcement, or the laboratory gateway/egress.
- `.claude/skills/add-scanner`, `add-pack`, `add-boundary-event`,
  `oss-validation` — inventory scanners, packs, the event model, and the
  OSS validation suite.

## Safety invariants an agent must not break

- `--egress deny` (default) contacts nothing real; never make the gateway
  forward a request the policy refuses, and never weaken a treatment to
  make it "enforceable" (invariants 11, 15).
- Only the `ovid_domain::classify` module mints required/optional labels;
  `CausalConclusion` has no public constructor (invariant 10).
- A world is `verified` only via a clean replay; writers project status,
  never set it (invariant 12).
- Backends claim exactly their isolation tier; the process backend is not
  a security boundary, remote code needs the guest VM or explicit
  `--trusted-process` (invariants 8, ADR-011).
- No secrets in outputs (invariant 9).

## Local gate before committing

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

`strace` must be installed for the observation tests. User-facing changes
get a `CHANGELOG.md` **Unreleased** entry in the same commit.
