---
name: use-ovid
description: Choose and run the right Ovid command safely — inspect vs prove vs replay, the egress posture, the execution backend, and the trust opt-ins — and read the results honestly. Use when deciding how to analyze a repository with Ovid, or when a user asks whether/how running Ovid is safe against real systems.
---

# Using Ovid appropriately

Ovid answers a *scoped* question: "what does this workload, at this
revision, in this environment, actually need?" Every label is
required / optional / **unresolved**, and unresolved beats a wrong guess.
Use it that way — don't push it to assert more than the evidence supports.

## Pick the command

| Want | Command | Executes repo code? |
|---|---|---|
| Composition, declared endpoints, ranked workloads (fast) | `ovid inspect .` | no (static only) |
| Prove what a workload needs, verify a world | `ovid prove . --workload test` | yes (sandboxed) |
| Re-verify a proved bundle from clean state | `ovid replay .ovid/runs/<id>` | yes |
| Trace a claim to its evidence | `ovid explain <query> --from <bundle>` | no |
| Compare two runs | `ovid diff --before A --after B` | no |

Start with `inspect`. Move to `prove` only when you need causal
(required/optional) answers — it costs provisioning + a snapshot fork per
trial.

## Choose the egress posture (safety-critical)

- **`--egress deny` (default)** — trials run in a network namespace with an
  in-namespace deny gateway; the workload contacts **nothing real**, and
  attempted destinations are named as evidence. A destination refused
  while the baseline still passed is classified `optional` on the strength
  of that enforcement, no trial spent. Use this by default.
- **`--egress allow`** — forwards attributed egress through the host proxy
  so network dependencies classify causally, and can block one dependency
  at a time. This makes **real** outbound requests. Use only when you
  intend real contact and want per-dependency causal labels.

Independent of posture: the **provision step is always online** (it
installs deps into the frozen snapshot, mechanism `host-network`). If the
requirement is *zero* external contact, provision offline / from a warm
cache and pass no provision command.

## Choose the backend / trust level

- **Process backend (default)** — host namespace isolation for
  **repositories you trust**. Not a security boundary against hostile code.
- **`--backend microsandbox`** — libkrun guest VM; use for untrusted or
  remote code, or on non-Linux hosts.
- **Remote sources refuse the host process** unless you pass
  `--trusted-process` (an explicit, recorded opt-in). Prefer the guest VM
  over `--trusted-process` for anything you did not write.

Run `ovid doctor` first; if a needed capability is `[--]`, expect narrower
results (see the `setup-ovid` skill).

## Bound the cost

`--max-trials` caps experiment trials; `--timeout` bounds per-trial
wall-clock. On a huge repo, `inspect` first, then a bounded `prove`.

## Read the results honestly

- **`required`** — stable baseline passed, an enforced single-dependency
  treatment failed repeatedly. **`optional`** — the workload passed while
  the dependency was demonstrably (or enforced-) unavailable.
  **`unresolved`** — everything else; it is a real, honest answer, not a
  failure. Never restate a scoped label as a universal fact ("repo needs
  X"); keep the scope (revision + workload + environment).
- **World `verified`** only after a clean replay passed — a `Proposed` or
  `ReplayFailed` world is not proof.
- **`ip-only` / completeness limitations** mean evidence was missing, not
  that nothing happened — surface them, don't hide them.
- Everything traces to evidence: use `ovid explain` rather than trusting
  the summary line.

## The safety one-liner (for user questions)

Under the default `--egress deny` on a host with user namespaces, the
workload itself contacts nothing real (enforced, tested). The parts that
*do* reach out are: provisioning (dependency install), `--egress allow`
(by design), and — on hosts without user namespaces — direct sockets under
partial deny. The process backend is not a jail for hostile code; use the
guest VM for that. Full detail: README *Safety & isolation*.
