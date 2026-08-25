---
name: troubleshoot-ovid
description: Diagnose and fix a failing or surprising Ovid run — missing observation, unenforceable egress, remote-repo refusal, unresolved labels, provisioning/network problems, replay failures, pack or ledger errors. Use when `ovid inspect`/`prove`/`replay` errors, degrades, or produces results a user does not expect.
---

# Troubleshooting Ovid

First move, always: **`ovid doctor`**. Most surprises are a host
capability the run needed and didn't have. Ovid degrades honestly, so a
"limitation" in the report is usually the real story, not a crash.

## Symptom → cause → fix

| Symptom | Cause | Fix |
|---|---|---|
| `strace unavailable: boundary observation was not captured` | no `strace` on the process backend | `apt-get install strace`; the run still completes, only observation is missing |
| Network candidates stay `unresolved` with "cannot enforce deny-all egress" | no unprivileged user namespaces → deny cannot be enforced, and Ovid refuses to weaken the experiment | enable user namespaces, or `--backend microsandbox` |
| Deny run shows `PartiallyEnforced` / `gateway-deny-partial` | user namespaces missing; gateway refuses proxied requests but the kernel can't block direct sockets | same as above; do not treat a partial-deny trial as an airtight block |
| `spawn "<tool>": No such file or directory` in a trial | the lab scrubs the env; only `PATH`/`HOME` inherit by default | pass `--inherit-env NAME` for each variable the workload needs |
| Remote repo won't run / refuses host process | remote sources never execute on the host by default (ADR-011) | `--backend microsandbox` (preferred), or explicit `--trusted-process` if you trust it |
| Provisioning fails (`make deps`, install errors) | provision runs **online** with host network; registry/network/tooling issue | fix connectivity/tooling, or pre-provision a warm cache and pass no provision command |
| Everything is `unresolved` after a `prove` | baseline was not stable-passing, or no counterfactual was enforceable | check the baseline verdict in the report; a flaky workload never gets causal labels — stabilize it or raise confirmation runs |
| External systems show `identity: ip-only` | no DNS resolution observed (hardcoded IP, or resolution predated observation) | expected; the count is reported so absence-of-name reads as unknown, not nameless |
| `--egress allow` reaches nothing / times out | no host upstream proxy detected, or the service is genuinely down | `ovid doctor` shows the detected upstream; `forward-failed` in intents means genuinely unreachable, distinct from an enforced `refused` |
| World stays `Proposed` / `ReplayFailed` | clean replay did not pass; a world is `verified` only after a clean replay | read the preserved failure in the bundle; fix the world/deps, re-`prove` |
| Analysis is slow on a large repo | `prove` pays provisioning + a fork per trial | `ovid inspect` for the fast path; lower `--max-trials`, set `--timeout` |
| `pack validation failed` | missing `api_version: ovid.dev/pack/v1` or an unpinned image | `ovid packs validate <dir>` for the exact error; digest-pin service images |
| Ledger `chain break at record …` | `evidence.jsonl` was edited/truncated | evidence is immutable — rerun; never hand-edit the ledger |
| `File name too long` during environment prep | the `--out` bundle dir is *inside* the source tree, so the snapshot copy recurses | point `--out` outside the locator (e.g. `--out /tmp/run`), or run from a short path |

## When a result is "wrong"

Before assuming a bug: is the label actually `unresolved` (a correct,
honest answer) rather than the required/optional you expected? Ovid will
not guess. Confirm the baseline was stable-passing and the treatment was
`Enforced` (not `PartiallyEnforced`/`Unsupported`) — an unenforceable
treatment can only yield `unresolved` by design (invariant 11). Use
`ovid explain <query> --from <bundle>` to see the evidence behind any
label before concluding it is incorrect.

## If it's a real code bug

Reproduce against a fixture (`fixtures/prove-truth`, `fixtures/*`), run
the local gate (`cargo fmt --all && cargo clippy --workspace --all-targets
--locked -- -D warnings && cargo test --workspace --locked`), and if the
fix touches classification/enforcement/gateway, use the `extend-prove`
skill — such changes need a truth scenario, not just a unit test.
