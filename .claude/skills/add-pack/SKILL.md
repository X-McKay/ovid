---
name: add-pack
description: Author, modify, or validate Ovid packs (runner recipes, service packs, protocol classifiers, tool resolvers). Use when adding language/tool/service/protocol support — which must be pack-driven, never core code.
---

# Authoring packs

Packs are the only sanctioned way to add ecosystem knowledge (ADR-005).
Schema: `crates/ovid-packs/src/schema.rs`. On-disk tree: `packs/`.

## Kinds and their files

| Kind | Purpose | Example |
|---|---|---|
| `runner-recipe` | detect an ecosystem + conventional commands | `packs/runners/rust.yaml` |
| `service-pack` | start a disposable infra dependency | `packs/services/postgres.yaml` |
| `protocol-pack` | classify a destination (ports/first bytes/ALPN) | `packs/protocols/core-protocols.yaml` |
| `tool-resolver-pack` | missing executable/file -> trusted package | `packs/resolvers/system-tools.yaml` |

## Checklist

1. Write the YAML with `api_version: ovid.dev/pack/v1`, `kind`,
   `metadata: {name, version, license, signer}`. Multiple documents per
   file are fine (`---` separators).
2. Rules the validator enforces (and you should not fight):
   - service pack images **must** be digest-pinned (`…@sha256:…`);
   - permissions default to fully closed; only declare what is needed;
   - unknown `api_version` is rejected.
3. Conventions:
   - protocol packs: ports are weak evidence; add first-byte signatures
     when the protocol has them (spec §24.2 — port alone carries little
     weight);
   - resolver packs: candidates best-first with calibrated `confidence`;
     remember candidates are *proposals* — only a rerun confirms them;
   - runner recipes: commands are conventions, ranked below CI-mined
     commands by the planner; keep them non-destructive.
4. **Builtin vs external:** builtin packs are embedded via the
   `BUILTIN_PACKS` list in `crates/ovid-packs/src/registry.rs` — add the
   `include_str!` entry if the pack should ship in the binary. External
   packs load via `--packs-dir`.
5. **Tests:** add/extend a registry test in `registry.rs` (detection,
   resolution, or classification for your pack), and run
   `cargo run -p ovid-cli -- packs validate packs` (CI runs it too).
6. Fixture-scoped packs for tests live inside the fixture
   (see `fixtures/missing-tool/packs/`), not in the real `packs/` tree.
