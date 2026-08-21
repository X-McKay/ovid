---
name: add-scanner
description: Add or extend a native inventory scanner for a package ecosystem (manifest/lockfile parsing into Components). Use when asked to support a new language ecosystem's dependency files or fix parsing of an existing one.
---

# Adding an inventory scanner

Scanners turn manifest/lockfile files into `Component` records with
*static-only* states. They live in `crates/ovid-inventory/src/scanners/`.

## Checklist

1. **Create `crates/ovid-inventory/src/scanners/<eco>.rs`** implementing
   `Scanner`. Model on `cargo.rs` (TOML), `node.rs` (JSON), or
   `ruby.rs` (line format). Register it in `scanners/mod.rs::all()`.
2. **State discipline (critical):** manifest entries set only
   `ClaimState::Declared` (+ `direct: true`, correct `Scope`); lockfile
   entries set only `ClaimState::Resolved`. Never set `loaded`,
   `exercised`, or any dynamic state — that violates spec §6.3 and the
   integration tests will fail.
3. **Version discipline:** only an exact pin is a version. Ranges
   (`^1.2`, `>=2,<3`) and property placeholders (`${x.version}`) stay
   `version: None` — the merge pass in `lib.rs` joins the declared entry
   with the lockfile pin.
4. **Parse defensively.** Malformed files push a message onto
   `report.warnings` and return; never panic, never hard-error. Read
   files only via `read_or_warn` (bounded reads).
5. **Skip vendored trees** (`node_modules/`, `vendor/`) the way the
   existing scanners do.
6. **PURL:** use `crate::purl(ecosystem, name, version)`. If the
   ecosystem needs name normalization (like pypi lowercase), add it in
   `purl.rs` with a test.
7. **Tests:**
   - unit test in the scanner file: a temp-dir fixture with manifest +
     lockfile asserting the merged declared+resolved entry, a
     transitive-only entry, and the range-stays-versionless rule;
   - if the ecosystem is common, add files to an existing fixture repo
     (or a new `fixtures/<name>/`) and extend
     `crates/ovid-cli/tests/integration.rs`;
   - regenerate goldens if fixture output changed:
     `UPDATE_GOLDENS=1 cargo test -p ovid-cli --test golden`.
8. **Gate:** `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.

## When native parsing is wrong

If the format requires the ecosystem's own toolchain to resolve (Gradle
version catalogs, Maven property inheritance), do **not** approximate
deeply: parse the common shape, warn on the rest, and note that resolved
inventory for that ecosystem comes from runner-recipe execution
(spec §28.3) or an external SBOM provider (`provider.rs`).
