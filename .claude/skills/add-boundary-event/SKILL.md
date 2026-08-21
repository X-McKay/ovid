---
name: add-boundary-event
description: Extend the normalized boundary-event model (new syscall coverage, new event kind, or new evidence normalization). Use when observation needs to capture a new class of process/file/network/build behavior.
---

# Extending the boundary event model

The event model is the system's spine; changes ripple through observer,
aggregation, gateway analysis, resolution, and manifests. Work through
this list end to end — a half-wired event kind is worse than none.

## Checklist

1. **`ovid-core/src/event.rs`** — add the variant to `BoundaryEvent`
   with kebab-case serde tag, then update:
   - `is_failure()` if the event can represent a failed operation
     (failures are first-class evidence, §6.2);
   - `type_label()` (stable, used for metrics + ledger record types);
   - the serde round-trip test.
2. **`ovid-observer/src/strace.rs`** — extend `TRACE_SET` and the parser
   if the event comes from a syscall. Parsing rules:
   - stitch `<unfinished ...>` / `<... resumed>` pairs by (pid, syscall);
   - unparsed lines are *counted*, never silently dropped;
   - high-volume success events should be `Ignored`, failures captured
     (see the stat/access handling for the pattern).
   Add parser tests with verbatim strace output lines (copy them from a
   real `strace -f -o` run).
3. **`ovid-observer/src/aggregate.rs`** — decide the signature: is the
   event collapsible (repeated identical successes) or a state
   transition (never collapse)? Add to `signature()` and test.
4. **Consumers** — wire where the event carries meaning:
   - `ovid-gateway/src/analysis.rs` for network-shaped events;
   - `ovid-experiment/src/resolution.rs` if the event seeds proposals;
   - `ovid-cli/src/pipeline.rs` (`absorb_execution`) if it feeds a
     manifest section or claim (append ledger evidence first, then
     claims referencing the ids).
5. **Trust tier:** guest-observer events are T2; host-enforced facts
   (exit codes, gateway decisions) are T0. Don't inflate.
6. **Tests:** unit tests at each touched layer, plus an integration test
   in `crates/ovid-cli/tests/integration.rs` using a fixture that
   actually triggers the event under strace.
7. **Docs:** update the event list in `docs/ARCHITECTURE.md`.
