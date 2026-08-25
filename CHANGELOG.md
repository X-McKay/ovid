# Changelog

All notable changes to Ovid are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions track
the workspace version in `Cargo.toml`. The release workflow
(`.github/workflows/release.yml`) builds tagged binaries; entries under
**Unreleased** land in the next tag.

## [Unreleased]

### Documentation

- **Safety & isolation section** (README + `docs/ARCHITECTURE.md`): what
  the default `--egress deny` posture guarantees (workload trials contact
  nothing real), the two deliberate exceptions (online provisioning;
  `--egress allow`), the partial-deny caveat on hosts without user
  namespaces, and the process-vs-guest-VM trust boundary — with a
  per-activity decision table.
- **Operating skills** for running Ovid, usable by Claude Code and Codex
  (`.claude/skills/`, indexed in a new root `AGENTS.md`): `setup-ovid`
  (install + host prerequisites + `ovid doctor`), `use-ovid` (command,
  egress, backend and trust choices; reading results), and
  `troubleshoot-ovid` (diagnosing failing or surprising runs).

### Added

- **No-mount NFS dependency analysis.** Static inventory discovers Compose
  named NFS volumes and direct Kubernetes NFS volumes, including the declaring
  service and container path, without mounting or contacting them. Microsandbox
  runs receive declarations only as correlation metadata and expose no NFS
  folder; guest file attempts are aggregated by relative path with
  read/write/failure counts. A stable passing no-NFS run proves the export
  `optional` for that workload scope. A failing run records attempted paths but
  stays `unresolved`—it never guesses `required` without a controlled passing
  comparison. Trusted-process trials retain observation of already-mounted NFS
  exports without creating mounts. The typed journal, proof, manifest, diff,
  exports, and world projection preserve evidence links while excluding file
  contents, credentials, and raw mount options.
- **Current microsandbox CLI compatibility.** The guest adapter now uses the
  current `msb run` surface and relies on Ovid's host watchdog for the full
  pull/boot/workload deadline, avoiding removed legacy CLI flags.
- **Laboratory gateway — egress by name (ADR-017, spec §13.10).** A
  lab-controlled, std-only HTTP proxy names every destination a workload
  tries to reach (scheme, host, port, method, path) even when a loopback
  proxy hides it from the syscall boundary. `ovid prove --egress`/`ovid
  replay --egress` select the posture:
  - `deny` (default) — trials run in a network namespace and the
    in-namespace gateway refuses every proxied request; **nothing real is
    contacted**. Named intents are preserved as T1 `egress-observed`
    journal evidence and folded into network candidates (loopback
    excluded).
  - `allow` — a host-side forward gateway chains the host upstream for
    real, attributed egress, and can block exactly one dependency at a
    time (`BlockDependency`, the gateway's `ForwardExcept`) to resolve a
    coupled group into individual `required`/`optional` labels.
- **Enforced-deny counterfactuals.** Because a deny-posture refusal is
  *enforced*, a destination refused while the baseline still passed is
  classified `optional` on the strength of that enforcement
  (`ovid_domain::classify_enforced_deny`), with a reason that names the
  refusal — distinct from a passive natural counterfactual and from a
  `forward-failed` genuine outage. Deny mode alone now labels
  attempted-and-survivable endpoints, with no trial spent.

### Changed

- Network candidates carry `enforced_unavailable`, set only when every
  gateway attempt against a destination was a policy refusal (nothing
  forwarded, nothing merely failed to connect). It is ANDed across trials,
  so any forwarded or genuinely-failed observation downgrades the label to
  the natural-counterfactual path — enforcement is never assumed.

### Documentation

- `docs/ARCHITECTURE.md` gains the laboratory-gateway section and ADR-017;
  `CLAUDE.md` invariant 15 (egress is named, `--egress deny` contacts
  nothing real).
