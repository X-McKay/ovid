# Changelog

All notable changes to Ovid are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions track
the workspace version in `Cargo.toml`. The release workflow
(`.github/workflows/release.yml`) builds tagged binaries; entries under
**Unreleased** land in the next tag.

## [Unreleased]

### Added

- **Mounted NFS dependency evidence.** Linux process-backend trials now
  correlate observed absolute file opens and shared-object mappings with
  NFS/NFSv4 mount tables (Linux `/proc` plus a tested macOS/BSD table parser;
  runtime correlation there awaits a boundary observer). The typed T2 journal
  event, proof, and manifest preserve server/export identity, mount points,
  relative paths, read/write/failure counts, and evidence links without recording contents,
  credentials, or raw mount options. Because observation is not a
  counterfactual, these dependencies remain explicitly `unresolved`; their
  world-lock cells stay `proposed` until a mount treatment can be enforced.
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
