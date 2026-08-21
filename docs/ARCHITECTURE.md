# Ovid architecture

This document describes the implemented system and how it maps to the
Ovid technical specification ("spec §" references). Module docs in each
crate carry the fine-grained traceability; this is the map.

## Crate graph

```text
ovid-core        ids, digests, trust tiers (T0–T5), claim states, boundary events
   ├── ovid-evidence     hash-chained ledger, claims, confidence model
   ├── ovid-repository   acquisition, revision resolution, fingerprinting
   │      ├── ovid-inventory   language stats, ecosystem scanners, PURL, SBOM provider contract
   │      └── ovid-packs       pack schema + registry (runners/services/protocols/resolvers)
   ├── ovid-planner      command mining -> scored action graph
   ├── ovid-observer     BoundaryObserver contract + strace backend + aggregation
   ├── ovid-sandbox      ExecutionBackend: process sandbox + Firecracker layer
   ├── ovid-gateway      egress/DNS policy, virtual identities, fault policies, network analysis
   ├── ovid-experiment   success predicates, resolution proposals, MVW solver
   ├── ovid-world        worlds, world locks, Compose export
   ├── ovid-output       manifest, CycloneDX/SPDX, integration plan, diff
   └── ovid-cli          the pipeline wiring everything together
```

Layering is strict (no cycles); only the CLI composes all layers.

## Evidence flow (ADR-004)

1. Every observation — a scanned manifest file, a boundary event, a run
   outcome, an experiment result — is appended to the **evidence ledger**
   (`evidence.jsonl`) first. Each record embeds the digest of its
   predecessor; `verify_chain()` detects tampering, and the final chain
   head is published in the manifest's provenance (spec §22.6).
2. **Claims** (`claims.json`) are normalized graph statements
   (`workload:test connects-to service:orders-db`) holding evidence-id
   links and independent state dimensions (spec §22.3, §6.3).
   Confidence is a bounded noisy-OR over evidence trust tiers with
   contradiction penalties and hard caps — proposal-only (T5) claims cap
   at 0.5 (ADR-007).
3. The **manifest** and all exports are projections. Deleting them loses
   nothing that cannot be regenerated from the ledger.

## Boundary observation

`BoundaryObserver` is backend-neutral: `wrap(argv, out)` rewrites a
command to run under observation; `collect()` parses raw output into
normalized `EventEnvelope`s. The shipped backend uses `strace -f`
(ptrace), which works without kernel privileges; spec §30.5 explicitly
lists ptrace as an alternate mechanism, and an eBPF (Aya) backend slots
behind the same trait for MicroVM guests without touching the evidence
model.

Captured events (spec §13.7): exec success/failure, file opens and
misses, **stat/access misses** (modern shells and make locate tools with
stat-family PATH scans, not execve loops — a missing tool is visible only
as a stat miss), shared-object loads, socket connect results,
bind/listen, Unix sockets, **DNS queries and answers** (datagram payloads
on port-53 peers are decoded by a bounds-checked wire-format parser in
`ovid-observer/src/dns.rs`, FR-033), and process exits. Unparsed lines
are counted, never silently dropped (§27.5); aggregation collapses
repeated successes but preserves every failure signature and accounts
for all drops (§32.5).

DNS answers feed name identity into network analysis: external
observations are grouped by hostname (one logical dependency across CDN
address rotation, with an `endpoints` list), resolver servers are
surfaced so the pipeline can flag resolver bypass against
`/etc/resolv.conf`, and destinations with no observed resolution are
explicitly marked `ip-only` in the manifest — absence of a name is
reported as unknown, never hidden (§25.3). In MicroVM mode the gateway
serves DNS and supplies the same identities authoritatively.

Two §14.7 normalizers close the static/dynamic gap without crossing it:
successful opens under known package install layouts (`site-packages/`,
`node_modules/`, gem dirs — including `.dist-info` names, since import
and distribution names can differ) promote matching inventory components
to `loaded` with a `loads` claim (never `exercised`); and Compose files
are parsed into *declared* external systems (service, image, container
ports) that merge with observed destinations only on a name match —
port-only coincidence stays two records (§6.6).

Declared endpoints extend that dimension beyond Compose: a generic miner
(`ovid-inventory::endpoints`) extracts service-scheme URL literals from
structured config files (T4) and environment-bound indirections — config
placeholders (`https://${LLM_HOST}/v1`), `*_env:` convention keys, and
`getenv`-family reads of endpoint-named variables in source (T5,
proposal-only per ADR-007). An env-bound endpoint is reported as
`env-parameterized` external connectivity with everything the text
supports (scheme, URL path, shipped default, credential env *names* —
never values) and listed as unresolved rather than guessed; host matches
merge onto observed systems, and scheme default ports come from protocol
packs, not core code (ADR-005).

## Resolution and causality

After each run, `ovid-gateway` groups socket events into external-system
observations and classifies protocols via protocol packs (first-byte
signatures outrank ports, spec §24.2). `ovid-experiment` turns failures
into ranked **proposals** (spec §14.8, §18.1):

- missing executables (exec ENOENT or multi-directory PATH-scan misses
  with no successful exec) -> tool-resolver candidates;
- refused classified destinations -> service packs, else stubs;
- unknown protocols -> explicitly unresolved (FR-048).

Causality is strictly counterfactual (spec §20):

- a workload that **succeeded while a dependency was unavailable** is a
  natural counterfactual -> `optional`;
- `--counterfactual-env VAR` reruns the workload without a variable from
  clean state -> `required`/`optional`;
- the `MvwSolver` (crate `ovid-experiment`) minimizes a passing world by
  group-then-individual removal with repeat-based nondeterminism policy
  (§20.4–§20.6); unstable results become `unresolved`, never guessed.
  In local process mode the solver runs against simulated/world-runner
  backends; full service-cell minimization requires the MicroVM worker;
- `ovid tomography` runs each workload as an offline/online pair
  (isolated namespace vs. network access) and classifies dependencies
  from the comparison (`ovid-experiment/src/network.rs`): `required`
  only when exactly one externally-controlled dependency changed
  availability and flipped the outcome; when several changed together
  the verdict is group-level and each member stays `unresolved`, with
  the group named in the limitations (§20.4's coupling rule).

## Execution backends

### Process backend (trusted repositories)

`ProcessBackend` provides FR-027's "faster backend for trusted
repositories" on any Linux host:

- scrubbed environment (fixed PATH, workspace-scoped HOME/TMPDIR; host
  variables only via explicit `--inherit-env`);
- optional **network isolation** (`NetworkMode::Isolated`): the workload
  runs in an unprivileged user+network namespace — loopback up, no
  external routes — giving the process backend a real deny-all egress
  condition (FR-041) for counterfactual experiments;
- ephemeral copy-on-write workspaces — each run starts clean and the
  checkout is never modified (FR-025 semantics);
- process-group supervision with wall-clock deadlines, RLIMIT_CPU and
  RLIMIT_FSIZE (FR-024);
- optional strace observation.

It is **not** a security boundary; its `IsolationTier::TrustedProcess`
is recorded in every manifest so isolation claims stay honest.

### Firecracker backend (untrusted repositories, ADR-002)

`ovid-sandbox/src/firecracker.rs` implements the configuration plane:

- jailer command lines (dedicated jail dir, unprivileged UID/GID,
  netns — FR-021);
- the five-device layout of spec §13.5: immutable rootfs (root, ro),
  read-only source image (FR-023), writable overlay, bounded output,
  optional scratch;
- ordered Unix-socket REST payloads (§34.5): machine-config,
  boot-source, drives, vsock, InstanceStart;
- snapshot requests (pause-then-create, §16.6).

`run()` fails closed with `UnsupportedHost` when `/dev/kvm` or the
firecracker binary is absent — there is no silent fallback. Running the
full MicroVM loop requires a provisioned worker: a digest-pinned kernel
and base rootfs containing the guest agent, plus the jailer installed;
the payload generators are unit-tested so a worker integration is wiring,
not design.

## Gateway

`ovid-gateway` implements the Chameleon Gateway's decision plane
(spec §13.10, §17): deny-default egress (FR-041), registry-proxy
allowlists, DNS decisions (world aliases > registry proxy > virtual
identities in explore mode > NXDOMAIN), unconditional metadata-endpoint
blocking, stable per-name virtual identity allocation (`10.203.x.200+`),
and fault policies (refuse/timeout/reset/latency/malformed, FR-049) used
by counterfactual experiments. Packet-level enforcement belongs to the
MicroVM worker's netns/nftables data plane; in process mode decisions are
observational and the manifest's isolation tier says so.

## Worlds and outputs

A `World` is content-addressed; `with_treatment()` derives a world with
exactly one controlled change (§14.9). `WorldLock::from_world` produces
the replay-oriented lock (§26): cells, DNS map, startup order, workload +
success predicate, and a `Proposed`/`Verified` status — a lock is only
`verified` after a clean replay succeeds (ADR-008), which requires
service cells; local mode emits `proposed` and says so in limitations.

`ovid-output` renders the manifest (spec §25 shape with mandatory
completeness section), CycloneDX 1.5 (component state carried in
properties so declared/resolved/exercised distinctions survive export),
SPDX 2.3, the integration plan, and evidence-aware diffs.

## Extension points

| To add | Touch | Playbook |
|---|---|---|
| Ecosystem inventory | `ovid-inventory/src/scanners/` | `.claude/skills/add-scanner` |
| Language/tool/service/protocol support | `packs/*.yaml` | `.claude/skills/add-pack` |
| New boundary event | core event + observer + consumers | `.claude/skills/add-boundary-event` |
| Observer backend (eBPF) | implement `BoundaryObserver` | — |
| Execution backend | implement `ExecutionBackend` | — |
| External SBOM provider | `ovid-inventory/src/provider.rs` contract | — |

## Spec traceability (coarse)

| Spec area | Implementation |
|---|---|
| §8, §22, §23 evidence/claim model | `ovid-core`, `ovid-evidence` |
| §11.1 acquisition FR-001..007 | `ovid-repository` |
| §11.2 planning FR-010..017 | `ovid-planner` (+ predicates in `ovid-experiment`) |
| §11.3 isolation FR-020..028 | `ovid-sandbox` (process now; Firecracker config plane; full VM loop needs KVM worker) |
| §11.4 observation FR-030..039 | `ovid-observer` (+gateway corroboration pending MicroVM data plane) |
| §11.5 gateway FR-040..049 | `ovid-gateway` decision plane |
| §11.6 causality FR-050..054 | `ovid-experiment` |
| §11.8 SBOM FR-070..075 | `ovid-inventory`, `ovid-output` |
| §11.10 worlds FR-090..095 | `ovid-world`, pipeline synthesis (replay verification pending service cells) |
| §11.11/§29 remediation | `ovid diff` (composition scope); full validate pipeline is fleet-phase work |
| §11.12 explainability FR-110..113 | claims + `ovid explain` + completeness sections |
| §15 packs | `ovid-packs` + `packs/` |
| §37 testing | fixtures, integration, golden, perf suites |

Out of scope for this local-mode implementation (explicitly, per the
spec's phased plan §38): the distributed control plane, fleet graph and
reverse-caller resolution (Phase 3), adaptive HTTP/gRPC stub mutation
loops (Phase 2), LSP/SCIP source attribution (Phase 2), and VEX policy
engines (Phase 4). The data model already reserves their vocabulary
(fleet states, attribution tiers, treatments) so they extend rather than
break the schema.
