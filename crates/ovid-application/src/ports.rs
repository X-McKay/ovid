//! Outbound ports (proposal §8) and the capability model (proposal §5.5).
//!
//! Ports are coarse-grained and aligned to stable capabilities. The most
//! important one is [`LaboratoryPort`]: the application never separately
//! coordinates a sandbox, an observer, and a network controller — those
//! must cooperate atomically inside one laboratory adapter to enforce a
//! trial and produce enforcement provenance (proposal §8.3).
//!
//! Use cases select behavior by *capability*, never by backend name
//! (proposal §5.5): if a laboratory cannot enforce a requested treatment,
//! the affected candidates become `unresolved` — the experiment is never
//! silently weakened.

use ovid_domain::{BaselineVerdict, CausalConclusion, DependencyKey, Treatment, TrialRecord};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use thiserror::Error;

/// Identity of a provider (laboratory, observer, journal) for provenance.
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct ProviderIdentity {
    pub name: String,
    pub version: String,
}

impl ProviderIdentity {
    /// `name@version` form for scopes and reports.
    pub fn describe(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

/// What a laboratory adapter can truthfully do (proposal §5.5). Reported
/// by the adapter; verified by its contract tests, never assumed.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug, Default)]
pub struct LabCapabilities {
    /// Trials run inside a guest VM boundary.
    pub vm_isolation: bool,
    /// Every trial starts from an equivalent clean snapshot fork.
    pub clean_snapshot_restore: bool,
    /// Deny-all external egress with loopback intact.
    pub deny_all_egress: bool,
    /// Block exactly one logical network dependency while others remain
    /// reachable (per-dependency egress control via the gateway).
    pub per_dependency_egress: bool,
    /// Hide a single executable from the search path for a trial.
    pub executable_hiding: bool,
    /// Boundary observation (process/file/network events) is captured.
    pub observation: bool,
}

impl LabCapabilities {
    /// Whether this laboratory can *enforce* the given treatment
    /// (proposal §5.5). `Treatment::None` needs nothing.
    pub fn can_enforce(&self, treatment: &Treatment) -> bool {
        match treatment {
            Treatment::None => true,
            Treatment::DenyAllEgress => self.deny_all_egress,
            Treatment::BlockDependency { .. } => self.per_dependency_egress,
            Treatment::HideExecutable { .. } => self.executable_hiding,
        }
    }
}

/// A prepared environment: toolchain + provisioned dependencies
/// (proposal §8.3). The path is an opaque handle owned by the adapter.
#[derive(Clone, Debug)]
pub struct PreparedEnvironment {
    pub id: String,
    pub workspace: PathBuf,
    /// The provisioning trial, when a provision command ran.
    pub provision: Option<TrialRecord>,
    /// Digest describing the prepared environment for the scope.
    pub environment_digest: String,
}

/// An immutable snapshot every baseline and variant forks from
/// (proposal §10.8, ADR: same-snapshot rule).
#[derive(Clone, Debug)]
pub struct SnapshotRef {
    pub id: String,
    pub path: PathBuf,
    pub label: String,
}

/// One requested trial (proposal §8.3).
#[derive(Clone, Debug)]
pub struct TrialSpec {
    /// Human label recorded in the journal (`baseline-1`, `no-egress-2`).
    pub label: String,
    pub argv: Vec<String>,
    pub treatment: Treatment,
    pub timeout_seconds: u64,
}

/// One external-network candidate observed during a trial, normalized to
/// a logical identity (proposal §10.4).
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct NetworkCandidate {
    pub key: DependencyKey,
    /// Outside the workload's own control (not its own listener).
    pub externally_controlled: bool,
    /// Every observed attempt against this dependency failed.
    pub all_failed: bool,
    /// Every failure was an *enforced* refusal by the laboratory gateway's
    /// deny posture (nothing real was contacted), not a happenstance
    /// outage or a genuinely unreachable host. Distinguishes an enforced
    /// counterfactual from a merely natural one (spec §13.10, ADR-014).
    #[serde(default)]
    pub enforced_unavailable: bool,
    pub attempts: u64,
    pub failures: u64,
}

/// One environment-provided executable observed during a trial
/// (proposal §10.4): either used successfully, or searched for and
/// missing (a natural counterfactual seed when the baseline passes).
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct ExecutableCandidate {
    /// Basename as resolved on the search path.
    pub name: String,
    /// Whether the run actually found/used it (`false` = searched and
    /// demonstrably absent).
    pub found: bool,
    /// For a missing executable: the tool-resolver pack's install
    /// candidate (`package via provider`), when one exists. A proposal
    /// only — surfaced as remediation, never as evidence (ADR-007).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver_hint: Option<String>,
}

/// Aggregated accesses to one path below a mounted network filesystem.
/// Paths are relative to the mount point and file contents are never
/// captured (spec §12.1, §13.7).
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct NfsFileAccess {
    /// Mount point through which the file was accessed.
    pub mount_point: String,
    /// Path relative to the mount root (`/` denotes the root itself).
    pub path: String,
    pub read_attempts: u64,
    pub write_attempts: u64,
    pub failures: u64,
}

/// Repository-declared NFS mapping supplied to the laboratory. The lab
/// does not mount it; this is a path/identity map for an absent-mount probe.
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct NfsDeclaration {
    pub key: DependencyKey,
    pub server: String,
    pub export: String,
    pub fs_type: String,
    pub mount_point: String,
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    pub source_file: String,
    pub source_kind: String,
}

/// An NFS server/export observed through file access during a trial.
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct NfsCandidate {
    pub key: DependencyKey,
    pub server: String,
    pub export: String,
    /// Filesystem variants observed (`nfs`, `nfs4`).
    pub fs_types: Vec<String>,
    /// All local mount points mapping this export.
    pub mount_points: Vec<String>,
    /// True only when every observed mount of the export was read-only.
    pub read_only: bool,
    /// Repository deployment metadata declared this mapping.
    pub declared: bool,
    /// The trial ran without this NFS export mounted. Microsandbox makes
    /// this true by construction because Ovid forwards only the workspace.
    pub unavailable_during_trial: bool,
    /// Services/containers that declare this mapping.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
    /// Repository declaration files supporting this candidate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declaration_sources: Vec<String>,
    /// Deduplicated per-file access records.
    pub accesses: Vec<NfsFileAccess>,
    /// Ledger ids of `nfs-access-observed` records supporting this entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

/// One egress request the laboratory gateway named during a trial: what
/// the workload tried to reach and what the policy did about it. The
/// full record (method, path, decision) is richer than the host:port
/// candidate it feeds, so it is preserved as its own evidence.
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct EgressIntent {
    pub host: String,
    pub port: u16,
    /// `https` (CONNECT tunnel) or `http` (absolute-form request).
    pub scheme: String,
    /// `CONNECT`, or the HTTP method of a plain request.
    pub method: String,
    /// URL path for plain HTTP; empty for CONNECT (TLS is opaque).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// `refused` (nothing contacted), `forwarded`, or `forward-failed`.
    pub decision: String,
}

/// What the laboratory's observer established during one trial.
#[derive(Clone, PartialEq, Serialize, Debug, Default)]
pub struct TrialObservations {
    pub network: Vec<NetworkCandidate>,
    /// Named egress intents from the lab gateway (proxied destinations
    /// the syscall boundary hides).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress_intents: Vec<EgressIntent>,
    /// Environment-provided executables the workload used or searched
    /// for (workspace-internal tools are provisioned content, not
    /// environment dependencies, and are excluded).
    pub executables: Vec<ExecutableCandidate>,
    /// NFS server/exports reached through observed file operations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nfs: Vec<NfsCandidate>,
    /// Whether boundary observation actually ran (honesty over silence).
    pub observed: bool,
    pub events_captured: u64,
}

/// A completed trial: the domain record plus raw run detail.
#[derive(Clone, Debug)]
pub struct TrialResult {
    pub record: TrialRecord,
    pub observations: TrialObservations,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    /// Bounded output tail for diagnostics (never the full log).
    pub output_tail: String,
}

/// Laboratory failures (proposal §16.1's `CapabilityUnavailable` and
/// environment classes).
#[derive(Error, Debug)]
pub enum LabError {
    #[error("laboratory capability unavailable: {0}")]
    Unsupported(String),
    #[error("environment preparation failed: {0}")]
    Preparation(String),
    #[error("trial execution failed: {0}")]
    Execution(String),
}

/// The laboratory port (proposal §8.3): prepare once, snapshot once, fork
/// every trial from the snapshot, destroy at the end.
pub trait LaboratoryPort {
    /// Adapter identity for provenance.
    fn identity(&self) -> ProviderIdentity;
    /// Truthful capability report (proposal §5.5).
    fn capabilities(&self) -> LabCapabilities;
    /// Prepare the environment; runs the provisioning command when given.
    fn prepare(&mut self, provision: Option<&[String]>) -> Result<PreparedEnvironment, LabError>;
    /// Freeze an immutable snapshot of the prepared environment.
    fn snapshot(
        &mut self,
        environment: &PreparedEnvironment,
        label: &str,
    ) -> Result<SnapshotRef, LabError>;
    /// Run one trial from a clean fork of the snapshot, enforcing the
    /// treatment and reporting enforcement honestly.
    fn run_trial(
        &mut self,
        snapshot: &SnapshotRef,
        spec: &TrialSpec,
    ) -> Result<TrialResult, LabError>;
    /// Tear the environment down (best-effort; workspaces are disposable).
    fn destroy(&mut self, environment: PreparedEnvironment) -> Result<(), LabError>;
}

/// Typed journal events (proposal §12.1). Adapters append these to the
/// canonical hash-chained ledger; application code never writes untyped
/// JSON blobs.
#[derive(Clone, PartialEq, Serialize, Debug)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum JournalEvent {
    WorkloadSelected {
        workload: String,
        argv: Vec<String>,
    },
    EnvironmentPrepared {
        environment_digest: String,
        provision: Option<TrialRecord>,
    },
    SnapshotCreated {
        id: String,
        label: String,
    },
    TrialCompleted {
        record: TrialRecord,
        exit_code: Option<i32>,
        duration_ms: u64,
        /// Bounded output tail — the diagnostics bundle keeps enough to
        /// debug a failed trial without shipping full logs (§16.3).
        output_tail: String,
    },
    BaselineClassified {
        verdict: BaselineVerdict,
    },
    DependencyClassified {
        conclusion: CausalConclusion,
    },
    WorldSynthesized {
        digest: String,
        required: usize,
        optional: usize,
        unresolved: usize,
    },
    ReplayCompleted {
        label: String,
        passed: bool,
    },
    /// Named egress intents from one trial's gateway — what the workload
    /// tried to reach and whether anything was contacted.
    EgressObserved {
        trial: String,
        intents: Vec<EgressIntent>,
    },
    /// Static deployment declarations for an NFS mapping. This is T4
    /// repository evidence and does not imply that a mount was present.
    NfsDeclared {
        filesystems: Vec<NfsDeclaration>,
    },
    /// File operations attributed to declared NFS paths or already-mounted
    /// server/exports. This is observation evidence; causal necessity comes
    /// from the surrounding passing/failing no-mount condition.
    NfsAccessObserved {
        trial: String,
        filesystems: Vec<NfsCandidate>,
    },
    LimitationRecorded {
        detail: String,
    },
}

/// Journal failures.
#[derive(Error, Debug)]
pub enum JournalError {
    #[error("journal append failed: {0}")]
    Append(String),
}

/// The analysis journal port (proposal §8.5): append-only, typed, returns
/// the ledger evidence id for provenance links.
pub trait JournalPort {
    fn append(&mut self, event: &JournalEvent) -> Result<String, JournalError>;
}

/// Progress sink (proposal §8.8): conclusions for the terminal, raw logs
/// for the bundle.
pub trait ProgressPort {
    fn emit(&self, stage: &str, detail: &str);
}

/// A progress sink that discards everything (tests, quiet mode).
#[derive(Default)]
pub struct NullProgress;

impl ProgressPort for NullProgress {
    fn emit(&self, _stage: &str, _detail: &str) {}
}

/// Merge network candidates across trials into per-dependency evidence:
/// a dependency counts as attempted when any trial attempted it, and as
/// unavailable under treatment only when *no* trial saw it succeed.
pub fn merge_candidates(trials: &[&TrialObservations]) -> Vec<NetworkCandidate> {
    let mut merged: BTreeMap<DependencyKey, NetworkCandidate> = BTreeMap::new();
    for observations in trials {
        for candidate in &observations.network {
            merged
                .entry(candidate.key.clone())
                .and_modify(|existing| {
                    existing.attempts += candidate.attempts;
                    existing.failures += candidate.failures;
                    existing.all_failed &= candidate.all_failed;
                    existing.enforced_unavailable &= candidate.enforced_unavailable;
                    existing.externally_controlled |= candidate.externally_controlled;
                })
                .or_insert_with(|| candidate.clone());
        }
    }
    merged.into_values().collect()
}

/// Merge executable candidates across trials: one success anywhere means
/// the tool exists (`found`), mirroring the network merge rule.
pub fn merge_executables(trials: &[&TrialObservations]) -> Vec<ExecutableCandidate> {
    let mut merged: BTreeMap<String, ExecutableCandidate> = BTreeMap::new();
    for observations in trials {
        for candidate in &observations.executables {
            merged
                .entry(candidate.name.clone())
                .and_modify(|existing| {
                    existing.found |= candidate.found;
                    if existing.resolver_hint.is_none() {
                        existing.resolver_hint = candidate.resolver_hint.clone();
                    }
                })
                .or_insert_with(|| candidate.clone());
        }
    }
    merged.into_values().collect()
}

/// Merge NFS observations across repeated trials deterministically.
pub fn merge_nfs_candidates(trials: &[&TrialObservations]) -> Vec<NfsCandidate> {
    let mut merged: BTreeMap<DependencyKey, NfsCandidate> = BTreeMap::new();
    for observations in trials {
        for candidate in &observations.nfs {
            merged
                .entry(candidate.key.clone())
                .and_modify(|existing| {
                    existing.read_only &= candidate.read_only;
                    existing.declared |= candidate.declared;
                    existing.unavailable_during_trial &= candidate.unavailable_during_trial;
                    for service in &candidate.services {
                        if !existing.services.contains(service) {
                            existing.services.push(service.clone());
                        }
                    }
                    for source in &candidate.declaration_sources {
                        if !existing.declaration_sources.contains(source) {
                            existing.declaration_sources.push(source.clone());
                        }
                    }
                    for fs_type in &candidate.fs_types {
                        if !existing.fs_types.contains(fs_type) {
                            existing.fs_types.push(fs_type.clone());
                        }
                    }
                    for mount_point in &candidate.mount_points {
                        if !existing.mount_points.contains(mount_point) {
                            existing.mount_points.push(mount_point.clone());
                        }
                    }
                    for access in &candidate.accesses {
                        match existing.accesses.iter_mut().find(|record| {
                            record.mount_point == access.mount_point && record.path == access.path
                        }) {
                            Some(record) => {
                                record.read_attempts += access.read_attempts;
                                record.write_attempts += access.write_attempts;
                                record.failures += access.failures;
                            }
                            None => existing.accesses.push(access.clone()),
                        }
                    }
                    for evidence in &candidate.evidence {
                        if !existing.evidence.contains(evidence) {
                            existing.evidence.push(evidence.clone());
                        }
                    }
                })
                .or_insert_with(|| candidate.clone());
        }
    }
    for candidate in merged.values_mut() {
        candidate.fs_types.sort();
        candidate.mount_points.sort();
        candidate.services.sort();
        candidate.declaration_sources.sort();
        candidate.evidence.sort();
        candidate
            .accesses
            .sort_by(|a, b| (&a.mount_point, &a.path).cmp(&(&b.mount_point, &b.path)));
    }
    merged.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_gate_treatments() {
        let caps = LabCapabilities {
            deny_all_egress: true,
            ..Default::default()
        };
        assert!(caps.can_enforce(&Treatment::None));
        assert!(caps.can_enforce(&Treatment::DenyAllEgress));
        assert!(!caps.can_enforce(&Treatment::HideExecutable {
            name: "protoc".into()
        }));
    }

    #[test]
    fn merge_executables_prefers_found_and_keeps_hints() {
        let a = TrialObservations {
            executables: vec![ExecutableCandidate {
                name: "protoc".into(),
                found: false,
                resolver_hint: Some("protobuf-compiler via apt".into()),
            }],
            ..Default::default()
        };
        let b = TrialObservations {
            executables: vec![ExecutableCandidate {
                name: "protoc".into(),
                found: true,
                resolver_hint: None,
            }],
            ..Default::default()
        };
        let merged = merge_executables(&[&a, &b]);
        assert_eq!(merged.len(), 1);
        assert!(
            merged[0].found,
            "one success anywhere means the tool exists"
        );
        assert!(merged[0].resolver_hint.is_some());
    }

    #[test]
    fn merge_candidates_requires_failure_everywhere_for_unavailability() {
        let a = TrialObservations {
            network: vec![NetworkCandidate {
                key: DependencyKey::network("db:5432"),
                externally_controlled: true,
                all_failed: true,
                enforced_unavailable: false,
                attempts: 2,
                failures: 2,
            }],
            observed: true,
            ..Default::default()
        };
        let b = TrialObservations {
            network: vec![NetworkCandidate {
                key: DependencyKey::network("db:5432"),
                externally_controlled: true,
                all_failed: false,
                enforced_unavailable: false,
                attempts: 1,
                failures: 0,
            }],
            observed: true,
            ..Default::default()
        };
        let merged = merge_candidates(&[&a, &b]);
        assert_eq!(merged.len(), 1);
        assert!(
            !merged[0].all_failed,
            "one success anywhere means available"
        );
        assert_eq!(merged[0].attempts, 3);
    }

    #[test]
    fn merge_nfs_candidates_combines_mounts_accesses_and_evidence() {
        let candidate = |mount: &str, reads: u64, read_only: bool, evidence: &str| NfsCandidate {
            key: DependencyKey::network_filesystem("files.internal:/exports/models"),
            server: "files.internal".into(),
            export: "/exports/models".into(),
            fs_types: vec!["nfs4".into()],
            mount_points: vec![mount.into()],
            read_only,
            declared: true,
            unavailable_during_trial: true,
            services: vec!["model-api".into()],
            declaration_sources: vec!["compose.yaml".into()],
            accesses: vec![NfsFileAccess {
                mount_point: mount.into(),
                path: "/model.bin".into(),
                read_attempts: reads,
                write_attempts: 0,
                failures: 0,
            }],
            evidence: vec![evidence.into()],
        };
        let a = TrialObservations {
            nfs: vec![candidate("/mnt/a", 2, true, "evidence:1")],
            ..Default::default()
        };
        let b = TrialObservations {
            nfs: vec![candidate("/mnt/a", 1, false, "evidence:2")],
            ..Default::default()
        };

        let merged = merge_nfs_candidates(&[&a, &b]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].accesses[0].read_attempts, 3);
        assert!(!merged[0].read_only);
        assert_eq!(merged[0].evidence, vec!["evidence:1", "evidence:2"]);
    }
}
