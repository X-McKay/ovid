//! Laboratory adapters (proposal §8.3): the existing sandbox backends,
//! observer, and network isolation wrapped behind the application's
//! `LaboratoryPort`, composed here in the CLI composition root
//! (proposal §6.1: adapters stay modules until extraction is justified).
//!
//! Contract highlights:
//!
//! - **Immutable snapshot forks.** `prepare` materializes and provisions
//!   one environment; `snapshot` freezes it; every trial runs in a fresh
//!   full-fidelity copy of that snapshot and the copy is destroyed after
//!   the result is persisted. Baseline and variants therefore start from
//!   the same state (proposal §10.8) — unlike the legacy pipeline's
//!   shared mutable workspace.
//! - **Truthful capabilities.** Deny-all egress is reported only when the
//!   backend can actually enforce it (user network namespaces for the
//!   process backend, native `--no-net` for the microsandbox guest). A
//!   treatment the laboratory cannot enforce is refused with
//!   `LabError::Unsupported`, never silently weakened (proposal §5.5).
//! - **Scrubbed environment.** Only the pipeline's default allowlists
//!   (toolchain discovery online, `PATH`/`HOME` offline) plus explicit
//!   extra variables reach the workload; secrets never do.

use crate::pipeline::{BackendKind, OFFLINE_DEFAULT_ENV, ONLINE_DEFAULT_ENV};
use ovid_application::{
    LabCapabilities, LabError, LaboratoryPort, NetworkCandidate, PreparedEnvironment,
    ProviderIdentity, SnapshotRef, TrialObservations, TrialResult, TrialSpec,
};
use ovid_core::Digest;
use ovid_domain::{DependencyKey, EnforcementReport, Treatment, TrialOutcome, TrialRecord};
use ovid_experiment::externally_controlled;
use ovid_observer::aggregate;
use ovid_packs::PackRegistry;
use ovid_sandbox::{
    network_isolation_available, ExecutionBackend, NetworkMode, RunResult, RunSpec, WorkspaceMode,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Resolve to an absolute path: backends change the working directory of
/// spawned workloads, so relative workspace/trace paths would resolve
/// against the wrong root.
fn absolutize(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

/// Full-fidelity recursive copy: unlike `materialize_workspace` (which
/// skips caches for *source* trees), snapshot forks must preserve the
/// provisioned state — `node_modules`, `.venv`, `target` are exactly what
/// provisioning paid for.
fn copy_tree_full(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_tree_full(&entry.path(), &target)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &target)?;
        } else if file_type.is_symlink() {
            #[cfg(unix)]
            if let Ok(dest) = std::fs::read_link(entry.path()) {
                let _ = std::os::unix::fs::symlink(dest, &target);
            }
        }
    }
    Ok(())
}

/// The host laboratory: process or microsandbox backend + strace
/// observation + real network isolation, run out of one `.lab` directory
/// inside the analysis bundle.
pub struct HostLaboratory {
    backend: Box<dyn ExecutionBackend>,
    kind: BackendKind,
    registry: PackRegistry,
    source_root: PathBuf,
    lab_dir: PathBuf,
    /// Environment variable names inherited for untreated (online) runs.
    online_env: Vec<String>,
    /// Environment variable names inherited for egress-denied runs.
    offline_env: Vec<String>,
    source_digest: String,
    trial_counter: u64,
}

impl HostLaboratory {
    /// Build a laboratory over the chosen backend. `extra_env` names are
    /// added to both allowlists (never values — values come from the host
    /// at spawn time and are scrubbed otherwise).
    pub fn new(
        kind: BackendKind,
        guest_image: &str,
        source_root: &Path,
        source_digest: &str,
        lab_dir: &Path,
        extra_env: &[String],
        registry: PackRegistry,
    ) -> Result<HostLaboratory, LabError> {
        let backend: Box<dyn ExecutionBackend> = match kind {
            BackendKind::Process => Box::new(
                ovid_sandbox::ProcessBackend::new()
                    .map_err(|e| LabError::Unsupported(e.to_string()))?,
            ),
            BackendKind::Microsandbox => Box::new(
                ovid_sandbox::MicrosandboxBackend::new(guest_image)
                    .map_err(|e| LabError::Unsupported(e.to_string()))?,
            ),
        };
        let mut online_env: Vec<String> =
            ONLINE_DEFAULT_ENV.iter().map(|v| v.to_string()).collect();
        let mut offline_env: Vec<String> =
            OFFLINE_DEFAULT_ENV.iter().map(|v| v.to_string()).collect();
        for var in extra_env {
            if !online_env.contains(var) {
                online_env.push(var.clone());
            }
            if !offline_env.contains(var) {
                offline_env.push(var.clone());
            }
        }
        Ok(HostLaboratory {
            backend,
            kind,
            registry,
            source_root: absolutize(source_root),
            lab_dir: absolutize(lab_dir),
            online_env,
            offline_env,
            source_digest: source_digest.to_string(),
            trial_counter: 0,
        })
    }

    /// The isolation mechanism label recorded in enforcement reports.
    fn isolation_mechanism(&self) -> &'static str {
        match self.kind {
            BackendKind::Process => "user-netns",
            BackendKind::Microsandbox => "guest-no-net",
        }
    }

    fn run_in(
        &self,
        dir: &Path,
        argv: &[String],
        network: NetworkMode,
        inherit_env: &[String],
        timeout_seconds: u64,
    ) -> Result<RunResult, LabError> {
        let mut spec = RunSpec::new(
            argv.to_vec(),
            WorkspaceMode::InPlace {
                root: dir.to_path_buf(),
            },
        );
        spec.inherit_env = inherit_env.to_vec();
        spec.limits.wall_time = Duration::from_secs(timeout_seconds);
        spec.network = network;
        self.backend
            .run(&spec)
            .map_err(|e| LabError::Execution(format!("run {argv:?}: {e}")))
    }

    /// Stable failure signature for cross-run comparison (§20.6): the
    /// exit disposition, which is reproducible where log text is not.
    fn signature(result: &RunResult) -> Option<String> {
        if result.success() {
            return None;
        }
        Some(if result.timed_out {
            "timeout".to_string()
        } else if let Some(code) = result.exit_code {
            format!("exit:{code}")
        } else if let Some(signal) = result.signal {
            format!("signal:{signal}")
        } else {
            "unknown".to_string()
        })
    }

    fn observations(&self, result: &RunResult) -> TrialObservations {
        let (events, observed) = match &result.observation {
            Some(observation) => (observation.events.clone(), true),
            None => (vec![], false),
        };
        let aggregated = aggregate(events);
        let network =
            ovid_gateway::analyze_network(&aggregated.events, &self.registry, &BTreeMap::new());
        let candidates = network
            .external
            .iter()
            .map(|observation| NetworkCandidate {
                key: DependencyKey::network(observation.identity()),
                externally_controlled: externally_controlled(observation),
                all_failed: observation.all_failed(),
                attempts: observation.attempts,
            })
            .collect();
        TrialObservations {
            network: candidates,
            observed,
            events_captured: aggregated.events.len() as u64,
        }
    }

    fn record(
        label: &str,
        treatment: Treatment,
        enforcement: EnforcementReport,
        result: &RunResult,
    ) -> TrialRecord {
        TrialRecord {
            label: label.to_string(),
            treatment,
            enforcement,
            outcome: TrialOutcome {
                passed: result.success(),
                failure_signature: Self::signature(result),
            },
            evidence: vec![],
        }
    }
}

impl LaboratoryPort for HostLaboratory {
    fn identity(&self) -> ProviderIdentity {
        ProviderIdentity {
            name: self.backend.name().to_string(),
            version: ovid_core::OVID_VERSION.to_string(),
        }
    }

    fn capabilities(&self) -> LabCapabilities {
        let deny_all_egress = match self.kind {
            BackendKind::Process => network_isolation_available(),
            BackendKind::Microsandbox => true,
        };
        LabCapabilities {
            vm_isolation: matches!(self.kind, BackendKind::Microsandbox),
            clean_snapshot_restore: true,
            deny_all_egress,
            per_dependency_egress: false,
            env_removal: false,
            executable_hiding: false,
            observation: matches!(self.kind, BackendKind::Microsandbox)
                || ovid_observer::strace_available(),
        }
    }

    fn prepare(&mut self, provision: Option<&[String]>) -> Result<PreparedEnvironment, LabError> {
        let env_dir = self.lab_dir.join("env");
        if env_dir.exists() {
            std::fs::remove_dir_all(&env_dir)
                .map_err(|e| LabError::Preparation(format!("clear {}: {e}", env_dir.display())))?;
        }
        ovid_sandbox::materialize_workspace(&self.source_root, &env_dir)
            .map_err(|e| LabError::Preparation(format!("materialize workspace: {e}")))?;
        let provision_record = match provision {
            Some(argv) if !argv.is_empty() => {
                let result = self.run_in(
                    &env_dir,
                    argv,
                    NetworkMode::Inherit,
                    &self.online_env.clone(),
                    3600,
                )?;
                Some(Self::record(
                    "provision",
                    Treatment::None,
                    EnforcementReport::enforced(Treatment::None, "host-network"),
                    &result,
                ))
            }
            _ => None,
        };
        let environment_digest = Digest::of_bytes(
            format!(
                "source={};provision={:?};backend={}",
                self.source_digest,
                provision,
                self.backend.name()
            )
            .as_bytes(),
        )
        .hex()
        .to_string();
        Ok(PreparedEnvironment {
            id: "lab-env".into(),
            workspace: env_dir,
            provision: provision_record,
            environment_digest,
        })
    }

    fn snapshot(
        &mut self,
        environment: &PreparedEnvironment,
        label: &str,
    ) -> Result<SnapshotRef, LabError> {
        let snap_dir = self.lab_dir.join(format!("snapshot-{label}"));
        if snap_dir.exists() {
            std::fs::remove_dir_all(&snap_dir)
                .map_err(|e| LabError::Preparation(format!("clear snapshot: {e}")))?;
        }
        copy_tree_full(&environment.workspace, &snap_dir)
            .map_err(|e| LabError::Preparation(format!("freeze snapshot: {e}")))?;
        Ok(SnapshotRef {
            id: format!("snapshot-{label}"),
            path: snap_dir,
            label: label.to_string(),
        })
    }

    fn run_trial(
        &mut self,
        snapshot: &SnapshotRef,
        spec: &TrialSpec,
    ) -> Result<TrialResult, LabError> {
        let (network, inherit_env, enforcement) = match &spec.treatment {
            Treatment::None => (
                NetworkMode::Inherit,
                self.online_env.clone(),
                EnforcementReport::enforced(Treatment::None, "host-network"),
            ),
            Treatment::DenyAllEgress => {
                if !self.capabilities().deny_all_egress {
                    return Err(LabError::Unsupported(
                        "deny-all egress cannot be enforced on this host (no unprivileged \
                         user namespaces); refusing to run a weakened trial"
                            .into(),
                    ));
                }
                (
                    NetworkMode::Isolated,
                    self.offline_env.clone(),
                    EnforcementReport::enforced(
                        Treatment::DenyAllEgress,
                        self.isolation_mechanism(),
                    ),
                )
            }
            other => {
                return Err(LabError::Unsupported(format!(
                    "treatment `{}` is not supported by this laboratory",
                    other.describe()
                )))
            }
        };
        // Fork: every trial gets a pristine copy of the frozen snapshot.
        self.trial_counter += 1;
        let trial_dir = self
            .lab_dir
            .join(format!("trial-{:03}-{}", self.trial_counter, spec.label));
        if trial_dir.exists() {
            std::fs::remove_dir_all(&trial_dir)
                .map_err(|e| LabError::Preparation(format!("clear trial dir: {e}")))?;
        }
        copy_tree_full(&snapshot.path, &trial_dir)
            .map_err(|e| LabError::Preparation(format!("fork snapshot: {e}")))?;

        let result = self.run_in(
            &trial_dir,
            &spec.argv,
            network,
            &inherit_env,
            spec.timeout_seconds,
        )?;
        let observations = self.observations(&result);
        let record = Self::record(&spec.label, spec.treatment.clone(), enforcement, &result);
        let output_tail = format!("{}\n{}", result.stdout_tail, result.stderr_tail);
        let trial = TrialResult {
            record,
            observations,
            exit_code: result.exit_code,
            duration_ms: result.duration.as_millis() as u64,
            output_tail,
        };
        // Destroy the overlay after result persistence (proposal §14.5).
        let _ = std::fs::remove_dir_all(&trial_dir);
        Ok(trial)
    }

    fn destroy(&mut self, environment: PreparedEnvironment) -> Result<(), LabError> {
        let _ = std::fs::remove_dir_all(&environment.workspace);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_copy_preserves_provisioned_caches() {
        let source = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(source.path().join("node_modules/dep")).unwrap();
        std::fs::write(source.path().join("node_modules/dep/index.js"), "x").unwrap();
        std::fs::write(source.path().join("main.js"), "y").unwrap();
        let dest = tempfile::tempdir().unwrap();
        copy_tree_full(source.path(), dest.path()).unwrap();
        assert!(
            dest.path().join("node_modules/dep/index.js").exists(),
            "snapshot forks must keep what provisioning installed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn process_laboratory_reports_truthful_capabilities() {
        let registry = PackRegistry::builtin().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let lab = HostLaboratory::new(
            BackendKind::Process,
            "ubuntu",
            dir.path(),
            "digest",
            &dir.path().join(".lab"),
            &[],
            registry,
        )
        .unwrap();
        let caps = lab.capabilities();
        assert!(!caps.vm_isolation, "the process backend never claims a VM");
        assert!(caps.clean_snapshot_restore);
        assert_eq!(caps.deny_all_egress, network_isolation_available());
        assert!(
            !caps.per_dependency_egress,
            "not implemented -> not claimed"
        );
    }
}
