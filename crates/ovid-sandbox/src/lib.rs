//! Execution backends (spec §13.5, §16, FR-020..FR-028).
//!
//! Two backends implement the [`ExecutionBackend`] contract:
//!
//! - [`process::ProcessBackend`] — the alternate faster backend the spec
//!   allows for *trusted* repositories (FR-027 names gVisor/containers; a
//!   supervised, resource-limited, environment-scrubbed process fills the
//!   same role on hosts without KVM). It supports ephemeral copy-on-write
//!   workspaces (clean-rerun semantics, FR-025), deadline enforcement,
//!   rlimits, and strace observation. **It is not a security boundary for
//!   hostile code** and says so in its isolation tier.
//! - [`firecracker::FirecrackerBackend`] — the default untrusted-execution
//!   boundary (ADR-002): jailer configuration, the five-device disk layout
//!   of §13.5, vsock, and snapshot lifecycle, driven through Firecracker's
//!   Unix-socket REST API (§34.5). On hosts without `/dev/kvm` it reports
//!   `UnsupportedHost` rather than degrading silently.
//!
//! The experiment loop chooses a backend by policy; evidence records carry
//! which backend produced them so trust tiers stay honest.

pub mod firecracker;
pub mod process;

pub use firecracker::{FirecrackerBackend, VmSpec};
pub use process::{network_isolation_available, ProcessBackend};

use ovid_core::OvidError;
use ovid_observer::ObservationReport;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// How strong the isolation of a backend is. Recorded into provenance so a
/// manifest can never silently claim MicroVM isolation for a process run.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationTier {
    /// KVM MicroVM boundary — suitable for hostile repositories.
    Microvm,
    /// Supervised process — trusted repositories only (FR-027 analog).
    TrustedProcess,
}

/// Per-run resource budgets (FR-024).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ResourceLimits {
    pub wall_time: Duration,
    /// RLIMIT_CPU per process, seconds.
    pub cpu_seconds: u64,
    /// RLIMIT_FSIZE: largest file the workload may create.
    pub max_file_bytes: u64,
    /// Captured stdout/stderr tail size.
    pub max_output_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        ResourceLimits {
            wall_time: Duration::from_secs(600),
            cpu_seconds: 900,
            max_file_bytes: 2 * 1024 * 1024 * 1024,
            max_output_bytes: 256 * 1024,
        }
    }
}

/// Network posture for a run (FR-041's deny-default, process-backend
/// edition).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    /// The run shares the host network namespace. External reachability is
    /// whatever the host (and any proxy variables passed via
    /// `inherit_env`) provides.
    #[default]
    Inherit,
    /// The run executes in a fresh user+network namespace: loopback only,
    /// no external routes. This is a real deny-all for counterfactual
    /// experiments (§20). Requires unprivileged user namespaces
    /// (`unshare -r -n`); availability is probed with
    /// [`process::network_isolation_available`].
    Isolated,
}

/// How the workspace is materialized.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case", tag = "mode")]
pub enum WorkspaceMode {
    /// Copy the source tree into a disposable workspace; every run starts
    /// clean (FR-025's snapshot-reset semantics for the process backend).
    Ephemeral { source_root: PathBuf },
    /// Run in place. Faster for large trees; the run may dirty the tree, so
    /// only appropriate for observe-mode on trusted checkouts.
    InPlace { root: PathBuf },
}

/// A fully-specified run request (§8.3: one command in a defined world).
#[derive(Clone, Debug)]
pub struct RunSpec {
    pub argv: Vec<String>,
    pub workspace: WorkspaceMode,
    /// Extra environment; merged over the scrubbed base environment.
    pub env: BTreeMap<String, String>,
    /// Host environment variable names to pass through (e.g. `CARGO_HOME`
    /// when reusing a warm toolchain cache). Everything else is scrubbed.
    pub inherit_env: Vec<String>,
    pub limits: ResourceLimits,
    /// Observe boundaries with the configured observer.
    pub observe: bool,
    /// Network posture (default: inherit the host namespace).
    pub network: NetworkMode,
}

impl RunSpec {
    pub fn new(argv: Vec<String>, workspace: WorkspaceMode) -> Self {
        RunSpec {
            argv,
            workspace,
            env: BTreeMap::new(),
            inherit_env: Vec::new(),
            limits: ResourceLimits::default(),
            observe: true,
            network: NetworkMode::Inherit,
        }
    }
}

/// The outcome of one run.
#[derive(Debug)]
pub struct RunResult {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub duration: Duration,
    /// Bounded tails of workload output.
    pub stdout_tail: String,
    pub stderr_tail: String,
    /// Normalized boundary events, when observation was requested and
    /// available.
    pub observation: Option<ObservationReport>,
    /// The workspace the run executed in (ephemeral workspaces live until
    /// the result is dropped by the caller).
    pub workspace_path: PathBuf,
}

impl RunResult {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out
    }
}

pub trait ExecutionBackend {
    fn name(&self) -> &'static str;
    fn isolation_tier(&self) -> IsolationTier;
    fn run(&self, spec: &RunSpec) -> Result<RunResult, OvidError>;
}
