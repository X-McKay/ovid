//! Execution backends (spec §13.5, §16, FR-020..FR-028).
//!
//! Two backends implement the [`ExecutionBackend`] contract:
//!
//! - [`process::ProcessBackend`] — supervised, resource-limited,
//!   environment-scrubbed host process for *trusted* repositories
//!   (FR-027 analog). Ephemeral copy-on-write workspaces (clean-rerun
//!   semantics, FR-025), deadline enforcement, rlimits, strace
//!   observation. **Not a security boundary for hostile code**, and says
//!   so in its isolation tier.
//! - [`microsandbox::MicrosandboxBackend`] — libkrun guest VMs via the
//!   `msb` CLI: a real VM boundary with an always-Linux guest, portable
//!   across Linux/KVM, macOS/Apple Silicon, and Windows/WHP hosts.
//!
//! A Firecracker MicroVM backend returns when it can execute the
//! complete laboratory contract — prepare/snapshot/trial forks with
//! enforcement provenance — rather than only VM configuration
//! (proposal §8.3's deferral).
//!
//! The prove loop chooses a backend by policy; evidence records carry
//! which backend produced them so trust tiers stay honest.

#[cfg(unix)]
pub mod process;
/// Non-unix hosts get honest stubs: static analysis works everywhere;
/// execution backends fail at construction with `UnsupportedHost` rather
/// than degrading silently (invariant: isolation honesty).
#[cfg(not(unix))]
mod unsupported;

/// The microsandbox (libkrun) guest-VM backend is portable by design:
/// `msb` runs on Linux (KVM), macOS (Apple Silicon), and Windows (WHP),
/// and the guest is always Linux — so observation and network
/// counterfactuals behave identically on every host.
pub mod microsandbox;

pub use microsandbox::MicrosandboxBackend;

#[cfg(unix)]
pub use process::{network_isolation_available, ProcessBackend};
#[cfg(not(unix))]
pub use unsupported::{network_isolation_available, ProcessBackend};

use ovid_core::OvidError;
use ovid_observer::ObservationReport;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How strong the isolation of a backend is. Recorded into provenance so a
/// manifest can never silently claim MicroVM isolation for a process run.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationTier {
    /// libkrun guest VM boundary (microsandbox) — a real VM with an
    /// always-Linux guest.
    MicrovmGuest,
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

/// Drain a child stream on a thread so a chatty workload cannot deadlock
/// on a full pipe while the supervisor waits.
pub(crate) fn spawn_reader<R: std::io::Read + Send + 'static>(
    mut reader: R,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = reader.read_to_end(&mut buffer);
        buffer
    })
}

/// Bounded UTF-8 tail of captured output.
pub(crate) fn tail_string(bytes: &[u8], max: usize) -> String {
    let slice = if bytes.len() > max {
        &bytes[bytes.len() - max..]
    } else {
        bytes
    };
    String::from_utf8_lossy(slice).into_owned()
}

const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".venv", "__pycache__"];

/// Copy a source tree into `dest` (skipping build-output dirs, keeping the
/// root `.git`) so callers can maintain one persistent provisioned
/// workspace across runs (the dependency-installed layer of spec §16.5's
/// snapshot hierarchy). Portable: usable on every host, since static
/// analysis and future guest-VM backends need workspaces even where the
/// process backend is unsupported.
pub fn materialize_workspace(source_root: &Path, dest: &Path) -> Result<(), OvidError> {
    copy_tree(source_root, dest)?;
    // The top-level `.git` is preserved: without git metadata, workloads
    // that derive versions from VCS (setuptools-scm, hatch-vcs,
    // `git describe`) or run repo-hygiene tests (`git ls-files`) fail for
    // reasons the real checkout would not (§6.2: failures are evidence, so
    // they had better be the repository's own). Nested vendored `.git`
    // directories stay skipped.
    let git_dir = source_root.join(".git");
    if git_dir.is_dir() {
        copy_tree(&git_dir, &dest.join(".git"))?;
    }
    Ok(())
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), OvidError> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let target = to.join(&name);
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if SKIP_DIRS.contains(&name_str.as_ref()) {
                continue;
            }
            copy_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &target)?;
        } else if file_type.is_symlink() {
            // Preserve intra-tree symlinks; refuse to follow outside
            // links. On hosts without unix symlink semantics the entry is
            // skipped — a bounded fidelity loss on an already-degraded
            // platform, never an escape from the tree.
            #[cfg(unix)]
            if let Ok(dest) = std::fs::read_link(entry.path()) {
                let _ = std::os::unix::fs::symlink(dest, &target);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod copy_tests {
    use super::*;

    #[test]
    fn workspace_copy_keeps_root_git_and_skips_caches_and_nested_git() {
        let source = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(source.path().join(".git/objects")).unwrap();
        std::fs::write(source.path().join(".git/HEAD"), "ref: refs/heads/main").unwrap();
        std::fs::create_dir_all(source.path().join("vendor/dep/.git")).unwrap();
        std::fs::write(source.path().join("vendor/dep/.git/HEAD"), "nested").unwrap();
        std::fs::create_dir_all(source.path().join("node_modules/x")).unwrap();
        std::fs::write(source.path().join("main.rs"), "fn main() {}").unwrap();

        let dest = tempfile::tempdir().unwrap();
        materialize_workspace(source.path(), dest.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.path().join(".git/HEAD")).unwrap(),
            "ref: refs/heads/main",
            "root .git must survive so VCS-derived workloads behave"
        );
        assert!(dest.path().join("main.rs").exists());
        assert!(
            !dest.path().join("vendor/dep/.git").exists(),
            "nested vendored .git stays skipped"
        );
        assert!(
            !dest.path().join("node_modules").exists(),
            "caches stay skipped"
        );
    }
}
