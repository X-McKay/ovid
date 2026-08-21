//! microsandbox (libkrun) guest-VM backend.
//!
//! Drives the `msb` CLI (<https://github.com/microsandbox/microsandbox>)
//! to run each workload inside a real VM whose guest is always Linux —
//! on Linux/KVM, macOS/Apple Silicon, or Windows/WHP hosts alike. That
//! makes strace observation and network counterfactuals host-independent:
//! the guest carries the observer, not the host.
//!
//! Contract with `msb run` (grounded against the upstream CLI):
//!
//! ```text
//! msb run <image> --no-tty --quiet --pull if-missing --name <run-name>
//!         --volume <workspace>:/workspace --workdir /workspace
//!         --env K=V… --max-duration <secs>s [--no-net] -- <argv…>
//! ```
//!
//! `--no-net` is a true default-deny for the guest (no egress rules), so
//! [`NetworkMode::Isolated`] needs no user namespaces here. Isolation is
//! reported as [`IsolationTier::MicrovmGuest`] — a real VM boundary, kept
//! distinct from Firecracker's `Microvm` tier so manifests never conflate
//! the two stacks (isolation honesty).

use crate::{
    materialize_workspace, spawn_reader, tail_string, ExecutionBackend, IsolationTier, NetworkMode,
    RunResult, RunSpec, WorkspaceMode,
};
use ovid_core::{IdGenerator, OvidError};
use ovid_observer::{BoundaryObserver, StraceObserver};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Guest-side mount point for the workload workspace.
const GUEST_WORKSPACE: &str = "/workspace";
/// Guest-side trace path; lands in the mounted workspace so the host can
/// parse it after the run.
const GUEST_TRACE: &str = "/workspace/.ovid-trace";
/// Grace period past the guest's own `--max-duration` before the host
/// kills the `msb` process itself (covers boot/pull overhead and a hung
/// VMM).
const HOST_KILL_GRACE: Duration = Duration::from_secs(90);

/// Locate the `msb` binary: `OVID_MSB_BIN` override, else `msb` on PATH.
fn msb_binary() -> PathBuf {
    std::env::var_os("OVID_MSB_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("msb"))
}

/// Whether the microsandbox CLI is present and answers.
pub fn microsandbox_available() -> bool {
    Command::new(msb_binary())
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub struct MicrosandboxBackend {
    ids: IdGenerator,
    msb: PathBuf,
    /// Guest image (e.g. `ubuntu`); must carry the toolchains the
    /// repository's workloads need.
    image: String,
    /// Whether the guest image ships `strace`; probed once, lazily.
    guest_strace: OnceLock<bool>,
    /// Keeps ephemeral workspaces alive for result inspection.
    keep_dir: tempfile::TempDir,
    run_counter: std::sync::atomic::AtomicU64,
}

impl MicrosandboxBackend {
    /// Create a backend for `image`. Fails with `UnsupportedHost` when the
    /// `msb` CLI is absent — never a silent fallback to weaker isolation.
    pub fn new(image: &str) -> Result<Self, OvidError> {
        if !microsandbox_available() {
            return Err(OvidError::UnsupportedHost(
                "the microsandbox backend requires the `msb` CLI (and a VM hypervisor: \
                 KVM on Linux, Apple Silicon on macOS, WHP on Windows); install it from \
                 https://microsandbox.dev or set OVID_MSB_BIN"
                    .into(),
            ));
        }
        Ok(MicrosandboxBackend {
            ids: IdGenerator::new(),
            msb: msb_binary(),
            image: image.to_string(),
            guest_strace: OnceLock::new(),
            keep_dir: tempfile::tempdir()?,
            run_counter: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Probe once whether the guest image has `strace`. Observation is
    /// skipped (honestly: `observation: None`) when it does not, exactly
    /// like the process backend on hosts without strace.
    fn guest_has_strace(&self) -> bool {
        *self.guest_strace.get_or_init(|| {
            Command::new(&self.msb)
                .args([
                    "run",
                    &self.image,
                    "--no-tty",
                    "--quiet",
                    "--pull",
                    "if-missing",
                    "--no-net",
                    "--",
                    "sh",
                    "-lc",
                    "command -v strace",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        })
    }

    /// Build the full `msb run` argv for a spec. Pure, for testability.
    fn compose_run_argv(
        &self,
        spec: &RunSpec,
        workspace: &Path,
        run_name: &str,
        wrap_observation: bool,
    ) -> Vec<String> {
        let mut argv: Vec<String> = vec![
            self.msb.display().to_string(),
            "run".into(),
            self.image.clone(),
            "--no-tty".into(),
            "--quiet".into(),
            "--pull".into(),
            "if-missing".into(),
            "--name".into(),
            run_name.into(),
            "--volume".into(),
            format!("{}:{GUEST_WORKSPACE}", workspace.display()),
            "--workdir".into(),
            GUEST_WORKSPACE.into(),
            "--max-duration".into(),
            format!("{}s", spec.limits.wall_time.as_secs().max(1)),
        ];
        // Guest base environment mirrors the process backend's scrubbed
        // base: writable HOME/TMPDIR inside the workspace, stable locale.
        // The guest supplies its own PATH; host PATH/HOME values are
        // host-specific and never forwarded (§12.1 — the guest sees no
        // host environment it was not explicitly handed).
        for (key, value) in [
            ("HOME", format!("{GUEST_WORKSPACE}/.home")),
            ("TMPDIR", format!("{GUEST_WORKSPACE}/.tmp")),
            ("LANG", "C.UTF-8".into()),
        ] {
            argv.push("--env".into());
            argv.push(format!("{key}={value}"));
        }
        for name in &spec.inherit_env {
            if name == "PATH" || name == "HOME" {
                continue; // host paths are meaningless inside the guest
            }
            if let Ok(value) = std::env::var(name) {
                argv.push("--env".into());
                argv.push(format!("{name}={value}"));
            }
        }
        for (key, value) in &spec.env {
            argv.push("--env".into());
            argv.push(format!("{key}={value}"));
        }
        if spec.network == NetworkMode::Isolated {
            // True default-deny for the guest; loopback inside the guest
            // keeps working, exactly the §20 counterfactual posture.
            argv.push("--no-net".into());
        }
        argv.push("--".into());
        let inner = if wrap_observation {
            StraceObserver.wrap(&spec.argv, Path::new(GUEST_TRACE))
        } else {
            spec.argv.clone()
        };
        argv.extend(inner);
        argv
    }
}

impl ExecutionBackend for MicrosandboxBackend {
    fn name(&self) -> &'static str {
        "ovid-microsandbox-backend"
    }

    fn isolation_tier(&self) -> IsolationTier {
        IsolationTier::MicrovmGuest
    }

    fn run(&self, spec: &RunSpec) -> Result<RunResult, OvidError> {
        if spec.argv.is_empty() {
            return Err(OvidError::Execution("empty argv".into()));
        }
        let workspace = match &spec.workspace {
            WorkspaceMode::Ephemeral { source_root } => {
                let dir = tempfile::Builder::new()
                    .prefix("msb-world-")
                    .tempdir_in(self.keep_dir.path())?
                    .keep();
                materialize_workspace(source_root, &dir)?;
                dir
            }
            WorkspaceMode::InPlace { root } => root.clone(),
        };
        std::fs::create_dir_all(workspace.join(".home"))?;
        std::fs::create_dir_all(workspace.join(".tmp"))?;
        let trace_host = workspace.join(".ovid-trace");
        let _ = std::fs::remove_file(&trace_host);

        let observing = spec.observe && self.guest_has_strace();
        let run_name = format!(
            "ovid-{}-{}",
            std::process::id(),
            self.run_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let argv = self.compose_run_argv(spec, &workspace, &run_name, observing);

        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]);
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let start = Instant::now();
        let mut child = command
            .spawn()
            .map_err(|e| OvidError::Execution(format!("spawn {:?}: {e}", argv[0])))?;
        let stdout_handle = child.stdout.take().map(spawn_reader);
        let stderr_handle = child.stderr.take().map(spawn_reader);

        // The guest enforces --max-duration; the host bounds the whole
        // msb invocation (boot + pull + run) as a backstop.
        let host_deadline = spec.limits.wall_time + HOST_KILL_GRACE;
        let mut timed_out = false;
        let status = loop {
            match child
                .try_wait()
                .map_err(|e| OvidError::Execution(e.to_string()))?
            {
                Some(status) => break status,
                None => {
                    if start.elapsed() >= host_deadline {
                        timed_out = true;
                        let _ = child.kill();
                        let status = child
                            .wait()
                            .map_err(|e| OvidError::Execution(e.to_string()))?;
                        break status;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        };
        let duration = start.elapsed();

        // Best-effort cleanup of the named sandbox; failure is not an
        // analysis error.
        let _ = Command::new(&self.msb)
            .args(["rm", &run_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let collect = |handle: Option<std::thread::JoinHandle<Vec<u8>>>| {
            handle
                .and_then(|h| h.join().ok())
                .map(|bytes| tail_string(&bytes, spec.limits.max_output_bytes))
                .unwrap_or_default()
        };
        let stdout_tail = collect(stdout_handle);
        let stderr_tail = collect(stderr_handle);

        let observation = if observing && trace_host.exists() {
            let run_id = self.ids.next("run");
            Some(
                StraceObserver
                    .collect(&trace_host, &run_id, &self.ids)
                    .map_err(|e| OvidError::Execution(format!("trace parse: {e}")))?,
            )
        } else {
            None
        };

        Ok(RunResult {
            exit_code: status.code(),
            signal: None, // guest signals are not surfaced through msb
            timed_out,
            duration,
            stdout_tail,
            stderr_tail,
            observation,
            workspace_path: workspace,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn backend_for_test() -> MicrosandboxBackend {
        MicrosandboxBackend {
            ids: IdGenerator::deterministic(),
            msb: PathBuf::from("msb"),
            image: "ubuntu".into(),
            guest_strace: OnceLock::new(),
            keep_dir: tempfile::tempdir().unwrap(),
            run_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn spec(argv: &[&str], network: NetworkMode) -> RunSpec {
        let mut spec = RunSpec::new(
            argv.iter().map(|s| s.to_string()).collect(),
            WorkspaceMode::InPlace {
                root: PathBuf::from("/tmp/ws"),
            },
        );
        spec.network = network;
        spec.env = BTreeMap::from([("CI".to_string(), "1".to_string())]);
        spec
    }

    #[test]
    fn construction_fails_honestly_without_msb() {
        std::env::set_var("OVID_MSB_BIN", "/nonexistent/msb-binary");
        let error = match MicrosandboxBackend::new("ubuntu") {
            Err(error) => error,
            Ok(_) => panic!("construction must fail without the msb CLI"),
        };
        std::env::remove_var("OVID_MSB_BIN");
        assert!(
            matches!(error, OvidError::UnsupportedHost(_)),
            "missing CLI must be UnsupportedHost, got {error:?}"
        );
    }

    #[test]
    fn run_argv_mounts_workspace_and_carries_env_and_command() {
        let backend = backend_for_test();
        let spec = spec(&["make", "test"], NetworkMode::Inherit);
        let argv = backend.compose_run_argv(&spec, Path::new("/tmp/ws"), "ovid-1-0", false);
        let joined = argv.join(" ");
        assert!(joined.starts_with("msb run ubuntu --no-tty --quiet --pull if-missing"));
        assert!(joined.contains("--volume /tmp/ws:/workspace"));
        assert!(joined.contains("--workdir /workspace"));
        assert!(joined.contains("--env HOME=/workspace/.home"));
        assert!(joined.contains("--env CI=1"));
        assert!(joined.ends_with("-- make test"));
        assert!(
            !joined.contains("--no-net"),
            "inherit mode leaves default egress"
        );
    }

    #[test]
    fn isolated_network_is_a_no_net_guest() {
        let backend = backend_for_test();
        let spec = spec(&["make"], NetworkMode::Isolated);
        let argv = backend.compose_run_argv(&spec, Path::new("/tmp/ws"), "ovid-1-0", false);
        let no_net = argv.iter().position(|a| a == "--no-net").unwrap();
        let separator = argv.iter().position(|a| a == "--").unwrap();
        assert!(no_net < separator, "--no-net must precede the command");
    }

    #[test]
    fn host_path_and_home_are_never_forwarded_to_the_guest() {
        let backend = backend_for_test();
        let mut spec = spec(&["env"], NetworkMode::Inherit);
        spec.inherit_env = vec!["PATH".into(), "HOME".into(), "MAVEN_OPTS".into()];
        std::env::set_var("MAVEN_OPTS", "-Xmx1g");
        let argv = backend.compose_run_argv(&spec, Path::new("/tmp/ws"), "ovid-1-0", false);
        std::env::remove_var("MAVEN_OPTS");
        let joined = argv.join(" ");
        assert!(joined.contains("--env MAVEN_OPTS=-Xmx1g"));
        let host_path = std::env::var("PATH").unwrap_or_default();
        assert!(
            !joined.contains(&format!("--env PATH={host_path}")),
            "host PATH must not leak into the guest"
        );
        assert!(joined.contains("--env HOME=/workspace/.home"));
    }

    #[test]
    fn observation_wrap_targets_the_mounted_trace_path() {
        let backend = backend_for_test();
        let spec = spec(&["cargo", "build"], NetworkMode::Inherit);
        let argv = backend.compose_run_argv(&spec, Path::new("/tmp/ws"), "ovid-1-0", true);
        let joined = argv.join(" ");
        assert!(
            joined.contains("strace") && joined.contains(GUEST_TRACE),
            "observed runs wrap with strace into the shared workspace: {joined}"
        );
        assert!(joined.ends_with("cargo build"));
    }

    #[test]
    fn tier_and_name_are_the_guest_vm_identity() {
        let backend = backend_for_test();
        assert_eq!(backend.name(), "ovid-microsandbox-backend");
        assert_eq!(backend.isolation_tier(), IsolationTier::MicrovmGuest);
        assert_eq!(
            serde_json::to_value(IsolationTier::MicrovmGuest).unwrap(),
            "microvm-guest"
        );
    }

    /// End-to-end run, exercised only where an `msb` CLI and hypervisor
    /// exist (CI and this development sandbox have neither).
    #[test]
    fn real_guest_run_when_available() {
        if !microsandbox_available() {
            eprintln!("msb unavailable; skipping guest-run integration test");
            return;
        }
        let backend = MicrosandboxBackend::new("alpine").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let spec = RunSpec::new(
            vec!["sh".into(), "-c".into(), "echo guest-ok".into()],
            WorkspaceMode::InPlace {
                root: dir.path().to_path_buf(),
            },
        );
        let result = backend.run(&spec).unwrap();
        assert!(result.success(), "{}", result.stderr_tail);
        assert!(result.stdout_tail.contains("guest-ok"));
    }
}
