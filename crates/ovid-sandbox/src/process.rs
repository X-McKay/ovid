//! Supervised process backend.
//!
//! Provides the trusted-repository execution path (FR-027 analog):
//! environment scrubbing, disposable workspaces, process-group supervision
//! with hard deadlines, rlimits, and optional strace observation. This is
//! not a security boundary for hostile code — its [`IsolationTier`] says
//! so, and manifests carry that tier.

use crate::{ExecutionBackend, IsolationTier, NetworkMode, RunResult, RunSpec, WorkspaceMode};
use ovid_core::{IdGenerator, OvidError};
use ovid_observer::{BoundaryObserver, StraceObserver};

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct ProcessBackend {
    ids: IdGenerator,
    /// Keeps ephemeral workspaces alive for result inspection; cleared on drop.
    keep_dir: tempfile::TempDir,
}

impl ProcessBackend {
    pub fn new() -> Result<Self, OvidError> {
        Ok(ProcessBackend {
            ids: IdGenerator::new(),
            keep_dir: tempfile::tempdir()?,
        })
    }

    /// Copy `source_root` into a fresh workspace (clean-rerun semantics).
    /// Build-output directories are skipped — the guest gets sources, not
    /// the host's caches — but the root `.git` is preserved so workloads
    /// that ask git questions (VCS-derived versions, hygiene tests) behave
    /// as they would in a real checkout.
    fn materialize(&self, source_root: &Path) -> Result<PathBuf, OvidError> {
        let workspace = tempfile::Builder::new()
            .prefix("world-")
            .tempdir_in(self.keep_dir.path())?
            .keep();
        crate::materialize_workspace(source_root, &workspace)?;
        Ok(workspace)
    }
}

/// Whether this host supports unprivileged user+network namespaces.
pub fn network_isolation_available() -> bool {
    Command::new("unshare")
        .args(["-r", "-n", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Wrap `argv` in a fresh user+network namespace: no external routes, and
/// loopback brought up (via `ip` when present, else a python ioctl, else
/// left down) so 127.0.0.1 services inside the workload keep working.
fn isolate_network(argv: &[String]) -> Vec<String> {
    const LO_UP: &str = concat!(
        "ip link set lo up 2>/dev/null || ",
        "python3 -c 'import socket,fcntl,struct;",
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);",
        "fcntl.ioctl(s.fileno(),0x8914,struct.pack(\"16sH14s\",b\"lo\",0x41,b\"\\0\"*14))' ",
        "2>/dev/null || true; exec \"$0\" \"$@\"",
    );
    let mut wrapped = vec![
        "unshare".to_string(),
        "-r".to_string(),
        "-n".to_string(),
        "sh".to_string(),
        "-c".to_string(),
        LO_UP.to_string(),
    ];
    wrapped.extend(argv.iter().cloned());
    wrapped
}

/// The scrubbed base environment: no host secrets, no proxy credentials, no
/// user dotfile influence (§12.1: workers hold no production secrets, and
/// the workload must not inherit whatever the operator's shell had).
fn base_env(workspace: &Path) -> Vec<(String, String)> {
    vec![
        (
            "PATH".into(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        ),
        ("HOME".into(), workspace.join(".home").display().to_string()),
        ("LANG".into(), "C.UTF-8".into()),
        (
            "TMPDIR".into(),
            workspace.join(".tmp").display().to_string(),
        ),
    ]
}

impl ExecutionBackend for ProcessBackend {
    fn name(&self) -> &'static str {
        "ovid-process-backend"
    }

    fn isolation_tier(&self) -> IsolationTier {
        IsolationTier::TrustedProcess
    }

    fn run(&self, spec: &RunSpec) -> Result<RunResult, OvidError> {
        if spec.argv.is_empty() {
            return Err(OvidError::Execution("empty argv".into()));
        }
        let workspace = match &spec.workspace {
            WorkspaceMode::Ephemeral { source_root } => self.materialize(source_root)?,
            WorkspaceMode::InPlace { root } => root.clone(),
        };
        std::fs::create_dir_all(workspace.join(".home"))?;
        std::fs::create_dir_all(workspace.join(".tmp"))?;

        // Network isolation wraps the innermost command; observation wraps
        // the whole thing so strace follows into the namespace.
        let mut argv = match spec.network {
            NetworkMode::Inherit => spec.argv.clone(),
            NetworkMode::Isolated => {
                if !network_isolation_available() {
                    return Err(OvidError::UnsupportedHost(
                        "network isolation requires unprivileged user namespaces \
                         (`unshare -r -n`); this host does not support them"
                            .into(),
                    ));
                }
                isolate_network(&spec.argv)
            }
        };

        let trace_path = workspace.join(".ovid-trace");
        let observer = StraceObserver;
        let observing = spec.observe && ovid_observer::strace_available();
        if observing {
            argv = observer.wrap(&argv, &trace_path);
        }

        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]);
        command.current_dir(&workspace);
        command.env_clear();
        for (key, value) in base_env(&workspace) {
            command.env(key, value);
        }
        for name in &spec.inherit_env {
            if let Ok(value) = std::env::var(name) {
                command.env(name, value);
            }
        }
        for (key, value) in &spec.env {
            command.env(key, value);
        }
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let cpu_seconds = spec.limits.cpu_seconds;
        let max_file = spec.limits.max_file_bytes;
        unsafe {
            command.pre_exec(move || {
                // New session => new process group, so the whole workload
                // tree can be killed on deadline.
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                let cpu = libc::rlimit {
                    rlim_cur: cpu_seconds,
                    rlim_max: cpu_seconds,
                };
                libc::setrlimit(libc::RLIMIT_CPU, &cpu);
                let fsize = libc::rlimit {
                    rlim_cur: max_file,
                    rlim_max: max_file,
                };
                libc::setrlimit(libc::RLIMIT_FSIZE, &fsize);
                Ok(())
            });
        }

        let start = Instant::now();
        let mut child = command
            .spawn()
            .map_err(|e| OvidError::Execution(format!("spawn {:?}: {e}", argv[0])))?;
        let pid = child.id() as i32;

        // Drain output on threads so a chatty workload cannot deadlock on a
        // full pipe while we wait.
        let stdout_handle = child.stdout.take().map(spawn_reader);
        let stderr_handle = child.stderr.take().map(spawn_reader);

        let mut timed_out = false;
        let status = loop {
            match child
                .try_wait()
                .map_err(|e| OvidError::Execution(e.to_string()))?
            {
                Some(status) => break status,
                None => {
                    if start.elapsed() >= spec.limits.wall_time {
                        timed_out = true;
                        // Kill the entire process group.
                        unsafe {
                            libc::kill(-pid, libc::SIGKILL);
                        }
                        let status = child
                            .wait()
                            .map_err(|e| OvidError::Execution(e.to_string()))?;
                        break status;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        };
        let duration = start.elapsed();

        let collect = |handle: Option<std::thread::JoinHandle<Vec<u8>>>| {
            handle
                .and_then(|h| h.join().ok())
                .map(|bytes| tail_string(&bytes, spec.limits.max_output_bytes))
                .unwrap_or_default()
        };
        let stdout_tail = collect(stdout_handle);
        let stderr_tail = collect(stderr_handle);

        let observation = if observing && trace_path.exists() {
            let run_id = self.ids.next("run");
            Some(
                observer
                    .collect(&trace_path, &run_id, &self.ids)
                    .map_err(|e| OvidError::Execution(format!("trace parse: {e}")))?,
            )
        } else {
            None
        };

        use std::os::unix::process::ExitStatusExt;
        Ok(RunResult {
            exit_code: status.code(),
            signal: status.signal(),
            timed_out,
            duration,
            stdout_tail,
            stderr_tail,
            observation,
            workspace_path: workspace,
        })
    }
}

use crate::{spawn_reader, tail_string};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn spec_in_place(argv: &[&str], dir: &Path) -> RunSpec {
        RunSpec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            workspace: WorkspaceMode::InPlace {
                root: dir.to_path_buf(),
            },
            env: BTreeMap::new(),
            inherit_env: vec![],
            limits: crate::ResourceLimits {
                wall_time: Duration::from_secs(20),
                ..Default::default()
            },
            observe: false,
            network: crate::NetworkMode::Inherit,
        }
    }

    #[test]
    fn runs_command_and_captures_output() {
        let backend = ProcessBackend::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut spec = spec_in_place(
            &["sh", "-c", "echo out-marker; echo err-marker >&2"],
            dir.path(),
        );
        spec.observe = false;
        let result = backend.run(&spec).unwrap();
        assert!(result.success());
        assert!(result.stdout_tail.contains("out-marker"));
        assert!(result.stderr_tail.contains("err-marker"));
    }

    #[test]
    fn environment_is_scrubbed() {
        std::env::set_var("OVID_SECRET_CANARY", "leak-me");
        let backend = ProcessBackend::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let result = backend.run(&spec_in_place(&["env"], dir.path())).unwrap();
        assert!(
            !result.stdout_tail.contains("OVID_SECRET_CANARY"),
            "host env must not leak: {}",
            result.stdout_tail
        );
        std::env::remove_var("OVID_SECRET_CANARY");
    }

    #[test]
    fn deadline_kills_process_group() {
        let backend = ProcessBackend::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut spec = spec_in_place(&["sh", "-c", "sleep 300"], dir.path());
        spec.limits.wall_time = Duration::from_millis(300);
        let start = Instant::now();
        let result = backend.run(&spec).unwrap();
        assert!(result.timed_out);
        assert!(!result.success());
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "kill must be prompt"
        );
    }

    #[test]
    fn ephemeral_workspace_leaves_source_clean() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("input.txt"), "original").unwrap();
        let backend = ProcessBackend::new().unwrap();
        let spec = RunSpec {
            argv: vec![
                "sh".into(),
                "-c".into(),
                "echo dirty > input.txt && echo new > created.txt".into(),
            ],
            workspace: WorkspaceMode::Ephemeral {
                source_root: source.path().to_path_buf(),
            },
            env: BTreeMap::new(),
            inherit_env: vec![],
            limits: Default::default(),
            observe: false,
            network: crate::NetworkMode::Inherit,
        };
        let result = backend.run(&spec).unwrap();
        assert!(result.success());
        // Source untouched; workspace modified.
        assert_eq!(
            std::fs::read_to_string(source.path().join("input.txt")).unwrap(),
            "original"
        );
        assert!(result.workspace_path.join("created.txt").exists());
        assert!(!source.path().join("created.txt").exists());
    }

    #[test]
    fn isolated_network_blocks_external_but_keeps_loopback() {
        if !network_isolation_available() {
            eprintln!("user namespaces unavailable; skipping");
            return;
        }
        let backend = ProcessBackend::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // The script: loopback listen+connect must work; an external
        // connect must fail with a network error.
        let script = r#"
python3 - <<'PY'
import socket, sys
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
c = socket.socket(); c.settimeout(2); c.connect(srv.getsockname())
print("loopback-ok")
x = socket.socket(); x.settimeout(2)
try:
    x.connect(("192.0.2.1", 443))
    print("external-reached"); sys.exit(1)
except OSError:
    print("external-blocked")
PY
"#;
        let mut spec = spec_in_place(&["sh", "-c", script], dir.path());
        spec.network = crate::NetworkMode::Isolated;
        spec.limits.wall_time = Duration::from_secs(30);
        let result = backend.run(&spec).unwrap();
        assert!(result.success(), "stderr: {}", result.stderr_tail);
        assert!(
            result.stdout_tail.contains("loopback-ok"),
            "{}",
            result.stdout_tail
        );
        assert!(
            result.stdout_tail.contains("external-blocked"),
            "{}",
            result.stdout_tail
        );
    }

    #[test]
    fn observation_captures_exec_and_misses() {
        if !ovid_observer::strace_available() {
            eprintln!("strace unavailable; skipping");
            return;
        }
        let backend = ProcessBackend::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut spec = spec_in_place(
            &[
                "sh",
                "-c",
                "cat /nonexistent-ovid-test-file 2>/dev/null; true",
            ],
            dir.path(),
        );
        spec.observe = true;
        let result = backend.run(&spec).unwrap();
        let observation = result.observation.expect("observation present");
        assert!(!observation.events.is_empty());
        assert!(observation.events.iter().any(|e| {
            matches!(
                &e.event,
                ovid_core::BoundaryEvent::FileOpened { path, errno: Some(err), .. }
                    if path.contains("nonexistent-ovid-test-file") && err == "ENOENT"
            )
        }));
    }
}
