//! Supervised process backend.
//!
//! Provides the trusted-repository execution path (FR-027 analog):
//! environment scrubbing, disposable workspaces, process-group supervision
//! with hard deadlines, rlimits, and optional strace observation. This is
//! not a security boundary for hostile code — its [`IsolationTier`] says
//! so, and manifests carry that tier.

use crate::{ExecutionBackend, IsolationTier, RunResult, RunSpec, WorkspaceMode};
use ovid_core::{IdGenerator, OvidError};
use ovid_observer::{BoundaryObserver, StraceObserver};
use std::io::Read;
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
        Ok(ProcessBackend { ids: IdGenerator::new(), keep_dir: tempfile::tempdir()? })
    }

    /// Copy `source_root` into a fresh workspace (clean-rerun semantics).
    /// `.git` and common build-output directories are skipped: the guest
    /// gets sources, not the host's caches.
    fn materialize(&self, source_root: &Path) -> Result<PathBuf, OvidError> {
        let workspace = tempfile::Builder::new()
            .prefix("world-")
            .tempdir_in(self.keep_dir.path())?
            .keep();
        copy_tree(source_root, &workspace)?;
        Ok(workspace)
    }
}

const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".venv", "__pycache__"];

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
            // Preserve intra-tree symlinks; refuse to follow outside links.
            if let Ok(dest) = std::fs::read_link(entry.path()) {
                let _ = std::os::unix::fs::symlink(dest, &target);
            }
        }
    }
    Ok(())
}

/// The scrubbed base environment: no host secrets, no proxy credentials, no
/// user dotfile influence (§12.1: workers hold no production secrets, and
/// the workload must not inherit whatever the operator's shell had).
fn base_env(workspace: &Path) -> Vec<(String, String)> {
    vec![
        ("PATH".into(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()),
        ("HOME".into(), workspace.join(".home").display().to_string()),
        ("LANG".into(), "C.UTF-8".into()),
        ("TMPDIR".into(), workspace.join(".tmp").display().to_string()),
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

        let trace_path = workspace.join(".ovid-trace");
        let observer = StraceObserver;
        let observing = spec.observe && ovid_observer::strace_available();
        let argv: Vec<String> = if observing {
            observer.wrap(&spec.argv, &trace_path)
        } else {
            spec.argv.clone()
        };

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
                let cpu = libc::rlimit { rlim_cur: cpu_seconds, rlim_max: cpu_seconds };
                libc::setrlimit(libc::RLIMIT_CPU, &cpu);
                let fsize = libc::rlimit { rlim_cur: max_file, rlim_max: max_file };
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
            match child.try_wait().map_err(|e| OvidError::Execution(e.to_string()))? {
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

fn spawn_reader<R: Read + Send + 'static>(mut reader: R) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = reader.read_to_end(&mut buffer);
        buffer
    })
}

fn tail_string(bytes: &[u8], max: usize) -> String {
    let slice = if bytes.len() > max { &bytes[bytes.len() - max..] } else { bytes };
    String::from_utf8_lossy(slice).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn spec_in_place(argv: &[&str], dir: &Path) -> RunSpec {
        RunSpec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            workspace: WorkspaceMode::InPlace { root: dir.to_path_buf() },
            env: BTreeMap::new(),
            inherit_env: vec![],
            limits: crate::ResourceLimits {
                wall_time: Duration::from_secs(20),
                ..Default::default()
            },
            observe: false,
        }
    }

    #[test]
    fn runs_command_and_captures_output() {
        let backend = ProcessBackend::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut spec = spec_in_place(&["sh", "-c", "echo out-marker; echo err-marker >&2"], dir.path());
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
        assert!(start.elapsed() < Duration::from_secs(10), "kill must be prompt");
    }

    #[test]
    fn ephemeral_workspace_leaves_source_clean() {
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("input.txt"), "original").unwrap();
        let backend = ProcessBackend::new().unwrap();
        let spec = RunSpec {
            argv: vec!["sh".into(), "-c".into(), "echo dirty > input.txt && echo new > created.txt".into()],
            workspace: WorkspaceMode::Ephemeral { source_root: source.path().to_path_buf() },
            env: BTreeMap::new(),
            inherit_env: vec![],
            limits: Default::default(),
            observe: false,
        };
        let result = backend.run(&spec).unwrap();
        assert!(result.success());
        // Source untouched; workspace modified.
        assert_eq!(std::fs::read_to_string(source.path().join("input.txt")).unwrap(), "original");
        assert!(result.workspace_path.join("created.txt").exists());
        assert!(!source.path().join("created.txt").exists());
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
            &["sh", "-c", "cat /nonexistent-ovid-test-file 2>/dev/null; true"],
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
