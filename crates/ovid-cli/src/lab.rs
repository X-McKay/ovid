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

use anyhow::{bail, Result};
use ovid_application::{
    EgressIntent, ExecutableCandidate, LabCapabilities, LabError, LaboratoryPort, NetworkCandidate,
    PreparedEnvironment, ProviderIdentity, SnapshotRef, TrialObservations, TrialResult, TrialSpec,
};
use ovid_core::{BoundaryEvent, Digest, EventEnvelope};
use ovid_domain::{
    DependencyKey, EnforcementReport, EnforcementStatus, Treatment, TrialOutcome, TrialRecord,
};
use ovid_gateway::{GatewayIntent, GatewayPolicy, GatewayServer, Upstream};
use ovid_observer::aggregate;
use ovid_packs::PackRegistry;
use ovid_sandbox::{
    network_isolation_available, ExecutionBackend, NetworkMode, RunResult, RunSpec, WorkspaceMode,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Fixed loopback port the in-namespace deny gateway binds. Each isolated
/// trial has its own private loopback, so a constant is collision-free.
const NETNS_GATEWAY_PORT: u16 = 8899;

/// Whether the workload's runtime egress is allowed to reach real
/// services (proposal §15.1's egress posture; the gateway attributes it
/// either way).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum EgressPolicy {
    /// No real external egress: workload trials run with a deny gateway
    /// (in a network namespace when available). Ovid records *what the
    /// workload tried to reach* without contacting anything real.
    #[default]
    Deny,
    /// Real egress, mediated by a forward gateway that names every
    /// destination and chains through the host's own proxy. Required to
    /// classify network dependencies causally.
    Allow,
}

impl EgressPolicy {
    pub fn parse(name: &str) -> anyhow::Result<EgressPolicy> {
        match name {
            "deny" => Ok(EgressPolicy::Deny),
            "allow" => Ok(EgressPolicy::Allow),
            other => bail!("unknown egress policy {other:?} (use deny|allow)"),
        }
    }
}

/// How one trial's network boundary is realized: kernel isolation plus a
/// lab-controlled gateway that names egress intents.
enum GatewayPlan {
    /// In-process gateway on host loopback that forwards to real
    /// services (chaining the host upstream), blocking the named set.
    HostForward { block: BTreeSet<String> },
    /// In-namespace deny gateway: records intents, contacts nothing.
    NetnsDeny,
    /// Deny gateway on host loopback because namespace isolation is
    /// unavailable: proxied egress is refused, but direct-socket egress
    /// is not blocked — enforcement is only partial.
    HostDenyPartial,
}

/// Which execution backend runs trials (spec §13.5: backend by policy;
/// the chosen backend's isolation tier flows into provenance, never
/// upgraded, never silently downgraded).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum BackendKind {
    /// Supervised host process (trusted repositories, Linux/unix hosts).
    #[default]
    Process,
    /// microsandbox libkrun guest VM (`msb`): always-Linux guest, works
    /// on Linux/KVM, macOS/Apple Silicon, and Windows/WHP hosts.
    Microsandbox,
}

impl BackendKind {
    pub fn parse(name: &str) -> Result<BackendKind> {
        match name {
            "process" => Ok(BackendKind::Process),
            "microsandbox" => Ok(BackendKind::Microsandbox),
            other => bail!("unknown backend {other:?} (use process|microsandbox)"),
        }
    }

    /// (backend name, isolation tier) as recorded in provenance.
    pub fn identity(&self) -> (&'static str, &'static str) {
        match self {
            BackendKind::Process => ("ovid-process-backend", "trusted-process"),
            BackendKind::Microsandbox => ("ovid-microsandbox-backend", "microvm-guest"),
        }
    }
}

/// Environment untreated (online) trials inherit by default: toolchain
/// discovery plus proxy/CA plumbing. Names only — values come from the
/// host at spawn time; everything else is scrubbed.
pub(crate) const ONLINE_DEFAULT_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "https_proxy",
    "HTTPS_PROXY",
    "http_proxy",
    "HTTP_PROXY",
    "no_proxy",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "CARGO_HTTP_CAINFO",
    // JVM tooling reads proxy/truststore settings from its own variables,
    // not from http_proxy.
    "JAVA_TOOL_OPTIONS",
    "MAVEN_OPTS",
    "GRADLE_OPTS",
];
/// Egress-denied trials only need toolchain discovery; the namespace
/// blocks egress.
pub(crate) const OFFLINE_DEFAULT_ENV: &[&str] = &["PATH", "HOME"];

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
    /// The workload's runtime egress posture.
    egress: EgressPolicy,
    /// The host's own egress proxy, chained through by the forward
    /// gateway (parsed from the host proxy env at construction).
    upstream: Option<Upstream>,
    source_digest: String,
    trial_counter: u64,
}

/// Proxy env variable names Ovid overrides so all workload egress flows
/// through the lab gateway (and none uses the host proxy directly).
const PROXY_VARS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

impl HostLaboratory {
    /// Build a laboratory over the chosen backend. `extra_env` names are
    /// added to both allowlists (never values — values come from the host
    /// at spawn time and are scrubbed otherwise).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: BackendKind,
        guest_image: &str,
        source_root: &Path,
        source_digest: &str,
        lab_dir: &Path,
        extra_env: &[String],
        egress: EgressPolicy,
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
        // The forward gateway chains through the host's own egress proxy;
        // capture it before the workload env is scrubbed.
        let upstream = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
            .iter()
            .find_map(|var| std::env::var(var).ok())
            .and_then(|url| Upstream::parse(&url));
        Ok(HostLaboratory {
            backend,
            kind,
            registry,
            source_root: absolutize(source_root),
            lab_dir: absolutize(lab_dir),
            online_env,
            offline_env,
            egress,
            upstream,
            source_digest: source_digest.to_string(),
            trial_counter: 0,
        })
    }

    /// Environment names to inherit with all proxy variables removed —
    /// the workload must reach the network only through the lab gateway,
    /// never the host proxy directly.
    fn inherit_without_proxy(&self, base: &[String]) -> Vec<String> {
        base.iter()
            .filter(|v| !PROXY_VARS.contains(&v.as_str()))
            .cloned()
            .collect()
    }

    /// Proxy env pointing the workload at `127.0.0.1:port`.
    fn proxy_env(port: u16) -> BTreeMap<String, String> {
        let url = format!("http://127.0.0.1:{port}");
        let mut env = BTreeMap::new();
        for var in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            env.insert(var.to_string(), url.clone());
        }
        // A workload that special-cases localhost must still be proxied.
        env.insert("NO_PROXY".into(), String::new());
        env.insert("no_proxy".into(), String::new());
        env
    }

    fn run_in(
        &self,
        dir: &Path,
        argv: &[String],
        network: NetworkMode,
        inherit_env: &[String],
        env: BTreeMap<String, String>,
        timeout_seconds: u64,
    ) -> Result<RunResult, LabError> {
        let mut spec = RunSpec::new(
            argv.to_vec(),
            WorkspaceMode::InPlace {
                root: dir.to_path_buf(),
            },
        );
        spec.inherit_env = inherit_env.to_vec();
        spec.env = env;
        spec.limits.wall_time = Duration::from_secs(timeout_seconds);
        spec.network = network;
        self.backend
            .run(&spec)
            .map_err(|e| LabError::Execution(format!("run {argv:?}: {e}")))
    }

    /// Run a workload under a gateway plan, returning the run result and
    /// the egress intents the gateway recorded.
    #[allow(clippy::too_many_arguments)]
    fn execute(
        &self,
        dir: &Path,
        argv: &[String],
        network: NetworkMode,
        inherit_env: &[String],
        env: &mut BTreeMap<String, String>,
        gateway: GatewayPlan,
        spec: &TrialSpec,
    ) -> Result<(RunResult, Vec<GatewayIntent>), LabError> {
        // The host-loopback gateway policy for the host-side plans.
        let host_gateway = match &gateway {
            GatewayPlan::HostDenyPartial => Some((GatewayPolicy::Deny, None)),
            GatewayPlan::HostForward { block } if block.is_empty() => {
                Some((GatewayPolicy::Forward, self.upstream.clone()))
            }
            GatewayPlan::HostForward { block } => Some((
                GatewayPolicy::ForwardExcept(block.clone()),
                self.upstream.clone(),
            )),
            GatewayPlan::NetnsDeny => None,
        };

        if let Some((policy, upstream)) = host_gateway {
            // Host-side in-process gateway naming every destination; real
            // egress (when forwarding) chains the host upstream.
            let log = self
                .lab_dir
                .join(format!("gw-{:03}.jsonl", self.trial_counter));
            let server = GatewayServer::start("127.0.0.1:0", policy, upstream, &log)
                .map_err(|e| LabError::Preparation(format!("gateway: {e}")))?;
            env.extend(Self::proxy_env(server.port));
            let result = self.run_in(
                dir,
                argv,
                network,
                inherit_env,
                env.clone(),
                spec.timeout_seconds,
            );
            let intents = server.shutdown();
            return Ok((result?, intents));
        }

        // In-namespace deny gateway: the wrapper unshares the network,
        // starts `ovid internal-gateway` on the private loopback, and runs
        // the workload proxied at it. Nothing real is contacted.
        let intents_log = dir.join(".ovid-intents");
        let ready = dir.join(".ovid-gw-ready");
        let ovid_bin = std::env::current_exe()
            .map_err(|e| LabError::Preparation(format!("locate ovid binary: {e}")))?;
        env.extend(Self::proxy_env(NETNS_GATEWAY_PORT));
        env.insert("OVID_GW_BIN".into(), ovid_bin.display().to_string());
        env.insert("OVID_GW_INTENTS".into(), intents_log.display().to_string());
        env.insert("OVID_GW_READY".into(), ready.display().to_string());
        let wrapped = netns_deny_wrapper(argv);
        let result = self.run_in(
            dir,
            &wrapped,
            NetworkMode::Inherit,
            inherit_env,
            env.clone(),
            spec.timeout_seconds,
        );
        let intents = ovid_gateway::read_intents(&intents_log);
        Ok((result?, intents))
    }

    /// The microsandbox guest path keeps its native network behavior
    /// (the guest resolves its own routes; gateway attribution for the
    /// guest is a later step). Deny is the guest's `--no-net`.
    fn run_trial_guest(
        &mut self,
        snapshot: &SnapshotRef,
        spec: &TrialSpec,
    ) -> Result<TrialResult, LabError> {
        let (network, inherit_env, enforcement) = match &spec.treatment {
            Treatment::None => (
                NetworkMode::Inherit,
                self.online_env.clone(),
                EnforcementReport::enforced(Treatment::None, "guest-network"),
            ),
            Treatment::DenyAllEgress => (
                NetworkMode::Isolated,
                self.offline_env.clone(),
                EnforcementReport::enforced(Treatment::DenyAllEgress, "guest-no-net"),
            ),
            other => {
                return Err(LabError::Unsupported(format!(
                    "the guest laboratory does not enforce `{}` yet",
                    other.describe()
                )))
            }
        };
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
            BTreeMap::new(),
            spec.timeout_seconds,
        )?;
        let observations = self.observations(&result, spec, &trial_dir);
        let record = Self::record(&spec.label, spec.treatment.clone(), enforcement, &result);
        let output_tail = format!("{}\n{}", result.stdout_tail, result.stderr_tail);
        let _ = std::fs::remove_dir_all(&trial_dir);
        Ok(TrialResult {
            record,
            observations,
            exit_code: result.exit_code,
            duration_ms: result.duration.as_millis() as u64,
            output_tail,
        })
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

    fn observations(
        &self,
        result: &RunResult,
        spec: &TrialSpec,
        trial_dir: &Path,
    ) -> TrialObservations {
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
                externally_controlled: observation.externally_controlled(),
                all_failed: observation.all_failed(),
                // Syscall-observed failures are not gateway-enforced
                // refusals; only the gateway sets `enforced_unavailable`.
                enforced_unavailable: false,
                attempts: observation.attempts,
                failures: observation.failures,
            })
            .collect();
        TrialObservations {
            network: candidates,
            egress_intents: Vec::new(), // filled by merge_intent_candidates
            executables: self.executable_candidates(&aggregated.events, spec, trial_dir),
            observed,
            events_captured: aggregated.events.len() as u64,
        }
    }

    /// Environment-provided executable candidates from one trial's events
    /// (proposal §10.4): successful execs resolved outside the workspace
    /// are `found`; a basename searched and never found (exec `ENOENT`,
    /// or stat misses across ≥2 directories with no terminating hit) is
    /// a missing tool. PATH-scan honesty: a probe that *found* its tool
    /// (successful exec anywhere, or a stat hit in a `bin`/`sbin`
    /// directory) is never reported missing.
    fn executable_candidates(
        &self,
        events: &[EventEnvelope],
        spec: &TrialSpec,
        trial_dir: &Path,
    ) -> Vec<ExecutableCandidate> {
        // Launch plumbing, not workload dependencies: shells and `env`
        // are how commands start, and the workload entry command itself
        // is the subject of the analysis, not one of its dependencies.
        const LAUNCHERS: &[&str] = &["sh", "bash", "dash", "env"];
        // The deny-gateway netns wrapper execs these before the workload;
        // they are Ovid's own machinery, never a workload dependency.
        const WRAPPER_TOOLS: &[&str] = &["unshare", "ip", "sleep"];
        let ovid_bin = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default();
        let workload_entry = spec
            .argv
            .first()
            .map(|a| a.rsplit('/').next().unwrap_or(a).to_string())
            .unwrap_or_default();
        let excluded = |name: &str| {
            LAUNCHERS.contains(&name)
                || WRAPPER_TOOLS.contains(&name)
                || name == ovid_bin
                || name == workload_entry
                || name.is_empty()
        };
        let tool_found = |basename: &str| {
            events.iter().any(|envelope| match &envelope.event {
                BoundaryEvent::ProcessExec {
                    path, errno: None, ..
                } => path.rsplit('/').next() == Some(basename),
                BoundaryEvent::FileOpened {
                    path, errno: None, ..
                } => path.rsplit_once('/').is_some_and(|(dir, base)| {
                    base == basename && (dir.ends_with("/bin") || dir.ends_with("/sbin"))
                }),
                _ => false,
            })
        };

        let mut found: std::collections::BTreeSet<String> = Default::default();
        let mut missing: std::collections::BTreeSet<String> = Default::default();
        // Successful execs of absolute paths outside the workspace: the
        // environment supplied them, so the experiment can vary them.
        // Workspace-internal tools are provisioned content, not
        // environment dependencies.
        for envelope in events {
            if let BoundaryEvent::ProcessExec {
                path, errno: None, ..
            } = &envelope.event
            {
                if !path.starts_with('/') || Path::new(path).starts_with(trial_dir) {
                    continue;
                }
                let basename = path.rsplit('/').next().unwrap_or(path);
                if !excluded(basename) {
                    found.insert(basename.to_string());
                }
            }
        }
        // Direct exec misses.
        for envelope in events {
            if let BoundaryEvent::ProcessExec {
                path,
                errno: Some(errno),
                ..
            } = &envelope.event
            {
                if errno == "ENOENT" {
                    let basename = path.rsplit('/').next().unwrap_or(path);
                    if !excluded(basename) && !found.contains(basename) && !tool_found(basename) {
                        missing.insert(basename.to_string());
                    }
                }
            }
        }
        // PATH-scan stat misses: the same basename missing from two or
        // more directories with no terminating hit. Only resolver-known
        // executables qualify — arbitrary stat misses (module probing,
        // optional plugins) carry too little signal alone (spec §6.6).
        let mut scan_dirs: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
        for envelope in events {
            if let BoundaryEvent::FileOpened {
                path,
                errno: Some(errno),
                ..
            } = &envelope.event
            {
                if errno == "ENOENT" {
                    if let Some((dir, base)) = path.rsplit_once('/') {
                        if !base.is_empty() && !base.contains('.') {
                            scan_dirs
                                .entry(base.to_string())
                                .or_default()
                                .insert(dir.to_string());
                        }
                    }
                }
            }
        }
        for (basename, dirs) in &scan_dirs {
            if dirs.len() < 2
                || excluded(basename)
                || found.contains(basename)
                || missing.contains(basename)
                || tool_found(basename)
                || self.registry.resolve_executable(basename).is_empty()
            {
                continue;
            }
            missing.insert(basename.clone());
        }

        found
            .into_iter()
            .map(|name| ExecutableCandidate {
                name,
                found: true,
                resolver_hint: None,
            })
            .chain(missing.into_iter().map(|name| {
                let hint = self
                    .registry
                    .resolve_executable(&name)
                    .first()
                    .map(|c| format!("{} via {}", c.package, c.provider));
                ExecutableCandidate {
                    name,
                    found: false,
                    resolver_hint: hint,
                }
            }))
            .collect()
    }

    /// Build a PATH-shadow directory for `HideExecutable`: every
    /// executable reachable through the host search path is linked into
    /// one directory, except the hidden target. Setting `PATH` to this
    /// directory alone makes the treatment enforceable and verifiable —
    /// the target demonstrably cannot be resolved, while everything else
    /// resolves exactly once.
    fn build_shim_path(&mut self, hidden: &str) -> Result<PathBuf, LabError> {
        let host_path = std::env::var("PATH")
            .map_err(|_| LabError::Unsupported("host PATH is not set".into()))?;
        self.trial_counter += 1;
        let shim = self.lab_dir.join(format!("shim-{:03}", self.trial_counter));
        if shim.exists() {
            std::fs::remove_dir_all(&shim)
                .map_err(|e| LabError::Preparation(format!("clear shim dir: {e}")))?;
        }
        std::fs::create_dir_all(&shim)
            .map_err(|e| LabError::Preparation(format!("create shim dir: {e}")))?;
        let mut target_existed = false;
        for dir in std::env::split_paths(&host_path) {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy().into_owned();
                if name_str == hidden {
                    target_existed = true;
                    continue;
                }
                let link = shim.join(&name);
                if link.exists() {
                    continue; // first PATH hit wins, like real resolution
                }
                #[cfg(unix)]
                let _ = std::os::unix::fs::symlink(entry.path(), &link);
            }
        }
        if !target_existed {
            let _ = std::fs::remove_dir_all(&shim);
            return Err(LabError::Unsupported(format!(
                "`{hidden}` is not resolved via the host search path; hiding it there \
                 would not vary the dependency"
            )));
        }
        // Verify the enforcement precondition before the trial runs.
        if shim.join(hidden).exists() {
            let _ = std::fs::remove_dir_all(&shim);
            return Err(LabError::Preparation(format!(
                "shim construction failed: {hidden} still resolvable"
            )));
        }
        Ok(shim)
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
            // Per-dependency egress control runs through the forward
            // gateway, which needs real egress — so it is enforceable in
            // the process laboratory under the allow posture only.
            per_dependency_egress: matches!(self.kind, BackendKind::Process)
                && self.egress == EgressPolicy::Allow,
            // PATH shadowing controls host-process resolution only; the
            // guest VM has its own search path, so the guest laboratory
            // honestly does not claim it yet.
            executable_hiding: matches!(self.kind, BackendKind::Process),
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
                    BTreeMap::new(),
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
        if self.kind == BackendKind::Microsandbox {
            return self.run_trial_guest(snapshot, spec);
        }
        let mut shim_dir: Option<PathBuf> = None;
        // The base network posture the workload runs under, before any
        // treatment-specific change. Deny is the default: no real egress,
        // the deny gateway names what the workload tried to reach.
        let base_deny =
            || -> Result<(NetworkMode, Vec<String>, GatewayPlan, &'static str), LabError> {
                if network_isolation_available() {
                    Ok((
                        NetworkMode::Inherit, // the wrapper does its own unshare
                        self.inherit_without_proxy(&self.offline_env),
                        GatewayPlan::NetnsDeny,
                        "user-netns+gateway-deny",
                    ))
                } else {
                    Ok((
                        NetworkMode::Inherit,
                        self.inherit_without_proxy(&self.offline_env),
                        GatewayPlan::HostDenyPartial,
                        "gateway-deny-partial",
                    ))
                }
            };
        let base_allow = || {
            (
                NetworkMode::Inherit,
                self.inherit_without_proxy(&self.online_env),
                GatewayPlan::HostForward {
                    block: BTreeSet::new(),
                },
                "gateway-forward",
            )
        };

        let (network, inherit_env, mut env, gateway, enforcement) = match &spec.treatment {
            Treatment::None => {
                let (network, inherit, gateway, mechanism) = match self.egress {
                    EgressPolicy::Deny => base_deny()?,
                    EgressPolicy::Allow => base_allow(),
                };
                let status = if matches!(gateway, GatewayPlan::HostDenyPartial) {
                    EnforcementStatus::PartiallyEnforced
                } else {
                    EnforcementStatus::Enforced
                };
                (
                    network,
                    inherit,
                    BTreeMap::new(),
                    gateway,
                    enforcement_report(Treatment::None, mechanism, status),
                )
            }
            Treatment::DenyAllEgress => {
                if !self.capabilities().deny_all_egress {
                    return Err(LabError::Unsupported(
                        "deny-all egress cannot be enforced on this host (no unprivileged \
                         user namespaces); refusing to run a weakened trial"
                            .into(),
                    ));
                }
                (
                    NetworkMode::Inherit,
                    self.inherit_without_proxy(&self.offline_env),
                    BTreeMap::new(),
                    GatewayPlan::NetnsDeny,
                    EnforcementReport::enforced(
                        Treatment::DenyAllEgress,
                        "user-netns+gateway-deny",
                    ),
                )
            }
            Treatment::HideExecutable { name } => {
                if !self.capabilities().executable_hiding {
                    return Err(LabError::Unsupported(
                        "executable hiding is only enforceable in the host-process \
                         laboratory (the guest VM resolves its own search path)"
                            .into(),
                    ));
                }
                // Exactly one controlled change: the network posture
                // mirrors the baseline (same egress policy); only the
                // search path loses one tool.
                let (network, inherit, gateway, _) = match self.egress {
                    EgressPolicy::Deny => base_deny()?,
                    EgressPolicy::Allow => base_allow(),
                };
                let shim = self.build_shim_path(name)?;
                let inherit: Vec<String> = inherit.into_iter().filter(|v| v != "PATH").collect();
                let env = BTreeMap::from([("PATH".to_string(), shim.display().to_string())]);
                shim_dir = Some(shim);
                (
                    network,
                    inherit,
                    env,
                    gateway,
                    EnforcementReport::enforced(spec.treatment.clone(), "path-shadow"),
                )
            }
            Treatment::BlockDependency { dependency } => {
                // Per-dependency egress control: forward everything but
                // the one named service (proposal §10.5 step 5). Requires
                // the forward path, so real egress is used for the rest.
                let mut block: BTreeSet<String> = BTreeSet::new();
                block.insert(dependency.logical_identity.clone());
                if let Some((host, _)) = dependency.logical_identity.rsplit_once(':') {
                    block.insert(host.to_string());
                }
                (
                    NetworkMode::Inherit,
                    self.inherit_without_proxy(&self.online_env),
                    BTreeMap::new(),
                    GatewayPlan::HostForward { block },
                    EnforcementReport::enforced(spec.treatment.clone(), "gateway-block"),
                )
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

        let (result, intents) = self.execute(
            &trial_dir,
            &spec.argv,
            network,
            &inherit_env,
            &mut env,
            gateway,
            spec,
        )?;

        let mut observations = self.observations(&result, spec, &trial_dir);
        merge_intent_candidates(&mut observations, &intents);
        let record = Self::record(&spec.label, spec.treatment.clone(), enforcement, &result);
        let output_tail = format!("{}\n{}", result.stdout_tail, result.stderr_tail);
        let trial = TrialResult {
            record,
            observations,
            exit_code: result.exit_code,
            duration_ms: result.duration.as_millis() as u64,
            output_tail,
        };
        // Destroy the overlay (and any shim) after result persistence
        // (proposal §14.5).
        let _ = std::fs::remove_dir_all(&trial_dir);
        if let Some(shim) = shim_dir {
            let _ = std::fs::remove_dir_all(&shim);
        }
        Ok(trial)
    }

    fn destroy(&mut self, environment: PreparedEnvironment) -> Result<(), LabError> {
        let _ = std::fs::remove_dir_all(&environment.workspace);
        Ok(())
    }
}

/// Wrap `argv` so it runs in a fresh user+network namespace with the
/// lab deny gateway on the private loopback. Loopback is brought up
/// (`ip`, else a python ioctl); the gateway starts on the fixed port,
/// the workload waits for it, runs, and the gateway is killed. Paths and
/// the ovid binary arrive via `OVID_GW_*` env, so nothing user-supplied
/// is interpolated into the script. The workload argv is passed as
/// positional parameters (`"$@"`), never spliced into the shell text.
fn netns_deny_wrapper(argv: &[String]) -> Vec<String> {
    let script = format!(
        concat!(
            "ip link set lo up 2>/dev/null || ",
            "python3 -c 'import socket,fcntl,struct;",
            "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);",
            "fcntl.ioctl(s.fileno(),0x8914,struct.pack(\"16sH14s\",b\"lo\",0x41,b\"\\0\"*14))' ",
            "2>/dev/null || true\n",
            "\"$OVID_GW_BIN\" internal-gateway --listen 127.0.0.1:{port} --policy deny ",
            "--log \"$OVID_GW_INTENTS\" --ready \"$OVID_GW_READY\" >/dev/null 2>&1 &\n",
            "GW=$!\n",
            "i=0; while [ ! -f \"$OVID_GW_READY\" ] && [ \"$i\" -lt 100 ]; do ",
            "sleep 0.05; i=$((i+1)); done\n",
            "\"$@\"\n",
            "STATUS=$?\n",
            "kill \"$GW\" 2>/dev/null\n",
            "exit \"$STATUS\"\n",
        ),
        port = NETNS_GATEWAY_PORT,
    );
    let mut wrapped = vec![
        "unshare".to_string(),
        "-r".to_string(),
        "-n".to_string(),
        "sh".to_string(),
        "-c".to_string(),
        script,
        "ovid-netns".to_string(), // $0
    ];
    wrapped.extend(argv.iter().cloned());
    wrapped
}

/// Build an enforcement report with an explicit status (the domain
/// helpers cover only fully-enforced and not-enforced).
fn enforcement_report(
    treatment: Treatment,
    mechanism: &str,
    status: EnforcementStatus,
) -> EnforcementReport {
    let limitations = if status == EnforcementStatus::PartiallyEnforced {
        vec![
            "namespace isolation unavailable: proxied egress is refused and named, but a \
             workload opening sockets directly is not blocked"
                .into(),
        ]
    } else {
        Vec::new()
    };
    EnforcementReport {
        requested: treatment,
        status,
        mechanism: mechanism.into(),
        limitations,
    }
}

/// Whether a gateway-named host is loopback (the gateway itself or a
/// local service) and so never an external dependency.
fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

/// Fold one trial's gateway intents into its observations: preserve the
/// full intents (minus loopback) as evidence, and derive external
/// network candidates. A named destination is external by construction;
/// `all_failed` is true when every intent to it was refused (the
/// deny/block gateway contacted nothing), false when any was forwarded.
fn merge_intent_candidates(observations: &mut TrialObservations, intents: &[GatewayIntent]) {
    // Per identity: (attempts, non-forwarded failures, refused-by-policy,
    // forwarded). An enforced refusal (`refused`) is the gateway blocking
    // the destination itself; `forward-failed` is a genuinely unreachable
    // host; `forwarded` means it got through.
    let mut by_identity: BTreeMap<String, (u64, u64, u64, u64)> = BTreeMap::new();
    for intent in intents {
        if is_loopback_host(&intent.host) {
            continue;
        }
        observations.egress_intents.push(EgressIntent {
            host: intent.host.clone(),
            port: intent.port,
            scheme: intent.scheme.clone(),
            method: intent.method.clone(),
            path: intent.path.clone(),
            decision: intent.decision.clone(),
        });
        let identity = format!("{}:{}", intent.host, intent.port);
        let entry = by_identity.entry(identity).or_insert((0, 0, 0, 0));
        entry.0 += 1; // attempts
        match intent.decision.as_str() {
            "forwarded" => entry.3 += 1,
            "refused" => {
                entry.1 += 1;
                entry.2 += 1;
            }
            _ => entry.1 += 1, // forward-failed and anything else: a failure, but not enforced
        }
    }
    for (identity, (attempts, failures, refused, forwarded)) in by_identity {
        // Enforced only when every attempt was a policy refusal: nothing
        // forwarded and nothing merely failed to connect.
        let enforced = attempts > 0 && forwarded == 0 && refused == attempts;
        let key = DependencyKey::network(&identity);
        if let Some(existing) = observations.network.iter_mut().find(|c| c.key == key) {
            existing.attempts += attempts;
            existing.failures += failures;
            existing.all_failed = existing.failures >= existing.attempts;
            existing.enforced_unavailable &= enforced;
        } else {
            observations.network.push(NetworkCandidate {
                key,
                externally_controlled: true,
                all_failed: failures >= attempts,
                enforced_unavailable: enforced,
                attempts,
                failures,
            });
        }
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
            EgressPolicy::Allow,
            registry,
        )
        .unwrap();
        let caps = lab.capabilities();
        assert!(!caps.vm_isolation, "the process backend never claims a VM");
        assert!(caps.clean_snapshot_restore);
        assert_eq!(caps.deny_all_egress, network_isolation_available());
        assert!(
            caps.executable_hiding,
            "the process laboratory enforces PATH shadowing"
        );
        // Per-dependency egress needs the forward gateway; claimed only
        // under the allow posture.
        assert!(caps.per_dependency_egress);
    }

    fn intent(host: &str, port: u16, decision: &str) -> GatewayIntent {
        GatewayIntent {
            seq: 0,
            host: host.into(),
            port,
            scheme: "https".into(),
            method: "CONNECT".into(),
            path: String::new(),
            decision: decision.into(),
        }
    }

    #[test]
    fn intents_become_named_candidates_and_evidence() {
        let mut obs = TrialObservations::default();
        merge_intent_candidates(
            &mut obs,
            &[
                intent("api.example.com", 443, "refused"),
                intent("api.example.com", 443, "refused"),
            ],
        );
        assert_eq!(obs.egress_intents.len(), 2, "raw intents preserved");
        assert_eq!(obs.network.len(), 1, "collapsed to one candidate");
        let c = &obs.network[0];
        assert_eq!(c.key.logical_identity, "api.example.com:443");
        assert!(c.externally_controlled);
        assert!(c.all_failed, "every intent refused => unavailable");
        assert_eq!(c.attempts, 2);
    }

    #[test]
    fn forwarded_intents_mark_the_candidate_available() {
        let mut obs = TrialObservations::default();
        merge_intent_candidates(
            &mut obs,
            &[
                intent("db.example.com", 5432, "forwarded"),
                intent("db.example.com", 5432, "refused"),
            ],
        );
        assert!(
            !obs.network[0].all_failed,
            "one forwarded intent means the dependency was reachable"
        );
    }

    #[test]
    fn loopback_intents_are_never_candidates() {
        let mut obs = TrialObservations::default();
        merge_intent_candidates(
            &mut obs,
            &[
                intent("127.0.0.1", 8899, "refused"),
                intent("localhost", 5000, "refused"),
            ],
        );
        assert!(obs.network.is_empty(), "loopback is not an external dep");
        assert!(obs.egress_intents.is_empty());
    }

    #[test]
    fn netns_wrapper_passes_workload_as_positional_args() {
        let wrapped = netns_deny_wrapper(&["make".into(), "test".into()]);
        assert_eq!(wrapped[0], "unshare");
        assert!(wrapped.contains(&"-n".to_string()));
        // The workload is positional, never spliced into the script text.
        assert_eq!(wrapped[wrapped.len() - 2], "make");
        assert_eq!(wrapped[wrapped.len() - 1], "test");
        let script = &wrapped[5];
        assert!(script.contains("internal-gateway"));
        assert!(script.contains("--policy deny"));
        assert!(!script.contains("make"), "argv is not in the script text");
    }
}
