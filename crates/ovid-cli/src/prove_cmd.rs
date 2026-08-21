//! The `prove`, `replay`, `inspect`, and `doctor` commands — the 0.2
//! surface (proposal §4) wired through the application use cases.
//!
//! `prove` is the primary loop (proposal §9.2): the CLI resolves the
//! source, selects a workload, composes a laboratory + ledger journal +
//! terminal progress, and hands control to `ovid_application::prove`.
//! Everything written to disk is a projection of the typed journal and
//! the returned report; the terminal shows conclusions, the bundle keeps
//! the raw material (proposal §4.4).

use crate::lab::HostLaboratory;
use crate::pipeline::{self, BackendKind};
use anyhow::{anyhow, bail, Context as AnyhowContext, Result};
use ovid_application::{
    prove, run_clean_replay, JournalError, JournalEvent, JournalPort, LaboratoryPort, ProgressPort,
    ProvePolicy, ProveReport, ProveRequest,
};
use ovid_core::{Digest, IdGenerator, OvidId, TrustTier};
use ovid_domain::{AnalysisScope, Necessity, WorldOutcome};
use ovid_evidence::{Claim, ClaimStore, EvidenceLedger, EvidenceRecord};
use ovid_packs::PackRegistry;
use ovid_planner::ActionKind;
use ovid_world::{SuccessSpec, Treatment as WorldTreatment, World, WorldDependency, WorldStatus};
use std::path::{Path, PathBuf};

/// Version marker for the proof projection.
const PROOF_API_VERSION: &str = "ovid.dev/proof/v1alpha1";

/// Options for `ovid prove`.
pub struct ProveOptions {
    pub workload: String,
    /// Explicit argv (after `--`); overrides discovery.
    pub argv: Option<Vec<String>>,
    pub backend: BackendKind,
    pub guest_image: String,
    /// Explicit opt-in for host-process execution of remote repositories
    /// (proposal §15.2).
    pub trusted_process: bool,
    pub baseline_runs: usize,
    pub confirmation_runs: usize,
    pub max_trials: usize,
    pub timeout_seconds: u64,
    pub extra_env: Vec<String>,
    pub no_replay: bool,
    pub packs_dir: Option<PathBuf>,
    pub json: bool,
}

/// Journal adapter: typed events appended to the canonical hash-chained
/// evidence ledger (proposal §12.2 — the journal *is* the ledger; the
/// operational split comes later).
struct LedgerJournal {
    ledger: EvidenceLedger,
    ids: IdGenerator,
}

impl LedgerJournal {
    fn open(path: &Path) -> Result<LedgerJournal> {
        Ok(LedgerJournal {
            ledger: EvidenceLedger::open(path).map_err(|e| anyhow!("{e}"))?,
            ids: IdGenerator::new(),
        })
    }

    /// Execution-grounded events are T0 (host-enforced outcomes);
    /// bookkeeping events are T4 (tool-derived context).
    fn tier(event: &JournalEvent) -> TrustTier {
        match event {
            JournalEvent::TrialCompleted { .. }
            | JournalEvent::BaselineClassified { .. }
            | JournalEvent::DependencyClassified { .. }
            | JournalEvent::ReplayCompleted { .. } => TrustTier::T0,
            _ => TrustTier::T4,
        }
    }
}

impl JournalPort for LedgerJournal {
    fn append(&mut self, event: &JournalEvent) -> Result<String, JournalError> {
        let value = serde_json::to_value(event).map_err(|e| JournalError::Append(e.to_string()))?;
        let kind = value
            .get("event")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let id = self.ids.next("evidence");
        let record = EvidenceRecord {
            id: id.clone(),
            record_type: format!("journal:{kind}"),
            run_id: None,
            wall_time: Some(chrono::Utc::now()),
            provider: "ovid-application".into(),
            provider_version: ovid_core::OVID_VERSION.into(),
            trust_tier: Self::tier(event),
            data: value,
            previous: None,
        };
        self.ledger
            .append(record)
            .map_err(|e| JournalError::Append(e.to_string()))?;
        Ok(id.to_string())
    }
}

/// Terminal progress: one aligned line per stage (proposal §4.3).
struct TerminalProgress;

impl ProgressPort for TerminalProgress {
    fn emit(&self, stage: &str, detail: &str) {
        eprintln!("{stage:<14} {detail}");
    }
}

/// Whether a locator is a remote repository (URL-shaped) rather than a
/// local path.
fn is_remote(locator: &str) -> bool {
    locator.starts_with("http://")
        || locator.starts_with("https://")
        || locator.starts_with("git://")
        || locator.starts_with("ssh://")
        || locator.starts_with("git@")
}

/// Default bundle directory: `.ovid/runs/<analysis-id>`, with
/// `.ovid/latest` pointing at it (proposal §4.4 item 8).
fn default_out_dir(ids: &IdGenerator) -> Result<PathBuf> {
    let id = ids.next("analysis");
    let token = id.as_str().split(':').nth(1).unwrap_or("run").to_string();
    let dir = PathBuf::from(".ovid").join("runs").join(token);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        PathBuf::from(".ovid").join("latest"),
        format!("{}\n", dir.display()),
    )?;
    Ok(dir)
}

fn open_registry(packs_dir: Option<&Path>) -> Result<PackRegistry> {
    let mut registry = PackRegistry::builtin().map_err(|e| anyhow!("builtin packs: {e}"))?;
    if let Some(dir) = packs_dir {
        registry
            .load_dir(dir)
            .map_err(|e| anyhow!("loading packs from {}: {e}", dir.display()))?;
    }
    Ok(registry)
}

/// Run `ovid prove`. Returns the process exit code (proposal §16.2):
/// 0 = completed, 20 = workload/baseline failed or replay failed.
pub fn run_prove(
    locator: &str,
    reference: Option<String>,
    out: Option<PathBuf>,
    options: &ProveOptions,
) -> Result<i32> {
    // P0 safety (proposal §15.2): a remote repository never executes on
    // the host process without an explicit opt-in.
    if is_remote(locator) && options.backend == BackendKind::Process && !options.trusted_process {
        bail!(
            "remote repositories do not execute on the host process by default.\n\
             Either:\n\
             \x20 - use a guest VM:      ovid prove {locator} --backend microsandbox\n\
             \x20 - or accept reduced isolation for a repository you trust:\n\
             \x20                        ovid prove {locator} --trusted-process"
        );
    }

    let ids = IdGenerator::new();
    let out_dir = match out {
        Some(dir) => {
            std::fs::create_dir_all(&dir)?;
            dir
        }
        None => default_out_dir(&ids)?,
    };
    let registry = open_registry(options.packs_dir.as_deref())?;

    // Resolve source + select workload.
    let snapshot = pipeline::acquire_snapshot(locator, reference, &out_dir)?;
    let graph = ovid_planner::plan(&snapshot, &registry);
    let (workload_name, workload_argv) = match &options.argv {
        Some(argv) if !argv.is_empty() => (options.workload.clone(), argv.clone()),
        _ => {
            let kind = match options.workload.as_str() {
                "build" => ActionKind::Build,
                "test" => ActionKind::Test,
                "start" => ActionKind::Start,
                other => bail!("unknown workload {other:?} (use build|test|start, or pass an explicit command after --)"),
            };
            let action = graph.best(kind).ok_or_else(|| {
                anyhow!(
                    "no {} command was discovered for this repository; pass one explicitly:\n\
                     \x20 ovid prove {locator} --workload {} -- <command...>",
                    options.workload,
                    options.workload
                )
            })?;
            (options.workload.clone(), action.command.clone())
        }
    };
    let provision_argv = graph
        .candidates(ActionKind::DependencyInstall)
        .first()
        .map(|a| a.command.clone())
        .filter(|argv| *argv != workload_argv);

    let policy = ProvePolicy {
        baseline_runs: options.baseline_runs,
        confirmation_runs: options.confirmation_runs,
        max_trials: options.max_trials,
        timeout_seconds: options.timeout_seconds,
        attempt_replay: !options.no_replay,
    };
    let scope = AnalysisScope {
        repository: snapshot.canonical_url.clone(),
        revision: snapshot.revision.clone(),
        workload: workload_name.clone(),
        workload_argv: workload_argv.clone(),
        success_predicate: "exit-code == 0".into(),
        execution_policy: Digest::of_bytes(
            format!(
                "backend={:?};timeout={};extra_env={:?}",
                options.backend, options.timeout_seconds, options.extra_env
            )
            .as_bytes(),
        )
        .hex()
        .to_string(),
        ..Default::default()
    };

    let mut lab = HostLaboratory::new(
        options.backend.clone(),
        &options.guest_image,
        &snapshot.root,
        snapshot.source_digest.hex(),
        &out_dir.join(".lab"),
        &options.extra_env,
        registry,
    )
    .map_err(|e| anyhow!("{e}\nRun `ovid doctor` for host capability diagnostics."))?;
    let mut journal = LedgerJournal::open(&out_dir.join("evidence.jsonl"))?;

    eprintln!(
        "Ovid prove  {} @ {}  workload {}\n",
        snapshot.canonical_url,
        &snapshot.revision[..snapshot.revision.len().min(12)],
        workload_name
    );
    let request = ProveRequest {
        scope,
        provision_argv,
    };
    let report = prove(&mut lab, &mut journal, &TerminalProgress, &request, &policy)
        .map_err(|e| anyhow!("prove failed: {e}"))?;

    write_bundle(&out_dir, &report, &mut journal)?;
    if options.json {
        println!("{}", serde_json::to_string_pretty(&proof_value(&report))?);
    } else {
        print_report(&report, &out_dir);
    }
    Ok(exit_code(&report))
}

/// Map the report onto stable exit codes (proposal §16.2).
fn exit_code(report: &ProveReport) -> i32 {
    let baseline_ok = report.baseline.supports_experiments();
    let replay_failed = matches!(report.world, WorldOutcome::ReplayFailed { .. });
    if baseline_ok && !replay_failed {
        0
    } else {
        20
    }
}

fn proof_value(report: &ProveReport) -> serde_json::Value {
    let mut value = serde_json::to_value(report).expect("reports serialize");
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "api_version".into(),
            serde_json::Value::String(PROOF_API_VERSION.into()),
        );
    }
    value
}

/// Write the bundle projections: proof.json, timings.json, claims, world
/// lock + compose. Standards exports stay lazy (proposal §14.10).
fn write_bundle(out_dir: &Path, report: &ProveReport, journal: &mut LedgerJournal) -> Result<()> {
    std::fs::write(
        out_dir.join("proof.json"),
        serde_json::to_string_pretty(&proof_value(report))?,
    )?;
    std::fs::write(
        out_dir.join("timings.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "stages": report.timings,
            "trials_executed": report.trials_executed,
        }))?,
    )?;

    // Claims: required/optional conclusions become claims supported by
    // their journal evidence; unresolved stays visible in the proof
    // report without minting claims (mirrors the legacy classifier).
    let mut claims = ClaimStore::open(out_dir.join("claims.json")).map_err(|e| anyhow!("{e}"))?;
    for classified in &report.conclusions {
        let (predicate, states) = match classified.conclusion.necessity() {
            Necessity::Required => (
                "requires",
                ovid_core::ClaimStates::default()
                    .with(ovid_core::ClaimState::Attempted)
                    .with(ovid_core::ClaimState::CausallyRequired),
            ),
            Necessity::Optional => (
                "optionally-uses",
                ovid_core::ClaimStates::default().with(ovid_core::ClaimState::Attempted),
            ),
            Necessity::Unresolved => continue,
        };
        let claim = Claim {
            id: journal.ids.next("claim"),
            predicate: predicate.into(),
            subject: format!("workload:{}", report.scope.workload),
            object: classified.conclusion.dependency().describe(),
            states,
            confidence: 0.0,
            supports: vec![OvidId::from_string(classified.evidence.clone())],
            contradicts: vec![],
            normalizer: "ovid-prove".into(),
            normalizer_version: ovid_core::OVID_VERSION.into(),
        };
        claims.upsert(claim, &journal.ledger);
    }
    claims.save().map_err(|e| anyhow!("{e}"))?;

    // World lock projection (status can only reflect the domain outcome).
    let (proposed, status, replay_failure) = match &report.world {
        WorldOutcome::NotSynthesized { .. } => (None, WorldStatus::Proposed, None),
        WorldOutcome::Proposed { world, .. } => (Some(world), WorldStatus::Proposed, None),
        WorldOutcome::ReplayFailed { world, failure } => {
            (Some(world), WorldStatus::ReplayFailed, Some(failure))
        }
        WorldOutcome::Verified { world } => (Some(world.world()), WorldStatus::Verified, None),
    };
    let _ = replay_failure;
    if let Some(proposed) = proposed {
        let mut world = World {
            target: format!("{}#{}", report.scope.repository, report.scope.workload),
            ..Default::default()
        };
        for key in &proposed.candidate().required {
            let identity = &key.logical_identity;
            // Required executables are world tools; required network
            // services become dependency cells (proposal §11.1).
            if key.kind == ovid_domain::DependencyKind::Executable {
                world.tools.push(identity.clone());
                continue;
            }
            let (host, port) = identity
                .rsplit_once(':')
                .and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h.to_string(), Some(p))))
                .unwrap_or_else(|| (identity.clone(), None));
            world.dependencies.push(WorldDependency {
                id: identity.clone(),
                treatment: WorldTreatment::Unresolved {
                    reason: "proven required and verified against the live external \
                             service; no local treatment provider bound yet"
                        .into(),
                },
                aliases: vec![host],
                port,
                environment: Default::default(),
            });
        }
        let mut lock = ovid_world::WorldLock::from_world(
            &world,
            report.scope.workload_argv.clone(),
            SuccessSpec::ExitCode { expected: 0 },
        );
        lock.status = status;
        std::fs::write(out_dir.join("world.lock.yaml"), lock.to_yaml())?;
        std::fs::write(out_dir.join("compose.yaml"), lock.to_compose_yaml())?;
    }
    Ok(())
}

/// Terminal proof report (proposal §4.3).
fn print_report(report: &ProveReport, out_dir: &Path) {
    println!();
    let provision_line = match (&report.provision_argv, &report.provision) {
        (Some(argv), Some(record)) => format!(
            "{:<11} `{}`",
            if record.outcome.passed {
                "passed"
            } else {
                "failed"
            },
            argv.join(" ")
        ),
        _ => "skipped     no install candidate".into(),
    };
    println!("Provisioning   {provision_line}");
    println!("Baseline       {}", report.baseline.describe());
    println!(
        "Experiments    {} trial(s) executed",
        report.trials_executed
    );
    let world_line = match &report.world {
        WorldOutcome::Verified { .. } => "verified    clean replay passed".to_string(),
        WorldOutcome::ReplayFailed { failure, .. } => format!(
            "replay-failed  {}",
            failure
                .outcome
                .failure_signature
                .as_deref()
                .unwrap_or("failure preserved")
        ),
        WorldOutcome::Proposed { reason, .. } => format!("proposed    {reason}"),
        WorldOutcome::NotSynthesized { reason } => format!("not synthesized  {reason}"),
    };
    println!("World          {world_line}");

    for (label, necessity) in [
        ("REQUIRED", Necessity::Required),
        ("OPTIONAL", Necessity::Optional),
        ("UNRESOLVED", Necessity::Unresolved),
    ] {
        let group: Vec<_> = report
            .conclusions
            .iter()
            .filter(|c| c.conclusion.necessity() == necessity)
            .collect();
        if group.is_empty() {
            continue;
        }
        println!("\n{label}");
        for classified in group {
            println!("  {}", classified.conclusion.dependency().describe());
            println!("    {}", classified.conclusion.reason());
        }
    }
    if !report.limitations.is_empty() {
        println!("\nLimitations");
        for limitation in &report.limitations {
            println!("  - {limitation}");
        }
    }
    println!("\nBundle:  {}", out_dir.display());
    println!("Explain: ovid explain <query> --from {}", out_dir.display());
    println!("Replay:  ovid replay {}", out_dir.display());
}

/// Run `ovid replay <bundle>` (proposal §9.3): rebuild the environment
/// from the recorded scope, rerun the locked workload from a clean
/// snapshot, and update the lock's verification status from the outcome.
pub fn run_replay(
    bundle: &Path,
    backend: BackendKind,
    guest_image: &str,
    extra_env: &[String],
    timeout_seconds: u64,
) -> Result<i32> {
    let proof_path = bundle.join("proof.json");
    let text = std::fs::read_to_string(&proof_path).with_context(|| {
        format!(
            "no proof.json in {} (run `ovid prove` first)",
            bundle.display()
        )
    })?;
    let proof: serde_json::Value = serde_json::from_str(&text)?;
    let scope: AnalysisScope = serde_json::from_value(
        proof
            .get("scope")
            .cloned()
            .ok_or_else(|| anyhow!("proof.json has no scope"))?,
    )?;
    let provision_argv: Option<Vec<String>> = proof
        .get("provision_argv")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .flatten();

    let registry = open_registry(None)?;
    // Canonical URLs for local trees are `file://<path>`; re-acquire them
    // as the local path they came from, not as a git remote.
    let locator = scope
        .repository
        .strip_prefix("file://")
        .unwrap_or(&scope.repository)
        .to_string();
    let snapshot = pipeline::acquire_snapshot(&locator, None, bundle)?;
    if snapshot.revision != scope.revision {
        eprintln!(
            "warning: source is now at {} but the proof was for {}; replay verifies the \
             current tree",
            &snapshot.revision[..snapshot.revision.len().min(12)],
            &scope.revision[..scope.revision.len().min(12)]
        );
    }
    let mut lab = HostLaboratory::new(
        backend,
        guest_image,
        &snapshot.root,
        snapshot.source_digest.hex(),
        &bundle.join(".lab"),
        extra_env,
        registry,
    )
    .map_err(|e| anyhow!("{e}"))?;
    let mut journal = LedgerJournal::open(&bundle.join("evidence.jsonl"))?;

    eprintln!(
        "Ovid replay  {} @ {}  `{}`",
        scope.repository,
        &snapshot.revision[..snapshot.revision.len().min(12)],
        scope.workload_argv.join(" ")
    );
    let environment = lab
        .prepare(provision_argv.as_deref())
        .map_err(|e| anyhow!("{e}"))?;
    let snapshot_ref = lab
        .snapshot(&environment, "replay")
        .map_err(|e| anyhow!("{e}"))?;
    let result = run_clean_replay(
        &mut lab,
        &snapshot_ref,
        "replay",
        &scope.workload_argv,
        timeout_seconds,
    )
    .map_err(|e| anyhow!("{e}"))?;
    journal.append(&JournalEvent::ReplayCompleted {
        label: "replay".into(),
        passed: result.record.outcome.passed,
    })?;

    // Update the lock's status from the outcome — never the other way.
    let lock_path = bundle.join("world.lock.yaml");
    if let Ok(lock_text) = std::fs::read_to_string(&lock_path) {
        if let Ok(mut lock) = serde_yaml::from_str::<ovid_world::WorldLock>(&lock_text) {
            lock.status = if result.record.outcome.passed {
                WorldStatus::Verified
            } else {
                WorldStatus::ReplayFailed
            };
            std::fs::write(&lock_path, lock.to_yaml())?;
        }
    }
    if result.record.outcome.passed {
        println!("replay: verified (clean run passed)");
        Ok(0)
    } else {
        println!(
            "replay: failed ({})",
            result
                .record
                .outcome
                .failure_signature
                .as_deref()
                .unwrap_or("no signature")
        );
        println!("{}", result.output_tail.trim_end());
        Ok(20)
    }
}

/// Run `ovid doctor` (proposal §4.2): report host capabilities with exact
/// remediation, before a failed run makes the user discover them.
pub fn run_doctor() -> Result<()> {
    let check = |ok: bool| if ok { "ok  " } else { "MISS" };
    let git = which("git");
    let strace = ovid_observer::strace_available();
    let userns = ovid_sandbox::network_isolation_available();
    let kvm = Path::new("/dev/kvm").exists();
    let msb = which("msb") || std::env::var_os("OVID_MSB_BIN").is_some();

    println!("ovid doctor — host capability report\n");
    println!(
        "[{}] git                 repository acquisition",
        check(git)
    );
    if !git {
        println!("       -> install git (URL sources need it; local paths work without)");
    }
    println!(
        "[{}] strace              boundary observation (process backend)",
        check(strace)
    );
    if !strace {
        println!("       -> apt-get install strace  (runs execute unobserved without it)");
    }
    println!(
        "[{}] user namespaces     deny-all egress enforcement (process backend)",
        check(userns)
    );
    if !userns {
        println!(
            "       -> without `unshare -r -n`, network treatments cannot be enforced and \
             candidates stay unresolved"
        );
    }
    println!(
        "[{}] msb                 microsandbox guest-VM laboratory (--backend microsandbox)",
        check(msb)
    );
    if !msb {
        println!("       -> https://microsandbox.dev — required to prove remote repos safely");
    }
    println!(
        "[{}] /dev/kvm            Firecracker MicroVM backend (optional)",
        check(kvm)
    );
    println!();
    let lab_ready = strace && userns;
    if lab_ready {
        println!("process laboratory: ready (observation + enforced egress denial)");
    } else {
        println!("process laboratory: degraded — see items above");
    }
    Ok(())
}

fn which(binary: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let candidate = dir.join(binary);
                candidate.is_file()
            })
        })
        .unwrap_or(false)
}

/// Run `ovid inspect` (proposal §4.2): static-only, never executes
/// repository code, ends with ranked workload candidates so the next
/// step (`ovid prove --workload …`) is obvious.
pub fn run_inspect(
    locator: &str,
    reference: Option<String>,
    out: &Path,
    packs_dir: Option<&Path>,
    json: bool,
) -> Result<()> {
    let bundle = pipeline::run_inventory(locator, reference.clone(), out, packs_dir)?;
    if json {
        println!("{}", bundle.manifest.to_json_pretty());
        return Ok(());
    }
    pipeline::print_summary(&bundle);

    // Ranked workload candidates from the planner (static, not executed).
    let registry = open_registry(packs_dir)?;
    let snapshot = pipeline::acquire_snapshot(locator, reference, out)?;
    let graph = ovid_planner::plan(&snapshot, &registry);
    println!("\nworkload candidates (static ranking; nothing was executed):");
    for kind in [
        ActionKind::DependencyInstall,
        ActionKind::Build,
        ActionKind::Test,
        ActionKind::Start,
    ] {
        if let Some(action) = graph.best(kind) {
            let label = match kind {
                ActionKind::DependencyInstall => "install",
                ActionKind::Build => "build",
                ActionKind::Test => "test",
                ActionKind::Start => "start",
                _ => "other",
            };
            println!(
                "  {:<8} `{}`  (score {:.2}, {})",
                label,
                action.command.join(" "),
                action.score,
                action.source_file.as_deref().unwrap_or("mined")
            );
        }
    }
    println!("\nnext: ovid prove {locator} --workload test");
    Ok(())
}
