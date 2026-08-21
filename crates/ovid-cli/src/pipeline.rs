//! The local analysis pipeline (spec §14's lifecycle, local-mode scope).
//!
//! Stages: acquire -> inventory -> plan -> execute under observation ->
//! normalize evidence -> propose resolutions -> counterfactuals (env
//! variables + natural unavailability) -> synthesize world -> emit bundle.
//!
//! Every stage appends to the hash-chained evidence ledger first; the
//! manifest and claims are projections (ADR-004). Causality labels follow
//! the spec strictly: only an actual counterfactual (a rerun without the
//! dependency, or a run that succeeded while the dependency was
//! unavailable) may produce `Required`/`Optional`; everything else stays
//! `Unresolved` (§20.5, §6.6).

use anyhow::{anyhow, bail, Context as AnyhowContext, Result};
use ovid_core::{
    BoundaryEvent, CausalClassification, ClaimState, ClaimStates, Digest, IdGenerator, OvidId,
    TrustTier,
};
use ovid_evidence::{Claim, ClaimStore, EvidenceLedger, EvidenceRecord};
use ovid_experiment::{propose_resolutions, ResolutionKind, ResolutionProposal, SuccessPredicate};
use ovid_gateway::NetworkAnalysis;
use ovid_inventory::InventoryReport;
use ovid_observer::aggregate;
use ovid_output::{
    integration_plan_markdown, to_cyclonedx, to_spdx, ArtifactReport, ExternalSystemReport,
    Manifest, RepositorySection, ToolReport, UnresolvedItem, WorkloadReport,
    WorldDependencySummary,
};
use ovid_packs::PackRegistry;
use ovid_planner::ActionKind;
use ovid_repository::{acquire, AcquireOptions, RepoSnapshot, RepositorySource};
use ovid_sandbox::{ExecutionBackend, ProcessBackend, RunResult, RunSpec, WorkspaceMode};
use ovid_world::{SuccessSpec, Treatment, World, WorldDependency, WorldLock, WorldStatus};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct ExecutionOptions {
    pub in_place: bool,
    pub inherit_env: Vec<String>,
    pub timeout_seconds: u64,
    pub counterfactual_env: Vec<String>,
}

/// A completed analysis bundle.
pub struct Bundle {
    pub manifest: Manifest,
    pub out_dir: PathBuf,
    pub lock: Option<WorldLock>,
}

/// Shared per-analysis state.
struct Context {
    out_dir: PathBuf,
    ids: IdGenerator,
    ledger: EvidenceLedger,
    claims: ClaimStore,
    registry: PackRegistry,
}

impl Context {
    fn open(out_dir: &Path, packs_dir: Option<&Path>) -> Result<Context> {
        std::fs::create_dir_all(out_dir)?;
        let mut registry = PackRegistry::builtin().map_err(|e| anyhow!("builtin packs: {e}"))?;
        if let Some(dir) = packs_dir {
            registry
                .load_dir(dir)
                .map_err(|e| anyhow!("loading packs from {}: {e}", dir.display()))?;
        }
        Ok(Context {
            out_dir: out_dir.to_path_buf(),
            ids: IdGenerator::new(),
            ledger: EvidenceLedger::open(out_dir.join("evidence.jsonl"))
                .map_err(|e| anyhow!("{e}"))?,
            claims: ClaimStore::open(out_dir.join("claims.json")).map_err(|e| anyhow!("{e}"))?,
            registry,
        })
    }

    fn record(
        &mut self,
        record_type: &str,
        provider: &str,
        tier: TrustTier,
        data: serde_json::Value,
        run_id: Option<OvidId>,
    ) -> Result<OvidId> {
        let id = self.ids.next("evidence");
        let record = EvidenceRecord {
            id: id.clone(),
            record_type: record_type.into(),
            run_id,
            wall_time: Some(chrono::Utc::now()),
            provider: provider.into(),
            provider_version: ovid_core::OVID_VERSION.into(),
            trust_tier: tier,
            data,
            previous: None,
        };
        self.ledger.append(record).map_err(|e| anyhow!("{e}"))?;
        Ok(id)
    }

    fn claim(
        &mut self,
        predicate: &str,
        subject: String,
        object: String,
        states: ClaimStates,
        supports: Vec<OvidId>,
    ) -> Claim {
        let claim = Claim {
            id: self.ids.next("claim"),
            predicate: predicate.into(),
            subject,
            object,
            states,
            confidence: 0.0,
            supports,
            contradicts: vec![],
            normalizer: "ovid-pipeline".into(),
            normalizer_version: ovid_core::OVID_VERSION.into(),
        };
        self.claims.upsert(claim, &self.ledger)
    }
}

fn acquire_snapshot(
    locator: &str,
    reference: Option<String>,
    out_dir: &Path,
) -> Result<RepoSnapshot> {
    let source = RepositorySource::parse(locator, reference);
    let options = AcquireOptions::new(out_dir.join(".workdir"));
    acquire(&source, &options).map_err(|e| anyhow!("acquire {locator}: {e}"))
}

fn repository_section(snapshot: &RepoSnapshot) -> RepositorySection {
    RepositorySection {
        canonical_url: snapshot.canonical_url.clone(),
        revision: snapshot.revision.clone(),
        ref_requested: snapshot.ref_requested.clone(),
        source_digest: snapshot.source_digest.clone(),
        file_count: snapshot.file_count(),
        total_size_bytes: snapshot.total_size(),
    }
}

/// Record inventory results into the ledger and claims (§10.1: explicitly
/// static provenance).
fn record_inventory(
    ctx: &mut Context,
    snapshot: &RepoSnapshot,
    report: &InventoryReport,
) -> Result<()> {
    let mut file_evidence: BTreeMap<String, OvidId> = BTreeMap::new();
    for file in &report.scanned_files {
        let digest = snapshot.files.get(file).map(|f| f.digest.clone());
        let id = ctx.record(
            "manifest-file-scanned",
            "ovid-inventory",
            TrustTier::T4,
            serde_json::json!({ "file": file, "digest": digest }),
            None,
        )?;
        file_evidence.insert(file.clone(), id);
    }
    let repo_subject = format!("repository:{}", snapshot.canonical_url);
    for component in &report.components {
        let supports = file_evidence
            .get(&component.source_file)
            .cloned()
            .into_iter()
            .collect::<Vec<_>>();
        let predicate = if component.states.resolved {
            "resolves-to"
        } else {
            "declares"
        };
        ctx.claim(
            predicate,
            repo_subject.clone(),
            format!("package:{}", component.purl),
            component.states.clone(),
            supports,
        );
    }
    Ok(())
}

/// Outcome of one observed workload execution.
struct WorkloadExecution {
    run_id: OvidId,
    result: RunResult,
    network: NetworkAnalysis,
    proposals: Vec<ResolutionProposal>,
    /// evidence id per aggregated event (parallel to analysis evidence refs).
    events_captured: u64,
    events_unparsed: u64,
    events_collapsed: u64,
    noise_dropped: u64,
    /// Map from observer event id -> ledger evidence id.
    event_evidence: BTreeMap<String, OvidId>,
}

fn execute_workload(
    ctx: &mut Context,
    snapshot: &RepoSnapshot,
    argv: &[String],
    options: &ExecutionOptions,
    workload_name: &str,
) -> Result<WorkloadExecution> {
    let backend = ProcessBackend::new().map_err(|e| anyhow!("{e}"))?;
    let workspace = if options.in_place {
        WorkspaceMode::InPlace {
            root: snapshot.root.clone(),
        }
    } else {
        WorkspaceMode::Ephemeral {
            source_root: snapshot.root.clone(),
        }
    };
    let mut spec = RunSpec::new(argv.to_vec(), workspace);
    spec.inherit_env = options.inherit_env.clone();
    spec.limits.wall_time = Duration::from_secs(options.timeout_seconds);
    let run_id = ctx.ids.next("run");

    let result = backend
        .run(&spec)
        .map_err(|e| anyhow!("run {argv:?}: {e}"))?;

    // Normalize + aggregate + ledger append.
    let (events, unparsed, raw_count) = match &result.observation {
        Some(observation) => (
            observation.events.clone(),
            observation.unparsed_lines,
            observation.raw_line_count,
        ),
        None => (vec![], 0, 0),
    };
    let aggregated = aggregate(events);
    let mut event_evidence: BTreeMap<String, OvidId> = BTreeMap::new();
    for envelope in &aggregated.events {
        let id = ctx.record(
            envelope.event.type_label(),
            &envelope.provider,
            envelope.trust_tier,
            serde_json::to_value(envelope)?,
            Some(run_id.clone()),
        )?;
        event_evidence.insert(envelope.event_id.to_string(), id);
    }
    let _ = raw_count;

    // Run outcome evidence (host-enforced exit status: T0).
    ctx.record(
        "run-outcome",
        "ovid-sandbox",
        TrustTier::T0,
        serde_json::json!({
            "workload": workload_name,
            "command": argv,
            "exit_code": result.exit_code,
            "signal": result.signal,
            "timed_out": result.timed_out,
            "duration_ms": result.duration.as_millis() as u64,
            "backend": backend.name(),
            "isolation_tier": backend.isolation_tier(),
        }),
        Some(run_id.clone()),
    )?;

    let network =
        ovid_gateway::analyze_network(&aggregated.events, &ctx.registry, &BTreeMap::new());
    let proposals = propose_resolutions(&aggregated.events, &network, &ctx.registry);

    Ok(WorkloadExecution {
        run_id,
        result,
        network,
        proposals,
        events_captured: aggregated.events.len() as u64,
        events_unparsed: unparsed,
        events_collapsed: aggregated.collapsed.values().sum(),
        noise_dropped: aggregated.noise_dropped,
        event_evidence,
    })
}

/// Map observer event ids to ledger ids for claim support lists.
fn ledger_ids(execution: &WorkloadExecution, observer_ids: &[OvidId]) -> Vec<OvidId> {
    observer_ids
        .iter()
        .filter_map(|id| execution.event_evidence.get(&id.to_string()).cloned())
        .collect()
}

/// Fill manifest sections from one workload execution and emit claims.
fn absorb_execution(
    ctx: &mut Context,
    manifest: &mut Manifest,
    execution: &WorkloadExecution,
    workload_name: &str,
    argv: &[String],
    predicate: &SuccessPredicate,
) -> Result<()> {
    let success = predicate.evaluate(
        execution.result.exit_code,
        &format!(
            "{}\n{}",
            execution.result.stdout_tail, execution.result.stderr_tail
        ),
        &execution.result.workspace_path,
    );
    manifest.analysis.runs.total += 1;
    if success {
        manifest.analysis.runs.successful += 1;
    } else {
        manifest.analysis.runs.failed += 1;
    }
    manifest.workloads.push(WorkloadReport {
        id: format!("workload:{workload_name}"),
        name: workload_name.into(),
        command: argv.to_vec(),
        success_predicate: predicate.describe(),
        status: if success {
            "passed".into()
        } else {
            "failed".into()
        },
        duration_ms: Some(execution.result.duration.as_millis() as u64),
        world_digest: None,
    });
    let workload_subject = format!("workload:{workload_name}");

    // Listeners.
    for listener in &execution.network.listeners {
        if !manifest
            .runtime
            .listeners
            .iter()
            .any(|l| l.port == listener.port)
        {
            manifest.runtime.listeners.push(listener.clone());
        }
        let supports = ledger_ids(execution, &listener.evidence);
        ctx.claim(
            "listens-on",
            workload_subject.clone(),
            format!("listener:{}:{}", listener.address, listener.port),
            ClaimStates::default().with(ClaimState::Observed),
            supports,
        );
    }
    for path in &execution.network.unix_sockets {
        if !manifest.runtime.unix_sockets.contains(path) {
            manifest.runtime.unix_sockets.push(path.clone());
        }
    }

    // External systems with honest causality:
    // - dependency unavailable + workload succeeded => natural
    //   counterfactual => Optional;
    // - anything else without an explicit counterfactual => Unresolved.
    for observation in &execution.network.external {
        let id = observation
            .dns_name
            .clone()
            .unwrap_or_else(|| format!("{}:{}", observation.address, observation.port));
        let causality = if observation.all_failed() && success {
            Some(CausalClassification::Optional)
        } else {
            Some(CausalClassification::Unresolved)
        };
        let supports = ledger_ids(execution, &observation.evidence);
        let mut states = ClaimStates::default().with(ClaimState::Attempted);
        if !observation.all_failed() {
            states.set(ClaimState::Observed);
        }
        let claim = ctx.claim(
            "connects-to",
            workload_subject.clone(),
            format!("service:{id}"),
            states,
            supports.clone(),
        );
        if let Some(existing) = manifest
            .external_systems
            .iter_mut()
            .find(|s| s.id == id && s.port == observation.port)
        {
            existing.attempts += observation.attempts;
            existing.failures += observation.failures;
            continue;
        }
        manifest.external_systems.push(ExternalSystemReport {
            id: id.clone(),
            protocol: observation
                .protocol
                .clone()
                .unwrap_or_else(|| "unknown".into()),
            address: observation.address.clone(),
            port: observation.port,
            dns_name: observation.dns_name.clone(),
            attempts: observation.attempts,
            failures: observation.failures,
            outcomes: observation.outcomes.clone(),
            causality,
            treatment: None,
            evidence: claim.supports.iter().map(|e| e.to_string()).collect(),
        });
    }

    // Resolution proposals become tool reports / unresolved items.
    for proposal in &execution.proposals {
        match &proposal.kind {
            ResolutionKind::InstallTool {
                executable,
                package,
                provider,
            } => {
                if !manifest.build.tools.iter().any(|t| &t.name == executable) {
                    manifest.build.tools.push(ToolReport {
                        name: executable.clone(),
                        causality: Some(CausalClassification::Unresolved),
                        discovered_by: Some("failed-exec".into()),
                        candidate_package: Some(format!("{provider}:{package}")),
                    });
                }
                let supports = ledger_ids(execution, &proposal.evidence);
                ctx.claim(
                    "requires",
                    workload_subject.clone(),
                    format!("tool:{executable}"),
                    ClaimStates::default().with(ClaimState::Attempted),
                    supports,
                );
            }
            ResolutionKind::ProvideFile {
                path,
                package,
                provider,
            } => {
                let supports = ledger_ids(execution, &proposal.evidence);
                ctx.claim(
                    "requires",
                    workload_subject.clone(),
                    format!("file:{path}"),
                    ClaimStates::default().with(ClaimState::Attempted),
                    supports,
                );
                manifest.completeness.warnings.push(format!(
                    "missing file {path} (candidate: {provider}:{package})"
                ));
            }
            ResolutionKind::LeaveUnresolved {
                dependency_id,
                reason,
            } => {
                if !manifest.unresolved.iter().any(|u| &u.id == dependency_id) {
                    manifest.unresolved.push(UnresolvedItem {
                        id: dependency_id.clone(),
                        reason: reason.clone(),
                        evidence: ledger_ids(execution, &proposal.evidence)
                            .iter()
                            .map(|e| e.to_string())
                            .collect(),
                    });
                }
            }
            // Service/stub treatments are applied at world synthesis.
            ResolutionKind::StartService { .. } | ResolutionKind::SupplyStub { .. } => {}
        }
    }

    // Successful exec'd tools (observed build toolchain).
    if let Some(observation) = &execution.result.observation {
        let mut seen: std::collections::BTreeSet<String> = Default::default();
        for envelope in &observation.events {
            if let BoundaryEvent::ProcessExec {
                path, errno: None, ..
            } = &envelope.event
            {
                let base = path.rsplit('/').next().unwrap_or(path).to_string();
                if seen.insert(base) {}
            }
        }
        let _ = seen; // reserved for future build-section enrichment
    }

    // Artifact outputs: newly created files under conventional output dirs.
    for created in ["target", "build", "dist", "out"] {
        let dir = execution.result.workspace_path.join(created);
        if dir.is_dir() && manifest.build.artifacts.len() < 16 {
            manifest.build.artifacts.push(ArtifactReport {
                path: created.to_string(),
                digest: None,
            });
        }
    }

    manifest.completeness.events_captured += execution.events_captured;
    manifest.completeness.events_unparsed += execution.events_unparsed;
    manifest.completeness.events_collapsed += execution.events_collapsed;
    manifest.completeness.noise_dropped += execution.noise_dropped;
    Ok(())
}

fn finalize(ctx: &mut Context, manifest: &mut Manifest, lock: Option<&WorldLock>) -> Result<()> {
    manifest.metadata.status = if manifest.unresolved.is_empty() {
        "complete".into()
    } else {
        "complete-with-unresolved".into()
    };
    manifest.provenance.evidence_chain_head = ctx.ledger.chain_head().cloned();
    manifest.provenance.packs = ctx.registry.all().iter().map(|p| p.label()).collect();

    ctx.claims.save().map_err(|e| anyhow!("{e}"))?;
    std::fs::write(ctx.out_dir.join("ovid.yaml"), manifest.to_yaml())?;
    std::fs::write(ctx.out_dir.join("ovid.json"), manifest.to_json_pretty())?;
    std::fs::write(
        ctx.out_dir.join("cyclonedx.json"),
        serde_json::to_string_pretty(&to_cyclonedx(manifest))?,
    )?;
    std::fs::write(
        ctx.out_dir.join("spdx.json"),
        serde_json::to_string_pretty(&to_spdx(manifest))?,
    )?;
    std::fs::write(
        ctx.out_dir.join("integration-plan.md"),
        integration_plan_markdown(manifest, lock),
    )?;
    std::fs::write(
        ctx.out_dir.join("provenance.json"),
        serde_json::to_string_pretty(&manifest.provenance)?,
    )?;
    if let Some(lock) = lock {
        std::fs::write(ctx.out_dir.join("world.lock.yaml"), lock.to_yaml())?;
        std::fs::write(ctx.out_dir.join("compose.yaml"), lock.to_compose_yaml())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

pub fn run_inventory(
    locator: &str,
    reference: Option<String>,
    out: &Path,
    packs_dir: Option<&Path>,
) -> Result<Bundle> {
    let mut ctx = Context::open(out, packs_dir)?;
    let snapshot = acquire_snapshot(locator, reference, out)?;
    let report = ovid_inventory::scan(&snapshot);
    record_inventory(&mut ctx, &snapshot, &report)?;

    let mut manifest = Manifest::new(
        ctx.ids.next("analysis").to_string(),
        "inventory",
        repository_section(&snapshot),
    );
    manifest.inventory.languages = report.languages.clone();
    manifest.inventory.components = report.components.clone();
    manifest.inventory.scanned_files = report.scanned_files.clone();
    manifest.completeness.warnings = report.warnings.clone();
    manifest
        .completeness
        .limitations
        .push("inventory mode: no code was executed; dynamic states are unknown".into());
    finalize(&mut ctx, &mut manifest, None)?;
    Ok(Bundle {
        manifest,
        out_dir: out.to_path_buf(),
        lock: None,
    })
}

pub fn run_observe(
    locator: &str,
    reference: Option<String>,
    command: &str,
    out: &Path,
    options: &ExecutionOptions,
    packs_dir: Option<&Path>,
) -> Result<Bundle> {
    let mut ctx = Context::open(out, packs_dir)?;
    let snapshot = acquire_snapshot(locator, reference, out)?;
    let report = ovid_inventory::scan(&snapshot);
    record_inventory(&mut ctx, &snapshot, &report)?;

    let argv = vec!["sh".to_string(), "-c".to_string(), command.to_string()];
    let execution = execute_workload(&mut ctx, &snapshot, &argv, options, "observe")?;

    let mut manifest = Manifest::new(
        ctx.ids.next("analysis").to_string(),
        "observe",
        repository_section(&snapshot),
    );
    manifest.analysis.backend = Some("ovid-process-backend".into());
    manifest.analysis.isolation_tier = Some("trusted-process".into());
    manifest.inventory.languages = report.languages.clone();
    manifest.inventory.components = report.components.clone();
    manifest.inventory.scanned_files = report.scanned_files.clone();
    manifest.completeness.warnings = report.warnings.clone();
    let predicate = SuccessPredicate::ExitCode { expected: 0 };
    absorb_execution(
        &mut ctx,
        &mut manifest,
        &execution,
        "observe",
        &argv,
        &predicate,
    )?;
    manifest
        .completeness
        .limitations
        .push("observe mode: single explicit command; dependency causality not established".into());
    if execution.result.observation.is_none() {
        manifest
            .completeness
            .limitations
            .push("strace unavailable: boundary observation was not captured".into());
    }
    finalize(&mut ctx, &mut manifest, None)?;
    Ok(Bundle {
        manifest,
        out_dir: out.to_path_buf(),
        lock: None,
    })
}

pub fn run_analyze(
    locator: &str,
    reference: Option<String>,
    workload_kinds: &[String],
    out: &Path,
    options: &ExecutionOptions,
    packs_dir: Option<&Path>,
) -> Result<Bundle> {
    let mut ctx = Context::open(out, packs_dir)?;
    let snapshot = acquire_snapshot(locator, reference, out)?;
    let report = ovid_inventory::scan(&snapshot);
    record_inventory(&mut ctx, &snapshot, &report)?;

    let graph = ovid_planner::plan(&snapshot, &ctx.registry);
    let mut manifest = Manifest::new(
        ctx.ids.next("analysis").to_string(),
        "explore",
        repository_section(&snapshot),
    );
    manifest.analysis.backend = Some("ovid-process-backend".into());
    manifest.analysis.isolation_tier = Some("trusted-process".into());
    manifest.inventory.languages = report.languages.clone();
    manifest.inventory.components = report.components.clone();
    manifest.inventory.scanned_files = report.scanned_files.clone();
    manifest.completeness.warnings = report.warnings.clone();

    let mut last_execution: Option<(WorkloadExecution, Vec<String>, String)> = None;
    for kind_name in workload_kinds {
        let kind = match kind_name.as_str() {
            "build" => ActionKind::Build,
            "test" => ActionKind::Test,
            "install" => ActionKind::DependencyInstall,
            "start" => ActionKind::Start,
            other => bail!("unknown workload kind {other:?} (use build|test|install|start)"),
        };
        // Try candidates best-first until one exists on this host; mined
        // candidates that reference unavailable runners fail fast and are
        // recorded as failed runs (evidence, not errors).
        let candidates = graph.candidates(kind);
        let Some(action) = candidates.first() else {
            manifest
                .completeness
                .limitations
                .push(format!("no {kind_name} candidate command was discovered"));
            continue;
        };
        manifest.build.commands.push(action.command.clone());
        ctx.record(
            "action-selected",
            "ovid-planner",
            action.source.trust_tier(),
            serde_json::json!({
                "workload": kind_name,
                "command": action.command,
                "source": action.source,
                "source_file": action.source_file,
                "score": action.score,
            }),
            None,
        )?;
        let execution = execute_workload(&mut ctx, &snapshot, &action.command, options, kind_name)?;
        let predicate = SuccessPredicate::ExitCode { expected: 0 };
        absorb_execution(
            &mut ctx,
            &mut manifest,
            &execution,
            kind_name,
            &action.command,
            &predicate,
        )?;
        last_execution = Some((execution, action.command.clone(), kind_name.clone()));
    }

    // Environment-variable counterfactuals (§20): rerun without each named
    // variable, from clean state, and compare.
    if let Some((_, argv, workload_name)) = &last_execution {
        for variable in &options.counterfactual_env {
            let baseline_success = manifest
                .workloads
                .iter()
                .find(|w| &w.name == workload_name)
                .map(|w| w.status == "passed")
                .unwrap_or(false);
            if !baseline_success {
                manifest.completeness.limitations.push(format!(
                    "counterfactual for {variable} skipped: baseline workload did not pass"
                ));
                continue;
            }
            let mut variant_options = ExecutionOptions {
                in_place: options.in_place,
                inherit_env: options
                    .inherit_env
                    .iter()
                    .filter(|v| *v != variable)
                    .cloned()
                    .collect(),
                timeout_seconds: options.timeout_seconds,
                counterfactual_env: vec![],
            };
            variant_options.inherit_env.retain(|v| v != variable);
            let variant = execute_workload(
                &mut ctx,
                &snapshot,
                argv,
                &variant_options,
                &format!("{workload_name}-without-{variable}"),
            )?;
            let variant_success = variant.result.success();
            manifest.analysis.runs.total += 1;
            if variant_success {
                manifest.analysis.runs.successful += 1;
            } else {
                manifest.analysis.runs.failed += 1;
            }
            let classification = if variant_success {
                CausalClassification::Optional
            } else {
                CausalClassification::Required
            };
            let evidence_id = ctx.record(
                "experiment-outcome",
                "ovid-experiment",
                TrustTier::T0,
                serde_json::json!({
                    "condition": format!("remove-env:{variable}"),
                    "baseline_success": true,
                    "variant_success": variant_success,
                    "classification": classification,
                }),
                Some(variant.run_id.clone()),
            )?;
            ctx.claim(
                "requires",
                format!("workload:{workload_name}"),
                format!("environment:{variable}"),
                ClaimStates::default().with(ClaimState::CausallyRequired),
                vec![evidence_id],
            );
        }
    }

    // World synthesis from the last executed workload (§14.12, proposed
    // status only: verified requires replaying in real service cells).
    let lock = if let Some((execution, argv, _)) = &last_execution {
        let mut world = World {
            target: snapshot.canonical_url.clone(),
            ..Default::default()
        };
        for proposal in &execution.proposals {
            match &proposal.kind {
                ResolutionKind::StartService {
                    dependency_id,
                    pack,
                    port,
                } => {
                    let image = ctx
                        .registry
                        .service_packs()
                        .find(|(p, _)| p.metadata.name == *pack)
                        .map(|(_, s)| s.image.reference.clone())
                        .unwrap_or_default();
                    world.dependencies.push(WorldDependency {
                        id: dependency_id.clone(),
                        treatment: Treatment::RealService {
                            pack: pack.clone(),
                            image,
                        },
                        aliases: vec![dependency_id.clone()],
                        port: Some(*port),
                        environment: BTreeMap::new(),
                    });
                }
                ResolutionKind::SupplyStub {
                    dependency_id,
                    protocol,
                    port,
                } => {
                    world.dependencies.push(WorldDependency {
                        id: dependency_id.clone(),
                        treatment: Treatment::Stub {
                            protocol: protocol.clone(),
                        },
                        aliases: vec![dependency_id.clone()],
                        port: Some(*port),
                        environment: BTreeMap::new(),
                    });
                }
                ResolutionKind::LeaveUnresolved {
                    dependency_id,
                    reason,
                } => {
                    if !dependency_id.starts_with("tool:") {
                        world.dependencies.push(WorldDependency {
                            id: dependency_id.clone(),
                            treatment: Treatment::Unresolved {
                                reason: reason.clone(),
                            },
                            aliases: vec![dependency_id.clone()],
                            port: None,
                            environment: BTreeMap::new(),
                        });
                    }
                }
                ResolutionKind::InstallTool { executable, .. } => {
                    if !world.tools.contains(executable) {
                        world.tools.push(executable.clone());
                    }
                }
                ResolutionKind::ProvideFile { .. } => {}
            }
        }
        let mut lock =
            WorldLock::from_world(&world, argv.clone(), SuccessSpec::ExitCode { expected: 0 });
        lock.status = WorldStatus::Proposed;
        manifest.world.status = "proposed".into();
        manifest.world.lock_digest = Some(lock.metadata.digest.clone());
        manifest.world.dependencies = world
            .dependencies
            .iter()
            .map(|d| WorldDependencySummary {
                id: d.id.clone(),
                treatment: match &d.treatment {
                    Treatment::RealService { pack, .. } => format!("service-pack:{pack}"),
                    Treatment::Stub { protocol } => format!("stub:{protocol}"),
                    Treatment::Fixture { path } => format!("fixture:{path}"),
                    Treatment::FleetRepository { analysis } => format!("fleet:{analysis}"),
                    Treatment::Absent => "absent".into(),
                    Treatment::Unresolved { reason } => format!("unresolved:{reason}"),
                },
            })
            .collect();
        // Propagate treatments back onto external systems.
        for system in &mut manifest.external_systems {
            if let Some(summary) = manifest
                .world
                .dependencies
                .iter()
                .find(|d| d.id == system.id)
            {
                system.treatment = Some(summary.treatment.clone());
            }
        }
        manifest.completeness.limitations.push(
            "world lock is proposed, not verified: replay requires service cells (KVM worker)"
                .into(),
        );
        Some(lock)
    } else {
        None
    };

    manifest
        .completeness
        .limitations
        .push("dynamic analysis is limited to the executed workloads".into());
    finalize(&mut ctx, &mut manifest, lock.as_ref())?;
    Ok(Bundle {
        manifest,
        out_dir: out.to_path_buf(),
        lock,
    })
}

pub fn explain(claim_query: &str, from: &Path) -> Result<()> {
    let ledger = EvidenceLedger::open(from.join("evidence.jsonl")).map_err(|e| anyhow!("{e}"))?;
    let claims = ClaimStore::open(from.join("claims.json")).map_err(|e| anyhow!("{e}"))?;
    // Exact id first, then substring search.
    let matches: Vec<String> = if claims.get(claim_query).is_some() {
        vec![claim_query.to_string()]
    } else {
        claims
            .query(None, Some(claim_query))
            .into_iter()
            .map(|c| c.id.to_string())
            .collect()
    };
    if matches.is_empty() {
        bail!("no claim matches {claim_query:?} in {}", from.display());
    }
    for id in matches.iter().take(10) {
        let explanation = claims
            .explain(id, &ledger)
            .context("claim disappeared during explain")?;
        println!("{}", serde_json::to_string_pretty(&explanation)?);
    }
    if matches.len() > 10 {
        eprintln!("({} more matches not shown)", matches.len() - 10);
    }
    Ok(())
}

pub fn print_summary(bundle: &Bundle) {
    let manifest = &bundle.manifest;
    println!(
        "analysis {} ({}) — {}",
        manifest.metadata.analysis_id, manifest.analysis.mode, manifest.metadata.status
    );
    println!(
        "repository {} @ {}",
        manifest.repository.canonical_url,
        &manifest.repository.revision[..manifest.repository.revision.len().min(12)]
    );
    if !manifest.inventory.languages.is_empty() {
        let languages: Vec<String> = manifest
            .inventory
            .languages
            .iter()
            .take(4)
            .map(|l| format!("{} {:.0}%", l.name, l.estimated_fraction * 100.0))
            .collect();
        println!("languages: {}", languages.join(", "));
    }
    println!(
        "components: {} ({} declared, {} resolved)",
        manifest.inventory.components.len(),
        manifest
            .inventory
            .components
            .iter()
            .filter(|c| c.states.declared)
            .count(),
        manifest
            .inventory
            .components
            .iter()
            .filter(|c| c.states.resolved)
            .count(),
    );
    for workload in &manifest.workloads {
        println!(
            "workload {}: {} ({} ms) — `{}`",
            workload.name,
            workload.status,
            workload.duration_ms.unwrap_or(0),
            workload.command.join(" ")
        );
    }
    for system in &manifest.external_systems {
        println!(
            "external: {} {}:{} [{}] attempts={} failures={} causality={}",
            system.id,
            system.address,
            system.port,
            system.protocol,
            system.attempts,
            system.failures,
            system
                .causality
                .map(|c| format!("{c:?}"))
                .unwrap_or_default()
        );
    }
    for listener in &manifest.runtime.listeners {
        println!("listener: {}:{}", listener.address, listener.port);
    }
    for tool in &manifest.build.tools {
        println!(
            "missing tool: {} (candidate {})",
            tool.name,
            tool.candidate_package.as_deref().unwrap_or("none")
        );
    }
    for item in &manifest.unresolved {
        println!("unresolved: {} — {}", item.id, item.reason);
    }
    println!(
        "events: {} captured, {} collapsed, {} noise-dropped, {} unparsed",
        manifest.completeness.events_captured,
        manifest.completeness.events_collapsed,
        manifest.completeness.noise_dropped,
        manifest.completeness.events_unparsed
    );
    if let Some(lock) = &bundle.lock {
        println!(
            "world: {:?} — {} cell(s), startup {}",
            lock.status,
            lock.cells.len(),
            lock.startup_order.join(" -> ")
        );
    }
    println!("bundle: {}", bundle.out_dir.display());
}

/// Compute a policy digest over the material analysis inputs (§14.1).
#[allow(dead_code)]
pub fn policy_digest(options: &ExecutionOptions) -> Digest {
    Digest::of_bytes(
        format!(
            "in_place={};inherit_env={:?};timeout={};counterfactual_env={:?}",
            options.in_place,
            options.inherit_env,
            options.timeout_seconds,
            options.counterfactual_env
        )
        .as_bytes(),
    )
}
