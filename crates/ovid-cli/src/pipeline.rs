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
use ovid_experiment::{
    classify_network_counterfactual, externally_controlled, propose_resolutions,
    NetworkCounterfactual, ResolutionKind, ResolutionProposal, SuccessPredicate,
};
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
use ovid_sandbox::{
    network_isolation_available, ExecutionBackend, NetworkMode, ProcessBackend, RunResult, RunSpec,
    WorkspaceMode,
};
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

/// Nameservers configured in `/etc/resolv.conf` (the process backend
/// shares the host resolver configuration).
fn configured_resolvers() -> Vec<String> {
    std::fs::read_to_string("/etc/resolv.conf")
        .map(|text| {
            text.lines()
                .filter_map(|line| line.trim().strip_prefix("nameserver"))
                .map(|server| server.trim().to_string())
                .collect()
        })
        .unwrap_or_default()
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

/// Extract a package identity from a file path under a known package
/// installation layout (spec §14.7's package-load rule). Best-effort:
/// import names and distribution names can differ (e.g. PyYAML installs
/// `yaml/`); `.dist-info` opens carry the true distribution name and are
/// matched too. Returns lowercase, `_`->`-` normalized names.
fn package_from_install_path(path: &str) -> Option<String> {
    let normalize = |name: &str| name.to_lowercase().replace('_', "-");
    // Python: …/site-packages/<pkg>/… , <pkg>.py , <dist>-<ver>.dist-info
    if let Some(rest) = path
        .split("/site-packages/")
        .nth(1)
        .or_else(|| path.split("/dist-packages/").nth(1))
    {
        let first = rest.split('/').next()?;
        if let Some(dist_info) = first.strip_suffix(".dist-info") {
            // `<name>-<version>.dist-info`
            let name = dist_info
                .rsplit_once('-')
                .map(|(n, _)| n)
                .unwrap_or(dist_info);
            return Some(normalize(name));
        }
        let module = first.strip_suffix(".py").unwrap_or(first);
        if module.is_empty() || module.starts_with('_') || module == "pkg_resources" {
            return None;
        }
        return Some(normalize(module));
    }
    // Node: …/node_modules/<name>/… or …/node_modules/@scope/<name>/…
    if let Some(rest) = path.split("/node_modules/").nth(1) {
        let mut parts = rest.split('/');
        let first = parts.next()?;
        if first.starts_with('@') {
            let second = parts.next()?;
            return Some(format!("{first}/{second}").to_lowercase());
        }
        return Some(first.to_lowercase());
    }
    // Ruby: …/gems/<name>-<version>/…
    if let Some(rest) = path.split("/gems/").nth(1) {
        let dir = rest.split('/').next()?;
        if let Some((name, version)) = dir.rsplit_once('-') {
            if version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return Some(normalize(name));
            }
        }
    }
    None
}

/// Absorb Compose-declared services (FR-011 container metadata) into the
/// manifest: merged onto an observed system when the identity matches,
/// appended as a declared-only record otherwise. Declaration never sets
/// dynamic states (§6.3).
fn absorb_declared_services(
    ctx: &mut Context,
    manifest: &mut Manifest,
    snapshot: &RepoSnapshot,
) -> Result<()> {
    let services = ovid_inventory::scan_compose(snapshot);
    let repo_subject = format!("repository:{}", snapshot.canonical_url);
    for service in services {
        let evidence_id = ctx.record(
            "compose-service-declared",
            "ovid-inventory",
            TrustTier::T4,
            serde_json::to_value(&service)?,
            None,
        )?;
        ctx.claim(
            "declares",
            repo_subject.clone(),
            format!("service:{}", service.name),
            ClaimStates::default().with(ClaimState::Declared),
            vec![evidence_id.clone()],
        );
        // Merge onto an observed system whose DNS name or id matches the
        // compose service name (the docker-network alias case). Anything
        // weaker (port-only) would be guessing (§6.6).
        if let Some(existing) = manifest
            .external_systems
            .iter_mut()
            .find(|s| s.id == service.name || s.dns_name.as_deref() == Some(service.name.as_str()))
        {
            existing.declared = true;
            existing.evidence.push(evidence_id.to_string());
            continue;
        }
        let port = service.ports.first().copied().unwrap_or(0);
        let protocol = ctx
            .registry
            .classify_protocol(port, None)
            .map(|(_, p)| p.system.clone())
            .unwrap_or_else(|| "unknown".into());
        manifest.external_systems.push(ExternalSystemReport {
            id: service.name.clone(),
            protocol,
            address: service.name.clone(),
            port,
            dns_name: Some(service.name.clone()),
            endpoints: Vec::new(),
            identity: "declared".into(),
            declared: true,
            attempts: 0,
            failures: 0,
            outcomes: Vec::new(),
            causality: None,
            treatment: service
                .image
                .clone()
                .map(|image| format!("declared-image:{image}")),
            url_path: None,
            env_var: None,
            credential_env: Vec::new(),
            declared_sources: vec![service.source_file.clone()],
            evidence: vec![evidence_id.to_string()],
        });
    }
    Ok(())
}

/// Map a URL scheme onto the canonical protocol name used by protocol
/// packs, so scheme knowledge stays aligned with the pack registry
/// (ADR-005: the packs remain the authority on protocols).
fn scheme_protocol_name(scheme: &str) -> Option<&'static str> {
    Some(match scheme {
        "http" | "ws" => "http",
        "https" | "wss" => "https",
        "postgres" | "postgresql" => "postgresql",
        "redis" | "rediss" => "redis",
        "mysql" => "mysql",
        "mongodb" | "mongodb+srv" => "mongodb",
        "amqp" | "amqps" => "amqp",
        "kafka" => "kafka",
        "smtp" | "smtps" => "smtp",
        _ => return None,
    })
}

/// Absorb declared endpoints — literal config URLs and env-var-bound
/// indirections — into the manifest (§6.6, §25.3). A declaration merges
/// onto an observed system when the host matches; otherwise it appends a
/// declared-only record. An env-parameterized endpoint (host supplied at
/// runtime by an environment variable whose value Ovid cannot see) is
/// reported with everything the text *does* support — scheme, path,
/// default, credential variable names — and listed as unresolved rather
/// than guessed. Declaration never sets dynamic states (§6.3).
fn absorb_declared_endpoints(
    ctx: &mut Context,
    manifest: &mut Manifest,
    snapshot: &RepoSnapshot,
) -> Result<()> {
    let endpoints = ovid_inventory::scan_endpoints(snapshot);
    let repo_subject = format!("repository:{}", snapshot.canonical_url);
    for endpoint in endpoints {
        let tier = match endpoint.origin {
            ovid_inventory::EndpointOrigin::Config => TrustTier::T4,
            ovid_inventory::EndpointOrigin::SourceMined => TrustTier::T5,
        };
        let evidence_id = ctx.record(
            "endpoint-declared",
            "ovid-inventory",
            tier,
            serde_json::to_value(&endpoint)?,
            None,
        )?;
        let object = match (&endpoint.host, &endpoint.env_var) {
            (Some(host), _) => format!("service:{host}"),
            (None, Some(var)) => format!("service:env:{var}"),
            (None, None) => continue,
        };
        ctx.claim(
            "declares",
            repo_subject.clone(),
            object,
            ClaimStates::default().with(ClaimState::Declared),
            vec![evidence_id.clone()],
        );
        // Port: explicit beats scheme default; the default comes from the
        // protocol pack for the scheme, not hardcoded knowledge.
        let protocol_name = endpoint.scheme.as_deref().and_then(scheme_protocol_name);
        let default_port = protocol_name.and_then(|name| {
            ctx.registry
                .protocol_packs()
                .find(|(_, p)| p.system == name)
                .and_then(|(_, p)| p.matcher.ports.first().copied())
        });
        let port = endpoint.port.or(default_port).unwrap_or(0);
        // Merge onto an observed or compose-declared system with the same
        // host identity; anything weaker would be guessing (§6.6).
        if let Some(host) = &endpoint.host {
            if let Some(existing) = manifest
                .external_systems
                .iter_mut()
                .find(|s| s.dns_name.as_deref() == Some(host.as_str()) || s.address == *host)
            {
                existing.declared = true;
                if existing.url_path.is_none() {
                    existing.url_path = endpoint.path.clone();
                }
                for cred in &endpoint.credential_env {
                    if !existing.credential_env.contains(cred) {
                        existing.credential_env.push(cred.clone());
                    }
                }
                for source in &endpoint.sources {
                    if !existing.declared_sources.contains(source) {
                        existing.declared_sources.push(source.clone());
                    }
                }
                existing.evidence.push(evidence_id.to_string());
                continue;
            }
        }
        let protocol = protocol_name
            .map(str::to_string)
            .or_else(|| endpoint.scheme.clone())
            .or_else(|| {
                ctx.registry
                    .classify_protocol(port, None)
                    .map(|(_, p)| p.system.clone())
            })
            .unwrap_or_else(|| "unknown".into());
        // A host written entirely without lowercase letters
        // (`REPLACE-WITH-RIG0-ENDPOINT`) is a template placeholder by
        // config convention, not a resolvable name: the value is supplied
        // at deployment time, exactly like an env var. Report the
        // connectivity, flag the identity, never assert the name (§6.6).
        let template_placeholder = endpoint.host.as_deref().is_some_and(|host| {
            host.chars().any(|c| c.is_ascii_alphabetic())
                && !host.chars().any(|c| c.is_ascii_lowercase())
        });
        let (id, address, identity) = match (&endpoint.host, &endpoint.env_var) {
            (Some(host), _) if template_placeholder => (
                format!("{host}:{port}"),
                host.clone(),
                "template-placeholder".to_string(),
            ),
            (Some(host), _) => (
                format!("{host}:{port}"),
                host.clone(),
                "declared".to_string(),
            ),
            (None, Some(var)) => (
                format!("env:{var}"),
                format!("${{{var}}}"),
                "env-parameterized".to_string(),
            ),
            (None, None) => unreachable!("filtered above"),
        };
        let unresolved_reason = match (&endpoint.host, &endpoint.env_var) {
            (Some(host), _) if template_placeholder => Some(format!(
                "declared endpoint host is a template placeholder ({host}); \
                 the real value is supplied at deployment time"
            )),
            (None, Some(var)) => {
                let mut detail = format!("endpoint host bound at runtime from env var {var}");
                if let Some(scheme) = &endpoint.scheme {
                    detail.push_str(&format!(" (scheme {scheme}"));
                    if let Some(path) = &endpoint.path {
                        detail.push_str(&format!(", path {path}"));
                    }
                    detail.push(')');
                }
                Some(detail)
            }
            _ => None,
        };
        if let Some(reason) = unresolved_reason {
            manifest.unresolved.push(UnresolvedItem {
                id: id.clone(),
                reason,
                evidence: vec![evidence_id.to_string()],
            });
        }
        manifest.external_systems.push(ExternalSystemReport {
            id,
            protocol,
            address,
            port,
            dns_name: if template_placeholder {
                None // a placeholder token is not a DNS name
            } else {
                endpoint.host.clone()
            },
            endpoints: Vec::new(),
            identity,
            declared: true,
            attempts: 0,
            failures: 0,
            outcomes: Vec::new(),
            causality: None,
            treatment: None,
            url_path: endpoint.path.clone(),
            env_var: endpoint.env_var.clone(),
            credential_env: endpoint.credential_env.clone(),
            declared_sources: endpoint.sources.clone(),
            evidence: vec![evidence_id.to_string()],
        });
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
    network: NetworkMode,
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
    spec.network = network;
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
            endpoints: observation.endpoints.clone(),
            identity: if observation.dns_name.is_some() {
                "dns-name".into()
            } else {
                "ip-only".into()
            },
            declared: false,
            attempts: observation.attempts,
            failures: observation.failures,
            outcomes: observation.outcomes.clone(),
            causality,
            treatment: None,
            url_path: None,
            env_var: None,
            credential_env: Vec::new(),
            declared_sources: Vec::new(),
            evidence: claim.supports.iter().map(|e| e.to_string()).collect(),
        });
    }

    // Identity honesty: destinations without a DNS observation are
    // explicitly ip-only, and resolver bypass is surfaced (queries sent to
    // servers not configured in /etc/resolv.conf).
    let ip_only = execution
        .network
        .external
        .iter()
        .filter(|o| o.dns_name.is_none())
        .count();
    if ip_only > 0 {
        let note = format!(
            "{ip_only} external endpoint(s) identified by IP only (no DNS observation \
             covered their resolution)"
        );
        if !manifest.completeness.limitations.contains(&note) {
            manifest.completeness.limitations.push(note);
        }
    }
    let configured = configured_resolvers();
    for server in &execution.network.dns_servers {
        if !configured.contains(server) && !server.starts_with("127.") {
            let warning = format!(
                "resolver bypass: DNS queries sent directly to {server}, which is not in \
                 /etc/resolv.conf"
            );
            if !manifest.completeness.warnings.contains(&warning) {
                manifest.completeness.warnings.push(warning);
            }
        }
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

    // Package-load normalization (spec §14.7): a successful open of a
    // file under a known package installation path is package-load
    // evidence. Promotes `loaded` on matching inventory components and
    // records a `loads` claim — never `exercised` (§6.3: execution is a
    // stronger statement than loading).
    if let Some(observation) = &execution.result.observation {
        let mut loaded: BTreeMap<String, OvidId> = BTreeMap::new(); // package name -> first evidence
        for envelope in &observation.events {
            let path = match &envelope.event {
                BoundaryEvent::FileOpened {
                    path,
                    errno: None,
                    write: false,
                } => path,
                BoundaryEvent::SharedObjectMapped { path } => path,
                _ => continue,
            };
            if let Some(package) = package_from_install_path(path) {
                if let Some(ledger_id) =
                    execution.event_evidence.get(&envelope.event_id.to_string())
                {
                    loaded.entry(package).or_insert_with(|| ledger_id.clone());
                }
            }
        }
        for component in &mut manifest.inventory.components {
            if component.states.loaded {
                continue;
            }
            let key = component.name.to_lowercase().replace('_', "-");
            if let Some(evidence_id) = loaded.get(&key) {
                component.states.loaded = true;
                ctx.claim(
                    "loads",
                    workload_subject.clone(),
                    format!("package:{}", component.purl),
                    ClaimStates::default().with(ClaimState::Loaded),
                    vec![evidence_id.clone()],
                );
            }
        }
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
    // The read-first summary is a projection of the finished sections, so
    // it is rebuilt last and can never disagree with the file.
    manifest.summary = manifest.build_summary();

    ctx.claims.save().map_err(|e| anyhow!("{e}"))?;
    std::fs::write(ctx.out_dir.join("ovid.yaml"), manifest.to_yaml_annotated())?;
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
    // provenance.json was a byte-for-byte copy of the manifest's
    // provenance section; the manifest is the single home for it now.
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
    absorb_declared_services(&mut ctx, &mut manifest, &snapshot)?;
    absorb_declared_endpoints(&mut ctx, &mut manifest, &snapshot)?;
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
    let execution = execute_workload(
        &mut ctx,
        &snapshot,
        &argv,
        options,
        "observe",
        NetworkMode::Inherit,
    )?;

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
    absorb_declared_services(&mut ctx, &mut manifest, &snapshot)?;
    absorb_declared_endpoints(&mut ctx, &mut manifest, &snapshot)?;
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
        let execution = execute_workload(
            &mut ctx,
            &snapshot,
            &action.command,
            options,
            kind_name,
            NetworkMode::Inherit,
        )?;
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
                NetworkMode::Inherit,
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
    let lock = last_execution.as_ref().map(|(execution, argv, _)| {
        synthesize_world(
            &ctx,
            &mut manifest,
            &execution.proposals,
            &snapshot.canonical_url,
            argv,
        )
    });

    manifest
        .completeness
        .limitations
        .push("dynamic analysis is limited to the executed workloads".into());
    absorb_declared_services(&mut ctx, &mut manifest, &snapshot)?;
    absorb_declared_endpoints(&mut ctx, &mut manifest, &snapshot)?;
    finalize(&mut ctx, &mut manifest, lock.as_ref())?;
    Ok(Bundle {
        manifest,
        out_dir: out.to_path_buf(),
        lock,
    })
}

/// Build a proposed world lock from resolution proposals and record it in
/// the manifest (shared by analyze and tomography modes).
fn synthesize_world(
    ctx: &Context,
    manifest: &mut Manifest,
    proposals: &[ResolutionProposal],
    target: &str,
    argv: &[String],
) -> WorldLock {
    let mut world = World {
        target: target.to_string(),
        ..Default::default()
    };
    for proposal in proposals {
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
        WorldLock::from_world(&world, argv.to_vec(), SuccessSpec::ExitCode { expected: 0 });
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
    let note = "world lock is proposed, not verified: replay requires service cells (KVM worker)";
    if !manifest.completeness.limitations.iter().any(|l| l == note) {
        manifest.completeness.limitations.push(note.into());
    }
    lock
}

/// Tomography mode: the comprehensive single-command pipeline.
///
/// acquire -> inventory (+ Compose declarations) -> plan -> **provision**
/// (best discovered install candidate, online, in one persistent
/// workspace — the dependency-installed layer of §16.5) -> for each
/// requested workload kind, up to `max_candidates` discovered commands,
/// each run **twice**: network-isolated, then with network — and external
/// dependencies classified from the counterfactual pair (§20). Every
/// discovered-but-unexecuted candidate is disclosed in completeness so
/// gated tiers (live/db test targets) never silently vanish.
pub struct TomographyOptions {
    pub in_place: bool,
    pub extra_inherit_env: Vec<String>,
    pub timeout_seconds: u64,
    /// Run up to this many discovered candidates per workload kind.
    pub max_candidates: usize,
    /// Skip the default PATH/HOME/proxy inheritance (fully scrubbed env).
    pub no_default_env: bool,
}

/// Environment the online legs get by default: toolchain discovery plus
/// proxy/CA plumbing (the online leg exists to have network access).
const ONLINE_DEFAULT_ENV: &[&str] = &[
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
    // not the shell proxy vars — without these, Maven/Gradle cannot reach
    // repositories in proxied environments.
    "JAVA_TOOL_OPTIONS",
    "MAVEN_OPTS",
    "GRADLE_OPTS",
];
/// Offline legs only need toolchain discovery; the namespace blocks egress.
const OFFLINE_DEFAULT_ENV: &[&str] = &["PATH", "HOME"];

pub fn run_tomography(
    locator: &str,
    reference: Option<String>,
    workload_kinds: &[String],
    out: &Path,
    options: &TomographyOptions,
    packs_dir: Option<&Path>,
) -> Result<Bundle> {
    let mut ctx = Context::open(out, packs_dir)?;
    let snapshot = acquire_snapshot(locator, reference, out)?;
    let report = ovid_inventory::scan(&snapshot);
    record_inventory(&mut ctx, &snapshot, &report)?;
    let graph = ovid_planner::plan(&snapshot, &ctx.registry);

    let mut manifest = Manifest::new(
        ctx.ids.next("analysis").to_string(),
        "tomography",
        repository_section(&snapshot),
    );
    manifest.analysis.backend = Some("ovid-process-backend".into());
    manifest.analysis.isolation_tier = Some("trusted-process".into());
    manifest.inventory.languages = report.languages.clone();
    manifest.inventory.components = report.components.clone();
    manifest.inventory.scanned_files = report.scanned_files.clone();
    manifest.completeness.warnings = report.warnings.clone();

    let isolation = network_isolation_available();
    if !isolation {
        manifest.completeness.limitations.push(
            "network isolation unavailable (no unprivileged user namespaces): offline runs \
             only strip proxy variables, so direct egress may still succeed"
                .into(),
        );
    }

    let mut online_env: Vec<String> = if options.no_default_env {
        vec![]
    } else {
        ONLINE_DEFAULT_ENV.iter().map(|v| v.to_string()).collect()
    };
    let mut offline_env: Vec<String> = if options.no_default_env {
        vec![]
    } else {
        OFFLINE_DEFAULT_ENV.iter().map(|v| v.to_string()).collect()
    };
    for var in &options.extra_inherit_env {
        if !online_env.contains(var) {
            online_env.push(var.clone());
        }
        if !offline_env.contains(var) {
            offline_env.push(var.clone());
        }
    }
    // Without namespace isolation, best-effort offline strips proxy vars.
    if !isolation {
        let proxy_vars = ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"];
        offline_env.retain(|v| !proxy_vars.contains(&v.as_str()));
    }

    // One persistent workspace for the whole pipeline: provisioning
    // effects (installed dependencies) must be visible to the workload
    // runs (§16.5's dependency-installed layer).
    let workspace_root = if options.in_place {
        snapshot.root.clone()
    } else {
        let workspace = out.join(".workspace");
        if !workspace.exists() {
            ovid_sandbox::materialize_workspace(&snapshot.root, &workspace)
                .map_err(|e| anyhow!("materialize workspace: {e}"))?;
        }
        workspace
    };
    let make_options = |inherit: &[String]| ExecutionOptions {
        in_place: true, // all runs share the provisioned workspace
        inherit_env: inherit.to_vec(),
        timeout_seconds: options.timeout_seconds,
        counterfactual_env: vec![],
    };
    let online_options = make_options(&online_env);
    let offline_options = make_options(&offline_env);
    // A snapshot pointing at the persistent workspace for execution.
    let mut exec_snapshot = snapshot.clone();
    exec_snapshot.root = workspace_root;

    // ------------------------------------------------------------------
    // Provisioning: best discovered install candidate, online, once.
    // Observed like any workload (its downloads are evidence), but not a
    // counterfactual pair — it exists to create the world, not test it.
    // ------------------------------------------------------------------
    let predicate = SuccessPredicate::ExitCode { expected: 0 };
    let mut executed_commands: Vec<Vec<String>> = Vec::new();
    if let Some(install) = graph.candidates(ActionKind::DependencyInstall).first() {
        manifest.build.commands.push(install.command.clone());
        executed_commands.push(install.command.clone());
        ctx.record(
            "action-selected",
            "ovid-planner",
            install.source.trust_tier(),
            serde_json::json!({
                "workload": "provision",
                "command": install.command,
                "source": install.source,
                "source_file": install.source_file,
                "score": install.score,
            }),
            None,
        )?;
        let provisioning = execute_workload(
            &mut ctx,
            &exec_snapshot,
            &install.command,
            &online_options,
            "provision",
            NetworkMode::Inherit,
        )?;
        absorb_execution(
            &mut ctx,
            &mut manifest,
            &provisioning,
            "provision",
            &install.command,
            &predicate,
        )?;
        manifest.completeness.limitations.push(
            "provisioning (install) ran online only: it prepares the world and is not \
             part of the counterfactual comparison"
                .into(),
        );
    }

    // ------------------------------------------------------------------
    // Workload pairs: up to max_candidates per requested kind.
    // ------------------------------------------------------------------
    let mut last_online: Option<(WorkloadExecution, Vec<String>)> = None;
    for kind_name in workload_kinds {
        let kind = match kind_name.as_str() {
            "build" => ActionKind::Build,
            "test" => ActionKind::Test,
            "install" => ActionKind::DependencyInstall,
            "start" => ActionKind::Start,
            other => bail!("unknown workload kind {other:?} (use build|test|install|start)"),
        };
        if kind == ActionKind::DependencyInstall {
            continue; // provisioning already covered install
        }
        let candidates = graph.candidates(kind);
        if candidates.is_empty() {
            manifest
                .completeness
                .limitations
                .push(format!("no {kind_name} candidate command was discovered"));
            continue;
        }
        for (index, action) in candidates
            .iter()
            .take(options.max_candidates.max(1))
            .enumerate()
        {
            if executed_commands.contains(&action.command) {
                continue;
            }
            executed_commands.push(action.command.clone());
            let label = if index == 0 {
                kind_name.clone()
            } else {
                format!("{kind_name}-{}", index + 1)
            };
            manifest.build.commands.push(action.command.clone());
            ctx.record(
                "action-selected",
                "ovid-planner",
                action.source.trust_tier(),
                serde_json::json!({
                    "workload": label,
                    "command": action.command,
                    "source": action.source,
                    "source_file": action.source_file,
                    "score": action.score,
                }),
                None,
            )?;

            let offline_name = format!("{label}-offline");
            let offline = execute_workload(
                &mut ctx,
                &exec_snapshot,
                &action.command,
                &offline_options,
                &offline_name,
                if isolation {
                    NetworkMode::Isolated
                } else {
                    NetworkMode::Inherit
                },
            )?;
            absorb_execution(
                &mut ctx,
                &mut manifest,
                &offline,
                &offline_name,
                &action.command,
                &predicate,
            )?;

            let online_name = format!("{label}-online");
            let online = execute_workload(
                &mut ctx,
                &exec_snapshot,
                &action.command,
                &online_options,
                &online_name,
                NetworkMode::Inherit,
            )?;
            absorb_execution(
                &mut ctx,
                &mut manifest,
                &online,
                &online_name,
                &action.command,
                &predicate,
            )?;

            classify_pair(
                &mut ctx,
                &mut manifest,
                &label,
                &offline,
                &online,
                isolation,
            )?;
            last_online = Some((online, action.command.clone()));
        }
    }

    // ------------------------------------------------------------------
    // Disclosure: everything discovered but not executed (§25.2/§25.3 —
    // the gated-tier case: a `test-live` target that needs a database
    // must be visible even though it was not run).
    // ------------------------------------------------------------------
    for action in &graph.actions {
        if executed_commands.contains(&action.command) {
            continue;
        }
        if manifest.completeness.workloads_not_executed.len() >= 12 {
            manifest
                .completeness
                .workloads_not_executed
                .push("… further candidates truncated".into());
            break;
        }
        manifest.completeness.workloads_not_executed.push(format!(
            "{:?}: `{}` ({})",
            action.kind,
            action.command.join(" "),
            action.source_file.as_deref().unwrap_or("mined"),
        ));
    }

    let lock = last_online.as_ref().map(|(execution, argv)| {
        synthesize_world(
            &ctx,
            &mut manifest,
            &execution.proposals,
            &snapshot.canonical_url,
            argv,
        )
    });

    manifest
        .completeness
        .limitations
        .push("dynamic analysis is limited to the executed workloads".into());
    absorb_declared_services(&mut ctx, &mut manifest, &snapshot)?;
    absorb_declared_endpoints(&mut ctx, &mut manifest, &snapshot)?;
    finalize(&mut ctx, &mut manifest, lock.as_ref())?;
    Ok(Bundle {
        manifest,
        out_dir: out.to_path_buf(),
        lock,
    })
}

/// Counterfactual classification for one offline/online pair (extracted
/// from the per-kind loop; see `ovid-experiment::network` for the rules).
fn classify_pair(
    ctx: &mut Context,
    manifest: &mut Manifest,
    kind_name: &str,
    offline: &WorkloadExecution,
    online: &WorkloadExecution,
    isolation: bool,
) -> Result<()> {
    let offline_passed = offline.result.success();
    let online_passed = online.result.success();
    let offline_map: BTreeMap<String, &ovid_gateway::ExternalObservation> = offline
        .network
        .external
        .iter()
        .map(|o| (o.identity(), o))
        .collect();
    let online_map: BTreeMap<String, &ovid_gateway::ExternalObservation> = online
        .network
        .external
        .iter()
        .map(|o| (o.identity(), o))
        .collect();
    let identities: std::collections::BTreeSet<String> = offline_map
        .keys()
        .chain(online_map.keys())
        .cloned()
        .collect();

    let controlled_group: Vec<String> = identities
        .iter()
        .filter(|identity| {
            let offline_obs = offline_map.get(*identity).copied();
            let online_obs = online_map.get(*identity).copied();
            let controlled = offline_obs
                .or(online_obs)
                .map(externally_controlled)
                .unwrap_or(false);
            let offline_unavailable = offline_obs.map(|o| o.all_failed()).unwrap_or(true);
            let online_available = online_obs.map(|o| !o.all_failed()).unwrap_or(false);
            controlled && offline_unavailable && online_available
        })
        .cloned()
        .collect();
    if controlled_group.len() > 1 && !offline_passed && online_passed {
        manifest.completeness.limitations.push(format!(
            "network counterfactual for {kind_name} is group-level: {} dependencies \
             changed availability together ({}); per-dependency causality needs \
             individual variation",
            controlled_group.len(),
            controlled_group.join(", ")
        ));
    }

    for identity in &identities {
        let pair = NetworkCounterfactual {
            offline: offline_map.get(identity).copied(),
            online: online_map.get(identity).copied(),
        };
        let verdict = classify_network_counterfactual(
            &pair,
            offline_passed,
            online_passed,
            controlled_group.len(),
        );
        let evidence_id = ctx.record(
            "experiment-outcome",
            "ovid-experiment",
            TrustTier::T0,
            serde_json::json!({
                "condition": "network-isolated",
                "workload": kind_name,
                "dependency": identity,
                "offline_passed": offline_passed,
                "online_passed": online_passed,
                "classification": verdict.classification,
                "group_level": verdict.group_level,
                "isolation": if isolation { "user-netns" } else { "proxy-env-strip" },
            }),
            Some(offline.run_id.clone()),
        )?;
        match verdict.classification {
            CausalClassification::Required => {
                ctx.claim(
                    "requires",
                    format!("workload:{kind_name}"),
                    format!("service:{identity}"),
                    ClaimStates::default()
                        .with(ClaimState::Attempted)
                        .with(ClaimState::CausallyRequired),
                    vec![evidence_id.clone()],
                );
            }
            CausalClassification::Optional => {
                ctx.claim(
                    "optionally-uses",
                    format!("workload:{kind_name}"),
                    format!("service:{identity}"),
                    ClaimStates::default().with(ClaimState::Attempted),
                    vec![evidence_id.clone()],
                );
            }
            _ => {}
        }
        for system in &mut manifest.external_systems {
            let system_identity = format!(
                "{}:{}",
                system.dns_name.as_deref().unwrap_or(&system.address),
                system.port
            );
            if &system_identity == identity {
                system.causality = Some(verdict.classification);
                system.evidence.push(evidence_id.to_string());
            }
        }
    }
    Ok(())
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
