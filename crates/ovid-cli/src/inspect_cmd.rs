//! The static path: `ovid inspect`, plus the bundle read commands
//! (`explain`, `export`, `diff` helpers) that operate on what analyses
//! wrote (proposal §4.2, §9.1).
//!
//! `inspect` never executes repository code: it resolves the source,
//! scans declared composition (manifests, lockfiles, compose files,
//! declared endpoints with env-var indirection), records everything into
//! the hash-chained ledger, projects a manifest, and ranks workload
//! candidates so the next step (`ovid prove --workload …`) is obvious.
//! Standards exports are rendered lazily by `ovid export`
//! (proposal §14.10), never written on every run.

use anyhow::{anyhow, bail, Context as AnyhowContext, Result};
use ovid_core::{ClaimState, ClaimStates, IdGenerator, OvidId, TrustTier};
use ovid_evidence::{Claim, ClaimStore, EvidenceLedger, EvidenceRecord};
use ovid_inventory::InventoryReport;
use ovid_output::{ExternalSystemReport, Manifest, RepositorySection, UnresolvedItem};
use ovid_packs::PackRegistry;
use ovid_planner::ActionKind;
use ovid_repository::{acquire, AcquireOptions, RepoSnapshot, RepositorySource};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Shared per-analysis bundle state: the canonical ledger, the claim
/// store, and the pack registry (ADR-004: ledger first, always).
pub struct Context {
    pub out_dir: PathBuf,
    pub ids: IdGenerator,
    pub ledger: EvidenceLedger,
    pub claims: ClaimStore,
    pub registry: PackRegistry,
}

impl Context {
    pub fn open(out_dir: &Path, packs_dir: Option<&Path>) -> Result<Context> {
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
    ) -> Result<OvidId> {
        let id = self.ids.next("evidence");
        let record = EvidenceRecord {
            id: id.clone(),
            record_type: record_type.into(),
            run_id: None,
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
    ) {
        let claim = Claim {
            id: self.ids.next("claim"),
            predicate: predicate.into(),
            subject,
            object,
            states,
            confidence: 0.0,
            supports,
            contradicts: vec![],
            normalizer: "ovid-inspect".into(),
            normalizer_version: ovid_core::OVID_VERSION.into(),
        };
        self.claims.upsert(claim, &self.ledger);
    }
}

/// Resolve a locator (local path or git URL) into an immutable snapshot.
pub fn acquire_snapshot(
    locator: &str,
    reference: Option<String>,
    out_dir: &Path,
) -> Result<RepoSnapshot> {
    let source = RepositorySource::parse(locator, reference);
    let options = AcquireOptions::new(out_dir.join(".workdir"));
    acquire(&source, &options).map_err(|e| anyhow!("acquire {locator}: {e}"))
}

/// Manifest repository section from a snapshot.
pub fn repository_section(snapshot: &RepoSnapshot) -> RepositorySection {
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

/// Absorb Compose-declared services (FR-011 container metadata) into the
/// manifest: merged onto an existing system when the identity matches,
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
        )?;
        ctx.claim(
            "declares",
            repo_subject.clone(),
            format!("service:{}", service.name),
            ClaimStates::default().with(ClaimState::Declared),
            vec![evidence_id.clone()],
        );
        // Merge onto a system whose DNS name or id matches the compose
        // service name (the docker-network alias case). Anything weaker
        // (port-only) would be guessing (§6.6).
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
/// onto an existing system when the host matches; otherwise it appends a
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
        // Merge onto an existing system with the same host identity;
        // anything weaker would be guessing (§6.6).
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

/// Finalize a bundle: status, provenance, the read-first summary, and
/// the manifest documents. Standards exports are *not* written — they
/// render on demand via `ovid export` (proposal §14.10).
pub fn finalize(ctx: &mut Context, manifest: &mut Manifest) -> Result<()> {
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
    Ok(())
}

/// Run `ovid inspect` (proposal §4.2, §9.1): static-only, fast, ends
/// with ranked workload candidates.
pub fn run_inspect(
    locator: &str,
    reference: Option<String>,
    out: &Path,
    packs_dir: Option<&Path>,
    json: bool,
) -> Result<()> {
    let mut ctx = Context::open(out, packs_dir)?;
    let snapshot = acquire_snapshot(locator, reference, out)?;
    let report = ovid_inventory::scan(&snapshot);
    record_inventory(&mut ctx, &snapshot, &report)?;

    let mut manifest = Manifest::new(
        ctx.ids.next("analysis").to_string(),
        "inspect",
        repository_section(&snapshot),
    );
    manifest.inventory.languages = report.languages.clone();
    manifest.inventory.components = report.components.clone();
    manifest.inventory.scanned_files = report.scanned_files.clone();
    manifest.completeness.warnings = report.warnings.clone();
    manifest
        .completeness
        .limitations
        .push("inspect mode: no code was executed; dynamic states are unknown".into());
    absorb_declared_services(&mut ctx, &mut manifest, &snapshot)?;
    absorb_declared_endpoints(&mut ctx, &mut manifest, &snapshot)?;
    finalize(&mut ctx, &mut manifest)?;

    if json {
        println!("{}", manifest.to_json_pretty());
        return Ok(());
    }
    print_summary(&manifest, out);

    // Ranked workload candidates from the planner (static, not executed).
    let graph = ovid_planner::plan(&snapshot, &ctx.registry);
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

/// Concise terminal summary of a manifest.
pub fn print_summary(manifest: &Manifest, out_dir: &Path) {
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
    for system in &manifest.external_systems {
        println!(
            "external: {} {}:{} [{}] {}",
            system.id,
            system.address,
            system.port,
            system.protocol,
            system
                .causality
                .map(|c| format!("causality={c:?}"))
                .unwrap_or_else(|| system.identity.clone())
        );
    }
    for item in &manifest.unresolved {
        println!("unresolved: {} — {}", item.id, item.reason);
    }
    println!("bundle: {}", out_dir.display());
}

/// Run `ovid explain` (FR-110): traverse a claim to its evidence.
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

/// Run `ovid export`: render a standards projection from a completed
/// bundle on demand (proposal §14.10 — lazy outputs).
pub fn export(from: &Path, format: &str) -> Result<()> {
    let load_manifest = || -> Result<Manifest> {
        let path = from.join("ovid.json");
        let text = std::fs::read_to_string(&path).with_context(|| {
            format!("no manifest at {} (run an analysis first)", path.display())
        })?;
        Ok(Manifest::from_json(&text)?)
    };
    let load_lock = || -> Result<ovid_world::WorldLock> {
        let path = from.join("world.lock.yaml");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("no world lock at {}", path.display()))?;
        Ok(serde_yaml::from_str(&text)?)
    };
    match format {
        "cyclonedx" => println!(
            "{}",
            serde_json::to_string_pretty(&ovid_output::to_cyclonedx(&load_manifest()?))?
        ),
        "spdx" => println!(
            "{}",
            serde_json::to_string_pretty(&ovid_output::to_spdx(&load_manifest()?))?
        ),
        "plan" => {
            let manifest = load_manifest()?;
            let lock = load_lock().ok();
            print!(
                "{}",
                ovid_output::integration_plan_markdown(&manifest, lock.as_ref())
            );
        }
        "lock" => print!("{}", load_lock()?.to_yaml()),
        "compose" => print!("{}", load_lock()?.to_compose_yaml()),
        other => bail!("unknown export format {other:?} (use cyclonedx|spdx|plan|lock|compose)"),
    }
    Ok(())
}
