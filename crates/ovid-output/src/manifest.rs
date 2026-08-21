//! The Ovid Manifest (spec §25).
//!
//! Field names and section layout follow §25.1/§25.2. Sections that local
//! mode cannot yet populate (fleet, vulnerabilities) are present but empty
//! so the schema is stable; consumers must treat absence as *unknown*, not
//! as proof of absence (§25.3), which is why `completeness` is mandatory.

use ovid_core::{CausalClassification, Digest, MANIFEST_API_VERSION, OVID_VERSION};
use ovid_gateway::Listener;
use ovid_inventory::{Component, LanguageStat};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Section order is reading order: identity, then the summary and the
/// dynamic story (workloads, external systems, unresolved, completeness),
/// then supporting detail, with the bulk inventory second-to-last and
/// provenance closing the file. Serialization follows this field order in
/// both YAML and JSON.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Manifest {
    pub api_version: String,
    pub kind: String,
    pub metadata: ManifestMetadata,
    pub repository: RepositorySection,
    pub analysis: AnalysisSection,
    /// Read-first digest: headline, counts, and ranked findings. A pure
    /// projection of the sections below — it introduces no new facts.
    #[serde(default)]
    pub summary: SummarySection,
    #[serde(default)]
    pub workloads: Vec<WorkloadReport>,
    #[serde(default)]
    pub external_systems: Vec<ExternalSystemReport>,
    #[serde(default)]
    pub unresolved: Vec<UnresolvedItem>,
    pub completeness: CompletenessSection,
    #[serde(default)]
    pub build: BuildSection,
    #[serde(default)]
    pub runtime: RuntimeSection,
    #[serde(default)]
    pub world: WorldSection,
    /// Always present, possibly empty — v1 local mode performs no
    /// vulnerability validation, and saying so explicitly beats omission.
    #[serde(default)]
    pub vulnerabilities: Vec<serde_json::Value>,
    pub inventory: InventorySection,
    pub provenance: ProvenanceSection,
}

/// The read-first digest at the top of every manifest (§25.2's summary
/// posture): one headline, the counts a reviewer scans, and typed
/// findings ranked `attention` before `note`. Downstream agents can act
/// on this section alone and follow subjects into the detail sections.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct SummarySection {
    /// One sentence: what happened.
    #[serde(default)]
    pub headline: String,
    #[serde(default)]
    pub counts: SummaryCounts,
    /// Ranked, typed findings. Empty means "nothing noteworthy", which is
    /// itself a statement (completeness still says what was examined).
    #[serde(default)]
    pub findings: Vec<Finding>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct SummaryCounts {
    pub workload_runs: usize,
    pub workloads_passed: usize,
    pub workloads_failed: usize,
    pub components_resolved: usize,
    pub components_loaded: usize,
    pub external_systems: usize,
    pub unresolved: usize,
    pub workloads_not_executed: usize,
}

/// One noteworthy fact, typed for machine consumption and worded for
/// human review. `subject` names an entry in the detail sections.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Finding {
    /// `attention` (act on this) or `note` (worth knowing).
    pub severity: String,
    /// Stable machine kind, kebab-case (`workload-failed`,
    /// `endpoint-runtime-bound`, `declared-endpoint-never-exercised`, …).
    pub kind: String,
    pub subject: String,
    pub detail: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ManifestMetadata {
    pub analysis_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub ovid_version: String,
    /// `complete`, `complete-with-unresolved`, or `partial`.
    pub status: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct RepositorySection {
    pub canonical_url: String,
    pub revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_requested: Option<String>,
    pub source_digest: Digest,
    pub file_count: usize,
    pub total_size_bytes: u64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct AnalysisSection {
    /// `inventory`, `observe`, or `explore`.
    pub mode: String,
    /// Execution backend name, when anything was executed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Isolation honesty (§22.1's independence concerns): `microvm` or
    /// `trusted-process`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation_tier: Option<String>,
    #[serde(default)]
    pub runs: RunCounts,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct RunCounts {
    pub total: u32,
    pub successful: u32,
    pub failed: u32,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct WorkloadReport {
    pub id: String,
    pub name: String,
    pub command: Vec<String>,
    pub success_predicate: String,
    /// `passed`, `failed`, `not-executed`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world_digest: Option<Digest>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct InventorySection {
    #[serde(default)]
    pub languages: Vec<LanguageStat>,
    #[serde(default)]
    pub components: Vec<Component>,
    #[serde(default)]
    pub scanned_files: Vec<String>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct BuildSection {
    #[serde(default)]
    pub commands: Vec<Vec<String>>,
    #[serde(default)]
    pub tools: Vec<ToolReport>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactReport>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ToolReport {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causality: Option<CausalClassification>,
    /// e.g. `failed-exec` for tools discovered through an ENOENT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovered_by: Option<String>,
    /// Resolver candidate that would satisfy it, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_package: Option<String>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ArtifactReport {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<Digest>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct RuntimeSection {
    #[serde(default)]
    pub listeners: Vec<Listener>,
    #[serde(default)]
    pub unix_sockets: Vec<String>,
}

/// One external system the workload interacted with (§25.2's
/// `external_systems` entries, local-mode fields).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ExternalSystemReport {
    pub id: String,
    /// Classified protocol/system, or `unknown` (FR-048).
    pub protocol: String,
    pub address: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    /// All distinct addresses observed for this dependency (a named CDN
    /// dependency typically has several).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// How the dependency is identified: `dns-name` (name observed),
    /// `ip-only` (no DNS observation was available — absence of a name is
    /// explicitly unknown, not "nameless", §25.3), or `declared`
    /// (named by repository metadata such as a Compose file, unobserved).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub identity: String,
    /// Whether repository metadata (e.g. a Compose service) declares this
    /// dependency, independent of observation.
    #[serde(default)]
    pub declared: bool,
    pub attempts: u64,
    pub failures: u64,
    #[serde(default)]
    pub outcomes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causality: Option<CausalClassification>,
    /// Selected world treatment label (`service-pack:postgres`, `stub`,
    /// `unresolved`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub treatment: Option<String>,
    /// URL path from a declaration (`/v1`): how the resource is addressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_path: Option<String>,
    /// Environment variable that binds this endpoint's host at runtime.
    /// Connectivity is declared even though the destination is not: the
    /// value is external input Ovid cannot see (§6.6 — unknown, not
    /// absent). Name only, never a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    /// Environment variable *names* declared as credentials for this
    /// endpoint (`api_key_env:` conventions). Names only (§12.1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_env: Vec<String>,
    /// Repository locations declaring this endpoint: `file (key.path)` or
    /// `file:line (VAR)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_sources: Vec<String>,
    /// Evidence ids supporting this entry (G-8: every conclusion links).
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct WorldSection {
    /// `proposed`, `verified`, `replay-failed`, or `none`.
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_digest: Option<Digest>,
    #[serde(default)]
    pub dependencies: Vec<WorldDependencySummary>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct WorldDependencySummary {
    pub id: String,
    pub treatment: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct UnresolvedItem {
    pub id: String,
    pub reason: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

/// §11.12/FR-113: what was and wasn't examined. Consumers must read this
/// before trusting any absence.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct CompletenessSection {
    pub events_captured: u64,
    /// Observer lines that could not be normalized (accounted losses).
    pub events_unparsed: u64,
    pub events_collapsed: u64,
    pub noise_dropped: u64,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
    /// Candidate workloads that were discovered but not executed
    /// (spec §25.2 completeness: absence of results for these is
    /// unexamined, not proven-absent). Format: "kind: command (source)".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workloads_not_executed: Vec<String>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ProvenanceSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_chain_head: Option<Digest>,
    #[serde(default)]
    pub tools: Vec<ProvenanceTool>,
    #[serde(default)]
    pub packs: Vec<String>,
    /// Digest of the analysis policy inputs (§14.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<Digest>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ProvenanceTool {
    pub name: String,
    pub version: String,
}

impl Manifest {
    /// Skeleton with mandatory sections filled and everything else empty.
    pub fn new(analysis_id: String, mode: &str, repository: RepositorySection) -> Manifest {
        Manifest {
            api_version: MANIFEST_API_VERSION.to_string(),
            kind: "RepositoryAnalysis".to_string(),
            metadata: ManifestMetadata {
                analysis_id,
                created_at: chrono::Utc::now(),
                ovid_version: OVID_VERSION.to_string(),
                status: "partial".to_string(),
            },
            repository,
            analysis: AnalysisSection {
                mode: mode.to_string(),
                backend: None,
                isolation_tier: None,
                runs: RunCounts::default(),
            },
            summary: SummarySection::default(),
            workloads: Vec::new(),
            inventory: InventorySection::default(),
            build: BuildSection::default(),
            runtime: RuntimeSection::default(),
            external_systems: Vec::new(),
            world: WorldSection {
                status: "none".into(),
                ..Default::default()
            },
            vulnerabilities: Vec::new(),
            unresolved: Vec::new(),
            completeness: CompletenessSection::default(),
            provenance: ProvenanceSection {
                evidence_chain_head: None,
                tools: vec![ProvenanceTool {
                    name: "ovid".into(),
                    version: OVID_VERSION.into(),
                }],
                packs: Vec::new(),
                policy_digest: None,
            },
        }
    }

    /// Rebuild the read-first summary from the detail sections. Pure
    /// projection: every number and finding here restates a fact already
    /// present below it — the summary can never disagree with the file.
    pub fn build_summary(&self) -> SummarySection {
        let passed = self
            .workloads
            .iter()
            .filter(|w| w.status == "passed")
            .count();
        let failed = self
            .workloads
            .iter()
            .filter(|w| w.status == "failed")
            .count();
        let counts = SummaryCounts {
            workload_runs: self.workloads.len(),
            workloads_passed: passed,
            workloads_failed: failed,
            components_resolved: self
                .inventory
                .components
                .iter()
                .filter(|c| c.states.resolved)
                .count(),
            components_loaded: self
                .inventory
                .components
                .iter()
                .filter(|c| c.states.loaded)
                .count(),
            external_systems: self.external_systems.len(),
            unresolved: self.unresolved.len(),
            workloads_not_executed: self.completeness.workloads_not_executed.len(),
        };
        let headline = if self.workloads.is_empty() {
            "static analysis only; no workloads executed".to_string()
        } else if failed == 0 {
            match self.unresolved.len() {
                0 => format!(
                    "all {} workload runs passed; nothing unresolved",
                    counts.workload_runs
                ),
                n => format!(
                    "all {} workload runs passed; {n} unresolved item(s) flagged, not guessed",
                    counts.workload_runs
                ),
            }
        } else {
            format!("{failed} of {} workload runs failed", counts.workload_runs)
        };

        let mut findings: Vec<Finding> = Vec::new();
        for workload in &self.workloads {
            if workload.status == "failed" {
                findings.push(Finding {
                    severity: "attention".into(),
                    kind: "workload-failed".into(),
                    subject: workload.name.clone(),
                    detail: format!("`{}` exited nonzero", workload.command.join(" ")),
                });
            }
        }
        for system in &self.external_systems {
            let subject = system.id.clone();
            if system.causality == Some(CausalClassification::Required) {
                findings.push(Finding {
                    severity: "attention".into(),
                    kind: "required-external-dependency".into(),
                    subject: subject.clone(),
                    detail: "workload fails without it (counterfactual evidence)".into(),
                });
            }
            match system.identity.as_str() {
                "env-parameterized" => findings.push(Finding {
                    severity: "note".into(),
                    kind: "endpoint-runtime-bound".into(),
                    subject: subject.clone(),
                    detail: format!(
                        "external connectivity declared; host supplied at runtime by ${}{}",
                        system.env_var.as_deref().unwrap_or("?"),
                        system
                            .url_path
                            .as_deref()
                            .map(|p| format!(" ({} …{p})", system.protocol))
                            .unwrap_or_default()
                    ),
                }),
                "template-placeholder" => findings.push(Finding {
                    severity: "note".into(),
                    kind: "endpoint-runtime-bound".into(),
                    subject: subject.clone(),
                    detail: "declared endpoint host is a template placeholder; value supplied at deployment"
                        .into(),
                }),
                "declared" if system.attempts == 0 => {
                    let path = system
                        .url_path
                        .as_deref()
                        .map(|p| format!(", path {p}"))
                        .unwrap_or_default();
                    let credential = if system.credential_env.is_empty() {
                        String::new()
                    } else {
                        format!(", credential via {}", system.credential_env.join(", "))
                    };
                    findings.push(Finding {
                        severity: "note".into(),
                        kind: "declared-endpoint-never-exercised".into(),
                        subject: subject.clone(),
                        detail: format!(
                            "declared in {} location(s){path}{credential} — never dialed by \
                             any executed workload",
                            system.declared_sources.len().max(1),
                        ),
                    });
                }
                _ => {}
            }
            if system.protocol == "unknown" && system.attempts > 0 {
                findings.push(Finding {
                    severity: "note".into(),
                    kind: "unclassified-protocol".into(),
                    subject,
                    detail: format!(
                        "{} attempt(s), {} failure(s); no protocol pack matched",
                        system.attempts, system.failures
                    ),
                });
            }
        }
        for tool in &self.build.tools {
            if tool.causality == Some(CausalClassification::Unresolved) || tool.causality.is_none()
            {
                findings.push(Finding {
                    severity: "note".into(),
                    kind: "tool-unresolved".into(),
                    subject: format!("tool:{}", tool.name),
                    detail: match &tool.candidate_package {
                        Some(candidate) => {
                            format!("missing on PATH; resolver candidate {candidate}")
                        }
                        None => "missing on PATH; no trusted resolver candidate".into(),
                    },
                });
            }
        }
        if !self.completeness.workloads_not_executed.is_empty() {
            findings.push(Finding {
                severity: "note".into(),
                kind: "coverage-gap".into(),
                subject: "workloads".into(),
                detail: format!(
                    "{} discovered candidate(s) not executed — see completeness.workloads_not_executed",
                    self.completeness.workloads_not_executed.len()
                ),
            });
        }
        findings.sort_by(|a, b| {
            let rank = |s: &str| if s == "attention" { 0 } else { 1 };
            rank(&a.severity)
                .cmp(&rank(&b.severity))
                .then_with(|| a.kind.cmp(&b.kind))
                .then_with(|| a.subject.cmp(&b.subject))
        });
        SummarySection {
            headline,
            counts,
            findings,
        }
    }

    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).expect("manifests serialize")
    }

    /// YAML with a file header and one banner comment per section — the
    /// human-facing rendering. Content is byte-identical to [`to_yaml`]
    /// minus comments; parsers see the same document.
    pub fn to_yaml_annotated(&self) -> String {
        let blurb = |section: &str| -> Option<&'static str> {
            Some(match section {
                "metadata" => "what this analysis is and when it ran",
                "repository" => "exactly what was analyzed (revision + content digest)",
                "analysis" => "mode, backend, and isolation tier (honesty: no silent upgrades)",
                "summary" => "read this first: headline, counts, ranked findings",
                "workloads" => "every executed run and its outcome",
                "external_systems" => "everything dialed or declared, with identity and causality",
                "unresolved" => "explicitly unknown — flagged instead of guessed (§6.6)",
                "completeness" => "what was examined, collapsed, dropped, and NOT executed",
                "build" => "commands run, tools probed, artifacts produced",
                "runtime" => "listeners and sockets observed",
                "world" => "synthesized replay world (see world.lock.yaml)",
                "vulnerabilities" => "empty means not validated, not vulnerability-free",
                "inventory" => "full component inventory (bulk detail; states are independent)",
                "provenance" => "evidence chain head, tool and pack versions",
                _ => return None,
            })
        };
        let value = serde_yaml::to_value(self).expect("manifests serialize");
        let serde_yaml::Value::Mapping(map) = value else {
            return self.to_yaml();
        };
        let mut out = String::new();
        out.push_str(&format!(
            "# Ovid analysis manifest — generated by ovid {OVID_VERSION}\n\
             # Reading order: summary -> workloads -> external_systems -> unresolved -> completeness.\n\
             # evidence.jsonl is the canonical ledger; every id here resolves into it\n\
             # (`ovid explain <id>`). ovid.json is this same document for machines.\n"
        ));
        for (key, section) in map {
            let name = key.as_str().unwrap_or_default().to_string();
            if let Some(text) = blurb(&name) {
                let pad = "\u{2500}".repeat(56usize.saturating_sub(name.len()));
                out.push_str(&format!("\n# \u{2500}\u{2500} {name} {pad}\n# {text}\n"));
            }
            let mut single = serde_yaml::Mapping::new();
            single.insert(serde_yaml::Value::String(name), section);
            out.push_str(
                &serde_yaml::to_string(&serde_yaml::Value::Mapping(single))
                    .expect("manifest sections serialize"),
            );
        }
        out
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("manifests serialize")
    }

    pub fn from_json(json: &str) -> Result<Manifest, ovid_core::OvidError> {
        serde_json::from_str(json).map_err(|e| ovid_core::OvidError::Serde(e.to_string()))
    }

    /// Component index by purl, used by diffs.
    pub fn components_by_purl(&self) -> BTreeMap<&str, &Component> {
        self.inventory
            .components
            .iter()
            .map(|c| (c.purl.as_str(), c))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample_repository() -> RepositorySection {
        RepositorySection {
            canonical_url: "https://github.com/acme/app".into(),
            revision: "deadbeef".into(),
            ref_requested: None,
            source_digest: Digest::of_bytes(b"tree"),
            file_count: 10,
            total_size_bytes: 1000,
        }
    }

    #[test]
    fn manifest_round_trips_yaml_and_json() {
        let manifest = Manifest::new("analysis:test".into(), "observe", sample_repository());
        let yaml = manifest.to_yaml();
        assert!(yaml.contains("api_version: ovid.dev/manifest/v1alpha1"));
        assert!(yaml.contains("completeness:"));
        let json = manifest.to_json_pretty();
        let back = Manifest::from_json(&json).unwrap();
        assert_eq!(back.repository.revision, "deadbeef");
        assert_eq!(back.kind, "RepositoryAnalysis");
    }

    #[test]
    fn empty_sections_are_present_not_missing() {
        let manifest = Manifest::new("analysis:test".into(), "inventory", sample_repository());
        let yaml = manifest.to_yaml();
        // §25.3: consumers must see explicit empty sections + completeness.
        assert!(yaml.contains("vulnerabilities: []"));
        assert!(yaml.contains("unresolved: []"));
    }

    fn manifest_with_story() -> Manifest {
        let mut manifest = Manifest::new("analysis:test".into(), "tomography", sample_repository());
        manifest.workloads.push(WorkloadReport {
            id: "workload:test-offline".into(),
            name: "test-offline".into(),
            command: vec!["make".into(), "test".into()],
            success_predicate: "exit-code == 0".into(),
            status: "failed".into(),
            duration_ms: Some(10),
            world_digest: None,
        });
        manifest.external_systems.push(ExternalSystemReport {
            id: "env:LLM_HOST".into(),
            protocol: "https".into(),
            address: "${LLM_HOST}".into(),
            port: 443,
            dns_name: None,
            endpoints: vec![],
            identity: "env-parameterized".into(),
            declared: true,
            attempts: 0,
            failures: 0,
            outcomes: vec![],
            causality: None,
            treatment: None,
            url_path: Some("/v1".into()),
            env_var: Some("LLM_HOST".into()),
            credential_env: vec![],
            declared_sources: vec!["config/app.yaml (model.base_url)".into()],
            evidence: vec![],
        });
        manifest
            .completeness
            .workloads_not_executed
            .push("Test: `make e2e` (Makefile)".into());
        manifest
    }

    #[test]
    fn summary_is_a_ranked_projection_of_the_sections() {
        let manifest = manifest_with_story();
        let summary = manifest.build_summary();
        assert!(summary.headline.contains("1 of 1 workload runs failed"));
        assert_eq!(summary.counts.workloads_failed, 1);
        assert_eq!(summary.counts.workloads_not_executed, 1);
        // Attention findings rank before notes.
        assert_eq!(summary.findings[0].kind, "workload-failed");
        assert_eq!(summary.findings[0].severity, "attention");
        let kinds: Vec<&str> = summary.findings.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"endpoint-runtime-bound"));
        assert!(kinds.contains(&"coverage-gap"));
        let bound = summary
            .findings
            .iter()
            .find(|f| f.kind == "endpoint-runtime-bound")
            .unwrap();
        assert!(bound.detail.contains("$LLM_HOST"), "{}", bound.detail);
    }

    #[test]
    fn annotated_yaml_reads_summary_first_and_inventory_late() {
        let mut manifest = manifest_with_story();
        manifest.summary = manifest.build_summary();
        let yaml = manifest.to_yaml_annotated();
        assert!(yaml.starts_with("# Ovid analysis manifest"));
        assert!(yaml.contains("# \u{2500}\u{2500} summary "));
        let position = |needle: &str| yaml.find(needle).unwrap_or_else(|| panic!("{needle}"));
        assert!(position("\nsummary:") < position("\nworkloads:"));
        assert!(position("\nworkloads:") < position("\nexternal_systems:"));
        assert!(position("\ncompleteness:") < position("\ninventory:"));
        assert!(position("\ninventory:") < position("\nprovenance:"));
        // Comments only — stripped of them, the document parses back into
        // the same manifest.
        let back: Manifest = serde_yaml::from_str(&yaml).expect("annotated yaml parses");
        assert_eq!(back.summary.findings.len(), manifest.summary.findings.len());
        assert_eq!(back.repository.revision, "deadbeef");
    }
}
