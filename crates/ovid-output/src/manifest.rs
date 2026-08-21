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

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Manifest {
    pub api_version: String,
    pub kind: String,
    pub metadata: ManifestMetadata,
    pub repository: RepositorySection,
    pub analysis: AnalysisSection,
    #[serde(default)]
    pub workloads: Vec<WorkloadReport>,
    pub inventory: InventorySection,
    #[serde(default)]
    pub build: BuildSection,
    #[serde(default)]
    pub runtime: RuntimeSection,
    #[serde(default)]
    pub external_systems: Vec<ExternalSystemReport>,
    #[serde(default)]
    pub world: WorldSection,
    /// Always present, possibly empty — v1 local mode performs no
    /// vulnerability validation, and saying so explicitly beats omission.
    #[serde(default)]
    pub vulnerabilities: Vec<serde_json::Value>,
    #[serde(default)]
    pub unresolved: Vec<UnresolvedItem>,
    pub completeness: CompletenessSection,
    pub provenance: ProvenanceSection,
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

    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).expect("manifests serialize")
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
}
