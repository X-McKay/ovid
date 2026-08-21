//! Static inventory (spec §10.1, §11.8, §28).
//!
//! This crate answers "what does the repository *declare and resolve*?"
//! without executing anything. It is explicitly labeled static provenance
//! (T4 for manifests, T3 for lockfiles produced by package managers) and its
//! results feed the `declared`/`resolved` claim-state dimensions only —
//! never `loaded` or `exercised` (§6.3).
//!
//! Per FR-070 the long-term posture is to *integrate* external SBOM tools
//! (Syft, cdxgen) as sandboxed providers rather than reimplement every
//! ecosystem. The native scanners here cover the major lockfile formats so
//! Ovid produces useful inventory with zero external dependencies; the
//! [`provider`] module defines the contract external SBOM providers plug
//! into.

pub mod languages;
pub mod provider;
pub mod purl;
pub mod scanners;

use ovid_repository::RepoSnapshot;
use serde::{Deserialize, Serialize};

pub use languages::{detect_languages, LanguageStat};
pub use purl::purl;

/// Dependency scope, as declared by the manifest.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    Runtime,
    Dev,
    Build,
    Unknown,
}

/// One inventoried software component (§25.2 `inventory.components`).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Component {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Package ecosystem (`cargo`, `npm`, `pypi`, `golang`, `maven`, …).
    pub ecosystem: String,
    /// Package URL (FR-072). Best-effort when version is unknown.
    pub purl: String,
    pub scope: Scope,
    /// Whether the manifest names it directly (vs. lockfile-only).
    pub direct: bool,
    pub states: ovid_core::ClaimStates,
    /// Repository-relative file the component was discovered in.
    pub source_file: String,
}

/// The full static inventory result for a snapshot.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct InventoryReport {
    pub languages: Vec<LanguageStat>,
    pub components: Vec<Component>,
    /// Manifest/lockfile files that were recognized and scanned.
    pub scanned_files: Vec<String>,
    /// Non-fatal scanner problems, surfaced as completeness limitations.
    pub warnings: Vec<String>,
}

impl InventoryReport {
    pub fn declared_count(&self) -> usize {
        self.components.iter().filter(|c| c.states.declared).count()
    }

    pub fn resolved_count(&self) -> usize {
        self.components.iter().filter(|c| c.states.resolved).count()
    }
}

/// Run language detection and every applicable scanner over a snapshot.
pub fn scan(snapshot: &RepoSnapshot) -> InventoryReport {
    let mut report = InventoryReport {
        languages: detect_languages(snapshot),
        ..Default::default()
    };
    for scanner in scanners::all() {
        scanner.scan(snapshot, &mut report);
    }
    merge_components(&mut report);
    report
}

/// Deduplicate components by (ecosystem, name, version), merging state
/// dimensions: a package both declared in a manifest and pinned in a
/// lockfile ends up with `declared: true, resolved: true` on one entry.
fn merge_components(report: &mut InventoryReport) {
    use std::collections::BTreeMap;
    let mut merged: BTreeMap<(String, String, Option<String>), Component> = BTreeMap::new();
    for component in report.components.drain(..) {
        let key = (
            component.ecosystem.clone(),
            component.name.clone(),
            component.version.clone(),
        );
        match merged.get_mut(&key) {
            Some(existing) => {
                existing.states.declared |= component.states.declared;
                existing.states.resolved |= component.states.resolved;
                existing.direct |= component.direct;
                if existing.scope == Scope::Unknown {
                    existing.scope = component.scope;
                }
            }
            None => {
                merged.insert(key, component);
            }
        }
    }
    // Second pass: a version-pinned lockfile entry absorbs the `declared`
    // flag of a versionless manifest entry with the same name, and the
    // versionless duplicate is dropped.
    let names_with_versions: std::collections::BTreeSet<(String, String)> = merged
        .keys()
        .filter(|(_, _, v)| v.is_some())
        .map(|(e, n, _)| (e.clone(), n.clone()))
        .collect();
    let mut out: Vec<Component> = Vec::with_capacity(merged.len());
    let mut declared_versionless: std::collections::BTreeSet<(String, String)> = Default::default();
    for ((eco, name, version), component) in &merged {
        if version.is_none() && names_with_versions.contains(&(eco.clone(), name.clone())) {
            if component.states.declared {
                declared_versionless.insert((eco.clone(), name.clone()));
            }
            continue;
        }
        out.push(component.clone());
    }
    for component in &mut out {
        let key = (component.ecosystem.clone(), component.name.clone());
        if declared_versionless.contains(&key) {
            component.states.declared = true;
            component.direct = true;
        }
    }
    report.components = out;
}
