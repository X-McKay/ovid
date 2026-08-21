//! Evidence-aware manifest comparison (FR-100/FR-101, local-mode scope:
//! composition, tools, interfaces, and external-system changes).

use crate::manifest::Manifest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct ManifestDiff {
    pub components_added: Vec<String>,
    pub components_removed: Vec<String>,
    /// name -> (before, after).
    pub version_changes: BTreeMap<String, (String, String)>,
    pub external_added: Vec<String>,
    pub external_removed: Vec<String>,
    pub listeners_added: Vec<u16>,
    pub listeners_removed: Vec<u16>,
    pub tools_added: Vec<String>,
    pub tools_removed: Vec<String>,
}

impl ManifestDiff {
    pub fn is_empty(&self) -> bool {
        self.components_added.is_empty()
            && self.components_removed.is_empty()
            && self.version_changes.is_empty()
            && self.external_added.is_empty()
            && self.external_removed.is_empty()
            && self.listeners_added.is_empty()
            && self.listeners_removed.is_empty()
            && self.tools_added.is_empty()
            && self.tools_removed.is_empty()
    }

    pub fn to_markdown(&self) -> String {
        if self.is_empty() {
            return "No material differences detected.\n".to_string();
        }
        let mut out = String::from("# Manifest diff\n\n");
        let section = |title: &str, items: &[String], out: &mut String| {
            if !items.is_empty() {
                out.push_str(&format!("## {title}\n\n"));
                for item in items {
                    out.push_str(&format!("- {item}\n"));
                }
                out.push('\n');
            }
        };
        section("Components added", &self.components_added, &mut out);
        section("Components removed", &self.components_removed, &mut out);
        if !self.version_changes.is_empty() {
            out.push_str("## Version changes\n\n");
            for (name, (before, after)) in &self.version_changes {
                out.push_str(&format!("- {name}: {before} -> {after}\n"));
            }
            out.push('\n');
        }
        section("External systems added", &self.external_added, &mut out);
        section("External systems removed", &self.external_removed, &mut out);
        section("Tools added", &self.tools_added, &mut out);
        section("Tools removed", &self.tools_removed, &mut out);
        if !self.listeners_added.is_empty() || !self.listeners_removed.is_empty() {
            out.push_str("## Listener changes\n\n");
            for port in &self.listeners_added {
                out.push_str(&format!("- added listener on port {port}\n"));
            }
            for port in &self.listeners_removed {
                out.push_str(&format!("- removed listener on port {port}\n"));
            }
        }
        out
    }
}

pub fn diff_manifests(before: &Manifest, after: &Manifest) -> ManifestDiff {
    let mut diff = ManifestDiff::default();

    // Components: keyed by (ecosystem, name); versions compared when both
    // sides pin one.
    let index = |manifest: &Manifest| -> BTreeMap<(String, String), Option<String>> {
        manifest
            .inventory
            .components
            .iter()
            .map(|c| ((c.ecosystem.clone(), c.name.clone()), c.version.clone()))
            .collect()
    };
    let before_components = index(before);
    let after_components = index(after);
    for (key, after_version) in &after_components {
        match before_components.get(key) {
            None => diff.components_added.push(format!("{}/{}", key.0, key.1)),
            Some(before_version) => {
                if let (Some(b), Some(a)) = (before_version, after_version) {
                    if b != a {
                        diff.version_changes
                            .insert(format!("{}/{}", key.0, key.1), (b.clone(), a.clone()));
                    }
                }
            }
        }
    }
    for key in before_components.keys() {
        if !after_components.contains_key(key) {
            diff.components_removed.push(format!("{}/{}", key.0, key.1));
        }
    }

    let externals = |manifest: &Manifest| -> Vec<String> {
        manifest
            .external_systems
            .iter()
            .map(|s| s.id.clone())
            .collect()
    };
    let before_external = externals(before);
    let after_external = externals(after);
    diff.external_added = after_external
        .iter()
        .filter(|id| !before_external.contains(id))
        .cloned()
        .collect();
    diff.external_removed = before_external
        .iter()
        .filter(|id| !after_external.contains(id))
        .cloned()
        .collect();

    let listeners = |manifest: &Manifest| -> Vec<u16> {
        manifest.runtime.listeners.iter().map(|l| l.port).collect()
    };
    let before_listeners = listeners(before);
    let after_listeners = listeners(after);
    diff.listeners_added = after_listeners
        .iter()
        .filter(|p| !before_listeners.contains(p))
        .copied()
        .collect();
    diff.listeners_removed = before_listeners
        .iter()
        .filter(|p| !after_listeners.contains(p))
        .copied()
        .collect();

    let tools = |manifest: &Manifest| -> Vec<String> {
        manifest
            .build
            .tools
            .iter()
            .map(|t| t.name.clone())
            .collect()
    };
    let before_tools = tools(before);
    let after_tools = tools(after);
    diff.tools_added = after_tools
        .iter()
        .filter(|t| !before_tools.contains(t))
        .cloned()
        .collect();
    diff.tools_removed = before_tools
        .iter()
        .filter(|t| !after_tools.contains(t))
        .cloned()
        .collect();

    diff
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Manifest, RepositorySection};
    use ovid_core::{ClaimState, ClaimStates, Digest};
    use ovid_inventory::{Component, Scope};

    fn base(version: &str) -> Manifest {
        let mut manifest = Manifest::new(
            "analysis:x".into(),
            "observe",
            RepositorySection {
                canonical_url: "https://github.com/acme/app".into(),
                revision: "abc".into(),
                ref_requested: None,
                source_digest: Digest::of_bytes(b"t"),
                file_count: 1,
                total_size_bytes: 1,
            },
        );
        manifest.inventory.components.push(Component {
            name: "serde".into(),
            version: Some(version.into()),
            ecosystem: "cargo".into(),
            purl: format!("pkg:cargo/serde@{version}"),
            scope: Scope::Runtime,
            direct: true,
            states: ClaimStates::default().with(ClaimState::Resolved),
            source_file: "Cargo.lock".into(),
        });
        manifest
    }

    #[test]
    fn version_bump_and_addition_detected() {
        let before = base("1.0.100");
        let mut after = base("1.0.200");
        after.inventory.components.push(Component {
            name: "anyhow".into(),
            version: Some("1.0.80".into()),
            ecosystem: "cargo".into(),
            purl: "pkg:cargo/anyhow@1.0.80".into(),
            scope: Scope::Runtime,
            direct: true,
            states: ClaimStates::default().with(ClaimState::Resolved),
            source_file: "Cargo.lock".into(),
        });
        let diff = diff_manifests(&before, &after);
        assert_eq!(
            diff.version_changes["cargo/serde"],
            ("1.0.100".into(), "1.0.200".into())
        );
        assert_eq!(diff.components_added, vec!["cargo/anyhow"]);
        assert!(diff.components_removed.is_empty());
        assert!(diff.to_markdown().contains("1.0.100 -> 1.0.200"));
    }

    #[test]
    fn identical_manifests_diff_empty() {
        let a = base("1.0.100");
        let b = base("1.0.100");
        let diff = diff_manifests(&a, &b);
        assert!(diff.is_empty());
        assert!(diff.to_markdown().contains("No material differences"));
    }
}
