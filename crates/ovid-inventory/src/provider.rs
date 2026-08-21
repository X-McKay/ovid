//! External SBOM provider contract (FR-070, §28.2, §34.4).
//!
//! Ovid prefers integrating existing SBOM generators (Syft, cdxgen) over
//! reimplementing every ecosystem. An external provider is an executable
//! invoked in a sandbox with pinned identity; its raw output is retained as
//! evidence and normalized separately. This module defines the contract and
//! a CycloneDX normalizer so any provider that emits CycloneDX JSON can be
//! plugged in.

use crate::{Component, Scope};
use ovid_core::{ClaimState, ClaimStates, OvidError};
use serde::Deserialize;

/// Identity and invocation description for an external provider.
#[derive(Clone, Debug)]
pub struct ExternalProvider {
    pub name: String,
    /// Pinned version or digest recorded into provenance.
    pub version: String,
    pub command: Vec<String>,
}

/// Normalize CycloneDX JSON (as produced by Syft/cdxgen) into components.
///
/// Every component is marked `resolved` (the tool inspected concrete
/// files), never `loaded`/`exercised` — those states only come from
/// dynamic observation (§6.3).
pub fn normalize_cyclonedx(json: &str, source_label: &str) -> Result<Vec<Component>, OvidError> {
    #[derive(Deserialize)]
    struct Doc {
        #[serde(default)]
        components: Vec<CdxComponent>,
    }
    #[derive(Deserialize)]
    struct CdxComponent {
        name: String,
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        purl: Option<String>,
    }
    let doc: Doc = serde_json::from_str(json)
        .map_err(|e| OvidError::Serde(format!("cyclonedx parse: {e}")))?;
    Ok(doc
        .components
        .into_iter()
        .map(|c| {
            let ecosystem = c
                .purl
                .as_deref()
                .and_then(|p| p.strip_prefix("pkg:"))
                .and_then(|p| p.split('/').next())
                .unwrap_or("generic")
                .to_string();
            let purl = c
                .purl
                .clone()
                .unwrap_or_else(|| crate::purl(&ecosystem, &c.name, c.version.as_deref()));
            Component {
                name: c.name,
                version: c.version,
                ecosystem,
                purl,
                scope: Scope::Unknown,
                direct: false,
                states: ClaimStates::default().with(ClaimState::Resolved),
                source_file: source_label.to_string(),
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_cyclonedx_components() {
        let json = r#"{
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
                {"name": "mystery"}
            ]
        }"#;
        let components = normalize_cyclonedx(json, "syft:source").unwrap();
        assert_eq!(components.len(), 2);
        assert_eq!(components[0].ecosystem, "npm");
        assert!(components[0].states.resolved);
        assert!(
            !components[0].states.loaded,
            "static provider must not set loaded"
        );
        assert_eq!(components[1].purl, "pkg:generic/mystery");
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(normalize_cyclonedx("not json", "x").is_err());
    }
}
