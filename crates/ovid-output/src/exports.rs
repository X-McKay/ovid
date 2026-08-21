//! Standards exports (FR-075, ADR-006): CycloneDX 1.5 and SPDX 2.3 JSON.
//!
//! Both are projections of the manifest; neither is the internal model.
//! Component states that the standards cannot express (declared vs
//! resolved vs exercised) are carried in CycloneDX `properties` so the
//! distinction is not silently lost.

use crate::manifest::Manifest;
use serde_json::{json, Value};

/// CycloneDX 1.5 JSON export: components plus external systems as
/// services (CycloneDX's service model, §13.14).
pub fn to_cyclonedx(manifest: &Manifest) -> Value {
    let components: Vec<Value> = manifest
        .inventory
        .components
        .iter()
        .map(|component| {
            let mut properties = vec![];
            for (name, present) in [
                ("ovid:state:declared", component.states.declared),
                ("ovid:state:resolved", component.states.resolved),
                ("ovid:state:loaded", component.states.loaded),
                ("ovid:state:exercised", component.states.exercised),
            ] {
                if present {
                    properties.push(json!({ "name": name, "value": "true" }));
                }
            }
            json!({
                "type": "library",
                "name": component.name,
                "version": component.version,
                "purl": component.purl,
                "scope": match component.scope {
                    ovid_inventory::Scope::Runtime => "required",
                    ovid_inventory::Scope::Dev | ovid_inventory::Scope::Build => "optional",
                    ovid_inventory::Scope::Unknown => "required",
                },
                "properties": properties,
            })
        })
        .collect();

    let services: Vec<Value> = manifest
        .external_systems
        .iter()
        .map(|system| {
            json!({
                "name": system.id,
                "endpoints": [format!("{}:{}", system.dns_name.as_deref().unwrap_or(&system.address), system.port)],
                "properties": [
                    { "name": "ovid:protocol", "value": system.protocol },
                    { "name": "ovid:causality",
                      "value": system.causality.map(|c| format!("{c:?}")).unwrap_or_else(|| "unknown".into()) },
                ],
            })
        })
        .collect();

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": manifest.metadata.created_at.to_rfc3339(),
            "tools": [{ "vendor": "ovid", "name": "ovid", "version": manifest.metadata.ovid_version }],
            "component": {
                "type": "application",
                "name": manifest.repository.canonical_url,
                "version": manifest.repository.revision,
            },
        },
        "components": components,
        "services": services,
    })
}

/// SPDX 2.3 JSON export (packages only — SPDX has no service concept).
pub fn to_spdx(manifest: &Manifest) -> Value {
    let packages: Vec<Value> = manifest
        .inventory
        .components
        .iter()
        .enumerate()
        .map(|(index, component)| {
            json!({
                "name": component.name,
                "SPDXID": format!("SPDXRef-Package-{index}"),
                "versionInfo": component.version.clone().unwrap_or_else(|| "NOASSERTION".into()),
                "downloadLocation": "NOASSERTION",
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": component.purl,
                }],
            })
        })
        .collect();
    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("ovid-analysis-{}", manifest.metadata.analysis_id),
        "documentNamespace": format!(
            "https://ovid.dev/spdx/{}/{}",
            manifest.repository.revision, manifest.metadata.analysis_id
        ),
        "creationInfo": {
            "created": manifest.metadata.created_at.to_rfc3339(),
            "creators": [format!("Tool: ovid-{}", manifest.metadata.ovid_version)],
        },
        "packages": packages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ExternalSystemReport, Manifest, RepositorySection};
    use ovid_core::{ClaimState, ClaimStates, Digest};
    use ovid_inventory::{Component, Scope};

    fn manifest_with_component() -> Manifest {
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
            version: Some("1.0.200".into()),
            ecosystem: "cargo".into(),
            purl: "pkg:cargo/serde@1.0.200".into(),
            scope: Scope::Runtime,
            direct: true,
            states: ClaimStates::default()
                .with(ClaimState::Declared)
                .with(ClaimState::Resolved),
            source_file: "Cargo.lock".into(),
        });
        manifest.external_systems.push(ExternalSystemReport {
            id: "orders-db".into(),
            protocol: "postgresql".into(),
            address: "10.0.0.5".into(),
            port: 5432,
            dns_name: Some("orders-db".into()),
            endpoints: vec!["10.0.0.5".into()],
            identity: "dns-name".into(),
            attempts: 2,
            failures: 2,
            outcomes: vec!["ECONNREFUSED".into()],
            causality: Some(ovid_core::CausalClassification::Required),
            treatment: Some("service-pack:postgres".into()),
            evidence: vec!["evidence:1".into()],
        });
        manifest
    }

    #[test]
    fn cyclonedx_has_components_services_and_state_properties() {
        let bom = to_cyclonedx(&manifest_with_component());
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], "1.5");
        assert_eq!(bom["components"][0]["purl"], "pkg:cargo/serde@1.0.200");
        let properties = bom["components"][0]["properties"].as_array().unwrap();
        assert!(properties
            .iter()
            .any(|p| p["name"] == "ovid:state:declared"));
        assert!(!properties
            .iter()
            .any(|p| p["name"] == "ovid:state:exercised"));
        assert_eq!(bom["services"][0]["name"], "orders-db");
    }

    #[test]
    fn spdx_export_is_well_formed() {
        let doc = to_spdx(&manifest_with_component());
        assert_eq!(doc["spdxVersion"], "SPDX-2.3");
        assert_eq!(doc["packages"][0]["name"], "serde");
        assert_eq!(
            doc["packages"][0]["externalRefs"][0]["referenceLocator"],
            "pkg:cargo/serde@1.0.200"
        );
    }
}
