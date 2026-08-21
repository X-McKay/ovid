//! Rust: `Cargo.toml` (declared) + `Cargo.lock` (resolved).

use super::{read_or_warn, Scanner};
use crate::{purl, Component, InventoryReport, Scope};
use ovid_core::{ClaimState, ClaimStates};
use ovid_repository::RepoSnapshot;

pub struct CargoScanner;

impl Scanner for CargoScanner {
    fn name(&self) -> &'static str {
        "cargo"
    }

    fn scan(&self, snapshot: &RepoSnapshot, report: &mut InventoryReport) {
        for path in snapshot.find_files_named("Cargo.toml") {
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_manifest(&text, &path, report);
            }
        }
        for path in snapshot.find_files_named("Cargo.lock") {
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_lockfile(&text, &path, report);
            }
        }
    }
}

fn dep_component(name: &str, spec: &toml::Value, scope: Scope, source: &str) -> Component {
    // Specs are either a version string or a table with optional `version`,
    // `path`, `git`, `package` (rename) keys.
    let real_name = match spec {
        toml::Value::Table(t) => {
            t.get("package").and_then(|v| v.as_str()).unwrap_or(name).to_string()
        }
        _ => name.to_string(),
    };
    Component {
        purl: purl("cargo", &real_name, None),
        name: real_name,
        // Manifest version requirements are ranges, not resolutions; the
        // lockfile supplies the concrete version. Recording the range as a
        // version would conflate declared with resolved (§6.3).
        version: None,
        ecosystem: "cargo".into(),
        scope,
        direct: true,
        states: ClaimStates::default().with(ClaimState::Declared),
        source_file: source.to_string(),
    }
}

fn scan_manifest(text: &str, source: &str, report: &mut InventoryReport) {
    let Ok(value) = text.parse::<toml::Value>() else {
        report.warnings.push(format!("unparseable Cargo.toml at {source}"));
        return;
    };
    let sections = [
        ("dependencies", Scope::Runtime),
        ("dev-dependencies", Scope::Dev),
        ("build-dependencies", Scope::Build),
    ];
    for (section, scope) in sections {
        // Plain and workspace-level sections.
        for table in [
            value.get(section),
            value.get("workspace").and_then(|w| w.get(section)),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(deps) = table.as_table() {
                for (name, spec) in deps {
                    report.components.push(dep_component(name, spec, scope, source));
                }
            }
        }
    }
}

fn scan_lockfile(text: &str, source: &str, report: &mut InventoryReport) {
    let Ok(value) = text.parse::<toml::Value>() else {
        report.warnings.push(format!("unparseable Cargo.lock at {source}"));
        return;
    };
    let Some(packages) = value.get("package").and_then(|p| p.as_array()) else { return };
    for package in packages {
        let (Some(name), Some(version)) = (
            package.get("name").and_then(|v| v.as_str()),
            package.get("version").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        report.components.push(Component {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: "cargo".into(),
            purl: purl("cargo", name, Some(version)),
            scope: Scope::Unknown,
            direct: false,
            states: ClaimStates::default().with(ClaimState::Resolved),
            source_file: source.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::scan;
    use ovid_repository::{acquire, AcquireOptions, RepositorySource};

    #[test]
    fn manifest_and_lockfile_merge() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
renamed = { package = "actual-crate", version = "2" }

[dev-dependencies]
tempfile = "3"
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Cargo.lock"),
            r#"version = 3

[[package]]
name = "serde"
version = "1.0.200"

[[package]]
name = "itoa"
version = "1.0.11"
"#,
        )
        .unwrap();
        let snapshot = acquire(
            &RepositorySource::parse(dir.path().to_str().unwrap(), None),
            &AcquireOptions::new(dir.path().join(".work")),
        )
        .unwrap();
        let report = scan(&snapshot);
        // serde: declared (manifest) + resolved (lock) merged onto the
        // pinned entry.
        let serde = report
            .components
            .iter()
            .find(|c| c.name == "serde" && c.version.as_deref() == Some("1.0.200"))
            .expect("merged serde entry");
        assert!(serde.states.declared && serde.states.resolved && serde.direct);
        // itoa: lockfile-only, transitive.
        let itoa = report.components.iter().find(|c| c.name == "itoa").unwrap();
        assert!(!itoa.states.declared && itoa.states.resolved && !itoa.direct);
        // rename respected.
        assert!(report.components.iter().any(|c| c.name == "actual-crate"));
        // dev dep declared but unpinned.
        let tf = report.components.iter().find(|c| c.name == "tempfile").unwrap();
        assert_eq!(tf.scope, crate::Scope::Dev);
    }
}
