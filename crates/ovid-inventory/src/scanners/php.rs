//! PHP: `composer.json` (declared) + `composer.lock` (resolved).

use super::{read_or_warn, Scanner};
use crate::{purl, Component, InventoryReport, Scope};
use ovid_core::{ClaimState, ClaimStates};
use ovid_repository::RepoSnapshot;
use serde_json::Value;

pub struct PhpScanner;

impl Scanner for PhpScanner {
    fn name(&self) -> &'static str {
        "php"
    }

    fn scan(&self, snapshot: &RepoSnapshot, report: &mut InventoryReport) {
        for path in snapshot.find_files_named("composer.json") {
            if path.contains("vendor/") {
                continue;
            }
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_composer_json(&text, &path, report);
            }
        }
        for path in snapshot.find_files_named("composer.lock") {
            if path.contains("vendor/") {
                continue;
            }
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_composer_lock(&text, &path, report);
            }
        }
    }
}

fn scan_composer_json(text: &str, source: &str, report: &mut InventoryReport) {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        report
            .warnings
            .push(format!("unparseable composer.json at {source}"));
        return;
    };
    for (section, scope) in [("require", Scope::Runtime), ("require-dev", Scope::Dev)] {
        if let Some(deps) = value.get(section).and_then(|d| d.as_object()) {
            for name in deps.keys() {
                // Platform requirements like `php` or `ext-json` are not
                // packagist packages.
                if name == "php" || name.starts_with("ext-") || name.starts_with("lib-") {
                    continue;
                }
                report.components.push(Component {
                    name: name.clone(),
                    version: None,
                    ecosystem: "composer".into(),
                    purl: purl("composer", name, None),
                    scope,
                    direct: true,
                    states: ClaimStates::default().with(ClaimState::Declared),
                    source_file: source.to_string(),
                });
            }
        }
    }
}

fn scan_composer_lock(text: &str, source: &str, report: &mut InventoryReport) {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        report
            .warnings
            .push(format!("unparseable composer.lock at {source}"));
        return;
    };
    for section in ["packages", "packages-dev"] {
        if let Some(packages) = value.get(section).and_then(|p| p.as_array()) {
            for package in packages {
                let (Some(name), Some(version)) = (
                    package.get("name").and_then(|v| v.as_str()),
                    package.get("version").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                let version = version.trim_start_matches('v');
                report.components.push(Component {
                    name: name.to_string(),
                    version: Some(version.to_string()),
                    ecosystem: "composer".into(),
                    purl: purl("composer", name, Some(version)),
                    scope: if section == "packages-dev" {
                        Scope::Dev
                    } else {
                        Scope::Unknown
                    },
                    direct: false,
                    states: ClaimStates::default().with(ClaimState::Resolved),
                    source_file: source.to_string(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::scan;
    use ovid_repository::{acquire, AcquireOptions, RepositorySource};

    #[test]
    fn composer_json_and_lock() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("composer.json"),
            r#"{"require": {"php": ">=8.1", "ext-json": "*", "monolog/monolog": "^3.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("composer.lock"),
            r#"{"packages": [{"name": "monolog/monolog", "version": "v3.6.0"}]}"#,
        )
        .unwrap();
        let snapshot = acquire(
            &RepositorySource::parse(dir.path().to_str().unwrap(), None),
            &AcquireOptions::new(dir.path().join(".work")),
        )
        .unwrap();
        let report = scan(&snapshot);
        let monolog = report
            .components
            .iter()
            .find(|c| c.name == "monolog/monolog" && c.version.as_deref() == Some("3.6.0"))
            .unwrap();
        assert!(monolog.states.declared && monolog.states.resolved);
        assert!(!report
            .components
            .iter()
            .any(|c| c.name == "php" || c.name == "ext-json"));
    }
}
