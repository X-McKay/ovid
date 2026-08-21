//! Node.js: `package.json` (declared) + `package-lock.json` /
//! `pnpm-lock.yaml` / `yarn.lock` (resolved).

use super::{read_or_warn, Scanner};
use crate::{purl, Component, InventoryReport, Scope};
use ovid_core::{ClaimState, ClaimStates};
use ovid_repository::RepoSnapshot;
use serde_json::Value;

pub struct NodeScanner;

impl Scanner for NodeScanner {
    fn name(&self) -> &'static str {
        "node"
    }

    fn scan(&self, snapshot: &RepoSnapshot, report: &mut InventoryReport) {
        for path in snapshot.find_files_named("package.json") {
            // Vendored packages inside node_modules are artifacts of an
            // installed tree, not declarations of this repository.
            if path.contains("node_modules/") {
                continue;
            }
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_package_json(&text, &path, report);
            }
        }
        for path in snapshot.find_files_named("package-lock.json") {
            if path.contains("node_modules/") {
                continue;
            }
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_package_lock(&text, &path, report);
            }
        }
        for path in snapshot.find_files_named("pnpm-lock.yaml") {
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_pnpm_lock(&text, &path, report);
            }
        }
        for path in snapshot.find_files_named("yarn.lock") {
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_yarn_lock(&text, &path, report);
            }
        }
    }
}

fn declared(name: &str, scope: Scope, source: &str) -> Component {
    Component {
        name: name.to_string(),
        version: None,
        ecosystem: "npm".into(),
        purl: purl("npm", name, None),
        scope,
        direct: true,
        states: ClaimStates::default().with(ClaimState::Declared),
        source_file: source.to_string(),
    }
}

fn resolved(name: &str, version: &str, source: &str) -> Component {
    Component {
        name: name.to_string(),
        version: Some(version.to_string()),
        ecosystem: "npm".into(),
        purl: purl("npm", name, Some(version)),
        scope: Scope::Unknown,
        direct: false,
        states: ClaimStates::default().with(ClaimState::Resolved),
        source_file: source.to_string(),
    }
}

fn scan_package_json(text: &str, source: &str, report: &mut InventoryReport) {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        report
            .warnings
            .push(format!("unparseable package.json at {source}"));
        return;
    };
    let sections = [
        ("dependencies", Scope::Runtime),
        ("devDependencies", Scope::Dev),
        ("optionalDependencies", Scope::Runtime),
    ];
    for (section, scope) in sections {
        if let Some(deps) = value.get(section).and_then(|d| d.as_object()) {
            for name in deps.keys() {
                report.components.push(declared(name, scope, source));
            }
        }
    }
}

/// npm lockfile v2/v3: `packages` maps `node_modules/<name>` paths to
/// `{version}`. v1 uses a nested `dependencies` map.
fn scan_package_lock(text: &str, source: &str, report: &mut InventoryReport) {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        report
            .warnings
            .push(format!("unparseable package-lock.json at {source}"));
        return;
    };
    if let Some(packages) = value.get("packages").and_then(|p| p.as_object()) {
        for (path, info) in packages {
            let Some(name) = path
                .rsplit("node_modules/")
                .next()
                .filter(|_| !path.is_empty())
            else {
                continue;
            };
            if path.is_empty() || !path.contains("node_modules/") {
                continue; // the root project entry
            }
            if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                report.components.push(resolved(name, version, source));
            }
        }
    } else if let Some(deps) = value.get("dependencies").and_then(|d| d.as_object()) {
        for (name, info) in deps {
            if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                report.components.push(resolved(name, version, source));
            }
        }
    }
}

/// pnpm lockfile: `packages` keys like `/name@version` or `/@scope/name@1.2.3`.
fn scan_pnpm_lock(text: &str, source: &str, report: &mut InventoryReport) {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(text) else {
        report
            .warnings
            .push(format!("unparseable pnpm-lock.yaml at {source}"));
        return;
    };
    let Some(packages) = value.get("packages").and_then(|p| p.as_mapping()) else {
        return;
    };
    for key in packages.keys() {
        let Some(key) = key.as_str() else { continue };
        let key = key.trim_start_matches('/');
        // Split at the last '@' that is not the scope prefix.
        if let Some(at) = key.rfind('@').filter(|&i| i > 0) {
            let (name, version) = key.split_at(at);
            let version = version.trim_start_matches('@');
            let version = version.split('(').next().unwrap_or(version); // strip peer suffixes
            report.components.push(resolved(name, version, source));
        }
    }
}

/// yarn.lock (v1): entries like `name@^1.0.0:` followed by
/// `  version "1.2.3"`.
fn scan_yarn_lock(text: &str, source: &str, report: &mut InventoryReport) {
    let mut current_name: Option<String> = None;
    for line in text.lines() {
        if !line.starts_with(' ') && line.trim_end().ends_with(':') {
            let head = line.trim_end().trim_end_matches(':');
            let first = head
                .split(',')
                .next()
                .unwrap_or(head)
                .trim()
                .trim_matches('"');
            // `@scope/name@range` or `name@range` — split at last '@'.
            current_name = first
                .rfind('@')
                .filter(|&i| i > 0)
                .map(|i| first[..i].to_string());
        } else if let Some(version) = line.trim().strip_prefix("version ") {
            if let Some(name) = current_name.take() {
                let version = version.trim().trim_matches('"');
                report.components.push(resolved(&name, version, source));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::scan;
    use ovid_repository::{acquire, AcquireOptions, RepositorySource};

    #[test]
    fn package_json_and_lock_v3() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"app","dependencies":{"express":"^4.19.0"},"devDependencies":{"@types/node":"^20"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("package-lock.json"),
            r#"{"lockfileVersion": 3, "packages": {
                "": {"name": "app"},
                "node_modules/express": {"version": "4.19.2"},
                "node_modules/accepts": {"version": "1.3.8"}
            }}"#,
        )
        .unwrap();
        let snapshot = acquire(
            &RepositorySource::parse(dir.path().to_str().unwrap(), None),
            &AcquireOptions::new(dir.path().join(".work")),
        )
        .unwrap();
        let report = scan(&snapshot);
        let express = report
            .components
            .iter()
            .find(|c| c.name == "express" && c.version.as_deref() == Some("4.19.2"))
            .unwrap();
        assert!(express.states.declared && express.states.resolved);
        assert!(report
            .components
            .iter()
            .any(|c| c.name == "accepts" && !c.direct));
        assert!(report.components.iter().any(|c| c.name == "@types/node"));
    }

    #[test]
    fn yarn_lock_parses_scoped_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("yarn.lock"),
            "# yarn lockfile v1\n\n\"@babel/core@^7.0.0\":\n  version \"7.24.0\"\n\nlodash@^4.17.21:\n  version \"4.17.21\"\n",
        )
        .unwrap();
        let snapshot = acquire(
            &RepositorySource::parse(dir.path().to_str().unwrap(), None),
            &AcquireOptions::new(dir.path().join(".work")),
        )
        .unwrap();
        let report = scan(&snapshot);
        assert!(report
            .components
            .iter()
            .any(|c| c.name == "@babel/core" && c.version.as_deref() == Some("7.24.0")));
        assert!(report.components.iter().any(|c| c.name == "lodash"));
    }
}
