//! Python: `pyproject.toml` / `requirements*.txt` (declared),
//! `poetry.lock` / `uv.lock` (resolved).

use super::{read_or_warn, Scanner};
use crate::{purl, Component, InventoryReport, Scope};
use ovid_core::{ClaimState, ClaimStates};
use ovid_repository::RepoSnapshot;

pub struct PythonScanner;

impl Scanner for PythonScanner {
    fn name(&self) -> &'static str {
        "python"
    }

    fn scan(&self, snapshot: &RepoSnapshot, report: &mut InventoryReport) {
        for path in snapshot.find_files_named("pyproject.toml") {
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_pyproject(&text, &path, report);
            }
        }
        let requirement_files: Vec<String> = snapshot
            .files
            .keys()
            .filter(|p| {
                let base = p.rsplit('/').next().unwrap_or(p);
                (base.starts_with("requirements") && base.ends_with(".txt"))
                    || (p.contains("requirements/") && base.ends_with(".txt"))
            })
            .cloned()
            .collect();
        for path in requirement_files {
            let scope = requirements_scope(&path);
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_requirements(&text, &path, scope, report);
            }
        }
        for lock in ["poetry.lock", "uv.lock"] {
            for path in snapshot.find_files_named(lock) {
                let path = path.to_string();
                if let Some(text) = read_or_warn(snapshot, &path, report) {
                    scan_toml_lock(&text, &path, report);
                }
            }
        }
    }
}

fn declared(name: &str, version: Option<&str>, scope: Scope, source: &str) -> Component {
    let name = name.to_lowercase().replace('_', "-");
    Component {
        purl: purl("pypi", &name, version),
        name,
        version: version.map(String::from),
        ecosystem: "pypi".into(),
        scope,
        direct: true,
        states: ClaimStates::default().with(ClaimState::Declared),
        source_file: source.to_string(),
    }
}

/// Split a PEP 508 requirement like `requests[socks]>=2.31 ; python_version…`
/// into (name, exact-version-if-pinned).
fn parse_requirement(line: &str) -> Option<(String, Option<String>)> {
    let line = line.split(&[';', '#'][..]).next()?.trim();
    if line.is_empty() || line.starts_with('-') {
        return None; // options like -r, -e, --hash
    }
    let name_end = line
        .find(|c: char| !(c.is_alphanumeric() || c == '-' || c == '_' || c == '.'))
        .unwrap_or(line.len());
    let (name, rest) = line.split_at(name_end);
    if name.is_empty() {
        return None;
    }
    let rest = rest.trim_start_matches(|c: char| {
        c == '[' || c == ']' || c.is_alphanumeric() || c == ',' || c == '-' || c == '_'
    });
    // Only `==x.y.z` counts as a pin; ranges stay versionless (§6.3).
    let version = rest
        .trim()
        .strip_prefix("==")
        .map(|v| v.trim().trim_end_matches(".*").to_string());
    Some((name.to_string(), version))
}

/// Infer scope from a requirements file's name: `requirements-dev.txt`,
/// `requirements/tests.txt`, docs/lint/typing variants are development
/// declarations, not runtime dependencies.
fn requirements_scope(path: &str) -> Scope {
    let lowered = path.to_lowercase();
    let dev_markers = [
        "dev", "test", "docs", "doc", "lint", "typing", "style", "ci", "build",
    ];
    let base = lowered.rsplit('/').next().unwrap_or(&lowered);
    if dev_markers.iter().any(|marker| base.contains(marker)) {
        Scope::Dev
    } else {
        Scope::Runtime
    }
}

fn scan_requirements(text: &str, source: &str, scope: Scope, report: &mut InventoryReport) {
    for line in text.lines() {
        if let Some((name, version)) = parse_requirement(line) {
            report
                .components
                .push(declared(&name, version.as_deref(), scope, source));
        }
    }
}

fn scan_pyproject(text: &str, source: &str, report: &mut InventoryReport) {
    let Ok(value) = text.parse::<toml::Value>() else {
        report
            .warnings
            .push(format!("unparseable pyproject.toml at {source}"));
        return;
    };
    // PEP 621: [project] dependencies / optional-dependencies.
    if let Some(project) = value.get("project") {
        if let Some(deps) = project.get("dependencies").and_then(|d| d.as_array()) {
            for dep in deps.iter().filter_map(|d| d.as_str()) {
                if let Some((name, version)) = parse_requirement(dep) {
                    report.components.push(declared(
                        &name,
                        version.as_deref(),
                        Scope::Runtime,
                        source,
                    ));
                }
            }
        }
        if let Some(optional) = project
            .get("optional-dependencies")
            .and_then(|d| d.as_table())
        {
            for deps in optional.values().filter_map(|d| d.as_array()) {
                for dep in deps.iter().filter_map(|d| d.as_str()) {
                    if let Some((name, version)) = parse_requirement(dep) {
                        report.components.push(declared(
                            &name,
                            version.as_deref(),
                            Scope::Dev,
                            source,
                        ));
                    }
                }
            }
        }
    }
    // Poetry: [tool.poetry.dependencies] table.
    if let Some(deps) = value
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_table())
    {
        for name in deps.keys().filter(|n| n.as_str() != "python") {
            report
                .components
                .push(declared(name, None, Scope::Runtime, source));
        }
    }
}

/// poetry.lock and uv.lock share the `[[package]] name/version` TOML shape.
fn scan_toml_lock(text: &str, source: &str, report: &mut InventoryReport) {
    let Ok(value) = text.parse::<toml::Value>() else {
        report
            .warnings
            .push(format!("unparseable lockfile at {source}"));
        return;
    };
    let Some(packages) = value.get("package").and_then(|p| p.as_array()) else {
        return;
    };
    for package in packages {
        let (Some(name), Some(version)) = (
            package.get("name").and_then(|v| v.as_str()),
            package.get("version").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let name = name.to_lowercase().replace('_', "-");
        report.components.push(Component {
            purl: purl("pypi", &name, Some(version)),
            name,
            version: Some(version.to_string()),
            ecosystem: "pypi".into(),
            scope: Scope::Unknown,
            direct: false,
            states: ClaimStates::default().with(ClaimState::Resolved),
            source_file: source.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::parse_requirement;
    use crate::scan;
    use ovid_repository::{acquire, AcquireOptions, RepositorySource};

    #[test]
    fn requirement_parsing() {
        assert_eq!(
            parse_requirement("requests==2.31.0"),
            Some(("requests".into(), Some("2.31.0".into())))
        );
        assert_eq!(
            parse_requirement("flask>=2,<3"),
            Some(("flask".into(), None))
        );
        assert_eq!(
            parse_requirement("uvicorn[standard]==0.29.0 ; python_version >= '3.8'"),
            Some(("uvicorn".into(), Some("0.29.0".into())))
        );
        assert_eq!(parse_requirement("# comment"), None);
        assert_eq!(parse_requirement("-r other.txt"), None);
    }

    #[test]
    fn requirements_scope_inference() {
        use super::requirements_scope;
        use crate::Scope;
        assert_eq!(requirements_scope("requirements.txt"), Scope::Runtime);
        assert_eq!(requirements_scope("requirements/base.txt"), Scope::Runtime);
        assert_eq!(requirements_scope("requirements-dev.txt"), Scope::Dev);
        assert_eq!(requirements_scope("requirements/tests.txt"), Scope::Dev);
        assert_eq!(requirements_scope("docs/requirements-docs.txt"), Scope::Dev);
    }

    #[test]
    fn pyproject_pep621_and_poetry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            r#"[project]
name = "svc"
dependencies = ["fastapi>=0.100", "SQLAlchemy==2.0.30"]

[tool.poetry.dependencies]
python = "^3.11"
httpx = "^0.27"
"#,
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
            .any(|c| c.name == "fastapi" && c.version.is_none()));
        assert!(report
            .components
            .iter()
            .any(|c| c.name == "sqlalchemy" && c.version.as_deref() == Some("2.0.30")));
        assert!(report.components.iter().any(|c| c.name == "httpx"));
        assert!(!report.components.iter().any(|c| c.name == "python"));
    }
}
