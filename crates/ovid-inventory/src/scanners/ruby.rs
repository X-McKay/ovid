//! Ruby: `Gemfile` (declared) + `Gemfile.lock` (resolved).

use super::{read_or_warn, Scanner};
use crate::{purl, Component, InventoryReport, Scope};
use ovid_core::{ClaimState, ClaimStates};
use ovid_repository::RepoSnapshot;
use regex::Regex;
use std::sync::OnceLock;

pub struct RubyScanner;

impl Scanner for RubyScanner {
    fn name(&self) -> &'static str {
        "ruby"
    }

    fn scan(&self, snapshot: &RepoSnapshot, report: &mut InventoryReport) {
        for path in snapshot.find_files_named("Gemfile") {
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_gemfile(&text, &path, report);
            }
        }
        for path in snapshot.find_files_named("Gemfile.lock") {
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_gemfile_lock(&text, &path, report);
            }
        }
    }
}

fn gem_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?m)^\s*gem\s+["']([\w\-]+)["']"#).expect("gem regex"))
}

fn scan_gemfile(text: &str, source: &str, report: &mut InventoryReport) {
    for caps in gem_regex().captures_iter(text) {
        report.components.push(Component {
            name: caps[1].to_string(),
            version: None,
            ecosystem: "gem".into(),
            purl: purl("gem", &caps[1], None),
            scope: Scope::Runtime,
            direct: true,
            states: ClaimStates::default().with(ClaimState::Declared),
            source_file: source.to_string(),
        });
    }
}

/// Gemfile.lock `specs:` entries: four-space indent = a resolved gem,
/// deeper indents are its dependency ranges.
fn scan_gemfile_lock(text: &str, source: &str, report: &mut InventoryReport) {
    let mut in_specs = false;
    for line in text.lines() {
        if line.trim_end() == "  specs:" {
            in_specs = true;
            continue;
        }
        if in_specs {
            if !line.starts_with("    ") {
                in_specs = false;
                continue;
            }
            if line.starts_with("      ") {
                continue; // dependency range line, not a resolution
            }
            let entry = line.trim();
            if let Some((name, version)) = entry.split_once(" (") {
                let version = version.trim_end_matches(')');
                report.components.push(Component {
                    name: name.to_string(),
                    version: Some(version.to_string()),
                    ecosystem: "gem".into(),
                    purl: purl("gem", name, Some(version)),
                    scope: Scope::Unknown,
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
    fn gemfile_and_lock() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Gemfile"), "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\ngem \"pg\"\n").unwrap();
        std::fs::write(
            dir.path().join("Gemfile.lock"),
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    pg (1.5.6)\n    rails (7.1.3)\n      actionpack (= 7.1.3)\n",
        )
        .unwrap();
        let snapshot = acquire(
            &RepositorySource::parse(dir.path().to_str().unwrap(), None),
            &AcquireOptions::new(dir.path().join(".work")),
        )
        .unwrap();
        let report = scan(&snapshot);
        let rails = report
            .components
            .iter()
            .find(|c| c.name == "rails" && c.version.as_deref() == Some("7.1.3"))
            .unwrap();
        assert!(rails.states.declared && rails.states.resolved);
        // The `actionpack (= 7.1.3)` range line must not be parsed as a gem.
        assert!(!report.components.iter().any(|c| c.name == "actionpack"));
    }
}
