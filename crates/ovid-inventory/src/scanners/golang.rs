//! Go: `go.mod` (declared) + `go.sum` (resolution evidence).

use super::{read_or_warn, Scanner};
use crate::{purl, Component, InventoryReport, Scope};
use ovid_core::{ClaimState, ClaimStates};
use ovid_repository::RepoSnapshot;

pub struct GoScanner;

impl Scanner for GoScanner {
    fn name(&self) -> &'static str {
        "go"
    }

    fn scan(&self, snapshot: &RepoSnapshot, report: &mut InventoryReport) {
        for path in snapshot.find_files_named("go.mod") {
            if path.contains("vendor/") {
                continue;
            }
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_go_mod(&text, &path, report);
            }
        }
        for path in snapshot.find_files_named("go.sum") {
            if path.contains("vendor/") {
                continue;
            }
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_go_sum(&text, &path, report);
            }
        }
    }
}

fn component(
    module: &str,
    version: &str,
    direct: bool,
    state: ClaimState,
    source: &str,
) -> Component {
    Component {
        name: module.to_string(),
        version: Some(version.to_string()),
        ecosystem: "golang".into(),
        purl: purl("golang", module, Some(version)),
        scope: if direct {
            Scope::Runtime
        } else {
            Scope::Unknown
        },
        direct,
        states: ClaimStates::default().with(state),
        source_file: source.to_string(),
    }
}

fn scan_go_mod(text: &str, source: &str, report: &mut InventoryReport) {
    let mut in_require_block = false;
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("require (") {
            in_require_block = true;
            continue;
        }
        if in_require_block && line == ")" {
            in_require_block = false;
            continue;
        }
        let entry = if in_require_block {
            Some(line)
        } else {
            line.strip_prefix("require ").map(str::trim)
        };
        if let Some(entry) = entry {
            let mut parts = entry.split_whitespace();
            if let (Some(module), Some(version)) = (parts.next(), parts.next()) {
                // `// indirect` markers were stripped with the comment; a
                // module in go.mod without the marker is direct. We already
                // dropped comments, so treat all as declared and mark
                // directness from the raw line.
                let direct = !raw.contains("// indirect");
                report.components.push(component(
                    module,
                    version,
                    direct,
                    ClaimState::Declared,
                    source,
                ));
            }
        }
    }
}

fn scan_go_sum(text: &str, source: &str, report: &mut InventoryReport) {
    let mut seen = std::collections::BTreeSet::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(module), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        let version = version.trim_end_matches("/go.mod");
        if seen.insert((module.to_string(), version.to_string())) {
            report.components.push(component(
                module,
                version,
                false,
                ClaimState::Resolved,
                source,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::scan;
    use ovid_repository::{acquire, AcquireOptions, RepositorySource};

    #[test]
    fn go_mod_and_sum() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("go.mod"),
            "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.10.0\n\tgolang.org/x/sys v0.20.0 // indirect\n)\n\nrequire github.com/lib/pq v1.10.9\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("go.sum"),
            "github.com/gin-gonic/gin v1.10.0 h1:xx\ngithub.com/gin-gonic/gin v1.10.0/go.mod h1:yy\n",
        )
        .unwrap();
        let snapshot = acquire(
            &RepositorySource::parse(dir.path().to_str().unwrap(), None),
            &AcquireOptions::new(dir.path().join(".work")),
        )
        .unwrap();
        let report = scan(&snapshot);
        let gin = report
            .components
            .iter()
            .find(|c| c.name == "github.com/gin-gonic/gin")
            .unwrap();
        assert!(gin.states.declared && gin.states.resolved && gin.direct);
        let sys = report
            .components
            .iter()
            .find(|c| c.name == "golang.org/x/sys")
            .unwrap();
        assert!(!sys.direct, "indirect modules must not be direct");
        assert!(report
            .components
            .iter()
            .any(|c| c.name == "github.com/lib/pq"));
    }
}
