//! Candidate command miners (FR-011).
//!
//! Each miner extracts *candidate* shell commands from one class of
//! repository metadata. Extraction is intentionally shallow — a generic
//! shell-command miner plus small format parsers, per §13.4 — because
//! candidates are validated experimentally, never trusted.

use crate::{ActionKind, ActionSource};
use ovid_repository::RepoSnapshot;

/// A mined candidate before scoring.
pub struct MinedCommand {
    pub command: Vec<String>,
    pub source: ActionSource,
    pub source_file: Option<String>,
    pub kind_hint: Option<ActionKind>,
}

const MAX_DOC_BYTES: u64 = 1024 * 1024;

pub fn mine_all(snapshot: &RepoSnapshot) -> Vec<MinedCommand> {
    let mut out = Vec::new();
    mine_github_actions(snapshot, &mut out);
    mine_package_scripts(snapshot, &mut out);
    mine_makefiles(snapshot, &mut out);
    mine_dockerfiles(snapshot, &mut out);
    mine_docs(snapshot, &mut out);
    out
}

/// Split a shell line into argv, respecting simple quoting. Lines with
/// shell control structure (pipes, subshells, heredocs) are kept as
/// `sh -c` commands so the executor can still run them under supervision.
fn shell_split(line: &str) -> Option<Vec<String>> {
    let line = line.trim().trim_start_matches("$ ").trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let complex = ['|', '&', ';', '<', '>', '`', '(', ')'];
    if line.contains(|c| complex.contains(&c)) || line.contains("$(") {
        return Some(vec!["sh".into(), "-c".into(), line.to_string()]);
    }
    let mut args: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for ch in line.chars() {
        match (ch, quote) {
            ('"', None) | ('\'', None) => quote = Some(ch),
            (c, Some(q)) if c == q => quote = None,
            (c, Some(_)) => current.push(c),
            (c, None) if c.is_whitespace() => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            (c, None) => current.push(c),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    if args.is_empty() {
        None
    } else {
        Some(args)
    }
}

/// GitHub Actions: every `run:` step. YAML is parsed generically — we walk
/// the tree for `run` keys rather than modeling the workflow schema.
fn mine_github_actions(snapshot: &RepoSnapshot, out: &mut Vec<MinedCommand>) {
    let workflow_files: Vec<String> = snapshot
        .files
        .keys()
        .filter(|p| {
            (p.starts_with(".github/workflows/") || p.starts_with(".gitlab-ci"))
                && (p.ends_with(".yml") || p.ends_with(".yaml"))
        })
        .cloned()
        .collect();
    for path in workflow_files {
        let Ok(text) = snapshot.read_file(&path, MAX_DOC_BYTES) else { continue };
        let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&text) else { continue };
        let mut runs = Vec::new();
        collect_run_values(&value, &mut runs);
        for script in runs {
            for line in script.lines() {
                if let Some(command) = shell_split(line) {
                    out.push(MinedCommand {
                        command,
                        source: ActionSource::CiFile,
                        source_file: Some(path.clone()),
                        kind_hint: None,
                    });
                }
            }
        }
    }
}

fn collect_run_values(value: &serde_yaml::Value, out: &mut Vec<String>) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (key, val) in map {
                if key.as_str() == Some("run") {
                    if let Some(script) = val.as_str() {
                        out.push(script.to_string());
                    }
                } else {
                    collect_run_values(val, out);
                }
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                collect_run_values(item, out);
            }
        }
        _ => {}
    }
}

/// package.json scripts: `npm run <name>` for conventional names.
fn mine_package_scripts(snapshot: &RepoSnapshot, out: &mut Vec<MinedCommand>) {
    for path in snapshot.find_files_named("package.json") {
        if path.contains("node_modules/") {
            continue;
        }
        let Ok(text) = snapshot.read_file(path, MAX_DOC_BYTES) else { continue };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        let Some(scripts) = value.get("scripts").and_then(|s| s.as_object()) else { continue };
        for (name, _) in scripts {
            let kind_hint = match name.as_str() {
                "test" => Some(ActionKind::Test),
                "build" => Some(ActionKind::Build),
                "start" | "serve" | "dev" => Some(ActionKind::Start),
                _ => continue, // only conventional entrypoints
            };
            let command = if name == "test" || name == "start" {
                vec!["npm".into(), name.clone()]
            } else {
                vec!["npm".into(), "run".into(), name.clone()]
            };
            out.push(MinedCommand {
                command,
                source: ActionSource::PackageScript,
                source_file: Some(path.to_string()),
                kind_hint,
            });
        }
    }
}

/// Makefile targets: conventional build/test/check targets only.
fn mine_makefiles(snapshot: &RepoSnapshot, out: &mut Vec<MinedCommand>) {
    for name in ["Makefile", "makefile", "GNUmakefile", "justfile"] {
        for path in snapshot.find_files_named(name) {
            let Ok(text) = snapshot.read_file(path, MAX_DOC_BYTES) else { continue };
            let runner = if name == "justfile" { "just" } else { "make" };
            for line in text.lines() {
                let Some((target, _)) = line.split_once(':') else { continue };
                let target = target.trim();
                if line.starts_with(['\t', ' ', '.', '#']) || target.contains(['=', '$', ' ']) {
                    continue;
                }
                let kind_hint = match target {
                    "test" | "check" => Some(ActionKind::Test),
                    "build" | "all" | "compile" => Some(ActionKind::Build),
                    "install" | "deps" => Some(ActionKind::DependencyInstall),
                    "run" | "start" | "serve" => Some(ActionKind::Start),
                    _ => continue,
                };
                out.push(MinedCommand {
                    command: vec![runner.into(), target.into()],
                    source: ActionSource::Makefile,
                    source_file: Some(path.to_string()),
                    kind_hint,
                });
            }
        }
    }
}

/// Dockerfiles: ENTRYPOINT/CMD as start candidates (container metadata).
fn mine_dockerfiles(snapshot: &RepoSnapshot, out: &mut Vec<MinedCommand>) {
    for path in snapshot.find_files_named("Dockerfile") {
        let Ok(text) = snapshot.read_file(path, MAX_DOC_BYTES) else { continue };
        for line in text.lines() {
            let line = line.trim();
            let Some(rest) = line
                .strip_prefix("ENTRYPOINT")
                .or_else(|| line.strip_prefix("CMD"))
                .map(str::trim)
            else {
                continue;
            };
            let command = if rest.starts_with('[') {
                serde_json::from_str::<Vec<String>>(rest).ok()
            } else {
                shell_split(rest)
            };
            if let Some(command) = command {
                out.push(MinedCommand {
                    command,
                    source: ActionSource::ContainerMetadata,
                    source_file: Some(path.to_string()),
                    kind_hint: Some(ActionKind::Start),
                });
            }
        }
    }
}

/// Documentation shell blocks: fenced ```sh/bash/console blocks in README
/// and docs. Lowest-confidence source (§13.4 item 7).
fn mine_docs(snapshot: &RepoSnapshot, out: &mut Vec<MinedCommand>) {
    let doc_files: Vec<String> = snapshot
        .files
        .keys()
        .filter(|p| {
            let base = p.rsplit('/').next().unwrap_or(p).to_lowercase();
            base == "readme.md" || base == "contributing.md" || base == "development.md"
        })
        .cloned()
        .collect();
    for path in doc_files {
        let Ok(text) = snapshot.read_file(&path, MAX_DOC_BYTES) else { continue };
        let mut in_shell_block = false;
        for line in text.lines() {
            if let Some(fence) = line.trim().strip_prefix("```") {
                let lang = fence.trim().to_lowercase();
                in_shell_block = !in_shell_block
                    && matches!(lang.as_str(), "sh" | "bash" | "shell" | "console" | "zsh");
                continue;
            }
            if in_shell_block {
                // In console blocks only `$ `-prefixed lines are commands;
                // in plain blocks any non-comment line is a candidate.
                let candidate = line.trim();
                if candidate.starts_with("$ ") || !candidate.starts_with('$') {
                    if let Some(command) = shell_split(candidate) {
                        out.push(MinedCommand {
                            command,
                            source: ActionSource::Documentation,
                            source_file: Some(path.clone()),
                            kind_hint: None,
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_split_handles_quotes_and_complex_lines() {
        assert_eq!(
            shell_split(r#"cargo test --package "my crate""#).unwrap(),
            vec!["cargo", "test", "--package", "my crate"]
        );
        assert_eq!(
            shell_split("make && make test").unwrap(),
            vec!["sh", "-c", "make && make test"]
        );
        assert_eq!(shell_split("# a comment"), None);
        assert_eq!(shell_split("$ npm test").unwrap(), vec!["npm", "test"]);
    }
}
