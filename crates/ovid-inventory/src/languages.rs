//! Language detection by file extension, weighted by bytes.
//!
//! Produces the `inventory.languages` manifest section. This is inventory
//! metadata, not a capability claim (§6.9): runner support is reported
//! separately by the pack registry.

use ovid_repository::RepoSnapshot;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct LanguageStat {
    pub name: String,
    /// Fraction of recognized source bytes, in [0, 1], rounded to 4 places.
    pub estimated_fraction: f64,
    pub file_count: usize,
}

fn language_for_extension(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "rs" => "rust",
        "py" | "pyi" => "python",
        "js" | "mjs" | "cjs" | "jsx" => "javascript",
        "ts" | "tsx" | "mts" | "cts" => "typescript",
        "go" => "go",
        "java" => "java",
        "kt" | "kts" => "kotlin",
        "scala" | "sc" => "scala",
        "rb" => "ruby",
        "php" => "php",
        "c" | "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => "cpp",
        "cs" => "csharp",
        "zig" => "zig",
        "pl" | "pm" => "perl",
        "sh" | "bash" | "zsh" => "shell",
        "swift" => "swift",
        "lua" => "lua",
        "ex" | "exs" => "elixir",
        _ => return None,
    })
}

/// Common vendored/generated directories excluded from language stats so a
/// vendored dependency tree does not dominate the profile.
fn is_vendored(path: &str) -> bool {
    let prefixes =
        ["node_modules/", "vendor/", "target/", "dist/", "build/", ".venv/", "venv/"];
    prefixes.iter().any(|p| path.starts_with(p) || path.contains(&format!("/{p}")))
}

pub fn detect_languages(snapshot: &RepoSnapshot) -> Vec<LanguageStat> {
    let mut bytes: BTreeMap<&'static str, (u64, usize)> = BTreeMap::new();
    let mut total: u64 = 0;
    for (path, entry) in &snapshot.files {
        if is_vendored(path) {
            continue;
        }
        let Some(ext) = path.rsplit('.').next().filter(|e| !e.contains('/')) else { continue };
        let Some(lang) = language_for_extension(&ext.to_lowercase()) else { continue };
        let slot = bytes.entry(lang).or_insert((0, 0));
        slot.0 += entry.size;
        slot.1 += 1;
        total += entry.size;
    }
    let mut stats: Vec<LanguageStat> = bytes
        .into_iter()
        .map(|(name, (size, count))| LanguageStat {
            name: name.to_string(),
            estimated_fraction: if total == 0 {
                0.0
            } else {
                (size as f64 / total as f64 * 10_000.0).round() / 10_000.0
            },
            file_count: count,
        })
        .collect();
    stats.sort_by(|a, b| {
        b.estimated_fraction
            .partial_cmp(&a.estimated_fraction)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.name.cmp(&b.name))
    });
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovid_repository::{acquire, AcquireOptions, RepositorySource};

    #[test]
    fn detects_and_ranks_languages() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/main.rs"), "fn main() {}\n".repeat(50)).unwrap();
        std::fs::write(dir.path().join("helper.py"), "print('x')\n").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules/dep")).unwrap();
        std::fs::write(dir.path().join("node_modules/dep/index.js"), "x".repeat(9999)).unwrap();
        let snapshot = acquire(
            &RepositorySource::parse(dir.path().to_str().unwrap(), None),
            &AcquireOptions::new(dir.path().join(".work")),
        )
        .unwrap();
        let stats = detect_languages(&snapshot);
        assert_eq!(stats[0].name, "rust");
        // Vendored node_modules must not appear.
        assert!(!stats.iter().any(|s| s.name == "javascript"));
        let sum: f64 = stats.iter().map(|s| s.estimated_fraction).sum();
        assert!((sum - 1.0).abs() < 0.01, "fractions should sum to ~1: {sum}");
    }
}
