//! Pack registry: embedded builtins plus directory loading.

use crate::schema::{Pack, PackBody, ProtocolPack, ResolverCandidate, RunnerRecipe, ServicePack, ToolResolverPack};
use ovid_core::OvidError;
use ovid_repository::RepoSnapshot;
use std::path::Path;

/// Built-in packs embedded from the repository `packs/` tree at compile
/// time, so the binary is useful with zero configuration.
const BUILTIN_PACKS: &[&str] = &[
    include_str!("../../../packs/runners/rust.yaml"),
    include_str!("../../../packs/runners/python.yaml"),
    include_str!("../../../packs/runners/node.yaml"),
    include_str!("../../../packs/runners/go.yaml"),
    include_str!("../../../packs/runners/java.yaml"),
    include_str!("../../../packs/runners/make.yaml"),
    include_str!("../../../packs/services/postgres.yaml"),
    include_str!("../../../packs/services/redis.yaml"),
    include_str!("../../../packs/services/generic-http.yaml"),
    include_str!("../../../packs/protocols/core-protocols.yaml"),
    include_str!("../../../packs/resolvers/system-tools.yaml"),
];

pub struct PackRegistry {
    packs: Vec<Pack>,
}

impl PackRegistry {
    /// Registry with only embedded builtin packs.
    pub fn builtin() -> Result<Self, OvidError> {
        let mut registry = PackRegistry { packs: Vec::new() };
        for source in BUILTIN_PACKS {
            registry.load_yaml_documents(source, "builtin")?;
        }
        Ok(registry)
    }

    /// Load additional packs from `*.yaml` files in a directory tree.
    /// Unlike builtins, a broken external pack is an error: silently
    /// skipping would mask a supply-chain problem (§15.7).
    pub fn load_dir(&mut self, dir: &Path) -> Result<usize, OvidError> {
        let mut loaded = 0;
        if !dir.exists() {
            return Ok(0);
        }
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            for entry in std::fs::read_dir(&current)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                    let text = std::fs::read_to_string(&path)?;
                    loaded += self.load_yaml_documents(&text, &path.display().to_string())?;
                }
            }
        }
        Ok(loaded)
    }

    /// Parse one YAML file that may contain multiple `---` documents.
    fn load_yaml_documents(&mut self, text: &str, origin: &str) -> Result<usize, OvidError> {
        let mut count = 0;
        for document in text.split("\n---") {
            let document = document.trim();
            if document.is_empty() || document.lines().all(|l| l.trim_start().starts_with('#')) {
                continue;
            }
            let pack = Pack::parse(document)
                .map_err(|e| OvidError::Pack(format!("{origin}: {e}")))?;
            self.packs.push(pack);
            count += 1;
        }
        Ok(count)
    }

    pub fn all(&self) -> &[Pack] {
        &self.packs
    }

    pub fn runner_recipes(&self) -> impl Iterator<Item = (&Pack, &RunnerRecipe)> {
        self.packs.iter().filter_map(|p| match &p.body {
            PackBody::RunnerRecipe(r) => Some((p, r)),
            _ => None,
        })
    }

    pub fn service_packs(&self) -> impl Iterator<Item = (&Pack, &ServicePack)> {
        self.packs.iter().filter_map(|p| match &p.body {
            PackBody::ServicePack(s) => Some((p, s)),
            _ => None,
        })
    }

    pub fn protocol_packs(&self) -> impl Iterator<Item = (&Pack, &ProtocolPack)> {
        self.packs.iter().filter_map(|p| match &p.body {
            PackBody::ProtocolPack(pr) => Some((p, pr)),
            _ => None,
        })
    }

    /// Runner recipes whose detection matches the snapshot, best-first
    /// (file matches beat extension matches; `make` sorts last as the
    /// generic fallback).
    pub fn detect_runners(&self, snapshot: &RepoSnapshot) -> Vec<(&Pack, &RunnerRecipe)> {
        let mut matches: Vec<(usize, &Pack, &RunnerRecipe)> = Vec::new();
        for (pack, recipe) in self.runner_recipes() {
            let file_hit = recipe
                .detect
                .any_files
                .iter()
                .any(|name| !snapshot.find_files_named(name).is_empty());
            let ext_hit = !recipe.detect.extensions.is_empty()
                && snapshot.files.keys().any(|p| {
                    p.rsplit('.')
                        .next()
                        .is_some_and(|e| recipe.detect.extensions.iter().any(|x| x == e))
                });
            if file_hit || ext_hit {
                let priority = match (pack.metadata.name.as_str(), file_hit) {
                    ("make", _) => 2,
                    (_, true) => 0,
                    (_, false) => 1,
                };
                matches.push((priority, pack, recipe));
            }
        }
        matches.sort_by_key(|(priority, pack, _)| (*priority, pack.metadata.name.clone()));
        matches.into_iter().map(|(_, pack, recipe)| (pack, recipe)).collect()
    }

    /// Resolve a missing executable to trusted candidates (§15.3).
    pub fn resolve_executable(&self, name: &str) -> Vec<&ResolverCandidate> {
        self.resolver_lookup(|r| r.executables.get(name))
    }

    /// Resolve a missing file by path suffix.
    pub fn resolve_file(&self, path: &str) -> Vec<&ResolverCandidate> {
        self.resolver_lookup(|r| {
            r.files.iter().find(|(suffix, _)| path.ends_with(suffix.as_str())).map(|(_, v)| v)
        })
    }

    fn resolver_lookup<'a>(
        &'a self,
        pick: impl Fn(&'a ToolResolverPack) -> Option<&'a Vec<ResolverCandidate>>,
    ) -> Vec<&'a ResolverCandidate> {
        let mut out: Vec<&ResolverCandidate> = self
            .packs
            .iter()
            .filter_map(|p| match &p.body {
                PackBody::ToolResolverPack(r) => pick(r),
                _ => None,
            })
            .flatten()
            .collect();
        out.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        out
    }

    /// Classify a destination by port and optional first bytes. Returns the
    /// protocol system name and the pack that matched. First-byte matches
    /// outrank port-only matches (§24.2: port alone carries little weight).
    pub fn classify_protocol(&self, port: u16, first_bytes: Option<&[u8]>) -> Option<(&Pack, &ProtocolPack)> {
        let mut best: Option<(u8, &Pack, &ProtocolPack)> = None;
        for (pack, protocol) in self.protocol_packs() {
            let port_hit = protocol.matcher.ports.contains(&port);
            let bytes_hit = first_bytes.is_some_and(|bytes| {
                protocol
                    .matcher
                    .first_bytes_ascii_prefix_any
                    .iter()
                    .any(|prefix| bytes.starts_with(prefix.as_bytes()))
            });
            let score = match (bytes_hit, port_hit) {
                (true, true) => 3,
                (true, false) => 2,
                (false, true) => 1,
                (false, false) => continue,
            };
            if best.map_or(true, |(s, _, _)| score > s) {
                best = Some((score, pack, protocol));
            }
        }
        best.map(|(_, pack, protocol)| (pack, protocol))
    }
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
        // Leak tempdir so the snapshot outlives this helper in tests.
        std::mem::forget(dir);
        snap
    }

    #[test]
    fn builtins_load_and_validate() {
        let registry = PackRegistry::builtin().unwrap();
        assert!(registry.runner_recipes().count() >= 6);
        assert!(registry.service_packs().count() >= 3);
        assert!(registry.protocol_packs().count() >= 8);
    }

    #[test]
    fn detects_rust_project_before_make() {
        let registry = PackRegistry::builtin().unwrap();
        let snapshot = snapshot_with(&[("Cargo.toml", "[package]"), ("Makefile", "all:")]);
        let runners = registry.detect_runners(&snapshot);
        assert_eq!(runners[0].0.metadata.name, "rust");
        assert!(runners.iter().any(|(p, _)| p.metadata.name == "make"));
    }

    #[test]
    fn resolves_missing_protoc() {
        let registry = PackRegistry::builtin().unwrap();
        let candidates = registry.resolve_executable("protoc");
        assert_eq!(candidates[0].package, "protobuf-compiler");
        assert!(candidates[0].confidence > candidates[1].confidence);
        assert!(registry.resolve_executable("no-such-tool-xyz").is_empty());
    }

    #[test]
    fn resolves_missing_header_by_suffix() {
        let registry = PackRegistry::builtin().unwrap();
        let candidates = registry.resolve_file("/usr/include/openssl/ssl.h");
        assert_eq!(candidates[0].package, "libssl-dev");
    }

    #[test]
    fn protocol_classification_prefers_bytes_over_port() {
        let registry = PackRegistry::builtin().unwrap();
        // Redis RESP bytes on a non-standard port beat the port-only HTTP
        // match on 8080.
        let (_, protocol) = registry.classify_protocol(8080, Some(b"*1\r\n$4\r\nPING\r\n")).unwrap();
        assert_eq!(protocol.system, "redis");
        let (_, protocol) = registry.classify_protocol(5432, None).unwrap();
        assert_eq!(protocol.system, "postgresql");
        assert!(registry.classify_protocol(9999, None).is_none());
    }

    #[test]
    fn external_dir_load_rejects_broken_pack() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.yaml"), "api_version: nope\nkind: runner-recipe\nmetadata: {name: x}\ndetect: {}\n").unwrap();
        let mut registry = PackRegistry::builtin().unwrap();
        assert!(registry.load_dir(dir.path()).is_err());
    }
}
