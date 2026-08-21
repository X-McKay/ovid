//! Repository acquisition and fingerprinting (spec §13.3, FR-001..FR-007).
//!
//! Responsibilities:
//!
//! 1. canonicalize repository identity (local path or Git URL);
//! 2. resolve the revision to an immutable commit digest (FR-002);
//! 3. materialize source into a content-addressed workdir, deduplicated by
//!    identity + revision (FR-006);
//! 4. fingerprint the tree (per-file digests combined into a source digest);
//! 5. emit repository provenance.
//!
//! No repository hook or build command is executed during acquisition
//! (§14.2): cloning uses plain `git` with hooks and fsmonitor disabled, and
//! fingerprinting only reads bytes. Exposing the tree to a guest as a
//! read-only block device (FR-023) is the sandbox layer's job; this crate
//! guarantees the checkout itself is never handed out writable
//! (`RepoSnapshot::root` is conceptually immutable once fingerprinted).

use ovid_core::{Digest, OvidError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

/// Where a repository comes from.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RepositorySource {
    LocalPath { path: PathBuf },
    GitUrl { url: String, reference: Option<String> },
}

impl RepositorySource {
    /// Parse a CLI-style locator: an existing path, or anything that looks
    /// like a Git URL.
    pub fn parse(locator: &str, reference: Option<String>) -> Self {
        let path = Path::new(locator);
        if path.exists() {
            RepositorySource::LocalPath { path: path.to_path_buf() }
        } else {
            RepositorySource::GitUrl { url: locator.to_string(), reference }
        }
    }

    pub fn canonical_url(&self) -> String {
        match self {
            RepositorySource::LocalPath { path } => format!("file://{}", path.display()),
            RepositorySource::GitUrl { url, .. } => url.clone(),
        }
    }
}

/// A materialized, fingerprinted repository revision (spec §8.1).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RepoSnapshot {
    pub canonical_url: String,
    /// Resolved immutable commit digest, or `workdir` for a non-git local
    /// tree (recorded, never invented — FR-002).
    pub revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_requested: Option<String>,
    /// Combined digest over all file digests + relative paths.
    pub source_digest: Digest,
    /// Root of the materialized tree on the worker.
    pub root: PathBuf,
    /// Relative path -> (size, digest) for every regular file. Sorted map
    /// so the combined digest is deterministic.
    pub files: BTreeMap<String, FileEntry>,
    pub acquired_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FileEntry {
    pub size: u64,
    pub digest: Digest,
}

impl RepoSnapshot {
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    pub fn total_size(&self) -> u64 {
        self.files.values().map(|f| f.size).sum()
    }

    /// Relative paths whose final component matches `name` exactly.
    pub fn find_files_named(&self, name: &str) -> Vec<&str> {
        self.files
            .keys()
            .filter(|p| p.rsplit('/').next() == Some(name))
            .map(String::as_str)
            .collect()
    }

    /// Whether a file exists at exactly this relative path.
    pub fn has_file(&self, relative: &str) -> bool {
        self.files.contains_key(relative)
    }

    /// Read a file's contents (bounded) from the snapshot.
    pub fn read_file(&self, relative: &str, max_bytes: u64) -> Result<String, OvidError> {
        let path = self.root.join(relative);
        let metadata = std::fs::metadata(&path)?;
        if metadata.len() > max_bytes {
            return Err(OvidError::Repository(format!(
                "{relative} is {} bytes, over the {max_bytes} byte read bound",
                metadata.len()
            )));
        }
        std::fs::read_to_string(&path)
            .map_err(|e| OvidError::Repository(format!("read {relative}: {e}")))
    }
}

/// Acquisition options.
#[derive(Clone, Debug)]
pub struct AcquireOptions {
    /// Directory used for clones and the materialization cache.
    pub workdir: PathBuf,
    /// Shallow clone depth (FR-004). `None` = full history.
    pub depth: Option<u32>,
    /// Skip files larger than this during fingerprinting (they are still
    /// listed, with size only).
    pub max_hash_file_bytes: u64,
}

impl AcquireOptions {
    pub fn new(workdir: impl Into<PathBuf>) -> Self {
        AcquireOptions { workdir: workdir.into(), depth: Some(1), max_hash_file_bytes: 32 * 1024 * 1024 }
    }
}

/// Acquire and fingerprint a repository.
pub fn acquire(source: &RepositorySource, options: &AcquireOptions) -> Result<RepoSnapshot, OvidError> {
    match source {
        RepositorySource::LocalPath { path } => {
            let root = path
                .canonicalize()
                .map_err(|e| OvidError::Repository(format!("bad path {}: {e}", path.display())))?;
            let revision = git_revision(&root).unwrap_or_else(|| "workdir".to_string());
            fingerprint(format!("file://{}", root.display()), revision, None, &root, options)
        }
        RepositorySource::GitUrl { url, reference } => {
            let clone_dir = clone_target_dir(&options.workdir, url, reference.as_deref());
            if !clone_dir.join(".git").exists() {
                clone(url, reference.as_deref(), &clone_dir, options.depth)?;
            }
            let revision = git_revision(&clone_dir).ok_or_else(|| {
                OvidError::Repository(format!("could not resolve a commit for {url}"))
            })?;
            fingerprint(url.clone(), revision, reference.clone(), &clone_dir, options)
        }
    }
}

/// Content-addressed clone location (FR-006): the same URL+ref reuses the
/// same materialization.
fn clone_target_dir(workdir: &Path, url: &str, reference: Option<&str>) -> PathBuf {
    let key = Digest::of_bytes(format!("{url}\n{}", reference.unwrap_or("HEAD")).as_bytes());
    workdir.join("sources").join(&key.hex()[..24])
}

fn clone(url: &str, reference: Option<&str>, target: &Path, depth: Option<u32>) -> Result<(), OvidError> {
    std::fs::create_dir_all(target.parent().unwrap_or(Path::new(".")))?;
    let mut cmd = Command::new("git");
    // Acquisition must not execute repository-controlled code (§14.2):
    // disable hooks and filesystem monitors for the clone.
    cmd.arg("-c").arg("core.hooksPath=/dev/null");
    cmd.arg("-c").arg("core.fsmonitor=false");
    cmd.arg("clone").arg("--quiet");
    if let Some(d) = depth {
        cmd.arg(format!("--depth={d}"));
    }
    if let Some(r) = reference {
        cmd.arg("--branch").arg(r);
    }
    cmd.arg(url).arg(target);
    let output = cmd.output().map_err(|e| OvidError::Repository(format!("git clone: {e}")))?;
    if !output.status.success() {
        return Err(OvidError::Repository(format!(
            "git clone failed for {url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn git_revision(root: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

fn fingerprint(
    canonical_url: String,
    revision: String,
    ref_requested: Option<String>,
    root: &Path,
    options: &AcquireOptions,
) -> Result<RepoSnapshot, OvidError> {
    let mut files = BTreeMap::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".git")
    {
        let entry = entry.map_err(|e| OvidError::Repository(format!("walk: {e}")))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|e| OvidError::Repository(format!("strip prefix: {e}")))?
            .to_string_lossy()
            .replace('\\', "/");
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let digest = if size <= options.max_hash_file_bytes {
            Digest::of_file(entry.path())?
        } else {
            // Oversized files are identified by path+size only; recorded as
            // a limitation rather than silently skipped.
            Digest::of_bytes(format!("oversized:{relative}:{size}").as_bytes())
        };
        files.insert(relative, FileEntry { size, digest });
    }
    let source_digest = Digest::combine(
        files
            .iter()
            .map(|(path, entry)| {
                // Bind the path into the digest, not just contents.
                Digest::of_bytes(format!("{path}\n{}", entry.digest).as_bytes())
            })
            .collect::<Vec<_>>()
            .iter(),
    );
    Ok(RepoSnapshot {
        canonical_url,
        revision,
        ref_requested,
        source_digest,
        root: root.to_path_buf(),
        files,
        acquired_at: chrono::Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tree(dir: &Path) {
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        std::fs::write(dir.join("src/main.rs"), "fn main() {}\n").unwrap();
    }

    #[test]
    fn fingerprints_local_tree() {
        let dir = tempfile::tempdir().unwrap();
        make_tree(dir.path());
        let source = RepositorySource::parse(dir.path().to_str().unwrap(), None);
        let snapshot = acquire(&source, &AcquireOptions::new(dir.path().join(".work"))).unwrap();
        assert_eq!(snapshot.file_count(), 2);
        assert_eq!(snapshot.revision, "workdir");
        assert!(snapshot.has_file("Cargo.toml"));
        assert_eq!(snapshot.find_files_named("main.rs"), vec!["src/main.rs"]);
    }

    #[test]
    fn source_digest_is_content_sensitive() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        make_tree(dir_a.path());
        make_tree(dir_b.path());
        let opts_a = AcquireOptions::new(dir_a.path().join(".work"));
        let opts_b = AcquireOptions::new(dir_b.path().join(".work"));
        let snap_a =
            acquire(&RepositorySource::parse(dir_a.path().to_str().unwrap(), None), &opts_a)
                .unwrap();
        let snap_b =
            acquire(&RepositorySource::parse(dir_b.path().to_str().unwrap(), None), &opts_b)
                .unwrap();
        // Identical content -> identical digest, regardless of location.
        assert_eq!(snap_a.source_digest, snap_b.source_digest);

        std::fs::write(dir_b.path().join("src/main.rs"), "fn main() { changed(); }\n").unwrap();
        let snap_c =
            acquire(&RepositorySource::parse(dir_b.path().to_str().unwrap(), None), &opts_b)
                .unwrap();
        assert_ne!(snap_a.source_digest, snap_c.source_digest);
    }

    #[test]
    fn git_urls_parse_when_path_missing() {
        let source = RepositorySource::parse("https://github.com/acme/x", Some("main".into()));
        assert!(matches!(source, RepositorySource::GitUrl { .. }));
        assert_eq!(source.canonical_url(), "https://github.com/acme/x");
    }

    #[test]
    fn bounded_read_rejects_oversize() {
        let dir = tempfile::tempdir().unwrap();
        make_tree(dir.path());
        let source = RepositorySource::parse(dir.path().to_str().unwrap(), None);
        let snapshot = acquire(&source, &AcquireOptions::new(dir.path().join(".work"))).unwrap();
        assert!(snapshot.read_file("Cargo.toml", 4).is_err());
        assert!(snapshot.read_file("Cargo.toml", 4096).unwrap().contains("[package]"));
    }
}
