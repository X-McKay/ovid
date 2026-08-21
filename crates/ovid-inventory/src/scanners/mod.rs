//! Native manifest/lockfile scanners.
//!
//! Each scanner recognizes files by name, parses them defensively (a broken
//! manifest becomes a warning, never a panic or hard error), and emits
//! components with `declared` (manifest) and/or `resolved` (lockfile)
//! states. Scanners are deliberately ecosystem-shaped, not
//! framework-shaped: they read dependency declarations, they do not try to
//! understand application semantics (§6.1).

mod cargo;
mod golang;
mod java;
mod node;
mod php;
mod python;
mod ruby;

use crate::InventoryReport;
use ovid_repository::RepoSnapshot;

/// Bound on manifest/lockfile reads. Large generated lockfiles are real
/// (package-lock.json in big repos), so this is generous but finite.
pub(crate) const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;

pub trait Scanner: Sync {
    fn name(&self) -> &'static str;
    fn scan(&self, snapshot: &RepoSnapshot, report: &mut InventoryReport);
}

/// All built-in scanners.
pub fn all() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(cargo::CargoScanner),
        Box::new(node::NodeScanner),
        Box::new(python::PythonScanner),
        Box::new(golang::GoScanner),
        Box::new(java::JavaScanner),
        Box::new(ruby::RubyScanner),
        Box::new(php::PhpScanner),
    ]
}

/// Shared helper: read a snapshot file, recording a warning on failure.
pub(crate) fn read_or_warn(
    snapshot: &RepoSnapshot,
    path: &str,
    report: &mut InventoryReport,
) -> Option<String> {
    match snapshot.read_file(path, MAX_MANIFEST_BYTES) {
        Ok(text) => {
            report.scanned_files.push(path.to_string());
            Some(text)
        }
        Err(e) => {
            report.warnings.push(format!("could not read {path}: {e}"));
            None
        }
    }
}
