//! Output generation (spec §13.14, §25, FR-075, FR-090..FR-092, FR-101).
//!
//! - [`manifest`] — the Ovid Manifest: the revision- and workload-scoped
//!   projection of the evidence ledger (§25). YAML is the human profile,
//!   JSON the machine profile; neither is the canonical store (ADR-004).
//! - [`exports`] — CycloneDX and SPDX exports (FR-075). Standards are
//!   exports, not the internal model (ADR-006).
//! - [`plan`] — the human-readable integration plan (FR-092).
//! - [`diff`] — evidence-aware manifest comparison (FR-100/FR-101's
//!   composition dimension for local mode).

pub mod diff;
pub mod exports;
pub mod manifest;
pub mod plan;

pub use diff::{diff_manifests, ManifestDiff};
pub use exports::{to_cyclonedx, to_spdx};
pub use manifest::*;
pub use plan::integration_plan_markdown;
