//! The evidence ledger is canonical (spec §6.4, ADR-004).
//!
//! Everything else Ovid produces — the manifest, the graph, SBOM exports —
//! is a projection of the immutable records stored here. This crate
//! provides:
//!
//! - [`record::EvidenceRecord`] — one immutable observation with provenance.
//! - [`ledger::EvidenceLedger`] — an append-only, hash-chained JSONL store
//!   (§22.6): each record embeds the digest of the previous record, so
//!   tampering or truncation is detectable, and the final chain head is
//!   published in the manifest's provenance section.
//! - [`claim::Claim`] — normalized graph statements linking to supporting
//!   and contradicting evidence (§22.3), with explain traversal (FR-110).
//! - [`confidence`] — a bounded log-odds combination model (§22.4) with
//!   hard caps by evidence class.
//!
//! Local mode stores the ledger as plain JSONL on disk. Fleet-mode
//! projections (PostgreSQL, Parquet, graph databases) are explicitly
//! *projections* per ADR-004 and are out of scope for this crate.

pub mod claim;
pub mod confidence;
pub mod ledger;
pub mod record;

pub use claim::{Claim, ClaimStore};
pub use confidence::{combine_confidence, ConfidenceCap};
pub use ledger::EvidenceLedger;
pub use record::EvidenceRecord;
