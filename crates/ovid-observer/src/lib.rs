//! Boundary observers (spec §13.7, FR-030..FR-039).
//!
//! The production design attaches a small eBPF observer (Aya/libbpf-rs)
//! inside the laboratory guest. This crate defines the backend-neutral
//! observer contract and ships the first interchangeable implementation: a
//! ptrace-based observer built on `strace`, which works in any Linux
//! environment without kernel privileges and produces the same normalized
//! event stream. §30.5 explicitly calls for alternate observation
//! mechanisms (ptrace among them) so critical observations can be
//! cross-checked; the eBPF backend slots in behind [`BoundaryObserver`]
//! without changing the evidence model.
//!
//! Modules:
//! - [`strace`] — command wrapping and strace output parsing.
//! - [`mod@aggregate`] — event reduction (§32.5): collapse repeated successful
//!   opens, always preserve first occurrences and every failure.

pub mod aggregate;
pub mod dns;
pub mod strace;

pub use aggregate::{aggregate, AggregatedEvents};
pub use strace::{strace_available, StraceObserver};

use ovid_core::EventEnvelope;

/// The result of observing one run.
#[derive(Debug, Default)]
pub struct ObservationReport {
    pub events: Vec<EventEnvelope>,
    /// Raw observer lines that could not be parsed (accounted, per FR-039 /
    /// §27.5 drop counters — never silently lost).
    pub unparsed_lines: u64,
    pub raw_line_count: u64,
}

/// Backend-neutral observer contract.
///
/// `wrap` rewrites an argv so the workload runs under observation;
/// `collect` parses the observation output into normalized events after the
/// run finishes.
pub trait BoundaryObserver {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    /// Rewrite `argv` to run under observation, writing raw data to
    /// `output_path`.
    fn wrap(&self, argv: &[String], output_path: &std::path::Path) -> Vec<String>;
    /// Parse raw observation output into normalized events.
    fn collect(
        &self,
        output_path: &std::path::Path,
        run_id: &ovid_core::OvidId,
        ids: &ovid_core::IdGenerator,
    ) -> std::io::Result<ObservationReport>;
}
