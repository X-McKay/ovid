//! Application layer: use cases and outbound ports (proposal §5.1, §8, §9).
//!
//! This crate orchestrates the differentiated loop — *prepare a
//! deterministic environment, establish a stable baseline, apply
//! controlled interventions, classify, synthesize the smallest credible
//! world, replay-verify it* — against coarse-grained ports. It depends on
//! [`ovid_domain`] for every rule and on **no concrete adapter**: Git,
//! strace, microsandbox, ledgers, and terminals are all behind traits,
//! wired together only in the CLI composition root (proposal §6.1).
//!
//! Deliberate deviation from the proposal's sketch: ports are synchronous.
//! The whole workspace is synchronous today, laboratories run one trial at
//! a time in v0.2, and adding an async runtime would be an adapter concern
//! leaking inward. The port shapes match the proposal §8; only the
//! `async` keyword is dropped (recorded in docs/ARCHITECTURE.md ADR-016).

pub mod ports;
pub mod prove;
pub mod workflow;

pub use ports::{
    JournalError, JournalEvent, JournalPort, LabCapabilities, LabError, LaboratoryPort,
    NetworkCandidate, NullProgress, PreparedEnvironment, ProgressPort, ProviderIdentity,
    SnapshotRef, TrialObservations, TrialResult, TrialSpec,
};
pub use prove::{
    prove, run_clean_replay, ClassifiedDependency, ProveError, ProvePolicy, ProveReport,
    ProveRequest, StageTiming,
};
pub use workflow::{AnalysisState, Workflow};
