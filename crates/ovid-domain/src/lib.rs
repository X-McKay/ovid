//! The pure causal-verification domain (proposal §5.2, §7).
//!
//! Ovid 0.2 repositions the project around one differentiated loop:
//! *experimentally determine what a repository workload needs, explain
//! why, and verify that the inferred environment can reproduce the
//! workload* (proposal §1). This crate is the functional core of that
//! loop: every consequential rule — baseline stability, treatment
//! enforcement, causal classification, world verification — lives here as
//! pure, deterministic code with no filesystem, process, or network
//! dependencies (proposal §5.2).
//!
//! Load-bearing design constraints, enforced by construction:
//!
//! - [`classify::CausalConclusion`] has no public constructor: only the
//!   domain classifier can label a dependency `required` or `optional`
//!   (proposal §7.5). Adapters and use cases cannot mint conclusions.
//! - A trial whose treatment was not [`trial::EnforcementStatus::Enforced`]
//!   can only ever produce `unresolved` (proposal §7.6, §10.7).
//! - [`world::VerifiedWorld`] can only be created from
//!   [`world::ReplayEvidence`], which itself only exists for a passing
//!   clean replay (proposal §7.7, §11.3). A renderer cannot promote a
//!   world's status.
//! - Every conclusion carries an explicit [`scope::AnalysisScope`]
//!   (proposal §2.2): Ovid never claims "this repository always requires
//!   X", only "X was required for this workload, under this environment
//!   and policy, on the paths exercised".

pub mod baseline;
pub mod classify;
pub mod dependency;
pub mod scope;
pub mod trial;
pub mod world;

pub use baseline::{assess_baseline, BaselineVerdict};
pub use classify::{
    classify_enforced_deny, classify_intervention, classify_natural_counterfactual,
    classify_unenforceable, CausalConclusion, Necessity,
};
pub use dependency::{DependencyKey, DependencyKind};
pub use scope::AnalysisScope;
pub use trial::{
    CandidateEvidence, EnforcementReport, EnforcementStatus, Treatment, TrialOutcome, TrialRecord,
};
pub use world::{ProposedWorld, ReplayEvidence, VerifiedWorld, WorldCandidate, WorldOutcome};
