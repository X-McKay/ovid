//! Active experimentation (spec §14, §19, §20, FR-050..FR-054).
//!
//! The heart of Ovid's "repository execution tomography": treat every run
//! as an experiment in a defined world, satisfy failures one controlled
//! change at a time, then establish causality by removing dependencies and
//! rerunning from clean state.
//!
//! - [`predicate`] — success predicates (FR-016).
//! - [`resolution`] — turn failure evidence into ranked resolution
//!   proposals (§14.8): missing tool → resolver candidates, refused
//!   connections → service packs or stubs, unknown protocol → unresolved.
//! - [`counterfactual`] — the [`counterfactual::MvwSolver`]: additive
//!   discovery, subtractive delta-debugging minimization (§20.4), the
//!   nondeterminism policy (§20.6), and causal classification (§20.5).
//!
//! The solver drives an abstract [`WorldRunner`] so the same logic is unit
//! tested against simulated workloads and wired to real sandbox execution
//! by the CLI.

pub mod counterfactual;
pub mod network;
pub mod predicate;
pub mod resolution;

pub use counterfactual::{ExperimentBudget, ExperimentRecord, MvwSolver, SolverOutcome};
pub use network::{
    classify_network_counterfactual, externally_controlled, NetworkCounterfactual, NetworkVerdict,
};
pub use predicate::SuccessPredicate;
pub use resolution::{propose_resolutions, ResolutionKind, ResolutionProposal};

use ovid_world::World;

/// Runs a workload in a world and reports whether the success predicate
/// held. Implementations must provide clean-rerun semantics (§14.9): each
/// call starts from an equivalent clean state.
pub trait WorldRunner {
    fn run(&mut self, world: &World) -> RunOutcome;
}

/// Outcome of one run, as the solver sees it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RunOutcome {
    pub success: bool,
    /// Stable failure signature (first actionable error) used to compare
    /// runs (§20.6 compares error signatures, not just booleans).
    pub failure_signature: Option<String>,
}

impl RunOutcome {
    pub fn passed() -> Self {
        RunOutcome {
            success: true,
            failure_signature: None,
        }
    }

    pub fn failed(signature: impl Into<String>) -> Self {
        RunOutcome {
            success: false,
            failure_signature: Some(signature.into()),
        }
    }
}

impl<F: FnMut(&World) -> RunOutcome> WorldRunner for F {
    fn run(&mut self, world: &World) -> RunOutcome {
        self(world)
    }
}
