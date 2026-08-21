//! The explicit analysis state machine (proposal §5.3).
//!
//! Replaces "a long procedural pipeline" with named, validated states.
//! v0.2 uses the machine to structure and journal the `prove` use case;
//! persistence/resume hangs off the same states in a later phase.

use serde::Serialize;

/// The lifecycle states of one analysis (proposal §5.3).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum AnalysisState {
    Created,
    SourceResolved,
    Inspected,
    EnvironmentPrepared,
    Provisioned,
    BaselineValidated,
    CandidatesObserved,
    ExperimentsCompleted,
    WorldSynthesized,
    ReplayVerified,
    ReplayFailed,
    ReplayUnavailable,
    Finalized,
}

impl AnalysisState {
    /// Whether `next` is a legal successor of `self`.
    fn allows(self, next: AnalysisState) -> bool {
        use AnalysisState::*;
        matches!(
            (self, next),
            (Created, SourceResolved)
                | (SourceResolved, Inspected)
                | (Inspected, EnvironmentPrepared)
                | (EnvironmentPrepared, Provisioned)
                | (Provisioned, BaselineValidated)
                | (BaselineValidated, CandidatesObserved)
                // A failing/unstable baseline skips experiments entirely.
                | (BaselineValidated, Finalized)
                | (CandidatesObserved, ExperimentsCompleted)
                | (ExperimentsCompleted, WorldSynthesized)
                // No world was synthesized (unstable baseline, or nothing
                // to synthesize from): finalize without replay states.
                | (ExperimentsCompleted, Finalized)
                | (WorldSynthesized, ReplayVerified)
                | (WorldSynthesized, ReplayFailed)
                | (WorldSynthesized, ReplayUnavailable)
                | (ReplayVerified, Finalized)
                | (ReplayFailed, Finalized)
                | (ReplayUnavailable, Finalized)
        )
    }
}

/// A validated state history for one analysis.
#[derive(Clone, Debug)]
pub struct Workflow {
    state: AnalysisState,
    history: Vec<AnalysisState>,
}

impl Default for Workflow {
    fn default() -> Self {
        Workflow::new()
    }
}

impl Workflow {
    pub fn new() -> Workflow {
        Workflow {
            state: AnalysisState::Created,
            history: vec![AnalysisState::Created],
        }
    }

    pub fn state(&self) -> AnalysisState {
        self.state
    }

    pub fn history(&self) -> &[AnalysisState] {
        &self.history
    }

    /// Advance to `next`; panics in debug on an illegal transition and
    /// refuses (keeping state) in release — an illegal transition is a
    /// programming error in the use case, never a runtime condition.
    pub fn advance(&mut self, next: AnalysisState) {
        debug_assert!(
            self.state.allows(next),
            "illegal workflow transition {:?} -> {next:?}",
            self.state
        );
        if self.state.allows(next) {
            self.state = next;
            self.history.push(next);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_reaches_finalized() {
        use AnalysisState::*;
        let mut wf = Workflow::new();
        for state in [
            SourceResolved,
            Inspected,
            EnvironmentPrepared,
            Provisioned,
            BaselineValidated,
            CandidatesObserved,
            ExperimentsCompleted,
            WorldSynthesized,
            ReplayVerified,
            Finalized,
        ] {
            wf.advance(state);
        }
        assert_eq!(wf.state(), Finalized);
        assert_eq!(wf.history().len(), 11);
    }

    #[test]
    fn unstable_baseline_may_finalize_directly() {
        use AnalysisState::*;
        let mut wf = Workflow::new();
        for state in [
            SourceResolved,
            Inspected,
            EnvironmentPrepared,
            Provisioned,
            BaselineValidated,
            Finalized,
        ] {
            wf.advance(state);
        }
        assert_eq!(wf.state(), Finalized);
    }

    #[test]
    #[should_panic(expected = "illegal workflow transition")]
    fn skipping_states_is_illegal() {
        let mut wf = Workflow::new();
        wf.advance(AnalysisState::WorldSynthesized);
    }
}
