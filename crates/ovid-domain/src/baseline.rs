//! Baseline stability (proposal §10.1 item 2, §10.2).
//!
//! Causal claims require a *stable* reference condition: repeated runs
//! from the same immutable snapshot with identical success results and
//! compatible failure signatures. A workload that alternates between
//! pass and fail must never receive a causal label (proposal §10.2);
//! it is reported unstable and every candidate stays unresolved.

use crate::trial::TrialOutcome;
use serde::{Deserialize, Serialize};

/// The verdict over the repeated baseline runs (proposal §10.2).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(tag = "verdict", rename_all = "kebab-case")]
pub enum BaselineVerdict {
    /// Every baseline run passed the success predicate.
    StablePassing { runs: usize },
    /// Every baseline run failed with a compatible signature. Honest, but
    /// no causal experiments can proceed from a failing reference.
    StableFailing {
        runs: usize,
        signature: Option<String>,
    },
    /// Runs disagreed (pass/fail mix, or divergent failure signatures).
    Unstable { runs: usize },
}

impl BaselineVerdict {
    /// Whether causal experiments may proceed (proposal §10.7: only a
    /// stable *passing* baseline supports required/optional labels).
    pub fn supports_experiments(&self) -> bool {
        matches!(self, BaselineVerdict::StablePassing { .. })
    }

    /// Human description for reports.
    pub fn describe(&self) -> String {
        match self {
            BaselineVerdict::StablePassing { runs } => {
                format!("stable ({runs}/{runs} passed)")
            }
            BaselineVerdict::StableFailing { runs, signature } => format!(
                "failing ({runs}/{runs} failed{})",
                signature
                    .as_deref()
                    .map(|s| format!(": {s}"))
                    .unwrap_or_default()
            ),
            BaselineVerdict::Unstable { runs } => format!("unstable across {runs} runs"),
        }
    }
}

/// Assess repeated baseline outcomes (proposal §10.2's stability rule:
/// identical success result; failures must share a signature).
pub fn assess_baseline(outcomes: &[TrialOutcome]) -> BaselineVerdict {
    let runs = outcomes.len();
    if runs == 0 {
        return BaselineVerdict::Unstable { runs: 0 };
    }
    if outcomes.iter().all(|o| o.passed) {
        return BaselineVerdict::StablePassing { runs };
    }
    if outcomes.iter().all(|o| !o.passed) {
        let signature = outcomes[0].failure_signature.clone();
        let compatible = outcomes
            .iter()
            .all(|o| o.failure_signature == signature || o.failure_signature.is_none());
        if compatible {
            return BaselineVerdict::StableFailing { runs, signature };
        }
        return BaselineVerdict::Unstable { runs };
    }
    BaselineVerdict::Unstable { runs }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_passing_is_stable() {
        let verdict = assess_baseline(&[TrialOutcome::passed(), TrialOutcome::passed()]);
        assert_eq!(verdict, BaselineVerdict::StablePassing { runs: 2 });
        assert!(verdict.supports_experiments());
    }

    #[test]
    fn pass_fail_mix_is_unstable_and_blocks_experiments() {
        let verdict = assess_baseline(&[TrialOutcome::passed(), TrialOutcome::failed("boom")]);
        assert_eq!(verdict, BaselineVerdict::Unstable { runs: 2 });
        assert!(!verdict.supports_experiments());
    }

    #[test]
    fn consistent_failures_are_stable_failing_but_block_experiments() {
        let verdict = assess_baseline(&[TrialOutcome::failed("e1"), TrialOutcome::failed("e1")]);
        assert!(matches!(verdict, BaselineVerdict::StableFailing { .. }));
        assert!(!verdict.supports_experiments());
    }

    #[test]
    fn divergent_failure_signatures_are_unstable() {
        let verdict = assess_baseline(&[TrialOutcome::failed("e1"), TrialOutcome::failed("e2")]);
        assert_eq!(verdict, BaselineVerdict::Unstable { runs: 2 });
    }

    #[test]
    fn zero_runs_never_support_experiments() {
        assert!(!assess_baseline(&[]).supports_experiments());
    }
}
