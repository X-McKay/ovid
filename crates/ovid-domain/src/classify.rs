//! Causal classification (proposal §10.7) — the only place a dependency
//! can be labeled `required` or `optional`.
//!
//! [`CausalConclusion`] deliberately has **no public constructor**
//! (proposal §7.5): application and adapter code can read conclusions but
//! cannot mint them, so every `required`/`optional` label in any Ovid
//! output traces back to this classifier and the rules below.
//!
//! The rules (proposal §10.7):
//!
//! - `required` — stable passing baseline, enforced dependency-specific
//!   treatment, repeated variant failure, no other material change.
//! - `optional` — unavailability enforced or naturally demonstrated, and
//!   the workload repeatedly passed.
//! - `unresolved` — everything else: unenforced treatments, unstable
//!   baselines or variants, group-level changes that were never isolated,
//!   exhausted budgets. Unresolved beats wrong (spec §6.6, FR-048).

use crate::baseline::BaselineVerdict;
use crate::dependency::DependencyKey;
use crate::trial::{CandidateEvidence, EnforcementStatus, Treatment, TrialRecord};
use serde::Serialize;

/// The causal label (proposal §7.5). Readable everywhere; producible only
/// via this module's classifier.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum Necessity {
    Required,
    Optional,
    Unresolved,
}

/// One classified dependency. Fields are private — construction happens
/// only inside [`classify_intervention`] / [`classify_unenforceable`]
/// (proposal §7.5). `Serialize`-only: projections write conclusions, but
/// nothing can deserialize one back into existence.
#[derive(Clone, PartialEq, Serialize, Debug)]
pub struct CausalConclusion {
    dependency: DependencyKey,
    necessity: Necessity,
    /// Why the label holds, in evidence terms.
    reason: String,
    /// Labels of the trials this conclusion rests on.
    trials: Vec<String>,
    /// Confidence in the label; `unresolved` is always 0.0.
    confidence: f64,
}

impl CausalConclusion {
    pub fn dependency(&self) -> &DependencyKey {
        &self.dependency
    }

    pub fn necessity(&self) -> Necessity {
        self.necessity
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn trials(&self) -> &[String] {
        &self.trials
    }

    pub fn confidence(&self) -> f64 {
        self.confidence
    }
}

fn unresolved(key: &DependencyKey, reason: impl Into<String>) -> CausalConclusion {
    CausalConclusion {
        dependency: key.clone(),
        necessity: Necessity::Unresolved,
        reason: reason.into(),
        trials: Vec::new(),
        confidence: 0.0,
    }
}

/// Classify every candidate as unresolved because the laboratory could
/// not enforce the treatment at all (proposal §5.5: if the required
/// treatment cannot be enforced, the result is `unresolved`; Ovid must
/// not silently weaken the experiment).
pub fn classify_unenforceable(
    candidates: &[CandidateEvidence],
    treatment: &Treatment,
    reason: &str,
) -> Vec<CausalConclusion> {
    candidates
        .iter()
        .map(|candidate| {
            unresolved(
                &candidate.key,
                format!(
                    "treatment `{}` could not be enforced: {reason}",
                    treatment.describe()
                ),
            )
        })
        .collect()
}

/// Reuse a natural counterfactual (proposal §10.5 step 1): a dependency
/// that was *demonstrably unavailable during a stable passing baseline*
/// (every attempt failed, or a searched executable was absent) is
/// `optional` in scope without spending a single intervention trial —
/// the baseline itself is the experiment. Candidates whose
/// unavailability was not demonstrated are not returned; they proceed to
/// controlled interventions.
pub fn classify_natural_counterfactual(
    baseline: &BaselineVerdict,
    baseline_trials: &[String],
    candidates: &[CandidateEvidence],
) -> Vec<CausalConclusion> {
    let BaselineVerdict::StablePassing { runs } = baseline else {
        return Vec::new();
    };
    let confidence = if *runs >= 2 { 0.9 } else { 0.75 };
    candidates
        .iter()
        .filter(|c| c.externally_controlled && c.unavailable_under_treatment)
        .map(|candidate| CausalConclusion {
            dependency: candidate.key.clone(),
            necessity: Necessity::Optional,
            reason: format!(
                "workload passed {runs}/{runs} baseline runs while this dependency was \
                 demonstrably unavailable (natural counterfactual)"
            ),
            trials: baseline_trials.to_vec(),
            confidence,
        })
        .collect()
}

/// Classify the candidates affected by one intervention: a set of trials
/// that all applied the same treatment, compared against the baseline
/// verdict (proposal §10.7).
pub fn classify_intervention(
    baseline: &BaselineVerdict,
    trials: &[TrialRecord],
    candidates: &[CandidateEvidence],
) -> Vec<CausalConclusion> {
    // Rule 0: no causal claims without a stable passing baseline.
    if !baseline.supports_experiments() {
        let reason = format!("baseline is not stable-passing ({})", baseline.describe());
        return candidates
            .iter()
            .map(|c| unresolved(&c.key, reason.clone()))
            .collect();
    }
    if trials.is_empty() {
        return candidates
            .iter()
            .map(|c| unresolved(&c.key, "no trials executed (experiment budget exhausted)"))
            .collect();
    }
    // Rule 1: every trial's treatment must have been enforced.
    if let Some(bad) = trials
        .iter()
        .find(|t| t.enforcement.status != EnforcementStatus::Enforced)
    {
        let detail = bad.enforcement.limitations.join("; ");
        let reason = format!(
            "treatment `{}` was not enforced in trial {} ({detail})",
            bad.treatment.describe(),
            bad.label
        );
        return candidates
            .iter()
            .map(|c| unresolved(&c.key, reason.clone()))
            .collect();
    }
    let trial_labels: Vec<String> = trials.iter().map(|t| t.label.clone()).collect();
    // Rule 2: the variant runs must agree with each other (§20.6's
    // signature comparison), or nothing can be concluded.
    let all_passed = trials.iter().all(|t| t.outcome.passed);
    let all_failed = trials.iter().all(|t| !t.outcome.passed);
    let signatures_compatible = {
        let first = trials
            .iter()
            .find_map(|t| t.outcome.failure_signature.clone());
        trials.iter().all(|t| {
            t.outcome.passed
                || t.outcome.failure_signature.is_none()
                || t.outcome.failure_signature == first
        })
    };
    if !(all_passed || (all_failed && signatures_compatible)) {
        return candidates
            .iter()
            .map(|c| {
                unresolved(
                    &c.key,
                    "variant runs disagreed with each other (unstable under treatment)",
                )
            })
            .collect();
    }
    let confidence = if trials.len() >= 2 { 0.9 } else { 0.75 };

    if all_passed {
        // The workload passed under the treatment: dependencies whose
        // unavailability was *demonstrated* are optional in scope;
        // everything else was never actually tested.
        return candidates
            .iter()
            .map(|candidate| {
                if candidate.externally_controlled && candidate.unavailable_under_treatment {
                    CausalConclusion {
                        dependency: candidate.key.clone(),
                        necessity: Necessity::Optional,
                        reason: format!(
                            "workload passed {}/{} trials while this dependency was \
                             demonstrably unavailable (treatment: {})",
                            trials.len(),
                            trials.len(),
                            trials[0].treatment.describe()
                        ),
                        trials: trial_labels.clone(),
                        confidence,
                    }
                } else {
                    unresolved(
                        &candidate.key,
                        "workload passed under treatment, but this dependency's \
                         unavailability was not demonstrated",
                    )
                }
            })
            .collect();
    }

    // The workload failed under the treatment. Only an isolated,
    // single-dependency change supports `required`; a group change stays
    // unresolved until individually varied (proposal §10.5 step 5).
    let changed: Vec<&CandidateEvidence> = candidates
        .iter()
        .filter(|c| {
            c.externally_controlled && c.unavailable_under_treatment && c.attempted_in_baseline
        })
        .collect();
    let single_change = changed.len() == 1;
    candidates
        .iter()
        .map(|candidate| {
            let in_changed_set = changed.iter().any(|c| c.key == candidate.key);
            if single_change && in_changed_set {
                CausalConclusion {
                    dependency: candidate.key.clone(),
                    necessity: Necessity::Required,
                    reason: format!(
                        "stable baseline passed; enforced `{}` failed {}/{} trials while \
                         only this dependency changed availability",
                        trials[0].treatment.describe(),
                        trials.len(),
                        trials.len()
                    ),
                    trials: trial_labels.clone(),
                    confidence,
                }
            } else if in_changed_set {
                unresolved(
                    &candidate.key,
                    format!(
                        "workload failed under `{}`, but {} dependencies changed \
                         availability together; per-dependency causality needs \
                         individual variation",
                        trials[0].treatment.describe(),
                        changed.len()
                    ),
                )
            } else {
                unresolved(
                    &candidate.key,
                    "workload failed under treatment, but this dependency's \
                     availability did not demonstrably change",
                )
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::assess_baseline;
    use crate::trial::{EnforcementReport, TrialOutcome};

    fn stable_baseline() -> BaselineVerdict {
        assess_baseline(&[TrialOutcome::passed(), TrialOutcome::passed()])
    }

    fn enforced_trial(label: &str, passed: bool) -> TrialRecord {
        TrialRecord {
            label: label.into(),
            treatment: Treatment::DenyAllEgress,
            enforcement: EnforcementReport::enforced(Treatment::DenyAllEgress, "user-netns"),
            outcome: if passed {
                TrialOutcome::passed()
            } else {
                TrialOutcome::failed("connect refused")
            },
            evidence: vec![],
        }
    }

    fn candidate(identity: &str, unavailable: bool, attempted: bool) -> CandidateEvidence {
        CandidateEvidence {
            key: DependencyKey::network(identity),
            externally_controlled: true,
            unavailable_under_treatment: unavailable,
            attempted_in_baseline: attempted,
        }
    }

    #[test]
    fn single_changed_dependency_with_repeated_failure_is_required() {
        let conclusions = classify_intervention(
            &stable_baseline(),
            &[enforced_trial("t1", false), enforced_trial("t2", false)],
            &[candidate("postgres:5432", true, true)],
        );
        assert_eq!(conclusions[0].necessity(), Necessity::Required);
        assert!(conclusions[0].confidence() >= 0.9);
        assert_eq!(conclusions[0].trials().len(), 2);
    }

    #[test]
    fn passing_variant_makes_demonstrably_unavailable_dependencies_optional() {
        let conclusions = classify_intervention(
            &stable_baseline(),
            &[enforced_trial("t1", true), enforced_trial("t2", true)],
            &[
                candidate("redis:6379", true, true),
                candidate("api.internal:443", false, true),
            ],
        );
        assert_eq!(conclusions[0].necessity(), Necessity::Optional);
        assert_eq!(
            conclusions[1].necessity(),
            Necessity::Unresolved,
            "unavailability not demonstrated -> unresolved, never optional"
        );
    }

    #[test]
    fn group_level_failure_stays_unresolved() {
        let conclusions = classify_intervention(
            &stable_baseline(),
            &[enforced_trial("t1", false)],
            &[
                candidate("postgres:5432", true, true),
                candidate("kafka:9092", true, true),
            ],
        );
        assert!(conclusions
            .iter()
            .all(|c| c.necessity() == Necessity::Unresolved));
        assert!(conclusions[0].reason().contains("individual variation"));
    }

    #[test]
    fn unenforced_treatment_can_only_yield_unresolved() {
        let mut trial = enforced_trial("t1", false);
        trial.enforcement =
            EnforcementReport::not_enforced(Treatment::DenyAllEgress, "no user namespaces");
        let conclusions = classify_intervention(
            &stable_baseline(),
            &[trial],
            &[candidate("postgres:5432", true, true)],
        );
        assert_eq!(conclusions[0].necessity(), Necessity::Unresolved);
        assert!(conclusions[0].reason().contains("not enforced"));
    }

    #[test]
    fn unstable_baseline_blocks_all_causal_labels() {
        let unstable = assess_baseline(&[TrialOutcome::passed(), TrialOutcome::failed("flake")]);
        let conclusions = classify_intervention(
            &unstable,
            &[enforced_trial("t1", false), enforced_trial("t2", false)],
            &[candidate("postgres:5432", true, true)],
        );
        assert_eq!(conclusions[0].necessity(), Necessity::Unresolved);
        assert!(conclusions[0].reason().contains("baseline"));
    }

    #[test]
    fn disagreeing_variant_runs_stay_unresolved() {
        let conclusions = classify_intervention(
            &stable_baseline(),
            &[enforced_trial("t1", true), enforced_trial("t2", false)],
            &[candidate("postgres:5432", true, true)],
        );
        assert_eq!(conclusions[0].necessity(), Necessity::Unresolved);
    }

    #[test]
    fn natural_counterfactual_makes_unavailable_dependencies_optional() {
        let conclusions = classify_natural_counterfactual(
            &stable_baseline(),
            &["baseline-1".into(), "baseline-2".into()],
            &[
                candidate("redis:6379", true, true), // unavailable during baseline
                candidate("postgres:5432", false, true), // available -> not returned
            ],
        );
        assert_eq!(conclusions.len(), 1, "only the demonstrated one classifies");
        assert_eq!(conclusions[0].necessity(), Necessity::Optional);
        assert!(conclusions[0].reason().contains("natural counterfactual"));
        assert_eq!(conclusions[0].trials().len(), 2);
    }

    #[test]
    fn natural_counterfactual_requires_a_stable_passing_baseline() {
        let unstable = assess_baseline(&[TrialOutcome::passed(), TrialOutcome::failed("f")]);
        assert!(classify_natural_counterfactual(
            &unstable,
            &["baseline-1".into()],
            &[candidate("redis:6379", true, true)],
        )
        .is_empty());
    }

    #[test]
    fn unenforceable_helper_never_produces_causal_labels() {
        let conclusions = classify_unenforceable(
            &[candidate("postgres:5432", true, true)],
            &Treatment::DenyAllEgress,
            "laboratory lacks egress control",
        );
        assert_eq!(conclusions[0].necessity(), Necessity::Unresolved);
        assert_eq!(conclusions[0].confidence(), 0.0);
    }
}
