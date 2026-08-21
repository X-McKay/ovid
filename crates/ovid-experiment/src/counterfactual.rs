//! Counterfactual causality and the Minimum Viable World solver
//! (spec §20, FR-050..FR-054).
//!
//! The solver takes a world that already satisfies the success predicate
//! and answers: which dependencies are *causally required*? It uses
//! delta-debugging-style group removal (§20.4), repeats runs per the
//! nondeterminism policy (§20.6), and refuses minimality claims when
//! results are unstable (FR-053).

use crate::{RunOutcome, WorldRunner};
use ovid_core::{CausalClassification, OvidError};
use ovid_world::{Treatment, World};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Experiment budget (§8.4, FR-024's run-count dimension).
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct ExperimentBudget {
    pub max_runs: u32,
    /// Consistent repeats required to promote a causal conclusion (§20.6's
    /// default of two).
    pub required_repeats: u32,
}

impl Default for ExperimentBudget {
    fn default() -> Self {
        ExperimentBudget { max_runs: 60, required_repeats: 2 }
    }
}

/// One recorded experiment (§19.6): the controlled mutation, world digests,
/// and outcome.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ExperimentRecord {
    pub condition: String,
    pub parent_world_digest: String,
    pub world_digest: String,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_signature: Option<String>,
}

/// Solver result.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SolverOutcome {
    /// The minimal world found (relative to workload, policy, and budget —
    /// empirical minimality, §20.1).
    pub minimal_world: World,
    /// Per-dependency causal classification.
    pub classifications: BTreeMap<String, CausalClassification>,
    pub experiments: Vec<ExperimentRecord>,
    /// True when baseline repeats disagreed; minimality is not claimed
    /// (FR-053).
    pub nondeterministic: bool,
    pub runs_used: u32,
}

pub struct MvwSolver {
    budget: ExperimentBudget,
    runs_used: u32,
    experiments: Vec<ExperimentRecord>,
}

impl MvwSolver {
    pub fn new(budget: ExperimentBudget) -> Self {
        MvwSolver { budget, runs_used: 0, experiments: Vec::new() }
    }

    fn run_once(
        &mut self,
        runner: &mut dyn WorldRunner,
        world: &World,
        parent: &World,
        condition: &str,
    ) -> Result<RunOutcome, OvidError> {
        if self.runs_used >= self.budget.max_runs {
            return Err(OvidError::BudgetExhausted(format!(
                "experiment budget of {} runs exhausted",
                self.budget.max_runs
            )));
        }
        self.runs_used += 1;
        let outcome = runner.run(world);
        self.experiments.push(ExperimentRecord {
            condition: condition.to_string(),
            parent_world_digest: parent.digest().to_string(),
            world_digest: world.digest().to_string(),
            success: outcome.success,
            failure_signature: outcome.failure_signature.clone(),
        });
        Ok(outcome)
    }

    /// Run `world` `required_repeats` times; `Some(outcome)` when all
    /// repeats agree (same success flag and failure signature), `None` when
    /// they disagree (nondeterministic).
    fn run_stable(
        &mut self,
        runner: &mut dyn WorldRunner,
        world: &World,
        parent: &World,
        condition: &str,
    ) -> Result<Option<RunOutcome>, OvidError> {
        let first = self.run_once(runner, world, parent, condition)?;
        for _ in 1..self.budget.required_repeats {
            let repeat = self.run_once(runner, world, parent, condition)?;
            if repeat != first {
                return Ok(None);
            }
        }
        Ok(Some(first))
    }

    /// Subtractive minimization (§20.4): starting from a world where the
    /// workload succeeds, classify each dependency by removing it (making
    /// it [`Treatment::Absent`]) and rerunning from clean state.
    ///
    /// Group removal first: if removing *all* candidates at once still
    /// succeeds, everything is optional in one pass (the common
    /// all-telemetry case); otherwise dependencies are tested one at a
    /// time.
    pub fn minimize(
        mut self,
        runner: &mut dyn WorldRunner,
        baseline: &World,
    ) -> Result<SolverOutcome, OvidError> {
        let mut classifications: BTreeMap<String, CausalClassification> = BTreeMap::new();

        // 1. Stable baseline success is a precondition (§20.6).
        let Some(baseline_outcome) =
            self.run_stable(runner, baseline, baseline, "baseline")?
        else {
            // Nondeterministic baseline: no causal claims at all (FR-053).
            for dependency in &baseline.dependencies {
                classifications
                    .insert(dependency.id.clone(), CausalClassification::Unresolved);
            }
            return Ok(SolverOutcome {
                minimal_world: baseline.clone(),
                classifications,
                experiments: self.experiments,
                nondeterministic: true,
                runs_used: self.runs_used,
            });
        };
        if !baseline_outcome.success {
            return Err(OvidError::Execution(
                "minimization requires a world whose baseline run succeeds (§20.4)".into(),
            ));
        }

        let candidate_ids: Vec<String> = baseline
            .dependencies
            .iter()
            .filter(|d| !matches!(d.treatment, Treatment::Absent | Treatment::Unresolved { .. }))
            .map(|d| d.id.clone())
            .collect();

        let mut minimal = baseline.clone();

        // 2. Group phase: remove everything at once.
        if candidate_ids.len() > 1 {
            let mut all_removed = baseline.clone();
            for id in &candidate_ids {
                all_removed = all_removed.with_treatment(id, Treatment::Absent);
            }
            if let Some(outcome) =
                self.run_stable(runner, &all_removed, baseline, "remove-all")?
            {
                if outcome.success {
                    for id in &candidate_ids {
                        classifications.insert(id.clone(), CausalClassification::Optional);
                        minimal = minimal.with_treatment(id, Treatment::Absent);
                    }
                    return Ok(SolverOutcome {
                        minimal_world: minimal,
                        classifications,
                        experiments: self.experiments,
                        nondeterministic: false,
                        runs_used: self.runs_used,
                    });
                }
            }
        }

        // 3. Individual phase: remove one dependency at a time from the
        //    current minimal world (§14.9: exactly one controlled change).
        let mut nondeterministic = false;
        for id in &candidate_ids {
            let variant = minimal.with_treatment(id, Treatment::Absent);
            match self.run_stable(runner, &variant, &minimal, &format!("remove:{id}")) {
                Ok(Some(outcome)) => {
                    if outcome.success {
                        classifications.insert(id.clone(), CausalClassification::Optional);
                        minimal = variant;
                    } else {
                        classifications.insert(id.clone(), CausalClassification::Required);
                    }
                }
                Ok(None) => {
                    // Variant unstable: no claim for this dependency.
                    classifications.insert(id.clone(), CausalClassification::Unresolved);
                    nondeterministic = true;
                }
                Err(OvidError::BudgetExhausted(_)) => {
                    // Budget ran out mid-minimization: remaining
                    // dependencies stay unresolved rather than guessed.
                    classifications.entry(id.clone()).or_insert(CausalClassification::Unresolved);
                }
                Err(other) => return Err(other),
            }
        }

        // 4. Confirmation replay of the final minimal world (ADR-008's
        //    verify-before-labeling, at solver scope). Failure or budget
        //    exhaustion downgrades to the baseline world.
        if minimal.digest() != baseline.digest() {
            match self.run_once(runner, &minimal, baseline, "confirm-minimal") {
                Ok(outcome) if outcome.success => {}
                Ok(_) | Err(OvidError::BudgetExhausted(_)) => {
                    minimal = baseline.clone();
                    nondeterministic = true;
                }
                Err(other) => return Err(other),
            }
        }

        Ok(SolverOutcome {
            minimal_world: minimal,
            classifications,
            experiments: self.experiments,
            nondeterministic,
            runs_used: self.runs_used,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovid_world::WorldDependency;

    fn world(dependency_ids: &[&str]) -> World {
        World {
            target: "app".into(),
            tools: vec![],
            dependencies: dependency_ids
                .iter()
                .map(|id| WorldDependency {
                    id: id.to_string(),
                    treatment: Treatment::Stub { protocol: "tcp".into() },
                    aliases: vec![id.to_string()],
                    port: None,
                    environment: Default::default(),
                })
                .collect(),
            environment: Default::default(),
        }
    }

    /// A simulated workload that needs a specific dependency set.
    fn needs(required: &'static [&'static str]) -> impl FnMut(&World) -> RunOutcome {
        move |world: &World| {
            for id in required {
                let present = world
                    .dependency(id)
                    .map(|d| !matches!(d.treatment, Treatment::Absent))
                    .unwrap_or(false);
                if !present {
                    return RunOutcome::failed(format!("connect {id}: ECONNREFUSED"));
                }
            }
            RunOutcome::passed()
        }
    }

    #[test]
    fn distinguishes_required_from_optional() {
        let baseline = world(&["postgres", "telemetry", "cache"]);
        let mut runner = needs(&["postgres"]);
        let outcome = MvwSolver::new(ExperimentBudget::default())
            .minimize(&mut runner, &baseline)
            .unwrap();
        assert_eq!(outcome.classifications["postgres"], CausalClassification::Required);
        assert_eq!(outcome.classifications["telemetry"], CausalClassification::Optional);
        assert_eq!(outcome.classifications["cache"], CausalClassification::Optional);
        assert!(!outcome.nondeterministic);
        // Minimal world keeps postgres, drops the rest.
        assert!(matches!(
            outcome.minimal_world.dependency("postgres").unwrap().treatment,
            Treatment::Stub { .. }
        ));
        assert!(matches!(
            outcome.minimal_world.dependency("telemetry").unwrap().treatment,
            Treatment::Absent
        ));
    }

    #[test]
    fn all_optional_short_circuits_in_group_phase() {
        let baseline = world(&["telemetry", "metrics"]);
        let mut runner = needs(&[]);
        let outcome = MvwSolver::new(ExperimentBudget::default())
            .minimize(&mut runner, &baseline)
            .unwrap();
        assert!(outcome.classifications.values().all(|c| *c == CausalClassification::Optional));
        // Group phase: baseline (2) + remove-all (2) = 4 runs, no per-dep loop.
        assert_eq!(outcome.runs_used, 4);
    }

    #[test]
    fn nondeterministic_baseline_makes_no_claims() {
        let baseline = world(&["postgres"]);
        let mut flip = false;
        let mut runner = move |_: &World| {
            flip = !flip;
            if flip {
                RunOutcome::passed()
            } else {
                RunOutcome::failed("flaky test")
            }
        };
        let outcome = MvwSolver::new(ExperimentBudget::default())
            .minimize(&mut runner, &baseline)
            .unwrap();
        assert!(outcome.nondeterministic);
        assert_eq!(outcome.classifications["postgres"], CausalClassification::Unresolved);
        assert_eq!(outcome.minimal_world.digest(), baseline.digest());
    }

    #[test]
    fn budget_exhaustion_leaves_unresolved_not_guessed() {
        let baseline = world(&["a", "b", "c", "d", "e", "f"]);
        let mut runner = needs(&["a", "b", "c", "d", "e", "f"]);
        // Enough for baseline (2) + remove-all (2) + a couple of variants.
        let outcome = MvwSolver::new(ExperimentBudget { max_runs: 8, required_repeats: 2 })
            .minimize(&mut runner, &baseline)
            .unwrap();
        assert!(outcome
            .classifications
            .values()
            .any(|c| *c == CausalClassification::Unresolved));
        assert!(outcome.runs_used <= 8);
    }

    #[test]
    fn failing_baseline_is_an_error() {
        let baseline = world(&["postgres"]);
        let mut runner = |_: &World| RunOutcome::failed("broken");
        let result = MvwSolver::new(ExperimentBudget::default()).minimize(&mut runner, &baseline);
        assert!(result.is_err());
    }

    #[test]
    fn experiments_record_conditions_and_digests() {
        let baseline = world(&["postgres", "telemetry"]);
        let mut runner = needs(&["postgres"]);
        let outcome = MvwSolver::new(ExperimentBudget::default())
            .minimize(&mut runner, &baseline)
            .unwrap();
        assert!(outcome.experiments.iter().any(|e| e.condition == "baseline"));
        assert!(outcome.experiments.iter().any(|e| e.condition == "remove:postgres" && !e.success));
        for record in &outcome.experiments {
            assert!(record.world_digest.starts_with("sha256:"));
        }
    }
}
