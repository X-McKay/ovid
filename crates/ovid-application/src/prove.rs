//! The `prove` use case (proposal §9.2) — Ovid's primary loop.
//!
//! ```text
//! prepare environment -> provision -> freeze immutable snapshot
//! -> repeated baseline trials (stability gate)
//! -> collect candidate dependencies from observation
//! -> enforced deny-all-egress intervention (+ confirmation)
//! -> domain classification (required / optional / unresolved)
//! -> synthesize world candidate -> clean replay -> verified or preserved
//! ```
//!
//! Every baseline and variant forks from the same immutable
//! post-provisioning snapshot (proposal §10.8); every trial carries an
//! enforcement report; every conclusion comes from the domain classifier
//! and is journaled before it appears in any projection.

use crate::ports::{
    merge_candidates, JournalError, JournalEvent, JournalPort, LabError, LaboratoryPort,
    ProgressPort, TrialResult, TrialSpec,
};
use crate::workflow::{AnalysisState, Workflow};
use ovid_domain::{
    assess_baseline, classify_intervention, classify_unenforceable, AnalysisScope, BaselineVerdict,
    CandidateEvidence, CausalConclusion, ReplayEvidence, Treatment, TrialRecord, WorldCandidate,
    WorldOutcome,
};
use serde::Serialize;
use std::time::Instant;
use thiserror::Error;

/// Bounded experiment policy (proposal §4.5's `standard` depth defaults).
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct ProvePolicy {
    /// Baseline repetitions from the frozen snapshot.
    pub baseline_runs: usize,
    /// Extra confirmation runs per intervention.
    pub confirmation_runs: usize,
    /// Hard ceiling on trials in one analysis (proposal §10.5 step 7).
    pub max_trials: usize,
    /// Per-trial wall-clock timeout.
    pub timeout_seconds: u64,
    /// Attempt clean replay verification after world synthesis.
    pub attempt_replay: bool,
}

impl Default for ProvePolicy {
    fn default() -> Self {
        ProvePolicy {
            baseline_runs: 2,
            confirmation_runs: 1,
            max_trials: 12,
            timeout_seconds: 1800,
            attempt_replay: true,
        }
    }
}

impl ProvePolicy {
    /// Description recorded into the analysis scope.
    pub fn describe(&self) -> String {
        format!(
            "baseline-runs={} confirmation-runs={} max-trials={}",
            self.baseline_runs, self.confirmation_runs, self.max_trials
        )
    }
}

/// What the CLI asks the use case to prove.
#[derive(Clone, Debug)]
pub struct ProveRequest {
    /// Scope with repository/revision/workload/argv/predicate/policy
    /// filled in; `environment_digest` and `observer` are completed here.
    pub scope: AnalysisScope,
    /// Provisioning command (dependency install), when discovered.
    pub provision_argv: Option<Vec<String>>,
}

/// One classified dependency with its journal evidence id.
#[derive(Clone, PartialEq, Serialize, Debug)]
pub struct ClassifiedDependency {
    pub conclusion: CausalConclusion,
    /// Ledger evidence id of the `dependency-classified` journal event.
    pub evidence: String,
}

/// Wall-clock stage timing (proposal §16.4).
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct StageTiming {
    pub stage: String,
    pub millis: u64,
}

/// The complete result of one `prove` run — the source every projection
/// (terminal report, proof.json, manifest, claims) renders from.
#[derive(Clone, Serialize, Debug)]
pub struct ProveReport {
    pub scope: AnalysisScope,
    /// The provisioning command, preserved so `replay` can re-provision.
    pub provision_argv: Option<Vec<String>>,
    pub provision: Option<TrialRecord>,
    pub baseline: BaselineVerdict,
    pub trials: Vec<TrialRecord>,
    pub conclusions: Vec<ClassifiedDependency>,
    pub world: WorldOutcome,
    pub limitations: Vec<String>,
    pub timings: Vec<StageTiming>,
    pub trials_executed: usize,
}

/// Failures of the prove loop itself (trial *outcomes* are results, not
/// errors — a failing workload is evidence).
#[derive(Error, Debug)]
pub enum ProveError {
    #[error(transparent)]
    Lab(#[from] LabError),
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Run one clean, untreated trial from the snapshot — shared by baseline
/// runs, replay verification, and the `ovid replay` command (§9.3).
pub fn run_clean_replay(
    lab: &mut dyn LaboratoryPort,
    snapshot: &crate::ports::SnapshotRef,
    label: &str,
    argv: &[String],
    timeout_seconds: u64,
) -> Result<TrialResult, LabError> {
    lab.run_trial(
        snapshot,
        &TrialSpec {
            label: label.to_string(),
            argv: argv.to_vec(),
            treatment: Treatment::None,
            timeout_seconds,
        },
    )
}

/// The prove use case (proposal §9.2). See the module docs for the loop.
pub fn prove(
    lab: &mut dyn LaboratoryPort,
    journal: &mut dyn JournalPort,
    progress: &dyn ProgressPort,
    request: &ProveRequest,
    policy: &ProvePolicy,
) -> Result<ProveReport, ProveError> {
    let mut workflow = Workflow::new();
    let mut scope = request.scope.clone();
    scope.observer = lab.identity().describe();
    scope.experiment_policy = policy.describe();
    let mut limitations: Vec<String> = Vec::new();
    let mut timings: Vec<StageTiming> = Vec::new();
    let mut trials: Vec<TrialRecord> = Vec::new();
    let mut trials_executed = 0usize;

    // Source resolution and workload selection happened upstream (the
    // scope carries the exact revision and argv); record them.
    workflow.advance(AnalysisState::SourceResolved);
    workflow.advance(AnalysisState::Inspected);
    journal.append(&JournalEvent::WorkloadSelected {
        workload: scope.workload.clone(),
        argv: scope.workload_argv.clone(),
    })?;

    // ---------------------------------------------------- environment
    let stage_start = Instant::now();
    progress.emit("environment", "preparing workspace");
    let environment = lab.prepare(request.provision_argv.as_deref())?;
    scope.environment_digest = environment.environment_digest.clone();
    workflow.advance(AnalysisState::EnvironmentPrepared);
    let provision = environment.provision.clone();
    journal.append(&JournalEvent::EnvironmentPrepared {
        environment_digest: environment.environment_digest.clone(),
        provision: provision.clone(),
    })?;
    if let Some(record) = &provision {
        if !record.outcome.passed {
            limitations.push(format!(
                "provisioning command failed ({}); workloads ran against a partially \
                 provisioned environment",
                record.label
            ));
        }
    }
    workflow.advance(AnalysisState::Provisioned);
    timings.push(StageTiming {
        stage: "environment".into(),
        millis: stage_start.elapsed().as_millis() as u64,
    });

    // ------------------------------------------------------- snapshot
    let stage_start = Instant::now();
    let snapshot = lab.snapshot(&environment, "post-provision")?;
    journal.append(&JournalEvent::SnapshotCreated {
        id: snapshot.id.clone(),
        label: snapshot.label.clone(),
    })?;
    timings.push(StageTiming {
        stage: "snapshot".into(),
        millis: stage_start.elapsed().as_millis() as u64,
    });

    // A budget-aware trial runner: journals every completed trial.
    let run_trial = |lab: &mut dyn LaboratoryPort,
                     journal: &mut dyn JournalPort,
                     trials: &mut Vec<TrialRecord>,
                     trials_executed: &mut usize,
                     label: String,
                     treatment: Treatment|
     -> Result<Option<TrialResult>, ProveError> {
        if *trials_executed >= policy.max_trials {
            return Ok(None);
        }
        *trials_executed += 1;
        let result = lab.run_trial(
            &snapshot,
            &TrialSpec {
                label,
                argv: scope.workload_argv.clone(),
                treatment,
                timeout_seconds: policy.timeout_seconds,
            },
        )?;
        journal.append(&JournalEvent::TrialCompleted {
            record: result.record.clone(),
            exit_code: result.exit_code,
            duration_ms: result.duration_ms,
            output_tail: result.output_tail.clone(),
        })?;
        if let Some(signature) = &result.record.outcome.failure_signature {
            progress.emit(
                "trial",
                &format!("{} failed ({signature})", result.record.label),
            );
        }
        trials.push(result.record.clone());
        Ok(Some(result))
    };

    // ------------------------------------------------------- baseline
    let stage_start = Instant::now();
    progress.emit("baseline", &format!("{} clean runs", policy.baseline_runs));
    let mut baseline_results: Vec<TrialResult> = Vec::new();
    for index in 1..=policy.baseline_runs.max(1) {
        match run_trial(
            lab,
            journal,
            &mut trials,
            &mut trials_executed,
            format!("baseline-{index}"),
            Treatment::None,
        )? {
            Some(result) => baseline_results.push(result),
            None => {
                limitations.push("trial budget exhausted during baseline".into());
                break;
            }
        }
    }
    let baseline_outcomes: Vec<_> = baseline_results
        .iter()
        .map(|r| r.record.outcome.clone())
        .collect();
    let baseline = assess_baseline(&baseline_outcomes);
    journal.append(&JournalEvent::BaselineClassified {
        verdict: baseline.clone(),
    })?;
    workflow.advance(AnalysisState::BaselineValidated);
    timings.push(StageTiming {
        stage: "baseline".into(),
        millis: stage_start.elapsed().as_millis() as u64,
    });
    if !baseline_results.iter().any(|r| r.observations.observed) {
        limitations.push(
            "boundary observation was unavailable: no dependency candidates could be \
             collected from baseline runs"
                .into(),
        );
    }

    // ---------------------------------------- candidates + experiments
    let stage_start = Instant::now();
    let baseline_observations: Vec<_> = baseline_results.iter().map(|r| &r.observations).collect();
    let candidates: Vec<_> = merge_candidates(&baseline_observations)
        .into_iter()
        .filter(|c| c.externally_controlled)
        .collect();
    workflow.advance(AnalysisState::CandidatesObserved);
    progress.emit(
        "observation",
        &format!("{} external candidate(s)", candidates.len()),
    );

    let mut conclusions: Vec<ClassifiedDependency> = Vec::new();
    if !candidates.is_empty() {
        let treatment = Treatment::DenyAllEgress;
        let raw_conclusions: Vec<CausalConclusion> = if !baseline.supports_experiments() {
            let evidence: Vec<CandidateEvidence> = candidates
                .iter()
                .map(|c| CandidateEvidence {
                    key: c.key.clone(),
                    externally_controlled: c.externally_controlled,
                    unavailable_under_treatment: false,
                    attempted_in_baseline: true,
                })
                .collect();
            classify_intervention(&baseline, &[], &evidence)
        } else if !lab.capabilities().can_enforce(&treatment) {
            let reason = "this laboratory cannot enforce deny-all egress";
            limitations.push(format!(
                "{reason}; every network candidate stays unresolved (the experiment is \
                 never silently weakened)"
            ));
            let evidence: Vec<CandidateEvidence> = candidates
                .iter()
                .map(|c| CandidateEvidence {
                    key: c.key.clone(),
                    externally_controlled: c.externally_controlled,
                    unavailable_under_treatment: false,
                    attempted_in_baseline: true,
                })
                .collect();
            classify_unenforceable(&evidence, &treatment, reason)
        } else {
            progress.emit("experiments", "deny-all-egress intervention");
            let mut variant_results: Vec<TrialResult> = Vec::new();
            for index in 1..=(1 + policy.confirmation_runs) {
                match run_trial(
                    lab,
                    journal,
                    &mut trials,
                    &mut trials_executed,
                    format!("no-egress-{index}"),
                    treatment.clone(),
                )? {
                    Some(result) => variant_results.push(result),
                    None => {
                        limitations.push("trial budget exhausted during intervention".into());
                        break;
                    }
                }
            }
            let variant_observations: Vec<_> =
                variant_results.iter().map(|r| &r.observations).collect();
            let variant_merged = merge_candidates(&variant_observations);
            let evidence: Vec<CandidateEvidence> = candidates
                .iter()
                .map(|c| {
                    let under_treatment = variant_merged.iter().find(|v| v.key == c.key);
                    CandidateEvidence {
                        key: c.key.clone(),
                        externally_controlled: c.externally_controlled,
                        // Unavailable only when no variant run saw it
                        // succeed (absence counts: it never got through).
                        unavailable_under_treatment: under_treatment
                            .map(|v| v.all_failed)
                            .unwrap_or(true),
                        attempted_in_baseline: true,
                    }
                })
                .collect();
            let variant_records: Vec<TrialRecord> =
                variant_results.iter().map(|r| r.record.clone()).collect();
            classify_intervention(&baseline, &variant_records, &evidence)
        };
        for conclusion in raw_conclusions {
            let evidence = journal.append(&JournalEvent::DependencyClassified {
                conclusion: conclusion.clone(),
            })?;
            conclusions.push(ClassifiedDependency {
                conclusion,
                evidence,
            });
        }
    }
    workflow.advance(AnalysisState::ExperimentsCompleted);
    timings.push(StageTiming {
        stage: "experiments".into(),
        millis: stage_start.elapsed().as_millis() as u64,
    });

    // ------------------------------------------------ world + replay
    let stage_start = Instant::now();
    let world = if !baseline.supports_experiments() {
        WorldOutcome::NotSynthesized {
            reason: format!(
                "baseline is not stable-passing ({}); a world synthesized from an \
                 unreproducible workload would be unverifiable",
                baseline.describe()
            ),
        }
    } else {
        use ovid_domain::Necessity;
        let mut candidate_world = WorldCandidate {
            workload_argv: scope.workload_argv.clone(),
            ..Default::default()
        };
        for classified in &conclusions {
            let key = classified.conclusion.dependency().clone();
            match classified.conclusion.necessity() {
                Necessity::Required => candidate_world.required.push(key),
                Necessity::Optional => candidate_world.optional.push(key),
                Necessity::Unresolved => candidate_world.unresolved.push(key),
            }
        }
        let proposed = candidate_world.propose(&scope);
        journal.append(&JournalEvent::WorldSynthesized {
            digest: proposed.digest().hex().to_string(),
            required: proposed.candidate().required.len(),
            optional: proposed.candidate().optional.len(),
            unresolved: proposed.candidate().unresolved.len(),
        })?;
        workflow.advance(AnalysisState::WorldSynthesized);
        if !policy.attempt_replay {
            workflow.advance(AnalysisState::ReplayUnavailable);
            WorldOutcome::Proposed {
                world: proposed,
                reason: "replay disabled by policy".into(),
            }
        } else if trials_executed >= policy.max_trials {
            workflow.advance(AnalysisState::ReplayUnavailable);
            WorldOutcome::Proposed {
                world: proposed,
                reason: "trial budget exhausted before replay".into(),
            }
        } else {
            progress.emit("replay", "clean replay from snapshot");
            let replay = run_trial(
                lab,
                journal,
                &mut trials,
                &mut trials_executed,
                "replay".into(),
                Treatment::None,
            )?
            .expect("budget checked above");
            journal.append(&JournalEvent::ReplayCompleted {
                label: replay.record.label.clone(),
                passed: replay.record.outcome.passed,
            })?;
            match ReplayEvidence::from_clean_replay(&replay.record) {
                Some(evidence) => {
                    workflow.advance(AnalysisState::ReplayVerified);
                    WorldOutcome::Verified {
                        world: proposed.verify(evidence),
                    }
                }
                None => {
                    workflow.advance(AnalysisState::ReplayFailed);
                    WorldOutcome::ReplayFailed {
                        world: proposed,
                        failure: replay.record.clone(),
                    }
                }
            }
        }
    };
    timings.push(StageTiming {
        stage: "world".into(),
        millis: stage_start.elapsed().as_millis() as u64,
    });

    for limitation in &limitations {
        journal.append(&JournalEvent::LimitationRecorded {
            detail: limitation.clone(),
        })?;
    }
    workflow.advance(AnalysisState::Finalized);
    let _ = lab.destroy(environment);

    Ok(ProveReport {
        scope,
        provision_argv: request.provision_argv.clone(),
        provision,
        baseline,
        trials,
        conclusions,
        world,
        limitations,
        timings,
        trials_executed,
    })
}
