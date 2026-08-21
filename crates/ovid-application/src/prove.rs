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
    merge_candidates, merge_executables, EgressIntent, ExecutableCandidate, JournalError,
    JournalEvent, JournalPort, LabError, LaboratoryPort, NetworkCandidate, ProgressPort,
    TrialResult, TrialSpec,
};
use crate::workflow::{AnalysisState, Workflow};
use ovid_domain::{
    assess_baseline, classify_intervention, classify_natural_counterfactual,
    classify_unenforceable, AnalysisScope, BaselineVerdict, CandidateEvidence, CausalConclusion,
    DependencyKey, ReplayEvidence, Treatment, TrialRecord, WorldCandidate, WorldOutcome,
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
    /// External network dependencies observed during baseline (merged).
    pub network_candidates: Vec<NetworkCandidate>,
    /// Named egress intents the lab gateway recorded (what the workload
    /// tried to reach, and whether anything was contacted), deduplicated.
    pub egress_intents: Vec<EgressIntent>,
    /// Environment-provided executables observed during baseline (merged).
    pub executable_candidates: Vec<ExecutableCandidate>,
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

/// Ubiquitous POSIX/coreutils-style utilities present in effectively
/// every execution environment. This is a *scheduling heuristic only*
/// (proposal §10.5's bounded budget): proving `cat` required is far less
/// informative for world synthesis than proving `protoc` required, so a
/// bounded trial budget tests project tooling first and these last.
/// Classification is unaffected — a utility that does get tested is
/// classified by exactly the same rules.
const UBIQUITOUS_UTILITIES: &[&str] = &[
    "awk",
    "basename",
    "cat",
    "chmod",
    "chown",
    "cp",
    "cut",
    "date",
    "df",
    "diff",
    "dirname",
    "du",
    "echo",
    "expr",
    "false",
    "find",
    "grep",
    "head",
    "hostname",
    "id",
    "ln",
    "ls",
    "md5sum",
    "mkdir",
    "mktemp",
    "mv",
    "nproc",
    "od",
    "printf",
    "ps",
    "pwd",
    "readlink",
    "rm",
    "rmdir",
    "sed",
    "seq",
    "sha1sum",
    "sha256sum",
    "sleep",
    "sort",
    "stat",
    "sync",
    "tail",
    "tar",
    "tee",
    "touch",
    "tr",
    "true",
    "uname",
    "uniq",
    "wc",
    "which",
    "xargs",
];

/// Scheduling class for hide-executable trials: 0 = project tooling
/// (tested first), 1 = ubiquitous utility (tested last).
fn hide_schedule_class(name: &str) -> u8 {
    u8::from(UBIQUITOUS_UTILITIES.contains(&name))
}

/// Journal a batch of freshly minted conclusions and record their
/// evidence ids.
fn journal_conclusions(
    journal: &mut dyn JournalPort,
    conclusions: &mut Vec<ClassifiedDependency>,
    raw: Vec<CausalConclusion>,
) -> Result<(), ProveError> {
    for conclusion in raw {
        let evidence = journal.append(&JournalEvent::DependencyClassified {
            conclusion: conclusion.clone(),
        })?;
        conclusions.push(ClassifiedDependency {
            conclusion,
            evidence,
        });
    }
    Ok(())
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
        let result = lab.run_trial(
            &snapshot,
            &TrialSpec {
                label,
                argv: scope.workload_argv.clone(),
                treatment,
                timeout_seconds: policy.timeout_seconds,
            },
        )?;
        *trials_executed += 1;
        journal.append(&JournalEvent::TrialCompleted {
            record: result.record.clone(),
            exit_code: result.exit_code,
            duration_ms: result.duration_ms,
            output_tail: result.output_tail.clone(),
        })?;
        if !result.observations.egress_intents.is_empty() {
            journal.append(&JournalEvent::EgressObserved {
                trial: result.record.label.clone(),
                intents: result.observations.egress_intents.clone(),
            })?;
        }
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
    //
    // The bounded scheduler (proposal §10.5): reuse natural
    // counterfactuals first, screen the network group with one enforced
    // deny-all intervention, then isolate individual executables with
    // per-dependency hide treatments until the budget (minus a reserved
    // replay trial) is spent. Anything the budget drops is reported —
    // never silently capped.
    let stage_start = Instant::now();
    let baseline_observations: Vec<_> = baseline_results.iter().map(|r| &r.observations).collect();
    let network_candidates: Vec<NetworkCandidate> = merge_candidates(&baseline_observations)
        .into_iter()
        .filter(|c| c.externally_controlled)
        .collect();
    let executable_candidates: Vec<ExecutableCandidate> = merge_executables(&baseline_observations);
    // Named egress intents from the baseline posture — what the workload
    // tried to reach — deduplicated for the report.
    let mut egress_intents: Vec<EgressIntent> = Vec::new();
    for observations in &baseline_observations {
        for intent in &observations.egress_intents {
            if !egress_intents.contains(intent) {
                egress_intents.push(intent.clone());
            }
        }
    }
    egress_intents.sort_by(|a, b| (&a.host, a.port).cmp(&(&b.host, b.port)));
    workflow.advance(AnalysisState::CandidatesObserved);
    progress.emit(
        "observation",
        &format!(
            "{} network / {} executable candidate(s)",
            network_candidates.len(),
            executable_candidates.len()
        ),
    );

    let baseline_labels: Vec<String> = baseline_results
        .iter()
        .map(|r| r.record.label.clone())
        .collect();
    let mut conclusions: Vec<ClassifiedDependency> = Vec::new();
    let network_evidence = |c: &NetworkCandidate, unavailable: bool| CandidateEvidence {
        key: c.key.clone(),
        externally_controlled: c.externally_controlled,
        unavailable_under_treatment: unavailable,
        attempted_in_baseline: true,
    };
    // An environment-provided executable is outside the workload's own
    // control (the experiment can vary it via the search path).
    let executable_evidence = |name: &str, unavailable: bool| CandidateEvidence {
        key: DependencyKey::executable(name),
        externally_controlled: true,
        unavailable_under_treatment: unavailable,
        attempted_in_baseline: true,
    };

    if !baseline.supports_experiments() {
        // No experiments can run; every observed candidate stays
        // unresolved with the baseline reason.
        let evidence: Vec<CandidateEvidence> = network_candidates
            .iter()
            .map(|c| network_evidence(c, false))
            .chain(
                executable_candidates
                    .iter()
                    .map(|e| executable_evidence(&e.name, !e.found)),
            )
            .collect();
        journal_conclusions(
            journal,
            &mut conclusions,
            classify_intervention(&baseline, &[], &evidence),
        )?;
    } else {
        // Step 1 — natural counterfactuals (proposal §10.5 step 1):
        // dependencies demonstrably unavailable while the baseline
        // passed are optional without spending a trial.
        let natural: Vec<CandidateEvidence> = network_candidates
            .iter()
            .filter(|c| c.all_failed)
            .map(|c| network_evidence(c, true))
            .chain(
                executable_candidates
                    .iter()
                    .filter(|e| !e.found)
                    .map(|e| executable_evidence(&e.name, true)),
            )
            .collect();
        if !natural.is_empty() {
            progress.emit(
                "experiments",
                &format!("{} natural counterfactual(s) reused", natural.len()),
            );
            journal_conclusions(
                journal,
                &mut conclusions,
                classify_natural_counterfactual(&baseline, &baseline_labels, &natural),
            )?;
        }

        // Step 2 — deny-all-egress screen for the network dependencies
        // the baseline actually reached.
        let screened: Vec<&NetworkCandidate> = network_candidates
            .iter()
            .filter(|c| !c.all_failed)
            .collect();
        if !screened.is_empty() {
            let treatment = Treatment::DenyAllEgress;
            if !lab.capabilities().can_enforce(&treatment) {
                let reason = "this laboratory cannot enforce deny-all egress";
                limitations.push(format!(
                    "{reason}; every network candidate stays unresolved (the experiment \
                     is never silently weakened)"
                ));
                let evidence: Vec<CandidateEvidence> = screened
                    .iter()
                    .map(|c| network_evidence(c, false))
                    .collect();
                journal_conclusions(
                    journal,
                    &mut conclusions,
                    classify_unenforceable(&evidence, &treatment, reason),
                )?;
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
                let evidence: Vec<CandidateEvidence> = screened
                    .iter()
                    .map(|c| {
                        let under_treatment = variant_merged.iter().find(|v| v.key == c.key);
                        // Unavailable only when no variant run saw it
                        // succeed (absence counts: it never got through).
                        network_evidence(c, under_treatment.map(|v| v.all_failed).unwrap_or(true))
                    })
                    .collect();
                let variant_records: Vec<TrialRecord> =
                    variant_results.iter().map(|r| r.record.clone()).collect();

                // Was the group screen ambiguous? The workload failed with
                // more than one externally-controlled dependency changing
                // availability together (proposal §10.5 step 5's coupling
                // case). If so, and the lab can block one dependency at a
                // time, isolate each — otherwise accept the group verdict.
                let group_failed = !variant_records.is_empty()
                    && variant_records.iter().all(|t| !t.outcome.passed);
                let changed: Vec<&NetworkCandidate> = screened
                    .iter()
                    .copied()
                    .filter(|c| {
                        evidence
                            .iter()
                            .any(|e| e.key == c.key && e.unavailable_under_treatment)
                    })
                    .collect();
                let can_isolate = lab.capabilities().can_enforce(&Treatment::BlockDependency {
                    dependency: changed
                        .first()
                        .map(|c| c.key.clone())
                        .unwrap_or_else(|| DependencyKey::network("placeholder:0")),
                });

                if group_failed && changed.len() > 1 && can_isolate {
                    progress.emit(
                        "experiments",
                        &format!(
                            "per-dependency egress isolation ({} services)",
                            changed.len()
                        ),
                    );
                    let runs_per = 1 + policy.confirmation_runs;
                    let mut dropped: Vec<String> = Vec::new();
                    for candidate in &changed {
                        // Reserve one trial for replay verification.
                        if trials_executed + runs_per + 1 > policy.max_trials {
                            dropped.push(candidate.key.logical_identity.clone());
                            continue;
                        }
                        let treatment = Treatment::BlockDependency {
                            dependency: candidate.key.clone(),
                        };
                        let mut block_results: Vec<TrialResult> = Vec::new();
                        for index in 1..=runs_per {
                            match run_trial(
                                lab,
                                journal,
                                &mut trials,
                                &mut trials_executed,
                                format!("block-{}-{index}", candidate.key.logical_identity),
                                treatment.clone(),
                            )? {
                                Some(result) => block_results.push(result),
                                None => break,
                            }
                        }
                        // Only this dependency was blocked; enforcement
                        // guarantees it was unavailable while the rest
                        // stayed reachable — a single controlled change.
                        let block_records: Vec<TrialRecord> =
                            block_results.iter().map(|r| r.record.clone()).collect();
                        journal_conclusions(
                            journal,
                            &mut conclusions,
                            classify_intervention(
                                &baseline,
                                &block_records,
                                &[network_evidence(candidate, true)],
                            ),
                        )?;
                    }
                    if !dropped.is_empty() {
                        limitations.push(format!(
                            "trial budget reached before per-dependency isolation of: {} \
                             (raise --max-trials to resolve them)",
                            dropped.join(", ")
                        ));
                        for identity in &dropped {
                            journal_conclusions(
                                journal,
                                &mut conclusions,
                                classify_intervention(
                                    &baseline,
                                    &[],
                                    &[CandidateEvidence {
                                        key: DependencyKey::network(identity),
                                        externally_controlled: true,
                                        unavailable_under_treatment: false,
                                        attempted_in_baseline: true,
                                    }],
                                ),
                            )?;
                        }
                    }
                } else {
                    journal_conclusions(
                        journal,
                        &mut conclusions,
                        classify_intervention(&baseline, &variant_records, &evidence),
                    )?;
                }
            }
        }

        // Step 3 — per-dependency isolation for executables the baseline
        // used (proposal §10.5 step 5): hide exactly one tool per trial.
        // Project tooling is scheduled before ubiquitous utilities so a
        // bounded budget is spent on the most informative candidates
        // first; the order affects only budget spending, never the
        // classification rules, and remains deterministic.
        let mut hide_targets: Vec<&ExecutableCandidate> =
            executable_candidates.iter().filter(|e| e.found).collect();
        hide_targets.sort_by_key(|e| (hide_schedule_class(&e.name), e.name.clone()));
        if !hide_targets.is_empty() {
            if !lab.capabilities().executable_hiding {
                let reason = "this laboratory cannot hide executables";
                limitations.push(format!(
                    "{reason}; {} executable candidate(s) stay unresolved",
                    hide_targets.len()
                ));
                for exe in &hide_targets {
                    let treatment = Treatment::HideExecutable {
                        name: exe.name.clone(),
                    };
                    journal_conclusions(
                        journal,
                        &mut conclusions,
                        classify_unenforceable(
                            &[executable_evidence(&exe.name, false)],
                            &treatment,
                            reason,
                        ),
                    )?;
                }
            } else {
                progress.emit(
                    "experiments",
                    &format!(
                        "hide-executable trials ({} candidate(s))",
                        hide_targets.len()
                    ),
                );
                let runs_per_target = 1 + policy.confirmation_runs;
                let mut dropped: Vec<String> = Vec::new();
                for exe in &hide_targets {
                    // Reserve one trial so replay verification stays
                    // possible after the executable sweep.
                    if trials_executed + runs_per_target + 1 > policy.max_trials {
                        dropped.push(exe.name.clone());
                        continue;
                    }
                    let treatment = Treatment::HideExecutable {
                        name: exe.name.clone(),
                    };
                    let mut variant_records: Vec<TrialRecord> = Vec::new();
                    let mut unsupported: Option<String> = None;
                    for index in 1..=runs_per_target {
                        match run_trial(
                            lab,
                            journal,
                            &mut trials,
                            &mut trials_executed,
                            format!("hide-{}-{index}", exe.name),
                            treatment.clone(),
                        ) {
                            Ok(Some(result)) => variant_records.push(result.record.clone()),
                            Ok(None) => break,
                            // The laboratory may discover per-target that
                            // enforcement is impossible (e.g. the tool is
                            // not resolved via the search path at all):
                            // that one candidate stays unresolved, the
                            // sweep continues.
                            Err(ProveError::Lab(LabError::Unsupported(reason))) => {
                                unsupported = Some(reason);
                                break;
                            }
                            Err(other) => return Err(other),
                        }
                    }
                    // Enforcement guarantees the tool was absent for the
                    // whole trial, so unavailability is demonstrated.
                    let evidence = vec![executable_evidence(&exe.name, true)];
                    let raw = match unsupported {
                        Some(reason) => classify_unenforceable(&evidence, &treatment, &reason),
                        None => classify_intervention(&baseline, &variant_records, &evidence),
                    };
                    journal_conclusions(journal, &mut conclusions, raw)?;
                }
                if !dropped.is_empty() {
                    limitations.push(format!(
                        "trial budget reached before hide-executable trials for: {} \
                         (raise --max-trials to test them)",
                        dropped.join(", ")
                    ));
                    for name in &dropped {
                        journal_conclusions(
                            journal,
                            &mut conclusions,
                            classify_intervention(
                                &baseline,
                                &[],
                                &[executable_evidence(name, false)],
                            ),
                        )?;
                    }
                }
            }
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
        network_candidates,
        egress_intents,
        executable_candidates,
        trials,
        conclusions,
        world,
        limitations,
        timings,
        trials_executed,
    })
}
