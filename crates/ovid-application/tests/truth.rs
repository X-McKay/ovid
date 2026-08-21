//! Truth-fixture scenarios for the prove loop (proposal §17.3): known
//! ground truth in a scripted laboratory, asserted end to end through the
//! use case — the acceptance scenario of migration Phase 0.

use ovid_application::{prove, JournalEvent, NullProgress, ProveError, ProvePolicy, ProveRequest};
use ovid_domain::{AnalysisScope, Necessity, TrialOutcome, WorldOutcome};
use ovid_testkit::{external_candidate, FixtureLaboratory, RecordingJournal};

fn request() -> ProveRequest {
    ProveRequest {
        scope: AnalysisScope {
            repository: "fixture://truth".into(),
            revision: "0000".into(),
            workload: "test".into(),
            workload_argv: vec!["make".into(), "test".into()],
            success_predicate: "exit-code == 0".into(),
            execution_policy: "fixture".into(),
            ..Default::default()
        },
        provision_argv: Some(vec!["make".into(), "deps".into()]),
    }
}

fn policy() -> ProvePolicy {
    ProvePolicy::default()
}

#[test]
fn required_service_is_proven_and_world_verified() -> Result<(), ProveError> {
    // Ground truth: postgres:5432 is required. Baseline passes; enforced
    // egress denial fails repeatedly while only postgres changed
    // availability; clean replay passes.
    let mut lab = FixtureLaboratory::new()
        .with_baseline_outcomes(vec![TrialOutcome::passed()])
        .with_baseline_candidates(vec![external_candidate("postgres:5432", false)])
        .with_no_egress_outcomes(vec![TrialOutcome::failed("connect refused")])
        .with_no_egress_candidates(vec![external_candidate("postgres:5432", true)]);
    let mut journal = RecordingJournal::default();
    let report = prove(&mut lab, &mut journal, &NullProgress, &request(), &policy())?;

    assert!(report.baseline.supports_experiments());
    let classified = &report.conclusions[0];
    assert_eq!(classified.conclusion.necessity(), Necessity::Required);
    assert!(
        classified.conclusion.confidence() >= 0.9,
        "2 trials confirm"
    );
    assert!(classified.evidence.starts_with("evidence:"));
    assert!(matches!(report.world, WorldOutcome::Verified { .. }));
    // 2 baseline + 2 egress + 1 replay
    assert_eq!(report.trials_executed, 5);
    assert!(journal
        .events
        .iter()
        .any(|e| matches!(e, JournalEvent::ReplayCompleted { passed: true, .. })));
    Ok(())
}

#[test]
fn optional_service_is_proven_by_passing_without_it() -> Result<(), ProveError> {
    // Ground truth: redis:6379 is optional — the workload passes while
    // redis is demonstrably unavailable.
    let mut lab = FixtureLaboratory::new()
        .with_baseline_outcomes(vec![TrialOutcome::passed()])
        .with_baseline_candidates(vec![external_candidate("redis:6379", false)])
        .with_no_egress_outcomes(vec![TrialOutcome::passed()])
        .with_no_egress_candidates(vec![external_candidate("redis:6379", true)]);
    let mut journal = RecordingJournal::default();
    let report = prove(&mut lab, &mut journal, &NullProgress, &request(), &policy())?;

    assert_eq!(
        report.conclusions[0].conclusion.necessity(),
        Necessity::Optional
    );
    assert!(matches!(report.world, WorldOutcome::Verified { .. }));
    Ok(())
}

#[test]
fn coupled_services_stay_unresolved_until_individually_varied() -> Result<(), ProveError> {
    // Ground truth withheld from Ovid: postgres and kafka both vanish
    // under the group treatment and the workload fails — neither may be
    // called required (proposal §17.3 scenario 2).
    let mut lab = FixtureLaboratory::new()
        .with_baseline_outcomes(vec![TrialOutcome::passed()])
        .with_baseline_candidates(vec![
            external_candidate("postgres:5432", false),
            external_candidate("kafka:9092", false),
        ])
        .with_no_egress_outcomes(vec![TrialOutcome::failed("connect refused")])
        .with_no_egress_candidates(vec![
            external_candidate("postgres:5432", true),
            external_candidate("kafka:9092", true),
        ]);
    let mut journal = RecordingJournal::default();
    let report = prove(&mut lab, &mut journal, &NullProgress, &request(), &policy())?;

    assert_eq!(report.conclusions.len(), 2);
    for classified in &report.conclusions {
        assert_eq!(classified.conclusion.necessity(), Necessity::Unresolved);
        assert!(classified
            .conclusion
            .reason()
            .contains("individual variation"));
    }
    Ok(())
}

#[test]
fn flaky_baseline_never_receives_causal_labels_or_a_world() -> Result<(), ProveError> {
    // Ground truth: the workload is flaky (proposal §17.3 scenario 3).
    let mut lab = FixtureLaboratory::new()
        .with_baseline_outcomes(vec![TrialOutcome::passed(), TrialOutcome::failed("flake")])
        .with_baseline_candidates(vec![external_candidate("postgres:5432", false)]);
    let mut journal = RecordingJournal::default();
    let report = prove(&mut lab, &mut journal, &NullProgress, &request(), &policy())?;

    assert!(!report.baseline.supports_experiments());
    for classified in &report.conclusions {
        assert_eq!(classified.conclusion.necessity(), Necessity::Unresolved);
    }
    assert!(matches!(report.world, WorldOutcome::NotSynthesized { .. }));
    // No intervention trials ran: 2 baseline runs only.
    assert_eq!(report.trials_executed, 2);
    Ok(())
}

#[test]
fn unenforceable_treatment_yields_unresolved_not_weakened_experiments() -> Result<(), ProveError> {
    // A laboratory without egress control: candidates stay unresolved and
    // the limitation is recorded; no deny-all trial is attempted.
    let mut lab = FixtureLaboratory::new()
        .with_capabilities(ovid_application::LabCapabilities {
            deny_all_egress: false,
            clean_snapshot_restore: true,
            observation: true,
            ..Default::default()
        })
        .with_baseline_outcomes(vec![TrialOutcome::passed()])
        .with_baseline_candidates(vec![external_candidate("postgres:5432", false)]);
    let mut journal = RecordingJournal::default();
    let report = prove(&mut lab, &mut journal, &NullProgress, &request(), &policy())?;

    assert_eq!(
        report.conclusions[0].conclusion.necessity(),
        Necessity::Unresolved
    );
    assert!(report.conclusions[0]
        .conclusion
        .reason()
        .contains("could not be enforced"));
    assert!(report
        .limitations
        .iter()
        .any(|l| l.contains("never silently weakened")));
    assert!(
        !lab.trials_run.iter().any(|l| l.starts_with("no-egress")),
        "an unenforceable treatment must not run at all"
    );
    Ok(())
}

#[test]
fn replay_failure_is_preserved_never_promoted() -> Result<(), ProveError> {
    // Baseline passes twice, but the replay fails: the world must be
    // ReplayFailed with the failure preserved (proposal §11.3).
    let mut lab = FixtureLaboratory::new().with_baseline_outcomes(vec![
        TrialOutcome::passed(),
        TrialOutcome::passed(),
        TrialOutcome::failed("port already bound"),
    ]);
    let mut journal = RecordingJournal::default();
    let report = prove(&mut lab, &mut journal, &NullProgress, &request(), &policy())?;

    match &report.world {
        WorldOutcome::ReplayFailed { failure, .. } => {
            assert_eq!(
                failure.outcome.failure_signature.as_deref(),
                Some("port already bound")
            );
        }
        other => panic!("expected ReplayFailed, got {}", other.label()),
    }
    Ok(())
}

#[test]
fn trial_budget_bounds_execution_and_is_reported() -> Result<(), ProveError> {
    let mut lab = FixtureLaboratory::new()
        .with_baseline_outcomes(vec![TrialOutcome::passed()])
        .with_baseline_candidates(vec![external_candidate("postgres:5432", false)])
        .with_no_egress_outcomes(vec![TrialOutcome::failed("refused")])
        .with_no_egress_candidates(vec![external_candidate("postgres:5432", true)]);
    let mut journal = RecordingJournal::default();
    let tight = ProvePolicy {
        max_trials: 3, // 2 baseline + 1 intervention; no confirmation, no replay
        ..ProvePolicy::default()
    };
    let report = prove(&mut lab, &mut journal, &NullProgress, &request(), &tight)?;

    assert_eq!(report.trials_executed, 3);
    assert!(report
        .limitations
        .iter()
        .any(|l| l.contains("budget exhausted")));
    // A single unconfirmed failing trial still classifies (lower
    // confidence), but replay never ran, so the world stays proposed.
    assert!(matches!(report.world, WorldOutcome::Proposed { .. }));
    Ok(())
}
