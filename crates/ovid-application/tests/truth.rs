//! Truth-fixture scenarios for the prove loop (proposal §17.3): known
//! ground truth in a scripted laboratory, asserted end to end through the
//! use case — the acceptance scenario of migration Phase 0.

use ovid_application::{prove, JournalEvent, NullProgress, ProveError, ProvePolicy, ProveRequest};
use ovid_domain::{AnalysisScope, DependencyKind, Necessity, TrialOutcome, WorldOutcome};
use ovid_testkit::{executable_candidate, external_candidate, FixtureLaboratory, RecordingJournal};

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
fn hiding_a_required_executable_proves_it_required() -> Result<(), ProveError> {
    // Ground truth (proposal §4.3's protoc example): the workload uses
    // protoc during a passing baseline; with protoc hidden from the
    // search path it fails 2/2 — required by individual variation.
    let mut lab = FixtureLaboratory::new()
        .with_baseline_outcomes(vec![TrialOutcome::passed()])
        .with_baseline_executables(vec![executable_candidate("protoc", true)])
        .with_hide_outcomes("protoc", vec![TrialOutcome::failed("protoc: not found")]);
    let mut journal = RecordingJournal::default();
    let report = prove(&mut lab, &mut journal, &NullProgress, &request(), &policy())?;

    let classified = &report.conclusions[0];
    assert_eq!(
        classified.conclusion.dependency().kind,
        DependencyKind::Executable
    );
    assert_eq!(classified.conclusion.necessity(), Necessity::Required);
    assert!(classified.conclusion.confidence() >= 0.9);
    // 2 baseline + 2 hide + 1 replay; the required tool lands in the world.
    assert_eq!(report.trials_executed, 5);
    match &report.world {
        WorldOutcome::Verified { world } => {
            assert!(world
                .world()
                .candidate()
                .required
                .iter()
                .any(|k| k.logical_identity == "protoc"));
        }
        other => panic!("expected verified world, got {}", other.label()),
    }
    Ok(())
}

#[test]
fn hiding_an_optional_executable_proves_it_optional() -> Result<(), ProveError> {
    let mut lab = FixtureLaboratory::new()
        .with_baseline_outcomes(vec![TrialOutcome::passed()])
        .with_baseline_executables(vec![executable_candidate("dot", true)])
        .with_hide_outcomes("dot", vec![TrialOutcome::passed()]);
    let mut journal = RecordingJournal::default();
    let report = prove(&mut lab, &mut journal, &NullProgress, &request(), &policy())?;

    assert_eq!(
        report.conclusions[0].conclusion.necessity(),
        Necessity::Optional
    );
    Ok(())
}

#[test]
fn missing_executable_during_passing_baseline_is_a_natural_counterfactual() -> Result<(), ProveError>
{
    // The workload searched for `docker`, never found it, and passed
    // anyway: optional without spending a single trial (§10.5 step 1).
    let mut lab = FixtureLaboratory::new()
        .with_baseline_outcomes(vec![TrialOutcome::passed()])
        .with_baseline_executables(vec![executable_candidate("docker", false)]);
    let mut journal = RecordingJournal::default();
    let report = prove(&mut lab, &mut journal, &NullProgress, &request(), &policy())?;

    let classified = &report.conclusions[0];
    assert_eq!(classified.conclusion.necessity(), Necessity::Optional);
    assert!(classified
        .conclusion
        .reason()
        .contains("natural counterfactual"));
    assert!(
        !lab.trials_run.iter().any(|l| l.starts_with("hide-")),
        "a missing tool needs no hide trial"
    );
    // 2 baseline + 1 replay only.
    assert_eq!(report.trials_executed, 3);
    Ok(())
}

#[test]
fn hide_trials_respect_the_budget_and_report_what_was_dropped() -> Result<(), ProveError> {
    // Three executables but budget for only one hide pair after
    // baseline + replay: the untested ones are reported unresolved with
    // an explicit limitation — never silently skipped.
    let mut lab = FixtureLaboratory::new()
        .with_baseline_outcomes(vec![TrialOutcome::passed()])
        .with_baseline_executables(vec![
            executable_candidate("aa-tool", true),
            executable_candidate("bb-tool", true),
            executable_candidate("cc-tool", true),
        ])
        .with_hide_outcomes("aa-tool", vec![TrialOutcome::failed("missing")]);
    let mut journal = RecordingJournal::default();
    let tight = ProvePolicy {
        max_trials: 5, // 2 baseline + 2 hide + 1 replay
        ..ProvePolicy::default()
    };
    let report = prove(&mut lab, &mut journal, &NullProgress, &request(), &tight)?;

    let necessity_of = |name: &str| {
        report
            .conclusions
            .iter()
            .find(|c| c.conclusion.dependency().logical_identity == name)
            .map(|c| c.conclusion.necessity())
    };
    assert_eq!(necessity_of("aa-tool"), Some(Necessity::Required));
    assert_eq!(necessity_of("bb-tool"), Some(Necessity::Unresolved));
    assert_eq!(necessity_of("cc-tool"), Some(Necessity::Unresolved));
    assert!(report
        .limitations
        .iter()
        .any(|l| l.contains("bb-tool") && l.contains("cc-tool")));
    // Budget respected AND replay still happened.
    assert_eq!(report.trials_executed, 5);
    assert!(matches!(report.world, WorldOutcome::Verified { .. }));
    Ok(())
}

#[test]
fn budget_is_spent_on_project_tooling_before_ubiquitous_utilities() -> Result<(), ProveError> {
    // `cat` sorts before `protoc` alphabetically, but a bounded budget
    // must test the project tool first — proving coreutils required is
    // the least informative way to spend trials. The untested utility
    // is still reported, never silently skipped.
    let mut lab = FixtureLaboratory::new()
        .with_baseline_outcomes(vec![TrialOutcome::passed()])
        .with_baseline_executables(vec![
            executable_candidate("cat", true),
            executable_candidate("protoc", true),
        ])
        .with_hide_outcomes("protoc", vec![TrialOutcome::failed("protoc: not found")]);
    let mut journal = RecordingJournal::default();
    let tight = ProvePolicy {
        max_trials: 5, // 2 baseline + one hide pair + 1 replay
        ..ProvePolicy::default()
    };
    let report = prove(&mut lab, &mut journal, &NullProgress, &request(), &tight)?;

    assert!(
        lab.trials_run.iter().any(|l| l.starts_with("hide-protoc")),
        "project tooling tested first: {:?}",
        lab.trials_run
    );
    assert!(
        !lab.trials_run.iter().any(|l| l.starts_with("hide-cat")),
        "the utility yields its budget slot: {:?}",
        lab.trials_run
    );
    let necessity_of = |name: &str| {
        report
            .conclusions
            .iter()
            .find(|c| c.conclusion.dependency().logical_identity == name)
            .map(|c| c.conclusion.necessity())
    };
    assert_eq!(necessity_of("protoc"), Some(Necessity::Required));
    assert_eq!(necessity_of("cat"), Some(Necessity::Unresolved));
    assert!(report.limitations.iter().any(|l| l.contains("cat")));
    Ok(())
}

#[test]
fn network_natural_counterfactual_skips_the_egress_trial() -> Result<(), ProveError> {
    // The only network candidate already failed every attempt during the
    // passing baseline: optional naturally; no deny-all trial needed.
    let mut lab = FixtureLaboratory::new()
        .with_baseline_outcomes(vec![TrialOutcome::passed()])
        .with_baseline_candidates(vec![external_candidate("telemetry.corp:443", true)]);
    let mut journal = RecordingJournal::default();
    let report = prove(&mut lab, &mut journal, &NullProgress, &request(), &policy())?;

    assert_eq!(
        report.conclusions[0].conclusion.necessity(),
        Necessity::Optional
    );
    assert!(
        !lab.trials_run.iter().any(|l| l.starts_with("no-egress")),
        "already-demonstrated unavailability must not spend trials"
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
