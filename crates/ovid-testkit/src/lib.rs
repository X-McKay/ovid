//! Deterministic test doubles for Ovid (proposal §6's `ovid-testkit`).
//!
//! - [`FixtureLaboratory`] — a scripted, in-memory [`LaboratoryPort`]:
//!   truth fixtures declare exactly how trials behave under each
//!   treatment, so use-case and classifier behavior is tested with known
//!   ground truth (proposal §17.3) and zero real execution.
//! - [`RecordingJournal`] — an in-memory [`JournalPort`] that keeps every
//!   typed event for assertions.
//!
//! The laboratory honestly implements the contract: trials "fork" from
//! the snapshot (scripts index from a stable state, order-independent per
//! treatment), capabilities gate what can be enforced, and enforcement
//! reports match what was actually applied.

use ovid_application::{
    ExecutableCandidate, JournalError, JournalEvent, JournalPort, LabCapabilities, LabError,
    LaboratoryPort, NetworkCandidate, PreparedEnvironment, ProviderIdentity, SnapshotRef,
    TrialObservations, TrialResult, TrialSpec,
};
use ovid_domain::{EnforcementReport, Treatment, TrialOutcome, TrialRecord};
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;

/// An in-memory journal that records every event and hands out
/// sequential evidence ids.
#[derive(Default)]
pub struct RecordingJournal {
    pub events: Vec<JournalEvent>,
}

impl JournalPort for RecordingJournal {
    fn append(&mut self, event: &JournalEvent) -> Result<String, JournalError> {
        self.events.push(event.clone());
        Ok(format!("evidence:{:04}", self.events.len()))
    }
}

/// Scripted behavior for one treatment class.
#[derive(Clone, Default)]
struct TreatmentScript {
    /// Outcomes consumed in order; the last repeats when exhausted.
    outcomes: VecDeque<TrialOutcome>,
    /// Network candidates observed during these trials.
    candidates: Vec<NetworkCandidate>,
    /// Executable candidates observed during these trials.
    executables: Vec<ExecutableCandidate>,
}

impl TreatmentScript {
    fn next_outcome(&mut self) -> TrialOutcome {
        if self.outcomes.len() > 1 {
            self.outcomes.pop_front().expect("checked non-empty")
        } else {
            self.outcomes
                .front()
                .cloned()
                .unwrap_or_else(TrialOutcome::passed)
        }
    }
}

/// A scripted laboratory for truth fixtures (proposal §17.3).
pub struct FixtureLaboratory {
    capabilities: LabCapabilities,
    baseline: TreatmentScript,
    no_egress: TreatmentScript,
    /// Per-executable scripts for `HideExecutable` trials.
    hide: BTreeMap<String, TreatmentScript>,
    provision_outcome: Option<TrialOutcome>,
    /// Labels of every trial run, in order (for assertions).
    pub trials_run: Vec<String>,
}

impl Default for FixtureLaboratory {
    fn default() -> Self {
        FixtureLaboratory::new()
    }
}

impl FixtureLaboratory {
    /// A laboratory with full enforcement capabilities and observation.
    pub fn new() -> FixtureLaboratory {
        FixtureLaboratory {
            capabilities: LabCapabilities {
                vm_isolation: false,
                clean_snapshot_restore: true,
                deny_all_egress: true,
                executable_hiding: true,
                observation: true,
            },
            baseline: TreatmentScript::default(),
            no_egress: TreatmentScript::default(),
            hide: BTreeMap::new(),
            provision_outcome: None,
            trials_run: Vec::new(),
        }
    }

    /// Override the capability report (e.g. to model a laboratory that
    /// cannot enforce egress denial).
    pub fn with_capabilities(mut self, capabilities: LabCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Script the outcomes of untreated (baseline/replay) trials.
    pub fn with_baseline_outcomes(mut self, outcomes: Vec<TrialOutcome>) -> Self {
        self.baseline.outcomes = outcomes.into();
        self
    }

    /// Candidates observed during untreated trials.
    pub fn with_baseline_candidates(mut self, candidates: Vec<NetworkCandidate>) -> Self {
        self.baseline.candidates = candidates;
        self
    }

    /// Script the outcomes of deny-all-egress trials.
    pub fn with_no_egress_outcomes(mut self, outcomes: Vec<TrialOutcome>) -> Self {
        self.no_egress.outcomes = outcomes.into();
        self
    }

    /// Candidates observed during deny-all-egress trials (typically the
    /// same identities with `all_failed: true`).
    pub fn with_no_egress_candidates(mut self, candidates: Vec<NetworkCandidate>) -> Self {
        self.no_egress.candidates = candidates;
        self
    }

    /// Script the provisioning outcome.
    pub fn with_provision_outcome(mut self, outcome: TrialOutcome) -> Self {
        self.provision_outcome = Some(outcome);
        self
    }

    /// Executable candidates observed during untreated trials.
    pub fn with_baseline_executables(mut self, executables: Vec<ExecutableCandidate>) -> Self {
        self.baseline.executables = executables;
        self
    }

    /// Script the outcomes of `HideExecutable { name }` trials.
    pub fn with_hide_outcomes(mut self, name: &str, outcomes: Vec<TrialOutcome>) -> Self {
        self.hide.insert(
            name.to_string(),
            TreatmentScript {
                outcomes: outcomes.into(),
                candidates: Vec::new(),
                executables: Vec::new(),
            },
        );
        self
    }
}

impl LaboratoryPort for FixtureLaboratory {
    fn identity(&self) -> ProviderIdentity {
        ProviderIdentity {
            name: "fixture-laboratory".into(),
            version: "0".into(),
        }
    }

    fn capabilities(&self) -> LabCapabilities {
        self.capabilities
    }

    fn prepare(&mut self, provision: Option<&[String]>) -> Result<PreparedEnvironment, LabError> {
        let provision_record = provision.map(|argv| TrialRecord {
            label: "provision".into(),
            treatment: Treatment::None,
            enforcement: EnforcementReport::enforced(Treatment::None, "fixture"),
            outcome: self
                .provision_outcome
                .clone()
                .unwrap_or_else(TrialOutcome::passed),
            evidence: vec![format!("argv:{}", argv.join(" "))],
        });
        Ok(PreparedEnvironment {
            id: "fixture-env".into(),
            workspace: PathBuf::from("/fixture"),
            provision: provision_record,
            environment_digest: "fixture-env-digest".into(),
        })
    }

    fn snapshot(
        &mut self,
        environment: &PreparedEnvironment,
        label: &str,
    ) -> Result<SnapshotRef, LabError> {
        Ok(SnapshotRef {
            id: format!("{}-snap", environment.id),
            path: environment.workspace.clone(),
            label: label.to_string(),
        })
    }

    fn run_trial(
        &mut self,
        _snapshot: &SnapshotRef,
        spec: &TrialSpec,
    ) -> Result<TrialResult, LabError> {
        if !self.capabilities.can_enforce(&spec.treatment) {
            // The contract: a laboratory refuses treatments it cannot
            // enforce rather than running them weakened.
            return Err(LabError::Unsupported(format!(
                "cannot enforce {}",
                spec.treatment.describe()
            )));
        }
        self.trials_run.push(spec.label.clone());
        let script = match &spec.treatment {
            Treatment::None => &mut self.baseline,
            Treatment::DenyAllEgress => &mut self.no_egress,
            Treatment::HideExecutable { name } => self.hide.entry(name.clone()).or_default(),
        };
        let outcome = script.next_outcome();
        let observations = TrialObservations {
            network: script.candidates.clone(),
            executables: script.executables.clone(),
            observed: true,
            events_captured: (script.candidates.len() + script.executables.len()) as u64,
        };
        Ok(TrialResult {
            record: TrialRecord {
                label: spec.label.clone(),
                treatment: spec.treatment.clone(),
                enforcement: EnforcementReport::enforced(spec.treatment.clone(), "fixture"),
                outcome: outcome.clone(),
                evidence: vec![],
            },
            observations,
            exit_code: Some(if outcome.passed { 0 } else { 1 }),
            duration_ms: 1,
            output_tail: String::new(),
        })
    }

    fn destroy(&mut self, _environment: PreparedEnvironment) -> Result<(), LabError> {
        Ok(())
    }
}

/// Convenience: an externally-controlled network candidate.
pub fn external_candidate(identity: &str, all_failed: bool) -> NetworkCandidate {
    NetworkCandidate {
        key: ovid_domain::DependencyKey::network(identity),
        externally_controlled: true,
        all_failed,
        attempts: 3,
        failures: if all_failed { 3 } else { 0 },
    }
}

/// Convenience: an environment-provided executable candidate.
pub fn executable_candidate(name: &str, found: bool) -> ExecutableCandidate {
    ExecutableCandidate {
        name: name.to_string(),
        found,
        resolver_hint: None,
    }
}
