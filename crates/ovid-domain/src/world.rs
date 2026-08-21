//! World verification type-states (proposal §7.7, §11).
//!
//! A world moves `WorldCandidate -> ProposedWorld -> VerifiedWorld`, and
//! the last transition is only possible with [`ReplayEvidence`] — which
//! itself only exists for a *passing, untreated, clean-state* replay
//! trial. A renderer or adapter cannot promote a world's status
//! (proposal §7.7); the type system enforces ADR-008/FR-095.

use crate::dependency::DependencyKey;
use crate::scope::AnalysisScope;
use crate::trial::TrialRecord;
use ovid_core::Digest;
use serde::Serialize;
use std::collections::BTreeMap;

/// The raw material for a world: the classified dependency sets plus the
/// workload they support (proposal §11.1). Aggregated from an explicit
/// workload scope, never "whichever command ran last" (proposal §11.4).
#[derive(Clone, PartialEq, Serialize, Debug, Default)]
pub struct WorldCandidate {
    /// Dependencies proven required in scope.
    pub required: Vec<DependencyKey>,
    /// Dependencies proven optional in scope (recorded, not started).
    pub optional: Vec<DependencyKey>,
    /// Dependencies that stayed unresolved (visible, never hidden).
    pub unresolved: Vec<DependencyKey>,
    /// The workload argv this world supports.
    pub workload_argv: Vec<String>,
    /// Target-level environment the workload needs.
    pub environment: BTreeMap<String, String>,
}

impl WorldCandidate {
    /// Freeze the candidate into a proposed world bound to its scope.
    pub fn propose(self, scope: &AnalysisScope) -> ProposedWorld {
        let mut canonical = self.clone();
        canonical.required.sort();
        canonical.optional.sort();
        canonical.unresolved.sort();
        let digest = Digest::of_bytes(
            serde_json::to_vec(&(&canonical, scope.digest().hex()))
                .expect("world candidates serialize")
                .as_slice(),
        );
        ProposedWorld {
            candidate: canonical,
            scope: scope.clone(),
            digest,
        }
    }
}

/// A synthesized world awaiting replay verification (proposal §7.7).
#[derive(Clone, PartialEq, Serialize, Debug)]
pub struct ProposedWorld {
    candidate: WorldCandidate,
    scope: AnalysisScope,
    digest: Digest,
}

impl ProposedWorld {
    pub fn candidate(&self) -> &WorldCandidate {
        &self.candidate
    }

    pub fn scope(&self) -> &AnalysisScope {
        &self.scope
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// The only path to `VerifiedWorld`: present replay evidence
    /// (proposal §11.3). Consumes the proposal so a world is never both
    /// proposed and verified.
    pub fn verify(self, replay: ReplayEvidence) -> VerifiedWorld {
        VerifiedWorld {
            world: self,
            replay,
        }
    }
}

/// Proof that a clean replay of the locked workload passed. Constructible
/// only from a passing, untreated trial — a failed or treated run yields
/// `None`, so no code path can fabricate verification.
#[derive(Clone, PartialEq, Serialize, Debug)]
pub struct ReplayEvidence {
    trial: TrialRecord,
}

impl ReplayEvidence {
    /// Accept a replay trial as verification evidence only when it ran
    /// untreated and passed (proposal §11.3).
    pub fn from_clean_replay(trial: &TrialRecord) -> Option<ReplayEvidence> {
        if trial.treatment.is_baseline() && trial.outcome.passed {
            Some(ReplayEvidence {
                trial: trial.clone(),
            })
        } else {
            None
        }
    }

    pub fn trial(&self) -> &TrialRecord {
        &self.trial
    }
}

/// A world whose clean replay succeeded (proposal §7.7).
#[derive(Clone, PartialEq, Serialize, Debug)]
pub struct VerifiedWorld {
    world: ProposedWorld,
    replay: ReplayEvidence,
}

impl VerifiedWorld {
    pub fn world(&self) -> &ProposedWorld {
        &self.world
    }

    pub fn replay(&self) -> &ReplayEvidence {
        &self.replay
    }
}

/// The reportable outcome of world synthesis + replay for one analysis.
#[derive(Clone, PartialEq, Serialize, Debug)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum WorldOutcome {
    /// No world was synthesized (and why).
    NotSynthesized { reason: String },
    /// A world was proposed but replay was not attempted (and why).
    Proposed {
        world: ProposedWorld,
        reason: String,
    },
    /// Replay was attempted and failed; the failure is preserved.
    ReplayFailed {
        world: ProposedWorld,
        failure: TrialRecord,
    },
    /// Replay from clean state passed.
    Verified { world: VerifiedWorld },
}

impl WorldOutcome {
    /// Short status label for reports (`verified`, `proposed`, …).
    pub fn label(&self) -> &'static str {
        match self {
            WorldOutcome::NotSynthesized { .. } => "not-synthesized",
            WorldOutcome::Proposed { .. } => "proposed",
            WorldOutcome::ReplayFailed { .. } => "replay-failed",
            WorldOutcome::Verified { .. } => "verified",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trial::{EnforcementReport, Treatment, TrialOutcome};

    fn scope() -> AnalysisScope {
        AnalysisScope {
            repository: "repo".into(),
            revision: "abc".into(),
            workload: "test".into(),
            workload_argv: vec!["make".into(), "test".into()],
            ..Default::default()
        }
    }

    fn replay_trial(passed: bool, treatment: Treatment) -> TrialRecord {
        TrialRecord {
            label: "replay".into(),
            enforcement: EnforcementReport::enforced(treatment.clone(), "user-netns"),
            treatment,
            outcome: if passed {
                TrialOutcome::passed()
            } else {
                TrialOutcome::failed("exit 1")
            },
            evidence: vec![],
        }
    }

    #[test]
    fn failed_replay_cannot_produce_evidence() {
        assert!(ReplayEvidence::from_clean_replay(&replay_trial(false, Treatment::None)).is_none());
    }

    #[test]
    fn treated_replay_cannot_produce_evidence() {
        assert!(
            ReplayEvidence::from_clean_replay(&replay_trial(true, Treatment::DenyAllEgress))
                .is_none(),
            "a treated run is not a clean replay"
        );
    }

    #[test]
    fn verification_requires_replay_evidence_and_consumes_the_proposal() {
        let proposed = WorldCandidate {
            workload_argv: vec!["make".into(), "test".into()],
            ..Default::default()
        }
        .propose(&scope());
        let evidence =
            ReplayEvidence::from_clean_replay(&replay_trial(true, Treatment::None)).unwrap();
        let verified = proposed.verify(evidence);
        assert!(verified.replay().trial().outcome.passed);
    }

    #[test]
    fn world_digest_binds_scope() {
        let candidate = WorldCandidate::default();
        let a = candidate.clone().propose(&scope());
        let mut other = scope();
        other.revision = "def".into();
        let b = candidate.propose(&other);
        assert_ne!(a.digest(), b.digest());
    }
}
