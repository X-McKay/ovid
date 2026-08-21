//! Treatments, trials, and enforcement evidence (proposal §7.6, §10.1).
//!
//! An experiment is only scientifically valid when the laboratory can
//! *prove* the requested treatment was applied (proposal §10.1 item 4).
//! Every trial therefore carries an [`EnforcementReport`]; the classifier
//! refuses to draw `required`/`optional` conclusions from anything other
//! than an [`EnforcementStatus::Enforced`] trial.

use crate::dependency::DependencyKey;
use serde::{Deserialize, Serialize};

/// One controlled change applied to a trial (proposal §8.4).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(tag = "treatment", rename_all = "kebab-case")]
pub enum Treatment {
    /// No change: a baseline (or replay) run under the reference world.
    None,
    /// All external egress unavailable — the broad screening treatment
    /// (proposal §10.5 step 2). Loopback stays intact.
    DenyAllEgress,
    /// Exactly one logical network dependency made unavailable.
    BlockDependency { dependency: DependencyKey },
    /// One environment variable removed from the workload environment.
    RemoveEnvVar { name: String },
    /// One executable hidden from the workload's search path.
    HideExecutable { name: String },
}

impl Treatment {
    /// Whether this is the untreated reference condition.
    pub fn is_baseline(&self) -> bool {
        matches!(self, Treatment::None)
    }

    /// Human description used in journals and reports.
    pub fn describe(&self) -> String {
        match self {
            Treatment::None => "none (baseline)".into(),
            Treatment::DenyAllEgress => "deny all external egress".into(),
            Treatment::BlockDependency { dependency } => {
                format!("block {}", dependency.describe())
            }
            Treatment::RemoveEnvVar { name } => format!("remove env var {name}"),
            Treatment::HideExecutable { name } => format!("hide executable {name}"),
        }
    }
}

/// Whether the laboratory proved the treatment was applied
/// (proposal §7.6).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementStatus {
    /// The treatment demonstrably held for the whole trial.
    Enforced,
    /// The treatment held only partially (e.g. proxy-variable stripping
    /// without namespace isolation: direct egress may still succeed).
    PartiallyEnforced,
    /// The treatment could not be applied.
    NotEnforced,
}

/// The laboratory's account of how a treatment was applied
/// (proposal §7.6).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct EnforcementReport {
    pub requested: Treatment,
    pub status: EnforcementStatus,
    /// Mechanism used (e.g. `user-netns`, `guest-no-net`, `env-scrub`).
    pub mechanism: String,
    /// Known limitations of the mechanism, preserved for the report.
    #[serde(default)]
    pub limitations: Vec<String>,
}

impl EnforcementReport {
    /// An enforced treatment with the given mechanism.
    pub fn enforced(requested: Treatment, mechanism: impl Into<String>) -> EnforcementReport {
        EnforcementReport {
            requested,
            status: EnforcementStatus::Enforced,
            mechanism: mechanism.into(),
            limitations: Vec::new(),
        }
    }

    /// A treatment the laboratory could not apply.
    pub fn not_enforced(requested: Treatment, reason: impl Into<String>) -> EnforcementReport {
        EnforcementReport {
            requested,
            status: EnforcementStatus::NotEnforced,
            mechanism: "none".into(),
            limitations: vec![reason.into()],
        }
    }
}

/// The outcome of one trial run, as the classifier sees it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct TrialOutcome {
    /// Whether the locked success predicate held.
    pub passed: bool,
    /// Stable failure signature (first actionable error) used to compare
    /// runs — spec §20.6 compares signatures, not just booleans.
    pub failure_signature: Option<String>,
}

impl TrialOutcome {
    pub fn passed() -> TrialOutcome {
        TrialOutcome {
            passed: true,
            failure_signature: None,
        }
    }

    pub fn failed(signature: impl Into<String>) -> TrialOutcome {
        TrialOutcome {
            passed: false,
            failure_signature: Some(signature.into()),
        }
    }
}

/// One completed trial: what was asked, what held, what happened.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct TrialRecord {
    /// Human label (`baseline-1`, `no-egress-1`, `replay`).
    pub label: String,
    pub treatment: Treatment,
    pub enforcement: EnforcementReport,
    pub outcome: TrialOutcome,
    /// Ledger evidence ids supporting this trial.
    #[serde(default)]
    pub evidence: Vec<String>,
}

/// What the observation layer established about one candidate dependency
/// under a treatment — the classifier's per-dependency input
/// (proposal §10.7).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct CandidateEvidence {
    pub key: DependencyKey,
    /// The dependency is outside the workload's own control (an external
    /// service, not a listener the workload itself starts).
    pub externally_controlled: bool,
    /// Under the treatment, every attempt to use the dependency failed —
    /// its unavailability was demonstrated, not assumed.
    pub unavailable_under_treatment: bool,
    /// The dependency was actually used (or attempted) during baseline.
    pub attempted_in_baseline: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforcement_constructors_carry_reasons() {
        let ok = EnforcementReport::enforced(Treatment::DenyAllEgress, "user-netns");
        assert_eq!(ok.status, EnforcementStatus::Enforced);
        assert!(ok.limitations.is_empty());

        let no = EnforcementReport::not_enforced(Treatment::DenyAllEgress, "no userns");
        assert_eq!(no.status, EnforcementStatus::NotEnforced);
        assert_eq!(no.limitations, vec!["no userns".to_string()]);
    }
}
