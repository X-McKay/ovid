//! Claim state vocabulary (spec §22.5) and causal classifications (§20.5).
//!
//! §6.3 requires that Ovid never collapse "declared", "resolved",
//! "installed", "loaded", "exercised", "causally required", etc. into one
//! statement. `ClaimStates` therefore keeps each dimension as an independent
//! boolean rather than a single enum, and consumers must check the specific
//! dimension they care about.

use serde::{Deserialize, Serialize};

/// One dimension of a claim's lifecycle. Used as evidence-derived labels.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ClaimState {
    Declared,
    Resolved,
    Downloaded,
    Installed,
    IncludedInArtifact,
    Loaded,
    Exercised,
    Attempted,
    Observed,
    StaticallyPossible,
    CausallyRequired,
    Optional,
    DegradedMode,
    BuildOnly,
    TestOnly,
    InitializationOnly,
    FleetCandidate,
    FleetConfirmed,
    Unresolved,
    Contradicted,
}

/// The independent state dimensions attached to a claim or component.
///
/// All default to `false`; `None`-like absence is represented by leaving the
/// flag unset, and consumers must not treat absence as proof of absence
/// (§25.3).
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ClaimStates {
    #[serde(default, skip_serializing_if = "is_false")]
    pub declared: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub resolved: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub downloaded: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub installed: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub included_in_artifact: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub loaded: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub exercised: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub attempted: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub observed: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub statically_possible: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub causally_required: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub fleet_confirmed: bool,
}

fn is_false(b: &bool) -> bool {
    !b
}

impl ClaimStates {
    /// A builder-style setter used by normalizers.
    pub fn with(mut self, state: ClaimState) -> Self {
        self.set(state);
        self
    }

    pub fn set(&mut self, state: ClaimState) {
        match state {
            ClaimState::Declared => self.declared = true,
            ClaimState::Resolved => self.resolved = true,
            ClaimState::Downloaded => self.downloaded = true,
            ClaimState::Installed => self.installed = true,
            ClaimState::IncludedInArtifact => self.included_in_artifact = true,
            ClaimState::Loaded => self.loaded = true,
            ClaimState::Exercised => self.exercised = true,
            ClaimState::Attempted => self.attempted = true,
            ClaimState::Observed => self.observed = true,
            ClaimState::StaticallyPossible => self.statically_possible = true,
            ClaimState::CausallyRequired => self.causally_required = true,
            ClaimState::FleetConfirmed => self.fleet_confirmed = true,
            // Classification-style states carry no boolean dimension here;
            // they live in `CausalClassification`.
            _ => {}
        }
    }
}

/// Outcome of counterfactual dependency experiments (spec §20.5).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CausalClassification {
    /// Removal reliably breaks the success predicate.
    Required,
    /// Workload starts but a defined scenario or assertion fails.
    RequiredForFullBehavior,
    /// Succeeds under a weaker predicate but loses capability or retries.
    DegradedMode,
    /// Attempted, but removal does not materially change the outcome.
    Optional,
    /// Caused by tooling/telemetry/environment, not target behavior.
    Incidental,
    /// Required for build but not the runtime world.
    BuildOnly,
    /// Required by the test harness but not the runtime workload.
    TestOnly,
    /// Required to create state, not after snapshot.
    InitializationOnly,
    /// Evidence insufficient or experiments inconclusive.
    Unresolved,
}

impl CausalClassification {
    /// Whether the dependency must be present in a Minimum Viable World for
    /// the *runtime* workload.
    pub fn needed_at_runtime(self) -> bool {
        matches!(
            self,
            CausalClassification::Required | CausalClassification::RequiredForFullBehavior
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_stay_independent() {
        let s = ClaimStates::default()
            .with(ClaimState::Declared)
            .with(ClaimState::IncludedInArtifact);
        assert!(s.declared);
        assert!(s.included_in_artifact);
        // §6.3: declaring must not imply loading or exercising.
        assert!(!s.loaded);
        assert!(!s.exercised);
    }

    #[test]
    fn serde_skips_false_flags() {
        let s = ClaimStates::default().with(ClaimState::Observed);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"observed":true}"#);
    }

    #[test]
    fn runtime_need_classification() {
        assert!(CausalClassification::Required.needed_at_runtime());
        assert!(!CausalClassification::BuildOnly.needed_at_runtime());
        assert!(!CausalClassification::Optional.needed_at_runtime());
    }
}
