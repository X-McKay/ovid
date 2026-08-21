//! Network-availability counterfactuals (spec §20, tomography mode).
//!
//! Running the same workload twice — once in an isolated network namespace
//! (deny-all egress) and once with network access — is a controlled
//! counterfactual over the *group* of external dependencies. Per §20.4,
//! group-level evidence only supports per-dependency `Required` when the
//! group that changed availability has exactly one member; otherwise each
//! member honestly stays `Unresolved` (individual variation would be the
//! next experiment).

use ovid_core::CausalClassification;
use ovid_gateway::ExternalObservation;
use serde::Serialize;

/// The paired observations for one dependency identity across the two runs.
#[derive(Debug, Default)]
pub struct NetworkCounterfactual<'a> {
    pub offline: Option<&'a ExternalObservation>,
    pub online: Option<&'a ExternalObservation>,
}

/// Outcome of the offline/online comparison for one dependency.
#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
pub struct NetworkVerdict {
    pub classification: CausalClassification,
    /// True when the verdict rests on the network group changing as a
    /// whole rather than this dependency alone.
    pub group_level: bool,
}

/// Whether an observation is under the experiment's control: the isolated
/// namespace removes *external* reachability, but loopback keeps working,
/// so loopback destinations were never made unavailable by the
/// intervention and cannot be attributed by it.
pub fn externally_controlled(observation: &ExternalObservation) -> bool {
    !(observation.address.starts_with("127.") || observation.address == "::1")
}

/// Classify one dependency from the offline/online pair.
///
/// `controlled_group_size` is the number of externally-controlled
/// dependencies that were unavailable offline and available online — the
/// size of the group the intervention actually varied.
pub fn classify_network_counterfactual(
    pair: &NetworkCounterfactual<'_>,
    offline_passed: bool,
    online_passed: bool,
    controlled_group_size: usize,
) -> NetworkVerdict {
    let offline_unavailable = pair.offline.map(|o| o.all_failed()).unwrap_or(true);
    let online_available = pair.online.map(|o| !o.all_failed()).unwrap_or(false);
    let controlled = pair
        .offline
        .or(pair.online)
        .map(externally_controlled)
        .unwrap_or(false);

    if offline_passed {
        // The workload succeeded while this dependency was unavailable or
        // absent: a genuine counterfactual for optionality, per-dependency.
        if offline_unavailable {
            return NetworkVerdict {
                classification: CausalClassification::Optional,
                group_level: false,
            };
        }
        // Dependency was reachable even in the isolated run (loopback):
        // it was never varied, so no causal claim.
        return NetworkVerdict {
            classification: CausalClassification::Unresolved,
            group_level: false,
        };
    }

    // Offline run failed.
    if online_passed && offline_unavailable && online_available && controlled {
        if controlled_group_size == 1 {
            // Exactly one controlled dependency changed: the comparison is
            // a per-dependency counterfactual.
            return NetworkVerdict {
                classification: CausalClassification::Required,
                group_level: false,
            };
        }
        // Several dependencies changed together: required as a group, not
        // individually attributable (§20.4's coupling caveat).
        return NetworkVerdict {
            classification: CausalClassification::Unresolved,
            group_level: true,
        };
    }

    NetworkVerdict {
        classification: CausalClassification::Unresolved,
        group_level: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(address: &str, attempts: u64, failures: u64) -> ExternalObservation {
        ExternalObservation {
            address: address.into(),
            port: 443,
            dns_name: None,
            endpoints: vec![address.into()],
            protocol: None,
            service_candidates: vec![],
            attempts,
            failures,
            outcomes: vec![],
            evidence: vec![],
        }
    }

    #[test]
    fn required_when_single_controlled_dependency_flips_outcome() {
        let offline = observation("104.21.27.83", 2, 2);
        let online = observation("104.21.27.83", 2, 0);
        let verdict = classify_network_counterfactual(
            &NetworkCounterfactual {
                offline: Some(&offline),
                online: Some(&online),
            },
            false, // offline failed
            true,  // online passed
            1,
        );
        assert_eq!(verdict.classification, CausalClassification::Required);
        assert!(!verdict.group_level);
    }

    #[test]
    fn group_of_many_stays_unresolved_but_flagged() {
        let offline = observation("104.21.27.83", 1, 1);
        let online = observation("104.21.27.83", 1, 0);
        let verdict = classify_network_counterfactual(
            &NetworkCounterfactual {
                offline: Some(&offline),
                online: Some(&online),
            },
            false,
            true,
            3,
        );
        assert_eq!(verdict.classification, CausalClassification::Unresolved);
        assert!(verdict.group_level);
    }

    #[test]
    fn optional_when_offline_run_passes_without_it() {
        let offline = observation("104.21.27.83", 1, 1);
        let verdict = classify_network_counterfactual(
            &NetworkCounterfactual {
                offline: Some(&offline),
                online: None,
            },
            true,
            true,
            1,
        );
        assert_eq!(verdict.classification, CausalClassification::Optional);

        // Also optional when the dependency only ever appears online but
        // the offline run passed without attempting it.
        let online = observation("104.21.27.83", 1, 0);
        let verdict = classify_network_counterfactual(
            &NetworkCounterfactual {
                offline: None,
                online: Some(&online),
            },
            true,
            true,
            1,
        );
        assert_eq!(verdict.classification, CausalClassification::Optional);
    }

    #[test]
    fn loopback_consequences_are_not_attributed() {
        // A loopback destination that fails offline and works online is a
        // downstream consequence, not a controlled variable.
        let offline = observation("127.0.0.1", 1, 1);
        let online = observation("127.0.0.1", 1, 0);
        assert!(!externally_controlled(&offline));
        let verdict = classify_network_counterfactual(
            &NetworkCounterfactual {
                offline: Some(&offline),
                online: Some(&online),
            },
            false,
            true,
            1,
        );
        assert_eq!(verdict.classification, CausalClassification::Unresolved);
    }

    #[test]
    fn both_runs_failing_yields_no_claim() {
        let offline = observation("104.21.27.83", 1, 1);
        let online = observation("104.21.27.83", 1, 1);
        let verdict = classify_network_counterfactual(
            &NetworkCounterfactual {
                offline: Some(&offline),
                online: Some(&online),
            },
            false,
            false,
            1,
        );
        assert_eq!(verdict.classification, CausalClassification::Unresolved);
    }

    #[test]
    fn reachable_offline_dependency_is_never_attributed() {
        // A dependency that succeeded even in the isolated run (loopback
        // service) was not varied by the experiment.
        let offline = observation("127.0.0.1", 2, 0);
        let online = observation("127.0.0.1", 2, 0);
        let verdict = classify_network_counterfactual(
            &NetworkCounterfactual {
                offline: Some(&offline),
                online: Some(&online),
            },
            true,
            true,
            0,
        );
        assert_eq!(verdict.classification, CausalClassification::Unresolved);
    }
}
