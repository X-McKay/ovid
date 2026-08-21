//! Evidence trust tiers (spec §22.1).
//!
//! Trust tier is a property of the *source* of evidence, not a confidence
//! score: a repository-declared endpoint (T4) can be an exact declaration
//! while remaining unobserved. Tier ordering matters for policy — e.g.
//! ADR-007 forbids promoting a claim to confirmed on T5 evidence alone.

use serde::{Deserialize, Serialize};

/// T0 (strongest, host-enforced) through T5 (heuristic/model proposal).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub enum TrustTier {
    /// Host-enforced fact: revision digest, VM policy, gateway routing.
    T0,
    /// Independent host decoder/provider running in a sandbox.
    T1,
    /// Trusted guest agent/observer (may be compromised by a malicious guest).
    T2,
    /// Standard code-intelligence / tool output (LSP, SCIP, package manager).
    T3,
    /// Repository-declared metadata (manifests, CI, config, docs).
    T4,
    /// Heuristic or model proposal. Can never confirm a claim by itself.
    T5,
}

impl TrustTier {
    /// Whether evidence at this tier may, by policy default, confirm a claim
    /// without corroboration from a higher tier (ADR-007).
    pub fn can_confirm_alone(self) -> bool {
        !matches!(self, TrustTier::T5)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TrustTier::T0 => "T0",
            TrustTier::T1 => "T1",
            TrustTier::T2 => "T2",
            TrustTier::T3 => "T3",
            TrustTier::T4 => "T4",
            TrustTier::T5 => "T5",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_ordering_is_strongest_first() {
        assert!(TrustTier::T0 < TrustTier::T5);
        assert!(TrustTier::T2 < TrustTier::T4);
    }

    #[test]
    fn t5_cannot_confirm() {
        assert!(!TrustTier::T5.can_confirm_alone());
        assert!(TrustTier::T0.can_confirm_alone());
    }
}
