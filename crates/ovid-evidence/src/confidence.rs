//! Confidence combination (spec §22.4).
//!
//! Ovid exposes evidence rather than trusting a single number, but a score
//! is still useful for ranking and policy. The model here follows the
//! spec's recommendation: per-tier calibrated likelihoods combined in
//! log-odds space, contradiction penalties, and hard caps by evidence
//! class so that, for example, a pile of model proposals can never
//! outrank one observed host fact.

use ovid_core::TrustTier;

/// Hard cap applied after combination, keyed by the *class* of claim.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfidenceCap {
    /// Claim backed by observation or causal experiments.
    Observed,
    /// Claim backed only by declarations/static references.
    Declared,
    /// Claim backed only by heuristic/model proposals (T5).
    ProposalOnly,
}

impl ConfidenceCap {
    fn value(self) -> f64 {
        match self {
            ConfidenceCap::Observed => 0.999,
            ConfidenceCap::Declared => 0.90,
            // ADR-007: proposals are never facts.
            ConfidenceCap::ProposalOnly => 0.50,
        }
    }
}

/// Calibrated per-observation likelihood for a single evidence record at a
/// given trust tier. These are policy data in spirit; the defaults are
/// conservative.
fn tier_likelihood(tier: TrustTier) -> f64 {
    match tier {
        TrustTier::T0 => 0.99,
        TrustTier::T1 => 0.97,
        TrustTier::T2 => 0.95,
        TrustTier::T3 => 0.90,
        TrustTier::T4 => 0.80,
        TrustTier::T5 => 0.55,
    }
}

/// Combine supporting evidence tiers into one confidence value.
///
/// Combination is a bounded noisy-OR: each independent support reduces the
/// probability that the claim is spurious. Every contradiction applies a
/// fixed log-odds penalty. The result is clamped to `cap`.
pub fn combine_confidence(
    supports: &[TrustTier],
    contradiction_count: usize,
    cap: ConfidenceCap,
) -> f64 {
    if supports.is_empty() {
        return 0.0;
    }
    // Noisy-OR over independent supports.
    let mut spurious = 1.0f64;
    for tier in supports {
        spurious *= 1.0 - tier_likelihood(*tier);
    }
    let mut p: f64 = 1.0 - spurious;
    // Contradiction penalty in log-odds space (~1.5 nats each).
    if contradiction_count > 0 {
        let odds = (p / (1.0 - p)).max(f64::MIN_POSITIVE);
        let penalized = odds.ln() - 1.5 * contradiction_count as f64;
        p = penalized.exp() / (1.0 + penalized.exp());
    }
    p.min(cap.value()).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn more_independent_support_raises_confidence() {
        let one = combine_confidence(&[TrustTier::T2], 0, ConfidenceCap::Observed);
        let two = combine_confidence(&[TrustTier::T2, TrustTier::T0], 0, ConfidenceCap::Observed);
        assert!(two > one);
    }

    #[test]
    fn contradictions_lower_confidence() {
        let clean = combine_confidence(&[TrustTier::T1], 0, ConfidenceCap::Observed);
        let contested = combine_confidence(&[TrustTier::T1], 2, ConfidenceCap::Observed);
        assert!(contested < clean);
    }

    #[test]
    fn proposal_cap_holds_regardless_of_volume() {
        let many_proposals = vec![TrustTier::T5; 50];
        let p = combine_confidence(&many_proposals, 0, ConfidenceCap::ProposalOnly);
        assert!(p <= 0.50);
    }

    #[test]
    fn no_evidence_means_zero() {
        assert_eq!(combine_confidence(&[], 0, ConfidenceCap::Observed), 0.0);
    }

    #[test]
    fn declared_only_caps_below_observed() {
        let declared = combine_confidence(
            &[TrustTier::T4, TrustTier::T4, TrustTier::T4, TrustTier::T4],
            0,
            ConfidenceCap::Declared,
        );
        assert!(declared <= 0.90);
    }
}
