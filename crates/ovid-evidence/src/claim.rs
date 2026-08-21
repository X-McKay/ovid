//! Claims: normalized graph statements derived from evidence (spec §8.8,
//! §22.3), plus the explain traversal required by FR-110.

use crate::confidence::{combine_confidence, ConfidenceCap};
use crate::ledger::EvidenceLedger;
use crate::record::EvidenceRecord;
use ovid_core::{ClaimStates, OvidError, OvidId, TrustTier};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A normalized statement such as
/// `workload:integration-tests REQUIRES service:postgres`.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Claim {
    pub id: OvidId,
    /// Edge predicate from the graph ontology (§23.2), lower-kebab-case,
    /// e.g. `requires`, `calls`, `connects-to`, `declares`.
    pub predicate: String,
    /// Subject node identity, e.g. `workload:build`.
    pub subject: String,
    /// Object node identity, e.g. `tool:protoc` or `package:pkg:cargo/serde@1`.
    pub object: String,
    #[serde(default)]
    pub states: ClaimStates,
    /// Combined confidence in [0, 1]. Ranking aid only — the evidence links
    /// are the real answer to "why do you believe this?" (G-8).
    pub confidence: f64,
    #[serde(default)]
    pub supports: Vec<OvidId>,
    #[serde(default)]
    pub contradicts: Vec<OvidId>,
    pub normalizer: String,
    pub normalizer_version: String,
}

/// One line of an explain traversal: the claim plus resolved evidence.
#[derive(Serialize, Debug)]
pub struct Explanation {
    pub claim: Claim,
    pub supporting_evidence: Vec<EvidenceRecord>,
    pub contradicting_evidence: Vec<EvidenceRecord>,
    /// Ids referenced by the claim that were not found in the ledger —
    /// surfaced rather than hidden, per §6.6.
    pub missing_evidence: Vec<OvidId>,
}

/// A simple durable claim store (JSON file) with explain traversal.
///
/// Claims are projections and may be regenerated from the ledger; unlike
/// the ledger they are not hash-chained.
pub struct ClaimStore {
    path: PathBuf,
    claims: BTreeMap<String, Claim>,
}

impl ClaimStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, OvidError> {
        let path = path.into();
        let mut claims = BTreeMap::new();
        if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            let list: Vec<Claim> = serde_json::from_str(&text)
                .map_err(|e| OvidError::Evidence(format!("corrupt claim store: {e}")))?;
            for claim in list {
                claims.insert(claim.id.to_string(), claim);
            }
        } else if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(ClaimStore { path, claims })
    }

    /// Insert or replace a claim, recomputing confidence from its evidence
    /// tiers with class-based caps (ADR-007: T5-only support caps low).
    pub fn upsert(&mut self, mut claim: Claim, ledger: &EvidenceLedger) -> Claim {
        let tiers: Vec<TrustTier> = claim
            .supports
            .iter()
            .filter_map(|id| ledger.get(id).map(|r| r.trust_tier))
            .collect();
        let cap = if tiers.iter().all(|t| *t == TrustTier::T5) && !tiers.is_empty() {
            ConfidenceCap::ProposalOnly
        } else if claim.states.observed || claim.states.causally_required {
            ConfidenceCap::Observed
        } else {
            ConfidenceCap::Declared
        };
        claim.confidence = combine_confidence(&tiers, claim.contradicts.len(), cap);
        self.claims.insert(claim.id.to_string(), claim.clone());
        claim
    }

    pub fn get(&self, id: &str) -> Option<&Claim> {
        self.claims.get(id)
    }

    pub fn all(&self) -> impl Iterator<Item = &Claim> {
        self.claims.values()
    }

    pub fn len(&self) -> usize {
        self.claims.len()
    }

    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// Find claims by predicate and/or subject/object substring.
    pub fn query(&self, predicate: Option<&str>, term: Option<&str>) -> Vec<&Claim> {
        self.claims
            .values()
            .filter(|c| predicate.is_none_or(|p| c.predicate == p))
            .filter(|c| term.is_none_or(|t| c.subject.contains(t) || c.object.contains(t)))
            .collect()
    }

    /// Explain a claim by resolving its evidence links (FR-110).
    pub fn explain(&self, id: &str, ledger: &EvidenceLedger) -> Option<Explanation> {
        let claim = self.claims.get(id)?.clone();
        let mut missing = Vec::new();
        let resolve = |ids: &[OvidId], missing: &mut Vec<OvidId>| {
            ids.iter()
                .filter_map(|eid| match ledger.get(eid) {
                    Some(record) => Some(record.clone()),
                    None => {
                        missing.push(eid.clone());
                        None
                    }
                })
                .collect::<Vec<_>>()
        };
        let supporting_evidence = resolve(&claim.supports, &mut missing);
        let contradicting_evidence = resolve(&claim.contradicts, &mut missing);
        Some(Explanation {
            claim,
            supporting_evidence,
            contradicting_evidence,
            missing_evidence: missing,
        })
    }

    /// Persist all claims to disk.
    pub fn save(&self) -> Result<(), OvidError> {
        let list: Vec<&Claim> = self.claims.values().collect();
        let json = serde_json::to_string_pretty(&list)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovid_core::{ClaimState, IdGenerator};

    fn ledger_with_records(
        dir: &std::path::Path,
        tiers: &[TrustTier],
    ) -> (EvidenceLedger, Vec<OvidId>) {
        let generator = IdGenerator::deterministic();
        let mut ledger = EvidenceLedger::open(dir.join("evidence.jsonl")).unwrap();
        let mut ids = Vec::new();
        for tier in tiers {
            let rec = EvidenceRecord {
                id: generator.next("evidence"),
                record_type: "test".into(),
                run_id: None,
                wall_time: None,
                provider: "p".into(),
                provider_version: "0".into(),
                trust_tier: *tier,
                data: serde_json::json!({}),
                previous: None,
            };
            ids.push(rec.id.clone());
            ledger.append(rec).unwrap();
        }
        (ledger, ids)
    }

    #[test]
    fn explain_resolves_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let (ledger, ids) = ledger_with_records(dir.path(), &[TrustTier::T0, TrustTier::T2]);
        let generator = IdGenerator::deterministic();
        let mut store = ClaimStore::open(dir.path().join("claims.json")).unwrap();
        let claim = Claim {
            id: generator.next("claim"),
            predicate: "requires".into(),
            subject: "workload:test".into(),
            object: "service:postgres".into(),
            states: ClaimStates::default().with(ClaimState::Observed),
            confidence: 0.0,
            supports: ids.clone(),
            contradicts: vec![],
            normalizer: "test".into(),
            normalizer_version: "0".into(),
        };
        let claim = store.upsert(claim, &ledger);
        let explanation = store.explain(claim.id.as_str(), &ledger).unwrap();
        assert_eq!(explanation.supporting_evidence.len(), 2);
        assert!(explanation.missing_evidence.is_empty());
        assert!(
            claim.confidence > 0.9,
            "two strong tiers should be high: {}",
            claim.confidence
        );
    }

    #[test]
    fn t5_only_claims_are_capped() {
        let dir = tempfile::tempdir().unwrap();
        let (ledger, ids) = ledger_with_records(dir.path(), &[TrustTier::T5, TrustTier::T5]);
        let generator = IdGenerator::deterministic();
        let mut store = ClaimStore::open(dir.path().join("claims.json")).unwrap();
        let claim = store.upsert(
            Claim {
                id: generator.next("claim"),
                predicate: "calls".into(),
                subject: "a".into(),
                object: "b".into(),
                states: ClaimStates::default(),
                confidence: 0.0,
                supports: ids,
                contradicts: vec![],
                normalizer: "test".into(),
                normalizer_version: "0".into(),
            },
            &ledger,
        );
        // ADR-007: heuristic/model proposals can never be confident facts.
        assert!(
            claim.confidence <= 0.5,
            "T5-only must cap low: {}",
            claim.confidence
        );
    }

    #[test]
    fn save_and_reload_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let (ledger, ids) = ledger_with_records(dir.path(), &[TrustTier::T1]);
        let generator = IdGenerator::deterministic();
        let path = dir.path().join("claims.json");
        {
            let mut store = ClaimStore::open(&path).unwrap();
            store.upsert(
                Claim {
                    id: generator.next("claim"),
                    predicate: "declares".into(),
                    subject: "repo".into(),
                    object: "package:x".into(),
                    states: ClaimStates::default(),
                    confidence: 0.0,
                    supports: ids,
                    contradicts: vec![],
                    normalizer: "test".into(),
                    normalizer_version: "0".into(),
                },
                &ledger,
            );
            store.save().unwrap();
        }
        let store = ClaimStore::open(&path).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.query(Some("declares"), Some("package")).len(), 1);
    }
}
