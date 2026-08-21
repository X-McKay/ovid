//! Evidence records (spec §22.2).

use ovid_core::{Digest, EventEnvelope, OvidId, TrustTier};
use serde::{Deserialize, Serialize};

/// One immutable observation or provider result.
///
/// `data` is schemaless JSON on purpose: providers evolve independently and
/// the normalizers that project records into claims are versioned (§14.7).
/// The chain fields are filled in by the ledger at append time.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct EvidenceRecord {
    pub id: OvidId,
    /// Record type, e.g. `socket-connect-result`, `sbom-component`,
    /// `experiment-outcome`.
    #[serde(rename = "type")]
    pub record_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<OvidId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Producing provider and version — facts require provenance (§6.5).
    pub provider: String,
    pub provider_version: String,
    pub trust_tier: TrustTier,
    /// Free-form payload; shape is owned by (`provider`, `record_type`).
    pub data: serde_json::Value,
    /// Digest of the previous record in the ledger (chain link, §22.6).
    /// `None` only for the first record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<Digest>,
}

impl EvidenceRecord {
    /// Build a record from a normalized boundary event envelope.
    pub fn from_event(id: OvidId, envelope: &EventEnvelope) -> Self {
        EvidenceRecord {
            id,
            record_type: envelope.event.type_label().to_string(),
            run_id: Some(envelope.run_id.clone()),
            wall_time: envelope.wall_time,
            provider: envelope.provider.clone(),
            provider_version: envelope.provider_version.clone(),
            trust_tier: envelope.trust_tier,
            data: serde_json::to_value(envelope).expect("event envelopes are serializable"),
            previous: None,
        }
    }

    /// Digest of this record's canonical JSON serialization (with the chain
    /// link included, so the digest covers ordering).
    pub fn digest(&self) -> Digest {
        let json = serde_json::to_vec(self).expect("evidence records are serializable");
        Digest::of_bytes(&json)
    }
}
