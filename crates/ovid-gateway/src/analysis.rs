//! Post-run network analysis: turn observed socket events into classified
//! external-dependency observations (§14.7's normalization step for the
//! network boundary, FR-044).

use ovid_core::{BoundaryEvent, EventEnvelope, OvidId};
use ovid_packs::PackRegistry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One external destination the workload attempted to reach.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ExternalObservation {
    pub address: String,
    pub port: u16,
    /// Original DNS name when the gateway allocated a virtual identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    /// Classified protocol system (`postgresql`, `redis`, `http`, …), or
    /// `None` — unresolved is preserved, never guessed (FR-048, §6.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Compatible service packs for the classified protocol.
    #[serde(default)]
    pub service_candidates: Vec<String>,
    pub attempts: u64,
    pub failures: u64,
    /// Distinct connect results seen (`success`, `ECONNREFUSED`, …).
    pub outcomes: Vec<String>,
    /// Evidence ids of the underlying socket events.
    pub evidence: Vec<OvidId>,
}

impl ExternalObservation {
    /// All attempts failed — the classic "dependency missing" signal that
    /// seeds resolution (§14.8).
    pub fn all_failed(&self) -> bool {
        self.attempts > 0 && self.failures == self.attempts
    }
}

/// A port the workload listened on (inbound interface discovery, §17.7).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Listener {
    pub address: String,
    pub port: u16,
    pub evidence: Vec<OvidId>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct NetworkAnalysis {
    pub external: Vec<ExternalObservation>,
    pub listeners: Vec<Listener>,
    /// Unix socket paths connected to (local IPC boundary).
    pub unix_sockets: Vec<String>,
}

/// Analyze a run's events. `dns_names` maps virtual-identity addresses back
/// to the names the workload asked for.
pub fn analyze_network(
    events: &[EventEnvelope],
    registry: &PackRegistry,
    dns_names: &BTreeMap<String, String>,
) -> NetworkAnalysis {
    let mut destinations: BTreeMap<(String, u16), ExternalObservation> = BTreeMap::new();
    let mut listeners: BTreeMap<(String, u16), Listener> = BTreeMap::new();
    let mut unix_sockets: Vec<String> = Vec::new();

    for envelope in events {
        match &envelope.event {
            BoundaryEvent::SocketConnect { address, port, original_dns_name, result, .. } => {
                if *port == 53 {
                    continue; // resolver traffic, not an application dependency
                }
                let entry = destinations.entry((address.clone(), *port)).or_insert_with(|| {
                    ExternalObservation {
                        address: address.clone(),
                        port: *port,
                        dns_name: original_dns_name
                            .clone()
                            .or_else(|| dns_names.get(address).cloned()),
                        protocol: None,
                        service_candidates: Vec::new(),
                        attempts: 0,
                        failures: 0,
                        outcomes: Vec::new(),
                        evidence: Vec::new(),
                    }
                });
                entry.attempts += 1;
                if envelope.event.is_failure() {
                    entry.failures += 1;
                }
                if let Some(result) = result {
                    if !entry.outcomes.contains(result) {
                        entry.outcomes.push(result.clone());
                    }
                }
                entry.evidence.push(envelope.event_id.clone());
            }
            BoundaryEvent::SocketListening { address, port } => {
                let entry = listeners.entry((address.clone(), *port)).or_insert_with(|| {
                    Listener { address: address.clone(), port: *port, evidence: Vec::new() }
                });
                entry.evidence.push(envelope.event_id.clone());
            }
            BoundaryEvent::UnixSocketConnected { path, .. } => {
                if !unix_sockets.contains(path) {
                    unix_sockets.push(path.clone());
                }
            }
            _ => {}
        }
    }

    let mut external: Vec<ExternalObservation> = destinations.into_values().collect();
    for observation in &mut external {
        // Protocol classification by port (first bytes are a data-plane
        // input not available at this layer). Unknown stays None.
        if let Some((_, protocol)) = registry.classify_protocol(observation.port, None) {
            observation.protocol = Some(protocol.system.clone());
            observation.service_candidates = protocol.service_candidates.clone();
        }
    }

    NetworkAnalysis { external, listeners: listeners.into_values().collect(), unix_sockets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovid_core::{IdGenerator, TrustTier};

    fn envelope(ids: &IdGenerator, event: BoundaryEvent) -> EventEnvelope {
        EventEnvelope {
            event_id: ids.next("evidence"),
            run_id: OvidId::from_string("run:test"),
            sequence: 0,
            wall_time: None,
            provider: "test".into(),
            provider_version: "0".into(),
            trust_tier: TrustTier::T2,
            process: None,
            event,
        }
    }

    #[test]
    fn groups_classifies_and_flags_failures() {
        let ids = IdGenerator::deterministic();
        let registry = PackRegistry::builtin().unwrap();
        let connect = |result: &str| BoundaryEvent::SocketConnect {
            address: "10.203.17.201".into(),
            port: 5432,
            original_dns_name: None,
            result: Some(result.into()),
            protocol_hint: None,
        };
        let events = vec![
            envelope(&ids, connect("ECONNREFUSED")),
            envelope(&ids, connect("ECONNREFUSED")),
            envelope(&ids, BoundaryEvent::SocketListening { address: "0.0.0.0".into(), port: 8080 }),
        ];
        let mut dns = BTreeMap::new();
        dns.insert("10.203.17.201".to_string(), "orders-db".to_string());
        let analysis = analyze_network(&events, &registry, &dns);
        assert_eq!(analysis.external.len(), 1);
        let observation = &analysis.external[0];
        assert_eq!(observation.attempts, 2);
        assert!(observation.all_failed());
        assert_eq!(observation.protocol.as_deref(), Some("postgresql"));
        assert_eq!(observation.service_candidates, vec!["postgres"]);
        assert_eq!(observation.dns_name.as_deref(), Some("orders-db"));
        assert_eq!(observation.evidence.len(), 2);
        assert_eq!(analysis.listeners.len(), 1);
        assert_eq!(analysis.listeners[0].port, 8080);
    }

    #[test]
    fn unknown_protocol_stays_unresolved() {
        let ids = IdGenerator::deterministic();
        let registry = PackRegistry::builtin().unwrap();
        let events = vec![envelope(
            &ids,
            BoundaryEvent::SocketConnect {
                address: "10.0.0.9".into(),
                port: 7777,
                original_dns_name: Some("telemetry.internal".into()),
                result: Some("success".into()),
                protocol_hint: None,
            },
        )];
        let analysis = analyze_network(&events, &registry, &BTreeMap::new());
        assert_eq!(analysis.external[0].protocol, None, "unknown must stay unresolved (FR-048)");
        assert!(!analysis.external[0].all_failed());
    }

    #[test]
    fn dns_port_53_is_not_a_dependency() {
        let ids = IdGenerator::deterministic();
        let registry = PackRegistry::builtin().unwrap();
        let events = vec![envelope(
            &ids,
            BoundaryEvent::SocketConnect {
                address: "127.0.0.53".into(),
                port: 53,
                original_dns_name: None,
                result: Some("success".into()),
                protocol_hint: None,
            },
        )];
        let analysis = analyze_network(&events, &registry, &BTreeMap::new());
        assert!(analysis.external.is_empty());
    }
}
