//! Post-run network analysis: turn observed socket and DNS events into
//! classified external-dependency observations (§14.7's normalization step
//! for the network boundary, FR-033, FR-044).
//!
//! Identity resolution order for a destination:
//! 1. the gateway-supplied name (virtual identities / world aliases);
//! 2. names recovered from observed DNS answers (the process backend's
//!    resolver-traffic capture);
//! 3. the raw address, explicitly marked ip-only — absence of a name is
//!    reported, never papered over (§25.3).
//!
//! Observations that resolve to the same DNS name are grouped into one
//! logical dependency with an endpoint list, so a CDN rotating A records
//! does not fragment into per-IP records.

use ovid_core::{BoundaryEvent, EventEnvelope, OvidId};
use ovid_packs::PackRegistry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One external dependency the workload attempted to reach, grouped by
/// DNS name when one is known.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ExternalObservation {
    /// Primary address (first observed endpoint).
    pub address: String,
    pub port: u16,
    /// DNS name identity, from the gateway or observed resolver traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,
    /// All distinct addresses observed for this dependency.
    #[serde(default)]
    pub endpoints: Vec<String>,
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
    /// Evidence ids of the underlying socket and DNS events.
    pub evidence: Vec<OvidId>,
}

impl ExternalObservation {
    /// All attempts failed — the classic "dependency missing" signal that
    /// seeds resolution (§14.8).
    pub fn all_failed(&self) -> bool {
        self.attempts > 0 && self.failures == self.attempts
    }

    /// Stable identity for cross-run comparison: the DNS name when known
    /// (survives CDN address rotation), the address otherwise.
    pub fn identity(&self) -> String {
        match &self.dns_name {
            Some(name) => format!("{name}:{}", self.port),
            None => format!("{}:{}", self.address, self.port),
        }
    }

    /// Whether this destination is under an experiment's control: an
    /// isolated network namespace removes *external* reachability, but
    /// loopback keeps working, so loopback destinations are never varied
    /// by a network intervention and cannot be attributed by one
    /// (spec §20).
    pub fn externally_controlled(&self) -> bool {
        !(self.address.starts_with("127.") || self.address == "::1")
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
    /// Resolver servers queried (port-53 peers). The pipeline compares
    /// these against `/etc/resolv.conf` to flag resolver bypass.
    #[serde(default)]
    pub dns_servers: Vec<String>,
    /// Names the workload queried, with any observed answers.
    #[serde(default)]
    pub dns_queries: BTreeMap<String, Vec<String>>,
}

/// Analyze a run's events. `dns_names` maps addresses back to names when
/// the caller (a gateway) already knows them; names recovered from
/// observed DNS answers are merged in.
pub fn analyze_network(
    events: &[EventEnvelope],
    registry: &PackRegistry,
    dns_names: &BTreeMap<String, String>,
) -> NetworkAnalysis {
    // Pass 1: harvest DNS evidence — address -> name, plus resolver
    // servers and the query log.
    let mut names: BTreeMap<String, String> = dns_names.clone();
    let mut dns_servers: Vec<String> = Vec::new();
    let mut dns_queries: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut dns_evidence: BTreeMap<String, Vec<OvidId>> = BTreeMap::new();
    for envelope in events {
        match &envelope.event {
            BoundaryEvent::DnsQuery {
                name,
                answer,
                server,
                ..
            } => {
                let answers = dns_queries.entry(name.clone()).or_default();
                if let Some(answer) = answer {
                    names.entry(answer.clone()).or_insert_with(|| name.clone());
                    if !answers.contains(answer) {
                        answers.push(answer.clone());
                    }
                }
                if let Some(server) = server {
                    if !dns_servers.contains(server) {
                        dns_servers.push(server.clone());
                    }
                }
                dns_evidence
                    .entry(name.clone())
                    .or_default()
                    .push(envelope.event_id.clone());
            }
            BoundaryEvent::SocketConnect {
                address, port: 53, ..
            } if !dns_servers.contains(address) => {
                dns_servers.push(address.clone());
            }
            _ => {}
        }
    }

    // Pass 2: group connects by identity — DNS name when known, address
    // otherwise. Port-0 datagram route probes carry no dependency signal.
    let mut destinations: BTreeMap<(String, u16), ExternalObservation> = BTreeMap::new();
    let mut listeners: BTreeMap<(String, u16), Listener> = BTreeMap::new();
    let mut unix_sockets: Vec<String> = Vec::new();

    for envelope in events {
        match &envelope.event {
            BoundaryEvent::SocketConnect {
                address,
                port,
                original_dns_name,
                result,
                ..
            } => {
                if *port == 53 || *port == 0 {
                    continue; // resolver traffic / route probes
                }
                let dns_name = original_dns_name
                    .clone()
                    .or_else(|| names.get(address).cloned());
                let key = (dns_name.clone().unwrap_or_else(|| address.clone()), *port);
                let entry = destinations
                    .entry(key)
                    .or_insert_with(|| ExternalObservation {
                        address: address.clone(),
                        port: *port,
                        dns_name: dns_name.clone(),
                        endpoints: Vec::new(),
                        protocol: None,
                        service_candidates: Vec::new(),
                        attempts: 0,
                        failures: 0,
                        outcomes: Vec::new(),
                        evidence: Vec::new(),
                    });
                if !entry.endpoints.contains(address) {
                    entry.endpoints.push(address.clone());
                }
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
                let entry = listeners
                    .entry((address.clone(), *port))
                    .or_insert_with(|| Listener {
                        address: address.clone(),
                        port: *port,
                        evidence: Vec::new(),
                    });
                entry.evidence.push(envelope.event_id.clone());
            }
            BoundaryEvent::UnixSocketConnected { path, .. } if !unix_sockets.contains(path) => {
                unix_sockets.push(path.clone());
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
        // A named dependency's record also carries the DNS evidence that
        // established the name (the claim's support set stays complete).
        if let Some(name) = &observation.dns_name {
            if let Some(ids) = dns_evidence.get(name) {
                for id in ids {
                    if !observation.evidence.contains(id) {
                        observation.evidence.push(id.clone());
                    }
                }
            }
        }
    }

    NetworkAnalysis {
        external,
        listeners: listeners.into_values().collect(),
        unix_sockets,
        dns_servers,
        dns_queries,
    }
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
            envelope(
                &ids,
                BoundaryEvent::SocketListening {
                    address: "0.0.0.0".into(),
                    port: 8080,
                },
            ),
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
        assert_eq!(observation.identity(), "orders-db:5432");
        assert_eq!(observation.evidence.len(), 2);
        assert_eq!(analysis.listeners.len(), 1);
        assert_eq!(analysis.listeners[0].port, 8080);
    }

    #[test]
    fn observed_dns_answers_name_and_group_multiple_endpoints() {
        let ids = IdGenerator::deterministic();
        let registry = PackRegistry::builtin().unwrap();
        let answer = |ip: &str| BoundaryEvent::DnsQuery {
            name: "temporal.download".into(),
            answer: Some(ip.into()),
            decision: None,
            server: Some("8.8.8.8".into()),
        };
        let connect = |ip: &str| BoundaryEvent::SocketConnect {
            address: ip.into(),
            port: 443,
            original_dns_name: None,
            result: Some("EINPROGRESS".into()),
            protocol_hint: None,
        };
        let events = vec![
            envelope(&ids, answer("104.21.27.83")),
            envelope(&ids, answer("172.67.141.216")),
            envelope(&ids, connect("104.21.27.83")),
            envelope(&ids, connect("172.67.141.216")),
        ];
        let analysis = analyze_network(&events, &registry, &BTreeMap::new());
        // Two IPs collapse into one logical dependency, identified by name.
        assert_eq!(analysis.external.len(), 1, "{:?}", analysis.external);
        let observation = &analysis.external[0];
        assert_eq!(observation.dns_name.as_deref(), Some("temporal.download"));
        assert_eq!(observation.identity(), "temporal.download:443");
        assert_eq!(observation.endpoints.len(), 2);
        assert_eq!(observation.attempts, 2);
        // Evidence covers both connects and both DNS answers.
        assert_eq!(observation.evidence.len(), 4);
        // Resolver server surfaced.
        assert_eq!(analysis.dns_servers, vec!["8.8.8.8"]);
        assert_eq!(
            analysis.dns_queries["temporal.download"],
            vec!["104.21.27.83", "172.67.141.216"]
        );
    }

    #[test]
    fn unnamed_destination_is_ip_only_identity() {
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
        assert_eq!(
            analysis.external[0].protocol, None,
            "unknown must stay unresolved (FR-048)"
        );
        assert!(!analysis.external[0].all_failed());

        // Truly unnamed destination: identity falls back to the address.
        let events = vec![envelope(
            &ids,
            BoundaryEvent::SocketConnect {
                address: "203.0.113.7".into(),
                port: 9999,
                original_dns_name: None,
                result: Some("success".into()),
                protocol_hint: None,
            },
        )];
        let analysis = analyze_network(&events, &registry, &BTreeMap::new());
        assert_eq!(analysis.external[0].dns_name, None);
        assert_eq!(analysis.external[0].identity(), "203.0.113.7:9999");
    }

    #[test]
    fn resolver_traffic_and_route_probes_are_not_dependencies() {
        let ids = IdGenerator::deterministic();
        let registry = PackRegistry::builtin().unwrap();
        let events = vec![
            envelope(
                &ids,
                BoundaryEvent::SocketConnect {
                    address: "127.0.0.53".into(),
                    port: 53,
                    original_dns_name: None,
                    result: Some("success".into()),
                    protocol_hint: None,
                },
            ),
            // UDP route probe (port 0).
            envelope(
                &ids,
                BoundaryEvent::SocketConnect {
                    address: "104.21.27.83".into(),
                    port: 0,
                    original_dns_name: None,
                    result: Some("success".into()),
                    protocol_hint: None,
                },
            ),
        ];
        let analysis = analyze_network(&events, &registry, &BTreeMap::new());
        assert!(analysis.external.is_empty());
        // But the resolver server is still surfaced.
        assert_eq!(analysis.dns_servers, vec!["127.0.0.53"]);
    }
}
