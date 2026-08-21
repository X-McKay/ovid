//! Resolution proposals (spec §14.8, §18.1).
//!
//! Given a failed run's evidence, propose the next controlled change. Every
//! proposal carries provenance and is only a *candidate*: applying it in a
//! derived world and observing progress is what confirms it (§15.3,
//! ADR-007).

use ovid_core::{BoundaryEvent, EventEnvelope, OvidId};
use ovid_gateway::NetworkAnalysis;
use ovid_packs::PackRegistry;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ResolutionKind {
    /// Install a missing executable via a trusted resolver candidate.
    InstallTool {
        executable: String,
        package: String,
        provider: String,
    },
    /// Provide a missing file via a trusted resolver candidate.
    ProvideFile {
        path: String,
        package: String,
        provider: String,
    },
    /// Start a recognized infrastructure service (§18.1 step 3).
    StartService {
        dependency_id: String,
        pack: String,
        port: u16,
    },
    /// Supply a minimal protocol stub (§18.1 step 5).
    SupplyStub {
        dependency_id: String,
        protocol: String,
        port: u16,
    },
    /// Leave unresolved — preserved explicitly (§18.1 step 7, FR-048).
    LeaveUnresolved {
        dependency_id: String,
        reason: String,
    },
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ResolutionProposal {
    pub kind: ResolutionKind,
    /// Ranking confidence from the proposing source.
    pub confidence: f64,
    /// Evidence ids that motivated this proposal.
    pub evidence: Vec<OvidId>,
}

/// Paths that are expected to be missing in normal operation and must not
/// generate proposals (locale probing, optional configs under /etc, shell
/// PATH scans are handled separately via exec events).
fn ignorable_missing_file(path: &str) -> bool {
    path.starts_with("/proc/")
        || path.starts_with("/sys/")
        || path.contains("/.cache/")
        || path.ends_with(".pyc")
        || path.contains("__pycache__")
        || path.contains("locale")
        || path.starts_with("/usr/share/")
}

/// Derive ranked proposals from run evidence and network analysis.
pub fn propose_resolutions(
    events: &[EventEnvelope],
    network: &NetworkAnalysis,
    registry: &PackRegistry,
) -> Vec<ResolutionProposal> {
    let mut proposals: Vec<ResolutionProposal> = Vec::new();
    let mut seen_tools: std::collections::BTreeSet<String> = Default::default();
    let mut seen_files: std::collections::BTreeSet<String> = Default::default();

    for envelope in events {
        match &envelope.event {
            // A failed exec is only a *missing tool* if no exec of the same
            // basename succeeded anywhere (PATH scans produce many ENOENTs
            // before the successful hit).
            BoundaryEvent::ProcessExec {
                path,
                errno: Some(errno),
                ..
            } if errno == "ENOENT" => {
                let basename = path.rsplit('/').next().unwrap_or(path).to_string();
                if seen_tools.contains(&basename) {
                    continue;
                }
                let succeeded_elsewhere = events.iter().any(|other| {
                    matches!(
                        &other.event,
                        BoundaryEvent::ProcessExec { path: p, errno: None, .. }
                            if p.rsplit('/').next() == Some(basename.as_str())
                    )
                });
                if succeeded_elsewhere {
                    continue;
                }
                seen_tools.insert(basename.clone());
                let candidates = registry.resolve_executable(&basename);
                match candidates.first() {
                    Some(candidate) => proposals.push(ResolutionProposal {
                        kind: ResolutionKind::InstallTool {
                            executable: basename,
                            package: candidate.package.clone(),
                            provider: candidate.provider.clone(),
                        },
                        confidence: candidate.confidence,
                        evidence: vec![envelope.event_id.clone()],
                    }),
                    None => proposals.push(ResolutionProposal {
                        kind: ResolutionKind::LeaveUnresolved {
                            dependency_id: format!("tool:{basename}"),
                            reason: "no trusted resolver candidate".into(),
                        },
                        confidence: 0.0,
                        evidence: vec![envelope.event_id.clone()],
                    }),
                }
            }
            BoundaryEvent::FileOpened {
                path,
                errno: Some(errno),
                ..
            } if errno == "ENOENT" && !ignorable_missing_file(path) => {
                if !seen_files.insert(path.clone()) {
                    continue;
                }
                if let Some(candidate) = registry.resolve_file(path).first() {
                    proposals.push(ResolutionProposal {
                        kind: ResolutionKind::ProvideFile {
                            path: path.clone(),
                            package: candidate.package.clone(),
                            provider: candidate.provider.clone(),
                        },
                        confidence: candidate.confidence,
                        evidence: vec![envelope.event_id.clone()],
                    });
                }
            }
            _ => {}
        }
    }

    // PATH-scan misses: shells and make locate commands with stat/access
    // probes, so a missing tool shows up as the same basename missing from
    // two or more directories with no successful exec of that basename.
    // Only resolver-known executables become proposals here — arbitrary
    // stat misses (module probing, optional plugins) carry too little
    // signal on their own (§6.6: prefer precision over forced resolution).
    let mut scan_dirs: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        Default::default();
    for envelope in events {
        if let BoundaryEvent::FileOpened {
            path,
            errno: Some(errno),
            ..
        } = &envelope.event
        {
            if errno == "ENOENT" {
                if let Some((dir, base)) = path.rsplit_once('/') {
                    if !base.is_empty() && !base.contains('.') {
                        scan_dirs
                            .entry(base.to_string())
                            .or_default()
                            .insert(dir.to_string());
                    }
                }
            }
        }
    }
    for (basename, dirs) in &scan_dirs {
        if dirs.len() < 2 || seen_tools.contains(basename) {
            continue;
        }
        let succeeded = events.iter().any(|other| {
            matches!(
                &other.event,
                BoundaryEvent::ProcessExec { path: p, errno: None, .. }
                    if p.rsplit('/').next() == Some(basename.as_str())
            )
        });
        if succeeded {
            continue;
        }
        if let Some(candidate) = registry.resolve_executable(basename).first() {
            let evidence: Vec<OvidId> = events
                .iter()
                .filter(|e| {
                    matches!(
                        &e.event,
                        BoundaryEvent::FileOpened { path, errno: Some(_), .. }
                            if path.rsplit('/').next() == Some(basename.as_str())
                    )
                })
                .map(|e| e.event_id.clone())
                .collect();
            seen_tools.insert(basename.clone());
            proposals.push(ResolutionProposal {
                kind: ResolutionKind::InstallTool {
                    executable: basename.clone(),
                    package: candidate.package.clone(),
                    provider: candidate.provider.clone(),
                },
                confidence: candidate.confidence * 0.9, // stat scans are one step weaker than exec misses
                evidence,
            });
        }
    }

    // Failed external destinations: service pack, stub, or unresolved
    // (§18.1's resolution order, steps 3/5/7 — fleet providers are steps
    // 2/6 and out of scope for local mode).
    for observation in &network.external {
        if !observation.all_failed() {
            continue;
        }
        let dependency_id = observation
            .dns_name
            .clone()
            .unwrap_or_else(|| format!("{}:{}", observation.address, observation.port));
        match (
            &observation.protocol,
            observation.service_candidates.first(),
        ) {
            (Some(_), Some(pack)) => proposals.push(ResolutionProposal {
                kind: ResolutionKind::StartService {
                    dependency_id,
                    pack: pack.clone(),
                    port: observation.port,
                },
                confidence: 0.8,
                evidence: observation.evidence.clone(),
            }),
            (Some(protocol), None) => proposals.push(ResolutionProposal {
                kind: ResolutionKind::SupplyStub {
                    dependency_id,
                    protocol: protocol.clone(),
                    port: observation.port,
                },
                confidence: 0.5,
                evidence: observation.evidence.clone(),
            }),
            (None, _) => proposals.push(ResolutionProposal {
                kind: ResolutionKind::LeaveUnresolved {
                    dependency_id,
                    reason: "unclassified protocol".into(),
                },
                confidence: 0.0,
                evidence: observation.evidence.clone(),
            }),
        }
    }

    proposals.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    proposals
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovid_core::{IdGenerator, TrustTier};
    use ovid_gateway::analyze_network;
    use std::collections::BTreeMap;

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
    fn missing_protoc_proposes_install() {
        let ids = IdGenerator::deterministic();
        let registry = PackRegistry::builtin().unwrap();
        let events = vec![envelope(
            &ids,
            BoundaryEvent::ProcessExec {
                path: "/usr/bin/protoc".into(),
                argv: vec!["protoc".into()],
                errno: Some("ENOENT".into()),
            },
        )];
        let network = analyze_network(&events, &registry, &BTreeMap::new());
        let proposals = propose_resolutions(&events, &network, &registry);
        assert!(matches!(
            &proposals[0].kind,
            ResolutionKind::InstallTool { executable, package, .. }
                if executable == "protoc" && package == "protobuf-compiler"
        ));
        assert!(
            !proposals[0].evidence.is_empty(),
            "proposals must carry provenance"
        );
    }

    #[test]
    fn path_scan_enoents_are_not_missing_tools() {
        let ids = IdGenerator::deterministic();
        let registry = PackRegistry::builtin().unwrap();
        // Shell PATH search: several ENOENTs then a success.
        let events = vec![
            envelope(
                &ids,
                BoundaryEvent::ProcessExec {
                    path: "/usr/local/bin/make".into(),
                    argv: vec!["make".into()],
                    errno: Some("ENOENT".into()),
                },
            ),
            envelope(
                &ids,
                BoundaryEvent::ProcessExec {
                    path: "/usr/bin/make".into(),
                    argv: vec!["make".into()],
                    errno: None,
                },
            ),
        ];
        let network = analyze_network(&events, &registry, &BTreeMap::new());
        let proposals = propose_resolutions(&events, &network, &registry);
        assert!(
            proposals.is_empty(),
            "resolved PATH scans must not propose installs: {proposals:?}"
        );
    }

    #[test]
    fn path_scan_stat_misses_propose_known_tool() {
        let ids = IdGenerator::deterministic();
        let registry = PackRegistry::builtin().unwrap();
        let miss = |dir: &str| BoundaryEvent::FileOpened {
            path: format!("{dir}/protoc"),
            errno: Some("ENOENT".into()),
            write: false,
        };
        let events = vec![
            envelope(&ids, miss("/usr/local/bin")),
            envelope(&ids, miss("/usr/bin")),
            envelope(&ids, miss("/bin")),
        ];
        let network = analyze_network(&events, &registry, &BTreeMap::new());
        let proposals = propose_resolutions(&events, &network, &registry);
        assert!(matches!(
            &proposals[0].kind,
            ResolutionKind::InstallTool { executable, package, .. }
                if executable == "protoc" && package == "protobuf-compiler"
        ));
        assert_eq!(proposals[0].evidence.len(), 3);
    }

    #[test]
    fn path_scan_with_successful_exec_is_not_missing() {
        let ids = IdGenerator::deterministic();
        let registry = PackRegistry::builtin().unwrap();
        let events = vec![
            envelope(
                &ids,
                BoundaryEvent::FileOpened {
                    path: "/usr/local/bin/make".into(),
                    errno: Some("ENOENT".into()),
                    write: false,
                },
            ),
            envelope(
                &ids,
                BoundaryEvent::FileOpened {
                    path: "/opt/bin/make".into(),
                    errno: Some("ENOENT".into()),
                    write: false,
                },
            ),
            envelope(
                &ids,
                BoundaryEvent::ProcessExec {
                    path: "/usr/bin/make".into(),
                    argv: vec!["make".into()],
                    errno: None,
                },
            ),
        ];
        let network = analyze_network(&events, &registry, &BTreeMap::new());
        let proposals = propose_resolutions(&events, &network, &registry);
        assert!(
            proposals.is_empty(),
            "found tool must not be proposed: {proposals:?}"
        );
    }

    #[test]
    fn unknown_stat_misses_are_not_proposed() {
        let ids = IdGenerator::deterministic();
        let registry = PackRegistry::builtin().unwrap();
        let events = vec![
            envelope(
                &ids,
                BoundaryEvent::FileOpened {
                    path: "/usr/lib/python3/dist-packages/optional_module".into(),
                    errno: Some("ENOENT".into()),
                    write: false,
                },
            ),
            envelope(
                &ids,
                BoundaryEvent::FileOpened {
                    path: "/usr/local/lib/python3/optional_module".into(),
                    errno: Some("ENOENT".into()),
                    write: false,
                },
            ),
        ];
        let network = analyze_network(&events, &registry, &BTreeMap::new());
        let proposals = propose_resolutions(&events, &network, &registry);
        assert!(
            proposals.is_empty(),
            "unknown probes must not spam proposals: {proposals:?}"
        );
    }

    #[test]
    fn refused_postgres_proposes_service_pack() {
        let ids = IdGenerator::deterministic();
        let registry = PackRegistry::builtin().unwrap();
        let events = vec![envelope(
            &ids,
            BoundaryEvent::SocketConnect {
                address: "10.203.0.201".into(),
                port: 5432,
                original_dns_name: Some("orders-db".into()),
                result: Some("ECONNREFUSED".into()),
                protocol_hint: None,
            },
        )];
        let network = analyze_network(&events, &registry, &BTreeMap::new());
        let proposals = propose_resolutions(&events, &network, &registry);
        assert!(matches!(
            &proposals[0].kind,
            ResolutionKind::StartService { dependency_id, pack, port: 5432 }
                if dependency_id == "orders-db" && pack == "postgres"
        ));
    }

    #[test]
    fn unknown_protocol_left_unresolved() {
        let ids = IdGenerator::deterministic();
        let registry = PackRegistry::builtin().unwrap();
        let events = vec![envelope(
            &ids,
            BoundaryEvent::SocketConnect {
                address: "10.0.0.5".into(),
                port: 7654,
                original_dns_name: Some("telemetry.internal".into()),
                result: Some("ECONNREFUSED".into()),
                protocol_hint: None,
            },
        )];
        let network = analyze_network(&events, &registry, &BTreeMap::new());
        let proposals = propose_resolutions(&events, &network, &registry);
        assert!(matches!(
            &proposals[0].kind,
            ResolutionKind::LeaveUnresolved { dependency_id, .. } if dependency_id == "telemetry.internal"
        ));
    }

    #[test]
    fn successful_connections_produce_no_proposals() {
        let ids = IdGenerator::deterministic();
        let registry = PackRegistry::builtin().unwrap();
        let events = vec![envelope(
            &ids,
            BoundaryEvent::SocketConnect {
                address: "127.0.0.1".into(),
                port: 5432,
                original_dns_name: None,
                result: Some("success".into()),
                protocol_hint: None,
            },
        )];
        let network = analyze_network(&events, &registry, &BTreeMap::new());
        assert!(propose_resolutions(&events, &network, &registry).is_empty());
    }
}
