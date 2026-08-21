//! Normalized boundary events (spec §13.7, §27.4).
//!
//! Boundary events are the durable abstraction of the whole system: a
//! process executed a binary, opened a file, attempted a connection, and so
//! on. Failed operations are first-class evidence (§6.2) — an `execve` that
//! returns `ENOENT` is the seed for a missing-tool experiment, so failures
//! are modeled explicitly rather than filtered.

use crate::digest::Digest;
use crate::id::OvidId;
use crate::trust::TrustTier;
use serde::{Deserialize, Serialize};

/// Identity of the process an event is attributed to.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct ProcessIdentity {
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    /// Executable path as observed at exec time, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
}

/// The event payload. Field sets intentionally mirror the spec's initial
/// event list; host-gateway events (DNS, flows) share the same envelope.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BoundaryEvent {
    ProcessForked {
        child_pid: u32,
    },
    /// An exec attempt. `errno` is present when the attempt failed
    /// (e.g. `ENOENT` for a missing tool — FR-030/FR-037).
    ProcessExec {
        path: String,
        argv: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        errno: Option<String>,
    },
    ProcessExited {
        exit_code: i32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signal: Option<i32>,
    },
    /// A file open. `errno` present means the open failed (missing config,
    /// missing header, …) — a candidate requirement.
    FileOpened {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        errno: Option<String>,
        #[serde(default)]
        write: bool,
    },
    /// A shared object was mapped executable — package-load evidence.
    SharedObjectMapped {
        path: String,
    },
    /// A socket connect attempt and its result.
    SocketConnect {
        address: String,
        port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original_dns_name: Option<String>,
        /// `None` = in progress/unknown, `Some("success")`, or an errno such
        /// as `ECONNREFUSED`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protocol_hint: Option<String>,
    },
    SocketBound {
        address: String,
        port: u16,
    },
    SocketListening {
        address: String,
        port: u16,
    },
    UnixSocketConnected {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<String>,
    },
    DnsQuery {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answer: Option<String>,
        /// Gateway policy decision: `answered`, `virtual-identity`,
        /// `nxdomain`, `blocked`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decision: Option<String>,
    },
    /// A build/workload output artifact.
    ArtifactCreated {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        digest: Option<Digest>,
    },
    /// A package/artifact download observed at the gateway proxy (FR-034).
    ArtifactDownloaded {
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        digest: Option<Digest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_type: Option<String>,
    },
    /// Mandatory drop accounting (§27.5): lost events become completeness
    /// limitations, never silent gaps.
    EventsDropped {
        count: u64,
        reason: String,
    },
    /// A test framework-level result, when parseable.
    TestResult {
        name: String,
        passed: bool,
    },
    /// Terminal outcome of a run under a success predicate.
    RunOutcome {
        success: bool,
        detail: String,
    },
}

impl BoundaryEvent {
    /// Whether this event represents a failed operation. Failures seed the
    /// resolution loop (§14.8) and must never be aggregated away (§32.5).
    pub fn is_failure(&self) -> bool {
        match self {
            BoundaryEvent::ProcessExec { errno, .. } => errno.is_some(),
            BoundaryEvent::FileOpened { errno, .. } => errno.is_some(),
            BoundaryEvent::SocketConnect { result, .. } => {
                matches!(result.as_deref(), Some(r) if r != "success")
            }
            BoundaryEvent::UnixSocketConnected { result, .. } => {
                matches!(result.as_deref(), Some(r) if r != "success")
            }
            BoundaryEvent::ProcessExited { exit_code, signal } => {
                *exit_code != 0 || signal.is_some()
            }
            BoundaryEvent::TestResult { passed, .. } => !passed,
            BoundaryEvent::RunOutcome { success, .. } => !success,
            _ => false,
        }
    }

    /// A short stable label used for aggregation and metrics
    /// (`ovid_boundary_events_total{type}`).
    pub fn type_label(&self) -> &'static str {
        match self {
            BoundaryEvent::ProcessForked { .. } => "process-forked",
            BoundaryEvent::ProcessExec { .. } => "process-exec",
            BoundaryEvent::ProcessExited { .. } => "process-exited",
            BoundaryEvent::FileOpened { .. } => "file-opened",
            BoundaryEvent::SharedObjectMapped { .. } => "shared-object-mapped",
            BoundaryEvent::SocketConnect { .. } => "socket-connect",
            BoundaryEvent::SocketBound { .. } => "socket-bound",
            BoundaryEvent::SocketListening { .. } => "socket-listening",
            BoundaryEvent::UnixSocketConnected { .. } => "unix-socket-connected",
            BoundaryEvent::DnsQuery { .. } => "dns-query",
            BoundaryEvent::ArtifactCreated { .. } => "artifact-created",
            BoundaryEvent::ArtifactDownloaded { .. } => "artifact-downloaded",
            BoundaryEvent::EventsDropped { .. } => "events-dropped",
            BoundaryEvent::TestResult { .. } => "test-result",
            BoundaryEvent::RunOutcome { .. } => "run-outcome",
        }
    }
}

/// Convenience alias used by observers when only the discriminant matters.
pub type EventKind = &'static str;

/// The full envelope: event plus attribution, ordering, and provenance
/// (spec §27.4's `EvidenceEvent`, JSON profile).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct EventEnvelope {
    pub event_id: OvidId,
    pub run_id: OvidId,
    /// Monotonic ordering within the run (observer sequence number).
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_time: Option<chrono::DateTime<chrono::Utc>>,
    pub provider: String,
    pub provider_version: String,
    pub trust_tier: TrustTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessIdentity>,
    #[serde(flatten)]
    pub event: BoundaryEvent,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_exec_is_failure_evidence() {
        let ev = BoundaryEvent::ProcessExec {
            path: "protoc".into(),
            argv: vec!["protoc".into()],
            errno: Some("ENOENT".into()),
        };
        assert!(ev.is_failure());
        let ok = BoundaryEvent::ProcessExec {
            path: "/usr/bin/cc".into(),
            argv: vec![],
            errno: None,
        };
        assert!(!ok.is_failure());
    }

    #[test]
    fn connect_refused_is_failure() {
        let ev = BoundaryEvent::SocketConnect {
            address: "10.0.0.1".into(),
            port: 5432,
            original_dns_name: Some("orders-db".into()),
            result: Some("ECONNREFUSED".into()),
            protocol_hint: None,
        };
        assert!(ev.is_failure());
    }

    #[test]
    fn envelope_round_trips_through_json() {
        let generator = crate::id::IdGenerator::deterministic();
        let env = EventEnvelope {
            event_id: generator.next("evidence"),
            run_id: generator.next("run"),
            sequence: 7,
            wall_time: None,
            provider: "ovid-strace-observer".into(),
            provider_version: "0.1.0".into(),
            trust_tier: TrustTier::T2,
            process: Some(ProcessIdentity {
                pid: 42,
                parent_pid: Some(1),
                executable: Some("/bin/sh".into()),
            }),
            event: BoundaryEvent::FileOpened {
                path: "/etc/app.yaml".into(),
                errno: Some("ENOENT".into()),
                write: false,
            },
        };
        let json = serde_json::to_string(&env).unwrap();
        let back: EventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
        assert!(json.contains("\"kind\":\"file-opened\""));
    }
}
