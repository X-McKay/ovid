//! Event reduction (spec §32.5, FR-039).
//!
//! Rules:
//! - repeated *successful* events with the same signature collapse to their
//!   first occurrence plus a count;
//! - every failure signature is preserved (first occurrence) — failures are
//!   first-class evidence (§6.2);
//! - configured noise paths are dropped entirely unless they failed;
//! - nothing disappears without accounting: collapsed and noise counts are
//!   reported so completeness can be assessed.

use ovid_core::{BoundaryEvent, EventEnvelope};
use std::collections::HashMap;

/// Default noise path prefixes: high-churn reads that carry no dependency
/// signal. Failures under these paths are still retained.
const NOISE_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/etc/ld.so.cache",
    "/usr/lib/locale",
    "/usr/share/locale",
    "/dev/null",
    "/dev/urandom",
];

#[derive(Debug)]
pub struct AggregatedEvents {
    /// Retained events in original order.
    pub events: Vec<EventEnvelope>,
    /// signature -> duplicate count (only signatures that repeated).
    pub collapsed: HashMap<String, u64>,
    /// Successful noise-path opens dropped.
    pub noise_dropped: u64,
    pub input_count: usize,
}

/// Stable signature for dedup: kind + primary key + failure code.
fn signature(event: &BoundaryEvent) -> String {
    match event {
        BoundaryEvent::FileOpened { path, errno, write } => {
            format!(
                "file-opened|{path}|{}|{write}",
                errno.as_deref().unwrap_or("ok")
            )
        }
        BoundaryEvent::SharedObjectMapped { path } => format!("so-mapped|{path}"),
        BoundaryEvent::ProcessExec { path, errno, .. } => {
            format!("exec|{path}|{}", errno.as_deref().unwrap_or("ok"))
        }
        BoundaryEvent::SocketConnect {
            address,
            port,
            result,
            ..
        } => {
            format!(
                "connect|{address}|{port}|{}",
                result.as_deref().unwrap_or("?")
            )
        }
        BoundaryEvent::UnixSocketConnected { path, result } => {
            format!("unix-connect|{path}|{}", result.as_deref().unwrap_or("?"))
        }
        BoundaryEvent::DnsQuery { name, .. } => format!("dns|{name}"),
        // Everything else is a state transition; never collapse.
        other => format!("unique|{}|{}", other.type_label(), fastrand_counter()),
    }
}

/// Monotonic counter to make non-collapsible signatures unique.
fn fastrand_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn is_noise(event: &BoundaryEvent) -> bool {
    match event {
        BoundaryEvent::FileOpened { path, errno, .. } if errno.is_none() => {
            NOISE_PREFIXES.iter().any(|p| path.starts_with(p))
        }
        _ => false,
    }
}

pub fn aggregate(input: Vec<EventEnvelope>) -> AggregatedEvents {
    let input_count = input.len();
    let mut seen: HashMap<String, u64> = HashMap::new();
    let mut events = Vec::new();
    let mut noise_dropped = 0u64;
    for envelope in input {
        if is_noise(&envelope.event) {
            noise_dropped += 1;
            continue;
        }
        let sig = signature(&envelope.event);
        match seen.get_mut(&sig) {
            Some(count) => *count += 1,
            None => {
                seen.insert(sig, 0);
                events.push(envelope);
            }
        }
    }
    let collapsed = seen.into_iter().filter(|(_, count)| *count > 0).collect();
    AggregatedEvents {
        events,
        collapsed,
        noise_dropped,
        input_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovid_core::{IdGenerator, ProcessIdentity, TrustTier};

    fn envelope(ids: &IdGenerator, event: BoundaryEvent) -> EventEnvelope {
        EventEnvelope {
            event_id: ids.next("evidence"),
            run_id: ovid_core::OvidId::from_string("run:test"),
            sequence: 0,
            wall_time: None,
            provider: "test".into(),
            provider_version: "0".into(),
            trust_tier: TrustTier::T2,
            process: Some(ProcessIdentity {
                pid: 1,
                parent_pid: None,
                executable: None,
            }),
            event,
        }
    }

    #[test]
    fn repeated_success_collapses_failures_survive() {
        let ids = IdGenerator::deterministic();
        let open_ok = || BoundaryEvent::FileOpened {
            path: "/app/config.yaml".into(),
            errno: None,
            write: false,
        };
        let open_fail = || BoundaryEvent::FileOpened {
            path: "/app/missing.yaml".into(),
            errno: Some("ENOENT".into()),
            write: false,
        };
        let input = vec![
            envelope(&ids, open_ok()),
            envelope(&ids, open_ok()),
            envelope(&ids, open_ok()),
            envelope(&ids, open_fail()),
            envelope(&ids, open_fail()),
        ];
        let result = aggregate(input);
        assert_eq!(result.events.len(), 2, "one success + one failure retained");
        assert_eq!(result.collapsed.len(), 2);
        let total_collapsed: u64 = result.collapsed.values().sum();
        assert_eq!(total_collapsed, 3);
    }

    #[test]
    fn noise_paths_dropped_but_counted() {
        let ids = IdGenerator::deterministic();
        let input = vec![
            envelope(
                &ids,
                BoundaryEvent::FileOpened {
                    path: "/proc/self/stat".into(),
                    errno: None,
                    write: false,
                },
            ),
            // A *failed* open under /proc still survives.
            envelope(
                &ids,
                BoundaryEvent::FileOpened {
                    path: "/proc/kcore".into(),
                    errno: Some("EACCES".into()),
                    write: false,
                },
            ),
        ];
        let result = aggregate(input);
        assert_eq!(result.noise_dropped, 1);
        assert_eq!(result.events.len(), 1);
        assert!(result.events[0].event.is_failure());
    }

    #[test]
    fn state_transitions_never_collapse() {
        let ids = IdGenerator::deterministic();
        let input = vec![
            envelope(
                &ids,
                BoundaryEvent::ProcessExited {
                    exit_code: 0,
                    signal: None,
                },
            ),
            envelope(
                &ids,
                BoundaryEvent::ProcessExited {
                    exit_code: 0,
                    signal: None,
                },
            ),
        ];
        let result = aggregate(input);
        assert_eq!(result.events.len(), 2);
    }
}
