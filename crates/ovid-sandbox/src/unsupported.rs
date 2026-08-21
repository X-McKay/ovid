//! Honest stubs for hosts without unix process semantics (Windows).
//!
//! Static analysis (`inventory`, compose/endpoint mining, planning) is
//! fully portable and works here; workload *execution* is not. Backends on
//! these hosts fail at construction with [`OvidError::UnsupportedHost`] —
//! never a silent degrade (isolation honesty) — so every pipeline error
//! message tells the operator exactly what is missing.

use crate::{ExecutionBackend, IsolationTier, RunResult, RunSpec};
use ovid_core::OvidError;

fn unsupported(what: &str) -> OvidError {
    OvidError::UnsupportedHost(format!(
        "{what} requires a unix host (Linux for observation and network \
         counterfactuals); static analysis commands remain available here"
    ))
}

/// Stub for [`crate::process::ProcessBackend`].
pub struct ProcessBackend;

impl ProcessBackend {
    pub fn new() -> Result<Self, OvidError> {
        Err(unsupported("the supervised process backend"))
    }
}

impl ExecutionBackend for ProcessBackend {
    fn name(&self) -> &'static str {
        "ovid-process-backend"
    }
    fn isolation_tier(&self) -> IsolationTier {
        IsolationTier::TrustedProcess
    }
    fn run(&self, _spec: &RunSpec) -> Result<RunResult, OvidError> {
        Err(unsupported("the supervised process backend"))
    }
}

/// Unprivileged user+network namespaces are a Linux facility.
pub fn network_isolation_available() -> bool {
    false
}
