//! Explicit conclusion scope (proposal §2.2, §7.1).
//!
//! A causal conclusion is meaningless without its scope: one repository
//! revision, one workload, one environment, one success predicate, one
//! policy, one observer. The scope travels with every conclusion and is
//! digested into provenance, so "PostgreSQL was required" always reads as
//! "…for `integration-test` at revision `abc123`, under environment
//! `env:…`" — never as a universal statement about the repository.

use ovid_core::Digest;
use serde::{Deserialize, Serialize};

/// The scope every conclusion is bound to (proposal §7.1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct AnalysisScope {
    /// Canonical repository locator (URL or absolute path).
    pub repository: String,
    /// Exact revision analyzed (or the source digest for non-git trees).
    pub revision: String,
    /// Selected workload name (e.g. `test`).
    pub workload: String,
    /// The exact argv executed for the workload.
    pub workload_argv: Vec<String>,
    /// Digest of the prepared environment (toolchain + provisioning).
    pub environment_digest: String,
    /// Human description of the success predicate in force.
    pub success_predicate: String,
    /// Digest of the execution policy (isolation, limits, env policy).
    pub execution_policy: String,
    /// Observer identity (`name@version`) that produced boundary facts.
    pub observer: String,
    /// Digest/description of the experiment policy (baseline runs,
    /// confirmation runs, trial budget).
    pub experiment_policy: String,
}

impl AnalysisScope {
    /// Content digest of the scope, recorded in provenance so cached
    /// trial reuse can prove the causal inputs matched (proposal §14.9).
    pub fn digest(&self) -> Digest {
        let json = serde_json::to_vec(self).expect("scopes serialize");
        Digest::of_bytes(&json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_content_sensitive() {
        let a = AnalysisScope {
            repository: "repo".into(),
            revision: "abc".into(),
            workload: "test".into(),
            ..Default::default()
        };
        let mut b = a.clone();
        assert_eq!(a.digest(), b.digest());
        b.revision = "def".into();
        assert_ne!(a.digest(), b.digest());
    }
}
