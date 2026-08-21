//! Typed, logical dependency identity (proposal §7.2).
//!
//! Dependencies are identified logically (`postgres:5432`, `protoc`,
//! `DATABASE_URL`), never by raw observation artifacts like file
//! descriptors or rotating CDN addresses. The kind is part of the
//! identity: a network service named `redis` and an executable named
//! `redis` are different dependencies.

use serde::{Deserialize, Serialize};

/// What kind of thing a workload depends on (proposal §7.2).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyKind {
    /// A declared/installed package (from inventory evidence).
    Package,
    /// An executable found (or missed) on the search path.
    Executable,
    /// A shared library mapping.
    SharedLibrary,
    /// A plain file or fixture.
    File,
    /// An environment variable the workload reads.
    EnvironmentVariable,
    /// An external network service (host:port identity).
    NetworkService,
    /// A local Unix domain socket.
    UnixSocket,
    /// A port the workload itself listens on.
    Listener,
    /// A cloud resource reached through provider APIs.
    CloudResource,
    /// An artifact produced by an earlier workload phase.
    BuildArtifact,
}

/// Logical identity of one dependency (proposal §7.2).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct DependencyKey {
    pub kind: DependencyKind,
    /// Stable logical name: `host:port` for network services, the
    /// basename for executables, the variable name for env vars.
    pub logical_identity: String,
}

impl DependencyKey {
    /// A network-service dependency keyed by `host:port`.
    pub fn network(identity: impl Into<String>) -> DependencyKey {
        DependencyKey {
            kind: DependencyKind::NetworkService,
            logical_identity: identity.into(),
        }
    }

    /// An executable dependency keyed by basename.
    pub fn executable(name: impl Into<String>) -> DependencyKey {
        DependencyKey {
            kind: DependencyKind::Executable,
            logical_identity: name.into(),
        }
    }

    /// An environment-variable dependency keyed by variable name.
    pub fn env_var(name: impl Into<String>) -> DependencyKey {
        DependencyKey {
            kind: DependencyKind::EnvironmentVariable,
            logical_identity: name.into(),
        }
    }

    /// Human-readable `kind:identity` form used in reports and journals.
    pub fn describe(&self) -> String {
        let kind = match self.kind {
            DependencyKind::Package => "package",
            DependencyKind::Executable => "executable",
            DependencyKind::SharedLibrary => "shared-library",
            DependencyKind::File => "file",
            DependencyKind::EnvironmentVariable => "env",
            DependencyKind::NetworkService => "service",
            DependencyKind::UnixSocket => "unix-socket",
            DependencyKind::Listener => "listener",
            DependencyKind::CloudResource => "cloud",
            DependencyKind::BuildArtifact => "artifact",
        };
        format!("{kind}:{}", self.logical_identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_is_part_of_identity() {
        let service = DependencyKey::network("redis:6379");
        let tool = DependencyKey::executable("redis");
        assert_ne!(service, tool);
        assert_eq!(service.describe(), "service:redis:6379");
        assert_eq!(tool.describe(), "executable:redis");
    }
}
