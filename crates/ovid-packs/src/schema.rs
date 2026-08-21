//! Pack schema types (spec §15.1–§15.5).

use ovid_core::{OvidError, PACK_API_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Common metadata every pack carries (§15.1).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct PackMetadata {
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

fn default_version() -> String {
    "0.1.0".to_string()
}

/// Pack permissions default to fully closed (§15.7).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct PackPermissions {
    #[serde(default)]
    pub network: PermissionLevel,
    #[serde(default)]
    pub host_files: PermissionLevel,
    #[serde(default)]
    pub guest_capabilities: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionLevel {
    #[default]
    None,
    Declared,
}

/// A parsed pack of any kind.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Pack {
    pub api_version: String,
    pub metadata: PackMetadata,
    #[serde(default)]
    pub permissions: PackPermissions,
    #[serde(flatten)]
    pub body: PackBody,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PackBody {
    RunnerRecipe(RunnerRecipe),
    ServicePack(ServicePack),
    ProtocolPack(ProtocolPack),
    ToolResolverPack(ToolResolverPack),
}

impl Pack {
    /// Parse and validate a pack from YAML.
    pub fn parse(yaml: &str) -> Result<Pack, OvidError> {
        let pack: Pack = serde_yaml::from_str(yaml)
            .map_err(|e| OvidError::Pack(format!("pack parse error: {e}")))?;
        pack.validate()?;
        Ok(pack)
    }

    pub fn validate(&self) -> Result<(), OvidError> {
        if self.api_version != PACK_API_VERSION {
            return Err(OvidError::Pack(format!(
                "unsupported pack api_version {:?} (expected {PACK_API_VERSION})",
                self.api_version
            )));
        }
        if self.metadata.name.is_empty() {
            return Err(OvidError::Pack("pack metadata.name is required".into()));
        }
        if let PackBody::ServicePack(service) = &self.body {
            if !service.image.reference.contains("@sha256:") {
                return Err(OvidError::Pack(format!(
                    "service pack {} image must be digest-pinned (…@sha256:…)",
                    self.metadata.name
                )));
            }
        }
        Ok(())
    }

    pub fn kind_label(&self) -> &'static str {
        match self.body {
            PackBody::RunnerRecipe(_) => "runner-recipe",
            PackBody::ServicePack(_) => "service-pack",
            PackBody::ProtocolPack(_) => "protocol-pack",
            PackBody::ToolResolverPack(_) => "tool-resolver-pack",
        }
    }

    /// `name@version` label used in provenance sections.
    pub fn label(&self) -> String {
        format!("{}@{}", self.metadata.name, self.metadata.version)
    }
}

// ---------------------------------------------------------------------------
// runner-recipe (§15.2)
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct RunnerDetect {
    /// Any of these files present (exact basename match) triggers detection.
    #[serde(default)]
    pub any_files: Vec<String>,
    /// Or: any file with one of these extensions.
    #[serde(default)]
    pub extensions: Vec<String>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct RunnerCommands {
    #[serde(default)]
    pub inventory: Vec<Vec<String>>,
    #[serde(default)]
    pub install: Vec<Vec<String>>,
    #[serde(default)]
    pub build: Vec<Vec<String>>,
    #[serde(default)]
    pub test: Vec<Vec<String>>,
    #[serde(default)]
    pub start: Vec<Vec<String>>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct RunnerRecipe {
    pub detect: RunnerDetect,
    #[serde(default)]
    pub commands: RunnerCommands,
    /// Executables the recipe's commands require (used to pre-check the
    /// world and to seed tool-resolver queries).
    #[serde(default)]
    pub required_tools: Vec<String>,
}

// ---------------------------------------------------------------------------
// service-pack (§15.5)
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ServiceImage {
    /// Digest-pinned OCI reference.
    pub reference: String,
    #[serde(default = "default_isolation")]
    pub isolation: String,
}

fn default_isolation() -> String {
    "dedicated-microvm".to_string()
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ServicePort {
    pub name: String,
    pub container: u16,
    #[serde(default = "default_tcp")]
    pub protocol: String,
}

fn default_tcp() -> String {
    "tcp".to_string()
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct ServiceReadiness {
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_port: Option<u16>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    30
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ServiceProvides {
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ServicePack {
    pub provides: ServiceProvides,
    pub image: ServiceImage,
    #[serde(default)]
    pub ports: Vec<ServicePort>,
    #[serde(default)]
    pub readiness: ServiceReadiness,
    /// Environment configuration; the literal value `generated-secret`
    /// means an ephemeral per-job secret is created (never stored).
    #[serde(default)]
    pub configuration: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// protocol-pack (§15.4)
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct ProtocolMatch {
    #[serde(default)]
    pub ports: Vec<u16>,
    /// ASCII prefixes any of which identify the protocol from first bytes.
    #[serde(default)]
    pub first_bytes_ascii_prefix_any: Vec<String>,
    /// ALPN identifiers (TLS metadata).
    #[serde(default)]
    pub alpn_any: Vec<String>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ProtocolPack {
    #[serde(rename = "match", default)]
    pub matcher: ProtocolMatch,
    /// Canonical protocol/system name reported in claims.
    pub system: String,
    /// Compatible service packs, in preference order.
    #[serde(default)]
    pub service_candidates: Vec<String>,
}

// ---------------------------------------------------------------------------
// tool-resolver-pack (§15.3)
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ResolverCandidate {
    pub provider: String,
    pub package: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
}

fn default_confidence() -> f64 {
    0.9
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ToolResolverPack {
    /// Missing executable name -> trusted candidates, best first.
    #[serde(default)]
    pub executables: BTreeMap<String, Vec<ResolverCandidate>>,
    /// Missing file path suffix -> trusted candidates (e.g. openssl/ssl.h).
    #[serde(default)]
    pub files: BTreeMap<String, Vec<ResolverCandidate>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_runner_recipe() {
        let yaml = r#"
api_version: ovid.dev/pack/v1
kind: runner-recipe
metadata:
  name: rust
detect:
  any_files: [Cargo.toml]
commands:
  build:
    - [cargo, build, --locked]
  test:
    - [cargo, test, --locked]
required_tools: [cargo]
"#;
        let pack = Pack::parse(yaml).unwrap();
        assert_eq!(pack.kind_label(), "runner-recipe");
        assert_eq!(pack.label(), "rust@0.1.0");
        let PackBody::RunnerRecipe(recipe) = &pack.body else {
            panic!("wrong kind")
        };
        assert_eq!(recipe.detect.any_files, vec!["Cargo.toml"]);
        assert_eq!(recipe.commands.test[0][0], "cargo");
    }

    #[test]
    fn rejects_wrong_api_version() {
        let yaml = r#"
api_version: ovid.dev/pack/v999
kind: runner-recipe
metadata: { name: x }
detect: {}
"#;
        assert!(Pack::parse(yaml).is_err());
    }

    #[test]
    fn rejects_unpinned_service_image() {
        let yaml = r#"
api_version: ovid.dev/pack/v1
kind: service-pack
metadata: { name: postgres, version: 1.0.0 }
provides: { protocols: [postgresql], aliases: [postgres] }
image: { reference: "docker.io/library/postgres:latest" }
"#;
        let err = Pack::parse(yaml).unwrap_err().to_string();
        assert!(err.contains("digest-pinned"), "{err}");
    }

    #[test]
    fn permissions_default_closed() {
        let yaml = r#"
api_version: ovid.dev/pack/v1
kind: protocol-pack
metadata: { name: redis }
system: redis
match:
  ports: [6379]
  first_bytes_ascii_prefix_any: ["*", "+"]
service_candidates: [redis]
"#;
        let pack = Pack::parse(yaml).unwrap();
        assert_eq!(pack.permissions.network, PermissionLevel::None);
        assert_eq!(pack.permissions.host_files, PermissionLevel::None);
    }
}
