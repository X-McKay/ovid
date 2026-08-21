//! Worlds and world locks (spec §8.5, §26, FR-090..FR-095).
//!
//! A [`World`] is the complete description of the environment an experiment
//! runs in: the target, its dependency treatments, configuration, and
//! provisioned tools. Worlds are content-addressed — the digest of the
//! canonical serialization scopes every claim (§23.3).
//!
//! A [`WorldLock`] is the replay-optimized projection (§26): no floating
//! references, explicit startup order, health checks, and the workload
//! command with its success predicate. A lock is only labeled `verified`
//! after a clean replay succeeds (FR-095, ADR-008) — the lock carries its
//! status so consumers can tell proposed worlds from verified ones.

use ovid_core::{Digest, WORLD_API_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How a dependency is satisfied in a world (FR-091).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(tag = "treatment", rename_all = "kebab-case")]
pub enum Treatment {
    /// Real disposable service from a service pack.
    RealService { pack: String, image: String },
    /// Adaptive or minimal stub.
    Stub { protocol: String },
    /// Static fixture (file, seed data).
    Fixture { path: String },
    /// Another repository's verified world (fleet mode).
    FleetRepository { analysis: String },
    /// Deliberately absent — e.g. counterfactually removed, or optional.
    Absent,
    /// Could not be satisfied; preserved, not hidden (FR-048).
    Unresolved { reason: String },
}

/// One dependency slot in a world.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct WorldDependency {
    /// Stable id, e.g. `orders-db` or `payments`.
    pub id: String,
    pub treatment: Treatment,
    /// DNS aliases the workload may use for this dependency.
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Environment variables this dependency contributes to the target.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

/// The full world description.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct World {
    /// Human-scoped name of the target (repository/workload).
    pub target: String,
    /// Tools provisioned beyond the base image (from resolver candidates).
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<WorldDependency>,
    /// Target-level environment.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

impl World {
    /// Content digest of the canonical (JSON) serialization. Dependencies
    /// are sorted by id first so digest is order-insensitive.
    pub fn digest(&self) -> Digest {
        let mut canonical = self.clone();
        canonical.dependencies.sort_by(|a, b| a.id.cmp(&b.id));
        canonical.tools.sort();
        let json = serde_json::to_vec(&canonical).expect("worlds serialize");
        Digest::of_bytes(&json)
    }

    /// Derive a new world with one dependency's treatment replaced — the
    /// "exactly one controlled change" rule of §14.9.
    pub fn with_treatment(&self, dependency_id: &str, treatment: Treatment) -> World {
        let mut derived = self.clone();
        for dependency in &mut derived.dependencies {
            if dependency.id == dependency_id {
                dependency.treatment = treatment;
                return derived;
            }
        }
        derived.dependencies.push(WorldDependency {
            id: dependency_id.to_string(),
            treatment,
            aliases: vec![dependency_id.to_string()],
            port: None,
            environment: BTreeMap::new(),
        });
        derived
    }

    pub fn dependency(&self, id: &str) -> Option<&WorldDependency> {
        self.dependencies.iter().find(|d| d.id == id)
    }
}

/// Verification status of a lock (ADR-008).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub enum WorldStatus {
    #[default]
    Proposed,
    Verified,
    ReplayFailed,
}

/// Success predicate carried in the lock (§26's `workload.success`).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum SuccessSpec {
    ExitCode { expected: i32 },
    OutputContains { needle: String },
    ArtifactExists { path: String },
}

/// The replay-optimized lock (§26).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct WorldLock {
    pub api_version: String,
    pub kind: String,
    pub metadata: WorldLockMetadata,
    pub policy: BTreeMap<String, String>,
    pub network: WorldNetwork,
    pub cells: Vec<WorldCell>,
    pub startup_order: Vec<String>,
    pub workload: WorkloadSpec,
    pub status: WorldStatus,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct WorldLockMetadata {
    pub world_id: String,
    pub digest: Digest,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct WorldNetwork {
    pub cidr: String,
    /// alias -> address.
    #[serde(default)]
    pub dns: BTreeMap<String, String>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct WorldCell {
    pub id: String,
    /// `target`, `service`, `stub`, or `repository`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_pack: Option<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct WorkloadSpec {
    pub cell: String,
    pub command: Vec<String>,
    pub success: SuccessSpec,
}

impl WorldLock {
    /// Build a lock from a world + workload. Services start before the
    /// target; unresolved/absent dependencies are excluded from startup but
    /// unresolved ones remain visible as cells so nothing is hidden.
    pub fn from_world(world: &World, workload_command: Vec<String>, success: SuccessSpec) -> WorldLock {
        let digest = world.digest();
        let mut cells = Vec::new();
        let mut startup = Vec::new();
        let mut dns = BTreeMap::new();
        let mut address_host = 20u8;
        for dependency in &world.dependencies {
            let address = format!("10.203.0.{address_host}");
            match &dependency.treatment {
                Treatment::RealService { pack, image } => {
                    cells.push(WorldCell {
                        id: dependency.id.clone(),
                        kind: "service".into(),
                        image: Some(image.clone()),
                        provider_pack: Some(pack.clone()),
                        environment: dependency.environment.clone(),
                        port: dependency.port,
                    });
                    startup.push(dependency.id.clone());
                    for alias in &dependency.aliases {
                        dns.insert(alias.clone(), address.clone());
                    }
                    address_host += 1;
                }
                Treatment::Stub { protocol } => {
                    cells.push(WorldCell {
                        id: dependency.id.clone(),
                        kind: "stub".into(),
                        image: None,
                        provider_pack: Some(format!("stub:{protocol}")),
                        environment: dependency.environment.clone(),
                        port: dependency.port,
                    });
                    startup.push(dependency.id.clone());
                    for alias in &dependency.aliases {
                        dns.insert(alias.clone(), address.clone());
                    }
                    address_host += 1;
                }
                Treatment::FleetRepository { analysis } => {
                    cells.push(WorldCell {
                        id: dependency.id.clone(),
                        kind: "repository".into(),
                        image: None,
                        provider_pack: Some(analysis.clone()),
                        environment: dependency.environment.clone(),
                        port: dependency.port,
                    });
                    startup.push(dependency.id.clone());
                    address_host += 1;
                }
                Treatment::Unresolved { .. } => {
                    cells.push(WorldCell {
                        id: dependency.id.clone(),
                        kind: "unresolved".into(),
                        image: None,
                        provider_pack: None,
                        environment: BTreeMap::new(),
                        port: dependency.port,
                    });
                }
                Treatment::Fixture { .. } | Treatment::Absent => {}
            }
        }
        cells.push(WorldCell {
            id: "target".into(),
            kind: "target".into(),
            image: None,
            provider_pack: None,
            environment: world.environment.clone(),
            port: None,
        });
        startup.push("target".into());
        let mut policy = BTreeMap::new();
        policy.insert("egress".into(), "deny".into());
        policy.insert("tls_mode".into(), "metadata".into());
        policy.insert("payload_retention".into(), "metadata".into());
        WorldLock {
            api_version: WORLD_API_VERSION.to_string(),
            kind: "WorldLock".to_string(),
            metadata: WorldLockMetadata {
                world_id: format!("world:{}", &digest.hex()[..16]),
                digest,
            },
            policy,
            network: WorldNetwork { cidr: "10.203.0.0/24".into(), dns },
            cells,
            startup_order: startup,
            workload: WorkloadSpec { cell: "target".into(), command: workload_command, success },
            status: WorldStatus::Proposed,
        }
    }

    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).expect("world locks serialize")
    }

    /// Export a local Compose replay file (FR-093). Only startable cells
    /// become services; the target is rendered as a commented build slot
    /// because the target image is produced by the analysis, not pulled.
    pub fn to_compose_yaml(&self) -> String {
        let mut out = String::from(
            "# Generated by Ovid — local replay environment (spec FR-093).\n# Startup order: ",
        );
        out.push_str(&self.startup_order.join(" -> "));
        out.push_str("\nservices:\n");
        for cell in &self.cells {
            match cell.kind.as_str() {
                "service" => {
                    out.push_str(&format!("  {}:\n", cell.id));
                    if let Some(image) = &cell.image {
                        out.push_str(&format!("    image: \"{image}\"\n"));
                    }
                    if !cell.environment.is_empty() {
                        out.push_str("    environment:\n");
                        for (key, value) in &cell.environment {
                            out.push_str(&format!("      {key}: \"{value}\"\n"));
                        }
                    }
                    if let Some(port) = cell.port {
                        out.push_str(&format!("    ports:\n      - \"{port}:{port}\"\n"));
                    }
                }
                "target" => {
                    out.push_str(&format!(
                        "  # target workload: {}\n  # command: {}\n",
                        self.workload.cell,
                        self.workload.command.join(" ")
                    ));
                }
                _ => {
                    out.push_str(&format!(
                        "  # {} cell {} — not locally startable\n",
                        cell.kind, cell.id
                    ));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn world_with_postgres() -> World {
        let mut world = World { target: "checkout".into(), ..Default::default() };
        world.dependencies.push(WorldDependency {
            id: "orders-db".into(),
            treatment: Treatment::RealService {
                pack: "postgres@1.0.0".into(),
                image: "docker.io/library/postgres@sha256:abc".into(),
            },
            aliases: vec!["orders-db".into(), "postgres".into()],
            port: Some(5432),
            environment: BTreeMap::from([("POSTGRES_USER".into(), "ovid".into())]),
        });
        world
    }

    #[test]
    fn digest_is_order_insensitive_but_content_sensitive() {
        let mut a = world_with_postgres();
        a.dependencies.push(WorldDependency {
            id: "cache".into(),
            treatment: Treatment::Stub { protocol: "redis".into() },
            aliases: vec![],
            port: None,
            environment: BTreeMap::new(),
        });
        let mut b = a.clone();
        b.dependencies.reverse();
        assert_eq!(a.digest(), b.digest());
        let c = a.with_treatment("cache", Treatment::Absent);
        assert_ne!(a.digest(), c.digest());
    }

    #[test]
    fn with_treatment_changes_exactly_one_dependency() {
        let world = world_with_postgres();
        let derived = world.with_treatment("orders-db", Treatment::Absent);
        assert_eq!(derived.dependencies.len(), 1);
        assert_eq!(derived.dependency("orders-db").unwrap().treatment, Treatment::Absent);
        // Original untouched.
        assert!(matches!(
            world.dependency("orders-db").unwrap().treatment,
            Treatment::RealService { .. }
        ));
    }

    #[test]
    fn lock_orders_services_before_target_and_maps_dns() {
        let world = world_with_postgres();
        let lock = WorldLock::from_world(
            &world,
            vec!["cargo".into(), "test".into()],
            SuccessSpec::ExitCode { expected: 0 },
        );
        assert_eq!(lock.startup_order.last().map(String::as_str), Some("target"));
        assert_eq!(lock.startup_order[0], "orders-db");
        assert!(lock.network.dns.contains_key("postgres"));
        assert_eq!(lock.status, WorldStatus::Proposed);
        assert_eq!(lock.policy["egress"], "deny");
    }

    #[test]
    fn unresolved_dependencies_stay_visible_in_lock() {
        let mut world = world_with_postgres();
        world.dependencies.push(WorldDependency {
            id: "telemetry".into(),
            treatment: Treatment::Unresolved { reason: "certificate-pinned".into() },
            aliases: vec![],
            port: Some(8443),
            environment: BTreeMap::new(),
        });
        let lock = WorldLock::from_world(
            &world,
            vec!["make".into(), "test".into()],
            SuccessSpec::ExitCode { expected: 0 },
        );
        assert!(lock.cells.iter().any(|c| c.id == "telemetry" && c.kind == "unresolved"));
        assert!(!lock.startup_order.contains(&"telemetry".to_string()));
    }

    #[test]
    fn compose_export_contains_service_and_env() {
        let world = world_with_postgres();
        let lock = WorldLock::from_world(
            &world,
            vec!["cargo".into(), "test".into()],
            SuccessSpec::ExitCode { expected: 0 },
        );
        let compose = lock.to_compose_yaml();
        assert!(compose.contains("orders-db:"));
        assert!(compose.contains("docker.io/library/postgres@sha256:abc"));
        assert!(compose.contains("POSTGRES_USER"));
        assert!(compose.contains("5432:5432"));
    }
}
