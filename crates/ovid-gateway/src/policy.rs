//! Egress, DNS, and fault policy (FR-040..FR-043, FR-048, FR-049, §17.2,
//! §30.6).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// Egress posture. Default deny (FR-041).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EgressMode {
    #[default]
    Deny,
    /// Deny except approved package registries/source hosts via recording
    /// proxies (§30.6's default exception set).
    RegistriesOnly,
    /// Unrestricted — only valid for trusted-repository policies.
    Allow,
}

/// DNS behavior for unknown names (§17.2).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DnsMode {
    /// Return NXDOMAIN for unknown names (observe/strict policy).
    #[default]
    Strict,
    /// Allocate a job-local virtual identity so exploration can watch what
    /// the workload does with a resolvable name (FR-043). Must be disclosed
    /// in the manifest because it changes behavior (§17.2).
    Explore,
}

/// Metadata endpoints that are always blocked (§17.2 item 5, §30.3).
const METADATA_ADDRESSES: &[&str] = &["169.254.169.254", "fd00:ec2::254", "metadata.google.internal"];
const METADATA_NAMES: &[&str] =
    &["metadata.google.internal", "metadata", "instance-data", "169.254.169.254"];

/// Default approved registry hosts for `RegistriesOnly` mode.
const DEFAULT_REGISTRY_HOSTS: &[&str] = &[
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "proxy.golang.org",
    "sum.golang.org",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "rubygems.org",
    "packagist.org",
    "github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
];

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NetworkPolicy {
    pub egress: EgressMode,
    pub dns: DnsMode,
    /// Approved registry/source hosts (suffix match on labels).
    pub registry_hosts: Vec<String>,
    /// Known service aliases from the world: name -> address (§17.2 item 1).
    pub service_aliases: BTreeMap<String, String>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        NetworkPolicy {
            egress: EgressMode::Deny,
            dns: DnsMode::Strict,
            registry_hosts: DEFAULT_REGISTRY_HOSTS.iter().map(|s| s.to_string()).collect(),
            service_aliases: BTreeMap::new(),
        }
    }
}

impl NetworkPolicy {
    pub fn registries_only() -> Self {
        NetworkPolicy { egress: EgressMode::RegistriesOnly, ..Default::default() }
    }

    fn is_registry_host(&self, name: &str) -> bool {
        self.registry_hosts
            .iter()
            .any(|host| name == host || name.ends_with(&format!(".{host}")))
    }

    fn is_metadata(&self, name_or_address: &str) -> bool {
        METADATA_ADDRESSES.contains(&name_or_address) || METADATA_NAMES.contains(&name_or_address)
    }

    /// Decide a DNS query (§17.2's six behaviors).
    pub fn decide_dns(&self, name: &str, allocator: &mut VirtualIdentityAllocator) -> DnsDecision {
        if self.is_metadata(name) {
            return DnsDecision::Blocked;
        }
        if let Some(address) = self.service_aliases.get(name) {
            return DnsDecision::ServiceAlias { address: address.clone() };
        }
        if self.egress != EgressMode::Deny && self.is_registry_host(name) {
            return DnsDecision::RegistryProxy;
        }
        if self.egress == EgressMode::Allow {
            return DnsDecision::Upstream;
        }
        match self.dns {
            DnsMode::Explore => {
                DnsDecision::VirtualIdentity { address: allocator.allocate(name).to_string() }
            }
            DnsMode::Strict => DnsDecision::NxDomain,
        }
    }

    /// Decide a direct connection attempt (§17.3).
    pub fn decide_connect(&self, address: &str, _port: u16) -> ConnectDecision {
        if self.is_metadata(address) {
            return ConnectDecision::Blocked;
        }
        if address.starts_with("127.") || address == "::1" {
            // Loopback stays inside the job.
            return ConnectDecision::AllowedLocal;
        }
        if self.service_aliases.values().any(|a| a == address) {
            return ConnectDecision::AllowedService;
        }
        match self.egress {
            EgressMode::Allow => ConnectDecision::Allowed,
            EgressMode::RegistriesOnly => ConnectDecision::ProxyOnly,
            EgressMode::Deny => ConnectDecision::Blocked,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(tag = "decision", rename_all = "kebab-case")]
pub enum DnsDecision {
    /// Known world service.
    ServiceAlias { address: String },
    /// Approved registry through the recording proxy (FR-042).
    RegistryProxy,
    /// Resolved upstream (trusted policy only).
    Upstream,
    /// Job-local virtual identity for discovery (FR-043).
    VirtualIdentity { address: String },
    NxDomain,
    Blocked,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectDecision {
    Allowed,
    AllowedLocal,
    AllowedService,
    /// Must go through the registry proxy.
    ProxyOnly,
    Blocked,
}

/// Allocates stable per-name virtual identities in the job's synthetic
/// range (§17.1: `.200+` addresses).
pub struct VirtualIdentityAllocator {
    job_octet: u8,
    next_host: u8,
    assigned: BTreeMap<String, Ipv4Addr>,
}

impl VirtualIdentityAllocator {
    pub fn new(job_octet: u8) -> Self {
        VirtualIdentityAllocator { job_octet, next_host: 200, assigned: BTreeMap::new() }
    }

    /// Same name always gets the same identity within a job.
    pub fn allocate(&mut self, name: &str) -> Ipv4Addr {
        if let Some(existing) = self.assigned.get(name) {
            return *existing;
        }
        let address = Ipv4Addr::new(10, 203, self.job_octet, self.next_host);
        self.next_host = self.next_host.saturating_add(1);
        self.assigned.insert(name.to_string(), address);
        address
    }

    /// Reverse lookup: which name owns this identity?
    pub fn name_for(&self, address: &str) -> Option<&str> {
        self.assigned
            .iter()
            .find(|(_, ip)| ip.to_string() == address)
            .map(|(name, _)| name.as_str())
    }
}

/// Fault injection conditions for counterfactual experiments (FR-049).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(tag = "fault", rename_all = "kebab-case")]
pub enum FaultPolicy {
    /// Connection refused (service absent).
    Refuse,
    /// Accept then never respond.
    Timeout { seconds: u64 },
    /// Reset established connections.
    Reset,
    /// Added latency.
    Latency { millis: u64 },
    /// Malformed response bytes.
    Malformed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_denies_unknown_dns() {
        let policy = NetworkPolicy::default();
        let mut allocator = VirtualIdentityAllocator::new(17);
        assert_eq!(policy.decide_dns("payments.internal", &mut allocator), DnsDecision::NxDomain);
    }

    #[test]
    fn metadata_is_always_blocked() {
        // Even the most permissive policy blocks metadata endpoints.
        let policy = NetworkPolicy {
            egress: EgressMode::Allow,
            dns: DnsMode::Explore,
            ..Default::default()
        };
        let mut allocator = VirtualIdentityAllocator::new(1);
        assert_eq!(policy.decide_dns("169.254.169.254", &mut allocator), DnsDecision::Blocked);
        assert_eq!(
            policy.decide_dns("metadata.google.internal", &mut allocator),
            DnsDecision::Blocked
        );
        assert_eq!(policy.decide_connect("169.254.169.254", 80), ConnectDecision::Blocked);
    }

    #[test]
    fn registries_route_to_proxy() {
        let policy = NetworkPolicy::registries_only();
        let mut allocator = VirtualIdentityAllocator::new(1);
        assert_eq!(policy.decide_dns("crates.io", &mut allocator), DnsDecision::RegistryProxy);
        assert_eq!(
            policy.decide_dns("static.crates.io", &mut allocator),
            DnsDecision::RegistryProxy
        );
        // Non-registry names still get NXDOMAIN under strict DNS.
        assert_eq!(policy.decide_dns("evil.example.com", &mut allocator), DnsDecision::NxDomain);
    }

    #[test]
    fn explore_mode_allocates_stable_virtual_identities() {
        let policy = NetworkPolicy {
            dns: DnsMode::Explore,
            ..NetworkPolicy::default()
        };
        let mut allocator = VirtualIdentityAllocator::new(17);
        let first = policy.decide_dns("payments", &mut allocator);
        let second = policy.decide_dns("payments", &mut allocator);
        assert_eq!(first, second, "same name must resolve to the same identity");
        let DnsDecision::VirtualIdentity { address } = first else { panic!("wrong decision") };
        assert!(address.starts_with("10.203.17.2"), "virtual range is .200+: {address}");
        assert_eq!(allocator.name_for(&address), Some("payments"));
    }

    #[test]
    fn world_aliases_win_over_everything_but_metadata() {
        let mut policy = NetworkPolicy::default();
        policy.service_aliases.insert("orders-db".into(), "10.203.17.22".into());
        let mut allocator = VirtualIdentityAllocator::new(17);
        assert_eq!(
            policy.decide_dns("orders-db", &mut allocator),
            DnsDecision::ServiceAlias { address: "10.203.17.22".into() }
        );
        assert_eq!(policy.decide_connect("10.203.17.22", 5432), ConnectDecision::AllowedService);
    }

    #[test]
    fn deny_blocks_external_connects_but_allows_loopback() {
        let policy = NetworkPolicy::default();
        assert_eq!(policy.decide_connect("93.184.216.34", 443), ConnectDecision::Blocked);
        assert_eq!(policy.decide_connect("127.0.0.1", 5432), ConnectDecision::AllowedLocal);
    }
}
