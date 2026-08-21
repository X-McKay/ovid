//! Chameleon Gateway control plane (spec §13.10, §17, FR-040..FR-049).
//!
//! The gateway is the center of external-system discovery. This crate
//! implements its *decision* layer — egress policy, DNS handling, virtual
//! service identities, protocol classification, and fault policies — as
//! pure, unit-testable logic, plus the post-run analysis that turns
//! observed socket events into classified external-dependency
//! observations.
//!
//! The packet-forwarding data plane (netns + nftables/eBPF redirection in
//! the MicroVM worker) consumes these decisions; on the process backend,
//! enforcement is observational (deny-by-policy is recorded and surfaced)
//! rather than packet-level, and manifests carry that distinction via the
//! backend's isolation tier.

pub mod analysis;
pub mod policy;

pub use analysis::{analyze_network, ExternalObservation, Listener, NetworkAnalysis};
pub use policy::{
    ConnectDecision, DnsDecision, DnsMode, EgressMode, FaultPolicy, NetworkPolicy,
    VirtualIdentityAllocator,
};
