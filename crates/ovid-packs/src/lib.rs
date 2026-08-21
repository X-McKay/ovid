//! Declarative packs (spec §15, ADR-005).
//!
//! Most ecosystem growth happens through packs, not core analyzers. A pack
//! is versioned, schema-validated YAML; four kinds are supported:
//!
//! - **runner-recipe** — how to detect an ecosystem and which conventional
//!   commands provision/build/test/start it (§15.2). The core never learns
//!   what `Cargo.toml` means beyond evaluating the recipe.
//! - **service-pack** — how to start a disposable infrastructure dependency
//!   (§15.5): image, ports, readiness, generated configuration.
//! - **protocol-pack** — how to classify a network destination (§15.4):
//!   default ports, first-byte signatures, compatible service packs.
//! - **tool-resolver-pack** — which trusted artifact can provide a missing
//!   executable or file (§15.3). Candidates are proposals; only a rerun
//!   experiment confirms them (§15.3, ADR-007).
//!
//! Built-in packs ship embedded in the binary from the repository's
//! `packs/` tree; additional packs load from a directory. Signature
//! verification is modeled by the `signer` metadata field plus local
//! allow-policy; cryptographic verification is a documented follow-up.

pub mod registry;
pub mod schema;

pub use registry::PackRegistry;
pub use schema::{
    Pack, PackMetadata, ProtocolMatch, ProtocolPack, ResolverCandidate, RunnerRecipe, ServicePack,
    ToolResolverPack,
};
