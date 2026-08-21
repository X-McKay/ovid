//! Core vocabulary shared by every Ovid crate.
//!
//! This crate deliberately contains no I/O and no policy: it defines the
//! stable data model that the rest of the system builds on, mirroring the
//! spec's "observe boundaries, not frameworks" principle (§6.1):
//!
//! - [`id`] — typed, sortable identifiers (`evidence:…`, `claim:…`, `run:…`).
//! - [`digest`] — SHA-256 content digests used for content addressing.
//! - [`trust`] — the T0–T5 evidence trust tiers (§22.1).
//! - [`states`] — the claim-state vocabulary and causal classifications
//!   (§22.5, §20.5). These are the words Ovid is *not allowed to collapse*
//!   into each other (§6.3).
//! - [`event`] — normalized boundary events (§13.7) emitted by observers.
//! - [`error`] — the shared error type.

pub mod digest;
pub mod error;
pub mod event;
pub mod id;
pub mod states;
pub mod trust;

pub use digest::Digest;
pub use error::OvidError;
pub use event::{BoundaryEvent, EventEnvelope, EventKind, ProcessIdentity};
pub use id::{IdGenerator, OvidId};
pub use states::{CausalClassification, ClaimState, ClaimStates};
pub use trust::TrustTier;

/// The manifest / schema API version emitted by this build.
pub const MANIFEST_API_VERSION: &str = "ovid.dev/manifest/v1alpha1";
/// The world-lock schema API version emitted by this build.
pub const WORLD_API_VERSION: &str = "ovid.dev/world/v1alpha1";
/// The pack schema API version accepted by this build.
pub const PACK_API_VERSION: &str = "ovid.dev/pack/v1";
/// Ovid version, propagated into provenance sections.
pub const OVID_VERSION: &str = env!("CARGO_PKG_VERSION");
