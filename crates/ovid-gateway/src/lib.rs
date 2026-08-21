//! Network analysis (spec §13.10, §17, FR-040..FR-049).
//!
//! Turns observed socket/DNS boundary events into classified
//! external-dependency observations: logical identities grouped by DNS
//! name (surviving CDN address rotation), listeners, unix sockets,
//! resolver-bypass detection, and per-destination failure accounting.
//! These observations are the raw material for the prove loop's network
//! candidates (proposal §10.4); network *enforcement* lives in the
//! laboratories (namespace isolation, guest `--no-net`), never here.

pub mod analysis;
pub mod proxy;

pub use analysis::{analyze_network, ExternalObservation, Listener, NetworkAnalysis};
pub use proxy::{
    read_intents, serve_blocking, GatewayIntent, GatewayPolicy, GatewayServer, Upstream,
};
