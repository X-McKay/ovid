//! Typed, lexicographically sortable identifiers.
//!
//! Every first-class object in Ovid (evidence record, claim, run, experiment,
//! analysis, world, …) is addressed by an id of the form `<kind>:<token>`.
//! Tokens are ULID-like: a millisecond timestamp prefix followed by a
//! counter/entropy suffix, encoded in Crockford base32 so that ids created
//! later sort later. A [`IdGenerator`] can be seeded deterministically for
//! golden tests (spec §37.7 requires deterministic digest tests).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A typed identifier such as `evidence:01J6V8...` or `claim:01J6W...`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OvidId(String);

impl OvidId {
    /// Construct from a raw string. The caller asserts the format is valid.
    pub fn from_string(s: impl Into<String>) -> Self {
        OvidId(s.into())
    }

    /// The `kind` prefix (text before the first `:`), e.g. `evidence`.
    pub fn kind(&self) -> &str {
        self.0.split(':').next().unwrap_or("")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OvidId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for OvidId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Generates sortable ids. Thread-safe.
///
/// In `deterministic` mode the timestamp component is replaced by a fixed
/// epoch so equivalent runs produce identical ids — required for golden
/// regression tests.
pub struct IdGenerator {
    counter: AtomicU64,
    deterministic: bool,
}

impl IdGenerator {
    pub fn new() -> Self {
        IdGenerator {
            counter: AtomicU64::new(0),
            deterministic: false,
        }
    }

    /// Deterministic generator for tests and reproducible fixtures.
    pub fn deterministic() -> Self {
        IdGenerator {
            counter: AtomicU64::new(0),
            deterministic: true,
        }
    }

    /// Create the next id with the given kind prefix.
    pub fn next(&self, kind: &str) -> OvidId {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let millis = if self.deterministic {
            0
        } else {
            chrono::Utc::now().timestamp_millis().max(0) as u64
        };
        OvidId(format!(
            "{kind}:{}{}",
            encode_base32(millis, 10),
            encode_base32(n, 8)
        ))
    }
}

impl Default for IdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode `value` as fixed-width Crockford base32 (big-endian).
fn encode_base32(mut value: u64, width: usize) -> String {
    let mut out = vec![b'0'; width];
    for slot in out.iter_mut().rev() {
        *slot = CROCKFORD[(value & 0x1f) as usize];
        value >>= 5;
    }
    String::from_utf8(out).expect("base32 output is ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_typed_and_sortable() {
        let generator = IdGenerator::new();
        let a = generator.next("evidence");
        let b = generator.next("evidence");
        assert_eq!(a.kind(), "evidence");
        assert!(a < b, "later ids must sort later: {a} vs {b}");
    }

    #[test]
    fn deterministic_ids_are_stable() {
        let g1 = IdGenerator::deterministic();
        let g2 = IdGenerator::deterministic();
        assert_eq!(g1.next("claim"), g2.next("claim"));
        assert_eq!(g1.next("claim"), g2.next("claim"));
    }

    #[test]
    fn base32_is_fixed_width() {
        assert_eq!(encode_base32(0, 8).len(), 8);
        assert_eq!(encode_base32(u64::MAX, 13).len(), 13);
    }
}
