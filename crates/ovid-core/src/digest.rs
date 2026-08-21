//! SHA-256 content digests.
//!
//! Content addressing underpins the evidence ledger's immutability (§6.4),
//! cache reuse rules (§32.3), and provenance pinning (§12.4). All digests are
//! rendered in the conventional `sha256:<hex>` form.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::io::Read;
use std::path::Path;

/// A `sha256:<hex>` content digest.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    /// Digest of an in-memory byte slice.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Digest(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    /// Digest of a file's contents, streamed.
    pub fn of_file(path: &Path) -> std::io::Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(Digest(format!("sha256:{}", hex::encode(hasher.finalize()))))
    }

    /// Combine multiple digests into one (order-sensitive), for chain heads
    /// and composite fingerprints.
    pub fn combine<'a>(parts: impl IntoIterator<Item = &'a Digest>) -> Self {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part.0.as_bytes());
            hasher.update(b"\n");
        }
        Digest(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The hex portion without the `sha256:` prefix.
    pub fn hex(&self) -> &str {
        self.0.strip_prefix("sha256:").unwrap_or(&self.0)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_matches_known_vector() {
        // sha256("") is a well-known constant.
        assert_eq!(
            Digest::of_bytes(b"").as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn combine_is_order_sensitive() {
        let a = Digest::of_bytes(b"a");
        let b = Digest::of_bytes(b"b");
        assert_ne!(Digest::combine([&a, &b]), Digest::combine([&b, &a]));
    }

    #[test]
    fn file_digest_matches_bytes_digest() {
        let dir = std::env::temp_dir().join("ovid-digest-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.txt");
        std::fs::write(&path, b"hello").unwrap();
        assert_eq!(Digest::of_file(&path).unwrap(), Digest::of_bytes(b"hello"));
    }
}
