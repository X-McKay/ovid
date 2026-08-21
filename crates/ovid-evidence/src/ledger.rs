//! Append-only, hash-chained JSONL evidence ledger (spec §22.6).

use crate::record::EvidenceRecord;
use ovid_core::{Digest, OvidError};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use ovid_core::OvidId;

/// An on-disk evidence ledger.
///
/// Records are appended as one JSON object per line. Each record's
/// `previous` field holds the digest of the prior record, forming a hash
/// chain whose head is exported into provenance. `verify_chain` recomputes
/// the chain and detects any modification or reordering.
pub struct EvidenceLedger {
    path: PathBuf,
    head: Option<Digest>,
    count: u64,
    /// In-memory index for explain traversal (FR-110). The file remains
    /// canonical; this is a projection.
    index: HashMap<OvidId, EvidenceRecord>,
}

impl EvidenceLedger {
    /// Open or create a ledger at `path`, loading any existing records.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, OvidError> {
        let path = path.into();
        let mut ledger = EvidenceLedger {
            path: path.clone(),
            head: None,
            count: 0,
            index: HashMap::new(),
        };
        if path.exists() {
            let reader = BufReader::new(File::open(&path)?);
            for line in reader.lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let record: EvidenceRecord = serde_json::from_str(&line)
                    .map_err(|e| OvidError::Evidence(format!("corrupt ledger line: {e}")))?;
                ledger.head = Some(record.digest());
                ledger.index.insert(record.id.clone(), record);
                ledger.count += 1;
            }
        } else if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(ledger)
    }

    /// Append a record, linking it into the hash chain. Returns the record's
    /// digest (the new chain head).
    pub fn append(&mut self, mut record: EvidenceRecord) -> Result<Digest, OvidError> {
        record.previous = self.head.clone();
        let digest = record.digest();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let json = serde_json::to_string(&record)?;
        writeln!(file, "{json}")?;
        self.head = Some(digest.clone());
        self.index.insert(record.id.clone(), record);
        self.count += 1;
        Ok(digest)
    }

    /// The current chain head, exported as `provenance.evidence_chain_head`.
    pub fn chain_head(&self) -> Option<&Digest> {
        self.head.as_ref()
    }

    pub fn len(&self) -> u64 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Look up a record by id (explain traversal).
    pub fn get(&self, id: &OvidId) -> Option<&EvidenceRecord> {
        self.index.get(id)
    }

    /// Iterate all records in insertion order by re-reading the file (the
    /// canonical copy), useful for projections and exports.
    pub fn iter_all(&self) -> Result<Vec<EvidenceRecord>, OvidError> {
        let mut out = Vec::with_capacity(self.count as usize);
        if !self.path.exists() {
            return Ok(out);
        }
        let reader = BufReader::new(File::open(&self.path)?);
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            out.push(
                serde_json::from_str(&line)
                    .map_err(|e| OvidError::Evidence(format!("corrupt ledger line: {e}")))?,
            );
        }
        Ok(out)
    }

    /// Recompute the hash chain from disk and confirm it matches. Returns
    /// the verified head digest.
    pub fn verify_chain(&self) -> Result<Option<Digest>, OvidError> {
        let mut previous: Option<Digest> = None;
        for record in self.iter_all()? {
            if record.previous != previous {
                return Err(OvidError::Evidence(format!(
                    "chain break at record {}: expected previous {:?}, found {:?}",
                    record.id, previous, record.previous
                )));
            }
            previous = Some(record.digest());
        }
        if previous != self.head {
            return Err(OvidError::Evidence(
                "ledger head does not match file contents".into(),
            ));
        }
        Ok(previous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovid_core::{IdGenerator, TrustTier};

    fn record(generator: &IdGenerator, data: &str) -> EvidenceRecord {
        EvidenceRecord {
            id: generator.next("evidence"),
            record_type: "test".into(),
            run_id: None,
            wall_time: None,
            provider: "test-provider".into(),
            provider_version: "0.0.0".into(),
            trust_tier: TrustTier::T1,
            data: serde_json::json!({ "value": data }),
            previous: None,
        }
    }

    #[test]
    fn append_chains_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        let generator = IdGenerator::deterministic();
        let mut ledger = EvidenceLedger::open(&path).unwrap();
        ledger.append(record(&generator, "a")).unwrap();
        let head = ledger.append(record(&generator, "b")).unwrap();
        assert_eq!(ledger.chain_head(), Some(&head));
        assert_eq!(ledger.verify_chain().unwrap(), Some(head));
    }

    #[test]
    fn reopen_restores_head_and_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        let generator = IdGenerator::deterministic();
        let id = {
            let mut ledger = EvidenceLedger::open(&path).unwrap();
            let rec = record(&generator, "persisted");
            let id = rec.id.clone();
            ledger.append(rec).unwrap();
            id
        };
        let reopened = EvidenceLedger::open(&path).unwrap();
        assert_eq!(reopened.len(), 1);
        assert!(reopened.get(&id).is_some());
        reopened.verify_chain().unwrap();
    }

    #[test]
    fn tampering_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        let generator = IdGenerator::deterministic();
        let mut ledger = EvidenceLedger::open(&path).unwrap();
        ledger.append(record(&generator, "a")).unwrap();
        ledger.append(record(&generator, "b")).unwrap();
        // Tamper with the first line.
        let contents = std::fs::read_to_string(&path).unwrap();
        let tampered = contents.replacen("\"a\"", "\"attacker\"", 1);
        std::fs::write(&path, tampered).unwrap();
        assert!(ledger.verify_chain().is_err());
    }
}
