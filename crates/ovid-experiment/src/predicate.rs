//! Success predicates (FR-016, §8.2).

use serde::{Deserialize, Serialize};

/// A user-visible definition of "the workload succeeded".
///
/// Mirrors `ovid_world::SuccessSpec` but evaluates against raw run
/// signals; the CLI converts between the two when writing locks.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SuccessPredicate {
    ExitCode {
        expected: i32,
    },
    /// Exit code AND a marker in combined output (e.g. `test result: ok`).
    OutputContains {
        expected_exit: i32,
        needle: String,
    },
    /// A file exists in the workspace after the run.
    ArtifactExists {
        path: String,
    },
}

impl SuccessPredicate {
    pub fn evaluate(
        &self,
        exit_code: Option<i32>,
        combined_output: &str,
        workspace: &std::path::Path,
    ) -> bool {
        match self {
            SuccessPredicate::ExitCode { expected } => exit_code == Some(*expected),
            SuccessPredicate::OutputContains {
                expected_exit,
                needle,
            } => exit_code == Some(*expected_exit) && combined_output.contains(needle),
            SuccessPredicate::ArtifactExists { path } => workspace.join(path).exists(),
        }
    }

    /// Human description, recorded into experiment records (FR-054).
    pub fn describe(&self) -> String {
        match self {
            SuccessPredicate::ExitCode { expected } => format!("exit-code == {expected}"),
            SuccessPredicate::OutputContains {
                expected_exit,
                needle,
            } => {
                format!("exit-code == {expected_exit} and output contains {needle:?}")
            }
            SuccessPredicate::ArtifactExists { path } => format!("artifact exists: {path}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn exit_code_predicate() {
        let predicate = SuccessPredicate::ExitCode { expected: 0 };
        assert!(predicate.evaluate(Some(0), "", Path::new("/tmp")));
        assert!(!predicate.evaluate(Some(1), "", Path::new("/tmp")));
        assert!(
            !predicate.evaluate(None, "", Path::new("/tmp")),
            "signal death is not success"
        );
    }

    #[test]
    fn output_predicate_requires_both() {
        let predicate = SuccessPredicate::OutputContains {
            expected_exit: 0,
            needle: "test result: ok".into(),
        };
        assert!(predicate.evaluate(Some(0), "…test result: ok. 12 passed…", Path::new("/tmp")));
        assert!(!predicate.evaluate(Some(0), "no tests ran", Path::new("/tmp")));
        assert!(!predicate.evaluate(Some(1), "test result: ok", Path::new("/tmp")));
    }

    #[test]
    fn artifact_predicate_checks_workspace() {
        let dir = std::env::temp_dir().join("ovid-predicate-test");
        std::fs::create_dir_all(dir.join("target")).unwrap();
        std::fs::write(dir.join("target/app"), "bin").unwrap();
        let predicate = SuccessPredicate::ArtifactExists {
            path: "target/app".into(),
        };
        assert!(
            predicate.evaluate(Some(1), "", &dir),
            "artifact predicate ignores exit code"
        );
        assert!(!predicate.evaluate(Some(0), "", Path::new("/nonexistent")));
    }
}
