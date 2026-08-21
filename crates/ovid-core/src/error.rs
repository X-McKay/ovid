//! Shared error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OvidError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(String),

    #[error("repository error: {0}")]
    Repository(String),

    #[error("pack error: {0}")]
    Pack(String),

    #[error("execution error: {0}")]
    Execution(String),

    #[error("policy violation: {0}")]
    Policy(String),

    #[error("evidence store error: {0}")]
    Evidence(String),

    #[error("unsupported on this host: {0}")]
    UnsupportedHost(String),

    #[error("budget exhausted: {0}")]
    BudgetExhausted(String),

    #[error("{0}")]
    Other(String),
}

impl From<serde_json::Error> for OvidError {
    fn from(e: serde_json::Error) -> Self {
        OvidError::Serde(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, OvidError>;
