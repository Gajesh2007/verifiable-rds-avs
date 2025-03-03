//! Error types for the PostgreSQL proxy
//!
//! This module provides error types for the PostgreSQL proxy server.

use std::io;
use std::net::AddrParseError;
use std::num::ParseIntError;
use thiserror::Error;

/// Result type for the proxy
pub type Result<T> = std::result::Result<T, ProxyError>;

/// Error type for the proxy
#[derive(Debug, Error)]
pub enum ProxyError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
    
    /// Address parsing error
    #[error("Address parsing error: {0}")]
    AddrParse(#[from] AddrParseError),
    
    /// Integer parsing error
    #[error("Integer parsing error: {0}")]
    ParseInt(#[from] ParseIntError),
    
    /// PostgreSQL protocol error
    #[error("PostgreSQL protocol error: {0}")]
    Protocol(String),
    
    /// Authentication error
    #[error("Authentication error: {0}")]
    Auth(String),
    
    /// Database error
    #[error("Database error: {0}")]
    Database(String),
    
    /// Query error
    #[error("Query error: {0}")]
    Query(String),
    
    /// Transaction error
    #[error("Transaction error: {0}")]
    Transaction(String),
    
    /// Security error
    #[error("Security error: {0}")]
    Security(String),
    
    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    /// Non-deterministic query
    #[error("Non-deterministic query: {0}")]
    NonDeterministicQuery(String),
    
    /// Verification error
    #[error("Verification error: {0}")]
    Verification(String),
    
    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),
    
    /// Analysis error
    #[error("Analysis error: {0}")]
    Analysis(String),
    
    /// Execution error
    #[error("Execution error: {0}")]
    Execution(String),
    
    /// Not implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    
    /// Other error
    #[error("{0}")]
    Other(String),
}

/// Helper function to convert string errors to ProxyError
pub fn to_proxy_error<E: ToString>(err: E) -> ProxyError {
    ProxyError::Other(err.to_string())
}

/// Convert a ProxyError to a PostgreSQL error message
pub fn to_pg_error(error: &ProxyError) -> (String, String) {
    match error {
        ProxyError::Auth(msg) => ("28000".to_string(), msg.clone()), // Invalid authorization specification
        ProxyError::Protocol(msg) => ("08P01".to_string(), msg.clone()), // Protocol violation
        ProxyError::Query(msg) => ("42000".to_string(), msg.clone()), // Syntax error or access rule violation
        ProxyError::Verification(msg) => ("XX000".to_string(), format!("Verification error: {}", msg)), // Internal error
        ProxyError::Execution(msg) => ("XX000".to_string(), format!("Execution error: {}", msg)), // Internal error
        ProxyError::Security(msg) => ("28000".to_string(), format!("Security error: {}", msg)), // Invalid authorization specification
        _ => ("XX000".to_string(), format!("Internal error: {}", error)), // Internal error
    }
} 