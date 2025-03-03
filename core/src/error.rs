//! Error types for the core crate
//!
//! This module provides a consolidated error type for the core crate,
//! wrapping errors from various components.

use thiserror::Error;
use std::io;

/// Core error type
#[derive(Error, Debug)]
pub enum CoreError {
    /// Cryptographic operation error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Merkle tree operation error
    #[error("Merkle tree error: {0}")]
    MerkleError(String),

    /// Data serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid state transition
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    /// Schema validation error
    #[error("Schema validation error: {0}")]
    SchemaValidationError(String),

    /// Resource limit exceeded
    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    /// JSON error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Bincode error
    #[error("Bincode error: {0}")]
    BincodeError(#[from] bincode::Error),

    /// Hex decoding error
    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),

    /// UUID error
    #[error("UUID error: {0}")]
    UuidError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// State management error
    #[error("State management error: {0}")]
    StateError(String),

    /// General error
    #[error("General error: {0}")]
    GeneralError(String),
}

/// Result type for the core crate
pub type Result<T> = std::result::Result<T, CoreError>;

/// Convert a string error to a CoreError
pub fn to_crypto_error<E: std::fmt::Display>(err: E) -> CoreError {
    CoreError::CryptoError(err.to_string())
}

/// Convert a string error to a MerkleError
pub fn to_merkle_error<E: std::fmt::Display>(err: E) -> CoreError {
    CoreError::MerkleError(err.to_string())
}

/// Convert a string error to a SerializationError
pub fn to_serialization_error<E: std::fmt::Display>(err: E) -> CoreError {
    CoreError::SerializationError(err.to_string())
}

/// Convert a string error to a SchemaValidationError
pub fn to_schema_validation_error<E: std::fmt::Display>(err: E) -> CoreError {
    CoreError::SchemaValidationError(err.to_string())
}

/// Convert a string error to a ResourceLimitExceeded
pub fn to_resource_limit_error<E: std::fmt::Display>(err: E) -> CoreError {
    CoreError::ResourceLimitExceeded(err.to_string())
}

/// Convert a string error to a StateError
pub fn to_state_error<E: std::fmt::Display>(err: E) -> CoreError {
    CoreError::StateError(err.to_string())
}

/// Convert a string error to a ConfigError
pub fn to_config_error<E: std::fmt::Display>(err: E) -> CoreError {
    CoreError::ConfigError(err.to_string())
}

/// Convert a string error to a GeneralError
pub fn to_general_error<E: std::fmt::Display>(err: E) -> CoreError {
    CoreError::GeneralError(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_conversion() {
        // Test conversion from io::Error
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let core_err: CoreError = io_err.into();
        match core_err {
            CoreError::IoError(_) => {}
            _ => panic!("Expected IoError variant"),
        }

        // Test conversion from serde_json::Error
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let core_err: CoreError = json_err.into();
        match core_err {
            CoreError::JsonError(_) => {}
            _ => panic!("Expected JsonError variant"),
        }

        // Test helper functions
        let core_err = to_crypto_error("test error");
        match core_err {
            CoreError::CryptoError(msg) => assert_eq!(msg, "test error"),
            _ => panic!("Expected CryptoError variant"),
        }

        let core_err = to_merkle_error("test error");
        match core_err {
            CoreError::MerkleError(msg) => assert_eq!(msg, "test error"),
            _ => panic!("Expected MerkleError variant"),
        }
    }

    #[test]
    fn test_error_display() {
        let err = CoreError::CryptoError("invalid key".to_string());
        assert_eq!(err.to_string(), "Cryptographic error: invalid key");

        let err = CoreError::MerkleError("invalid proof".to_string());
        assert_eq!(err.to_string(), "Merkle tree error: invalid proof");

        let err = CoreError::GeneralError("something went wrong".to_string());
        assert_eq!(err.to_string(), "General error: something went wrong");
    }
} 