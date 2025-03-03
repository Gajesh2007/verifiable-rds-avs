//! # Verifiable Database Core
//!
//! Core data structures and utilities for the Verifiable RDS AVS.
//! This crate provides the fundamental building blocks for the verification system.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

pub mod crypto;
pub mod merkle;
pub mod models;
pub mod schema;
pub mod utils;

/// Re-export common types for ease of use
pub use merkle::{SecureMerkleTree, SecureMerkleProof};
pub use models::{BlockState, TableState, Row, TransactionRecord, Challenge};
pub use crypto::SecureHasher;

/// Error types for the core crate
pub mod error {
    use thiserror::Error;

    /// Core error types
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

        /// General error
        #[error("General error: {0}")]
        GeneralError(String),
    }
}

/// Result type for the core crate
pub type Result<T> = std::result::Result<T, error::CoreError>;

/// Version of the core crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Create a domain-separated secure hash
///
/// # Arguments
///
/// * `domain` - Domain prefix (e.g., "LEAF", "NODE")
/// * `data` - Data to hash
///
/// # Returns
///
/// A 32-byte secure hash with domain separation
pub fn secure_hash(domain: &str, data: &[u8]) -> [u8; 32] {
    crypto::secure_hash(domain, data)
}

/// Create a domain-separated secure hash of multiple inputs
///
/// # Arguments
///
/// * `domain` - Domain prefix (e.g., "LEAF", "NODE")
/// * `data` - Vector of data to hash
///
/// # Returns
///
/// A 32-byte secure hash with domain separation
pub fn secure_hash_multiple(domain: &str, data: &[&[u8]]) -> [u8; 32] {
    crypto::secure_hash_multiple(domain, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_hash_domain_separation() {
        let data = b"test data";
        
        // Different domains should produce different hashes
        let hash1 = secure_hash("DOMAIN1", data);
        let hash2 = secure_hash("DOMAIN2", data);
        
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_secure_hash_multiple() {
        let data1 = b"test data 1";
        let data2 = b"test data 2";
        
        let hash1 = secure_hash_multiple("TEST", &[data1, data2]);
        
        // Order matters
        let hash2 = secure_hash_multiple("TEST", &[data2, data1]);
        
        assert_ne!(hash1, hash2);
    }
} 