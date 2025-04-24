//! Verification module for cryptographic verification of database state
//! 
//! This module provides cryptographic verification capabilities for the database,
//! including Merkle trees, state tracking, and proof generation/verification.

// Re-export the merkle submodule
pub mod merkle;
pub use merkle::{MerkleTree, SparseMerkleTree, MerkleProof, MerkleLeaf, ProofNode, NodePosition};

// Export the state capture module
pub mod state;
pub use state::{StateCaptureManager, TableState, DatabaseState, TableSchema, Row, Value, CoreDatabaseState as BlockState};

// Export the verification environment module
pub mod environment;
pub use environment::{VerificationEnvironment, VerificationEnvironmentConfig, VerificationExecutionResult};

// Export the EigenLayer integration module
pub mod contract;
pub use contract::{ContractManager, ContractConfig, StateCommitment, Challenge, ChallengeStatus};

// Export the deterministic module
pub mod deterministic;
pub use deterministic::{DeterministicTimestamp, DeterministicRandom, DeterministicSqlFunctions};

// Export the verification service client
pub mod client;
pub use client::VerificationServiceClient;

// Space for additional verification components
// These will be implemented in future PRs:
// - Merkle trie for efficient key-value storage
// - Zero-knowledge proof integration

/// Result of a verification operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// Verification succeeded
    Success,
    
    /// Verification failed
    Failure(String),
    
    /// Verification was skipped
    Skipped(String),
}

/// Trait for verifiable components
pub trait Verifiable {
    /// Get the current state root
    fn state_root(&self) -> [u8; 32];
    
    /// Verify a transaction
    fn verify_transaction(&self, transaction_id: u64) -> crate::error::Result<VerificationResult>;
    
    /// Generate a proof for a specific key
    fn generate_proof(&self, key: &str) -> crate::error::Result<Vec<u8>>;
    
    /// Verify a proof for a specific key
    fn verify_proof(&self, key: &str, proof: &[u8]) -> crate::error::Result<bool>;
}