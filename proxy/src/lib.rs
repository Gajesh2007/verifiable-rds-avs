//! PostgreSQL wire protocol proxy for the Verifiable RDS AVS
//!
//! This crate implements a PostgreSQL-compatible wire protocol handler
//! that intercepts and analyzes database operations for verification.

/// Error types for the proxy
pub mod error;

/// Configuration for the proxy
pub mod config;

/// PostgreSQL wire protocol implementation
pub mod protocol;

/// Query interception and analysis
pub mod interception;

/// Security features like rate limiting and DoS protection
pub mod security;

/// Server implementation
pub mod server;

/// Verification module
pub mod verification;

/// Transaction module
pub mod transaction;

// Re-export important types
pub use config::ProxyConfig;
pub use server::ProxyServer;
pub use error::ProxyError;

// Re-export commonly used types
pub use error::{ProxyError, Result};
pub use protocol::{
    message::{FrontendMessage, BackendMessage, AuthenticationRequest},
    parser::MessageParser,
    formatter::MessageFormatter,
    connection::{ClientConnection, ConnectionState, ConnectionStats},
    auth::{AuthHandler, AuthState, AuthMethod, AuthConfig},
    transaction::{TransactionTracker, TransactionState, IsolationLevel, AccessMode},
    validator::{ProtocolValidator, ProtocolValidatorConfig},
};
pub use interception::{
    analyzer::{QueryAnalyzer, QueryMetadata, QueryType},
    execution::{QueryExecutor, ExecutionPlan, ExecutionResult},
    rewrite::{QueryRewriter, RewriteAction, RewriteReason},
    verification::{VerificationManager, VerificationResult, VerificationStatus},
};
pub use verification::{
    MerkleTree, SparseMerkleTree, MerkleProof, Verifiable,
}; 