//! Verifiable PostgreSQL Proxy
//!
//! This crate provides a proxy for PostgreSQL that intercepts queries and verifies them on a blockchain.

// Error types and result
pub mod error;
pub use error::{ProxyError, Result};

// Configuration
pub mod config;
pub use config::ProxyConfig;

// Protocol-related modules
pub mod protocol;
pub use protocol::{FrontendMessage, BackendMessage, AuthenticationRequest, AuthMethod, ClientConnection};

// Query interception and analysis
pub mod interception;
pub use interception::{QueryMetadata, QueryType};

// Security features
pub mod security;
pub use security::{RateLimiter, RateLimiterConfig};

// Server implementation
pub mod server;
pub use server::ProxyServer;

// Verification engine
pub mod verification;

// Transaction processing
pub mod transaction; 