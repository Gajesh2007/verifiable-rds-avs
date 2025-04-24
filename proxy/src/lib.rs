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

// WAL listener
pub mod wal_listener;

// Test utilities
#[cfg(test)]
pub mod test_utils {
    use std::future::Future;
    use std::time::Duration;
    use tokio::time::timeout;
    
    /// Run an async test with a timeout to prevent hanging
    pub async fn run_with_timeout<F, T>(fut: F, timeout_duration: Duration) -> T 
    where
        F: Future<Output = T>,
    {
        match timeout(timeout_duration, fut).await {
            Ok(result) => result,
            Err(_) => panic!("Test timed out after {:?}", timeout_duration),
        }
    }
    
    /// Run a test with the default 5-second timeout
    pub async fn run_test<F, T>(fut: F) -> T 
    where
        F: Future<Output = T>,
    {
        run_with_timeout(fut, Duration::from_secs(5)).await
    }
} 